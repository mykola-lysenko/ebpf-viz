import { exec } from "child_process";
import { readdir, readlink, readFile, stat } from "fs/promises";
import { promisify } from "util";

const execAsync = promisify(exec);

/** How to run a command inside a discovered namespace:
 *  - nsenter: enter its netns by path (works when the process is in our /proc)
 *  - docker:  `docker exec` into the container (separate PID namespace, e.g.
 *    WSL + Docker Desktop, where the workloads live in another WSL VM) */
export type NetnsReach =
  | { via: "nsenter"; nsPath: string }
  | { via: "docker"; container: string };

/** A discovered non-root network namespace and how to enter it. */
export interface NetnsRef {
  /** nsfs inode number, or container id, as a string. */
  id: string;
  /** Human label — see discoverNetNamespaces for the preference order. */
  label: string;
  reach: NetnsReach;
}

/** Upper bound on namespaces scanned per poll. Every namespace costs one
 *  nsenter+bpftool exec; a busy k8s node can have hundreds of pods. */
export const MAX_NETNS = 64;

/** Parse the readlink target of /proc/<pid>/ns/net ("net:[4026531840]"). */
export function parseNsInode(link: string): string | null {
  const m = /^net:\[(\d+)\]$/.exec(link.trim());
  return m ? m[1] : null;
}

/** Pick the best label from the processes living in a netns: the comm of the
 *  lowest pid that isn't a k8s "pause" sandbox placeholder, falling back to
 *  the lowest pid's comm. Assumes `procs` is sorted by pid ascending. */
export function pickNetnsLabel(
  procs: Array<{ pid: number; comm: string }>
): string {
  const real = procs.find(p => p.comm !== "pause");
  return (real ?? procs[0])?.comm ?? "unknown";
}

/** Make labels unique by suffixing duplicates with the last digits of their
 *  netns inode (two kind nodes both label as their hostname otherwise). */
export function dedupeNetnsLabels(refs: NetnsRef[]): NetnsRef[] {
  const counts = new Map<string, number>();
  for (const ref of refs) counts.set(ref.label, (counts.get(ref.label) ?? 0) + 1);
  return refs.map(ref =>
    (counts.get(ref.label) ?? 0) > 1
      ? { ...ref, label: `${ref.label}#${ref.id.slice(-4)}` }
      : ref
  );
}

/** Enumerate running Docker containers as reachable namespaces. Best-effort:
 *  returns [] when the `docker` CLI is absent or the daemon is unreachable.
 *  `seen` is not consulted here (container ids are their own identity), but we
 *  skip nothing since /proc found nothing when this runs. */
export async function discoverDockerNamespaces(
  _seen: Set<string>
): Promise<NetnsRef[]> {
  let stdout: string;
  try {
    const res = await execAsync("docker ps --format '{{.ID}} {{.Names}}'", {
      timeout: 5000,
    });
    stdout = res.stdout;
  } catch {
    return []; // no docker, or daemon down
  }
  const refs: NetnsRef[] = [];
  for (const line of stdout.trim().split("\n")) {
    if (!line.trim()) continue;
    const [id, ...nameParts] = line.trim().split(/\s+/);
    if (!id) continue;
    refs.push({
      id,
      label: nameParts.join(" ") || id,
      reach: { via: "docker", container: id },
    });
  }
  return refs;
}

async function readComm(pid: number): Promise<string> {
  try {
    return (await readFile(`/proc/${pid}/comm`, "utf8")).trim();
  } catch {
    return "unknown";
  }
}

/** Container hostname beats comm as a label: for kind nodes it's the node
 *  name, for pods the pod name. Only readable as root; requires the process
 *  to have a mounted root with /etc/hostname. */
async function readContainerHostname(pid: number): Promise<string | null> {
  try {
    const name = (await readFile(`/proc/${pid}/root/etc/hostname`, "utf8")).trim();
    return name || null;
  } catch {
    return null;
  }
}

/**
 * Enumerate every network namespace reachable from this host:
 *  - named namespaces bind-mounted under /var/run/netns (`ip netns add`),
 *    labelled by their file name;
 *  - namespaces of live processes found by scanning /proc/<pid>/ns/net,
 *    labelled by container hostname, else representative comm.
 * The host's own netns is excluded. Capped at MAX_NETNS (a warning is
 * logged when namespaces are dropped — silence would read as coverage).
 */
export async function discoverNetNamespaces(): Promise<NetnsRef[]> {
  const refs: NetnsRef[] = [];
  const seen = new Set<string>();

  let hostInode: string | null = null;
  try {
    hostInode = parseNsInode(await readlink("/proc/self/ns/net"));
  } catch {
    return []; // no /proc — nothing to discover
  }
  if (hostInode) seen.add(hostInode);

  // Named namespaces: /var/run/netns/<name> are nsfs bind mounts whose stat
  // inode IS the netns inode.
  try {
    for (const name of await readdir("/var/run/netns")) {
      const nsPath = `/var/run/netns/${name}`;
      try {
        const st = await stat(nsPath);
        const id = String(st.ino);
        if (seen.has(id)) continue;
        seen.add(id);
        refs.push({ id, label: name, reach: { via: "nsenter", nsPath } });
      } catch { /* vanished mid-scan */ }
    }
  } catch { /* no named namespaces */ }

  // Process scan: group pids by netns inode. On WSL/shared-pid setups this
  // finds every container and pod namespace.
  const byInode = new Map<string, number[]>();
  try {
    const entries = await readdir("/proc");
    const pids = entries
      .filter(e => /^\d+$/.test(e))
      .map(Number)
      .sort((a, b) => a - b);
    for (const pid of pids) {
      try {
        const inode = parseNsInode(await readlink(`/proc/${pid}/ns/net`));
        if (!inode || seen.has(inode)) continue;
        const list = byInode.get(inode);
        if (list) list.push(pid);
        else byInode.set(inode, [pid]);
      } catch { /* process exited or not ours */ }
    }
  } catch { /* /proc unreadable */ }

  for (const [inode, pids] of Array.from(byInode.entries())) {
    const procs = await Promise.all(
      pids.slice(0, 8).map(async pid => ({ pid, comm: await readComm(pid) }))
    );
    const representative = procs.find(p => p.comm !== "pause") ?? procs[0];
    const label =
      (representative && (await readContainerHostname(representative.pid))) ??
      pickNetnsLabel(procs);
    refs.push({
      id: inode,
      label,
      reach: { via: "nsenter", nsPath: `/proc/${pids[0]}/ns/net` },
    });
  }

  // Docker bridge: when the /proc scan finds nothing beyond our own namespace
  // but a Docker daemon is reachable (e.g. WSL + Docker Desktop, where the
  // containers run in a separate WSL VM and are invisible to our /proc),
  // enumerate running containers and reach them via `docker exec`.
  if (refs.length === 0) {
    for (const ref of await discoverDockerNamespaces(seen)) refs.push(ref);
  }

  const deduped = dedupeNetnsLabels(refs);
  if (deduped.length > MAX_NETNS) {
    console.warn(
      `[ebpf-netns] ${deduped.length} network namespaces found, scanning first ${MAX_NETNS} — ` +
      "attachments in the dropped namespaces will not appear in the Network view"
    );
    return deduped.slice(0, MAX_NETNS);
  }
  return deduped;
}

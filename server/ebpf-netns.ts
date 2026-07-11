import { exec, execFile } from "child_process";
import { readdir, readlink, readFile, stat } from "fs/promises";
import { promisify } from "util";

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

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
 *  netns inode / container id (two kind nodes both label as their hostname
 *  otherwise). Generic so the parser can apply it to uploaded snapshots too. */
export function dedupeNetnsLabels<T extends { id: string; label: string }>(
  refs: T[]
): T[] {
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
 *  Containers whose init pid is visible in OUR /proc with an already-seen
 *  netns inode are skipped — the nsenter path covers them; the docker-exec
 *  path is for containers in a separate VM (WSL + Docker Desktop). */
export async function discoverDockerNamespaces(
  seenInodes: Set<string>
): Promise<NetnsRef[]> {
  let idsOut: string;
  try {
    idsOut = (await execAsync("docker ps -q", { timeout: 5000 })).stdout;
  } catch {
    return []; // no docker, or daemon down
  }
  const ids = idsOut
    .trim()
    .split("\n")
    .map(l => l.trim())
    .filter(Boolean);
  if (ids.length === 0) return [];

  let inspectOut: string;
  try {
    inspectOut = (
      await execFileAsync(
        "docker",
        ["inspect", "--format", "{{.Id}}\t{{.State.Pid}}\t{{.Name}}", ...ids],
        { timeout: 5000, maxBuffer: 4 * 1024 * 1024 }
      )
    ).stdout;
  } catch {
    return [];
  }

  const refs: NetnsRef[] = [];
  for (const line of inspectOut.trim().split("\n")) {
    const [fullId, pidStr, rawName] = line.split("\t");
    if (!fullId) continue;
    const shortId = fullId.slice(0, 12);
    const pid = Number(pidStr);
    if (Number.isFinite(pid) && pid > 0) {
      try {
        const inode = parseNsInode(await readlink(`/proc/${pid}/ns/net`));
        // Visible in our /proc and already discovered (or it IS the host
        // netns, e.g. --network=host) → the nsenter path covers it.
        if (inode && seenInodes.has(inode)) continue;
      } catch {
        /* pid not in our /proc → separate VM → reach via docker exec */
      }
    }
    refs.push({
      id: shortId,
      label: (rawName ?? "").replace(/^\//, "") || shortId,
      reach: { via: "docker", container: shortId },
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
 *    labelled by container hostname, else representative comm;
 *  - Docker containers not otherwise visible (separate VM), via docker exec.
 * The host's own netns is excluded. Capped at MAX_NETNS (a warning is
 * logged when namespaces are dropped — silence would read as coverage).
 * Results are cached briefly: the namespace set changes on container churn,
 * not every poll, and the full scan costs a /proc sweep + docker round-trip.
 */
const DISCOVERY_TTL_MS = 30_000;
let cachedRefs: NetnsRef[] | null = null;
let cachedAt = 0;

export async function discoverNetNamespaces(): Promise<NetnsRef[]> {
  const now = Date.now();
  if (cachedRefs && now - cachedAt < DISCOVERY_TTL_MS) return cachedRefs;
  const refs = await discoverNetNamespacesUncached();
  cachedRefs = refs;
  cachedAt = now;
  return refs;
}

/** Test hook / config-change hook: forget the cached namespace list. */
export function clearNetnsDiscoveryCache(): void {
  cachedRefs = null;
  cachedAt = 0;
}

async function discoverNetNamespacesUncached(): Promise<NetnsRef[]> {
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

  // Process scan: group pids by netns inode, batching the readlinks (a busy
  // host has thousands of pids; one awaited readlink each would serialize
  // into hundreds of ms). On WSL/shared-pid setups this finds every
  // container and pod namespace.
  const byInode = new Map<string, number[]>();
  try {
    const entries = await readdir("/proc");
    const pids = entries
      .filter(e => /^\d+$/.test(e))
      .map(Number)
      .sort((a, b) => a - b);
    const CHUNK = 256;
    for (let i = 0; i < pids.length; i += CHUNK) {
      const chunk = await Promise.all(
        pids.slice(i, i + CHUNK).map(async pid => {
          try {
            return { pid, inode: parseNsInode(await readlink(`/proc/${pid}/ns/net`)) };
          } catch {
            return null; // process exited or not ours
          }
        })
      );
      for (const entry of chunk) {
        if (!entry?.inode || seen.has(entry.inode)) continue;
        const list = byInode.get(entry.inode);
        if (list) list.push(entry.pid);
        else byInode.set(entry.inode, [entry.pid]);
      }
    }
  } catch { /* /proc unreadable */ }

  // Apply the cap BEFORE labeling — no point reading comm/hostname for
  // namespaces that get dropped anyway.
  const inodeEntries = Array.from(byInode.entries());
  const budget = Math.max(0, MAX_NETNS - refs.length);
  if (inodeEntries.length > budget) {
    console.warn(
      `[ebpf-netns] ${refs.length + inodeEntries.length} network namespaces found, scanning first ${MAX_NETNS} — ` +
      "attachments in the dropped namespaces will not appear in the Network view"
    );
  }
  const labeled = await Promise.all(
    inodeEntries.slice(0, budget).map(async ([inode, pids]) => {
      const procs = await Promise.all(
        pids.slice(0, 8).map(async pid => ({ pid, comm: await readComm(pid) }))
      );
      const representative = procs.find(p => p.comm !== "pause") ?? procs[0];
      const label =
        (representative && (await readContainerHostname(representative.pid))) ??
        pickNetnsLabel(procs);
      return {
        id: inode,
        label,
        reach: { via: "nsenter" as const, nsPath: `/proc/${pids[0]}/ns/net` },
      };
    })
  );
  refs.push(...labeled);

  // Docker bridge: containers running in a separate VM (WSL + Docker
  // Desktop) are invisible to our /proc; reach them via docker exec.
  // Containers whose netns we already found are skipped inside.
  for (const ref of await discoverDockerNamespaces(seen)) refs.push(ref);

  const deduped = dedupeNetnsLabels(refs);
  return deduped.length > MAX_NETNS ? deduped.slice(0, MAX_NETNS) : deduped;
}

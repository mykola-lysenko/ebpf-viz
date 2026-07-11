import { exec, execFile, execSync } from "child_process";
import { existsSync } from "fs";
import { promisify } from "util";
import { hostname } from "os";
import type {
  BpfMap,
  EbpfSnapshot,
  PollingConfig,
  RawBpfLink,
  RawBpfMap,
  RawBpfProg,
  RawCgroupEntry,
  RawNetSnapshot,
  RawNetnsSnapshot,
  RawNetnsLink,
  RawTcFilterEntry,
} from "../shared/ebpf-types";
import { buildSnapshot, netnsLinkKind, PAIRED_LINK_KINDS } from "./ebpf-parser";
import { buildMockMaps, parseMaps } from "./ebpf-map-parser";
import { discoverNetNamespaces, type NetnsReach } from "./ebpf-netns";
import { MOCK_CGROUPS, MOCK_LINKS, MOCK_NET, MOCK_NETNS, MOCK_PROGS } from "./ebpf-mock";
import {
  ingestSnapshot,
  pruneStale,
  buildActivitySummary,
  getAllHistories,
  getHistory,
} from "./ebpf-stats-ring";

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

// ─── Config ──────────────────────────────────────────────────────────────────

/**
 * Discover the bpftool binary path at startup.
 * Priority: BPFTOOL_PATH env var → `which bpftool` → common install locations.
 * Returns the first path that exists, or the last fallback (so the error
 * message still shows a useful path rather than "undefined").
 */
export function resolveBpftoolPath(): string {
  if (process.env.BPFTOOL_PATH) return process.env.BPFTOOL_PATH;
  // Try `which bpftool` (works on any distro with bpftool in PATH)
  try {
    const found = execSync("which bpftool 2>/dev/null", { encoding: "utf8" }).trim();
    if (found) return found;
  } catch { /* not in PATH */ }
  // Common install locations across distros
  const candidates = [
    "/usr/sbin/bpftool",
    "/usr/bin/bpftool",
    "/usr/local/sbin/bpftool",
    "/usr/local/bin/bpftool",
    "/sbin/bpftool",
  ];
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  // Return the most common path as a fallback so the error message is helpful
  return "/usr/sbin/bpftool";
}

// ─── Env-var defaults ──────────────────────────────────────────────────────────────────
// Read environment variables at module load time so they are available
// before startPoller() is called. These are the same variables documented
// in .env.example and start.sh.
function resolveDefaultConfig(): PollingConfig {
  const demoMode = process.env.DEMO_MODE === "1" || process.env.DEMO_MODE === "true";
  const bpftoolPath = resolveBpftoolPath();
  const intervalMs = process.env.POLL_INTERVAL_MS
    ? parseInt(process.env.POLL_INTERVAL_MS, 10)
    : 5000;
  return { intervalMs, demoMode, bpftoolPath, sudo: true };
}

const DEFAULT_CONFIG: PollingConfig = resolveDefaultConfig();

// ─── State ─────────────────────────────────────────────────────────────────

let config: PollingConfig = { ...DEFAULT_CONFIG };
let latestSnapshot: EbpfSnapshot | null = null;
let latestMaps: BpfMap[] = [];
let pollingTimer: ReturnType<typeof setInterval> | null = null;
let lastError: string | null = null;
let bpftoolVersion = "unknown";
let bpftoolHasSkeletons: boolean | null = null;
let kernelVersion = "unknown";
let isPolling = false;
let statsEnabled = false;
/** True when *we* flipped kernel.bpf_stats_enabled from 0 to 1, so we can
 *  restore it on shutdown instead of leaving per-invocation overhead on
 *  every BPF program in the system forever. */
let statsEnabledByUs = false;

const listeners = new Set<(snap: EbpfSnapshot) => void>();

// ─── bpf_stats_enabled ─────────────────────────────────────────────────────

async function ensureBpfStatsEnabled(): Promise<void> {
  try {
    const { stdout } = await execAsync("cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null");
    const current = parseInt(stdout.trim(), 10);
    if (current === 1) {
      statsEnabled = true;
      console.log("[ebpf-poller] bpf_stats_enabled is already 1 — run_time_ns will be collected");
      return;
    }
    // Try to enable it
    await execAsync("sudo sysctl -w kernel.bpf_stats_enabled=1 2>/dev/null");
    statsEnabled = true;
    statsEnabledByUs = true;
    console.log("[ebpf-poller] Enabled kernel.bpf_stats_enabled=1 — runtime stats will accumulate (restored on shutdown)");
  } catch {
    statsEnabled = false;
    console.warn("[ebpf-poller] Could not enable bpf_stats_enabled — run_time_ns will be 0");
  }
}

// ─── System info ───────────────────────────────────────────────────────────

/**
 * Parse `bpftool version` output. `hasSkeletons` is null when the build is
 * too old to print a features line at all (pre-v5.19), so we can't tell.
 * A build without the "skeletons" feature silently omits the `pids` field
 * from all prog/map listings — every program then looks ownerless/orphaned.
 */
export function parseBpftoolVersion(stdout: string): {
  version: string;
  hasSkeletons: boolean | null;
} {
  const lines = stdout.trim().split("\n");
  const featuresLine = lines.find(line => line.trim().startsWith("features:"));
  return {
    version: lines[0] ?? "unknown",
    hasSkeletons: featuresLine ? /\bskeletons\b/.test(featuresLine) : null,
  };
}

async function getSystemInfo(): Promise<void> {
  try {
    const { stdout: kv } = await execAsync("uname -r");
    kernelVersion = kv.trim();
  } catch { kernelVersion = "unknown"; }

  try {
    const { stdout } = await execFileAsync(config.bpftoolPath, ["version"], { timeout: 5000 });
    const parsed = parseBpftoolVersion(stdout);
    bpftoolVersion = parsed.version;
    bpftoolHasSkeletons = parsed.hasSkeletons;
    if (bpftoolHasSkeletons === false) {
      console.warn(
        `[ebpf-poller] ${config.bpftoolPath} was built without skeleton support ` +
        "(no \"skeletons\" entry in `bpftool version` features) — it cannot report " +
        "process ownership, so the pids field is silently omitted and every program " +
        "will appear orphaned. Ubuntu's linux-tools bpftool is a common culprit; " +
        "build from https://github.com/libbpf/bpftool and point BPFTOOL_PATH at it."
      );
    }
  } catch { bpftoolVersion = "built from source"; }
}

// ─── Run bpftool commands ──────────────────────────────────────────────────

async function runBpftool(args: string): Promise<string> {
  // -f/--bpffs: include bpffs pin paths ("pinned" arrays) in prog/map/link
  // listings — without it bpftool omits the field entirely. Harmless for the
  // other subcommands.
  const argv = ["-j", "-f", ...args.split(/\s+/)];
  const cmd = config.sudo ? "sudo" : config.bpftoolPath;
  const fullArgv = config.sudo ? [config.bpftoolPath, ...argv] : argv;
  // Raise maxBuffer from the Node default (1 MB) to 32 MB.
  // On systems with 200+ BPF programs, bpftool map list / prog list JSON output
  // can easily exceed 1 MB, causing exec() to throw ERR_CHILD_PROCESS_STDIO_MAXBUFFER
  // and silently returning an empty result.
  const { stdout } = await execFileAsync(cmd, fullArgv, { timeout: 10000, maxBuffer: 32 * 1024 * 1024 });
  return stdout.trim();
}

/** Build the command prefix that runs argv inside a discovered namespace. */
function reachCommand(reach: NetnsReach, argv: string[]): { cmd: string; args: string[] } {
  if (reach.via === "docker") {
    // docker talks to its own daemon; no sudo needed with docker-group access.
    return { cmd: "docker", args: ["exec", reach.container, ...argv] };
  }
  const nsenterArgv = [`--net=${reach.nsPath}`, "--", ...argv];
  return config.sudo
    ? { cmd: "sudo", args: ["nsenter", ...nsenterArgv] }
    : { cmd: "nsenter", args: nsenterArgv };
}

/** Run `bpftool net show` inside a namespace. For docker reach, uses whatever
 *  bpftool the container provides (kind nodes often lack a working one — the
 *  caller tolerates an empty result and falls back to ip-link topology). */
async function runBpftoolNetInNetns(reach: NetnsReach): Promise<string> {
  const bpftool = reach.via === "docker" ? "bpftool" : config.bpftoolPath;
  const { cmd, args } = reachCommand(reach, [bpftool, "-j", "net", "show"]);
  const { stdout } = await execFileAsync(cmd, args, {
    timeout: 10000,
    maxBuffer: 32 * 1024 * 1024,
  });
  return stdout.trim();
}

/** Run `ip -d -j link show` inside a namespace for device-pair topology. */
async function runIpLinkInNetns(reach: NetnsReach): Promise<string> {
  const { cmd, args } = reachCommand(reach, ["ip", "-d", "-j", "link", "show"]);
  const { stdout } = await execFileAsync(cmd, args, {
    timeout: 10000,
    maxBuffer: 32 * 1024 * 1024,
  });
  return stdout.trim();
}

/** Normalize `ip -d -j link show` JSON into RawNetnsLink[]. */
function parseIpLinks(stdout: string): RawNetnsLink[] {
  let raw: unknown;
  try {
    raw = JSON.parse(stripNonJson(stdout));
  } catch {
    return [];
  }
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((l): l is Record<string, unknown> => !!l && typeof l === "object")
    .map(l => ({
      ifindex: Number(l.ifindex),
      ifname: String(l.ifname ?? ""),
      link_index: typeof l.link_index === "number" ? l.link_index : undefined,
      link_netnsid:
        typeof l.link_netnsid === "number" ? l.link_netnsid : undefined,
      kind: (l.linkinfo as { info_kind?: string } | undefined)?.info_kind,
      operstate: typeof l.operstate === "string" ? l.operstate : undefined,
    }))
    .filter(l => Number.isFinite(l.ifindex) && l.ifname);
}

/** Does this namespace hold anything worth showing — a netdev BPF attachment,
 *  or a device pair (netkit/veth) that connects it to another namespace? */
function isInterestingNetns(ns: RawNetnsSnapshot): boolean {
  const snapshot = ns.net[0];
  const hasProg =
    !!snapshot &&
    [
      snapshot.xdp,
      snapshot.tc,
      snapshot.tcx,
      snapshot.netkit,
      snapshot.flow_dissector,
      snapshot.netfilter,
    ].some(section => (section?.length ?? 0) > 0);
  const hasPair = (ns.links ?? []).some(
    l => PAIRED_LINK_KINDS.has(netnsLinkKind(l) ?? "") && typeof l.link_index === "number"
  );
  return hasProg || hasPair;
}

/** Namespaces that recently had nothing to show are skipped for a while —
 *  most pods never carry netdev BPF programs, and each scan costs two execs. */
const UNINTERESTING_NETNS_TTL_MS = 60_000;
const uninterestingNetns = new Map<string, number>();

/** Scan all reachable non-root network namespaces for BPF net attachments and
 *  device-pair topology. Per-namespace failures (vanished mid-poll, nsenter
 *  denied, no bpftool in container, non-JSON bpftool output) degrade
 *  gracefully — a namespace with only ip-link topology and no bpftool net
 *  still contributes to the graph. */
async function fetchNetnsData(): Promise<RawNetnsSnapshot[]> {
  const now = Date.now();
  const refs = (await discoverNetNamespaces()).filter(ref => {
    const boringSince = uninterestingNetns.get(ref.id);
    return !(boringSince && now - boringSince < UNINTERESTING_NETNS_TTL_MS);
  });
  const scans = await Promise.allSettled(
    refs.map(async (ref): Promise<RawNetnsSnapshot> => {
      const [netRes, linkRes] = await Promise.allSettled([
        runBpftoolNetInNetns(ref.reach),
        runIpLinkInNetns(ref.reach),
      ]);
      const net =
        netRes.status === "fulfilled"
          ? parseJsonOr<RawNetSnapshot[]>(netRes.value, [])
          : [];
      const links =
        linkRes.status === "fulfilled" ? parseIpLinks(linkRes.value) : [];
      return { id: ref.id, label: ref.label, net, links };
    })
  );
  const snapshots = scans
    .filter(
      (s): s is PromiseFulfilledResult<RawNetnsSnapshot> =>
        s.status === "fulfilled"
    )
    .map(s => s.value);
  for (const ns of snapshots) {
    if (isInterestingNetns(ns)) uninterestingNetns.delete(ns.id);
    else uninterestingNetns.set(ns.id, now);
  }
  // Drop stale suppressions so the map doesn't grow with pod churn.
  for (const [id, t] of Array.from(uninterestingNetns.entries())) {
    if (now - t > UNINTERESTING_NETNS_TTL_MS * 5) uninterestingNetns.delete(id);
  }
  return snapshots.filter(isInterestingNetns);
}

async function runTcFilterShow(
  devname: string,
  direction: RawTcFilterEntry["direction"]
): Promise<RawTcFilterEntry[]> {
  const tcArgs = [
    "-s",
    "-d",
    "-j",
    "filter",
    "show",
    "dev",
    devname,
    direction,
  ];
  const cmd = config.sudo ? "sudo" : "tc";
  const fullArgv = config.sudo ? ["tc", ...tcArgs] : tcArgs;
  const { stdout } = await execFileAsync(cmd, fullArgv, {
    timeout: 5000,
    maxBuffer: 16 * 1024 * 1024,
  });
  const parsed = JSON.parse(stripNonJson(stdout));
  if (!Array.isArray(parsed)) return [];

  return parsed
    .filter(item => item && typeof item === "object")
    .map((item, order) => ({
      ...(item as Record<string, unknown>),
      devname,
      direction,
      order,
    })) as RawTcFilterEntry[];
}

/** Parse bpftool/tc JSON output, tolerating warning noise and non-JSON
 *  stdout — callers get the fallback instead of a throw. */
function parseJsonOr<T>(raw: string, fallback: T): T {
  try {
    return JSON.parse(stripNonJson(raw)) as T;
  } catch {
    return fallback;
  }
}

// Strip libbpf warning lines that pollute JSON output
function stripNonJson(raw: string): string {
  return raw
    .split("\n")
    .filter(line => !line.startsWith("libbpf:"))
    .join("\n")
    .trim();
}

async function fetchLiveData(): Promise<{
  progs: RawBpfProg[];
  net: RawNetSnapshot[];
  cgroups: RawCgroupEntry[];
  cgroupsEffective: RawCgroupEntry[];
  rawMaps: RawBpfMap[];
  links: RawBpfLink[];
  netns: RawNetnsSnapshot[];
}> {
  const [
    progOut,
    netOut,
    cgroupOut,
    cgroupEffectiveOut,
    mapOut,
    linkOut,
    netnsOut,
  ] = await Promise.allSettled([
    runBpftool("prog list"),
    runBpftool("net"),
    runBpftool("cgroup tree"),
    runBpftool("cgroup tree /sys/fs/cgroup effective"),
    runBpftool("map list"),
    runBpftool("link list"),
    fetchNetnsData(),
  ]);

  let progs: RawBpfProg[] = [];
  let net: RawNetSnapshot[] = [];
  let cgroups: RawCgroupEntry[] = [];
  let cgroupsEffective: RawCgroupEntry[] = [];
  let rawMaps: RawBpfMap[] = [];
  let links: RawBpfLink[] = [];
  const netns: RawNetnsSnapshot[] =
    netnsOut.status === "fulfilled" ? netnsOut.value : [];

  if (progOut.status === "fulfilled") progs = parseJsonOr(progOut.value, []);
  if (netOut.status === "fulfilled") net = parseJsonOr(netOut.value, []);
  if (cgroupOut.status === "fulfilled") cgroups = parseJsonOr(cgroupOut.value, []);
  if (cgroupEffectiveOut.status === "fulfilled") {
    cgroupsEffective = parseJsonOr(cgroupEffectiveOut.value, []);
  }
  if (mapOut.status === "fulfilled") rawMaps = parseJsonOr(mapOut.value, []);
  if (linkOut.status === "fulfilled") links = parseJsonOr(linkOut.value, []);

  const netSnapshot = net[0];
  const tcDevices = new Map<string, number>();
  for (const entry of netSnapshot?.tc ?? []) {
    tcDevices.set(entry.devname, entry.ifindex);
  }
  if (netSnapshot && tcDevices.size > 0) {
    const filterResults = await Promise.allSettled(
      Array.from(tcDevices.keys()).flatMap(devname =>
        (["ingress", "egress"] as const).map(direction =>
          runTcFilterShow(devname, direction)
        )
      )
    );
    const tcFilters = filterResults.flatMap(result =>
      result.status === "fulfilled" ? result.value : []
    );
    if (tcFilters.length > 0) {
      for (const filter of tcFilters) {
        filter.ifindex = tcDevices.get(filter.devname);
      }
      net = [{ ...netSnapshot, tcFilters }, ...net.slice(1)];
    }
  }

  return { progs, net, cgroups, cgroupsEffective, rawMaps, links, netns };
}

// ─── Poll ──────────────────────────────────────────────────────────────────

async function poll(): Promise<void> {
  if (isPolling) return;
  isPolling = true;

  const pollStart = Date.now();
  try {
    let progs: RawBpfProg[];
    let net: RawNetSnapshot[];
    let cgroups: RawCgroupEntry[];
    let cgroupsEffective: RawCgroupEntry[] = [];

    let rawMaps: RawBpfMap[] = [];
    let links: RawBpfLink[] = [];
    let netns: RawNetnsSnapshot[] = [];

    if (config.demoMode) {
      // Simulate incrementing stats in demo mode so sparklines are always active
      const now = Date.now();
      progs = MOCK_PROGS.map(p => ({
        ...p,
        run_cnt: (p.run_cnt ?? 0) + Math.floor(Math.random() * 200 + 10),
        run_time_ns: (p.run_time_ns ?? 0) + Math.floor(Math.random() * 5_000_000 + 50_000),
      }));
      net = MOCK_NET;
      cgroups = MOCK_CGROUPS;
      cgroupsEffective = [];
      links = MOCK_LINKS;
      netns = MOCK_NETNS;
      void now; // used implicitly via Date.now() in ingestSnapshot
    } else {
      const data = await fetchLiveData();
      progs = data.progs;
      net = data.net;
      cgroups = data.cgroups;
      cgroupsEffective = data.cgroupsEffective;
      rawMaps = data.rawMaps;
      links = data.links;
      netns = data.netns;
    }

    const snap = buildSnapshot(
      progs,
      net,
      cgroups,
      {
        hostname: hostname(),
        kernelVersion,
        bpftoolVersion,
        demoMode: config.demoMode,
      },
      cgroupsEffective,
      links,
      netns
    );

    // ── Parse maps ─────────────────────────────────────────────────────────
    if (config.demoMode) {
      latestMaps = buildMockMaps(snap.programs);
    } else {
      latestMaps = parseMaps(rawMaps, snap.programs);
    }

    // ── Feed the stats ring buffer ──────────────────────────────────────────
    ingestSnapshot(snap.programs, snap.timestamp);
    pruneStale(new Set(snap.programs.map(p => p.id)));

    latestSnapshot = snap;
    lastError = null;

    const elapsed = Date.now() - pollStart;
    if (elapsed > 2000 || !latestSnapshot) {
      console.log(`[ebpf-poller] poll completed in ${elapsed}ms — ${snap.stats.total} programs, ${latestMaps.length} maps`);
    }

    for (const cb of Array.from(listeners)) {
      try { cb(snap); } catch { /* ignore listener errors */ }
    }
  } catch (err) {
    lastError = err instanceof Error ? err.message : String(err);
    console.error("[ebpf-poller] poll error:", lastError);
    // Keep serving the last good snapshot and surface the error via poller
    // status. Swapping in mock data here (as this used to do) presented
    // synthetic programs as live while config.demoMode stayed false, routed
    // prog/map drill-downs at nonexistent kernel IDs, and mixed mock samples
    // into the real stats rings. Demo mode is only entered explicitly, via
    // DEMO_MODE or the startup bpftool availability check.
  } finally {
    isPolling = false;
  }
}

// ─── Public API ────────────────────────────────────────────────────────────

export async function startPoller(): Promise<void> {
  // Run system info discovery and bpftool checks in background so the
  // HTTP server can start accepting connections immediately.  SSE clients
  // receive a "ping" until the first snapshot is ready, then get the full
  // data bundle automatically via the subscriber callback.

  // Log if demo mode was requested via env var
  if (config.demoMode) {
    console.log("[ebpf-poller] Demo mode enabled via DEMO_MODE env var — using synthetic data");
    statsEnabled = true;
  } else {
    // Check if bpftool is actually available (runs in background)
    try {
      await getSystemInfo();
      await runBpftool("version");
      // Only try to enable stats when we have a real bpftool
      await ensureBpfStatsEnabled();
    } catch {
      console.warn("[ebpf-poller] bpftool not accessible, enabling demo mode");
      config.demoMode = true;
      statsEnabled = true; // demo mode always has stats
    }
  }

  // First poll runs in background — don't block server startup
  poll().catch(err => {
    console.error("[ebpf-poller] first poll failed:", err);
  });

  if (pollingTimer) clearInterval(pollingTimer);
  pollingTimer = setInterval(poll, config.intervalMs);
}

export function stopPoller(): void {
  if (pollingTimer) {
    clearInterval(pollingTimer);
    pollingTimer = null;
  }
}

/**
 * Undo kernel settings this process changed. Currently: disable
 * kernel.bpf_stats_enabled if we were the ones who enabled it (it adds
 * measurable per-invocation overhead to every BPF program on the host).
 */
export async function restoreKernelSettings(): Promise<void> {
  if (!statsEnabledByUs) return;
  statsEnabledByUs = false;
  try {
    await execAsync("sudo sysctl -w kernel.bpf_stats_enabled=0 2>/dev/null");
    console.log("[ebpf-poller] Restored kernel.bpf_stats_enabled=0");
  } catch {
    console.error("[ebpf-poller] Failed to restore kernel.bpf_stats_enabled — check it manually");
  }
}

export function getLatestSnapshot(): EbpfSnapshot | null {
  return latestSnapshot;
}

export function getLatestMaps(): BpfMap[] {
  return latestMaps;
}

export function isStatsEnabled(): boolean {
  return statsEnabled;
}

export function getPollerStatus(): {
  running: boolean;
  config: PollingConfig;
  lastError: string | null;
  lastPollTime: number | null;
  statsEnabled: boolean;
  /** false = bpftool build cannot report pids (all programs look orphaned);
   *  null = unknown (demo mode, or bpftool too old to list features). */
  bpftoolHasSkeletons: boolean | null;
} {
  return {
    running: pollingTimer !== null,
    config,
    lastError,
    lastPollTime: latestSnapshot?.timestamp ?? null,
    statsEnabled,
    bpftoolHasSkeletons,
  };
}

export function updateConfig(updates: Partial<PollingConfig>): void {
  config = { ...config, ...updates };

  // Restart interval if changed
  if (updates.intervalMs !== undefined && pollingTimer) {
    clearInterval(pollingTimer);
    pollingTimer = setInterval(poll, config.intervalMs);
  }

  // Immediate poll on config change
  poll();
}

export function subscribe(
  cb: (snap: EbpfSnapshot) => void,
  options: { immediate?: boolean } = {}
): () => void {
  listeners.add(cb);
  // Immediately deliver latest if available
  if (options.immediate !== false && latestSnapshot) cb(latestSnapshot);
  return () => listeners.delete(cb);
}

export function triggerPoll(): Promise<void> {
  return poll();
}

// Re-export ring buffer accessors for use in routers
export { getAllHistories, getHistory, buildActivitySummary };

/** Returns true when the poller is running in demo mode (DEMO_MODE env var or auto-fallback). */
export function isDemoMode(): boolean {
  return config.demoMode;
}

export function getBpftoolPath(): string {
  return config.bpftoolPath;
}

export function isSudoEnabled(): boolean {
  return config.sudo;
}

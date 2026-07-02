import { exec, execFile, execSync } from "child_process";
import { existsSync } from "fs";
import { promisify } from "util";
import { hostname } from "os";
import type {
  BpfMap,
  EbpfSnapshot,
  PollingConfig,
  RawBpfMap,
  RawBpfProg,
  RawCgroupEntry,
  RawNetSnapshot,
  RawTcFilterEntry,
} from "../shared/ebpf-types";
import { buildSnapshot } from "./ebpf-parser";
import { buildMockMaps, parseMaps } from "./ebpf-map-parser";
import { MOCK_CGROUPS, MOCK_NET, MOCK_PROGS } from "./ebpf-mock";
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
    console.log("[ebpf-poller] Enabled kernel.bpf_stats_enabled=1 — runtime stats will accumulate");
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
  const argv = ["-j", ...args.split(/\s+/)];
  const cmd = config.sudo ? "sudo" : config.bpftoolPath;
  const fullArgv = config.sudo ? [config.bpftoolPath, ...argv] : argv;
  // Raise maxBuffer from the Node default (1 MB) to 32 MB.
  // On systems with 200+ BPF programs, bpftool map list / prog list JSON output
  // can easily exceed 1 MB, causing exec() to throw ERR_CHILD_PROCESS_STDIO_MAXBUFFER
  // and silently returning an empty result.
  const { stdout } = await execFileAsync(cmd, fullArgv, { timeout: 10000, maxBuffer: 32 * 1024 * 1024 });
  return stdout.trim();
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
}> {
  const [
    progOut,
    netOut,
    cgroupOut,
    cgroupEffectiveOut,
    mapOut,
  ] = await Promise.allSettled([
    runBpftool("prog list"),
    runBpftool("net"),
    runBpftool("cgroup tree"),
    runBpftool("cgroup tree /sys/fs/cgroup effective"),
    runBpftool("map list"),
  ]);

  let progs: RawBpfProg[] = [];
  let net: RawNetSnapshot[] = [];
  let cgroups: RawCgroupEntry[] = [];
  let cgroupsEffective: RawCgroupEntry[] = [];
  let rawMaps: RawBpfMap[] = [];

  if (progOut.status === "fulfilled") {
    try { progs = JSON.parse(stripNonJson(progOut.value)); } catch { progs = []; }
  }
  if (netOut.status === "fulfilled") {
    try { net = JSON.parse(stripNonJson(netOut.value)); } catch { net = []; }
  }
  if (cgroupOut.status === "fulfilled") {
    try { cgroups = JSON.parse(stripNonJson(cgroupOut.value)); } catch { cgroups = []; }
  }
  if (cgroupEffectiveOut.status === "fulfilled") {
    try { cgroupsEffective = JSON.parse(stripNonJson(cgroupEffectiveOut.value)); } catch { cgroupsEffective = []; }
  }
  if (mapOut.status === "fulfilled") {
    try { rawMaps = JSON.parse(stripNonJson(mapOut.value)); } catch { rawMaps = []; }
  }

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

  return { progs, net, cgroups, cgroupsEffective, rawMaps };
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
      void now; // used implicitly via Date.now() in ingestSnapshot
    } else {
      const data = await fetchLiveData();
      progs = data.progs;
      net = data.net;
      cgroups = data.cgroups;
      cgroupsEffective = data.cgroupsEffective;
      rawMaps = data.rawMaps;
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
      cgroupsEffective
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

    // Fall back to demo mode on error
    if (!config.demoMode) {
      console.warn("[ebpf-poller] Falling back to demo mode due to error");
      const snap = buildSnapshot(MOCK_PROGS, MOCK_NET, MOCK_CGROUPS, {
        hostname: hostname(),
        kernelVersion,
        bpftoolVersion: "demo",
        demoMode: true,
      });
      latestMaps = buildMockMaps(snap.programs);
      ingestSnapshot(snap.programs, snap.timestamp);
      latestSnapshot = snap;
      for (const cb of Array.from(listeners)) {
        try { cb(snap); } catch { /* ignore */ }
      }
    }
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

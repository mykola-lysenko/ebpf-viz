import { exec } from "child_process";
import { promisify } from "util";
import { hostname } from "os";
import type { BpfMap, EbpfSnapshot, PollingConfig, RawBpfMap, RawBpfProg, RawCgroupEntry, RawNetSnapshot } from "../shared/ebpf-types";
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

// ─── Config ────────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: PollingConfig = {
  intervalMs: 5000,
  demoMode: false,
  bpftoolPath: "/usr/local/bin/bpftool",
  sudo: true,
};

// ─── State ─────────────────────────────────────────────────────────────────

let config: PollingConfig = { ...DEFAULT_CONFIG };
let latestSnapshot: EbpfSnapshot | null = null;
let latestMaps: BpfMap[] = [];
let pollingTimer: ReturnType<typeof setInterval> | null = null;
let lastError: string | null = null;
let bpftoolVersion = "unknown";
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

async function getSystemInfo(): Promise<void> {
  try {
    const { stdout: kv } = await execAsync("uname -r");
    kernelVersion = kv.trim();
  } catch { kernelVersion = "unknown"; }

  try {
    const cmd = `${config.bpftoolPath} version 2>/dev/null | head -1`;
    const { stdout } = await execAsync(cmd);
    bpftoolVersion = stdout.trim();
  } catch { bpftoolVersion = "built from source"; }
}

// ─── Run bpftool commands ──────────────────────────────────────────────────

async function runBpftool(args: string): Promise<string> {
  const prefix = config.sudo ? "sudo " : "";
  const cmd = `${prefix}${config.bpftoolPath} -j ${args} 2>/dev/null`;
  const { stdout } = await execAsync(cmd, { timeout: 10000 });
  return stdout.trim();
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
  rawMaps: RawBpfMap[];
}> {
  const [progOut, netOut, cgroupOut, mapOut] = await Promise.allSettled([
    runBpftool("prog list"),
    runBpftool("net"),
    runBpftool("cgroup tree"),
    runBpftool("map list"),
  ]);

  let progs: RawBpfProg[] = [];
  let net: RawNetSnapshot[] = [];
  let cgroups: RawCgroupEntry[] = [];
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
  if (mapOut.status === "fulfilled") {
    try { rawMaps = JSON.parse(stripNonJson(mapOut.value)); } catch { rawMaps = []; }
  }

  return { progs, net, cgroups, rawMaps };
}

// ─── Poll ──────────────────────────────────────────────────────────────────

async function poll(): Promise<void> {
  if (isPolling) return;
  isPolling = true;

  try {
    let progs: RawBpfProg[];
    let net: RawNetSnapshot[];
    let cgroups: RawCgroupEntry[];

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
      void now; // used implicitly via Date.now() in ingestSnapshot
    } else {
      const data = await fetchLiveData();
      progs = data.progs;
      net = data.net;
      cgroups = data.cgroups;
      rawMaps = data.rawMaps;
    }

    const snap = buildSnapshot(progs, net, cgroups, {
      hostname: hostname(),
      kernelVersion,
      bpftoolVersion,
      demoMode: config.demoMode,
    });

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
  await getSystemInfo();

  // Check if bpftool is actually available
  try {
    await runBpftool("version");
    // Only try to enable stats when we have a real bpftool
    await ensureBpfStatsEnabled();
  } catch {
    console.warn("[ebpf-poller] bpftool not accessible, enabling demo mode");
    config.demoMode = true;
    statsEnabled = true; // demo mode always has stats
  }

  await poll(); // immediate first poll

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
} {
  return {
    running: pollingTimer !== null,
    config,
    lastError,
    lastPollTime: latestSnapshot?.timestamp ?? null,
    statsEnabled,
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

export function subscribe(cb: (snap: EbpfSnapshot) => void): () => void {
  listeners.add(cb);
  // Immediately deliver latest if available
  if (latestSnapshot) cb(latestSnapshot);
  return () => listeners.delete(cb);
}

export function triggerPoll(): Promise<void> {
  return poll();
}

// Re-export ring buffer accessors for use in routers
export { getAllHistories, getHistory, buildActivitySummary };

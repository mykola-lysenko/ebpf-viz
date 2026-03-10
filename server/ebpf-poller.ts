import { exec } from "child_process";
import { promisify } from "util";
import { hostname } from "os";
import type { EbpfSnapshot, PollingConfig, RawBpfProg, RawCgroupEntry, RawNetSnapshot } from "../shared/ebpf-types";
import { buildSnapshot } from "./ebpf-parser";
import { MOCK_CGROUPS, MOCK_NET, MOCK_PROGS } from "./ebpf-mock";

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
let pollingTimer: ReturnType<typeof setInterval> | null = null;
let lastError: string | null = null;
let bpftoolVersion = "unknown";
let kernelVersion = "unknown";
let isPolling = false;

const listeners = new Set<(snap: EbpfSnapshot) => void>();

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
}> {
  const [progOut, netOut, cgroupOut] = await Promise.allSettled([
    runBpftool("prog list"),
    runBpftool("net"),
    runBpftool("cgroup tree"),
  ]);

  let progs: RawBpfProg[] = [];
  let net: RawNetSnapshot[] = [];
  let cgroups: RawCgroupEntry[] = [];

  if (progOut.status === "fulfilled") {
    try { progs = JSON.parse(stripNonJson(progOut.value)); } catch { progs = []; }
  }
  if (netOut.status === "fulfilled") {
    try { net = JSON.parse(stripNonJson(netOut.value)); } catch { net = []; }
  }
  if (cgroupOut.status === "fulfilled") {
    try { cgroups = JSON.parse(stripNonJson(cgroupOut.value)); } catch { cgroups = []; }
  }

  return { progs, net, cgroups };
}

// ─── Poll ──────────────────────────────────────────────────────────────────

async function poll(): Promise<void> {
  if (isPolling) return;
  isPolling = true;

  try {
    let progs: RawBpfProg[];
    let net: RawNetSnapshot[];
    let cgroups: RawCgroupEntry[];

    if (config.demoMode) {
      // Add slight variation to mock data to simulate live updates
      progs = MOCK_PROGS.map(p => ({
        ...p,
        run_cnt: p.run_cnt !== undefined ? p.run_cnt + Math.floor(Math.random() * 50) : undefined,
        run_time_ns: p.run_time_ns !== undefined ? p.run_time_ns + Math.floor(Math.random() * 1000000) : undefined,
      }));
      net = MOCK_NET;
      cgroups = MOCK_CGROUPS;
    } else {
      const data = await fetchLiveData();
      progs = data.progs;
      net = data.net;
      cgroups = data.cgroups;
    }

    const snap = buildSnapshot(progs, net, cgroups, {
      hostname: hostname(),
      kernelVersion,
      bpftoolVersion,
      demoMode: config.demoMode,
    });

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
  } catch {
    console.warn("[ebpf-poller] bpftool not accessible, enabling demo mode");
    config.demoMode = true;
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

export function getPollerStatus(): {
  running: boolean;
  config: PollingConfig;
  lastError: string | null;
  lastPollTime: number | null;
} {
  return {
    running: pollingTimer !== null,
    config,
    lastError,
    lastPollTime: latestSnapshot?.timestamp ?? null,
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

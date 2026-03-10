/**
 * ebpf-stats-ring.ts
 *
 * Maintains a fixed-size ring buffer of ProgSample snapshots for every
 * BPF program seen by the poller.  After each poll the caller pushes a new
 * snapshot; the ring automatically evicts the oldest entry once it reaches
 * RING_SIZE entries.
 *
 * Derived rates (calls/sec, avg latency, CPU fraction) are computed lazily
 * from the last two samples whenever getHistory() is called.
 */

import type {
  ProgSample,
  ProgRates,
  ProgHistory,
  ActivitySummary,
  BpfProgram,
} from "../shared/ebpf-types";

export const RING_SIZE = 60; // keep 60 samples ≈ 5 min at 5 s interval

// ─── Internal ring storage ────────────────────────────────────────────────────

interface RingEntry {
  samples: ProgSample[];
  head: number; // index of the next write slot (circular)
  count: number; // number of valid entries (≤ RING_SIZE)
}

const rings = new Map<number, RingEntry>();

function getOrCreate(id: number): RingEntry {
  let ring = rings.get(id);
  if (!ring) {
    ring = { samples: new Array(RING_SIZE), head: 0, count: 0 };
    rings.set(id, ring);
  }
  return ring;
}

/** Push a new sample for a program.  O(1). */
export function pushSample(id: number, sample: ProgSample): void {
  const ring = getOrCreate(id);
  ring.samples[ring.head] = sample;
  ring.head = (ring.head + 1) % RING_SIZE;
  if (ring.count < RING_SIZE) ring.count++;
}

/** Read all valid samples in chronological order.  O(n). */
function readSamples(ring: RingEntry): ProgSample[] {
  if (ring.count === 0) return [];
  if (ring.count < RING_SIZE) {
    // Buffer not yet full — samples are stored linearly from index 0
    return ring.samples.slice(0, ring.count);
  }
  // Buffer is full — oldest sample is at ring.head
  const tail = ring.samples.slice(ring.head);
  const head = ring.samples.slice(0, ring.head);
  return [...tail, ...head];
}

// ─── Rate computation ─────────────────────────────────────────────────────────

function computeRates(prev: ProgSample, curr: ProgSample): ProgRates {
  const dtMs = curr.ts - prev.ts;
  if (dtMs <= 0) {
    return { callsPerSec: 0, avgLatencyNs: 0, cpuFraction: 0, recursionRate: 0 };
  }
  const dtSec = dtMs / 1000;
  const dtNs = dtMs * 1_000_000;

  const deltaCnt = Math.max(0, curr.runCnt - prev.runCnt);
  const deltaTime = Math.max(0, curr.runTimeNs - prev.runTimeNs);
  const deltaMisses = Math.max(0, curr.recursionMisses - prev.recursionMisses);

  const callsPerSec = deltaCnt / dtSec;
  const avgLatencyNs = deltaCnt > 0 ? deltaTime / deltaCnt : 0;
  const cpuFraction = Math.min(1, deltaTime / dtNs);
  const recursionRate = deltaCnt > 0 ? deltaMisses / deltaCnt : 0;

  return { callsPerSec, avgLatencyNs, cpuFraction, recursionRate };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/** Get the full history for a single program. */
export function getHistory(id: number): ProgHistory | null {
  const ring = rings.get(id);
  if (!ring || ring.count === 0) return null;

  const samples = readSamples(ring);
  let latest: ProgRates | null = null;
  let peakCallsPerSec = 0;
  let peakAvgLatencyNs = 0;

  // Compute rates for each consecutive pair to find peaks
  for (let i = 1; i < samples.length; i++) {
    const rates = computeRates(samples[i - 1], samples[i]);
    if (i === samples.length - 1) latest = rates;
    if (rates.callsPerSec > peakCallsPerSec) peakCallsPerSec = rates.callsPerSec;
    if (rates.avgLatencyNs > peakAvgLatencyNs) peakAvgLatencyNs = rates.avgLatencyNs;
  }

  return { id, samples, latest, peakCallsPerSec, peakAvgLatencyNs };
}

/** Get histories for a list of program IDs (skips programs with no data). */
export function getHistories(ids: number[]): ProgHistory[] {
  return ids.map(id => getHistory(id)).filter((h): h is ProgHistory => h !== null);
}

/** Get all histories (for all programs seen so far). */
export function getAllHistories(): ProgHistory[] {
  return Array.from(rings.keys())
    .map(id => getHistory(id))
    .filter((h): h is ProgHistory => h !== null);
}

/**
 * Ingest a full bpftool snapshot.  For each program that has run_time_ns
 * data, push a new sample.  Programs without stats (run_time_ns === undefined)
 * still get a zero-sample so the timeline stays gapless.
 */
export function ingestSnapshot(
  programs: BpfProgram[],
  ts: number = Date.now()
): void {
  for (const prog of programs) {
    const sample: ProgSample = {
      ts,
      runCnt: prog.runCnt ?? 0,
      runTimeNs: prog.runTimeNs ?? 0,
      recursionMisses: 0, // not yet in BpfProgram model; will be 0
    };
    pushSample(prog.id, sample);
  }
}

/**
 * Build an ActivitySummary from the latest rates of all programs.
 * `statsEnabled` should be passed from the poller.
 */
export function buildActivitySummary(
  programs: BpfProgram[],
  statsEnabled: boolean
): ActivitySummary {
  const entries: ActivitySummary["topByCallsPerSec"] = [];
  let totalCallsPerSec = 0;
  let totalCpuFraction = 0;

  for (const prog of programs) {
    const hist = getHistory(prog.id);
    if (!hist?.latest) continue;
    const { callsPerSec, avgLatencyNs, cpuFraction } = hist.latest;
    if (callsPerSec > 0 || avgLatencyNs > 0) {
      entries.push({
        id: prog.id,
        name: prog.name,
        rawType: prog.rawType,
        callsPerSec,
        avgLatencyNs,
      });
    }
    totalCallsPerSec += callsPerSec;
    totalCpuFraction += cpuFraction;
  }

  entries.sort((a, b) => b.callsPerSec - a.callsPerSec);

  return {
    topByCallsPerSec: entries.slice(0, 10),
    totalCallsPerSec,
    totalCpuFraction: Math.min(1, totalCpuFraction),
    statsEnabled,
  };
}

/** Remove stale program IDs that are no longer in the current snapshot. */
export function pruneStale(currentIds: Set<number>): void {
  for (const id of Array.from(rings.keys())) {
    if (!currentIds.has(id)) rings.delete(id);
  }
}

/** Clear all ring data (used in tests). */
export function clearAll(): void {
  rings.clear();
}

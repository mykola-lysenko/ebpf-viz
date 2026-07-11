// Per-interval rate derivation from cumulative ProgSamples. Shared so the
// server ring buffer and the client's time-scrubbing derive identical numbers.

import type { ProgSample, ProgRates, ProgHistory } from "./ebpf-types";

const ZERO_RATES: ProgRates = {
  callsPerSec: 0,
  avgLatencyNs: 0,
  cpuFraction: 0,
  recursionRate: 0,
};

/** Rates over the interval between two consecutive cumulative samples. */
export function computeProgRates(prev: ProgSample, curr: ProgSample): ProgRates {
  const dtMs = curr.ts - prev.ts;
  if (dtMs <= 0) return { ...ZERO_RATES };

  const dtSec = dtMs / 1000;
  const dtNs = dtMs * 1_000_000;
  const deltaCnt = Math.max(0, curr.runCnt - prev.runCnt);
  const deltaTime = Math.max(0, curr.runTimeNs - prev.runTimeNs);
  const deltaMisses = Math.max(0, curr.recursionMisses - prev.recursionMisses);

  return {
    callsPerSec: deltaCnt / dtSec,
    avgLatencyNs: deltaCnt > 0 ? deltaTime / deltaCnt : 0,
    cpuFraction: Math.min(1, deltaTime / dtNs),
    recursionRate: deltaCnt > 0 ? deltaMisses / deltaCnt : 0,
  };
}

/**
 * Rates at a historical interval, `offset` steps back from the latest.
 * offset 0 = most recent interval (same as history.latest); larger = older.
 * The interval at offset k is derived from samples[n-1-k] and samples[n-2-k].
 * Returns the interval's end timestamp and rates, or null when there is not
 * enough history that far back.
 */
export function progRatesAtOffset(
  history: ProgHistory | null | undefined,
  offset: number
): { ts: number; rates: ProgRates } | null {
  const samples = history?.samples;
  if (!samples || samples.length < 2) return null;
  const currIdx = samples.length - 1 - offset;
  if (currIdx < 1) return null;
  return {
    ts: samples[currIdx].ts,
    rates: computeProgRates(samples[currIdx - 1], samples[currIdx]),
  };
}

/** Number of scrubbable intervals in a ring (0 when there's no derivable rate). */
export function ringIntervalCount(history: ProgHistory | null | undefined): number {
  const n = history?.samples?.length ?? 0;
  return Math.max(0, n - 1);
}

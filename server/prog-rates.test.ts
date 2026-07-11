import { describe, expect, it } from "vitest";
import {
  computeProgRates,
  progRatesAtOffset,
  ringIntervalCount,
} from "../shared/prog-rates";
import type { ProgHistory, ProgSample } from "../shared/ebpf-types";

const sample = (ts: number, runCnt: number, runTimeNs: number): ProgSample => ({
  ts,
  runCnt,
  runTimeNs,
  recursionMisses: 0,
});

describe("computeProgRates", () => {
  it("derives calls/sec, latency and cpu over an interval", () => {
    const r = computeProgRates(sample(1000, 0, 0), sample(2000, 100, 5_000_000));
    expect(r.callsPerSec).toBe(100); // 100 calls / 1s
    expect(r.avgLatencyNs).toBe(50_000); // 5ms / 100 calls
    expect(r.cpuFraction).toBeCloseTo(0.005); // 5ms of 1000ms
  });

  it("returns zeroes for a non-positive interval", () => {
    expect(computeProgRates(sample(2000, 0, 0), sample(2000, 9, 9))).toEqual({
      callsPerSec: 0,
      avgLatencyNs: 0,
      cpuFraction: 0,
      recursionRate: 0,
    });
  });

  it("clamps counter resets (program reloaded) to zero deltas", () => {
    const r = computeProgRates(sample(1000, 500, 9), sample(2000, 3, 1));
    expect(r.callsPerSec).toBe(0);
  });
});

describe("progRatesAtOffset", () => {
  const history: ProgHistory = {
    id: 1,
    samples: [
      sample(1000, 0, 0),
      sample(2000, 10, 1_000_000), // interval offset 2
      sample(3000, 40, 4_000_000), // interval offset 1
      sample(4000, 45, 4_500_000), // interval offset 0 (latest)
    ],
    latest: null,
    peakCallsPerSec: 0,
    peakAvgLatencyNs: 0,
  };

  it("offset 0 is the most recent interval", () => {
    const at = progRatesAtOffset(history, 0);
    expect(at?.ts).toBe(4000);
    expect(at?.rates.callsPerSec).toBe(5); // 45-40 over 1s
  });

  it("offset steps back through the ring", () => {
    expect(progRatesAtOffset(history, 1)?.rates.callsPerSec).toBe(30); // 40-10
    expect(progRatesAtOffset(history, 2)?.rates.callsPerSec).toBe(10); // 10-0
  });

  it("returns null past the start of the ring", () => {
    expect(progRatesAtOffset(history, 3)).toBeNull();
    expect(progRatesAtOffset({ ...history, samples: [] }, 0)).toBeNull();
    expect(progRatesAtOffset(null, 0)).toBeNull();
  });
});

describe("ringIntervalCount", () => {
  it("is samples-1, floored at 0", () => {
    expect(ringIntervalCount({ samples: [] } as unknown as ProgHistory)).toBe(0);
    expect(ringIntervalCount({ samples: [1, 2, 3] } as unknown as ProgHistory)).toBe(2);
    expect(ringIntervalCount(null)).toBe(0);
  });
});

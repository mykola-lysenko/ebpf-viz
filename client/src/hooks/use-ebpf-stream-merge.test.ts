import { describe, expect, it } from "vitest";
import {
  applyHistoryDeltas,
  applySnapshotMetrics,
  mergeProgramListMetrics,
} from "./useEbpfStream";
import type {
  BpfProgram,
  EbpfSnapshot,
  ProgHistory,
  ProgHistoryDelta,
  SnapshotMetricsUpdate,
} from "../../../shared/ebpf-types";
import { PROG_HISTORY_RING_SIZE } from "../../../shared/ebpf-constants";

function prog(id: number, runCnt = 0): BpfProgram {
  return {
    id, type: "kprobe", rawType: "kprobe", name: `p${id}`, tag: `${id}`.padStart(16, "0"),
    gplCompatible: true, loadedAt: 1, orphaned: false, bytesXlated: 0, jited: true,
    memlock: 0, mapIds: [], attachments: [], osiLayer: "kernel", color: "#fff",
    runCnt, runTimeNs: 0,
  };
}
function snap(programs: BpfProgram[]): EbpfSnapshot {
  return {
    timestamp: 1, hostname: "h", kernelVersion: "6", bpftoolVersion: "7", demoMode: false,
    programs, networkInterfaces: [], cgroupTree: [], kernelZones: [], programChains: [],
    stats: { total: programs.length, byType: {}, jited: programs.length, orphaned: 0 },
  };
}

describe("mergeProgramListMetrics (SSE identity preservation)", () => {
  it("preserves the array and unchanged objects, replacing only changed ones", () => {
    const p1 = prog(1, 10);
    const p2 = prog(2, 20);
    const programs = [p1, p2];
    const metrics = new Map([[2, { id: 2, runCnt: 25 }]]); // only p2 changed

    const next = mergeProgramListMetrics(programs, metrics);
    expect(next).not.toBe(programs); // new array (p2 changed)
    expect(next[0]).toBe(p1); // p1 identity preserved → memoized row won't re-render
    expect(next[1]).not.toBe(p2); // p2 replaced
    expect(next[1].runCnt).toBe(25);
    expect(next[0].runCnt).toBe(10);
  });

  it("returns the SAME array when nothing changed (no wasted re-renders)", () => {
    const programs = [prog(1, 10)];
    const metrics = new Map([[1, { id: 1, runCnt: 10 }]]); // identical
    expect(mergeProgramListMetrics(programs, metrics)).toBe(programs);
  });
});

describe("applySnapshotMetrics", () => {
  it("updates timestamp/stats, merges program metrics, and preserves unchanged topology objects", () => {
    const p1 = prog(1, 10);
    const base = snap([p1]);
    const iface = {
      name: "eth0", ifindex: 2, kind: "nic" as const,
      layers: { L2: [], L3: [], L4: [], L7: [] }, allPrograms: [],
    };
    base.networkInterfaces = [iface];
    const update: SnapshotMetricsUpdate = {
      timestamp: 999,
      stats: { total: 1, byType: { kprobe: 1 }, jited: 1, orphaned: 0 },
      programs: [{ id: 1, runCnt: 50, runTimeNs: 5 }],
    };
    const next = applySnapshotMetrics(base, update)!;
    expect(next.timestamp).toBe(999);
    expect(next.stats.byType).toEqual({ kprobe: 1 });
    expect(next.programs[0].runCnt).toBe(50);
    // the interface has no affected programs → its object identity is kept
    // (memoized interface nodes don't re-render on a metrics-only update)
    expect(next.networkInterfaces[0]).toBe(iface);
  });

  it("returns null passthrough when there is no snapshot yet", () => {
    expect(applySnapshotMetrics(null, { timestamp: 1, stats: snap([]).stats, programs: [] })).toBeNull();
  });
});

describe("applyHistoryDeltas", () => {
  const hist = (id: number, samples: ProgHistory["samples"]): ProgHistory => ({
    id, samples, latest: null, peakCallsPerSec: 0, peakAvgLatencyNs: 0,
  });
  const s = (ts: number, runCnt: number) => ({ ts, runCnt, runTimeNs: 0, recursionMisses: 0 });

  it("appends a new sample for a fresh timestamp", () => {
    const before = [hist(1, [s(1000, 0)])];
    const deltas: ProgHistoryDelta[] = [
      { id: 1, sample: s(2000, 10), latest: null, peakCallsPerSec: 5, peakAvgLatencyNs: 0 },
    ];
    const after = applyHistoryDeltas(before, deltas);
    expect(after[0].samples.map(x => x.ts)).toEqual([1000, 2000]);
    expect(after[0].peakCallsPerSec).toBe(5);
  });

  it("replaces (not appends) the last sample when the timestamp matches", () => {
    const before = [hist(1, [s(1000, 0), s(2000, 10)])];
    const deltas: ProgHistoryDelta[] = [
      { id: 1, sample: s(2000, 99), latest: null, peakCallsPerSec: 0, peakAvgLatencyNs: 0 },
    ];
    const after = applyHistoryDeltas(before, deltas);
    expect(after[0].samples).toHaveLength(2);
    expect(after[0].samples[1].runCnt).toBe(99);
  });

  it("trims the ring to PROG_HISTORY_RING_SIZE", () => {
    const full = Array.from({ length: PROG_HISTORY_RING_SIZE }, (_, i) => s(i, i));
    const before = [hist(1, full)];
    const deltas: ProgHistoryDelta[] = [
      { id: 1, sample: s(9999, 1), latest: null, peakCallsPerSec: 0, peakAvgLatencyNs: 0 },
    ];
    const after = applyHistoryDeltas(before, deltas);
    expect(after[0].samples).toHaveLength(PROG_HISTORY_RING_SIZE);
    expect(after[0].samples[after[0].samples.length - 1].ts).toBe(9999); // newest kept
    expect(after[0].samples[0].ts).toBe(1); // oldest dropped
  });

  it("returns the same array reference when there are no deltas", () => {
    const before = [hist(1, [s(1000, 0)])];
    expect(applyHistoryDeltas(before, [])).toBe(before);
  });
});

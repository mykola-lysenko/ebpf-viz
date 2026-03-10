import { describe, it, expect, beforeEach } from "vitest";
import {
  ingestSnapshot,
  getHistory,
  getAllHistories,
  buildActivitySummary,
  pruneStale,
} from "./ebpf-stats-ring";
import type { BpfProgram } from "../shared/ebpf-types";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeProgram(id: number, runCnt = 0, runTimeNs = 0): BpfProgram {
  return {
    id,
    name: `prog_${id}`,
    rawType: "kprobe",
    type: "kprobe",
    tag: "aabbccdd11223344",
    color: "#f59e0b",
    osiLayer: "L7",
    loadedAt: 1700000000,
    jited: true,
    gplCompatible: true,
    bytesXlated: 256,
    memlock: 4096,
    mapIds: [],
    attachments: [],
    orphaned: false,
    runCnt,
    runTimeNs,
  } satisfies BpfProgram;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("ebpf-stats-ring", () => {
  // Each test gets a fresh module state by re-importing — we use beforeEach to
  // call pruneStale with an empty set to reset the ring buffer between tests.
  beforeEach(() => {
    // Prune all entries by passing an empty set of active IDs
    pruneStale(new Set());
  });

  describe("ingestSnapshot", () => {
    it("creates a history entry on first ingest", () => {
      const prog = makeProgram(1, 100, 500_000);
      ingestSnapshot([prog], 1000);

      const history = getHistory(1);
      expect(history).not.toBeNull();
      expect(history!.id).toBe(1);
      expect(history!.samples).toHaveLength(1);
      expect(history!.samples[0].runCnt).toBe(100);
      expect(history!.samples[0].runTimeNs).toBe(500_000);
    });

    it("accumulates samples over multiple ingests", () => {
      const t0 = 1_000_000;
      ingestSnapshot([makeProgram(1, 0, 0)], t0);
      ingestSnapshot([makeProgram(1, 100, 500_000)], t0 + 5000);
      ingestSnapshot([makeProgram(1, 200, 1_000_000)], t0 + 10000);

      const history = getHistory(1);
      expect(history!.samples).toHaveLength(3);
    });

    it("computes correct calls/sec in latest", () => {
      const t0 = 1_000_000;
      ingestSnapshot([makeProgram(1, 0, 0)], t0);
      // 1000 calls in 5 seconds = 200 calls/sec
      ingestSnapshot([makeProgram(1, 1000, 5_000_000)], t0 + 5000);

      const history = getHistory(1);
      expect(history!.latest).not.toBeNull();
      expect(history!.latest!.callsPerSec).toBeCloseTo(200, 0);
    });

    it("computes correct avg latency in latest", () => {
      const t0 = 1_000_000;
      ingestSnapshot([makeProgram(1, 0, 0)], t0);
      // 1000 calls, 10ms total = 10µs avg
      ingestSnapshot([makeProgram(1, 1000, 10_000_000)], t0 + 5000);

      const history = getHistory(1);
      expect(history!.latest!.avgLatencyNs).toBeCloseTo(10_000, 0);
    });

    it("computes cpu fraction correctly", () => {
      const t0 = 1_000_000;
      ingestSnapshot([makeProgram(1, 0, 0)], t0);
      // 500ms of CPU in 5 seconds = 10% of 1 core
      ingestSnapshot([makeProgram(1, 1000, 500_000_000)], t0 + 5000);

      const history = getHistory(1);
      expect(history!.latest!.cpuFraction).toBeCloseTo(0.1, 3);
    });

    it("handles monotonically non-decreasing counters (no negative rates)", () => {
      const t0 = 1_000_000;
      ingestSnapshot([makeProgram(1, 500, 2_000_000)], t0);
      // Counter went backwards (shouldn't happen but guard against it)
      ingestSnapshot([makeProgram(1, 400, 1_000_000)], t0 + 5000);

      const history = getHistory(1);
      expect(history!.latest!.callsPerSec).toBe(0);
      expect(history!.latest!.avgLatencyNs).toBe(0);
    });

    it("tracks peak calls/sec across samples", () => {
      const t0 = 1_000_000;
      ingestSnapshot([makeProgram(1, 0, 0)], t0);
      ingestSnapshot([makeProgram(1, 1000, 5_000_000)], t0 + 5000);  // 200/s
      ingestSnapshot([makeProgram(1, 3000, 10_000_000)], t0 + 10000); // 400/s
      ingestSnapshot([makeProgram(1, 3500, 15_000_000)], t0 + 15000); // 100/s

      const history = getHistory(1);
      expect(history!.peakCallsPerSec).toBeGreaterThanOrEqual(400);
    });
  });

  describe("getAllHistories", () => {
    it("returns all tracked programs", () => {
      const t0 = 1_000_000;
      ingestSnapshot([makeProgram(1), makeProgram(2), makeProgram(3)], t0);

      const all = getAllHistories();
      expect(all).toHaveLength(3);
      const ids = all.map(h => h.id).sort();
      expect(ids).toEqual([1, 2, 3]);
    });
  });

  describe("pruneStale", () => {
    it("removes programs no longer in the active set", () => {
      const t0 = 1_000_000;
      ingestSnapshot([makeProgram(1), makeProgram(2), makeProgram(3)], t0);

      // Program 2 and 3 were unloaded
      pruneStale(new Set([1]));

      const all = getAllHistories();
      expect(all).toHaveLength(1);
      expect(all[0].id).toBe(1);
    });
  });

  describe("buildActivitySummary", () => {
    it("returns top programs sorted by calls/sec descending", () => {
      const t0 = 1_000_000;
      // Prog 1: 100/s, Prog 2: 500/s, Prog 3: 50/s
      ingestSnapshot([
        makeProgram(1, 0, 0),
        makeProgram(2, 0, 0),
        makeProgram(3, 0, 0),
      ], t0);
      ingestSnapshot([
        makeProgram(1, 500, 1_000_000),   // 100/s
        makeProgram(2, 2500, 5_000_000),  // 500/s
        makeProgram(3, 250, 500_000),     // 50/s
      ], t0 + 5000);

      const programs = [makeProgram(1), makeProgram(2), makeProgram(3)];
      const summary = buildActivitySummary(programs, true);

      expect(summary.topByCallsPerSec[0].id).toBe(2);
      expect(summary.topByCallsPerSec[1].id).toBe(1);
      expect(summary.topByCallsPerSec[2].id).toBe(3);
      expect(summary.totalCallsPerSec).toBeCloseTo(650, 0);
    });

    it("returns statsEnabled=false when stats are disabled", () => {
      const programs = [makeProgram(1)];
      const summary = buildActivitySummary(programs, false);
      expect(summary.statsEnabled).toBe(false);
      expect(summary.topByCallsPerSec).toHaveLength(0);
    });

    it("excludes programs with zero calls/sec from top list", () => {
      const t0 = 1_000_000;
      ingestSnapshot([makeProgram(1, 0, 0), makeProgram(2, 0, 0)], t0);
      ingestSnapshot([makeProgram(1, 0, 0), makeProgram(2, 1000, 5_000_000)], t0 + 5000);

      const programs = [makeProgram(1), makeProgram(2)];
      const summary = buildActivitySummary(programs, true);

      // Only prog 2 should appear (prog 1 has 0 calls/sec)
      expect(summary.topByCallsPerSec.every(e => e.callsPerSec > 0)).toBe(true);
    });
  });
});

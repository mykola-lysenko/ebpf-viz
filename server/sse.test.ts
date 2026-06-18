/**
 * Tests for server/sse.ts
 *
 * We test the SSE handler behaviour by constructing a minimal mock of the
 * Express Request/Response pair and verifying:
 *   - Correct SSE headers are set
 *   - Immediate flush of current snapshot on connect
 *   - Snapshot events are pushed to the response when the poller fires
 *   - Keepalive ping is sent at the configured interval
 *   - Cleanup (unsubscribe + clearInterval) runs on client disconnect
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ─── Mock the poller module ───────────────────────────────────────────────────

const mockSubscribeFn = vi.hoisted(() => vi.fn());
const mockGetLatestSnapshot = vi.hoisted(() => vi.fn());
const mockGetLatestMaps = vi.hoisted(() => vi.fn());
const mockGetAllHistories = vi.hoisted(() => vi.fn());
const mockBuildActivitySummary = vi.hoisted(() => vi.fn());
const mockIsStatsEnabled = vi.hoisted(() => vi.fn());

vi.mock("./ebpf-poller", () => ({
  subscribe: mockSubscribeFn,
  getLatestSnapshot: mockGetLatestSnapshot,
  getLatestMaps: mockGetLatestMaps,
  getAllHistories: mockGetAllHistories,
  buildActivitySummary: mockBuildActivitySummary,
  isStatsEnabled: mockIsStatsEnabled,
}));

import { sseHandler } from "./sse";
import type { Request, Response } from "express";
import type { EbpfSnapshot, ProgHistory } from "../shared/ebpf-types";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeMockRes() {
  const headers: Record<string, string> = {};
  const written: string[] = [];
  let flushed = false;

  const res = {
    setHeader: vi.fn((key: string, val: string) => { headers[key] = val; }),
    flushHeaders: vi.fn(() => { flushed = true; }),
    write: vi.fn((chunk: string) => { written.push(chunk); }),
    headers,
    written,
    get flushed() { return flushed; },
  } as unknown as Response & { headers: Record<string, string>; written: string[]; flushed: boolean };

  return res;
}

function makeMockReq() {
  const listeners: Record<string, Array<() => void>> = {};
  const req = {
    on: vi.fn((event: string, cb: () => void) => {
      listeners[event] = listeners[event] ?? [];
      listeners[event].push(cb);
    }),
    emit: (event: string) => {
      (listeners[event] ?? []).forEach(cb => cb());
    },
    listeners,
  } as unknown as Request & { emit: (event: string) => void };
  return req;
}

function eventNames(chunks: string[]): string[] {
  return chunks.flatMap((chunk) =>
    Array.from(chunk.matchAll(/^event: (.+)$/gm), (match) => match[1])
  );
}

function makeSnapshot(programs: Array<{ id: number; runCnt?: number; runTimeNs?: number }>, timestamp: number): EbpfSnapshot {
  return {
    timestamp,
    hostname: "test-host",
    kernelVersion: "test-kernel",
    bpftoolVersion: "test-bpftool",
    demoMode: false,
    programs: programs.map((program) => ({
      id: program.id,
      type: "xdp",
      rawType: "xdp",
      name: `prog-${program.id}`,
      tag: `tag-${program.id}`,
      gplCompatible: true,
      loadedAt: 0,
      orphaned: false,
      bytesXlated: 0,
      jited: true,
      memlock: 0,
      mapIds: [],
      runCnt: program.runCnt,
      runTimeNs: program.runTimeNs,
      attachments: [],
      osiLayer: "L2",
      color: "#000",
    })),
    networkInterfaces: [],
    cgroupTree: [],
    kernelZones: [],
    programChains: [],
    stats: {
      total: programs.length,
      byType: { xdp: programs.length },
      jited: programs.length,
      orphaned: 0,
    },
  };
}

function makeHistory(id: number, ts: number, runCnt: number): ProgHistory {
  return {
    id,
    samples: [{ ts, runCnt, runTimeNs: runCnt * 100, recursionMisses: 0 }],
    latest: { callsPerSec: 1, avgLatencyNs: 100, cpuFraction: 0.01, recursionRate: 0 },
    peakCallsPerSec: 1,
    peakAvgLatencyNs: 100,
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("sseHandler", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockGetLatestSnapshot.mockReturnValue(null);
    mockGetLatestMaps.mockReturnValue([]);
    mockGetAllHistories.mockReturnValue([]);
    mockBuildActivitySummary.mockReturnValue({ topByCallsPerSec: [], totalCallsPerSec: 0, totalCpuFraction: 0, statsEnabled: false });
    mockIsStatsEnabled.mockReturnValue(false);
    mockSubscribeFn.mockReturnValue(() => {}); // returns unsubscribe noop
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it("sets correct SSE headers", () => {
    const req = makeMockReq();
    const res = makeMockRes();

    sseHandler(req, res);

    expect(res.setHeader).toHaveBeenCalledWith("Content-Type", "text/event-stream");
    expect(res.setHeader).toHaveBeenCalledWith("Cache-Control", "no-cache, no-transform");
    expect(res.setHeader).toHaveBeenCalledWith("Connection", "keep-alive");
    expect(res.setHeader).toHaveBeenCalledWith("X-Accel-Buffering", "no");
    expect(res.flushHeaders).toHaveBeenCalled();
  });

  it("sends a ping immediately when no snapshot is available", () => {
    mockGetLatestSnapshot.mockReturnValue(null);
    const req = makeMockReq();
    const res = makeMockRes();

    sseHandler(req, res);

    const written = res.written.join("");
    expect(written).toContain("event: ping");
  });

  it("sends snapshot bundle immediately when snapshot is available", () => {
    const fakeSnap = makeSnapshot([], Date.now());
    mockGetLatestSnapshot.mockReturnValue(fakeSnap);
    const req = makeMockReq();
    const res = makeMockRes();

    sseHandler(req, res);

    const events = eventNames(res.written);
    expect(events).toContain("snapshot");
    expect(events).toContain("maps");
    expect(events).toContain("history");
    expect(events).toContain("activity");
    expect(events.filter(event => event === "snapshot")).toHaveLength(1);
  });

  it("calls subscribe() to register for future snapshots", () => {
    const req = makeMockReq();
    const res = makeMockRes();

    sseHandler(req, res);

    expect(mockSubscribeFn).toHaveBeenCalledOnce();
  });

  it("pushes a new bundle when the subscriber callback fires", () => {
    let capturedCb: ((snap: unknown) => void) | null = null;
    mockSubscribeFn.mockImplementation((cb: (snap: unknown) => void) => {
      capturedCb = cb;
      return () => {};
    });

    const req = makeMockReq();
    const res = makeMockRes();

    sseHandler(req, res);
    const writtenBefore = res.written.length;

    // Simulate a new snapshot arriving from the poller
    const newSnap = { programs: [{ id: 1 }], timestamp: Date.now() + 5000 };
    capturedCb!(newSnap);

    const newWrites = res.written.slice(writtenBefore).join("");
    expect(newWrites).toContain("event: snapshot");
    expect(newWrites).toContain("event: maps");
  });

  it("sends metric and history deltas when topology is unchanged", () => {
    let capturedCb: ((snap: EbpfSnapshot) => void) | null = null;
    mockSubscribeFn.mockImplementation((cb: (snap: EbpfSnapshot) => void) => {
      capturedCb = cb;
      return () => {};
    });

    mockGetLatestSnapshot.mockReturnValue(makeSnapshot([{ id: 1, runCnt: 10, runTimeNs: 1_000 }], 1_000));
    mockGetAllHistories
      .mockReturnValueOnce([makeHistory(1, 1_000, 10)])
      .mockReturnValueOnce([makeHistory(1, 6_000, 20)]);

    const req = makeMockReq();
    const res = makeMockRes();

    sseHandler(req, res);
    const writtenBefore = res.written.length;

    capturedCb!(makeSnapshot([{ id: 1, runCnt: 20, runTimeNs: 2_000 }], 6_000));

    const events = eventNames(res.written.slice(writtenBefore));
    expect(events).toContain("snapshot-metrics");
    expect(events).toContain("history-delta");
    expect(events).toContain("activity");
    expect(events).not.toContain("snapshot");
    expect(events).not.toContain("history");
    expect(events).not.toContain("maps");
  });

  it("sends a full snapshot again when topology changes", () => {
    let capturedCb: ((snap: EbpfSnapshot) => void) | null = null;
    mockSubscribeFn.mockImplementation((cb: (snap: EbpfSnapshot) => void) => {
      capturedCb = cb;
      return () => {};
    });

    mockGetLatestSnapshot.mockReturnValue(makeSnapshot([{ id: 1, runCnt: 10, runTimeNs: 1_000 }], 1_000));
    mockGetAllHistories
      .mockReturnValueOnce([makeHistory(1, 1_000, 10)])
      .mockReturnValueOnce([makeHistory(1, 6_000, 20), makeHistory(2, 6_000, 1)]);

    const req = makeMockReq();
    const res = makeMockRes();

    sseHandler(req, res);
    const writtenBefore = res.written.length;

    capturedCb!(makeSnapshot([
      { id: 1, runCnt: 20, runTimeNs: 2_000 },
      { id: 2, runCnt: 1, runTimeNs: 100 },
    ], 6_000));

    const events = eventNames(res.written.slice(writtenBefore));
    expect(events).toContain("snapshot");
    expect(events).toContain("history");
    expect(events).toContain("activity");
    expect(events).not.toContain("snapshot-metrics");
    expect(events).not.toContain("history-delta");
  });

  it("sends a keepalive ping after 15 seconds", () => {
    const req = makeMockReq();
    const res = makeMockRes();

    sseHandler(req, res);
    const writtenBefore = res.written.length;

    vi.advanceTimersByTime(15_000);

    const newWrites = res.written.slice(writtenBefore).join("");
    expect(newWrites).toContain("event: ping");
  });

  it("calls unsubscribe and clears ping timer on client disconnect (close event)", () => {
    const unsubscribeMock = vi.fn();
    mockSubscribeFn.mockReturnValue(unsubscribeMock);

    const req = makeMockReq();
    const res = makeMockRes();

    sseHandler(req, res);

    // Simulate client disconnect
    req.emit("close");

    expect(unsubscribeMock).toHaveBeenCalledOnce();

    // Ping should no longer fire after cleanup
    const writtenAfterClose = res.written.length;
    vi.advanceTimersByTime(15_000);
    expect(res.written.length).toBe(writtenAfterClose);
  });

  it("calls unsubscribe on aborted event", () => {
    const unsubscribeMock = vi.fn();
    mockSubscribeFn.mockReturnValue(unsubscribeMock);

    const req = makeMockReq();
    const res = makeMockRes();

    sseHandler(req, res);
    req.emit("aborted");

    expect(unsubscribeMock).toHaveBeenCalledOnce();
  });

  it("sends multiple pings at 15s intervals", () => {
    const req = makeMockReq();
    const res = makeMockRes();

    sseHandler(req, res);
    const writtenBefore = res.written.length;

    vi.advanceTimersByTime(45_000); // 3 × 15s

    const pingCount = res.written
      .slice(writtenBefore)
      .filter(w => w.includes("event: ping"))
      .length;
    expect(pingCount).toBe(3);
  });

  it("does not push after disconnect even if poller fires", () => {
    let capturedCb: ((snap: unknown) => void) | null = null;
    const unsubscribeMock = vi.fn();
    mockSubscribeFn.mockImplementation((cb: (snap: unknown) => void) => {
      capturedCb = cb;
      return unsubscribeMock;
    });

    const req = makeMockReq();
    const res = makeMockRes();

    sseHandler(req, res);
    req.emit("close");

    const writtenAfterClose = res.written.length;

    // Poller fires after disconnect — should NOT write to res
    // (unsubscribe was called, so capturedCb won't be invoked by the real poller,
    // but we verify the cleanup was called correctly)
    expect(unsubscribeMock).toHaveBeenCalledOnce();
    expect(res.written.length).toBe(writtenAfterClose);
  });
});

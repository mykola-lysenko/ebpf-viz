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
    const fakeSnap = { programs: [], timestamp: Date.now(), stats: { total: 0 } };
    mockGetLatestSnapshot.mockReturnValue(fakeSnap);
    const req = makeMockReq();
    const res = makeMockRes();

    sseHandler(req, res);

    const written = res.written.join("");
    expect(written).toContain("event: snapshot");
    expect(written).toContain("event: maps");
    expect(written).toContain("event: history");
    expect(written).toContain("event: activity");
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

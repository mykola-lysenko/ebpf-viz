// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, renderHook } from "@testing-library/react";
import superjson from "superjson";
import { useEbpfStream } from "./useEbpfStream";

// ── Minimal controllable EventSource stand-in ────────────────────────────────
// happy-dom ships no EventSource, and even if it did we need to drive open/
// error/message events deterministically. This mock records every instance so a
// test can grab the live one, dispatch named events, and assert reconnects.
class MockEventSource {
  static instances: MockEventSource[] = [];
  url: string;
  onerror: ((this: MockEventSource, ev: unknown) => void) | null = null;
  private listeners = new Map<string, Set<(ev: MessageEvent) => void>>();
  closed = false;

  constructor(url: string) {
    this.url = url;
    MockEventSource.instances.push(this);
  }
  addEventListener(type: string, cb: (ev: MessageEvent) => void) {
    const set = this.listeners.get(type) ?? new Set();
    set.add(cb);
    this.listeners.set(type, set);
  }
  close() {
    this.closed = true;
  }
  // ── test drivers ──
  emit(type: string, data: unknown) {
    const payload = { data: superjson.stringify(data) } as MessageEvent;
    this.listeners.get(type)?.forEach((cb) => cb(payload));
  }
  fail() {
    this.onerror?.call(this, {});
  }
  static latest() {
    return MockEventSource.instances[MockEventSource.instances.length - 1];
  }
  static reset() {
    MockEventSource.instances = [];
  }
}

const snap = {
  timestamp: 1, hostname: "h", kernelVersion: "6", bpftoolVersion: "7", demoMode: false,
  programs: [], networkInterfaces: [], cgroupTree: [], kernelZones: [], programChains: [],
  stats: { total: 0, byType: {}, jited: 0, orphaned: 0 },
};

beforeEach(() => {
  vi.useFakeTimers();
  MockEventSource.reset();
  vi.stubGlobal("EventSource", MockEventSource as unknown as typeof EventSource);
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  cleanup();
});

describe("useEbpfStream reconnect / back-off", () => {
  it("starts connecting and flips to live on the first snapshot", () => {
    const { result } = renderHook(() => useEbpfStream());
    expect(result.current.status).toBe("connecting");

    act(() => MockEventSource.latest().emit("snapshot", snap));
    expect(result.current.status).toBe("live");
    expect(result.current.snapshot?.hostname).toBe("h");
  });

  it("reconnects with exponential back-off after an error, and resets on success", () => {
    const { result } = renderHook(() => useEbpfStream());
    const es1 = MockEventSource.latest();
    act(() => es1.emit("snapshot", snap)); // live, backoff at initial (1s)

    // First failure → reconnecting, schedules a retry after 1s.
    act(() => es1.fail());
    expect(result.current.status).toBe("reconnecting");
    expect(es1.closed).toBe(true);
    expect(MockEventSource.instances).toHaveLength(1); // not yet reconnected

    act(() => vi.advanceTimersByTime(1_000));
    expect(MockEventSource.instances).toHaveLength(2); // reconnected

    // Second failure without a successful event → back-off doubled to 2s.
    const es2 = MockEventSource.latest();
    act(() => es2.fail());
    act(() => vi.advanceTimersByTime(1_000));
    expect(MockEventSource.instances).toHaveLength(2); // 1s is not enough now
    act(() => vi.advanceTimersByTime(1_000));
    expect(MockEventSource.instances).toHaveLength(3); // fired at 2s

    // A successful event resets the back-off back to the initial delay.
    const es3 = MockEventSource.latest();
    act(() => es3.emit("snapshot", snap));
    expect(result.current.status).toBe("live");
    act(() => es3.fail());
    act(() => vi.advanceTimersByTime(1_000));
    expect(MockEventSource.instances).toHaveLength(4); // back to a 1s retry
  });

  it("caps at offline once back-off reaches the maximum", () => {
    const { result } = renderHook(() => useEbpfStream());
    // Back-off doubles 1→2→4→8→16→30(capped) s across failures with no
    // successful event to reset it. The first failure is always "reconnecting";
    // once the delay reaches the 30s ceiling the status latches to "offline".
    act(() => MockEventSource.latest().fail());
    expect(result.current.status).toBe("reconnecting");

    // Keep failing (advancing past each growing delay to trigger the retry)
    // until the ceiling is reached. 30s / doubling from 1s ⇒ ≤6 failures.
    let offlineReached = false;
    for (let i = 0; i < 6 && !offlineReached; i++) {
      act(() => vi.advanceTimersByTime(30_000)); // fire the pending retry
      act(() => MockEventSource.latest().fail());
      offlineReached = result.current.status === "offline";
    }
    expect(offlineReached).toBe(true);
  });

  it("stops reconnecting after unmount", () => {
    const { unmount } = renderHook(() => useEbpfStream());
    const es = MockEventSource.latest();
    act(() => es.emit("snapshot", snap));

    unmount();
    expect(es.closed).toBe(true);

    const countAtUnmount = MockEventSource.instances.length;
    act(() => vi.advanceTimersByTime(60_000));
    expect(MockEventSource.instances).toHaveLength(countAtUnmount); // no new connections
  });
});

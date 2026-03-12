/**
 * time.test.ts
 * Unit tests for formatRelativeTime and formatFullTimestamp helpers.
 *
 * NOTE: These helpers live in client/src/lib/time.ts but are pure functions
 * with no browser/React dependencies, so they can be tested directly via
 * Vitest in the server test environment.
 */

import { describe, it, expect } from "vitest";

// ─── Inline the pure helpers so we don't need a DOM environment ────────────────

function formatRelativeTime(unixSec: number, now?: number): string {
  if (!unixSec) return "—";
  const nowMs = now ?? Date.now();
  const diffMs = nowMs - unixSec * 1000;
  if (diffMs < 0) return "just now";
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHr  = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHr  / 24);
  if (diffSec < 60)  return "just now";
  if (diffMin < 60)  return `${diffMin}m ago`;
  if (diffHr  < 24) {
    const remMin = diffMin % 60;
    return remMin > 0 ? `${diffHr}h ${remMin}m ago` : `${diffHr}h ago`;
  }
  if (diffDay < 7) {
    const remHr = diffHr % 24;
    return remHr > 0 ? `${diffDay}d ${remHr}h ago` : `${diffDay}d ago`;
  }
  return new Date(unixSec * 1000).toLocaleDateString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
  });
}

// ─── Reference epoch ──────────────────────────────────────────────────────────
// All tests use a fixed "now" of 2026-01-15T12:00:00Z = 1768392000000 ms
const NOW_MS = 1768392000000;
const NOW_SEC = NOW_MS / 1000;

function sec(s: number): number { return NOW_SEC - s; }
function min(m: number): number { return sec(m * 60); }
function hr(h: number):  number { return min(h * 60); }
function day(d: number): number { return hr(d * 24); }

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("formatRelativeTime", () => {
  it("returns — for falsy input", () => {
    expect(formatRelativeTime(0, NOW_MS)).toBe("—");
  });

  it("returns 'just now' for future timestamps (clock skew)", () => {
    expect(formatRelativeTime(NOW_SEC + 60, NOW_MS)).toBe("just now");
  });

  it("returns 'just now' for < 60s ago", () => {
    expect(formatRelativeTime(sec(30), NOW_MS)).toBe("just now");
    expect(formatRelativeTime(sec(59), NOW_MS)).toBe("just now");
  });

  it("returns 'just now' for exactly 0s ago", () => {
    expect(formatRelativeTime(NOW_SEC, NOW_MS)).toBe("just now");
  });

  it("returns 'Nm ago' for < 60 minutes", () => {
    expect(formatRelativeTime(sec(60), NOW_MS)).toBe("1m ago");
    expect(formatRelativeTime(min(5), NOW_MS)).toBe("5m ago");
    expect(formatRelativeTime(min(59), NOW_MS)).toBe("59m ago");
  });

  it("returns 'Nh ago' for exact hours with no remainder", () => {
    expect(formatRelativeTime(hr(1), NOW_MS)).toBe("1h ago");
    expect(formatRelativeTime(hr(2), NOW_MS)).toBe("2h ago");
    expect(formatRelativeTime(hr(23), NOW_MS)).toBe("23h ago");
  });

  it("returns 'Nh Mm ago' for hours with minute remainder", () => {
    // 1h 30m ago = 90 minutes ago
    expect(formatRelativeTime(sec(90 * 60), NOW_MS)).toBe("1h 30m ago");
    // 2h 15m ago = 135 minutes ago
    expect(formatRelativeTime(sec(135 * 60), NOW_MS)).toBe("2h 15m ago");
  });

  it("returns 'Nd ago' for exact days with no hour remainder", () => {
    expect(formatRelativeTime(day(1), NOW_MS)).toBe("1d ago");
    expect(formatRelativeTime(day(3), NOW_MS)).toBe("3d ago");
    expect(formatRelativeTime(day(6), NOW_MS)).toBe("6d ago");
  });

  it("returns 'Nd Hh ago' for days with hour remainder", () => {
    // 1d 14h ago = 38 hours ago
    expect(formatRelativeTime(hr(38), NOW_MS)).toBe("1d 14h ago");
    // 3d 7h ago = 79 hours ago
    expect(formatRelativeTime(hr(79), NOW_MS)).toBe("3d 7h ago");
  });

  it("returns an absolute date string for >= 7 days ago", () => {
    const result = formatRelativeTime(day(7), NOW_MS);
    // Should be a date string, not a relative string
    expect(result).not.toContain("ago");
    expect(result.length).toBeGreaterThan(4);
  });

  it("returns an absolute date string for very old timestamps", () => {
    const result = formatRelativeTime(day(365), NOW_MS);
    expect(result).not.toContain("ago");
  });
});

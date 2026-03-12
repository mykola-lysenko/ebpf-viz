/**
 * time.ts
 * Utilities for human-readable relative and absolute time display.
 */

import { useState, useEffect } from "react";

// ─── formatRelativeTime ────────────────────────────────────────────────────────

/**
 * Convert a Unix timestamp (seconds) to a human-readable relative string.
 *
 * Rules:
 *   < 60s          → "just now"
 *   < 60m          → "5m ago"
 *   < 24h          → "2h 15m ago"
 *   < 7d           → "3d 14h ago"
 *   >= 7d          → "12 Jan 2025"  (absolute date, no time)
 *
 * @param unixSec  Unix timestamp in seconds (as returned by bpftool loaded_at)
 * @param now      Optional reference time in ms (defaults to Date.now())
 */
export function formatRelativeTime(unixSec: number, now?: number): string {
  if (!unixSec) return "—";
  const nowMs = now ?? Date.now();
  const diffMs = nowMs - unixSec * 1000;

  // Clamp negative diffs (clock skew / future timestamps)
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
  // Older than 7 days: show absolute date
  return new Date(unixSec * 1000).toLocaleDateString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
  });
}

/**
 * Format a Unix timestamp (seconds) as a full locale string for use in tooltips.
 */
export function formatFullTimestamp(unixSec: number): string {
  if (!unixSec) return "—";
  return new Date(unixSec * 1000).toLocaleString();
}

// ─── useNow ────────────────────────────────────────────────────────────────────

/**
 * React hook that returns the current time in milliseconds and re-renders
 * every `intervalMs` so relative times stay fresh.
 *
 * @param intervalMs  Refresh interval in ms (default: 30 000 = 30 seconds)
 */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}

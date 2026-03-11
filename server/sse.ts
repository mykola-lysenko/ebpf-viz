/**
 * sse.ts — Server-Sent Events endpoint for live eBPF data streaming.
 *
 * GET /api/sse
 *
 * The client receives a stream of named events:
 *   event: snapshot   — full EbpfSnapshot (programs, kernel zones, network, cgroups)
 *   event: history    — all ProgHistory ring-buffer entries
 *   event: activity   — ActivitySummary (top programs by calls/sec)
 *   event: maps       — BpfMap[] list
 *   event: ping       — keepalive heartbeat every 15 s
 *
 * Each data line is JSON-serialised with superjson so Date objects survive
 * the wire (matching the tRPC superjson transformer already in use).
 *
 * The server pushes a full payload immediately on connect, then on every
 * poller tick thereafter. Clients do NOT need to poll — they simply listen.
 */

import type { Request, Response } from "express";
import superjson from "superjson";
import {
  subscribe,
  getLatestSnapshot,
  getLatestMaps,
  getAllHistories,
  buildActivitySummary,
  isStatsEnabled,
} from "./ebpf-poller";
import type { EbpfSnapshot } from "../shared/ebpf-types";

// How often to send a keepalive ping (ms) to prevent proxy timeouts
const PING_INTERVAL_MS = 15_000;

/** Write a single SSE frame to the response */
function sendEvent(res: Response, event: string, data: unknown): void {
  try {
    const json = superjson.stringify(data);
    res.write(`event: ${event}\ndata: ${json}\n\n`);
  } catch {
    // Ignore serialisation errors for individual events
  }
}

/** Build and push the full data bundle for a given snapshot */
function pushBundle(res: Response, snap: EbpfSnapshot): void {
  sendEvent(res, "snapshot", snap);
  sendEvent(res, "maps", getLatestMaps());
  sendEvent(res, "history", getAllHistories());
  sendEvent(res, "activity", buildActivitySummary(snap.programs, isStatsEnabled()));
}

/**
 * Express route handler for GET /api/sse.
 * Registers the response as an SSE client and unregisters it on close.
 */
export function sseHandler(req: Request, res: Response): void {
  // ── SSE headers ────────────────────────────────────────────────────────────
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no"); // disable nginx buffering
  res.flushHeaders();

  // ── Immediate flush of current state ──────────────────────────────────────
  const snap = getLatestSnapshot();
  if (snap) {
    pushBundle(res, snap);
  } else {
    // Send an empty ping so the client knows the connection is alive
    sendEvent(res, "ping", { ts: Date.now() });
  }

  // ── Subscribe to future snapshots ─────────────────────────────────────────
  const unsubscribe = subscribe((newSnap: EbpfSnapshot) => {
    pushBundle(res, newSnap);
  });

  // ── Keepalive ping ─────────────────────────────────────────────────────────
  const pingTimer = setInterval(() => {
    sendEvent(res, "ping", { ts: Date.now() });
  }, PING_INTERVAL_MS);

  // ── Cleanup on client disconnect ───────────────────────────────────────────
  const cleanup = () => {
    clearInterval(pingTimer);
    unsubscribe();
  };

  req.on("close", cleanup);
  req.on("aborted", cleanup);
}

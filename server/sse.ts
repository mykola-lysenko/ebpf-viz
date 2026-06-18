/**
 * sse.ts — Server-Sent Events endpoint for live eBPF data streaming.
 *
 * GET /api/sse
 *
 * The client receives a stream of named events:
 *   event: snapshot         — full EbpfSnapshot when topology changes
 *   event: snapshot-metrics — lightweight per-program counters between topology changes
 *   event: history          — all ProgHistory ring-buffer entries on connect/topology change
 *   event: history-delta    — latest ProgHistory samples between topology changes
 *   event: activity         — ActivitySummary (top programs by calls/sec)
 *   event: maps             — BpfMap[] list when map topology changes
 *   event: ping             — keepalive heartbeat every 15 s
 *
 * Each data line is JSON-serialised with superjson so Date objects survive
 * the wire (matching the tRPC superjson transformer already in use).
 *
 * The server pushes a full payload immediately on connect. Later poller ticks
 * only send topology payloads when they change; live counters and history use
 * compact delta events. Clients do NOT need to poll — they simply listen.
 */

import type { Request, Response } from "express";
import { createHash } from "crypto";
import superjson from "superjson";
import {
  subscribe,
  getLatestSnapshot,
  getLatestMaps,
  getAllHistories,
  buildActivitySummary,
  isStatsEnabled,
} from "./ebpf-poller";
import type {
  BpfMap,
  EbpfSnapshot,
  ProgHistoryDelta,
  SnapshotMetricsUpdate,
} from "../shared/ebpf-types";

// How often to send a keepalive ping (ms) to prevent proxy timeouts
const PING_INTERVAL_MS = 15_000;
const SNAPSHOT_TOPOLOGY_IGNORED_KEYS = new Set(["timestamp", "stats", "runCnt", "runTimeNs"]);

interface ClientStreamState {
  snapshotTopologyHash: string | null;
  mapsHash: string | null;
}

/** Write a single SSE frame to the response */
function sendEvent(res: Response, event: string, data: unknown): void {
  try {
    const json = superjson.stringify(data);
    res.write(`event: ${event}\ndata: ${json}\n\n`);
  } catch {
    // Ignore serialisation errors for individual events
  }
}

function hashJson(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function stripSnapshotVolatileFields(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stripSnapshotVolatileFields);
  }

  if (value && typeof value === "object") {
    const next: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      if (SNAPSHOT_TOPOLOGY_IGNORED_KEYS.has(key)) continue;
      next[key] = stripSnapshotVolatileFields(child);
    }
    return next;
  }

  return value;
}

function snapshotTopologyHash(snap: EbpfSnapshot): string {
  return hashJson(stripSnapshotVolatileFields(snap));
}

function mapsHash(maps: BpfMap[]): string {
  return hashJson(maps);
}

function buildSnapshotMetricsUpdate(snap: EbpfSnapshot): SnapshotMetricsUpdate {
  return {
    timestamp: snap.timestamp,
    stats: snap.stats,
    programs: snap.programs.map((prog) => {
      const metrics: SnapshotMetricsUpdate["programs"][number] = { id: prog.id };
      if (prog.runCnt !== undefined) metrics.runCnt = prog.runCnt;
      if (prog.runTimeNs !== undefined) metrics.runTimeNs = prog.runTimeNs;
      return metrics;
    }),
  };
}

function buildHistoryDelta(): ProgHistoryDelta[] {
  return getAllHistories().flatMap((history) => {
    const sample = history.samples[history.samples.length - 1];
    if (!sample) return [];
    return [{
      id: history.id,
      sample,
      latest: history.latest,
      peakCallsPerSec: history.peakCallsPerSec,
      peakAvgLatencyNs: history.peakAvgLatencyNs,
    }];
  });
}

/** Build and push the minimal data bundle for a given snapshot */
function pushBundle(
  res: Response,
  state: ClientStreamState,
  snap: EbpfSnapshot,
  options: { forceFullSnapshot?: boolean; forceMaps?: boolean } = {}
): void {
  const nextSnapshotHash = snapshotTopologyHash(snap);
  const shouldSendFullSnapshot = options.forceFullSnapshot || state.snapshotTopologyHash !== nextSnapshotHash;
  const maps = getLatestMaps();
  const nextMapsHash = mapsHash(maps);
  const shouldSendMaps = options.forceMaps || state.mapsHash !== nextMapsHash;

  if (shouldSendFullSnapshot) {
    sendEvent(res, "snapshot", snap);
    sendEvent(res, "history", getAllHistories());
    state.snapshotTopologyHash = nextSnapshotHash;
  } else {
    sendEvent(res, "snapshot-metrics", buildSnapshotMetricsUpdate(snap));
    sendEvent(res, "history-delta", buildHistoryDelta());
  }

  if (shouldSendMaps) {
    sendEvent(res, "maps", maps);
    state.mapsHash = nextMapsHash;
  }

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

  const streamState: ClientStreamState = {
    snapshotTopologyHash: null,
    mapsHash: null,
  };

  // ── Immediate flush of current state ──────────────────────────────────────
  const snap = getLatestSnapshot();
  if (snap) {
    pushBundle(res, streamState, snap, { forceFullSnapshot: true, forceMaps: true });
  } else {
    // Send an empty ping so the client knows the connection is alive
    sendEvent(res, "ping", { ts: Date.now() });
  }

  // ── Subscribe to future snapshots ─────────────────────────────────────────
  const unsubscribe = subscribe((newSnap: EbpfSnapshot) => {
    pushBundle(res, streamState, newSnap);
  }, { immediate: snap === null });

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

/**
 * useEbpfStream — SSE-based live data hook.
 *
 * Connects to GET /api/sse and maintains a persistent stream.
 * Automatically reconnects with exponential back-off on disconnect.
 *
 * Emitted server events:
 *   snapshot         → EbpfSnapshot
 *   snapshot-metrics → SnapshotMetricsUpdate
 *   maps             → BpfMap[]
 *   history          → ProgHistory[]
 *   history-delta    → ProgHistoryDelta[]
 *   activity         → ActivitySummary
 *   ping             → keepalive (ignored by the hook)
 *
 * Data is serialised with superjson on the server; we deserialise here.
 */

import { useEffect, useRef, useState, useCallback } from "react";
import superjson from "superjson";
import type {
  EbpfSnapshot,
  BpfProgram,
  BpfMap,
  CgroupNode,
  KernelAttachmentZone,
  NetworkInterface,
  ProgHistory,
  ProgHistoryDelta,
  SnapshotMetricsUpdate,
  ActivitySummary,
} from "../../../shared/ebpf-types";
import { PROG_HISTORY_RING_SIZE } from "../../../shared/ebpf-constants";

export type StreamStatus = "connecting" | "live" | "reconnecting" | "offline";

export interface EbpfStreamState {
  snapshot: EbpfSnapshot | null;
  maps: BpfMap[];
  allHistories: ProgHistory[];
  activity: ActivitySummary | null;
  status: StreamStatus;
  /** Timestamp of the last received event (ms) */
  lastEventAt: number | null;
}

const SSE_URL = "/api/sse";
const INITIAL_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 30_000;
const BACKOFF_FACTOR = 2;

function parseEvent<T>(data: string): T | null {
  try {
    return superjson.parse<T>(data);
  } catch {
    return null;
  }
}

type ProgramMetrics = SnapshotMetricsUpdate["programs"][number];

function mergeProgramMetrics(program: BpfProgram, metricsById: Map<number, ProgramMetrics>): BpfProgram {
  const metrics = metricsById.get(program.id);
  if (!metrics) return program;

  const runCntChanged = metrics.runCnt !== undefined && metrics.runCnt !== program.runCnt;
  const runTimeChanged = metrics.runTimeNs !== undefined && metrics.runTimeNs !== program.runTimeNs;
  if (!runCntChanged && !runTimeChanged) return program;

  const next = { ...program };
  if (metrics.runCnt !== undefined) next.runCnt = metrics.runCnt;
  if (metrics.runTimeNs !== undefined) next.runTimeNs = metrics.runTimeNs;
  return next;
}

function mergeProgramListMetrics(programs: BpfProgram[], metricsById: Map<number, ProgramMetrics>): BpfProgram[] {
  let changed = false;
  const next = programs.map((program) => {
    const merged = mergeProgramMetrics(program, metricsById);
    if (merged !== program) changed = true;
    return merged;
  });
  return changed ? next : programs;
}

function mergeNetworkInterfaceMetrics(iface: NetworkInterface, metricsById: Map<number, ProgramMetrics>): NetworkInterface {
  const layers = {
    L2: mergeProgramListMetrics(iface.layers.L2, metricsById),
    L3: mergeProgramListMetrics(iface.layers.L3, metricsById),
    L4: mergeProgramListMetrics(iface.layers.L4, metricsById),
    L7: mergeProgramListMetrics(iface.layers.L7, metricsById),
  };
  const allPrograms = mergeProgramListMetrics(iface.allPrograms, metricsById);

  if (
    layers.L2 === iface.layers.L2 &&
    layers.L3 === iface.layers.L3 &&
    layers.L4 === iface.layers.L4 &&
    layers.L7 === iface.layers.L7 &&
    allPrograms === iface.allPrograms
  ) {
    return iface;
  }

  return { ...iface, layers, allPrograms };
}

function mergeCgroupMetrics(node: CgroupNode, metricsById: Map<number, ProgramMetrics>): CgroupNode {
  const programs = mergeProgramListMetrics(node.programs, metricsById);
  let childrenChanged = false;
  const children = node.children.map((child) => {
    const merged = mergeCgroupMetrics(child, metricsById);
    if (merged !== child) childrenChanged = true;
    return merged;
  });

  if (programs === node.programs && !childrenChanged) return node;
  return { ...node, programs, children: childrenChanged ? children : node.children };
}

function mergeKernelZoneMetrics(zone: KernelAttachmentZone, metricsById: Map<number, ProgramMetrics>): KernelAttachmentZone {
  const programs = mergeProgramListMetrics(zone.programs, metricsById);
  return programs === zone.programs ? zone : { ...zone, programs };
}

function applySnapshotMetrics(snapshot: EbpfSnapshot | null, update: SnapshotMetricsUpdate): EbpfSnapshot | null {
  if (!snapshot) return snapshot;
  const metricsById = new Map(update.programs.map((program) => [program.id, program]));

  return {
    ...snapshot,
    timestamp: update.timestamp,
    stats: update.stats,
    programs: mergeProgramListMetrics(snapshot.programs, metricsById),
    networkInterfaces: snapshot.networkInterfaces.map((iface) => mergeNetworkInterfaceMetrics(iface, metricsById)),
    cgroupTree: snapshot.cgroupTree.map((node) => mergeCgroupMetrics(node, metricsById)),
    kernelZones: snapshot.kernelZones.map((zone) => mergeKernelZoneMetrics(zone, metricsById)),
  };
}

function applyHistoryDeltas(histories: ProgHistory[], deltas: ProgHistoryDelta[]): ProgHistory[] {
  if (deltas.length === 0) return histories;

  const byId = new Map(histories.map((history) => [history.id, history]));
  for (const delta of deltas) {
    const existing = byId.get(delta.id);
    const existingSamples = existing?.samples ?? [];
    const lastSample = existingSamples[existingSamples.length - 1];
    const samples = lastSample?.ts === delta.sample.ts
      ? [...existingSamples.slice(0, -1), delta.sample]
      : [...existingSamples, delta.sample];
    const trimmedSamples = samples.length > PROG_HISTORY_RING_SIZE
      ? samples.slice(samples.length - PROG_HISTORY_RING_SIZE)
      : samples;

    byId.set(delta.id, {
      id: delta.id,
      samples: trimmedSamples,
      latest: delta.latest,
      peakCallsPerSec: delta.peakCallsPerSec,
      peakAvgLatencyNs: delta.peakAvgLatencyNs,
    });
  }

  return Array.from(byId.values());
}

export function useEbpfStream(): EbpfStreamState {
  const [state, setState] = useState<EbpfStreamState>({
    snapshot: null,
    maps: [],
    allHistories: [],
    activity: null,
    status: "connecting",
    lastEventAt: null,
  });

  const esRef = useRef<EventSource | null>(null);
  const backoffRef = useRef(INITIAL_BACKOFF_MS);
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    if (!mountedRef.current) return;

    // Close any existing connection
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }

    setState(prev => ({
      ...prev,
      status: prev.status === "live" ? "reconnecting" : "connecting",
    }));

    const es = new EventSource(SSE_URL);
    esRef.current = es;

    es.addEventListener("snapshot", (e: MessageEvent) => {
      const snap = parseEvent<EbpfSnapshot>(e.data);
      if (!snap || !mountedRef.current) return;
      backoffRef.current = INITIAL_BACKOFF_MS; // reset on successful event
      setState(prev => ({
        ...prev,
        snapshot: snap,
        status: "live",
        lastEventAt: Date.now(),
      }));
    });

    es.addEventListener("snapshot-metrics", (e: MessageEvent) => {
      const metrics = parseEvent<SnapshotMetricsUpdate>(e.data);
      if (!metrics || !mountedRef.current) return;
      backoffRef.current = INITIAL_BACKOFF_MS;
      setState(prev => ({
        ...prev,
        snapshot: applySnapshotMetrics(prev.snapshot, metrics),
        status: "live",
        lastEventAt: Date.now(),
      }));
    });

    es.addEventListener("maps", (e: MessageEvent) => {
      const maps = parseEvent<BpfMap[]>(e.data);
      if (!maps || !mountedRef.current) return;
      setState(prev => ({ ...prev, maps, lastEventAt: Date.now() }));
    });

    es.addEventListener("history", (e: MessageEvent) => {
      const histories = parseEvent<ProgHistory[]>(e.data);
      if (!histories || !mountedRef.current) return;
      setState(prev => ({ ...prev, allHistories: histories, lastEventAt: Date.now() }));
    });

    es.addEventListener("history-delta", (e: MessageEvent) => {
      const deltas = parseEvent<ProgHistoryDelta[]>(e.data);
      if (!deltas || !mountedRef.current) return;
      setState(prev => ({
        ...prev,
        allHistories: applyHistoryDeltas(prev.allHistories, deltas),
        lastEventAt: Date.now(),
      }));
    });

    es.addEventListener("activity", (e: MessageEvent) => {
      const activity = parseEvent<ActivitySummary>(e.data);
      if (!activity || !mountedRef.current) return;
      setState(prev => ({ ...prev, activity, lastEventAt: Date.now() }));
    });

    es.addEventListener("ping", () => {
      if (!mountedRef.current) return;
      // Ping confirms the connection is alive; mark as live if we were reconnecting
      setState(prev => ({
        ...prev,
        status: "live",
        lastEventAt: Date.now(),
      }));
    });

    es.onerror = () => {
      if (!mountedRef.current) return;
      es.close();
      esRef.current = null;

      setState(prev => ({
        ...prev,
        status: backoffRef.current >= MAX_BACKOFF_MS ? "offline" : "reconnecting",
      }));

      // Exponential back-off reconnect
      const delay = backoffRef.current;
      backoffRef.current = Math.min(backoffRef.current * BACKOFF_FACTOR, MAX_BACKOFF_MS);

      retryTimerRef.current = setTimeout(() => {
        if (mountedRef.current) connect();
      }, delay);
    };
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;
      if (retryTimerRef.current) clearTimeout(retryTimerRef.current);
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
    };
  }, [connect]);

  return state;
}

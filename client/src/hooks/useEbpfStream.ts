/**
 * useEbpfStream — SSE-based live data hook.
 *
 * Connects to GET /api/sse and maintains a persistent stream.
 * Automatically reconnects with exponential back-off on disconnect.
 *
 * Emitted server events:
 *   snapshot  → EbpfSnapshot
 *   maps      → BpfMap[]
 *   history   → ProgHistory[]
 *   activity  → ActivitySummary
 *   ping      → keepalive (ignored by the hook)
 *
 * Data is serialised with superjson on the server; we deserialise here.
 */

import { useEffect, useRef, useState, useCallback } from "react";
import superjson from "superjson";
import type {
  EbpfSnapshot,
  BpfMap,
  ProgHistory,
  ActivitySummary,
} from "../../../shared/ebpf-types";

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

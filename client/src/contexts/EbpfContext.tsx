import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  useMemo,
  useRef,
} from "react";
import { useLocation, useSearchParams } from "wouter";
import { trpc } from "@/lib/trpc";
import { useEbpfStream } from "@/hooks/useEbpfStream";
import type {
  BpfProgram,
  BpfMap,
  EbpfSnapshot,
  ProgHistory,
  ActivitySummary,
  MapDumpResult,
} from "../../../shared/ebpf-types";

export type { StreamStatus } from "@/hooks/useEbpfStream";

/** The three operating modes of the app */
export type AppMode = "live" | "demo" | "snapshot";

export interface SnapshotMeta {
  filename: string;
  capturedAt: string;
  hostname: string;
  kernelVersion: string;
}

interface EbpfContextValue {
  snapshot: EbpfSnapshot | null;
  isLoading: boolean;
  error: string | null;
  selectedProgram: BpfProgram | null;
  setSelectedProgram: (p: BpfProgram | null) => void;
  /** Globally-selected map id (drives the Maps page detail panel; lifted to
   *  context so cross-navigation and deep links can set it from anywhere). */
  selectedMapId: number | null;
  setSelectedMapId: (id: number | null) => void;
  /** Cross-navigation: open a program's detail drawer by id (stays on the
   *  current page — the drawer is global). */
  focusProgram: (id: number) => void;
  /** Cross-navigation: select a map by id and go to the Maps page. */
  focusMap: (id: number) => void;
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  typeFilter: string[];
  setTypeFilter: (types: string[]) => void;
  filteredPrograms: BpfProgram[];
  /** SSE stream status — replaces the old autoRefresh boolean */
  streamStatus: import("@/hooks/useEbpfStream").StreamStatus;
  /** Legacy compat: true when stream is live */
  autoRefresh: boolean;
  setAutoRefresh: (v: boolean) => void;
  refreshInterval: number;
  setRefreshInterval: (ms: number) => void;
  refresh: () => void;
  demoMode: boolean;
  /** Current operating mode */
  appMode: AppMode;
  /** Metadata about the loaded snapshot (only set in snapshot mode) */
  snapshotMeta: SnapshotMeta | null;
  /** Load a snapshot JSON file into snapshot mode */
  loadSnapshot: (file: File) => Promise<void>;
  /** Parse a snapshot file WITHOUT entering snapshot mode (for the diff view). */
  parseSnapshotFile: (
    file: File
  ) => Promise<{ snapshot: EbpfSnapshot; maps: BpfMap[]; meta: SnapshotMeta }>;
  /** Load a map dump file (from capture-snapshot.sh --dump-maps) into snapshot mode */
  loadMapDumps: (file: File) => Promise<{ loaded: number }> | never;
  /** Parse a map dump file against a given map set WITHOUT touching global state
   *  (for the diff view, which parses one dump per side). */
  parseMapDumpsFile: (
    file: File,
    maps: BpfMap[]
  ) => Promise<Record<number, MapDumpResult>>;
  /** Clear the loaded snapshot and return to live/demo mode */
  clearSnapshot: () => void;
  /** Snapshot map dumps: Record<mapId, MapDumpResult> — populated after loadMapDumps() */
  snapshotMapDumps: Record<number, MapDumpResult>;
  /** Map from program ID → ProgHistory (ring buffer data) */
  historyMap: Map<number, ProgHistory>;
  /** Activity summary — top programs by calls/sec */
  activity: ActivitySummary | null;
  statsEnabled: boolean;
  /** BPF maps — pushed via SSE stream, updated on every poller tick */
  maps: BpfMap[];
}

const EbpfContext = createContext<EbpfContextValue | null>(null);

/** Numeric id from a URLSearchParams entry, else null. */
function paramId(params: URLSearchParams, key: string): number | null {
  const raw = params.get(key);
  const n = raw != null && raw !== "" ? Number(raw) : NaN;
  return Number.isFinite(n) ? n : null;
}

export function EbpfProvider({ children }: { children: React.ReactNode }) {
  const [, navigate] = useLocation();
  // The URL query is the SINGLE SOURCE OF TRUTH for selection: `?prog=<id>`
  // opens a program's drawer, `?map=<id>` selects a map. Deriving selection
  // from the URL (rather than mirroring it into React state with sync effects)
  // is what makes deep links work AND avoids an infinite loop — a prior
  // two-way sync fought itself whenever navigation dropped the query while a
  // selection was active ("Maximum update depth exceeded"). See the regression
  // in client/src/contexts/url-sync-loop.test.tsx.
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedProgramId = paramId(searchParams, "prog");
  const selectedMapId = paramId(searchParams, "map");

  // Write a single selection param (replace, so per-click doesn't spam history).
  const setParam = useCallback(
    (key: string, value: number | null) => {
      setSearchParams(
        prev => {
          const next = new URLSearchParams(prev);
          if (value != null) next.set(key, String(value));
          else next.delete(key);
          return next;
        },
        { replace: true }
      );
    },
    [setSearchParams]
  );
  // String variant, for the search box and type-filter chips.
  const setStringParam = useCallback(
    (key: string, value: string) => {
      setSearchParams(
        prev => {
          const next = new URLSearchParams(prev);
          if (value) next.set(key, value);
          else next.delete(key);
          return next;
        },
        { replace: true }
      );
    },
    [setSearchParams]
  );

  // Detail panel keeps showing a program's last-known state if it unloads.
  const lastKnownProgramRef = useRef<BpfProgram | null>(null);
  const setSelectedProgram = useCallback(
    (p: BpfProgram | null) => {
      if (p) lastKnownProgramRef.current = p;
      setParam("prog", p?.id ?? null);
    },
    [setParam]
  );
  const setSelectedMapId = useCallback(
    (id: number | null) => setParam("map", id),
    [setParam]
  );

  // Search + type filters live in the URL as well, so a filtered program view
  // is shareable and survives reload — same URL-as-source-of-truth pattern as
  // the prog/map selection (?q=<text>&type=<t1,t2>).
  const searchQuery = searchParams.get("q") ?? "";
  const setSearchQuery = useCallback((q: string) => setStringParam("q", q), [setStringParam]);
  const typeFilterRaw = searchParams.get("type") ?? "";
  const typeFilter = useMemo(
    () => (typeFilterRaw ? typeFilterRaw.split(",").filter(Boolean) : []),
    [typeFilterRaw]
  );
  const setTypeFilter = useCallback(
    (types: string[]) => setStringParam("type", types.join(",")),
    [setStringParam]
  );
  // refreshInterval is kept for the Settings page UI but no longer drives polling
  const [refreshInterval, setRefreshInterval] = useState(5000);

  // ── Snapshot mode state ────────────────────────────────────────────────────
  const [loadedSnapshot, setLoadedSnapshot] = useState<EbpfSnapshot | null>(
    null
  );
  const [snapshotMaps, setSnapshotMaps] = useState<BpfMap[]>([]);
  const [snapshotMeta, setSnapshotMeta] = useState<SnapshotMeta | null>(null);
  const [snapshotMapDumps, setSnapshotMapDumps] = useState<
    Record<number, MapDumpResult>
  >({});

  // ── SSE live stream ────────────────────────────────────────────────────────
  const {
    snapshot: rawLiveSnapshot,
    maps: rawLiveMaps,
    allHistories,
    activity,
    status: streamStatus,
  } = useEbpfStream();

  // No client-side deep-compare stabilization: the SSE layer already sends
  // full snapshots only on topology-hash changes and preserves per-object
  // identity on metrics updates, so a whole-snapshot deepEqual every poll
  // was pure CPU that nearly always concluded "changed" anyway (per-program
  // counters mutate each poll). Memoized rows rely on the per-object
  // identities instead.
  const liveSnapshot = rawLiveSnapshot;
  const liveMaps = rawLiveMaps;

  // ── Poller status (for statsEnabled flag) — lightweight 30s poll ──────────
  const { data: pollerStatus, refetch } = trpc.ebpf.status.useQuery(undefined, {
    refetchInterval: 30_000,
    staleTime: 15_000,
  });

  // ── Active snapshot: loaded snapshot takes priority over live stream ───────
  const snapshot = loadedSnapshot ?? liveSnapshot ?? null;

  // Live-resolve the selected program from the current snapshot so the detail
  // panel tracks poll updates; fall back to the last-known object when the
  // program has unloaded (panel keeps showing its last state) or is not yet in
  // the snapshot (deep-linked before the stream connected → resolves on load).
  const selectedProgram = useMemo(() => {
    if (selectedProgramId == null) return null;
    const live = snapshot?.programs.find(p => p.id === selectedProgramId) ?? null;
    if (live) return live;
    return lastKnownProgramRef.current?.id === selectedProgramId
      ? lastKnownProgramRef.current
      : null;
  }, [selectedProgramId, snapshot]);
  useEffect(() => {
    if (selectedProgram) lastKnownProgramRef.current = selectedProgram;
  }, [selectedProgram]);

  // Cross-navigation. focusProgram opens a program's drawer (stays on the
  // current page — the drawer is global). focusMap goes to the Maps page with
  // the map selected, atomically (path + query in one navigation), which also
  // clears any open program drawer.
  const focusProgram = useCallback((id: number) => setParam("prog", id), [setParam]);
  const focusMap = useCallback(
    (id: number) => navigate(`/maps?map=${id}`),
    [navigate]
  );
  const maps: BpfMap[] = loadedSnapshot ? snapshotMaps : liveMaps;
  const isLoading =
    loadedSnapshot === null &&
    liveSnapshot === null &&
    streamStatus === "connecting";

  // Manual refresh: trigger an immediate server-side poll via tRPC mutation
  const refreshMutation = trpc.ebpf.refresh.useMutation();
  // Server-side snapshot parser for raw bpftool format (capture-snapshot.sh output)
  const parseSnapshotMutation = trpc.ebpf.parseSnapshot.useMutation();
  // Server-side map dump parser for map dump files (capture-snapshot.sh --dump-maps output)
  const parseMapDumpsMutation = trpc.ebpf.parseMapDumps.useMutation();

  // Stable refs for mutation functions — useMutation() returns new objects every
  // render, which would destabilize any useCallback that depends on them.
  const refreshMutateRef = useRef(refreshMutation.mutate);
  refreshMutateRef.current = refreshMutation.mutate;
  const parseSnapshotRef = useRef(parseSnapshotMutation.mutateAsync);
  parseSnapshotRef.current = parseSnapshotMutation.mutateAsync;
  const parseMapDumpsRef = useRef(parseMapDumpsMutation.mutateAsync);
  parseMapDumpsRef.current = parseMapDumpsMutation.mutateAsync;
  const refetchRef = useRef(refetch);
  refetchRef.current = refetch;

  const refresh = useCallback(() => {
    if (loadedSnapshot) return; // no-op in snapshot mode
    refreshMutateRef.current();
    refetchRef.current();
  }, [loadedSnapshot]);

  // ── Snapshot parsing (shared by loadSnapshot and the diff view) ────────────
  // Parses a snapshot File into an EbpfSnapshot + maps + meta WITHOUT touching
  // any global state, so the diff page can parse two files independently.
  const parseSnapshotFile = useCallback(
    async (
      file: File
    ): Promise<{ snapshot: EbpfSnapshot; maps: BpfMap[]; meta: SnapshotMeta }> => {
      const { formatValidationError, snapshotUploadSchema } = await import(
        "../../../shared/snapshot-validation"
      );
      const text = await file.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new Error("Invalid JSON file");
      }

      const validation = snapshotUploadSchema.safeParse(parsed);
      if (!validation.success) {
        throw new Error(
          formatValidationError("Invalid eBPF Viz snapshot file.", validation.error)
        );
      }
      const obj = validation.data;

      // Two formats: a pre-parsed "snapshot" key, or "raw" bpftool outputs
      // that the server parses via the parseSnapshot mutation.
      let ebpfSnapshot: EbpfSnapshot;
      let parsedMaps: BpfMap[] = [];
      if (obj.snapshot) {
        ebpfSnapshot = obj.snapshot as EbpfSnapshot;
        parsedMaps = (obj.maps ?? []) as BpfMap[];
      } else if (obj.raw) {
        const result = await parseSnapshotRef.current({
          raw: obj.raw,
          hostname: obj.hostname,
          kernelVersion: obj.kernelVersion,
          bpftoolVersion: obj.bpftoolVersion,
          capturedAt: obj.capturedAt,
          timestamp: obj.timestamp,
        });
        ebpfSnapshot = result.snapshot;
        parsedMaps = result.maps;
      } else {
        throw new Error("Snapshot file is missing the 'snapshot' or 'raw' field.");
      }

      const capturedAt =
        (obj.capturedAt as string) ?? new Date(ebpfSnapshot.timestamp).toISOString();
      return {
        snapshot: ebpfSnapshot,
        maps: parsedMaps,
        meta: {
          filename: file.name,
          capturedAt,
          hostname: ebpfSnapshot.hostname ?? "unknown",
          kernelVersion: ebpfSnapshot.kernelVersion ?? "unknown",
        },
      };
    },
    []
  );

  // ── Snapshot loading (into snapshot mode) ──────────────────────────────────
  const loadSnapshot = useCallback(
    async (file: File) => {
      const { snapshot, maps, meta } = await parseSnapshotFile(file);
      setLoadedSnapshot(snapshot);
      setSnapshotMaps(maps);
      setSnapshotMeta(meta);
    },
    [parseSnapshotFile]
  );

  // ── Map dump loading ───────────────────────────────────────────────────────
  const snapshotMapsRef = useRef(snapshotMaps);
  snapshotMapsRef.current = snapshotMaps;
  const loadedSnapshotRef = useRef(loadedSnapshot);
  loadedSnapshotRef.current = loadedSnapshot;

  // Parse a map-dump file against a given set of maps WITHOUT touching global
  // state — shared by loadMapDumps (live snapshot mode) and the diff view, which
  // parses a dump for each side independently.
  const parseMapDumpsFile = useCallback(
    async (file: File, maps: BpfMap[]): Promise<Record<number, MapDumpResult>> => {
      const { formatValidationError, mapDumpsUploadSchema } = await import(
        "../../../shared/snapshot-validation"
      );
      const text = await file.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new Error("Invalid JSON file");
      }
      const validation = mapDumpsUploadSchema.safeParse(parsed);
      if (!validation.success) {
        throw new Error(
          formatValidationError("Invalid eBPF Viz map dump file.", validation.error)
        );
      }
      // Send to server for parsing (normalizes RawMapEntry → MapEntry)
      const result = await parseMapDumpsRef.current({
        mapDumps: validation.data.mapDumps,
        maps: maps.map(m => ({ id: m.id, rawType: m.rawType, name: m.name })),
      });
      return result as Record<number, MapDumpResult>;
    },
    []
  );

  const loadMapDumps = useCallback(
    async (file: File): Promise<{ loaded: number }> => {
      if (!loadedSnapshotRef.current) {
        throw new Error("Load a snapshot first before loading map dumps.");
      }
      const result = await parseMapDumpsFile(file, snapshotMapsRef.current);
      setSnapshotMapDumps(result);
      return { loaded: Object.keys(result).length };
    },
    [parseMapDumpsFile]
  );

  const clearSnapshot = useCallback(() => {
    setLoadedSnapshot(null);
    setSnapshotMaps([]);
    setSnapshotMeta(null);
    setSnapshotMapDumps({});
  }, []);

  // ── Derived mode ───────────────────────────────────────────────────────────
  const appMode: AppMode = loadedSnapshot
    ? "snapshot"
    : snapshot?.demoMode
      ? "demo"
      : "live";

  // Build a Map<id, ProgHistory> for O(1) lookup in components
  const historyMap = useMemo(() => {
    const m = new Map<number, ProgHistory>();
    if (allHistories) {
      for (const h of allHistories) m.set(h.id, h);
    }
    return m;
  }, [allHistories]);

  // Filter programs based on search + type filter
  const filteredPrograms = useMemo(() => {
    if (!snapshot) return [];
    let progs = snapshot.programs;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      progs = progs.filter(
        p =>
          p.name.toLowerCase().includes(q) ||
          p.rawType.toLowerCase().includes(q) ||
          p.tag.toLowerCase().includes(q) ||
          String(p.id).includes(q) ||
          p.attachments.some(a => a.detail.toLowerCase().includes(q))
      );
    }

    if (typeFilter.length > 0) {
      progs = progs.filter(p => typeFilter.includes(p.rawType));
    }

    return progs;
  }, [snapshot, searchQuery, typeFilter]);

  // Legacy compat shim — components that read autoRefresh get true when live
  const autoRefresh =
    appMode !== "snapshot" &&
    (streamStatus === "live" || streamStatus === "reconnecting");
  const setAutoRefresh = useCallback((v: boolean) => {
    // No-op: SSE manages its own connection lifecycle.
    // Kept for API compatibility with SettingsView and EbpfLayout.
    void v;
  }, []);

  const error =
    appMode !== "snapshot" && streamStatus === "offline"
      ? "Stream disconnected — check server"
      : null;
  const demoMode = appMode === "demo";
  const statsEnabled = pollerStatus?.statsEnabled ?? false;
  const activityValue = activity ?? null;

  const contextValue = useMemo<EbpfContextValue>(
    () => ({
      snapshot: snapshot ?? null,
      isLoading,
      error,
      selectedProgram,
      setSelectedProgram,
      selectedMapId,
      setSelectedMapId,
      focusProgram,
      focusMap,
      searchQuery,
      setSearchQuery,
      typeFilter,
      setTypeFilter,
      filteredPrograms,
      streamStatus,
      autoRefresh,
      setAutoRefresh,
      refreshInterval,
      setRefreshInterval,
      refresh,
      demoMode,
      appMode,
      snapshotMeta,
      loadSnapshot,
      parseSnapshotFile,
      loadMapDumps,
      parseMapDumpsFile,
      clearSnapshot,
      snapshotMapDumps,
      historyMap,
      activity: activityValue,
      statsEnabled,
      maps,
    }),
    [
      snapshot,
      isLoading,
      error,
      selectedProgram,
      selectedMapId,
      focusProgram,
      focusMap,
      searchQuery,
      typeFilter,
      filteredPrograms,
      streamStatus,
      autoRefresh,
      refreshInterval,
      setAutoRefresh,
      refresh,
      demoMode,
      appMode,
      snapshotMeta,
      loadSnapshot,
      loadMapDumps,
      parseMapDumpsFile,
      parseSnapshotFile,
      clearSnapshot,
      snapshotMapDumps,
      historyMap,
      activityValue,
      statsEnabled,
      maps,
    ]
  );

  return (
    <EbpfContext.Provider value={contextValue}>{children}</EbpfContext.Provider>
  );
}

export function useEbpf() {
  const ctx = useContext(EbpfContext);
  if (!ctx) throw new Error("useEbpf must be used within EbpfProvider");
  return ctx;
}

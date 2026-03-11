import React, { createContext, useContext, useState, useCallback, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { useEbpfStream } from "@/hooks/useEbpfStream";
import type { BpfProgram, BpfMap, EbpfSnapshot, ProgHistory, ActivitySummary } from "../../../shared/ebpf-types";

export type { StreamStatus } from "@/hooks/useEbpfStream";

interface EbpfContextValue {
  snapshot: EbpfSnapshot | null;
  isLoading: boolean;
  error: string | null;
  selectedProgram: BpfProgram | null;
  setSelectedProgram: (p: BpfProgram | null) => void;
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
  /** Map from program ID → ProgHistory (ring buffer data) */
  historyMap: Map<number, ProgHistory>;
  /** Activity summary — top programs by calls/sec */
  activity: ActivitySummary | null;
  statsEnabled: boolean;
  /** BPF maps — pushed via SSE stream, updated on every poller tick */
  maps: BpfMap[];
}

const EbpfContext = createContext<EbpfContextValue | null>(null);

export function EbpfProvider({ children }: { children: React.ReactNode }) {
  const [selectedProgram, setSelectedProgram] = useState<BpfProgram | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<string[]>([]);
  // refreshInterval is kept for the Settings page UI but no longer drives polling
  const [refreshInterval, setRefreshInterval] = useState(5000);

  // ── SSE live stream ────────────────────────────────────────────────────────
  const {
    snapshot,
    maps,
    allHistories,
    activity,
    status: streamStatus,
  } = useEbpfStream();

  // ── Poller status (for statsEnabled flag) — lightweight 30s poll ──────────
  const { data: pollerStatus, refetch } = trpc.ebpf.status.useQuery(undefined, {
    refetchInterval: 30_000,
    staleTime: 15_000,
  });

  const isLoading = snapshot === null && streamStatus === "connecting";

  // Manual refresh: trigger an immediate server-side poll via tRPC mutation
  const refreshMutation = trpc.ebpf.refresh.useMutation();
  const refresh = useCallback(() => {
    refreshMutation.mutate();
    refetch();
  }, [refreshMutation, refetch]);

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
      progs = progs.filter(p =>
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
  const autoRefresh = streamStatus === "live" || streamStatus === "reconnecting";
  const setAutoRefresh = useCallback((v: boolean) => {
    // No-op: SSE manages its own connection lifecycle.
    // Kept for API compatibility with SettingsView and EbpfLayout.
    void v;
  }, []);

  return (
    <EbpfContext.Provider value={{
      snapshot: snapshot ?? null,
      isLoading,
      error: streamStatus === "offline" ? "Stream disconnected — check server" : null,
      selectedProgram,
      setSelectedProgram,
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
      demoMode: snapshot?.demoMode ?? false,
      historyMap,
      activity: activity ?? null,
      statsEnabled: pollerStatus?.statsEnabled ?? false,
      maps,
    }}>
      {children}
    </EbpfContext.Provider>
  );
}

export function useEbpf() {
  const ctx = useContext(EbpfContext);
  if (!ctx) throw new Error("useEbpf must be used within EbpfProvider");
  return ctx;
}

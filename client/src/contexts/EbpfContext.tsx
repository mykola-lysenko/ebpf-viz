import React, { createContext, useContext, useState, useCallback, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import type { BpfProgram, EbpfSnapshot, ProgHistory, ActivitySummary } from "../../../shared/ebpf-types";

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
}

const EbpfContext = createContext<EbpfContextValue | null>(null);

export function EbpfProvider({ children }: { children: React.ReactNode }) {
  const [selectedProgram, setSelectedProgram] = useState<BpfProgram | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<string[]>([]);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(5000);

  // ── Core snapshot ──────────────────────────────────────────────────────────
  const { data: snapshot, isLoading, error, refetch } = trpc.ebpf.snapshot.useQuery(undefined, {
    refetchInterval: autoRefresh ? refreshInterval : false,
    staleTime: 1000,
  });

  // ── History ring buffer — poll at same interval ────────────────────────────
  const { data: allHistories } = trpc.ebpf.allHistory.useQuery(undefined, {
    refetchInterval: autoRefresh ? refreshInterval : false,
    staleTime: 1000,
  });

  // ── Activity summary — slightly faster poll for the live indicator ─────────
  const { data: activity } = trpc.ebpf.activity.useQuery(undefined, {
    refetchInterval: autoRefresh ? Math.min(refreshInterval, 3000) : false,
    staleTime: 500,
  });

  // ── Poller status (for statsEnabled flag) ─────────────────────────────────
  const { data: pollerStatus } = trpc.ebpf.status.useQuery(undefined, {
    refetchInterval: 10000,
    staleTime: 5000,
  });

  const refresh = useCallback(() => { refetch(); }, [refetch]);

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

  return (
    <EbpfContext.Provider value={{
      snapshot: snapshot ?? null,
      isLoading,
      error: error?.message ?? null,
      selectedProgram,
      setSelectedProgram,
      searchQuery,
      setSearchQuery,
      typeFilter,
      setTypeFilter,
      filteredPrograms,
      autoRefresh,
      setAutoRefresh,
      refreshInterval,
      setRefreshInterval,
      refresh,
      demoMode: snapshot?.demoMode ?? false,
      historyMap,
      activity: activity ?? null,
      statsEnabled: pollerStatus?.statsEnabled ?? false,
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

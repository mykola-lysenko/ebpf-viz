/**
 * Full-screen modal for inspecting BPF map entries.
 *
 * The low-level byte interpretation and row rendering live in
 * components/map-entries so this file stays focused on data loading, modal
 * state, filtering, and pagination.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Database,
  Download,
  Loader2,
  RefreshCw,
  Search,
  X,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { trpc } from "@/lib/trpc";
import type { MapDumpResult, MapEntry } from "../../../shared/ebpf-types";
import { EntryRow } from "./map-entries/EntryRow";
import { InterpretToggle } from "./map-entries/InterpretToggle";
import { entryKeyText, entryValText } from "./map-entries/entryText";
import { exportAsCSV, exportAsJSON } from "./map-entries/exportEntries";
import {
  compatibleOptions,
  defaultKeyInterpret,
  loadInterpretPrefs,
  saveInterpretPrefs,
} from "./map-entries/interpretation";
import type { DisplayMode, InterpretMode } from "./map-entries/types";
import { PAGE_SIZE } from "./map-entries/types";

interface MapEntriesModalProps {
  mapId: number;
  mapName: string;
  mapType: string;
  mapColor: string;
  /** Byte length of the key field — used to filter interpretation options */
  keyBytes?: number;
  /** Byte length of the value field — used to filter interpretation options */
  valueBytes?: number;
  onClose: () => void;
  /** Pre-loaded dump from snapshot mode — skips the live tRPC query when provided */
  snapshotDump?: MapDumpResult;
}

export function MapEntriesModal({
  mapId,
  mapName,
  mapType,
  mapColor,
  keyBytes,
  valueBytes,
  onClose,
  snapshotDump,
}: MapEntriesModalProps) {
  const [mode, setMode] = useState<DisplayMode>("btf");
  const [keyInterpret, setKeyInterpret] = useState<InterpretMode>(() => {
    const saved = loadInterpretPrefs(mapType);
    const preferred = saved ? saved.key : defaultKeyInterpret(mapType);
    const compat = compatibleOptions(keyBytes);
    return compat.some(o => o.value === preferred) ? preferred : "raw";
  });
  const [valInterpret, setValInterpret] = useState<InterpretMode>(() => {
    const saved = loadInterpretPrefs(mapType);
    const preferred = saved ? saved.val : "raw";
    const compat = compatibleOptions(valueBytes);
    return compat.some(o => o.value === preferred) ? preferred : "raw";
  });
  const [keyBE, setKeyBE] = useState(false);
  const [valBE, setValBE] = useState(false);
  const [page, setPage] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");
  const searchInputRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const handleKeyInterpretChange = (v: InterpretMode) => {
    setKeyInterpret(v);
    saveInterpretPrefs(mapType, v, valInterpret);
  };
  const handleValInterpretChange = (v: InterpretMode) => {
    setValInterpret(v);
    saveInterpretPrefs(mapType, keyInterpret, v);
  };

  const liveQuery = trpc.ebpf.mapDump.useQuery(
    { id: mapId },
    { staleTime: 10_000, enabled: !snapshotDump }
  );
  const data = snapshotDump ?? liveQuery.data;
  const isLoading = snapshotDump ? false : liveQuery.isLoading;
  const isError = snapshotDump ? false : liveQuery.isError;
  const isFetching = snapshotDump ? false : liveQuery.isFetching;
  const refetch = snapshotDump ? () => Promise.resolve() : liveQuery.refetch;

  const hasBtf = data?.btfDecoded ?? false;
  const effectiveMode: DisplayMode = mode === "btf" && !hasBtf ? "hex" : mode;
  const interpretDisabled = effectiveMode !== "hex";

  const handleSearchChange = useCallback((q: string) => {
    setSearchQuery(q);
    setPage(0);
  }, []);

  const filteredEntries = useMemo((): MapEntry[] => {
    if (!data?.entries) return [];
    const q = searchQuery.trim().toLowerCase();
    if (!q) return data.entries;
    return data.entries.filter(entry => {
      const k = entryKeyText(
        entry,
        effectiveMode,
        keyInterpret,
        keyBE
      ).toLowerCase();
      const v = entryValText(
        entry,
        effectiveMode,
        valInterpret,
        valBE
      ).toLowerCase();
      return k.includes(q) || v.includes(q);
    });
  }, [
    data,
    searchQuery,
    effectiveMode,
    keyInterpret,
    valInterpret,
    keyBE,
    valBE,
  ]);

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil(filteredEntries.length / PAGE_SIZE)),
    [filteredEntries]
  );

  const pageEntries = useMemo((): MapEntry[] => {
    const start = page * PAGE_SIZE;
    return filteredEntries.slice(start, start + PAGE_SIZE);
  }, [filteredEntries, page]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape" && searchQuery) {
        e.stopPropagation();
        handleSearchChange("");
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handler, true);
    return () => window.removeEventListener("keydown", handler, true);
  }, [searchQuery, handleSearchChange]);

  return (
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      onMouseDown={e => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={containerRef}
        className="w-full max-w-4xl max-h-[90vh] flex flex-col bg-[#0d1117] border border-white/10 rounded-2xl shadow-2xl overflow-hidden"
        onMouseDown={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/10 flex-shrink-0">
          <div className="flex items-center gap-3">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
              style={{
                backgroundColor: `${mapColor}22`,
                border: `1px solid ${mapColor}55`,
              }}
            >
              <Database className="w-4 h-4" style={{ color: mapColor }} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-semibold text-white">
                  {mapName}
                </span>
                <Badge
                  variant="outline"
                  className="text-[10px] px-1.5 py-0 border-white/20 text-white/50"
                >
                  #{mapId}
                </Badge>
              </div>
              <div className="text-xs mt-0.5" style={{ color: mapColor }}>
                {mapType}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {filteredEntries.length > 0 && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <button
                    className="p-1.5 rounded-lg hover:bg-white/10 text-white/40 hover:text-white transition-colors"
                    title={`Export ${filteredEntries.length} entr${filteredEntries.length === 1 ? "y" : "ies"}`}
                  >
                    <Download className="w-4 h-4" />
                  </button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="min-w-[160px]">
                  <DropdownMenuItem
                    onClick={() =>
                      exportAsJSON(
                        filteredEntries,
                        mapName,
                        effectiveMode,
                        keyInterpret,
                        valInterpret,
                        keyBE,
                        valBE
                      )
                    }
                  >
                    Export as JSON
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={() =>
                      exportAsCSV(
                        filteredEntries,
                        mapName,
                        effectiveMode,
                        keyInterpret,
                        valInterpret,
                        keyBE,
                        valBE
                      )
                    }
                  >
                    Export as CSV
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="p-1.5 rounded-lg hover:bg-white/10 text-white/40 hover:text-white transition-colors disabled:opacity-40"
              title="Refresh entries"
            >
              <RefreshCw
                className={`w-4 h-4 ${isFetching ? "animate-spin" : ""}`}
              />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-white/10 text-white/40 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="flex flex-col gap-2 px-5 py-2.5 border-b border-white/5 bg-white/[0.02] flex-shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1 bg-black/30 rounded-lg p-0.5 border border-white/10">
              {(["hex", "decimal", "btf"] as DisplayMode[]).map(m => (
                <button
                  key={m}
                  onClick={() => setMode(m)}
                  disabled={m === "btf" && !hasBtf}
                  className={`
                    px-3 py-1 rounded-md text-xs font-mono transition-all
                    ${
                      effectiveMode === m
                        ? "bg-[var(--accent)]/20 text-[var(--accent)] border border-[var(--accent)]/40"
                        : "text-white/40 hover:text-white/70 disabled:opacity-30 disabled:cursor-not-allowed"
                    }
                  `}
                  title={
                    m === "btf" && !hasBtf
                      ? "BTF info not available for this map"
                      : undefined
                  }
                >
                  {m.toUpperCase()}
                </button>
              ))}
            </div>

            {data && !data.unsupported && !data.error && (
              <div className="flex items-center gap-3 text-xs text-white/40">
                {data.btfDecoded && (
                  <span className="px-1.5 py-0.5 rounded-full bg-purple-500/20 border border-purple-500/30 text-purple-400 text-[10px]">
                    BTF decoded
                  </span>
                )}
                {data.truncated && (
                  <span className="px-1.5 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/30 text-amber-400 text-[10px]">
                    truncated to {data.maxReturned}
                  </span>
                )}
                <span>
                  {data.totalEntries} entr
                  {data.totalEntries === 1 ? "y" : "ies"}
                </span>
              </div>
            )}
          </div>

          {!interpretDisabled && (
            <div className="flex items-center gap-6 flex-wrap">
              <InterpretToggle
                label="Key as"
                value={keyInterpret}
                bigEndian={keyBE}
                onChangeBE={setKeyBE}
                onChange={handleKeyInterpretChange}
                container={containerRef.current}
                byteLen={keyBytes}
              />
              <InterpretToggle
                label="Value as"
                value={valInterpret}
                bigEndian={valBE}
                onChangeBE={setValBE}
                onChange={handleValInterpretChange}
                container={containerRef.current}
                byteLen={valueBytes}
              />
            </div>
          )}

          {data &&
            !data.unsupported &&
            !data.error &&
            data.entries.length > 0 && (
              <div className="relative flex items-center">
                <Search className="absolute left-2.5 w-3.5 h-3.5 text-white/25 pointer-events-none" />
                <input
                  ref={searchInputRef}
                  type="text"
                  value={searchQuery}
                  onChange={e => handleSearchChange(e.target.value)}
                  placeholder="Search keys or values…"
                  className="w-full pl-8 pr-8 py-1.5 bg-black/30 border border-white/10 rounded-lg text-xs font-mono text-white/70 placeholder-white/20 focus:outline-none focus:border-white/25 focus:bg-black/40 transition-colors"
                  aria-label="Filter map entries"
                />
                {searchQuery.trim() && (
                  <span className="absolute right-8 text-[10px] font-mono text-white/30 select-none">
                    {filteredEntries.length}/{data.entries.length}
                  </span>
                )}
                {searchQuery && (
                  <button
                    onClick={() => {
                      handleSearchChange("");
                      searchInputRef.current?.focus();
                    }}
                    className="absolute right-2 p-0.5 rounded text-white/25 hover:text-white/60 transition-colors"
                    title="Clear filter (Esc)"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            )}
        </div>

        <div className="flex-1 overflow-hidden flex flex-col min-h-0">
          {isLoading ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/40">
              <Loader2 className="w-8 h-8 animate-spin" />
              <span className="text-sm">Dumping map entries…</span>
            </div>
          ) : isError ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-red-400">
              <AlertTriangle className="w-8 h-8" />
              <span className="text-sm">Failed to fetch map entries</span>
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Retry
              </Button>
            </div>
          ) : data?.unsupported ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/40 px-8 text-center">
              <AlertTriangle className="w-8 h-8 text-amber-400/60" />
              <div>
                <div className="text-sm text-white/60 mb-1">
                  Map type not dumpable
                </div>
                <div className="text-xs text-white/30">{data.error}</div>
                <div className="text-xs text-white/20 mt-2">
                  Types like perf_event_array, ringbuf, and devmap are
                  kernel-internal and cannot be enumerated via bpftool.
                </div>
              </div>
            </div>
          ) : data?.error ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/40 px-8 text-center">
              <AlertTriangle className="w-8 h-8 text-red-400/60" />
              <div>
                <div className="text-sm text-white/60 mb-1">
                  Error reading map
                </div>
                <div className="text-xs font-mono text-red-400/70">
                  {data.error}
                </div>
              </div>
            </div>
          ) : data?.entries.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/30">
              <Database className="w-10 h-10 opacity-30" />
              <div className="text-sm">Map is empty</div>
              <div className="text-xs text-white/20">
                No entries found in this map
              </div>
            </div>
          ) : filteredEntries.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/30">
              <Search className="w-10 h-10 opacity-30" />
              <div className="text-sm">No matching entries</div>
              <div className="text-xs text-white/20">
                0 of {data?.entries.length ?? 0} entries match{" "}
                <span className="font-mono text-white/40">"{searchQuery}"</span>
              </div>
              <button
                onClick={() => handleSearchChange("")}
                className="mt-1 text-xs text-[var(--accent)] hover:underline"
              >
                Clear filter
              </button>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto">
              <table className="w-full border-collapse">
                <thead className="sticky top-0 z-10 bg-[#0d1117]">
                  <tr className="border-b border-white/10">
                    <th className="px-3 py-2 text-[10px] text-white/30 uppercase tracking-wider text-right w-12">
                      #
                    </th>
                    <th className="px-3 py-2 text-[10px] text-white/30 uppercase tracking-wider text-left w-1/2">
                      Key
                      {keyInterpret !== "raw" && (
                        <span className="ml-1.5 text-emerald-400/60 normal-case font-normal">
                          ({keyInterpret})
                        </span>
                      )}
                    </th>
                    <th className="px-3 py-2 text-[10px] text-white/30 uppercase tracking-wider text-left">
                      Value
                      {valInterpret !== "raw" && (
                        <span className="ml-1.5 text-emerald-400/60 normal-case font-normal">
                          ({valInterpret})
                        </span>
                      )}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {pageEntries.map((entry, i) => (
                    <EntryRow
                      key={entry.index}
                      entry={entry}
                      mode={effectiveMode}
                      keyInterpret={keyInterpret}
                      valInterpret={valInterpret}
                      keyBE={keyBE}
                      valBE={valBE}
                      index={page * PAGE_SIZE + i}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {data &&
          !data.unsupported &&
          !data.error &&
          filteredEntries.length > PAGE_SIZE && (
            <div className="flex items-center justify-between px-5 py-3 border-t border-white/10 bg-white/[0.02] flex-shrink-0">
              <button
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs text-white/50 hover:text-white hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
                Previous
              </button>
              <span className="text-xs text-white/40">
                Page {page + 1} of {totalPages}
                <span className="text-white/20 ml-2">
                  (rows {page * PAGE_SIZE + 1}–
                  {Math.min((page + 1) * PAGE_SIZE, filteredEntries.length)})
                </span>
              </span>
              <button
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs text-white/50 hover:text-white hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                Next
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
      </div>
    </div>
  );
}

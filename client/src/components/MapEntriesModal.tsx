/**
 * MapEntriesModal
 * Full-screen modal that shows the entries of a BPF map by calling
 * trpc.ebpf.mapDump.  Supports:
 *  - Hex / Decimal / BTF display modes for keys and values
 *  - Pagination (50 rows per page)
 *  - Copy-to-clipboard for individual cells
 *  - Per-CPU value expansion
 *  - Graceful unsupported / error states
 */

import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import type { MapEntry } from "../../../shared/ebpf-types";
import {
  X,
  Copy,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  Database,
  Loader2,
  RefreshCw,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

// ─── Types ────────────────────────────────────────────────────────────────────

type DisplayMode = "hex" | "decimal" | "btf";

interface MapEntriesModalProps {
  mapId: number;
  mapName: string;
  mapType: string;
  mapColor: string;
  onClose: () => void;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const PAGE_SIZE = 50;

function displayKey(entry: MapEntry, mode: DisplayMode): string {
  if (mode === "btf" && entry.keyBtf) return entry.keyBtf;
  if (mode === "decimal" && entry.keyDecimal !== null) return entry.keyDecimal;
  return entry.keyHex || entry.keyBtf || "—";
}

function displayValue(entry: MapEntry, mode: DisplayMode): string {
  if (entry.valueError) return `error: ${entry.valueError}`;
  if (mode === "btf" && entry.valueBtf) return entry.valueBtf;
  if (mode === "decimal" && entry.valueDecimal !== null) return entry.valueDecimal;
  return entry.valueHex || entry.valueBtf || "—";
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <button
      onClick={handleCopy}
      className="ml-1.5 p-0.5 rounded opacity-0 group-hover:opacity-100 hover:bg-white/10 text-white/30 hover:text-white/70 transition-all flex-shrink-0"
      title="Copy"
    >
      {copied ? (
        <span className="text-[10px] text-green-400 font-mono">✓</span>
      ) : (
        <Copy className="w-3 h-3" />
      )}
    </button>
  );
}

// ─── Entry Row ────────────────────────────────────────────────────────────────

function EntryRow({
  entry,
  mode,
  index,
}: {
  entry: MapEntry;
  mode: DisplayMode;
  index: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const hasPerCpu = entry.perCpuValues && entry.perCpuValues.length > 0;
  const keyText = displayKey(entry, mode);
  const valText = displayValue(entry, mode);

  return (
    <>
      <tr
        className={`
          border-b border-white/5 transition-colors
          ${hasPerCpu ? "cursor-pointer hover:bg-white/5" : "hover:bg-white/3"}
          ${index % 2 === 0 ? "bg-transparent" : "bg-white/[0.02]"}
        `}
        onClick={() => hasPerCpu && setExpanded(e => !e)}
      >
        {/* Index */}
        <td className="px-3 py-2 text-[11px] font-mono text-white/25 text-right w-12 select-none">
          {entry.index}
        </td>

        {/* Key */}
        <td className="px-3 py-2 max-w-0">
          <div className="flex items-center group">
            <span
              className={`
                text-xs font-mono truncate
                ${entry.keyBtf ? "text-sky-300" : "text-white/70"}
              `}
              title={keyText}
            >
              {keyText}
            </span>
            <CopyButton text={keyText} />
          </div>
        </td>

        {/* Value */}
        <td className="px-3 py-2 max-w-0">
          <div className="flex items-center group">
            {entry.valueError ? (
              <span className="text-xs font-mono text-red-400 italic truncate" title={valText}>
                {valText}
              </span>
            ) : (
              <span
                className={`
                  text-xs font-mono truncate
                  ${entry.valueBtf ? "text-emerald-300" : "text-white/70"}
                `}
                title={valText}
              >
                {valText}
              </span>
            )}
            {!entry.valueError && <CopyButton text={valText} />}
            {hasPerCpu && (
              <span className="ml-auto flex-shrink-0 text-white/30">
                {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </span>
            )}
          </div>
        </td>
      </tr>

      {/* Per-CPU expansion */}
      {hasPerCpu && expanded && (
        <tr className="bg-black/20">
          <td />
          <td colSpan={2} className="px-3 py-2">
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-1.5">
              {entry.perCpuValues!.map(cv => (
                <div
                  key={cv.cpu}
                  className="bg-white/5 rounded-md p-1.5 border border-white/10"
                >
                  <div className="text-[9px] text-white/30 mb-0.5">CPU {cv.cpu}</div>
                  <div className="text-[11px] font-mono text-white/70 truncate" title={cv.hex}>
                    {mode === "decimal" && cv.decimal !== null ? cv.decimal : cv.hex}
                  </div>
                </div>
              ))}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Main Modal ───────────────────────────────────────────────────────────────

export function MapEntriesModal({
  mapId,
  mapName,
  mapType,
  mapColor,
  onClose,
}: MapEntriesModalProps) {
  const [mode, setMode] = useState<DisplayMode>("hex");
  const [page, setPage] = useState(0);

  const { data, isLoading, isError, refetch, isFetching } =
    trpc.ebpf.mapDump.useQuery({ id: mapId }, { staleTime: 10_000 });

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil((data?.entries.length ?? 0) / PAGE_SIZE)),
    [data],
  );

  const pageEntries = useMemo((): MapEntry[] => {
    if (!data?.entries) return [];
    const start = page * PAGE_SIZE;
    return data.entries.slice(start, start + PAGE_SIZE);
  }, [data, page]);

  // Auto-select BTF mode when BTF data is available
  const hasBtf = data?.btfDecoded ?? false;
  const effectiveMode: DisplayMode = mode === "btf" && !hasBtf ? "hex" : mode;

  return (
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      onClick={e => e.target === e.currentTarget && onClose()}
    >
      <div className="w-full max-w-4xl max-h-[90vh] flex flex-col bg-[#0d1117] border border-white/10 rounded-2xl shadow-2xl overflow-hidden">

        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/10 flex-shrink-0">
          <div className="flex items-center gap-3">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
              style={{ backgroundColor: `${mapColor}22`, border: `1px solid ${mapColor}55` }}
            >
              <Database className="w-4 h-4" style={{ color: mapColor }} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-semibold text-white">{mapName}</span>
                <Badge
                  variant="outline"
                  className="text-[10px] px-1.5 py-0 border-white/20 text-white/50"
                >
                  #{mapId}
                </Badge>
              </div>
              <div className="text-xs mt-0.5" style={{ color: mapColor }}>{mapType}</div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Refresh */}
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="p-1.5 rounded-lg hover:bg-white/10 text-white/40 hover:text-white transition-colors disabled:opacity-40"
              title="Refresh entries"
            >
              <RefreshCw className={`w-4 h-4 ${isFetching ? "animate-spin" : ""}`} />
            </button>
            {/* Close */}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-white/10 text-white/40 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* ── Toolbar ────────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between px-5 py-2.5 border-b border-white/5 bg-white/[0.02] flex-shrink-0">
          {/* Display mode toggle */}
          <div className="flex items-center gap-1 bg-black/30 rounded-lg p-0.5 border border-white/10">
            {(["hex", "decimal", "btf"] as DisplayMode[]).map(m => (
              <button
                key={m}
                onClick={() => setMode(m)}
                disabled={m === "btf" && !hasBtf}
                className={`
                  px-3 py-1 rounded-md text-xs font-mono transition-all
                  ${effectiveMode === m
                    ? "bg-[var(--accent)]/20 text-[var(--accent)] border border-[var(--accent)]/40"
                    : "text-white/40 hover:text-white/70 disabled:opacity-30 disabled:cursor-not-allowed"
                  }
                `}
                title={m === "btf" && !hasBtf ? "BTF info not available for this map" : undefined}
              >
                {m.toUpperCase()}
              </button>
            ))}
          </div>

          {/* Stats */}
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
              <span>{data.totalEntries} entr{data.totalEntries === 1 ? "y" : "ies"}</span>
            </div>
          )}
        </div>

        {/* ── Body ───────────────────────────────────────────────────────── */}
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
                <div className="text-sm text-white/60 mb-1">Map type not dumpable</div>
                <div className="text-xs text-white/30">{data.error}</div>
                <div className="text-xs text-white/20 mt-2">
                  Types like perf_event_array, ringbuf, and devmap are kernel-internal
                  and cannot be enumerated via bpftool.
                </div>
              </div>
            </div>
          ) : data?.error ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/40 px-8 text-center">
              <AlertTriangle className="w-8 h-8 text-red-400/60" />
              <div>
                <div className="text-sm text-white/60 mb-1">Error reading map</div>
                <div className="text-xs font-mono text-red-400/70">{data.error}</div>
              </div>
            </div>
          ) : data?.entries.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/30">
              <Database className="w-10 h-10 opacity-30" />
              <div className="text-sm">Map is empty</div>
              <div className="text-xs text-white/20">No entries found in this map</div>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto">
              <table className="w-full border-collapse">
                <thead className="sticky top-0 z-10 bg-[#0d1117]">
                  <tr className="border-b border-white/10">
                    <th className="px-3 py-2 text-[10px] text-white/30 uppercase tracking-wider text-right w-12">#</th>
                    <th className="px-3 py-2 text-[10px] text-white/30 uppercase tracking-wider text-left w-1/2">Key</th>
                    <th className="px-3 py-2 text-[10px] text-white/30 uppercase tracking-wider text-left">Value</th>
                  </tr>
                </thead>
                <tbody>
                  {pageEntries.map((entry, i) => (
                    <EntryRow
                      key={entry.index}
                      entry={entry}
                      mode={effectiveMode}
                      index={page * PAGE_SIZE + i}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ── Pagination ─────────────────────────────────────────────────── */}
        {data && !data.unsupported && !data.error && data.entries.length > PAGE_SIZE && (
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
                (rows {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, data.entries.length)})
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

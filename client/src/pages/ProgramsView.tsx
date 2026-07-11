import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useEbpf } from "@/contexts/EbpfContext";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Activity, SortAsc, SortDesc, Filter, X, Zap, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import type { BpfProgram, ProgHistory } from "../../../shared/ebpf-types";
import { BPF_PROGRAM_TYPE_COLORS } from "../../../shared/ebpf-constants";
import Sparkline, { samplesToCallsPerSec, fmtCps, fmtNs, fmtCpu } from "@/components/Sparkline";
import { formatRelativeTime, formatFullTimestamp, useNow } from "@/lib/time";

type SortKey = "id" | "name" | "type" | "loadedAt" | "runCnt" | "bytesXlated" | "callsPerSec" | "avgLatency" | "cpuFraction";
type SortDir = "asc" | "desc";
const PROGRAM_COLUMN_STORAGE_KEY = "ebpf-viz:programs-table-column-widths";

const PROGRAM_COLUMN_ORDER = [
  "id",
  "name",
  "type",
  "callsPerSec",
  "avgLatency",
  "cpuFraction",
  "tag",
  "flags",
  "bytesXlated",
  "loadedAt",
] as const;

type ProgramColumnKey = typeof PROGRAM_COLUMN_ORDER[number];

interface ProgramColumnConfig {
  key: ProgramColumnKey;
  label: string;
  defaultWidth: number;
  minWidth: number;
  maxWidth: number;
  sortKey?: SortKey;
  className?: string;
}

type ProgramColumnWidths = Record<ProgramColumnKey, number>;

const PROGRAM_COLUMNS: Record<ProgramColumnKey, ProgramColumnConfig> = {
  id:          { key: "id",          label: "ID",          defaultWidth: 72,  minWidth: 56,  maxWidth: 120, sortKey: "id" },
  name:        { key: "name",        label: "Name",        defaultWidth: 260, minWidth: 150, maxWidth: 520, sortKey: "name" },
  type:        { key: "type",        label: "Type",        defaultWidth: 140, minWidth: 110, maxWidth: 240, sortKey: "type" },
  callsPerSec: { key: "callsPerSec", label: "Calls/s",     defaultWidth: 160, minWidth: 140, maxWidth: 260, sortKey: "callsPerSec", className: "hidden lg:table-cell" },
  avgLatency:  { key: "avgLatency",  label: "Avg Latency", defaultWidth: 140, minWidth: 120, maxWidth: 240, sortKey: "avgLatency", className: "hidden xl:table-cell" },
  cpuFraction: { key: "cpuFraction", label: "CPU%",        defaultWidth: 110, minWidth: 90,  maxWidth: 180, sortKey: "cpuFraction", className: "hidden xl:table-cell" },
  tag:         { key: "tag",         label: "Tag",         defaultWidth: 260, minWidth: 150, maxWidth: 420, className: "hidden md:table-cell" },
  flags:       { key: "flags",       label: "Flags",       defaultWidth: 160, minWidth: 120, maxWidth: 260, className: "hidden lg:table-cell" },
  bytesXlated: { key: "bytesXlated", label: "Size",        defaultWidth: 100, minWidth: 80,  maxWidth: 160, sortKey: "bytesXlated", className: "hidden xl:table-cell" },
  loadedAt:    { key: "loadedAt",    label: "Loaded",      defaultWidth: 150, minWidth: 120, maxWidth: 260, sortKey: "loadedAt", className: "hidden sm:table-cell" },
};

function getDefaultColumnWidths(): ProgramColumnWidths {
  return PROGRAM_COLUMN_ORDER.reduce((acc, key) => {
    acc[key] = PROGRAM_COLUMNS[key].defaultWidth;
    return acc;
  }, {} as ProgramColumnWidths);
}

function clampWidth(key: ProgramColumnKey, width: number): number {
  const column = PROGRAM_COLUMNS[key];
  return Math.min(column.maxWidth, Math.max(column.minWidth, Math.round(width)));
}

function readColumnWidths(): ProgramColumnWidths {
  const defaults = getDefaultColumnWidths();
  if (typeof window === "undefined") return defaults;

  try {
    const raw = window.localStorage.getItem(PROGRAM_COLUMN_STORAGE_KEY);
    if (!raw) return defaults;
    const parsed = JSON.parse(raw) as Partial<Record<ProgramColumnKey, unknown>>;
    return PROGRAM_COLUMN_ORDER.reduce((acc, key) => {
      const value = parsed[key];
      acc[key] = typeof value === "number" && Number.isFinite(value)
        ? clampWidth(key, value)
        : defaults[key];
      return acc;
    }, {} as ProgramColumnWidths);
  } catch {
    return defaults;
  }
}

function getColumnStyle(widths: ProgramColumnWidths, key: ProgramColumnKey): React.CSSProperties {
  const width = widths[key];
  return { width, minWidth: width, maxWidth: width };
}

function formatBytes(b: number) {
  if (b < 1024) return `${b}B`;
  return `${(b / 1024).toFixed(1)}KB`;
}

// Latency → color
function latencyColor(ns: number): string {
  if (ns === 0) return "#6b7280";
  if (ns < 1_000) return "#22d3ee";
  if (ns < 100_000) return "#4ade80";
  if (ns < 1_000_000) return "#f59e0b";
  return "#f87171";
}

function TruncatedProgramName({ name }: { name: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className="min-w-0 flex-1 truncate text-sm font-mono text-foreground group-hover:text-primary transition-colors"
          title={name}
        >
          {name}
        </span>
      </TooltipTrigger>
      <TooltipContent
        side="top"
        align="start"
        className="max-w-[min(520px,calc(100vw-2rem))] break-all bg-popover text-popover-foreground border border-border shadow-xl font-mono"
      >
        {name}
      </TooltipContent>
    </Tooltip>
  );
}

/** Memoized: with ~300 live programs, user interactions (search keystrokes,
 *  sort clicks, opening a panel) must not re-render every row. Poll updates
 *  still re-render rows whose prog/history object identity changed — the SSE
 *  layer preserves identity for unchanged objects, so this composes. */
const ProgramRow = React.memo(function ProgramRow({
  prog,
  history,
  maxCallsPerSec,
  tagCount,
  onTagFilter,
  now,
  columnWidths,
}: {
  prog: BpfProgram;
  history?: ProgHistory | null;
  maxCallsPerSec: number;
  tagCount: Map<string, number>;
  onTagFilter: (tag: string) => void;
  now: number;
  columnWidths: ProgramColumnWidths;
}) {
  const { setSelectedProgram } = useEbpf();
  const color = BPF_PROGRAM_TYPE_COLORS[prog.rawType] ?? BPF_PROGRAM_TYPE_COLORS.unknown;
  const displayName = prog.name || `prog_${prog.id}`;

  const callsPerSec = history?.latest?.callsPerSec ?? 0;
  const avgLatencyNs = history?.latest?.avgLatencyNs ?? 0;
  const cpuFraction = history?.latest?.cpuFraction ?? 0;
  const hasStats = callsPerSec > 0 || avgLatencyNs > 0;

  const sparkData = useMemo(() => {
    if (!history?.samples || history.samples.length < 2) return [];
    return samplesToCallsPerSec(history.samples);
  }, [history]);

  const barFraction = maxCallsPerSec > 0 ? Math.min(1, callsPerSec / maxCallsPerSec) : 0;
  const lColor = latencyColor(avgLatencyNs);

  return (
    <tr
      className="border-b border-border/40 hover:bg-accent/20 transition-colors cursor-pointer group"
      onClick={() => setSelectedProgram(prog)}
    >
      {/* ID */}
      <td
        className="px-4 py-3 font-mono text-xs text-muted-foreground"
        style={getColumnStyle(columnWidths, "id")}
      >
        {prog.id}
      </td>

      {/* Name */}
      <td className="px-4 py-3" style={getColumnStyle(columnWidths, "name")}>
        <div className="flex min-w-0 items-center gap-2">
          <span
            className="w-2 h-2 rounded-full shrink-0"
            style={{ background: color, boxShadow: `0 0 6px ${color}60` }}
          />
          <TruncatedProgramName name={displayName} />
          {prog.orphaned && (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-destructive/50 text-destructive shrink-0">
              orphaned
            </Badge>
          )}
        </div>
      </td>

      {/* Type */}
      <td className="px-4 py-3" style={getColumnStyle(columnWidths, "type")}>
        <span
          className="text-[11px] font-mono px-2 py-0.5 rounded border"
          style={{ color, borderColor: `${color}40`, background: `${color}10` }}
        >
          {prog.rawType}
        </span>
      </td>

      {/* Calls/sec — with inline bar + sparkline */}
      <td
        className="px-4 py-3 hidden lg:table-cell"
        style={getColumnStyle(columnWidths, "callsPerSec")}
      >
        {hasStats ? (
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono tabular-nums" style={{ color: lColor }}>
                {fmtCps(callsPerSec)}
              </span>
              {sparkData.length >= 2 && (
                <Sparkline data={sparkData} height={16} width={50} color={lColor} variant="calls" />
              )}
            </div>
            {/* Relative bar */}
            <div className="h-[2px] rounded-full bg-white/5 overflow-hidden w-full">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{
                  width: `${barFraction * 100}%`,
                  background: lColor,
                  minWidth: barFraction > 0 ? 2 : 0,
                }}
              />
            </div>
          </div>
        ) : (
          <span className="text-xs text-muted-foreground/40">—</span>
        )}
      </td>

      {/* Avg Latency */}
      <td
        className="px-4 py-3 hidden xl:table-cell"
        style={getColumnStyle(columnWidths, "avgLatency")}
      >
        {avgLatencyNs > 0 ? (
          <span className="text-xs font-mono tabular-nums" style={{ color: lColor }}>
            {fmtNs(avgLatencyNs)}
          </span>
        ) : (
          <span className="text-xs text-muted-foreground/40">—</span>
        )}
      </td>

      {/* CPU% */}
      <td
        className="px-4 py-3 hidden xl:table-cell"
        style={getColumnStyle(columnWidths, "cpuFraction")}
      >
        {cpuFraction > 0 ? (
          <span className="text-xs font-mono tabular-nums text-violet-400">
            {fmtCpu(cpuFraction)}
          </span>
        ) : (
          <span className="text-xs text-muted-foreground/40">—</span>
        )}
      </td>

      {/* Tag */}
      <td
        className="px-4 py-3 text-xs font-mono text-muted-foreground hidden md:table-cell"
        style={getColumnStyle(columnWidths, "tag")}
      >
        <div className="flex min-w-0 items-center gap-1.5 flex-wrap">
          <span className="min-w-0 truncate">{prog.tag}</span>
          {(tagCount.get(prog.tag) ?? 1) > 1 && (
            <button
              onClick={e => { e.stopPropagation(); onTagFilter(prog.tag); }}
              title={`${tagCount.get(prog.tag)} programs share this bytecode — click to filter`}
              className="inline-flex items-center gap-0.5 text-[10px] font-sans px-1.5 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 transition-colors cursor-pointer"
            >
              ×{tagCount.get(prog.tag)} clones
            </button>
          )}
        </div>
      </td>

      {/* Flags */}
      <td
        className="px-4 py-3 text-xs text-muted-foreground hidden lg:table-cell"
        style={getColumnStyle(columnWidths, "flags")}
      >
        <div className="flex gap-1 flex-wrap">
          {prog.jited && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">JIT</span>
          )}
          {prog.gplCompatible && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">GPL</span>
          )}
          {prog.btfId !== undefined && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/10 text-violet-400 border border-violet-500/20">BTF</span>
          )}
        </div>
      </td>

      {/* Size */}
      <td
        className="px-4 py-3 text-xs font-mono text-muted-foreground hidden xl:table-cell"
        style={getColumnStyle(columnWidths, "bytesXlated")}
      >
        {formatBytes(prog.bytesXlated)}
      </td>

      {/* Loaded */}
      <td
        className="px-4 py-3 text-xs text-muted-foreground hidden sm:table-cell"
        style={getColumnStyle(columnWidths, "loadedAt")}
      >
        <span title={formatFullTimestamp(prog.loadedAt)}>
          {formatRelativeTime(prog.loadedAt, now)}
        </span>
      </td>
    </tr>
  );
});

export default function ProgramsView() {
  const { snapshot, filteredPrograms, typeFilter, setTypeFilter, historyMap, statsEnabled } = useEbpf();
  const [sortKey, setSortKey] = useState<SortKey>("id");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [tagFilter, setTagFilter] = useState<string | null>(null);
  const [orphanFilter, setOrphanFilter] = useState(false);
  const [columnWidths, setColumnWidths] = useState<ProgramColumnWidths>(readColumnWidths);
  const resizeCleanupRef = useRef<(() => void) | null>(null);
  const now = useNow(30_000); // refresh relative times every 30s

  // Compute tag frequency map across ALL programs (not just filtered)
  const tagCount = useMemo(() => {
    const m = new Map<string, number>();
    if (!snapshot) return m;
    for (const p of snapshot.programs) m.set(p.tag, (m.get(p.tag) ?? 0) + 1);
    return m;
  }, [snapshot]);

  // Programs visible after type filter + tag filter + orphan filter
  const visiblePrograms = useMemo(() => {
    let progs = filteredPrograms;
    if (tagFilter) progs = progs.filter(p => p.tag === tagFilter);
    if (orphanFilter) progs = progs.filter(p => p.orphaned);
    return progs;
  }, [filteredPrograms, tagFilter, orphanFilter]);

  // Compute max calls/sec across all visible programs for bar scaling
  // NOTE: must be before any early returns to satisfy Rules of Hooks
  const maxCallsPerSec = useMemo(() => {
    return visiblePrograms.reduce((max, p) => {
      const h = historyMap.get(p.id);
      return Math.max(max, h?.latest?.callsPerSec ?? 0);
    }, 0);
  }, [visiblePrograms, historyMap]);

  const tableMinWidth = useMemo(
    () => PROGRAM_COLUMN_ORDER.reduce((total, key) => total + columnWidths[key], 0),
    [columnWidths]
  );

  useEffect(() => {
    try {
      window.localStorage.setItem(PROGRAM_COLUMN_STORAGE_KEY, JSON.stringify(columnWidths));
    } catch {
      // Ignore persistence failures, e.g. private browsing or quota errors.
    }
  }, [columnWidths]);

  useEffect(() => {
    return () => {
      resizeCleanupRef.current?.();
    };
  }, []);

  const resizeColumnBy = useCallback((key: ProgramColumnKey, delta: number) => {
    setColumnWidths(prev => ({
      ...prev,
      [key]: clampWidth(key, prev[key] + delta),
    }));
  }, []);

  const startColumnResize = useCallback((key: ProgramColumnKey, event: React.PointerEvent<HTMLButtonElement>) => {
    event.preventDefault();
    event.stopPropagation();
    resizeCleanupRef.current?.();

    const startX = event.clientX;
    const startWidth = columnWidths[key];
    const previousCursor = document.body.style.cursor;
    const previousUserSelect = document.body.style.userSelect;

    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    const handleMove = (moveEvent: PointerEvent) => {
      setColumnWidths(prev => ({
        ...prev,
        [key]: clampWidth(key, startWidth + moveEvent.clientX - startX),
      }));
    };

    const cleanup = () => {
      document.removeEventListener("pointermove", handleMove);
      document.removeEventListener("pointerup", cleanup);
      document.body.style.cursor = previousCursor;
      document.body.style.userSelect = previousUserSelect;
      resizeCleanupRef.current = null;
    };

    resizeCleanupRef.current = cleanup;
    document.addEventListener("pointermove", handleMove);
    document.addEventListener("pointerup", cleanup);
  }, [columnWidths]);

  if (!snapshot) {
    return <div className="flex items-center justify-center h-full"><p className="text-muted-foreground">Loading…</p></div>;
  }

  const allTypes = Array.from(new Set(snapshot.programs.map(p => p.rawType))).sort();
  const sharedTagCount = Array.from(tagCount.values()).filter(c => c > 1).length;
  const orphanedCount = snapshot.programs.filter(p => p.orphaned).length;

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortKey(key); setSortDir("asc"); }
  };

  const sorted = [...visiblePrograms].sort((a, b) => {
    let av: string | number = 0, bv: string | number = 0;
    const ha = historyMap.get(a.id);
    const hb = historyMap.get(b.id);
    switch (sortKey) {
      case "id": av = a.id; bv = b.id; break;
      case "name": av = a.name; bv = b.name; break;
      case "type": av = a.rawType; bv = b.rawType; break;
      case "loadedAt": av = a.loadedAt; bv = b.loadedAt; break;
      case "runCnt": av = a.runCnt ?? -1; bv = b.runCnt ?? -1; break;
      case "bytesXlated": av = a.bytesXlated; bv = b.bytesXlated; break;
      case "callsPerSec": av = ha?.latest?.callsPerSec ?? -1; bv = hb?.latest?.callsPerSec ?? -1; break;
      case "avgLatency": av = ha?.latest?.avgLatencyNs ?? -1; bv = hb?.latest?.avgLatencyNs ?? -1; break;
      case "cpuFraction": av = ha?.latest?.cpuFraction ?? -1; bv = hb?.latest?.cpuFraction ?? -1; break;
    }
    const cmp = av < bv ? -1 : av > bv ? 1 : 0;
    return sortDir === "asc" ? cmp : -cmp;
  });

  function SortIcon({ col }: { col: SortKey }) {
    if (sortKey !== col) return <SortAsc size={11} className="opacity-30" />;
    return sortDir === "asc" ? <SortAsc size={11} className="text-primary" /> : <SortDesc size={11} className="text-primary" />;
  }

  function ColHeader({ columnKey }: { columnKey: ProgramColumnKey }) {
    const column = PROGRAM_COLUMNS[columnKey];
    const sortable = column.sortKey !== undefined;

    return (
      <th
        className={cn(
          "relative px-4 py-3 text-left text-xs font-semibold text-muted-foreground select-none transition-colors",
          sortable && "cursor-pointer hover:text-foreground",
          column.className
        )}
        style={getColumnStyle(columnWidths, columnKey)}
        onClick={sortable ? () => handleSort(column.sortKey!) : undefined}
      >
        <div className="flex min-w-0 items-center gap-1 pr-2">
          <span className="truncate">{column.label}</span>
          {sortable && <SortIcon col={column.sortKey!} />}
        </div>
        <button
          type="button"
          aria-label={`Resize ${column.label} column`}
          className="absolute right-0 top-0 h-full w-2 cursor-col-resize touch-none border-r border-transparent hover:border-primary/60 focus-visible:border-primary focus-visible:outline-none"
          onClick={e => e.stopPropagation()}
          onPointerDown={e => startColumnResize(columnKey, e)}
          onKeyDown={e => {
            if (e.key === "ArrowLeft") {
              e.preventDefault();
              resizeColumnBy(columnKey, -16);
            } else if (e.key === "ArrowRight") {
              e.preventDefault();
              resizeColumnBy(columnKey, 16);
            }
          }}
        />
      </th>
    );
  }

  return (
    <div className="p-6 space-y-4 max-w-full">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
            <Activity size={20} className="text-primary" />
            All Programs
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            {sorted.length} of {snapshot.stats.total} programs{tagFilter && ` · filtered to tag ${tagFilter.slice(0, 8)}…`}{orphanFilter && " · orphaned only"}
            {statsEnabled && (
              <span className="ml-2 text-cyan-400 text-xs inline-flex items-center gap-1">
                <Zap size={10} />
                runtime stats active
              </span>
            )}
          </p>
        </div>
      </div>

      {/* Type filter chips */}
      <div className="flex flex-wrap gap-2 items-center">
        <Filter size={13} className="text-muted-foreground" />
        <span className="text-xs text-muted-foreground">Filter by type:</span>
        {allTypes.map(type => {
          const color = BPF_PROGRAM_TYPE_COLORS[type] ?? BPF_PROGRAM_TYPE_COLORS.unknown;
          const active = typeFilter.includes(type);
          return (
            <button
              key={type}
              onClick={() => setTypeFilter(
                active ? typeFilter.filter(t => t !== type) : [...typeFilter, type]
              )}
              className="text-[11px] font-mono px-2 py-0.5 rounded border transition-all"
              style={{
                color: active ? color : "oklch(0.55 0.01 240)",
                borderColor: active ? `${color}60` : "oklch(0.22 0.015 240)",
                background: active ? `${color}15` : "transparent",
              }}
            >
              {type}
            </button>
          );
        })}
        {typeFilter.length > 0 && (
          <Button
            variant="ghost"
            size="sm"
            className="h-6 px-2 text-xs text-muted-foreground"
            onClick={() => setTypeFilter([])}
          >
            <X size={11} className="mr-1" />
            Clear
          </Button>
        )}
        {orphanedCount > 0 && (
          <button
            onClick={() => setOrphanFilter(v => !v)}
            title={orphanFilter ? "Show all programs" : `Show only orphaned programs (${orphanedCount})`}
            className="ml-auto inline-flex items-center gap-1.5 text-[11px] font-medium px-2.5 py-0.5 rounded border transition-all"
            style={orphanFilter ? {
              color: "#f87171",
              borderColor: "#f8717160",
              background: "#f8717115",
            } : {
              color: "oklch(0.55 0.01 240)",
              borderColor: "oklch(0.22 0.015 240)",
              background: "transparent",
            }}
          >
            <AlertTriangle size={11} />
            Orphaned only
            <span className="font-mono opacity-70">({orphanedCount})</span>
          </button>
        )}
      </div>
      {/* Shared-tag filter indicator */}
      {(tagFilter || sharedTagCount > 0) && (
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs text-muted-foreground">Shared bytecode:</span>
          {tagFilter ? (
            <button
              onClick={() => setTagFilter(null)}
              className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded border border-amber-500/60 bg-amber-500/15 text-amber-400 hover:bg-amber-500/25 transition-colors"
            >
              tag {tagFilter.slice(0, 8)}… ×{tagCount.get(tagFilter) ?? 0} clones
              <X size={10} className="ml-0.5" />
            </button>
          ) : (
            <span className="text-xs text-amber-400/70">{sharedTagCount} tag{sharedTagCount !== 1 ? "s" : ""} with duplicate bytecode — click ×N clones in the Tag column to filter</span>
          )}
        </div>
      )}

      {/* Table */}
      <div className="glass rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table
            className="w-full"
            style={{ minWidth: tableMinWidth, tableLayout: "fixed" }}
          >
            <thead>
              <tr className="border-b border-border/60 bg-muted/20">
                {PROGRAM_COLUMN_ORDER.map(columnKey => (
                  <ColHeader key={columnKey} columnKey={columnKey} />
                ))}
              </tr>
            </thead>
            <tbody>
              {sorted.map(prog => (
                <ProgramRow
                  key={prog.id}
                  prog={prog}
                  history={historyMap.get(prog.id)}
                  maxCallsPerSec={maxCallsPerSec}
                  tagCount={tagCount}
                  onTagFilter={setTagFilter}
                  now={now}
                  columnWidths={columnWidths}
                />
              ))}
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={PROGRAM_COLUMN_ORDER.length} className="px-4 py-12 text-center text-muted-foreground text-sm">
                    No programs match the current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

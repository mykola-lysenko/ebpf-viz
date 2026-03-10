import React, { useState, useMemo } from "react";
import { useEbpf } from "@/contexts/EbpfContext";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Activity, SortAsc, SortDesc, Filter, X, Zap } from "lucide-react";
import { cn } from "@/lib/utils";
import type { BpfProgram, ProgHistory } from "../../../shared/ebpf-types";
import Sparkline, { samplesToCallsPerSec, fmtCps, fmtNs, fmtCpu } from "@/components/Sparkline";

type SortKey = "id" | "name" | "type" | "loadedAt" | "runCnt" | "bytesXlated" | "callsPerSec" | "avgLatency" | "cpuFraction";
type SortDir = "asc" | "desc";

const TYPE_COLORS_MAP: Record<string, string> = {
  xdp:            "#00d4ff",
  sched_cls:      "#7c3aed",
  sched_act:      "#6d28d9",
  kprobe:         "#f59e0b",
  kretprobe:      "#d97706",
  fentry:         "#b45309",
  fexit:          "#92400e",
  tracepoint:     "#10b981",
  raw_tracepoint: "#059669",
  perf_event:     "#f97316",
  cgroup_skb:     "#3b82f6",
  cgroup_device:  "#2563eb",
  cgroup_sock:    "#1d4ed8",
  sock_ops:       "#8b5cf6",
  sk_skb:         "#a78bfa",
  sk_msg:         "#c4b5fd",
  sk_lookup:      "#7c3aed",
  flow_dissector: "#ec4899",
  netfilter:      "#f43f5e",
  lsm:            "#ef4444",
};

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

function ProgramRow({
  prog,
  history,
  maxCallsPerSec,
}: {
  prog: BpfProgram;
  history?: ProgHistory | null;
  maxCallsPerSec: number;
}) {
  const { setSelectedProgram } = useEbpf();
  const color = TYPE_COLORS_MAP[prog.rawType] ?? "#6b7280";

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
      <td className="px-4 py-3 font-mono text-xs text-muted-foreground w-16">{prog.id}</td>

      {/* Name */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <span
            className="w-2 h-2 rounded-full shrink-0"
            style={{ background: color, boxShadow: `0 0 6px ${color}60` }}
          />
          <span className="text-sm font-mono text-foreground group-hover:text-primary transition-colors truncate max-w-[180px]">
            {prog.name || `prog_${prog.id}`}
          </span>
          {prog.orphaned && (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-destructive/50 text-destructive shrink-0">
              orphaned
            </Badge>
          )}
        </div>
      </td>

      {/* Type */}
      <td className="px-4 py-3">
        <span
          className="text-[11px] font-mono px-2 py-0.5 rounded border"
          style={{ color, borderColor: `${color}40`, background: `${color}10` }}
        >
          {prog.rawType}
        </span>
      </td>

      {/* Calls/sec — with inline bar + sparkline */}
      <td className="px-4 py-3 hidden lg:table-cell min-w-[140px]">
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
      <td className="px-4 py-3 hidden xl:table-cell">
        {avgLatencyNs > 0 ? (
          <span className="text-xs font-mono tabular-nums" style={{ color: lColor }}>
            {fmtNs(avgLatencyNs)}
          </span>
        ) : (
          <span className="text-xs text-muted-foreground/40">—</span>
        )}
      </td>

      {/* CPU% */}
      <td className="px-4 py-3 hidden xl:table-cell">
        {cpuFraction > 0 ? (
          <span className="text-xs font-mono tabular-nums text-violet-400">
            {fmtCpu(cpuFraction)}
          </span>
        ) : (
          <span className="text-xs text-muted-foreground/40">—</span>
        )}
      </td>

      {/* Tag */}
      <td className="px-4 py-3 text-xs font-mono text-muted-foreground hidden md:table-cell">
        {prog.tag}
      </td>

      {/* Flags */}
      <td className="px-4 py-3 text-xs text-muted-foreground hidden lg:table-cell">
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
      <td className="px-4 py-3 text-xs font-mono text-muted-foreground hidden xl:table-cell">
        {formatBytes(prog.bytesXlated)}
      </td>

      {/* Loaded */}
      <td className="px-4 py-3 text-xs text-muted-foreground hidden sm:table-cell">
        {prog.loadedAt ? new Date(prog.loadedAt * 1000).toLocaleTimeString() : "—"}
      </td>
    </tr>
  );
}

export default function ProgramsView() {
  const { snapshot, filteredPrograms, typeFilter, setTypeFilter, historyMap, statsEnabled } = useEbpf();
  const [sortKey, setSortKey] = useState<SortKey>("id");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  // Compute max calls/sec across all visible programs for bar scaling
  // NOTE: must be before any early returns to satisfy Rules of Hooks
  const maxCallsPerSec = useMemo(() => {
    return filteredPrograms.reduce((max, p) => {
      const h = historyMap.get(p.id);
      return Math.max(max, h?.latest?.callsPerSec ?? 0);
    }, 0);
  }, [filteredPrograms, historyMap]);

  if (!snapshot) {
    return <div className="flex items-center justify-center h-full"><p className="text-muted-foreground">Loading…</p></div>;
  }

  const allTypes = Array.from(new Set(snapshot.programs.map(p => p.rawType))).sort();

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortKey(key); setSortDir("asc"); }
  };

  const sorted = [...filteredPrograms].sort((a, b) => {
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

  function ColHeader({ col, label, className }: { col: SortKey; label: string; className?: string }) {
    return (
      <th
        className={cn("px-4 py-3 text-left text-xs font-semibold text-muted-foreground cursor-pointer hover:text-foreground transition-colors select-none", className)}
        onClick={() => handleSort(col)}
      >
        <div className="flex items-center gap-1">
          {label}
          <SortIcon col={col} />
        </div>
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
            {sorted.length} of {snapshot.stats.total} programs
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
          const color = TYPE_COLORS_MAP[type] ?? "#6b7280";
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
      </div>

      {/* Table */}
      <div className="glass rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border/60 bg-muted/20">
                <ColHeader col="id" label="ID" className="w-16" />
                <ColHeader col="name" label="Name" />
                <ColHeader col="type" label="Type" />
                <ColHeader col="callsPerSec" label="Calls/s" className="hidden lg:table-cell" />
                <ColHeader col="avgLatency" label="Avg Latency" className="hidden xl:table-cell" />
                <ColHeader col="cpuFraction" label="CPU%" className="hidden xl:table-cell" />
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground hidden md:table-cell">Tag</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground hidden lg:table-cell">Flags</th>
                <ColHeader col="bytesXlated" label="Size" className="hidden xl:table-cell" />
                <ColHeader col="loadedAt" label="Loaded" className="hidden sm:table-cell" />
              </tr>
            </thead>
            <tbody>
              {sorted.map(prog => (
                <ProgramRow
                  key={prog.id}
                  prog={prog}
                  history={historyMap.get(prog.id)}
                  maxCallsPerSec={maxCallsPerSec}
                />
              ))}
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={10} className="px-4 py-12 text-center text-muted-foreground text-sm">
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

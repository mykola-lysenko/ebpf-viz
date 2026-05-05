import React, { useState, useMemo } from "react";
import { useEbpf } from "@/contexts/EbpfContext";
import { ProgList } from "@/components/ProgBadge";
import { Badge } from "@/components/ui/badge";
import { Cpu, ChevronDown, ChevronRight, Zap } from "lucide-react";
import { cn } from "@/lib/utils";
import type { KernelAttachmentZone, BpfProgram, KernelZone } from "../../../shared/ebpf-types";
import Sparkline, { samplesToCallsPerSec, fmtCps } from "@/components/Sparkline";

const ZONE_ICONS: Record<string, string> = {
  xdp:            "⚡",
  tc_ingress:     "↓",
  tc_egress:      "↑",
  socket_filter:  "🔌",
  kprobe:         "🔍",
  tracepoint:     "📍",
  perf_event:     "📊",
  cgroup:         "📁",
  flow_dissector: "🔀",
  netfilter:      "🛡",
  sk_ops:         "🔧",
  other:          "⚙",
};

const ZONE_COLORS: Record<string, string> = {
  xdp:            "#00d4ff",
  tc_ingress:     "#7c3aed",
  tc_egress:      "#6d28d9",
  socket_filter:  "#a78bfa",
  kprobe:         "#f59e0b",
  tracepoint:     "#10b981",
  perf_event:     "#f97316",
  cgroup:         "#3b82f6",
  flow_dissector: "#ec4899",
  netfilter:      "#f43f5e",
  sk_ops:         "#8b5cf6",
  other:          "#6b7280",
};

const PACKET_FLOW_ZONES: KernelZone[] = ["xdp", "tc_ingress", "netfilter", "socket_filter", "tc_egress"];
const SYSTEM_ZONES: KernelZone[] = ["kprobe", "tracepoint", "perf_event", "cgroup", "flow_dissector", "sk_ops", "other"];

// ── Zone heat helpers ────────────────────────────────────────────────────────

/** Sum calls/sec across all programs in a zone */
function zoneCallsPerSec(
  programs: BpfProgram[],
  historyMap: Map<number, { latest?: { callsPerSec: number } | null }>
): number {
  return programs.reduce((sum, p) => sum + (historyMap.get(p.id)?.latest?.callsPerSec ?? 0), 0);
}

/** Aggregate sparkline: sum of calls/sec per sample across all programs in zone */
function zoneSparkData(
  programs: BpfProgram[],
  historyMap: Map<number, { samples?: Array<{ ts: number; runCnt: number }> } | null>
): number[] {
  const allSeries = programs
    .map(p => {
      const h = historyMap.get(p.id);
      if (!h?.samples || h.samples.length < 2) return [];
      return samplesToCallsPerSec(h.samples);
    })
    .filter(s => s.length > 0);

  if (allSeries.length === 0) return [];

  const maxLen = Math.max(...allSeries.map(s => s.length));
  const result: number[] = [];
  for (let i = 0; i < maxLen; i++) {
    result.push(allSeries.reduce((sum, s) => sum + (s[i] ?? 0), 0));
  }
  return result;
}

// ── ZoneCard ─────────────────────────────────────────────────────────────────

function ZoneCard({
  zone,
  expanded,
  onToggle,
  heatFraction,
  totalCps,
  sparkData,
}: {
  zone: KernelAttachmentZone;
  expanded: boolean;
  onToggle: () => void;
  heatFraction: number;
  totalCps: number;
  sparkData: number[];
}) {
  const { historyMap } = useEbpf();
  const color = ZONE_COLORS[zone.zone] ?? "#6b7280";
  const icon = ZONE_ICONS[zone.zone] ?? "⚙";
  const hasProgs = zone.programs.length > 0;
  const isHot = heatFraction > 0.01;

  // Heatmap glow intensity: 0 → dark, 1 → full glow
  const glowOpacity = Math.min(1, heatFraction * 2.5);
  const borderOpacity = hasProgs ? (isHot ? 0.7 : 0.5) : 0.2;

  return (
    <div
      className={cn("kernel-zone", hasProgs && "has-progs")}
      style={{
        borderColor: `${color}${Math.round(borderOpacity * 255).toString(16).padStart(2, "0")}`,
        boxShadow: isHot ? `0 0 ${Math.round(glowOpacity * 20)}px ${color}${Math.round(glowOpacity * 0.35 * 255).toString(16).padStart(2, "0")}` : undefined,
        transition: "box-shadow 0.8s ease, border-color 0.8s ease",
      }}
    >
      {/* Heatmap background overlay */}
      {isHot && (
        <div
          className="absolute inset-0 rounded-xl pointer-events-none"
          style={{
            background: `radial-gradient(ellipse at 50% 0%, ${color}${Math.round(glowOpacity * 0.18 * 255).toString(16).padStart(2, "0")} 0%, transparent 70%)`,
            transition: "opacity 0.8s ease",
          }}
        />
      )}

      <button
        className="w-full flex items-start gap-3 text-left relative"
        onClick={onToggle}
      >
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center text-lg shrink-0 mt-0.5"
          style={{
            background: `${color}${isHot ? "22" : "15"}`,
            border: `1px solid ${color}${isHot ? "50" : "30"}`,
            boxShadow: isHot ? `0 0 8px ${color}40` : undefined,
          }}
        >
          {icon}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-sm font-semibold text-foreground">{zone.label}</span>
            <Badge
              variant="outline"
              className="text-[10px] px-1.5 py-0"
              style={{
                borderColor: hasProgs ? `${color}50` : undefined,
                color: hasProgs ? color : undefined,
              }}
            >
              {zone.programs.length}
            </Badge>
            {/* Live calls/sec badge */}
            {isHot && (
              <span
                className="text-[9px] font-mono flex items-center gap-0.5"
                style={{ color }}
              >
                <Zap size={8} />
                {fmtCps(totalCps)}
              </span>
            )}
            <span className="text-[10px] text-muted-foreground ml-auto">{zone.osiLayer}</span>
          </div>
          <p className="text-xs text-muted-foreground leading-snug">{zone.description}</p>

          {/* Zone-level sparkline */}
          {sparkData.length >= 2 && (
            <div className="mt-1.5">
              <Sparkline
                data={sparkData}
                height={18}
                width="100%"
                color={color}
                variant="calls"
              />
            </div>
          )}
        </div>
        <div className="text-muted-foreground shrink-0 mt-1">
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </div>
      </button>

      {expanded && hasProgs && (
        <div className="mt-3 pt-3 border-t border-border/50 relative">
          <ProgList
            programs={zone.programs}
            maxVisible={20}
            histories={historyMap}
          />
        </div>
      )}

      {expanded && !hasProgs && (
        <div className="mt-3 pt-3 border-t border-border/50 relative">
          <p className="text-xs text-muted-foreground italic">No programs attached to this zone.</p>
        </div>
      )}
    </div>
  );
}

// ── Kernel diagram ────────────────────────────────────────────────────────────

function ZoneNode({
  zoneKey,
  zoneMap,
  historyMap,
  maxZoneCps,
}: {
  zoneKey: string;
  zoneMap: Map<string, KernelAttachmentZone>;
  historyMap: Map<number, { latest?: { callsPerSec: number } | null }>;
  maxZoneCps: number;
}) {
  const zone = zoneMap.get(zoneKey as KernelZone);
  if (!zone) return null;
  const color = ZONE_COLORS[zoneKey] ?? "#6b7280";
  const hasProgs = zone.programs.length > 0;
  const cps = zoneCallsPerSec(zone.programs, historyMap);
  const heat = maxZoneCps > 0 ? Math.min(1, cps / maxZoneCps) : 0;
  const isHot = heat > 0.01;

  return (
    <div
      className="flex flex-col items-center gap-1 shrink-0 p-3 rounded-xl border transition-all min-w-[90px]"
      style={{
        borderColor: hasProgs ? `${color}50` : "oklch(0.22 0.015 240 / 0.6)",
        background: isHot
          ? `linear-gradient(180deg, ${color}${Math.round(heat * 0.25 * 255).toString(16).padStart(2, "0")} 0%, ${color}10 100%)`
          : hasProgs ? `${color}10` : "oklch(0.13 0.015 240 / 0.5)",
        boxShadow: isHot ? `0 0 ${Math.round(heat * 16)}px ${color}${Math.round(heat * 0.4 * 255).toString(16).padStart(2, "0")}` : undefined,
        transition: "background 0.8s ease, box-shadow 0.8s ease",
      }}
    >
      <span className="text-xl">{ZONE_ICONS[zoneKey]}</span>
      <span className="text-[11px] font-semibold text-center leading-tight" style={{ color: hasProgs ? color : undefined }}>
        {zone.label}
      </span>
      <Badge
        variant="outline"
        className="text-[10px] px-1.5 py-0"
        style={{ borderColor: `${color}40`, color: hasProgs ? color : undefined }}
      >
        {zone.programs.length}
      </Badge>
      {isHot && (
        <span className="text-[9px] font-mono tabular-nums" style={{ color }}>
          {fmtCps(cps)}
        </span>
      )}
    </div>
  );
}

function KernelDiagram({
  zones,
  historyMap,
  maxZoneCps,
}: {
  zones: KernelAttachmentZone[];
  historyMap: Map<number, { latest?: { callsPerSec: number } | null }>;
  maxZoneCps: number;
}) {
  const zoneMap = new Map(zones.map(z => [z.zone, z]));

  return (
    <div className="relative">
      <div className="rounded-2xl border border-border/60 p-6 relative"
        style={{ background: "oklch(0.11 0.012 240 / 0.6)" }}>
        <div className="absolute -top-3 left-6">
          <span className="bg-background px-3 text-xs font-mono font-semibold text-muted-foreground border border-border rounded-md py-0.5">
            Linux Kernel
          </span>
        </div>

        {/* Packet path */}
        <div className="mb-6">
          <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-2">
            <span className="w-4 h-px bg-border inline-block" />
            Packet Processing Path
            <span className="flex-1 h-px bg-border inline-block" />
          </div>
          <div className="flex items-center gap-2 overflow-x-auto pb-2">
            {PACKET_FLOW_ZONES.map((zoneKey, idx) => (
              <React.Fragment key={zoneKey}>
                <ZoneNode zoneKey={zoneKey} zoneMap={zoneMap} historyMap={historyMap} maxZoneCps={maxZoneCps} />
                {idx < PACKET_FLOW_ZONES.length - 1 && (
                  <div className="text-muted-foreground text-lg shrink-0">→</div>
                )}
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* System observability */}
        <div>
          <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-2">
            <span className="w-4 h-px bg-border inline-block" />
            System Observability & Control
            <span className="flex-1 h-px bg-border inline-block" />
          </div>
          <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-7 gap-2">
            {SYSTEM_ZONES.map(zoneKey => (
              <ZoneNode key={zoneKey} zoneKey={zoneKey} zoneMap={zoneMap} historyMap={historyMap} maxZoneCps={maxZoneCps} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main view ─────────────────────────────────────────────────────────────────

export default function KernelView() {
  const { snapshot, filteredPrograms, searchQuery, historyMap } = useEbpf();
  const [expandedZones, setExpandedZones] = useState<Set<string>>(new Set());

  const toggleZone = (zone: string) => {
    setExpandedZones(prev => {
      const next = new Set(prev);
      if (next.has(zone)) next.delete(zone);
      else next.add(zone);
      return next;
    });
  };

  // Filter zones based on search — computed before hooks so they run unconditionally
  const zones = useMemo(() => {
    if (!snapshot) return [];
    return searchQuery
      ? snapshot.kernelZones.map(z => ({
          ...z,
          programs: z.programs.filter(p => filteredPrograms.some(fp => fp.id === p.id)),
        })).filter(z => z.programs.length > 0)
      : snapshot.kernelZones;
  }, [snapshot, searchQuery, filteredPrograms]);

  // Compute per-zone heat data
  const zoneHeatData = useMemo(() => {
    return zones.map(z => ({
      zone: z.zone,
      cps: zoneCallsPerSec(z.programs, historyMap),
      sparkData: zoneSparkData(z.programs, historyMap),
    }));
  }, [zones, historyMap]);

  const maxZoneCps = useMemo(
    () => Math.max(0, ...zoneHeatData.map(z => z.cps)),
    [zoneHeatData]
  );

  if (!snapshot) {
    return <div className="flex items-center justify-center h-full"><p className="text-muted-foreground">Loading…</p></div>;
  }

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
          <Cpu size={20} className="text-primary" />
          Kernel Attachment Points
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          eBPF programs organized by kernel hook type
          {maxZoneCps > 0 && (
            <span className="ml-2 text-cyan-400 text-xs inline-flex items-center gap-1">
              <Zap size={10} />
              live activity — zones glow with CPU heat
            </span>
          )}
        </p>
      </div>

      {/* Visual diagram with heatmap */}
      <KernelDiagram
        zones={snapshot.kernelZones}
        historyMap={historyMap}
        maxZoneCps={maxZoneCps}
      />

      {/* Detailed zone list */}
      <div>
        <h2 className="text-sm font-semibold text-foreground mb-3">Zone Details</h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {zones.map(zone => {
            const heat = zoneHeatData.find(z => z.zone === zone.zone);
            const heatFraction = maxZoneCps > 0 ? Math.min(1, (heat?.cps ?? 0) / maxZoneCps) : 0;
            return (
              <ZoneCard
                key={zone.zone}
                zone={zone}
                expanded={expandedZones.has(zone.zone)}
                onToggle={() => toggleZone(zone.zone)}
                heatFraction={heatFraction}
                totalCps={heat?.cps ?? 0}
                sparkData={heat?.sparkData ?? []}
              />
            );
          })}
          {zones.length === 0 && (
            <div className="col-span-2 text-center py-12 text-muted-foreground">
              No programs match the current filter.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

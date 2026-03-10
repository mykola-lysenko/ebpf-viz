import React, { useState } from "react";
import { useEbpf } from "@/contexts/EbpfContext";
import { ProgList } from "@/components/ProgBadge";
import { Badge } from "@/components/ui/badge";
import { Cpu, ChevronDown, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import type { KernelAttachmentZone, BpfProgram, KernelZone } from "../../../shared/ebpf-types";

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

// Kernel diagram: packet flow path
const PACKET_FLOW_ZONES: KernelZone[] = ["xdp", "tc_ingress", "netfilter", "socket_filter", "tc_egress"];
const SYSTEM_ZONES: KernelZone[] = ["kprobe", "tracepoint", "perf_event", "cgroup", "flow_dissector", "sk_ops", "other"];

function ZoneCard({ zone, expanded, onToggle }: {
  zone: KernelAttachmentZone;
  expanded: boolean;
  onToggle: () => void;
}) {
  const color = ZONE_COLORS[zone.zone] ?? "#6b7280";
  const icon = ZONE_ICONS[zone.zone] ?? "⚙";
  const hasProgs = zone.programs.length > 0;

  return (
    <div
      className={cn("kernel-zone", hasProgs && "has-progs")}
      style={hasProgs ? { borderColor: `${color}50` } : {}}
    >
      <button
        className="w-full flex items-start gap-3 text-left"
        onClick={onToggle}
      >
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center text-lg shrink-0 mt-0.5"
          style={{ background: `${color}15`, border: `1px solid ${color}30` }}
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
            <span className="text-[10px] text-muted-foreground ml-auto">{zone.osiLayer}</span>
          </div>
          <p className="text-xs text-muted-foreground leading-snug">{zone.description}</p>
        </div>
        <div className="text-muted-foreground shrink-0 mt-1">
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </div>
      </button>

      {expanded && hasProgs && (
        <div className="mt-3 pt-3 border-t border-border/50">
          <ProgList programs={zone.programs} maxVisible={20} />
        </div>
      )}

      {expanded && !hasProgs && (
        <div className="mt-3 pt-3 border-t border-border/50">
          <p className="text-xs text-muted-foreground italic">No programs attached to this zone.</p>
        </div>
      )}
    </div>
  );
}

function KernelDiagram({ zones }: { zones: KernelAttachmentZone[] }) {
  const zoneMap = new Map(zones.map(z => [z.zone, z]));

  return (
    <div className="relative">
      {/* Kernel boundary */}
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
            {PACKET_FLOW_ZONES.map((zoneKey, idx) => {
              const zone = zoneMap.get(zoneKey);
              if (!zone) return null;
              const color = ZONE_COLORS[zoneKey] ?? "#6b7280";
              const hasProgs = zone.programs.length > 0;
              return (
                <React.Fragment key={zoneKey}>
                  <div
                    className="flex flex-col items-center gap-1 shrink-0 p-3 rounded-xl border transition-all min-w-[90px]"
                    style={{
                      borderColor: hasProgs ? `${color}50` : "oklch(0.22 0.015 240 / 0.6)",
                      background: hasProgs ? `${color}10` : "oklch(0.13 0.015 240 / 0.5)",
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
                  </div>
                  {idx < PACKET_FLOW_ZONES.length - 1 && (
                    <div className="text-muted-foreground text-lg shrink-0">→</div>
                  )}
                </React.Fragment>
              );
            })}
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
            {SYSTEM_ZONES.map(zoneKey => {
              const zone = zoneMap.get(zoneKey);
              if (!zone) return null;
              const color = ZONE_COLORS[zoneKey] ?? "#6b7280";
              const hasProgs = zone.programs.length > 0;
              return (
                <div
                  key={zoneKey}
                  className="flex flex-col items-center gap-1 p-2 rounded-xl border transition-all"
                  style={{
                    borderColor: hasProgs ? `${color}50` : "oklch(0.22 0.015 240 / 0.6)",
                    background: hasProgs ? `${color}10` : "oklch(0.13 0.015 240 / 0.5)",
                  }}
                >
                  <span className="text-lg">{ZONE_ICONS[zoneKey]}</span>
                  <span className="text-[10px] font-semibold text-center leading-tight" style={{ color: hasProgs ? color : undefined }}>
                    {zone.label}
                  </span>
                  <Badge
                    variant="outline"
                    className="text-[10px] px-1.5 py-0"
                    style={{ borderColor: `${color}40`, color: hasProgs ? color : undefined }}
                  >
                    {zone.programs.length}
                  </Badge>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function KernelView() {
  const { snapshot, filteredPrograms, searchQuery } = useEbpf();
  const [expandedZones, setExpandedZones] = useState<Set<string>>(new Set());

  const toggleZone = (zone: string) => {
    setExpandedZones(prev => {
      const next = new Set(prev);
      if (next.has(zone)) next.delete(zone);
      else next.add(zone);
      return next;
    });
  };

  if (!snapshot) {
    return <div className="flex items-center justify-center h-full"><p className="text-muted-foreground">Loading…</p></div>;
  }

  // Filter zones based on search
  const zones = searchQuery
    ? snapshot.kernelZones.map(z => ({
        ...z,
        programs: z.programs.filter(p => filteredPrograms.some(fp => fp.id === p.id)),
      })).filter(z => z.programs.length > 0)
    : snapshot.kernelZones;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
          <Cpu size={20} className="text-primary" />
          Kernel Attachment Points
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          eBPF programs organized by kernel hook type
        </p>
      </div>

      {/* Visual diagram */}
      <KernelDiagram zones={snapshot.kernelZones} />

      {/* Detailed zone list */}
      <div>
        <h2 className="text-sm font-semibold text-foreground mb-3">Zone Details</h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {zones.map(zone => (
            <ZoneCard
              key={zone.zone}
              zone={zone}
              expanded={expandedZones.has(zone.zone)}
              onToggle={() => toggleZone(zone.zone)}
            />
          ))}
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

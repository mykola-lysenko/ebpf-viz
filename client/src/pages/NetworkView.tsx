import React, { useState } from "react";
import { useEbpf } from "@/contexts/EbpfContext";
import { ProgList } from "@/components/ProgBadge";
import { Network, ChevronDown, ChevronRight, Wifi } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { NetworkInterface } from "../../../shared/ebpf-types";

const OSI_LAYERS = [
  {
    key: "L2" as const,
    label: "L2 — Data Link",
    sublabel: "XDP, raw packet",
    color: "#00d4ff",
    description: "eXpress Data Path hooks at the earliest point in the NIC driver",
  },
  {
    key: "L3" as const,
    label: "L3 — Network",
    sublabel: "TC, netfilter",
    color: "#7c3aed",
    description: "Traffic Control classifiers/actions and netfilter hooks",
  },
  {
    key: "L4" as const,
    label: "L4 — Transport",
    sublabel: "sk_filter, flow_dissector",
    color: "#3b82f6",
    description: "Socket filters, flow dissection, and transport-layer hooks",
  },
  {
    key: "L7" as const,
    label: "L7 — Application",
    sublabel: "sk_msg, sockops",
    color: "#8b5cf6",
    description: "Socket message redirection and TCP socket operation callbacks",
  },
];

function OsiLayerRow({ layerDef, programs }: {
  layerDef: typeof OSI_LAYERS[0];
  programs: ReturnType<typeof useEbpf>["snapshot"] extends null ? never : NetworkInterface["layers"]["L2"];
}) {
  const hasProgs = programs.length > 0;
  return (
    <div className={cn("osi-layer", hasProgs && "has-progs")}>
      <div
        className="w-16 shrink-0 text-center"
        style={{ color: layerDef.color }}
      >
        <div className="text-xs font-bold font-mono">{layerDef.key}</div>
        <div className="text-[10px] text-muted-foreground mt-0.5 leading-tight">{layerDef.sublabel}</div>
      </div>
      <div
        className="w-px self-stretch shrink-0"
        style={{ background: `${layerDef.color}30` }}
      />
      <div className="flex-1 min-w-0">
        <div className="text-xs text-muted-foreground mb-1">{layerDef.description}</div>
        {hasProgs ? (
          <ProgList programs={programs} maxVisible={8} />
        ) : (
          <span className="text-xs text-muted-foreground/50 italic">No programs attached</span>
        )}
      </div>
      <Badge
        variant="outline"
        className="text-[10px] px-1.5 py-0 shrink-0 self-start"
        style={hasProgs ? { borderColor: `${layerDef.color}50`, color: layerDef.color } : {}}
      >
        {programs.length}
      </Badge>
    </div>
  );
}

function InterfaceCard({ iface }: { iface: NetworkInterface }) {
  const [expanded, setExpanded] = useState(iface.allPrograms.length > 0);
  const totalProgs = iface.allPrograms.length;

  return (
    <div className="glass rounded-xl overflow-hidden">
      {/* Interface header */}
      <button
        className="w-full flex items-center gap-4 px-5 py-4 hover:bg-accent/30 transition-colors text-left"
        onClick={() => setExpanded(e => !e)}
      >
        <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
          style={{ background: "oklch(0.70 0.18 160 / 0.15)", border: "1px solid oklch(0.70 0.18 160 / 0.3)" }}>
          <Wifi size={16} style={{ color: "oklch(0.70 0.18 160)" }} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold font-mono text-foreground">{iface.name}</span>
            <span className="text-xs text-muted-foreground">ifindex {iface.ifindex}</span>
          </div>
          <div className="flex gap-2 mt-1">
            {OSI_LAYERS.map(l => {
              const count = iface.layers[l.key].length;
              if (count === 0) return null;
              return (
                <span
                  key={l.key}
                  className="text-[10px] font-mono px-1.5 py-0.5 rounded border"
                  style={{ color: l.color, borderColor: `${l.color}40`, background: `${l.color}10` }}
                >
                  {l.key}: {count}
                </span>
              );
            })}
            {totalProgs === 0 && (
              <span className="text-[10px] text-muted-foreground/50">no BPF programs</span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Badge variant="outline" className={cn(
            "text-xs",
            totalProgs > 0 ? "border-emerald-500/40 text-emerald-400" : "border-muted-foreground/30 text-muted-foreground"
          )}>
            {totalProgs} prog{totalProgs !== 1 ? "s" : ""}
          </Badge>
          {expanded ? <ChevronDown size={14} className="text-muted-foreground" /> : <ChevronRight size={14} className="text-muted-foreground" />}
        </div>
      </button>

      {/* OSI layers */}
      {expanded && (
        <div className="px-5 pb-5 space-y-2 border-t border-border/50">
          <div className="pt-4 space-y-2">
            {OSI_LAYERS.map(layerDef => (
              <OsiLayerRow
                key={layerDef.key}
                layerDef={layerDef}
                programs={iface.layers[layerDef.key]}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function NetworkView() {
  const { snapshot, filteredPrograms, searchQuery } = useEbpf();

  if (!snapshot) {
    return <div className="flex items-center justify-center h-full"><p className="text-muted-foreground">Loading…</p></div>;
  }

  // When searching, filter programs within each interface
  const interfaces = searchQuery
    ? snapshot.networkInterfaces.map(iface => ({
        ...iface,
        layers: {
          L2: iface.layers.L2.filter(p => filteredPrograms.some(fp => fp.id === p.id)),
          L3: iface.layers.L3.filter(p => filteredPrograms.some(fp => fp.id === p.id)),
          L4: iface.layers.L4.filter(p => filteredPrograms.some(fp => fp.id === p.id)),
          L7: iface.layers.L7.filter(p => filteredPrograms.some(fp => fp.id === p.id)),
        },
        allPrograms: iface.allPrograms.filter(p => filteredPrograms.some(fp => fp.id === p.id)),
      })).filter(i => i.allPrograms.length > 0)
    : snapshot.networkInterfaces;

  const totalNetProgs = snapshot.networkInterfaces.reduce((a, i) => a + i.allPrograms.length, 0);

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
          <Network size={20} className="text-primary" />
          Network Interfaces
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          {snapshot.networkInterfaces.length} interface{snapshot.networkInterfaces.length !== 1 ? "s" : ""} · {totalNetProgs} BPF programs attached
        </p>
      </div>

      {/* OSI legend */}
      <div className="glass rounded-xl p-4">
        <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">OSI Layer Legend</div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {OSI_LAYERS.map(l => (
            <div key={l.key} className="flex items-start gap-2">
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold font-mono shrink-0"
                style={{ background: `${l.color}15`, border: `1px solid ${l.color}30`, color: l.color }}
              >
                {l.key}
              </div>
              <div>
                <div className="text-xs font-medium text-foreground">{l.label.split(" — ")[1]}</div>
                <div className="text-[10px] text-muted-foreground">{l.sublabel}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Interface cards */}
      <div className="space-y-4">
        {interfaces.length > 0 ? (
          interfaces.map(iface => (
            <InterfaceCard key={iface.name} iface={iface} />
          ))
        ) : (
          <div className="glass rounded-xl p-8 text-center">
            <Network size={32} className="text-muted-foreground mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">
              {searchQuery ? "No interfaces match the current filter." : "No BPF programs attached to network interfaces."}
            </p>
            {!searchQuery && (
              <p className="text-xs text-muted-foreground/60 mt-1">
                XDP, TC, and netfilter programs will appear here when attached to interfaces.
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

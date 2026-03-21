import React, { useState, useMemo } from "react";
import { useEbpf } from "@/contexts/EbpfContext";
import { ProgBadge } from "@/components/ProgBadge";
import { Network, ChevronDown, ChevronRight, Wifi, Share2, AlertTriangle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { NetworkInterface, ProgramChain, BpfProgram } from "../../../shared/ebpf-types";

/** Classify live rate drop between consecutive chain programs */
function classifyRateDrop(
  prevRate: number | undefined,
  currRate: number | undefined,
): { rate: number; label: string; color: string } | null {
  if (prevRate == null || currRate == null || prevRate <= 0) return null;
  const drop = 1 - currRate / prevRate;
  if (drop < 0.05) return null;
  if (drop < 0.2) return { rate: drop, label: `~${Math.round(drop * 100)}% fewer/s`, color: "#f59e0b" };
  if (drop < 0.5) return { rate: drop, label: `~${Math.round(drop * 100)}% fewer/s`, color: "#f97316" };
  return { rate: drop, label: `~${Math.round(drop * 100)}% fewer/s`, color: "#ef4444" };
}

function formatRunCnt(n: number): string {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function formatAge(loadedAt: number): string {
  const now = Date.now() / 1000;
  const secs = Math.max(0, now - loadedAt);
  if (secs < 60) return `${Math.round(secs)}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

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

// Layers shown for NIC interfaces
const NIC_LAYERS = OSI_LAYERS.filter(l => l.key === "L2" || l.key === "L3");
// Layers shown for sockmap interfaces
const SOCKMAP_LAYERS = OSI_LAYERS.filter(l => l.key === "L4" || l.key === "L7");

function OsiLayerRow({ layerDef, programs, chains }: {
  layerDef: typeof OSI_LAYERS[0];
  programs: NetworkInterface["layers"]["L2"];
  chains?: ProgramChain[];
}) {
  const { historyMap } = useEbpf();
  const hasProgs = programs.length > 0;

  // Build a position map from all relevant chains: progId → { position, chain }
  const positionMap = useMemo(() => {
    const map = new Map<number, { position: number; chain: ProgramChain }>();
    if (!chains) return map;
    for (const chain of chains) {
      for (const cp of chain.programs) {
        map.set(cp.id, { position: cp.position, chain });
      }
    }
    return map;
  }, [chains]);

  // Group programs by chain, keeping unchained programs separate
  const { chainGroups, unchained } = useMemo(() => {
    const chainGroups = new Map<string, { chain: ProgramChain; progs: BpfProgram[] }>();
    const unchained: BpfProgram[] = [];
    for (const p of programs) {
      const info = positionMap.get(p.id);
      if (info) {
        if (!chainGroups.has(info.chain.hookId)) {
          chainGroups.set(info.chain.hookId, { chain: info.chain, progs: [] });
        }
        chainGroups.get(info.chain.hookId)!.progs.push(p);
      } else {
        unchained.push(p);
      }
    }
    // Sort programs within each chain by position
    for (const g of Array.from(chainGroups.values())) {
      g.progs.sort((a, b) => (positionMap.get(a.id)?.position ?? 0) - (positionMap.get(b.id)?.position ?? 0));
    }
    return { chainGroups: Array.from(chainGroups.values()), unchained };
  }, [programs, positionMap]);

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
          <div className="space-y-2">
            {/* Chain groups — programs shown in execution order */}
            {chainGroups.map(({ chain, progs }) => (
              <div key={chain.hookId}>
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="text-[10px] text-muted-foreground/70 font-mono">
                    {chain.attachType}
                  </span>
                  <span className="text-[9px] text-muted-foreground/50">
                    chain of {chain.programs.length}
                  </span>
                  {chain.canShortCircuit && (
                    <span className="text-[9px] text-amber-400/70 flex items-center gap-0.5">
                      <AlertTriangle size={8} />
                      can short-circuit
                    </span>
                  )}
                </div>
                <div className="space-y-0.5 ml-1">
                  {progs.map((p, pIdx) => {
                    const pos = positionMap.get(p.id)?.position;
                    // Drop indicator: compare live rates, not cumulative run_cnt
                    const currRate = historyMap.get(p.id)?.latest?.callsPerSec;
                    const prevRate = chain.canShortCircuit && pIdx > 0
                      ? historyMap.get(progs[pIdx - 1].id)?.latest?.callsPerSec
                      : undefined;
                    const dropInfo = classifyRateDrop(prevRate, currRate);
                    return (
                      <React.Fragment key={p.id}>
                        {dropInfo && (
                          <div
                            className="flex items-center gap-1 ml-5 text-[9px] font-mono py-0.5"
                            style={{ color: dropInfo.color }}
                          >
                            <AlertTriangle size={8} />
                            {dropInfo.label} (live rate)
                          </div>
                        )}
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {pos != null && (
                            <span
                              className="w-4 h-4 rounded-full flex items-center justify-center text-[9px] font-bold shrink-0"
                              style={{
                                background: `${p.color}20`,
                                border: `1.5px solid ${p.color}`,
                                color: p.color,
                              }}
                            >
                              {pos}
                            </span>
                          )}
                          <ProgBadge program={p} />
                          <span className="text-[9px] font-mono text-muted-foreground/50 tabular-nums shrink-0">
                            {p.runCnt != null && `${formatRunCnt(p.runCnt)} total`}
                            {p.loadedAt > 0 && ` · loaded ${formatAge(p.loadedAt)}`}
                          </span>
                        </div>
                      </React.Fragment>
                    );
                  })}
                </div>
              </div>
            ))}
            {/* Unchained programs */}
            {unchained.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {unchained.map(p => (
                  <ProgBadge key={p.id} program={p} />
                ))}
              </div>
            )}
          </div>
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

function InterfaceCard({ iface, tcChains }: { iface: NetworkInterface; tcChains: ProgramChain[] }) {
  const [expanded, setExpanded] = useState(iface.allPrograms.length > 0);
  const totalProgs = iface.allPrograms.length;
  const isSockmap = iface.kind === "sockmap";

  // NIC cards show L2+L3; sockmap cards show L4+L7
  const visibleLayers = isSockmap ? SOCKMAP_LAYERS : NIC_LAYERS;

  // Filter TC chains relevant to this interface
  const ifaceChains = useMemo(() =>
    tcChains.filter(c => c.attachPoint === iface.name),
    [tcChains, iface.name]
  );

  const iconBg = isSockmap
    ? "oklch(0.65 0.18 290 / 0.15)"
    : "oklch(0.70 0.18 160 / 0.15)";
  const iconBorder = isSockmap
    ? "1px solid oklch(0.65 0.18 290 / 0.3)"
    : "1px solid oklch(0.70 0.18 160 / 0.3)";
  const iconColor = isSockmap
    ? "oklch(0.65 0.18 290)"
    : "oklch(0.70 0.18 160)";

  return (
    <div className="glass rounded-xl overflow-hidden">
      {/* Interface header */}
      <button
        className="w-full flex items-center gap-4 px-5 py-4 hover:bg-accent/30 transition-colors text-left"
        onClick={() => setExpanded(e => !e)}
      >
        <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
          style={{ background: iconBg, border: iconBorder }}>
          {isSockmap
            ? <Share2 size={16} style={{ color: iconColor }} />
            : <Wifi size={16} style={{ color: iconColor }} />
          }
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold font-mono text-foreground">{iface.name}</span>
            {iface.ifindex > 0 && (
              <span className="text-xs text-muted-foreground">ifindex {iface.ifindex}</span>
            )}
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
            {visibleLayers.map(layerDef => (
              <OsiLayerRow
                key={layerDef.key}
                layerDef={layerDef}
                programs={iface.layers[layerDef.key]}
                chains={layerDef.key === "L3" ? ifaceChains : undefined}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

interface SectionProps {
  title: string;
  description: string;
  icon: React.ReactNode;
  interfaces: NetworkInterface[];
  emptyMessage: string;
  emptyHint?: string;
  accentColor?: string;
  tcChains?: ProgramChain[];
}

function InterfaceSection({ title, description, icon, interfaces, emptyMessage, emptyHint, accentColor, tcChains = [] }: SectionProps) {
  return (
    <div className="space-y-3">
      {/* Section header */}
      <div className="flex items-center gap-3">
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
          style={{
            background: accentColor ? `${accentColor}15` : "oklch(0.70 0.18 160 / 0.1)",
            border: `1px solid ${accentColor ?? "oklch(0.70 0.18 160)"}30`,
          }}
        >
          {icon}
        </div>
        <div>
          <h2 className="text-sm font-semibold text-foreground">{title}</h2>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
        <Badge variant="outline" className="ml-auto text-xs text-muted-foreground">
          {interfaces.length}
        </Badge>
      </div>

      {/* Cards */}
      <div className="space-y-3 pl-11">
        {interfaces.length > 0 ? (
          interfaces.map(iface => (
            <InterfaceCard key={iface.name} iface={iface} tcChains={tcChains} />
          ))
        ) : (
          <div className="glass rounded-xl p-6 text-center">
            <p className="text-sm text-muted-foreground">{emptyMessage}</p>
            {emptyHint && (
              <p className="text-xs text-muted-foreground/60 mt-1">{emptyHint}</p>
            )}
          </div>
        )}
      </div>
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

  const nicInterfaces = interfaces.filter(i => i.kind === "nic");
  const sockmapInterfaces = interfaces.filter(i => i.kind === "sockmap");
  const totalNetProgs = snapshot.networkInterfaces.reduce((a, i) => a + i.allPrograms.length, 0);

  const tcChains = useMemo(() =>
    snapshot.programChains.filter(c => c.hookType === "tc"),
    [snapshot.programChains]
  );

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Page header */}
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

      {/* ── NIC section ─────────────────────────────────────────────────── */}
      <InterfaceSection
        title="Network Interfaces"
        description="Physical and virtual NICs — XDP, TC, netfilter, and netkit hooks"
        icon={<Wifi size={15} style={{ color: "oklch(0.70 0.18 160)" }} />}
        interfaces={nicInterfaces}
        accentColor="#10b981"
        tcChains={tcChains}
        emptyMessage={searchQuery ? "No NIC interfaces match the current filter." : "No BPF programs attached to network interfaces."}
        emptyHint={!searchQuery ? "XDP, TC, and netfilter programs will appear here when attached to interfaces." : undefined}
      />

      {/* ── Sockmap section (hidden when empty in live mode) ─────────────── */}
      {(sockmapInterfaces.length > 0 || searchQuery) && (
        <InterfaceSection
          title="Sockmap Interfaces"
          description="Socket-level BPF programs — sk_msg, sk_skb, sock_ops, sk_lookup"
          icon={<Share2 size={15} style={{ color: "oklch(0.65 0.18 290)" }} />}
          interfaces={sockmapInterfaces}
          accentColor="#8b5cf6"
          emptyMessage={searchQuery ? "No sockmap interfaces match the current filter." : "No sockmap programs loaded."}
          emptyHint={!searchQuery ? "sk_msg, sk_skb, sock_ops, and sk_lookup programs will appear here." : undefined}
        />
      )}

      {/* Fallback when everything is empty and not searching */}
      {interfaces.length === 0 && !searchQuery && (
        <div className="glass rounded-xl p-8 text-center">
          <Network size={32} className="text-muted-foreground mx-auto mb-3" />
          <p className="text-sm text-muted-foreground">No BPF programs attached to any network interface.</p>
          <p className="text-xs text-muted-foreground/60 mt-1">
            XDP, TC, netfilter, and sockmap programs will appear here when loaded.
          </p>
        </div>
      )}
    </div>
  );
}

import React from "react";
import { useEbpf } from "@/contexts/EbpfContext";
import { ProgBadge } from "@/components/ProgBadge";
import { Badge } from "@/components/ui/badge";
import { Cpu, Network, FolderTree, Activity, Zap, AlertTriangle, Server, GitBranch } from "lucide-react";
import { Link } from "wouter";
import { cn } from "@/lib/utils";
import { TYPE_COLORS } from "../../../server/ebpf-parser";

function StatCard({ label, value, sub, icon: Icon, color }: {
  label: string; value: string | number; sub?: string;
  icon: React.ElementType; color: string;
}) {
  return (
    <div className="stat-card">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-muted-foreground">{label}</span>
        <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: `${color}20` }}>
          <Icon size={14} style={{ color }} />
        </div>
      </div>
      <div className="text-2xl font-bold text-foreground font-mono">{value}</div>
      {sub && <div className="text-xs text-muted-foreground">{sub}</div>}
    </div>
  );
}

function TypeBar({ byType }: { byType: Record<string, number> }) {
  const total = Object.values(byType).reduce((a, b) => a + b, 0);
  if (total === 0) return null;

  const sorted = Object.entries(byType)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 12);

  return (
    <div className="space-y-2">
      {sorted.map(([type, count]) => {
        const color = TYPE_COLORS[type] ?? "#6b7280";
        const pct = (count / total) * 100;
        return (
          <div key={type} className="flex items-center gap-3">
            <div className="w-28 text-xs font-mono text-muted-foreground truncate shrink-0">{type}</div>
            <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{ width: `${pct}%`, background: color }}
              />
            </div>
            <div className="w-6 text-xs font-mono text-right" style={{ color }}>{count}</div>
          </div>
        );
      })}
    </div>
  );
}

function QuickNavCard({ href, icon: Icon, label, count, color }: {
  href: string; icon: React.ElementType; label: string; count?: number; color: string;
}) {
  return (
    <Link href={href}>
      <div className="glass rounded-xl p-4 flex items-center gap-4 cursor-pointer hover:border-primary/40 transition-all duration-200 group">
        <div
          className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0 transition-all group-hover:scale-110"
          style={{ background: `${color}20`, border: `1px solid ${color}30` }}
        >
          <Icon size={18} style={{ color }} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-foreground">{label}</div>
          {count !== undefined && (
            <div className="text-xs text-muted-foreground">{count} programs</div>
          )}
        </div>
        <div className="text-muted-foreground group-hover:text-foreground transition-colors">→</div>
      </div>
    </Link>
  );
}

export default function Dashboard() {
  const { snapshot, isLoading, demoMode } = useEbpf();

  if (isLoading && !snapshot) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center space-y-3">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="text-sm text-muted-foreground">Connecting to bpftool…</p>
        </div>
      </div>
    );
  }

  if (!snapshot) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-muted-foreground">No data available</p>
      </div>
    );
  }

  const { stats, programs, networkInterfaces, cgroupTree, kernelZones } = snapshot;
  const recentProgs = [...programs].sort((a, b) => b.loadedAt - a.loadedAt).slice(0, 8);
  const netProgs = networkInterfaces.reduce((acc, i) => acc + i.allPrograms.length, 0);
  const cgroupProgs = programs.filter(p => p.type.startsWith("cgroup") || p.type === "sock_ops").length;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground">eBPF Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            {snapshot.hostname} · {snapshot.kernelVersion}
            {demoMode && <span className="ml-2 text-amber-400">(demo mode)</span>}
          </p>
        </div>
        <div className="text-xs text-muted-foreground font-mono">
          {new Date(snapshot.timestamp).toLocaleString()}
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Programs" value={stats.total} icon={Activity} color="#00d4ff"
          sub={`${stats.jited} JIT compiled`} />
        <StatCard label="Kernel Zones" value={kernelZones.length} icon={Cpu} color="#7c3aed"
          sub="attachment points" />
        <StatCard label="Network" value={networkInterfaces.length} icon={Network} color="#10b981"
          sub={`${netProgs} programs attached`} />
        <StatCard label="Cgroup Programs" value={cgroupProgs} icon={FolderTree} color="#3b82f6"
          sub={`${cgroupTree.length} cgroup nodes`} />
      </div>

      {/* Orphaned warning */}
      {stats.orphaned > 0 && (
        <div className="flex items-center gap-3 p-3 rounded-xl bg-destructive/10 border border-destructive/30">
          <AlertTriangle size={16} className="text-destructive shrink-0" />
          <p className="text-sm text-destructive/80">
            {stats.orphaned} orphaned program{stats.orphaned > 1 ? "s" : ""} detected — owning process has exited.
          </p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Type distribution */}
        <div className="glass rounded-xl p-5 lg:col-span-1">
          <h2 className="text-sm font-semibold text-foreground mb-4 flex items-center gap-2">
            <GitBranch size={14} className="text-primary" />
            Program Types
          </h2>
          <TypeBar byType={stats.byType} />
        </div>

        {/* Quick nav */}
        <div className="space-y-3 lg:col-span-1">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Zap size={14} className="text-primary" />
            Views
          </h2>
          <QuickNavCard href="/kernel" icon={Cpu} label="Kernel Diagram" color="#7c3aed"
            count={kernelZones.reduce((a, z) => a + z.programs.length, 0)} />
          <QuickNavCard href="/network" icon={Network} label="Network Interfaces" color="#10b981"
            count={netProgs} />
          <QuickNavCard href="/cgroups" icon={FolderTree} label="Cgroup Hierarchy" color="#3b82f6"
            count={cgroupProgs} />
          <QuickNavCard href="/programs" icon={Activity} label="All Programs" color="#00d4ff"
            count={stats.total} />
        </div>

        {/* Recently loaded */}
        <div className="glass rounded-xl p-5 lg:col-span-1">
          <h2 className="text-sm font-semibold text-foreground mb-4 flex items-center gap-2">
            <Server size={14} className="text-primary" />
            Recently Loaded
          </h2>
          <div className="space-y-2">
            {recentProgs.map(p => (
              <div key={p.id} className="flex items-center gap-2">
                <ProgBadge program={p} />
                <span className="text-xs text-muted-foreground ml-auto shrink-0">
                  {p.loadedAt ? new Date(p.loadedAt * 1000).toLocaleTimeString() : "—"}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Kernel zones overview */}
      <div className="glass rounded-xl p-5">
        <h2 className="text-sm font-semibold text-foreground mb-4 flex items-center gap-2">
          <Cpu size={14} className="text-primary" />
          Kernel Attachment Zones
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-3">
          {kernelZones.map(zone => (
            <Link key={zone.zone} href="/kernel">
              <div className={cn(
                "kernel-zone cursor-pointer",
                zone.programs.length > 0 && "has-progs"
              )}>
                <div className="text-xs font-semibold text-foreground mb-1">{zone.label}</div>
                <div className="text-2xl font-bold font-mono" style={{
                  color: zone.programs.length > 0 ? "#00d4ff" : "oklch(0.55 0.01 240)"
                }}>
                  {zone.programs.length}
                </div>
                <div className="text-[10px] text-muted-foreground mt-1 leading-tight">{zone.description.split(" — ")[0]}</div>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}

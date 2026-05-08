import React, { useMemo } from "react";
import { useEbpf } from "@/contexts/EbpfContext";
import { ProgBadge } from "@/components/ProgBadge";
import { Badge } from "@/components/ui/badge";
import { Cpu, Network, FolderTree, Activity, Zap, AlertTriangle, Server, GitBranch, Timer, BarChart2 } from "lucide-react";
import { Link } from "wouter";
import { cn } from "@/lib/utils";
import { TYPE_COLORS } from "../../../server/ebpf-parser";
import Sparkline, { samplesToCallsPerSec, fmtCps, fmtNs, fmtCpu } from "@/components/Sparkline";
import { formatRelativeTime, formatFullTimestamp, useNow } from "@/lib/time";

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

// ── Activity Leaderboard ──────────────────────────────────────────────────────

function ActivityLeaderboard() {
  const { activity, historyMap, snapshot, statsEnabled } = useEbpf();

  const topProgramsRaw = activity?.topByCallsPerSec ?? [];
  const totalCps = activity?.totalCallsPerSec ?? 0;
  const totalCpu = activity?.totalCpuFraction ?? 0;

  // Get full program objects for the top programs
  const progMap = useMemo(() => {
    const m = new Map();
    if (snapshot) for (const p of snapshot.programs) m.set(p.id, p);
    return m;
  }, [snapshot]);

  // Aggregate duplicate programs by tag+name
  const topPrograms = useMemo(() => {
    if (topProgramsRaw.length === 0) return [];
    
    // Group by tag (which uniquely identifies the compiled bytecode)
    const grouped = new Map<string, { id: number; callsPerSec: number; avgLatencyNs: number; cloneCount: number }>();
    
    topProgramsRaw.forEach(entry => {
      const prog = progMap.get(entry.id);
      if (!prog) return; // shouldn't happen unless snapshot is out of sync with history
      
      const existing = grouped.get(prog.tag);
      if (existing) {
        // Merge stats
        // calls/sec sum up. Latency averages out (weighted by calls/sec)
        const totalCalls = existing.callsPerSec + entry.callsPerSec;
        const weightedLat = totalCalls > 0 
          ? ((existing.avgLatencyNs * existing.callsPerSec) + (entry.avgLatencyNs * entry.callsPerSec)) / totalCalls
          : (existing.avgLatencyNs + entry.avgLatencyNs) / 2;
          
        existing.callsPerSec += entry.callsPerSec;
        existing.avgLatencyNs = weightedLat;
        existing.cloneCount += 1;
      } else {
        grouped.set(prog.tag, { ...entry, cloneCount: 1 });
      }
    });

    // Re-sort the aggregated list by total calls per sec and take top 5
    return Array.from(grouped.values())
      .sort((a, b) => b.callsPerSec - a.callsPerSec)
      .slice(0, 5);
  }, [topProgramsRaw, progMap]);

  if (!statsEnabled) {
    return (
      <div className="glass rounded-xl p-5">
        <h2 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
          <Zap size={14} className="text-primary" />
          Runtime Activity
        </h2>
        <div className="text-xs text-muted-foreground/60 text-center py-6">
          Enable <code className="font-mono bg-white/5 px-1 rounded">kernel.bpf_stats_enabled=1</code> to see live call rates and CPU usage.
        </div>
      </div>
    );
  }

  if (topPrograms.length === 0) {
    return (
      <div className="glass rounded-xl p-5">
        <h2 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
          <Zap size={14} className="text-primary" />
          Runtime Activity
        </h2>
        <div className="text-xs text-muted-foreground/60 text-center py-6">
          Accumulating data… programs will appear here once they execute.
        </div>
      </div>
    );
  }

  const maxCps = topPrograms[0]?.callsPerSec ?? 1;

  return (
    <div className="glass rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Zap size={14} className="text-cyan-400" />
          Runtime Activity
        </h2>
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            {fmtCps(totalCps)} total
          </span>
          <span className="text-violet-400">{fmtCpu(totalCpu)} CPU</span>
        </div>
      </div>

      <div className="space-y-3">
        {topPrograms.map((entry, rank) => {
          const prog = progMap.get(entry.id);
          if (!prog) return null;
          const history = historyMap.get(entry.id);
          const sparkData = history?.samples && history.samples.length >= 2
            ? samplesToCallsPerSec(history.samples)
            : [];
          const barFraction = maxCps > 0 ? Math.min(1, entry.callsPerSec / maxCps) : 0;

          // Latency color
          const lat = entry.avgLatencyNs;
          const lColor = lat === 0 ? "#6b7280"
            : lat < 1_000 ? "#22d3ee"
            : lat < 100_000 ? "#4ade80"
            : lat < 1_000_000 ? "#f59e0b"
            : "#f87171";

          return (
            <div key={entry.id} className="flex items-center gap-3 group">
              {/* Rank */}
              <span className="text-[10px] font-mono text-muted-foreground/40 w-4 shrink-0 text-right">
                {rank + 1}
              </span>

              {/* Program badge */}
              <div className="w-36 shrink-0 flex flex-col gap-1">
                <ProgBadge program={prog} history={history} compact />
                {entry.cloneCount > 1 && (
                  <div className="text-[9px] font-sans px-1 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-400 w-fit">
                    ×{entry.cloneCount} active clones
                  </div>
                )}
              </div>

              {/* Bar + sparkline */}
              <div className="flex-1 flex flex-col gap-0.5 min-w-0">
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-[3px] rounded-full bg-white/5 overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{
                        width: `${barFraction * 100}%`,
                        background: lColor,
                        minWidth: barFraction > 0 ? 2 : 0,
                      }}
                    />
                  </div>
                  {sparkData.length >= 2 && (
                    <Sparkline data={sparkData} height={14} width={48} color={lColor} variant="calls" />
                  )}
                </div>
              </div>

              {/* Metrics */}
              <div className="flex flex-col items-end gap-0.5 shrink-0 min-w-[72px]">
                <span className="text-[11px] font-mono tabular-nums" style={{ color: lColor }}>
                  {fmtCps(entry.callsPerSec)}
                </span>
                <span className="text-[10px] font-mono tabular-nums text-muted-foreground/60">
                  {fmtNs(entry.avgLatencyNs)}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const { snapshot, isLoading, demoMode, activity, statsEnabled } = useEbpf();
  const now = useNow(30_000); // refresh relative times every 30s

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
  const orphanedProgs = programs.filter(p => p.orphaned);
  const netProgs = networkInterfaces.reduce((acc, i) => acc + i.allPrograms.length, 0);
  const cgroupProgs = programs.filter(p => p.type.startsWith("cgroup") || p.type === "sock_ops").length;

  const totalCps = activity?.totalCallsPerSec ?? 0;
  const totalCpu = activity?.totalCpuFraction ?? 0;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground">eBPF Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            {snapshot.hostname} · {snapshot.kernelVersion}
            {demoMode && <span className="ml-2 text-amber-400">(demo mode)</span>}
            {statsEnabled && totalCps > 0 && (
              <span className="ml-2 text-cyan-400 inline-flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                {fmtCps(totalCps)} · {fmtCpu(totalCpu)} CPU
              </span>
            )}
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
      {orphanedProgs.length > 0 && (
        <div className="p-4 rounded-xl bg-destructive/10 border border-destructive/30 space-y-2">
          <div className="flex items-center gap-2">
            <AlertTriangle size={15} className="text-destructive shrink-0" />
            <span className="text-sm font-semibold text-destructive">
              {orphanedProgs.length} orphaned program{orphanedProgs.length > 1 ? "s" : ""} detected
            </span>
            <Link href="/programs" className="ml-auto text-xs text-destructive/60 hover:text-destructive underline underline-offset-2">
              View in Programs →
            </Link>
          </div>
          <div className="space-y-1.5 pl-5">
            {orphanedProgs.map(p => {
              const ownerParts = (p.pids ?? []).map(({ pid, comm }) => `${comm} (PID ${pid})`);
              const ownerStr = ownerParts.length > 0
                ? `last owned by ${ownerParts.join(", ")}`
                : "owning process PID unknown";
              return (
                <div key={p.id} className="flex items-baseline gap-2 text-xs">
                  <span className="font-mono text-destructive/90 font-semibold">{p.name}</span>
                  <span className="text-destructive/50">#{p.id}</span>
                  <span className="text-destructive/60">·</span>
                  <span className="text-destructive/60">{ownerStr}</span>
                </div>
              );
            })}
          </div>
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
                <span
                  className="text-xs text-muted-foreground ml-auto shrink-0"
                  title={formatFullTimestamp(p.loadedAt)}
                >
                  {formatRelativeTime(p.loadedAt, now)}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Activity Leaderboard */}
      <ActivityLeaderboard />

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

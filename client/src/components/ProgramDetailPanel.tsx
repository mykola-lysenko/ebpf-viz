import React, { useMemo, useState } from "react";
import { formatRelativeTime, formatFullTimestamp, useNow } from "@/lib/time";
import { X, Copy, Check, Clock, Cpu, Hash, Tag, Database, Activity, Shield, AlertTriangle, Zap, Timer, BarChart2, Code2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { AreaChart, Area, XAxis, YAxis, Tooltip as RechartTooltip, ResponsiveContainer } from "recharts";
import type { BpfProgram, ProgHistory } from "../../../shared/ebpf-types";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { samplesToCallsPerSec, samplesToAvgLatency, fmtCps, fmtNs, fmtCpu } from "./Sparkline";
import { CodeInspector } from "./CodeInspector";

interface Props {
  program: BpfProgram;
  history?: ProgHistory | null;
  onClose: () => void;
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(value);
    setCopied(true);
    toast.success(`Copied ${label}`);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={copy} className="text-muted-foreground hover:text-foreground transition-colors ml-1">
      {copied ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

function MetaRow({ icon: Icon, label, value, mono = false, copyable = false }: {
  icon: React.ElementType;
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  copyable?: boolean;
}) {
  return (
    <div className="flex items-start gap-3 py-2">
      <div className="flex items-center gap-2 w-32 shrink-0">
        <Icon size={13} className="text-muted-foreground shrink-0" />
        <span className="text-xs text-muted-foreground">{label}</span>
      </div>
      <div className={cn("text-xs text-foreground flex-1", mono && "font-mono")}>
        {value}
        {copyable && typeof value === "string" && (
          <CopyButton value={value} label={label} />
        )}
      </div>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, sub, color }: {
  icon: React.ElementType;
  label: string;
  value: string;
  sub?: string;
  color: string;
}) {
  return (
    <div
      className="rounded-lg p-3 border flex flex-col gap-1"
      style={{ borderColor: `${color}25`, background: `${color}08` }}
    >
      <div className="flex items-center gap-1.5">
        <Icon size={11} style={{ color }} />
        <span className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</span>
      </div>
      <div className="text-sm font-mono font-semibold" style={{ color }}>{value}</div>
      {sub && <div className="text-[10px] text-muted-foreground">{sub}</div>}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

// Replaced by formatRelativeTime from @/lib/time — kept as alias for any remaining callers
function formatTimestamp(unix: number): string {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleString();
}

const ATTACH_KIND_COLORS: Record<string, string> = {
  xdp:            "#00d4ff",
  tc:             "#7c3aed",
  tcx:            "#6d28d9",
  cgroup:         "#3b82f6",
  flow_dissector: "#ec4899",
  netfilter:      "#f43f5e",
  perf:           "#f97316",
  unknown:        "#6b7280",
};

// Custom tooltip for the detail chart
function ChartTooltip({ active, payload, label, mode }: {
  active?: boolean;
  payload?: Array<{ value: number }>;
  label?: number;
  mode: "calls" | "latency";
}) {
  if (!active || !payload?.length) return null;
  const val = payload[0]?.value ?? 0;
  return (
    <div className="bg-[#0f172a] border border-white/10 rounded px-2 py-1 text-xs text-white/80">
      {mode === "calls" ? fmtCps(val) : fmtNs(val)}
    </div>
  );
}

export function ProgramDetailPanel({ program, history, onClose }: Props) {
  const [showCode, setShowCode] = useState(false);
  const hasHistory = (history?.samples?.length ?? 0) >= 2;
  const now = useNow(30_000); // refresh relative times every 30s

  // Derive chart series
  const { callsSeries, latencySeries, chartData } = useMemo(() => {
    if (!hasHistory || !history) return { callsSeries: [], latencySeries: [], chartData: [] };
    const calls = samplesToCallsPerSec(history.samples);
    const lats = samplesToAvgLatency(history.samples);
    const data = calls.map((c, i) => ({ i, calls: c, latency: lats[i] ?? 0 }));
    return { callsSeries: calls, latencySeries: lats, chartData: data };
  }, [history, hasHistory]);

  const latest = history?.latest;
  const hasLiveStats = latest !== null && latest !== undefined && (latest.callsPerSec > 0 || latest.avgLatencyNs > 0);

  return (
    <>
    <div className="detail-panel fade-up">
      {/* Header */}
      <div className="sticky top-0 z-10 bg-[oklch(0.10_0.012_240/0.97)] backdrop-blur-xl border-b border-border px-5 py-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span
                className="inline-block w-2.5 h-2.5 rounded-full shrink-0"
                style={{ background: program.color, boxShadow: `0 0 8px ${program.color}80` }}
              />
              <span className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
                {program.rawType}
              </span>
              {program.orphaned && (
                <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-destructive/50 text-destructive">
                  orphaned
                </Badge>
              )}
            </div>
            <h2 className="text-sm font-semibold text-foreground font-mono truncate">
              {program.name || `prog_${program.id}`}
            </h2>
            <div className="text-xs text-muted-foreground mt-0.5">ID: {program.id}</div>
          </div>
          <div className="flex items-center gap-1 shrink-0">
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground gap-1.5"
              onClick={() => setShowCode(true)}
              title="Open Code Inspector"
            >
              <Code2 size={12} />
              Code
            </Button>
            <Button variant="ghost" size="icon" className="w-7 h-7" onClick={onClose}>
              <X size={14} />
            </Button>
          </div>
        </div>

        {/* State badges */}
        <div className="flex flex-wrap gap-1.5 mt-3">
          <Badge
            variant="outline"
            className="text-[10px] px-2 py-0.5"
            style={{ borderColor: `${program.color}50`, color: program.color }}
          >
            {program.osiLayer}
          </Badge>
          {program.jited && (
            <Badge variant="outline" className="text-[10px] px-2 py-0.5 border-emerald-500/40 text-emerald-400">
              JIT compiled
            </Badge>
          )}
          {program.gplCompatible && (
            <Badge variant="outline" className="text-[10px] px-2 py-0.5 border-sky-500/40 text-sky-400">
              GPL
            </Badge>
          )}
          {program.attachments.some(a => a.attachFlags?.includes("multi")) && (
            <Badge variant="outline" className="text-[10px] px-2 py-0.5 border-violet-500/40 text-violet-400">
              multi-attach
            </Badge>
          )}
          {hasLiveStats && (
            <Badge variant="outline" className="text-[10px] px-2 py-0.5 border-cyan-500/40 text-cyan-400 animate-pulse">
              ● live stats
            </Badge>
          )}
        </div>
      </div>

      <div className="px-5 py-4 space-y-5">

        {/* ── Runtime statistics chart ─────────────────────────────────────── */}
        {hasHistory && (
          <>
            <section>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
                Runtime Activity
              </h3>

              {/* Stat cards */}
              {hasLiveStats && (
                <div className="grid grid-cols-3 gap-2 mb-4">
                  <StatCard
                    icon={Zap}
                    label="Calls/s"
                    value={fmtCps(latest!.callsPerSec)}
                    sub={`peak ${fmtCps(history!.peakCallsPerSec)}`}
                    color="#22d3ee"
                  />
                  <StatCard
                    icon={Timer}
                    label="Avg Latency"
                    value={fmtNs(latest!.avgLatencyNs)}
                    sub={`peak ${fmtNs(history!.peakAvgLatencyNs)}`}
                    color="#f59e0b"
                  />
                  <StatCard
                    icon={BarChart2}
                    label="CPU Share"
                    value={fmtCpu(latest!.cpuFraction)}
                    sub="of 1 core"
                    color="#a78bfa"
                  />
                </div>
              )}

              {/* Calls/sec chart */}
              {callsSeries.length >= 2 && (
                <div className="mb-3">
                  <div className="text-[10px] text-muted-foreground mb-1 flex items-center gap-1">
                    <span className="inline-block w-2 h-2 rounded-full bg-cyan-400" />
                    Calls / sec
                  </div>
                  <div className="h-[72px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={chartData} margin={{ top: 2, right: 0, bottom: 2, left: 0 }}>
                        <defs>
                          <linearGradient id="dp-calls" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="#22d3ee" stopOpacity={0.02} />
                          </linearGradient>
                        </defs>
                        <XAxis dataKey="i" hide />
                        <YAxis hide />
                        <RechartTooltip content={<ChartTooltip mode="calls" />} />
                        <Area
                          type="monotone"
                          dataKey="calls"
                          stroke="#22d3ee"
                          strokeWidth={1.5}
                          fill="url(#dp-calls)"
                          dot={false}
                          isAnimationActive={false}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}

              {/* Avg latency chart */}
              {latencySeries.length >= 2 && (
                <div>
                  <div className="text-[10px] text-muted-foreground mb-1 flex items-center gap-1">
                    <span className="inline-block w-2 h-2 rounded-full bg-amber-400" />
                    Avg latency (ns)
                  </div>
                  <div className="h-[56px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={chartData} margin={{ top: 2, right: 0, bottom: 2, left: 0 }}>
                        <defs>
                          <linearGradient id="dp-latency" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.02} />
                          </linearGradient>
                        </defs>
                        <XAxis dataKey="i" hide />
                        <YAxis hide />
                        <RechartTooltip content={<ChartTooltip mode="latency" />} />
                        <Area
                          type="monotone"
                          dataKey="latency"
                          stroke="#f59e0b"
                          strokeWidth={1.5}
                          fill="url(#dp-latency)"
                          dot={false}
                          isAnimationActive={false}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}

              {!hasLiveStats && hasHistory && (
                <div className="text-xs text-muted-foreground/50 text-center py-3">
                  Accumulating data… stats appear after the program executes with bpf_stats_enabled=1
                </div>
              )}
            </section>
            <Separator className="bg-border/50" />
          </>
        )}

        {/* Identity */}
        <section>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Identity</h3>
          <div className="divide-y divide-border/50">
            <MetaRow icon={Hash} label="ID" value={String(program.id)} mono />
            <MetaRow icon={Tag} label="Tag" value={program.tag} mono copyable />
            {program.btfId !== undefined && (
              <MetaRow icon={Database} label="BTF ID" value={String(program.btfId)} mono />
            )}
            <MetaRow icon={Shield} label="GPL" value={program.gplCompatible ? "Yes" : "No"} />
          </div>
        </section>

        <Separator className="bg-border/50" />

        {/* Timing */}
        <section>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Timing</h3>
          <div className="divide-y divide-border/50">
            <MetaRow
              icon={Clock}
              label="Loaded at"
              value={
                <span title={formatFullTimestamp(program.loadedAt)} className="cursor-default">
                  {formatRelativeTime(program.loadedAt, now)}
                </span>
              }
            />
            {program.runTimeNs !== undefined && (
              <MetaRow icon={Activity} label="Total run time" value={fmtNs(program.runTimeNs)} mono />
            )}
            {program.runCnt !== undefined && (
              <MetaRow icon={Activity} label="Run count" value={program.runCnt.toLocaleString()} mono />
            )}
            {program.runTimeNs !== undefined && program.runCnt !== undefined && program.runCnt > 0 && (
              <MetaRow icon={Activity} label="Avg per run" value={fmtNs(Math.round(program.runTimeNs / program.runCnt))} mono />
            )}
          </div>
        </section>

        <Separator className="bg-border/50" />

        {/* Memory */}
        <section>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Memory & Size</h3>
          <div className="divide-y divide-border/50">
            <MetaRow icon={Cpu} label="Translated" value={formatBytes(program.bytesXlated)} mono />
            <MetaRow icon={Cpu} label="Memlock" value={formatBytes(program.memlock)} mono />
            <MetaRow icon={Cpu} label="JIT compiled" value={program.jited ? "Yes" : "No"} />
          </div>
        </section>

        {/* Maps */}
        {program.mapIds.length > 0 && (
          <>
            <Separator className="bg-border/50" />
            <section>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                Maps ({program.mapIds.length})
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {program.mapIds.map(id => (
                  <span key={id} className="prog-badge text-sky-400 border-sky-400/30">
                    map #{id}
                  </span>
                ))}
              </div>
            </section>
          </>
        )}

        {/* Attachments */}
        {program.attachments.length > 0 && (
          <>
            <Separator className="bg-border/50" />
            <section>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                Attachments ({program.attachments.length})
              </h3>
              <div className="space-y-2">
                {program.attachments.map((att, i) => (
                  <div
                    key={i}
                    className="rounded-lg p-3 border text-xs"
                    style={{
                      borderColor: `${ATTACH_KIND_COLORS[att.kind] ?? "#6b7280"}30`,
                      background: `${ATTACH_KIND_COLORS[att.kind] ?? "#6b7280"}08`,
                    }}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <span
                        className="prog-badge text-[10px]"
                        style={{
                          color: ATTACH_KIND_COLORS[att.kind] ?? "#6b7280",
                          borderColor: `${ATTACH_KIND_COLORS[att.kind] ?? "#6b7280"}50`,
                        }}
                      >
                        {att.kind}
                      </span>
                      {att.attachFlags && (
                        <span className="text-[10px] text-violet-400 font-mono">[{att.attachFlags}]</span>
                      )}
                    </div>
                    <div className="text-muted-foreground font-mono text-[11px] break-all">{att.detail}</div>
                    {att.cgroupPath && (
                      <div className="text-muted-foreground/60 font-mono text-[10px] mt-1 break-all">{att.cgroupPath}</div>
                    )}
                  </div>
                ))}
              </div>
            </section>
          </>
        )}

        {/* PIDs */}
        {program.pids && program.pids.length > 0 && (
          <>
            <Separator className="bg-border/50" />
            <section>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                Owning Processes
              </h3>
              <div className="space-y-1">
                {program.pids.map((p, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs font-mono">
                    <span className="text-muted-foreground">PID {p.pid}</span>
                    <span className="text-foreground">{p.comm}</span>
                  </div>
                ))}
              </div>
            </section>
          </>
        )}

        {program.orphaned && (
          <>
            <Separator className="bg-border/50" />
            <div className="flex items-start gap-2 p-3 rounded-lg bg-destructive/10 border border-destructive/30">
              <AlertTriangle size={13} className="text-destructive shrink-0 mt-0.5" />
              <p className="text-xs text-destructive/80">
                This program is orphaned — its owning process has exited but the program remains loaded in the kernel.
              </p>
            </div>
          </>
        )}
      </div>
    </div>

    {/* Code Inspector full-screen modal */}
    {showCode && (
      <CodeInspector program={program} onClose={() => setShowCode(false)} />
    )}
    </>
  );
}

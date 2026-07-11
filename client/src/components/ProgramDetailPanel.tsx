import React, { lazy, Suspense, useMemo, useState } from "react";
import { formatRelativeTime, formatFullTimestamp, useNow } from "@/lib/time";
import {
  X,
  Copy,
  Check,
  Clock,
  Cpu,
  Hash,
  Tag,
  Database,
  Activity,
  Shield,
  AlertTriangle,
  Zap,
  Timer,
  BarChart2,
  Code2,
  Loader2,
  Share2,
  Pin,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip as RechartTooltip,
  ResponsiveContainer,
} from "recharts";
import type {
  BpfMap,
  BpfProgram,
  ProgHistory,
} from "../../../shared/ebpf-types";
import { cn } from "@/lib/utils";
import { useEbpf } from "@/contexts/EbpfContext";
import { toast } from "sonner";
import {
  samplesToCallsPerSec,
  samplesToAvgLatency,
  fmtCps,
  fmtNs,
  fmtCpu,
} from "./Sparkline";

const CodeInspector = lazy(() =>
  import("./CodeInspector").then(module => ({ default: module.CodeInspector }))
);

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
    <button
      onClick={copy}
      className="text-muted-foreground hover:text-foreground transition-colors ml-1"
    >
      {copied ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

function MetaRow({
  icon: Icon,
  label,
  value,
  mono = false,
  copyable = false,
}: {
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
      <div
        className={cn("text-xs text-foreground flex-1", mono && "font-mono")}
      >
        {value}
        {copyable && typeof value === "string" && (
          <CopyButton value={value} label={label} />
        )}
      </div>
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  color,
}: {
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
        <span className="text-[10px] text-muted-foreground uppercase tracking-wider">
          {label}
        </span>
      </div>
      <div className="text-sm font-mono font-semibold" style={{ color }}>
        {value}
      </div>
      {sub && <div className="text-[10px] text-muted-foreground">{sub}</div>}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function isSharedMap(map: BpfMap): boolean {
  return map.usedByProgIds.length > 1;
}

function SharedMapBadge({
  map,
  users,
  currentProgramId,
  onSelectProgram,
}: {
  map: BpfMap;
  users: BpfProgram[];
  currentProgramId: number;
  onSelectProgram: (id: number) => void;
}) {
  const otherUsers = users.filter(user => user.id !== currentProgramId);
  const visibleUsers = otherUsers.slice(0, 8);
  const unknownCount = Math.max(0, map.usedByProgIds.length - users.length);

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className="inline-flex cursor-help items-center gap-1 rounded border border-amber-500/35 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-mono text-amber-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-300/50"
        >
          <Share2 size={10} />
          shared by {map.usedByProgIds.length}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-80 text-left">
        <div className="space-y-2">
          <div>
            <div className="font-semibold">Shared map</div>
            <div className="text-[11px] opacity-80">
              This map is referenced by {map.usedByProgIds.length} programs.
              Shared maps often carry state, policy, counters, or tail-call
              routing between programs.
            </div>
          </div>
          {visibleUsers.length > 0 ? (
            <div className="space-y-1">
              {visibleUsers.map(user => (
                <button
                  key={user.id}
                  type="button"
                  onClick={e => {
                    e.stopPropagation();
                    onSelectProgram(user.id);
                  }}
                  title="Open this program's details"
                  className="flex w-full min-w-0 items-center gap-2 rounded bg-background/20 px-1.5 py-1 text-left transition-colors hover:bg-background/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-300/50"
                >
                  <span
                    className="h-2 w-2 shrink-0 rounded-full"
                    style={{ backgroundColor: user.color }}
                  />
                  <span className="min-w-0 flex-1 truncate font-mono text-[11px]">
                    {user.name || `prog_${user.id}`}
                  </span>
                  <span className="shrink-0 text-[10px] opacity-70">
                    {user.rawType} #{user.id}
                  </span>
                </button>
              ))}
              {otherUsers.length > visibleUsers.length && (
                <div className="text-[11px] opacity-70">
                  +{otherUsers.length - visibleUsers.length} more program
                  {otherUsers.length - visibleUsers.length === 1 ? "" : "s"}
                </div>
              )}
            </div>
          ) : (
            <div className="text-[11px] opacity-70">
              Other program details are not present in this snapshot.
            </div>
          )}
          {unknownCount > 0 && (
            <div className="text-[11px] opacity-70">
              +{unknownCount} referenced program
              {unknownCount === 1 ? "" : "s"} not present in this snapshot
            </div>
          )}
        </div>
      </TooltipContent>
    </Tooltip>
  );
}

function CodeInspectorLoading({ onClose }: { onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 bg-[oklch(0.08_0.012_240/0.98)] backdrop-blur-xl flex items-center justify-center">
      <button
        onClick={onClose}
        className="absolute top-4 right-4 p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-white/10 transition-colors"
        aria-label="Close code inspector"
      >
        <X size={18} />
      </button>
      <div className="flex items-center gap-3 rounded-xl border border-border bg-card/70 px-5 py-4 text-sm text-muted-foreground shadow-xl">
        <Loader2 size={16} className="animate-spin text-primary" />
        Loading code inspector...
      </div>
    </div>
  );
}

// Replaced by formatRelativeTime from @/lib/time — kept as alias for any remaining callers
function formatTimestamp(unix: number): string {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleString();
}

const ATTACH_KIND_COLORS: Record<string, string> = {
  xdp: "#00d4ff",
  tc: "#7c3aed",
  tcx: "#6d28d9",
  cgroup: "#3b82f6",
  flow_dissector: "#ec4899",
  netfilter: "#f43f5e",
  perf: "#f97316",
  link: "#22d3ee",
  unknown: "#6b7280",
};

// Custom tooltip for the detail chart
function ChartTooltip({
  active,
  payload,
  label,
  mode,
}: {
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
  const { maps, snapshot, focusMap, focusProgram } = useEbpf();
  const [showCode, setShowCode] = useState(false);
  const hasHistory = (history?.samples?.length ?? 0) >= 2;
  const now = useNow(30_000); // refresh relative times every 30s

  const mapById = useMemo(
    () => new Map(maps.map(map => [map.id, map])),
    [maps]
  );
  const progById = useMemo(
    () => new Map((snapshot?.programs ?? []).map(prog => [prog.id, prog])),
    [snapshot]
  );

  // Derive chart series
  const { callsSeries, latencySeries, chartData } = useMemo(() => {
    if (!hasHistory || !history)
      return { callsSeries: [], latencySeries: [], chartData: [] };
    const calls = samplesToCallsPerSec(history.samples);
    const lats = samplesToAvgLatency(history.samples);
    const data = calls.map((c, i) => ({ i, calls: c, latency: lats[i] ?? 0 }));
    return { callsSeries: calls, latencySeries: lats, chartData: data };
  }, [history, hasHistory]);

  const latest = history?.latest;
  const hasLiveStats =
    latest !== null &&
    latest !== undefined &&
    (latest.callsPerSec > 0 || latest.avgLatencyNs > 0);

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
                  style={{
                    background: program.color,
                    boxShadow: `0 0 8px ${program.color}80`,
                  }}
                />
                <span className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
                  {program.rawType}
                </span>
                {program.orphaned && (
                  <Badge
                    variant="outline"
                    className="text-[10px] px-1.5 py-0 border-destructive/50 text-destructive"
                  >
                    orphaned
                  </Badge>
                )}
              </div>
              <h2 className="text-sm font-semibold text-foreground font-mono truncate">
                {program.name || `prog_${program.id}`}
              </h2>
              <div className="text-xs text-muted-foreground mt-0.5">
                ID: {program.id}
              </div>
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
              <Button
                variant="ghost"
                size="icon"
                className="w-7 h-7"
                onClick={onClose}
              >
                <X size={14} />
              </Button>
            </div>
          </div>

          {/* State badges */}
          <div className="flex flex-wrap gap-1.5 mt-3">
            <Badge
              variant="outline"
              className="text-[10px] px-2 py-0.5"
              style={{
                borderColor: `${program.color}50`,
                color: program.color,
              }}
            >
              {program.osiLayer}
            </Badge>
            {program.jited && (
              <Badge
                variant="outline"
                className="text-[10px] px-2 py-0.5 border-emerald-500/40 text-emerald-400"
              >
                JIT compiled
              </Badge>
            )}
            {program.gplCompatible && (
              <Badge
                variant="outline"
                className="text-[10px] px-2 py-0.5 border-sky-500/40 text-sky-400"
              >
                GPL
              </Badge>
            )}
            {program.attachments.some(a =>
              a.attachFlags?.includes("multi")
            ) && (
              <Badge
                variant="outline"
                className="text-[10px] px-2 py-0.5 border-violet-500/40 text-violet-400"
              >
                multi-attach
              </Badge>
            )}
            {hasLiveStats && (
              <Badge
                variant="outline"
                className="text-[10px] px-2 py-0.5 border-cyan-500/40 text-cyan-400 animate-pulse"
              >
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
                        <AreaChart
                          data={chartData}
                          margin={{ top: 2, right: 0, bottom: 2, left: 0 }}
                        >
                          <defs>
                            <linearGradient
                              id="dp-calls"
                              x1="0"
                              y1="0"
                              x2="0"
                              y2="1"
                            >
                              <stop
                                offset="5%"
                                stopColor="#22d3ee"
                                stopOpacity={0.3}
                              />
                              <stop
                                offset="95%"
                                stopColor="#22d3ee"
                                stopOpacity={0.02}
                              />
                            </linearGradient>
                          </defs>
                          <XAxis dataKey="i" hide />
                          <YAxis hide />
                          <RechartTooltip
                            content={<ChartTooltip mode="calls" />}
                          />
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
                        <AreaChart
                          data={chartData}
                          margin={{ top: 2, right: 0, bottom: 2, left: 0 }}
                        >
                          <defs>
                            <linearGradient
                              id="dp-latency"
                              x1="0"
                              y1="0"
                              x2="0"
                              y2="1"
                            >
                              <stop
                                offset="5%"
                                stopColor="#f59e0b"
                                stopOpacity={0.3}
                              />
                              <stop
                                offset="95%"
                                stopColor="#f59e0b"
                                stopOpacity={0.02}
                              />
                            </linearGradient>
                          </defs>
                          <XAxis dataKey="i" hide />
                          <YAxis hide />
                          <RechartTooltip
                            content={<ChartTooltip mode="latency" />}
                          />
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
                    Accumulating data… stats appear after the program executes
                    with bpf_stats_enabled=1
                  </div>
                )}
              </section>
              <Separator className="bg-border/50" />
            </>
          )}

          {/* Identity */}
          <section>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
              Identity
            </h3>
            <div className="divide-y divide-border/50">
              <MetaRow icon={Hash} label="ID" value={String(program.id)} mono />
              <MetaRow
                icon={Tag}
                label="Tag"
                value={program.tag}
                mono
                copyable
              />
              {program.btfId !== undefined && (
                <MetaRow
                  icon={Database}
                  label="BTF ID"
                  value={String(program.btfId)}
                  mono
                />
              )}
              <MetaRow
                icon={Shield}
                label="GPL"
                value={program.gplCompatible ? "Yes" : "No"}
              />
            </div>
          </section>

          <Separator className="bg-border/50" />

          {/* Timing */}
          <section>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
              Timing
            </h3>
            <div className="divide-y divide-border/50">
              <MetaRow
                icon={Clock}
                label="Loaded at"
                value={
                  <span
                    title={formatFullTimestamp(program.loadedAt)}
                    className="cursor-default"
                  >
                    {formatRelativeTime(program.loadedAt, now)}
                  </span>
                }
              />
              {program.runTimeNs !== undefined && (
                <MetaRow
                  icon={Activity}
                  label="Total run time"
                  value={fmtNs(program.runTimeNs)}
                  mono
                />
              )}
              {program.runCnt !== undefined && (
                <MetaRow
                  icon={Activity}
                  label="Run count"
                  value={program.runCnt.toLocaleString()}
                  mono
                />
              )}
              {program.runTimeNs !== undefined &&
                program.runCnt !== undefined &&
                program.runCnt > 0 && (
                  <MetaRow
                    icon={Activity}
                    label="Avg per run"
                    value={fmtNs(
                      Math.round(program.runTimeNs / program.runCnt)
                    )}
                    mono
                  />
                )}
            </div>
          </section>

          <Separator className="bg-border/50" />

          {/* Memory */}
          <section>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
              Memory & Size
            </h3>
            <div className="divide-y divide-border/50">
              <MetaRow
                icon={Cpu}
                label="Translated"
                value={formatBytes(program.bytesXlated)}
                mono
              />
              <MetaRow
                icon={Cpu}
                label="Memlock"
                value={formatBytes(program.memlock)}
                mono
              />
              <MetaRow
                icon={Cpu}
                label="JIT compiled"
                value={program.jited ? "Yes" : "No"}
              />
            </div>
          </section>

          {/* Pinned paths — the ownership breadcrumb when no process holds an fd */}
          {(program.pinnedPaths?.length ?? 0) > 0 && (
            <>
              <Separator className="bg-border/50" />
              <section>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                  Pinned in bpffs ({program.pinnedPaths!.length})
                </h3>
                <div className="space-y-1">
                  {program.pinnedPaths!.map(path => (
                    <div
                      key={path}
                      className="flex items-center gap-2 text-[11px] font-mono text-muted-foreground break-all"
                    >
                      <Pin className="w-3 h-3 shrink-0 text-cyan-400/70" />
                      {path}
                    </div>
                  ))}
                </div>
              </section>
            </>
          )}

          {/* Maps */}
          {program.mapIds.length > 0 && (
            <>
              <Separator className="bg-border/50" />
              <section>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                  Maps ({program.mapIds.length})
                </h3>
                <div className="space-y-1.5">
                  {program.mapIds.map(id => {
                    const map = mapById.get(id);
                    if (!map) {
                      return (
                        <div
                          key={id}
                          className="rounded-lg border border-sky-400/20 bg-sky-400/5 px-2.5 py-2"
                        >
                          <div className="flex items-center gap-2">
                            <Database
                              size={12}
                              className="shrink-0 text-sky-400"
                            />
                            <span className="font-mono text-xs text-sky-300">
                              map #{id}
                            </span>
                            <span className="text-[10px] text-muted-foreground">
                              metadata unavailable
                            </span>
                          </div>
                        </div>
                      );
                    }

                    const users = map.usedByProgIds
                      .map(progId => progById.get(progId))
                      .filter((user): user is BpfProgram => user !== undefined);

                    return (
                      <div
                        key={id}
                        role="button"
                        tabIndex={0}
                        onClick={() => focusMap(map.id)}
                        onKeyDown={e => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            focusMap(map.id);
                          }
                        }}
                        title="Open this map on the Maps page"
                        className={cn(
                          "cursor-pointer rounded-lg border px-2.5 py-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/50",
                          isSharedMap(map)
                            ? "border-amber-500/25 bg-amber-500/5 hover:bg-amber-500/10"
                            : "border-sky-400/20 bg-sky-400/5 hover:bg-sky-400/10"
                        )}
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <Database
                            size={12}
                            className={cn(
                              "shrink-0",
                              isSharedMap(map)
                                ? "text-amber-300"
                                : "text-sky-400"
                            )}
                          />
                          <span className="font-mono text-xs text-foreground">
                            {map.name || `map_${map.id}`}
                          </span>
                          <span className="rounded border border-border/60 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                            #{map.id}
                          </span>
                          <span className="rounded border border-sky-400/25 bg-sky-400/5 px-1.5 py-0.5 text-[10px] font-mono text-sky-300">
                            {map.rawType}
                          </span>
                          {isSharedMap(map) && (
                            <SharedMapBadge
                              map={map}
                              users={users}
                              currentProgramId={program.id}
                              onSelectProgram={focusProgram}
                            />
                          )}
                        </div>
                        <div className="mt-1 text-[10px] font-mono text-muted-foreground/70">
                          key {map.bytesKey}B · value {map.bytesValue}B · max{" "}
                          {map.maxEntries.toLocaleString()} entries
                        </div>
                      </div>
                    );
                  })}
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
                          <span className="text-[10px] text-violet-400 font-mono">
                            [{att.attachFlags}]
                          </span>
                        )}
                      </div>
                      <div className="text-muted-foreground font-mono text-[11px] break-all">
                        {att.detail}
                      </div>
                      {att.cgroupPath && (
                        <div className="text-muted-foreground/60 font-mono text-[10px] mt-1 break-all">
                          {att.cgroupPath}
                        </div>
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
                    <div
                      key={i}
                      className="flex items-center gap-2 text-xs font-mono"
                    >
                      <span className="text-muted-foreground">PID {p.pid}</span>
                      <span className="text-foreground">{p.comm}</span>
                    </div>
                  ))}
                </div>
              </section>
            </>
          )}

          {/* Inferred owner — attachment-evidence attribution when no PID is visible */}
          {(!program.pids || program.pids.length === 0) && program.ownerHint && (
            <>
              <Separator className="bg-border/50" />
              <section>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                  Inferred Owner
                </h3>
                <div className="text-xs font-mono text-foreground mb-1.5">
                  {program.ownerHint.label}
                </div>
                <p className="text-[11px] leading-relaxed text-muted-foreground">
                  {program.ownerHint.reason}
                </p>
              </section>
            </>
          )}

          {program.orphaned && (
            <>
              <Separator className="bg-border/50" />
              <div className="flex items-start gap-2 p-3 rounded-lg bg-destructive/10 border border-destructive/30">
                <AlertTriangle
                  size={13}
                  className="text-destructive shrink-0 mt-0.5"
                />
                <p className="text-xs text-destructive/80">
                  This program is orphaned — its owning process has exited but
                  the program remains loaded in the kernel.
                </p>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Code Inspector full-screen modal */}
      {showCode && (
        <Suspense
          fallback={<CodeInspectorLoading onClose={() => setShowCode(false)} />}
        >
          <CodeInspector program={program} onClose={() => setShowCode(false)} />
        </Suspense>
      )}
    </>
  );
}

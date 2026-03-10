import React, { useMemo } from "react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { BpfProgram, ProgHistory } from "../../../shared/ebpf-types";
import { useEbpf } from "@/contexts/EbpfContext";
import { cn } from "@/lib/utils";
import Sparkline, { samplesToCallsPerSec, fmtCps, fmtNs } from "./Sparkline";

interface ProgBadgeProps {
  program: BpfProgram;
  showType?: boolean;
  compact?: boolean;
  className?: string;
  /** Optional history for inline activity bar */
  history?: ProgHistory | null;
  /** Max calls/sec in the current view — used to scale the activity bar width */
  maxCallsPerSec?: number;
}

export function ProgBadge({
  program,
  showType = false,
  compact = false,
  className,
  history,
  maxCallsPerSec = 0,
}: ProgBadgeProps) {
  const { setSelectedProgram } = useEbpf();

  // Derive current calls/sec from latest rates
  const callsPerSec = history?.latest?.callsPerSec ?? 0;
  const avgLatencyNs = history?.latest?.avgLatencyNs ?? 0;
  const hasStats = callsPerSec > 0 || (history?.samples?.length ?? 0) > 1;

  // Activity bar width as fraction of the busiest program in the view
  const barFraction = maxCallsPerSec > 0 ? Math.min(1, callsPerSec / maxCallsPerSec) : 0;

  // Latency color: green < 1µs, yellow < 100µs, orange < 1ms, red >= 1ms
  const latencyColor = useMemo(() => {
    if (avgLatencyNs === 0) return program.color;
    if (avgLatencyNs < 1_000) return "#22d3ee";      // cyan  < 1µs
    if (avgLatencyNs < 100_000) return "#4ade80";    // green < 100µs
    if (avgLatencyNs < 1_000_000) return "#f59e0b";  // amber < 1ms
    return "#f87171";                                 // red   >= 1ms
  }, [avgLatencyNs, program.color]);

  // Mini sparkline data (calls/sec series)
  const sparkData = useMemo(() => {
    if (!history?.samples || history.samples.length < 2) return [];
    return samplesToCallsPerSec(history.samples);
  }, [history]);

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          onClick={() => setSelectedProgram(program)}
          className={cn(
            "prog-badge transition-all hover:opacity-100 hover:scale-105 cursor-pointer",
            "flex flex-col gap-0.5",
            program.orphaned && "opacity-40 line-through",
            className
          )}
          style={{ color: program.color, borderColor: `${program.color}60` }}
        >
          {/* Top row: dot + name + type */}
          <div className="flex items-center gap-1.5 w-full">
            {!compact && (
              <span
                className="inline-block w-1.5 h-1.5 rounded-full shrink-0"
                style={{ background: program.color }}
              />
            )}
            <span className="truncate max-w-[120px]">
              {compact ? `#${program.id}` : (program.name || `prog_${program.id}`)}
            </span>
            {showType && (
              <span className="opacity-60 text-[10px] shrink-0">{program.rawType}</span>
            )}
            {/* Calls/sec label when active */}
            {hasStats && callsPerSec > 0 && (
              <span
                className="ml-auto text-[9px] font-mono shrink-0 tabular-nums"
                style={{ color: latencyColor }}
              >
                {fmtCps(callsPerSec)}
              </span>
            )}
          </div>

          {/* Activity bar — only shown when we have stats */}
          {hasStats && !compact && (
            <div className="w-full flex items-center gap-1">
              {/* Relative width bar */}
              <div className="flex-1 h-[3px] rounded-full bg-white/5 overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{
                    width: `${barFraction * 100}%`,
                    background: latencyColor,
                    opacity: barFraction > 0 ? 0.85 : 0.2,
                    minWidth: barFraction > 0 ? 3 : 0,
                  }}
                />
              </div>
              {/* Tiny sparkline */}
              {sparkData.length >= 2 && (
                <Sparkline
                  data={sparkData}
                  height={12}
                  width={36}
                  color={latencyColor}
                  variant="calls"
                />
              )}
            </div>
          )}
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        <div className="space-y-1 text-xs">
          <div className="font-semibold font-mono">{program.name || `prog_${program.id}`}</div>
          <div className="text-muted-foreground">ID: {program.id} · Type: {program.rawType}</div>
          <div className="text-muted-foreground font-mono text-[10px]">tag: {program.tag}</div>
          {hasStats && (
            <div className="border-t border-white/10 pt-1 mt-1 space-y-0.5">
              {callsPerSec > 0 && (
                <div className="text-cyan-400">
                  {fmtCps(callsPerSec)} · avg {fmtNs(avgLatencyNs)}
                </div>
              )}
              {history?.peakCallsPerSec && history.peakCallsPerSec > 0 && (
                <div className="text-white/40 text-[10px]">
                  peak {fmtCps(history.peakCallsPerSec)}
                </div>
              )}
            </div>
          )}
          {program.attachments.length > 0 && (
            <div className="text-muted-foreground">
              {program.attachments.map((a, i) => (
                <div key={i}>{a.detail}</div>
              ))}
            </div>
          )}
        </div>
      </TooltipContent>
    </Tooltip>
  );
}

interface ProgListProps {
  programs: BpfProgram[];
  maxVisible?: number;
  compact?: boolean;
  histories?: Map<number, ProgHistory>;
  maxCallsPerSec?: number;
}

export function ProgList({
  programs,
  maxVisible = 5,
  compact = false,
  histories,
  maxCallsPerSec,
}: ProgListProps) {
  const visible = programs.slice(0, maxVisible);
  const hidden = programs.length - maxVisible;

  // Compute maxCallsPerSec across visible programs if not provided
  const effectiveMax = useMemo(() => {
    if (maxCallsPerSec !== undefined) return maxCallsPerSec;
    if (!histories) return 0;
    return visible.reduce((max, p) => {
      const h = histories.get(p.id);
      return Math.max(max, h?.latest?.callsPerSec ?? 0);
    }, 0);
  }, [visible, histories, maxCallsPerSec]);

  return (
    <div className="flex flex-wrap gap-1.5">
      {visible.map(p => (
        <ProgBadge
          key={p.id}
          program={p}
          compact={compact}
          history={histories?.get(p.id)}
          maxCallsPerSec={effectiveMax}
        />
      ))}
      {hidden > 0 && (
        <span className="prog-badge text-muted-foreground border-muted-foreground/30">
          +{hidden} more
        </span>
      )}
    </div>
  );
}

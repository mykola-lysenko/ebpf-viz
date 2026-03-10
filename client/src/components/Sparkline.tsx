/**
 * Sparkline.tsx
 *
 * A tiny reusable sparkline built on recharts AreaChart.
 * Designed to be embedded inline inside badges, table cells, and detail panels.
 *
 * Props:
 *   data      – array of numbers (y-values); x-axis is implicit index
 *   height    – pixel height (default 24)
 *   width     – pixel width (default 80)
 *   color     – stroke/fill color (default cyan)
 *   variant   – "calls" | "latency" | "cpu"  controls color semantics
 *   showTooltip – show a recharts tooltip on hover (default false)
 */

import { useMemo } from "react";
import { AreaChart, Area, Tooltip, ResponsiveContainer } from "recharts";

export type SparklineVariant = "calls" | "latency" | "cpu" | "custom";

interface SparklineProps {
  data: number[];
  height?: number;
  width?: number | string;
  color?: string;
  variant?: SparklineVariant;
  showTooltip?: boolean;
  /** Format function for tooltip value */
  formatValue?: (v: number) => string;
  className?: string;
}

const VARIANT_COLORS: Record<SparklineVariant, string> = {
  calls: "#22d3ee",    // cyan-400
  latency: "#f59e0b",  // amber-400
  cpu: "#a78bfa",      // violet-400
  custom: "#22d3ee",
};

export default function Sparkline({
  data,
  height = 24,
  width = "100%",
  color,
  variant = "calls",
  showTooltip = false,
  formatValue,
  className,
}: SparklineProps) {
  const stroke = color ?? VARIANT_COLORS[variant];

  const chartData = useMemo(
    () => data.map((v, i) => ({ i, v })),
    [data]
  );

  if (data.length < 2) {
    // Not enough data — render a flat placeholder line
    return (
      <div
        className={className}
        style={{
          height,
          width: typeof width === "number" ? `${width}px` : width,
          display: "flex",
          alignItems: "center",
        }}
      >
        <div
          style={{
            width: "100%",
            height: 1,
            background: `${stroke}33`,
            borderRadius: 1,
          }}
        />
      </div>
    );
  }

  return (
    <div
      className={className}
      style={{
        height,
        width: typeof width === "number" ? `${width}px` : width,
        minWidth: 40,
      }}
    >
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 1, right: 0, bottom: 1, left: 0 }}>
          <defs>
            <linearGradient id={`sg-${variant}-${stroke.replace("#", "")}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={stroke} stopOpacity={0.35} />
              <stop offset="95%" stopColor={stroke} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          {showTooltip && (
            <Tooltip
              content={({ active, payload }) => {
                if (!active || !payload?.length) return null;
                const val = payload[0]?.value as number;
                return (
                  <div className="bg-[#0f172a] border border-white/10 rounded px-2 py-1 text-xs text-white/80">
                    {formatValue ? formatValue(val) : val.toFixed(1)}
                  </div>
                );
              }}
            />
          )}
          <Area
            type="monotone"
            dataKey="v"
            stroke={stroke}
            strokeWidth={1.5}
            fill={`url(#sg-${variant}-${stroke.replace("#", "")})`}
            dot={false}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

// ─── Derived helpers ──────────────────────────────────────────────────────────

/** Extract calls-per-second series from a ProgHistory samples array */
export function samplesToCallsPerSec(
  samples: Array<{ ts: number; runCnt: number }>
): number[] {
  const rates: number[] = [];
  for (let i = 1; i < samples.length; i++) {
    const dt = (samples[i].ts - samples[i - 1].ts) / 1000;
    if (dt <= 0) { rates.push(0); continue; }
    rates.push(Math.max(0, (samples[i].runCnt - samples[i - 1].runCnt) / dt));
  }
  return rates;
}

/** Extract avg-latency-ns series from a ProgHistory samples array */
export function samplesToAvgLatency(
  samples: Array<{ ts: number; runCnt: number; runTimeNs: number }>
): number[] {
  const lats: number[] = [];
  for (let i = 1; i < samples.length; i++) {
    const dc = samples[i].runCnt - samples[i - 1].runCnt;
    const dt = samples[i].runTimeNs - samples[i - 1].runTimeNs;
    lats.push(dc > 0 ? Math.max(0, dt / dc) : 0);
  }
  return lats;
}

/** Format nanoseconds to a human-readable string */
export function fmtNs(ns: number): string {
  if (ns < 1_000) return `${ns.toFixed(0)} ns`;
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(1)} µs`;
  return `${(ns / 1_000_000).toFixed(2)} ms`;
}

/** Format calls/sec */
export function fmtCps(cps: number): string {
  if (cps < 1000) return `${cps.toFixed(1)}/s`;
  if (cps < 1_000_000) return `${(cps / 1000).toFixed(1)}k/s`;
  return `${(cps / 1_000_000).toFixed(2)}M/s`;
}

/** Format CPU fraction as percentage */
export function fmtCpu(fraction: number): string {
  return `${(fraction * 100).toFixed(2)}%`;
}

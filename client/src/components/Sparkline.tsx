/**
 * Sparkline.tsx
 *
 * A tiny reusable sparkline rendered as inline SVG.
 * Designed to be embedded inline inside badges, table cells, and detail panels.
 *
 * Props:
 *   data      – array of numbers (y-values); x-axis is implicit index
 *   height    – pixel height (default 24)
 *   width     – pixel width (default 80)
 *   color     – stroke/fill color (default cyan)
 *   variant   – "calls" | "latency" | "cpu"  controls color semantics
 *   showTooltip – expose the latest value via a native SVG title
 */

import { useId, useMemo } from "react";

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
  const gradientId = `sparkline-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}-${variant}`;
  const chartHeight = typeof height === "number" ? Math.max(height, 2) : 24;
  const chart = useMemo(() => {
    const values = data.map(value => (Number.isFinite(value) ? value : 0));
    if (values.length < 2) return null;

    const min = Math.min(...values);
    const max = Math.max(...values);
    const range = max - min;
    const padding = 1;
    const drawableHeight = Math.max(1, chartHeight - padding * 2);
    const points = values.map((value, index) => {
      const x = (index / (values.length - 1)) * 100;
      const y =
        range === 0
          ? chartHeight / 2
          : padding + (1 - (value - min) / range) * drawableHeight;
      return { x, y };
    });
    const linePath = points
      .map((point, index) =>
        `${index === 0 ? "M" : "L"} ${point.x.toFixed(3)} ${point.y.toFixed(3)}`
      )
      .join(" ");
    const areaPath = `${linePath} L 100 ${chartHeight} L 0 ${chartHeight} Z`;

    return {
      areaPath,
      linePath,
      latestValue: values.at(-1) ?? 0,
    };
  }, [chartHeight, data]);

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
      {chart && (
        <svg
          aria-hidden={!showTooltip}
          focusable="false"
          height="100%"
          preserveAspectRatio="none"
          viewBox={`0 0 100 ${chartHeight}`}
          width="100%"
        >
          {showTooltip && (
            <title>
              {formatValue
                ? formatValue(chart.latestValue)
                : chart.latestValue.toFixed(1)}
            </title>
          )}
          <defs>
            <linearGradient id={gradientId} x1="0" x2="0" y1="0" y2="1">
              <stop offset="5%" stopColor={stroke} stopOpacity={0.35} />
              <stop offset="95%" stopColor={stroke} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <path d={chart.areaPath} fill={`url(#${gradientId})`} />
          <path
            d={chart.linePath}
            fill="none"
            stroke={stroke}
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="1.5"
            vectorEffect="non-scaling-stroke"
          />
        </svg>
      )}
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

/** Format bytes to human readable string (KB, MB, GB) */
export function fmtBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/** Format nanoseconds to human readable string */
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

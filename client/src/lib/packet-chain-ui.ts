import type { PacketVerdict, ProgramChain } from "../../../shared/ebpf-types";

export type RateDropInfo = {
  rate: number;
  label: string;
  color: string;
};

/** Classify live calls/sec changes between consecutive chain programs. */
export function classifyRateDrop(
  prevRate: number | undefined,
  currRate: number | undefined,
  options: { flagIncreases?: boolean } = {}
): RateDropInfo | null {
  if (prevRate == null || currRate == null || prevRate <= 0) return null;
  const drop = 1 - currRate / prevRate;
  if (options.flagIncreases && drop < -0.05) {
    return {
      rate: -drop,
      label: `~${Math.round(-drop * 100)}% MORE/s`,
      color: "#22d3ee",
    };
  }
  if (drop < 0.05) return null;
  if (drop < 0.2) {
    return {
      rate: drop,
      label: `~${Math.round(drop * 100)}% fewer/s`,
      color: "#f59e0b",
    };
  }
  if (drop < 0.5) {
    return {
      rate: drop,
      label: `~${Math.round(drop * 100)}% fewer/s`,
      color: "#f97316",
    };
  }
  return {
    rate: drop,
    label: `~${Math.round(drop * 100)}% fewer/s`,
    color: "#ef4444",
  };
}

export function formatRunCnt(n: number): string {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

export function formatAge(loadedAt: number): string {
  const now = Date.now() / 1000;
  const secs = Math.max(0, now - loadedAt);
  if (secs < 60) return `${Math.round(secs)}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

export function formatActions(actions: string[]): string {
  if (actions.length === 0) return "not modeled";
  const visible = actions.slice(0, 2).join(", ");
  return actions.length > 2 ? `${visible}, +${actions.length - 2}` : visible;
}

export function hasModeledReturnSemantics(chain: ProgramChain): boolean {
  const semantics = chain.packetContext?.semantics;
  if (!semantics) return false;
  return (
    semantics.pass.length > 0 ||
    semantics.drop.length > 0 ||
    semantics.redirect.length > 0 ||
    semantics.other.length > 0
  );
}

export function chainTone(
  outcomes: PacketVerdict[],
  hasUnknownBehavior: boolean
): PacketVerdict {
  if (outcomes.includes("drop")) return "drop";
  if (outcomes.includes("redirect")) return "redirect";
  if (hasUnknownBehavior || outcomes.includes("unknown")) return "unknown";
  if (outcomes.includes("other")) return "other";
  return "pass";
}

export const VERDICT_TONE_CLASSES: Record<PacketVerdict, string> = {
  pass: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  drop: "border-red-500/35 bg-red-500/10 text-red-300",
  redirect: "border-cyan-500/35 bg-cyan-500/10 text-cyan-300",
  unknown: "border-amber-500/35 bg-amber-500/10 text-amber-300",
  other: "border-slate-500/35 bg-slate-500/10 text-slate-300",
};

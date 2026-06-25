import type {
  BpfProgram,
  PacketVerdict,
  ProgramChain,
  ProgramReturnAnalysisResult,
  XlatedReturnAnalysis,
} from "../../../shared/ebpf-types";

export type ChainProgramRow = {
  chainProgram: ProgramChain["programs"][number];
  program: BpfProgram;
};

export function buildChainProgramRows(
  chain: ProgramChain,
  programs: readonly BpfProgram[]
): ChainProgramRow[] {
  const programById = new Map<number, BpfProgram>();
  for (const program of programs) {
    if (!programById.has(program.id)) {
      programById.set(program.id, program);
    }
  }

  return chain.programs.flatMap(chainProgram => {
    const program = programById.get(chainProgram.id);
    return program ? [{ chainProgram, program }] : [];
  });
}

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

export function isSideEffectOnlySocketChain(chain: ProgramChain): boolean {
  return (
    chain.hookType === "cgroup" &&
    chain.packetContext?.family === "cgroup_sock" &&
    !hasModeledReturnSemantics(chain)
  );
}

export function formatObservedReturnConstants(
  analysis: XlatedReturnAnalysis | null | undefined
): string {
  if (!analysis) return "not analyzed";

  const parts = analysis.observedConstants
    .slice()
    .sort((a, b) => a.value - b.value)
    .map(
      observed =>
        `${observed.value}${observed.exitCount > 1 ? ` x${observed.exitCount}` : ""}`
    );
  if (analysis.unknownExits.length > 0) {
    parts.push(
      `${analysis.unknownExits.length} unknown exit${analysis.unknownExits.length === 1 ? "" : "s"}`
    );
  }
  if (analysis.tailCallIndices.length > 0) {
    parts.push(
      `${analysis.tailCallIndices.length} tail call${analysis.tailCallIndices.length === 1 ? "" : "s"}`
    );
  }

  return parts.length > 0 ? parts.join(", ") : "none";
}

export function formatChainObservedReturnConstants(
  chain: ProgramChain,
  returnAnalysisById: Map<number, ProgramReturnAnalysisResult>
): string {
  const counts = new Map<number, number>();
  let analyzed = 0;
  let unknownExits = 0;
  let tailCalls = 0;

  for (const program of chain.programs) {
    const analysis = returnAnalysisById.get(program.id)?.returnAnalysis;
    if (!analysis) continue;

    analyzed += 1;
    unknownExits += analysis.unknownExits.length;
    tailCalls += analysis.tailCallIndices.length;
    for (const observed of analysis.observedConstants) {
      counts.set(
        observed.value,
        (counts.get(observed.value) ?? 0) + observed.exitCount
      );
    }
  }

  if (analyzed === 0) return "not analyzed";

  const parts = Array.from(counts.entries())
    .sort(([a], [b]) => a - b)
    .map(([value, count]) => `${value}${count > 1 ? ` x${count}` : ""}`);
  if (unknownExits > 0) {
    parts.push(`${unknownExits} unknown exit${unknownExits === 1 ? "" : "s"}`);
  }
  if (tailCalls > 0) {
    parts.push(`${tailCalls} tail call${tailCalls === 1 ? "" : "s"}`);
  }

  const missing = chain.programs.length - analyzed;
  if (missing > 0) {
    parts.push(`${missing} program${missing === 1 ? "" : "s"} not analyzed`);
  }

  return parts.length > 0 ? parts.join(", ") : "none";
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

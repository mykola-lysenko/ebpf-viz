import type {
  PacketActionSemantics,
  PacketChainPrediction,
  PacketProgramPrediction,
  PacketVerdict,
  ProgramChain,
  XlatedReturnAnalysis,
} from "./ebpf-types";

type AnalysisLookup = (
  progId: number
) => XlatedReturnAnalysis | null | undefined;

const VERDICT_ORDER: PacketVerdict[] = [
  "drop",
  "redirect",
  "other",
  "unknown",
  "pass",
];

function valuesSet(values?: number[]): Set<number> {
  return new Set(values ?? []);
}

function uniqueVerdicts(verdicts: readonly PacketVerdict[]): PacketVerdict[] {
  const seen = new Set<PacketVerdict>();
  for (const verdict of verdicts) {
    seen.add(verdict);
  }
  return VERDICT_ORDER.filter(verdict => seen.has(verdict));
}

export function classifyPacketReturnConstant(
  value: number,
  semantics: PacketActionSemantics
): PacketVerdict {
  if (valuesSet(semantics.dropValues).has(value)) return "drop";
  if (valuesSet(semantics.redirectValues).has(value)) return "redirect";
  if (valuesSet(semantics.passValues).has(value)) return "pass";
  if (valuesSet(semantics.otherValues).has(value)) return "other";
  return "unknown";
}

function verdictTone(
  verdicts: PacketVerdict[],
  hasUnknownBehavior: boolean
): PacketVerdict {
  if (verdicts.includes("drop")) return "drop";
  if (verdicts.includes("redirect")) return "redirect";
  if (hasUnknownBehavior || verdicts.includes("unknown")) return "unknown";
  if (verdicts.includes("other")) return "other";
  return "pass";
}

function verdictLabel(
  verdicts: PacketVerdict[],
  hasUnknownBehavior: boolean
): string {
  if (verdicts.includes("drop")) return "can drop";
  if (verdicts.includes("redirect")) return "can redirect";
  if (hasUnknownBehavior || verdicts.includes("unknown"))
    return "unknown verdict";
  if (verdicts.includes("other")) return "other verdict";
  if (verdicts.length === 1 && verdicts[0] === "pass") return "all exits pass";
  if (verdicts.includes("pass")) return "may pass";
  return "unknown verdict";
}

function verdictTitle(
  analysis: XlatedReturnAnalysis | null | undefined
): string {
  if (!analysis) {
    return "No return analysis is available for this program.";
  }

  const observedText =
    analysis.observedConstants.length > 0
      ? analysis.observedConstants
          .map(
            v =>
              `${v.value} (${v.exitCount} exit${v.exitCount === 1 ? "" : "s"})`
          )
          .join(", ")
      : "none";
  const unknownText = analysis.hasUnknownExits
    ? `${analysis.unknownExits.length} unknown exit${analysis.unknownExits.length === 1 ? "" : "s"}`
    : "no unknown exits";
  const tailCallText = analysis.hasTailCalls
    ? `${analysis.tailCallIndices.length} tail call${analysis.tailCallIndices.length === 1 ? "" : "s"}`
    : "no tail calls";

  return `Observed return constants: ${observedText}; ${unknownText}; ${tailCallText}.`;
}

function analyzeProgramVerdicts(
  analysis: XlatedReturnAnalysis | null | undefined,
  semantics: PacketActionSemantics
): { verdicts: PacketVerdict[]; hasUnknownBehavior: boolean } {
  if (!analysis || analysis.exitCount === 0) {
    return { verdicts: ["unknown"], hasUnknownBehavior: true };
  }

  const verdicts: PacketVerdict[] = analysis.observedConstants.map(observed =>
    classifyPacketReturnConstant(observed.value, semantics)
  );
  const hasUnknownBehavior =
    analysis.hasUnknownExits ||
    analysis.hasTailCalls ||
    verdicts.includes("unknown");

  if (hasUnknownBehavior) {
    verdicts.push("unknown");
  }

  return {
    verdicts: uniqueVerdicts(
      verdicts.length > 0 ? verdicts : (["unknown"] as const)
    ),
    hasUnknownBehavior,
  };
}

function stepCanTerminate(
  verdicts: PacketVerdict[],
  hasUnknownBehavior: boolean
): boolean {
  return (
    hasUnknownBehavior ||
    verdicts.includes("drop") ||
    verdicts.includes("redirect") ||
    verdicts.includes("other") ||
    verdicts.includes("unknown")
  );
}

function stepDefinitelyTerminates(
  verdicts: PacketVerdict[],
  hasUnknownBehavior: boolean
): boolean {
  if (hasUnknownBehavior) return false;
  if (
    verdicts.includes("pass") ||
    verdicts.includes("other") ||
    verdicts.includes("unknown")
  )
    return false;
  return verdicts.includes("drop") || verdicts.includes("redirect");
}

function summarizeChain(
  outcomes: PacketVerdict[],
  hasUnknownBehavior: boolean
): string {
  if (outcomes.length === 1 && outcomes[0] === "pass" && !hasUnknownBehavior) {
    return "All analyzed exits pass; packets should continue through this chain.";
  }

  const actions: string[] = [];
  if (outcomes.includes("pass")) actions.push("pass");
  if (outcomes.includes("drop")) actions.push("drop");
  if (outcomes.includes("redirect")) actions.push("redirect");
  if (outcomes.includes("other"))
    actions.push("take another hook-specific action");

  if (actions.length > 0 && hasUnknownBehavior) {
    return `Packets may ${actions.join(", ")}; some exits remain unknown.`;
  }
  if (actions.length > 0) {
    return `Packets may ${actions.join(" or ")} in this chain.`;
  }
  return "Packet outcome is unknown for this chain.";
}

export function predictPacketChain(
  chain: ProgramChain,
  getAnalysis: AnalysisLookup
): PacketChainPrediction | null {
  const semantics = chain.packetContext?.semantics;
  if (!semantics) return null;

  const steps: PacketProgramPrediction[] = [];
  let reachability: PacketProgramPrediction["reachability"] = "always";
  let mayReachEnd = true;
  let hasUnknownBehavior = false;
  const possibleOutcomes = new Set<PacketVerdict>();

  for (const program of chain.programs) {
    const analysis = getAnalysis(program.id);
    const { verdicts, hasUnknownBehavior: programHasUnknown } =
      analyzeProgramVerdicts(analysis, semantics);
    const canTerminateChain =
      chain.canShortCircuit && stepCanTerminate(verdicts, programHasUnknown);
    const definitelyTerminatesChain =
      chain.canShortCircuit &&
      stepDefinitelyTerminates(verdicts, programHasUnknown);
    const terminalVerdicts = verdicts.filter(verdict => verdict !== "pass");

    if (reachability !== "not-reached") {
      for (const verdict of terminalVerdicts) {
        possibleOutcomes.add(verdict);
      }
      if (programHasUnknown) {
        possibleOutcomes.add("unknown");
        hasUnknownBehavior = true;
      }
    }

    steps.push({
      progId: program.id,
      position: program.position,
      name: program.name,
      verdicts,
      label: verdictLabel(verdicts, programHasUnknown),
      tone: verdictTone(verdicts, programHasUnknown),
      title: verdictTitle(analysis),
      reachability,
      canTerminateChain,
      definitelyTerminatesChain,
      hasUnknownBehavior: programHasUnknown,
    });

    if (reachability !== "not-reached" && canTerminateChain) {
      reachability = definitelyTerminatesChain ? "not-reached" : "conditional";
      if (definitelyTerminatesChain) {
        mayReachEnd = false;
      }
    }
  }

  if (mayReachEnd) {
    possibleOutcomes.add("pass");
  }

  const outcomes = uniqueVerdicts(Array.from(possibleOutcomes));
  const firstTerminalReachability = steps.find(
    step => step.canTerminateChain && step.reachability !== "not-reached"
  )?.position;
  const firstTerminalPrograms =
    firstTerminalReachability === undefined
      ? []
      : steps.filter(step => step.position === firstTerminalReachability);
  const alwaysPass =
    outcomes.length === 1 && outcomes[0] === "pass" && !hasUnknownBehavior;
  const confidence = hasUnknownBehavior
    ? steps.every(step => step.hasUnknownBehavior)
      ? "unknown"
      : "partial"
    : "high";

  return {
    chainId: chain.hookId,
    summary: summarizeChain(outcomes, hasUnknownBehavior),
    confidence,
    possibleOutcomes: outcomes,
    alwaysPass,
    hasUnknownBehavior,
    firstTerminalPrograms,
    steps,
  };
}

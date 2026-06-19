import type {
  PacketActionSemantics,
  PacketChainPrediction,
  PacketProgramPrediction,
  PacketVerdict,
  PacketVerdictExplanation,
  ProgramChain,
  XlatedReturnAnalysis,
  XlatedReturnExit,
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

function sideEffectTitle(
  analysis: XlatedReturnAnalysis | null | undefined
): string | undefined {
  const effects = analysis?.sideEffects.effects ?? [];
  if (effects.length === 0) return undefined;

  const visible = effects
    .slice(0, 6)
    .map(effect =>
      effect.helper
        ? `${effect.label}: ${effect.helper} at insn ${effect.insnIndex}`
        : `${effect.label} at insn ${effect.insnIndex}`
    );
  if (effects.length > visible.length) {
    visible.push(`+${effects.length - visible.length} more`);
  }
  return visible.join("; ");
}

function verdictAction(verdict: PacketVerdict): string {
  if (verdict === "drop") return "Can drop";
  if (verdict === "redirect") return "Can redirect";
  if (verdict === "pass") return "Can pass";
  if (verdict === "other") return "Can take another hook-specific action";
  return "Returns an unmodeled value";
}

function sourceText(
  evidence: Pick<
    XlatedReturnExit,
    "source" | "sourceFile" | "sourceLine" | "sourceColumn"
  >
): string | undefined {
  const parts: string[] = [];
  if (evidence.sourceFile) {
    parts.push(
      evidence.sourceLine
        ? `${evidence.sourceFile}:${evidence.sourceLine}`
        : evidence.sourceFile
    );
  }
  if (evidence.source) {
    parts.push(evidence.source);
  }
  return parts.length > 0 ? parts.join(" - ") : undefined;
}

function finishSentence(text: string): string {
  return /[.!?;]$/.test(text.trim()) ? text : `${text}.`;
}

function branchConditionText(exit: XlatedReturnExit): string | undefined {
  const branch = exit.branchEvidence?.at(-1);
  if (!branch) return undefined;

  const branchText = branch.source
    ? `"${branch.source}"`
    : `branch at insn ${branch.insnIndex}`;
  if (branch.branch === "taken") return `${branchText} is taken`;
  if (branch.branch === "fallthrough") return `${branchText} falls through`;
  return branchText;
}

function constantExitExplanation(
  exit: XlatedReturnExit,
  semantics: PacketActionSemantics
): PacketVerdictExplanation | null {
  if (exit.value === undefined) return null;

  const verdict = classifyPacketReturnConstant(exit.value, semantics);
  const condition = branchConditionText(exit);
  const source = sourceText(exit);
  const location = source ? ` from ${source}` : "";
  const conditionText = condition ? ` when ${condition}` : "";

  return {
    verdict,
    summary: finishSentence(
      `${verdictAction(verdict)} with return ${exit.value} at exit ${exit.exitIndex}${conditionText}${location}`
    ),
    exitIndex: exit.exitIndex,
    returnValue: exit.value,
    source: exit.source,
    sourceFile: exit.sourceFile,
    sourceLine: exit.sourceLine,
    sourceColumn: exit.sourceColumn,
    branchEvidence: exit.branchEvidence,
  };
}

function unknownExitExplanation(
  exit: XlatedReturnExit
): PacketVerdictExplanation {
  const source = sourceText(exit);
  const location = source ? ` from ${source}` : "";
  const reason = exit.reason ?? "unknown";

  return {
    verdict: "unknown",
    summary: finishSentence(
      `May return a runtime-dependent verdict at exit ${exit.exitIndex} (${reason})${location}`
    ),
    exitIndex: exit.exitIndex,
    source: exit.source,
    sourceFile: exit.sourceFile,
    sourceLine: exit.sourceLine,
    sourceColumn: exit.sourceColumn,
    branchEvidence: exit.branchEvidence,
  };
}

function buildVerdictExplanations(
  analysis: XlatedReturnAnalysis | null | undefined,
  semantics: PacketActionSemantics
): PacketVerdictExplanation[] {
  if (!analysis) {
    return [
      {
        verdict: "unknown",
        summary: "No return analysis is available for this program.",
      },
    ];
  }
  if (analysis.exitCount === 0) {
    return [
      {
        verdict: "unknown",
        summary: "No reachable BPF exit instructions were found.",
      },
    ];
  }

  const explanations = analysis.constantExits
    .map(exit => constantExitExplanation(exit, semantics))
    .filter(
      (explanation): explanation is PacketVerdictExplanation =>
        explanation !== null
    );

  explanations.push(...analysis.unknownExits.map(unknownExitExplanation));

  if (analysis.hasTailCalls) {
    explanations.push({
      verdict: "unknown",
      summary: `Tail calls at instruction(s) ${analysis.tailCallIndices.join(", ")} can transfer the final verdict to another program.`,
    });
  }

  return explanations;
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
  hasUnknownBehavior: boolean,
  sideEffectLabels: string[]
): string {
  const sideEffectText =
    sideEffectLabels.length > 0
      ? ` Known side effects: ${sideEffectLabels.join(", ")}.`
      : "";

  if (outcomes.length === 1 && outcomes[0] === "pass" && !hasUnknownBehavior) {
    return `All analyzed exits pass; packets should continue through this chain.${sideEffectText}`;
  }

  const actions: string[] = [];
  if (outcomes.includes("pass")) actions.push("pass");
  if (outcomes.includes("drop")) actions.push("drop");
  if (outcomes.includes("redirect")) actions.push("redirect");
  if (outcomes.includes("other"))
    actions.push("take another hook-specific action");

  if (actions.length > 0 && hasUnknownBehavior) {
    return `Packets may ${actions.join(", ")}; some exits remain unknown.${sideEffectText}`;
  }
  if (actions.length > 0) {
    return `Packets may ${actions.join(" or ")} in this chain.${sideEffectText}`;
  }
  return `Packet outcome is unknown for this chain.${sideEffectText}`;
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
  const chainSideEffectLabels = new Set<string>();

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
    const sideEffectLabels = analysis?.sideEffects.labels ?? [];
    for (const label of sideEffectLabels) {
      chainSideEffectLabels.add(label);
    }

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
      verdictExplanations: buildVerdictExplanations(analysis, semantics),
      reachability,
      canTerminateChain,
      definitelyTerminatesChain,
      hasUnknownBehavior: programHasUnknown,
      hasSideEffects: sideEffectLabels.length > 0,
      sideEffectLabels,
      sideEffectTitle: sideEffectTitle(analysis),
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
  const sideEffectLabels = Array.from(chainSideEffectLabels);
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
    summary: summarizeChain(outcomes, hasUnknownBehavior, sideEffectLabels),
    confidence,
    possibleOutcomes: outcomes,
    alwaysPass,
    hasUnknownBehavior,
    hasSideEffects: sideEffectLabels.length > 0,
    sideEffectLabels,
    firstTerminalPrograms,
    steps,
  };
}

import type {
  BpfMap,
  PacketTailCallTarget,
  PacketActionSemantics,
  PacketChainPrediction,
  PacketProgramPrediction,
  PacketTailCallContinuation,
  PacketVerdict,
  PacketVerdictExplanation,
  ProgArrayTarget,
  ProgramChain,
  XlatedReturnAnalysis,
  XlatedReturnExit,
  XlatedTailCall,
} from "./ebpf-types";

type AnalysisLookup = (
  progId: number
) => XlatedReturnAnalysis | null | undefined;

interface PredictionContext {
  maps?: BpfMap[];
  programs?: Array<{ id: number; name: string; rawType?: string }>;
  progArrayTargets?: ProgArrayTarget[];
  maxTailCallDepth?: number;
}

const DEFAULT_MAX_TAIL_CALL_DEPTH = 8;
const REDIRECT_RETURN_HELPERS = new Set(["redirect", "redirect_map"]);

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

function callHelperName(disasm?: string): string | undefined {
  const body = disasm?.trim().replace(/^\([0-9a-fA-F]+\)\s+/, "");
  const match = body?.match(/^call\s+(\S+)/);
  if (!match) return undefined;

  const helper = match[1].split("#")[0].replace(/^bpf_/, "").toLowerCase();
  return helper || undefined;
}

function helperReturnVerdict(
  exit: XlatedReturnExit,
  semantics: PacketActionSemantics
): PacketVerdict | null {
  const helper = callHelperName(exit.assignmentDisasm ?? exit.exitDisasm);
  if (
    helper &&
    REDIRECT_RETURN_HELPERS.has(helper) &&
    ((semantics.redirectValues?.length ?? 0) > 0 ||
      semantics.redirect.length > 0)
  ) {
    return "redirect";
  }

  return null;
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

function hasModeledActionSemantics(semantics: PacketActionSemantics): boolean {
  return (
    (semantics.passValues?.length ?? semantics.pass.length) > 0 ||
    (semantics.dropValues?.length ?? semantics.drop.length) > 0 ||
    (semantics.redirectValues?.length ?? semantics.redirect.length) > 0 ||
    (semantics.otherValues?.length ?? semantics.other.length) > 0
  );
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

function helperReturnExplanation(
  exit: XlatedReturnExit,
  semantics: PacketActionSemantics
): PacketVerdictExplanation | null {
  const verdict = helperReturnVerdict(exit, semantics);
  if (!verdict) return null;

  const source = sourceText(exit);
  const location = source ? ` from ${source}` : "";
  const helper = callHelperName(exit.assignmentDisasm ?? exit.exitDisasm);

  return {
    verdict,
    summary: finishSentence(
      `Can ${verdict} via ${helper ? `bpf_${helper}` : "helper"} return at exit ${exit.exitIndex}; exact numeric return is runtime-dependent${location}`
    ),
    exitIndex: exit.exitIndex,
    source: exit.source,
    sourceFile: exit.sourceFile,
    sourceLine: exit.sourceLine,
    sourceColumn: exit.sourceColumn,
    branchEvidence: exit.branchEvidence,
  };
}

function tailCallsForAnalysis(
  analysis: XlatedReturnAnalysis
): XlatedTailCall[] {
  return (
    analysis.tailCalls ??
    analysis.tailCallIndices.map(
      (insnIndex): XlatedTailCall => ({
        insnIndex,
        disasm: "bpf_tail_call",
      })
    )
  );
}

function tailCallTargetKey(target: PacketTailCallTarget): string {
  return `${target.mapId}:${target.slot}`;
}

function resolveTailCallTarget(
  tailCall: XlatedTailCall,
  context: PredictionContext
): PacketTailCallTarget | undefined {
  if (tailCall.mapId === undefined || tailCall.slot === undefined) {
    return undefined;
  }

  const map = (context.maps ?? []).find(map => map.id === tailCall.mapId);
  const resolvedTarget = (context.progArrayTargets ?? []).find(
    target => target.mapId === tailCall.mapId && target.slot === tailCall.slot
  );
  const targetProgram =
    resolvedTarget !== undefined
      ? (context.programs ?? []).find(
          program => program.id === resolvedTarget.targetProgId
        )
      : undefined;

  return {
    mapId: tailCall.mapId,
    mapName: map?.name,
    slot: tailCall.slot,
    targetProgId: resolvedTarget?.targetProgId,
    targetProgName: targetProgram?.name,
    targetProgType: targetProgram?.rawType,
    resolved: resolvedTarget !== undefined,
  };
}

function continuationByTargetKey(
  continuations: PacketTailCallContinuation[]
): Map<string, PacketTailCallContinuation> {
  return new Map(
    continuations.map(continuation => [
      tailCallTargetKey(continuation.target),
      continuation,
    ])
  );
}

function continuationExplanation(
  continuation: PacketTailCallContinuation | undefined
): string {
  if (!continuation) return "";
  return ` ${continuation.summary}`;
}

function buildVerdictExplanations(
  analysis: XlatedReturnAnalysis | null | undefined,
  semantics: PacketActionSemantics,
  context: PredictionContext = {},
  continuations: PacketTailCallContinuation[] = []
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

  explanations.push(
    ...analysis.unknownExits.map(
      exit =>
        helperReturnExplanation(exit, semantics) ?? unknownExitExplanation(exit)
    )
  );

  if (analysis.hasTailCalls) {
    const continuationsByTarget = continuationByTargetKey(continuations);
    const tailCalls = tailCallsForAnalysis(analysis);

    for (const tailCall of tailCalls) {
      const tailCallTarget = resolveTailCallTarget(tailCall, context);
      const continuation =
        tailCallTarget !== undefined
          ? continuationsByTarget.get(tailCallTargetKey(tailCallTarget))
          : undefined;
      const mapText =
        tailCall.mapId !== undefined
          ? tailCallTarget?.mapName
            ? `prog-array ${tailCallTarget.mapName} (#${tailCall.mapId})`
            : `prog-array map #${tailCall.mapId}`
          : "an unresolved prog-array map";
      const slotText =
        tailCall.slot !== undefined
          ? ` slot ${tailCall.slot}`
          : " an unresolved slot";
      const resolvedTargetText =
        tailCallTarget?.targetProgId !== undefined
          ? tailCallTarget.targetProgName
            ? `program ${tailCallTarget.targetProgName} (#${tailCallTarget.targetProgId})`
            : `program #${tailCallTarget.targetProgId}`
          : null;

      explanations.push({
        verdict: continuation?.tone ?? "unknown",
        summary: resolvedTargetText
          ? `Tail call at instruction ${tailCall.insnIndex} may continue in ${resolvedTargetText} via ${tailCallTarget?.mapName ?? `map #${tailCall.mapId}`}[${tailCall.slot}].${continuationExplanation(continuation)}`
          : `Tail call at instruction ${tailCall.insnIndex} may continue in ${mapText}${slotText}; target program is not resolved from current snapshot.`,
        exitIndex: tailCall.insnIndex,
        source: tailCall.source,
        sourceFile: tailCall.sourceFile,
        sourceLine: tailCall.sourceLine,
        sourceColumn: tailCall.sourceColumn,
        tailCallTarget,
      });
    }
  }

  return explanations;
}

function tailCallTargetsForAnalysis(
  analysis: XlatedReturnAnalysis | null | undefined,
  context: PredictionContext
): PacketTailCallTarget[] {
  if (!analysis) return [];

  return tailCallsForAnalysis(analysis).flatMap(tailCall => {
    const target = resolveTailCallTarget(tailCall, context);
    return target ? [target] : [];
  });
}

interface ProgramBehavior {
  verdicts: PacketVerdict[];
  hasUnknownBehavior: boolean;
  tailCallContinuations: PacketTailCallContinuation[];
  sideEffectLabels: string[];
}

function programTargetLabel(target: PacketTailCallTarget): string {
  return target.targetProgId !== undefined
    ? `${target.targetProgName ?? "program"} (#${target.targetProgId})`
    : "target program";
}

function confidenceFromBehavior(
  verdicts: PacketVerdict[],
  hasUnknownBehavior: boolean
): PacketChainPrediction["confidence"] {
  if (!hasUnknownBehavior) return "high";
  return verdicts.some(verdict => verdict !== "unknown") ? "partial" : "unknown";
}

function summarizeContinuationBehavior(
  target: PacketTailCallTarget,
  verdicts: PacketVerdict[],
  hasUnknownBehavior: boolean,
  sideEffectLabels: string[]
): string {
  const targetText = programTargetLabel(target);
  const sideEffectText =
    sideEffectLabels.length > 0
      ? ` Known side effects: ${sideEffectLabels.join(", ")}.`
      : "";

  if (verdicts.length === 1 && verdicts[0] === "pass" && !hasUnknownBehavior) {
    return `${targetText}: all analyzed exits pass.${sideEffectText}`;
  }

  const actions: string[] = [];
  if (verdicts.includes("pass")) actions.push("pass");
  if (verdicts.includes("drop")) actions.push("drop");
  if (verdicts.includes("redirect")) actions.push("redirect");
  if (verdicts.includes("other"))
    actions.push("take another hook-specific action");

  if (actions.length > 0 && hasUnknownBehavior) {
    return `${targetText}: may ${actions.join(", ")}; some paths remain unknown.${sideEffectText}`;
  }
  if (actions.length > 0) {
    return `${targetText}: may ${actions.join(" or ")}.${sideEffectText}`;
  }
  return `${targetText}: packet outcome is unknown.${sideEffectText}`;
}

function unknownContinuation(
  target: PacketTailCallTarget,
  depth: number,
  status: PacketTailCallContinuation["status"]
): PacketTailCallContinuation {
  const reason =
    status === "cycle"
      ? "tail-call cycle detected"
      : status === "max-depth"
        ? "tail-call analysis depth limit reached"
        : "return analysis unavailable";
  const summary = `${programTargetLabel(target)}: ${reason}; outcome is unknown.`;

  return {
    target,
    depth,
    status,
    verdicts: ["unknown"],
    label: "unknown verdict",
    tone: "unknown",
    summary,
    confidence: "unknown",
    hasUnknownBehavior: true,
    hasSideEffects: false,
    sideEffectLabels: [],
    continuations: [],
  };
}

function analyzeTailCallContinuations(
  analysis: XlatedReturnAnalysis,
  semantics: PacketActionSemantics,
  getAnalysis: AnalysisLookup,
  context: PredictionContext,
  path: number[],
  depth: number
): {
  continuations: PacketTailCallContinuation[];
  hasUnresolvedTailCalls: boolean;
} {
  const continuations: PacketTailCallContinuation[] = [];
  let hasUnresolvedTailCalls = false;
  const maxDepth = context.maxTailCallDepth ?? DEFAULT_MAX_TAIL_CALL_DEPTH;

  for (const tailCall of tailCallsForAnalysis(analysis)) {
    const target = resolveTailCallTarget(tailCall, context);
    if (!target?.resolved || target.targetProgId === undefined) {
      hasUnresolvedTailCalls = true;
      continue;
    }

    const nextDepth = depth + 1;
    if (path.includes(target.targetProgId)) {
      continuations.push(unknownContinuation(target, nextDepth, "cycle"));
      continue;
    }
    if (nextDepth > maxDepth) {
      continuations.push(unknownContinuation(target, nextDepth, "max-depth"));
      continue;
    }

    const targetAnalysis = getAnalysis(target.targetProgId);
    if (!targetAnalysis) {
      continuations.push(
        unknownContinuation(target, nextDepth, "analysis-unavailable")
      );
      continue;
    }

    const behavior = analyzeProgramBehavior(
      target.targetProgId,
      targetAnalysis,
      semantics,
      getAnalysis,
      context,
      [...path, target.targetProgId],
      nextDepth
    );

    continuations.push({
      target,
      depth: nextDepth,
      status: "analyzed",
      verdicts: behavior.verdicts,
      label: verdictLabel(behavior.verdicts, behavior.hasUnknownBehavior),
      tone: verdictTone(behavior.verdicts, behavior.hasUnknownBehavior),
      summary: summarizeContinuationBehavior(
        target,
        behavior.verdicts,
        behavior.hasUnknownBehavior,
        behavior.sideEffectLabels
      ),
      confidence: confidenceFromBehavior(
        behavior.verdicts,
        behavior.hasUnknownBehavior
      ),
      hasUnknownBehavior: behavior.hasUnknownBehavior,
      hasSideEffects: behavior.sideEffectLabels.length > 0,
      sideEffectLabels: behavior.sideEffectLabels,
      continuations: behavior.tailCallContinuations,
    });
  }

  return { continuations, hasUnresolvedTailCalls };
}

function analyzeProgramBehavior(
  progId: number,
  analysis: XlatedReturnAnalysis | null | undefined,
  semantics: PacketActionSemantics,
  getAnalysis: AnalysisLookup,
  context: PredictionContext,
  path: number[] = [progId],
  depth = 0
): ProgramBehavior {
  if (!analysis) {
    return {
      verdicts: ["unknown"],
      hasUnknownBehavior: true,
      tailCallContinuations: [],
      sideEffectLabels: [],
    };
  }

  const verdicts: PacketVerdict[] = [
    ...analysis.observedConstants.map(observed =>
      classifyPacketReturnConstant(observed.value, semantics)
    ),
    ...analysis.unknownExits
      .map(exit => helperReturnVerdict(exit, semantics))
      .filter((verdict): verdict is PacketVerdict => verdict !== null),
  ];
  const sideEffectLabels = new Set(analysis.sideEffects.labels);
  let hasUnknownBehavior =
    analysis.exitCount === 0 ||
    analysis.hasUnknownExits ||
    verdicts.includes("unknown");

  if (analysis.hasTailCalls) {
    const { continuations, hasUnresolvedTailCalls } =
      analyzeTailCallContinuations(
        analysis,
        semantics,
        getAnalysis,
        context,
        path,
        depth
      );
    if (hasUnresolvedTailCalls) {
      hasUnknownBehavior = true;
    }
    for (const continuation of continuations) {
      verdicts.push(...continuation.verdicts);
      if (continuation.hasUnknownBehavior) {
        hasUnknownBehavior = true;
      }
      for (const label of continuation.sideEffectLabels) {
        sideEffectLabels.add(label);
      }
    }
    if (hasUnknownBehavior) {
      verdicts.push("unknown");
    }
    return {
      verdicts: uniqueVerdicts(
        verdicts.length > 0 ? verdicts : (["unknown"] as const)
      ),
      hasUnknownBehavior,
      tailCallContinuations: continuations,
      sideEffectLabels: Array.from(sideEffectLabels),
    };
  }

  if (hasUnknownBehavior) {
    verdicts.push("unknown");
  }

  return {
    verdicts: uniqueVerdicts(
      verdicts.length > 0 ? verdicts : (["unknown"] as const)
    ),
    hasUnknownBehavior,
    tailCallContinuations: [],
    sideEffectLabels: Array.from(sideEffectLabels),
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
  chain: ProgramChain,
  outcomes: PacketVerdict[],
  hasUnknownBehavior: boolean
): string {
  const semantics = chain.packetContext?.semantics;

  if (!semantics || !hasModeledActionSemantics(semantics)) {
    const family = chain.packetContext?.family ?? chain.hookType;
    return `Return-value semantics for this ${family} hook are not modeled yet.`;
  }

  const subject =
    chain.packetContext?.family === "cgroup_sock_addr"
      ? "Socket operations"
      : "Packets";

  if (outcomes.length === 1 && outcomes[0] === "pass" && !hasUnknownBehavior) {
    return `All analyzed exits pass; ${subject.toLowerCase()} should continue through this chain.`;
  }

  const actions: string[] = [];
  if (outcomes.includes("pass")) {
    actions.push(
      chain.packetContext?.family === "cgroup_sock_addr" ? "be allowed" : "pass"
    );
  }
  if (outcomes.includes("drop")) {
    actions.push(
      chain.packetContext?.family === "cgroup_sock_addr" ? "be denied" : "drop"
    );
  }
  if (outcomes.includes("redirect")) actions.push("redirect");
  if (outcomes.includes("other"))
    actions.push("take another hook-specific action");

  if (actions.length > 0 && hasUnknownBehavior) {
    return `${subject} may ${actions.join(", ")}; some exits remain unknown.`;
  }
  if (actions.length > 0) {
    return `${subject} may ${actions.join(" or ")} in this chain.`;
  }
  return `${subject} outcome is unknown for this chain.`;
}

function summarizeChainEffects(sideEffectLabels: string[]): string {
  return sideEffectLabels.length > 0
    ? sideEffectLabels.join(", ")
    : "none detected";
}

export function predictPacketChain(
  chain: ProgramChain,
  getAnalysis: AnalysisLookup,
  context: PredictionContext = {}
): PacketChainPrediction | null {
  const semantics = chain.packetContext?.semantics;
  if (!semantics) return null;
  const hasModeledSemantics = hasModeledActionSemantics(semantics);

  const steps: PacketProgramPrediction[] = [];
  let reachability: PacketProgramPrediction["reachability"] = "always";
  let mayReachEnd = true;
  let hasUnknownBehavior = false;
  const possibleOutcomes = new Set<PacketVerdict>();
  const chainSideEffectLabels = new Set<string>();

  for (const program of chain.programs) {
    const analysis = getAnalysis(program.id);
    const behavior = analyzeProgramBehavior(
      program.id,
      analysis,
      semantics,
      getAnalysis,
      context
    );
    const { verdicts, hasUnknownBehavior: programHasUnknown } = behavior;
    const canTerminateChain =
      hasModeledSemantics &&
      chain.canShortCircuit &&
      stepCanTerminate(verdicts, programHasUnknown);
    const definitelyTerminatesChain =
      hasModeledSemantics &&
      chain.canShortCircuit &&
      stepDefinitelyTerminates(verdicts, programHasUnknown);
    const terminalVerdicts = verdicts.filter(verdict => verdict !== "pass");
    const sideEffectLabels = behavior.sideEffectLabels;
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
      verdictExplanations: buildVerdictExplanations(
        analysis,
        semantics,
        context,
        behavior.tailCallContinuations
      ),
      reachability,
      canTerminateChain,
      definitelyTerminatesChain,
      hasUnknownBehavior: programHasUnknown,
      tailCallTargets: tailCallTargetsForAnalysis(analysis, context),
      tailCallContinuations: behavior.tailCallContinuations,
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

  if (mayReachEnd && hasModeledSemantics) {
    possibleOutcomes.add("pass");
  } else if (!hasModeledSemantics) {
    possibleOutcomes.add("unknown");
    hasUnknownBehavior = true;
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
  const verdictSummary = summarizeChain(
    chain,
    outcomes,
    hasUnknownBehavior
  );
  const effectSummary = summarizeChainEffects(sideEffectLabels);

  return {
    chainId: chain.hookId,
    verdictSummary,
    effectSummary,
    summary: verdictSummary,
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

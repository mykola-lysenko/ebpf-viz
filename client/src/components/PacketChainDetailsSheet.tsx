import type { ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  GitBranch,
  Route,
  ShieldCheck,
} from "lucide-react";
import { ProgBadge } from "@/components/ProgBadge";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { VERDICT_TONE_CLASSES } from "@/lib/packet-chain-ui";
import { cn } from "@/lib/utils";
import type {
  BpfProgram,
  PacketChainPrediction,
  PacketProgramPrediction,
  PacketTailCallContinuation,
  PacketTailCallTarget,
  PacketVerdictExplanation,
  ProgramChain,
  ProgramReturnAnalysisResult,
  XlatedBranchEvidence,
  XlatedReturnExit,
  XlatedSideEffect,
  XlatedTailCall,
} from "../../../shared/ebpf-types";

interface PacketChainDetailsSheetProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  chain: ProgramChain | null;
  prediction: PacketChainPrediction | null;
  programs: BpfProgram[];
  returnAnalysisById: Map<number, ProgramReturnAnalysisResult>;
}

function formatSource(
  exit: XlatedReturnExit | XlatedSideEffect | XlatedBranchEvidence
): string | null {
  const parts: string[] = [];
  if (exit.sourceFile) {
    parts.push(
      exit.sourceLine
        ? `${exit.sourceFile}:${exit.sourceLine}`
        : exit.sourceFile
    );
  }
  if (exit.source) {
    parts.push(exit.source);
  }
  return parts.length > 0 ? parts.join(" - ") : null;
}

function formatBranchEvidence(branch: XlatedBranchEvidence): string {
  if (branch.branch === "taken") {
    return branch.targetIndex !== undefined
      ? `taken -> ${branch.targetIndex}`
      : "taken";
  }
  if (branch.branch === "fallthrough") return "fallthrough";
  return "branch edge";
}

function formatReachability(step: PacketProgramPrediction): string {
  if (step.reachability === "always") return "runs if packet reaches this hook";
  if (step.reachability === "conditional")
    return "may be skipped by an earlier program";
  return "not reached after analyzed terminal verdict";
}

function formatConfidence(prediction: PacketChainPrediction): string {
  if (prediction.confidence === "high") {
    return "High: every analyzed exit resolved to modeled return values or known helper outcomes, and no tail calls or unknown exits were found.";
  }
  if (prediction.confidence === "partial") {
    return "Partial: some behavior is modeled, but at least one exit, return path, or tail call remains unknown.";
  }
  return "Unknown: return analysis could not resolve enough behavior to predict the packet path.";
}

function EmptyLine({ children }: { children: ReactNode }) {
  return <div className="text-[11px] text-muted-foreground/60">{children}</div>;
}

function returnEvidenceKey(
  value: Pick<XlatedReturnExit | PacketVerdictExplanation, "exitIndex"> & {
    assignmentIndex?: number;
  }
): string {
  return `${value.exitIndex ?? "unknown"}:${value.assignmentIndex ?? "unknown"}`;
}

function VerdictExplanations({
  explanations,
}: {
  explanations: PacketVerdictExplanation[];
}) {
  if (explanations.length === 0) {
    return <EmptyLine>No verdict explanations available.</EmptyLine>;
  }

  return (
    <div className="space-y-1">
      {explanations.slice(0, 8).map((explanation, index) => (
        <div
          key={`${explanation.verdict}-${explanation.exitIndex ?? index}-${explanation.returnValue ?? "unknown"}`}
          className={cn(
            "rounded border px-2 py-1.5",
            VERDICT_TONE_CLASSES[explanation.verdict]
          )}
        >
          <div className="text-[11px] leading-relaxed">
            {explanation.summary}
          </div>
          {explanation.branchEvidence &&
            explanation.branchEvidence.length > 0 && (
              <div className="mt-1 text-[10px] text-current/70">
                Path uses {explanation.branchEvidence.length} resolved branch
                {explanation.branchEvidence.length === 1 ? "" : "es"}.
              </div>
            )}
        </div>
      ))}
      {explanations.length > 8 && (
        <EmptyLine>+{explanations.length - 8} more explanations.</EmptyLine>
      )}
    </div>
  );
}

function ReturnEvidence({
  exits,
  label,
  modeledLabel,
}: {
  exits: XlatedReturnExit[];
  label: string;
  modeledLabel?: string;
}) {
  if (exits.length === 0) {
    return <EmptyLine>No {label} exits.</EmptyLine>;
  }

  return (
    <div className="space-y-1">
      {exits.slice(0, 8).map(exit => (
        <div
          key={`${label}-${exit.exitIndex}`}
          className="rounded border border-border/60 bg-muted/20 px-2 py-1"
        >
          <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
            <span className="text-muted-foreground">exit {exit.exitIndex}</span>
            {exit.value !== undefined && (
              <span className="rounded border border-border/60 px-1 py-0.5 text-foreground">
                return {exit.value}
              </span>
            )}
            {exit.reason && (
              <span
                className={cn(
                  "rounded border px-1 py-0.5",
                  modeledLabel
                    ? "border-cyan-500/25 bg-cyan-500/5 text-cyan-300"
                    : "border-amber-500/25 bg-amber-500/5 text-amber-300"
                )}
              >
                {modeledLabel ?? exit.reason}
              </span>
            )}
          </div>
          <div className="mt-0.5 break-all text-[10px] font-mono text-muted-foreground">
            {exit.assignmentDisasm ?? exit.exitDisasm}
          </div>
          {formatSource(exit) && (
            <div className="mt-0.5 break-words text-[10px] text-muted-foreground/70">
              {formatSource(exit)}
            </div>
          )}
          {exit.branchEvidence && exit.branchEvidence.length > 0 && (
            <div className="mt-1 space-y-1 border-t border-border/50 pt-1">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                Path evidence
              </div>
              {exit.branchEvidence.map(branch => (
                <div
                  key={`${exit.exitIndex}-${branch.insnIndex}-${branch.branch}`}
                  className="rounded border border-border/40 bg-background/30 px-1.5 py-1"
                >
                  <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                    <span className="text-muted-foreground">
                      insn {branch.insnIndex}
                    </span>
                    <span className="rounded border border-border/50 px-1 py-0.5 text-foreground/80">
                      {formatBranchEvidence(branch)}
                    </span>
                  </div>
                  <div className="mt-0.5 break-all text-[10px] font-mono text-muted-foreground">
                    {branch.disasm}
                  </div>
                  {formatSource(branch) && (
                    <div className="mt-0.5 break-words text-[10px] text-muted-foreground/70">
                      {formatSource(branch)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
      {exits.length > 8 && (
        <EmptyLine>
          +{exits.length - 8} more {label} exits.
        </EmptyLine>
      )}
    </div>
  );
}

function SideEffectEvidence({ effects }: { effects: XlatedSideEffect[] }) {
  if (effects.length === 0) {
    return <EmptyLine>No known side effects detected.</EmptyLine>;
  }

  return (
    <div className="space-y-1">
      {effects.slice(0, 8).map(effect => (
        <div
          key={`${effect.kind}-${effect.insnIndex}`}
          className="rounded border border-cyan-500/20 bg-cyan-500/5 px-2 py-1"
        >
          <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono text-cyan-300">
            <span>{effect.label}</span>
            <span className="text-cyan-300/60">insn {effect.insnIndex}</span>
            {effect.helper && (
              <span className="text-cyan-300/70">{effect.helper}</span>
            )}
          </div>
          <div className="mt-0.5 break-all text-[10px] font-mono text-muted-foreground">
            {effect.disasm}
          </div>
          {formatSource(effect) && (
            <div className="mt-0.5 break-words text-[10px] text-muted-foreground/70">
              {formatSource(effect)}
            </div>
          )}
        </div>
      ))}
      {effects.length > 8 && (
        <EmptyLine>+{effects.length - 8} more side effects.</EmptyLine>
      )}
    </div>
  );
}

function formatTailCall(tailCall: XlatedTailCall): string {
  const mapText =
    tailCall.mapId !== undefined
      ? `prog-array map #${tailCall.mapId}`
      : "unresolved prog-array map";
  const slotText =
    tailCall.slot !== undefined ? `slot ${tailCall.slot}` : "unresolved slot";
  return `insn ${tailCall.insnIndex}: ${mapText}, ${slotText}`;
}

function TailCallEvidence({
  tailCalls,
  fallbackIndices,
  targets,
  continuations,
}: {
  tailCalls?: XlatedTailCall[];
  fallbackIndices: number[];
  targets: PacketTailCallTarget[];
  continuations: PacketTailCallContinuation[];
}) {
  const calls =
    tailCalls ??
    fallbackIndices.map(
      (insnIndex): XlatedTailCall => ({
        insnIndex,
        disasm: "bpf_tail_call",
      })
    );

  return (
    <div className="mt-1 space-y-1">
      {calls.map(tailCall => {
        const target = targets.find(
          candidate =>
            candidate.mapId === tailCall.mapId &&
            candidate.slot === tailCall.slot
        );
        const continuation = continuations.find(
          candidate =>
            candidate.target.mapId === tailCall.mapId &&
            candidate.target.slot === tailCall.slot
        );
        return (
          <div
            key={tailCall.insnIndex}
            className="rounded border border-amber-500/25 bg-amber-500/5 px-2 py-1 text-[11px] text-amber-300"
          >
            <div>
              {formatTailCall(tailCall)}.{" "}
              {target?.targetProgId !== undefined
                ? `Resolved target: ${target.targetProgName ?? "program"} (#${target.targetProgId}).`
                : "Final verdict may be in another program."}
            </div>
            {continuation && (
              <div className="mt-1 rounded border border-border/50 bg-background/30 px-1.5 py-1 text-[10px] text-muted-foreground">
                <span
                  className={cn(
                    "mr-1 rounded border px-1 py-0.5 font-mono",
                    VERDICT_TONE_CLASSES[continuation.tone]
                  )}
                >
                  {continuation.label}
                </span>
                {continuation.summary}
                {continuation.continuations.length > 0 && (
                  <div className="mt-1 text-[10px] text-muted-foreground/70">
                    Follows {continuation.continuations.length} nested tail-call
                    continuation
                    {continuation.continuations.length === 1 ? "" : "s"}.
                  </div>
                )}
              </div>
            )}
            <div className="mt-0.5 break-all font-mono text-[10px] text-amber-300/70">
              {tailCall.disasm}
            </div>
            {tailCall.mapAssignmentDisasm && (
              <div className="mt-0.5 break-all font-mono text-[10px] text-amber-300/60">
                map: {tailCall.mapAssignmentDisasm}
              </div>
            )}
            {tailCall.slotAssignmentDisasm && (
              <div className="mt-0.5 break-all font-mono text-[10px] text-amber-300/60">
                slot: {tailCall.slotAssignmentDisasm}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function StepDetails({
  step,
  program,
  analysisResult,
}: {
  step: PacketProgramPrediction;
  program?: BpfProgram;
  analysisResult?: ProgramReturnAnalysisResult;
}) {
  const analysis = analysisResult?.returnAnalysis;
  const modeledHelperExitKeys = new Set(
    step.verdictExplanations
      .filter(
        explanation => explanation.evidenceKind === "modeled-helper-return"
      )
      .map(returnEvidenceKey)
  );
  const modeledHelperExits =
    analysis?.unknownExits.filter(exit =>
      modeledHelperExitKeys.has(returnEvidenceKey(exit))
    ) ?? [];
  const unresolvedUnknownExits =
    analysis?.unknownExits.filter(
      exit => !modeledHelperExitKeys.has(returnEvidenceKey(exit))
    ) ?? [];
  const tailCallSummary =
    step.tailCallContinuations.length > 0
      ? step.tailCallContinuations
          .map(
            continuation =>
              `${continuation.target.targetProgName ?? "program"}: ${continuation.label}`
          )
          .join("; ")
      : undefined;

  return (
    <div className="rounded-xl border border-border/70 bg-card/50 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex h-6 w-6 items-center justify-center rounded-full border border-border/70 bg-muted/40 text-[11px] font-bold">
          {step.position}
        </span>
        {program ? (
          <ProgBadge program={program} />
        ) : (
          <span className="text-sm font-mono">{step.name}</span>
        )}
        <span
          className={cn(
            "rounded border px-1.5 py-0.5 text-[10px] font-mono",
            VERDICT_TONE_CLASSES[step.tone]
          )}
        >
          verdict: {step.label}
        </span>
        <span
          className={cn(
            "rounded border px-1.5 py-0.5 text-[10px] font-mono",
            step.hasSideEffects
              ? "border-cyan-500/25 bg-cyan-500/5 text-cyan-300/80"
              : "border-border/60 bg-muted/20 text-muted-foreground/70"
          )}
        >
          effects:{" "}
          {step.hasSideEffects ? step.sideEffectLabels.join(", ") : "none"}
        </span>
        {step.tailCallContinuations.length > 0 && (
          <span
            className="rounded border border-amber-500/25 bg-amber-500/5 px-1.5 py-0.5 text-[10px] font-mono text-amber-300/80"
            title={tailCallSummary}
          >
            tail calls: {step.tailCallContinuations.length}
          </span>
        )}
      </div>

      <div className="mt-2 grid gap-2 text-[11px] text-muted-foreground sm:grid-cols-2">
        <div>
          <span className="text-muted-foreground/60">Reachability: </span>
          {formatReachability(step)}
        </div>
        <div>
          <span className="text-muted-foreground/60">Chain impact: </span>
          {step.definitelyTerminatesChain
            ? "always terminates normal flow"
            : step.canTerminateChain
              ? "may terminate normal flow"
              : "does not terminate normal flow based on modeled exits"}
        </div>
      </div>

      {analysisResult?.error && (
        <div className="mt-2 rounded border border-amber-500/25 bg-amber-500/5 px-2 py-1 text-[11px] text-amber-300">
          Analysis unavailable: {analysisResult.error}
        </div>
      )}

      <div className="mt-3">
        <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Verdict Explanation
        </div>
        <VerdictExplanations explanations={step.verdictExplanations} />
      </div>

      {analysis && (
        <div className="mt-3 space-y-3">
          <div>
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Return Evidence
            </div>
            <ReturnEvidence exits={analysis.constantExits} label="constant" />
          </div>

          {modeledHelperExits.length > 0 && (
            <div>
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-cyan-300/80">
                Modeled Helper Returns
              </div>
              <ReturnEvidence
                exits={modeledHelperExits}
                label="modeled helper"
                modeledLabel="modeled helper return"
              />
            </div>
          )}

          {(unresolvedUnknownExits.length > 0 || analysis.hasTailCalls) && (
            <div>
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-amber-300/80">
                {analysis.hasTailCalls
                  ? "Tail Calls & Unresolved Returns"
                  : "Unresolved Returns"}
              </div>
              <ReturnEvidence
                exits={unresolvedUnknownExits}
                label="unresolved"
              />
              {analysis.hasTailCalls && (
                <TailCallEvidence
                  tailCalls={analysis.tailCalls}
                  fallbackIndices={analysis.tailCallIndices}
                  targets={step.tailCallTargets}
                  continuations={step.tailCallContinuations}
                />
              )}
            </div>
          )}

          <div>
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-cyan-300/80">
              Side Effects
            </div>
            <SideEffectEvidence effects={analysis.sideEffects.effects} />
          </div>
        </div>
      )}
    </div>
  );
}

export function PacketChainDetailsSheet({
  open,
  onOpenChange,
  chain,
  prediction,
  programs,
  returnAnalysisById,
}: PacketChainDetailsSheetProps) {
  const programsById = new Map(programs.map(program => [program.id, program]));

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full gap-0 p-0 sm:max-w-3xl">
        <SheetHeader className="border-b border-border/70 p-5 pr-12">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="font-mono text-[10px]">
              {chain?.packetContext?.family ?? chain?.hookType ?? "chain"}
              {chain?.packetContext?.direction &&
              chain.packetContext.direction !== "unknown"
                ? `/${chain.packetContext.direction}`
                : ""}
            </Badge>
            {prediction?.possibleOutcomes.map(outcome => (
              <span
                key={outcome}
                className={cn(
                  "rounded border px-1.5 py-0.5 text-[10px] font-mono",
                  VERDICT_TONE_CLASSES[outcome]
                )}
              >
                {outcome}
              </span>
            ))}
          </div>
          <SheetTitle className="font-mono text-base">
            {chain?.hookLabel ?? "Packet Chain"}
          </SheetTitle>
          <SheetDescription>
            {chain?.attachPoint} - {chain?.attachType} -{" "}
            {chain?.programs.length ?? 0} program chain
          </SheetDescription>
        </SheetHeader>

        {chain && prediction ? (
          <ScrollArea className="min-h-0 flex-1">
            <div className="space-y-4 p-5">
              <section className="rounded-xl border border-border/70 bg-muted/20 p-4">
                <div className="flex items-start gap-3">
                  <Route className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-foreground">
                      verdict: {prediction.verdictSummary}
                    </div>
                    <div className="mt-1 text-xs text-cyan-300/85">
                      effects: {prediction.effectSummary}
                    </div>
                    <div className="mt-1 text-xs text-muted-foreground">
                      {formatConfidence(prediction)}
                    </div>
                  </div>
                </div>
              </section>

              <div className="grid gap-3 sm:grid-cols-3">
                <div className="rounded-lg border border-border/70 bg-card/40 p-3">
                  <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider text-muted-foreground">
                    <ShieldCheck className="h-3.5 w-3.5" />
                    Confidence
                  </div>
                  <div className="mt-1 text-sm font-semibold">
                    {prediction.confidence}
                  </div>
                </div>
                <div className="rounded-lg border border-border/70 bg-card/40 p-3">
                  <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider text-muted-foreground">
                    <GitBranch className="h-3.5 w-3.5" />
                    First Stop
                  </div>
                  <div className="mt-1 text-sm font-semibold">
                    {prediction.firstTerminalPrograms[0]
                      ? `#${prediction.firstTerminalPrograms[0].position} ${prediction.firstTerminalPrograms[0].name}`
                      : "none"}
                  </div>
                </div>
                <div className="rounded-lg border border-border/70 bg-card/40 p-3">
                  <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider text-muted-foreground">
                    <Activity className="h-3.5 w-3.5" />
                    Side Effects
                  </div>
                  <div className="mt-1 text-sm font-semibold">
                    {prediction.hasSideEffects
                      ? prediction.sideEffectLabels.join(", ")
                      : "none detected"}
                  </div>
                </div>
              </div>

              <Separator />

              <section className="space-y-2">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-amber-300" />
                  <h3 className="text-sm font-semibold">Execution Steps</h3>
                </div>
                <div className="space-y-3">
                  {prediction.steps.map(step => (
                    <StepDetails
                      key={step.progId}
                      step={step}
                      program={programsById.get(step.progId)}
                      analysisResult={returnAnalysisById.get(step.progId)}
                    />
                  ))}
                </div>
              </section>
            </div>
          </ScrollArea>
        ) : (
          <div className="p-5 text-sm text-muted-foreground">
            Select a predicted packet chain to inspect details.
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}

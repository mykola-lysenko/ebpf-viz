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
import { cn } from "@/lib/utils";
import type {
  BpfProgram,
  PacketChainPrediction,
  PacketProgramPrediction,
  PacketVerdict,
  ProgramChain,
  ProgramReturnAnalysisResult,
  XlatedReturnExit,
  XlatedSideEffect,
} from "../../../shared/ebpf-types";

const VERDICT_TONE_CLASSES: Record<PacketVerdict, string> = {
  pass: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  drop: "border-red-500/35 bg-red-500/10 text-red-300",
  redirect: "border-cyan-500/35 bg-cyan-500/10 text-cyan-300",
  unknown: "border-amber-500/35 bg-amber-500/10 text-amber-300",
  other: "border-slate-500/35 bg-slate-500/10 text-slate-300",
};

interface PacketChainDetailsSheetProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  chain: ProgramChain | null;
  prediction: PacketChainPrediction | null;
  programs: BpfProgram[];
  returnAnalysisById: Map<number, ProgramReturnAnalysisResult>;
}

function formatSource(
  exit: XlatedReturnExit | XlatedSideEffect
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

function formatReachability(step: PacketProgramPrediction): string {
  if (step.reachability === "always") return "runs if packet reaches this hook";
  if (step.reachability === "conditional")
    return "may be skipped by an earlier program";
  return "not reached after analyzed terminal verdict";
}

function formatConfidence(prediction: PacketChainPrediction): string {
  if (prediction.confidence === "high") {
    return "High: every analyzed exit resolved to modeled return values and no tail calls or unknown exits were found.";
  }
  if (prediction.confidence === "partial") {
    return "Partial: some behavior is modeled, but at least one exit, return path, or tail call remains unknown.";
  }
  return "Unknown: return analysis could not resolve enough behavior to predict the packet path.";
}

function EmptyLine({ children }: { children: ReactNode }) {
  return <div className="text-[11px] text-muted-foreground/60">{children}</div>;
}

function ReturnEvidence({
  exits,
  label,
}: {
  exits: XlatedReturnExit[];
  label: string;
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
              <span className="rounded border border-amber-500/25 bg-amber-500/5 px-1 py-0.5 text-amber-300">
                {exit.reason}
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
          {step.label}
        </span>
        {step.hasSideEffects && (
          <span className="rounded border border-cyan-500/25 bg-cyan-500/5 px-1.5 py-0.5 text-[10px] font-mono text-cyan-300/80">
            effects: {step.sideEffectLabels.join(", ")}
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

      {analysis && (
        <div className="mt-3 space-y-3">
          <div>
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Return Evidence
            </div>
            <ReturnEvidence exits={analysis.constantExits} label="constant" />
          </div>

          {(analysis.unknownExits.length > 0 || analysis.hasTailCalls) && (
            <div>
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-amber-300/80">
                Uncertainty
              </div>
              <ReturnEvidence exits={analysis.unknownExits} label="unknown" />
              {analysis.hasTailCalls && (
                <div className="mt-1 rounded border border-amber-500/25 bg-amber-500/5 px-2 py-1 text-[11px] text-amber-300">
                  Tail calls at instruction(s):{" "}
                  {analysis.tailCallIndices.join(", ")}. Final verdict may be in
                  another program.
                </div>
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
                      {prediction.summary}
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

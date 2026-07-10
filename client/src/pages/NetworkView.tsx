import React, { useState, useMemo } from "react";
import { useEbpf } from "@/contexts/EbpfContext";
import { PacketChainDetailsSheet } from "@/components/PacketChainDetailsSheet";
import { ProgBadge } from "@/components/ProgBadge";
import {
  Network,
  ChevronDown,
  ChevronRight,
  Wifi,
  Share2,
  AlertTriangle,
  Box,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { fmtBytes, fmtCps } from "@/components/Sparkline";
import { usePacketChainAnalysis } from "@/hooks/usePacketChainAnalysis";
import {
  chainTone,
  classifyRateDrop,
  buildChainProgramRows,
  formatActions,
  formatAge,
  formatRunCnt,
  VERDICT_TONE_CLASSES,
} from "@/lib/packet-chain-ui";
import {
  buildTcpCongestionControlSummaries,
  type StructOpsAlgorithmSummary,
} from "@/lib/struct-ops-summary";
import { predictPacketChain } from "../../../shared/packet-chain-prediction";
import type {
  BpfProgram,
  NetworkInterface,
  PacketChainPrediction,
  ProgHistory,
  ProgArrayTarget,
  ProgramChain,
  ProgramReturnAnalysisResult,
} from "../../../shared/ebpf-types";

const OSI_LAYERS = [
  {
    key: "L2" as const,
    label: "L2 — Data Link",
    sublabel: "XDP, raw packet",
    color: "#00d4ff",
    description:
      "eXpress Data Path hooks at the earliest point in the NIC driver",
  },
  {
    key: "L3" as const,
    label: "L3 — Network",
    sublabel: "TC, netfilter",
    color: "#7c3aed",
    description: "Traffic Control classifiers/actions and netfilter hooks",
  },
  {
    key: "L4" as const,
    label: "L4 — Transport",
    sublabel: "sk_filter, flow_dissector",
    color: "#3b82f6",
    description: "Socket filters, flow dissection, and transport-layer hooks",
  },
  {
    key: "L7" as const,
    label: "L7 — Application",
    sublabel: "sk_msg, sockops",
    color: "#8b5cf6",
    description:
      "Socket message redirection and TCP socket operation callbacks",
  },
];

// Layers shown for NIC interfaces
const NIC_LAYERS = OSI_LAYERS.filter(l => l.key === "L2" || l.key === "L3");
// Layers shown for sockmap interfaces
const SOCKMAP_LAYERS = OSI_LAYERS.filter(l => l.key === "L4" || l.key === "L7");

type ChainProgram = ProgramChain["programs"][number];

function formatTcStats(stats: NonNullable<ChainProgram["tc"]>["stats"]): string {
  if (!stats) return "";
  const parts: string[] = [];
  if (stats.packets != null) parts.push(`${formatRunCnt(stats.packets)} pkts`);
  if (stats.bytes != null) parts.push(`${formatRunCnt(stats.bytes)} bytes`);
  if (stats.drops != null && stats.drops > 0) {
    parts.push(`${formatRunCnt(stats.drops)} drops`);
  }
  return parts.join(", ");
}

type TcDirection = "ingress" | "egress";

function directionFromText(value: string): TcDirection | undefined {
  const lower = value.toLowerCase();
  if (lower.includes("ingress")) return "ingress";
  if (lower.includes("egress")) return "egress";
  return undefined;
}

function TcDirectionMismatchBadge({
  attachType,
  programName,
  attachDirection,
  title,
}: {
  attachType: string;
  programName: string;
  attachDirection?: TcDirection;
  title?: string;
}) {
  const resolvedAttachDirection =
    attachDirection ?? directionFromText(attachType);
  const nameDirection = directionFromText(programName);
  if (
    !resolvedAttachDirection ||
    !nameDirection ||
    resolvedAttachDirection === nameDirection
  ) {
    return null;
  }

  return (
    <span
      className="inline-flex items-center gap-1 rounded border border-amber-500/30 bg-amber-500/5 px-1.5 py-0.5 text-[9px] font-mono text-amber-300/85"
      title={
        title ??
        `Program name contains "${nameDirection}", but the attachment reports ${resolvedAttachDirection} (${attachType}). Program names are not authoritative for packet direction.`
      }
    >
      <AlertTriangle size={8} />
      name says {nameDirection}
    </span>
  );
}

function TcAttachmentDirectionWarning({
  program,
  ifaceName,
}: {
  program: BpfProgram;
  ifaceName: string;
}) {
  const attachment = program.attachments.find(att => {
    if (att.kind !== "tc" && att.kind !== "tcx") return false;
    if (att.ifname !== ifaceName) return false;
    const attachDirection = att.direction ?? directionFromText(att.detail);
    const nameDirection = directionFromText(program.name);
    return (
      attachDirection !== undefined &&
      nameDirection !== undefined &&
      attachDirection !== nameDirection
    );
  });

  if (!attachment) return null;

  return (
    <TcDirectionMismatchBadge
      attachType={attachment.detail}
      programName={program.name}
      attachDirection={attachment.direction}
    />
  );
}

function TcFilterMetadata({
  attachType,
  programName,
  tc,
}: {
  attachType: string;
  programName: string;
  tc?: ChainProgram["tc"];
}) {
  if (!tc) return null;
  const attachDirection = directionFromText(attachType);
  const nameDirection = directionFromText(programName);
  const directionMismatch =
    attachDirection && nameDirection && attachDirection !== nameDirection;
  const statsText = formatTcStats(tc.stats);
  const title = [
    "Detailed TC filter metadata from tc -s -d -j filter show.",
    attachDirection ? `tc attach direction: ${attachDirection}` : null,
    directionMismatch
      ? `Program name contains "${nameDirection}", but tc reports this filter on ${attachType}. Program names are not authoritative for packet direction.`
      : null,
    tc.priority != null ? `priority/pref: ${tc.priority}` : null,
    tc.chain != null ? `chain: ${tc.chain}` : null,
    tc.handle ? `handle: ${tc.handle}` : null,
    tc.protocol ? `protocol: ${tc.protocol}` : null,
    tc.directAction != null ? `direct-action: ${tc.directAction}` : null,
    tc.actionCount != null ? `actions: ${tc.actionCount}` : null,
    statsText ? `action stats: ${statsText}` : null,
  ]
    .filter(Boolean)
    .join("\n");

  return (
    <>
      <TcDirectionMismatchBadge
        attachType={attachType}
        programName={programName}
        attachDirection={attachDirection}
        title={directionMismatch ? title : undefined}
      />
      {tc.priority != null && (
        <span
          className="rounded border border-violet-500/25 bg-violet-500/5 px-1.5 py-0.5 text-[9px] font-mono text-violet-300/80"
          title={title}
        >
          pref {tc.priority}
        </span>
      )}
      {tc.handle && (
        <span
          className="rounded border border-violet-500/20 bg-violet-500/5 px-1.5 py-0.5 text-[9px] font-mono text-violet-300/70"
          title={title}
        >
          handle {tc.handle}
        </span>
      )}
      {tc.directAction && (
        <span
          className="rounded border border-sky-500/25 bg-sky-500/5 px-1.5 py-0.5 text-[9px] font-mono text-sky-300/80"
          title={title}
        >
          direct-action
        </span>
      )}
      {tc.actionCount != null && tc.actionCount > 0 && (
        <span
          className="rounded border border-slate-500/25 bg-slate-500/5 px-1.5 py-0.5 text-[9px] font-mono text-slate-300/80"
          title={title}
        >
          actions {tc.actionCount}
        </span>
      )}
      {tc.stats?.drops != null && tc.stats.drops > 0 && (
        <span
          className="rounded border border-red-500/25 bg-red-500/5 px-1.5 py-0.5 text-[9px] font-mono text-red-300/80"
          title={title}
        >
          tc drops {formatRunCnt(tc.stats.drops)}
        </span>
      )}
    </>
  );
}

function OsiLayerRow({
  layerDef,
  ifaceName,
  programs,
  chains,
  returnAnalysisById,
  returnAnalysisLoading,
  progArrayTargets,
}: {
  layerDef: (typeof OSI_LAYERS)[0];
  ifaceName: string;
  programs: NetworkInterface["layers"]["L2"];
  chains?: ProgramChain[];
  returnAnalysisById: Map<number, ProgramReturnAnalysisResult>;
  returnAnalysisLoading: boolean;
  progArrayTargets: ProgArrayTarget[];
}) {
  const { historyMap, maps, snapshot } = useEbpf();
  const hasProgs = programs.length > 0;
  const [selectedChainDetails, setSelectedChainDetails] = useState<{
    chain: ProgramChain;
    prediction: PacketChainPrediction;
    programs: BpfProgram[];
  } | null>(null);

  // Render chain rows from ProgramChain itself, then resolve live program metadata.
  // This keeps displayed rows aligned with the "chain of N" header even when a
  // program appears in multiple bpftool attachment records.
  const { chainGroups, unchained } = useMemo(() => {
    const chainedProgramIds = new Set<number>();
    const chainGroups =
      chains
        ?.map(chain => {
          const rows = buildChainProgramRows(chain, programs);
          for (const row of rows) {
            chainedProgramIds.add(row.program.id);
          }
          return { chain, rows };
        })
        .filter(group => group.rows.length > 0) ?? [];

    const unchained: BpfProgram[] = [];
    const seenUnchainedIds = new Set<number>();
    for (const p of programs) {
      if (!chainedProgramIds.has(p.id) && !seenUnchainedIds.has(p.id)) {
        unchained.push(p);
        seenUnchainedIds.add(p.id);
      }
    }
    return { chainGroups, unchained };
  }, [chains, programs]);

  return (
    <>
      <div className={cn("osi-layer", hasProgs && "has-progs")}>
        <div
          className="w-16 shrink-0 text-center"
          style={{ color: layerDef.color }}
        >
          <div className="text-xs font-bold font-mono">{layerDef.key}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5 leading-tight">
            {layerDef.sublabel}
          </div>
        </div>
        <div
          className="w-px self-stretch shrink-0"
          style={{ background: `${layerDef.color}30` }}
        />
        <div className="flex-1 min-w-0">
          <div className="text-xs text-muted-foreground mb-1">
            {layerDef.description}
          </div>
          {hasProgs ? (
            <div className="space-y-2">
              {/* Chain groups — programs shown in execution order */}
              {chainGroups.map(({ chain, rows }) => {
                const chainPrograms = rows.map(row => row.program);
                const hasAnyAnalysis = chain.programs.some(program =>
                  returnAnalysisById.has(program.id)
                );
                const prediction =
                  chain.packetContext &&
                  (hasAnyAnalysis || !returnAnalysisLoading)
                    ? predictPacketChain(
                        chain,
                        progId =>
                          returnAnalysisById.get(progId)?.returnAnalysis,
                        {
                          maps,
                          programs: snapshot?.programs ?? [],
                          progArrayTargets,
                        }
                      )
                    : null;
                const predictionStepsById = new Map(
                  prediction?.steps.map(step => [step.position, step]) ?? []
                );
                const firstTerminal = prediction?.firstTerminalPrograms[0];

                return (
                  <div key={chain.hookId}>
                    <div className="flex items-center gap-1.5 mb-1">
                      <span className="text-[10px] text-muted-foreground/70 font-mono">
                        {chain.attachType}
                      </span>
                      <span className="text-[9px] text-muted-foreground/50">
                        chain of {chain.programs.length}
                      </span>
                      {chain.canShortCircuit && (
                        <span className="text-[9px] text-amber-400/70 flex items-center gap-0.5">
                          <AlertTriangle size={8} />
                          can short-circuit
                        </span>
                      )}
                    </div>
                    {chain.packetContext && (
                      <div
                        className="mb-1 ml-1 flex flex-wrap items-center gap-1.5 text-[9px] font-mono text-muted-foreground/70"
                        title={chain.packetContext.summary}
                      >
                        <span className="rounded border border-border/60 px-1 py-0.5 text-muted-foreground">
                          {chain.packetContext.family}
                          {chain.packetContext.direction !== "unknown" &&
                            `/${chain.packetContext.direction}`}
                        </span>
                        <span className="rounded border border-emerald-500/25 bg-emerald-500/5 px-1 py-0.5 text-emerald-400/80">
                          pass:{" "}
                          {formatActions(chain.packetContext.semantics.pass)}
                        </span>
                        <span className="rounded border border-red-500/25 bg-red-500/5 px-1 py-0.5 text-red-400/80">
                          drop:{" "}
                          {formatActions(chain.packetContext.semantics.drop)}
                        </span>
                        {chain.packetContext.semantics.redirect.length > 0 && (
                          <span className="rounded border border-cyan-500/25 bg-cyan-500/5 px-1 py-0.5 text-cyan-400/80">
                            redirect:{" "}
                            {formatActions(
                              chain.packetContext.semantics.redirect
                            )}
                          </span>
                        )}
                      </div>
                    )}
                    {chain.packetContext && (
                      <div className="mb-1.5 ml-1">
                        {prediction ? (
                          <button
                            type="button"
                            className={cn(
                              "w-full rounded border px-2 py-1 text-left text-[10px] leading-snug transition-colors hover:bg-accent/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50",
                              VERDICT_TONE_CLASSES[
                                chainTone(
                                  prediction.possibleOutcomes,
                                  prediction.hasUnknownBehavior
                                )
                              ]
                            )}
                            title={
                              firstTerminal
                                ? `First program that may alter normal chain flow: #${firstTerminal.position} ${firstTerminal.name}. Confidence: ${prediction.confidence}.`
                                : `Confidence: ${prediction.confidence}.`
                            }
                            onClick={() =>
                              setSelectedChainDetails({
                                chain,
                                prediction,
                                programs: chainPrograms,
                              })
                            }
                          >
                            <span className="block font-medium">
                              verdict: {prediction.verdictSummary}
                            </span>
                            <span className="block opacity-80">
                              effects: {prediction.effectSummary}
                            </span>
                            <span className="opacity-75">
                              confidence: {prediction.confidence}
                            </span>
                            {firstTerminal && (
                              <span className="ml-1 opacity-75">
                                first possible stop: #{firstTerminal.position}{" "}
                                {firstTerminal.name}
                              </span>
                            )}
                            <span className="ml-1 opacity-60">
                              click for details
                            </span>
                          </button>
                        ) : (
                          <div className="rounded border border-border/60 px-2 py-1 text-[10px] text-muted-foreground/60">
                            Predicting packet path…
                          </div>
                        )}
                      </div>
                    )}
                    <div className="space-y-0.5 ml-1">
                      {rows.map((row, pIdx) => {
                        const p = row.program;
                        const pos = row.chainProgram.position;
                        const predictionStep = predictionStepsById.get(pos);
                        // Drop indicator: compare live rates, not cumulative run_cnt
                        const currRate = historyMap.get(p.id)?.latest
                          ?.callsPerSec;
                        const prevRate =
                          chain.canShortCircuit && pIdx > 0
                            ? historyMap.get(rows[pIdx - 1].program.id)?.latest
                                ?.callsPerSec
                            : undefined;
                        const dropInfo = classifyRateDrop(prevRate, currRate);
                        return (
                          <React.Fragment key={`${chain.hookId}:${pos}:${p.id}`}>
                            {dropInfo && (
                              <div
                                className="flex items-center gap-1 ml-5 text-[9px] font-mono py-0.5"
                                style={{ color: dropInfo.color }}
                              >
                                <AlertTriangle size={8} />
                                {dropInfo.label} (live rate)
                              </div>
                            )}
                            <div className="flex items-center gap-1.5 flex-wrap">
                              {pos != null && (
                                <span
                                  className="w-4 h-4 rounded-full flex items-center justify-center text-[9px] font-bold shrink-0"
                                  style={{
                                    background: `${p.color}20`,
                                    border: `1.5px solid ${p.color}`,
                                    color: p.color,
                                  }}
                                >
                                  {pos}
                                </span>
                              )}
                              <ProgBadge program={p} />
                              <TcFilterMetadata
                                attachType={chain.attachType}
                                programName={p.name}
                                tc={row.chainProgram.tc}
                              />
                              {predictionStep && (
                                <span
                                  className={cn(
                                    "rounded border px-1.5 py-0.5 text-[9px] font-mono",
                                    VERDICT_TONE_CLASSES[predictionStep.tone]
                                  )}
                                  title={predictionStep.title}
                                >
                                  verdict: {predictionStep.label}
                                </span>
                              )}
                              {predictionStep?.hasSideEffects && (
                                <span
                                  className="rounded border border-cyan-500/25 bg-cyan-500/5 px-1.5 py-0.5 text-[9px] font-mono text-cyan-300/80"
                                  title={predictionStep.sideEffectTitle}
                                >
                                  effects:{" "}
                                  {formatActions(
                                    predictionStep.sideEffectLabels
                                  )}
                                </span>
                              )}
                              {predictionStep &&
                                predictionStep.tailCallContinuations.length >
                                  0 && (
                                  <span
                                    className="rounded border border-amber-500/25 bg-amber-500/5 px-1.5 py-0.5 text-[9px] font-mono text-amber-300/80"
                                    title={predictionStep.tailCallContinuations
                                      .map(continuation => continuation.summary)
                                      .join("; ")}
                                  >
                                    tail call →{" "}
                                    {formatActions(
                                      predictionStep.tailCallContinuations.map(
                                        continuation =>
                                          continuation.target.targetProgName ??
                                          `#${continuation.target.targetProgId ?? "unknown"}`
                                      )
                                    )}
                                  </span>
                                )}
                              {predictionStep?.reachability ===
                                "conditional" && (
                                <span
                                  className="rounded border border-amber-500/25 bg-amber-500/5 px-1.5 py-0.5 text-[9px] font-mono text-amber-300/80"
                                  title="An earlier program may terminate packet processing before this program runs."
                                >
                                  conditional
                                </span>
                              )}
                              {predictionStep?.reachability ===
                                "not-reached" && (
                                <span
                                  className="rounded border border-slate-500/25 bg-slate-500/5 px-1.5 py-0.5 text-[9px] font-mono text-slate-300/80"
                                  title="An earlier analyzed program always terminates normal chain flow before this program."
                                >
                                  not reached
                                </span>
                              )}
                              {chain.packetContext &&
                                !predictionStep &&
                                (() => {
                                  const result = returnAnalysisById.get(p.id);
                                  if (returnAnalysisLoading && !result) {
                                    return (
                                      <span className="rounded border border-border/60 px-1.5 py-0.5 text-[9px] font-mono text-muted-foreground/60">
                                        analyzing
                                      </span>
                                    );
                                  }
                                  if (result?.error) {
                                    return (
                                      <span
                                        className="rounded border border-amber-500/25 bg-amber-500/5 px-1.5 py-0.5 text-[9px] font-mono text-amber-300/80"
                                        title={result.error}
                                      >
                                        analysis unavailable
                                      </span>
                                    );
                                  }
                                  return null;
                                })()}
                              <span className="text-[9px] font-mono text-muted-foreground/50 tabular-nums shrink-0">
                                {p.runCnt != null &&
                                  `${formatRunCnt(p.runCnt)} total`}
                                {p.loadedAt > 0 &&
                                  ` · loaded ${formatAge(p.loadedAt)}`}
                              </span>
                            </div>
                          </React.Fragment>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
              {/* Unchained programs */}
              {unchained.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {unchained.map(p => (
                    <span
                      key={p.id}
                      className="inline-flex items-center gap-1.5 flex-wrap"
                    >
                      <ProgBadge program={p} />
                      <TcAttachmentDirectionWarning
                        program={p}
                        ifaceName={ifaceName}
                      />
                    </span>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <span className="text-xs text-muted-foreground/50 italic">
              No programs attached
            </span>
          )}
        </div>
        <Badge
          variant="outline"
          className="text-[10px] px-1.5 py-0 shrink-0 self-start"
          style={
            hasProgs
              ? { borderColor: `${layerDef.color}50`, color: layerDef.color }
              : {}
          }
        >
          {programs.length}
        </Badge>
      </div>
      <PacketChainDetailsSheet
        open={selectedChainDetails !== null}
        onOpenChange={open => {
          if (!open) setSelectedChainDetails(null);
        }}
        chain={selectedChainDetails?.chain ?? null}
        prediction={selectedChainDetails?.prediction ?? null}
        programs={selectedChainDetails?.programs ?? []}
        returnAnalysisById={returnAnalysisById}
      />
    </>
  );
}

function confidenceClasses(confidence: StructOpsAlgorithmSummary["confidence"]) {
  switch (confidence) {
    case "high":
      return "border-emerald-500/25 bg-emerald-500/5 text-emerald-300/80";
    case "medium":
      return "border-amber-500/25 bg-amber-500/5 text-amber-300/80";
    case "low":
      return "border-slate-500/25 bg-slate-500/5 text-slate-300/80";
  }
}

function algorithmSourceSummary(algorithm: StructOpsAlgorithmSummary): string {
  if (algorithm.instanceCount > 1 && algorithm.mapNames.length > 0) {
    return `${algorithm.sourceLabel} · ${algorithm.mapNames[0]} · ${algorithm.instanceCount} instances`;
  }
  return `source: ${algorithm.sourceLabel}${
    algorithm.sourceDetail ? ` · ${algorithm.sourceDetail}` : ""
  }`;
}

function TcpCongestionControlStructOpsCard({
  algorithms,
  historyMap,
  statsEnabled,
}: {
  algorithms: StructOpsAlgorithmSummary<BpfProgram>[];
  historyMap: Map<number, ProgHistory>;
  statsEnabled: boolean;
}) {
  if (algorithms.length === 0) return null;

  const callbackProgramCount = algorithms.reduce(
    (total, algorithm) => total + algorithm.count,
    0
  );
  const roleCount = algorithms.reduce(
    (total, algorithm) => total + algorithm.callbackRoleCount,
    0
  );
  const duplicateInstanceCount = algorithms.reduce(
    (total, algorithm) => total + algorithm.duplicateInstanceCount,
    0
  );
  const activeCount = algorithms.reduce(
    (total, algorithm) => total + algorithm.activeCount,
    0
  );
  const totalCallsPerSec = algorithms.reduce(
    (total, algorithm) => total + algorithm.totalCallsPerSec,
    0
  );
  const totalMemlock = algorithms.reduce(
    (total, algorithm) => total + algorithm.totalMemlock,
    0
  );

  return (
    <div className="glass rounded-xl p-4 border-teal-500/20">
      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Network size={15} className="text-teal-400" />
            TCP Congestion Control
            <span className="rounded border border-teal-500/25 bg-teal-500/5 px-1.5 py-0.5 text-[9px] font-mono text-teal-300/80">
              struct_ops
            </span>
          </h2>
          <p className="text-xs text-muted-foreground mt-1 max-w-3xl">
            Registered BPF TCP congestion-control algorithms. These callbacks
            influence transport behavior such as congestion window, pacing, and
            state transitions; they are not packet classifier chains and do not
            directly pass/drop individual packets.
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5 text-[10px] font-mono">
          <span className="rounded border border-teal-500/25 bg-teal-500/5 px-1.5 py-0.5 text-teal-300/80">
            {algorithms.length} algorithm{algorithms.length === 1 ? "" : "s"}
          </span>
          <span className="rounded border border-border/60 px-1.5 py-0.5 text-muted-foreground">
            {roleCount} role{roleCount === 1 ? "" : "s"}
          </span>
          <span className="rounded border border-border/60 px-1.5 py-0.5 text-muted-foreground">
            {callbackProgramCount} callback program
            {callbackProgramCount === 1 ? "" : "s"}
          </span>
          {duplicateInstanceCount > 0 && (
            <span
              className="rounded border border-amber-500/25 bg-amber-500/5 px-1.5 py-0.5 text-amber-300/80"
              title="Multiple struct_ops registrations for the same inferred algorithm. These are loaded BPF objects, not sockets."
            >
              {duplicateInstanceCount} duplicate instance
              {duplicateInstanceCount === 1 ? "" : "s"}
            </span>
          )}
          {statsEnabled && totalCallsPerSec > 0 ? (
            <span className="rounded border border-cyan-500/25 bg-cyan-500/5 px-1.5 py-0.5 text-cyan-300/80">
              {fmtCps(totalCallsPerSec)}
            </span>
          ) : (
            <span className="rounded border border-border/60 px-1.5 py-0.5 text-muted-foreground">
              {fmtBytes(totalMemlock)}
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {algorithms.map(algorithm => {
          return (
            <div
              key={`${algorithm.kind}:${algorithm.algorithm}`}
              className={cn(
                "rounded-lg border bg-white/[0.03] p-3",
                algorithm.duplicateInstanceCount > 0
                  ? "border-amber-500/25"
                  : "border-white/8"
              )}
            >
              <div className="flex items-start justify-between gap-3 mb-2">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-sm font-semibold text-foreground">
                      {algorithm.algorithm}
                    </span>
                    <span
                      className={cn(
                        "rounded border px-1.5 py-0.5 text-[9px] font-mono",
                        confidenceClasses(algorithm.confidence)
                      )}
                      title={`Inference confidence: ${algorithm.confidence}. Source: ${algorithm.sourceLabel} (${algorithm.sourceDetail}).`}
                    >
                      {algorithm.confidence}
                    </span>
                  </div>
                  <div
                    className="text-[10px] text-muted-foreground truncate"
                    title={[
                      `source: ${algorithm.sourceLabel}`,
                      algorithm.sourceDetail,
                      algorithm.mapNames.length > 0
                        ? `struct_ops map${algorithm.mapNames.length === 1 ? "" : "s"}: ${algorithm.mapNames.join(", ")}`
                        : null,
                      algorithm.btfIds.length > 0
                        ? `BTF id${algorithm.btfIds.length === 1 ? "" : "s"}: ${algorithm.btfIds.join(", ")}`
                        : null,
                      `loaded callback programs: ${algorithm.count}`,
                      `callback roles: ${algorithm.callbackRoleCount}`,
                      algorithm.duplicateInstanceCount > 0
                        ? `duplicate instances: ${algorithm.duplicateInstanceCount}`
                        : null,
                    ]
                      .filter(Boolean)
                      .join("\n")}
                  >
                    {algorithmSourceSummary(algorithm)}
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <div className="text-[11px] font-mono text-teal-300">
                    {algorithm.callbackRoleCount} role
                    {algorithm.callbackRoleCount === 1 ? "" : "s"}
                  </div>
                  <div className="text-[10px] font-mono text-muted-foreground">
                    {algorithm.instanceCount > 1
                      ? `${algorithm.instanceCount} inst · ${algorithm.count} progs`
                      : `${algorithm.count} prog${algorithm.count === 1 ? "" : "s"}`}
                  </div>
                </div>
              </div>

              {algorithm.duplicateInstanceCount > 0 && (
                <div
                  className="mb-2 rounded border border-amber-500/20 bg-amber-500/5 px-2 py-1 text-[10px] text-amber-200/80"
                  title="Duplicate instances mean multiple loaded struct_ops registrations with the same inferred algorithm name. This consumes kernel memory, but does not mean one instance per socket."
                >
                  {algorithm.duplicateInstanceCount} extra loaded instance
                  {algorithm.duplicateInstanceCount === 1 ? "" : "s"} detected
                </div>
              )}

              <div className="space-y-1.5">
                {algorithm.callbacks.slice(0, 6).map(callback => (
                  <div
                    key={callback.program.id}
                    className="flex items-center gap-2 min-w-0"
                  >
                    <ProgBadge
                      program={callback.program}
                      history={historyMap.get(callback.program.id)}
                      compact
                    />
                    <span
                      className="text-[10px] text-muted-foreground truncate"
                      title={`callback: ${callback.descriptor.callback}\nsource: ${callback.descriptor.sourceLabel} (${callback.descriptor.sourceDetail})\nconfidence: ${callback.descriptor.confidence}`}
                    >
                      {callback.descriptor.callbackLabel}
                    </span>
                    <span className="ml-auto text-[10px] font-mono text-muted-foreground/70 shrink-0">
                      {callback.callsPerSec > 0
                        ? fmtCps(callback.callsPerSec)
                        : fmtBytes(callback.program.memlock)}
                    </span>
                  </div>
                ))}
                {algorithm.callbacks.length > 6 && (
                  <div className="text-[10px] text-muted-foreground/60">
                    +{algorithm.callbacks.length - 6} more callback program
                    {algorithm.callbacks.length - 6 === 1 ? "" : "s"}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {statsEnabled && activeCount > 0 && (
        <div className="mt-3 text-[10px] text-muted-foreground">
          {activeCount} callback program{activeCount === 1 ? "" : "s"} currently
          have runtime activity.
        </div>
      )}
    </div>
  );
}

function InterfaceCard({
  iface,
  tcChains,
  returnAnalysisById,
  returnAnalysisLoading,
  progArrayTargets,
}: {
  iface: NetworkInterface;
  tcChains: ProgramChain[];
  returnAnalysisById: Map<number, ProgramReturnAnalysisResult>;
  returnAnalysisLoading: boolean;
  progArrayTargets: ProgArrayTarget[];
}) {
  const [expanded, setExpanded] = useState(iface.allPrograms.length > 0);
  const totalProgs = iface.allPrograms.length;
  const isSockmap = iface.kind === "sockmap";

  // NIC cards show L2+L3; sockmap cards show L4+L7
  const visibleLayers = isSockmap ? SOCKMAP_LAYERS : NIC_LAYERS;

  // Filter TC chains relevant to this interface
  const ifaceChains = useMemo(
    () => tcChains.filter(c => c.attachPoint === iface.name),
    [tcChains, iface.name]
  );

  const iconBg = isSockmap
    ? "oklch(0.65 0.18 290 / 0.15)"
    : "oklch(0.70 0.18 160 / 0.15)";
  const iconBorder = isSockmap
    ? "1px solid oklch(0.65 0.18 290 / 0.3)"
    : "1px solid oklch(0.70 0.18 160 / 0.3)";
  const iconColor = isSockmap ? "oklch(0.65 0.18 290)" : "oklch(0.70 0.18 160)";

  return (
    <div className="glass rounded-xl overflow-hidden">
      {/* Interface header */}
      <button
        className="w-full flex items-center gap-4 px-5 py-4 hover:bg-accent/30 transition-colors text-left"
        onClick={() => setExpanded(e => !e)}
      >
        <div
          className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
          style={{ background: iconBg, border: iconBorder }}
        >
          {isSockmap ? (
            <Share2 size={16} style={{ color: iconColor }} />
          ) : (
            <Wifi size={16} style={{ color: iconColor }} />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold font-mono text-foreground">
              {iface.name}
            </span>
            {iface.ifindex > 0 && (
              <span className="text-xs text-muted-foreground">
                ifindex {iface.ifindex}
              </span>
            )}
          </div>
          <div className="flex gap-2 mt-1">
            {OSI_LAYERS.map(l => {
              const count = iface.layers[l.key].length;
              if (count === 0) return null;
              return (
                <span
                  key={l.key}
                  className="text-[10px] font-mono px-1.5 py-0.5 rounded border"
                  style={{
                    color: l.color,
                    borderColor: `${l.color}40`,
                    background: `${l.color}10`,
                  }}
                >
                  {l.key}: {count}
                </span>
              );
            })}
            {totalProgs === 0 && (
              <span className="text-[10px] text-muted-foreground/50">
                no BPF programs
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Badge
            variant="outline"
            className={cn(
              "text-xs",
              totalProgs > 0
                ? "border-emerald-500/40 text-emerald-400"
                : "border-muted-foreground/30 text-muted-foreground"
            )}
          >
            {totalProgs} prog{totalProgs !== 1 ? "s" : ""}
          </Badge>
          {expanded ? (
            <ChevronDown size={14} className="text-muted-foreground" />
          ) : (
            <ChevronRight size={14} className="text-muted-foreground" />
          )}
        </div>
      </button>

      {/* OSI layers */}
      {expanded && (
        <div className="px-5 pb-5 space-y-2 border-t border-border/50">
          <div className="pt-4 space-y-2">
            {visibleLayers.map(layerDef => (
              <OsiLayerRow
                key={layerDef.key}
                layerDef={layerDef}
                ifaceName={iface.name}
                programs={iface.layers[layerDef.key]}
                chains={layerDef.key === "L3" ? ifaceChains : undefined}
                returnAnalysisById={returnAnalysisById}
                returnAnalysisLoading={returnAnalysisLoading}
                progArrayTargets={progArrayTargets}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

interface SectionProps {
  title: string;
  description: string;
  icon: React.ReactNode;
  interfaces: NetworkInterface[];
  emptyMessage: string;
  emptyHint?: string;
  accentColor?: string;
  tcChains?: ProgramChain[];
  returnAnalysisById: Map<number, ProgramReturnAnalysisResult>;
  returnAnalysisLoading: boolean;
  progArrayTargets: ProgArrayTarget[];
}

function InterfaceSection({
  title,
  description,
  icon,
  interfaces,
  emptyMessage,
  emptyHint,
  accentColor,
  tcChains = [],
  returnAnalysisById,
  returnAnalysisLoading,
  progArrayTargets,
}: SectionProps) {
  return (
    <div className="space-y-3">
      {/* Section header */}
      <div className="flex items-center gap-3">
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
          style={{
            background: accentColor
              ? `${accentColor}15`
              : "oklch(0.70 0.18 160 / 0.1)",
            border: `1px solid ${accentColor ?? "oklch(0.70 0.18 160)"}30`,
          }}
        >
          {icon}
        </div>
        <div>
          <h2 className="text-sm font-semibold text-foreground">{title}</h2>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
        <Badge
          variant="outline"
          className="ml-auto text-xs text-muted-foreground"
        >
          {interfaces.length}
        </Badge>
      </div>

      {/* Cards */}
      <div className="space-y-3 pl-11">
        {interfaces.length > 0 ? (
          interfaces.map(iface => (
            <InterfaceCard
              key={`${iface.netns ?? ""}::${iface.name}`}
              iface={iface}
              tcChains={tcChains}
              returnAnalysisById={returnAnalysisById}
              returnAnalysisLoading={returnAnalysisLoading}
              progArrayTargets={progArrayTargets}
            />
          ))
        ) : (
          <div className="glass rounded-xl p-6 text-center">
            <p className="text-sm text-muted-foreground">{emptyMessage}</p>
            {emptyHint && (
              <p className="text-xs text-muted-foreground/60 mt-1">
                {emptyHint}
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default function NetworkView() {
  const {
    snapshot,
    filteredPrograms,
    searchQuery,
    appMode,
    maps,
    snapshotMapDumps,
    historyMap,
    statsEnabled,
  } = useEbpf();

  const tcChains = useMemo(
    () =>
      snapshot ? snapshot.programChains.filter(c => c.hookType === "tc") : [],
    [snapshot]
  );

  const visibleStructOpsPrograms = useMemo(
    () =>
      (searchQuery ? filteredPrograms : snapshot?.programs ?? []).filter(
        program =>
          program.rawType === "struct_ops" || program.type === "struct_ops"
      ),
    [filteredPrograms, searchQuery, snapshot]
  );

  const structOpsCallsById = useMemo(
    () =>
      new Map(
        visibleStructOpsPrograms.map(program => [
          program.id,
          historyMap.get(program.id)?.latest?.callsPerSec ?? 0,
        ])
      ),
    [visibleStructOpsPrograms, historyMap]
  );

  const tcpCongestionAlgorithms = useMemo(
    () =>
      buildTcpCongestionControlSummaries(
        visibleStructOpsPrograms,
        maps,
        structOpsCallsById
      ),
    [visibleStructOpsPrograms, maps, structOpsCallsById]
  );

  const { returnAnalysisById, returnAnalysisLoading, progArrayTargets } =
    usePacketChainAnalysis({
      chains: tcChains,
      filteredPrograms,
      searchQuery,
      appMode,
      maps,
      snapshotMapDumps,
    });

  if (!snapshot) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-muted-foreground">Loading…</p>
      </div>
    );
  }

  // When searching, filter programs within each interface
  const interfaces = searchQuery
    ? snapshot.networkInterfaces
        .map(iface => ({
          ...iface,
          layers: {
            L2: iface.layers.L2.filter(p =>
              filteredPrograms.some(fp => fp.id === p.id)
            ),
            L3: iface.layers.L3.filter(p =>
              filteredPrograms.some(fp => fp.id === p.id)
            ),
            L4: iface.layers.L4.filter(p =>
              filteredPrograms.some(fp => fp.id === p.id)
            ),
            L7: iface.layers.L7.filter(p =>
              filteredPrograms.some(fp => fp.id === p.id)
            ),
          },
          allPrograms: iface.allPrograms.filter(p =>
            filteredPrograms.some(fp => fp.id === p.id)
          ),
        }))
        .filter(i => i.allPrograms.length > 0)
    : snapshot.networkInterfaces;

  const nicInterfaces = interfaces.filter(i => i.kind === "nic" && !i.netns);
  const sockmapInterfaces = interfaces.filter(i => i.kind === "sockmap");
  // Interfaces discovered inside other network namespaces (containers,
  // pods, named netns), grouped per namespace.
  const netnsGroups = new Map<string, typeof interfaces>();
  for (const iface of interfaces) {
    if (iface.kind !== "nic" || !iface.netns) continue;
    const group = netnsGroups.get(iface.netns);
    if (group) group.push(iface);
    else netnsGroups.set(iface.netns, [iface]);
  }
  const totalNetProgs = snapshot.networkInterfaces.reduce(
    (a, i) => a + i.allPrograms.length,
    0
  );

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
          <Network size={20} className="text-primary" />
          Network Interfaces
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          {snapshot.networkInterfaces.length} interface
          {snapshot.networkInterfaces.length !== 1 ? "s" : ""} · {totalNetProgs}{" "}
          BPF programs attached
        </p>
      </div>

      {/* OSI legend */}
      <div className="glass rounded-xl p-4">
        <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
          OSI Layer Legend
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {OSI_LAYERS.map(l => (
            <div key={l.key} className="flex items-start gap-2">
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold font-mono shrink-0"
                style={{
                  background: `${l.color}15`,
                  border: `1px solid ${l.color}30`,
                  color: l.color,
                }}
              >
                {l.key}
              </div>
              <div>
                <div className="text-xs font-medium text-foreground">
                  {l.label.split(" — ")[1]}
                </div>
                <div className="text-[10px] text-muted-foreground">
                  {l.sublabel}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── NIC section ─────────────────────────────────────────────────── */}
      <InterfaceSection
        title="Network Interfaces"
        description="Physical and virtual NICs — XDP, TC, netfilter, and netkit hooks"
        icon={<Wifi size={15} style={{ color: "oklch(0.70 0.18 160)" }} />}
        interfaces={nicInterfaces}
        accentColor="#10b981"
        tcChains={tcChains}
        returnAnalysisById={returnAnalysisById}
        returnAnalysisLoading={returnAnalysisLoading}
        progArrayTargets={progArrayTargets}
        emptyMessage={
          searchQuery
            ? "No NIC interfaces match the current filter."
            : "No BPF programs attached to network interfaces."
        }
        emptyHint={
          !searchQuery
            ? "XDP, TC, and netfilter programs will appear here when attached to interfaces."
            : undefined
        }
      />

      {/* ── Per-netns sections (containers, pods, named namespaces) ──────── */}
      {Array.from(netnsGroups.entries()).map(([netns, ifaces]) => (
        <InterfaceSection
          key={`netns-${netns}`}
          title={`Namespace: ${netns}`}
          description="Devices inside this network namespace — scanned via nsenter"
          icon={<Box size={15} style={{ color: "oklch(0.72 0.15 220)" }} />}
          interfaces={ifaces}
          accentColor="#38bdf8"
          tcChains={tcChains}
          returnAnalysisById={returnAnalysisById}
          returnAnalysisLoading={returnAnalysisLoading}
          progArrayTargets={progArrayTargets}
          emptyMessage="No interfaces match the current filter."
        />
      ))}

      {/* ── Sockmap section (hidden when empty in live mode) ─────────────── */}
      {(sockmapInterfaces.length > 0 || searchQuery) && (
        <InterfaceSection
          title="Sockmap Interfaces"
          description="Socket-level BPF programs — sk_msg, sk_skb, sock_ops, sk_lookup"
          icon={<Share2 size={15} style={{ color: "oklch(0.65 0.18 290)" }} />}
          interfaces={sockmapInterfaces}
          accentColor="#8b5cf6"
          returnAnalysisById={returnAnalysisById}
          returnAnalysisLoading={returnAnalysisLoading}
          progArrayTargets={progArrayTargets}
          emptyMessage={
            searchQuery
              ? "No sockmap interfaces match the current filter."
              : "No sockmap programs loaded."
          }
          emptyHint={
            !searchQuery
              ? "sk_msg, sk_skb, sock_ops, and sk_lookup programs will appear here."
              : undefined
          }
        />
      )}

      <TcpCongestionControlStructOpsCard
        algorithms={tcpCongestionAlgorithms}
        historyMap={historyMap}
        statsEnabled={statsEnabled}
      />

      {/* Fallback when everything is empty and not searching */}
      {interfaces.length === 0 &&
        tcpCongestionAlgorithms.length === 0 &&
        !searchQuery && (
        <div className="glass rounded-xl p-8 text-center">
          <Network size={32} className="text-muted-foreground mx-auto mb-3" />
          <p className="text-sm text-muted-foreground">
            No BPF programs attached to any network interface.
          </p>
          <p className="text-xs text-muted-foreground/60 mt-1">
            XDP, TC, netfilter, and sockmap programs will appear here when
            loaded.
          </p>
        </div>
      )}
    </div>
  );
}

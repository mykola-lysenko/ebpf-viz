import React, { useState, useMemo } from "react";
import { useEbpf } from "@/contexts/EbpfContext";
import { PacketChainDetailsSheet } from "@/components/PacketChainDetailsSheet";
import { ProgBadge } from "@/components/ProgBadge";
import {
  FolderTree,
  Folder,
  FolderOpen,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { usePacketChainAnalysis } from "@/hooks/usePacketChainAnalysis";
import {
  buildChainProgramRows,
  chainTone,
  classifyRateDrop,
  formatActions,
  formatAge,
  formatRunCnt,
  hasModeledReturnSemantics,
  VERDICT_TONE_CLASSES,
} from "@/lib/packet-chain-ui";
import { predictPacketChain } from "../../../shared/packet-chain-prediction";
import type {
  BpfProgram,
  CgroupNode,
  PacketChainPrediction,
  ProgArrayTarget,
  ProgramChain,
  ProgramReturnAnalysisResult,
} from "../../../shared/ebpf-types";

// Palette of visually distinct colours for shared-tag dots
const SHARED_TAG_PALETTE = [
  "#f59e0b", // amber
  "#10b981", // emerald
  "#f43f5e", // rose
  "#8b5cf6", // violet
  "#06b6d4", // cyan
  "#f97316", // orange
  "#84cc16", // lime
  "#ec4899", // pink
  "#14b8a6", // teal
  "#a855f7", // purple
];

/** Collect all (id, cgroupPath) pairs for each program tag across the full cgroup tree */
function collectTagSiblings(
  nodes: CgroupNode[],
  acc: Map<string, Array<{ id: number; cgroupPath: string }>>
) {
  for (const node of nodes) {
    for (const p of node.programs) {
      const entry = acc.get(p.tag) ?? [];
      if (!entry.some(e => e.id === p.id && e.cgroupPath === node.path)) {
        entry.push({ id: p.id, cgroupPath: node.path });
      }
      acc.set(p.tag, entry);
    }
    collectTagSiblings(node.children, acc);
  }
}

function cgroupPathLabel(path: string): string {
  if (path === "/sys/fs/cgroup") return "/";
  const parts = path.split("/").filter(Boolean);
  return parts[parts.length - 1] ?? path;
}

function chainSourceLabel(source: ProgramChain["chainSource"]): string {
  if (source === "kernel-effective") return "kernel effective";
  if (source === "inferred") return "inferred";
  return source ?? "unknown source";
}

function chainSourceTitle(source: ProgramChain["chainSource"]): string {
  if (source === "kernel-effective") {
    return "Program order comes from bpftool cgroup tree effective.";
  }
  if (source === "inferred") {
    return "Program order is inferred from direct cgroup attachments and attach flags because kernel-effective data is unavailable.";
  }
  return "Program-chain data source.";
}

/** Dot shown on a program chip when its tag is shared across multiple cgroup nodes */
function SharedTagDot({
  tag,
  color,
  siblings,
}: {
  tag: string;
  color: string;
  siblings: Array<{ id: number; cgroupPath: string }>;
}) {
  const [hovered, setHovered] = useState(false);
  return (
    <span className="relative inline-block">
      <span
        className="inline-block w-2 h-2 rounded-full cursor-help shrink-0"
        style={{ background: color, boxShadow: `0 0 5px ${color}80` }}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
      />
      {hovered && (
        <div
          className="absolute z-50 left-3 top-0 w-72 rounded-lg border border-border/60 bg-popover text-popover-foreground shadow-xl p-3 text-xs"
          onMouseEnter={() => setHovered(true)}
          onMouseLeave={() => setHovered(false)}
        >
          <div className="font-semibold mb-1.5 flex items-center gap-1.5">
            <span
              className="inline-block w-2 h-2 rounded-full shrink-0"
              style={{ background: color }}
            />
            Same bytecode — tag{" "}
            <span className="font-mono">{tag.slice(0, 8)}…</span>
          </div>
          <div className="text-muted-foreground mb-1.5">
            {siblings.length} program{siblings.length !== 1 ? "s" : ""} share
            identical instructions:
          </div>
          <div className="space-y-1 max-h-40 overflow-y-auto">
            {siblings.map(s => (
              <div
                key={`${s.id}-${s.cgroupPath}`}
                className="flex items-center gap-1.5"
              >
                <span className="font-mono text-primary shrink-0">
                  id={s.id}
                </span>
                <span className="text-muted-foreground truncate">
                  {s.cgroupPath.replace("/sys/fs/cgroup/", "")}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </span>
  );
}

const ATTACH_TYPE_COLORS: Record<string, string> = {
  cgroup_inet_ingress: "#3b82f6",
  cgroup_inet_egress: "#6d28d9",
  cgroup_device: "#1d4ed8",
  cgroup_sock_create: "#2563eb",
  cgroup_sockops: "#8b5cf6",
  cgroup_sock_release: "#a78bfa",
  cgroup_inet4_bind: "#0ea5e9",
  cgroup_inet6_bind: "#0284c7",
  cgroup_inet4_connect: "#0369a1",
  cgroup_inet6_connect: "#075985",
  cgroup_udp4_sendmsg: "#7c3aed",
  cgroup_udp6_sendmsg: "#6d28d9",
  cgroup_udp4_recvmsg: "#5b21b6",
  cgroup_udp6_recvmsg: "#4c1d95",
  cgroup_bind4: "#0ea5e9",
  cgroup_bind6: "#0284c7",
  cgroup_connect4: "#0369a1",
  cgroup_connect6: "#075985",
  cgroup_sendmsg4: "#7c3aed",
  cgroup_sendmsg6: "#6d28d9",
  cgroup_recvmsg4: "#5b21b6",
  cgroup_recvmsg6: "#4c1d95",
  cgroup_sysctl: "#f59e0b",
  cgroup_getsockopt: "#d97706",
  cgroup_setsockopt: "#b45309",
};

function AttachTypeTag({
  attachType,
  attachFlags,
}: {
  attachType: string;
  attachFlags?: string;
}) {
  const color = ATTACH_TYPE_COLORS[attachType] ?? "#6b7280";
  return (
    <span
      className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border"
      style={{ color, borderColor: `${color}40`, background: `${color}10` }}
    >
      {attachType.replace("cgroup_", "")}
      {attachFlags && <span className="opacity-60">[{attachFlags}]</span>}
    </span>
  );
}

function CgroupNodeRow({
  node,
  depth,
  searchQuery,
  filteredIds,
  sharedTagMap,
  tagColorMap,
  chainsByHook,
  returnAnalysisById,
  returnAnalysisLoading,
  progArrayTargets,
  onSelectChainDetails,
}: {
  node: CgroupNode;
  depth: number;
  searchQuery: string;
  filteredIds: Set<number>;
  sharedTagMap: Map<string, Array<{ id: number; cgroupPath: string }>>;
  tagColorMap: Map<string, string>;
  chainsByHook: Map<string, ProgramChain>;
  returnAnalysisById: Map<number, ProgramReturnAnalysisResult>;
  returnAnalysisLoading: boolean;
  progArrayTargets: ProgArrayTarget[];
  onSelectChainDetails: (details: {
    chain: ProgramChain;
    prediction: PacketChainPrediction;
    programs: BpfProgram[];
  }) => void;
}) {
  const { historyMap, maps, snapshot } = useEbpf();
  const hasMatchingProgs = node.programs.some(p => filteredIds.has(p.id));
  const hasMatchingChildren = (n: CgroupNode): boolean =>
    n.programs.some(p => filteredIds.has(p.id)) ||
    n.children.some(hasMatchingChildren);

  const isVisible =
    !searchQuery || hasMatchingProgs || hasMatchingChildren(node);
  const [expanded, setExpanded] = useState(depth < 2 || hasMatchingProgs);

  if (!isVisible) return null;

  const visibleProgs = searchQuery
    ? node.programs.filter(p => filteredIds.has(p.id))
    : node.programs;

  const hasChildren = node.children.length > 0;
  const indent = depth * 20;

  return (
    <div className="cgroup-node">
      {/* Node row */}
      <div
        className={cn(
          "flex items-start gap-2 py-2 px-3 rounded-lg hover:bg-accent/20 transition-colors group",
          visibleProgs.length > 0 && "bg-blue-500/5"
        )}
        style={{ paddingLeft: `${indent + 12}px` }}
      >
        {/* Expand toggle */}
        <button
          className="shrink-0 mt-0.5 text-muted-foreground hover:text-foreground transition-colors"
          onClick={() => setExpanded(e => !e)}
          disabled={!hasChildren}
        >
          {hasChildren ? (
            expanded ? (
              <ChevronDown size={13} />
            ) : (
              <ChevronRight size={13} />
            )
          ) : (
            <span className="w-3 inline-block" />
          )}
        </button>

        {/* Folder icon */}
        <div className="shrink-0 mt-0.5">
          {expanded && hasChildren ? (
            <FolderOpen size={14} className="text-amber-400/70" />
          ) : (
            <Folder
              size={14}
              className={cn(
                "transition-colors",
                visibleProgs.length > 0
                  ? "text-blue-400/70"
                  : "text-muted-foreground/50"
              )}
            />
          )}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-foreground font-medium">
              {node.name}
            </span>
            {visibleProgs.length > 0 && (
              <Badge
                variant="outline"
                className="text-[10px] px-1.5 py-0 border-blue-500/40 text-blue-400"
              >
                {visibleProgs.length} prog{visibleProgs.length !== 1 ? "s" : ""}
              </Badge>
            )}
          </div>

          {/* Programs — grouped by attach_type, showing execution order for chains */}
          {visibleProgs.length > 0 &&
            (() => {
              // Group by attach_type preserving order
              const groups: Array<{
                attachType: string;
                attachFlags?: string;
                progs: typeof visibleProgs;
              }> = [];
              const seen = new Map<string, number>();
              for (const p of visibleProgs) {
                const cgroupAtt = p.attachments.find(
                  a => a.cgroupPath === node.path
                );
                const at = cgroupAtt?.detail.split(" ")[0] ?? "unknown";
                const idx = seen.get(at);
                if (idx !== undefined) {
                  groups[idx].progs.push(p);
                } else {
                  seen.set(at, groups.length);
                  groups.push({
                    attachType: at,
                    attachFlags: cgroupAtt?.attachFlags,
                    progs: [p],
                  });
                }
              }
              return (
                <div className="mt-2 space-y-2">
                  {groups.map(g => {
                    const chain = chainsByHook.get(
                      `cgroup:${node.path}:${g.attachType}`
                    );
                    const isChain = chain && chain.programs.length >= 2;
                    const displayRows =
                      isChain && chain
                        ? buildChainProgramRows(
                            chain,
                            snapshot?.programs ?? g.progs
                          )
                        : g.progs.map(program => ({
                            program,
                            chainProgram: undefined,
                          }));
                    const displayPrograms = displayRows.map(row => row.program);
                    const hasAnyAnalysis = chain?.programs.some(program =>
                      returnAnalysisById.has(program.id)
                    );
                    const prediction =
                      chain?.packetContext &&
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
                    const hasModeledSemantics =
                      chain !== undefined && hasModeledReturnSemantics(chain);

                    return (
                      <div key={g.attachType}>
                        {/* Attach type header with chain indicator */}
                        <div className="flex items-center gap-1.5 mb-1">
                          <AttachTypeTag
                            attachType={g.attachType}
                            attachFlags={g.attachFlags}
                          />
                          {isChain && (
                            <span className="text-[9px] text-muted-foreground/60 flex items-center gap-0.5">
                              effective chain of {chain.programs.length}
                              {chain.chainSource && (
                                <span
                                  className={cn(
                                    "ml-1 rounded border px-1 py-0.5 font-mono",
                                    chain.chainSource === "kernel-effective"
                                      ? "border-emerald-500/25 bg-emerald-500/5 text-emerald-300/80"
                                      : "border-amber-500/25 bg-amber-500/5 text-amber-300/80"
                                  )}
                                  title={chainSourceTitle(chain.chainSource)}
                                >
                                  {chainSourceLabel(chain.chainSource)}
                                </span>
                              )}
                              {chain.canShortCircuit && (
                                <span className="text-amber-400/70 flex items-center gap-0.5 ml-1">
                                  <AlertTriangle size={8} />
                                  can short-circuit
                                </span>
                              )}
                            </span>
                          )}
                        </div>
                        {isChain && chain.packetContext && (
                          <div
                            className="mb-1 ml-1 flex flex-wrap items-center gap-1.5 text-[9px] font-mono text-muted-foreground/70"
                            title={chain.packetContext.summary}
                          >
                            <span className="rounded border border-border/60 px-1 py-0.5 text-muted-foreground">
                              {chain.packetContext.family}
                              {chain.packetContext.direction !== "unknown" &&
                                `/${chain.packetContext.direction}`}
                            </span>
                            {hasModeledSemantics ? (
                              <>
                                <span className="rounded border border-emerald-500/25 bg-emerald-500/5 px-1 py-0.5 text-emerald-400/80">
                                  allow:{" "}
                                  {formatActions(
                                    chain.packetContext.semantics.pass
                                  )}
                                </span>
                                <span className="rounded border border-red-500/25 bg-red-500/5 px-1 py-0.5 text-red-400/80">
                                  deny:{" "}
                                  {formatActions(
                                    chain.packetContext.semantics.drop
                                  )}
                                </span>
                              </>
                            ) : (
                              <span className="rounded border border-amber-500/25 bg-amber-500/5 px-1 py-0.5 text-amber-300/80">
                                return semantics not modeled
                              </span>
                            )}
                          </div>
                        )}
                        {isChain && chain.packetContext && (
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
                                  onSelectChainDetails({
                                    chain,
                                    prediction,
                                    programs: displayPrograms,
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
                                    first possible stop: #
                                    {firstTerminal.position}{" "}
                                    {firstTerminal.name}
                                  </span>
                                )}
                                <span className="ml-1 opacity-60">
                                  click for details
                                </span>
                              </button>
                            ) : (
                              <div className="rounded border border-border/60 px-2 py-1 text-[10px] text-muted-foreground/60">
                                Analyzing cgroup verdicts…
                              </div>
                            )}
                          </div>
                        )}
                        {/* Programs with optional position numbers and stats */}
                        <div className="space-y-0.5 ml-1">
                          {displayRows.map((row, pIdx) => {
                            const p = row.program;
                            const position = row.chainProgram?.position;
                            const cgroupMeta = row.chainProgram?.cgroup;
                            const predictionStep =
                              position != null
                                ? predictionStepsById.get(position)
                                : undefined;
                            const sharedColor = tagColorMap.get(p.tag);
                            const siblings = sharedTagMap.get(p.tag);
                            // Drop indicator: compare live rates (calls/sec), not raw run_cnt
                            const currRate = historyMap.get(p.id)?.latest
                              ?.callsPerSec;
                            const prevRate =
                              isChain && chain.canShortCircuit && pIdx > 0
                                ? historyMap.get(
                                    displayRows[pIdx - 1].program.id
                                  )?.latest?.callsPerSec
                                : undefined;
                            const dropInfo = classifyRateDrop(
                              prevRate,
                              currRate,
                              { flagIncreases: true }
                            );
                            return (
                              <React.Fragment
                                key={
                                  position != null && chain
                                    ? `${chain.hookId}:${position}:${p.id}`
                                    : p.id
                                }
                              >
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
                                  {position != null && (
                                    <span
                                      className="w-4 h-4 rounded-full flex items-center justify-center text-[9px] font-bold shrink-0"
                                      style={{
                                        background: `${p.color}20`,
                                        border: `1.5px solid ${p.color}`,
                                        color: p.color,
                                      }}
                                    >
                                      {position}
                                    </span>
                                  )}
                                  <ProgBadge program={p} />
                                  {cgroupMeta && (
                                    <span
                                      className={cn(
                                        "rounded border px-1.5 py-0.5 text-[9px] font-mono",
                                        cgroupMeta.inherited
                                          ? "border-blue-500/25 bg-blue-500/5 text-blue-300/80"
                                          : "border-emerald-500/20 bg-emerald-500/5 text-emerald-300/70"
                                      )}
                                      title={`${cgroupMeta.inherited ? "Inherited" : "Direct"} cgroup attachment: ${cgroupMeta.attachPath}${cgroupMeta.attachFlags ? ` [${cgroupMeta.attachFlags}]` : ""}`}
                                    >
                                      {cgroupMeta.inherited
                                        ? `inherited from ${cgroupPathLabel(cgroupMeta.attachPath)}`
                                        : "direct"}
                                    </span>
                                  )}
                                  {predictionStep && (
                                    <span
                                      className={cn(
                                        "rounded border px-1.5 py-0.5 text-[9px] font-mono",
                                        VERDICT_TONE_CLASSES[
                                          predictionStep.tone
                                        ]
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
                                    predictionStep.tailCallContinuations
                                      .length > 0 && (
                                      <span
                                        className="rounded border border-amber-500/25 bg-amber-500/5 px-1.5 py-0.5 text-[9px] font-mono text-amber-300/80"
                                        title={predictionStep.tailCallContinuations
                                          .map(
                                            continuation => continuation.summary
                                          )
                                          .join("; ")}
                                      >
                                        tail call →{" "}
                                        {formatActions(
                                          predictionStep.tailCallContinuations.map(
                                            continuation =>
                                              continuation.target
                                                .targetProgName ??
                                              `#${continuation.target.targetProgId ?? "unknown"}`
                                          )
                                        )}
                                      </span>
                                    )}
                                  {predictionStep?.reachability ===
                                    "conditional" && (
                                    <span
                                      className="rounded border border-amber-500/25 bg-amber-500/5 px-1.5 py-0.5 text-[9px] font-mono text-amber-300/80"
                                      title="An earlier program may terminate socket or packet processing before this program runs."
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
                                  {isChain &&
                                    chain.packetContext &&
                                    !predictionStep &&
                                    (() => {
                                      const result = returnAnalysisById.get(
                                        p.id
                                      );
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
                                  {isChain && (
                                    <span className="text-[9px] font-mono text-muted-foreground/50 tabular-nums shrink-0">
                                      {p.runCnt != null &&
                                        `${formatRunCnt(p.runCnt)} total`}
                                      {p.loadedAt > 0 &&
                                        ` · loaded ${formatAge(p.loadedAt)}`}
                                    </span>
                                  )}
                                  {sharedColor &&
                                    siblings &&
                                    siblings.length > 1 && (
                                      <SharedTagDot
                                        tag={p.tag}
                                        color={sharedColor}
                                        siblings={siblings}
                                      />
                                    )}
                                </div>
                              </React.Fragment>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>
              );
            })()}
        </div>
      </div>

      {/* Children */}
      {expanded && node.children.length > 0 && (
        <div className="relative">
          <div
            className="absolute top-0 bottom-0 border-l border-dashed border-border/30"
            style={{ left: `${indent + 20}px` }}
          />
          {node.children.map(child => (
            <CgroupNodeRow
              key={child.path}
              node={child}
              depth={depth + 1}
              searchQuery={searchQuery}
              filteredIds={filteredIds}
              sharedTagMap={sharedTagMap}
              tagColorMap={tagColorMap}
              chainsByHook={chainsByHook}
              returnAnalysisById={returnAnalysisById}
              returnAnalysisLoading={returnAnalysisLoading}
              progArrayTargets={progArrayTargets}
              onSelectChainDetails={onSelectChainDetails}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function CgroupView() {
  const {
    snapshot,
    filteredPrograms,
    searchQuery,
    appMode,
    maps,
    snapshotMapDumps,
  } = useEbpf();
  const [selectedChainDetails, setSelectedChainDetails] = useState<{
    chain: ProgramChain;
    prediction: PacketChainPrediction;
    programs: BpfProgram[];
  } | null>(null);

  const cgroupChains = useMemo(
    () =>
      snapshot
        ? snapshot.programChains.filter(c => c.hookType === "cgroup")
        : [],
    [snapshot]
  );

  const { returnAnalysisById, returnAnalysisLoading, progArrayTargets } =
    usePacketChainAnalysis({
      chains: cgroupChains,
      filteredPrograms,
      searchQuery,
      appMode,
      maps,
      snapshotMapDumps,
    });

  // Build chain lookup: hookId → ProgramChain for O(1) access in tree nodes
  const chainsByHook = useMemo(() => {
    if (!snapshot) return new Map<string, ProgramChain>();
    return new Map(cgroupChains.map(c => [c.hookId, c]));
  }, [cgroupChains, snapshot]);

  // Build shared-tag maps: tags that appear on 2+ programs in the cgroup tree
  const { sharedTagMap, tagColorMap } = useMemo(() => {
    if (!snapshot) return { sharedTagMap: new Map(), tagColorMap: new Map() };
    const raw = new Map<string, Array<{ id: number; cgroupPath: string }>>();
    collectTagSiblings(snapshot.cgroupTree, raw);
    const sharedTagMap = new Map<
      string,
      Array<{ id: number; cgroupPath: string }>
    >();
    Array.from(raw.entries()).forEach(([tag, entries]) => {
      if (entries.length > 1) sharedTagMap.set(tag, entries);
    });
    // Assign a stable colour per shared tag (sorted for determinism)
    const tagColorMap = new Map<string, string>();
    const sortedTags = Array.from(sharedTagMap.keys()).sort();
    sortedTags.forEach((tag, i) => {
      tagColorMap.set(tag, SHARED_TAG_PALETTE[i % SHARED_TAG_PALETTE.length]);
    });
    return { sharedTagMap, tagColorMap };
  }, [snapshot]);

  if (!snapshot) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-muted-foreground">Loading…</p>
      </div>
    );
  }

  const filteredIds = new Set(filteredPrograms.map(p => p.id));
  const cgroupProgs = snapshot.programs.filter(
    p => p.type.startsWith("cgroup") || p.type === "sock_ops"
  );

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
          <FolderTree size={20} className="text-primary" />
          Cgroup Hierarchy
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          {snapshot.cgroupTree.length} top-level cgroup
          {snapshot.cgroupTree.length !== 1 ? "s" : ""} · {cgroupProgs.length}{" "}
          BPF programs
        </p>
      </div>

      {/* Shared-bytecode legend */}
      {tagColorMap.size > 0 && (
        <div className="glass rounded-xl p-4">
          <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
            Shared Bytecode
          </div>
          <p className="text-xs text-muted-foreground mb-3">
            Programs with the same colour dot have identical compiled bytecode
            (same BPF tag). Hover a dot for details.
          </p>
          <div className="flex flex-wrap gap-3">
            {(Array.from(tagColorMap.entries()) as [string, string][]).map(
              ([tag, color]) => {
                const siblings = sharedTagMap.get(tag) ?? [];
                return (
                  <div key={tag} className="flex items-center gap-1.5">
                    <span
                      className="inline-block w-2.5 h-2.5 rounded-full shrink-0"
                      style={{
                        background: color,
                        boxShadow: `0 0 5px ${color}80`,
                      }}
                    />
                    <span className="text-[10px] font-mono text-muted-foreground">
                      {tag.slice(0, 8)}…
                    </span>
                    <span className="text-[10px] text-muted-foreground/60">
                      ×{siblings.length}
                    </span>
                  </div>
                );
              }
            )}
          </div>
        </div>
      )}

      {/* Attach type legend */}
      <div className="glass rounded-xl p-4">
        <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
          Attach Types
        </div>
        <div className="flex flex-wrap gap-2">
          {Object.entries(ATTACH_TYPE_COLORS)
            .slice(0, 10)
            .map(([type, color]) => (
              <span
                key={type}
                className="text-[10px] font-mono px-2 py-0.5 rounded border"
                style={{
                  color,
                  borderColor: `${color}40`,
                  background: `${color}10`,
                }}
              >
                {type.replace("cgroup_", "")}
              </span>
            ))}
          <span className="text-[10px] text-muted-foreground px-2 py-0.5">
            + more
          </span>
        </div>
      </div>

      {/* Tree */}
      <div className="glass rounded-xl p-4">
        <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 font-mono">
          /sys/fs/cgroup
        </div>
        {snapshot.cgroupTree.length > 0 ? (
          <div className="space-y-0.5">
            {snapshot.cgroupTree.map(node => (
              <CgroupNodeRow
                key={node.path}
                node={node}
                depth={0}
                searchQuery={searchQuery}
                filteredIds={filteredIds}
                sharedTagMap={sharedTagMap}
                tagColorMap={tagColorMap}
                chainsByHook={chainsByHook}
                returnAnalysisById={returnAnalysisById}
                returnAnalysisLoading={returnAnalysisLoading}
                progArrayTargets={progArrayTargets}
                onSelectChainDetails={setSelectedChainDetails}
              />
            ))}
          </div>
        ) : (
          <div className="text-center py-8">
            <FolderTree
              size={32}
              className="text-muted-foreground mx-auto mb-3"
            />
            <p className="text-sm text-muted-foreground">
              No cgroup BPF programs found.
            </p>
            <p className="text-xs text-muted-foreground/60 mt-1">
              cgroup_skb, cgroup_sock, and sock_ops programs will appear here.
            </p>
          </div>
        )}
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
    </div>
  );
}

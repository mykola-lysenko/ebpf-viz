import type { XlatedInsn } from "../../../shared/ebpf-types";

export const CFG_AUTO_RENDER_LIMITS = {
  maxInstructions: 1_200,
  maxDotChars: 250_000,
  maxNodes: 450,
  maxEdges: 900,
} as const;

export interface CfgBasicBlockSummary {
  id: string;
  start: number;
  end: number;
  instructionCount: number;
  branchTargets: number[];
  fallthroughTarget?: number;
  calls: string[];
  sourceSnippets: string[];
  terminalDisasm: string;
}

export interface CfgRenderAnalysis {
  instructionCount: number;
  dotChars: number;
  estimatedNodeCount: number;
  estimatedEdgeCount: number;
  blockCount: number;
  shouldAutoRender: boolean;
  reasons: string[];
}

function parseJumpTarget(insn: XlatedInsn): number | null {
  const match = insn.disasm.match(/\bgoto pc([+-]\d+)/);
  if (!match) return null;
  return insn.index + 1 + Number.parseInt(match[1], 10);
}

function isConditionalBranch(disasm: string): boolean {
  return /\bif\b/.test(disasm);
}

function isTerminalInsn(disasm: string): boolean {
  return /\b(exit|return)\b/.test(disasm);
}

function parseCall(disasm: string): string | null {
  const match = disasm.match(/\bcall\s+(.+)$/);
  if (!match) return null;
  return match[1].trim();
}

function unique<T>(values: T[]): T[] {
  return Array.from(new Set(values));
}

export function buildCfgBasicBlocks(insns: XlatedInsn[]): CfgBasicBlockSummary[] {
  if (insns.length === 0) return [];

  const sorted = [...insns].sort((a, b) => a.index - b.index);
  const sortedIndices = sorted.map(insn => insn.index);
  const instructionIndices = new Set(sortedIndices);
  const indexPosition = new Map(
    sortedIndices.map((instructionIndex, position) => [instructionIndex, position])
  );
  const blockStarts = new Set<number>([sorted[0].index]);

  for (let i = 0; i < sorted.length; i++) {
    const insn = sorted[i];
    const target = parseJumpTarget(insn);
    if (target !== null && instructionIndices.has(target)) {
      blockStarts.add(target);
    }

    if ((target !== null || isTerminalInsn(insn.disasm)) && i + 1 < sorted.length) {
      blockStarts.add(sorted[i + 1].index);
    }
  }

  const blocks: CfgBasicBlockSummary[] = [];
  let current: XlatedInsn[] = [];

  const flush = () => {
    if (current.length === 0) return;
    const first = current[0];
    const last = current[current.length - 1];
    const jumpTarget = parseJumpTarget(last);
    const branchTargets =
      jumpTarget !== null && instructionIndices.has(jumpTarget)
        ? [jumpTarget]
        : [];
    const lastPosition = indexPosition.get(last.index) ?? -1;
    const nextInstruction = sortedIndices[lastPosition + 1];
    const fallthroughTarget =
      jumpTarget !== null && isConditionalBranch(last.disasm)
        ? nextInstruction
        : jumpTarget === null && !isTerminalInsn(last.disasm)
        ? nextInstruction
        : undefined;
    const calls = unique(
      current
        .map(insn => parseCall(insn.disasm))
        .filter((call): call is string => call !== null)
    ).slice(0, 4);
    const sourceSnippets = unique(
      current
        .map(insn => insn.source ?? insn.linum)
        .filter((source): source is string => Boolean(source))
    ).slice(0, 3);

    blocks.push({
      id: `bb_${first.index}`,
      start: first.index,
      end: last.index,
      instructionCount: current.length,
      branchTargets,
      fallthroughTarget,
      calls,
      sourceSnippets,
      terminalDisasm: last.disasm,
    });
    current = [];
  };

  for (const insn of sorted) {
    if (blockStarts.has(insn.index) && current.length > 0) {
      flush();
    }
    current.push(insn);

    if (parseJumpTarget(insn) !== null || isTerminalInsn(insn.disasm)) {
      flush();
    }
  }
  flush();

  return blocks;
}

function estimateDotNodeCount(dot: string): number {
  const nodeStatements = dot.match(/^\s*(?!(?:node|edge|graph)\b)(?:"[^"]+"|[A-Za-z_][\w.]*)\s+\[/gm);
  return nodeStatements?.length ?? 0;
}

function estimateDotEdgeCount(dot: string): number {
  return dot.match(/->/g)?.length ?? 0;
}

export function analyzeCfgRender(
  dot: string,
  insns: XlatedInsn[]
): CfgRenderAnalysis {
  const blocks = buildCfgBasicBlocks(insns);
  const dotChars = dot.length;
  const estimatedNodeCount = Math.max(estimateDotNodeCount(dot), blocks.length);
  const estimatedEdgeCount = estimateDotEdgeCount(dot);
  const reasons: string[] = [];

  if (insns.length > CFG_AUTO_RENDER_LIMITS.maxInstructions) {
    reasons.push(
      `${insns.length.toLocaleString()} instructions exceeds the automatic render limit of ${CFG_AUTO_RENDER_LIMITS.maxInstructions.toLocaleString()}`
    );
  }
  if (dotChars > CFG_AUTO_RENDER_LIMITS.maxDotChars) {
    reasons.push(
      `${dotChars.toLocaleString()} DOT characters exceeds the automatic render limit of ${CFG_AUTO_RENDER_LIMITS.maxDotChars.toLocaleString()}`
    );
  }
  if (estimatedNodeCount > CFG_AUTO_RENDER_LIMITS.maxNodes) {
    reasons.push(
      `${estimatedNodeCount.toLocaleString()} estimated CFG nodes exceeds the automatic render limit of ${CFG_AUTO_RENDER_LIMITS.maxNodes.toLocaleString()}`
    );
  }
  if (estimatedEdgeCount > CFG_AUTO_RENDER_LIMITS.maxEdges) {
    reasons.push(
      `${estimatedEdgeCount.toLocaleString()} estimated CFG edges exceeds the automatic render limit of ${CFG_AUTO_RENDER_LIMITS.maxEdges.toLocaleString()}`
    );
  }

  return {
    instructionCount: insns.length,
    dotChars,
    estimatedNodeCount,
    estimatedEdgeCount,
    blockCount: blocks.length,
    shouldAutoRender: reasons.length === 0,
    reasons,
  };
}

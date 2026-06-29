import type {
  CfgBasicBlockSummary,
  CfgBlockSearchResult,
  CfgRenderAnalysis,
  CfgSummary,
  XlatedInsn,
} from "./ebpf-types";

export type {
  CfgBasicBlockSummary,
  CfgBlockSearchResult,
  CfgRenderAnalysis,
  CfgSummary,
} from "./ebpf-types";

export const CFG_AUTO_RENDER_LIMITS = {
  maxInstructions: 2_400,
  maxDotChars: 250_000,
  maxNodes: 1_400,
  maxEdges: 2_000,
} as const;

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
  insns: XlatedInsn[],
  blocks = buildCfgBasicBlocks(insns)
): CfgRenderAnalysis {
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

function hashStringPart(hash: number, value: string): number {
  for (let i = 0; i < value.length; i++) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 16_777_619);
  }
  return hash >>> 0;
}

export function computeCfgSummaryFingerprint(
  dot: string,
  insns: XlatedInsn[]
): string {
  let hash = 2_166_136_261;
  hash = hashStringPart(hash, dot);
  hash = hashStringPart(hash, "\0");

  for (const insn of insns) {
    hash = hashStringPart(
      hash,
      [
        insn.index,
        insn.disasm,
        insn.opcodes ?? "",
        insn.linum ?? "",
        insn.source ?? "",
        insn.sourceFile ?? "",
        insn.sourceLine ?? "",
        insn.sourceColumn ?? "",
      ].join("\u0001")
    );
    hash = hashStringPart(hash, "\0");
  }

  return `${insns.length}:${dot.length}:${hash.toString(16).padStart(8, "0")}`;
}

export function buildCfgSummary(
  dot: string,
  insns: XlatedInsn[],
  fingerprint = computeCfgSummaryFingerprint(dot, insns)
): CfgSummary {
  const blocks = buildCfgBasicBlocks(insns);
  return {
    fingerprint,
    analysis: analyzeCfgRender(dot, insns, blocks),
    blocks,
  };
}

export function searchCfgBlocks(
  blocks: CfgBasicBlockSummary[],
  rawQuery: string
): CfgBlockSearchResult[] {
  const query = rawQuery.trim().toLowerCase();
  if (!query) {
    return blocks.map(block => ({ block, matchReason: "all blocks" }));
  }

  const strictInstructionMatch = query.match(/^(?:#|insn:|pc:|bb:)\s*(\d+)$/);
  const numericMatch = strictInstructionMatch ?? query.match(/^(\d+)$/);
  const numericQuery = numericMatch ? Number.parseInt(numericMatch[1], 10) : null;

  return blocks.flatMap(block => {
    if (numericQuery !== null) {
      if (block.start <= numericQuery && numericQuery <= block.end) {
        return [{ block, matchReason: `contains instruction ${numericQuery}` }];
      }
      if (strictInstructionMatch) return [];
      if (block.branchTargets.includes(numericQuery)) {
        return [{ block, matchReason: `branches to ${numericQuery}` }];
      }
      if (block.fallthroughTarget === numericQuery) {
        return [{ block, matchReason: `falls through to ${numericQuery}` }];
      }
    }

    const call = block.calls.find(value => value.toLowerCase().includes(query));
    if (call) {
      return [{ block, matchReason: `helper call: ${call}` }];
    }

    if (block.terminalDisasm.toLowerCase().includes(query)) {
      return [{ block, matchReason: "terminal instruction" }];
    }

    const source = block.sourceSnippets.find(value =>
      value.toLowerCase().includes(query)
    );
    if (source) {
      return [{ block, matchReason: `source: ${source}` }];
    }

    const branchText = [
      ...block.branchTargets.map(target => `branch ${target}`),
      block.fallthroughTarget === undefined
        ? undefined
        : `fallthrough ${block.fallthroughTarget}`,
    ]
      .filter((value): value is string => Boolean(value))
      .join(" ");

    if (branchText.toLowerCase().includes(query)) {
      return [{ block, matchReason: "branch target" }];
    }

    return [];
  });
}

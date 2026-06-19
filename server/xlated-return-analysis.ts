import type {
  XlatedBranchEvidence,
  XlatedInsn,
  XlatedReturnAnalysis,
  XlatedReturnExit,
  XlatedTailCall,
} from "../shared/ebpf-types";
import { analyzeXlatedSideEffects } from "./xlated-side-effect-analysis";

type RegisterName = `r${number}`;
type UnknownReason = NonNullable<XlatedReturnExit["reason"]>;

interface ParsedInsn {
  pos: number;
  insn: XlatedInsn;
  jump: "none" | "conditional" | "unconditional";
  jumpTargetPos?: number;
  writes: RegisterWrite[];
  isExit: boolean;
}

type RegisterWrite =
  | { kind: "const"; reg: RegisterName; value: number; insn: XlatedInsn }
  | { kind: "map"; reg: RegisterName; mapId: number; insn: XlatedInsn }
  | { kind: "copy"; reg: RegisterName; source: RegisterName; insn: XlatedInsn }
  | { kind: "unknown"; reg: RegisterName; insn: XlatedInsn };

type ResolveResult =
  | { kind: "const"; value: number; assignmentInsn?: XlatedInsn }
  | { kind: "map"; mapId: number; assignmentInsn?: XlatedInsn }
  | { kind: "unknown"; reason: UnknownReason; assignmentInsn?: XlatedInsn };

const RETURN_REGISTER: RegisterName = "r0";
const CALL_CLOBBERED_REGS: RegisterName[] = [
  "r0",
  "r1",
  "r2",
  "r3",
  "r4",
  "r5",
];
const MAX_RESOLUTION_STEPS = 10_000;
const MAX_BRANCH_EVIDENCE = 4;
const MAX_BRANCH_WALK_STEPS = 32;

function isExitInsn(disasm: string): boolean {
  return /^\(95\)\s+exit\b/.test(disasm.trim());
}

function parseIntegerLiteral(raw: string): number | null {
  const value = raw.startsWith("-0x")
    ? -Number.parseInt(raw.slice(3), 16)
    : raw.startsWith("0x")
      ? Number.parseInt(raw.slice(2), 16)
      : Number.parseInt(raw, 10);

  return Number.isFinite(value) ? normalizeReturnConstant(value) : null;
}

function normalizeReturnConstant(value: number): number {
  // BPF return verdicts are consumed as 32-bit action codes by packet hooks.
  // Normalize common unsigned encodings like 0xffffffff back to -1.
  if (value >= 0x80000000 && value <= 0xffffffff) {
    return value - 0x100000000;
  }
  return value;
}

function normalizeRegister(raw: string): RegisterName | null {
  const match = raw.match(/^[rw](10|[0-9])$/);
  if (!match) return null;
  return `r${match[1]}` as RegisterName;
}

function isTailCallInsn(disasm: string): boolean {
  return disasm.includes("tail_call");
}

function sourceEvidence(
  insn: XlatedInsn
): Pick<
  XlatedReturnExit | XlatedTailCall,
  "source" | "sourceFile" | "sourceLine" | "sourceColumn"
> {
  const evidence: Pick<
    XlatedReturnExit | XlatedTailCall,
    "source" | "sourceFile" | "sourceLine" | "sourceColumn"
  > = {};
  if (insn.source) evidence.source = insn.source;
  if (insn.linum && !evidence.source) evidence.source = insn.linum;
  if (insn.sourceFile) evidence.sourceFile = insn.sourceFile;
  if (insn.sourceLine !== undefined) evidence.sourceLine = insn.sourceLine;
  if (insn.sourceColumn !== undefined)
    evidence.sourceColumn = insn.sourceColumn;
  return evidence;
}

function parseRegisterWrites(insn: XlatedInsn): RegisterWrite[] {
  const trimmed = insn.disasm.trim();
  const body = trimmed.replace(/^\([0-9a-fA-F]+\)\s+/, "");

  if (/^call\b/.test(body)) {
    return CALL_CLOBBERED_REGS.map(reg => ({ kind: "unknown", reg, insn }));
  }

  const constMatch = body.match(
    /^([rw](?:10|[0-9]))\s*=\s*(-?(?:0x[0-9a-fA-F]+|\d+))\b/
  );
  if (constMatch) {
    const reg = normalizeRegister(constMatch[1]);
    const value = parseIntegerLiteral(constMatch[2]);
    if (reg && value !== null) {
      return [{ kind: "const", reg, value, insn }];
    }
  }

  const mapMatch = body.match(/^([rw](?:10|[0-9]))\s*=\s*map\[id:(\d+)\]/);
  if (mapMatch) {
    const reg = normalizeRegister(mapMatch[1]);
    const mapId = Number.parseInt(mapMatch[2], 10);
    if (reg && Number.isFinite(mapId)) {
      return [{ kind: "map", reg, mapId, insn }];
    }
  }

  const copyMatch = body.match(
    /^([rw](?:10|[0-9]))\s*=\s*([rw](?:10|[0-9]))\b/
  );
  if (copyMatch) {
    const reg = normalizeRegister(copyMatch[1]);
    const source = normalizeRegister(copyMatch[2]);
    if (reg && source) {
      return [{ kind: "copy", reg, source, insn }];
    }
  }

  const unknownRegisterWrite = body.match(
    /^([rw](?:10|[0-9]))\s*(?:[-+*/%&|^]?=|[<>]{2}=|s[<>]{2}=)/
  );
  if (unknownRegisterWrite) {
    const reg = normalizeRegister(unknownRegisterWrite[1]);
    return reg ? [{ kind: "unknown", reg, insn }] : [];
  }

  return [];
}

function parseJump(
  insn: XlatedInsn,
  indexToPos: Map<number, number>
): Pick<ParsedInsn, "jump" | "jumpTargetPos"> {
  const body = insn.disasm.trim().replace(/^\([0-9a-fA-F]+\)\s+/, "");
  const match = body.match(/\b(?:goto|may_goto|goto_or_nop)\s+pc([+-]\d+)/);
  if (!match) return { jump: "none" };

  const targetPc = insn.index + 1 + Number.parseInt(match[1], 10);
  const jumpTargetPos = indexToPos.get(targetPc);
  const jump = body.startsWith("goto ") ? "unconditional" : "conditional";

  return jumpTargetPos === undefined ? { jump } : { jump, jumpTargetPos };
}

function parseInstructions(insns: XlatedInsn[]): ParsedInsn[] {
  const indexToPos = new Map<number, number>();
  insns.forEach((insn, pos) => indexToPos.set(insn.index, pos));

  return insns.map((insn, pos) => ({
    pos,
    insn,
    ...parseJump(insn, indexToPos),
    writes: parseRegisterWrites(insn),
    isExit: isExitInsn(insn.disasm),
  }));
}

function buildControlFlow(parsed: ParsedInsn[]): {
  predecessors: number[][];
  reachable: Set<number>;
} {
  const successorsByPos = parsed.map((): number[] => []);
  const predecessors = parsed.map((): number[] => []);

  for (const insn of parsed) {
    const successors = new Set<number>();
    const nextPos = insn.pos + 1 < parsed.length ? insn.pos + 1 : undefined;

    if (!insn.isExit) {
      if (insn.jumpTargetPos !== undefined) {
        successors.add(insn.jumpTargetPos);
      }
      if (insn.jump !== "unconditional" && nextPos !== undefined) {
        successors.add(nextPos);
      }
    }

    for (const successor of Array.from(successors)) {
      successorsByPos[insn.pos].push(successor);
    }
  }

  const reachable = new Set<number>();
  const queue = parsed.length > 0 ? [0] : [];
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const pos = queue[cursor];
    if (reachable.has(pos)) continue;
    reachable.add(pos);
    queue.push(...successorsByPos[pos]);
  }

  for (let pos = 0; pos < successorsByPos.length; pos += 1) {
    if (!reachable.has(pos)) continue;
    for (const successor of successorsByPos[pos]) {
      if (reachable.has(successor)) {
        predecessors[successor].push(pos);
      }
    }
  }

  return { predecessors, reachable };
}

function sourceEvidenceForBranch(
  insn: XlatedInsn
): Pick<
  XlatedBranchEvidence,
  "source" | "sourceFile" | "sourceLine" | "sourceColumn"
> {
  return sourceEvidence(insn);
}

function extractBranchEvidence(
  parsed: ParsedInsn[],
  predecessors: number[][],
  exitPos: number
): XlatedBranchEvidence[] | undefined {
  const evidence: XlatedBranchEvidence[] = [];
  const visited = new Set<number>();
  let currentPos = exitPos;

  for (
    let step = 0;
    step < MAX_BRANCH_WALK_STEPS && evidence.length < MAX_BRANCH_EVIDENCE;
    step += 1
  ) {
    if (visited.has(currentPos)) break;
    visited.add(currentPos);

    const preds = predecessors[currentPos] ?? [];
    if (preds.length !== 1) break;

    const predPos = preds[0];
    const pred = parsed[predPos];
    if (!pred) break;

    if (pred.jump === "conditional") {
      const fallthroughPos =
        pred.pos + 1 < parsed.length ? pred.pos + 1 : undefined;
      const branch =
        pred.jumpTargetPos === currentPos
          ? "taken"
          : fallthroughPos === currentPos
            ? "fallthrough"
            : "unknown";

      evidence.push({
        insnIndex: pred.insn.index,
        disasm: pred.insn.disasm,
        targetIndex:
          pred.jumpTargetPos !== undefined
            ? parsed[pred.jumpTargetPos]?.insn.index
            : undefined,
        branch,
        ...sourceEvidenceForBranch(pred.insn),
      });
    }

    currentPos = predPos;
  }

  return evidence.length > 0 ? evidence.reverse() : undefined;
}

function mergeResults(results: ResolveResult[]): ResolveResult {
  if (results.length === 0) {
    return { kind: "unknown", reason: "no-direct-assignment" };
  }

  const unknown = results.find(
    (result): result is Extract<ResolveResult, { kind: "unknown" }> =>
      result.kind === "unknown"
  );
  if (unknown) return unknown;

  const constants = results.filter(
    (result): result is Extract<ResolveResult, { kind: "const" }> =>
      result.kind === "const"
  );
  if (constants.length === results.length) {
    const firstValue = constants[0]?.value;
    if (
      firstValue === undefined ||
      constants.some(result => result.value !== firstValue)
    ) {
      return { kind: "unknown", reason: "conflicting-values" };
    }

    const firstAssignmentIndex = constants[0]?.assignmentInsn?.index;
    const assignmentInsn =
      firstAssignmentIndex !== undefined &&
      constants.every(
        result => result.assignmentInsn?.index === firstAssignmentIndex
      )
        ? constants[0]?.assignmentInsn
        : undefined;

    return { kind: "const", value: firstValue, assignmentInsn };
  }

  const maps = results.filter(
    (result): result is Extract<ResolveResult, { kind: "map" }> =>
      result.kind === "map"
  );
  if (maps.length === results.length) {
    const firstMapId = maps[0]?.mapId;
    if (
      firstMapId === undefined ||
      maps.some(result => result.mapId !== firstMapId)
    ) {
      return { kind: "unknown", reason: "conflicting-values" };
    }

    const firstAssignmentIndex = maps[0]?.assignmentInsn?.index;
    const assignmentInsn =
      firstAssignmentIndex !== undefined &&
      maps.every(
        result => result.assignmentInsn?.index === firstAssignmentIndex
      )
        ? maps[0]?.assignmentInsn
        : undefined;

    return { kind: "map", mapId: firstMapId, assignmentInsn };
  }

  return { kind: "unknown", reason: "conflicting-values" };
}

function writeForRegister(
  parsed: ParsedInsn,
  reg: RegisterName
): RegisterWrite | undefined {
  return parsed.writes.find(write => write.reg === reg);
}

function createRegisterResolver(
  parsed: ParsedInsn[],
  predecessors: number[][]
): {
  resolveBefore: (pos: number, reg: RegisterName) => ResolveResult;
} {
  const memo = new Map<string, ResolveResult>();
  const visiting = new Set<string>();
  let steps = 0;

  const resolveBefore = (pos: number, reg: RegisterName): ResolveResult => {
    const key = `before:${pos}:${reg}`;
    if (steps++ > MAX_RESOLUTION_STEPS)
      return { kind: "unknown", reason: "analysis-limit" };
    if (memo.has(key)) return memo.get(key)!;
    if (visiting.has(key)) return { kind: "unknown", reason: "analysis-limit" };

    visiting.add(key);
    const result = mergeResults(
      predecessors[pos].map(predPos => resolveAfter(predPos, reg))
    );
    visiting.delete(key);
    memo.set(key, result);
    return result;
  };

  const resolveAfter = (pos: number, reg: RegisterName): ResolveResult => {
    const key = `after:${pos}:${reg}`;
    if (steps++ > MAX_RESOLUTION_STEPS)
      return { kind: "unknown", reason: "analysis-limit" };
    if (memo.has(key)) return memo.get(key)!;
    if (visiting.has(key)) return { kind: "unknown", reason: "analysis-limit" };

    visiting.add(key);
    const parsedInsn = parsed[pos];
    const write = writeForRegister(parsedInsn, reg);
    let result: ResolveResult;

    if (!write) {
      result = resolveBefore(pos, reg);
    } else if (write.kind === "const") {
      result = {
        kind: "const",
        value: write.value,
        assignmentInsn: write.insn,
      };
    } else if (write.kind === "map") {
      result = {
        kind: "map",
        mapId: write.mapId,
        assignmentInsn: write.insn,
      };
    } else if (write.kind === "copy") {
      const source = resolveBefore(pos, write.source);
      result =
        source.kind === "const"
          ? { kind: "const", value: source.value, assignmentInsn: write.insn }
          : source.kind === "map"
            ? { kind: "map", mapId: source.mapId, assignmentInsn: write.insn }
            : {
                kind: "unknown",
                reason:
                  source.reason === "no-direct-assignment"
                    ? "dynamic-assignment"
                    : source.reason,
                assignmentInsn: write.insn,
              };
    } else {
      result = {
        kind: "unknown",
        reason: "dynamic-assignment",
        assignmentInsn: write.insn,
      };
    }

    visiting.delete(key);
    memo.set(key, result);
    return result;
  };

  return { resolveBefore };
}

function resolveRegisterAtExit(
  parsed: ParsedInsn[],
  predecessors: number[][],
  exitPos: number
): ResolveResult {
  return createRegisterResolver(parsed, predecessors).resolveBefore(
    exitPos,
    RETURN_REGISTER
  );
}

function extractTailCalls(
  parsed: ParsedInsn[],
  predecessors: number[][]
): XlatedTailCall[] {
  const resolver = createRegisterResolver(parsed, predecessors);
  const tailCalls: XlatedTailCall[] = [];

  for (const parsedInsn of parsed) {
    if (!isTailCallInsn(parsedInsn.insn.disasm)) continue;

    const map = resolver.resolveBefore(parsedInsn.pos, "r2");
    const slot = resolver.resolveBefore(parsedInsn.pos, "r3");
    const tailCall: XlatedTailCall = {
      insnIndex: parsedInsn.insn.index,
      disasm: parsedInsn.insn.disasm,
      ...sourceEvidence(parsedInsn.insn),
    };

    if (map.kind === "map") {
      tailCall.mapId = map.mapId;
      tailCall.mapAssignmentIndex = map.assignmentInsn?.index;
      tailCall.mapAssignmentDisasm = map.assignmentInsn?.disasm;
    }

    if (slot.kind === "const") {
      tailCall.slot = slot.value;
      tailCall.slotAssignmentIndex = slot.assignmentInsn?.index;
      tailCall.slotAssignmentDisasm = slot.assignmentInsn?.disasm;
    }

    tailCalls.push(tailCall);
  }

  return tailCalls;
}

function toKnownExit(
  exitInsn: XlatedInsn,
  resolved: Extract<ResolveResult, { kind: "const" }>,
  branchEvidence?: XlatedBranchEvidence[]
): XlatedReturnExit {
  return {
    exitIndex: exitInsn.index,
    exitDisasm: exitInsn.disasm,
    assignmentIndex: resolved.assignmentInsn?.index,
    assignmentDisasm: resolved.assignmentInsn?.disasm,
    value: resolved.value,
    ...(branchEvidence ? { branchEvidence } : {}),
    ...sourceEvidence(resolved.assignmentInsn ?? exitInsn),
  };
}

function toUnknownExit(
  exitInsn: XlatedInsn,
  resolved: Extract<ResolveResult, { kind: "unknown" }>,
  branchEvidence?: XlatedBranchEvidence[]
): XlatedReturnExit {
  return {
    exitIndex: exitInsn.index,
    exitDisasm: exitInsn.disasm,
    assignmentIndex: resolved.assignmentInsn?.index,
    assignmentDisasm: resolved.assignmentInsn?.disasm,
    reason: resolved.reason,
    ...(branchEvidence ? { branchEvidence } : {}),
    ...sourceEvidence(resolved.assignmentInsn ?? exitInsn),
  };
}

/**
 * Conservative return-value analyzer for xlated BPF bytecode.
 *
 * It builds a small CFG from branch offsets and resolves r0 at each exit by
 * walking backward through predecessors. The analysis intentionally understands
 * only constants, register copies, and simple control-flow merges; helpers,
 * memory loads, arithmetic, loops, and conflicting paths remain unknown.
 */
export function analyzeXlatedReturns(
  insns: XlatedInsn[]
): XlatedReturnAnalysis {
  const constantExits: XlatedReturnExit[] = [];
  const unknownExits: XlatedReturnExit[] = [];
  const constantCounts = new Map<number, number>();
  const tailCallIndices = insns
    .filter(insn => isTailCallInsn(insn.disasm))
    .map(insn => insn.index);
  const parsed = parseInstructions(insns);
  const { predecessors, reachable } = buildControlFlow(parsed);
  const tailCalls = extractTailCalls(parsed, predecessors);

  for (const parsedInsn of parsed) {
    if (!parsedInsn.isExit) continue;
    if (!reachable.has(parsedInsn.pos)) continue;

    const resolved = resolveRegisterAtExit(
      parsed,
      predecessors,
      parsedInsn.pos
    );
    const branchEvidence = extractBranchEvidence(
      parsed,
      predecessors,
      parsedInsn.pos
    );
    if (resolved.kind === "const") {
      constantExits.push(
        toKnownExit(parsedInsn.insn, resolved, branchEvidence)
      );
      constantCounts.set(
        resolved.value,
        (constantCounts.get(resolved.value) ?? 0) + 1
      );
      continue;
    }

    unknownExits.push(
      toUnknownExit(
        parsedInsn.insn,
        resolved.kind === "unknown"
          ? resolved
          : {
              kind: "unknown",
              reason: "dynamic-assignment",
              assignmentInsn: resolved.assignmentInsn,
            },
        branchEvidence
      )
    );
  }

  return {
    exitCount: constantExits.length + unknownExits.length,
    constantExits,
    unknownExits,
    observedConstants: Array.from(constantCounts.entries())
      .map(([value, exitCount]) => ({ value, exitCount }))
      .sort((a, b) => a.value - b.value),
    tailCallIndices,
    ...(tailCalls.length > 0 ? { tailCalls } : {}),
    hasUnknownExits: unknownExits.length > 0,
    hasTailCalls: tailCallIndices.length > 0,
    sideEffects: analyzeXlatedSideEffects(insns),
  };
}

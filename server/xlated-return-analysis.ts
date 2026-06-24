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
  | {
      kind: "helper-return";
      reg: "r0";
      helper: string;
      insn: XlatedInsn;
    }
  | {
      kind: "local-call";
      reg: "r0";
      targetIndex: number;
      insn: XlatedInsn;
    }
  | { kind: "unknown"; reg: RegisterName; insn: XlatedInsn };

type ResolveResult =
  | { kind: "const"; value: number; assignmentInsn?: XlatedInsn }
  | { kind: "const-set"; values: number[]; assignmentInsn?: XlatedInsn }
  | { kind: "helper-return"; helper: string; assignmentInsn?: XlatedInsn }
  | {
      kind: "const-helper-set";
      values: number[];
      helperReturns: HelperReturnResult[];
      assignmentInsn?: XlatedInsn;
    }
  | { kind: "map"; mapId: number; assignmentInsn?: XlatedInsn }
  | { kind: "unknown"; reason: UnknownReason; assignmentInsn?: XlatedInsn };

interface HelperReturnResult {
  helper: string;
  assignmentInsn?: XlatedInsn;
}

const RETURN_REGISTER = "r0" satisfies RegisterName;
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
const MODELED_HELPER_RETURNS = new Set(["redirect", "redirect_map"]);

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

function localCallTargetIndex(insn: XlatedInsn): number | undefined {
  const body = insn.disasm.trim().replace(/^\([0-9a-fA-F]+\)\s+/, "");
  const match = body.match(/^call\s+pc([+-]\d+)/);
  if (!match) return undefined;

  const targetIndex = insn.index + 1 + Number.parseInt(match[1], 10);
  return Number.isFinite(targetIndex) ? targetIndex : undefined;
}

function callHelperName(insn: XlatedInsn): string | undefined {
  const body = insn.disasm.trim().replace(/^\([0-9a-fA-F]+\)\s+/, "");
  const match = body.match(/^call\s+(\S+)/);
  if (!match) return undefined;

  const helper = match[1].split("#")[0].replace(/^bpf_/, "").toLowerCase();
  return helper || undefined;
}

function modeledHelperReturnName(insn: XlatedInsn): string | undefined {
  const helper = callHelperName(insn);
  return helper && MODELED_HELPER_RETURNS.has(helper) ? helper : undefined;
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
    const targetIndex = localCallTargetIndex(insn);
    if (targetIndex !== undefined) {
      return [
        { kind: "local-call", reg: RETURN_REGISTER, targetIndex, insn },
        ...CALL_CLOBBERED_REGS.filter(reg => reg !== RETURN_REGISTER).map(
          reg => ({ kind: "unknown" as const, reg, insn })
        ),
      ];
    }

    const helper = modeledHelperReturnName(insn);
    if (helper) {
      return [
        { kind: "helper-return", reg: RETURN_REGISTER, helper, insn },
        ...CALL_CLOBBERED_REGS.filter(reg => reg !== RETURN_REGISTER).map(
          reg => ({ kind: "unknown" as const, reg, insn })
        ),
      ];
    }

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

  const selfXorMatch = body.match(
    /^([rw](?:10|[0-9]))\s*\^=\s*([rw](?:10|[0-9]))\b/
  );
  if (selfXorMatch) {
    const reg = normalizeRegister(selfXorMatch[1]);
    const source = normalizeRegister(selfXorMatch[2]);
    if (reg && source && reg === source) {
      return [{ kind: "const", reg, value: 0, insn }];
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

function constantResults(
  result: ResolveResult
): Array<{ value: number; assignmentInsn?: XlatedInsn }> {
  if (result.kind === "const") {
    return [{ value: result.value, assignmentInsn: result.assignmentInsn }];
  }
  if (result.kind === "const-set") {
    return result.values.map(value => ({
      value,
      assignmentInsn: result.assignmentInsn,
    }));
  }
  if (result.kind === "const-helper-set") {
    return result.values.map(value => ({
      value,
      assignmentInsn: result.assignmentInsn,
    }));
  }
  return [];
}

function helperReturnResults(result: ResolveResult): HelperReturnResult[] {
  if (result.kind === "helper-return") {
    return [{ helper: result.helper, assignmentInsn: result.assignmentInsn }];
  }
  if (result.kind === "const-helper-set") {
    return result.helperReturns;
  }
  return [];
}

function commonAssignmentInsn(
  assignments: Array<{ assignmentInsn?: XlatedInsn }>
): XlatedInsn | undefined {
  const firstAssignmentIndex = assignments[0]?.assignmentInsn?.index;
  if (
    firstAssignmentIndex === undefined ||
    assignments.some(
      result => result.assignmentInsn?.index !== firstAssignmentIndex
    )
  ) {
    return undefined;
  }
  return assignments[0]?.assignmentInsn;
}

function uniqueHelperReturns(
  helperReturns: HelperReturnResult[]
): HelperReturnResult[] {
  const seen = new Set<string>();
  const unique: HelperReturnResult[] = [];
  for (const helperReturn of helperReturns) {
    const key = `${helperReturn.helper}:${helperReturn.assignmentInsn?.index ?? ""}:${helperReturn.assignmentInsn?.disasm ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(helperReturn);
  }
  return unique;
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

  const constants = results.flatMap(constantResults);
  const helperReturns = uniqueHelperReturns(
    results.flatMap(helperReturnResults)
  );
  const maps = results.filter(
    (result): result is Extract<ResolveResult, { kind: "map" }> =>
      result.kind === "map"
  );

  if (maps.length > 0 && maps.length !== results.length) {
    return { kind: "unknown", reason: "conflicting-values" };
  }

  if (helperReturns.length > 0) {
    const values = Array.from(
      new Set(constants.map(result => result.value))
    ).sort((a, b) => a - b);
    const assignmentInsn = commonAssignmentInsn(constants);

    if (values.length === 0 && helperReturns.length === 1) {
      return {
        kind: "helper-return",
        helper: helperReturns[0].helper,
        assignmentInsn: helperReturns[0].assignmentInsn,
      };
    }

    return { kind: "const-helper-set", values, helperReturns, assignmentInsn };
  }

  if (
    results.every(
      result => result.kind === "const" || result.kind === "const-set"
    )
  ) {
    const values = Array.from(
      new Set(constants.map(result => result.value))
    ).sort((a, b) => a - b);
    if (values.length === 0) {
      return { kind: "unknown", reason: "no-direct-assignment" };
    }

    const assignmentInsn = commonAssignmentInsn(constants);

    return values.length === 1
      ? { kind: "const", value: values[0], assignmentInsn }
      : { kind: "const-set", values, assignmentInsn };
  }

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

function propagateResolvedAssignment(
  source: ResolveResult,
  assignmentInsn: XlatedInsn
): ResolveResult {
  if (source.kind === "const") {
    return {
      kind: "const",
      value: source.value,
      assignmentInsn,
    };
  }
  if (source.kind === "const-set") {
    return {
      kind: "const-set",
      values: source.values,
      assignmentInsn,
    };
  }
  if (source.kind === "helper-return") {
    return {
      kind: "helper-return",
      helper: source.helper,
      assignmentInsn: source.assignmentInsn ?? assignmentInsn,
    };
  }
  if (source.kind === "const-helper-set") {
    return {
      kind: "const-helper-set",
      values: source.values,
      helperReturns: source.helperReturns,
      assignmentInsn,
    };
  }
  if (source.kind === "map") {
    return { kind: "map", mapId: source.mapId, assignmentInsn };
  }
  return {
    kind: "unknown",
    reason:
      source.reason === "no-direct-assignment"
        ? "dynamic-assignment"
        : source.reason,
    assignmentInsn: source.assignmentInsn ?? assignmentInsn,
  };
}

function writeForRegister(
  parsed: ParsedInsn,
  reg: RegisterName
): RegisterWrite | undefined {
  return parsed.writes.find(write => write.reg === reg);
}

function createRegisterResolver(
  parsed: ParsedInsn[],
  predecessors: number[][],
  resolveLocalCall?: (targetIndex: number) => ResolveResult
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
      result = propagateResolvedAssignment(source, write.insn);
    } else if (write.kind === "helper-return") {
      result = {
        kind: "helper-return",
        helper: write.helper,
        assignmentInsn: write.insn,
      };
    } else {
      if (write.kind === "local-call") {
        const callResult = resolveLocalCall?.(write.targetIndex) ?? {
          kind: "unknown",
          reason: "dynamic-assignment",
        };
        result = propagateResolvedAssignment(callResult, write.insn);
      } else {
        result = {
          kind: "unknown",
          reason: "dynamic-assignment",
          assignmentInsn: write.insn,
        };
      }
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
  exitPos: number,
  resolveLocalCall?: (targetIndex: number) => ResolveResult
): ResolveResult {
  return createRegisterResolver(
    parsed,
    predecessors,
    resolveLocalCall
  ).resolveBefore(exitPos, RETURN_REGISTER);
}

function extractTailCalls(
  parsed: ParsedInsn[],
  predecessors: number[][],
  resolveLocalCall?: (targetIndex: number) => ResolveResult
): XlatedTailCall[] {
  const resolver = createRegisterResolver(
    parsed,
    predecessors,
    resolveLocalCall
  );
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

function mergeFunctionExitResults(
  parsed: ParsedInsn[],
  predecessors: number[][],
  reachable: Set<number>,
  resolveLocalCall?: (targetIndex: number) => ResolveResult
): ResolveResult {
  const results: ResolveResult[] = [];

  for (const parsedInsn of parsed) {
    if (!parsedInsn.isExit) continue;
    if (!reachable.has(parsedInsn.pos)) continue;
    results.push(
      resolveRegisterAtExit(
        parsed,
        predecessors,
        parsedInsn.pos,
        resolveLocalCall
      )
    );
  }

  return mergeResults(results);
}

function createLocalCallResolver(
  insns: XlatedInsn[]
): (targetIndex: number) => ResolveResult {
  const indexToPos = new Map<number, number>();
  insns.forEach((insn, pos) => indexToPos.set(insn.index, pos));

  const targetIndices = new Set<number>();
  for (const insn of insns) {
    const targetIndex = localCallTargetIndex(insn);
    if (targetIndex !== undefined && indexToPos.has(targetIndex)) {
      targetIndices.add(targetIndex);
    }
  }

  const targetPositions = Array.from(targetIndices)
    .map(targetIndex => indexToPos.get(targetIndex))
    .filter((pos): pos is number => pos !== undefined)
    .sort((a, b) => a - b);
  const memo = new Map<number, ResolveResult>();
  const visiting = new Set<number>();

  const resolve = (targetIndex: number): ResolveResult => {
    if (!targetIndices.has(targetIndex)) {
      return { kind: "unknown", reason: "dynamic-assignment" };
    }
    if (memo.has(targetIndex)) return memo.get(targetIndex)!;
    if (visiting.has(targetIndex)) {
      return { kind: "unknown", reason: "analysis-limit" };
    }

    const startPos = indexToPos.get(targetIndex);
    if (startPos === undefined) {
      return { kind: "unknown", reason: "dynamic-assignment" };
    }

    visiting.add(targetIndex);
    const endPos =
      targetPositions.find(candidate => candidate > startPos) ?? insns.length;
    const parsed = parseInstructions(insns.slice(startPos, endPos));
    const { predecessors, reachable } = buildControlFlow(parsed);
    const result = mergeFunctionExitResults(
      parsed,
      predecessors,
      reachable,
      resolve
    );
    visiting.delete(targetIndex);
    memo.set(targetIndex, result);
    return result;
  };

  return resolve;
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

function toKnownExits(
  exitInsn: XlatedInsn,
  resolved: Extract<
    ResolveResult,
    { kind: "const" | "const-set" | "const-helper-set" }
  >,
  branchEvidence?: XlatedBranchEvidence[]
): XlatedReturnExit[] {
  if (resolved.kind === "const") {
    return [toKnownExit(exitInsn, resolved, branchEvidence)];
  }

  return resolved.values.map(value => ({
    exitIndex: exitInsn.index,
    exitDisasm: exitInsn.disasm,
    assignmentIndex: resolved.assignmentInsn?.index,
    assignmentDisasm: resolved.assignmentInsn?.disasm,
    value,
    ...(branchEvidence ? { branchEvidence } : {}),
    ...sourceEvidence(resolved.assignmentInsn ?? exitInsn),
  }));
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

function toHelperUnknownExits(
  exitInsn: XlatedInsn,
  resolved: Extract<
    ResolveResult,
    { kind: "helper-return" | "const-helper-set" }
  >,
  branchEvidence?: XlatedBranchEvidence[]
): XlatedReturnExit[] {
  const helperReturns =
    resolved.kind === "helper-return"
      ? [{ helper: resolved.helper, assignmentInsn: resolved.assignmentInsn }]
      : resolved.helperReturns;

  return helperReturns.map(helperReturn => ({
    exitIndex: exitInsn.index,
    exitDisasm: exitInsn.disasm,
    assignmentIndex: helperReturn.assignmentInsn?.index,
    assignmentDisasm: helperReturn.assignmentInsn?.disasm,
    reason: "dynamic-assignment" as const,
    ...(branchEvidence ? { branchEvidence } : {}),
    ...sourceEvidence(helperReturn.assignmentInsn ?? exitInsn),
  }));
}

/**
 * Conservative return-value analyzer for xlated BPF bytecode.
 *
 * It builds a small CFG from branch offsets and resolves r0 at each exit by
 * walking backward through predecessors. The analysis understands constants,
 * register copies, simple control-flow merges, and local BPF subprogram calls;
 * helpers, memory loads, arithmetic, loops, and conflicting paths remain
 * unknown.
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
  const resolveLocalCall = createLocalCallResolver(insns);
  const tailCalls = extractTailCalls(parsed, predecessors, resolveLocalCall);

  for (const parsedInsn of parsed) {
    if (!parsedInsn.isExit) continue;
    if (!reachable.has(parsedInsn.pos)) continue;

    const resolved = resolveRegisterAtExit(
      parsed,
      predecessors,
      parsedInsn.pos,
      resolveLocalCall
    );
    const branchEvidence = extractBranchEvidence(
      parsed,
      predecessors,
      parsedInsn.pos
    );
    if (
      resolved.kind === "const" ||
      resolved.kind === "const-set" ||
      resolved.kind === "const-helper-set"
    ) {
      for (const exit of toKnownExits(
        parsedInsn.insn,
        resolved,
        branchEvidence
      )) {
        constantExits.push(exit);
        if (exit.value !== undefined) {
          constantCounts.set(
            exit.value,
            (constantCounts.get(exit.value) ?? 0) + 1
          );
        }
      }
    }

    if (
      resolved.kind === "helper-return" ||
      resolved.kind === "const-helper-set"
    ) {
      unknownExits.push(
        ...toHelperUnknownExits(parsedInsn.insn, resolved, branchEvidence)
      );
      continue;
    }

    if (resolved.kind === "const" || resolved.kind === "const-set") {
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

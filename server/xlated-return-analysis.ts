import type { XlatedInsn, XlatedReturnAnalysis, XlatedReturnExit } from "../shared/ebpf-types";

function isExitInsn(disasm: string): boolean {
  return /^\(95\)\s+exit\b/.test(disasm.trim());
}

function parseIntegerLiteral(raw: string): number | null {
  const value = raw.startsWith("-0x")
    ? -Number.parseInt(raw.slice(3), 16)
    : raw.startsWith("0x")
      ? Number.parseInt(raw.slice(2), 16)
      : Number.parseInt(raw, 10);

  return Number.isFinite(value) ? value : null;
}

function parseDirectConstantReturn(disasm: string): number | null {
  const match = disasm.trim().match(/^\([0-9a-fA-F]+\)\s+[rw]0\s*=\s*(-?(?:0x[0-9a-fA-F]+|\d+))\b/);
  return match ? parseIntegerLiteral(match[1]) : null;
}

function isR0Assignment(disasm: string): boolean {
  return /^\([0-9a-fA-F]+\)\s+[rw]0\s*=/.test(disasm.trim());
}

function sourceEvidence(insn: XlatedInsn): Pick<XlatedReturnExit, "source" | "sourceFile" | "sourceLine" | "sourceColumn"> {
  const evidence: Pick<XlatedReturnExit, "source" | "sourceFile" | "sourceLine" | "sourceColumn"> = {};
  if (insn.source) evidence.source = insn.source;
  if (insn.linum && !evidence.source) evidence.source = insn.linum;
  if (insn.sourceFile) evidence.sourceFile = insn.sourceFile;
  if (insn.sourceLine !== undefined) evidence.sourceLine = insn.sourceLine;
  if (insn.sourceColumn !== undefined) evidence.sourceColumn = insn.sourceColumn;
  return evidence;
}

/**
 * Simple return-value analyzer for xlated BPF bytecode.
 *
 * This intentionally detects only direct patterns:
 *   r0 = <constant>
 *   exit
 *
 * It does not do CFG/path analysis yet. If an exit is reached through a shared
 * epilogue or a dynamic assignment, the exit is marked unknown for later passes.
 */
export function analyzeXlatedReturns(insns: XlatedInsn[]): XlatedReturnAnalysis {
  const constantExits: XlatedReturnExit[] = [];
  const unknownExits: XlatedReturnExit[] = [];
  const constantCounts = new Map<number, number>();

  for (let i = 0; i < insns.length; i += 1) {
    const exitInsn = insns[i];
    if (!isExitInsn(exitInsn.disasm)) continue;

    const previous = i > 0 ? insns[i - 1] : undefined;
    const value = previous ? parseDirectConstantReturn(previous.disasm) : null;

    if (previous && value !== null) {
      constantExits.push({
        exitIndex: exitInsn.index,
        exitDisasm: exitInsn.disasm,
        assignmentIndex: previous.index,
        assignmentDisasm: previous.disasm,
        value,
        ...sourceEvidence(previous),
      });
      constantCounts.set(value, (constantCounts.get(value) ?? 0) + 1);
      continue;
    }

    unknownExits.push({
      exitIndex: exitInsn.index,
      exitDisasm: exitInsn.disasm,
      assignmentIndex: previous?.index,
      assignmentDisasm: previous?.disasm,
      reason: previous && isR0Assignment(previous.disasm) ? "dynamic-assignment" : "no-direct-assignment",
      ...sourceEvidence(previous ?? exitInsn),
    });
  }

  return {
    exitCount: constantExits.length + unknownExits.length,
    constantExits,
    unknownExits,
    observedConstants: Array.from(constantCounts.entries())
      .map(([value, exitCount]) => ({ value, exitCount }))
      .sort((a, b) => a.value - b.value),
    hasUnknownExits: unknownExits.length > 0,
  };
}

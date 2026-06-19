/**
 * ebpf-dump.ts
 * Fetches code dumps for a single BPF program via bpftool:
 *   - xlated bytecode (always available)
 *   - CFG in Graphviz DOT format (always available)
 *   - jited native assembly (requires jited=true + kptr_restrict=0)
 *   - BTF line-number info interleaved with xlated (requires btf_id)
 */

import { execFile } from "child_process";
import { promisify } from "util";
import type { ProgDump, XlatedInsn, JitedInsn } from "../shared/ebpf-types";
import { getBpftoolPath, isSudoEnabled } from "./ebpf-poller";

const execFileAsync = promisify(execFile);

async function run(args: string[]): Promise<{ stdout: string; stderr: string; failed: boolean }> {
  const bpftool = getBpftoolPath();
  const sudo = isSudoEnabled();
  const cmd = sudo ? "sudo" : bpftool;
  const argv = sudo ? [bpftool, ...args] : args;
  try {
    const result = await execFileAsync(cmd, argv, {
      timeout: 10_000,
      maxBuffer: 64 * 1024 * 1024, // Large programs can produce very large code dumps.
    });
    return { stdout: result.stdout, stderr: result.stderr, failed: false };
  } catch (err: any) {
    return { stdout: err.stdout ?? "", stderr: err.stderr ?? String(err), failed: true };
  }
}

// ─── Parsers ──────────────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function optionalFiniteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function hasXlatedSourceInfo(insn: XlatedInsn): boolean {
  return !!insn.linum || !!insn.source || !!insn.sourceFile || insn.sourceLine !== undefined;
}

/**
 * Parse `bpftool -jp prog dump xlated id N` JSON output.
 * Each element is { "disasm": "..." } and optionally source metadata:
 * { "src": "...", "file": "...", "line_num": 42, "line_col": 5 }.
 */
export function parseXlatedJson(raw: string): XlatedInsn[] {
  try {
    const parsed = JSON.parse(raw) as unknown;
    const arr = Array.isArray(parsed) ? parsed : [];
    return arr
      .filter(isRecord)
      .filter(e => optionalString(e.disasm))
      .map((e, idx) => {
        const insn: XlatedInsn = {
          index: idx,
          disasm: optionalString(e.disasm)!,
        };
        const opcodes = optionalString(e.opcodes);
        const source = optionalString(e.src);
        const sourceFile = optionalString(e.file);
        const sourceLine = optionalFiniteNumber(e.line_num);
        const sourceColumn = optionalFiniteNumber(e.line_col);

        if (opcodes) insn.opcodes = opcodes;
        if (source) {
          insn.linum = source;
          insn.source = source;
        }
        if (sourceFile) insn.sourceFile = sourceFile;
        if (sourceLine !== undefined) insn.sourceLine = sourceLine;
        if (sourceColumn !== undefined) insn.sourceColumn = sourceColumn;
        return insn;
      });
  } catch {
    return [];
  }
}

/**
 * Parse `bpftool prog dump xlated id N linum` text output.
 * Lines look like:
 *   ; int cgroup_dev(struct bpf_cgroup_dev_ctx *ctx)   <- source annotation
 *      0: (61) r2 = *(u32 *)(r1 +0)
 * We interleave the source comments into the XlatedInsn array.
 */
function parseXlatedLinum(raw: string): XlatedInsn[] {
  const lines = raw.split("\n");
  const result: XlatedInsn[] = [];
  let pendingLinum: string | undefined;
  let idx = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Source annotation line: starts with ";"
    if (trimmed.startsWith(";")) {
      pendingLinum = trimmed.slice(1).trim();
      continue;
    }

    // Instruction line: "   N: (XX) ..."
    const m = trimmed.match(/^(\d+):\s+(.+)$/);
    if (m) {
      result.push({
        index: idx++,
        disasm: m[2],
        linum: pendingLinum,
        source: pendingLinum,
      });
      pendingLinum = undefined;
    }
  }

  return result;
}

interface JitedJsonInsn {
  pc?: unknown;
  disasm?: unknown;
  opcodes?: unknown;
  operation?: unknown;
  operands?: unknown;
}

function collectJitedJsonInsns(parsed: unknown): JitedJsonInsn[] {
  const items = Array.isArray(parsed) ? parsed : [parsed];
  const result: JitedJsonInsn[] = [];

  for (const item of items) {
    if (!isRecord(item)) continue;
    if (Array.isArray(item.insns)) {
      result.push(...item.insns.filter(isRecord));
    } else {
      result.push(item);
    }
  }

  return result;
}

function formatJitedJsonDisasm(insn: JitedJsonInsn): string | undefined {
  if (typeof insn.disasm === "string" && insn.disasm.trim()) {
    return insn.disasm.trim();
  }

  if (typeof insn.operation !== "string" || !insn.operation.trim()) {
    return undefined;
  }

  const operands = Array.isArray(insn.operands)
    ? insn.operands.filter((operand): operand is string => typeof operand === "string" && operand.length > 0)
    : [];
  return operands.length > 0
    ? `${insn.operation.trim()} ${operands.join(",")}`
    : insn.operation.trim();
}

/**
 * Parse `bpftool -jp prog dump jited id N` JSON output. bpftool versions differ:
 * some return flat instructions with `disasm`; others return program objects
 * with nested `insns` using `operation` and `operands`.
 */
export function parseJitedJson(raw: string): JitedInsn[] {
  try {
    const result: JitedInsn[] = [];
    for (const insn of collectJitedJsonInsns(JSON.parse(raw))) {
      const disasm = formatJitedJsonDisasm(insn);
      if (!disasm) continue;

      const parsed: JitedInsn = {
        pc: typeof insn.pc === "string" ? insn.pc : "0x?",
        disasm,
      };
      if (typeof insn.opcodes === "string") {
        parsed.opcodes = insn.opcodes;
      }
      result.push(parsed);
    }
    return result;
  } catch {
    return [];
  }
}

function formatTextPc(offset: bigint, basePc: bigint | null): string {
  const pc = basePc === null ? offset : basePc + offset;
  return `0x${pc.toString(16)}`;
}

function normalizeHexPc(pc: string): string {
  return pc.startsWith("0x") ? pc : `0x${pc}`;
}

function splitJitedInstruction(raw: string): { disasm: string; opcodes?: string } {
  const trimmed = raw.trim();
  const opcodeMatch = trimmed.match(/^((?:[0-9a-fA-F]{2}\s+)+)(.+)$/);
  if (!opcodeMatch) return { disasm: trimmed };

  return {
    opcodes: opcodeMatch[1].trim().replace(/\s+/g, " "),
    disasm: opcodeMatch[2].trim(),
  };
}

/**
 * Parse `bpftool prog dump jited id N` text output. Some bpftool versions do
 * not return useful JSON for JIT dumps, while text mode still prints native
 * assembly.
 */
export function parseJitedText(raw: string): JitedInsn[] {
  const result: JitedInsn[] = [];
  let basePc: bigint | null = null;

  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith(";")) continue;

    const baseMatch = trimmed.match(/^(?:0x)?([0-9a-fA-F]{8,}):$/);
    if (baseMatch) {
      basePc = BigInt(`0x${baseMatch[1]}`);
      continue;
    }

    const absoluteMatch = trimmed.match(/^(0x[0-9a-fA-F]+|[0-9a-fA-F]{8,}):\s+(\d+):\s+(.+)$/);
    if (absoluteMatch) {
      const parsed = splitJitedInstruction(absoluteMatch[3]);
      if (parsed.disasm) {
        result.push({
          pc: normalizeHexPc(absoluteMatch[1]),
          disasm: parsed.disasm,
          opcodes: parsed.opcodes,
        });
      }
      continue;
    }

    const offsetMatch = trimmed.match(/^(\d+):\s+(.+)$/);
    if (!offsetMatch) continue;

    const parsed = splitJitedInstruction(offsetMatch[2]);
    if (parsed.disasm) {
      result.push({
        pc: formatTextPc(BigInt(offsetMatch[1]), basePc),
        disasm: parsed.disasm,
        opcodes: parsed.opcodes,
      });
    }
  }

  return result;
}

// ─── Main export ──────────────────────────────────────────────────────────────

export async function fetchProgDump(progId: number, hasBtf: boolean, isJited: boolean): Promise<ProgDump> {
  // ── 1. BPF bytecode (xlated) ─────────────────────────────────────────────
  let xlated: XlatedInsn[] = [];
  let hasLineInfo = false;
  let xlatedFailed = false;
  let xlatedError = "";

  if (hasBtf) {
    // Try linum first — gives us file:line source annotations (richest output)
    const linumResult = await run(["-jp", "prog", "dump", "xlated", "id", String(progId), "linum"]);
    if (!linumResult.failed && linumResult.stdout.trim()) {
      xlated = parseXlatedJson(linumResult.stdout);
      hasLineInfo = xlated.some(hasXlatedSourceInfo);
    }
  }

  if (xlated.length === 0) {
    // Fall back to plain JSON xlated
    const xlatedResult = await run(["-jp", "prog", "dump", "xlated", "id", String(progId)]);
    if (xlatedResult.failed) {
      xlatedFailed = true;
      xlatedError = xlatedResult.stderr.trim();
    } else {
      xlated = parseXlatedJson(xlatedResult.stdout);
      hasLineInfo = xlated.some(hasXlatedSourceInfo);
    }
  }

  // If JSON parsing produced no source annotations, try text-mode xlated.
  // bpftool text output embeds "; <C source>" lines even when the linum flag
  // isn't used, as long as the kernel has BTF/DWARF info for the program.
  if (!hasLineInfo && xlated.length > 0) {
    const textResult = await run(["prog", "dump", "xlated", "id", String(progId)]);
    if (!textResult.failed && textResult.stdout.trim()) {
      const textXlated = parseXlatedLinum(textResult.stdout);
      if (textXlated.some(i => i.linum !== undefined)) {
        xlated = textXlated;
        hasLineInfo = true;
      }
    }
  }

  // ── 2. CFG in DOT format ─────────────────────────────────────────────────
  let cfgDot = "";
  const dotResult = await run(["prog", "dump", "xlated", "id", String(progId), "visual"]);
  if (!dotResult.failed && dotResult.stdout.trim().startsWith("digraph")) {
    cfgDot = dotResult.stdout;
  } else {
    // Build a minimal DOT from xlated if visual failed
    cfgDot = buildMinimalDot(xlated);
  }

  // ── 3. JIT assembly ──────────────────────────────────────────────────────
  let jited: JitedInsn[] | null = null;
  let jitedUnavailableReason: string | undefined;

  if (!isJited) {
    jitedUnavailableReason = "This program was not JIT-compiled (jited=false). JIT compilation requires CONFIG_BPF_JIT and net.core.bpf_jit_enable=1.";
  } else {
    // Ensure kptr_restrict=0 so kernel pointers are visible
    try {
      const sysctlCmd = isSudoEnabled() ? "sudo" : "sysctl";
      const sysctlArgv = isSudoEnabled()
        ? ["sysctl", "-w", "kernel.kptr_restrict=0"]
        : ["-w", "kernel.kptr_restrict=0"];
      await execFileAsync(sysctlCmd, sysctlArgv, { timeout: 5_000 });
    } catch { /* best-effort — JIT dump may still work */ }

    const jitedJsonResult = await run(["-jp", "prog", "dump", "jited", "id", String(progId)]);
    let parsed = jitedJsonResult.failed
      ? []
      : [
          ...parseJitedJson(jitedJsonResult.stdout),
          ...parseJitedText(jitedJsonResult.stdout),
        ];

    let jitedTextResult: Awaited<ReturnType<typeof run>> | undefined;
    if (parsed.length === 0) {
      jitedTextResult = await run(["prog", "dump", "jited", "id", String(progId)]);
      if (!jitedTextResult.failed) {
        parsed = parseJitedText(jitedTextResult.stdout);
      }
    }

    if (parsed.length > 0) {
      jited = parsed;
    } else {
      const jitedErr = jitedTextResult?.stderr || jitedJsonResult.stderr;
      jitedUnavailableReason =
        jitedErr.includes("kptr_restrict")
          ? "JIT dump blocked by kernel.kptr_restrict. Run: sudo sysctl -w kernel.kptr_restrict=0"
          : jitedErr.includes("no instructions")
          ? "No JIT instructions returned. The program may have been loaded before JIT was enabled."
          : `JIT dump unavailable: ${jitedErr.trim() || "unknown error"}`;
    }
  }

  // Build error message if the critical xlated dump failed
  let error: string | undefined;
  if (xlatedFailed) {
    if (xlatedError.includes("ENOENT") || xlatedError.includes("not found")) {
      error = `bpftool not found. Check that the configured path is correct.`;
    } else if (xlatedError.includes("EACCES") || xlatedError.includes("permission denied") || xlatedError.includes("Operation not permitted")) {
      error = `Permission denied. Try enabling sudo in Settings.`;
    } else if (xlatedError.includes("ETIMEDOUT") || xlatedError.includes("timed out")) {
      error = `bpftool timed out dumping program ${progId}.`;
    } else {
      error = `Failed to dump program ${progId}: ${xlatedError || "unknown error"}`;
    }
  }

  return {
    progId,
    xlated,
    cfgDot,
    jited,
    jitedUnavailableReason,
    hasLineInfo,
    hasBtf,
    btfId: undefined, // populated by caller if needed
    error,
  };
}

// ─── Fallback minimal DOT builder ─────────────────────────────────────────────

/**
 * When bpftool visual fails, build a simple linear DOT graph from xlated insns.
 * Groups instructions into basic blocks split at jump instructions.
 */
function buildMinimalDot(insns: XlatedInsn[]): string {
  if (insns.length === 0) return `digraph "BPF CFG" { empty [label="No instructions"]; }`;

  // Find basic block boundaries: jumps and their targets
  const jumpTargets = new Set<number>();
  const jumpSources = new Map<number, number[]>(); // src index → [target indices]

  for (const insn of insns) {
    const m = insn.disasm.match(/goto pc([+-]\d+)/);
    if (m) {
      const offset = parseInt(m[1]);
      const target = insn.index + 1 + offset;
      jumpTargets.add(target);
      const targets = jumpSources.get(insn.index) ?? [];
      targets.push(target);
      targets.push(insn.index + 1); // fall-through
      jumpSources.set(insn.index, targets);
    }
  }

  // Build blocks
  const blocks: Array<{ start: number; insns: XlatedInsn[] }> = [];
  let current: XlatedInsn[] = [];

  for (const insn of insns) {
    if (jumpTargets.has(insn.index) && current.length > 0) {
      blocks.push({ start: current[0].index, insns: current });
      current = [];
    }
    current.push(insn);
    if (jumpSources.has(insn.index)) {
      blocks.push({ start: current[0].index, insns: current });
      current = [];
    }
  }
  if (current.length > 0) blocks.push({ start: current[0].index, insns: current });

  // Render DOT
  const lines: string[] = [`digraph "BPF CFG" {`, `  node [shape=record fontname="monospace" fontsize=10];`];

  for (const block of blocks) {
    const label = block.insns
      .map(i => `${i.index}: ${i.disasm.replace(/"/g, '\\"').replace(/[<>|{}]/g, "\\$&")}`)
      .join("\\l");
    lines.push(`  bb_${block.start} [label="{${label}\\l}"];`);
  }

  // Edges
  for (const block of blocks) {
    const last = block.insns[block.insns.length - 1];
    const targets = jumpSources.get(last.index);
    if (targets) {
      for (const t of targets) {
        const targetBlock = blocks.find(b => b.start <= t && t < b.start + b.insns.length);
        if (targetBlock) {
          lines.push(`  bb_${block.start} -> bb_${targetBlock.start};`);
        }
      }
    } else {
      // Fall-through to next block
      const nextIdx = blocks.indexOf(block) + 1;
      if (nextIdx < blocks.length) {
        lines.push(`  bb_${block.start} -> bb_${blocks[nextIdx].start};`);
      }
    }
  }

  lines.push("}");
  return lines.join("\n");
}

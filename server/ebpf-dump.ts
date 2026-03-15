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
      maxBuffer: 8 * 1024 * 1024, // 8 MB — large programs can produce big dumps
    });
    return { stdout: result.stdout, stderr: result.stderr, failed: false };
  } catch (err: any) {
    return { stdout: err.stdout ?? "", stderr: err.stderr ?? String(err), failed: true };
  }
}

// ─── Parsers ──────────────────────────────────────────────────────────────────

/**
 * Parse `bpftool -jp prog dump xlated id N` JSON output.
 * Each element is { "disasm": "..." } and optionally { "opcodes": "..." }.
 */
function parseXlatedJson(raw: string): XlatedInsn[] {
  try {
    const arr: Array<{ disasm?: string; opcodes?: string }> = JSON.parse(raw);
    return arr
      .filter(e => e.disasm)
      .map((e, idx) => ({
        index: idx,
        disasm: e.disasm!,
        opcodes: e.opcodes,
      }));
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
      });
      pendingLinum = undefined;
    }
  }

  return result;
}

/**
 * Parse `bpftool -jp prog dump jited id N` JSON output.
 * Each element: { "pc": "0xffffc...", "disasm": "push %rbp" }
 */
function parseJitedJson(raw: string): JitedInsn[] {
  try {
    const arr: Array<{ pc?: string; disasm?: string; opcodes?: string }> = JSON.parse(raw);
    return arr
      .filter(e => e.disasm)
      .map(e => ({
        pc: e.pc ?? "0x?",
        disasm: e.disasm!,
        opcodes: e.opcodes,
      }));
  } catch {
    return [];
  }
}

// ─── Main export ──────────────────────────────────────────────────────────────

export async function fetchProgDump(progId: number, hasBtf: boolean, isJited: boolean): Promise<ProgDump> {
  // ── 1. BPF bytecode (xlated) ─────────────────────────────────────────────
  let xlated: XlatedInsn[] = [];
  let hasLineInfo = false;
  let xlatedFailed = false;
  let xlatedError = "";

  if (hasBtf) {
    // Try linum first — gives us source annotations
    const linumResult = await run(["-jp", "prog", "dump", "xlated", "id", String(progId), "linum"]);
    if (!linumResult.failed && linumResult.stdout.trim()) {
      xlated = parseXlatedLinum(linumResult.stdout);
      hasLineInfo = xlated.some(i => i.linum !== undefined);
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

    const jitedResult = await run(["-jp", "prog", "dump", "jited", "id", String(progId)]);
    const parsed = jitedResult.failed ? [] : parseJitedJson(jitedResult.stdout);

    if (parsed.length > 0) {
      jited = parsed;
    } else {
      const jitedErr = jitedResult.stderr;
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

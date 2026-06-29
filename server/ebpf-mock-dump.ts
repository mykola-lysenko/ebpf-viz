/**
 * ebpf-mock-dump.ts
 *
 * Generates realistic-looking BPF code dumps for demo mode programs.
 * Each mock program has hand-crafted xlated bytecode that reflects its
 * actual purpose (XDP packet filter, kprobe, cgroup policy, etc.).
 *
 * The CFG DOT is built from the xlated instructions using the same
 * buildMinimalDot logic used in ebpf-dump.ts.
 */

import type { ProgDump, XlatedInsn } from "../shared/ebpf-types";
import { buildCfgSummary } from "../shared/cfg-summary";
import { analyzeXlatedReturns } from "./xlated-return-analysis";

// ─── Instruction templates ────────────────────────────────────────────────────

/** Build a linear sequence of XlatedInsn from a list of disasm strings */
function insns(lines: string[]): XlatedInsn[] {
  return lines.map((disasm, index) => ({ index, disasm }));
}

/** Build a minimal DOT graph from xlated instructions */
function buildDot(xlated: XlatedInsn[]): string {
  if (xlated.length === 0) return `digraph "BPF CFG" { empty [label="No instructions"]; }`;

  const jumpTargets = new Set<number>();
  const jumpSources = new Map<number, number[]>();

  for (const insn of xlated) {
    const m = insn.disasm.match(/goto pc([+-]\d+)/);
    if (m) {
      const offset = parseInt(m[1]);
      const target = insn.index + 1 + offset;
      jumpTargets.add(target);
      const targets = jumpSources.get(insn.index) ?? [];
      targets.push(target);
      targets.push(insn.index + 1);
      jumpSources.set(insn.index, targets);
    }
  }

  const blocks: Array<{ start: number; insns: XlatedInsn[] }> = [];
  let current: XlatedInsn[] = [];

  for (const insn of xlated) {
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

  const lines: string[] = [
    `digraph "BPF CFG" {`,
    `  node [shape=record fontname="monospace" fontsize=10];`,
  ];

  for (const block of blocks) {
    const label = block.insns
      .map(i => `${i.index}: ${i.disasm.replace(/"/g, '\\"').replace(/[<>|{}]/g, "\\$&")}`)
      .join("\\l");
    lines.push(`  bb_${block.start} [label="{${label}\\l}"];`);
  }

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
      const nextIdx = blocks.indexOf(block) + 1;
      if (nextIdx < blocks.length) {
        lines.push(`  bb_${block.start} -> bb_${blocks[nextIdx].start};`);
      }
    }
  }

  lines.push("}");
  return lines.join("\n");
}

// ─── Per-program mock dumps ───────────────────────────────────────────────────

const MOCK_XLATED: Record<number, XlatedInsn[]> = {
  // id=1: xdp_drop_icmp — drop ICMP packets, pass everything else
  1: insns([
    "(bf) r6 = r1",
    "(61) r1 = *(u32 *)(r6 +4)",
    "(61) r2 = *(u32 *)(r6 +0)",
    "(bf) r3 = r2",
    "(07) r3 += 14",
    "(2d) if r3 > r1 goto pc+12",
    "(71) r4 = *(u8 *)(r2 +12)",
    "(71) r5 = *(u8 *)(r2 +13)",
    "(67) r4 <<= 8",
    "(4f) r4 |= r5",
    "(55) if r4 != 0x800 goto pc+7",
    "(bf) r3 = r2",
    "(07) r3 += 34",
    "(2d) if r3 > r1 goto pc+4",
    "(71) r1 = *(u8 *)(r2 +23)",
    "(55) if r1 != 0x1 goto pc+1",
    "(b7) r0 = 1",
    "(05) goto pc+1",
    "(b7) r0 = 2",
    "(95) exit",
  ]),

  // id=2: xdp_lb_kern — load-balancer with LPM trie lookup
  2: insns([
    "(bf) r6 = r1",
    "(61) r7 = *(u32 *)(r6 +4)",
    "(61) r8 = *(u32 *)(r6 +0)",
    "(bf) r1 = r8",
    "(07) r1 += 14",
    "(2d) if r1 > r7 goto pc+30",
    "(71) r1 = *(u8 *)(r8 +12)",
    "(71) r2 = *(u8 *)(r8 +13)",
    "(67) r1 <<= 8",
    "(4f) r1 |= r2",
    "(55) if r1 != 0x800 goto pc+24",
    "(bf) r1 = r8",
    "(07) r1 += 34",
    "(2d) if r1 > r7 goto pc+21",
    "(61) r9 = *(u32 *)(r8 +26)",
    "(18) r1 = 0xffff000000000000",
    "(b7) r2 = 32",
    "(63) *(u32 *)(r10 -8) = r2",
    "(7b) *(u64 *)(r10 -16) = r9",
    "(bf) r2 = r10",
    "(07) r2 += -16",
    "(85) call map_lookup_elem",
    "(15) if r0 == 0x0 goto pc+11",
    "(61) r1 = *(u32 *)(r0 +0)",
    "(61) r2 = *(u32 *)(r0 +4)",
    "(61) r3 = *(u32 *)(r0 +8)",
    "(63) *(u32 *)(r8 +26) = r1",
    "(63) *(u32 *)(r8 +30) = r2",
    "(b7) r0 = 3",
    "(05) goto pc+3",
    "(b7) r0 = 2",
    "(05) goto pc+1",
    "(b7) r0 = 2",
    "(95) exit",
  ]),

  // id=3: cls_bpf_ingress — TC ingress classifier
  3: insns([
    "(bf) r6 = r1",
    "(61) r7 = *(u32 *)(r6 +80)",
    "(61) r8 = *(u32 *)(r6 +76)",
    "(bf) r1 = r8",
    "(07) r1 += 14",
    "(2d) if r1 > r7 goto pc+14",
    "(71) r1 = *(u8 *)(r8 +12)",
    "(71) r2 = *(u8 *)(r8 +13)",
    "(67) r1 <<= 8",
    "(4f) r1 |= r2",
    "(55) if r1 != 0x800 goto pc+8",
    "(71) r1 = *(u8 *)(r8 +23)",
    "(55) if r1 != 0x6 goto pc+5",
    "(69) r1 = *(u16 *)(r8 +34)",
    "(55) if r1 != 0x50 goto pc+2",
    "(b7) r0 = 0",
    "(05) goto pc+1",
    "(b7) r0 = -1",
    "(95) exit",
  ]),

  // id=6: kprobe__sys_execve — trace execve syscall
  6: insns([
    "(bf) r6 = r1",
    "(85) call get_current_pid_tgid",
    "(77) r0 >>= 32",
    "(bf) r7 = r0",
    "(18) r1 = 0xffff000000000000",
    "(bf) r2 = r7",
    "(85) call map_lookup_elem",
    "(15) if r0 == 0x0 goto pc+4",
    "(61) r1 = *(u32 *)(r0 +0)",
    "(55) if r1 != 0x0 goto pc+1",
    "(05) goto pc+1",
    "(05) goto pc+18",
    "(bf) r1 = r10",
    "(07) r1 += -128",
    "(b7) r2 = 128",
    "(85) call probe_read_str",
    "(85) call get_current_uid_gid",
    "(63) *(u32 *)(r10 -132) = r0",
    "(85) call ktime_get_ns",
    "(7b) *(u64 *)(r10 -144) = r0",
    "(bf) r1 = r10",
    "(07) r1 += -144",
    "(b7) r2 = 144",
    "(18) r3 = 0xffff000000000000",
    "(85) call perf_event_output",
    "(b7) r0 = 0",
    "(95) exit",
  ]),

  // id=8: fentry__tcp_connect — BTF-enabled TCP connect hook
  8: insns([
    "; int fentry__tcp_connect(struct sock *sk)",
    "(bf) r6 = r1",
    "(85) call get_current_pid_tgid",
    "(77) r0 >>= 32",
    "(bf) r7 = r0",
    "(79) r8 = *(u64 *)(r6 +32)",
    "(69) r9 = *(u16 *)(r6 +14)",
    "(bf) r1 = r10",
    "(07) r1 += -256",
    "(b7) r2 = 256",
    "(85) call probe_read_kernel",
    "(63) *(u32 *)(r10 -260) = r7",
    "(69) r1 = *(u16 *)(r6 +12)",
    "(6b) *(u16 *)(r10 -264) = r1",
    "(6b) *(u16 *)(r10 -266) = r9",
    "(bf) r1 = r10",
    "(07) r1 += -272",
    "(b7) r2 = 272",
    "(18) r3 = 0xffff000000000000",
    "(85) call ringbuf_output",
    "(b7) r0 = 0",
    "(95) exit",
  ]),

  // id=10: tracepoint__syscalls__sys_enter_openat
  10: insns([
    "(bf) r6 = r1",
    "(85) call get_current_pid_tgid",
    "(77) r0 >>= 32",
    "(bf) r7 = r0",
    "(18) r1 = 0xffff000000000000",
    "(bf) r2 = r7",
    "(85) call map_lookup_elem",
    "(15) if r0 == 0x0 goto pc+3",
    "(61) r1 = *(u32 *)(r0 +0)",
    "(55) if r1 != 0x0 goto pc+0",
    "(05) goto pc+20",
    "(79) r8 = *(u64 *)(r6 +24)",
    "(bf) r1 = r10",
    "(07) r1 += -256",
    "(b7) r2 = 256",
    "(bf) r3 = r8",
    "(85) call probe_read_user_str",
    "(85) call get_current_uid_gid",
    "(63) *(u32 *)(r10 -260) = r0",
    "(85) call ktime_get_ns",
    "(7b) *(u64 *)(r10 -272) = r0",
    "(63) *(u32 *)(r10 -276) = r7",
    "(bf) r1 = r10",
    "(07) r1 += -280",
    "(b7) r2 = 280",
    "(18) r3 = 0xffff000000000000",
    "(85) call perf_event_output",
    "(b7) r0 = 0",
    "(95) exit",
  ]),

  // id=14: cgroup_skb_ingress — cgroup SKB ingress filter
  14: insns([
    "(61) r1 = *(u32 *)(r1 +0)",
    "(55) if r1 != 0x2 goto pc+1",
    "(b7) r0 = 1",
    "(95) exit",
    "(b7) r0 = 0",
    "(95) exit",
  ]),

  // id=16: cgroup_device_policy — cgroup device access policy
  16: insns([
    "(61) r2 = *(u32 *)(r1 +0)",
    "(54) w2 &= 65535",
    "(61) r3 = *(u32 *)(r1 +0)",
    "(74) w3 >>= 16",
    "(61) r4 = *(u32 *)(r1 +4)",
    "(61) r5 = *(u32 *)(r1 +8)",
    "(55) if r2 != 0x2 goto pc+3",
    "(55) if r4 != 0x1 goto pc+2",
    "(55) if r5 != 0x3 goto pc+1",
    "(05) goto pc+10",
    "(55) if r2 != 0x2 goto pc+3",
    "(55) if r4 != 0x1 goto pc+2",
    "(55) if r5 != 0x5 goto pc+1",
    "(05) goto pc+6",
    "(55) if r2 != 0x1 goto pc+3",
    "(55) if r4 != 0x0 goto pc+2",
    "(55) if r5 != 0x0 goto pc+1",
    "(05) goto pc+2",
    "(b7) r0 = 0",
    "(05) goto pc+1",
    "(b7) r0 = 1",
    "(95) exit",
  ]),

  // id=24: lsm_file_open — LSM hook for file open
  24: insns([
    "; int lsm_file_open(struct file *file)",
    "(bf) r6 = r1",
    "(79) r7 = *(u64 *)(r6 +24)",
    "(85) call get_current_pid_tgid",
    "(77) r0 >>= 32",
    "(bf) r8 = r0",
    "(18) r1 = 0xffff000000000000",
    "(bf) r2 = r8",
    "(85) call map_lookup_elem",
    "(15) if r0 == 0x0 goto pc+8",
    "(79) r1 = *(u64 *)(r0 +0)",
    "(15) if r1 == 0x0 goto pc+6",
    "(bf) r1 = r10",
    "(07) r1 += -256",
    "(b7) r2 = 256",
    "(bf) r3 = r7",
    "(85) call probe_read_kernel",
    "(b7) r0 = -1",
    "(05) goto pc+1",
    "(b7) r0 = 0",
    "(95) exit",
  ]),
};

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Returns a mock ProgDump for demo mode programs.
 * If the program ID has a hand-crafted mock, it returns that.
 * Otherwise, it generates a generic dump based on the program type.
 */
export function buildMockProgDump(
  progId: number,
  progType: string,
  hasBtf: boolean,
  isJited: boolean
): ProgDump {
  const xlated = MOCK_XLATED[progId] ?? buildGenericDump(progId, progType);
  const cfgDot = buildDot(xlated);

  // For jited programs, generate mock JIT instructions
  const jited = isJited
    ? xlated.slice(0, Math.min(xlated.length, 20)).map((insn, i) => ({
        pc: `0xffffffffc0${(i * 4).toString(16).padStart(6, "0")}`,
        disasm: toX86Approx(insn.disasm),
      }))
    : null;

  const jitedUnavailableReason = isJited
    ? undefined
    : "This program was not JIT-compiled (jited=false). JIT compilation requires CONFIG_BPF_JIT and net.core.bpf_jit_enable=1.";

  return {
    progId,
    xlated,
    cfgDot,
    cfgSummary: buildCfgSummary(cfgDot, xlated),
    jited,
    jitedUnavailableReason,
    hasLineInfo: hasBtf,
    hasBtf,
    btfId: hasBtf ? progId + 40 : undefined,
    returnAnalysis: analyzeXlatedReturns(xlated),
  };
}

/** Generate a generic BPF dump for program types without a hand-crafted mock */
function buildGenericDump(progId: number, progType: string): XlatedInsn[] {
  // Generate a plausible set of instructions based on program type
  const base: string[] = [
    "(bf) r6 = r1",
    "(85) call get_current_pid_tgid",
    "(77) r0 >>= 32",
    "(bf) r7 = r0",
  ];

  // Add type-specific logic
  if (progType.includes("skb") || progType.includes("sock")) {
    base.push(
      "(61) r1 = *(u32 *)(r6 +0)",
      "(55) if r1 != 0x2 goto pc+3",
      "(61) r2 = *(u32 *)(r6 +4)",
      "(55) if r2 != 0x50 goto pc+1",
      "(b7) r0 = 0",
      "(05) goto pc+1",
      "(b7) r0 = 1"
    );
  } else if (progType.includes("kprobe") || progType.includes("tracepoint")) {
    base.push(
      "(bf) r1 = r10",
      "(07) r1 += -128",
      "(b7) r2 = 128",
      "(85) call probe_read_str",
      "(85) call ktime_get_ns",
      "(7b) *(u64 *)(r10 -136) = r0",
      "(b7) r0 = 0"
    );
  } else if (progType.includes("cgroup")) {
    base.push(
      "(61) r1 = *(u32 *)(r6 +0)",
      "(55) if r1 != 0x0 goto pc+1",
      "(b7) r0 = 1",
      "(05) goto pc+1",
      "(b7) r0 = 0"
    );
  } else {
    base.push(
      "(b7) r0 = 0",
    );
  }

  base.push("(95) exit");
  return insns(base);
}

/** Very rough BPF-to-x86 approximation for mock JIT output */
function toX86Approx(bpf: string): string {
  if (bpf.startsWith("(bf)")) return "mov    %rdi,%rsi";
  if (bpf.startsWith("(b7)")) return "xor    %eax,%eax";
  if (bpf.startsWith("(85)")) return "callq  0xffffffff81000000";
  if (bpf.startsWith("(95)")) return "retq";
  if (bpf.startsWith("(61)")) return "mov    0x0(%rdi),%esi";
  if (bpf.startsWith("(7b)")) return "mov    %rax,-0x8(%rbp)";
  if (bpf.startsWith("(79)")) return "mov    0x0(%rdi),%rax";
  if (bpf.startsWith("(55)")) return "cmp    $0x0,%rax";
  if (bpf.startsWith("(05)")) return "jmp    0x0";
  if (bpf.startsWith("(15)")) return "je     0x0";
  if (bpf.startsWith("(2d)")) return "ja     0x0";
  return "nop";
}

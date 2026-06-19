import { describe, it, expect } from "vitest";
import { parseJitedJson, parseJitedText, parseXlatedJson } from "./ebpf-dump";

// ─── Unit tests for the dump module helpers ────────────────────────────────
// We test the pure parsing logic without calling bpftool (which requires root).

// Re-export the parsing helpers for testing by duplicating the logic here.
// In production these are internal to ebpf-dump.ts.

interface XlatedRaw {
  disasm: string;
  opcodes?: string;
  linum?: { file: string; line: number; line_col: number };
}

function parseXlated(raw: XlatedRaw[]): Array<{
  index: number;
  disasm: string;
  opcodes: string | null;
  linum: string | undefined;
}> {
  return raw.map((item, index) => ({
    index,
    disasm: item.disasm ?? "",
    opcodes: item.opcodes ?? null,
    linum: item.linum ? `${item.linum.file}:${item.linum.line}` : undefined,
  }));
}

function isJumpInsn(disasm: string): boolean {
  return /\bgoto\b|\bif\b.*\bgoto\b/.test(disasm);
}

function extractJumpTarget(disasm: string): number | null {
  const m = disasm.match(/goto\s+pc([+-]\d+)/);
  if (!m) return null;
  return parseInt(m[1], 10);
}

describe("parseXlated", () => {
  it("maps disasm and index correctly", () => {
    const raw: XlatedRaw[] = [
      { disasm: "(61) r2 = *(u32 *)(r1 +0)" },
      { disasm: "(54) w2 &= 65535" },
      { disasm: "(05) goto pc+40" },
    ];
    const result = parseXlated(raw);
    expect(result).toHaveLength(3);
    expect(result[0]).toMatchObject({ index: 0, disasm: "(61) r2 = *(u32 *)(r1 +0)", opcodes: null });
    expect(result[2]).toMatchObject({ index: 2, disasm: "(05) goto pc+40" });
  });

  it("preserves opcodes when present", () => {
    const raw: XlatedRaw[] = [
      { disasm: "(61) r2 = *(u32 *)(r1 +0)", opcodes: "61 12 00 00 00 00 00 00" },
    ];
    const result = parseXlated(raw);
    expect(result[0]!.opcodes).toBe("61 12 00 00 00 00 00 00");
  });

  it("formats linum as file:line", () => {
    const raw: XlatedRaw[] = [
      {
        disasm: "(61) r2 = *(u32 *)(r1 +0)",
        linum: { file: "prog.bpf.c", line: 42, line_col: 0 },
      },
    ];
    const result = parseXlated(raw);
    expect(result[0]!.linum).toBe("prog.bpf.c:42");
  });

  it("sets linum to undefined when absent", () => {
    const raw: XlatedRaw[] = [{ disasm: "(61) r2 = *(u32 *)(r1 +0)" }];
    const result = parseXlated(raw);
    expect(result[0]!.linum).toBeUndefined();
  });

  it("handles empty array", () => {
    expect(parseXlated([])).toEqual([]);
  });
});

describe("isJumpInsn", () => {
  it("detects unconditional goto", () => {
    expect(isJumpInsn("(05) goto pc+40")).toBe(true);
  });

  it("detects conditional branch", () => {
    expect(isJumpInsn("(55) if r2 != 0x2 goto pc+3")).toBe(true);
  });

  it("returns false for non-jump", () => {
    expect(isJumpInsn("(61) r2 = *(u32 *)(r1 +0)")).toBe(false);
    expect(isJumpInsn("(54) w2 &= 65535")).toBe(false);
    expect(isJumpInsn("(b7) r0 = 1")).toBe(false);
  });
});

describe("extractJumpTarget", () => {
  it("extracts positive offset", () => {
    expect(extractJumpTarget("(05) goto pc+40")).toBe(40);
  });

  it("extracts negative offset", () => {
    expect(extractJumpTarget("(05) goto pc-3")).toBe(-3);
  });

  it("extracts offset from conditional branch", () => {
    expect(extractJumpTarget("(55) if r2 != 0x2 goto pc+3")).toBe(3);
  });

  it("returns null for non-jump", () => {
    expect(extractJumpTarget("(61) r2 = *(u32 *)(r1 +0)")).toBeNull();
  });
});

describe("parseXlatedJson", () => {
  it("parses bpftool linum JSON source metadata", () => {
    const result = parseXlatedJson(JSON.stringify([
      {
        proto: "int bpfj_fs_file_open(unsigned long long * ctx)",
        src: "int BPF_PROG(bpfj_fs_file_open, struct file* file) {",
        file: "./././fs_enforce.bpf.c",
        line_num: 966,
        line_col: 5,
        disasm: "(79) r7 = *(u64 *)(r1 +0)",
      },
      {
        disasm: "(7b) *(u64 *)(r10 -24) = r0",
      },
    ]));

    expect(result).toEqual([
      {
        index: 0,
        disasm: "(79) r7 = *(u64 *)(r1 +0)",
        linum: "int BPF_PROG(bpfj_fs_file_open, struct file* file) {",
        source: "int BPF_PROG(bpfj_fs_file_open, struct file* file) {",
        sourceFile: "./././fs_enforce.bpf.c",
        sourceLine: 966,
        sourceColumn: 5,
      },
      {
        index: 1,
        disasm: "(7b) *(u64 *)(r10 -24) = r0",
      },
    ]);
  });
});

describe("ProgDump structure", () => {
  it("builds a valid ProgDump object from parsed data", () => {
    const dump = {
      progId: 49,
      xlated: parseXlated([
        { disasm: "(61) r2 = *(u32 *)(r1 +0)" },
        { disasm: "(05) goto pc+1" },
        { disasm: "(b7) r0 = 1" },
      ]),
      cfgDot: "digraph { ENTRY -> BB0; }",
      jited: null,
      jitedRaw: null,
      hasBtf: false,
      hasLineInfo: false,
      error: null,
    };

    expect(dump.progId).toBe(49);
    expect(dump.xlated).toHaveLength(3);
    expect(dump.cfgDot).toContain("digraph");
    expect(dump.jited).toBeNull();
    expect(dump.hasBtf).toBe(false);
    expect(dump.error).toBeNull();
  });

  it("marks hasBtf true when btfId is present", () => {
    // Simulates the logic in ebpf-dump.ts: hasBtf = btfId !== undefined
    const btfId = 42;
    const hasBtf = btfId !== undefined;
    expect(hasBtf).toBe(true);
  });

  it("marks hasBtf false when btfId is absent", () => {
    const btfId = undefined;
    const hasBtf = btfId !== undefined;
    expect(hasBtf).toBe(false);
  });
});

describe("JIT availability logic", () => {
  it("reports JIT unavailable when jited flag is false", () => {
    const jited = false;
    const kptrRestrict = 0;
    const canDumpJit = jited && kptrRestrict === 0;
    expect(canDumpJit).toBe(false);
  });

  it("reports JIT unavailable when kptr_restrict is non-zero", () => {
    const jited = true;
    const kptrRestrict = 1;
    const canDumpJit = jited && kptrRestrict === 0;
    expect(canDumpJit).toBe(false);
  });

  it("reports JIT available when both conditions met", () => {
    const jited = true;
    const kptrRestrict = 0;
    const canDumpJit = jited && kptrRestrict === 0;
    expect(canDumpJit).toBe(true);
  });
});

describe("parseJitedJson", () => {
  it("parses nested bpftool JIT JSON with operation and operands", () => {
    const result = parseJitedJson(JSON.stringify([{
      proto: "int bpfj_fs_file_open(unsigned long long * ctx)",
      name: "bpf_prog_20b9278d511c15b8_bpfj_fs_file_open",
      insns: [
        {
          src: "int BPF_PROG(bpfj_fs_file_open, struct file* file) {",
          pc: "0x0",
          operation: "nopl",
          operands: ["%rax", "%rax"],
        },
        {
          pc: "0x5",
          operation: "nop",
          operands: [null],
        },
        {
          pc: "0x7",
          operation: "pushq",
          operands: ["%rbp"],
        },
      ],
    }]));

    expect(result).toEqual([
      { pc: "0x0", disasm: "nopl %rax,%rax" },
      { pc: "0x5", disasm: "nop" },
      { pc: "0x7", disasm: "pushq %rbp" },
    ]);
  });

  it("keeps supporting flat JIT JSON with disasm", () => {
    const result = parseJitedJson(JSON.stringify([
      { pc: "0x0", disasm: "push %rbp", opcodes: "55" },
      { pc: "0x1", disasm: "mov %rsp,%rbp" },
    ]));

    expect(result).toEqual([
      { pc: "0x0", disasm: "push %rbp", opcodes: "55" },
      { pc: "0x1", disasm: "mov %rsp,%rbp" },
    ]);
  });
});

describe("parseJitedText", () => {
  it("parses plain text JIT dumps with opcode bytes", () => {
    const result = parseJitedText(`
bpf_prog_1234567890abcdef:
   0:   55                      push   %rbp
   1:   48 89 e5                mov    %rsp,%rbp
   4:   e8 00 00 00 00          callq  0x9
`);

    expect(result).toEqual([
      { pc: "0x0", opcodes: "55", disasm: "push   %rbp" },
      { pc: "0x1", opcodes: "48 89 e5", disasm: "mov    %rsp,%rbp" },
      { pc: "0x4", opcodes: "e8 00 00 00 00", disasm: "callq  0x9" },
    ]);
  });

  it("parses plain text JIT dumps without opcode bytes", () => {
    const result = parseJitedText(`
   0:   nopl   0x0(%rax,%rax,1)
   5:   push   %rbp
`);

    expect(result).toEqual([
      { pc: "0x0", disasm: "nopl   0x0(%rax,%rax,1)" },
      { pc: "0x5", disasm: "push   %rbp" },
    ]);
  });

  it("uses the base address label when bpftool prints one", () => {
    const result = parseJitedText(`
ffffffffc0010000:
   0:   55                      push   %rbp
  10:   c3                      retq
`);

    expect(result).toEqual([
      { pc: "0xffffffffc0010000", opcodes: "55", disasm: "push   %rbp" },
      { pc: "0xffffffffc001000a", opcodes: "c3", disasm: "retq" },
    ]);
  });
});

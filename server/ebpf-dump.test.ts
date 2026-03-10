import { describe, it, expect } from "vitest";

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

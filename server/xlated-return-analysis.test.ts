import { describe, expect, it } from "vitest";
import type { XlatedInsn } from "../shared/ebpf-types";
import { analyzeXlatedReturns } from "./xlated-return-analysis";

function insn(
  index: number,
  disasm: string,
  extras: Partial<XlatedInsn> = {}
): XlatedInsn {
  return { index, disasm, ...extras };
}

describe("analyzeXlatedReturns", () => {
  it("detects direct r0 constant returns", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(61) r1 = *(u32 *)(r6 +0)"),
      insn(1, "(b7) r0 = 2", {
        source: "return TC_ACT_SHOT;",
        sourceFile: "prog.bpf.c",
        sourceLine: 42,
      }),
      insn(2, "(95) exit"),
    ]);

    expect(result).toMatchObject({
      exitCount: 1,
      hasUnknownExits: false,
      hasTailCalls: false,
      observedConstants: [{ value: 2, exitCount: 1 }],
    });
    expect(result.constantExits).toEqual([
      {
        exitIndex: 2,
        exitDisasm: "(95) exit",
        assignmentIndex: 1,
        assignmentDisasm: "(b7) r0 = 2",
        value: 2,
        source: "return TC_ACT_SHOT;",
        sourceFile: "prog.bpf.c",
        sourceLine: 42,
      },
    ]);
  });

  it("detects direct w0 constant returns and aggregates constants", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(15) if r1 == 0x0 goto pc+2"),
      insn(1, "(b4) w0 = 0"),
      insn(2, "(95) exit"),
      insn(3, "(15) if r2 == 0x0 goto pc+2"),
      insn(4, "(b4) w0 = 0"),
      insn(5, "(95) exit"),
      insn(6, "(b7) r0 = -1"),
      insn(7, "(95) exit"),
    ]);

    expect(result.exitCount).toBe(3);
    expect(result.observedConstants).toEqual([
      { value: -1, exitCount: 1 },
      { value: 0, exitCount: 2 },
    ]);
  });

  it("attaches branch evidence on unique paths to exits", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(15) if r1 == 0x0 goto pc+2", {
        source: "if (!ok) return TC_ACT_SHOT;",
        sourceFile: "prog.bpf.c",
        sourceLine: 10,
      }),
      insn(1, "(b7) r0 = 0"),
      insn(2, "(95) exit"),
      insn(3, "(b7) r0 = 2"),
      insn(4, "(95) exit"),
    ]);

    expect(result.constantExits).toHaveLength(2);
    expect(result.constantExits.find(exit => exit.value === 0)).toMatchObject({
      exitIndex: 2,
      value: 0,
      branchEvidence: [
        {
          insnIndex: 0,
          disasm: "(15) if r1 == 0x0 goto pc+2",
          targetIndex: 3,
          branch: "fallthrough",
          source: "if (!ok) return TC_ACT_SHOT;",
          sourceFile: "prog.bpf.c",
          sourceLine: 10,
        },
      ],
    });
    expect(result.constantExits.find(exit => exit.value === 2)).toMatchObject({
      exitIndex: 4,
      value: 2,
      branchEvidence: [
        {
          insnIndex: 0,
          disasm: "(15) if r1 == 0x0 goto pc+2",
          targetIndex: 3,
          branch: "taken",
          source: "if (!ok) return TC_ACT_SHOT;",
          sourceFile: "prog.bpf.c",
          sourceLine: 10,
        },
      ],
    });
  });

  it("parses hexadecimal return constants", () => {
    const result = analyzeXlatedReturns([
      insn(10, "(b7) r0 = 0x7"),
      insn(11, "(95) exit"),
    ]);

    expect(result.constantExits[0].value).toBe(7);
  });

  it("normalizes unsigned 32-bit return constants", () => {
    const result = analyzeXlatedReturns([
      insn(10, "(b7) r0 = 0xffffffff"),
      insn(11, "(95) exit"),
    ]);

    expect(result.constantExits[0].value).toBe(-1);
    expect(result.observedConstants).toEqual([{ value: -1, exitCount: 1 }]);
  });

  it("resolves return values through register copies", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(b7) r6 = 2"),
      insn(1, "(61) r1 = *(u32 *)(r1 +0)"),
      insn(2, "(bf) r0 = r6"),
      insn(3, "(95) exit"),
    ]);

    expect(result).toMatchObject({
      exitCount: 1,
      hasUnknownExits: false,
      observedConstants: [{ value: 2, exitCount: 1 }],
    });
    expect(result.constantExits[0]).toMatchObject({
      exitIndex: 3,
      assignmentIndex: 2,
      assignmentDisasm: "(bf) r0 = r6",
      value: 2,
    });
  });

  it("resolves return values through shared exit blocks", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(b7) r0 = 0"),
      insn(1, "(05) goto pc+1"),
      insn(2, "(b7) r1 = 42"),
      insn(3, "(95) exit"),
    ]);

    expect(result).toMatchObject({
      exitCount: 1,
      hasUnknownExits: false,
      observedConstants: [{ value: 0, exitCount: 1 }],
    });
  });

  it("ignores exits that are not reachable from the program entry", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(b7) r0 = 0"),
      insn(1, "(95) exit"),
      insn(2, "(b7) r0 = 2"),
      insn(3, "(95) exit"),
    ]);

    expect(result).toMatchObject({
      exitCount: 1,
      hasUnknownExits: false,
      observedConstants: [{ value: 0, exitCount: 1 }],
    });
  });

  it("marks dynamic r0 assignments as unknown exits", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(bf) r0 = r6"),
      insn(1, "(95) exit"),
    ]);

    expect(result).toMatchObject({
      exitCount: 1,
      hasUnknownExits: true,
      constantExits: [],
      unknownExits: [
        {
          exitIndex: 1,
          exitDisasm: "(95) exit",
          assignmentIndex: 0,
          assignmentDisasm: "(bf) r0 = r6",
          reason: "dynamic-assignment",
        },
      ],
    });
  });

  it("marks helper return values as dynamic unknown exits", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(85) call bpf_map_lookup_elem#1"),
      insn(1, "(95) exit"),
    ]);

    expect(result.unknownExits).toEqual([
      {
        exitIndex: 1,
        exitDisasm: "(95) exit",
        assignmentIndex: 0,
        assignmentDisasm: "(85) call bpf_map_lookup_elem#1",
        reason: "dynamic-assignment",
      },
    ]);
  });

  it("marks exits without any r0/w0 assignment as unknown", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(b7) r1 = 0"),
      insn(1, "(95) exit"),
    ]);

    expect(result.unknownExits).toEqual([
      {
        exitIndex: 1,
        exitDisasm: "(95) exit",
        reason: "no-direct-assignment",
      },
    ]);
  });

  it("marks conflicting branch return values as unknown", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(15) if r1 == 0x0 goto pc+2"),
      insn(1, "(b7) r0 = 0"),
      insn(2, "(05) goto pc+1"),
      insn(3, "(b7) r0 = 2"),
      insn(4, "(95) exit"),
    ]);

    expect(result).toMatchObject({
      exitCount: 1,
      hasUnknownExits: true,
      constantExits: [],
      unknownExits: [
        {
          exitIndex: 4,
          exitDisasm: "(95) exit",
          reason: "conflicting-values",
        },
      ],
    });
  });

  it("does not attach branch evidence when control flow merges", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(15) if r1 == 0x0 goto pc+2"),
      insn(1, "(b7) r0 = 0"),
      insn(2, "(05) goto pc+1"),
      insn(3, "(b7) r0 = 2"),
      insn(4, "(95) exit"),
    ]);

    expect(result.unknownExits[0].branchEvidence).toBeUndefined();
  });

  it("handles programs with no exits", () => {
    expect(analyzeXlatedReturns([insn(0, "(b7) r0 = 0")])).toEqual({
      exitCount: 0,
      constantExits: [],
      unknownExits: [],
      observedConstants: [],
      tailCallIndices: [],
      hasUnknownExits: false,
      hasTailCalls: false,
      sideEffects: {
        hasSideEffects: false,
        labels: [],
        effects: [],
        hasMapWrites: false,
        hasDirectMemoryWrites: false,
        hasPacketMutations: false,
        hasRedirects: false,
        hasTelemetryOutput: false,
        hasTailCalls: false,
        hasSocketMutations: false,
      },
    });
  });

  it("flags tail calls because final verdict may be in another program", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(85) call bpf_tail_call#12"),
      insn(1, "(b7) r0 = 0"),
      insn(2, "(95) exit"),
    ]);

    expect(result.tailCallIndices).toEqual([0]);
    expect(result.hasTailCalls).toBe(true);
  });
});

import { describe, expect, it } from "vitest";
import type { XlatedInsn } from "../shared/ebpf-types";
import { analyzeXlatedReturns } from "./xlated-return-analysis";

function insn(index: number, disasm: string, extras: Partial<XlatedInsn> = {}): XlatedInsn {
  return { index, disasm, ...extras };
}

describe("analyzeXlatedReturns", () => {
  it("detects direct r0 constant returns", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(61) r1 = *(u32 *)(r6 +0)"),
      insn(1, "(b7) r0 = 2", { source: "return TC_ACT_SHOT;", sourceFile: "prog.bpf.c", sourceLine: 42 }),
      insn(2, "(95) exit"),
    ]);

    expect(result).toMatchObject({
      exitCount: 1,
      hasUnknownExits: false,
      observedConstants: [{ value: 2, exitCount: 1 }],
    });
    expect(result.constantExits).toEqual([{
      exitIndex: 2,
      exitDisasm: "(95) exit",
      assignmentIndex: 1,
      assignmentDisasm: "(b7) r0 = 2",
      value: 2,
      source: "return TC_ACT_SHOT;",
      sourceFile: "prog.bpf.c",
      sourceLine: 42,
    }]);
  });

  it("detects direct w0 constant returns and aggregates constants", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(b4) w0 = 0"),
      insn(1, "(95) exit"),
      insn(2, "(b4) w0 = 0"),
      insn(3, "(95) exit"),
      insn(4, "(b7) r0 = -1"),
      insn(5, "(95) exit"),
    ]);

    expect(result.exitCount).toBe(3);
    expect(result.observedConstants).toEqual([
      { value: -1, exitCount: 1 },
      { value: 0, exitCount: 2 },
    ]);
  });

  it("parses hexadecimal return constants", () => {
    const result = analyzeXlatedReturns([
      insn(10, "(b7) r0 = 0x7"),
      insn(11, "(95) exit"),
    ]);

    expect(result.constantExits[0].value).toBe(7);
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
      unknownExits: [{
        exitIndex: 1,
        exitDisasm: "(95) exit",
        assignmentIndex: 0,
        assignmentDisasm: "(bf) r0 = r6",
        reason: "dynamic-assignment",
      }],
    });
  });

  it("marks exits without direct r0/w0 assignment as unknown", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(85) call bpf_map_lookup_elem#1"),
      insn(1, "(95) exit"),
    ]);

    expect(result.unknownExits).toEqual([{
      exitIndex: 1,
      exitDisasm: "(95) exit",
      assignmentIndex: 0,
      assignmentDisasm: "(85) call bpf_map_lookup_elem#1",
      reason: "no-direct-assignment",
    }]);
  });

  it("handles programs with no exits", () => {
    expect(analyzeXlatedReturns([insn(0, "(b7) r0 = 0")])).toEqual({
      exitCount: 0,
      constantExits: [],
      unknownExits: [],
      observedConstants: [],
      hasUnknownExits: false,
    });
  });
});

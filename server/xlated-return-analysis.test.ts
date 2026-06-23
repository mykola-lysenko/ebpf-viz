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

  it("recognizes self-xor register zeroing as constant zero", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(ac) w0 ^= w0"),
      insn(1, "(95) exit"),
    ]);

    expect(result).toMatchObject({
      exitCount: 1,
      hasUnknownExits: false,
      observedConstants: [{ value: 0, exitCount: 1 }],
    });
    expect(result.constantExits[0]).toMatchObject({
      exitIndex: 1,
      assignmentIndex: 0,
      assignmentDisasm: "(ac) w0 ^= w0",
      value: 0,
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

  it("resolves return values through local BPF subprogram calls", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(85) call pc+2#bpf_prog_deadbeef_subprog"),
      insn(1, "(95) exit"),
      insn(2, "(b7) r1 = 0"),
      insn(3, "(15) if r1 == 0x0 goto pc+2"),
      insn(4, "(b7) r0 = -1"),
      insn(5, "(95) exit"),
      insn(6, "(b7) r0 = 2"),
      insn(7, "(95) exit"),
    ]);

    expect(result).toMatchObject({
      exitCount: 2,
      hasUnknownExits: false,
      observedConstants: [
        { value: -1, exitCount: 1 },
        { value: 2, exitCount: 1 },
      ],
    });
    expect(result.constantExits.map(exit => [exit.exitIndex, exit.value])).toEqual([
      [1, -1],
      [1, 2],
    ]);
    expect(
      result.constantExits.every(
        exit =>
          exit.assignmentIndex === 0 &&
          exit.assignmentDisasm === "(85) call pc+2#bpf_prog_deadbeef_subprog"
      )
    ).toBe(true);
  });

  it("resolves nested local BPF subprogram calls", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(85) call pc+3#bpf_prog_outer"),
      insn(1, "(95) exit"),
      insn(2, "(b7) r1 = 0"),
      insn(3, "(b7) r1 = 0"),
      insn(4, "(85) call pc+3#bpf_prog_inner"),
      insn(5, "(95) exit"),
      insn(6, "(b7) r1 = 0"),
      insn(7, "(b7) r1 = 0"),
      insn(8, "(b7) r0 = 7"),
      insn(9, "(95) exit"),
    ]);

    expect(result).toMatchObject({
      exitCount: 1,
      hasUnknownExits: false,
      observedConstants: [{ value: 7, exitCount: 1 }],
    });
    expect(result.constantExits[0]).toMatchObject({
      exitIndex: 1,
      assignmentIndex: 0,
      assignmentDisasm: "(85) call pc+3#bpf_prog_outer",
      value: 7,
    });
  });

  it("preserves unknown helper evidence from local BPF subprogram calls", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(85) call pc+4#bpf_prog_redirector"),
      insn(1, "(bc) w1 = w0"),
      insn(2, "(bc) w0 = w1"),
      insn(3, "(95) exit"),
      insn(4, "(b7) r1 = 0"),
      insn(5, "(b7) r1 = 1"),
      insn(6, "(b7) r2 = 0"),
      insn(7, "(85) call bpf_redirect#23", {
        source: "return bpf_redirect(skb->ifindex, BPF_F_INGRESS);",
        sourceFile: "prog.bpf.c",
        sourceLine: 18,
      }),
      insn(8, "(95) exit"),
    ]);

    expect(result).toMatchObject({
      exitCount: 1,
      hasUnknownExits: true,
      constantExits: [],
      observedConstants: [],
    });
    expect(result.unknownExits[0]).toMatchObject({
      exitIndex: 3,
      assignmentIndex: 7,
      assignmentDisasm: "(85) call bpf_redirect#23",
      reason: "dynamic-assignment",
      source: "return bpf_redirect(skb->ifindex, BPF_F_INGRESS);",
      sourceFile: "prog.bpf.c",
      sourceLine: 18,
    });
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

  it("preserves conflicting branch constants at shared exit blocks", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(15) if r1 == 0x0 goto pc+2"),
      insn(1, "(b7) r0 = 0"),
      insn(2, "(05) goto pc+1"),
      insn(3, "(b7) r0 = 2"),
      insn(4, "(95) exit"),
    ]);

    expect(result).toMatchObject({
      exitCount: 2,
      hasUnknownExits: false,
      unknownExits: [],
      observedConstants: [
        { value: 0, exitCount: 1 },
        { value: 2, exitCount: 1 },
      ],
    });
    expect(result.constantExits.map(exit => [exit.exitIndex, exit.value])).toEqual([
      [4, 0],
      [4, 2],
    ]);
  });

  it("does not attach branch evidence when control flow merges", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(15) if r1 == 0x0 goto pc+2"),
      insn(1, "(b7) r0 = 0"),
      insn(2, "(05) goto pc+1"),
      insn(3, "(b7) r0 = 2"),
      insn(4, "(95) exit"),
    ]);

    expect(result.constantExits.every(exit => !exit.branchEvidence)).toBe(true);
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

  it("extracts prog-array map and slot for tail calls", () => {
    const result = analyzeXlatedReturns([
      insn(0, "(bf) r1 = r6"),
      insn(1, "(18) r2 = map[id:123]"),
      insn(3, "(b7) r3 = 7"),
      insn(4, "(85) call bpf_tail_call#12", {
        source: "bpf_tail_call(ctx, &jmp_table, 7);",
        sourceFile: "prog.bpf.c",
        sourceLine: 50,
      }),
      insn(5, "(b7) r0 = 0"),
      insn(6, "(95) exit"),
    ]);

    expect(result.tailCalls).toEqual([
      {
        insnIndex: 4,
        disasm: "(85) call bpf_tail_call#12",
        mapId: 123,
        mapAssignmentIndex: 1,
        mapAssignmentDisasm: "(18) r2 = map[id:123]",
        slot: 7,
        slotAssignmentIndex: 3,
        slotAssignmentDisasm: "(b7) r3 = 7",
        source: "bpf_tail_call(ctx, &jmp_table, 7);",
        sourceFile: "prog.bpf.c",
        sourceLine: 50,
      },
    ]);
  });
});

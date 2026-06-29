import { describe, expect, it } from "vitest";
import type { XlatedInsn } from "../../../shared/ebpf-types";
import {
  analyzeCfgRender,
  buildCfgBasicBlocks,
  CFG_AUTO_RENDER_LIMITS,
  searchCfgBlocks,
} from "./cfg-summary";

function insns(lines: string[]): XlatedInsn[] {
  return lines.map((disasm, index) => ({ index, disasm }));
}

describe("cfg-summary helpers", () => {
  it("splits basic blocks at branch targets and branch exits", () => {
    const blocks = buildCfgBasicBlocks(
      insns([
        "(b7) r0 = 0",
        "(15) if r1 == 0x0 goto pc+2",
        "(85) call bpf_map_lookup_elem#1",
        "(05) goto pc+1",
        "(b7) r0 = 2",
        "(95) exit",
      ])
    );

    expect(blocks.map(block => [block.start, block.end])).toEqual([
      [0, 1],
      [2, 3],
      [4, 4],
      [5, 5],
    ]);
    expect(blocks[0].branchTargets).toEqual([4]);
    expect(blocks[0].fallthroughTarget).toBe(2);
    expect(blocks[1].calls).toEqual(["bpf_map_lookup_elem#1"]);
    expect(blocks[2].fallthroughTarget).toBe(5);
  });

  it("allows small CFGs to render automatically", () => {
    const dot = `digraph "BPF CFG" {\n  bb_0 [label="0"];\n  bb_0 -> bb_1;\n}`;
    const analysis = analyzeCfgRender(dot, insns(["(b7) r0 = 0", "(95) exit"]));

    expect(analysis.shouldAutoRender).toBe(true);
    expect(analysis.reasons).toEqual([]);
    expect(analysis.blockCount).toBe(1);
  });

  it("blocks automatic rendering for very large instruction dumps", () => {
    const largeInsnSet = insns(
      Array.from(
        { length: CFG_AUTO_RENDER_LIMITS.maxInstructions + 1 },
        () => "(b7) r0 = 0"
      )
    );
    const analysis = analyzeCfgRender("digraph {}", largeInsnSet);

    expect(analysis.shouldAutoRender).toBe(false);
    expect(analysis.reasons[0]).toContain("instructions exceeds");
  });

  it("blocks automatic rendering for very large DOT payloads", () => {
    const dot = `digraph {\n${"a".repeat(CFG_AUTO_RENDER_LIMITS.maxDotChars + 1)}\n}`;
    const analysis = analyzeCfgRender(dot, insns(["(95) exit"]));

    expect(analysis.shouldAutoRender).toBe(false);
    expect(analysis.reasons.some(reason => reason.includes("DOT characters"))).toBe(true);
  });

  it("searches blocks by instruction, target, helper, terminal instruction, and source", () => {
    const blocks = buildCfgBasicBlocks([
      { index: 0, disasm: "(b7) r0 = 0", source: "int allowed = 0;" },
      { index: 1, disasm: "(15) if r1 == 0x0 goto pc+2" },
      { index: 2, disasm: "(85) call bpf_map_lookup_elem#1" },
      { index: 3, disasm: "(05) goto pc+1" },
      { index: 4, disasm: "(b7) r0 = 2", source: "return TC_ACT_SHOT;" },
      { index: 5, disasm: "(95) exit" },
    ]);

    expect(searchCfgBlocks(blocks, "insn:2").map(result => result.block.start)).toEqual([
      2,
    ]);
    expect(searchCfgBlocks(blocks, "2").map(result => result.block.start)).toEqual([
      0,
      2,
      4,
    ]);
    expect(searchCfgBlocks(blocks, "4").map(result => result.block.start)).toEqual([
      0,
      4,
    ]);
    expect(searchCfgBlocks(blocks, "map_lookup").map(result => result.block.start)).toEqual([
      2,
    ]);
    expect(searchCfgBlocks(blocks, "exit").map(result => result.block.start)).toEqual([
      5,
    ]);
    expect(searchCfgBlocks(blocks, "TC_ACT_SHOT").map(result => result.block.start)).toEqual([
      4,
    ]);
  });
});

import { describe, expect, it } from "vitest";
import type { ProgramChain, XlatedReturnAnalysis } from "../shared/ebpf-types";
import { predictPacketChain } from "../shared/packet-chain-prediction";

function tcChain(): ProgramChain {
  return {
    hookId: "tc:eth0:clsact/egress",
    hookLabel: "eth0 egress",
    hookType: "tc",
    attachPoint: "eth0",
    attachType: "clsact/egress",
    canShortCircuit: true,
    packetContext: {
      family: "tc",
      direction: "egress",
      summary: "TC return values decide packet flow.",
      semantics: {
        pass: ["TC_ACT_OK (0)", "TC_ACT_UNSPEC (-1)"],
        passValues: [0, -1],
        drop: ["TC_ACT_SHOT (2)"],
        dropValues: [2],
        redirect: ["TC_ACT_REDIRECT (7)"],
        redirectValues: [7],
        other: ["TC_ACT_PIPE (3)"],
        otherValues: [3],
      },
    },
    programs: [
      { id: 1, position: 1, name: "first" },
      { id: 2, position: 2, name: "middle" },
      { id: 3, position: 3, name: "last" },
    ],
  };
}

function returnAnalysis(
  constants: number[],
  options: { unknown?: boolean; tailCall?: boolean } = {}
): XlatedReturnAnalysis {
  const counts = new Map<number, number>();
  for (const value of constants) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }

  return {
    exitCount: constants.length + (options.unknown ? 1 : 0),
    constantExits: constants.map((value, index) => ({
      exitIndex: index,
      exitDisasm: "(95) exit",
      value,
    })),
    unknownExits: options.unknown
      ? [
          {
            exitIndex: constants.length,
            exitDisasm: "(95) exit",
            reason: "dynamic-assignment",
          },
        ]
      : [],
    observedConstants: Array.from(counts.entries()).map(
      ([value, exitCount]) => ({ value, exitCount })
    ),
    tailCallIndices: options.tailCall ? [42] : [],
    hasUnknownExits: !!options.unknown,
    hasTailCalls: !!options.tailCall,
  };
}

describe("predictPacketChain", () => {
  it("marks a chain as always passing when every analyzed exit passes", () => {
    const analyses = new Map([
      [1, returnAnalysis([0])],
      [2, returnAnalysis([-1])],
      [3, returnAnalysis([0])],
    ]);

    const prediction = predictPacketChain(tcChain(), id => analyses.get(id));

    expect(prediction).toMatchObject({
      possibleOutcomes: ["pass"],
      alwaysPass: true,
      hasUnknownBehavior: false,
      confidence: "high",
    });
    expect(prediction?.steps.map(step => step.label)).toEqual([
      "all exits pass",
      "all exits pass",
      "all exits pass",
    ]);
  });

  it("marks downstream programs conditional when a program can drop and pass", () => {
    const analyses = new Map([
      [1, returnAnalysis([0])],
      [2, returnAnalysis([0, 2])],
      [3, returnAnalysis([0])],
    ]);

    const prediction = predictPacketChain(tcChain(), id => analyses.get(id));

    expect(prediction?.possibleOutcomes).toEqual(["drop", "pass"]);
    expect(prediction?.alwaysPass).toBe(false);
    expect(
      prediction?.firstTerminalPrograms.map(program => program.progId)
    ).toEqual([2]);
    expect(
      prediction?.steps.map(step => [
        step.progId,
        step.label,
        step.reachability,
      ])
    ).toEqual([
      [1, "all exits pass", "always"],
      [2, "can drop", "always"],
      [3, "all exits pass", "conditional"],
    ]);
  });

  it("marks later programs not reached when an earlier program always drops", () => {
    const analyses = new Map([
      [1, returnAnalysis([0])],
      [2, returnAnalysis([2])],
      [3, returnAnalysis([0])],
    ]);

    const prediction = predictPacketChain(tcChain(), id => analyses.get(id));

    expect(prediction?.possibleOutcomes).toEqual(["drop"]);
    expect(
      prediction?.steps.map(step => [step.progId, step.reachability])
    ).toEqual([
      [1, "always"],
      [2, "always"],
      [3, "not-reached"],
    ]);
  });

  it("keeps confidence partial when an otherwise pass chain has unknown exits", () => {
    const analyses = new Map([
      [1, returnAnalysis([0])],
      [2, returnAnalysis([0], { unknown: true })],
      [3, returnAnalysis([0])],
    ]);

    const prediction = predictPacketChain(tcChain(), id => analyses.get(id));

    expect(prediction?.possibleOutcomes).toEqual(["unknown", "pass"]);
    expect(prediction?.confidence).toBe("partial");
    expect(prediction?.hasUnknownBehavior).toBe(true);
    expect(prediction?.steps[1]).toMatchObject({
      label: "unknown verdict",
      reachability: "always",
      canTerminateChain: true,
      definitelyTerminatesChain: false,
    });
    expect(prediction?.steps[2].reachability).toBe("conditional");
  });
});

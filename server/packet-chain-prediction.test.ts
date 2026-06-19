import { describe, expect, it } from "vitest";
import type {
  BpfMap,
  ProgramChain,
  XlatedReturnAnalysis,
  XlatedSideEffectSummary,
} from "../shared/ebpf-types";
import { predictPacketChain } from "../shared/packet-chain-prediction";

const EMPTY_SIDE_EFFECTS: XlatedSideEffectSummary = {
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
};

function progArrayMap(id: number, name: string): BpfMap {
  return {
    id,
    type: "prog_array",
    rawType: "prog_array",
    name,
    flags: 0,
    bytesKey: 4,
    bytesValue: 4,
    maxEntries: 16,
    bytesMemlock: 4096,
    frozen: false,
    pinnedPaths: [],
    usedByProgIds: [1],
    color: "#f59e0b",
    category: "control",
  };
}

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
  options: {
    unknown?: boolean;
    tailCall?: boolean;
    sideEffects?: XlatedSideEffectSummary;
  } = {}
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
    sideEffects: options.sideEffects ?? EMPTY_SIDE_EFFECTS,
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

  it("explains packet verdicts with source and branch evidence", () => {
    const firstProgram = returnAnalysis([0, 2]);
    firstProgram.constantExits[1] = {
      ...firstProgram.constantExits[1],
      exitIndex: 9,
      source: "return TC_ACT_SHOT;",
      branchEvidence: [
        {
          insnIndex: 4,
          disasm: "(15) if r1 == 0x0 goto pc+4",
          targetIndex: 8,
          branch: "taken",
          source: "if (blocked)",
          sourceFile: "prog.bpf.c",
          sourceLine: 12,
        },
      ],
    };

    const analyses = new Map([
      [1, firstProgram],
      [2, returnAnalysis([0])],
      [3, returnAnalysis([0])],
    ]);

    const prediction = predictPacketChain(tcChain(), id => analyses.get(id));

    expect(prediction?.steps[0].verdictExplanations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          verdict: "pass",
          summary: "Can pass with return 0 at exit 0.",
          exitIndex: 0,
          returnValue: 0,
        }),
        expect.objectContaining({
          verdict: "drop",
          summary:
            'Can drop with return 2 at exit 9 when "if (blocked)" is taken from return TC_ACT_SHOT;',
          exitIndex: 9,
          returnValue: 2,
          branchEvidence: [
            expect.objectContaining({
              insnIndex: 4,
              branch: "taken",
              source: "if (blocked)",
            }),
          ],
        }),
      ])
    );
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

  it("explains tail calls with resolved prog-array map and slot", () => {
    const analysis = returnAnalysis([0], { tailCall: true });
    analysis.tailCalls = [
      {
        insnIndex: 42,
        disasm: "(85) call bpf_tail_call#12",
        mapId: 21,
        slot: 3,
      },
    ];
    const analyses = new Map([
      [1, analysis],
      [2, returnAnalysis([0])],
      [3, returnAnalysis([0])],
    ]);

    const prediction = predictPacketChain(tcChain(), id => analyses.get(id), {
      maps: [progArrayMap(21, "tail_calls")],
    });

    expect(prediction?.steps[0].verdictExplanations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          verdict: "unknown",
          summary:
            "Tail call at instruction 42 may continue in prog-array tail_calls (#21) slot 3; target program is not resolved from current snapshot.",
        }),
      ])
    );
  });

  it("keeps all-pass verdict prediction while reporting known side effects", () => {
    const sideEffects: XlatedSideEffectSummary = {
      ...EMPTY_SIDE_EFFECTS,
      hasSideEffects: true,
      labels: ["updates maps", "emits events"],
      hasMapWrites: true,
      hasTelemetryOutput: true,
      effects: [
        {
          kind: "map-write",
          label: "updates maps",
          insnIndex: 4,
          disasm: "(85) call map_update_elem",
          helper: "map_update_elem",
        },
        {
          kind: "telemetry-output",
          label: "emits events",
          insnIndex: 8,
          disasm: "(85) call ringbuf_output",
          helper: "ringbuf_output",
        },
      ],
    };
    const analyses = new Map([
      [1, returnAnalysis([0], { sideEffects })],
      [2, returnAnalysis([0])],
      [3, returnAnalysis([0])],
    ]);

    const prediction = predictPacketChain(tcChain(), id => analyses.get(id));

    expect(prediction).toMatchObject({
      possibleOutcomes: ["pass"],
      alwaysPass: true,
      hasSideEffects: true,
      sideEffectLabels: ["updates maps", "emits events"],
    });
    expect(prediction?.summary).toContain(
      "Known side effects: updates maps, emits events."
    );
    expect(prediction?.steps[0]).toMatchObject({
      hasSideEffects: true,
      sideEffectLabels: ["updates maps", "emits events"],
      sideEffectTitle:
        "updates maps: map_update_elem at insn 4; emits events: ringbuf_output at insn 8",
    });
  });
});

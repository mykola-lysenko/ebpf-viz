import { describe, expect, it } from "vitest";
import type {
  PacketActionSemantics,
  XlatedReturnAnalysis,
  XlatedSideEffectSummary,
} from "../shared/ebpf-types";
import {
  auditProgramVerdict,
  type VerdictAuditContext,
} from "../scripts/audit-packet-verdicts";

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

const TC_SEMANTICS: PacketActionSemantics = {
  pass: ["TC_ACT_OK (0)", "TC_ACT_UNSPEC (-1)"],
  passValues: [0, -1],
  drop: ["TC_ACT_SHOT (2)"],
  dropValues: [2],
  redirect: ["TC_ACT_REDIRECT (7)"],
  redirectValues: [7],
  other: ["TC_ACT_PIPE (3)"],
  otherValues: [3],
};

const EMPTY_SEMANTICS: PacketActionSemantics = {
  pass: [],
  drop: [],
  redirect: [],
  other: [],
};

function context(semantics = TC_SEMANTICS): VerdictAuditContext {
  return {
    key: "tc:test",
    source: "tc",
    family: "tc",
    direction: "egress",
    attachType: "clsact/egress",
    summary: "test",
    semantics,
  };
}

function analysis(
  constants: number[],
  unknown: XlatedReturnAnalysis["unknownExits"] = []
): XlatedReturnAnalysis {
  const counts = new Map<number, number>();
  for (const value of constants) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }

  return {
    exitCount: constants.length + unknown.length,
    constantExits: constants.map((value, index) => ({
      exitIndex: index,
      exitDisasm: "(95) exit",
      value,
    })),
    unknownExits: unknown,
    observedConstants: Array.from(counts.entries()).map(
      ([value, exitCount]) => ({ value, exitCount })
    ),
    tailCallIndices: [],
    hasUnknownExits: unknown.length > 0,
    hasTailCalls: false,
    sideEffects: EMPTY_SIDE_EFFECTS,
  };
}

describe("packet verdict audit", () => {
  it("keeps modeled TC constants issue-free", () => {
    const result = auditProgramVerdict(analysis([0, -1, 2, 7]), context());

    expect(result.verdicts).toEqual(["drop", "redirect", "pass"]);
    expect(result.issueReasons).toEqual([]);
  });

  it("flags constants outside hook semantics", () => {
    const result = auditProgramVerdict(analysis([99]), context());

    expect(result.verdicts).toEqual(["unknown"]);
    expect(result.issueReasons).toEqual(["unmodeled-return-constant:99"]);
  });

  it("flags unmodeled hook semantics", () => {
    const result = auditProgramVerdict(analysis([0, 1]), context(EMPTY_SEMANTICS));

    expect(result.verdicts).toEqual(["unknown"]);
    expect(result.issueReasons).toEqual(["unmodeled-hook-semantics"]);
  });

  it("groups unknown exit reasons", () => {
    const result = auditProgramVerdict(
      analysis([], [
        {
          exitIndex: 7,
          exitDisasm: "(95) exit",
          reason: "dynamic-assignment",
        },
      ]),
      context()
    );

    expect(result.verdicts).toEqual(["unknown"]);
    expect(result.issueReasons).toEqual(["unknown-exit:dynamic-assignment"]);
    expect(result.unknownExitReasons).toEqual({ "dynamic-assignment": 1 });
  });

  it("does not flag modeled TC redirect helper returns as unknown exits", () => {
    const result = auditProgramVerdict(
      analysis([], [
        {
          exitIndex: 4,
          exitDisasm: "(95) exit",
          assignmentIndex: 3,
          assignmentDisasm: "(85) call bpf_redirect#23",
          reason: "dynamic-assignment",
        },
      ]),
      context()
    );

    expect(result.verdicts).toEqual(["redirect"]);
    expect(result.issueReasons).toEqual([]);
  });
});

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { ProgramChain } from "../shared/ebpf-types";
import { predictPacketChain } from "../shared/packet-chain-prediction";
import { parseXlatedJson } from "./ebpf-dump";
import { analyzeXlatedReturns } from "./xlated-return-analysis";

const TC_REDIRECT_FIXTURE = new URL(
  "./fixtures/tc-ingress-redirect-helper-merge.xlated.json",
  import.meta.url
);

// Reduced from a real TC ingress bpftool xlated dump. It keeps the
// original return shape: local call -> shared exit -> pass/drop/bpf_redirect.
function tcIngressChain(): ProgramChain {
  return {
    hookId: "tc:eth0:clsact/ingress",
    hookLabel: "eth0 ingress",
    hookType: "tc",
    attachPoint: "eth0",
    attachType: "clsact/ingress",
    canShortCircuit: true,
    packetContext: {
      family: "tc",
      direction: "ingress",
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
    programs: [{ id: 1001, position: 1, name: "sample_tc_ingress" }],
  };
}

describe("packet chain corpus regressions", () => {
  it("models TC redirect helper merges without generic unknown", () => {
    const xlated = parseXlatedJson(readFileSync(TC_REDIRECT_FIXTURE, "utf8"));
    const analysis = analyzeXlatedReturns(xlated);

    expect(analysis.observedConstants).toEqual([
      { value: -1, exitCount: 1 },
      { value: 2, exitCount: 1 },
    ]);
    expect(analysis.unknownExits).toEqual([
      expect.objectContaining({
        assignmentDisasm: "(85) call bpf_redirect#12139344",
        reason: "dynamic-assignment",
        source: "return bpf_redirect(skb->ifindex, BPF_F_INGRESS);",
        sourceFile: "./././SampleTcRouter.h",
        sourceLine: 220,
      }),
    ]);

    const prediction = predictPacketChain(tcIngressChain(), progId =>
      progId === 1001 ? analysis : undefined
    );

    expect(prediction).toMatchObject({
      possibleOutcomes: ["drop", "redirect", "pass"],
      confidence: "high",
      hasUnknownBehavior: false,
    });
    expect(prediction?.steps[0]).toMatchObject({
      label: "can pass, drop, or redirect",
      verdicts: ["drop", "redirect", "pass"],
      hasUnknownBehavior: false,
      canTerminateChain: true,
      definitelyTerminatesChain: false,
    });
    expect(prediction?.steps[0].verdictExplanations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          evidenceKind: "modeled-helper-return",
          verdict: "redirect",
          helper: "bpf_redirect",
          assignmentDisasm: "(85) call bpf_redirect#12139344",
        }),
      ])
    );
  });
});

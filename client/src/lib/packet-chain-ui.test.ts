import { describe, expect, it, vi, afterEach } from "vitest";
import type {
  PacketActionSemantics,
  ProgramChain,
} from "../../../shared/ebpf-types";
import {
  chainTone,
  classifyRateDrop,
  formatActions,
  formatAge,
  formatRunCnt,
  hasModeledReturnSemantics,
  VERDICT_TONE_CLASSES,
} from "./packet-chain-ui";

function makeChain(semantics?: PacketActionSemantics): ProgramChain {
  return {
    hookId: "tc:eth0:clsact/ingress",
    hookLabel: "clsact/ingress",
    hookType: "tc",
    attachPoint: "eth0",
    attachType: "clsact/ingress",
    programs: [],
    canShortCircuit: true,
    packetContext: semantics
      ? {
          family: "tc",
          direction: "ingress",
          summary: "tc ingress",
          semantics,
        }
      : undefined,
  };
}

describe("packet-chain-ui helpers", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("classifies meaningful live rate drops", () => {
    expect(classifyRateDrop(undefined, 90)).toBeNull();
    expect(classifyRateDrop(100, 97)).toBeNull();

    expect(classifyRateDrop(100, 85)).toMatchObject({
      label: "~15% fewer/s",
      color: "#f59e0b",
    });
    expect(classifyRateDrop(100, 85)?.rate).toBeCloseTo(0.15);
    expect(classifyRateDrop(100, 60)).toMatchObject({
      label: "~40% fewer/s",
      color: "#f97316",
    });
    expect(classifyRateDrop(100, 60)?.rate).toBeCloseTo(0.4);
    expect(classifyRateDrop(100, 20)).toMatchObject({
      label: "~80% fewer/s",
      color: "#ef4444",
    });
    expect(classifyRateDrop(100, 20)?.rate).toBeCloseTo(0.8);
  });

  it("can flag suspicious rate increases for cgroup chains", () => {
    expect(classifyRateDrop(100, 110)).toBeNull();
    expect(classifyRateDrop(100, 110, { flagIncreases: true })).toMatchObject({
      label: "~10% MORE/s",
      color: "#22d3ee",
    });
    expect(
      classifyRateDrop(100, 110, { flagIncreases: true })?.rate
    ).toBeCloseTo(0.1);
  });

  it("formats run counts and program age labels", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-06-24T12:00:00Z"));

    expect(formatRunCnt(999)).toBe("999");
    expect(formatRunCnt(1_500)).toBe("1.5K");
    expect(formatRunCnt(2_000_000)).toBe("2.0M");
    expect(formatRunCnt(3_000_000_000)).toBe("3.0B");

    expect(formatAge(Date.now() / 1000 - 42)).toBe("42s ago");
    expect(formatAge(Date.now() / 1000 - 5 * 60)).toBe("5m ago");
    expect(formatAge(Date.now() / 1000 - 2 * 3600)).toBe("2h ago");
    expect(formatAge(Date.now() / 1000 - 3 * 86400)).toBe("3d ago");
  });

  it("formats action lists compactly", () => {
    expect(formatActions([])).toBe("not modeled");
    expect(formatActions(["TC_ACT_OK"])).toBe("TC_ACT_OK");
    expect(formatActions(["OK", "RECLASSIFY"])).toBe("OK, RECLASSIFY");
    expect(formatActions(["OK", "RECLASSIFY", "REDIRECT"])).toBe(
      "OK, RECLASSIFY, +1"
    );
  });

  it("prioritizes verdict tone consistently", () => {
    expect(chainTone(["pass"], false)).toBe("pass");
    expect(chainTone(["pass"], true)).toBe("unknown");
    expect(chainTone(["other"], false)).toBe("other");
    expect(chainTone(["unknown"], false)).toBe("unknown");
    expect(chainTone(["pass", "redirect"], false)).toBe("redirect");
    expect(chainTone(["pass", "drop", "redirect"], false)).toBe("drop");
  });

  it("detects whether a chain has modeled return semantics", () => {
    expect(hasModeledReturnSemantics(makeChain())).toBe(false);
    expect(
      hasModeledReturnSemantics(
        makeChain({ pass: [], drop: [], redirect: [], other: [] })
      )
    ).toBe(false);
    expect(
      hasModeledReturnSemantics(
        makeChain({ pass: ["TC_ACT_OK"], drop: [], redirect: [], other: [] })
      )
    ).toBe(true);
    expect(
      hasModeledReturnSemantics(
        makeChain({ pass: [], drop: ["0"], redirect: [], other: [] })
      )
    ).toBe(true);
  });

  it("exports verdict tone classes for every verdict", () => {
    expect(Object.keys(VERDICT_TONE_CLASSES).sort()).toEqual([
      "drop",
      "other",
      "pass",
      "redirect",
      "unknown",
    ]);
  });
});

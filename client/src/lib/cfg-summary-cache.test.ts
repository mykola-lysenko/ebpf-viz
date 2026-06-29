import { describe, expect, it, beforeEach } from "vitest";
import { buildCfgSummary } from "./cfg-summary";
import {
  clearCfgSummaryCacheForTests,
  getCachedCfgSummary,
} from "./cfg-summary-cache";
import type { ProgDump, XlatedInsn } from "../../../shared/ebpf-types";

function insns(lines: string[]): XlatedInsn[] {
  return lines.map((disasm, index) => ({ index, disasm }));
}

function dump(
  progId: number,
  xlated: XlatedInsn[],
  cfgSummary?: ProgDump["cfgSummary"]
): ProgDump {
  return {
    progId,
    xlated,
    cfgDot: "digraph {}",
    cfgSummary,
    jited: null,
    hasLineInfo: false,
    hasBtf: false,
  };
}

describe("cfg summary cache", () => {
  beforeEach(() => {
    clearCfgSummaryCacheForTests();
  });

  it("uses a server-computed summary without recomputing it locally", () => {
    const xlated = insns(["(b7) r0 = 0", "(95) exit"]);
    const serverSummary = buildCfgSummary("digraph {}", xlated);

    expect(getCachedCfgSummary(dump(10, xlated, serverSummary))).toBe(serverSummary);
    expect(getCachedCfgSummary(dump(10, xlated, serverSummary))).toBe(serverSummary);
  });

  it("invalidates cached summaries when bytecode changes", () => {
    const first = getCachedCfgSummary(dump(10, insns(["(b7) r0 = 0", "(95) exit"])));
    const second = getCachedCfgSummary(dump(10, insns(["(b7) r0 = 1", "(95) exit"])));

    expect(second).not.toBe(first);
    expect(second.fingerprint).not.toBe(first.fingerprint);
  });
});

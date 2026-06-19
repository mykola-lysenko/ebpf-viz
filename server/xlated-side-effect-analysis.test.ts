import { describe, expect, it } from "vitest";
import type { XlatedInsn } from "../shared/ebpf-types";
import { analyzeXlatedSideEffects } from "./xlated-side-effect-analysis";

function insn(
  index: number,
  disasm: string,
  extras: Partial<XlatedInsn> = {}
): XlatedInsn {
  return { index, disasm, ...extras };
}

describe("analyzeXlatedSideEffects", () => {
  it("detects helper-based packet mutation, map writes, telemetry, redirects, and tail calls", () => {
    const result = analyzeXlatedSideEffects([
      insn(0, "(85) call bpf_skb_store_bytes#9", {
        source: "bpf_skb_store_bytes(skb, 0, data, len, 0);",
      }),
      insn(1, "(85) call map_update_elem"),
      insn(2, "(85) call bpf_redirect_map#51"),
      insn(3, "(85) call ringbuf_output"),
      insn(4, "(85) call bpf_tail_call#12"),
    ]);

    expect(result).toMatchObject({
      hasSideEffects: true,
      hasPacketMutations: true,
      hasMapWrites: true,
      hasRedirects: true,
      hasTelemetryOutput: true,
      hasTailCalls: true,
    });
    expect(result.labels).toEqual([
      "mutates packet",
      "redirect helper",
      "updates maps",
      "emits events",
      "tail calls",
    ]);
    expect(result.effects[0]).toMatchObject({
      kind: "packet-mutation",
      helper: "skb_store_bytes",
      source: "bpf_skb_store_bytes(skb, 0, data, len, 0);",
    });
  });

  it("detects non-stack direct memory writes but ignores stack spills", () => {
    const result = analyzeXlatedSideEffects([
      insn(0, "(7b) *(u64 *)(r10 -24) = r0"),
      insn(1, "(63) *(u32 *)(r8 +26) = r1"),
    ]);

    expect(result.labels).toEqual(["writes through pointer"]);
    expect(result.effects).toEqual([
      {
        kind: "direct-memory-write",
        label: "writes through pointer",
        insnIndex: 1,
        disasm: "(63) *(u32 *)(r8 +26) = r1",
      },
    ]);
  });

  it("ignores read-only helpers and BPF-to-BPF subprogram calls", () => {
    const result = analyzeXlatedSideEffects([
      insn(0, "(85) call bpf_map_lookup_elem#1"),
      insn(1, "(85) call bpf_ktime_get_ns#5"),
      insn(2, "(85) call pc+188#bpf_prog_8dfdd00d230d7712_helper"),
    ]);

    expect(result.hasSideEffects).toBe(false);
    expect(result.effects).toEqual([]);
  });
});

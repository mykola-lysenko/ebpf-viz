import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { buildSnapshot } from "./ebpf-parser";
import type { RawNetSnapshot, RawTcFilterDump } from "../shared/ebpf-types";

const capture = JSON.parse(readFileSync(new URL("./fixtures/tcx-audit/ingress-next.json", import.meta.url), "utf8"));
const raw = capture.raw;
const net = [{ ...raw.net[0], tcFilters: raw.tcFilters as RawTcFilterDump[] }];
const meta = { hostname: "audit", kernelVersion: "UML", bpftoolVersion: "7.8", demoMode: false };
function snapshot(input: RawNetSnapshot[] = net) { return buildSnapshot(raw.progs, input, [], meta, [], raw.links); }

describe("TCX captured kernel evidence", () => {
  it("retains all mixed attachments with their real mechanism", () => {
    const s = snapshot();
    expect(s.networkInterfaces.find(i => i.name === "a3-recv")!.allPrograms.map(p => p.name)).toEqual(["a3_first", "a3_second", "a3_third", "a3_legacy"]);
    const first = s.programs.find(p => p.name === "a3_first")!;
    expect(first.attachments).toContainEqual(expect.objectContaining({ kind: "tcx", direction: "ingress" }));
  });
  it("preserves query order and separates the conditional legacy stage", () => {
    const chains = snapshot().programChains;
    expect(chains.map(c => c.mechanism)).toEqual(["tcx", "legacy-tc"]);
    expect(chains[0].programs.map(p => p.id)).toEqual([4, 3, 2]);
    expect(chains[0].ordering).toBe("kernel-query");
    expect(chains[0].revision).toBeUndefined();
    expect(chains[1].programs.map(p => p.name)).toEqual(["a3_legacy"]);
    expect(chains[1].afterTcx).toBe(true);
  });
  it("handles the separate tcx array without losing chains or classifying it as legacy TC", () => {
    const shape = { ...net[0], tc: net[0].tc.filter((e: { kind: string }) => !e.kind.startsWith("tcx/")), tcx: net[0].tc.filter((e: { kind: string }) => e.kind.startsWith("tcx/")) };
    expect(snapshot([shape]).programChains[0].programs.map(p => p.id)).toEqual([4, 3, 2]);
  });
  it("marks non-query TCX rows with unknown order", () => {
    const tcx = net[0].tc.filter((e: { kind: string }) => e.kind.startsWith("tcx/")).map((e: { prog_id: number }) => ({ ...e, id: e.prog_id, prog_id: undefined }));
    const chains = snapshot([{ tcx }]).programChains;
    expect(chains[0].ordering).toBe("unknown");
  });
  it("builds namespace-scoped chains without mixing identical interface names", () => {
    const s = buildSnapshot(raw.progs, [], [], meta, [], raw.links, [
      { id: "1", label: "one", net }, { id: "2", label: "two", net },
    ]);
    expect(s.programChains.filter(c => c.mechanism === "tcx").map(c => c.netns)).toEqual(["one", "two"]);
    expect(new Set(s.programChains.map(c => c.hookId)).size).toBe(4);
  });
});

it.each(["ingress-next", "ingress-pass", "egress-next", "egress-pass"])("matches raw %s capture to measured query and packet execution", name => {
  const captured = JSON.parse(readFileSync(new URL(`./fixtures/tcx-audit/${name}.json`, import.meta.url), "utf8"));
  const evidence = JSON.parse(readFileSync(new URL(`./fixtures/tcx-audit/${name}-evidence.json`, import.meta.url), "utf8"));
  const r = captured.raw;
  const s = buildSnapshot(r.progs, [{ ...r.net[0], tcFilters: r.tcFilters }], [], meta, [], [...r.links].reverse());
  const tcx = s.programChains.find(c => c.mechanism === "tcx")!;
  expect(tcx.programs.map(p => p.id)).toEqual(evidence.expectedProgramIds);
  expect(evidence.query.Programs.map((p: { ID: number }) => p.ID)).toEqual(evidence.expectedProgramIds);
  expect(evidence.query.Revision).toBe(evidence.revisionBefore + 3);
  expect(evidence.observedExecution).toBe(evidence.terminalTCX ? 12 : 1234);
  expect(s.programChains[1].afterTcx).toBe(true);
  expect(tcx.packetContext).toBeUndefined(); // legacy TC continuation model is inapplicable
});

it("does not imply complete chain order when a queried program is absent from inventory", () => {
  const s = buildSnapshot(raw.progs.filter((p: { id: number }) => p.id !== 3), net, [], meta);
  expect(s.programChains.find(c => c.mechanism === "tcx")!.ordering).toBe("unknown");
});
it("does not give netkit rows TC classifier chains", () => {
  const tc = net[0].tc.filter((e: { kind: string }) => e.kind.startsWith("tcx/")).map((e: { kind: string }) => ({ ...e, kind: "netkit/primary" }));
  expect(snapshot([{ tc }]).programChains).toEqual([]);
});

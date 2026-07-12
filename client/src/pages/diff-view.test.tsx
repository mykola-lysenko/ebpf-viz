// @vitest-environment happy-dom
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render } from "@testing-library/react";
import type { BpfProgram, BpfMap, EbpfSnapshot, MapEntry, MapDumpResult } from "../../../shared/ebpf-types";

function prog(id: number, name: string, tag: string): BpfProgram {
  return {
    id, type: "sched_cls", rawType: "sched_cls", name, tag,
    gplCompatible: true, loadedAt: 1, orphaned: false, bytesXlated: 0, jited: true,
    memlock: 0, mapIds: [], attachments: [], osiLayer: "L3", color: "#fff",
  };
}
function snap(programs: BpfProgram[]): EbpfSnapshot {
  return {
    timestamp: 0, hostname: "h", kernelVersion: "6", bpftoolVersion: "7", demoMode: false,
    programs, networkInterfaces: [], cgroupTree: [], kernelZones: [], programChains: [],
    stats: { total: programs.length, byType: {}, jited: programs.length, orphaned: 0 },
  };
}
const A = snap([prog(1, "keep", "t"), prog(2, "gone", "g")]);
const B = snap([prog(1, "keep", "t"), prog(9, "fresh", "f")]);

// A "cfg" hash map exists on both sides (different kernel ids — matched by name+type).
function cfgMap(id: number): BpfMap {
  return {
    id, name: "cfg", rawType: "hash", type: "hash", maxEntries: 16,
    bytesKey: 4, bytesValue: 4, memlock: 0, frozen: false,
    usedByProgIds: [], pinnedPaths: [],
  } as unknown as BpfMap;
}
function entry(keyHex: string, valueHex: string): MapEntry {
  return { index: 0, keyHex, keyDecimal: null, keyBtf: null, valueHex, valueDecimal: null, valueBtf: null, valueError: null };
}
const DUMP_A: Record<number, MapDumpResult> = {
  10: { mapId: 10, mapType: "hash", mapName: "cfg", totalEntries: 2, truncated: false, maxReturned: 2,
    entries: [entry("01", "aa"), entry("02", "bb")], btfDecoded: false, error: null, unsupported: false },
};
const DUMP_B: Record<number, MapDumpResult> = {
  20: { mapId: 20, mapType: "hash", mapName: "cfg", totalEntries: 2, truncated: false, maxReturned: 2,
    entries: [entry("02", "b9"), entry("03", "cc")], btfDecoded: false, error: null, unsupported: false },
};

vi.mock("@/contexts/EbpfContext", () => ({
  useEbpf: () => ({
    parseSnapshotFile: async (file: File) => ({
      snapshot: file.name === "a.json" ? A : B,
      maps: file.name === "a.json" ? [cfgMap(10)] : [cfgMap(20)],
      meta: { filename: file.name, capturedAt: "t", hostname: "h", kernelVersion: "6" },
    }),
    // Keyed by the side's map id (10 for A, 20 for B).
    parseMapDumpsFile: async (_file: File, maps: BpfMap[]) =>
      maps[0]?.id === 10 ? DUMP_A : DUMP_B,
  }),
}));

import DiffView from "./DiffView";

afterEach(cleanup);

describe("DiffView", () => {
  it("loads two snapshots and renders the program diff", async () => {
    const r = render(<DiffView />);
    const inputs = r.container.querySelectorAll('input[type="file"]');
    expect(inputs).toHaveLength(2);

    await act(async () => {
      fireEvent.change(inputs[0], { target: { files: [new File(["{}"], "a.json")] } });
    });
    await act(async () => {
      fireEvent.change(inputs[1], { target: { files: [new File(["{}"], "b.json")] } });
    });

    const text = r.container.textContent ?? "";
    // Added / removed programs surface by name.
    expect(text).toContain("fresh"); // added in B
    expect(text).toContain("gone"); // removed from A
    // "keep" is unchanged → not listed as a diff row beyond the file summary.
    // Summary tiles reflect +1 / -1 program.
    expect(text).toContain("Progs +");
    expect(text).toContain("Progs −");
  });

  it("shows the empty state before both snapshots are loaded", () => {
    const r = render(<DiffView />);
    expect(r.container.textContent).toContain("Load two snapshots");
  });

  it("diffs map contents key-by-key once dumps are attached to both sides", async () => {
    const r = render(<DiffView />);
    const snapInputs = r.container.querySelectorAll('input[type="file"]');
    // Load both snapshots first (each side then exposes a map-dump upload).
    await act(async () => {
      fireEvent.change(snapInputs[0], { target: { files: [new File(["{}"], "a.json")] } });
    });
    await act(async () => {
      fireEvent.change(snapInputs[1], { target: { files: [new File(["{}"], "b.json")] } });
    });

    // Now two more file inputs exist (the map-dump uploads). Within each slot the
    // dump input renders before the always-present snapshot input, so DOM order is
    // [dumpA, snapA, dumpB, snapB].
    const allInputs = r.container.querySelectorAll('input[type="file"]');
    expect(allInputs.length).toBe(4); // 2 snapshot + 2 dump
    await act(async () => {
      fireEvent.change(allInputs[0], { target: { files: [new File(["{}"], "dumpA.json")] } });
    });
    await act(async () => {
      fireEvent.change(allInputs[2], { target: { files: [new File(["{}"], "dumpB.json")] } });
    });

    const text = r.container.textContent ?? "";
    expect(text).toContain("Map contents");
    // key 03 added, key 01 removed, key 02 changed (bb → b9).
    expect(text).toContain("bb → b9");
    expect(text).toContain("+1"); // one added entry (key 03)
    expect(text).toContain("−1"); // one removed entry (key 01)
  });
});

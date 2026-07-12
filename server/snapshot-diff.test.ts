import { describe, expect, it } from "vitest";
import { diffSnapshots, diffMapEntries } from "../shared/snapshot-diff";
import type { BpfProgram, BpfMap, EbpfSnapshot, MapEntry } from "../shared/ebpf-types";

function prog(over: Partial<BpfProgram> & { id: number }): BpfProgram {
  return {
    type: "kprobe",
    rawType: "kprobe",
    name: `prog_${over.id}`,
    tag: "aaaa",
    gplCompatible: true,
    loadedAt: 1,
    orphaned: false,
    bytesXlated: 0,
    jited: true,
    memlock: 0,
    mapIds: [],
    attachments: [],
    osiLayer: "kernel",
    color: "#fff",
    ...over,
  };
}

function map(over: Partial<BpfMap> & { id: number }): BpfMap {
  return {
    type: "hash",
    rawType: "hash",
    name: `map_${over.id}`,
    flags: 0,
    bytesKey: 4,
    bytesValue: 8,
    maxEntries: 1024,
    bytesMemlock: 0,
    frozen: false,
    pinnedPaths: [],
    usedByProgIds: [],
    color: "#fff",
    category: "data",
    ...over,
  };
}

function snap(programs: BpfProgram[]): EbpfSnapshot {
  return {
    timestamp: 0,
    hostname: "h",
    kernelVersion: "6",
    bpftoolVersion: "7",
    demoMode: false,
    programs,
    networkInterfaces: [],
    cgroupTree: [],
    kernelZones: [],
    programChains: [],
    stats: { total: programs.length, byType: {}, jited: 0, orphaned: 0 },
  };
}

describe("diffSnapshots", () => {
  it("reports identical when nothing changed", () => {
    const a = snap([prog({ id: 1, name: "x", tag: "t1" })]);
    const b = snap([prog({ id: 5, name: "x", tag: "t1" })]); // new id, same code
    const d = diffSnapshots(a, b);
    expect(d.summary.identical).toBe(true);
    expect(d.programs.changed).toHaveLength(0);
  });

  it("detects added and removed programs by name#tag", () => {
    const a = snap([prog({ id: 1, name: "keep", tag: "t" }), prog({ id: 2, name: "gone", tag: "g" })]);
    const b = snap([prog({ id: 1, name: "keep", tag: "t" }), prog({ id: 9, name: "fresh", tag: "f" })]);
    const d = diffSnapshots(a, b);
    expect(d.programs.added.map(e => e.name)).toEqual(["fresh"]);
    expect(d.programs.removed.map(e => e.name)).toEqual(["gone"]);
    expect(d.summary.identical).toBe(false);
  });

  it("treats changed bytecode as removed+added, not changed", () => {
    const a = snap([prog({ id: 1, name: "p", tag: "old" })]);
    const b = snap([prog({ id: 1, name: "p", tag: "new" })]);
    const d = diffSnapshots(a, b);
    expect(d.programs.removed.map(e => e.name)).toEqual(["p"]);
    expect(d.programs.added.map(e => e.name)).toEqual(["p"]);
    expect(d.programs.changed).toHaveLength(0);
  });

  it("reports field changes for matched programs", () => {
    const a = snap([prog({ id: 1, name: "p", tag: "t", attachments: [], orphaned: false })]);
    const b = snap([prog({
      id: 1, name: "p", tag: "t", orphaned: true,
      attachments: [{ kind: "tcx", detail: "eth0 tcx/ingress" }],
    })]);
    const d = diffSnapshots(a, b);
    expect(d.programs.changed).toHaveLength(1);
    expect(d.programs.changed[0].changes).toContain("+1 attachment");
    expect(d.programs.changed[0].changes).toContain("became orphaned");
  });

  it("pairs clones by id and reports the extra as added", () => {
    // Two clones in A (same key), three in B → one added, none removed.
    const clones = (ids: number[]) => ids.map(id => prog({ id, name: "clone", tag: "c" }));
    const d = diffSnapshots(snap(clones([1, 2])), snap(clones([1, 2, 3])));
    expect(d.programs.added).toHaveLength(1);
    expect(d.programs.removed).toHaveLength(0);
  });

  it("diffs maps by name#type with field changes", () => {
    const aMaps = [map({ id: 1, name: "lb", rawType: "lru_hash", maxEntries: 1024 })];
    const bMaps = [
      map({ id: 1, name: "lb", rawType: "lru_hash", maxEntries: 2048 }),
      map({ id: 2, name: "new", rawType: "array" }),
    ];
    const d = diffSnapshots(snap([]), snap([]), aMaps, bMaps);
    expect(d.maps.added.map(e => e.name)).toEqual(["new"]);
    expect(d.maps.changed).toHaveLength(1);
    expect(d.maps.changed[0].changes).toContain("max entries 1024 → 2048");
  });

  it("tracks owner changes (e.g. process appeared/left)", () => {
    const a = snap([prog({ id: 1, name: "p", tag: "t", pids: [{ pid: 10, comm: "cilium" }] })]);
    const b = snap([prog({ id: 1, name: "p", tag: "t", pids: [] })]);
    const d = diffSnapshots(a, b);
    expect(d.programs.changed[0].changes.some(c => c.startsWith("owner "))).toBe(true);
  });
});

function entry(over: Partial<MapEntry> & { keyHex: string }): MapEntry {
  return {
    index: 0,
    keyDecimal: null,
    keyBtf: null,
    valueHex: "00",
    valueDecimal: null,
    valueBtf: null,
    valueError: null,
    ...over,
  };
}

describe("diffMapEntries (map contents)", () => {
  it("classifies entries as added / removed / changed by key", () => {
    const a = [
      entry({ keyHex: "01", valueHex: "aa" }),
      entry({ keyHex: "02", valueHex: "bb" }), // will change
      entry({ keyHex: "03", valueHex: "cc" }), // will be removed
    ];
    const b = [
      entry({ keyHex: "01", valueHex: "aa" }), // unchanged
      entry({ keyHex: "02", valueHex: "b9" }), // value changed
      entry({ keyHex: "04", valueHex: "dd" }), // added
    ];
    const d = diffMapEntries(a, b);
    expect(d.added.map(e => e.keyHex)).toEqual(["04"]);
    expect(d.removed.map(e => e.keyHex)).toEqual(["03"]);
    expect(d.changed).toHaveLength(1);
    expect(d.changed[0].keyHex).toBe("02");
    expect(d.changed[0].before.valueHex).toBe("bb");
    expect(d.changed[0].after.valueHex).toBe("b9");
    expect(d.identical).toBe(false);
  });

  it("is identical when the same keys map to the same values", () => {
    const a = [entry({ keyHex: "01", valueHex: "aa" }), entry({ keyHex: "02", valueHex: "bb" })];
    const b = [entry({ keyHex: "02", valueHex: "bb" }), entry({ keyHex: "01", valueHex: "aa" })];
    const d = diffMapEntries(a, b);
    expect(d.identical).toBe(true);
    expect(d.added).toHaveLength(0);
    expect(d.removed).toHaveLength(0);
    expect(d.changed).toHaveLength(0);
  });

  it("detects a per-cpu value change even when the flat hex matches", () => {
    const a = [entry({ keyHex: "01", valueHex: "00", perCpuValues: [{ cpu: 0, hex: "aa", decimal: null }] })];
    const b = [entry({ keyHex: "01", valueHex: "00", perCpuValues: [{ cpu: 0, hex: "ab", decimal: null }] })];
    const d = diffMapEntries(a, b);
    expect(d.changed).toHaveLength(1);
  });

  it("prefers BTF › decimal › hex for the key label", () => {
    const d1 = diffMapEntries([], [entry({ keyHex: "01", keyBtf: "{ip: 1.2.3.4}" })]);
    expect(d1.added[0]).toBeDefined();
    const d2 = diffMapEntries([entry({ keyHex: "07", valueHex: "aa" })], [entry({ keyHex: "07", valueHex: "bb", keyDecimal: "7" })]);
    expect(d2.changed[0].keyLabel).toBe("7"); // decimal used when no BTF
  });
});

import { describe, expect, it } from "vitest";
import { diffSnapshots, diffMapEntries, diffSnapshotMapEntries } from "../shared/snapshot-diff";
import type { BpfProgram, BpfMap, EbpfSnapshot, MapEntry, MapDumpResult } from "../shared/ebpf-types";

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

  it("leaves clones ambiguous even when kernel IDs overlap", () => {
    const clones = (ids: number[]) => ids.map(id => prog({ id, name: "clone", tag: "c" }));
    const d = diffSnapshots(snap(clones([1, 2])), snap(clones([1, 2, 3])));
    expect(d.programs.added).toHaveLength(0);
    expect(d.programs.removed).toHaveLength(0);
    expect(d.programs.ambiguous[0]).toMatchObject({ beforeIds: [1, 2], afterIds: [1, 2, 3] });
    expect(d.summary.identical).toBe(false);
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

function dump(entries: MapEntry[], over: Partial<MapDumpResult> = {}): MapDumpResult {
  return { mapId: 1, mapType: "hash", mapName: "cfg", entries, totalEntries: entries.length,
    maxReturned: 1000, truncated: false, error: null, unsupported: false, btfDecoded: false, complete: true, ...over };
}

describe("snapshot identity and relationship evidence", () => {
  it("compares relationships through matched identities across hosts and reloads", () => {
    const a = snap([prog({ id: 1, name: "p", mapIds: [10, 11] })]);
    const b = { ...snap([prog({ id: 9, name: "p", mapIds: [21, 20] })]), hostname: "other-host" };
    const d = diffSnapshots(a, b,
      [map({ id: 10, name: "x", usedByProgIds: [1] }), map({ id: 11, name: "y", usedByProgIds: [1] })],
      [map({ id: 20, name: "x", usedByProgIds: [9] }), map({ id: 21, name: "y", usedByProgIds: [9] })]);
    expect(d.summary.identical).toBe(true);
  });
  it("detects same-count replacements of program maps and map users", () => {
    const a = snap([prog({ id: 1, name: "p", mapIds: [10] }), prog({ id: 2, name: "q", mapIds: [11] })]);
    const b = snap([prog({ id: 9, name: "p", mapIds: [21] }), prog({ id: 8, name: "q", mapIds: [20] })]);
    const d = diffSnapshots(a, b,
      [map({ id: 10, name: "x", usedByProgIds: [1] }), map({ id: 11, name: "y", usedByProgIds: [2] })],
      [map({ id: 20, name: "x", usedByProgIds: [8] }), map({ id: 21, name: "y", usedByProgIds: [9] })]);
    expect(d.programs.changed).toHaveLength(2);
    expect(d.programs.changed[0].changes).toContain("maps added: B #21");
    expect(d.maps.changed).toHaveLength(2);
  });
  it("detects replaced pin paths and ignores ordering and duplicate paths", () => {
    const d = diffSnapshots(snap([prog({ id: 1, name: "p", pinnedPaths: ["/old"] })]),
      snap([prog({ id: 2, name: "p", pinnedPaths: ["/new"] })]),
      [map({ id: 1, name: "m", pinnedPaths: ["/a", "/b", "/a"] })],
      [map({ id: 2, name: "m", pinnedPaths: ["/b", "/a"] })]);
    expect(d.programs.changed[0].changes).toEqual(["pins added: /new", "pins removed: /old"]);
    expect(d.maps.changed).toEqual([]);
    const maps = diffSnapshots(snap([]), snap([]), [map({ id: 1, name: "m", pinnedPaths: ["/old"] })], [map({ id: 2, name: "m", pinnedPaths: ["/new"] })]);
    expect(maps.maps.changed[0].changes).toContain("pins removed: /old");
  });
  it("uses the same pin-disambiguated clone pairs for inventory and contents", () => {
    const a = [map({ id: 1, name: "clone", pinnedPaths: ["/x"] }), map({ id: 2, name: "clone", pinnedPaths: ["/y"] })];
    const b = [map({ id: 1, name: "clone", pinnedPaths: ["/y"] }), map({ id: 2, name: "clone", pinnedPaths: ["/x"] })];
    const d = diffSnapshots(snap([]), snap([]), a, b);
    expect(d.maps.matched).toEqual([{ beforeId: 1, afterId: 2 }, { beforeId: 2, afterId: 1 }]);
    const x = dump([entry({ keyHex: "01", valueHex: "aa" })]), y = dump([entry({ keyHex: "01", valueHex: "bb" })]);
    const contents = diffSnapshotMapEntries(d.maps, b, { 1: x, 2: y }, { 1: y, 2: x });
    expect(contents).toHaveLength(2);
    expect(contents.every(c => c.diff.identical)).toBe(true);
  });
  it("does not choose a first clone or infer relationships through ambiguous targets", () => {
    const maps = [map({ id: 1, name: "clone" }), map({ id: 2, name: "clone" })];
    const d = diffSnapshots(snap([prog({ id: 1, name: "p", mapIds: [1] })]), snap([prog({ id: 1, name: "p", mapIds: [2] })]), maps, maps);
    expect(d.maps.matched).toEqual([]);
    expect(d.programs.uncertain[0]).toContain("map relationships unverified");
    expect(d.summary.identical).toBe(false);
    expect(diffSnapshotMapEntries(d.maps, maps, { 1: dump([]) }, { 1: dump([]) })).toEqual([]);
  });
  it("does not use a dangling ID as proof of relationship equality", () => {
    const s = snap([prog({ id: 1, name: "p", mapIds: [99] })]);
    const d = diffSnapshots(s, s);
    expect(d.programs.uncertain).toHaveLength(1);
    expect(d.summary.identical).toBe(false);
  });
  it("includes program type in identity and does not treat ID reuse as continuity", () => {
    const d = diffSnapshots(snap([prog({ id: 1, name: "p", rawType: "kprobe" })]), snap([prog({ id: 1, name: "p", rawType: "xdp" })]));
    expect(d.programs.matched).toEqual([]);
    expect(d.programs.added).toHaveLength(1);
    expect(d.programs.removed).toHaveLength(1);
  });
  it("normalizes owner process names as sets", () => {
    const a = snap([prog({ id: 1, name: "p", pids: [{ pid: 1, comm: "x" }, { pid: 2, comm: "y" }] })]);
    const b = snap([prog({ id: 2, name: "p", pids: [{ pid: 3, comm: "y" }, { pid: 4, comm: "x" }, { pid: 5, comm: "x" }] })]);
    expect(diffSnapshots(a, b).summary.identical).toBe(true);
  });
});

describe("incomplete map contents and decoded data", () => {
  const x = entry({ keyHex: "01", valueHex: "aa" });
  const y = entry({ keyHex: "02", valueHex: "bb" });
  it.each([{ truncated: true, totalEntries: 10 }, { error: "permission denied" }, { unsupported: true }, { complete: false }])(
    "does not confirm deletion or equality from an incomplete B dump: %j", partial => {
      const d = diffMapEntries(dump([x, y]), dump([x], partial));
      expect(d.removed).toEqual([]);
      expect(d.onlyBefore).toEqual([y]);
      expect(d.identical).toBe(false);
      expect(diffMapEntries(dump([x], partial), dump([x], partial)).identical).toBe(false);
    });
  it("does not confirm additions against an incomplete baseline, but compares shared readable values", () => {
    const d = diffMapEntries(dump([x], { truncated: true, totalEntries: 5 }), dump([{ ...x, valueHex: "cc" }, y]));
    expect(d.added).toEqual([]);
    expect(d.onlyAfter).toEqual([y]);
    expect(d.changed).toHaveLength(1);
  });
  it("shows missing dumps and distinguishes a successful empty dump", () => {
    expect(diffMapEntries(null, dump([])).identical).toBe(false);
    expect(diffMapEntries(dump([]), dump([])).identical).toBe(true);
    expect(diffMapEntries(dump([x]), dump([])).removed).toEqual([x]);
  });
  it("does not collapse distinct BTF keys and compares decoded values canonically", () => {
    const one = entry({ keyHex: "", keyBtf: '{"id":1,"zone":2}', valueHex: "", valueBtf: '{"a":1,"b":2}' });
    const two = entry({ keyHex: "", keyBtf: '{"id":2}', valueHex: "", valueBtf: '3' });
    const d = diffMapEntries([one, two], [{ ...one, keyBtf: '{"zone":2,"id":1}', valueBtf: '{"b":2,"a":1}' }, { ...two, valueBtf: '4' }]);
    expect(d.changed).toHaveLength(1);
    expect(d.changed[0].keyLabel).toBe('{"id":2}');
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
  });
  it("leaves read errors unresolved instead of presenting them as values", () => {
    const d = diffMapEntries(dump([x]), dump([{ ...x, valueHex: "", valueError: "ENOENT" }]));
    expect(d.changed).toEqual([]);
    expect(d.identical).toBe(false);
    expect(d.warnings.join(" ")).toContain("ENOENT");
  });
  it("flags duplicate keys instead of silently selecting a value", () => {
    const d = diffMapEntries([x, { ...x, valueHex: "ff" }], [x]);
    expect(d.identical).toBe(false);
    expect(d.changed).toEqual([]);
    expect(d.warnings.join(" ")).toContain("duplicate");
  });
  it("does not infer additions and removals between incomparable key encodings", () => {
    const d = diffMapEntries([x], [{ ...x, keyHex: "", keyBtf: "1" }]);
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
    expect(d.onlyBefore).toHaveLength(1);
    expect(d.onlyAfter).toHaveLength(1);
  });
  it("ignores per-CPU order and its redundant display value", () => {
    const a = entry({ keyHex: "01", valueHex: "aa", perCpuValues: [{ cpu: 0, hex: "aa", decimal: null }, { cpu: 1, hex: "bb", decimal: null }] });
    expect(diffMapEntries([a], [{ ...a, valueHex: "bb", perCpuValues: [...a.perCpuValues!].reverse() }]).identical).toBe(true);
  });
});


it("reports missing bytecode identity instead of inventing a reload or equality", () => {
  const d = diffSnapshots(snap([prog({ id: 1, name: "p", tag: "0000000000000000" })]), snap([prog({ id: 2, name: "p", tag: "real" })]));
  expect(d.programs.matched).toEqual([]);
  expect(d.programs.added).toEqual([]);
  expect(d.programs.removed).toEqual([]);
  expect(d.programs.ambiguous[0].reason).toContain("Bytecode identity is unavailable");
});

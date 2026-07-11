import { describe, it, expect } from "vitest";
import { parseMaps } from "./ebpf-map-parser";
import { MAP_TYPE_META } from "../shared/ebpf-types";
import type { BpfProgram, RawBpfMap } from "../shared/ebpf-types";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const NO_PROGS: BpfProgram[] = [];

function makeRaw(overrides: Partial<RawBpfMap> & { id: number; type: string }): RawBpfMap {
  return {
    name: "test_map",
    flags: 0,
    bytes_key: 4,
    bytes_value: 8,
    max_entries: 1024,
    bytes_memlock: 32768,
    frozen: false,
    pinned: [],
    ...overrides,
  } as RawBpfMap;
}

function makeProgWithMaps(id: number, mapIds: number[]): BpfProgram {
  return {
    id,
    name: `prog_${id}`,
    rawType: "xdp",
    type: "networking",
    tag: "aabbccdd11223344",
    jited: true,
    gpl_compatible: true,
    loadedAt: Date.now(),
    mapIds,
    btfId: undefined,
    pids: undefined,
    runTimeNs: 0,
    runCnt: 0,
    recursionMisses: 0,
  } as unknown as BpfProgram;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("parseMaps", () => {
  it("filters out bpftool's own skeleton/libbpf internal maps", () => {
    // Concurrent poll invocations leak transient owner-less copies of these.
    const maps = parseMaps(
      [
        makeRaw({ id: 137648, type: "array", name: "libbpf_global" }),
        makeRaw({ id: 137649, type: "array", name: "pid_iter.rodata", frozen: true }),
        makeRaw({ id: 137650, type: "array", name: "libbpf_det_bind" }),
        makeRaw({ id: 137653, type: "array", name: "libbpf_global" }), // 2nd concurrent copy
        makeRaw({ id: 42, type: "hash", name: "cilium_lb4_services" }), // a real map
      ],
      NO_PROGS
    );
    expect(maps.map(m => m.name)).toEqual(["cilium_lb4_services"]);
  });

  it("parses a basic hash map with correct fields", () => {
    const maps = parseMaps([makeRaw({ id: 1, type: "hash", name: "my_hash", bytes_key: 4, bytes_value: 8, bytes_memlock: 32768 })], NO_PROGS);
    expect(maps).toHaveLength(1);
    const m = maps[0];
    expect(m.id).toBe(1);
    expect(m.name).toBe("my_hash");
    expect(m.rawType).toBe("hash");
    expect(m.bytesKey).toBe(4);
    expect(m.bytesValue).toBe(8);
    expect(m.maxEntries).toBe(1024);
    expect(m.bytesMemlock).toBe(32768);
    expect(m.frozen).toBe(false);
    expect(m.pinnedPaths).toEqual([]);
    expect(m.usedByProgIds).toEqual([]);
  });

  it("assigns category 'data' to hash and array maps", () => {
    const maps = parseMaps([
      makeRaw({ id: 1, type: "hash" }),
      makeRaw({ id: 2, type: "array" }),
    ], NO_PROGS);
    expect(maps[0].category).toBe("data");
    expect(maps[1].category).toBe("data");
  });

  it("assigns category 'event' to ringbuf and perf_event_array maps", () => {
    const maps = parseMaps([
      makeRaw({ id: 3, type: "ringbuf" }),
      makeRaw({ id: 4, type: "perf_event_array" }),
    ], NO_PROGS);
    expect(maps[0].category).toBe("event");
    expect(maps[1].category).toBe("event");
  });

  it("assigns category 'data' to lpm_trie maps", () => {
    const maps = parseMaps([makeRaw({ id: 5, type: "lpm_trie" })], NO_PROGS);
    expect(maps[0].category).toBe("data");
  });

  it("assigns category 'control' to prog_array maps", () => {
    const maps = parseMaps([makeRaw({ id: 6, type: "prog_array" })], NO_PROGS);
    expect(maps[0].category).toBe("control");
  });

  it("assigns category 'socket' to sockmap maps", () => {
    const maps = parseMaps([makeRaw({ id: 7, type: "sockmap" })], NO_PROGS);
    expect(maps[0].category).toBe("socket");
  });

  it("parses pinned paths correctly", () => {
    const maps = parseMaps([makeRaw({ id: 8, type: "hash", pinned: ["/sys/fs/bpf/my_map"] })], NO_PROGS);
    expect(maps[0].pinnedPaths).toEqual(["/sys/fs/bpf/my_map"]);
  });

  it("parses frozen flag as boolean", () => {
    const maps = parseMaps([makeRaw({ id: 9, type: "hash", frozen: true as any })], NO_PROGS);
    expect(maps[0].frozen).toBe(true);
  });

  it("cross-references programs via mapIds to populate usedByProgIds", () => {
    const prog = makeProgWithMaps(10, [42]);
    const maps = parseMaps([makeRaw({ id: 42, type: "array" })], [prog]);
    expect(maps[0].usedByProgIds).toContain(10);
  });

  it("populates usedByProgIds from multiple programs sharing a map", () => {
    const prog1 = makeProgWithMaps(10, [42]);
    const prog2 = makeProgWithMaps(11, [42]);
    const maps = parseMaps([makeRaw({ id: 42, type: "hash" })], [prog1, prog2]);
    expect(maps[0].usedByProgIds).toContain(10);
    expect(maps[0].usedByProgIds).toContain(11);
    expect(maps[0].usedByProgIds).toHaveLength(2);
  });

  it("handles empty input", () => {
    expect(parseMaps([], NO_PROGS)).toEqual([]);
  });

  it("handles null/undefined input gracefully", () => {
    // The parser guards against non-array input
    expect(() => parseMaps(null as any, NO_PROGS)).not.toThrow();
    expect(() => parseMaps(undefined as any, NO_PROGS)).not.toThrow();
  });

  it("generates a display name for unnamed maps using map_<id>", () => {
    const raw = makeRaw({ id: 99, type: "hash", name: "" });
    const maps = parseMaps([raw], NO_PROGS);
    // Parser uses `map_${id}` for unnamed maps
    expect(maps[0].name).toBe("map_99");
  });

  it("parses multiple maps preserving order", () => {
    const maps = parseMaps([
      makeRaw({ id: 1, type: "hash" }),
      makeRaw({ id: 2, type: "array" }),
      makeRaw({ id: 3, type: "ringbuf" }),
    ], NO_PROGS);
    expect(maps.map(m => m.id)).toEqual([1, 2, 3]);
  });

  it("stores bytesMemlock as raw bytes", () => {
    const maps = parseMaps([makeRaw({ id: 1, type: "hash", bytes_memlock: 32768 })], NO_PROGS);
    expect(maps[0].bytesMemlock).toBe(32768);
  });

  it("assigns a color from MAP_TYPE_META", () => {
    const maps = parseMaps([makeRaw({ id: 1, type: "hash" })], NO_PROGS);
    expect(maps[0].color).toBe(MAP_TYPE_META["hash"].color);
  });
});

describe("MAP_TYPE_META", () => {
  it("exports a non-empty type metadata object", () => {
    expect(Object.keys(MAP_TYPE_META).length).toBeGreaterThan(0);
  });

  it("includes hash, ringbuf, perf_event_array entries", () => {
    expect(MAP_TYPE_META["hash"]).toBeDefined();
    expect(MAP_TYPE_META["ringbuf"]).toBeDefined();
    expect(MAP_TYPE_META["perf_event_array"]).toBeDefined();
  });

  it("assigns correct categories", () => {
    expect(MAP_TYPE_META["hash"].category).toBe("data");
    expect(MAP_TYPE_META["ringbuf"].category).toBe("event");
    expect(MAP_TYPE_META["perf_event_array"].category).toBe("event");
    expect(MAP_TYPE_META["prog_array"].category).toBe("control");
    expect(MAP_TYPE_META["sockmap"].category).toBe("socket");
  });

  it("every entry has a color and description", () => {
    for (const [type, meta] of Object.entries(MAP_TYPE_META)) {
      expect(meta.color, `${type} missing color`).toBeTruthy();
      expect(meta.description, `${type} missing description`).toBeTruthy();
    }
  });
});

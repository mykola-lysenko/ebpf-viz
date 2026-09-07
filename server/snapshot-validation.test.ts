import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import { MAX_DUMP_ENTRIES } from "./ebpf-map-dump";
import {
  mapDumpsUploadSchema,
  snapshotUploadSchema,
} from "../shared/snapshot-validation";

function mockReq(remoteAddress: string) {
  return {
    headers: {},
    socket: { remoteAddress },
  };
}

function makeCaller() {
  return appRouter.createCaller({
    req: mockReq("127.0.0.1") as never,
    res: {} as never,
  });
}

describe("snapshot upload validation", () => {
  it("accepts raw capture-snapshot payloads", () => {
    const result = snapshotUploadSchema.safeParse({
      _ebpfVizSnapshot: true,
      capturedAt: "2026-06-19T00:00:00Z",
      raw: {
        progs: [{ id: 1, type: "xdp", name: "prog" }],
        maps: [{ id: 10, type: "hash", name: "map" }],
        net: [],
        cgroups: [],
      },
    });

    expect(result.success).toBe(true);
  });

  it("rejects marker-only snapshot files", () => {
    const result = snapshotUploadSchema.safeParse({
      _ebpfVizSnapshot: true,
    });

    expect(result.success).toBe(false);
  });

  it("rejects malformed raw program records before parsing", async () => {
    const caller = makeCaller();

    await expect(caller.ebpf.parseSnapshot({
      raw: {
        progs: [{ type: "xdp" }],
      },
    } as never)).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });

  it("parses optional raw tc filter dumps into ordered program chains", async () => {
    const caller = makeCaller();

    const result = await caller.ebpf.parseSnapshot({
      raw: {
        progs: [
          { id: 1, type: "sched_cls", name: "later" },
          { id: 2, type: "sched_cls", name: "earlier" },
        ],
        maps: [],
        net: [
          {
            tc: [
              { devname: "eth0", ifindex: 2, kind: "clsact/ingress", id: 1 },
              { devname: "eth0", ifindex: 2, kind: "clsact/ingress", id: 2 },
            ],
          },
        ],
        tcFilters: [
          {
            devname: "eth0",
            direction: "ingress",
            filters: [
              {
                pref: 20,
                chain: 0,
                options: { handle: "0x2", prog: { id: 1 } },
              },
              {
                pref: 10,
                chain: 0,
                options: { handle: "0x1", prog: { id: 2 } },
              },
            ],
          },
        ],
        cgroups: [],
      },
    });

    expect(
      result.snapshot.programChains[0].programs.map(program => program.id)
    ).toEqual([2, 1]);
  });

  it("parses optional raw effective cgroup trees into chain metadata", async () => {
    const caller = makeCaller();

    const result = await caller.ebpf.parseSnapshot({
      raw: {
        progs: [
          { id: 1, type: "cgroup_skb", name: "parent" },
          { id: 2, type: "cgroup_skb", name: "child" },
        ],
        maps: [],
        net: [],
        cgroups: [
          {
            cgroup: "/sys/fs/cgroup",
            programs: [
              {
                id: 1,
                attach_type: "cgroup_inet_ingress",
                attach_flags: "multi",
              },
            ],
          },
          {
            cgroup: "/sys/fs/cgroup/test.slice",
            programs: [
              {
                id: 2,
                attach_type: "cgroup_inet_ingress",
                attach_flags: "multi",
              },
            ],
          },
        ],
        cgroupsEffective: [
          {
            cgroup: "/sys/fs/cgroup/test.slice",
            programs: [
              { id: 1, attach_type: "cgroup_inet_ingress" },
              { id: 2, attach_type: "cgroup_inet_ingress" },
            ],
          },
        ],
      },
    });

    expect(result.snapshot.programChains[0]).toMatchObject({
      chainSource: "kernel-effective",
      programs: [
        { id: 1, cgroup: { inherited: true } },
        { id: 2, cgroup: { inherited: false } },
      ],
    });
  });
});

describe("map dump upload validation", () => {
  it("accepts map dump payloads keyed by numeric map ID", () => {
    const result = mapDumpsUploadSchema.safeParse({
      _ebpfVizMapDumps: true,
      mapDumps: {
        "10": [{ key: ["0x00"], value: ["0x01"] }],
      },
    });

    expect(result.success).toBe(true);
  });

  it("rejects non-numeric map dump keys", () => {
    const result = mapDumpsUploadSchema.safeParse({
      _ebpfVizMapDumps: true,
      mapDumps: {
        abc: [{ key: ["0x00"], value: ["0x01"] }],
      },
    });

    expect(result.success).toBe(false);
  });

  it("rejects entries without value data", async () => {
    const caller = makeCaller();

    await expect(caller.ebpf.parseMapDumps({
      mapDumps: {
        "10": [{ key: ["0x00"] }],
      },
    } as never)).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });

  it("reports full map dump entry count when server truncates returned entries", async () => {
    const caller = makeCaller();
    const entries = Array.from({ length: MAX_DUMP_ENTRIES + 1 }, (_, index) => ({
      key: ["0x00", `0x${(index % 256).toString(16).padStart(2, "0")}`],
      value: ["0x01"],
    }));

    const result = await caller.ebpf.parseMapDumps({
      mapDumps: {
        "10": entries,
      },
    });

    expect(result[10].totalEntries).toBe(MAX_DUMP_ENTRIES + 1);
    expect(result[10].entries).toHaveLength(MAX_DUMP_ENTRIES);
    expect(result[10].truncated).toBe(true);
  });
});

describe("collection metadata round trips", () => {
  const collection = { sources: {
    progs: { label: "Programs", state: "error" as const, attemptedAt: 2000, lastSuccessAt: 1000, error: "permission denied" },
  }, namespaces: { limit: 64, discovered: 70, scanned: 64, skipped: 0, omitted: 6, discoveryAt: 1000 } };

  it("preserves capture evidence through raw import and parsed snapshot export/reimport", async () => {
    const captured = snapshotUploadSchema.parse({ _ebpfVizSnapshot: true, collection, raw: { progs: [] }, timestamp: 2000 });
    const parsed = await makeCaller().ebpf.parseSnapshot({ raw: captured.raw!, collection: captured.collection, timestamp: captured.timestamp });
    expect(parsed.snapshot.collection).toEqual(collection);
    const exported = JSON.parse(JSON.stringify({ _ebpfVizSnapshot: true, snapshot: parsed.snapshot, maps: parsed.maps }));
    expect(snapshotUploadSchema.parse(exported).snapshot?.collection).toEqual(collection);
  });

  it("leaves coverage unknown for older snapshots and rejects malformed status", async () => {
    const old = await makeCaller().ebpf.parseSnapshot({ raw: { progs: [] } });
    expect(old.snapshot.collection).toBeUndefined();
    expect(snapshotUploadSchema.safeParse({ _ebpfVizSnapshot: true, raw: { progs: [] }, collection: { sources: { progs: { ...collection.sources.progs, state: "healthy" } } } }).success).toBe(false);
  });
});

describe("map dump acquisition evidence", () => {
  it("preserves errors, truncation, counts and unsupported records through upload parsing", async () => {
    const uploaded = mapDumpsUploadSchema.parse({
      _ebpfVizMapDumps: true, _version: 2,
      mapDumps: {
        "1": { entries: [{ key: ["0x01"], value: ["0x02"] }], complete: false, totalEntries: 20, truncated: true, error: "timeout" },
        "2": { entries: [], complete: false, unsupported: true, error: "not enumerable" },
        "3": { entries: [], complete: true },
      },
    });
    const result = await makeCaller().ebpf.parseMapDumps({ mapDumps: uploaded.mapDumps });
    expect(result[1]).toMatchObject({ complete: false, totalEntries: 20, truncated: true, error: "timeout" });
    expect(result[1].entries).toHaveLength(1);
    expect(result[2]).toMatchObject({ complete: false, unsupported: true, error: "not enumerable" });
    expect(result[3]).toMatchObject({ complete: true, truncated: false, error: null, entries: [] });
    expect(JSON.parse(JSON.stringify(result))).toEqual(result);
  });
  it("imports legacy arrays with unknown acquisition completeness", async () => {
    const result = await makeCaller().ebpf.parseMapDumps({ mapDumps: { "1": [] } });
    expect(result[1]).toMatchObject({ entries: [], complete: false, error: null });
  });
  it("rejects contradictory counts and malformed dump metadata", () => {
    for (const dump of [
      { entries: [], complete: "yes" },
      { entries: [], complete: true, truncated: "no" },
      { entries: [{ key: ["0x00"], value: ["0x00"] }], complete: true, totalEntries: 0 },
    ]) expect(mapDumpsUploadSchema.safeParse({ _ebpfVizMapDumps: true, mapDumps: { "1": dump } }).success).toBe(false);
  });
});

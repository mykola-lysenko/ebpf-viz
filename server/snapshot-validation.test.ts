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

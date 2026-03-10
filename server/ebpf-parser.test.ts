import { describe, expect, it } from "vitest";
import {
  parseProgList,
  enrichWithNetAttachments,
  enrichWithCgroupAttachments,
  buildNetworkInterfaces,
  buildCgroupTree,
  buildKernelZones,
  buildSnapshot,
  TYPE_COLORS,
} from "./ebpf-parser";
import type { RawBpfProg, RawNetSnapshot, RawCgroupEntry } from "../shared/ebpf-types";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const xdpProg: RawBpfProg = {
  id: 1,
  type: "xdp",
  name: "my_xdp_prog",
  tag: "aabbccdd11223344",
  gpl_compatible: true,
  loaded_at: 1700000000,
  orphaned: false,
  bytes_xlated: 512,
  jited: true,
  bytes_memlock: 4096,
  run_time_ns: 1234567,
  run_cnt: 9999,
};

const cgroupSkbProg: RawBpfProg = {
  id: 2,
  type: "cgroup_skb",
  name: "",
  tag: "0000000000000000",
  gpl_compatible: true,
  loaded_at: 1700000001,
  orphaned: false,
  bytes_xlated: 64,
  jited: false,
  bytes_memlock: 4096,
};

const kprobeProg: RawBpfProg = {
  id: 3,
  type: "kprobe",
  name: "trace_sys_open",
  tag: "deadbeefcafebabe",
  gpl_compatible: false,
  loaded_at: 1700000002,
  orphaned: false,
  bytes_xlated: 256,
  jited: true,
  bytes_memlock: 4096,
  btf_id: 42,
  pids: [{ pid: 1234, comm: "my_tracer" }],
};

const orphanedProg: RawBpfProg = {
  id: 4,
  type: "sched_cls",
  name: "tc_filter",
  tag: "1111111111111111",
  gpl_compatible: true,
  loaded_at: 1700000003,
  orphaned: true,
  bytes_xlated: 128,
  jited: false,
  bytes_memlock: 4096,
};

// ─── parseProgList ─────────────────────────────────────────────────────────────

describe("parseProgList", () => {
  it("parses a basic XDP program correctly", () => {
    const map = parseProgList([xdpProg]);
    const prog = map.get(1);
    expect(prog).toBeDefined();
    expect(prog!.id).toBe(1);
    expect(prog!.name).toBe("my_xdp_prog");
    expect(prog!.rawType).toBe("xdp");
    expect(prog!.type).toBe("xdp");
    expect(prog!.jited).toBe(true);
    expect(prog!.gplCompatible).toBe(true);
    expect(prog!.bytesXlated).toBe(512);
    expect(prog!.runTimeNs).toBe(1234567);
    expect(prog!.runCnt).toBe(9999);
    expect(prog!.tag).toBe("aabbccdd11223344");
  });

  it("generates a fallback name for unnamed programs", () => {
    const map = parseProgList([cgroupSkbProg]);
    const prog = map.get(2);
    expect(prog!.name).toBe("cgroup_skb_2");
  });

  it("assigns correct OSI layer for XDP", () => {
    const map = parseProgList([xdpProg]);
    expect(map.get(1)!.osiLayer).toBe("L2");
  });

  it("assigns correct OSI layer for cgroup_skb", () => {
    const map = parseProgList([cgroupSkbProg]);
    // cgroup_skb is classified as L4 (socket/transport layer hook)
    expect(map.get(2)!.osiLayer).toBe("L4");
  });

  it("assigns correct OSI layer for kprobe", () => {
    const map = parseProgList([kprobeProg]);
    expect(map.get(3)!.osiLayer).toBe("kernel");
  });

  it("preserves BTF ID and pids", () => {
    const map = parseProgList([kprobeProg]);
    const prog = map.get(3)!;
    expect(prog.btfId).toBe(42);
    expect(prog.pids).toEqual([{ pid: 1234, comm: "my_tracer" }]);
  });

  it("marks orphaned programs correctly", () => {
    const map = parseProgList([orphanedProg]);
    expect(map.get(4)!.orphaned).toBe(true);
  });

  it("assigns a color for each program type", () => {
    const map = parseProgList([xdpProg, cgroupSkbProg, kprobeProg]);
    for (const prog of map.values()) {
      expect(prog.color).toBeTruthy();
      expect(prog.color).toMatch(/^#[0-9a-f]{6}$/i);
    }
  });

  it("handles empty input", () => {
    const map = parseProgList([]);
    expect(map.size).toBe(0);
  });

  it("handles multiple programs", () => {
    const map = parseProgList([xdpProg, cgroupSkbProg, kprobeProg, orphanedProg]);
    expect(map.size).toBe(4);
  });
});

// ─── enrichWithNetAttachments ─────────────────────────────────────────────────

describe("enrichWithNetAttachments", () => {
  it("attaches XDP program to correct interface", () => {
    const progs = parseProgList([xdpProg]);
    const net: RawNetSnapshot[] = [{
      xdp: [{ devname: "eth0", ifindex: 2, mode: "driver", id: 1, name: "my_xdp_prog" }],
    }];
    enrichWithNetAttachments(progs, net);
    const prog = progs.get(1)!;
    expect(prog.attachments).toHaveLength(1);
    expect(prog.attachments[0].kind).toBe("xdp");
    expect(prog.attachments[0].ifname).toBe("eth0");
    expect(prog.attachments[0].detail).toContain("eth0");
  });

  it("attaches TC program with correct kind", () => {
    const tcProg: RawBpfProg = { ...xdpProg, id: 10, type: "sched_cls", name: "tc_prog" };
    const progs = parseProgList([tcProg]);
    const net: RawNetSnapshot[] = [{
      tc: [{ devname: "eth0", ifindex: 2, id: 10, name: "tc_prog", kind: "filter" }],
    }];
    enrichWithNetAttachments(progs, net);
    const prog = progs.get(10)!;
    expect(prog.attachments[0].kind).toBe("tc");
    expect(prog.attachments[0].ifname).toBe("eth0");
  });

  it("ignores programs not in the prog map", () => {
    const progs = parseProgList([xdpProg]);
    const net: RawNetSnapshot[] = [{
      xdp: [{ devname: "eth0", ifindex: 2, mode: "driver", id: 999, name: "unknown" }],
    }];
    // Should not throw
    expect(() => enrichWithNetAttachments(progs, net)).not.toThrow();
    expect(progs.get(1)!.attachments).toHaveLength(0);
  });
});

// ─── enrichWithCgroupAttachments ──────────────────────────────────────────────

describe("enrichWithCgroupAttachments", () => {
  it("attaches cgroup program with correct path and attach type", () => {
    const progs = parseProgList([cgroupSkbProg]);
    const cgroups: RawCgroupEntry[] = [{
      cgroup: "/sys/fs/cgroup/system.slice/test.service",
      programs: [{
        id: 2,
        attach_type: "cgroup_inet_ingress",
        attach_flags: "multi",
        name: "",
        attach_btf_obj_id: 0,
        attach_btf_id: 0,
      }],
    }];
    enrichWithCgroupAttachments(progs, cgroups);
    const prog = progs.get(2)!;
    expect(prog.attachments).toHaveLength(1);
    expect(prog.attachments[0].kind).toBe("cgroup");
    expect(prog.attachments[0].cgroupPath).toBe("/sys/fs/cgroup/system.slice/test.service");
    expect(prog.attachments[0].attachFlags).toBe("multi");
  });
});

// ─── buildNetworkInterfaces ───────────────────────────────────────────────────

describe("buildNetworkInterfaces", () => {
  it("creates interface entries for each unique interface", () => {
    const progs = parseProgList([xdpProg]);
    const net: RawNetSnapshot[] = [{
      xdp: [{ devname: "eth0", ifindex: 2, mode: "driver", id: 1, name: "my_xdp_prog" }],
    }];
    enrichWithNetAttachments(progs, net);
    const interfaces = buildNetworkInterfaces(progs, net);
    expect(interfaces.length).toBeGreaterThanOrEqual(1);
    const eth0 = interfaces.find(i => i.name === "eth0");
    expect(eth0).toBeDefined();
    expect(eth0!.layers.L2).toHaveLength(1);
    expect(eth0!.allPrograms).toHaveLength(1);
  });

  it("places XDP programs in L2 layer", () => {
    const progs = parseProgList([xdpProg]);
    const net: RawNetSnapshot[] = [{
      xdp: [{ devname: "eth0", ifindex: 2, mode: "driver", id: 1, name: "my_xdp_prog" }],
    }];
    enrichWithNetAttachments(progs, net);
    const interfaces = buildNetworkInterfaces(progs, net);
    const eth0 = interfaces.find(i => i.name === "eth0")!;
    expect(eth0.layers.L2[0].id).toBe(1);
    expect(eth0.layers.L3).toHaveLength(0);
  });
});

// ─── buildCgroupTree ──────────────────────────────────────────────────────────

describe("buildCgroupTree", () => {
  it("builds a flat tree from cgroup entries", () => {
    const progs = parseProgList([cgroupSkbProg]);
    const cgroups: RawCgroupEntry[] = [{
      cgroup: "/sys/fs/cgroup/system.slice/test.service",
      programs: [{ id: 2, attach_type: "cgroup_inet_ingress", attach_flags: "multi", name: "" }],
    }];
    enrichWithCgroupAttachments(progs, cgroups);
    const tree = buildCgroupTree(progs, cgroups);
    expect(tree.length).toBeGreaterThanOrEqual(1);
    // Find the leaf node
    const findNode = (nodes: typeof tree, path: string): (typeof tree)[0] | undefined => {
      for (const n of nodes) {
        if (n.path === path) return n;
        const found = findNode(n.children, path);
        if (found) return found;
      }
    };
    const leaf = findNode(tree, "/sys/fs/cgroup/system.slice/test.service");
    expect(leaf).toBeDefined();
    expect(leaf!.programs).toHaveLength(1);
    expect(leaf!.programs[0].id).toBe(2);
  });

  it("handles empty cgroup list", () => {
    const progs = parseProgList([]);
    const tree = buildCgroupTree(progs, []);
    expect(tree).toEqual([]);
  });
});

// ─── buildKernelZones ─────────────────────────────────────────────────────────

describe("buildKernelZones", () => {
  it("places XDP programs in xdp zone", () => {
    const progs = parseProgList([xdpProg]);
    const zones = buildKernelZones(progs);
    const xdpZone = zones.find(z => z.zone === "xdp");
    expect(xdpZone).toBeDefined();
    expect(xdpZone!.programs).toHaveLength(1);
    expect(xdpZone!.programs[0].id).toBe(1);
  });

  it("places kprobe programs in kprobe zone", () => {
    const progs = parseProgList([kprobeProg]);
    const zones = buildKernelZones(progs);
    const kprobeZone = zones.find(z => z.zone === "kprobe");
    expect(kprobeZone).toBeDefined();
    expect(kprobeZone!.programs).toHaveLength(1);
  });

  it("places cgroup_skb in cgroup zone", () => {
    const progs = parseProgList([cgroupSkbProg]);
    const zones = buildKernelZones(progs);
    const cgroupZone = zones.find(z => z.zone === "cgroup");
    expect(cgroupZone).toBeDefined();
    expect(cgroupZone!.programs).toHaveLength(1);
  });

  it("only includes zones with programs", () => {
    const progs = parseProgList([xdpProg]);
    const zones = buildKernelZones(progs);
    for (const zone of zones) {
      expect(zone.programs.length).toBeGreaterThan(0);
    }
  });
});

// ─── TYPE_COLORS ──────────────────────────────────────────────────────────────

describe("TYPE_COLORS", () => {
  it("has a color for xdp", () => {
    expect(TYPE_COLORS["xdp"]).toBeDefined();
    expect(TYPE_COLORS["xdp"]).toMatch(/^#[0-9a-f]{6}$/i);
  });

  it("has a fallback unknown color", () => {
    expect(TYPE_COLORS["unknown"]).toBeDefined();
  });
});

// ─── buildSnapshot ────────────────────────────────────────────────────────────

describe("buildSnapshot", () => {
  it("builds a complete snapshot from raw data", () => {
    const snapshot = buildSnapshot(
      [xdpProg, cgroupSkbProg, kprobeProg],
      [{ xdp: [{ devname: "eth0", ifindex: 2, mode: "driver", id: 1, name: "my_xdp_prog" }] }],
      [{
        cgroup: "/sys/fs/cgroup/system.slice/test.service",
        programs: [{ id: 2, attach_type: "cgroup_inet_ingress", attach_flags: "multi", name: "" }],
      }],
      { hostname: "test-host", kernelVersion: "6.1.0", bpftoolVersion: "7.3.0", demoMode: false }
    );

    expect(snapshot.hostname).toBe("test-host");
    expect(snapshot.kernelVersion).toBe("6.1.0");
    expect(snapshot.demoMode).toBe(false);
    expect(snapshot.programs).toHaveLength(3);
    expect(snapshot.stats.total).toBe(3);
    expect(snapshot.stats.jited).toBe(2); // xdp and kprobe are jited
    expect(snapshot.stats.orphaned).toBe(0);
    expect(snapshot.networkInterfaces.length).toBeGreaterThanOrEqual(1);
    expect(snapshot.cgroupTree.length).toBeGreaterThanOrEqual(1);
    expect(snapshot.kernelZones.length).toBeGreaterThan(0);
  });

  it("counts orphaned programs correctly", () => {
    const snapshot = buildSnapshot(
      [orphanedProg],
      [{}],
      [],
      { hostname: "h", kernelVersion: "6.0", bpftoolVersion: "7.0", demoMode: false }
    );
    expect(snapshot.stats.orphaned).toBe(1);
  });

  it("counts byType correctly", () => {
    const snapshot = buildSnapshot(
      [xdpProg, cgroupSkbProg, cgroupSkbProg],
      [{}],
      [],
      { hostname: "h", kernelVersion: "6.0", bpftoolVersion: "7.0", demoMode: false }
    );
    // Note: duplicate IDs will be deduplicated by the Map
    expect(snapshot.stats.byType["xdp"]).toBe(1);
    expect(snapshot.stats.byType["cgroup_skb"]).toBe(1);
  });

  it("sets timestamp as a recent unix timestamp (ms)", () => {
    const before = Date.now();
    const snapshot = buildSnapshot([], [{}], [], {
      hostname: "h", kernelVersion: "6.0", bpftoolVersion: "7.0", demoMode: false
    });
    const after = Date.now();
    // timestamp is in milliseconds
    expect(snapshot.timestamp).toBeGreaterThanOrEqual(before);
    expect(snapshot.timestamp).toBeLessThanOrEqual(after);
  });
});

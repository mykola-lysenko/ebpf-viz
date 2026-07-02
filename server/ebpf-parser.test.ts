import { describe, expect, it } from "vitest";
import {
  parseProgList,
  enrichWithNetAttachments,
  enrichWithCgroupAttachments,
  enrichWithLinkAttachments,
  buildNetworkInterfaces,
  buildCgroupTree,
  buildKernelZones,
  buildProgramChains,
  buildSnapshot,
} from "./ebpf-parser";
import { BPF_PROGRAM_TYPE_COLORS } from "../shared/ebpf-constants";
import type {
  RawBpfProg,
  RawNetSnapshot,
  RawCgroupEntry,
} from "../shared/ebpf-types";

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

const cgroupSockAddrProg: RawBpfProg = {
  id: 5,
  type: "cgroup_sock_addr",
  name: "inet6_connect_guard",
  tag: "0000000000000005",
  gpl_compatible: true,
  loaded_at: 1700000004,
  orphaned: false,
  bytes_xlated: 96,
  jited: true,
  bytes_memlock: 4096,
};

const cgroupSockProg: RawBpfProg = {
  id: 6,
  type: "cgroup_sock",
  name: "post_bind_guard",
  tag: "0000000000000006",
  gpl_compatible: true,
  loaded_at: 1700000005,
  orphaned: false,
  bytes_xlated: 96,
  jited: true,
  bytes_memlock: 4096,
};

const cgroupSockoptProg: RawBpfProg = {
  id: 7,
  type: "cgroup_sockopt",
  name: "sockopt_guard",
  tag: "0000000000000007",
  gpl_compatible: true,
  loaded_at: 1700000006,
  orphaned: false,
  bytes_xlated: 96,
  jited: true,
  bytes_memlock: 4096,
};

const CGROUP_SOCKET_SIDE_EFFECT_SUMMARY =
  "This cgroup socket hook affects socket state/options rather than packet forwarding. eBPF Viz reports side effects but does not model its return value as a packet allow/drop verdict.";

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

const structOpsProg: RawBpfProg = {
  id: 8,
  type: "struct_ops",
  name: "tcp_init",
  tag: "0000000000000008",
  gpl_compatible: true,
  loaded_at: 1700000007,
  orphaned: false,
  bytes_xlated: 2440,
  jited: true,
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

  it("marks programs as JITed when bpftool reports bytes_jited without a jited boolean", () => {
    const map = parseProgList([
      {
        ...xdpProg,
        id: 99,
        jited: undefined,
        bytes_jited: 384,
      },
    ]);

    expect(map.get(99)!.jited).toBe(true);
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

  it("recognizes cgroup_sock_addr programs used by connect/bind hooks", () => {
    const map = parseProgList([cgroupSockAddrProg]);
    const prog = map.get(5)!;
    expect(prog.type).toBe("cgroup_sock_addr");
    expect(prog.osiLayer).toBe("L4");
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

  it("classifies real bpftool type strings for BTF-based programs (tracing/ext)", () => {
    // bpftool reports fentry/fexit/iter as "tracing" and freplace as "ext";
    // it never emits "fentry"/"fexit"/"freplace" in prog list output.
    const map = parseProgList([
      { ...xdpProg, id: 30, type: "tracing", name: "fentry__tcp_connect" },
      { ...xdpProg, id: 31, type: "ext", name: "freplace_xdp_pass" },
      { ...xdpProg, id: 32, type: "sk_reuseport", name: "select_sock" },
      { ...xdpProg, id: 33, type: "syscall", name: "bpf_loader" },
    ]);
    expect(map.get(30)!.type).toBe("tracing");
    expect(map.get(31)!.type).toBe("freplace");
    expect(map.get(32)!.type).toBe("sk_reuseport");
    expect(map.get(33)!.type).toBe("syscall");
    for (const id of [30, 31, 32, 33]) {
      expect(map.get(id)!.type).not.toBe("unknown");
      expect(map.get(id)!.color).not.toBe(BPF_PROGRAM_TYPE_COLORS.unknown);
    }
    expect(map.get(32)!.osiLayer).toBe("L4");
  });

  it("handles empty input", () => {
    const map = parseProgList([]);
    expect(map.size).toBe(0);
  });

  it("handles multiple programs", () => {
    const map = parseProgList([
      xdpProg,
      cgroupSkbProg,
      kprobeProg,
      orphanedProg,
    ]);
    expect(map.size).toBe(4);
  });
});

// ─── enrichWithLinkAttachments ────────────────────────────────────────────────

describe("enrichWithLinkAttachments", () => {
  const tracingProg: RawBpfProg = {
    id: 50,
    type: "tracing",
    name: "fentry__tcp_close",
    tag: "1111111111111111",
    gpl_compatible: true,
    loaded_at: 1700000000,
    orphaned: false,
    bytes_xlated: 128,
    jited: true,
    bytes_memlock: 4096,
  };
  const kprobeRawProg: RawBpfProg = { ...tracingProg, id: 51, type: "kprobe", name: "probe_prog" };

  it("refines tracing programs to fentry/fexit from the link attach_type", () => {
    const progs = parseProgList([tracingProg, { ...tracingProg, id: 52 }]);
    enrichWithLinkAttachments(progs, [
      { id: 1, type: "tracing", prog_id: 50, attach_type: "trace_fentry", target_btf_id: 123 },
      { id: 2, type: "tracing", prog_id: 52, attach_type: "trace_fexit" },
    ]);
    expect(progs.get(50)!.type).toBe("fentry");
    expect(progs.get(52)!.type).toBe("fexit");
    expect(progs.get(50)!.color).toBe(BPF_PROGRAM_TYPE_COLORS.fentry);
    expect(progs.get(50)!.rawType).toBe("tracing");
    expect(progs.get(50)!.attachments).toEqual([
      { kind: "link", detail: "trace_fentry → btf_id 123", linkId: 1 },
    ]);
  });

  it("refines kprobe programs via perf links (kretprobe, uprobe, uretprobe)", () => {
    const progs = parseProgList([
      kprobeRawProg,
      { ...kprobeRawProg, id: 53 },
      { ...kprobeRawProg, id: 54 },
    ]);
    enrichWithLinkAttachments(progs, [
      { id: 3, type: "perf", prog_id: 51, func: "do_sys_open", retprobe: true },
      { id: 4, type: "perf", prog_id: 53, file: "/usr/bin/node", offset: 0x1234, retprobe: false },
      { id: 5, type: "perf", prog_id: 54, file: "/usr/bin/node", retprobe: true },
    ]);
    expect(progs.get(51)!.type).toBe("kretprobe");
    expect(progs.get(51)!.attachments[0].detail).toBe("kretprobe do_sys_open");
    expect(progs.get(53)!.type).toBe("uprobe");
    expect(progs.get(53)!.attachments[0].detail).toBe("uprobe /usr/bin/node+0x1234");
    expect(progs.get(54)!.type).toBe("uretprobe");
  });

  it("attributes ownership from link pids when the program has none", () => {
    const progs = parseProgList([tracingProg]);
    enrichWithLinkAttachments(progs, [
      {
        id: 6,
        type: "tracing",
        prog_id: 50,
        attach_type: "trace_fentry",
        pids: [{ pid: 388, comm: "systemd" }],
      },
    ]);
    expect(progs.get(50)!.pids).toEqual([{ pid: 388, comm: "systemd" }]);
  });

  it("does not overwrite existing program pids with link pids", () => {
    const progs = parseProgList([
      { ...tracingProg, pids: [{ pid: 42, comm: "loader" }] },
    ]);
    enrichWithLinkAttachments(progs, [
      { id: 7, type: "tracing", prog_id: 50, pids: [{ pid: 388, comm: "systemd" }] },
    ]);
    expect(progs.get(50)!.pids).toEqual([{ pid: 42, comm: "loader" }]);
  });

  it("skips attachments for link types covered by net/cgroup sources", () => {
    const progs = parseProgList([xdpProg, cgroupSkbProg]);
    enrichWithLinkAttachments(progs, [
      { id: 8, type: "xdp", prog_id: 1, ifindex: 2 },
      { id: 9, type: "cgroup", prog_id: 2, cgroup_id: 4321, attach_type: "cgroup_inet_ingress" },
    ]);
    expect(progs.get(1)!.attachments).toEqual([]);
    expect(progs.get(2)!.attachments).toEqual([]);
  });

  it("still adopts pids from net/cgroup-covered link types", () => {
    const progs = parseProgList([cgroupSkbProg]);
    enrichWithLinkAttachments(progs, [
      { id: 10, type: "cgroup", prog_id: 2, pids: [{ pid: 1, comm: "systemd" }] },
    ]);
    expect(progs.get(2)!.pids).toEqual([{ pid: 1, comm: "systemd" }]);
  });

  it("ignores links without a prog_id or with unknown prog ids", () => {
    const progs = parseProgList([xdpProg]);
    enrichWithLinkAttachments(progs, [
      { id: 11, type: "iter", target_name: "bpf_map" },
      { id: 12, type: "tracing", prog_id: 9999 },
    ]);
    expect(progs.get(1)!.attachments).toEqual([]);
  });

  it("describes raw_tracepoint, kprobe_multi, and iter links", () => {
    const progs = parseProgList([
      { ...kprobeRawProg, id: 60, type: "raw_tracepoint" },
      { ...kprobeRawProg, id: 61 },
      { ...kprobeRawProg, id: 62, type: "tracing" },
    ]);
    enrichWithLinkAttachments(progs, [
      { id: 13, type: "raw_tracepoint", prog_id: 60, tp_name: "sched_switch" },
      { id: 14, type: "kprobe_multi", prog_id: 61, retprobe: false, func_cnt: 12 },
      { id: 15, type: "iter", prog_id: 62, target_name: "task_file" },
    ]);
    expect(progs.get(60)!.attachments[0].detail).toBe("raw_tp sched_switch");
    expect(progs.get(61)!.attachments[0].detail).toBe("kprobe.multi (12 funcs)");
    expect(progs.get(62)!.attachments[0].detail).toBe("iter task_file");
  });
});

// ─── enrichWithNetAttachments ─────────────────────────────────────────────────

describe("enrichWithNetAttachments", () => {
  it("attaches XDP program to correct interface", () => {
    const progs = parseProgList([xdpProg]);
    const net: RawNetSnapshot[] = [
      {
        xdp: [
          {
            devname: "eth0",
            ifindex: 2,
            mode: "driver",
            id: 1,
            name: "my_xdp_prog",
          },
        ],
      },
    ];
    enrichWithNetAttachments(progs, net);
    const prog = progs.get(1)!;
    expect(prog.attachments).toHaveLength(1);
    expect(prog.attachments[0].kind).toBe("xdp");
    expect(prog.attachments[0].ifname).toBe("eth0");
    expect(prog.attachments[0].detail).toContain("eth0");
  });

  it("attaches TC program with correct kind", () => {
    const tcProg: RawBpfProg = {
      ...xdpProg,
      id: 10,
      type: "sched_cls",
      name: "tc_prog",
    };
    const progs = parseProgList([tcProg]);
    const net: RawNetSnapshot[] = [
      {
        tc: [
          {
            devname: "eth0",
            ifindex: 2,
            id: 10,
            name: "tc_prog",
            kind: "filter",
          },
        ],
      },
    ];
    enrichWithNetAttachments(progs, net);
    const prog = progs.get(10)!;
    expect(prog.attachments[0].kind).toBe("tc");
    expect(prog.attachments[0].ifname).toBe("eth0");
  });

  it("sets direction=ingress for clsact/ingress TC attachment", () => {
    const tcProg: RawBpfProg = {
      ...xdpProg,
      id: 11,
      type: "sched_cls",
      name: "cls_ingress",
    };
    const progs = parseProgList([tcProg]);
    const net: RawNetSnapshot[] = [
      {
        tc: [
          {
            devname: "eth0",
            ifindex: 2,
            id: 11,
            name: "cls_ingress",
            kind: "clsact/ingress",
          },
        ],
      },
    ];
    enrichWithNetAttachments(progs, net);
    const prog = progs.get(11)!;
    expect(prog.attachments[0].direction).toBe("ingress");
  });

  it("sets direction=egress for clsact/egress TC attachment", () => {
    const tcProg: RawBpfProg = {
      ...xdpProg,
      id: 12,
      type: "sched_cls",
      name: "cls_egress",
    };
    const progs = parseProgList([tcProg]);
    const net: RawNetSnapshot[] = [
      {
        tc: [
          {
            devname: "eth0",
            ifindex: 2,
            id: 12,
            name: "cls_egress",
            kind: "clsact/egress",
          },
        ],
      },
    ];
    enrichWithNetAttachments(progs, net);
    const prog = progs.get(12)!;
    expect(prog.attachments[0].direction).toBe("egress");
  });

  it("sets direction=undefined for TC attachment without ingress/egress in kind", () => {
    const tcProg: RawBpfProg = {
      ...xdpProg,
      id: 13,
      type: "sched_cls",
      name: "tc_generic",
    };
    const progs = parseProgList([tcProg]);
    const net: RawNetSnapshot[] = [
      {
        tc: [
          {
            devname: "eth0",
            ifindex: 2,
            id: 13,
            name: "tc_generic",
            kind: "filter",
          },
        ],
      },
    ];
    enrichWithNetAttachments(progs, net);
    const prog = progs.get(13)!;
    expect(prog.attachments[0].direction).toBeUndefined();
  });

  it("sets direction for TCx ingress/egress attachments", () => {
    const tcxIngress: RawBpfProg = {
      ...xdpProg,
      id: 14,
      type: "sched_cls",
      name: "tcx_in",
    };
    const tcxEgress: RawBpfProg = {
      ...xdpProg,
      id: 15,
      type: "sched_cls",
      name: "tcx_out",
    };
    const progs = parseProgList([tcxIngress, tcxEgress]);
    const net: RawNetSnapshot[] = [
      {
        tcx: [
          { devname: "eth0", ifindex: 2, id: 14, kind: "tcx/ingress" },
          { devname: "eth0", ifindex: 2, id: 15, kind: "tcx/egress" },
        ],
      },
    ];
    enrichWithNetAttachments(progs, net);
    expect(progs.get(14)!.attachments[0].direction).toBe("ingress");
    expect(progs.get(15)!.attachments[0].direction).toBe("egress");
  });

  it("ignores programs not in the prog map", () => {
    const progs = parseProgList([xdpProg]);
    const net: RawNetSnapshot[] = [
      {
        xdp: [
          {
            devname: "eth0",
            ifindex: 2,
            mode: "driver",
            id: 999,
            name: "unknown",
          },
        ],
      },
    ];
    // Should not throw
    expect(() => enrichWithNetAttachments(progs, net)).not.toThrow();
    expect(progs.get(1)!.attachments).toHaveLength(0);
  });
});

// ─── enrichWithCgroupAttachments ──────────────────────────────────────────────

describe("enrichWithCgroupAttachments", () => {
  it("attaches cgroup program with correct path and attach type", () => {
    const progs = parseProgList([cgroupSkbProg]);
    const cgroups: RawCgroupEntry[] = [
      {
        cgroup: "/sys/fs/cgroup/system.slice/test.service",
        programs: [
          {
            id: 2,
            attach_type: "cgroup_inet_ingress",
            attach_flags: "multi",
            name: "",
            attach_btf_obj_id: 0,
            attach_btf_id: 0,
          },
        ],
      },
    ];
    enrichWithCgroupAttachments(progs, cgroups);
    const prog = progs.get(2)!;
    expect(prog.attachments).toHaveLength(1);
    expect(prog.attachments[0].kind).toBe("cgroup");
    expect(prog.attachments[0].cgroupPath).toBe(
      "/sys/fs/cgroup/system.slice/test.service"
    );
    expect(prog.attachments[0].attachFlags).toBe("multi");
  });
});

// ─── buildNetworkInterfaces ───────────────────────────────────────────────────

describe("buildNetworkInterfaces", () => {
  it("creates interface entries for each unique interface", () => {
    const progs = parseProgList([xdpProg]);
    const net: RawNetSnapshot[] = [
      {
        xdp: [
          {
            devname: "eth0",
            ifindex: 2,
            mode: "driver",
            id: 1,
            name: "my_xdp_prog",
          },
        ],
      },
    ];
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
    const net: RawNetSnapshot[] = [
      {
        xdp: [
          {
            devname: "eth0",
            ifindex: 2,
            mode: "driver",
            id: 1,
            name: "my_xdp_prog",
          },
        ],
      },
    ];
    enrichWithNetAttachments(progs, net);
    const interfaces = buildNetworkInterfaces(progs, net);
    const eth0 = interfaces.find(i => i.name === "eth0")!;
    expect(eth0.kind).toBe("nic");
    expect(eth0.layers.L2[0].id).toBe(1);
    expect(eth0.layers.L3).toHaveLength(0);
  });

  it("places netfilter programs in L3 layer", () => {
    const nfProg: RawBpfProg = {
      id: 50,
      type: "netfilter",
      name: "nf_hook",
      tag: "aabbccdd00000050",
      gpl_compatible: true,
      loaded_at: 1700000010,
      orphaned: false,
      bytes_xlated: 128,
      jited: false,
      bytes_memlock: 4096,
    };
    const progs = parseProgList([nfProg]);
    const net: RawNetSnapshot[] = [
      {
        netfilter: [{ devname: "eth0", ifindex: 2, id: 50 }],
      },
    ];
    enrichWithNetAttachments(progs, net);
    const interfaces = buildNetworkInterfaces(progs, net);
    const eth0 = interfaces.find(i => i.name === "eth0")!;
    expect(eth0.layers.L3).toHaveLength(1);
    expect(eth0.layers.L3[0].id).toBe(50);
    expect(eth0.layers.L4).toHaveLength(0);
  });

  it("places flow_dissector programs in L3 layer (not L4)", () => {
    const fdProg: RawBpfProg = {
      id: 51,
      type: "flow_dissector",
      name: "custom_dissector",
      tag: "aabbccdd00000051",
      gpl_compatible: true,
      loaded_at: 1700000011,
      orphaned: false,
      bytes_xlated: 192,
      jited: true,
      bytes_memlock: 4096,
    };
    const progs = parseProgList([fdProg]);
    const net: RawNetSnapshot[] = [
      {
        flow_dissector: [{ devname: "eth0", ifindex: 2, id: 51 }],
      },
    ];
    enrichWithNetAttachments(progs, net);
    const interfaces = buildNetworkInterfaces(progs, net);
    const eth0 = interfaces.find(i => i.name === "eth0")!;
    expect(eth0.layers.L3).toHaveLength(1);
    expect(eth0.layers.L3[0].id).toBe(51);
    expect(eth0.layers.L4).toHaveLength(0);
  });

  it("places sk_skb and sk_lookup sockmap programs in L4 layer", () => {
    const skSkbProg: RawBpfProg = {
      id: 52,
      type: "sk_skb",
      name: "sk_skb_verdict",
      tag: "aabbccdd00000052",
      gpl_compatible: true,
      loaded_at: 1700000012,
      orphaned: false,
      bytes_xlated: 256,
      jited: true,
      bytes_memlock: 4096,
    };
    const skLookupProg: RawBpfProg = {
      id: 53,
      type: "sk_lookup",
      name: "sk_lookup_dispatch",
      tag: "aabbccdd00000053",
      gpl_compatible: true,
      loaded_at: 1700000013,
      orphaned: false,
      bytes_xlated: 192,
      jited: true,
      bytes_memlock: 4096,
    };
    const progs = parseProgList([skSkbProg, skLookupProg]);
    const net: RawNetSnapshot[] = [
      {
        sockmap: [
          { devname: "sockmap0", ifindex: 0, kind: "sk_skb", id: 52 },
          { devname: "sockmap0", ifindex: 0, kind: "sk_lookup", id: 53 },
        ],
      },
    ];
    enrichWithNetAttachments(progs, net);
    const interfaces = buildNetworkInterfaces(progs, net);
    const sm = interfaces.find(i => i.name === "sockmap0")!;
    expect(sm).toBeDefined();
    expect(sm.kind).toBe("sockmap");
    expect(sm.layers.L4).toHaveLength(2);
    expect(sm.layers.L4.map(p => p.id)).toEqual(
      expect.arrayContaining([52, 53])
    );
    expect(sm.layers.L7).toHaveLength(0);
  });

  it("places sk_msg and sock_ops sockmap programs in L7 layer", () => {
    const skMsgProg: RawBpfProg = {
      id: 54,
      type: "sk_msg",
      name: "sk_msg_redirect",
      tag: "aabbccdd00000054",
      gpl_compatible: true,
      loaded_at: 1700000014,
      orphaned: false,
      bytes_xlated: 320,
      jited: true,
      bytes_memlock: 4096,
    };
    const sockOpsProg: RawBpfProg = {
      id: 55,
      type: "sock_ops",
      name: "sockops_rtt",
      tag: "aabbccdd00000055",
      gpl_compatible: true,
      loaded_at: 1700000015,
      orphaned: false,
      bytes_xlated: 448,
      jited: true,
      bytes_memlock: 4096,
    };
    const progs = parseProgList([skMsgProg, sockOpsProg]);
    const net: RawNetSnapshot[] = [
      {
        sockmap: [
          { devname: "sockmap0", ifindex: 0, kind: "sk_msg", id: 54 },
          { devname: "sockmap0", ifindex: 0, kind: "sockops", id: 55 },
        ],
      },
    ];
    enrichWithNetAttachments(progs, net);
    const interfaces = buildNetworkInterfaces(progs, net);
    const sm = interfaces.find(i => i.name === "sockmap0")!;
    expect(sm).toBeDefined();
    expect(sm.kind).toBe("sockmap");
    expect(sm.layers.L7).toHaveLength(2);
    expect(sm.layers.L7.map(p => p.id)).toEqual(
      expect.arrayContaining([54, 55])
    );
    expect(sm.layers.L4).toHaveLength(0);
  });

  it("sockmap interface with all 4 layers populated validates full stack", () => {
    const progs = parseProgList([
      {
        id: 60,
        type: "xdp",
        name: "xdp_prog",
        tag: "aa00000000000060",
        gpl_compatible: true,
        loaded_at: 1700000020,
        orphaned: false,
        bytes_xlated: 128,
        jited: true,
        bytes_memlock: 4096,
      },
      {
        id: 61,
        type: "sched_cls",
        name: "tc_prog",
        tag: "aa00000000000061",
        gpl_compatible: true,
        loaded_at: 1700000021,
        orphaned: false,
        bytes_xlated: 256,
        jited: true,
        bytes_memlock: 4096,
      },
      {
        id: 62,
        type: "sk_skb",
        name: "sk_skb_prog",
        tag: "aa00000000000062",
        gpl_compatible: true,
        loaded_at: 1700000022,
        orphaned: false,
        bytes_xlated: 192,
        jited: true,
        bytes_memlock: 4096,
      },
      {
        id: 63,
        type: "sk_msg",
        name: "sk_msg_prog",
        tag: "aa00000000000063",
        gpl_compatible: true,
        loaded_at: 1700000023,
        orphaned: false,
        bytes_xlated: 160,
        jited: true,
        bytes_memlock: 4096,
      },
    ]);
    const net: RawNetSnapshot[] = [
      {
        xdp: [{ devname: "eth0", ifindex: 2, id: 60 }],
        tc: [{ devname: "eth0", ifindex: 2, id: 61 }],
        sockmap: [
          { devname: "sockmap0", ifindex: 0, kind: "sk_skb", id: 62 },
          { devname: "sockmap0", ifindex: 0, kind: "sk_msg", id: 63 },
        ],
      },
    ];
    enrichWithNetAttachments(progs, net);
    const interfaces = buildNetworkInterfaces(progs, net);
    // eth0 has kind=nic, L2 (XDP) and L3 (TC)
    const eth0 = interfaces.find(i => i.name === "eth0")!;
    expect(eth0.kind).toBe("nic");
    expect(eth0.layers.L2).toHaveLength(1);
    expect(eth0.layers.L3).toHaveLength(1);
    expect(eth0.layers.L4).toHaveLength(0);
    expect(eth0.layers.L7).toHaveLength(0);
    // sockmap0 has kind=sockmap, L4 (sk_skb) and L7 (sk_msg)
    const sm = interfaces.find(i => i.name === "sockmap0")!;
    expect(sm.kind).toBe("sockmap");
    expect(sm.layers.L4).toHaveLength(1);
    expect(sm.layers.L7).toHaveLength(1);
    expect(sm.layers.L2).toHaveLength(0);
    expect(sm.layers.L3).toHaveLength(0);
  });
});

// ─── buildProgramChains ───────────────────────────────────────────────────────

describe("buildProgramChains", () => {
  function syntheticCgroupProgram(
    id: number,
    type: string,
    name: string
  ): RawBpfProg {
    return {
      id,
      type,
      name,
      tag: id.toString(16).padStart(16, "0"),
      gpl_compatible: true,
      loaded_at: 1700001000 + id,
      orphaned: false,
      bytes_xlated: 96,
      jited: true,
      bytes_memlock: 4096,
    };
  }

  function buildSyntheticCgroupChain(attachType: string, programType: string) {
    const progs = parseProgList([
      syntheticCgroupProgram(900, programType, `${attachType}_a`),
      syntheticCgroupProgram(901, programType, `${attachType}_b`),
    ]);
    const cgroups: RawCgroupEntry[] = [
      {
        cgroup: "/sys/fs/cgroup/synthetic.slice",
        programs: [
          { id: 900, attach_type: attachType, attach_flags: "multi" },
          { id: 901, attach_type: attachType, attach_flags: "multi" },
        ],
      },
    ];

    const chains = buildProgramChains(progs, [], cgroups);
    expect(chains).toHaveLength(1);
    return chains[0];
  }

  it("adds TC packet context and return semantics to chain metadata", () => {
    const tcA: RawBpfProg = {
      ...xdpProg,
      id: 80,
      type: "sched_cls",
      name: "tc_a",
    };
    const tcB: RawBpfProg = {
      ...xdpProg,
      id: 81,
      type: "sched_cls",
      name: "tc_b",
    };
    const progs = parseProgList([tcA, tcB]);
    const net: RawNetSnapshot[] = [
      {
        tc: [
          { devname: "eth0", ifindex: 2, id: 80, kind: "clsact/ingress" },
          { devname: "eth0", ifindex: 2, id: 81, kind: "clsact/ingress" },
        ],
      },
    ];

    const chains = buildProgramChains(progs, net, []);
    expect(chains).toHaveLength(1);
    expect(chains[0].packetContext).toMatchObject({
      family: "tc",
      direction: "ingress",
      semantics: {
        pass: expect.arrayContaining(["TC_ACT_OK (0)"]),
        drop: expect.arrayContaining(["TC_ACT_SHOT (2)"]),
        redirect: expect.arrayContaining(["TC_ACT_REDIRECT (7)"]),
      },
    });
  });

  it("prefers detailed tc filter order when available", () => {
    const tcA: RawBpfProg = {
      ...xdpProg,
      id: 80,
      type: "sched_cls",
      name: "late_prog",
    };
    const tcB: RawBpfProg = {
      ...xdpProg,
      id: 81,
      type: "sched_cls",
      name: "early_prog",
    };
    const progs = parseProgList([tcA, tcB]);
    const net: RawNetSnapshot[] = [
      {
        tc: [
          { devname: "eth0", ifindex: 2, id: 80, kind: "clsact/egress" },
          { devname: "eth0", ifindex: 2, id: 81, kind: "clsact/egress" },
        ],
        tcFilters: [
          {
            devname: "eth0",
            ifindex: 2,
            direction: "egress",
            protocol: "all",
            pref: 200,
            kind: "bpf",
            chain: 0,
            order: 0,
            options: {
              handle: "0x2",
              bpf_name: "late_filter",
              "direct-action": true,
              prog: { id: 80, name: "late_prog" },
              actions: [
                {
                  stats: {
                    bytes: 128,
                    packets: 4,
                    drops: 1,
                  },
                },
              ],
            },
          },
          {
            devname: "eth0",
            ifindex: 2,
            direction: "egress",
            protocol: "all",
            pref: 100,
            kind: "bpf",
            chain: 0,
            order: 1,
            options: {
              handle: "0x1",
              bpf_name: "early_filter",
              "direct-action": true,
              prog: { id: 81, name: "early_prog" },
            },
          },
        ],
      },
    ];

    const chains = buildProgramChains(progs, net, []);
    expect(chains).toHaveLength(1);
    expect(chains[0]).toMatchObject({
      hookId: "tc:eth0:clsact/egress",
      attachType: "clsact/egress",
      packetContext: {
        direction: "egress",
      },
    });
    expect(chains[0].programs.map(program => program.id)).toEqual([81, 80]);
    expect(chains[0].programs.map(program => program.name)).toEqual([
      "early_filter",
      "late_filter",
    ]);
    expect(chains[0].programs[1].tc).toMatchObject({
      protocol: "all",
      priority: 200,
      chain: 0,
      handle: "0x2",
      directAction: true,
      actionCount: 1,
      stats: {
        bytes: 128,
        packets: 4,
        drops: 1,
      },
    });

    const [iface] = buildNetworkInterfaces(progs, net);
    expect(iface.layers.L3.map(program => program.id)).toEqual([81, 80]);
  });

  it("preserves repeated tc program ids when filters are distinct", () => {
    const tcA: RawBpfProg = {
      ...xdpProg,
      id: 80,
      type: "sched_cls",
      name: "shared_prog",
    };
    const progs = parseProgList([tcA]);
    const net: RawNetSnapshot[] = [
      {
        tc: [{ devname: "eth0", ifindex: 2, id: 80, kind: "clsact/ingress" }],
        tcFilters: [
          {
            devname: "eth0",
            ifindex: 2,
            direction: "ingress",
            pref: 10,
            chain: 0,
            order: 0,
            options: { handle: "0x1", prog: { id: 80 } },
          },
          {
            devname: "eth0",
            ifindex: 2,
            direction: "ingress",
            pref: 20,
            chain: 0,
            order: 1,
            options: { handle: "0x2", prog: { id: 80 } },
          },
        ],
      },
    ];

    const chains = buildProgramChains(progs, net, []);
    expect(chains).toHaveLength(1);
    expect(chains[0].programs).toMatchObject([
      { id: 80, position: 1, tc: { priority: 10, handle: "0x1" } },
      { id: 80, position: 2, tc: { priority: 20, handle: "0x2" } },
    ]);
  });

  it("orders detailed tc hook groups ingress before egress", () => {
    const progs = parseProgList([
      { ...xdpProg, id: 80, type: "sched_cls", name: "ingress_a" },
      { ...xdpProg, id: 81, type: "sched_cls", name: "ingress_b" },
      { ...xdpProg, id: 82, type: "sched_cls", name: "egress_a" },
      { ...xdpProg, id: 83, type: "sched_cls", name: "egress_b" },
    ]);
    const net: RawNetSnapshot[] = [
      {
        tc: [
          { devname: "eth0", ifindex: 2, id: 80, kind: "clsact/ingress" },
          { devname: "eth0", ifindex: 2, id: 81, kind: "clsact/ingress" },
          { devname: "eth0", ifindex: 2, id: 82, kind: "clsact/egress" },
          { devname: "eth0", ifindex: 2, id: 83, kind: "clsact/egress" },
        ],
        tcFilters: [
          {
            devname: "eth0",
            ifindex: 2,
            direction: "egress",
            pref: 1,
            chain: 0,
            order: 0,
            options: { prog: { id: 82 } },
          },
          {
            devname: "eth0",
            ifindex: 2,
            direction: "egress",
            pref: 2,
            chain: 0,
            order: 1,
            options: { prog: { id: 83 } },
          },
          {
            devname: "eth0",
            ifindex: 2,
            direction: "ingress",
            pref: 100,
            chain: 0,
            order: 2,
            options: { prog: { id: 80 } },
          },
          {
            devname: "eth0",
            ifindex: 2,
            direction: "ingress",
            pref: 101,
            chain: 0,
            order: 3,
            options: { prog: { id: 81 } },
          },
        ],
      },
    ];

    const chains = buildProgramChains(progs, net, []);
    expect(chains.map(chain => chain.attachType)).toEqual([
      "clsact/ingress",
      "clsact/egress",
    ]);
    expect(
      chains.map(chain => chain.programs.map(program => program.id))
    ).toEqual([
      [80, 81],
      [82, 83],
    ]);
  });

  it("adds cgroup_skb packet context to ingress and egress chains", () => {
    const ingressA: RawBpfProg = {
      ...cgroupSkbProg,
      id: 82,
      name: "ingress_a",
    };
    const ingressB: RawBpfProg = {
      ...cgroupSkbProg,
      id: 83,
      name: "ingress_b",
    };
    const progs = parseProgList([ingressA, ingressB]);
    const cgroups: RawCgroupEntry[] = [
      {
        cgroup: "/sys/fs/cgroup/test.slice",
        programs: [
          { id: 82, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
          { id: 83, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
        ],
      },
    ];

    const chains = buildProgramChains(progs, [], cgroups);
    expect(chains).toHaveLength(1);
    expect(chains[0].packetContext).toMatchObject({
      family: "cgroup_skb",
      direction: "ingress",
      semantics: {
        pass: ["1 (allow/pass)"],
        drop: ["0 (drop/deny)"],
      },
    });
  });

  it("builds effective cgroup chains with inherited parent programs", () => {
    const parentProg: RawBpfProg = {
      ...cgroupSkbProg,
      id: 182,
      name: "root_ingress",
    };
    const childProg: RawBpfProg = {
      ...cgroupSkbProg,
      id: 183,
      name: "child_ingress",
    };
    const progs = parseProgList([parentProg, childProg]);
    const cgroups: RawCgroupEntry[] = [
      {
        cgroup: "/sys/fs/cgroup",
        programs: [
          {
            id: 182,
            attach_type: "cgroup_inet_ingress",
            attach_flags: "multi",
          },
        ],
      },
      {
        cgroup: "/sys/fs/cgroup/test.slice",
        programs: [
          {
            id: 183,
            attach_type: "cgroup_inet_ingress",
            attach_flags: "multi",
          },
        ],
      },
    ];

    const chains = buildProgramChains(progs, [], cgroups);
    expect(chains).toHaveLength(1);
    expect(chains[0]).toMatchObject({
      hookId: "cgroup:/sys/fs/cgroup/test.slice:cgroup_inet_ingress",
      programs: [
        {
          id: 182,
          position: 1,
          cgroup: {
            attachPath: "/sys/fs/cgroup",
            inherited: true,
            attachFlags: "multi",
          },
        },
        {
          id: 183,
          position: 2,
          cgroup: {
            attachPath: "/sys/fs/cgroup/test.slice",
            inherited: false,
            attachFlags: "multi",
          },
        },
      ],
    });
  });

  it("prefers kernel-reported effective cgroup chain order when available", () => {
    const parentProg: RawBpfProg = {
      ...cgroupSkbProg,
      id: 191,
      name: "root_ingress",
    };
    const childProg: RawBpfProg = {
      ...cgroupSkbProg,
      id: 192,
      name: "child_ingress",
    };
    const progs = parseProgList([parentProg, childProg]);
    const directCgroups: RawCgroupEntry[] = [
      {
        cgroup: "/sys/fs/cgroup",
        programs: [
          {
            id: 191,
            attach_type: "cgroup_inet_ingress",
            attach_flags: "multi",
          },
        ],
      },
      {
        cgroup: "/sys/fs/cgroup/test.slice",
        programs: [
          {
            id: 192,
            attach_type: "cgroup_inet_ingress",
            attach_flags: "multi",
          },
        ],
      },
    ];
    const effectiveCgroups: RawCgroupEntry[] = [
      {
        cgroup: "/sys/fs/cgroup",
        programs: [
          {
            id: 191,
            attach_type: "cgroup_inet_ingress",
          },
        ],
      },
      {
        cgroup: "/sys/fs/cgroup/test.slice",
        programs: [
          {
            id: 192,
            attach_type: "cgroup_inet_ingress",
          },
          {
            id: 191,
            attach_type: "cgroup_inet_ingress",
          },
        ],
      },
    ];

    const chains = buildProgramChains(
      progs,
      [],
      directCgroups,
      effectiveCgroups
    );
    expect(chains).toHaveLength(1);
    expect(chains[0]).toMatchObject({
      hookId: "cgroup:/sys/fs/cgroup/test.slice:cgroup_inet_ingress",
      chainSource: "kernel-effective",
      programs: [
        {
          id: 192,
          position: 1,
          cgroup: {
            attachPath: "/sys/fs/cgroup/test.slice",
            inherited: false,
            attachFlags: "multi",
          },
        },
        {
          id: 191,
          position: 2,
          cgroup: {
            attachPath: "/sys/fs/cgroup",
            inherited: true,
            attachFlags: "multi",
          },
        },
      ],
    });
  });

  it("does not duplicate inherited-only cgroup chains for descendants", () => {
    const rootA: RawBpfProg = {
      ...cgroupSkbProg,
      id: 186,
      name: "root_a",
    };
    const rootB: RawBpfProg = {
      ...cgroupSkbProg,
      id: 187,
      name: "root_b",
    };
    const progs = parseProgList([rootA, rootB]);
    const cgroups: RawCgroupEntry[] = [
      {
        cgroup: "/sys/fs/cgroup",
        programs: [
          {
            id: 186,
            attach_type: "cgroup_inet_ingress",
            attach_flags: "multi",
          },
          {
            id: 187,
            attach_type: "cgroup_inet_ingress",
            attach_flags: "multi",
          },
        ],
      },
      {
        cgroup: "/sys/fs/cgroup/test.slice",
        programs: [],
      },
    ];

    const chains = buildProgramChains(progs, [], cgroups);
    expect(chains.map(chain => chain.hookId)).toEqual([
      "cgroup:/sys/fs/cgroup:cgroup_inet_ingress",
    ]);
  });

  it("lets child cgroup attachments replace override-capable ancestors", () => {
    const rootProg: RawBpfProg = {
      ...cgroupSkbProg,
      id: 188,
      name: "root_override",
    };
    const childA: RawBpfProg = {
      ...cgroupSkbProg,
      id: 189,
      name: "child_a",
    };
    const childB: RawBpfProg = {
      ...cgroupSkbProg,
      id: 190,
      name: "child_b",
    };
    const progs = parseProgList([rootProg, childA, childB]);
    const cgroups: RawCgroupEntry[] = [
      {
        cgroup: "/sys/fs/cgroup",
        programs: [
          {
            id: 188,
            attach_type: "cgroup_inet_ingress",
            attach_flags: "override",
          },
        ],
      },
      {
        cgroup: "/sys/fs/cgroup/test.slice",
        programs: [
          { id: 189, attach_type: "cgroup_inet_ingress" },
          { id: 190, attach_type: "cgroup_inet_ingress" },
        ],
      },
    ];

    const chains = buildProgramChains(progs, [], cgroups);
    expect(chains).toHaveLength(1);
    expect(chains[0]).toMatchObject({
      hookId: "cgroup:/sys/fs/cgroup/test.slice:cgroup_inet_ingress",
      programs: [
        {
          id: 189,
          position: 1,
          cgroup: {
            attachPath: "/sys/fs/cgroup/test.slice",
            inherited: false,
          },
        },
        {
          id: 190,
          position: 2,
          cgroup: {
            attachPath: "/sys/fs/cgroup/test.slice",
            inherited: false,
          },
        },
      ],
    });
  });

  it("adds cgroup socket-address context to connect chains", () => {
    const connectA: RawBpfProg = {
      ...cgroupSockAddrProg,
      id: 84,
      name: "connect_a",
    };
    const connectB: RawBpfProg = {
      ...cgroupSockAddrProg,
      id: 85,
      name: "connect_b",
    };
    const progs = parseProgList([connectA, connectB]);
    const cgroups: RawCgroupEntry[] = [
      {
        cgroup: "/sys/fs/cgroup/test.slice",
        programs: [
          {
            id: 84,
            attach_type: "cgroup_inet6_connect",
            attach_flags: "multi",
          },
          {
            id: 85,
            attach_type: "cgroup_inet6_connect",
            attach_flags: "multi",
          },
        ],
      },
    ];

    const chains = buildProgramChains(progs, [], cgroups);
    expect(chains).toHaveLength(1);
    expect(chains[0].packetContext).toMatchObject({
      family: "cgroup_sock_addr",
      semantics: {
        pass: ["1 (allow)"],
        drop: ["0 (deny)"],
      },
    });
  });

  it("marks cgroup socket-address alias chains as short-circuiting", () => {
    const connectA: RawBpfProg = {
      ...cgroupSockAddrProg,
      id: 184,
      name: "connect4_a",
    };
    const connectB: RawBpfProg = {
      ...cgroupSockAddrProg,
      id: 185,
      name: "connect4_b",
    };
    const progs = parseProgList([connectA, connectB]);
    const cgroups: RawCgroupEntry[] = [
      {
        cgroup: "/sys/fs/cgroup/test.slice",
        programs: [
          { id: 184, attach_type: "cgroup_connect4", attach_flags: "multi" },
          { id: 185, attach_type: "cgroup_connect4", attach_flags: "multi" },
        ],
      },
    ];

    const chains = buildProgramChains(progs, [], cgroups);
    expect(chains).toHaveLength(1);
    expect(chains[0]).toMatchObject({
      attachType: "cgroup_connect4",
      canShortCircuit: true,
      packetContext: {
        family: "cgroup_sock_addr",
        semantics: {
          pass: ["1 (allow)"],
          drop: ["0 (deny)"],
        },
      },
    });
  });

  it.each([
    {
      attachType: "cgroup_inet_ingress",
      programType: "cgroup_skb",
      expected: {
        canShortCircuit: true,
        family: "cgroup_skb",
        direction: "ingress",
        summary:
          "cgroup_skb hooks use integer allow/drop verdicts for packet ingress or egress.",
        pass: ["1 (allow/pass)"],
        drop: ["0 (drop/deny)"],
      },
    },
    {
      attachType: "cgroup_inet_egress",
      programType: "cgroup_skb",
      expected: {
        canShortCircuit: true,
        family: "cgroup_skb",
        direction: "egress",
        summary:
          "cgroup_skb hooks use integer allow/drop verdicts for packet ingress or egress.",
        pass: ["1 (allow/pass)"],
        drop: ["0 (drop/deny)"],
      },
    },
    {
      attachType: "cgroup_inet4_connect",
      programType: "cgroup_sock_addr",
      expected: {
        canShortCircuit: true,
        family: "cgroup_sock_addr",
        direction: "unknown",
        summary:
          "cgroup socket-address hooks can allow or deny socket operations before packets are sent.",
        pass: ["1 (allow)"],
        drop: ["0 (deny)"],
      },
    },
    {
      attachType: "cgroup_inet6_bind",
      programType: "cgroup_sock_addr",
      expected: {
        canShortCircuit: true,
        family: "cgroup_sock_addr",
        direction: "unknown",
        summary:
          "cgroup socket-address hooks can allow or deny socket operations before packets are sent.",
        pass: ["1 (allow)"],
        drop: ["0 (deny)"],
      },
    },
    {
      attachType: "cgroup_inet6_getpeername",
      programType: "cgroup_sock_addr",
      expected: {
        canShortCircuit: true,
        family: "cgroup_sock_addr",
        direction: "unknown",
        summary:
          "cgroup socket-address hooks can allow or deny socket operations before packets are sent.",
        pass: ["1 (allow)"],
        drop: ["0 (deny)"],
      },
    },
    {
      attachType: "cgroup_setsockopt",
      programType: "cgroup_sockopt",
      expected: {
        canShortCircuit: false,
        family: "cgroup_sock",
        direction: "unknown",
        summary: CGROUP_SOCKET_SIDE_EFFECT_SUMMARY,
        pass: [],
        drop: [],
      },
    },
    {
      attachType: "cgroup_getsockopt",
      programType: "cgroup_sockopt",
      expected: {
        canShortCircuit: false,
        family: "cgroup_sock",
        direction: "unknown",
        summary: CGROUP_SOCKET_SIDE_EFFECT_SUMMARY,
        pass: [],
        drop: [],
      },
    },
    {
      attachType: "cgroup_sock_ops",
      programType: "sock_ops",
      expected: {
        canShortCircuit: false,
        family: "cgroup_sock",
        direction: "unknown",
        summary: CGROUP_SOCKET_SIDE_EFFECT_SUMMARY,
        pass: [],
        drop: [],
      },
    },
    {
      attachType: "cgroup_inet6_post_bind",
      programType: "cgroup_sock",
      expected: {
        canShortCircuit: false,
        family: "cgroup_sock",
        direction: "unknown",
        summary: CGROUP_SOCKET_SIDE_EFFECT_SUMMARY,
        pass: [],
        drop: [],
      },
    },
  ])(
    "classifies representative cgroup hook semantics for $attachType",
    ({ attachType, programType, expected }) => {
      const chain = buildSyntheticCgroupChain(attachType, programType);

      expect(chain).toMatchObject({
        attachType,
        canShortCircuit: expected.canShortCircuit,
        packetContext: {
          family: expected.family,
          direction: expected.direction,
          summary: expected.summary,
          semantics: {
            pass: expected.pass,
            drop: expected.drop,
          },
        },
      });
    }
  );

  it("classifies cgroup post-bind chains as cgroup_sock, not socket-address hooks", () => {
    const postBindA: RawBpfProg = {
      ...cgroupSockProg,
      id: 86,
      name: "post_bind_a",
    };
    const postBindB: RawBpfProg = {
      ...cgroupSockProg,
      id: 87,
      name: "post_bind_b",
    };
    const progs = parseProgList([postBindA, postBindB]);
    const cgroups: RawCgroupEntry[] = [
      {
        cgroup: "/sys/fs/cgroup/test.slice",
        programs: [
          {
            id: 86,
            attach_type: "cgroup_inet6_post_bind",
            attach_flags: "multi",
          },
          {
            id: 87,
            attach_type: "cgroup_inet6_post_bind",
            attach_flags: "multi",
          },
        ],
      },
    ];

    const chains = buildProgramChains(progs, [], cgroups);
    expect(chains).toHaveLength(1);
    expect(chains[0]).toMatchObject({
      canShortCircuit: false,
      packetContext: {
        family: "cgroup_sock",
        summary: CGROUP_SOCKET_SIDE_EFFECT_SUMMARY,
        semantics: {
          pass: [],
          drop: [],
        },
      },
    });
  });

  it("does not mark unmodeled cgroup sockopt chains as short-circuiting", () => {
    const sockoptA: RawBpfProg = {
      ...cgroupSockoptProg,
      id: 88,
      name: "sockopt_a",
    };
    const sockoptB: RawBpfProg = {
      ...cgroupSockoptProg,
      id: 89,
      name: "sockopt_b",
    };
    const progs = parseProgList([sockoptA, sockoptB]);
    const cgroups: RawCgroupEntry[] = [
      {
        cgroup: "/sys/fs/cgroup",
        programs: [
          { id: 88, attach_type: "cgroup_setsockopt", attach_flags: "multi" },
          { id: 89, attach_type: "cgroup_setsockopt", attach_flags: "multi" },
        ],
      },
    ];

    const chains = buildProgramChains(progs, [], cgroups);
    expect(chains).toHaveLength(1);
    expect(chains[0]).toMatchObject({
      canShortCircuit: false,
      packetContext: {
        family: "cgroup_sock",
        summary: CGROUP_SOCKET_SIDE_EFFECT_SUMMARY,
        semantics: {
          pass: [],
          drop: [],
        },
      },
    });
  });
});

// ─── buildCgroupTree ──────────────────────────────────────────────────────────

describe("buildCgroupTree", () => {
  // ── helpers ────────────────────────────────────────────────────────────────
  type CgNode = ReturnType<typeof buildCgroupTree>[0];
  const findNode = (nodes: CgNode[], path: string): CgNode | undefined => {
    for (const n of nodes) {
      if (n.path === path) return n;
      const found = findNode(n.children, path);
      if (found) return found;
    }
  };

  // ── base cases ─────────────────────────────────────────────────────────────
  it("builds a flat tree from cgroup entries", () => {
    const progs = parseProgList([cgroupSkbProg]);
    const cgroups: RawCgroupEntry[] = [
      {
        cgroup: "/sys/fs/cgroup/system.slice/test.service",
        programs: [
          {
            id: 2,
            attach_type: "cgroup_inet_ingress",
            attach_flags: "multi",
            name: "",
          },
        ],
      },
    ];
    enrichWithCgroupAttachments(progs, cgroups);
    const tree = buildCgroupTree(progs, cgroups);
    expect(tree.length).toBeGreaterThanOrEqual(1);
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

  // ── 4-level hierarchy ──────────────────────────────────────────────────────
  const cgroupIngress: RawBpfProg = {
    id: 10,
    type: "cgroup_skb",
    name: "cg_ingress",
    tag: "aabb000000000001",
    gpl_compatible: true,
    loaded_at: 0,
    uid: 0,
    orphaned: false,
    bytes_xlated: 64,
    jited: false,
    bytes_memlock: 4096,
  };
  const cgroupEgress: RawBpfProg = {
    id: 11,
    type: "cgroup_skb",
    name: "cg_egress",
    tag: "aabb000000000002",
    gpl_compatible: true,
    loaded_at: 0,
    uid: 0,
    orphaned: false,
    bytes_xlated: 64,
    jited: false,
    bytes_memlock: 4096,
  };
  const cgroupDevice: RawBpfProg = {
    id: 12,
    type: "cgroup_device",
    name: "cg_device",
    tag: "aabb000000000003",
    gpl_compatible: true,
    loaded_at: 0,
    uid: 0,
    orphaned: false,
    bytes_xlated: 128,
    jited: false,
    bytes_memlock: 4096,
  };
  const cgroupSockCreate: RawBpfProg = {
    id: 13,
    type: "cgroup_sock",
    name: "cg_sock_create",
    tag: "aabb000000000004",
    gpl_compatible: true,
    loaded_at: 0,
    uid: 0,
    orphaned: false,
    bytes_xlated: 192,
    jited: false,
    bytes_memlock: 4096,
  };
  const cgroupSockops: RawBpfProg = {
    id: 14,
    type: "sock_ops",
    name: "cg_sockops",
    tag: "aabb000000000005",
    gpl_compatible: true,
    loaded_at: 0,
    uid: 0,
    orphaned: false,
    bytes_xlated: 256,
    jited: true,
    bytes_memlock: 4096,
  };

  const deepCgroups: RawCgroupEntry[] = [
    // Level 0: root — global policy
    {
      cgroup: "/sys/fs/cgroup",
      programs: [
        { id: 10, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
        { id: 11, attach_type: "cgroup_inet_egress", attach_flags: "multi" },
      ],
    },
    // Level 1: system.slice — device policy for all services
    {
      cgroup: "/sys/fs/cgroup/system.slice",
      programs: [
        { id: 12, attach_type: "cgroup_device", attach_flags: "multi" },
      ],
    },
    // Level 1: user.slice — no programs (structural node)
    { cgroup: "/sys/fs/cgroup/user.slice", programs: [] },
    // Level 2: kubelet.service — network + device + socket policy
    {
      cgroup: "/sys/fs/cgroup/system.slice/kubelet.service",
      programs: [
        { id: 10, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
        { id: 11, attach_type: "cgroup_inet_egress", attach_flags: "multi" },
        { id: 12, attach_type: "cgroup_device", attach_flags: "multi" },
        { id: 13, attach_type: "cgroup_sock_create", attach_flags: "" },
        { id: 14, attach_type: "cgroup_sockops", attach_flags: "multi" },
      ],
    },
    // Level 2: ssh.service — network + socket policy
    {
      cgroup: "/sys/fs/cgroup/system.slice/ssh.service",
      programs: [
        { id: 10, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
        { id: 11, attach_type: "cgroup_inet_egress", attach_flags: "multi" },
        { id: 13, attach_type: "cgroup_sock_create", attach_flags: "" },
      ],
    },
    // Level 2: user-1000.slice
    { cgroup: "/sys/fs/cgroup/user.slice/user-1000.slice", programs: [] },
    // Level 3: burstable pod QoS class
    {
      cgroup:
        "/sys/fs/cgroup/system.slice/kubelet.service/kubepods-burstable.slice",
      programs: [
        { id: 10, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
        { id: 11, attach_type: "cgroup_inet_egress", attach_flags: "multi" },
      ],
    },
    // Level 3: user session
    {
      cgroup: "/sys/fs/cgroup/user.slice/user-1000.slice/session-1.scope",
      programs: [
        { id: 10, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
        { id: 11, attach_type: "cgroup_inet_egress", attach_flags: "multi" },
      ],
    },
    // Level 4: individual pod
    {
      cgroup:
        "/sys/fs/cgroup/system.slice/kubelet.service/kubepods-burstable.slice/pod-nginx.scope",
      programs: [
        { id: 10, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
        { id: 11, attach_type: "cgroup_inet_egress", attach_flags: "multi" },
        { id: 12, attach_type: "cgroup_device", attach_flags: "multi" },
        { id: 13, attach_type: "cgroup_sock_create", attach_flags: "" },
        { id: 14, attach_type: "cgroup_sockops", attach_flags: "multi" },
      ],
    },
  ];

  it("builds a 4-level hierarchy with correct parent-child wiring", () => {
    const progs = parseProgList([
      cgroupIngress,
      cgroupEgress,
      cgroupDevice,
      cgroupSockCreate,
      cgroupSockops,
    ]);
    enrichWithCgroupAttachments(progs, deepCgroups);
    const tree = buildCgroupTree(progs, deepCgroups);

    // Root node should be at the top level
    const root = findNode(tree, "/sys/fs/cgroup");
    expect(root).toBeDefined();
    expect(root!.depth).toBe(0);
    expect(root!.programs).toHaveLength(2); // ingress + egress

    // system.slice is a child of root
    const systemSlice = findNode(tree, "/sys/fs/cgroup/system.slice");
    expect(systemSlice).toBeDefined();
    expect(systemSlice!.depth).toBe(1);
    expect(systemSlice!.programs).toHaveLength(1); // device only

    // kubelet.service is a child of system.slice
    const kubelet = findNode(
      tree,
      "/sys/fs/cgroup/system.slice/kubelet.service"
    );
    expect(kubelet).toBeDefined();
    expect(kubelet!.depth).toBe(2);
    expect(kubelet!.programs).toHaveLength(5);

    // burstable.slice is a child of kubelet.service
    const burstable = findNode(
      tree,
      "/sys/fs/cgroup/system.slice/kubelet.service/kubepods-burstable.slice"
    );
    expect(burstable).toBeDefined();
    expect(burstable!.depth).toBe(3);

    // pod-nginx.scope is a child of burstable.slice (depth 4)
    const pod = findNode(
      tree,
      "/sys/fs/cgroup/system.slice/kubelet.service/kubepods-burstable.slice/pod-nginx.scope"
    );
    expect(pod).toBeDefined();
    expect(pod!.depth).toBe(4);
    expect(pod!.programs).toHaveLength(5);
    expect(pod!.children).toHaveLength(0); // leaf node
  });

  it("structural nodes with no programs have empty programs array", () => {
    const progs = parseProgList([cgroupIngress]);
    enrichWithCgroupAttachments(progs, deepCgroups);
    const tree = buildCgroupTree(progs, deepCgroups);

    const userSlice = findNode(tree, "/sys/fs/cgroup/user.slice");
    expect(userSlice).toBeDefined();
    expect(userSlice!.programs).toHaveLength(0);

    const user1000 = findNode(
      tree,
      "/sys/fs/cgroup/user.slice/user-1000.slice"
    );
    expect(user1000).toBeDefined();
    expect(user1000!.programs).toHaveLength(0);
  });

  it("children are sorted alphabetically at every level", () => {
    const progs = parseProgList([
      cgroupIngress,
      cgroupEgress,
      cgroupDevice,
      cgroupSockCreate,
      cgroupSockops,
    ]);
    enrichWithCgroupAttachments(progs, deepCgroups);
    const tree = buildCgroupTree(progs, deepCgroups);

    const systemSlice = findNode(tree, "/sys/fs/cgroup/system.slice");
    expect(systemSlice).toBeDefined();
    const childNames = systemSlice!.children.map(c => c.name);
    expect(childNames).toEqual([...childNames].sort());
  });

  it("user session (depth 3) is wired under user-1000.slice", () => {
    const progs = parseProgList([cgroupIngress, cgroupEgress]);
    enrichWithCgroupAttachments(progs, deepCgroups);
    const tree = buildCgroupTree(progs, deepCgroups);

    const session = findNode(
      tree,
      "/sys/fs/cgroup/user.slice/user-1000.slice/session-1.scope"
    );
    expect(session).toBeDefined();
    expect(session!.depth).toBe(3);
    expect(session!.name).toBe("session-1.scope");
    expect(session!.programs).toHaveLength(2);
  });

  it("total node count matches number of unique paths in deepCgroups", () => {
    const progs = parseProgList([
      cgroupIngress,
      cgroupEgress,
      cgroupDevice,
      cgroupSockCreate,
      cgroupSockops,
    ]);
    enrichWithCgroupAttachments(progs, deepCgroups);
    const tree = buildCgroupTree(progs, deepCgroups);

    const countNodes = (nodes: CgNode[]): number =>
      nodes.reduce((sum, n) => sum + 1 + countNodes(n.children), 0);
    expect(countNodes(tree)).toBe(deepCgroups.length);
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

  it("places tracing (fentry/fexit) and ext (freplace) programs in kprobe zone", () => {
    const progs = parseProgList([
      { ...kprobeProg, id: 40, type: "tracing", name: "fentry__tcp_connect" },
      { ...kprobeProg, id: 41, type: "ext", name: "freplace_xdp_pass" },
    ]);
    const zones = buildKernelZones(progs);
    const kprobeZone = zones.find(z => z.zone === "kprobe");
    expect(kprobeZone).toBeDefined();
    expect(kprobeZone!.programs.map(p => p.id).sort()).toEqual([40, 41]);
    expect(zones.find(z => z.zone === "other")).toBeUndefined();
  });

  it("places cgroup_skb in cgroup zone", () => {
    const progs = parseProgList([cgroupSkbProg]);
    const zones = buildKernelZones(progs);
    const cgroupZone = zones.find(z => z.zone === "cgroup");
    expect(cgroupZone).toBeDefined();
    expect(cgroupZone!.programs).toHaveLength(1);
  });

  it("places struct_ops programs in a dedicated struct_ops zone", () => {
    const progs = parseProgList([structOpsProg]);
    const zones = buildKernelZones(progs);
    const structOpsZone = zones.find(z => z.zone === "struct_ops");

    expect(structOpsZone).toMatchObject({
      label: "Struct Ops",
      description: "Kernel struct_ops callbacks",
      osiLayer: "kernel",
    });
    expect(structOpsZone?.programs.map(p => p.id)).toEqual([8]);
    expect(zones.find(z => z.zone === "other")).toBeUndefined();
  });

  it("does not count unattached TC programs as TC ingress", () => {
    const progs = parseProgList([
      { ...orphanedProg, id: 20, name: "loaded_tc_only" },
    ]);
    const zones = buildKernelZones(progs);

    expect(zones.find(z => z.zone === "tc_ingress")).toBeUndefined();
    expect(zones.find(z => z.zone === "tc_egress")).toBeUndefined();
    expect(zones.find(z => z.zone === "other")?.programs.map(p => p.id)).toEqual([
      20,
    ]);
  });

  it("classifies attached TC programs by attachment direction", () => {
    const progs = parseProgList([
      { ...orphanedProg, id: 20, name: "attached_ingress" },
      { ...orphanedProg, id: 21, name: "attached_egress" },
    ]);
    enrichWithNetAttachments(progs, [
      {
        tc: [
          {
            devname: "eth0",
            ifindex: 2,
            id: 20,
            name: "attached_ingress",
            kind: "clsact/ingress",
          },
          {
            devname: "eth0",
            ifindex: 2,
            id: 21,
            name: "attached_egress",
            kind: "clsact/egress",
          },
        ],
      },
    ]);

    const zones = buildKernelZones(progs);

    expect(zones.find(z => z.zone === "tc_ingress")?.programs.map(p => p.id)).toEqual([
      20,
    ]);
    expect(zones.find(z => z.zone === "tc_egress")?.programs.map(p => p.id)).toEqual([
      21,
    ]);
    expect(zones.find(z => z.zone === "other")).toBeUndefined();
  });

  it("only includes zones with programs", () => {
    const progs = parseProgList([xdpProg]);
    const zones = buildKernelZones(progs);
    for (const zone of zones) {
      expect(zone.programs.length).toBeGreaterThan(0);
    }
  });
});

// ─── BPF_PROGRAM_TYPE_COLORS ──────────────────────────────────────────────────

describe("BPF_PROGRAM_TYPE_COLORS", () => {
  it("has a color for xdp", () => {
    expect(BPF_PROGRAM_TYPE_COLORS["xdp"]).toBeDefined();
    expect(BPF_PROGRAM_TYPE_COLORS["xdp"]).toMatch(/^#[0-9a-f]{6}$/i);
  });

  it("has a fallback unknown color", () => {
    expect(BPF_PROGRAM_TYPE_COLORS["unknown"]).toBeDefined();
  });
});

// ─── buildSnapshot ────────────────────────────────────────────────────────────

describe("buildSnapshot", () => {
  it("builds a complete snapshot from raw data", () => {
    const snapshot = buildSnapshot(
      [xdpProg, cgroupSkbProg, kprobeProg],
      [
        {
          xdp: [
            {
              devname: "eth0",
              ifindex: 2,
              mode: "driver",
              id: 1,
              name: "my_xdp_prog",
            },
          ],
        },
      ],
      [
        {
          cgroup: "/sys/fs/cgroup/system.slice/test.service",
          programs: [
            {
              id: 2,
              attach_type: "cgroup_inet_ingress",
              attach_flags: "multi",
              name: "",
            },
          ],
        },
      ],
      {
        hostname: "test-host",
        kernelVersion: "6.1.0",
        bpftoolVersion: "7.3.0",
        demoMode: false,
      }
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
    const snapshot = buildSnapshot([orphanedProg], [{}], [], {
      hostname: "h",
      kernelVersion: "6.0",
      bpftoolVersion: "7.0",
      demoMode: false,
    });
    expect(snapshot.stats.orphaned).toBe(1);
  });

  it("counts byType correctly", () => {
    const snapshot = buildSnapshot(
      [xdpProg, cgroupSkbProg, cgroupSkbProg],
      [{}],
      [],
      {
        hostname: "h",
        kernelVersion: "6.0",
        bpftoolVersion: "7.0",
        demoMode: false,
      }
    );
    // Note: duplicate IDs will be deduplicated by the Map
    expect(snapshot.stats.byType["xdp"]).toBe(1);
    expect(snapshot.stats.byType["cgroup_skb"]).toBe(1);
  });

  it("sets timestamp as a recent unix timestamp (ms)", () => {
    const before = Date.now();
    const snapshot = buildSnapshot([], [{}], [], {
      hostname: "h",
      kernelVersion: "6.0",
      bpftoolVersion: "7.0",
      demoMode: false,
    });
    const after = Date.now();
    // timestamp is in milliseconds
    expect(snapshot.timestamp).toBeGreaterThanOrEqual(before);
    expect(snapshot.timestamp).toBeLessThanOrEqual(after);
  });
});

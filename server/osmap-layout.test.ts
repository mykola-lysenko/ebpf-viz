/**
 * Tests for the OS Map layout engine (useOsMapLayout / buildOsMapLayout).
 * We import the pure buildOsMapLayout function directly — no React hooks needed.
 */
import { describe, it, expect } from "vitest";
import { buildOsMapLayout } from "../client/src/hooks/useOsMapLayout";
import type { EbpfSnapshot } from "../shared/ebpf-types";

// ─── Minimal snapshot fixture ─────────────────────────────────────────────────

function makeSnapshot(overrides: Partial<EbpfSnapshot> = {}): EbpfSnapshot {
  return {
    timestamp: Date.now(),
    hostname: "test-host",
    kernelVersion: "6.1.0",
    bpftoolVersion: "7.0.0",
    demoMode: false,
    programs: [
      {
        id: 1,
        type: "xdp",
        rawType: "xdp",
        name: "xdp_drop",
        tag: "aabbccdd11223344",
        gplCompatible: true,
        loadedAt: 1700000000,
        orphaned: false,
        bytesXlated: 128,
        jited: true,
        memlock: 4096,
        mapIds: [],
        attachments: [{ kind: "xdp", detail: "eth0 (driver)", ifname: "eth0" }],
        osiLayer: "L2",
        color: "#00d4ff",
      },
      {
        id: 2,
        type: "cgroup_skb",
        rawType: "cgroup_skb",
        name: "cgroup_skb_2",
        tag: "1122334455667788",
        gplCompatible: true,
        loadedAt: 1700000001,
        orphaned: false,
        bytesXlated: 64,
        jited: true,
        memlock: 4096,
        mapIds: [],
        attachments: [{ kind: "cgroup", detail: "cgroup_inet_ingress", cgroupPath: "/sys/fs/cgroup/system.slice" }],
        osiLayer: "L3",
        color: "#3b82f6",
      },
    ],
    networkInterfaces: [
      {
        name: "eth0",
        ifindex: 2,
        layers: {
          L2: [],
          L3: [],
          L4: [],
          L7: [],
        },
        allPrograms: [],
      },
    ],
    cgroupTree: [
      {
        path: "/sys/fs/cgroup",
        name: "/",
        depth: 0,
        programs: [],
        children: [
          {
            path: "/sys/fs/cgroup/system.slice",
            name: "system.slice",
            depth: 1,
            programs: [],
            children: [],
          },
        ],
      },
    ],
    kernelZones: [
      {
        zone: "xdp",
        label: "XDP",
        description: "Express Data Path",
        programs: [],
        osiLayer: "L2",
      },
      {
        zone: "cgroup",
        label: "Cgroup Hooks",
        description: "Cgroup BPF programs",
        programs: [],
        osiLayer: "kernel",
      },
      {
        zone: "kprobe",
        label: "kprobes",
        description: "Kernel probes",
        programs: [],
        osiLayer: "kernel",
      },
      {
        zone: "tracepoint",
        label: "Tracepoints",
        description: "Static tracepoints",
        programs: [],
        osiLayer: "kernel",
      },
      {
        zone: "perf_event",
        label: "Perf Events",
        description: "Perf events",
        programs: [],
        osiLayer: "kernel",
      },
      {
        zone: "tc_ingress",
        label: "TC Ingress",
        description: "Traffic control ingress",
        programs: [],
        osiLayer: "L3",
      },
      {
        zone: "tc_egress",
        label: "TC Egress",
        description: "Traffic control egress",
        programs: [],
        osiLayer: "L3",
      },
      {
        zone: "socket_filter",
        label: "Socket Filter",
        description: "Socket-level filtering",
        programs: [],
        osiLayer: "L4",
      },
      {
        zone: "netfilter",
        label: "Netfilter",
        description: "Netfilter hooks",
        programs: [],
        osiLayer: "L3",
      },
      {
        zone: "flow_dissector",
        label: "Flow Dissector",
        description: "Flow dissection",
        programs: [],
        osiLayer: "L3",
      },
      {
        zone: "sk_ops",
        label: "Socket Ops",
        description: "Socket operations",
        programs: [],
        osiLayer: "L4",
      },
      {
        zone: "other",
        label: "Other",
        description: "Other BPF programs",
        programs: [],
        osiLayer: "kernel",
      },
    ],
    stats: {
      total: 2,
      byType: { xdp: 1, cgroup_skb: 1 },
      jited: 2,
      orphaned: 0,
    },
    ...overrides,
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("buildOsMapLayout", () => {
  it("returns nodes and edges arrays for a minimal snapshot", () => {
    const layout = buildOsMapLayout(makeSnapshot());
    expect(Array.isArray(layout.nodes)).toBe(true);
    expect(Array.isArray(layout.edges)).toBe(true);
    expect(layout.nodes.length).toBeGreaterThan(0);
  });

  it("includes band nodes for all three spatial regions", () => {
    const layout = buildOsMapLayout(makeSnapshot());
    const nodeIds = layout.nodes.map(n => n.id);
    expect(nodeIds).toContain("band-userspace");
    expect(nodeIds).toContain("band-kernel");
    expect(nodeIds).toContain("band-network");
  });

  it("creates zone nodes for all kernel zones in the snapshot", () => {
    const layout = buildOsMapLayout(makeSnapshot());
    const zoneNodeIds = layout.nodes
      .filter(n => n.type === "zoneNode")
      .map(n => n.id);
    expect(zoneNodeIds).toContain("zone-xdp");
    expect(zoneNodeIds).toContain("zone-cgroup");
    expect(zoneNodeIds).toContain("zone-kprobe");
  });

  it("creates cgroup nodes for each cgroup in the tree", () => {
    const layout = buildOsMapLayout(makeSnapshot());
    const cgroupNodeIds = layout.nodes
      .filter(n => n.type === "cgroupNode")
      .map(n => n.id);
    expect(cgroupNodeIds).toContain("cgroup-/sys/fs/cgroup");
    expect(cgroupNodeIds).toContain("cgroup-/sys/fs/cgroup/system.slice");
  });

  it("creates an edge between parent and child cgroup nodes", () => {
    const layout = buildOsMapLayout(makeSnapshot());
    const cgroupEdge = layout.edges.find(
      e => e.source === "cgroup-/sys/fs/cgroup" &&
           e.target === "cgroup-/sys/fs/cgroup/system.slice"
    );
    expect(cgroupEdge).toBeDefined();
  });

  it("creates interface nodes for each network interface", () => {
    const layout = buildOsMapLayout(makeSnapshot());
    const ifaceNodes = layout.nodes.filter(n => n.type === "interfaceNode");
    expect(ifaceNodes.length).toBe(1);
    expect(ifaceNodes[0].id).toBe("iface-eth0");
  });

  it("all content nodes have valid x,y positions", () => {
    const layout = buildOsMapLayout(makeSnapshot());
    const contentNodes = layout.nodes.filter(
      n => n.type === "zoneNode" || n.type === "cgroupNode" || n.type === "interfaceNode"
    );
    contentNodes.forEach(node => {
      expect(typeof node.position.x).toBe("number");
      expect(typeof node.position.y).toBe("number");
      expect(isNaN(node.position.x)).toBe(false);
      expect(isNaN(node.position.y)).toBe(false);
    });
  });

  it("reports a positive totalHeight", () => {
    const layout = buildOsMapLayout(makeSnapshot());
    expect(layout.totalHeight).toBeGreaterThan(500);
  });

  it("creates process nodes when programs have pids", () => {
    const snap = makeSnapshot();
    snap.programs[0].pids = [{ pid: 1234, comm: "my_tracer" }];
    const layout = buildOsMapLayout(snap);
    const procNodes = layout.nodes.filter(n => n.type === "processNode");
    expect(procNodes.length).toBe(1);
    expect(procNodes[0].id).toBe("proc-1234");
  });

  it("creates an animated edge from XDP zone to interface with XDP programs", () => {
    const snap = makeSnapshot();
    // Put an XDP program on the interface
    snap.networkInterfaces[0].layers.L2 = [snap.programs[0]];
    snap.networkInterfaces[0].allPrograms = [snap.programs[0]];
    const layout = buildOsMapLayout(snap);
    const xdpEdge = layout.edges.find(
      e => e.source === "zone-xdp" && e.target === "iface-eth0"
    );
    expect(xdpEdge).toBeDefined();
    expect((xdpEdge as any).animated).toBe(true);
  });

  it("does not create duplicate node IDs", () => {
    const layout = buildOsMapLayout(makeSnapshot());
    const ids = layout.nodes.map(n => n.id);
    const uniqueIds = new Set(ids);
    expect(ids.length).toBe(uniqueIds.size);
  });

  it("handles an empty snapshot gracefully", () => {
    const snap = makeSnapshot({
      programs: [],
      networkInterfaces: [],
      cgroupTree: [],
      kernelZones: [],
      stats: { total: 0, byType: {}, jited: 0, orphaned: 0 },
    });
    const layout = buildOsMapLayout(snap);
    expect(layout.nodes.length).toBeGreaterThan(0); // band nodes still exist
    expect(layout.edges.length).toBe(0);
  });
});

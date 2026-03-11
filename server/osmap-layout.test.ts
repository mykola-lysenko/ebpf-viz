/**
 * Tests for the OS Map layout engine (useOsMapLayout / buildOsMapLayout).
 * We import the pure buildOsMapLayout function directly — no React hooks needed.
 *
 * Key behaviour under test:
 *   - NIC-specific zones (xdp, tc_ingress, tc_egress, netfilter, socket_filter,
 *     flow_dissector, sk_ops) are NOT rendered as kernel zone nodes.
 *   - Those programs appear exclusively on the NIC interface nodes.
 *   - Kernel-only zones (kprobe, tracepoint, perf_event, cgroup, other) ARE
 *     rendered as zone nodes — but only when they have at least one program.
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
      {
        id: 3,
        type: "kprobe",
        rawType: "kprobe",
        name: "trace_sys_open",
        tag: "aabbccdd99887766",
        gplCompatible: true,
        loadedAt: 1700000002,
        orphaned: false,
        bytesXlated: 256,
        jited: true,
        memlock: 4096,
        mapIds: [],
        attachments: [],
        osiLayer: "kernel",
        color: "#f59e0b",
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
        programs: [{ id: 1 } as any],
        osiLayer: "L2",
      },
      {
        zone: "cgroup",
        label: "Cgroup Hooks",
        description: "Cgroup BPF programs",
        programs: [{ id: 2 } as any],
        osiLayer: "kernel",
      },
      {
        zone: "kprobe",
        label: "kprobes",
        description: "Kernel probes",
        programs: [{ id: 3 } as any],
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
      total: 3,
      byType: { xdp: 1, cgroup_skb: 1, kprobe: 1 },
      jited: 3,
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

  // ── NIC deduplication ────────────────────────────────────────────────────────

  it("does NOT create zone nodes for NIC-specific hook types (xdp, tc, netfilter, etc.)", () => {
    const layout = buildOsMapLayout(makeSnapshot());
    const zoneNodeIds = layout.nodes
      .filter(n => n.type === "zoneNode")
      .map(n => n.id);

    // These must NOT appear as kernel zone nodes
    expect(zoneNodeIds).not.toContain("zone-xdp");
    expect(zoneNodeIds).not.toContain("zone-tc_ingress");
    expect(zoneNodeIds).not.toContain("zone-tc_egress");
    expect(zoneNodeIds).not.toContain("zone-netfilter");
    expect(zoneNodeIds).not.toContain("zone-socket_filter");
    expect(zoneNodeIds).not.toContain("zone-flow_dissector");
    expect(zoneNodeIds).not.toContain("zone-sk_ops");
  });

  it("creates zone nodes only for kernel-only hook types that have programs", () => {
    const layout = buildOsMapLayout(makeSnapshot());
    const zoneNodeIds = layout.nodes
      .filter(n => n.type === "zoneNode")
      .map(n => n.id);

    // cgroup and kprobe have programs in the fixture → should be present
    expect(zoneNodeIds).toContain("zone-cgroup");
    expect(zoneNodeIds).toContain("zone-kprobe");

    // tracepoint and perf_event have no programs in the fixture → should be absent
    expect(zoneNodeIds).not.toContain("zone-tracepoint");
    expect(zoneNodeIds).not.toContain("zone-perf_event");
  });

  it("shows zone-tracepoint when tracepoint zone has programs", () => {
    const snap = makeSnapshot();
    snap.kernelZones.find(z => z.zone === "tracepoint")!.programs = [{ id: 99 } as any];
    const layout = buildOsMapLayout(snap);
    const zoneNodeIds = layout.nodes.filter(n => n.type === "zoneNode").map(n => n.id);
    expect(zoneNodeIds).toContain("zone-tracepoint");
  });

  it("does not render 'Kernel Hook Zones' section label when all zones are empty", () => {
    const snap = makeSnapshot();
    // Clear all kernel-only zone programs
    snap.kernelZones.forEach(z => { z.programs = []; });
    const layout = buildOsMapLayout(snap);
    const labelNode = layout.nodes.find(n => n.id === "label-zones");
    expect(labelNode).toBeUndefined();
  });

  it("renders 'Kernel Hook Zones' section label when at least one kernel zone has programs", () => {
    const layout = buildOsMapLayout(makeSnapshot()); // kprobe + cgroup have programs
    const labelNode = layout.nodes.find(n => n.id === "label-zones");
    expect(labelNode).toBeDefined();
  });

  // ── NIC interface nodes ───────────────────────────────────────────────────────

  it("creates interface nodes for each network interface", () => {
    const layout = buildOsMapLayout(makeSnapshot());
    const ifaceNodes = layout.nodes.filter(n => n.type === "interfaceNode");
    expect(ifaceNodes.length).toBe(1);
    expect(ifaceNodes[0].id).toBe("iface-eth0");
  });

  it("does not create zone-xdp→iface edge (NIC zones no longer have zone nodes)", () => {
    const snap = makeSnapshot();
    snap.networkInterfaces[0].layers.L2 = [snap.programs[0]];
    snap.networkInterfaces[0].allPrograms = [snap.programs[0]];
    const layout = buildOsMapLayout(snap);
    // Old behaviour: edge from zone-xdp to iface-eth0. New behaviour: no such edge.
    const oldEdge = layout.edges.find(
      e => e.source === "zone-xdp" && e.target === "iface-eth0"
    );
    expect(oldEdge).toBeUndefined();
  });

  // ── Process → target edges ────────────────────────────────────────────────────

  it("routes process→NIC-type program edge to the NIC interface node", () => {
    const snap = makeSnapshot();
    // Attach the XDP program to a process and to eth0
    snap.programs[0].pids = [{ pid: 42, comm: "loader" }];
    snap.networkInterfaces[0].allPrograms = [snap.programs[0]];
    const layout = buildOsMapLayout(snap);
    const edge = layout.edges.find(
      e => e.source === "proc-42" && e.target === "iface-eth0"
    );
    expect(edge).toBeDefined();
  });

  it("routes process→kernel-type program edge to the kernel zone node", () => {
    const snap = makeSnapshot();
    snap.programs[2].pids = [{ pid: 99, comm: "tracer" }]; // kprobe program
    const layout = buildOsMapLayout(snap);
    const edge = layout.edges.find(
      e => e.source === "proc-99" && e.target === "zone-kprobe"
    );
    expect(edge).toBeDefined();
  });

  // ── Cgroup tree ───────────────────────────────────────────────────────────────

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

  // ── General correctness ───────────────────────────────────────────────────────

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

  it("routes map→NIC-type program edge from the NIC interface node", () => {
    const snap = makeSnapshot();
    // XDP program (id=1) is attached to eth0 and uses a map
    snap.networkInterfaces[0].allPrograms = [snap.programs[0]];
    const maps = [
      {
        id: 10,
        type: "hash",
        rawType: "hash",
        name: "xdp_map",
        flags: 0,
        bytesKey: 4,
        bytesValue: 8,
        maxEntries: 128,
        bytesMemlock: 4096,
        frozen: false,
        pinnedPaths: [],
        btfId: null,
        usedByProgIds: [1], // used by the XDP program
        color: "#a78bfa",
        category: "data",
      },
    ];
    const layout = buildOsMapLayout(snap, maps as any);
    const mapEdge = layout.edges.find(
      e => e.source === "iface-eth0" && e.target === "map-10"
    );
    expect(mapEdge).toBeDefined();
    // Must NOT come from zone-xdp (which no longer exists)
    const badEdge = layout.edges.find(
      e => e.source === "zone-xdp" && e.target === "map-10"
    );
    expect(badEdge).toBeUndefined();
  });

  // ── Dynamic network band height ───────────────────────────────────────────────

  it("network band bottom edge is below all interface nodes (no overlap)", () => {
    const snap = makeSnapshot();
    // Give eth0 programs in all four layers to maximise node height
    const prog = snap.programs[0];
    snap.networkInterfaces[0].layers = {
      L2: [prog],
      L3: [prog],
      L4: [prog],
      L7: [prog],
    };
    snap.networkInterfaces[0].allPrograms = [prog];
    const layout = buildOsMapLayout(snap);

    const netBand = layout.nodes.find(n => n.id === "band-network")!;
    const ifaceNode = layout.nodes.find(n => n.id === "iface-eth0")!;

    const netBandBottom = netBand.position.y + (netBand.data as any).height;
    // The interface node does not have a fixed height in the style (it's auto),
    // so we just verify the band bottom is well below the node top + a minimum height.
    expect(netBandBottom).toBeGreaterThan(ifaceNode.position.y + 150);
  });

  it("network band is taller when interfaces have more programs", () => {
    const prog = makeSnapshot().programs[0];

    const snapFew = makeSnapshot();
    snapFew.networkInterfaces[0].layers = { L2: [prog], L3: [], L4: [], L7: [] };
    const layoutFew = buildOsMapLayout(snapFew);
    const bandFew = layoutFew.nodes.find(n => n.id === "band-network")!;

    const snapMany = makeSnapshot();
    snapMany.networkInterfaces[0].layers = { L2: [prog], L3: [prog], L4: [prog], L7: [prog] };
    const layoutMany = buildOsMapLayout(snapMany);
    const bandMany = layoutMany.nodes.find(n => n.id === "band-network")!;

    expect((bandMany.data as any).height).toBeGreaterThan((bandFew.data as any).height);
  });

  it("BPF Maps section starts below the network band bottom edge", () => {
    const prog = makeSnapshot().programs[0];
    const snap = makeSnapshot();
    snap.networkInterfaces[0].layers = { L2: [prog], L3: [prog], L4: [prog], L7: [prog] };
    snap.networkInterfaces[0].allPrograms = [prog];
    const maps = [{
      id: 10, type: "hash", rawType: "hash", name: "test_map",
      flags: 0, bytesKey: 4, bytesValue: 8, maxEntries: 128,
      bytesMemlock: 4096, frozen: false, pinnedPaths: [], btfId: null,
      usedByProgIds: [], color: "#a78bfa", category: "data",
    }];
    const layout = buildOsMapLayout(snap, maps as any);

    const netBand = layout.nodes.find(n => n.id === "band-network")!;
    const mapLabel = layout.nodes.find(n => n.id === "label-maps")!;
    const netBandBottom = netBand.position.y + (netBand.data as any).height;

    // The maps label should start below the network band
    expect(mapLabel.position.y).toBeGreaterThan(netBandBottom - 1);
  });
});

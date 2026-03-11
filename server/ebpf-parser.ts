import type {
  BpfAttachment,
  BpfProgram,
  BpfProgType,
  CgroupNode,
  EbpfSnapshot,
  KernelAttachmentZone,
  KernelZone,
  NetworkInterface,
  OsiLayer,
  RawBpfProg,
  RawCgroupEntry,
  RawNetSnapshot,
} from "../shared/ebpf-types";

// ─── Type normalization ────────────────────────────────────────────────────

const TYPE_MAP: Record<string, BpfProgType> = {
  xdp: "xdp",
  sched_cls: "sched_cls",
  sched_act: "sched_act",
  kprobe: "kprobe",
  kretprobe: "kretprobe",
  tracepoint: "tracepoint",
  raw_tracepoint: "raw_tracepoint",
  raw_tracepoint_writable: "raw_tracepoint",
  perf_event: "perf_event",
  cgroup_skb: "cgroup_skb",
  cgroup_sock: "cgroup_sock",
  cgroup_device: "cgroup_device",
  cgroup_sysctl: "cgroup_sysctl",
  cgroup_sockopt: "cgroup_sockopt",
  sock_ops: "sock_ops",
  sk_skb: "sk_skb",
  sk_msg: "sk_msg",
  sk_lookup: "sk_lookup",
  flow_dissector: "flow_dissector",
  netfilter: "netfilter",
  lsm: "lsm",
  struct_ops: "struct_ops",
  fentry: "fentry",
  fexit: "fexit",
  freplace: "freplace",
  lirc_mode2: "lirc_mode2",
  lwt_in: "lwt_in",
  lwt_out: "lwt_out",
  lwt_xmit: "lwt_xmit",
  lwt_seg6local: "lwt_seg6local",
  socket_filter: "socket_filter",
};

// ─── Color palette by type ─────────────────────────────────────────────────

export const TYPE_COLORS: Record<string, string> = {
  xdp:            "#00d4ff",
  sched_cls:      "#7c3aed",
  sched_act:      "#6d28d9",
  kprobe:         "#f59e0b",
  kretprobe:      "#d97706",
  tracepoint:     "#10b981",
  raw_tracepoint: "#059669",
  perf_event:     "#f97316",
  cgroup_skb:     "#3b82f6",
  cgroup_sock:    "#2563eb",
  cgroup_device:  "#1d4ed8",
  cgroup_sysctl:  "#1e40af",
  cgroup_sockopt: "#1e3a8a",
  sock_ops:       "#8b5cf6",
  sk_skb:         "#a78bfa",
  sk_msg:         "#c4b5fd",
  sk_lookup:      "#ddd6fe",
  flow_dissector: "#ec4899",
  netfilter:      "#f43f5e",
  lsm:            "#ef4444",
  fentry:         "#84cc16",
  fexit:          "#65a30d",
  freplace:       "#4d7c0f",
  struct_ops:     "#14b8a6",
  unknown:        "#6b7280",
};

function normalizeType(raw: string): BpfProgType {
  return TYPE_MAP[raw] ?? "unknown";
}

function getColor(type: BpfProgType): string {
  return TYPE_COLORS[type] ?? TYPE_COLORS.unknown;
}

function getOsiLayer(type: BpfProgType): OsiLayer {
  switch (type) {
    case "xdp":
      return "L2";
    case "sched_cls":
    case "sched_act":
    case "flow_dissector":
    case "netfilter":
      return "L3";
    case "socket_filter":
    case "sk_skb":
    case "sk_lookup":
    case "cgroup_skb":
      return "L4";
    case "sock_ops":
    case "sk_msg":
    case "cgroup_sock":
    case "cgroup_sockopt":
      return "L7";
    default:
      return "kernel";
  }
}

function getKernelZone(type: BpfProgType): KernelZone {
  switch (type) {
    case "xdp":
      return "xdp";
    case "sched_cls":
    case "sched_act":
      return "tc_ingress"; // will be refined by attachment info
    case "socket_filter":
    case "sk_skb":
    case "sk_msg":
    case "sk_lookup":
      return "socket_filter";
    case "kprobe":
    case "kretprobe":
    case "fentry":
    case "fexit":
    case "freplace":
      return "kprobe";
    case "tracepoint":
    case "raw_tracepoint":
      return "tracepoint";
    case "perf_event":
      return "perf_event";
    case "cgroup_skb":
    case "cgroup_sock":
    case "cgroup_device":
    case "cgroup_sysctl":
    case "cgroup_sockopt":
    case "sock_ops":
      return "cgroup";
    case "flow_dissector":
      return "flow_dissector";
    case "netfilter":
      return "netfilter";
    case "lsm":
    case "struct_ops":
    default:
      return "other";
  }
}

// ─── Parse raw prog list ───────────────────────────────────────────────────

export function parseProgList(raw: RawBpfProg[]): Map<number, BpfProgram> {
  const map = new Map<number, BpfProgram>();
  for (const r of raw) {
    const type = normalizeType(r.type);
    const prog: BpfProgram = {
      id: r.id,
      type,
      rawType: r.type,
      name: (r.name && r.name.trim()) ? r.name.trim() : `${r.type}_${r.id}`,
      tag: r.tag || "0000000000000000",
      gplCompatible: r.gpl_compatible ?? false,
      loadedAt: r.loaded_at ?? 0,
      orphaned: r.orphaned ?? false,
      bytesXlated: r.bytes_xlated ?? 0,
      jited: r.jited ?? false,
      memlock: r.bytes_memlock ?? 0,
      mapIds: r.map_ids ?? [],
      btfId: r.btf_id,
      runTimeNs: r.run_time_ns,
      runCnt: r.run_cnt,
      pids: r.pids,
      attachments: [],
      osiLayer: getOsiLayer(type),
      color: getColor(type),
    };
    map.set(prog.id, prog);
  }
  return map;
}

// ─── Enrich with net attachments ──────────────────────────────────────────

export function enrichWithNetAttachments(
  progs: Map<number, BpfProgram>,
  net: RawNetSnapshot[]
): void {
  const snapshot = net[0] ?? {};

  for (const entry of snapshot.xdp ?? []) {
    const p = progs.get(entry.id);
    if (!p) continue;
    p.attachments.push({
      kind: "xdp",
      detail: `${entry.devname} (${entry.mode ?? "driver"})`,
      ifname: entry.devname,
    });
  }

  for (const entry of snapshot.tc ?? []) {
    const p = progs.get(entry.id);
    if (!p) continue;
    const isIngress = entry.kind?.includes("ingress");
    p.attachments.push({
      kind: "tc",
      detail: `${entry.devname} ${entry.kind ?? "tc"} ${entry.name ? `[${entry.name}]` : ""}`.trim(),
      ifname: entry.devname,
    });
    // refine kernel zone
    if (p.type === "sched_cls" || p.type === "sched_act") {
      // keep as-is, zone already set
    }
  }

  for (const entry of snapshot.tcx ?? []) {
    const p = progs.get(entry.id);
    if (!p) continue;
    p.attachments.push({
      kind: "tcx",
      detail: `${entry.devname} tcx`,
      ifname: entry.devname,
    });
  }

  for (const entry of snapshot.flow_dissector ?? []) {
    const p = progs.get(entry.id);
    if (!p) continue;
    p.attachments.push({
      kind: "flow_dissector",
      detail: `${entry.devname} flow_dissector`,
      ifname: entry.devname,
    });
  }

  for (const entry of snapshot.netfilter ?? []) {
    const p = progs.get(entry.id);
    if (!p) continue;
    p.attachments.push({
      kind: "netfilter",
      detail: `netfilter id=${entry.id}`,
    });
  }
}

// ─── Enrich with cgroup attachments ───────────────────────────────────────

export function enrichWithCgroupAttachments(
  progs: Map<number, BpfProgram>,
  cgroups: RawCgroupEntry[]
): void {
  for (const cg of cgroups) {
    for (const cp of cg.programs ?? []) {
      const p = progs.get(cp.id);
      if (!p) continue;
      p.attachments.push({
        kind: "cgroup",
        detail: `${cp.attach_type}${cp.attach_flags ? ` [${cp.attach_flags}]` : ""}`,
        cgroupPath: cg.cgroup,
        attachFlags: cp.attach_flags,
      });
    }
  }
}

// ─── Build network interface view ─────────────────────────────────────────

export function buildNetworkInterfaces(
  progs: Map<number, BpfProgram>,
  net: RawNetSnapshot[]
): NetworkInterface[] {
  const snapshot = net[0] ?? {};
  const ifaceMap = new Map<string, NetworkInterface>();

  const getOrCreate = (name: string, ifindex: number): NetworkInterface => {
    if (!ifaceMap.has(name)) {
      ifaceMap.set(name, {
        name,
        ifindex,
        layers: { L2: [], L3: [], L4: [], L7: [] },
        allPrograms: [],
      });
    }
    return ifaceMap.get(name)!;
  };

  for (const entry of snapshot.xdp ?? []) {
    const p = progs.get(entry.id);
    if (!p) continue;
    const iface = getOrCreate(entry.devname, entry.ifindex);
    iface.layers.L2.push(p);
    iface.allPrograms.push(p);
  }

  for (const entry of [...(snapshot.tc ?? []), ...(snapshot.tcx ?? [])]) {
    const p = progs.get(entry.id);
    if (!p) continue;
    const iface = getOrCreate(entry.devname, entry.ifindex);
    iface.layers.L3.push(p);
    iface.allPrograms.push(p);
  }

  for (const entry of [...(snapshot.netfilter ?? []), ...(snapshot.flow_dissector ?? [])]) {
    const p = progs.get(entry.id);
    if (!p) continue;
    const iface = getOrCreate(entry.devname, entry.ifindex);
    iface.layers.L3.push(p);
    iface.allPrograms.push(p);
  }

  for (const entry of snapshot.netkit ?? []) {
    const p = progs.get(entry.id);
    if (!p) continue;
    const iface = getOrCreate(entry.devname, entry.ifindex);
    iface.layers.L2.push(p);
    iface.allPrograms.push(p);
  }

  // Sockmap/sockhash entries: route to L4 or L7 based on program type.
  // sk_skb and sk_lookup operate at the transport layer (L4).
  // sk_msg and sock_ops operate at the application/socket layer (L7).
  for (const entry of snapshot.sockmap ?? []) {
    const p = progs.get(entry.id);
    if (!p) continue;
    const iface = getOrCreate(entry.devname, entry.ifindex);
    const layer = (p.type === "sk_msg" || p.type === "sock_ops") ? "L7" : "L4";
    iface.layers[layer].push(p);
    iface.allPrograms.push(p);
  }

  return Array.from(ifaceMap.values() as Iterable<NetworkInterface>);
}

// ─── Build cgroup tree ─────────────────────────────────────────────────────

export function buildCgroupTree(
  progs: Map<number, BpfProgram>,
  cgroups: RawCgroupEntry[]
): CgroupNode[] {
  // Build a flat map first
  const nodeMap = new Map<string, CgroupNode>();

  for (const cg of cgroups) {
    const path = cg.cgroup;
    const parts = path.replace(/^\/sys\/fs\/cgroup/, "").split("/").filter(Boolean);
    const name = parts[parts.length - 1] || "/";
    const depth = parts.length;

    const programs: BpfProgram[] = [];
    for (const cp of cg.programs ?? []) {
      const p = progs.get(cp.id);
      if (p) programs.push(p);
    }

    nodeMap.set(path, {
      path,
      name,
      depth,
      programs,
      children: [],
    });
  }

  // Wire up parent-child relationships
  const roots: CgroupNode[] = [];
  for (const [path, node] of Array.from(nodeMap.entries())) {
    // Find parent: strip last segment
    const parentPath = path.substring(0, path.lastIndexOf("/"));
    const parent = nodeMap.get(parentPath);
    if (parent) {
      parent.children.push(node);
    } else {
      // Try the cgroup root
      const cgroupRoot = "/sys/fs/cgroup";
      if (path !== cgroupRoot) {
        // Check if parent is the root
        const relPath = path.replace(/^\/sys\/fs\/cgroup\//, "");
        if (!relPath.includes("/")) {
          roots.push(node);
        } else {
          roots.push(node); // orphan, show at top
        }
      }
    }
  }

  // Sort children alphabetically
  const sortChildren = (node: CgroupNode) => {
    node.children.sort((a: CgroupNode, b: CgroupNode) => a.name.localeCompare(b.name));
    node.children.forEach(sortChildren);
  };
  roots.forEach(sortChildren);
  roots.sort((a: CgroupNode, b: CgroupNode) => a.name.localeCompare(b.name));

  return roots;
}

// ─── Build kernel zones ────────────────────────────────────────────────────

const ZONE_META: Record<KernelZone, { label: string; description: string }> = {
  xdp:            { label: "XDP",            description: "eXpress Data Path — earliest NIC driver hook" },
  tc_ingress:     { label: "TC Ingress",      description: "Traffic Control ingress classifier/action" },
  tc_egress:      { label: "TC Egress",       description: "Traffic Control egress classifier/action" },
  socket_filter:  { label: "Socket Filter",   description: "sk_filter / sk_skb / sk_msg / sk_lookup" },
  kprobe:         { label: "kprobe/fentry",   description: "Kernel function entry/exit probes" },
  tracepoint:     { label: "Tracepoint",      description: "Static kernel tracepoints & raw tracepoints" },
  perf_event:     { label: "Perf Event",      description: "Hardware/software performance counters" },
  cgroup:         { label: "Cgroup Hooks",    description: "cgroup_skb, cgroup_sock, sock_ops, device" },
  flow_dissector: { label: "Flow Dissector",  description: "Custom packet flow dissection" },
  netfilter:      { label: "Netfilter",       description: "Netfilter / nftables BPF hooks" },
  sk_ops:         { label: "Socket Ops",      description: "TCP socket operations callbacks" },
  other:          { label: "Other",           description: "LSM, struct_ops, and other program types" },
};

export function buildKernelZones(progs: Map<number, BpfProgram>): KernelAttachmentZone[] {
  const zoneMap = new Map<KernelZone, BpfProgram[]>();

  for (const p of Array.from(progs.values())) {
    let zone = getKernelZone(p.type);

    // Refine TC direction from attachment info
    if (zone === "tc_ingress") {
      const hasEgress = p.attachments.some(a =>
        a.detail.toLowerCase().includes("egress")
      );
      if (hasEgress) zone = "tc_egress";
    }

    if (!zoneMap.has(zone)) zoneMap.set(zone, []);
    zoneMap.get(zone)!.push(p);
  }

  const orderedZones: KernelZone[] = [
    "xdp", "tc_ingress", "tc_egress", "netfilter",
    "socket_filter", "flow_dissector",
    "cgroup", "sk_ops",
    "kprobe", "tracepoint", "perf_event",
    "other",
  ];

  return orderedZones
    .filter(z => zoneMap.has(z))
    .map(z => ({
      zone: z,
      label: ZONE_META[z].label,
      description: ZONE_META[z].description,
      programs: zoneMap.get(z) ?? [],
      osiLayer: z === "xdp" ? "L2" : z === "tc_ingress" || z === "tc_egress" || z === "netfilter" ? "L3" : z === "socket_filter" ? "L4" : "kernel",
    }));
}

// ─── Master parse function ─────────────────────────────────────────────────

export function buildSnapshot(
  rawProgs: RawBpfProg[],
  rawNet: RawNetSnapshot[],
  rawCgroups: RawCgroupEntry[],
  meta: { hostname: string; kernelVersion: string; bpftoolVersion: string; demoMode: boolean }
): EbpfSnapshot {
  const progMap = parseProgList(rawProgs);
  enrichWithNetAttachments(progMap, rawNet);
  enrichWithCgroupAttachments(progMap, rawCgroups);

  const programs = Array.from(progMap.values());
  const byType: Record<string, number> = {};
  for (const p of programs) {
    byType[p.rawType] = (byType[p.rawType] ?? 0) + 1;
  }

  return {
    timestamp: Date.now(),
    hostname: meta.hostname,
    kernelVersion: meta.kernelVersion,
    bpftoolVersion: meta.bpftoolVersion,
    demoMode: meta.demoMode,
    programs,
    networkInterfaces: buildNetworkInterfaces(progMap, rawNet),
    cgroupTree: buildCgroupTree(progMap, rawCgroups),
    kernelZones: buildKernelZones(progMap),
    stats: {
      total: programs.length,
      byType,
      jited: programs.filter(p => p.jited).length,
      orphaned: programs.filter(p => p.orphaned).length,
    },
  };
}

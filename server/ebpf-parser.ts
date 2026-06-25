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
  PacketChainContext,
  PacketDirection,
  ProgramChain,
  RawBpfProg,
  RawCgroupEntry,
  RawNetEntry,
  RawNetSnapshot,
  RawTcFilterEntry,
} from "../shared/ebpf-types";
import { BPF_PROGRAM_TYPE_COLORS } from "../shared/ebpf-constants";

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
  cgroup_sock_addr: "cgroup_sock_addr",
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

function normalizeType(raw: string): BpfProgType {
  return TYPE_MAP[raw] ?? "unknown";
}

function getColor(type: BpfProgType): string {
  return BPF_PROGRAM_TYPE_COLORS[type] ?? BPF_PROGRAM_TYPE_COLORS.unknown;
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
    case "cgroup_sock_addr":
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

type TcProgramEntry = {
  id: number;
  name: string;
  devname: string;
  ifindex: number;
  kind: string;
  direction: PacketDirection;
  chain: number;
  priority?: number;
  order: number;
  protocol?: string;
  handle?: string;
  directAction?: boolean;
  actionCount?: number;
  stats?: {
    bytes?: number;
    packets?: number;
    drops?: number;
  };
};

function asFiniteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : undefined;
}

function tcDirectionFromKind(kind: string | undefined): PacketDirection {
  if (kind?.includes("ingress")) return "ingress";
  if (kind?.includes("egress")) return "egress";
  return "unknown";
}

function tcDirectionOrder(direction: PacketDirection): number {
  switch (direction) {
    case "ingress":
      return 0;
    case "egress":
      return 1;
    default:
      return 2;
  }
}

function tcKindFromDirection(direction: RawTcFilterEntry["direction"]): string {
  return direction === "ingress" ? "clsact/ingress" : "clsact/egress";
}

function tcHookKey(devname: string, kind: string, chain = 0): string {
  return chain === 0
    ? `${devname}:${kind}`
    : `${devname}:${kind}:chain:${chain}`;
}

function summarizeTcActionStats(
  actions: unknown[] | undefined
): TcProgramEntry["stats"] | undefined {
  if (!actions) return undefined;
  const stats: TcProgramEntry["stats"] = {};
  for (const action of actions) {
    if (!action || typeof action !== "object") continue;
    const actionStats = (action as { stats?: unknown }).stats;
    if (!actionStats || typeof actionStats !== "object") continue;
    const candidate = actionStats as Record<string, unknown>;
    for (const key of ["bytes", "packets", "drops"] as const) {
      const value = asFiniteNumber(candidate[key]);
      if (value !== undefined) {
        stats[key] = (stats[key] ?? 0) + value;
      }
    }
  }
  return Object.keys(stats).length > 0 ? stats : undefined;
}

function tcProgramEntriesFromFilters(
  progs: Map<number, BpfProgram>,
  snapshot: RawNetSnapshot
): TcProgramEntry[] {
  const entries: TcProgramEntry[] = [];
  const seen = new Set<string>();
  const ifindexByDevname = new Map<string, number>();
  for (const entry of [
    ...(snapshot.xdp ?? []),
    ...(snapshot.tc ?? []),
    ...(snapshot.tcx ?? []),
    ...(snapshot.netkit ?? []),
    ...(snapshot.flow_dissector ?? []),
    ...(snapshot.netfilter ?? []),
  ]) {
    ifindexByDevname.set(entry.devname, entry.ifindex);
  }

  const filters: RawTcFilterEntry[] = (snapshot.tcFilters ?? []).flatMap(
    filter => {
      if ("filters" in filter && Array.isArray(filter.filters)) {
        return filter.filters.map((nestedFilter, order) => ({
          ...nestedFilter,
          devname: filter.devname,
          direction: filter.direction,
          ifindex: filter.ifindex,
          order: nestedFilter.order ?? order,
        }));
      }
      return [filter];
    }
  );
  for (let index = 0; index < filters.length; index++) {
    const filter = filters[index];
    const id = filter.options?.prog?.id;
    if (id === undefined || !progs.has(id)) continue;

    const direction = filter.direction;
    const kind = tcKindFromDirection(direction);
    const chain = filter.chain ?? 0;
    const handle = filter.options?.handle;
    const priority = filter.pref;
    const signature = [
      filter.devname,
      direction,
      chain,
      priority ?? "",
      handle ?? "",
      id,
    ].join(":");
    if (seen.has(signature)) continue;
    seen.add(signature);

    entries.push({
      id,
      name:
        filter.options?.bpf_name ??
        filter.options?.prog?.name ??
        progs.get(id)!.name,
      devname: filter.devname,
      ifindex: filter.ifindex ?? ifindexByDevname.get(filter.devname) ?? 0,
      kind,
      direction,
      chain,
      priority,
      order: filter.order ?? index,
      protocol: filter.protocol,
      handle,
      directAction: filter.options?.["direct-action"],
      actionCount: filter.options?.actions?.length,
      stats: summarizeTcActionStats(filter.options?.actions),
    });
  }

  return entries.sort((a, b) => {
    if (a.devname !== b.devname) return a.devname.localeCompare(b.devname);
    const directionDelta =
      tcDirectionOrder(a.direction) - tcDirectionOrder(b.direction);
    if (directionDelta !== 0) return directionDelta;
    if (a.chain !== b.chain) return a.chain - b.chain;
    if (a.kind !== b.kind) return a.kind.localeCompare(b.kind);
    if ((a.priority ?? Infinity) !== (b.priority ?? Infinity)) {
      return (a.priority ?? Infinity) - (b.priority ?? Infinity);
    }
    return a.order - b.order;
  });
}

function detailedTcHookKeys(entries: TcProgramEntry[]): Set<string> {
  return new Set(entries.map(entry => tcHookKey(entry.devname, entry.kind, entry.chain)));
}

function tcLayerEntries(
  progs: Map<number, BpfProgram>,
  snapshot: RawNetSnapshot
): RawNetEntry[] {
  const detailed = tcProgramEntriesFromFilters(progs, snapshot);
  if (detailed.length === 0) {
    return [...(snapshot.tc ?? []), ...(snapshot.tcx ?? [])];
  }

  const detailedHooks = detailedTcHookKeys(detailed);
  const coarseEntries = [...(snapshot.tc ?? []), ...(snapshot.tcx ?? [])].filter(
    entry => !detailedHooks.has(tcHookKey(entry.devname, entry.kind ?? "tc"))
  );
  const detailedEntries: RawNetEntry[] = detailed.map(entry => ({
    devname: entry.devname,
    ifindex: entry.ifindex,
    kind: entry.kind,
    id: entry.id,
    name: entry.name,
  }));

  return [...coarseEntries, ...detailedEntries];
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
    case "cgroup_sock_addr":
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
      name: r.name && r.name.trim() ? r.name.trim() : `${r.type}_${r.id}`,
      tag: r.tag || "0000000000000000",
      gplCompatible: r.gpl_compatible ?? false,
      loadedAt: r.loaded_at ?? 0,
      orphaned: r.orphaned ?? false,
      bytesXlated: r.bytes_xlated ?? 0,
      jited: r.jited ?? (r.bytes_jited ?? 0) > 0,
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
    const kindStr = entry.kind ?? "";
    const direction: "ingress" | "egress" | undefined = kindStr.includes(
      "ingress"
    )
      ? "ingress"
      : kindStr.includes("egress")
        ? "egress"
        : undefined;
    p.attachments.push({
      kind: "tc",
      detail:
        `${entry.devname} ${kindStr || "tc"} ${entry.name ? `[${entry.name}]` : ""}`.trim(),
      ifname: entry.devname,
      direction,
    });
  }

  for (const entry of snapshot.tcx ?? []) {
    const p = progs.get(entry.id);
    if (!p) continue;
    const kindStr = entry.kind ?? "";
    const direction: "ingress" | "egress" | undefined = kindStr.includes(
      "ingress"
    )
      ? "ingress"
      : kindStr.includes("egress")
        ? "egress"
        : undefined;
    p.attachments.push({
      kind: "tcx",
      detail: `${entry.devname} tcx${kindStr ? ` ${kindStr}` : ""}`,
      ifname: entry.devname,
      direction,
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

  const getOrCreate = (
    name: string,
    ifindex: number,
    kind: "nic" | "sockmap" = "nic"
  ): NetworkInterface => {
    if (!ifaceMap.has(name)) {
      ifaceMap.set(name, {
        name,
        ifindex,
        kind,
        layers: { L2: [], L3: [], L4: [], L7: [] },
        allPrograms: [],
      });
    }
    return ifaceMap.get(name)!;
  };

  for (const entry of snapshot.xdp ?? []) {
    const p = progs.get(entry.id);
    if (!p) continue;
    const iface = getOrCreate(entry.devname, entry.ifindex, "nic");
    iface.layers.L2.push(p);
    iface.allPrograms.push(p);
  }

  for (const entry of tcLayerEntries(progs, snapshot)) {
    const p = progs.get(entry.id);
    if (!p) continue;
    const iface = getOrCreate(entry.devname, entry.ifindex, "nic");
    iface.layers.L3.push(p);
    iface.allPrograms.push(p);
  }

  for (const entry of [
    ...(snapshot.netfilter ?? []),
    ...(snapshot.flow_dissector ?? []),
  ]) {
    const p = progs.get(entry.id);
    if (!p) continue;
    const iface = getOrCreate(entry.devname, entry.ifindex, "nic");
    iface.layers.L3.push(p);
    iface.allPrograms.push(p);
  }

  for (const entry of snapshot.netkit ?? []) {
    const p = progs.get(entry.id);
    if (!p) continue;
    const iface = getOrCreate(entry.devname, entry.ifindex, "nic");
    iface.layers.L2.push(p);
    iface.allPrograms.push(p);
  }

  // Sockmap/sockhash entries: route to L4 or L7 based on program type.
  // sk_skb and sk_lookup operate at the transport layer (L4).
  // sk_msg and sock_ops operate at the application/socket layer (L7).
  for (const entry of snapshot.sockmap ?? []) {
    const p = progs.get(entry.id);
    if (!p) continue;
    const iface = getOrCreate(entry.devname, entry.ifindex, "sockmap");
    const layer = p.type === "sk_msg" || p.type === "sock_ops" ? "L7" : "L4";
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
    const parts = path
      .replace(/^\/sys\/fs\/cgroup/, "")
      .split("/")
      .filter(Boolean);
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
  const CGROUP_ROOT = "/sys/fs/cgroup";
  const roots: CgroupNode[] = [];
  for (const [path, node] of Array.from(nodeMap.entries())) {
    if (path === CGROUP_ROOT) {
      // The cgroup root itself is always a top-level root
      roots.push(node);
      continue;
    }
    // Find parent: strip last path segment
    const parentPath = path.substring(0, path.lastIndexOf("/"));
    const parent = nodeMap.get(parentPath);
    if (parent) {
      parent.children.push(node);
    } else if (parentPath === CGROUP_ROOT) {
      // Parent is the cgroup root but it wasn't included in the entries
      roots.push(node);
    } else {
      // Orphan: parent not in entries — show at top level
      roots.push(node);
    }
  }

  // Sort children alphabetically
  const sortChildren = (node: CgroupNode) => {
    node.children.sort((a: CgroupNode, b: CgroupNode) =>
      a.name.localeCompare(b.name)
    );
    node.children.forEach(sortChildren);
  };
  roots.forEach(sortChildren);
  roots.sort((a: CgroupNode, b: CgroupNode) => a.name.localeCompare(b.name));

  return roots;
}

// ─── Build kernel zones ────────────────────────────────────────────────────

const ZONE_META: Record<KernelZone, { label: string; description: string }> = {
  xdp: {
    label: "XDP",
    description: "eXpress Data Path — earliest NIC driver hook",
  },
  tc_ingress: {
    label: "TC Ingress",
    description: "Traffic Control ingress classifier/action",
  },
  tc_egress: {
    label: "TC Egress",
    description: "Traffic Control egress classifier/action",
  },
  socket_filter: {
    label: "Socket Filter",
    description: "sk_filter / sk_skb / sk_msg / sk_lookup",
  },
  kprobe: {
    label: "kprobe/fentry",
    description: "Kernel function entry/exit probes",
  },
  tracepoint: {
    label: "Tracepoint",
    description: "Static kernel tracepoints & raw tracepoints",
  },
  perf_event: {
    label: "Perf Event",
    description: "Hardware/software performance counters",
  },
  cgroup: {
    label: "Cgroup Hooks",
    description: "cgroup_skb, cgroup_sock, sock_ops, device",
  },
  flow_dissector: {
    label: "Flow Dissector",
    description: "Custom packet flow dissection",
  },
  netfilter: {
    label: "Netfilter",
    description: "Netfilter / nftables BPF hooks",
  },
  sk_ops: {
    label: "Socket Ops",
    description: "TCP socket operations callbacks",
  },
  other: {
    label: "Other",
    description: "LSM, struct_ops, and other program types",
  },
};

export function buildKernelZones(
  progs: Map<number, BpfProgram>
): KernelAttachmentZone[] {
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
    "xdp",
    "tc_ingress",
    "tc_egress",
    "netfilter",
    "socket_filter",
    "flow_dissector",
    "cgroup",
    "sk_ops",
    "kprobe",
    "tracepoint",
    "perf_event",
    "other",
  ];

  return orderedZones
    .filter(z => zoneMap.has(z))
    .map(z => ({
      zone: z,
      label: ZONE_META[z].label,
      description: ZONE_META[z].description,
      programs: zoneMap.get(z) ?? [],
      osiLayer:
        z === "xdp"
          ? "L2"
          : z === "tc_ingress" || z === "tc_egress" || z === "netfilter"
            ? "L3"
            : z === "socket_filter"
              ? "L4"
              : "kernel",
    }));
}

// ─── Build program chains (execution order at shared hook points) ────────

/** Cgroup attach types where eBPF Viz currently models an early terminal
 *  allow/drop verdict well enough to explain downstream reachability. */
const CGROUP_SHORT_CIRCUIT_TYPES = new Set([
  "cgroup_inet_ingress",
  "cgroup_inet_egress",
  "cgroup_inet4_bind",
  "cgroup_inet6_bind",
  "cgroup_bind4",
  "cgroup_bind6",
  "cgroup_inet4_connect",
  "cgroup_inet6_connect",
  "cgroup_connect4",
  "cgroup_connect6",
  "cgroup_inet4_getpeername",
  "cgroup_inet6_getpeername",
  "cgroup_inet4_getsockname",
  "cgroup_inet6_getsockname",
  "cgroup_udp4_sendmsg",
  "cgroup_udp6_sendmsg",
  "cgroup_sendmsg4",
  "cgroup_sendmsg6",
  "cgroup_udp4_recvmsg",
  "cgroup_udp6_recvmsg",
  "cgroup_recvmsg4",
  "cgroup_recvmsg6",
]);

const CGROUP_SOCK_ADDR_TYPES = new Set([
  "cgroup_inet4_bind",
  "cgroup_inet6_bind",
  "cgroup_inet4_connect",
  "cgroup_inet6_connect",
  "cgroup_bind4",
  "cgroup_bind6",
  "cgroup_connect4",
  "cgroup_connect6",
  "cgroup_inet4_getpeername",
  "cgroup_inet6_getpeername",
  "cgroup_inet4_getsockname",
  "cgroup_inet6_getsockname",
  "cgroup_udp4_sendmsg",
  "cgroup_udp6_sendmsg",
  "cgroup_udp4_recvmsg",
  "cgroup_udp6_recvmsg",
  "cgroup_sendmsg4",
  "cgroup_sendmsg6",
  "cgroup_recvmsg4",
  "cgroup_recvmsg6",
]);

const CGROUP_SOCK_TYPES = new Set([
  "cgroup_inet4_post_bind",
  "cgroup_inet6_post_bind",
  "cgroup_sock_create",
  "cgroup_inet_sock_create",
  "cgroup_sock_ops",
  "cgroup_sockops",
  "cgroup_sock_release",
  "cgroup_getsockopt",
  "cgroup_setsockopt",
]);

interface CgroupChainProgramEntry {
  id: number;
  name: string;
  attachFlags?: string;
  attachPath: string;
}

function cgroupDepth(path: string): number {
  return path
    .replace(/^\/sys\/fs\/cgroup/, "")
    .split("/")
    .filter(Boolean).length;
}

function parentCgroupPath(path: string): string | undefined {
  if (path === "/sys/fs/cgroup") return undefined;
  const parent = path.substring(0, path.lastIndexOf("/"));
  return parent || undefined;
}

function nearestKnownParentPath(
  path: string,
  knownPaths: Set<string>
): string | undefined {
  let parent = parentCgroupPath(path);
  while (parent) {
    if (knownPaths.has(parent)) return parent;
    parent = parentCgroupPath(parent);
  }
  return undefined;
}

function hasCgroupAttachFlag(
  attachFlags: string | undefined,
  flag: "multi" | "override"
): boolean {
  return new RegExp(`(^|[^a-z])${flag}([^a-z]|$)`).test(
    attachFlags?.toLowerCase() ?? ""
  );
}

function cloneCgroupEffectiveMap(
  source?: Map<string, CgroupChainProgramEntry[]>
): Map<string, CgroupChainProgramEntry[]> {
  return new Map(
    Array.from(source?.entries() ?? []).map(([attachType, entries]) => [
      attachType,
      [...entries],
    ])
  );
}

function cgroupProgramSequenceKey(
  entries: CgroupChainProgramEntry[] | undefined
): string {
  return (entries ?? [])
    .map(
      entry =>
        `${entry.attachPath}:${entry.id}:${entry.attachFlags ?? ""}`
    )
    .join("|");
}

function directCgroupProgramsByType(
  progs: Map<number, BpfProgram>,
  cg: RawCgroupEntry
): Map<string, CgroupChainProgramEntry[]> {
  const byType = new Map<string, CgroupChainProgramEntry[]>();
  for (const cp of cg.programs ?? []) {
    if (!progs.has(cp.id) || !cp.attach_type) continue;
    if (!byType.has(cp.attach_type)) byType.set(cp.attach_type, []);
    byType.get(cp.attach_type)!.push({
      id: cp.id,
      name: cp.name ?? progs.get(cp.id)!.name,
      attachFlags: cp.attach_flags,
      attachPath: cg.cgroup,
    });
  }
  return byType;
}

function mergeEffectiveCgroupPrograms(
  inherited: CgroupChainProgramEntry[],
  direct: CgroupChainProgramEntry[]
): CgroupChainProgramEntry[] {
  if (inherited.length === 0) return [...direct];
  if (direct.length === 0) return [...inherited];

  const inheritedAllowsOverride = inherited.some(entry =>
    hasCgroupAttachFlag(entry.attachFlags, "override")
  );
  const inheritedAllowsMulti = inherited.some(entry =>
    hasCgroupAttachFlag(entry.attachFlags, "multi")
  );
  const directUsesMulti = direct.some(entry =>
    hasCgroupAttachFlag(entry.attachFlags, "multi")
  );

  if (inheritedAllowsOverride && !inheritedAllowsMulti && !directUsesMulti) {
    return [...direct];
  }

  return [...inherited, ...direct];
}

function buildCgroupProgramChains(
  progs: Map<number, BpfProgram>,
  rawCgroups: RawCgroupEntry[]
): ProgramChain[] {
  const chains: ProgramChain[] = [];
  const knownPaths = new Set(rawCgroups.map(cg => cg.cgroup));
  const effectiveByPath = new Map<
    string,
    Map<string, CgroupChainProgramEntry[]>
  >();
  const sortedCgroups = rawCgroups
    .map((cg, index) => ({ cg, index }))
    .sort(
      (a, b) =>
        cgroupDepth(a.cg.cgroup) - cgroupDepth(b.cg.cgroup) ||
        a.index - b.index
    );

  for (const { cg } of sortedCgroups) {
    const parentPath = nearestKnownParentPath(cg.cgroup, knownPaths);
    const parentEffective = effectiveByPath.get(parentPath ?? "");
    const effective = cloneCgroupEffectiveMap(parentEffective);
    const directByType = directCgroupProgramsByType(progs, cg);

    for (const [attachType, directPrograms] of Array.from(
      directByType.entries()
    )) {
      effective.set(
        attachType,
        mergeEffectiveCgroupPrograms(
          effective.get(attachType) ?? [],
          directPrograms
        )
      );
    }

    effectiveByPath.set(cg.cgroup, effective);

    for (const [attachType, effectivePrograms] of Array.from(
      effective.entries()
    )) {
      if (effectivePrograms.length < 2) continue;

      const inheritedPrograms = parentEffective?.get(attachType);
      const changedFromParent =
        cgroupProgramSequenceKey(inheritedPrograms) !==
        cgroupProgramSequenceKey(effectivePrograms);
      if (!directByType.has(attachType) && !changedFromParent) continue;

      const shortName = attachType.replace(/^cgroup_/, "");
      chains.push({
        hookId: `cgroup:${cg.cgroup}:${attachType}`,
        hookLabel: shortName,
        hookType: "cgroup",
        attachPoint: cg.cgroup,
        attachType,
        programs: effectivePrograms.map((program, i) => ({
          id: program.id,
          position: i + 1,
          name: program.name,
          attachFlags: program.attachFlags,
          cgroup: {
            attachPath: program.attachPath,
            inherited: program.attachPath !== cg.cgroup,
            attachFlags: program.attachFlags,
          },
        })),
        canShortCircuit: CGROUP_SHORT_CIRCUIT_TYPES.has(attachType),
        packetContext: buildCgroupPacketContext(attachType),
      });
    }
  }

  return chains;
}

function buildTcPacketContext(direction: PacketDirection): PacketChainContext {
  return {
    family: "tc",
    direction,
    summary:
      "TC classifier/action return values decide whether the packet continues, is dropped, or is redirected.",
    semantics: {
      pass: ["TC_ACT_OK (0)", "TC_ACT_UNSPEC (-1)"],
      passValues: [0, -1],
      drop: ["TC_ACT_SHOT (2)"],
      dropValues: [2],
      redirect: ["TC_ACT_REDIRECT (7)"],
      redirectValues: [7],
      other: [
        "TC_ACT_RECLASSIFY (1)",
        "TC_ACT_PIPE (3)",
        "TC_ACT_STOLEN (4)",
        "TC_ACT_QUEUED (5)",
        "TC_ACT_REPEAT (6)",
      ],
      otherValues: [1, 3, 4, 5, 6],
    },
  };
}

function buildCgroupPacketContext(attachType: string): PacketChainContext {
  if (
    attachType === "cgroup_inet_ingress" ||
    attachType === "cgroup_inet_egress"
  ) {
    return {
      family: "cgroup_skb",
      direction: attachType.endsWith("_ingress") ? "ingress" : "egress",
      summary:
        "cgroup_skb hooks use integer allow/drop verdicts for packet ingress or egress.",
      semantics: {
        pass: ["1 (allow/pass)"],
        passValues: [1],
        drop: ["0 (drop/deny)"],
        dropValues: [0],
        redirect: [],
        other: [],
      },
    };
  }

  if (CGROUP_SOCK_ADDR_TYPES.has(attachType)) {
    return {
      family: "cgroup_sock_addr",
      direction: "unknown",
      summary:
        "cgroup socket-address hooks can allow or deny socket operations before packets are sent.",
      semantics: {
        pass: ["1 (allow)"],
        passValues: [1],
        drop: ["0 (deny)"],
        dropValues: [0],
        redirect: [],
        other: [],
      },
    };
  }

  return {
    family:
      CGROUP_SOCK_TYPES.has(attachType) || attachType.includes("sock")
        ? "cgroup_sock"
        : "unknown",
    direction: "unknown",
    summary: "Return-value semantics for this hook are not modeled yet.",
    semantics: {
      pass: [],
      drop: [],
      redirect: [],
      other: [],
    },
  };
}

export function buildProgramChains(
  progs: Map<number, BpfProgram>,
  rawNet: RawNetSnapshot[],
  rawCgroups: RawCgroupEntry[]
): ProgramChain[] {
  const chains: ProgramChain[] = buildCgroupProgramChains(progs, rawCgroups);

  // ── TC chains ──────────────────────────────────────────────────────────
  const snapshot = rawNet[0] ?? {};
  const detailedTcEntries = tcProgramEntriesFromFilters(progs, snapshot);
  const detailedHooks = detailedTcHookKeys(detailedTcEntries);

  // Group TC entries by hook, preserving kernel execution order.
  const tcByHook = new Map<
    string,
    {
      devname: string;
      kind: string;
      chain: number;
      programs: ProgramChain["programs"];
    }
  >();

  for (const entry of detailedTcEntries) {
    const key = tcHookKey(entry.devname, entry.kind, entry.chain);
    if (!tcByHook.has(key)) {
      tcByHook.set(key, {
        devname: entry.devname,
        kind: entry.kind,
        chain: entry.chain,
        programs: [],
      });
    }

    tcByHook.get(key)!.programs.push({
      id: entry.id,
      position: tcByHook.get(key)!.programs.length + 1,
      name: entry.name,
      tc: {
        protocol: entry.protocol,
        priority: entry.priority,
        chain: entry.chain,
        handle: entry.handle,
        directAction: entry.directAction,
        actionCount: entry.actionCount,
        stats: entry.stats,
      },
    });
  }

  for (const entry of snapshot.tc ?? []) {
    if (!progs.has(entry.id)) continue;
    const kind = entry.kind ?? "tc";
    const key = tcHookKey(entry.devname, kind);
    if (detailedHooks.has(key)) continue;
    if (!tcByHook.has(key)) {
      tcByHook.set(key, {
        devname: entry.devname,
        kind,
        chain: 0,
        programs: [],
      });
    }

    const group = tcByHook.get(key)!;
    // The coarse bpftool net view can repeat the same attachment; avoid
    // manufacturing duplicate chain positions unless detailed tc data says so.
    if (!group.programs.some(p => p.id === entry.id)) {
      group.programs.push({
        id: entry.id,
        position: group.programs.length + 1,
        name: entry.name ?? progs.get(entry.id)!.name,
      });
    }
  }

  for (const [key, group] of Array.from(tcByHook.entries())) {
    if (group.programs.length < 2) continue;
    const direction = tcDirectionFromKind(group.kind);
    chains.push({
      hookId: `tc:${key}`,
      hookLabel: `${group.devname} ${
        direction === "unknown" ? group.kind : direction
      }`,
      hookType: "tc",
      attachPoint: group.devname,
      attachType:
        group.chain === 0 ? group.kind : `${group.kind} chain ${group.chain}`,
      programs: group.programs,
      canShortCircuit: true, // TC programs can return TC_ACT_SHOT
      packetContext: buildTcPacketContext(direction),
    });
  }

  return chains;
}

// ─── Master parse function ─────────────────────────────────────────────────

export function buildSnapshot(
  rawProgs: RawBpfProg[],
  rawNet: RawNetSnapshot[],
  rawCgroups: RawCgroupEntry[],
  meta: {
    hostname: string;
    kernelVersion: string;
    bpftoolVersion: string;
    demoMode: boolean;
  }
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
    programChains: buildProgramChains(progMap, rawNet, rawCgroups),
    stats: {
      total: programs.length,
      byType,
      jited: programs.filter(p => p.jited).length,
      orphaned: programs.filter(p => p.orphaned).length,
    },
  };
}

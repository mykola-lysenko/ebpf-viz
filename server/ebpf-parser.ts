import type {
  BpfAttachment,
  BpfProgram,
  BpfProgType,
  RawBpfLink,
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
  RawNetnsSnapshot,
  RawNetnsLink,
  RawTcFilterEntry,
  NamespaceTopology,
  NamespaceTopologyEndpoint,
  NamespaceTopologyNode,
} from "../shared/ebpf-types";
import { BPF_PROGRAM_TYPE_COLORS, UNRESOLVED_NETNS_LABEL } from "../shared/ebpf-constants";
import { dedupeNetnsLabels } from "./ebpf-netns";

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
  // bpftool reports BPF_PROG_TYPE_TRACING (fentry/fexit/fmod_ret/iter) as
  // "tracing" and BPF_PROG_TYPE_EXT (freplace) as "ext". The fentry/fexit/
  // freplace keys below never appear in `bpftool prog list -j` output; they
  // are kept so older captured snapshots and refined subtypes (e.g. from a
  // future `bpftool link list` join) still normalize.
  tracing: "tracing",
  ext: "freplace",
  fentry: "fentry",
  fexit: "fexit",
  freplace: "freplace",
  sk_reuseport: "sk_reuseport",
  syscall: "syscall",
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
    case "sk_reuseport":
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
      return "other"; // TC direction is only known from attachment info.
    case "socket_filter":
    case "sk_skb":
    case "sk_msg":
    case "sk_lookup":
    case "sk_reuseport":
      return "socket_filter";
    case "kprobe":
    case "kretprobe":
    case "uprobe":
    case "uretprobe":
    case "fentry":
    case "fexit":
    case "freplace":
    case "tracing":
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
    case "struct_ops":
      return "struct_ops";
    case "lsm":
    default:
      return "other";
  }
}

function tcAttachmentZone(program: BpfProgram): KernelZone | undefined {
  const tcAttachments = program.attachments.filter(
    attachment => attachment.kind === "tc" || attachment.kind === "tcx"
  );
  const isEgress = (attachment: BpfAttachment) =>
    attachment.direction === "egress" ||
    attachment.detail.toLowerCase().includes("egress");
  const isIngress = (attachment: BpfAttachment) =>
    attachment.direction === "ingress" ||
    attachment.detail.toLowerCase().includes("ingress");

  // Preserve the previous egress preference for the rare case where one
  // program ID is attached at both directions.
  if (tcAttachments.some(isEgress)) return "tc_egress";
  if (tcAttachments.some(isIngress)) return "tc_ingress";
  return undefined;
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
      pinnedPaths: r.pinned ?? [],
      attachments: [],
      osiLayer: getOsiLayer(type),
      color: getColor(type),
    };
    map.set(prog.id, prog);
  }
  return map;
}

// ─── Enrich with BPF link attachments ──────────────────────────────────────

/** libbpf attach-type strings (as printed by `bpftool link list`) that let us
 *  refine the generic "tracing" prog type into its actual subtype. */
const TRACING_ATTACH_TYPE_MAP: Record<string, BpfProgType> = {
  trace_fentry: "fentry",
  fentry: "fentry",
  trace_fexit: "fexit",
  fexit: "fexit",
};

/** Link types whose attachments are always surfaced by another source
 *  (`bpftool cgroup tree` is cgroup-global) — skip the attachment (but still
 *  use the link for type refinement and pid attribution) to avoid duplicates. */
const LINK_TYPES_COVERED_ELSEWHERE = new Set(["cgroup", "netns", "netfilter"]);

/** Netdev-scoped link types: covered by `bpftool net` only when the scan that
 *  ran could actually see the device's namespace — decided per attachment via
 *  NetdevCoverage, never by devname (bpftool resolves a link's ifindex in its
 *  OWN netns, so a foreign ifindex that collides with a host ifindex gets a
 *  plausible-looking but wrong host devname). */
export const NETDEV_LINK_TYPES = new Set(["xdp", "tcx", "netkit"]);

/** Which netdev attachments the `bpftool net` scans (host + per-netns)
 *  already reported. Matched by link id when the net entry carries one
 *  (link-based tcx/netkit rows do), else by (prog id, ifindex) — the pair
 *  fallback can rarely over-match across namespaces with colliding ifindexes,
 *  but only for legacy non-link entries that carry no link id. */
export interface NetdevCoverage {
  linkIds: Set<number>;
  progIfindexPairs: Set<string>;
}

const EMPTY_NETDEV_COVERAGE: NetdevCoverage = {
  linkIds: new Set(),
  progIfindexPairs: new Set(),
};

/** All netdev-scoped sections of one `bpftool net` snapshot. netfilter
 *  entries carry no ifindex, so ifindex-keyed consumers skip them naturally. */
function netdevNetEntries(snapshot: RawNetSnapshot): RawNetEntry[] {
  return [
    ...(snapshot.xdp ?? []),
    ...(snapshot.tc ?? []),
    ...(snapshot.tcx ?? []),
    ...(snapshot.netkit ?? []),
    ...(snapshot.flow_dissector ?? []),
    ...(snapshot.netfilter ?? []),
  ];
}

export function computeNetdevCoverage(
  rawNet: RawNetSnapshot[],
  rawNetns: RawNetnsSnapshot[]
): NetdevCoverage {
  const coverage: NetdevCoverage = {
    linkIds: new Set(),
    progIfindexPairs: new Set(),
  };
  const snapshots = [rawNet[0] ?? {}, ...rawNetns.map(ns => ns.net[0] ?? {})];
  for (const snapshot of snapshots) {
    for (const entry of netdevNetEntries(snapshot)) {
      if (typeof entry.link_id === "number") coverage.linkIds.add(entry.link_id);
      const progId = netEntryProgId(entry);
      if (progId !== undefined && typeof entry.ifindex === "number") {
        coverage.progIfindexPairs.add(`${progId}:${entry.ifindex}`);
      }
    }
  }
  return coverage;
}

function isCoveredNetdevLink(
  link: RawBpfLink,
  coverage: NetdevCoverage
): boolean {
  if (coverage.linkIds.has(link.id)) return true;
  return (
    typeof link.prog_id === "number" &&
    typeof link.ifindex === "number" &&
    coverage.progIfindexPairs.has(`${link.prog_id}:${link.ifindex}`)
  );
}

function formatOffset(offset: number | undefined): string {
  return offset ? `+0x${offset.toString(16)}` : "";
}

/** bpftool ≥ ~7.5 prints "perf_event"; some earlier builds printed "perf". */
function isPerfLink(link: RawBpfLink): boolean {
  return link.type === "perf" || link.type === "perf_event";
}

function describeLink(link: RawBpfLink): string {
  switch (link.type) {
    case "tracing": {
      const attach = link.attach_type ?? "tracing";
      const target = link.target_btf_id ? ` → btf_id ${link.target_btf_id}` : "";
      return `${attach}${target}`;
    }
    case "raw_tracepoint":
      return `raw_tp ${link.tp_name ?? "?"}`;
    case "perf":
    case "perf_event": {
      if (link.file) {
        const kind = link.retprobe ? "uretprobe" : "uprobe";
        return `${kind} ${link.file}${formatOffset(link.offset)}`;
      }
      if (link.func) {
        const kind = link.retprobe ? "kretprobe" : "kprobe";
        return `${kind} ${link.func}${formatOffset(link.offset)}`;
      }
      if (link.tracepoint) return `tracepoint ${link.tracepoint}`;
      if (link.event_type) {
        return `perf event ${link.event_type}${link.event_config ? `:${link.event_config}` : ""}`;
      }
      return "perf event";
    }
    case "kprobe_multi": {
      const kind = link.retprobe ? "kretprobe" : "kprobe";
      return `${kind}.multi (${link.func_cnt ?? "?"} funcs)`;
    }
    case "uprobe_multi":
      return `uprobe.multi ${link.path ?? "?"} (${link.func_cnt ?? "?"} funcs)`;
    case "iter":
      return `iter ${link.target_name ?? "?"}${link.map_id ? ` map ${link.map_id}` : ""}`;
    case "struct_ops":
      return `struct_ops map ${link.map_id ?? "?"}`;
    case "xdp":
    case "tcx":
    case "netkit":
      // Only links no `bpftool net` scan covered reach here (see
      // NetdevCoverage); the device is in a namespace we could not see into.
      return `${link.attach_type ?? link.type} · ifindex ${link.ifindex ?? "?"} (other netns)`;
    default:
      return `${link.type} link`;
  }
}

/** Refine coarse prog-list types using link attach info:
 *  - "tracing" progs become fentry/fexit when the link says so
 *  - "kprobe" progs become kretprobe/uprobe/uretprobe based on the perf link */
function refineTypeFromLink(prog: BpfProgram, link: RawBpfLink): void {
  let refined: BpfProgType | undefined;

  if (prog.type === "tracing" && link.type === "tracing" && link.attach_type) {
    refined = TRACING_ATTACH_TYPE_MAP[link.attach_type];
  } else if (prog.type === "kprobe") {
    if (isPerfLink(link) && link.file) {
      refined = link.retprobe ? "uretprobe" : "uprobe";
    } else if (
      (isPerfLink(link) && link.func) ||
      link.type === "kprobe_multi"
    ) {
      refined = link.retprobe ? "kretprobe" : "kprobe";
    } else if (link.type === "uprobe_multi") {
      refined = "uprobe";
    }
  }

  if (refined && refined !== prog.type) {
    prog.type = refined;
    prog.color = getColor(refined);
    prog.osiLayer = getOsiLayer(refined);
  }
}

export function enrichWithLinkAttachments(
  progs: Map<number, BpfProgram>,
  links: RawBpfLink[],
  /** Attachments already reported by the `bpftool net` scans (host and
   *  per-netns) — their links don't need a fallback attachment entry. */
  coverage: NetdevCoverage = EMPTY_NETDEV_COVERAGE
): void {
  for (const link of links) {
    if (typeof link?.prog_id !== "number") continue;
    const prog = progs.get(link.prog_id);
    if (!prog) continue;

    refineTypeFromLink(prog, link);

    // Attribute ownership from the link holder when the program itself has
    // no fd holders — common for link-attached programs where the loader
    // keeps only the link fd (e.g. systemd, cilium).
    if ((!prog.pids || prog.pids.length === 0) && link.pids?.length) {
      prog.pids = link.pids;
    }

    // The link's bpffs pin paths are the ownership breadcrumb when nobody
    // holds an fd (e.g. Tetragon pins links under /sys/fs/bpf/tetragon).
    for (const pin of link.pinned ?? []) {
      prog.pinnedPaths ??= [];
      if (!prog.pinnedPaths.includes(pin)) prog.pinnedPaths.push(pin);
    }

    const covered = NETDEV_LINK_TYPES.has(link.type)
      ? isCoveredNetdevLink(link, coverage)
      : LINK_TYPES_COVERED_ELSEWHERE.has(link.type);
    if (!covered) {
      prog.attachments.push({
        kind: "link",
        detail: describeLink(link),
        linkId: link.id,
      });
    }
  }
}

// ─── Enrich with net attachments ──────────────────────────────────────────

/** bpftool net emits `id` for legacy tc/xdp entries but `prog_id` for
 *  link-based tcx/netkit entries. */
function netEntryProgId(entry: RawNetEntry): number | undefined {
  return entry.id ?? entry.prog_id;
}

export function enrichWithNetAttachments(
  progs: Map<number, BpfProgram>,
  net: RawNetSnapshot[],
  netnsLabel?: string
): void {
  const snapshot = net[0] ?? {};
  const suffix = netnsLabel ? ` · netns ${netnsLabel}` : "";

  const push = (
    entries: RawNetEntry[] | undefined,
    kind: BpfAttachment["kind"],
    detail: (entry: RawNetEntry) => string,
    withDirection = false
  ): void => {
    for (const entry of entries ?? []) {
      const p = progs.get(netEntryProgId(entry) ?? -1);
      if (!p) continue;
      const direction = withDirection
        ? directionFromKind(entry.kind)
        : undefined;
      p.attachments.push({
        kind,
        detail: detail(entry) + suffix,
        ...(entry.devname ? { ifname: entry.devname } : {}),
        ...(direction ? { direction } : {}),
      });
    }
  };

  push(snapshot.xdp, "xdp", e => `${e.devname} (${e.mode ?? "driver"})`);
  push(
    snapshot.tc,
    "tc",
    e => `${e.devname} ${e.kind ?? "tc"} ${e.name ? `[${e.name}]` : ""}`.trim(),
    true
  );
  push(snapshot.tcx, "tcx", e => `${e.devname} tcx${e.kind ? ` ${e.kind}` : ""}`, true);
  push(snapshot.netkit, "netkit", e => `${e.devname} netkit${e.kind ? ` ${e.kind}` : ""}`, true);
  push(snapshot.flow_dissector, "flow_dissector", e => `${e.devname} flow_dissector`);
  push(snapshot.netfilter, "netfilter", e => `netfilter id=${netEntryProgId(e)}`);
}

/** "tcx/ingress", "clsact/egress", "netkit/peer" → packet direction. */
function directionFromKind(kind: string | undefined): "ingress" | "egress" | undefined {
  const direction = tcDirectionFromKind(kind ?? "");
  return direction === "ingress" || direction === "egress" ? direction : undefined;
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
  net: RawNetSnapshot[],
  netns: RawNetnsSnapshot[] = [],
  /** Foreign netdev links (xdp/tcx/netkit with an unresolvable device) that
   *  no netns scan covered — rendered as ifindex-only pseudo-interfaces so
   *  the attachment is at least visible when we cannot name its device. */
  unresolvedNetdevLinks: RawBpfLink[] = []
): NetworkInterface[] {
  const ifaceMap = new Map<string, NetworkInterface>();

  const collect = (snapshot: RawNetSnapshot, netnsLabel?: string): void => {
    const getOrCreate = (
      name: string,
      ifindex: number,
      kind: "nic" | "sockmap" = "nic"
    ): NetworkInterface => {
      // Devnames repeat across namespaces (every pod has an eth0) — key by both.
      const key = `${netnsLabel ?? ""}::${name}`;
      if (!ifaceMap.has(key)) {
        ifaceMap.set(key, {
          name,
          ifindex,
          kind,
          ...(netnsLabel ? { netns: netnsLabel } : {}),
          layers: { L2: [], L3: [], L4: [], L7: [] },
          allPrograms: [],
        });
      }
      return ifaceMap.get(key)!;
    };

    for (const entry of snapshot.xdp ?? []) {
      const p = progs.get(netEntryProgId(entry) ?? -1);
      if (!p) continue;
      const iface = getOrCreate(entry.devname, entry.ifindex, "nic");
      iface.layers.L2.push(p);
      iface.allPrograms.push(p);
    }

    for (const entry of tcLayerEntries(progs, snapshot)) {
      const p = progs.get(netEntryProgId(entry) ?? -1);
      if (!p) continue;
      const iface = getOrCreate(entry.devname, entry.ifindex, "nic");
      // netkit programs ride the tc section (kind "netkit/peer|primary") but
      // hook the device like XDP does — show them at L2 with other netkit.
      const layer = entry.kind?.startsWith("netkit") ? "L2" : "L3";
      iface.layers[layer].push(p);
      iface.allPrograms.push(p);
    }

    for (const entry of [
      ...(snapshot.netfilter ?? []),
      ...(snapshot.flow_dissector ?? []),
    ]) {
      const p = progs.get(netEntryProgId(entry) ?? -1);
      if (!p) continue;
      const iface = getOrCreate(entry.devname, entry.ifindex, "nic");
      iface.layers.L3.push(p);
      iface.allPrograms.push(p);
    }

    for (const entry of snapshot.netkit ?? []) {
      const p = progs.get(netEntryProgId(entry) ?? -1);
      if (!p) continue;
      const iface = getOrCreate(entry.devname, entry.ifindex, "nic");
      iface.layers.L2.push(p);
      iface.allPrograms.push(p);
    }

    // Sockmap/sockhash entries: route to L4 or L7 based on program type.
    // sk_skb and sk_lookup operate at the transport layer (L4).
    // sk_msg and sock_ops operate at the application/socket layer (L7).
    for (const entry of snapshot.sockmap ?? []) {
      const p = progs.get(netEntryProgId(entry) ?? -1);
      if (!p) continue;
      const iface = getOrCreate(entry.devname, entry.ifindex, "sockmap");
      const layer = p.type === "sk_msg" || p.type === "sock_ops" ? "L7" : "L4";
      iface.layers[layer].push(p);
      iface.allPrograms.push(p);
    }
  };

  collect(net[0] ?? {});
  for (const ns of netns) {
    collect(ns.net[0] ?? {}, ns.label);
  }

  // Fallback: foreign netdev links we could not resolve to a named device,
  // shown as pseudo-interfaces under a single "unresolved" netns. ifindex is
  // only unique within a namespace, so links sharing an ifindex may be
  // DIFFERENT devices in different unreachable namespaces — when that
  // happens, each link gets its own pseudo-interface (suffixed by link id)
  // instead of silently merging into one.
  const linksByIfindex = new Map<number, RawBpfLink[]>();
  for (const link of unresolvedNetdevLinks) {
    if (typeof link.prog_id !== "number" || typeof link.ifindex !== "number") continue;
    if (!progs.has(link.prog_id)) continue;
    const list = linksByIfindex.get(link.ifindex);
    if (list) list.push(link);
    else linksByIfindex.set(link.ifindex, [link]);
  }
  for (const [ifindex, links] of Array.from(linksByIfindex.entries())) {
    for (const link of links) {
      const p = progs.get(link.prog_id!)!;
      const name =
        links.length > 1 ? `ifindex ${ifindex} · link ${link.id}` : `ifindex ${ifindex}`;
      const key = `${UNRESOLVED_NETNS_LABEL}::${name}`;
      let iface = ifaceMap.get(key);
      if (!iface) {
        iface = {
          name,
          ifindex,
          kind: "nic",
          netns: UNRESOLVED_NETNS_LABEL,
          layers: { L2: [], L3: [], L4: [], L7: [] },
          allPrograms: [],
        };
        ifaceMap.set(key, iface);
      }
      // netkit and xdp hook the device (L2); tcx sits at the tc layer (L3).
      const layer = link.type === "tcx" ? "L3" : "L2";
      if (!iface.allPrograms.some(ap => ap.id === p.id)) {
        iface.layers[layer].push(p);
        iface.allPrograms.push(p);
      }
    }
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
  struct_ops: {
    label: "Struct Ops",
    description: "Kernel struct_ops callbacks",
  },
  other: {
    label: "Other",
    description: "LSM and other program types",
  },
};

export function buildKernelZones(
  progs: Map<number, BpfProgram>
): KernelAttachmentZone[] {
  const zoneMap = new Map<KernelZone, BpfProgram[]>();

  for (const p of Array.from(progs.values())) {
    const zone =
      p.type === "sched_cls" || p.type === "sched_act"
        ? (tcAttachmentZone(p) ?? "other")
        : getKernelZone(p.type);

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
    "struct_ops",
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

const CGROUP_SOCKET_SIDE_EFFECT_SUMMARY =
  "This cgroup socket hook affects socket state/options rather than packet forwarding. eBPF Viz reports side effects but does not model its return value as a packet allow/drop verdict.";

interface CgroupChainProgramEntry {
  id: number;
  name: string;
  attachFlags?: string;
  attachPath: string;
}

type CgroupChainSource = NonNullable<ProgramChain["chainSource"]>;

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
    .map(entry => `${entry.attachPath}:${entry.id}:${entry.attachFlags ?? ""}`)
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

function cgroupProgramsByPath(
  progs: Map<number, BpfProgram>,
  cgroups: RawCgroupEntry[]
): Map<string, Map<string, CgroupChainProgramEntry[]>> {
  return new Map(
    cgroups.map(cg => [cg.cgroup, directCgroupProgramsByType(progs, cg)])
  );
}

function findCgroupAttachSource(
  programId: number,
  attachType: string,
  cgroupPath: string,
  directByPath: Map<string, Map<string, CgroupChainProgramEntry[]>>
): CgroupChainProgramEntry | undefined {
  let path: string | undefined = cgroupPath;
  while (path) {
    const match = directByPath
      .get(path)
      ?.get(attachType)
      ?.find(entry => entry.id === programId);
    if (match) return match;
    path = parentCgroupPath(path);
  }
  return undefined;
}

function effectiveCgroupProgramsByType(
  progs: Map<number, BpfProgram>,
  cg: RawCgroupEntry,
  directByPath: Map<string, Map<string, CgroupChainProgramEntry[]>>
): Map<string, CgroupChainProgramEntry[]> {
  const byType = new Map<string, CgroupChainProgramEntry[]>();
  for (const cp of cg.programs ?? []) {
    if (!progs.has(cp.id) || !cp.attach_type) continue;
    const source = findCgroupAttachSource(
      cp.id,
      cp.attach_type,
      cg.cgroup,
      directByPath
    );
    if (!byType.has(cp.attach_type)) byType.set(cp.attach_type, []);
    byType.get(cp.attach_type)!.push({
      id: cp.id,
      name: cp.name ?? source?.name ?? progs.get(cp.id)!.name,
      attachFlags: source?.attachFlags ?? cp.attach_flags,
      attachPath: source?.attachPath ?? cg.cgroup,
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

function makeCgroupProgramChain(
  cg: RawCgroupEntry,
  attachType: string,
  effectivePrograms: CgroupChainProgramEntry[],
  chainSource: CgroupChainSource
): ProgramChain {
  const shortName = attachType.replace(/^cgroup_/, "");
  return {
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
    chainSource,
    canShortCircuit: CGROUP_SHORT_CIRCUIT_TYPES.has(attachType),
    packetContext: buildCgroupPacketContext(attachType),
  };
}

function buildInferredCgroupProgramChains(
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

      chains.push(
        makeCgroupProgramChain(cg, attachType, effectivePrograms, "inferred")
      );
    }
  }

  return chains;
}

function buildKernelEffectiveCgroupProgramChains(
  progs: Map<number, BpfProgram>,
  rawCgroups: RawCgroupEntry[],
  rawEffectiveCgroups: RawCgroupEntry[]
): ProgramChain[] {
  const chains: ProgramChain[] = [];
  if (rawEffectiveCgroups.length === 0) return chains;

  const directByPath = cgroupProgramsByPath(progs, rawCgroups);
  const knownPaths = new Set(rawEffectiveCgroups.map(cg => cg.cgroup));
  const effectiveByPath = new Map<
    string,
    Map<string, CgroupChainProgramEntry[]>
  >();
  const sortedCgroups = rawEffectiveCgroups
    .map((cg, index) => ({ cg, index }))
    .sort(
      (a, b) =>
        cgroupDepth(a.cg.cgroup) - cgroupDepth(b.cg.cgroup) ||
        a.index - b.index
    );

  for (const { cg } of sortedCgroups) {
    const parentPath = nearestKnownParentPath(cg.cgroup, knownPaths);
    const parentEffective = effectiveByPath.get(parentPath ?? "");
    const effective = effectiveCgroupProgramsByType(progs, cg, directByPath);
    effectiveByPath.set(cg.cgroup, effective);
    const directByType = directByPath.get(cg.cgroup) ?? new Map();

    for (const [attachType, effectivePrograms] of Array.from(
      effective.entries()
    )) {
      if (effectivePrograms.length < 2) continue;

      const inheritedPrograms = parentEffective?.get(attachType);
      const changedFromParent =
        cgroupProgramSequenceKey(inheritedPrograms) !==
        cgroupProgramSequenceKey(effectivePrograms);
      if (!directByType.has(attachType) && !changedFromParent) continue;

      chains.push(
        makeCgroupProgramChain(
          cg,
          attachType,
          effectivePrograms,
          "kernel-effective"
        )
      );
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
    summary:
      CGROUP_SOCK_TYPES.has(attachType) || attachType.includes("sock")
        ? CGROUP_SOCKET_SIDE_EFFECT_SUMMARY
        : "Return-value semantics for this hook are not modeled yet.",
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
  rawCgroups: RawCgroupEntry[],
  rawEffectiveCgroups: RawCgroupEntry[] = []
): ProgramChain[] {
  const effectiveCgroupChains = buildKernelEffectiveCgroupProgramChains(
    progs,
    rawCgroups,
    rawEffectiveCgroups
  );
  const chains: ProgramChain[] =
    rawEffectiveCgroups.length > 0 && effectiveCgroupChains.length > 0
      ? effectiveCgroupChains
      : buildInferredCgroupProgramChains(progs, rawCgroups);

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
    const progId = netEntryProgId(entry);
    if (progId === undefined || !progs.has(progId)) continue;
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
    if (!group.programs.some(p => p.id === progId)) {
      group.programs.push({
        id: progId,
        position: group.programs.length + 1,
        name: entry.name ?? progs.get(progId)!.name,
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
      chainSource: detailedHooks.has(key) ? "tc-filter" : "bpftool-net",
      canShortCircuit: true, // TC programs can return TC_ACT_SHOT
      packetContext: buildTcPacketContext(direction),
    });
  }

  return chains;
}

// ─── Master parse function ─────────────────────────────────────────────────

// ─── Namespace topology ────────────────────────────────────────────────────

/** Device-pair link kinds that connect two network namespaces. */
export const PAIRED_LINK_KINDS = new Set(["netkit", "veth"]);

/** Device kind, tolerating both the poller's normalized shape and raw
 *  `ip -d -j link show` passthrough from snapshot captures. */
export function netnsLinkKind(dev: RawNetnsLink): string | undefined {
  return dev.kind ?? dev.linkinfo?.info_kind;
}

/** Index a RawNetSnapshot's netdev entries by ifindex → prog ids. */
function progIdsByIfindex(net: RawNetSnapshot | undefined): Map<number, number[]> {
  const byIfindex = new Map<number, number[]>();
  for (const entry of netdevNetEntries(net ?? {})) {
    const id = netEntryProgId(entry);
    if (id === undefined || typeof entry.ifindex !== "number") continue;
    pushMapList(byIfindex, entry.ifindex, id);
  }
  return byIfindex;
}

function pushMapList<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}

/** Programs on the given ifindex within one namespace. A SCANNED namespace's
 *  own `bpftool net` data is authoritative — including "nothing attached
 *  here" (netkit peer programs, for instance, are reported on the primary
 *  side). Only UNSCANNED (inferred) peers use the fallback: uncovered
 *  host-global links keyed by bare ifindex, filtered to the edge's device
 *  kind (netkit links can't sit on a veth pair). The fallback cannot
 *  distinguish namespaces (every pod's eth0 tends to be ifindex 2), so
 *  anything it supplies is marked ambiguous even for a single match. */
function programsAtIfindex(
  progs: Map<number, BpfProgram>,
  ifindex: number,
  localNet: Map<number, number[]> | undefined,
  uncoveredLinksByIfindex: Map<number, Array<{ progId: number; type: string }>>,
  edgeKind: string
): { programs: NamespaceTopologyEndpoint["programs"]; ambiguous: boolean } {
  if (localNet) {
    return {
      programs: (localNet.get(ifindex) ?? [])
        .map(id => progs.get(id))
        .filter((p): p is BpfProgram => !!p)
        .map(p => ({ id: p.id, name: p.name })),
      ambiguous: false,
    };
  }
  const fallback = (uncoveredLinksByIfindex.get(ifindex) ?? []).filter(entry =>
    edgeKind === "netkit" ? entry.type === "netkit" : entry.type !== "netkit"
  );
  return {
    programs: fallback
      .map(entry => progs.get(entry.progId))
      .filter((p): p is BpfProgram => !!p)
      .map(p => ({ id: p.id, name: p.name })),
    ambiguous: fallback.length > 0,
  };
}

/**
 * Build the namespace connectivity graph from per-namespace `ip link` data.
 * Each netkit/veth device with a peer becomes an edge linking two namespaces.
 * The peer namespace is resolved to a scanned namespace when exactly one holds
 * the peer ifindex; otherwise it is synthesized as an inferred node (e.g. a pod
 * netns behind a kind node that we could not enter directly).
 */
export function buildNamespaceTopology(
  progs: Map<number, BpfProgram>,
  netns: RawNetnsSnapshot[],
  hostLinks: RawBpfLink[],
  /** Attachments the bpftool net scans already reported — links they cover
   *  are excluded from the inferred-peer fallback (a scan saw them with a
   *  real device, so re-guessing them onto unknown peers only misleads). */
  coverage: NetdevCoverage = EMPTY_NETDEV_COVERAGE
): NamespaceTopology {
  const nodes = new Map<string, NamespaceTopologyNode>();
  const ensureNode = (
    id: string,
    inferred: boolean,
    displayLabel?: string
  ): NamespaceTopologyNode => {
    let node = nodes.get(id);
    if (!node) {
      node = {
        id,
        label: id,
        inferred,
        deviceCount: 0,
        programCount: 0,
        ...(displayLabel ? { displayLabel } : {}),
      };
      nodes.set(id, node);
    }
    return node;
  };

  // Host-global netdev links no scan covered → ifindex → prog ids, for the
  // inferred-peer fallback.
  const uncoveredLinksByIfindex = new Map<number, Array<{ progId: number; type: string }>>();
  for (const link of hostLinks) {
    if (
      !NETDEV_LINK_TYPES.has(link.type) ||
      typeof link.ifindex !== "number" ||
      typeof link.prog_id !== "number" ||
      isCoveredNetdevLink(link, coverage)
    ) {
      continue;
    }
    pushMapList(uncoveredLinksByIfindex, link.ifindex, {
      progId: link.prog_id,
      type: link.type,
    });
  }

  const netByLabel = new Map<string, Map<number, number[]>>();
  for (const ns of netns) {
    netByLabel.set(ns.label, progIdsByIfindex(ns.net[0]));
    ensureNode(ns.label, false).deviceCount = ns.links?.length ?? 0;
  }

  // Per-namespace device index (ifindex → its own peer_ifindex), for peer
  // resolution. ifindexes repeat across namespaces (every pod's eth0 tends to
  // be ifindex 2), so a device at the peer ifindex isn't enough on its own.
  const devByNsIfindex = new Map<string, Map<number, RawNetnsLink>>();
  const labelsByIfindex = new Map<number, string[]>();
  for (const ns of netns) {
    const byIf = new Map<number, RawNetnsLink>();
    for (const link of ns.links ?? []) {
      byIf.set(link.ifindex, link);
      pushMapList(labelsByIfindex, link.ifindex, ns.label);
    }
    devByNsIfindex.set(ns.label, byIf);
  }

  const edges: NamespaceTopology["edges"] = [];
  const seenEdges = new Set<string>();

  for (const ns of netns) {
    for (const dev of ns.links ?? []) {
      const devKind = netnsLinkKind(dev);
      if (!devKind || !PAIRED_LINK_KINDS.has(devKind)) continue;
      if (typeof dev.link_index !== "number") continue; // no peer → skip

      const peerIfindex = dev.link_index;
      // Resolve the peer namespace ONLY on a bidirectional match: the peer's
      // device points back at THIS device's (namespace-unique) ifindex. A
      // bare same-ifindex device in some other scanned namespace proves
      // nothing (ifindexes repeat everywhere), so without a back-reference
      // the peer stays an inferred node rather than a confident wrong edge.
      const backMatches = (labelsByIfindex.get(peerIfindex) ?? []).filter(l => {
        if (l === ns.label) return false;
        const candidate = devByNsIfindex.get(l)?.get(peerIfindex);
        // Small ifindexes mirror across namespaces often enough that even a
        // bidirectional index match can lie (worker veth 3→2 vs pod netkit
        // 2→3) — the pair's device kind must match too.
        return (
          candidate?.link_index === dev.ifindex &&
          netnsLinkKind(candidate) === devKind
        );
      });
      let peerLabel: string;
      let peerInferred: boolean;
      let peerDisplayLabel: string | undefined;
      if (backMatches.length === 1) {
        peerLabel = backMatches[0];
        peerInferred = false;
      } else {
        // Behind a namespace we did not enter (e.g. a pod behind a kind
        // node). Key by nsid when the kernel reported one (several devices
        // into the SAME peer namespace merge correctly); fall back to a
        // per-device id so two nsid-less peers never collapse into one node.
        peerDisplayLabel =
          dev.link_netnsid !== undefined
            ? `peer nsid ${dev.link_netnsid}`
            : `${dev.ifname} peer`;
        peerLabel = `${ns.label} · ${peerDisplayLabel}`;
        peerInferred = true;
      }

      const key = [
        `${ns.label}#${dev.ifindex}`,
        `${peerLabel}#${peerIfindex}`,
      ]
        .sort()
        .join("::");
      if (seenEdges.has(key)) continue;
      seenEdges.add(key);

      ensureNode(peerLabel, peerInferred, peerDisplayLabel);

      const localProgs = programsAtIfindex(
        progs,
        dev.ifindex,
        netByLabel.get(ns.label),
        uncoveredLinksByIfindex,
        devKind
      );
      const peerProgs = programsAtIfindex(
        progs,
        peerIfindex,
        netByLabel.get(peerLabel),
        uncoveredLinksByIfindex,
        devKind
      );

      edges.push({
        kind: devKind,
        a: {
          namespace: ns.label,
          ifindex: dev.ifindex,
          ifname: dev.ifname,
          programs: localProgs.programs,
        },
        b: {
          namespace: peerLabel,
          ifindex: peerIfindex,
          programs: peerProgs.programs,
        },
        ...(localProgs.ambiguous || peerProgs.ambiguous ? { ambiguous: true } : {}),
      });
    }
  }

  // Tally program counts per namespace from the edges.
  for (const edge of edges) {
    const na = nodes.get(edge.a.namespace);
    const nb = nodes.get(edge.b.namespace);
    if (na) na.programCount += edge.a.programs.length;
    if (nb) nb.programCount += edge.b.programs.length;
  }

  return { nodes: Array.from(nodes.values()), edges };
}

/** Infer a best-effort owner for a program with no visible owning process,
 *  from attachment evidence only (never from program names). Cgroup BPF
 *  programs normally outlive their loader's fd, and on split setups (Docker
 *  Desktop's VM, containers with private /proc) the loader's processes are
 *  invisible — the attachment points still say who manages them. */
export function inferOwnerHint(
  prog: BpfProgram
): { label: string; reason: string } | undefined {
  if (prog.pids && prog.pids.length > 0) return undefined;

  // Strongest signal: a bpffs pin — whoever owns that pin directory keeps
  // the program alive deliberately (Tetragon, Cilium, labs).
  const pin = prog.pinnedPaths?.[0];
  if (pin) {
    const m = /^\/sys\/fs\/bpf\/([^/]+)/.exec(pin);
    if (m) {
      return {
        label: `pinned: ${m[1]}`,
        reason:
          `No process holds a program fd; it is kept alive by a bpffs pin under ` +
          `/sys/fs/bpf/${m[1]} — the tool that created that pin owns it.`,
      };
    }
  }

  // Cgroup attachments: the manager of the cgroup attached the program.
  for (const att of prog.attachments) {
    const path = att.cgroupPath;
    if (!path) continue;
    if (/\/docker\//.test(path) || path.endsWith("/docker")) {
      return {
        label: "Docker (cgroup-managed)",
        reason:
          `Attached to a Docker-managed cgroup (${path}). The Docker runtime ` +
          `attaches these and holds no fd afterwards; on Docker Desktop the ` +
          `daemon runs in a separate VM, so no owning PID is visible here.`,
      };
    }
    if (/\/kubepods/.test(path)) {
      return {
        label: "Kubernetes (cgroup-managed)",
        reason: `Attached to a Kubernetes pod cgroup (${path}).`,
      };
    }
    const unit = /\/system\.slice\/([^/]+)/.exec(path);
    if (unit) {
      return {
        label: `systemd: ${unit[1]}`,
        reason: `Attached to the cgroup of systemd unit ${unit[1]} (${path}).`,
      };
    }
  }

  // Netdev links whose device no scan could see: the loader lives in a
  // namespace (or separate VM) whose /proc is not visible from here.
  if (prog.attachments.some(att => att.detail.includes("(other netns)"))) {
    return {
      label: "another namespace/VM",
      reason:
        "Attached to a device in a network namespace no scan could enter — " +
        "the owning process lives in a container or VM whose /proc is not " +
        "visible from this host.",
    };
  }

  return undefined;
}

export function buildSnapshot(
  rawProgs: RawBpfProg[],
  rawNet: RawNetSnapshot[],
  rawCgroups: RawCgroupEntry[],
  meta: {
    hostname: string;
    kernelVersion: string;
    bpftoolVersion: string;
    demoMode: boolean;
  },
  rawEffectiveCgroups: RawCgroupEntry[] = [],
  rawLinks: RawBpfLink[] = [],
  rawNetns: RawNetnsSnapshot[] = []
): EbpfSnapshot {
  const progMap = parseProgList(rawProgs);
  // Labels key interfaces and topology maps, so they must be unique. The live
  // poller dedupes at discovery time; snapshot uploads (capture-snapshot.sh)
  // arrive raw, so enforce it here for every producer.
  const netnsSnapshots = dedupeNetnsLabels(rawNetns);
  const coverage = computeNetdevCoverage(rawNet, netnsSnapshots);
  // Links first: they refine coarse prog types (tracing → fentry/fexit,
  // kprobe → kretprobe/uprobe) that zone/interface building depends on.
  enrichWithLinkAttachments(progMap, rawLinks, coverage);
  enrichWithNetAttachments(progMap, rawNet);
  for (const ns of netnsSnapshots) {
    enrichWithNetAttachments(progMap, ns.net, ns.label);
  }
  enrichWithCgroupAttachments(progMap, rawCgroups);
  for (const prog of Array.from(progMap.values())) {
    const hint = inferOwnerHint(prog);
    if (hint) prog.ownerHint = hint;
  }

  // Netdev links whose attachment no scan reported (device in a namespace we
  // could not see into) — surfaced as ifindex-only pseudo-interfaces.
  const unresolvedNetdevLinks = rawLinks.filter(
    link =>
      NETDEV_LINK_TYPES.has(link.type) &&
      typeof link.prog_id === "number" &&
      !isCoveredNetdevLink(link, coverage)
  );

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
    networkInterfaces: buildNetworkInterfaces(
      progMap,
      rawNet,
      netnsSnapshots,
      unresolvedNetdevLinks
    ),
    cgroupTree: buildCgroupTree(progMap, rawCgroups),
    kernelZones: buildKernelZones(progMap),
    programChains: buildProgramChains(
      progMap,
      rawNet,
      rawCgroups,
      rawEffectiveCgroups
    ),
    namespaceTopology: buildNamespaceTopology(
      progMap,
      netnsSnapshots,
      rawLinks,
      coverage
    ),
    stats: {
      total: programs.length,
      byType,
      jited: programs.filter(p => p.jited).length,
      orphaned: programs.filter(p => p.orphaned).length,
    },
  };
}

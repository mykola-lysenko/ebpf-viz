// ─── Raw bpftool JSON shapes ───────────────────────────────────────────────

export interface RawBpfProg {
  id: number;
  type: string;
  name?: string;
  tag?: string;
  gpl_compatible?: boolean;
  loaded_at?: number;
  uid?: number;
  orphaned?: boolean;
  bytes_xlated?: number;
  bytes_jited?: number;
  bytes_memlock?: number;
  jited?: boolean;
  map_ids?: number[];
  btf_id?: number;
  run_time_ns?: number;
  run_cnt?: number;
  recursion_misses?: number;
  verified_insns?: number;
  pids?: Array<{ pid: number; comm: string }>;
}

export interface RawNetEntry {
  devname: string;
  ifindex: number;
  mode?: string;
  id: number;
  name?: string;
  kind?: string;
  act?: unknown[];
}

export interface RawNetSnapshot {
  xdp?: RawNetEntry[];
  tc?: RawNetEntry[];
  tcx?: RawNetEntry[];
  netkit?: RawNetEntry[];
  flow_dissector?: RawNetEntry[];
  netfilter?: RawNetEntry[];
}

export interface RawCgroupEntry {
  cgroup: string;
  programs?: Array<{
    id: number;
    attach_type: string;
    attach_flags?: string;
    name?: string;
    attach_btf_obj_id?: number;
    attach_btf_id?: number;
  }>;
}

// ─── Normalized visualization models ──────────────────────────────────────

export type BpfProgType =
  | "xdp"
  | "sched_cls"
  | "sched_act"
  | "kprobe"
  | "kretprobe"
  | "tracepoint"
  | "raw_tracepoint"
  | "perf_event"
  | "cgroup_skb"
  | "cgroup_sock"
  | "cgroup_device"
  | "cgroup_sysctl"
  | "cgroup_sockopt"
  | "sock_ops"
  | "sk_skb"
  | "sk_msg"
  | "sk_lookup"
  | "flow_dissector"
  | "netfilter"
  | "lsm"
  | "struct_ops"
  | "fentry"
  | "fexit"
  | "freplace"
  | "lirc_mode2"
  | "lwt_in"
  | "lwt_out"
  | "lwt_xmit"
  | "lwt_seg6local"
  | "socket_filter"
  | "unknown";

export type OsiLayer = "L2" | "L3" | "L4" | "L7" | "kernel";

export interface BpfProgram {
  id: number;
  type: BpfProgType;
  rawType: string;
  name: string;
  tag: string;
  gplCompatible: boolean;
  loadedAt: number; // unix seconds
  orphaned: boolean;
  bytesXlated: number;
  jited: boolean;
  memlock: number;
  mapIds: number[];
  btfId?: number;
  runTimeNs?: number;
  runCnt?: number;
  pids?: Array<{ pid: number; comm: string }>;
  // enriched
  attachments: BpfAttachment[];
  osiLayer: OsiLayer;
  color: string;
}

export interface BpfAttachment {
  kind: "xdp" | "tc" | "tcx" | "netkit" | "flow_dissector" | "netfilter" | "cgroup" | "perf" | "unknown";
  detail: string; // e.g. "eth0 (driver)", "cgroup_inet_ingress", "sys_enter_openat"
  ifname?: string;
  cgroupPath?: string;
  attachFlags?: string;
}

// ─── Network interface model ───────────────────────────────────────────────

export interface NetworkInterface {
  name: string;
  ifindex: number;
  layers: {
    L2: BpfProgram[];  // XDP, TC ingress/egress
    L3: BpfProgram[];  // TC, netfilter
    L4: BpfProgram[];  // sk_filter, sock_ops
    L7: BpfProgram[];  // sk_msg, sockops application level
  };
  allPrograms: BpfProgram[];
}

// ─── Cgroup tree model ─────────────────────────────────────────────────────

export interface CgroupNode {
  path: string;
  name: string;
  depth: number;
  programs: BpfProgram[];
  children: CgroupNode[];
}

// ─── Kernel attachment point model ────────────────────────────────────────

export type KernelZone =
  | "xdp"
  | "tc_ingress"
  | "tc_egress"
  | "socket_filter"
  | "kprobe"
  | "tracepoint"
  | "perf_event"
  | "cgroup"
  | "flow_dissector"
  | "netfilter"
  | "sk_ops"
  | "other";

export interface KernelAttachmentZone {
  zone: KernelZone;
  label: string;
  description: string;
  programs: BpfProgram[];
  osiLayer: OsiLayer;
}

// ─── Top-level snapshot ────────────────────────────────────────────────────

export interface EbpfSnapshot {
  timestamp: number;
  hostname: string;
  kernelVersion: string;
  bpftoolVersion: string;
  demoMode: boolean;
  programs: BpfProgram[];
  networkInterfaces: NetworkInterface[];
  cgroupTree: CgroupNode[];
  kernelZones: KernelAttachmentZone[];
  stats: {
    total: number;
    byType: Record<string, number>;
    jited: number;
    orphaned: number;
  };
}

export interface PollingConfig {
  intervalMs: number;
  demoMode: boolean;
  bpftoolPath: string;
  sudo: boolean;
}

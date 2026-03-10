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

// ─── Runtime statistics ───────────────────────────────────────────────────────

/** One data point from a single poll snapshot for a specific program */
export interface ProgSample {
  /** Unix timestamp in milliseconds */
  ts: number;
  /** Cumulative run count at this snapshot */
  runCnt: number;
  /** Cumulative run_time_ns at this snapshot */
  runTimeNs: number;
  /** Recursion misses at this snapshot */
  recursionMisses: number;
}

/** Derived per-interval rates computed from two consecutive ProgSamples */
export interface ProgRates {
  /** Calls per second over the last interval */
  callsPerSec: number;
  /** Average execution latency in nanoseconds over the last interval */
  avgLatencyNs: number;
  /** CPU time share as a fraction 0–1 over the last interval */
  cpuFraction: number;
  /** Recursion miss rate (misses / calls) over the last interval */
  recursionRate: number;
}

/** Full history ring for one program — up to RING_SIZE samples */
export interface ProgHistory {
  id: number;
  /** Raw samples in chronological order */
  samples: ProgSample[];
  /** Latest derived rates (computed from last two samples) */
  latest: ProgRates | null;
  /** Peak calls/sec seen in the ring window */
  peakCallsPerSec: number;
  /** Peak avg latency seen in the ring window */
  peakAvgLatencyNs: number;
}

/** Summary of all programs' activity for the current snapshot */
export interface ActivitySummary {
  /** Programs sorted by current calls/sec descending */
  topByCallsPerSec: Array<{ id: number; name: string; rawType: string; callsPerSec: number; avgLatencyNs: number }>;
  /** Total calls/sec across all programs */
  totalCallsPerSec: number;
  /** Total CPU fraction across all programs */
  totalCpuFraction: number;
  /** Whether bpf_stats_enabled is active on this host */
  statsEnabled: boolean;
}

// ─── Code Inspector types ─────────────────────────────────────────────────────

/** A single xlated (BPF bytecode) instruction */
export interface XlatedInsn {
  index: number;
  disasm: string;
  opcodes?: string;
  /** Source file:line annotation from BTF linum info, e.g. "kernel/bpf/core.c:42" */
  linum?: string;
}

/** A single JIT-compiled native instruction */
export interface JitedInsn {
  /** PC address as hex string */
  pc: string;
  disasm: string;
  opcodes?: string;
}

/** Full code dump for one BPF program */
export interface ProgDump {
  progId: number;
  /** BPF bytecode instructions — always available */
  xlated: XlatedInsn[];
  /** Graphviz DOT source for the CFG — always available */
  cfgDot: string;
  /** JIT-compiled native instructions — null when unavailable */
  jited: JitedInsn[] | null;
  /** Human-readable reason why jited is unavailable */
  jitedUnavailableReason?: string;
  /** True when BTF line-number info is embedded (linum annotations present) */
  hasLineInfo: boolean;
  /** True when a BTF object is attached to this program */
  hasBtf: boolean;
  btfId?: number;
}

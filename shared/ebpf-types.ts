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

export interface RawTcFilterEntry {
  devname: string;
  direction: "ingress" | "egress";
  ifindex?: number;
  protocol?: string;
  pref?: number;
  kind?: string;
  chain?: number;
  order?: number;
  options?: {
    handle?: string;
    bpf_name?: string;
    "direct-action"?: boolean;
    prog?: {
      id?: number;
      name?: string;
      tag?: string;
    };
    actions?: unknown[];
  };
}

export interface RawTcFilterDump {
  devname: string;
  direction: "ingress" | "egress";
  ifindex?: number;
  filters: Array<Omit<RawTcFilterEntry, "devname" | "direction" | "ifindex">>;
}

export interface RawNetSnapshot {
  xdp?: RawNetEntry[];
  tc?: RawNetEntry[];
  tcx?: RawNetEntry[];
  /** Normalized or grouped `tc -s -d -j filter show dev <ifname> ingress|egress` rows. */
  tcFilters?: Array<RawTcFilterEntry | RawTcFilterDump>;
  netkit?: RawNetEntry[];
  flow_dissector?: RawNetEntry[];
  netfilter?: RawNetEntry[];
  /** Synthetic sockmap/sockhash entries (not from bpftool net, but from bpftool prog show).
   *  devname is a virtual name like "sockmap0"; ifindex is 0 for synthetic entries. */
  sockmap?: RawNetEntry[];
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
  | "cgroup_sock_addr"
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
  kind:
    | "xdp"
    | "tc"
    | "tcx"
    | "netkit"
    | "flow_dissector"
    | "netfilter"
    | "cgroup"
    | "perf"
    | "unknown";
  detail: string; // e.g. "eth0 (driver)", "cgroup_inet_ingress", "sys_enter_openat"
  ifname?: string;
  cgroupPath?: string;
  attachFlags?: string;
  /** Packet flow direction — set for TC, TCx, and netkit attachments */
  direction?: "ingress" | "egress";
}

// ─── Network interface model ───────────────────────────────────────────────

export interface NetworkInterface {
  name: string;
  ifindex: number;
  /** "nic" = physical/virtual network device (XDP, TC, netfilter, flow_dissector);
   *  "sockmap" = synthetic socket-level attachment point (sk_msg, sk_skb, sk_lookup, sock_ops) */
  kind: "nic" | "sockmap";
  layers: {
    L2: BpfProgram[]; // XDP, netkit (NIC only)
    L3: BpfProgram[]; // TC, netfilter, flow_dissector (NIC only)
    L4: BpfProgram[]; // sk_skb, sk_lookup (sockmap only)
    L7: BpfProgram[]; // sk_msg, sock_ops (sockmap only)
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
  | "struct_ops"
  | "other";

export interface KernelAttachmentZone {
  zone: KernelZone;
  label: string;
  description: string;
  programs: BpfProgram[];
  osiLayer: OsiLayer;
}

// ─── Program chain (execution order at a hook point) ─────────────────────

export type PacketDirection =
  | "ingress"
  | "egress"
  | "bidirectional"
  | "unknown";

export type PacketHookFamily =
  | "xdp"
  | "tc"
  | "cgroup_skb"
  | "cgroup_sock_addr"
  | "cgroup_sock"
  | "netfilter"
  | "unknown";

export interface PacketActionSemantics {
  /** Return values that let packet/socket processing continue. */
  pass: string[];
  passValues?: number[];
  /** Return values that drop/deny/abort packet/socket processing. */
  drop: string[];
  dropValues?: number[];
  /** Return values that send the packet elsewhere instead of normal pass. */
  redirect: string[];
  redirectValues?: number[];
  /** Other hook-specific return values worth explaining. */
  other: string[];
  otherValues?: number[];
}

export interface PacketChainContext {
  family: PacketHookFamily;
  direction: PacketDirection;
  summary: string;
  semantics: PacketActionSemantics;
}

/** A chain of BPF programs attached to the same hook point, in execution order.
 *  The kernel runs them sequentially — for networking hooks (TC, XDP, cgroup),
 *  an early program can return a verdict (e.g. DROP) that prevents later
 *  programs from executing. */
export interface ProgramChain {
  /** Unique identifier, e.g. "cgroup:/sys/fs/cgroup:cgroup_inet4_connect" */
  hookId: string;
  /** Human-readable label, e.g. "inet4_connect" */
  hookLabel: string;
  /** Hook category */
  hookType: "cgroup" | "tc" | "xdp" | "netfilter";
  /** Where attached: cgroup path or interface name */
  attachPoint: string;
  /** Specific attach type, e.g. "cgroup_inet4_connect", "clsact/ingress" */
  attachType: string;
  /** Programs in execution order (position is 1-based) */
  programs: Array<{
    id: number;
    position: number;
    name: string;
    attachFlags?: string;
    cgroup?: {
      attachPath: string;
      inherited: boolean;
      attachFlags?: string;
    };
    tc?: {
      protocol?: string;
      priority?: number;
      chain?: number;
      handle?: string;
      directAction?: boolean;
      actionCount?: number;
      stats?: {
        bytes?: number;
        packets?: number;
        drops?: number;
      };
    };
  }>;
  /** Data source used to build this chain. */
  chainSource?: "kernel-effective" | "inferred" | "tc-filter" | "bpftool-net";
  /** Whether an early program can short-circuit (drop/reject) and prevent
   *  later programs from running. True for TC, cgroup networking hooks. */
  canShortCircuit: boolean;
  /** Packet/socket context and return-value semantics for this hook. */
  packetContext?: PacketChainContext;
}

export type PacketVerdict = "pass" | "drop" | "redirect" | "other" | "unknown";

export type PacketChainReachability = "always" | "conditional" | "not-reached";

export type PacketChainPredictionConfidence = "high" | "partial" | "unknown";

export interface PacketProgramPrediction {
  progId: number;
  position: number;
  name: string;
  verdicts: PacketVerdict[];
  label: string;
  tone: PacketVerdict;
  title: string;
  verdictExplanations: PacketVerdictExplanation[];
  reachability: PacketChainReachability;
  canTerminateChain: boolean;
  definitelyTerminatesChain: boolean;
  hasUnknownBehavior: boolean;
  tailCallTargets: PacketTailCallTarget[];
  tailCallContinuations: PacketTailCallContinuation[];
  hasSideEffects: boolean;
  sideEffectLabels: string[];
  sideEffectTitle?: string;
}

export interface PacketTailCallTarget {
  mapId: number;
  mapName?: string;
  slot: number;
  targetProgId?: number;
  targetProgName?: string;
  targetProgType?: string;
  resolved: boolean;
}

export type PacketTailCallContinuationStatus =
  | "analyzed"
  | "analysis-unavailable"
  | "cycle"
  | "max-depth";

export interface PacketTailCallContinuation {
  target: PacketTailCallTarget;
  depth: number;
  status: PacketTailCallContinuationStatus;
  verdicts: PacketVerdict[];
  label: string;
  tone: PacketVerdict;
  summary: string;
  confidence: PacketChainPredictionConfidence;
  hasUnknownBehavior: boolean;
  hasSideEffects: boolean;
  sideEffectLabels: string[];
  continuations: PacketTailCallContinuation[];
}

export interface PacketVerdictExplanation {
  verdict: PacketVerdict;
  evidenceKind?:
    | "constant-return"
    | "modeled-helper-return"
    | "unknown-return"
    | "tail-call";
  summary: string;
  exitIndex?: number;
  assignmentIndex?: number;
  assignmentDisasm?: string;
  returnValue?: number;
  helper?: string;
  source?: string;
  sourceFile?: string;
  sourceLine?: number;
  sourceColumn?: number;
  branchEvidence?: XlatedBranchEvidence[];
  tailCallTarget?: PacketTailCallTarget;
}

export interface PacketChainPrediction {
  chainId: string;
  /** Verdict-only summary; side effects are reported separately. */
  verdictSummary: string;
  /** Side-effect-only summary. */
  effectSummary: string;
  /** Backward-compatible alias for verdictSummary. */
  summary: string;
  confidence: PacketChainPredictionConfidence;
  possibleOutcomes: PacketVerdict[];
  alwaysPass: boolean;
  hasUnknownBehavior: boolean;
  hasSideEffects: boolean;
  sideEffectLabels: string[];
  firstTerminalPrograms: PacketProgramPrediction[];
  steps: PacketProgramPrediction[];
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
  /** Ordered program chains — multiple programs on the same hook point */
  programChains: ProgramChain[];
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

/** Full history ring for one program. The sample cap is PROG_HISTORY_RING_SIZE. */
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
  topByCallsPerSec: Array<{
    id: number;
    name: string;
    rawType: string;
    callsPerSec: number;
    avgLatencyNs: number;
    cpuFraction: number;
  }>;
  /** Total calls/sec across all programs */
  totalCallsPerSec: number;
  /** Total CPU fraction across all programs */
  totalCpuFraction: number;
  /** Whether bpf_stats_enabled is active on this host */
  statsEnabled: boolean;
}

/** Lightweight per-poll metric update sent over SSE when topology is unchanged. */
export interface SnapshotMetricsUpdate {
  timestamp: number;
  stats: EbpfSnapshot["stats"];
  programs: Array<{
    id: number;
    runCnt?: number;
    runTimeNs?: number;
  }>;
}

/** Incremental history update sent over SSE after the initial full history. */
export interface ProgHistoryDelta {
  id: number;
  sample: ProgSample;
  latest: ProgRates | null;
  peakCallsPerSec: number;
  peakAvgLatencyNs: number;
}

// ─── Code Inspector types ─────────────────────────────────────────────────────

/** A single xlated (BPF bytecode) instruction */
export interface XlatedInsn {
  index: number;
  disasm: string;
  opcodes?: string;
  /** Human-readable source annotation from BTF line info. */
  linum?: string;
  /** Source statement associated with this instruction, when bpftool returns it. */
  source?: string;
  /** Source file associated with this instruction, when available. */
  sourceFile?: string;
  /** 1-based source line number, when available. */
  sourceLine?: number;
  /** 1-based source column number, when available. */
  sourceColumn?: number;
}

export interface CfgBasicBlockSummary {
  id: string;
  start: number;
  end: number;
  instructionCount: number;
  branchTargets: number[];
  fallthroughTarget?: number;
  calls: string[];
  sourceSnippets: string[];
  terminalDisasm: string;
}

export interface CfgRenderAnalysis {
  instructionCount: number;
  dotChars: number;
  estimatedNodeCount: number;
  estimatedEdgeCount: number;
  blockCount: number;
  shouldAutoRender: boolean;
  reasons: string[];
}

export interface CfgSummary {
  fingerprint: string;
  analysis: CfgRenderAnalysis;
  blocks: CfgBasicBlockSummary[];
}

export interface CfgBlockSearchResult {
  block: CfgBasicBlockSummary;
  matchReason: string;
}

/** A single JIT-compiled native instruction */
export interface JitedInsn {
  /** PC address as hex string */
  pc: string;
  disasm: string;
  opcodes?: string;
}

export interface XlatedReturnExit {
  /** Instruction index of the exit instruction. */
  exitIndex: number;
  /** Disassembly of the exit instruction. */
  exitDisasm: string;
  /** Instruction index of the direct constant assignment to r0/w0, when found. */
  assignmentIndex?: number;
  /** Disassembly of the direct constant assignment to r0/w0, when found. */
  assignmentDisasm?: string;
  /** Constant assigned to r0/w0 before exit. Absent when return is dynamic/unknown. */
  value?: number;
  /** Source statement associated with the return assignment or exit, when available. */
  source?: string;
  sourceFile?: string;
  sourceLine?: number;
  sourceColumn?: number;
  /** Why the return value could not be resolved to a constant. */
  reason?:
    | "no-direct-assignment"
    | "dynamic-assignment"
    | "conflicting-values"
    | "analysis-limit";
  /** Conservative branch decisions on the unique CFG path leading to this exit. */
  branchEvidence?: XlatedBranchEvidence[];
}

export interface XlatedBranchEvidence {
  /** Instruction index of the conditional branch. */
  insnIndex: number;
  /** Branch instruction disassembly. */
  disasm: string;
  /** Instruction index reached when this branch is taken, when resolved. */
  targetIndex?: number;
  /** Which branch edge was followed on the unique path to the exit. */
  branch: "taken" | "fallthrough" | "unknown";
  /** Source statement associated with the branch, when available. */
  source?: string;
  sourceFile?: string;
  sourceLine?: number;
  sourceColumn?: number;
}

export interface XlatedReturnConstantSummary {
  value: number;
  exitCount: number;
}

export type XlatedSideEffectKind =
  | "map-write"
  | "direct-memory-write"
  | "packet-mutation"
  | "redirect-helper"
  | "telemetry-output"
  | "tail-call"
  | "socket-mutation";

export interface XlatedSideEffect {
  kind: XlatedSideEffectKind;
  label: string;
  insnIndex: number;
  disasm: string;
  helper?: string;
  source?: string;
  sourceFile?: string;
  sourceLine?: number;
  sourceColumn?: number;
}

export interface XlatedSideEffectSummary {
  hasSideEffects: boolean;
  labels: string[];
  effects: XlatedSideEffect[];
  hasMapWrites: boolean;
  hasDirectMemoryWrites: boolean;
  hasPacketMutations: boolean;
  hasRedirects: boolean;
  hasTelemetryOutput: boolean;
  hasTailCalls: boolean;
  hasSocketMutations: boolean;
}

export interface XlatedReturnAnalysis {
  /** Total number of reachable final BPF exit instructions analyzed. */
  exitCount: number;
  /** Reachable exits where the analyzer resolved r0/w0 to a constant. */
  constantExits: XlatedReturnExit[];
  /** Reachable exits where the analyzer could not resolve r0/w0 to a constant. */
  unknownExits: XlatedReturnExit[];
  /** Unique constant return values observed at reachable final exits. */
  observedConstants: XlatedReturnConstantSummary[];
  /** Tail calls can transfer control to another program, so final verdict may be outside this dump. */
  tailCallIndices: number[];
  /** Tail-call sites with best-effort prog-array map and slot extraction. */
  tailCalls?: XlatedTailCall[];
  hasUnknownExits: boolean;
  hasTailCalls: boolean;
  /** Known helper/direct-write side effects detected in xlated bytecode. */
  sideEffects: XlatedSideEffectSummary;
}

export interface XlatedTailCall {
  /** Instruction index of the bpf_tail_call helper call. */
  insnIndex: number;
  /** Tail-call instruction disassembly. */
  disasm: string;
  /** Prog-array map id passed in r2, when statically resolved. */
  mapId?: number;
  /** Instruction index that assigned the map reference to r2, when found. */
  mapAssignmentIndex?: number;
  /** Disassembly of the map assignment instruction, when found. */
  mapAssignmentDisasm?: string;
  /** Constant prog-array slot/index passed in r3, when statically resolved. */
  slot?: number;
  /** Instruction index that assigned the slot/index to r3, when found. */
  slotAssignmentIndex?: number;
  /** Disassembly of the slot/index assignment instruction, when found. */
  slotAssignmentDisasm?: string;
  /** Source statement associated with the call, when available. */
  source?: string;
  sourceFile?: string;
  sourceLine?: number;
  sourceColumn?: number;
}

export interface ProgramReturnAnalysisResult {
  progId: number;
  returnAnalysis: XlatedReturnAnalysis | null;
  error?: string;
}

/** Full code dump for one BPF program */
export interface ProgDump {
  progId: number;
  /** BPF bytecode instructions — always available */
  xlated: XlatedInsn[];
  /** Graphviz DOT source for the CFG — always available */
  cfgDot: string;
  /** Server-computed summary used by the large-program CFG fallback. */
  cfgSummary?: CfgSummary;
  /** JIT-compiled native instructions — null when unavailable */
  jited: JitedInsn[] | null;
  /** Human-readable reason why jited is unavailable */
  jitedUnavailableReason?: string;
  /** True when BTF line-number info is embedded (linum annotations present) */
  hasLineInfo: boolean;
  /** True when a BTF object is attached to this program */
  hasBtf: boolean;
  btfId?: number;
  /** Simple return-value analysis over xlated bytecode. */
  returnAnalysis?: XlatedReturnAnalysis;
  /** Non-null when bpftool failed — describes what went wrong */
  error?: string;
}

// ─── BPF Maps ─────────────────────────────────────────────────────────────────

/** Raw map entry from `bpftool -jp map list` */
export interface RawBpfMap {
  id: number;
  type: string;
  name?: string;
  flags?: number;
  bytes_key?: number;
  bytes_value?: number;
  max_entries?: number;
  bytes_memlock?: number;
  frozen?: number;
  pinned?: string[];
  btf_id?: number;
}

/** Normalized BPF map type */
export type BpfMapType =
  | "hash"
  | "array"
  | "prog_array"
  | "perf_event_array"
  | "percpu_hash"
  | "percpu_array"
  | "stack_trace"
  | "cgroup_array"
  | "lru_hash"
  | "lru_percpu_hash"
  | "lpm_trie"
  | "array_of_maps"
  | "hash_of_maps"
  | "devmap"
  | "sockmap"
  | "cpumap"
  | "xskmap"
  | "sockhash"
  | "cgroup_storage"
  | "reuseport_sockarray"
  | "percpu_cgroup_storage"
  | "queue"
  | "stack"
  | "sk_storage"
  | "devmap_hash"
  | "struct_ops"
  | "ringbuf"
  | "inode_storage"
  | "task_storage"
  | "bloom_filter"
  | "user_ringbuf"
  | "cgrp_storage"
  | "unknown";

/** Enriched BPF map with program relationships */
export interface BpfMap {
  id: number;
  type: BpfMapType;
  rawType: string;
  name: string;
  flags: number;
  bytesKey: number;
  bytesValue: number;
  maxEntries: number;
  bytesMemlock: number;
  frozen: boolean;
  pinnedPaths: string[];
  btfId?: number;
  /** IDs of programs that reference this map (from prog.map_ids) */
  usedByProgIds: number[];
  /** Color for this map type */
  color: string;
  /** Category for grouping */
  category: "data" | "event" | "control" | "socket" | "other";
}

/** Map type metadata: color, category, description */
export const MAP_TYPE_META: Record<
  string,
  { category: BpfMap["category"]; color: string; description: string }
> = {
  hash: {
    category: "data",
    color: "#3b82f6",
    description: "Hash table — O(1) lookup by key",
  },
  array: {
    category: "data",
    color: "#2563eb",
    description: "Array indexed by integer key",
  },
  percpu_hash: {
    category: "data",
    color: "#1d4ed8",
    description: "Per-CPU hash table",
  },
  percpu_array: {
    category: "data",
    color: "#1e40af",
    description: "Per-CPU array",
  },
  lru_hash: {
    category: "data",
    color: "#0ea5e9",
    description: "LRU hash — auto-evicts oldest entries",
  },
  lru_percpu_hash: {
    category: "data",
    color: "#38bdf8",
    description: "Per-CPU LRU hash",
  },
  lpm_trie: {
    category: "data",
    color: "#7dd3fc",
    description: "Longest-prefix-match trie (routing tables)",
  },
  bloom_filter: {
    category: "data",
    color: "#bae6fd",
    description: "Probabilistic membership test",
  },
  queue: { category: "data", color: "#e0f2fe", description: "FIFO queue" },
  stack: { category: "data", color: "#f0f9ff", description: "LIFO stack" },
  perf_event_array: {
    category: "event",
    color: "#f59e0b",
    description: "Ring buffer for perf events (legacy)",
  },
  ringbuf: {
    category: "event",
    color: "#d97706",
    description: "High-performance ring buffer",
  },
  user_ringbuf: {
    category: "event",
    color: "#b45309",
    description: "User-space ring buffer",
  },
  stack_trace: {
    category: "event",
    color: "#92400e",
    description: "Stack trace storage",
  },
  prog_array: {
    category: "control",
    color: "#10b981",
    description: "Program array for tail calls",
  },
  array_of_maps: {
    category: "control",
    color: "#059669",
    description: "Array of inner maps",
  },
  hash_of_maps: {
    category: "control",
    color: "#047857",
    description: "Hash of inner maps",
  },
  cgroup_array: {
    category: "control",
    color: "#065f46",
    description: "Cgroup references",
  },
  cgroup_storage: {
    category: "control",
    color: "#064e3b",
    description: "Per-cgroup storage",
  },
  percpu_cgroup_storage: {
    category: "control",
    color: "#022c22",
    description: "Per-CPU per-cgroup storage",
  },
  cgrp_storage: {
    category: "control",
    color: "#14532d",
    description: "Cgroup local storage",
  },
  devmap: {
    category: "control",
    color: "#7c3aed",
    description: "Device redirect map (XDP)",
  },
  devmap_hash: {
    category: "control",
    color: "#6d28d9",
    description: "Device redirect hash map",
  },
  cpumap: {
    category: "control",
    color: "#5b21b6",
    description: "CPU redirect map (XDP)",
  },
  xskmap: {
    category: "control",
    color: "#4c1d95",
    description: "AF_XDP socket map",
  },
  sockmap: {
    category: "socket",
    color: "#ec4899",
    description: "Socket map for redirection",
  },
  sockhash: {
    category: "socket",
    color: "#db2777",
    description: "Socket hash map",
  },
  sk_storage: {
    category: "socket",
    color: "#be185d",
    description: "Per-socket local storage",
  },
  reuseport_sockarray: {
    category: "socket",
    color: "#9d174d",
    description: "Reuseport socket array",
  },
  struct_ops: {
    category: "other",
    color: "#14b8a6",
    description: "Struct ops (kernel callbacks)",
  },
  inode_storage: {
    category: "other",
    color: "#0d9488",
    description: "Per-inode local storage",
  },
  task_storage: {
    category: "other",
    color: "#0f766e",
    description: "Per-task local storage",
  },
  unknown: {
    category: "other",
    color: "#6b7280",
    description: "Unknown map type",
  },
};

// ─── Map Entries Inspector ────────────────────────────────────────────────────

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

/**
 * A single raw entry from `bpftool -jp map dump id N`.
 * Both key and value can be:
 *   - string[] — hex byte array like ["0x00","0x01",...]
 *   - JsonValue — BTF-decoded struct/primitive
 *   - { error: string } — when bpftool cannot read the value (e.g. perf_event_array)
 */
export interface RawMapEntry {
  key: string[] | JsonValue;
  value?: string[] | JsonValue | { error: string };
  /** Present for per-cpu maps: one value per CPU */
  values?: Array<{ cpu: number; value: string[] | JsonValue }>;
  /** Formatted key string (hex, decimal, or BTF) */
  formatted?: {
    key: JsonValue;
    value: JsonValue;
  };
}

/** Parsed and normalized map entry for the UI */
export interface MapEntry {
  /** Zero-based row index */
  index: number;
  /** Key as hex string, e.g. "00 01 02 03" */
  keyHex: string;
  /** Key interpreted as little-endian decimal (for small keys ≤ 8 bytes) */
  keyDecimal: string | null;
  /** Key as BTF-decoded JSON string (when BTF info available) */
  keyBtf: string | null;
  /** Value as hex string */
  valueHex: string;
  /** Value interpreted as little-endian decimal (for small values ≤ 8 bytes) */
  valueDecimal: string | null;
  /** Value as BTF-decoded JSON string (when BTF info available) */
  valueBtf: string | null;
  /** True when bpftool returned an error reading this value */
  valueError: string | null;
  /** Per-CPU values (only for percpu_hash / percpu_array maps) */
  perCpuValues?: Array<{ cpu: number; hex: string; decimal: string | null }>;
}

/** A resolved entry from a prog_array map used by bpf_tail_call. */
export interface ProgArrayTarget {
  mapId: number;
  /** prog_array slot/index used as the bpf_tail_call third argument. */
  slot: number;
  /** Program id stored in that slot, when bpftool exposes it. */
  targetProgId: number;
  /** Row index in the parsed map dump. */
  entryIndex: number;
}

/** Result of a map dump operation */
export interface MapDumpResult {
  mapId: number;
  mapType: string;
  mapName: string;
  /** Total number of entries returned */
  totalEntries: number;
  /** Whether the dump was truncated (> MAX_ENTRIES limit) */
  truncated: boolean;
  /** Maximum entries returned in one dump call */
  maxReturned: number;
  entries: MapEntry[];
  /** Parsed prog_array slot -> program-id targets, only present for prog_array dumps. */
  progArrayTargets?: ProgArrayTarget[];
  /** True when BTF info was used to decode keys/values */
  btfDecoded: boolean;
  /** Error message if the dump failed entirely */
  error: string | null;
  /** Map types that cannot be dumped (perf_event_array, ringbuf, etc.) */
  unsupported: boolean;
}

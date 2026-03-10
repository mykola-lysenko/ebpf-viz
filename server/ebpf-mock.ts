import type { RawBpfProg, RawCgroupEntry, RawNetSnapshot } from "../shared/ebpf-types";

const NOW = Math.floor(Date.now() / 1000);

export const MOCK_PROGS: RawBpfProg[] = [
  // XDP programs
  { id: 1, type: "xdp", name: "xdp_drop_icmp", tag: "a1b2c3d4e5f60001", gpl_compatible: true, loaded_at: NOW - 3600, uid: 0, orphaned: false, bytes_xlated: 256, jited: true, bytes_memlock: 4096, map_ids: [10, 11] },
  { id: 2, type: "xdp", name: "xdp_lb_kern", tag: "a1b2c3d4e5f60002", gpl_compatible: true, loaded_at: NOW - 7200, uid: 0, orphaned: false, bytes_xlated: 1024, jited: true, bytes_memlock: 8192, map_ids: [12], run_time_ns: 48291000, run_cnt: 9823 },

  // TC classifiers
  { id: 3, type: "sched_cls", name: "cls_bpf_ingress", tag: "b2c3d4e5f6070003", gpl_compatible: true, loaded_at: NOW - 1800, uid: 0, orphaned: false, bytes_xlated: 512, jited: true, bytes_memlock: 4096, map_ids: [13] },
  { id: 4, type: "sched_cls", name: "cls_bpf_egress", tag: "b2c3d4e5f6070004", gpl_compatible: true, loaded_at: NOW - 1800, uid: 0, orphaned: false, bytes_xlated: 512, jited: true, bytes_memlock: 4096, map_ids: [13] },
  { id: 5, type: "sched_act", name: "act_bpf_mirror", tag: "c3d4e5f607080005", gpl_compatible: true, loaded_at: NOW - 900, uid: 0, orphaned: false, bytes_xlated: 384, jited: false, bytes_memlock: 4096 },

  // kprobes
  { id: 6, type: "kprobe", name: "kprobe__sys_execve", tag: "d4e5f60708090006", gpl_compatible: true, loaded_at: NOW - 5400, uid: 0, orphaned: false, bytes_xlated: 768, jited: true, bytes_memlock: 4096, map_ids: [14, 15], run_time_ns: 12049000, run_cnt: 2341 },
  { id: 7, type: "kretprobe", name: "kretprobe__sys_open", tag: "e5f6070809000007", gpl_compatible: true, loaded_at: NOW - 5400, uid: 0, orphaned: false, bytes_xlated: 640, jited: true, bytes_memlock: 4096, map_ids: [14] },
  { id: 8, type: "fentry", name: "fentry__tcp_connect", tag: "f607080900010008", gpl_compatible: true, loaded_at: NOW - 2700, uid: 0, orphaned: false, bytes_xlated: 896, jited: true, bytes_memlock: 4096, map_ids: [16], btf_id: 42 },
  { id: 9, type: "fexit", name: "fexit__tcp_sendmsg", tag: "0708090001020009", gpl_compatible: true, loaded_at: NOW - 2700, uid: 0, orphaned: false, bytes_xlated: 832, jited: true, bytes_memlock: 4096, btf_id: 43 },

  // Tracepoints
  { id: 10, type: "tracepoint", name: "tracepoint__syscalls__sys_enter_openat", tag: "080900010203000a", gpl_compatible: true, loaded_at: NOW - 10800, uid: 0, orphaned: false, bytes_xlated: 1280, jited: true, bytes_memlock: 8192, map_ids: [17, 18], run_time_ns: 98234000, run_cnt: 45621 },
  { id: 11, type: "tracepoint", name: "tracepoint__net__netif_receive_skb", tag: "09000102030400b0", gpl_compatible: true, loaded_at: NOW - 10800, uid: 0, orphaned: false, bytes_xlated: 960, jited: true, bytes_memlock: 4096, map_ids: [17] },
  { id: 12, type: "raw_tracepoint", name: "raw_tp__sched_switch", tag: "0001020304050c00", gpl_compatible: true, loaded_at: NOW - 8100, uid: 0, orphaned: false, bytes_xlated: 1152, jited: true, bytes_memlock: 4096, btf_id: 55 },

  // Perf events
  { id: 13, type: "perf_event", name: "perf__cpu_cycles", tag: "010203040506000d", gpl_compatible: true, loaded_at: NOW - 3200, uid: 1000, orphaned: false, bytes_xlated: 320, jited: false, bytes_memlock: 4096 },

  // Cgroup programs
  { id: 14, type: "cgroup_skb", name: "cgroup_skb_ingress", tag: "020304050607000e", gpl_compatible: true, loaded_at: NOW - 3600, uid: 0, orphaned: false, bytes_xlated: 64, jited: false, bytes_memlock: 4096 },
  { id: 15, type: "cgroup_skb", name: "cgroup_skb_egress", tag: "03040506070800f0", gpl_compatible: true, loaded_at: NOW - 3600, uid: 0, orphaned: false, bytes_xlated: 64, jited: false, bytes_memlock: 4096 },
  { id: 16, type: "cgroup_device", name: "cgroup_device_policy", tag: "04050607080901f0", gpl_compatible: true, loaded_at: NOW - 3600, uid: 0, orphaned: false, bytes_xlated: 448, jited: false, bytes_memlock: 4096 },
  { id: 17, type: "cgroup_sock", name: "cgroup_sock_create", tag: "05060708090a0200", gpl_compatible: true, loaded_at: NOW - 1200, uid: 0, orphaned: false, bytes_xlated: 192, jited: false, bytes_memlock: 4096 },
  { id: 18, type: "sock_ops", name: "sockops_tcp_rtt", tag: "060708090a0b0300", gpl_compatible: true, loaded_at: NOW - 600, uid: 0, orphaned: false, bytes_xlated: 576, jited: true, bytes_memlock: 4096, map_ids: [19], run_time_ns: 5021000, run_cnt: 1203 },

  // Socket programs
  { id: 19, type: "sk_skb", name: "sk_skb_verdict", tag: "0708090a0b0c0400", gpl_compatible: true, loaded_at: NOW - 2400, uid: 0, orphaned: false, bytes_xlated: 704, jited: true, bytes_memlock: 4096, map_ids: [20] },
  { id: 20, type: "sk_msg", name: "sk_msg_redirect", tag: "08090a0b0c0d0500", gpl_compatible: true, loaded_at: NOW - 2400, uid: 0, orphaned: false, bytes_xlated: 480, jited: true, bytes_memlock: 4096, map_ids: [20] },
  { id: 21, type: "sk_lookup", name: "sk_lookup_dispatch", tag: "090a0b0c0d0e0600", gpl_compatible: true, loaded_at: NOW - 1500, uid: 0, orphaned: false, bytes_xlated: 352, jited: true, bytes_memlock: 4096 },

  // Flow dissector
  { id: 22, type: "flow_dissector", name: "flow_dissector_custom", tag: "0a0b0c0d0e0f0700", gpl_compatible: true, loaded_at: NOW - 4800, uid: 0, orphaned: false, bytes_xlated: 288, jited: true, bytes_memlock: 4096 },

  // Netfilter
  { id: 23, type: "netfilter", name: "nf_bpf_hook", tag: "0b0c0d0e0f100800", gpl_compatible: true, loaded_at: NOW - 3000, uid: 0, orphaned: false, bytes_xlated: 224, jited: false, bytes_memlock: 4096 },

  // LSM
  { id: 24, type: "lsm", name: "lsm_file_open", tag: "0c0d0e0f10110900", gpl_compatible: true, loaded_at: NOW - 7200, uid: 0, orphaned: false, bytes_xlated: 512, jited: true, bytes_memlock: 4096, btf_id: 77, run_time_ns: 3291000, run_cnt: 8821 },

  // Orphaned
  { id: 25, type: "kprobe", name: "old_kprobe_handler", tag: "0d0e0f1011120a00", gpl_compatible: true, loaded_at: NOW - 86400, uid: 1000, orphaned: true, bytes_xlated: 256, jited: false, bytes_memlock: 4096 },
];

export const MOCK_NET: RawNetSnapshot[] = [
  {
    xdp: [
      { devname: "eth0", ifindex: 2, mode: "driver", id: 1 },
      { devname: "eth0", ifindex: 2, mode: "driver", id: 2 },
    ],
    tc: [
      { devname: "eth0", ifindex: 2, kind: "clsact/ingress", name: "cls_bpf_ingress", id: 3 },
      { devname: "eth0", ifindex: 2, kind: "clsact/egress", name: "cls_bpf_egress", id: 4 },
      { devname: "eth0", ifindex: 2, kind: "clsact/egress", name: "act_bpf_mirror", id: 5 },
    ],
    flow_dissector: [
      { devname: "eth0", ifindex: 2, id: 22 },
    ],
    netfilter: [
      { devname: "eth0", ifindex: 2, id: 23 },
    ],
    tcx: [],
    netkit: [],
  },
];

export const MOCK_CGROUPS: RawCgroupEntry[] = [
  {
    cgroup: "/sys/fs/cgroup/system.slice/systemd-udevd.service",
    programs: [
      { id: 15, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
      { id: 14, attach_type: "cgroup_inet_egress", attach_flags: "multi" },
      { id: 16, attach_type: "cgroup_device", attach_flags: "multi" },
    ],
  },
  {
    cgroup: "/sys/fs/cgroup/system.slice/systemd-journald.service",
    programs: [
      { id: 15, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
      { id: 14, attach_type: "cgroup_inet_egress", attach_flags: "multi" },
      { id: 16, attach_type: "cgroup_device", attach_flags: "multi" },
    ],
  },
  {
    cgroup: "/sys/fs/cgroup/system.slice/ssh.service",
    programs: [
      { id: 15, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
      { id: 14, attach_type: "cgroup_inet_egress", attach_flags: "multi" },
      { id: 17, attach_type: "cgroup_sock_create", attach_flags: "" },
      { id: 18, attach_type: "cgroup_sockops", attach_flags: "multi" },
    ],
  },
  {
    cgroup: "/sys/fs/cgroup/user.slice/user-1000.slice/session-1.scope",
    programs: [
      { id: 14, attach_type: "cgroup_inet_egress", attach_flags: "multi" },
      { id: 15, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
    ],
  },
  {
    cgroup: "/sys/fs/cgroup/system.slice/docker.service",
    programs: [
      { id: 14, attach_type: "cgroup_inet_egress", attach_flags: "multi" },
      { id: 15, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
      { id: 16, attach_type: "cgroup_device", attach_flags: "multi" },
    ],
  },
  {
    cgroup: "/sys/fs/cgroup/system.slice/containerd.service",
    programs: [
      { id: 14, attach_type: "cgroup_inet_egress", attach_flags: "multi" },
      { id: 15, attach_type: "cgroup_inet_ingress", attach_flags: "multi" },
      { id: 16, attach_type: "cgroup_device", attach_flags: "multi" },
    ],
  },
];

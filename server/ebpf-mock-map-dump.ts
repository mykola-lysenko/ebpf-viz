import type { MapDumpResult, MapEntry } from "../shared/ebpf-types";

// ─── Hex helpers ──────────────────────────────────────────────────────────────

/** Convert an IPv4 dotted-decimal string to a 4-byte space-separated hex string (network order). */
function ipv4Hex(addr: string): string {
  return addr
    .split(".")
    .map(n => Number(n).toString(16).padStart(2, "0"))
    .join(" ");
}

/** Convert a 6-byte MAC address string to space-separated hex. */
function macHex(mac: string): string {
  return mac.split(":").join(" ");
}

/** Convert a U32 little-endian value to 4-byte space-separated hex. */
function u32leHex(v: number): string {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v, true);
  return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join(" ");
}

/** Convert a U32 big-endian value to 4-byte space-separated hex. */
function u32beHex(v: number): string {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v, false);
  return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join(" ");
}

/** Convert a U16 big-endian value (port) to 2-byte space-separated hex. */
function portHex(port: number): string {
  return [
    ((port >> 8) & 0xff).toString(16).padStart(2, "0"),
    (port & 0xff).toString(16).padStart(2, "0"),
  ].join(" ");
}

/** Convert a U64 little-endian value to 8-byte space-separated hex (safe up to 2^53). */
function u64leHex(v: number): string {
  const b = new Uint8Array(8);
  const view = new DataView(b.buffer);
  view.setUint32(0, v >>> 0, true);
  view.setUint32(4, Math.floor(v / 0x100000000) >>> 0, true);
  return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join(" ");
}

/** Convert a 1-byte protocol number to hex. */
function protoHex(proto: number): string {
  return proto.toString(16).padStart(2, "0");
}

/** Build a MapEntry from raw hex strings. */
function entry(
  index: number,
  keyHex: string,
  valueHex: string,
  opts: { keyDecimal?: string; valueDecimal?: string; perCpuValues?: MapEntry["perCpuValues"] } = {},
): MapEntry {
  return {
    index,
    keyHex,
    keyDecimal: opts.keyDecimal ?? null,
    keyBtf: null,
    valueHex,
    valueDecimal: opts.valueDecimal ?? null,
    valueBtf: null,
    valueError: null,
    perCpuValues: opts.perCpuValues,
  };
}

function result(
  mapId: number,
  mapType: string,
  mapName: string,
  entries: MapEntry[],
  opts: { btfDecoded?: boolean; unsupported?: boolean; error?: string } = {},
): MapDumpResult {
  return {
    mapId,
    mapType,
    mapName,
    totalEntries: entries.length,
    truncated: false,
    maxReturned: 500,
    btfDecoded: opts.btfDecoded ?? false,
    error: opts.error ?? null,
    unsupported: opts.unsupported ?? false,
    entries,
  };
}

// ─── Per-map mock data ────────────────────────────────────────────────────────

/**
 * Map 10: xdp_blocked_ips — hash, key=IPv4 (4B), value=U64 LE drop counter (8B)
 * Used by: xdp_drop_icmp (prog 1)
 */
function mockXdpBlockedIps(): MapEntry[] {
  const ips = [
    ["192.168.1.100", 14823],
    ["10.0.0.5",      3291],
    ["172.16.0.50",   88201],
    ["192.168.1.200", 421],
    ["10.10.10.10",   7654],
    ["203.0.113.1",   1],
    ["198.51.100.42", 9912],
    ["192.0.2.1",     55],
  ];
  return ips.map(([ip, cnt], i) =>
    entry(i, ipv4Hex(ip as string), u64leHex(cnt as number), {
      keyDecimal: (ip as string).split(".").map(Number).join("."),
    }),
  );
}

/**
 * Map 11: xdp_stats — percpu_array, key=U32 LE index (XDP action), value=U64 LE per-CPU counters (16B)
 * Indices: 0=ABORTED, 1=DROP, 2=PASS, 3=TX, 4=REDIRECT
 * Used by: xdp_drop_icmp (prog 1)
 */
function mockXdpStats(): MapEntry[] {
  const actions = ["ABORTED", "DROP", "PASS", "TX", "REDIRECT", "UNKNOWN_5", "UNKNOWN_6", "UNKNOWN_7"];
  const cpuCounts = [
    [0, 14823, 98201, 12, 3291],   // ABORTED: mostly 0
    [3, 14823, 98201, 12, 3291],   // DROP: high on cpu1
    [88201, 421012, 1203921, 99821, 204812], // PASS: very high
    [0, 0, 12, 0, 0],              // TX: rare
    [3291, 1204, 9821, 421, 1023], // REDIRECT: moderate
    [0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0],
  ];
  return actions.map((action, i) => {
    const perCpuValues = cpuCounts[i].map((cnt, cpu) => ({
      cpu,
      hex: u64leHex(cnt) + " " + u64leHex(cnt * 64), // packets + bytes
      decimal: String(cnt),
    }));
    const totalPkts = cpuCounts[i].reduce((a, b) => a + b, 0);
    return entry(i, u32leHex(i), u64leHex(totalPkts), {
      keyDecimal: String(i),
      valueDecimal: String(totalPkts),
      perCpuValues,
    });
  });
}

/**
 * Map 12: lb_backends — lpm_trie, key=8B (prefix len U32 LE + IPv4 4B), value=20B backend info
 * Used by: xdp_lb_kern (prog 2)
 */
function mockLbBackends(): MapEntry[] {
  const prefixes: Array<[number, string, string, number]> = [
    [32, "10.0.1.10",  "10.0.0.1",  8080],
    [32, "10.0.1.11",  "10.0.0.2",  8080],
    [32, "10.0.1.12",  "10.0.0.3",  8080],
    [24, "10.0.2.0",   "10.0.0.10", 9090],
    [16, "172.16.0.0", "10.0.0.20", 443],
  ];
  return prefixes.map(([prefixLen, srcIp, dstIp, port], i) => {
    const keyHex = u32leHex(prefixLen) + " " + ipv4Hex(srcIp);
    // value: dst IPv4 (4B) + port U16 BE (2B) + weight U32 LE (4B) + flags U32 LE (4B) + padding (6B)
    const valueHex = ipv4Hex(dstIp) + " " + portHex(port) + " " + u32leHex(1) + " " + u32leHex(0) + " 00 00 00 00 00 00";
    return entry(i, keyHex, valueHex);
  });
}

/**
 * Map 13: tc_flow_table — hash, key=13B (src IPv4 4B + dst IPv4 4B + src port 2B + dst port 2B + proto 1B),
 * value=32B (bytes U64 LE + packets U64 LE + last_seen U64 LE + flags U32 LE + pad 4B)
 * Used by: cls_bpf_ingress (prog 3), cls_bpf_egress (prog 4)
 */
function mockTcFlowTable(): MapEntry[] {
  const flows: Array<[string, string, number, number, number]> = [
    ["10.0.0.5",   "10.0.1.10",  54321, 80,   6],  // TCP HTTP
    ["10.0.0.5",   "10.0.1.10",  54322, 443,  6],  // TCP HTTPS
    ["192.168.1.1","8.8.8.8",    12345, 53,   17], // UDP DNS
    ["10.0.0.10",  "10.0.1.11",  49152, 8080, 6],  // TCP custom
    ["172.16.0.5", "10.0.0.1",   33333, 22,   6],  // TCP SSH
    ["10.0.0.5",   "224.0.0.1",  0,     0,    1],  // ICMP multicast
  ];
  return flows.map(([src, dst, sport, dport, proto], i) => {
    const keyHex = ipv4Hex(src) + " " + ipv4Hex(dst) + " " + portHex(sport) + " " + portHex(dport) + " " + protoHex(proto);
    const bytes = 1400 * (i + 1) * 100;
    const pkts = (i + 1) * 100;
    const lastSeen = Math.floor(Date.now() / 1000) - i * 10;
    const valueHex = u64leHex(bytes) + " " + u64leHex(pkts) + " " + u64leHex(lastSeen) + " " + u32leHex(0) + " 00 00 00 00";
    return entry(i, keyHex, valueHex);
  });
}

/**
 * Map 15: pid_filter — hash, key=U32 LE PID (4B), value=U32 LE flag (4B, 1=allowed)
 * Used by: kprobe__sys_execve (prog 6)
 */
function mockPidFilter(): MapEntry[] {
  const pids = [1, 2, 456, 1234, 5678, 9999, 12345, 31337];
  return pids.map((pid, i) =>
    entry(i, u32leHex(pid), u32leHex(1), {
      keyDecimal: String(pid),
      valueDecimal: "1",
    }),
  );
}

/**
 * Map 18: syscall_filter — hash, key=U32 LE syscall number (4B), value=U32 LE flag (4B)
 * Used by: tracepoint__syscalls__sys_enter_openat (prog 10)
 */
function mockSyscallFilter(): MapEntry[] {
  // Common Linux syscall numbers (x86_64)
  const syscalls: Array<[number, string]> = [
    [0,   "read"],
    [1,   "write"],
    [2,   "open"],
    [3,   "close"],
    [59,  "execve"],
    [257, "openat"],
    [322, "execveat"],
    [56,  "clone"],
  ];
  return syscalls.map(([nr, _name], i) =>
    entry(i, u32leHex(nr), u32leHex(1), {
      keyDecimal: String(nr),
      valueDecimal: "1",
    }),
  );
}

/**
 * Map 19: rtt_histogram — array, key=U32 LE bucket index, value=U64 LE count
 * Buckets: 0-9=<1ms, 10-19=1-10ms, 20-29=10-100ms, 30-39=100ms-1s, 40-49=1s+, 50-99=empty
 * Used by: sockops_tcp_rtt (prog 18)
 */
function mockRttHistogram(): MapEntry[] {
  // Realistic RTT distribution: most connections are fast
  const counts = [
    // <1ms buckets (0-9)
    0, 12, 8921, 14823, 9012, 3421, 1203, 421, 88, 12,
    // 1-10ms buckets (10-19)
    8, 421, 3291, 8821, 12034, 9821, 4201, 1823, 421, 88,
    // 10-100ms buckets (20-29)
    12, 88, 421, 1203, 2891, 1823, 821, 312, 88, 21,
    // 100ms-1s buckets (30-39)
    3, 12, 45, 88, 121, 88, 45, 21, 8, 2,
    // 1s+ buckets (40-49)
    1, 2, 1, 0, 0, 0, 0, 0, 0, 0,
    // Unused (50-99)
    ...Array(50).fill(0),
  ];
  return counts.map((cnt, i) =>
    entry(i, u32leHex(i), u64leHex(cnt), {
      keyDecimal: String(i),
      valueDecimal: String(cnt),
    }),
  );
}

/**
 * Map 20: sock_redirect — sockmap, key=U32 LE socket index, value=U32 LE (socket fd placeholder)
 * Used by: sk_skb_verdict (prog 19), sk_msg_redirect (prog 20)
 */
function mockSockRedirect(): MapEntry[] {
  const entries: MapEntry[] = [];
  for (let i = 0; i < 8; i++) {
    entries.push(entry(i, u32leHex(i), u32leHex(100 + i), {
      keyDecimal: String(i),
      valueDecimal: String(100 + i),
    }));
  }
  return entries;
}

/**
 * Map 22: conn_track — lru_hash, key=12B (src IPv4 4B + dst IPv4 4B + src port 2B + dst port 2B),
 * value=24B (created_ns U64 LE + last_seen_ns U64 LE + bytes U64 LE)
 * Not directly referenced by a program in MOCK_PROGS but included as a standalone map
 */
function mockConnTrack(): MapEntry[] {
  const now = Math.floor(Date.now() / 1000) * 1_000_000_000; // nanoseconds
  const conns: Array<[string, string, number, number]> = [
    ["10.0.0.5",   "10.0.1.10",  54321, 80],
    ["10.0.0.5",   "10.0.1.10",  54322, 443],
    ["192.168.1.1","8.8.8.8",    12345, 53],
    ["10.0.0.10",  "10.0.1.11",  49152, 8080],
    ["172.16.0.5", "10.0.0.1",   33333, 22],
    ["10.0.0.5",   "10.0.1.12",  54323, 8080],
    ["10.0.0.20",  "10.0.1.10",  60000, 443],
    ["192.168.1.2","1.1.1.1",    55555, 53],
  ];
  return conns.map(([src, dst, sport, dport], i) => {
    const keyHex = ipv4Hex(src) + " " + ipv4Hex(dst) + " " + portHex(sport) + " " + portHex(dport);
    const created = now - (i + 1) * 60_000_000_000; // i+1 minutes ago
    const lastSeen = now - i * 1_000_000_000;        // i seconds ago
    const bytes = 1400 * (i + 1) * 50;
    const valueHex = u64leHex(created) + " " + u64leHex(lastSeen) + " " + u64leHex(bytes);
    return entry(i, keyHex, valueHex);
  });
}

/**
 * Map 23: config_map — array, key=U32 LE index, value=U32 LE config value
 * Global configuration flags/values for the XDP program
 */
function mockConfigMap(): MapEntry[] {
  const configs: Array<[string, number]> = [
    ["ENABLED",           1],
    ["LOG_LEVEL",         2],
    ["MAX_CONNS",         65535],
    ["TIMEOUT_MS",        5000],
    ["RATE_LIMIT_PPS",    10000],
    ["RATE_LIMIT_BPS",    1000000],
    ["BLOCK_ICMP",        1],
    ["BLOCK_FRAGMENTS",   0],
    ["ALLOW_MULTICAST",   0],
    ["ALLOW_BROADCAST",   1],
    ["DEBUG_MODE",        0],
    ["STATS_INTERVAL_MS", 1000],
    ["RESERVED_12",       0],
    ["RESERVED_13",       0],
    ["RESERVED_14",       0],
    ["RESERVED_15",       0],
  ];
  return configs.map(([_name, val], i) =>
    entry(i, u32leHex(i), u32leHex(val), {
      keyDecimal: String(i),
      valueDecimal: String(val),
    }),
  );
}

// ─── Unsupported map types ────────────────────────────────────────────────────

const UNSUPPORTED_TYPES = new Set([
  "perf_event_array", "ringbuf", "prog_array",
  "sockmap", "sockhash", "queue", "stack",
  "user_ringbuf", "bloom_filter",
]);

// ─── Dispatch ─────────────────────────────────────────────────────────────────

/**
 * Return a realistic mock MapDumpResult for the given map ID in demo mode.
 * Falls back to an empty result for unknown map IDs.
 */
export function buildMockMapDump(
  mapId: number,
  mapType: string,
  mapName: string,
): MapDumpResult {
  // Unsupported types cannot be dumped
  if (UNSUPPORTED_TYPES.has(mapType)) {
    return result(mapId, mapType, mapName, [], {
      unsupported: true,
      error: `Map type '${mapType}' does not support entry enumeration`,
    });
  }

  let entries: MapEntry[] = [];
  switch (mapId) {
    case 10: entries = mockXdpBlockedIps();  break;
    case 11: entries = mockXdpStats();       break;
    case 12: entries = mockLbBackends();     break;
    case 13: entries = mockTcFlowTable();    break;
    case 15: entries = mockPidFilter();      break;
    case 18: entries = mockSyscallFilter();  break;
    case 19: entries = mockRttHistogram();   break;
    case 20: entries = mockSockRedirect();   break;
    case 22: entries = mockConnTrack();      break;
    case 23: entries = mockConfigMap();      break;
    default:
      // Generic fallback: 4 array-style entries
      entries = [0, 1, 2, 3].map(i =>
        entry(i, u32leHex(i), u32leHex(0), { keyDecimal: String(i), valueDecimal: "0" }),
      );
  }

  return result(mapId, mapType, mapName, entries);
}

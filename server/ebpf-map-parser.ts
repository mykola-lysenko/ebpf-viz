import type { BpfMap, BpfMapType, BpfProgram, RawBpfMap } from "../shared/ebpf-types";
import { MAP_TYPE_META } from "../shared/ebpf-types";

// ─── Type normalization ────────────────────────────────────────────────────

const KNOWN_TYPES = new Set<BpfMapType>([
  "hash", "array", "prog_array", "perf_event_array",
  "percpu_hash", "percpu_array", "stack_trace", "cgroup_array",
  "lru_hash", "lru_percpu_hash", "lpm_trie", "array_of_maps",
  "hash_of_maps", "devmap", "sockmap", "cpumap", "xskmap",
  "sockhash", "cgroup_storage", "reuseport_sockarray",
  "percpu_cgroup_storage", "queue", "stack", "sk_storage",
  "devmap_hash", "struct_ops", "ringbuf", "inode_storage",
  "task_storage", "bloom_filter", "user_ringbuf", "cgrp_storage",
]);

function normalizeType(raw: string): BpfMapType {
  const lower = raw.toLowerCase().replace(/-/g, "_");
  if (KNOWN_TYPES.has(lower as BpfMapType)) return lower as BpfMapType;
  return "unknown";
}

// ─── Parser ────────────────────────────────────────────────────────────────

/**
 * Parse raw bpftool map list JSON into enriched BpfMap objects.
 * Cross-references programs to populate usedByProgIds.
 */
export function parseMaps(rawMaps: RawBpfMap[], programs: BpfProgram[]): BpfMap[] {
  if (!rawMaps || !Array.isArray(rawMaps)) return [];
  // Build reverse index: mapId → set of program IDs that reference it
  const mapToProgs = new Map<number, Set<number>>();
  for (const prog of programs) {
    for (const mapId of prog.mapIds) {
      if (!mapToProgs.has(mapId)) mapToProgs.set(mapId, new Set());
      mapToProgs.get(mapId)!.add(prog.id);
    }
  }

  return rawMaps.map(raw => {
    const type = normalizeType(raw.type ?? "unknown");
    const meta = MAP_TYPE_META[type] ?? MAP_TYPE_META["unknown"]!;
    const usedByProgIds = Array.from(mapToProgs.get(raw.id) ?? []);

    return {
      id: raw.id,
      type,
      rawType: raw.type ?? "unknown",
      name: raw.name?.trim() || `map_${raw.id}`,
      flags: raw.flags ?? 0,
      bytesKey: raw.bytes_key ?? 0,
      bytesValue: raw.bytes_value ?? 0,
      maxEntries: raw.max_entries ?? 0,
      bytesMemlock: raw.bytes_memlock ?? 0,
      frozen: Boolean(raw.frozen),
      pinnedPaths: raw.pinned ?? [],
      btfId: raw.btf_id,
      usedByProgIds,
      color: meta.color,
      category: meta.category,
    } satisfies BpfMap;
  });
}

/**
 * Build mock BPF maps that correspond to the mock programs' map_ids.
 * Used in demo mode.
 */
export function buildMockMaps(programs: BpfProgram[]): BpfMap[] {
  // Collect all unique map IDs referenced by programs
  const allMapIds = new Set<number>();
  for (const prog of programs) {
    for (const id of prog.mapIds) allMapIds.add(id);
  }

  const MOCK_MAP_DEFS: Record<number, Omit<RawBpfMap, "id">> = {
    10: { type: "hash",           name: "xdp_blocked_ips",   bytes_key: 4,  bytes_value: 8,  max_entries: 65536, bytes_memlock: 4194304 },
    11: { type: "percpu_array",   name: "xdp_stats",         bytes_key: 4,  bytes_value: 16, max_entries: 8,     bytes_memlock: 65536 },
    12: { type: "lpm_trie",       name: "lb_backends",       bytes_key: 8,  bytes_value: 20, max_entries: 1024,  bytes_memlock: 131072 },
    13: { type: "hash",           name: "tc_flow_table",     bytes_key: 13, bytes_value: 32, max_entries: 8192,  bytes_memlock: 524288 },
    14: { type: "perf_event_array", name: "exec_events",     bytes_key: 4,  bytes_value: 4,  max_entries: 64,    bytes_memlock: 4096 },
    15: { type: "hash",           name: "pid_filter",        bytes_key: 4,  bytes_value: 1,  max_entries: 1024,  bytes_memlock: 65536 },
    16: { type: "ringbuf",        name: "tcp_events",        bytes_key: 0,  bytes_value: 0,  max_entries: 262144, bytes_memlock: 262144 },
    17: { type: "perf_event_array", name: "syscall_events",  bytes_key: 4,  bytes_value: 4,  max_entries: 64,    bytes_memlock: 4096 },
    18: { type: "hash",           name: "syscall_filter",    bytes_key: 4,  bytes_value: 1,  max_entries: 512,   bytes_memlock: 32768 },
    19: { type: "array",          name: "rtt_histogram",     bytes_key: 4,  bytes_value: 8,  max_entries: 100,   bytes_memlock: 4096 },
    20: { type: "sockmap",        name: "sock_redirect",     bytes_key: 4,  bytes_value: 4,  max_entries: 65535, bytes_memlock: 524288 },
    21: { type: "prog_array",     name: "tail_calls",        bytes_key: 4,  bytes_value: 4,  max_entries: 8,     bytes_memlock: 4096 },
    22: { type: "lru_hash",       name: "conn_track",        bytes_key: 12, bytes_value: 24, max_entries: 65536, bytes_memlock: 4194304 },
    23: { type: "array",          name: "config_map",        bytes_key: 4,  bytes_value: 4,  max_entries: 16,    bytes_memlock: 4096 },
    24: { type: "hash",           name: "ktime_map",          bytes_key: 4,  bytes_value: 8,  max_entries: 1024,  bytes_memlock: 65536 },
  };

  const rawMaps: RawBpfMap[] = [];
  for (const id of Array.from(allMapIds).sort((a, b) => a - b)) {
    const def = MOCK_MAP_DEFS[id];
    if (def) {
      rawMaps.push({ id, ...def });
    } else {
      // Fallback for any map IDs not in our predefined list
      rawMaps.push({
        id,
        type: "array",
        name: `map_${id}`,
        bytes_key: 4,
        bytes_value: 8,
        max_entries: 256,
        bytes_memlock: 4096,
      });
    }
  }

  return parseMaps(rawMaps, programs);
}

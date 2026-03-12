/**
 * MapEntriesModal
 * Full-screen modal that shows the entries of a BPF map by calling
 * trpc.ebpf.mapDump.  Supports:
 *  - Hex / Decimal / BTF display modes for keys and values
 *  - Raw / IPv4 / IPv6 / MAC / Port / U32 / U64 / CgroupID / Protocol / Timestamp interpretation
 *  - Auto-detection of best default interpretation based on map type
 *  - Pagination (50 rows per page)
 *  - Copy-to-clipboard for individual cells
 *  - Per-CPU value expansion
 *  - Graceful unsupported / error states
 */

import { useState, useMemo, useRef, useCallback, useEffect } from "react";
import { trpc } from "@/lib/trpc";
import type { MapEntry } from "../../../shared/ebpf-types";
import {
  X,
  Copy,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  Database,
  Loader2,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Search,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

// ─── Types ────────────────────────────────────────────────────────────────────

type DisplayMode = "hex" | "decimal" | "btf";
type InterpretMode =
  | "raw"
  | "ipv4" | "ipv6"
  | "mac"
  | "port"
  | "u32"     // 4-byte unsigned integer (LE by default, BE via toggle)
  | "u64"     // 8-byte unsigned integer (LE by default, BE via toggle)
  | "cgroupid" // 8-byte cgroup inode + 4-byte attach type
  | "proto"   // 1-byte IP protocol number
  | "ts";     // 8-byte nanosecond timestamp → human-readable elapsed time

interface MapEntriesModalProps {
  mapId: number;
  mapName: string;
  mapType: string;
  mapColor: string;
  /** Byte length of the key field — used to filter interpretation options */
  keyBytes?: number;
  /** Byte length of the value field — used to filter interpretation options */
  valueBytes?: number;
  onClose: () => void;
}

// ─── IP interpretation helpers ────────────────────────────────────────────────

/**
 * Parse a space-separated hex byte string (e.g. "c0 a8 01 01") into a Uint8Array.
 * Returns null if the string is empty or malformed.
 */
function parseHexBytes(hex: string): Uint8Array | null {
  const parts = hex.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return null;
  const bytes = new Uint8Array(parts.length);
  for (let i = 0; i < parts.length; i++) {
    const v = parseInt(parts[i], 16);
    if (isNaN(v)) return null;
    bytes[i] = v;
  }
  return bytes;
}

/**
 * Convert bytes to an IPv4 dotted-decimal string.
 * BPF maps store IPv4 addresses in network byte order (big-endian).
 * Returns an error string if the byte count is wrong.
 */
function bytesToIPv4(bytes: Uint8Array): string {
  if (bytes.length === 4) {
    return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
  }
  // Some maps store IPv4 in a 16-byte field (IPv4-mapped IPv6 or padded)
  if (bytes.length === 16) {
    // Check for IPv4-mapped IPv6: 10 zero bytes + 2 0xff bytes + 4 IPv4 bytes
    const isV4Mapped =
      bytes.slice(0, 10).every(b => b === 0) &&
      bytes[10] === 0xff && bytes[11] === 0xff;
    if (isV4Mapped) {
      return `${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
    }
    // Some XDP/TC programs store IPv4 in the first 4 bytes of a 16-byte slot
    return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]} (first 4B of ${bytes.length}B)`;
  }
  return `(need 4B, got ${bytes.length}B)`;
}

/**
 * Convert bytes to a full IPv6 address string with :: compression.
 * Returns an error string if the byte count is wrong.
 */
function bytesToIPv6(bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    return `(need 16B, got ${bytes.length}B)`;
  }
  // Build array of 8 16-bit groups
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push((bytes[i] << 8) | bytes[i + 1]);
  }

  // Find the longest run of consecutive zero groups for :: compression
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i <= groups.length; i++) {
    if (i < groups.length && groups[i] === 0) {
      if (curStart === -1) { curStart = i; curLen = 0; }
      curLen++;
    } else {
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
      curStart = -1; curLen = 0;
    }
  }

  if (bestLen < 2) {
    // No compression — just join all groups
    return groups.map(g => g.toString(16)).join(":");
  }

  const left = groups.slice(0, bestStart).map(g => g.toString(16)).join(":");
  const right = groups.slice(bestStart + bestLen).map(g => g.toString(16)).join(":");
  return `${left}::${right}`;
}

/** Well-known TCP/UDP port numbers → service name */
const WELL_KNOWN_PORTS: Record<number, string> = {
  20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
  25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
  69: "tftp", 80: "http", 110: "pop3", 123: "ntp",
  143: "imap", 161: "snmp", 179: "bgp", 389: "ldap",
  443: "https", 465: "smtps", 514: "syslog", 515: "lpd",
  587: "smtp", 636: "ldaps", 993: "imaps", 995: "pop3s",
  1194: "openvpn", 1433: "mssql", 1521: "oracle",
  3306: "mysql", 3389: "rdp", 5432: "postgres",
  5672: "amqp", 5900: "vnc", 6379: "redis",
  6443: "k8s-api", 8080: "http-alt", 8443: "https-alt",
  9200: "elasticsearch", 9300: "elasticsearch",
  27017: "mongodb",
};

/**
 * Convert bytes to a port number string.
 * Expects exactly 2 bytes in big-endian (network) order.
 * Annotates well-known ports with their service name.
 */
function bytesToPort(bytes: Uint8Array): string {
  if (bytes.length !== 2) {
    return `(need 2B, got ${bytes.length}B)`;
  }
  const port = (bytes[0] << 8) | bytes[1];
  const name = WELL_KNOWN_PORTS[port];
  return name ? `${port} (${name})` : `${port}`;
}

/**
 * Convert bytes to a MAC address string (aa:bb:cc:dd:ee:ff).
 * Expects exactly 6 bytes. Returns an error string otherwise.
 */
function bytesToMAC(bytes: Uint8Array): string {
  if (bytes.length !== 6) {
    return `(need 6B, got ${bytes.length}B)`;
  }
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join(":");
}

/** IP protocol numbers → name */
const IP_PROTOCOLS: Record<number, string> = {
  0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IPv4",
  6: "TCP", 8: "EGP", 9: "IGP", 17: "UDP",
  33: "DCCP", 41: "IPv6", 43: "IPv6-Route", 44: "IPv6-Frag",
  47: "GRE", 50: "ESP", 51: "AH", 58: "IPv6-ICMP",
  89: "OSPF", 103: "PIM", 112: "VRRP", 115: "L2TP",
  132: "SCTP", 136: "UDPLite", 137: "MPLS-in-IP",
};

/** BPF cgroup attach types → short name */
const CGROUP_ATTACH_TYPES: Record<number, string> = {
  0: "ingress", 1: "egress", 2: "sock_create", 3: "sock_ops",
  4: "device", 5: "inet4_bind", 6: "inet6_bind",
  7: "inet_connect", 8: "inet_post_bind4", 9: "inet_post_bind6",
  10: "inet4_getpeername", 11: "inet6_getpeername",
  12: "inet4_getsockname", 13: "inet6_getsockname",
  14: "udp4_sendmsg", 15: "udp6_sendmsg",
  16: "udp4_recvmsg", 17: "udp6_recvmsg",
  18: "getsockopt", 19: "setsockopt",
  20: "sk_lookup",
};

/**
 * Read a 32-bit little-endian unsigned integer from exactly 4 bytes.
 * Uses DataView to avoid BigInt (compatible with ES2017 target).
 */
function readU32LE(bytes: Uint8Array): number {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(0, true /* little-endian */);
}

/**
 * Read a 32-bit big-endian unsigned integer from exactly 4 bytes.
 */
function readU32BE(bytes: Uint8Array): number {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(0, false /* big-endian */);
}

/**
 * Read a 64-bit little-endian unsigned integer from exactly 8 bytes.
 * JavaScript numbers lose precision above 2^53, so we split into two 32-bit
 * halves and combine as a decimal string to preserve all digits.
 */
function readU64LEAsString(bytes: Uint8Array): string {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const lo = view.getUint32(0, true);
  const hi = view.getUint32(4, true);
  // Combine: value = hi * 2^32 + lo
  // Use string arithmetic to avoid floating-point precision loss
  const hiStr = (hi * 4294967296).toFixed(0); // hi * 2^32 as integer string
  const total = BigInt(hiStr) + BigInt(lo);
  return total.toString();
}

/** 4-byte little-endian → decimal (array index, CPU ID, etc.) */
function bytesToU32LE(bytes: Uint8Array): string {
  if (bytes.length !== 4) return `(need 4B, got ${bytes.length}B)`;
  return String(readU32LE(bytes));
}

/** 4-byte big-endian → decimal */
function bytesToU32BE(bytes: Uint8Array): string {
  if (bytes.length !== 4) return `(need 4B, got ${bytes.length}B)`;
  return String(readU32BE(bytes));
}

/** 8-byte little-endian → decimal (counters, cgroup inode IDs, timestamps) */
function bytesToU64LE(bytes: Uint8Array): string {
  if (bytes.length !== 8) return `(need 8B, got ${bytes.length}B)`;
  return readU64LEAsString(bytes);
}

/**
 * Cgroup storage key: 8-byte inode ID (LE) + 4-byte attach type (LE).
 * Total 12 bytes. Returns "inode: N, attach: T".
 */
function bytesToCgroupId(bytes: Uint8Array): string {
  if (bytes.length === 8) {
    // Some maps use just the 8-byte inode ID
    return `inode: ${readU64LEAsString(bytes)}`;
  }
  if (bytes.length === 12) {
    const inode = readU64LEAsString(bytes.slice(0, 8));
    const attachType = readU32LE(bytes.slice(8, 12));
    const attachName = CGROUP_ATTACH_TYPES[attachType] ?? `type_${attachType}`;
    return `inode: ${inode}, attach: ${attachName}`;
  }
  return `(need 8B or 12B, got ${bytes.length}B)`;
}

/** 1-byte IP protocol number → "N (name)" */
function bytesToProtocol(bytes: Uint8Array): string {
  if (bytes.length !== 1) return `(need 1B, got ${bytes.length}B)`;
  const proto = bytes[0];
  const name = IP_PROTOCOLS[proto];
  return name ? `${proto} (${name})` : `${proto}`;
}

/**
 * Convert 8 bytes (little-endian U64) representing nanoseconds from
 * bpf_ktime_get_ns() into a human-readable elapsed-time string.
 *
 * Format: [Ny] [Nd] [Nh] [Nm] [Ns] [Nms]  — only non-zero components shown,
 * except for sub-millisecond values which show the raw nanosecond count.
 * Zero is shown as "0 (never)" to distinguish an unset map slot from
 * a program that ran at boot time with zero elapsed time.
 */
function bytesToTimestamp(bytes: Uint8Array): string {
  if (bytes.length !== 8) return `(need 8B, got ${bytes.length}B)`;

  // Read as LE U64 using BigInt for full 64-bit precision.
  // Use BigInt() constructor (not n-suffix literals) for ES2017 compat.
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const lo = BigInt(view.getUint32(0, true));
  const hi = BigInt(view.getUint32(4, true));
  const B32 = BigInt(32);
  const ns = (hi << B32) | lo;

  const ZERO = BigInt(0);
  if (ns === ZERO) return "0 (never)";

  // Time-unit constants as BigInt
  const MS  = BigInt(1_000_000);
  const SEC = BigInt(1_000) * MS;
  const MIN = BigInt(60) * SEC;
  const HR  = BigInt(60) * MIN;
  const DAY = BigInt(24) * HR;
  const YR  = BigInt(365) * DAY;

  let rem = ns;
  const years   = rem / YR;   rem %= YR;
  const days    = rem / DAY;  rem %= DAY;
  const hours   = rem / HR;   rem %= HR;
  const minutes = rem / MIN;  rem %= MIN;
  const seconds = rem / SEC;  rem %= SEC;
  const millis  = rem / MS;   rem %= MS;

  const parts: string[] = [];
  if (years   > ZERO) parts.push(`${years}y`);
  if (days    > ZERO) parts.push(`${days}d`);
  if (hours   > ZERO) parts.push(`${hours}h`);
  if (minutes > ZERO) parts.push(`${minutes}m`);
  if (seconds > ZERO) parts.push(`${seconds}s`);
  if (millis  > ZERO) parts.push(`${millis}ms`);

  // Sub-millisecond: show raw ns
  if (parts.length === 0) return `${ns}ns`;

  return parts.join(" ");
}

/**
 * Apply an interpretation mode to a raw hex string.
 * @param hex  Space-separated hex byte string.
 * @param mode Interpretation mode.
 * @param bigEndian When true, reverse the byte array before interpreting
 *                  (applies to u32, u64, ipv4, port, mac — byte-order-sensitive types).
 */
function interpretHex(hex: string, mode: InterpretMode, bigEndian = false): string {
  if (mode === "raw" || !hex || hex === "—") return hex;
  // Don't try to interpret BTF-decoded JSON or decimal strings
  if (hex.startsWith("{") || hex.startsWith("[")) return hex;
  let bytes = parseHexBytes(hex);
  if (!bytes) return hex;
  // Reverse byte order for BE interpretation of byte-order-sensitive types
  if (bigEndian && (mode === "u32" || mode === "u64" || mode === "ipv4" || mode === "port" || mode === "mac")) {
    bytes = bytes.slice().reverse();
  }
  if (mode === "ipv4") return bytesToIPv4(bytes);
  if (mode === "ipv6") return bytesToIPv6(bytes);
  if (mode === "mac") return bytesToMAC(bytes);
  if (mode === "port") return bytesToPort(bigEndian ? bytes : bytes); // already reversed above
  if (mode === "u32") return bytesToU32LE(bytes);  // after optional reversal, always read as LE
  if (mode === "u64") return bytesToU64LE(bytes);  // after optional reversal, always read as LE
  if (mode === "cgroupid") return bytesToCgroupId(bytes);
  if (mode === "proto") return bytesToProtocol(bytes);
  if (mode === "ts") return bytesToTimestamp(bytes);
  return hex;
}

/**
 * Auto-detect the best default key interpretation based on map type.
 * Returns "raw" when no specific interpretation is warranted.
 */
function defaultKeyInterpret(mapType: string): InterpretMode {
  const t = mapType.toLowerCase();
  if (t === "array" || t === "percpu_array") return "u32";
  if (t === "cgroup_storage" || t === "percpu_cgroup_storage" || t === "cgrp_storage") return "cgroupid";
  return "raw";
}

// ── localStorage persistence for per-map-type interpretation prefs ─────────────────────────────────

const VALID_MODES = new Set<string>([
  "raw", "ipv4", "ipv6", "mac", "port",
  "u32", "u64", "cgroupid", "proto", "ts",
]);

function storageKey(mapType: string): string {
  return `ebpf-viz:interp:${mapType.toLowerCase()}`;
}

interface InterpretPrefs {
  key: InterpretMode;
  val: InterpretMode;
}

function loadInterpretPrefs(mapType: string): InterpretPrefs | null {
  try {
    const raw = localStorage.getItem(storageKey(mapType));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { key?: string; val?: string };
    const key = VALID_MODES.has(parsed.key ?? "") ? (parsed.key as InterpretMode) : null;
    const val = VALID_MODES.has(parsed.val ?? "") ? (parsed.val as InterpretMode) : null;
    if (!key || !val) return null;
    return { key, val };
  } catch {
    return null;
  }
}

function saveInterpretPrefs(mapType: string, key: InterpretMode, val: InterpretMode): void {
  try {
    localStorage.setItem(storageKey(mapType), JSON.stringify({ key, val }));
  } catch {
    // localStorage may be unavailable in private browsing — silently ignore
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const PAGE_SIZE = 50;

/**
 * Compute the final display text for an entry's key or value, applying the
 * same interpretation logic used by EntryRow. Used for filtering.
 */
function entryKeyText(
  entry: MapEntry,
  mode: DisplayMode,
  interpret: InterpretMode,
  bigEndian: boolean,
): string {
  const raw = displayKey(entry, mode);
  return (mode === "hex" || (!entry.keyBtf && mode !== "decimal"))
    ? interpretHex(raw, interpret, bigEndian)
    : raw;
}

function entryValText(
  entry: MapEntry,
  mode: DisplayMode,
  interpret: InterpretMode,
  bigEndian: boolean,
): string {
  if (entry.valueError) return `error: ${entry.valueError}`;
  const raw = displayValue(entry, mode);
  return (mode === "hex" || (!entry.valueBtf && mode !== "decimal"))
    ? interpretHex(raw, interpret, bigEndian)
    : raw;
}

function displayKey(entry: MapEntry, mode: DisplayMode): string {
  if (mode === "btf" && entry.keyBtf) return entry.keyBtf;
  if (mode === "decimal" && entry.keyDecimal !== null) return entry.keyDecimal;
  return entry.keyHex || entry.keyBtf || "—";
}

function displayValue(entry: MapEntry, mode: DisplayMode): string {
  if (entry.valueError) return `error: ${entry.valueError}`;
  if (mode === "btf" && entry.valueBtf) return entry.valueBtf;
  if (mode === "decimal" && entry.valueDecimal !== null) return entry.valueDecimal;
  return entry.valueHex || entry.valueBtf || "—";
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <button
      onClick={handleCopy}
      className="ml-1.5 p-0.5 rounded opacity-0 group-hover:opacity-100 hover:bg-white/10 text-white/30 hover:text-white/70 transition-all flex-shrink-0"
      title="Copy"
    >
      {copied ? (
        <span className="text-[10px] text-green-400 font-mono">✓</span>
      ) : (
        <Copy className="w-3 h-3" />
      )}
    </button>
  );
}

// ─── Interpret toggle ──────────────────────────────────────────────────────────

const INTERPRET_OPTIONS: { value: InterpretMode; label: string; title: string; requiredBytes: number | number[] | null; beToggleable: boolean }[] = [
  { value: "raw",      label: "Raw",    title: "Show raw bytes as-is",                                                                        requiredBytes: null,    beToggleable: false },
  { value: "ipv4",     label: "IPv4",   title: "Interpret bytes as IPv4 address (4 bytes)",                                                  requiredBytes: 4,       beToggleable: true  },
  { value: "ipv6",     label: "IPv6",   title: "Interpret bytes as IPv6 address (16 bytes, network order)",                                  requiredBytes: 16,      beToggleable: false },
  { value: "mac",      label: "MAC",    title: "Interpret bytes as MAC/hardware address (6 bytes)",                                          requiredBytes: 6,       beToggleable: true  },
  { value: "port",     label: "Port",   title: "Interpret bytes as TCP/UDP port number (2 bytes)",                                           requiredBytes: 2,       beToggleable: true  },
  { value: "u32",      label: "U32",    title: "Interpret 4 bytes as unsigned 32-bit integer (LE by default; toggle BE for big-endian)",     requiredBytes: 4,       beToggleable: true  },
  { value: "u64",      label: "U64",    title: "Interpret 8 bytes as unsigned 64-bit integer (LE by default; toggle BE for big-endian)",     requiredBytes: 8,       beToggleable: true  },
  { value: "cgroupid", label: "Cgroup", title: "Interpret 8 or 12 bytes as cgroup storage key (inode ID + attach type)",                    requiredBytes: [8, 12], beToggleable: false },
  { value: "proto",    label: "Proto",  title: "Interpret 1 byte as IP protocol number (6=TCP, 17=UDP, 1=ICMP, …)",                         requiredBytes: 1,       beToggleable: false },
  { value: "ts",       label: "Timestamp", title: "Interpret 8 bytes as nanoseconds from bpf_ktime_get_ns() → elapsed time (e.g. 3d 14h 22m 5s)", requiredBytes: 8,       beToggleable: false },
];

/**
 * Return the subset of INTERPRET_OPTIONS compatible with a given byte length.
 * "raw" is always included. If byteLen is undefined/0, all options are returned.
 */
function compatibleOptions(byteLen: number | undefined) {
  if (!byteLen) return INTERPRET_OPTIONS;
  return INTERPRET_OPTIONS.filter(opt => {
    if (opt.requiredBytes === null) return true;
    if (Array.isArray(opt.requiredBytes)) return opt.requiredBytes.includes(byteLen);
    return opt.requiredBytes === byteLen;
  });
}

function InterpretToggle({
  label,
  value,
  bigEndian,
  onChangeBE,
  onChange,
  container,
  byteLen,
}: {
  label: string;
  value: InterpretMode;
  bigEndian: boolean;
  onChangeBE: (be: boolean) => void;
  onChange: (v: InterpretMode) => void;
  container?: HTMLElement | null;
  byteLen?: number;
}) {
  const options = compatibleOptions(byteLen);
  const selected = options.find(o => o.value === value) ?? options[0];
  // If the current value is no longer in the compatible set, reset to raw
  const effectiveValue = options.some(o => o.value === value) ? value : "raw";
  // Show BE toggle only when the selected mode supports byte-order flipping
  const showBeToggle = (options.find(o => o.value === effectiveValue)?.beToggleable) ?? false;
  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] text-white/30 uppercase tracking-wider font-medium whitespace-nowrap">{label}</span>
      <Select value={effectiveValue} onValueChange={(v) => onChange(v as InterpretMode)}>
        <SelectTrigger
          className="h-7 min-w-[100px] max-w-[130px] bg-black/30 border-white/10 text-xs font-mono text-white/70 hover:border-white/25 focus:ring-0 focus:ring-offset-0"
          title={selected?.title}
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent
          className="bg-[#0f1117] border-white/10 text-white z-[300]"
          container={container ?? undefined}
        >
          {options.map(opt => (
            <SelectItem
              key={opt.value}
              value={opt.value}
              className="text-xs font-mono text-white/70 hover:text-white focus:text-white focus:bg-white/10 cursor-pointer"
              title={opt.title}
            >
              {opt.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {showBeToggle && (
        <button
          onClick={() => onChangeBE(!bigEndian)}
          title={bigEndian ? "Big-endian (click to switch to little-endian)" : "Little-endian (click to switch to big-endian)"}
          className={`
            h-7 px-2 rounded-md text-[10px] font-mono font-semibold border transition-all
            ${bigEndian
              ? "bg-amber-500/20 border-amber-500/40 text-amber-300 hover:bg-amber-500/30"
              : "bg-black/30 border-white/10 text-white/30 hover:border-white/25 hover:text-white/50"
            }
          `}
        >
          BE
        </button>
      )}
    </div>
  );
}

// ─── Entry Row ────────────────────────────────────────────────────────────────

function EntryRow({
  entry,
  mode,
  keyInterpret,
  valInterpret,
  keyBE,
  valBE,
  index,
}: {
  entry: MapEntry;
  mode: DisplayMode;
  keyInterpret: InterpretMode;
  valInterpret: InterpretMode;
  keyBE: boolean;
  valBE: boolean;
  index: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const hasPerCpu = entry.perCpuValues && entry.perCpuValues.length > 0;

  const rawKeyText = displayKey(entry, mode);
  const rawValText = displayValue(entry, mode);

  // Apply interpretation only to hex-mode strings (not BTF/decimal)
  const keyText = (mode === "hex" || (!entry.keyBtf && mode !== "decimal"))
    ? interpretHex(rawKeyText, keyInterpret, keyBE)
    : rawKeyText;
  const valText = entry.valueError
    ? rawValText
    : (mode === "hex" || (!entry.valueBtf && mode !== "decimal"))
      ? interpretHex(rawValText, valInterpret, valBE)
      : rawValText;

  // Detect interpretation error markers for styling
  const keyIsError = keyText.startsWith("(need") || keyText.startsWith("(not");
  const valIsError = valText.startsWith("(need") || valText.startsWith("(not");

  return (
    <>
      <tr
        className={`
          border-b border-white/5 transition-colors
          ${hasPerCpu ? "cursor-pointer hover:bg-white/5" : "hover:bg-white/3"}
          ${index % 2 === 0 ? "bg-transparent" : "bg-white/[0.02]"}
        `}
        onClick={() => hasPerCpu && setExpanded(e => !e)}
      >
        {/* Index */}
        <td className="px-3 py-2 text-[11px] font-mono text-white/25 text-right w-12 select-none">
          {entry.index}
        </td>

        {/* Key */}
        <td className="px-3 py-2 max-w-0">
          <div className="flex items-center group">
            <span
              className={`
                text-xs font-mono truncate
                ${keyIsError ? "text-amber-400/60 italic" : entry.keyBtf ? "text-sky-300" : "text-white/70"}
              `}
              title={keyText}
            >
              {keyText}
            </span>
            <CopyButton text={keyText} />
          </div>
        </td>

        {/* Value */}
        <td className="px-3 py-2 max-w-0">
          <div className="flex items-center group">
            {entry.valueError ? (
              <span className="text-xs font-mono text-red-400 italic truncate" title={valText}>
                {valText}
              </span>
            ) : (
              <span
                className={`
                  text-xs font-mono truncate
                  ${valIsError ? "text-amber-400/60 italic" : entry.valueBtf ? "text-emerald-300" : "text-white/70"}
                `}
                title={valText}
              >
                {valText}
              </span>
            )}
            {!entry.valueError && <CopyButton text={valText} />}
            {hasPerCpu && (
              <span className="ml-auto flex-shrink-0 text-white/30">
                {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </span>
            )}
          </div>
        </td>
      </tr>

      {/* Per-CPU expansion */}
      {hasPerCpu && expanded && (
        <tr className="bg-black/20">
          <td />
          <td colSpan={2} className="px-3 py-2">
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-1.5">
              {entry.perCpuValues!.map(cv => {
                const rawPerCpu = mode === "decimal" && cv.decimal !== null ? cv.decimal : cv.hex;
                const interpretedPerCpu = mode === "hex"
                  ? interpretHex(cv.hex, valInterpret, valBE)
                  : rawPerCpu;
                return (
                  <div
                    key={cv.cpu}
                    className="bg-white/5 rounded-md p-1.5 border border-white/10"
                  >
                    <div className="text-[9px] text-white/30 mb-0.5">CPU {cv.cpu}</div>
                    <div className="text-[11px] font-mono text-white/70 truncate" title={interpretedPerCpu}>
                      {interpretedPerCpu}
                    </div>
                  </div>
                );
              })}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Main Modal ───────────────────────────────────────────────────────────────

export function MapEntriesModal({
  mapId,
  mapName,
  mapType,
  mapColor,
  keyBytes,
  valueBytes,
  onClose,
}: MapEntriesModalProps) {
  const [mode, setMode] = useState<DisplayMode>("hex");
  const [keyInterpret, setKeyInterpret] = useState<InterpretMode>(() => {
    const saved = loadInterpretPrefs(mapType);
    const preferred = saved ? saved.key : defaultKeyInterpret(mapType);
    // Fall back to raw if the saved/default preference is incompatible with actual key size
    const compat = compatibleOptions(keyBytes);
    return compat.some(o => o.value === preferred) ? preferred : "raw";
  });
  const [valInterpret, setValInterpret] = useState<InterpretMode>(() => {
    const saved = loadInterpretPrefs(mapType);
    const preferred = saved ? saved.val : "raw";
    // Fall back to raw if the saved preference is incompatible with actual value size
    const compat = compatibleOptions(valueBytes);
    return compat.some(o => o.value === preferred) ? preferred : "raw";
  });
  const [keyBE, setKeyBE] = useState(false);
  const [valBE, setValBE] = useState(false);
  const [page, setPage] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Persist interpretation preferences whenever they change
  const handleKeyInterpretChange = (v: InterpretMode) => {
    setKeyInterpret(v);
    saveInterpretPrefs(mapType, v, valInterpret);
  };
  const handleValInterpretChange = (v: InterpretMode) => {
    setValInterpret(v);
    saveInterpretPrefs(mapType, keyInterpret, v);
  };

  const { data, isLoading, isError, refetch, isFetching } =
    trpc.ebpf.mapDump.useQuery({ id: mapId }, { staleTime: 10_000 });

  // Auto-select BTF mode when BTF data is available
  const hasBtf = data?.btfDecoded ?? false;
  const effectiveMode: DisplayMode = mode === "btf" && !hasBtf ? "hex" : mode;

  // ── Search / filter ──────────────────────────────────────────────────────
  const handleSearchChange = useCallback((q: string) => {
    setSearchQuery(q);
    setPage(0); // always reset to first page when filter changes
  }, []);

  // Filtered entries: case-insensitive substring match on interpreted key + value text.
  // Recomputed whenever query, data, mode, or interpret settings change.
  const filteredEntries = useMemo((): MapEntry[] => {
    if (!data?.entries) return [];
    const q = searchQuery.trim().toLowerCase();
    if (!q) return data.entries;
    return data.entries.filter(entry => {
      const k = entryKeyText(entry, effectiveMode, keyInterpret, keyBE).toLowerCase();
      const v = entryValText(entry, effectiveMode, valInterpret, valBE).toLowerCase();
      return k.includes(q) || v.includes(q);
    });
  }, [data, searchQuery, effectiveMode, keyInterpret, valInterpret, keyBE, valBE]);

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil(filteredEntries.length / PAGE_SIZE)),
    [filteredEntries],
  );

  const pageEntries = useMemo((): MapEntry[] => {
    const start = page * PAGE_SIZE;
    return filteredEntries.slice(start, start + PAGE_SIZE);
  }, [filteredEntries, page]);

  // Escape key clears the search filter
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape" && searchQuery) {
        e.stopPropagation();
        handleSearchChange("");
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handler, true);
    return () => window.removeEventListener("keydown", handler, true);
  }, [searchQuery, handleSearchChange]);

  // Disable interpret toggles in BTF/decimal mode (bytes are already decoded)
  const interpretDisabled = effectiveMode !== "hex";

  // Ref for the modal container — passed to SelectContent portal so the dropdown
  // renders inside the modal's DOM node instead of document.body. This prevents
  // the preview iframe overlay from intercepting pointer events on the dropdown.
  const containerRef = useRef<HTMLDivElement>(null);

  return (
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      onMouseDown={e => {
        // Only close when clicking the backdrop itself, not Radix portal elements
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={containerRef}
        className="w-full max-w-4xl max-h-[90vh] flex flex-col bg-[#0d1117] border border-white/10 rounded-2xl shadow-2xl overflow-hidden"
        onMouseDown={e => e.stopPropagation()}
      >

        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/10 flex-shrink-0">
          <div className="flex items-center gap-3">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
              style={{ backgroundColor: `${mapColor}22`, border: `1px solid ${mapColor}55` }}
            >
              <Database className="w-4 h-4" style={{ color: mapColor }} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-semibold text-white">{mapName}</span>
                <Badge
                  variant="outline"
                  className="text-[10px] px-1.5 py-0 border-white/20 text-white/50"
                >
                  #{mapId}
                </Badge>
              </div>
              <div className="text-xs mt-0.5" style={{ color: mapColor }}>{mapType}</div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Refresh */}
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="p-1.5 rounded-lg hover:bg-white/10 text-white/40 hover:text-white transition-colors disabled:opacity-40"
              title="Refresh entries"
            >
              <RefreshCw className={`w-4 h-4 ${isFetching ? "animate-spin" : ""}`} />
            </button>
            {/* Close */}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-white/10 text-white/40 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* ── Toolbar ────────────────────────────────────────────────────── */}
        <div className="flex flex-col gap-2 px-5 py-2.5 border-b border-white/5 bg-white/[0.02] flex-shrink-0">
          {/* Row 1: display mode + stats */}
          <div className="flex items-center justify-between">
            {/* Display mode toggle */}
            <div className="flex items-center gap-1 bg-black/30 rounded-lg p-0.5 border border-white/10">
              {(["hex", "decimal", "btf"] as DisplayMode[]).map(m => (
                <button
                  key={m}
                  onClick={() => setMode(m)}
                  disabled={m === "btf" && !hasBtf}
                  className={`
                    px-3 py-1 rounded-md text-xs font-mono transition-all
                    ${effectiveMode === m
                      ? "bg-[var(--accent)]/20 text-[var(--accent)] border border-[var(--accent)]/40"
                      : "text-white/40 hover:text-white/70 disabled:opacity-30 disabled:cursor-not-allowed"
                    }
                  `}
                  title={m === "btf" && !hasBtf ? "BTF info not available for this map" : undefined}
                >
                  {m.toUpperCase()}
                </button>
              ))}
            </div>

            {/* Stats */}
            {data && !data.unsupported && !data.error && (
              <div className="flex items-center gap-3 text-xs text-white/40">
                {data.btfDecoded && (
                  <span className="px-1.5 py-0.5 rounded-full bg-purple-500/20 border border-purple-500/30 text-purple-400 text-[10px]">
                    BTF decoded
                  </span>
                )}
                {data.truncated && (
                  <span className="px-1.5 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/30 text-amber-400 text-[10px]">
                    truncated to {data.maxReturned}
                  </span>
                )}
                <span>{data.totalEntries} entr{data.totalEntries === 1 ? "y" : "ies"}</span>
              </div>
            )}
          </div>

          {/* Row 2: interpret toggles (only shown in hex mode) */}
          {!interpretDisabled && (
            <div className="flex items-center gap-6 flex-wrap">
              <InterpretToggle label="Key as" value={keyInterpret} bigEndian={keyBE} onChangeBE={setKeyBE} onChange={handleKeyInterpretChange} container={containerRef.current} byteLen={keyBytes} />
              <InterpretToggle label="Value as" value={valInterpret} bigEndian={valBE} onChangeBE={setValBE} onChange={handleValInterpretChange} container={containerRef.current} byteLen={valueBytes} />
            </div>
          )}

          {/* Row 3: search / filter bar (only shown when entries are loaded) */}
          {data && !data.unsupported && !data.error && data.entries.length > 0 && (
            <div className="relative flex items-center">
              <Search className="absolute left-2.5 w-3.5 h-3.5 text-white/25 pointer-events-none" />
              <input
                ref={searchInputRef}
                type="text"
                value={searchQuery}
                onChange={e => handleSearchChange(e.target.value)}
                placeholder="Search keys or values…"
                className="w-full pl-8 pr-8 py-1.5 bg-black/30 border border-white/10 rounded-lg text-xs font-mono text-white/70 placeholder-white/20 focus:outline-none focus:border-white/25 focus:bg-black/40 transition-colors"
                aria-label="Filter map entries"
              />
              {/* Match count badge */}
              {searchQuery.trim() && (
                <span className="absolute right-8 text-[10px] font-mono text-white/30 select-none">
                  {filteredEntries.length}/{data.entries.length}
                </span>
              )}
              {/* Clear button */}
              {searchQuery && (
                <button
                  onClick={() => { handleSearchChange(""); searchInputRef.current?.focus(); }}
                  className="absolute right-2 p-0.5 rounded text-white/25 hover:text-white/60 transition-colors"
                  title="Clear filter (Esc)"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          )}
        </div>

        {/* ── Body ───────────────────────────────────────────────────────── */}
        <div className="flex-1 overflow-hidden flex flex-col min-h-0">
          {isLoading ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/40">
              <Loader2 className="w-8 h-8 animate-spin" />
              <span className="text-sm">Dumping map entries…</span>
            </div>
          ) : isError ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-red-400">
              <AlertTriangle className="w-8 h-8" />
              <span className="text-sm">Failed to fetch map entries</span>
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Retry
              </Button>
            </div>
          ) : data?.unsupported ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/40 px-8 text-center">
              <AlertTriangle className="w-8 h-8 text-amber-400/60" />
              <div>
                <div className="text-sm text-white/60 mb-1">Map type not dumpable</div>
                <div className="text-xs text-white/30">{data.error}</div>
                <div className="text-xs text-white/20 mt-2">
                  Types like perf_event_array, ringbuf, and devmap are kernel-internal
                  and cannot be enumerated via bpftool.
                </div>
              </div>
            </div>
          ) : data?.error ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/40 px-8 text-center">
              <AlertTriangle className="w-8 h-8 text-red-400/60" />
              <div>
                <div className="text-sm text-white/60 mb-1">Error reading map</div>
                <div className="text-xs font-mono text-red-400/70">{data.error}</div>
              </div>
            </div>
          ) : data?.entries.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/30">
              <Database className="w-10 h-10 opacity-30" />
              <div className="text-sm">Map is empty</div>
              <div className="text-xs text-white/20">No entries found in this map</div>
            </div>
          ) : filteredEntries.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/30">
              <Search className="w-10 h-10 opacity-30" />
              <div className="text-sm">No matching entries</div>
              <div className="text-xs text-white/20">
                0 of {data?.entries.length ?? 0} entries match
                {" "}<span className="font-mono text-white/40">"{searchQuery}"</span>
              </div>
              <button
                onClick={() => handleSearchChange("")}
                className="mt-1 text-xs text-[var(--accent)] hover:underline"
              >
                Clear filter
              </button>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto">
              <table className="w-full border-collapse">
                <thead className="sticky top-0 z-10 bg-[#0d1117]">
                  <tr className="border-b border-white/10">
                    <th className="px-3 py-2 text-[10px] text-white/30 uppercase tracking-wider text-right w-12">#</th>
                    <th className="px-3 py-2 text-[10px] text-white/30 uppercase tracking-wider text-left w-1/2">
                      Key
                      {keyInterpret !== "raw" && (
                        <span className="ml-1.5 text-emerald-400/60 normal-case font-normal">
                          ({keyInterpret})
                        </span>
                      )}
                    </th>
                    <th className="px-3 py-2 text-[10px] text-white/30 uppercase tracking-wider text-left">
                      Value
                      {valInterpret !== "raw" && (
                        <span className="ml-1.5 text-emerald-400/60 normal-case font-normal">
                          ({valInterpret})
                        </span>
                      )}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {pageEntries.map((entry, i) => (
                    <EntryRow
                      key={entry.index}
                      entry={entry}
                      mode={effectiveMode}
                      keyInterpret={keyInterpret}
                      valInterpret={valInterpret}
                      keyBE={keyBE}
                      valBE={valBE}
                      index={page * PAGE_SIZE + i}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ── Pagination ────────────────────────────────────────────────────── */}
        {data && !data.unsupported && !data.error && filteredEntries.length > PAGE_SIZE && (
          <div className="flex items-center justify-between px-5 py-3 border-t border-white/10 bg-white/[0.02] flex-shrink-0">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs text-white/50 hover:text-white hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              Previous
            </button>
            <span className="text-xs text-white/40">
              Page {page + 1} of {totalPages}
              <span className="text-white/20 ml-2">
                (rows {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, filteredEntries.length)})
              </span>
            </span>
            <button
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs text-white/50 hover:text-white hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              Next
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

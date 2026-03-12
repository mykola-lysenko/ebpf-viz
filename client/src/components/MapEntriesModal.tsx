/**
 * MapEntriesModal
 * Full-screen modal that shows the entries of a BPF map by calling
 * trpc.ebpf.mapDump.  Supports:
 *  - Hex / Decimal / BTF display modes for keys and values
 *  - Raw / IPv4 / IPv6 / MAC / Port / Index / U32BE / U64LE / CgroupID / Protocol interpretation
 *  - Auto-detection of best default interpretation based on map type
 *  - Pagination (50 rows per page)
 *  - Copy-to-clipboard for individual cells
 *  - Per-CPU value expansion
 *  - Graceful unsupported / error states
 */

import { useState, useMemo } from "react";
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
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

// ─── Types ────────────────────────────────────────────────────────────────────

type DisplayMode = "hex" | "decimal" | "btf";
type InterpretMode =
  | "raw"
  | "ipv4" | "ipv6"
  | "mac"
  | "port"
  | "u32le"   // 4-byte little-endian unsigned (array index)
  | "u32be"   // 4-byte big-endian unsigned
  | "u64le"   // 8-byte little-endian unsigned (counters, cgroup inode IDs)
  | "cgroupid" // 8-byte cgroup inode + 4-byte attach type
  | "proto";  // 1-byte IP protocol number

interface MapEntriesModalProps {
  mapId: number;
  mapName: string;
  mapType: string;
  mapColor: string;
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
 * Apply an interpretation mode to a raw hex string.
 * Returns the interpreted string, or the original hex if interpretation is "raw"
 * or if the hex string is not a plain byte sequence (e.g. BTF-decoded JSON).
 */
function interpretHex(hex: string, mode: InterpretMode): string {
  if (mode === "raw" || !hex || hex === "—") return hex;
  // Don't try to interpret BTF-decoded JSON or decimal strings
  if (hex.startsWith("{") || hex.startsWith("[")) return hex;
  const bytes = parseHexBytes(hex);
  if (!bytes) return hex;
  if (mode === "ipv4") return bytesToIPv4(bytes);
  if (mode === "ipv6") return bytesToIPv6(bytes);
  if (mode === "mac") return bytesToMAC(bytes);
  if (mode === "port") return bytesToPort(bytes);
  if (mode === "u32le") return bytesToU32LE(bytes);
  if (mode === "u32be") return bytesToU32BE(bytes);
  if (mode === "u64le") return bytesToU64LE(bytes);
  if (mode === "cgroupid") return bytesToCgroupId(bytes);
  if (mode === "proto") return bytesToProtocol(bytes);
  return hex;
}

/**
 * Auto-detect the best default key interpretation based on map type.
 * Returns "raw" when no specific interpretation is warranted.
 */
function defaultKeyInterpret(mapType: string): InterpretMode {
  const t = mapType.toLowerCase();
  if (t === "array" || t === "percpu_array") return "u32le";
  if (t === "cgroup_storage" || t === "percpu_cgroup_storage" || t === "cgrp_storage") return "cgroupid";
  return "raw";
}

// ── localStorage persistence for per-map-type interpretation prefs ─────────────────────────────────

const VALID_MODES = new Set<string>([
  "raw", "ipv4", "ipv6", "mac", "port",
  "u32le", "u32be", "u64le", "cgroupid", "proto",
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

const INTERPRET_OPTIONS: { value: InterpretMode; label: string; title: string }[] = [
  { value: "raw",      label: "Raw",      title: "Show raw bytes as-is" },
  { value: "ipv4",     label: "IPv4",     title: "Interpret bytes as IPv4 address (4 bytes, network order)" },
  { value: "ipv6",     label: "IPv6",     title: "Interpret bytes as IPv6 address (16 bytes, network order)" },
  { value: "mac",      label: "MAC",      title: "Interpret bytes as MAC/hardware address (6 bytes, aa:bb:cc:dd:ee:ff)" },
  { value: "port",     label: "Port",     title: "Interpret bytes as TCP/UDP port number (2 bytes, big-endian)" },
  { value: "u32le",    label: "U32 LE",   title: "Interpret 4 bytes as unsigned 32-bit integer (little-endian) — array index, CPU ID" },
  { value: "u32be",    label: "U32 BE",   title: "Interpret 4 bytes as unsigned 32-bit integer (big-endian)" },
  { value: "u64le",    label: "U64 LE",   title: "Interpret 8 bytes as unsigned 64-bit integer (little-endian) — counters, timestamps, cgroup inode IDs" },
  { value: "cgroupid", label: "Cgroup",   title: "Interpret 8 or 12 bytes as cgroup storage key (inode ID + attach type)" },
  { value: "proto",    label: "Proto",    title: "Interpret 1 byte as IP protocol number (6=TCP, 17=UDP, 1=ICMP, …)" },
];

function InterpretToggle({
  label,
  value,
  onChange,
}: {
  label: string;
  value: InterpretMode;
  onChange: (v: InterpretMode) => void;
}) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[10px] text-white/30 uppercase tracking-wider font-medium">{label}</span>
      <div className="flex items-center gap-0.5 bg-black/30 rounded-md p-0.5 border border-white/10">
        {INTERPRET_OPTIONS.map(opt => (
          <button
            key={opt.value}
            onClick={() => onChange(opt.value)}
            title={opt.title}
            className={`
              px-2 py-0.5 rounded text-[11px] font-mono transition-all
              ${value === opt.value
                ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                : "text-white/35 hover:text-white/60"
              }
            `}
          >
            {opt.label}
          </button>
        ))}
      </div>
    </div>
  );
}

// ─── Entry Row ────────────────────────────────────────────────────────────────

function EntryRow({
  entry,
  mode,
  keyInterpret,
  valInterpret,
  index,
}: {
  entry: MapEntry;
  mode: DisplayMode;
  keyInterpret: InterpretMode;
  valInterpret: InterpretMode;
  index: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const hasPerCpu = entry.perCpuValues && entry.perCpuValues.length > 0;

  const rawKeyText = displayKey(entry, mode);
  const rawValText = displayValue(entry, mode);

  // Apply interpretation only to hex-mode strings (not BTF/decimal)
  const keyText = (mode === "hex" || (!entry.keyBtf && mode !== "decimal"))
    ? interpretHex(rawKeyText, keyInterpret)
    : rawKeyText;
  const valText = entry.valueError
    ? rawValText
    : (mode === "hex" || (!entry.valueBtf && mode !== "decimal"))
      ? interpretHex(rawValText, valInterpret)
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
                  ? interpretHex(cv.hex, valInterpret)
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
  onClose,
}: MapEntriesModalProps) {
  const [mode, setMode] = useState<DisplayMode>("hex");
  const [keyInterpret, setKeyInterpret] = useState<InterpretMode>(() => {
    const saved = loadInterpretPrefs(mapType);
    return saved ? saved.key : defaultKeyInterpret(mapType);
  });
  const [valInterpret, setValInterpret] = useState<InterpretMode>(() => {
    const saved = loadInterpretPrefs(mapType);
    return saved ? saved.val : "raw";
  });
  const [page, setPage] = useState(0);

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

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil((data?.entries.length ?? 0) / PAGE_SIZE)),
    [data],
  );

  const pageEntries = useMemo((): MapEntry[] => {
    if (!data?.entries) return [];
    const start = page * PAGE_SIZE;
    return data.entries.slice(start, start + PAGE_SIZE);
  }, [data, page]);

  // Auto-select BTF mode when BTF data is available
  const hasBtf = data?.btfDecoded ?? false;
  const effectiveMode: DisplayMode = mode === "btf" && !hasBtf ? "hex" : mode;

  // Disable interpret toggles in BTF/decimal mode (bytes are already decoded)
  const interpretDisabled = effectiveMode !== "hex";

  return (
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      onClick={e => e.target === e.currentTarget && onClose()}
    >
      <div className="w-full max-w-4xl max-h-[90vh] flex flex-col bg-[#0d1117] border border-white/10 rounded-2xl shadow-2xl overflow-hidden">

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
            <div className="flex items-center gap-4">
              <InterpretToggle label="Key as" value={keyInterpret} onChange={handleKeyInterpretChange} />
              <InterpretToggle label="Value as" value={valInterpret} onChange={handleValInterpretChange} />
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
                      index={page * PAGE_SIZE + i}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ── Pagination ─────────────────────────────────────────────────── */}
        {data && !data.unsupported && !data.error && data.entries.length > PAGE_SIZE && (
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
                (rows {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, data.entries.length)})
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

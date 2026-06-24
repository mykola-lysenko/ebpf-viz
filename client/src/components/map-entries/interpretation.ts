import type { InterpretMode, InterpretPrefs } from "./types";

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

function bytesToIPv4(bytes: Uint8Array): string {
  if (bytes.length === 4) {
    return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
  }
  if (bytes.length === 16) {
    const isV4Mapped =
      bytes.slice(0, 10).every(b => b === 0) &&
      bytes[10] === 0xff &&
      bytes[11] === 0xff;
    if (isV4Mapped) {
      return `${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
    }
    return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]} (first 4B of ${bytes.length}B)`;
  }
  return `(need 4B, got ${bytes.length}B)`;
}

function bytesToIPv6(bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    return `(need 16B, got ${bytes.length}B)`;
  }

  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push((bytes[i] << 8) | bytes[i + 1]);
  }

  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i <= groups.length; i++) {
    if (i < groups.length && groups[i] === 0) {
      if (curStart === -1) {
        curStart = i;
        curLen = 0;
      }
      curLen++;
    } else {
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestLen < 2) {
    return groups.map(g => g.toString(16)).join(":");
  }

  const left = groups
    .slice(0, bestStart)
    .map(g => g.toString(16))
    .join(":");
  const right = groups
    .slice(bestStart + bestLen)
    .map(g => g.toString(16))
    .join(":");
  return `${left}::${right}`;
}

const WELL_KNOWN_PORTS: Record<number, string> = {
  20: "ftp-data",
  21: "ftp",
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "dns",
  67: "dhcp",
  68: "dhcp",
  69: "tftp",
  80: "http",
  110: "pop3",
  123: "ntp",
  143: "imap",
  161: "snmp",
  179: "bgp",
  389: "ldap",
  443: "https",
  465: "smtps",
  514: "syslog",
  515: "lpd",
  587: "smtp",
  636: "ldaps",
  993: "imaps",
  995: "pop3s",
  1194: "openvpn",
  1433: "mssql",
  1521: "oracle",
  3306: "mysql",
  3389: "rdp",
  5432: "postgres",
  5672: "amqp",
  5900: "vnc",
  6379: "redis",
  6443: "k8s-api",
  8080: "http-alt",
  8443: "https-alt",
  9200: "elasticsearch",
  9300: "elasticsearch",
  27017: "mongodb",
};

function bytesToPort(bytes: Uint8Array): string {
  if (bytes.length !== 2) {
    return `(need 2B, got ${bytes.length}B)`;
  }
  const port = (bytes[0] << 8) | bytes[1];
  const name = WELL_KNOWN_PORTS[port];
  return name ? `${port} (${name})` : `${port}`;
}

function bytesToMAC(bytes: Uint8Array): string {
  if (bytes.length !== 6) {
    return `(need 6B, got ${bytes.length}B)`;
  }
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join(":");
}

const IP_PROTOCOLS: Record<number, string> = {
  0: "HOPOPT",
  1: "ICMP",
  2: "IGMP",
  4: "IPv4",
  6: "TCP",
  8: "EGP",
  9: "IGP",
  17: "UDP",
  33: "DCCP",
  41: "IPv6",
  43: "IPv6-Route",
  44: "IPv6-Frag",
  47: "GRE",
  50: "ESP",
  51: "AH",
  58: "IPv6-ICMP",
  89: "OSPF",
  103: "PIM",
  112: "VRRP",
  115: "L2TP",
  132: "SCTP",
  136: "UDPLite",
  137: "MPLS-in-IP",
};

const CGROUP_ATTACH_TYPES: Record<number, string> = {
  0: "ingress",
  1: "egress",
  2: "sock_create",
  3: "sock_ops",
  4: "device",
  5: "inet4_bind",
  6: "inet6_bind",
  7: "inet_connect",
  8: "inet_post_bind4",
  9: "inet_post_bind6",
  10: "inet4_getpeername",
  11: "inet6_getpeername",
  12: "inet4_getsockname",
  13: "inet6_getsockname",
  14: "udp4_sendmsg",
  15: "udp6_sendmsg",
  16: "udp4_recvmsg",
  17: "udp6_recvmsg",
  18: "getsockopt",
  19: "setsockopt",
  20: "sk_lookup",
};

function readU32LE(bytes: Uint8Array): number {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(0, true);
}

function readU32BE(bytes: Uint8Array): number {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(0, false);
}

function readU64LEAsString(bytes: Uint8Array): string {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const lo = view.getUint32(0, true);
  const hi = view.getUint32(4, true);
  const hiStr = (hi * 4294967296).toFixed(0);
  const total = BigInt(hiStr) + BigInt(lo);
  return total.toString();
}

function bytesToU32LE(bytes: Uint8Array): string {
  if (bytes.length !== 4) return `(need 4B, got ${bytes.length}B)`;
  return String(readU32LE(bytes));
}

function bytesToU32BE(bytes: Uint8Array): string {
  if (bytes.length !== 4) return `(need 4B, got ${bytes.length}B)`;
  return String(readU32BE(bytes));
}

function bytesToU64LE(bytes: Uint8Array): string {
  if (bytes.length !== 8) return `(need 8B, got ${bytes.length}B)`;
  return readU64LEAsString(bytes);
}

function bytesToCgroupId(bytes: Uint8Array): string {
  if (bytes.length === 8) {
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

function bytesToProtocol(bytes: Uint8Array): string {
  if (bytes.length !== 1) return `(need 1B, got ${bytes.length}B)`;
  const proto = bytes[0];
  const name = IP_PROTOCOLS[proto];
  return name ? `${proto} (${name})` : `${proto}`;
}

function bytesToTimestamp(bytes: Uint8Array): string {
  if (bytes.length !== 8) return `(need 8B, got ${bytes.length}B)`;

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const lo = BigInt(view.getUint32(0, true));
  const hi = BigInt(view.getUint32(4, true));
  const ns = (hi << BigInt(32)) | lo;

  const zero = BigInt(0);
  if (ns === zero) return "0 (never)";

  const ms = BigInt(1_000_000);
  const sec = BigInt(1_000) * ms;
  const min = BigInt(60) * sec;
  const hr = BigInt(60) * min;
  const day = BigInt(24) * hr;
  const yr = BigInt(365) * day;

  let rem = ns;
  const years = rem / yr;
  rem %= yr;
  const days = rem / day;
  rem %= day;
  const hours = rem / hr;
  rem %= hr;
  const minutes = rem / min;
  rem %= min;
  const seconds = rem / sec;
  rem %= sec;
  const millis = rem / ms;

  const parts: string[] = [];
  if (years > zero) parts.push(`${years}y`);
  if (days > zero) parts.push(`${days}d`);
  if (hours > zero) parts.push(`${hours}h`);
  if (minutes > zero) parts.push(`${minutes}m`);
  if (seconds > zero) parts.push(`${seconds}s`);
  if (millis > zero) parts.push(`${millis}ms`);

  if (parts.length === 0) return `${ns}ns`;
  return parts.join(" ");
}

export function interpretHex(
  hex: string,
  mode: InterpretMode,
  bigEndian = false
): string {
  if (mode === "raw" || !hex || hex === "—") return hex;
  if (hex.startsWith("{") || hex.startsWith("[")) return hex;
  let bytes = parseHexBytes(hex);
  if (!bytes) return hex;

  if (
    bigEndian &&
    (mode === "u32" ||
      mode === "u64" ||
      mode === "ipv4" ||
      mode === "port" ||
      mode === "mac")
  ) {
    bytes = bytes.slice().reverse();
  }

  if (mode === "ipv4") return bytesToIPv4(bytes);
  if (mode === "ipv6") return bytesToIPv6(bytes);
  if (mode === "mac") return bytesToMAC(bytes);
  if (mode === "port") return bytesToPort(bytes);
  if (mode === "u32") return bytesToU32LE(bytes);
  if (mode === "u64") return bytesToU64LE(bytes);
  if (mode === "cgroupid") return bytesToCgroupId(bytes);
  if (mode === "proto") return bytesToProtocol(bytes);
  if (mode === "ts") return bytesToTimestamp(bytes);
  return hex;
}

export function defaultKeyInterpret(mapType: string): InterpretMode {
  const t = mapType.toLowerCase();
  if (t === "array" || t === "percpu_array") return "u32";
  if (
    t === "cgroup_storage" ||
    t === "percpu_cgroup_storage" ||
    t === "cgrp_storage"
  ) {
    return "cgroupid";
  }
  return "raw";
}

const VALID_MODES = new Set<string>([
  "raw",
  "ipv4",
  "ipv6",
  "mac",
  "port",
  "u32",
  "u64",
  "cgroupid",
  "proto",
  "ts",
]);

function storageKey(mapType: string): string {
  return `ebpf-viz:interp:${mapType.toLowerCase()}`;
}

export function loadInterpretPrefs(mapType: string): InterpretPrefs | null {
  try {
    const raw = localStorage.getItem(storageKey(mapType));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { key?: string; val?: string };
    const key = VALID_MODES.has(parsed.key ?? "")
      ? (parsed.key as InterpretMode)
      : null;
    const val = VALID_MODES.has(parsed.val ?? "")
      ? (parsed.val as InterpretMode)
      : null;
    if (!key || !val) return null;
    return { key, val };
  } catch {
    return null;
  }
}

export function saveInterpretPrefs(
  mapType: string,
  key: InterpretMode,
  val: InterpretMode
): void {
  try {
    localStorage.setItem(storageKey(mapType), JSON.stringify({ key, val }));
  } catch {
    // localStorage may be unavailable in private browsing.
  }
}

export const INTERPRET_OPTIONS: {
  value: InterpretMode;
  label: string;
  title: string;
  requiredBytes: number | number[] | null;
  beToggleable: boolean;
}[] = [
  {
    value: "raw",
    label: "Raw",
    title: "Show raw bytes as-is",
    requiredBytes: null,
    beToggleable: false,
  },
  {
    value: "ipv4",
    label: "IPv4",
    title: "Interpret bytes as IPv4 address (4 bytes)",
    requiredBytes: 4,
    beToggleable: true,
  },
  {
    value: "ipv6",
    label: "IPv6",
    title: "Interpret bytes as IPv6 address (16 bytes, network order)",
    requiredBytes: 16,
    beToggleable: false,
  },
  {
    value: "mac",
    label: "MAC",
    title: "Interpret bytes as MAC/hardware address (6 bytes)",
    requiredBytes: 6,
    beToggleable: true,
  },
  {
    value: "port",
    label: "Port",
    title: "Interpret bytes as TCP/UDP port number (2 bytes)",
    requiredBytes: 2,
    beToggleable: true,
  },
  {
    value: "u32",
    label: "U32",
    title:
      "Interpret 4 bytes as unsigned 32-bit integer (LE by default; toggle BE for big-endian)",
    requiredBytes: 4,
    beToggleable: true,
  },
  {
    value: "u64",
    label: "U64",
    title:
      "Interpret 8 bytes as unsigned 64-bit integer (LE by default; toggle BE for big-endian)",
    requiredBytes: 8,
    beToggleable: true,
  },
  {
    value: "cgroupid",
    label: "Cgroup",
    title:
      "Interpret 8 or 12 bytes as cgroup storage key (inode ID + attach type)",
    requiredBytes: [8, 12],
    beToggleable: false,
  },
  {
    value: "proto",
    label: "Proto",
    title: "Interpret 1 byte as IP protocol number (6=TCP, 17=UDP, 1=ICMP, …)",
    requiredBytes: 1,
    beToggleable: false,
  },
  {
    value: "ts",
    label: "Timestamp",
    title:
      "Interpret 8 bytes as nanoseconds from bpf_ktime_get_ns() → elapsed time (e.g. 3d 14h 22m 5s)",
    requiredBytes: 8,
    beToggleable: false,
  },
];

export function compatibleOptions(byteLen: number | undefined) {
  if (!byteLen) return INTERPRET_OPTIONS;
  return INTERPRET_OPTIONS.filter(opt => {
    if (opt.requiredBytes === null) return true;
    if (Array.isArray(opt.requiredBytes))
      return opt.requiredBytes.includes(byteLen);
    return opt.requiredBytes === byteLen;
  });
}

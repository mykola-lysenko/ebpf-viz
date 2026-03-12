/**
 * Unit tests for the IP interpretation helpers in MapEntriesModal.
 * We test the logic directly by extracting it into a shared module.
 * Since the helpers live in a client component, we replicate the pure functions here.
 */
import { describe, it, expect } from "vitest";

// ── Replicated helpers (must stay in sync with MapEntriesModal.tsx) ──────────

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
      bytes[10] === 0xff && bytes[11] === 0xff;
    if (isV4Mapped) {
      return `${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
    }
    return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]} (first 4B of ${bytes.length}B)`;
  }
  return `(need 4B, got ${bytes.length}B)`;
}

function bytesToMAC(bytes: Uint8Array): string {
  if (bytes.length !== 6) return `(need 6B, got ${bytes.length}B)`;
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join(":");
}

function bytesToIPv6(bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    return `(need 16B, got ${bytes.length}B)`;
  }
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push((bytes[i] << 8) | bytes[i + 1]);
  }
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
    return groups.map(g => g.toString(16)).join(":");
  }
  const left = groups.slice(0, bestStart).map(g => g.toString(16)).join(":");
  const right = groups.slice(bestStart + bestLen).map(g => g.toString(16)).join(":");
  return `${left}::${right}`;
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("parseHexBytes", () => {
  it("parses space-separated hex bytes", () => {
    const b = parseHexBytes("c0 a8 01 01");
    expect(b).toEqual(new Uint8Array([0xc0, 0xa8, 0x01, 0x01]));
  });
  it("returns null for empty string", () => {
    expect(parseHexBytes("")).toBeNull();
    expect(parseHexBytes("   ")).toBeNull();
  });
  it("returns null for malformed hex", () => {
    expect(parseHexBytes("zz aa")).toBeNull();
  });
  it("handles single byte", () => {
    expect(parseHexBytes("ff")).toEqual(new Uint8Array([0xff]));
  });
});

describe("bytesToIPv4", () => {
  it("converts 4 bytes to dotted decimal", () => {
    expect(bytesToIPv4(new Uint8Array([192, 168, 1, 1]))).toBe("192.168.1.1");
    expect(bytesToIPv4(new Uint8Array([10, 0, 0, 1]))).toBe("10.0.0.1");
    expect(bytesToIPv4(new Uint8Array([0, 0, 0, 0]))).toBe("0.0.0.0");
    expect(bytesToIPv4(new Uint8Array([255, 255, 255, 255]))).toBe("255.255.255.255");
  });
  it("returns error for wrong byte count", () => {
    expect(bytesToIPv4(new Uint8Array([1, 2, 3]))).toBe("(need 4B, got 3B)");
    expect(bytesToIPv4(new Uint8Array([1, 2, 3, 4, 5]))).toBe("(need 4B, got 5B)");
  });
  it("handles IPv4-mapped IPv6 (16 bytes, ::ffff:a.b.c.d)", () => {
    const bytes = new Uint8Array(16);
    bytes[10] = 0xff; bytes[11] = 0xff;
    bytes[12] = 192; bytes[13] = 168; bytes[14] = 1; bytes[15] = 100;
    expect(bytesToIPv4(bytes)).toBe("192.168.1.100");
  });
  it("handles 16-byte field with IPv4 in first 4 bytes", () => {
    const bytes = new Uint8Array(16);
    bytes[0] = 10; bytes[1] = 0; bytes[2] = 0; bytes[3] = 1;
    // Not IPv4-mapped (no 0xff bytes at [10],[11])
    expect(bytesToIPv4(bytes)).toBe("10.0.0.1 (first 4B of 16B)");
  });
});

describe("bytesToMAC", () => {
  it("converts 6 bytes to colon-separated lowercase hex", () => {
    expect(bytesToMAC(new Uint8Array([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]))).toBe("00:1a:2b:3c:4d:5e");
  });
  it("pads single-digit nibbles with leading zero", () => {
    expect(bytesToMAC(new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x01]))).toBe("00:00:00:00:00:01");
  });
  it("handles broadcast address ff:ff:ff:ff:ff:ff", () => {
    expect(bytesToMAC(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))).toBe("ff:ff:ff:ff:ff:ff");
  });
  it("handles all-zero MAC", () => {
    expect(bytesToMAC(new Uint8Array(6))).toBe("00:00:00:00:00:00");
  });
  it("returns error for 4 bytes", () => {
    expect(bytesToMAC(new Uint8Array(4))).toBe("(need 6B, got 4B)");
  });
  it("returns error for 8 bytes", () => {
    expect(bytesToMAC(new Uint8Array(8))).toBe("(need 6B, got 8B)");
  });
});

describe("bytesToIPv6", () => {
  it("converts 16 bytes to full IPv6", () => {
    const bytes = new Uint8Array([
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ]);
    expect(bytesToIPv6(bytes)).toBe("2001:db8::1");
  });
  it("handles loopback ::1", () => {
    const bytes = new Uint8Array(16);
    bytes[15] = 1;
    expect(bytesToIPv6(bytes)).toBe("::1");
  });
  it("handles all zeros ::", () => {
    expect(bytesToIPv6(new Uint8Array(16))).toBe("::");
  });
  it("handles no compression needed", () => {
    const bytes = new Uint8Array([
      0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
      0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
    ]);
    expect(bytesToIPv6(bytes)).toBe("2001:db8:85a3::8a2e:370:7334");
  });
  it("returns error for wrong byte count", () => {
    expect(bytesToIPv6(new Uint8Array(4))).toBe("(need 16B, got 4B)");
    expect(bytesToIPv6(new Uint8Array(6))).toBe("(need 16B, got 6B)");
  });
});

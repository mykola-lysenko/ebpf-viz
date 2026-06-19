/**
 * ebpf-map-dump.ts
 * Calls `bpftool -jp map dump id N` and parses the output into MapDumpResult.
 *
 * bpftool map dump returns a JSON array of entries:
 *   [{ "key": ["0x00","0x01",...], "value": ["0x00",...] }, ...]
 *
 * For BTF-annotated maps the key/value may be decoded objects instead of byte arrays.
 * For per-cpu maps the entry has a "values" array: [{ "cpu": 0, "value": [...] }, ...]
 * For perf_event_array / ringbuf the value is { "error": "..." }.
 */

import { execFile } from "child_process";
import { promisify } from "util";
import type { MapDumpResult, MapEntry, RawMapEntry } from "../shared/ebpf-types";

const execFileAsync = promisify(execFile);

// Map types that bpftool cannot dump (kernel-internal or write-only)
const UNSUPPORTED_TYPES = new Set([
  "perf_event_array",
  "ringbuf",
  "user_ringbuf",
  "cgroup_array",
  "prog_array",
  "devmap",
  "devmap_hash",
  "cpumap",
  "xskmap",
  "sockmap",
  "sockhash",
  "reuseport_sockarray",
]);

// Maximum entries to return per dump (avoids huge payloads for large maps)
export const MAX_DUMP_ENTRIES = 1000;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Convert a hex byte array like ["0x00","0x01","0x02","0x03"] to "00 01 02 03" */
export function hexBytesToString(bytes: string[]): string {
  return bytes.map(b => b.replace(/^0x/, "").padStart(2, "0")).join(" ");
}

/** Interpret a little-endian hex byte array as an unsigned integer (≤ 8 bytes) */
export function hexBytesToDecimal(bytes: string[]): string | null {
  if (bytes.length === 0 || bytes.length > 8) return null;
  let val = BigInt(0);
  for (let i = bytes.length - 1; i >= 0; i--) {
    val = (val << BigInt(8)) | BigInt(parseInt(bytes[i], 16));
  }
  return val.toString();
}

/** Stringify a BTF-decoded object compactly */
export function btfToString(v: unknown): string {
  if (typeof v === "string") return v;
  if (typeof v === "number") return String(v);
  return JSON.stringify(v);
}

/** Parse a single raw entry into a normalized MapEntry */
export function parseEntry(raw: RawMapEntry, index: number): MapEntry {
  // ── Key ──────────────────────────────────────────────────────────────────
  let keyHex = "";
  let keyDecimal: string | null = null;
  let keyBtf: string | null = null;

  if (Array.isArray(raw.key)) {
    keyHex = hexBytesToString(raw.key as string[]);
    keyDecimal = hexBytesToDecimal(raw.key as string[]);
  } else if (raw.key && typeof raw.key === "object") {
    keyBtf = btfToString(raw.key);
    keyHex = "";
  } else if (raw.key !== undefined) {
    keyBtf = btfToString(raw.key);
    keyHex = "";
  }

  // ── Value ─────────────────────────────────────────────────────────────────
  let valueHex = "";
  let valueDecimal: string | null = null;
  let valueBtf: string | null = null;
  let valueError: string | null = null;
  let perCpuValues: MapEntry["perCpuValues"];

  // Per-CPU map: has "values" array
  if (raw.values && Array.isArray(raw.values)) {
    perCpuValues = raw.values.map(cv => {
      const hex = Array.isArray(cv.value)
        ? hexBytesToString(cv.value as string[])
        : btfToString(cv.value);
      const decimal = Array.isArray(cv.value)
        ? hexBytesToDecimal(cv.value as string[])
        : null;
      return { cpu: cv.cpu, hex, decimal };
    });
    // Use CPU 0 as the primary display value
    if (perCpuValues.length > 0) {
      valueHex = perCpuValues[0].hex;
      valueDecimal = perCpuValues[0].decimal ?? null;
    }
  } else if (raw.value && typeof raw.value === "object" && "error" in raw.value) {
    valueError = (raw.value as { error: string }).error;
  } else if (Array.isArray(raw.value)) {
    valueHex = hexBytesToString(raw.value as string[]);
    valueDecimal = hexBytesToDecimal(raw.value as string[]);
  } else if (raw.value && typeof raw.value === "object") {
    valueBtf = btfToString(raw.value);
    valueHex = "";
  } else if (raw.value !== undefined) {
    valueBtf = btfToString(raw.value);
    valueHex = "";
  }

  return {
    index,
    keyHex,
    keyDecimal,
    keyBtf,
    valueHex,
    valueDecimal,
    valueBtf,
    valueError,
    perCpuValues,
  };
}

/** Parse raw bpftool JSON output into normalized entries */
export function parseMapDumpOutput(
  stdout: string,
  stderr: string,
  mapId: number,
  mapType: string,
  mapName: string,
): MapDumpResult {
  const base: Omit<MapDumpResult, "entries"> = {
    mapId,
    mapType,
    mapName,
    totalEntries: 0,
    truncated: false,
    maxReturned: MAX_DUMP_ENTRIES,
    btfDecoded: false,
    error: null,
    unsupported: false,
  };

  const raw = stdout.trim();
  if (!raw || raw === "null") {
    return { ...base, entries: [] };
  }

  let parsed: RawMapEntry[];
  try {
    parsed = JSON.parse(raw);
  } catch {
    return {
      ...base,
      entries: [],
      error: `Failed to parse bpftool output: ${stderr || "invalid JSON"}`,
    };
  }

  if (!Array.isArray(parsed)) {
    return { ...base, entries: [] };
  }

  // Detect BTF decoding: if the first entry's key is an object (not array), BTF was used
  const btfDecoded =
    parsed.length > 0 &&
    !Array.isArray(parsed[0].key) &&
    typeof parsed[0].key === "object";

  const truncated = parsed.length > MAX_DUMP_ENTRIES;
  const slice = truncated ? parsed.slice(0, MAX_DUMP_ENTRIES) : parsed;
  const entries = slice.map((r, i) => parseEntry(r, i));

  return {
    ...base,
    totalEntries: parsed.length,
    truncated,
    btfDecoded,
    entries,
  };
}

// ─── Main export ──────────────────────────────────────────────────────────────

export async function dumpMapEntries(
  mapId: number,
  mapType: string,
  mapName: string,
  bpftoolPath: string,
  sudo: boolean = true,
): Promise<MapDumpResult> {
  const base: Omit<MapDumpResult, "entries"> = {
    mapId,
    mapType,
    mapName,
    totalEntries: 0,
    truncated: false,
    maxReturned: MAX_DUMP_ENTRIES,
    btfDecoded: false,
    error: null,
    unsupported: false,
  };

  // Check if this map type supports dump
  if (UNSUPPORTED_TYPES.has(mapType)) {
    return {
      ...base,
      entries: [],
      unsupported: true,
      error: `Map type '${mapType}' does not support entry enumeration`,
    };
  }

  try {
    const cmd = sudo ? "sudo" : bpftoolPath;
    const argv = sudo
      ? [bpftoolPath, "-jp", "map", "dump", "id", String(mapId)]
      : ["-jp", "map", "dump", "id", String(mapId)];
    const { stdout, stderr } = await execFileAsync(cmd, argv, {
      timeout: 10_000,
      maxBuffer: 20 * 1024 * 1024,
    });

    return parseMapDumpOutput(stdout, stderr, mapId, mapType, mapName);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    const errCode = (err as NodeJS.ErrnoException)?.code;

    // Binary not found — ENOENT or shell "command not found"
    if (errCode === "ENOENT" || msg.includes("command not found")) {
      return {
        ...base,
        entries: [],
        error: `bpftool not found at ${bpftoolPath}. Install bpftool or set the BPFTOOL_PATH environment variable to its location (e.g. BPFTOOL_PATH=/usr/sbin/bpftool).`,
      };
    }

    // bpftool exits with non-zero for empty hash maps on some kernel versions.
    // When it does, err.stdout may still contain valid JSON (e.g. "[]").
    const stdout = (err as any)?.stdout ?? "";
    if (stdout.trim()) {
      return parseMapDumpOutput(stdout, (err as any)?.stderr ?? "", mapId, mapType, mapName);
    }

    // All other errors — surface them to the user instead of silently swallowing
    return { ...base, entries: [], error: msg };
  }
}

import type { MapEntry } from "../../../../shared/ebpf-types";
import { interpretHex } from "./interpretation";
import type { DisplayMode, InterpretMode } from "./types";

export function displayKey(entry: MapEntry, mode: DisplayMode): string {
  if (mode === "btf" && entry.keyBtf) return entry.keyBtf;
  if (mode === "decimal" && entry.keyDecimal !== null) return entry.keyDecimal;
  return entry.keyHex || entry.keyBtf || "—";
}

export function displayValue(entry: MapEntry, mode: DisplayMode): string {
  if (entry.valueError) return `error: ${entry.valueError}`;
  if (mode === "btf" && entry.valueBtf) return entry.valueBtf;
  if (mode === "decimal" && entry.valueDecimal !== null) {
    return entry.valueDecimal;
  }
  return entry.valueHex || entry.valueBtf || "—";
}

export function entryKeyText(
  entry: MapEntry,
  mode: DisplayMode,
  interpret: InterpretMode,
  bigEndian: boolean
): string {
  const raw = displayKey(entry, mode);
  return mode === "hex" || (!entry.keyBtf && mode !== "decimal")
    ? interpretHex(raw, interpret, bigEndian)
    : raw;
}

export function entryValText(
  entry: MapEntry,
  mode: DisplayMode,
  interpret: InterpretMode,
  bigEndian: boolean
): string {
  if (entry.valueError) return `error: ${entry.valueError}`;
  const raw = displayValue(entry, mode);
  return mode === "hex" || (!entry.valueBtf && mode !== "decimal")
    ? interpretHex(raw, interpret, bigEndian)
    : raw;
}

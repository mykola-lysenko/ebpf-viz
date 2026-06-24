import { toast } from "sonner";
import type { MapEntry } from "../../../../shared/ebpf-types";
import { entryKeyText, entryValText } from "./entryText";
import type { DisplayMode, InterpretMode } from "./types";

function csvEscape(s: string): string {
  if (s.includes(",") || s.includes('"') || s.includes("\n")) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function triggerDownload(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function exportAsJSON(
  entries: MapEntry[],
  mapName: string,
  effectiveMode: DisplayMode,
  keyInterpret: InterpretMode,
  valInterpret: InterpretMode,
  keyBE: boolean,
  valBE: boolean
) {
  const rows = entries.map(e => ({
    index: e.index,
    keyHex: e.keyHex ?? null,
    key: entryKeyText(e, effectiveMode, keyInterpret, keyBE),
    valueHex: e.valueHex ?? null,
    value: entryValText(e, effectiveMode, valInterpret, valBE),
  }));
  const json = JSON.stringify(rows, null, 2);
  triggerDownload(json, `${mapName}-entries.json`, "application/json");
  toast.success(
    `Exported ${entries.length} entr${entries.length === 1 ? "y" : "ies"} as JSON`
  );
}

export function exportAsCSV(
  entries: MapEntry[],
  mapName: string,
  effectiveMode: DisplayMode,
  keyInterpret: InterpretMode,
  valInterpret: InterpretMode,
  keyBE: boolean,
  valBE: boolean
) {
  const lines = ["Index,Key,Value"];
  for (const e of entries) {
    const k = csvEscape(entryKeyText(e, effectiveMode, keyInterpret, keyBE));
    const v = csvEscape(entryValText(e, effectiveMode, valInterpret, valBE));
    lines.push(`${e.index},${k},${v}`);
  }
  triggerDownload(lines.join("\n"), `${mapName}-entries.csv`, "text/csv");
  toast.success(
    `Exported ${entries.length} entr${entries.length === 1 ? "y" : "ies"} as CSV`
  );
}

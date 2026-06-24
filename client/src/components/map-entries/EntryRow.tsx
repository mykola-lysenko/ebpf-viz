import { useState } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";
import type { MapEntry } from "../../../../shared/ebpf-types";
import { interpretHex } from "./interpretation";
import { CopyButton } from "./CopyButton";
import { displayKey, displayValue } from "./entryText";
import type { DisplayMode, InterpretMode } from "./types";

export function EntryRow({
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

  const keyText =
    mode === "hex" || (!entry.keyBtf && mode !== "decimal")
      ? interpretHex(rawKeyText, keyInterpret, keyBE)
      : rawKeyText;
  const valText = entry.valueError
    ? rawValText
    : mode === "hex" || (!entry.valueBtf && mode !== "decimal")
      ? interpretHex(rawValText, valInterpret, valBE)
      : rawValText;

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
        <td className="px-3 py-2 text-[11px] font-mono text-white/25 text-right w-12 select-none">
          {entry.index}
        </td>

        <td className="px-3 py-2 max-w-0">
          <div className="flex items-center group">
            <span
              className={`
                text-xs font-mono truncate
                ${
                  keyIsError
                    ? "text-amber-400/60 italic"
                    : entry.keyBtf
                      ? "text-sky-300"
                      : "text-white/70"
                }
              `}
              title={keyText}
            >
              {keyText}
            </span>
            <CopyButton text={keyText} />
          </div>
        </td>

        <td className="px-3 py-2 max-w-0">
          <div className="flex items-center group">
            {entry.valueError ? (
              <span
                className="text-xs font-mono text-red-400 italic truncate"
                title={valText}
              >
                {valText}
              </span>
            ) : (
              <span
                className={`
                  text-xs font-mono truncate
                  ${
                    valIsError
                      ? "text-amber-400/60 italic"
                      : entry.valueBtf
                        ? "text-emerald-300"
                        : "text-white/70"
                  }
                `}
                title={valText}
              >
                {valText}
              </span>
            )}
            {!entry.valueError && <CopyButton text={valText} />}
            {hasPerCpu && (
              <span className="ml-auto flex-shrink-0 text-white/30">
                {expanded ? (
                  <ChevronUp className="w-3 h-3" />
                ) : (
                  <ChevronDown className="w-3 h-3" />
                )}
              </span>
            )}
          </div>
        </td>
      </tr>

      {hasPerCpu && expanded && (
        <tr className="bg-black/20">
          <td />
          <td colSpan={2} className="px-3 py-2">
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-1.5">
              {entry.perCpuValues!.map(cv => {
                const rawPerCpu =
                  mode === "decimal" && cv.decimal !== null
                    ? cv.decimal
                    : cv.hex;
                const interpretedPerCpu =
                  mode === "hex"
                    ? interpretHex(cv.hex, valInterpret, valBE)
                    : rawPerCpu;
                return (
                  <div
                    key={cv.cpu}
                    className="bg-white/5 rounded-md p-1.5 border border-white/10"
                  >
                    <div className="text-[9px] text-white/30 mb-0.5">
                      CPU {cv.cpu}
                    </div>
                    <div
                      className="text-[11px] font-mono text-white/70 truncate"
                      title={interpretedPerCpu}
                    >
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

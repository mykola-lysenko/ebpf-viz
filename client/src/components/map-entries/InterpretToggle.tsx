import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { compatibleOptions } from "./interpretation";
import type { InterpretMode } from "./types";

export function InterpretToggle({
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
  const effectiveValue = options.some(o => o.value === value) ? value : "raw";
  const showBeToggle =
    options.find(o => o.value === effectiveValue)?.beToggleable ?? false;

  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] text-white/30 uppercase tracking-wider font-medium whitespace-nowrap">
        {label}
      </span>
      <Select
        value={effectiveValue}
        onValueChange={v => onChange(v as InterpretMode)}
      >
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
          title={
            bigEndian
              ? "Big-endian (click to switch to little-endian)"
              : "Little-endian (click to switch to big-endian)"
          }
          className={`
            h-7 px-2 rounded-md text-[10px] font-mono font-semibold border transition-all
            ${
              bigEndian
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

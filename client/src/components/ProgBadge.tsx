import React from "react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { BpfProgram } from "../../../shared/ebpf-types";
import { useEbpf } from "@/contexts/EbpfContext";
import { cn } from "@/lib/utils";

interface ProgBadgeProps {
  program: BpfProgram;
  showType?: boolean;
  compact?: boolean;
  className?: string;
}

export function ProgBadge({ program, showType = false, compact = false, className }: ProgBadgeProps) {
  const { setSelectedProgram } = useEbpf();

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          onClick={() => setSelectedProgram(program)}
          className={cn(
            "prog-badge transition-all hover:opacity-100 hover:scale-105 cursor-pointer",
            program.orphaned && "opacity-40 line-through",
            className
          )}
          style={{ color: program.color, borderColor: `${program.color}60` }}
        >
          {!compact && (
            <span
              className="inline-block w-1.5 h-1.5 rounded-full shrink-0"
              style={{ background: program.color }}
            />
          )}
          <span className="truncate max-w-[120px]">
            {compact ? `#${program.id}` : (program.name || `prog_${program.id}`)}
          </span>
          {showType && (
            <span className="opacity-60 text-[10px]">{program.rawType}</span>
          )}
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        <div className="space-y-1 text-xs">
          <div className="font-semibold font-mono">{program.name || `prog_${program.id}`}</div>
          <div className="text-muted-foreground">ID: {program.id} · Type: {program.rawType}</div>
          <div className="text-muted-foreground font-mono text-[10px]">tag: {program.tag}</div>
          {program.attachments.length > 0 && (
            <div className="text-muted-foreground">
              {program.attachments.map((a, i) => (
                <div key={i}>{a.detail}</div>
              ))}
            </div>
          )}
        </div>
      </TooltipContent>
    </Tooltip>
  );
}

interface ProgListProps {
  programs: BpfProgram[];
  maxVisible?: number;
  compact?: boolean;
}

export function ProgList({ programs, maxVisible = 5, compact = false }: ProgListProps) {
  const visible = programs.slice(0, maxVisible);
  const hidden = programs.length - maxVisible;

  return (
    <div className="flex flex-wrap gap-1.5">
      {visible.map(p => (
        <ProgBadge key={p.id} program={p} compact={compact} />
      ))}
      {hidden > 0 && (
        <span className="prog-badge text-muted-foreground border-muted-foreground/30">
          +{hidden} more
        </span>
      )}
    </div>
  );
}

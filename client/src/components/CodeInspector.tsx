/**
 * CodeInspector.tsx
 *
 * Full-screen modal that shows three code views for a BPF program:
 *   Tab 1 — BPF Bytecode (xlated) with syntax highlighting
 *   Tab 2 — CFG (control-flow graph) rendered via @viz-js/viz
 *   Tab 3 — JIT Assembly (jited) with register coloring
 *   Tab 4 — C Source (BTF linum interleaved) — shown only when available
 */

import React, {
  useEffect,
  useRef,
  useState,
  useCallback,
  useMemo,
} from "react";
import {
  X,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Loader2,
  AlertTriangle,
  Code2,
  GitBranch,
  Cpu,
  FileCode,
  Download,
  Search,
} from "lucide-react";
import { trpc } from "@/lib/trpc";
import {
  analyzeCfgRender,
  buildCfgBasicBlocks,
  searchCfgBlocks,
  type CfgBasicBlockSummary,
  type CfgBlockSearchResult,
} from "@/lib/cfg-summary";
import type { Viz } from "@viz-js/viz";
import type {
  BpfProgram,
  XlatedInsn,
  JitedInsn,
} from "../../../shared/ebpf-types";

// ─── Viz.js lazy loader ───────────────────────────────────────────────────────

let vizInstance: Viz | null = null;
async function getViz(): Promise<Viz> {
  if (vizInstance) return vizInstance;
  const { instance } = await import("@viz-js/viz");
  vizInstance = await instance();
  return vizInstance;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

// ─── BPF ISA syntax highlighter ───────────────────────────────────────────────

function highlightXlated(disasm: string): React.ReactNode {
  // Pattern: "(XX) rest of instruction"
  const opcodeMatch = disasm.match(/^(\(\w+\))\s+(.*)$/);
  if (!opcodeMatch) return <span className="text-slate-300">{disasm}</span>;

  const [, opcode, rest] = opcodeMatch;

  // Tokenize the rest
  const tokens: React.ReactNode[] = [];
  let remaining = rest;
  let key = 0;

  // Registers: r0-r10, w0-w10
  // Immediates: 0x... or decimal numbers
  // Jump targets: goto pc+N / goto pc-N
  // Memory: *(u32 *)(r1 +0)
  // Keywords: if, goto, call, exit, return

  const patterns: Array<[RegExp, string]> = [
    [/^(goto pc[+-]\d+)/, "text-yellow-300 font-semibold"],
    [/^(if\b)/, "text-purple-400"],
    [/^(call\b|exit\b|return\b)/, "text-red-400 font-semibold"],
    [/^([rw]\d{1,2})/, "text-cyan-400"],
    [/^(0x[0-9a-fA-F]+)/, "text-green-400"],
    [/^(-?\d+)/, "text-green-300"],
    [/^(\*\(u\d+\s*\*\))/, "text-orange-400"],
    [/^([!=<>]+)/, "text-purple-300"],
    [/^([(),+\-*&|^~])/, "text-slate-400"],
    [/^(\s+)/, ""],
    [/^([^\s()\[\],+\-*&|^~!=<>]+)/, "text-slate-200"],
  ];

  while (remaining.length > 0) {
    let matched = false;
    for (const [re, cls] of patterns) {
      const m = remaining.match(re);
      if (m) {
        const text = m[1];
        tokens.push(
          cls ? (
            <span key={key++} className={cls}>
              {text}
            </span>
          ) : (
            <span key={key++}>{text}</span>
          )
        );
        remaining = remaining.slice(text.length);
        matched = true;
        break;
      }
    }
    if (!matched) {
      tokens.push(
        <span key={key++} className="text-slate-300">
          {remaining[0]}
        </span>
      );
      remaining = remaining.slice(1);
    }
  }

  return (
    <>
      <span className="text-amber-400 mr-2">{opcode}</span>
      {tokens}
    </>
  );
}

// ─── JIT assembly highlighter ─────────────────────────────────────────────────

function highlightJited(disasm: string): React.ReactNode {
  // x86-64 / arm64 register coloring
  const x86Regs =
    /\b(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15|eax|ebx|ecx|edx|esi|edi|esp|ebp|al|bl|cl|dl)\b/g;
  const arm64Regs =
    /\b(x[0-9]|x1[0-9]|x2[0-9]|x30|sp|lr|fp|w[0-9]|w1[0-9]|w2[0-9])\b/g;
  const immediates = /\b(0x[0-9a-fA-F]+|-?\d+)\b/g;
  const mnemonics = /^(\s*)(\w+)/;

  const parts: React.ReactNode[] = [];
  let text = disasm;
  let key = 0;

  // Mnemonic first
  const mnemonicMatch = text.match(mnemonics);
  if (mnemonicMatch) {
    const indent = mnemonicMatch[1];
    const mnemonic = mnemonicMatch[2];
    const rest = text.slice(indent.length + mnemonic.length);
    parts.push(<span key={key++}>{indent}</span>);
    parts.push(
      <span key={key++} className="text-sky-400 font-medium">
        {mnemonic}
      </span>
    );

    // Highlight rest
    let remaining = rest;
    let lastIndex = 0;
    const combined = new RegExp(
      `(${x86Regs.source}|${arm64Regs.source}|${immediates.source})`,
      "g"
    );
    const matches = Array.from(remaining.matchAll(combined));

    for (const match of matches) {
      if (match.index! > lastIndex) {
        parts.push(
          <span key={key++} className="text-slate-300">
            {remaining.slice(lastIndex, match.index)}
          </span>
        );
      }
      const val = match[0];
      if (/^0x|^-?\d/.test(val)) {
        parts.push(
          <span key={key++} className="text-green-400">
            {val}
          </span>
        );
      } else {
        parts.push(
          <span key={key++} className="text-cyan-400">
            {val}
          </span>
        );
      }
      lastIndex = match.index! + val.length;
    }
    if (lastIndex < remaining.length) {
      parts.push(
        <span key={key++} className="text-slate-300">
          {remaining.slice(lastIndex)}
        </span>
      );
    }
  } else {
    parts.push(
      <span key={key++} className="text-slate-300">
        {text}
      </span>
    );
  }

  return <>{parts}</>;
}

// ─── Jump target map ──────────────────────────────────────────────────────────

function buildJumpMap(insns: XlatedInsn[]): Map<number, number[]> {
  const map = new Map<number, number[]>(); // target index → [source indices]
  for (const insn of insns) {
    const m = insn.disasm.match(/goto pc([+-]\d+)/);
    if (m) {
      const target = insn.index + 1 + parseInt(m[1]);
      const sources = map.get(target) ?? [];
      sources.push(insn.index);
      map.set(target, sources);
    }
  }
  return map;
}

// ─── Bytecode tab ─────────────────────────────────────────────────────────────

function BytecodeTab({
  insns,
  focusInstruction,
}: {
  insns: XlatedInsn[];
  focusInstruction?: number | null;
}) {
  const [highlightedLine, setHighlightedLine] = useState<number | null>(null);
  const lineRefs = useRef<Map<number, HTMLTableRowElement>>(new Map());
  const jumpMap = useMemo(() => buildJumpMap(insns), [insns]);
  const [copied, setCopied] = useState(false);

  const scrollToLine = useCallback((idx: number) => {
    const el = lineRefs.current.get(idx);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      setHighlightedLine(idx);
      setTimeout(() => setHighlightedLine(null), 1500);
    }
  }, []);

  useEffect(() => {
    if (focusInstruction == null) return;
    const handle = window.setTimeout(() => scrollToLine(focusInstruction), 0);
    return () => window.clearTimeout(handle);
  }, [focusInstruction, scrollToLine]);

  const copyAll = useCallback(() => {
    const text = insns
      .map(i => `${String(i.index).padStart(4)}: ${i.disasm}`)
      .join("\n");
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [insns]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2 border-b border-white/5 shrink-0">
        <span className="text-xs text-slate-400">
          {insns.length} instructions
        </span>
        <button
          onClick={copyAll}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors px-2 py-1 rounded hover:bg-white/5"
        >
          {copied ? (
            <Check size={12} className="text-green-400" />
          ) : (
            <Copy size={12} />
          )}
          {copied ? "Copied" : "Copy all"}
        </button>
      </div>
      <div className="flex-1 overflow-auto font-mono text-xs leading-relaxed">
        <table className="w-full border-collapse">
          <tbody>
            {insns.map(insn => {
              const isJumpTarget = jumpMap.has(insn.index);
              const isHighlighted = highlightedLine === insn.index;
              const jumpMatch = insn.disasm.match(/goto pc([+-]\d+)/);
              const jumpTarget = jumpMatch
                ? insn.index + 1 + parseInt(jumpMatch[1])
                : null;

              return (
                <React.Fragment key={insn.index}>
                  <tr
                    ref={el => {
                      if (el) lineRefs.current.set(insn.index, el);
                    }}
                    className={[
                      "group transition-colors",
                      isHighlighted
                        ? "bg-yellow-500/20"
                        : "hover:bg-white/[0.03]",
                      isJumpTarget
                        ? "border-l-2 border-blue-500/60"
                        : "border-l-2 border-transparent",
                    ].join(" ")}
                  >
                    {/* Line number */}
                    <td className="pl-4 pr-2 py-0.5 text-slate-600 select-none w-12 text-right shrink-0">
                      {insn.index}
                    </td>
                    {/* Instruction */}
                    <td className="px-2 py-0.5 whitespace-nowrap">
                      {highlightXlated(insn.disasm)}
                      {/* Clickable jump target */}
                      {jumpTarget !== null &&
                        jumpTarget >= 0 &&
                        jumpTarget < insns.length && (
                          <button
                            onClick={() => scrollToLine(jumpTarget)}
                            className="ml-2 text-yellow-400/60 hover:text-yellow-300 text-xs opacity-0 group-hover:opacity-100 transition-opacity"
                            title={`Jump to instruction ${jumpTarget}`}
                          >
                            → {jumpTarget}
                          </button>
                        )}
                    </td>
                    {/* Opcodes */}
                    {insn.opcodes && (
                      <td className="pr-4 py-0.5 text-slate-600 text-xs whitespace-nowrap">
                        {insn.opcodes}
                      </td>
                    )}
                  </tr>
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── CFG tab ──────────────────────────────────────────────────────────────────

const CFG_BLOCK_ROW_HEIGHT = 82;
const CFG_BLOCK_OVERSCAN = 6;

function downloadTextFile(filename: string, text: string) {
  const blob = new Blob([text], { type: "text/vnd.graphviz;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function CfgMetric({
  label,
  value,
}: {
  label: string;
  value: string | number;
}) {
  return (
    <div className="rounded-lg border border-white/8 bg-slate-950/50 px-3 py-2">
      <div className="text-[10px] uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-1 font-mono text-sm text-slate-200">{value}</div>
    </div>
  );
}

function CfgBlockRow({
  result,
  onOpenBytecode,
}: {
  result: CfgBlockSearchResult;
  onOpenBytecode: (instruction?: number) => void;
}) {
  const { block, matchReason } = result;
  const targets = [
    ...block.branchTargets.map(target => `branch → ${target}`),
    ...(block.fallthroughTarget !== undefined
      ? [`fallthrough → ${block.fallthroughTarget}`]
      : []),
  ];

  return (
    <div
      className="grid grid-cols-[120px_minmax(0,1fr)_120px] gap-3 border-b border-white/5 px-3 py-2 text-xs"
      style={{ height: CFG_BLOCK_ROW_HEIGHT }}
    >
      <div className="font-mono text-slate-300">
        <div>
          bb_{block.start}
          <span className="ml-1 text-slate-600">
            {block.start}-{block.end}
          </span>
        </div>
        <div className="mt-1 text-[11px] text-slate-500">
          {block.instructionCount} insns
        </div>
        <div className="mt-1 truncate text-[10px] uppercase tracking-wide text-cyan-400/70">
          {matchReason}
        </div>
      </div>
      <div className="min-w-0">
        <div className="truncate font-mono text-slate-400">
          {block.terminalDisasm}
        </div>
        <div className="mt-1 flex flex-wrap gap-1">
          {targets.length > 0 ? (
            targets.map(target => (
              <span
                key={target}
                className="rounded border border-cyan-500/20 bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[11px] text-cyan-300"
              >
                {target}
              </span>
            ))
          ) : (
            <span className="text-[11px] text-slate-600">no outgoing edge</span>
          )}
          {block.calls.map(call => (
            <span
              key={call}
              className="rounded border border-amber-500/20 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[11px] text-amber-300"
            >
              call {call}
            </span>
          ))}
        </div>
        {block.sourceSnippets[0] && (
          <div className="mt-1 truncate text-[11px] text-emerald-400/70">
            {block.sourceSnippets[0]}
          </div>
        )}
      </div>
      <div className="flex items-start justify-end">
        <button
          onClick={() => onOpenBytecode(block.start)}
          className="rounded border border-white/8 px-2 py-1 text-[11px] text-slate-400 transition-colors hover:border-cyan-500/40 hover:text-cyan-200"
        >
          Bytecode
        </button>
      </div>
    </div>
  );
}

function CfgBlockList({
  results,
  onOpenBytecode,
}: {
  results: CfgBlockSearchResult[];
  onOpenBytecode: (instruction?: number) => void;
}) {
  const [scrollTop, setScrollTop] = useState(0);
  const totalHeight = results.length * CFG_BLOCK_ROW_HEIGHT;
  const start = Math.max(
    0,
    Math.floor(scrollTop / CFG_BLOCK_ROW_HEIGHT) - CFG_BLOCK_OVERSCAN
  );
  const visibleCount = 20 + CFG_BLOCK_OVERSCAN * 2;
  const visibleResults = results.slice(start, start + visibleCount);

  if (results.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-slate-500">
        No matching basic blocks.
      </div>
    );
  }

  return (
    <div
      className="h-full overflow-auto rounded-lg border border-white/8 bg-slate-950/40"
      onScroll={event => setScrollTop(event.currentTarget.scrollTop)}
    >
      <div style={{ height: totalHeight, position: "relative" }}>
        <div
          style={{
            transform: `translateY(${start * CFG_BLOCK_ROW_HEIGHT}px)`,
          }}
        >
          {visibleResults.map(result => (
            <CfgBlockRow
              key={result.block.id}
              result={result}
              onOpenBytecode={onOpenBytecode}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

function CfgLargeFallback({
  dot,
  filename,
  onRenderAnyway,
  onOpenBytecode,
  copied,
  onCopyDot,
  analysis,
  blocks,
}: {
  dot: string;
  filename: string;
  onRenderAnyway: () => void;
  onOpenBytecode: (instruction?: number) => void;
  copied: boolean;
  onCopyDot: () => void;
  analysis: ReturnType<typeof analyzeCfgRender>;
  blocks: CfgBasicBlockSummary[];
}) {
  const [query, setQuery] = useState("");
  const results = useMemo(() => searchCfgBlocks(blocks, query), [blocks, query]);
  const firstMatch = results[0]?.block.start;

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-white/5 bg-slate-950/40 px-4 py-3">
        <div className="flex items-start gap-3">
          <div className="mt-0.5 rounded-full bg-amber-500/10 p-2 text-amber-300">
            <AlertTriangle size={16} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-medium text-slate-100">
              Large control-flow graph was not rendered automatically
            </div>
            <div className="mt-1 max-w-3xl text-xs leading-relaxed text-slate-400">
              Graphviz layout can freeze the browser for very large BPF
              programs. Use the basic-block summary below, or explicitly render
              the full graph if you need the SVG.
            </div>
            <div className="mt-2 space-y-1">
              {analysis.reasons.map(reason => (
                <div key={reason} className="text-xs text-amber-300/90">
                  {reason}
                </div>
              ))}
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap justify-end gap-2">
            <button
              onClick={onRenderAnyway}
              className="rounded-lg bg-amber-500/15 px-3 py-1.5 text-xs font-medium text-amber-200 transition-colors hover:bg-amber-500/25"
            >
              Render anyway
            </button>
            <button
              onClick={() => downloadTextFile(filename, dot)}
              className="flex items-center gap-1.5 rounded-lg border border-white/8 px-3 py-1.5 text-xs text-slate-300 transition-colors hover:border-cyan-500/40 hover:text-cyan-200"
            >
              <Download size={12} />
              DOT
            </button>
            <button
              onClick={onCopyDot}
              className="flex items-center gap-1.5 rounded-lg border border-white/8 px-3 py-1.5 text-xs text-slate-300 transition-colors hover:border-cyan-500/40 hover:text-cyan-200"
            >
              {copied ? <Check size={12} /> : <Copy size={12} />}
              {copied ? "Copied" : "Copy DOT"}
            </button>
            <button
              onClick={() => onOpenBytecode(blocks[0]?.start)}
              className="rounded-lg border border-white/8 px-3 py-1.5 text-xs text-slate-300 transition-colors hover:border-cyan-500/40 hover:text-cyan-200"
            >
              Open bytecode
            </button>
          </div>
        </div>
        <div className="mt-3 grid grid-cols-2 gap-2 md:grid-cols-5">
          <CfgMetric
            label="Instructions"
            value={analysis.instructionCount.toLocaleString()}
          />
          <CfgMetric label="Blocks" value={analysis.blockCount.toLocaleString()} />
          <CfgMetric
            label="DOT chars"
            value={analysis.dotChars.toLocaleString()}
          />
          <CfgMetric
            label="Nodes"
            value={analysis.estimatedNodeCount.toLocaleString()}
          />
          <CfgMetric
            label="Edges"
            value={analysis.estimatedEdgeCount.toLocaleString()}
          />
        </div>
      </div>
      <div className="border-b border-white/5 px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[260px] flex-1">
            <Search
              size={13}
              className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500"
            />
            <input
              value={query}
              onChange={event => setQuery(event.target.value)}
              onKeyDown={event => {
                if (event.key === "Enter" && firstMatch !== undefined) {
                  onOpenBytecode(firstMatch);
                }
              }}
              placeholder="Search instruction #, helper, branch target, source, or disasm"
              className="w-full rounded-lg border border-white/8 bg-slate-950/70 py-1.5 pl-8 pr-3 text-xs text-slate-200 outline-none transition-colors placeholder:text-slate-600 focus:border-cyan-500/40"
            />
          </div>
          <div className="font-mono text-xs text-slate-500">
            {results.length.toLocaleString()} / {blocks.length.toLocaleString()} blocks
          </div>
          {query && (
            <button
              onClick={() => setQuery("")}
              className="rounded border border-white/8 px-2 py-1 text-xs text-slate-400 transition-colors hover:border-cyan-500/40 hover:text-cyan-200"
            >
              Clear
            </button>
          )}
          <button
            disabled={firstMatch === undefined}
            onClick={() => onOpenBytecode(firstMatch)}
            className="rounded border border-white/8 px-2 py-1 text-xs text-slate-400 transition-colors enabled:hover:border-cyan-500/40 enabled:hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Jump to first match
          </button>
        </div>
        <div className="mt-2 text-[11px] text-slate-600">
          Examples: <span className="font-mono text-slate-500">42</span>,{" "}
          <span className="font-mono text-slate-500">map_lookup</span>,{" "}
          <span className="font-mono text-slate-500">branch 128</span>,{" "}
          <span className="font-mono text-slate-500">exit</span>
        </div>
      </div>
      <div className="min-h-0 flex-1 p-4">
        <CfgBlockList results={results} onOpenBytecode={onOpenBytecode} />
      </div>
    </div>
  );
}

function CfgTab({
  dot,
  insns,
  filename,
  onOpenBytecode,
}: {
  dot: string;
  insns: XlatedInsn[];
  filename: string;
  onOpenBytecode: (instruction?: number) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [svgContent, setSvgContent] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [scale, setScale] = useState(1);
  const [forceRender, setForceRender] = useState(false);
  const [copiedDot, setCopiedDot] = useState(false);
  const analysis = useMemo(() => analyzeCfgRender(dot, insns), [dot, insns]);
  const blocks = useMemo(() => buildCfgBasicBlocks(insns), [insns]);
  const shouldRenderGraph = forceRender || analysis.shouldAutoRender;

  const copyDot = useCallback(() => {
    navigator.clipboard.writeText(dot);
    setCopiedDot(true);
    window.setTimeout(() => setCopiedDot(false), 2000);
  }, [dot]);

  useEffect(() => {
    setForceRender(false);
  }, [dot]);

  useEffect(() => {
    let cancelled = false;
    if (!shouldRenderGraph) {
      setLoading(false);
      setError("");
      setSvgContent("");
      return () => {
        cancelled = true;
      };
    }

    setLoading(true);
    setError("");

    getViz()
      .then(viz => {
        if (cancelled) return;
        try {
          const svg = viz.renderSVGElement(dot);
          // Style the SVG for dark theme
          svg.style.maxWidth = "100%";
          svg.style.height = "auto";
          svg.querySelectorAll("text").forEach((t: SVGTextElement) => {
            t.style.fill = "#cbd5e1";
            t.style.fontFamily = "monospace";
            t.style.fontSize = "10px";
          });
          svg.querySelectorAll("polygon, path").forEach((el: Element) => {
            const e = el as SVGElement;
            const fill = e.getAttribute("fill");
            const stroke = e.getAttribute("stroke");
            if (fill && fill !== "none") e.setAttribute("fill", "#0f172a");
            if (stroke && stroke !== "none")
              e.setAttribute("stroke", "#334155");
          });
          svg.querySelectorAll("ellipse").forEach((el: Element) => {
            const e = el as SVGElement;
            e.setAttribute("fill", "#1e293b");
            e.setAttribute("stroke", "#3b82f6");
          });
          setSvgContent(svg.outerHTML);
        } catch (e: unknown) {
          setError(errorMessage(e, "Failed to render CFG"));
        } finally {
          setLoading(false);
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setError(errorMessage(e, "Failed to load Graphviz"));
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [dot, shouldRenderGraph]);

  if (!shouldRenderGraph) {
    return (
      <CfgLargeFallback
        dot={dot}
        filename={filename}
        onRenderAnyway={() => setForceRender(true)}
        onOpenBytecode={onOpenBytecode}
        copied={copiedDot}
        onCopyDot={copyDot}
        analysis={analysis}
        blocks={blocks}
      />
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full gap-2 text-slate-400">
        <Loader2 size={16} className="animate-spin" />
        <span className="text-sm">
          Rendering control-flow graph{forceRender ? " anyway" : ""}…
        </span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-slate-400 p-8">
        <AlertTriangle size={24} className="text-amber-400" />
        <p className="text-sm text-center">{error}</p>
        <details className="text-xs text-slate-600 max-w-lg">
          <summary className="cursor-pointer hover:text-slate-400">
            View DOT source
          </summary>
          <pre className="mt-2 p-3 bg-slate-900 rounded text-xs overflow-auto max-h-40">
            {dot}
          </pre>
        </details>
        <button
          onClick={() => downloadTextFile(filename, dot)}
          className="flex items-center gap-1.5 rounded-lg border border-white/8 px-3 py-1.5 text-xs text-slate-300 transition-colors hover:border-cyan-500/40 hover:text-cyan-200"
        >
          <Download size={12} />
          Download DOT
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-white/5 shrink-0">
        <span className="text-xs text-slate-400">
          Control-flow graph — basic blocks with branch edges
        </span>
        {!analysis.shouldAutoRender && (
          <span className="rounded border border-amber-500/25 bg-amber-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-amber-300">
            forced large render
          </span>
        )}
        <div className="ml-auto flex items-center gap-1">
          <button
            onClick={() => downloadTextFile(filename, dot)}
            className="flex items-center gap-1 px-2 py-0.5 text-xs text-slate-400 hover:text-white hover:bg-white/5 rounded"
          >
            <Download size={12} />
            DOT
          </button>
          <button
            onClick={() => setScale(s => Math.max(0.3, s - 0.1))}
            className="px-2 py-0.5 text-xs text-slate-400 hover:text-white hover:bg-white/5 rounded"
          >
            −
          </button>
          <span className="text-xs text-slate-500 w-10 text-center">
            {Math.round(scale * 100)}%
          </span>
          <button
            onClick={() => setScale(s => Math.min(3, s + 0.1))}
            className="px-2 py-0.5 text-xs text-slate-400 hover:text-white hover:bg-white/5 rounded"
          >
            +
          </button>
          <button
            onClick={() => setScale(1)}
            className="px-2 py-0.5 text-xs text-slate-400 hover:text-white hover:bg-white/5 rounded ml-1"
          >
            Reset
          </button>
        </div>
      </div>
      <div className="flex-1 overflow-auto p-4 flex items-start justify-center">
        <div
          ref={containerRef}
          style={{
            transform: `scale(${scale})`,
            transformOrigin: "top center",
            transition: "transform 0.15s",
          }}
          dangerouslySetInnerHTML={{ __html: svgContent }}
          className="[&_svg]:bg-slate-950 [&_svg]:rounded [&_svg]:p-2"
        />
      </div>
    </div>
  );
}

// ─── JIT tab ──────────────────────────────────────────────────────────────────

function JitTab({
  insns,
  unavailableReason,
}: {
  insns: JitedInsn[] | null;
  unavailableReason?: string;
}) {
  const [copied, setCopied] = useState(false);

  const copyAll = useCallback(() => {
    if (!insns) return;
    const text = insns
      .map(i => `${i.pc.padStart(18)}:  ${i.disasm}`)
      .join("\n");
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [insns]);

  if (!insns) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 p-8 text-center">
        <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center">
          <Cpu size={20} className="text-slate-500" />
        </div>
        <div>
          <p className="text-sm text-slate-300 font-medium mb-2">
            JIT assembly not available
          </p>
          <p className="text-xs text-slate-500 max-w-md leading-relaxed">
            {unavailableReason}
          </p>
        </div>
        <div className="mt-2 p-3 bg-slate-900/60 rounded-lg border border-white/5 text-left max-w-md">
          <p className="text-xs text-slate-500 font-mono">
            # To enable JIT compilation:
            <br />
            sudo sysctl -w net.core.bpf_jit_enable=1
            <br />
            sudo sysctl -w kernel.kptr_restrict=0
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2 border-b border-white/5 shrink-0">
        <span className="text-xs text-slate-400">
          {insns.length} native instructions
        </span>
        <button
          onClick={copyAll}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors px-2 py-1 rounded hover:bg-white/5"
        >
          {copied ? (
            <Check size={12} className="text-green-400" />
          ) : (
            <Copy size={12} />
          )}
          {copied ? "Copied" : "Copy all"}
        </button>
      </div>
      <div className="flex-1 overflow-auto font-mono text-xs leading-relaxed">
        <table className="w-full border-collapse">
          <tbody>
            {insns.map((insn, idx) => (
              <tr key={idx} className="hover:bg-white/[0.03] transition-colors">
                <td className="pl-4 pr-3 py-0.5 text-slate-600 select-none whitespace-nowrap">
                  {insn.pc}
                </td>
                <td className="px-2 py-0.5 whitespace-nowrap">
                  {highlightJited(insn.disasm)}
                </td>
                {insn.opcodes && (
                  <td className="pr-4 py-0.5 text-slate-700 text-xs whitespace-nowrap">
                    {insn.opcodes}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── C Source tab ─────────────────────────────────────────────────────────────

interface SourceLine {
  key: string;
  source: string;
  location?: string;
}

function formatSourceLocation(insn: XlatedInsn): string | undefined {
  if (!insn.sourceFile && insn.sourceLine === undefined) return undefined;

  const file = insn.sourceFile ?? "<unknown>";
  if (insn.sourceLine === undefined) return file;
  return insn.sourceColumn === undefined
    ? `${file}:${insn.sourceLine}`
    : `${file}:${insn.sourceLine}:${insn.sourceColumn}`;
}

function SourceTab({
  insns,
  hasLineInfo,
}: {
  insns: XlatedInsn[];
  hasLineInfo: boolean;
}) {
  if (!hasLineInfo) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 p-8 text-center">
        <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center">
          <FileCode size={20} className="text-slate-500" />
        </div>
        <div>
          <p className="text-sm text-slate-300 font-medium mb-2">
            C source not available
          </p>
          <p className="text-xs text-slate-500 max-w-md leading-relaxed">
            No source annotations found in the bytecode dump. Source annotations
            require programs compiled with clang -g and loaded with BTF enabled.
          </p>
        </div>
        <div className="mt-2 p-3 bg-slate-900/60 rounded-lg border border-white/5 text-left max-w-md">
          <p className="text-xs text-slate-500 font-mono">
            # Compile with BTF + debug info:
            <br />
            clang -O2 -g -target bpf \<br />
            {"  "}-D__TARGET_ARCH_x86 \<br />
            {"  "}-c prog.bpf.c -o prog.bpf.o
          </p>
        </div>
      </div>
    );
  }

  // Extract unique source lines in order of appearance
  const sourceLines: SourceLine[] = [];
  const seen = new Set<string>();
  for (const insn of insns) {
    const source = insn.source ?? insn.linum;
    if (!source) continue;

    const location = formatSourceLocation(insn);
    const key = `${location ?? ""}\0${source}`;
    if (!seen.has(key)) {
      seen.add(key);
      sourceLines.push({ key, source, location });
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-white/5 shrink-0">
        <AlertTriangle size={12} className="text-amber-400 shrink-0" />
        <span className="text-xs text-slate-400">
          Showing source annotations from BTF line info. Original source files
          are not loaded. Snippets follow bytecode order and may be incomplete
          or reordered by the compiler.
        </span>
      </div>
      <div className="flex-1 overflow-auto font-mono text-sm leading-relaxed p-4">
        {sourceLines.map((line, idx) => (
          <div
            key={line.key}
            className="py-0.5 flex gap-3 hover:bg-white/[0.03] transition-colors rounded px-2"
          >
            <span className="text-slate-600 select-none w-8 text-right shrink-0">
              {idx + 1}
            </span>
            <div className="min-w-0">
              {line.location && (
                <div className="text-[11px] leading-4 text-slate-500 truncate">
                  {line.location}
                </div>
              )}
              <div className="text-emerald-400/90 whitespace-pre-wrap">
                {line.source}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Main CodeInspector modal ─────────────────────────────────────────────────

type Tab = "bytecode" | "cfg" | "jit" | "source";

interface CodeInspectorProps {
  program: BpfProgram;
  onClose: () => void;
}

export function CodeInspector({ program, onClose }: CodeInspectorProps) {
  const [activeTab, setActiveTab] = useState<Tab>("bytecode");
  const [bytecodeFocus, setBytecodeFocus] = useState<number | null>(null);

  const {
    data: dump,
    isLoading,
    error,
  } = trpc.ebpf.progDump.useQuery(
    { id: program.id },
    { staleTime: 30_000, retry: 1 }
  );

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  const openBytecodeAt = useCallback((instruction?: number) => {
    setBytecodeFocus(instruction ?? null);
    setActiveTab("bytecode");
  }, []);

  const tabs: Array<{
    id: Tab;
    label: string;
    icon: React.ReactNode;
    available: boolean;
    badge?: string;
  }> = [
    {
      id: "bytecode",
      label: "BPF Bytecode",
      icon: <Code2 size={13} />,
      available: true,
      badge: dump ? String(dump.xlated.length) : undefined,
    },
    {
      id: "cfg",
      label: "Control Flow",
      icon: <GitBranch size={13} />,
      available: true,
    },
    {
      id: "jit",
      label: "JIT Assembly",
      icon: <Cpu size={13} />,
      available: true,
      badge: dump?.jited ? String(dump.jited.length) : undefined,
    },
    {
      id: "source",
      label: "C Source",
      icon: <FileCode size={13} />,
      available: !!dump?.hasLineInfo,
      badge: dump?.hasLineInfo
        ? dump?.hasBtf
          ? "BTF"
          : "annotations"
        : undefined,
    },
  ];

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{
        background: "oklch(0.04 0.01 240 / 0.85)",
        backdropFilter: "blur(4px)",
      }}
    >
      <div
        className="relative flex flex-col rounded-xl border border-white/10 shadow-2xl"
        style={{
          width: "min(1100px, 95vw)",
          height: "min(800px, 90vh)",
          background: "oklch(0.09 0.012 240)",
        }}
      >
        {/* Header */}
        <div className="flex items-center gap-3 px-5 py-3 border-b border-white/8 shrink-0">
          <div
            className="w-2 h-2 rounded-full shrink-0"
            style={{ background: program.color }}
          />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-white truncate">
                {program.name}
              </span>
              <span className="text-xs text-slate-500 font-mono">
                id:{program.id}
              </span>
              <span
                className="text-xs px-1.5 py-0.5 rounded font-mono"
                style={{
                  background: program.color + "22",
                  color: program.color,
                }}
              >
                {program.rawType}
              </span>
            </div>
            <div className="text-xs text-slate-500 font-mono mt-0.5">
              tag: {program.tag}
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/8 transition-colors shrink-0"
          >
            <X size={16} />
          </button>
        </div>

        {/* Tab bar */}
        <div className="flex items-center gap-0.5 px-4 pt-2 border-b border-white/8 shrink-0">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={[
                "flex items-center gap-1.5 px-3 py-2 text-xs rounded-t-lg transition-colors border-b-2 -mb-px",
                activeTab === tab.id
                  ? "text-white border-cyan-500 bg-white/5"
                  : "text-slate-500 border-transparent hover:text-slate-300 hover:bg-white/3",
                !tab.available && activeTab !== tab.id ? "opacity-40" : "",
              ].join(" ")}
            >
              {tab.icon}
              {tab.label}
              {tab.badge && (
                <span className="ml-1 px-1.5 py-0.5 rounded text-[10px] bg-white/8 text-slate-400">
                  {tab.badge}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 min-h-0 overflow-hidden">
          {isLoading && (
            <div className="flex items-center justify-center h-full gap-2 text-slate-400">
              <Loader2 size={16} className="animate-spin" />
              <span className="text-sm">Loading code dump…</span>
            </div>
          )}

          {error && (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-slate-400 p-8">
              <AlertTriangle size={20} className="text-amber-400" />
              <p className="text-sm">Failed to load code dump</p>
              <p className="text-xs text-slate-600">{error.message}</p>
            </div>
          )}

          {dump && (
            <>
              {dump.error && (
                <div className="flex items-center gap-2 px-4 py-2 bg-amber-950/30 border-b border-amber-500/20 shrink-0">
                  <AlertTriangle
                    size={14}
                    className="text-amber-400 shrink-0"
                  />
                  <span className="text-xs text-amber-300">{dump.error}</span>
                </div>
              )}
              {activeTab === "bytecode" && (
                <BytecodeTab
                  insns={dump.xlated}
                  focusInstruction={bytecodeFocus}
                />
              )}
              {activeTab === "cfg" && (
                <CfgTab
                  dot={dump.cfgDot}
                  insns={dump.xlated}
                  filename={`bpf-prog-${program.id}-cfg.dot`}
                  onOpenBytecode={openBytecodeAt}
                />
              )}
              {activeTab === "jit" && (
                <JitTab
                  insns={dump.jited}
                  unavailableReason={dump.jitedUnavailableReason}
                />
              )}
              {activeTab === "source" && (
                <SourceTab insns={dump.xlated} hasLineInfo={dump.hasLineInfo} />
              )}
            </>
          )}
        </div>

        {/* Footer */}
        {dump && (
          <div className="flex items-center gap-4 px-5 py-2 border-t border-white/5 shrink-0 text-xs text-slate-600">
            <span>{dump.xlated.length} BPF insns</span>
            {dump.jited && <span>{dump.jited.length} native insns</span>}
            {dump.hasBtf && (
              <span className="text-emerald-600">BTF id:{dump.btfId}</span>
            )}
            {dump.hasLineInfo && (
              <span className="text-emerald-600">source annotations</span>
            )}
            {!dump.jited && (
              <span className="text-amber-600/60">JIT not available</span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

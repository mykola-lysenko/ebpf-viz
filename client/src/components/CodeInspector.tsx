/**
 * CodeInspector.tsx
 *
 * Full-screen modal that shows three code views for a BPF program:
 *   Tab 1 — BPF Bytecode (xlated) with syntax highlighting
 *   Tab 2 — CFG (control-flow graph) rendered via @viz-js/viz
 *   Tab 3 — JIT Assembly (jited) with register coloring
 *   Tab 4 — C Source (BTF linum interleaved) — shown only when available
 */

import React, { useEffect, useRef, useState, useCallback, useMemo } from "react";
import { X, Copy, Check, ChevronDown, ChevronRight, Loader2, AlertTriangle, Code2, GitBranch, Cpu, FileCode } from "lucide-react";
import { trpc } from "@/lib/trpc";
import type { BpfProgram, XlatedInsn, JitedInsn } from "../../../shared/ebpf-types";

// ─── Viz.js lazy loader ───────────────────────────────────────────────────────

let vizInstance: any = null;
async function getViz() {
  if (vizInstance) return vizInstance;
  const { instance } = await import("@viz-js/viz");
  vizInstance = await instance();
  return vizInstance;
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
            <span key={key++} className={cls}>{text}</span>
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
      tokens.push(<span key={key++} className="text-slate-300">{remaining[0]}</span>);
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
  const x86Regs = /\b(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15|eax|ebx|ecx|edx|esi|edi|esp|ebp|al|bl|cl|dl)\b/g;
  const arm64Regs = /\b(x[0-9]|x1[0-9]|x2[0-9]|x30|sp|lr|fp|w[0-9]|w1[0-9]|w2[0-9])\b/g;
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
    parts.push(<span key={key++} className="text-sky-400 font-medium">{mnemonic}</span>);

    // Highlight rest
    let remaining = rest;
    let lastIndex = 0;
    const combined = new RegExp(`(${x86Regs.source}|${arm64Regs.source}|${immediates.source})`, "g");
    const matches = Array.from(remaining.matchAll(combined));

    for (const match of matches) {
      if (match.index! > lastIndex) {
        parts.push(<span key={key++} className="text-slate-300">{remaining.slice(lastIndex, match.index)}</span>);
      }
      const val = match[0];
      if (/^0x|^-?\d/.test(val)) {
        parts.push(<span key={key++} className="text-green-400">{val}</span>);
      } else {
        parts.push(<span key={key++} className="text-cyan-400">{val}</span>);
      }
      lastIndex = match.index! + val.length;
    }
    if (lastIndex < remaining.length) {
      parts.push(<span key={key++} className="text-slate-300">{remaining.slice(lastIndex)}</span>);
    }
  } else {
    parts.push(<span key={key++} className="text-slate-300">{text}</span>);
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

function BytecodeTab({ insns }: { insns: XlatedInsn[] }) {
  const [highlightedLine, setHighlightedLine] = useState<number | null>(null);
  const lineRefs = useRef<Map<number, HTMLDivElement>>(new Map());
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

  const copyAll = useCallback(() => {
    const text = insns.map(i => `${String(i.index).padStart(4)}: ${i.disasm}`).join("\n");
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [insns]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2 border-b border-white/5 shrink-0">
        <span className="text-xs text-slate-400">{insns.length} instructions</span>
        <button
          onClick={copyAll}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors px-2 py-1 rounded hover:bg-white/5"
        >
          {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
          {copied ? "Copied" : "Copy all"}
        </button>
      </div>
      <div className="flex-1 overflow-auto font-mono text-xs leading-relaxed">
        <table className="w-full border-collapse">
          <tbody>
            {insns.map((insn) => {
              const isJumpTarget = jumpMap.has(insn.index);
              const isHighlighted = highlightedLine === insn.index;
              const jumpMatch = insn.disasm.match(/goto pc([+-]\d+)/);
              const jumpTarget = jumpMatch ? insn.index + 1 + parseInt(jumpMatch[1]) : null;

              return (
                <React.Fragment key={insn.index}>
                  <tr
                    ref={el => { if (el) lineRefs.current.set(insn.index, el as any); }}
                    className={[
                      "group transition-colors",
                      isHighlighted ? "bg-yellow-500/20" : "hover:bg-white/[0.03]",
                      isJumpTarget ? "border-l-2 border-blue-500/60" : "border-l-2 border-transparent",
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
                      {jumpTarget !== null && jumpTarget >= 0 && jumpTarget < insns.length && (
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

function CfgTab({ dot }: { dot: string }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [svgContent, setSvgContent] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [scale, setScale] = useState(1);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");

    getViz().then(viz => {
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
          if (stroke && stroke !== "none") e.setAttribute("stroke", "#334155");
        });
        svg.querySelectorAll("ellipse").forEach((el: Element) => {
          const e = el as SVGElement;
          e.setAttribute("fill", "#1e293b");
          e.setAttribute("stroke", "#3b82f6");
        });
        setSvgContent(svg.outerHTML);
      } catch (e: any) {
        setError(e.message ?? "Failed to render CFG");
      } finally {
        setLoading(false);
      }
    }).catch(e => {
      if (!cancelled) {
        setError(e.message ?? "Failed to load Graphviz");
        setLoading(false);
      }
    });

    return () => { cancelled = true; };
  }, [dot]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full gap-2 text-slate-400">
        <Loader2 size={16} className="animate-spin" />
        <span className="text-sm">Rendering control-flow graph…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-slate-400 p-8">
        <AlertTriangle size={24} className="text-amber-400" />
        <p className="text-sm text-center">{error}</p>
        <details className="text-xs text-slate-600 max-w-lg">
          <summary className="cursor-pointer hover:text-slate-400">View DOT source</summary>
          <pre className="mt-2 p-3 bg-slate-900 rounded text-xs overflow-auto max-h-40">{dot}</pre>
        </details>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-white/5 shrink-0">
        <span className="text-xs text-slate-400">Control-flow graph — basic blocks with branch edges</span>
        <div className="ml-auto flex items-center gap-1">
          <button onClick={() => setScale(s => Math.max(0.3, s - 0.1))} className="px-2 py-0.5 text-xs text-slate-400 hover:text-white hover:bg-white/5 rounded">−</button>
          <span className="text-xs text-slate-500 w-10 text-center">{Math.round(scale * 100)}%</span>
          <button onClick={() => setScale(s => Math.min(3, s + 0.1))} className="px-2 py-0.5 text-xs text-slate-400 hover:text-white hover:bg-white/5 rounded">+</button>
          <button onClick={() => setScale(1)} className="px-2 py-0.5 text-xs text-slate-400 hover:text-white hover:bg-white/5 rounded ml-1">Reset</button>
        </div>
      </div>
      <div className="flex-1 overflow-auto p-4 flex items-start justify-center">
        <div
          ref={containerRef}
          style={{ transform: `scale(${scale})`, transformOrigin: "top center", transition: "transform 0.15s" }}
          dangerouslySetInnerHTML={{ __html: svgContent }}
          className="[&_svg]:bg-slate-950 [&_svg]:rounded [&_svg]:p-2"
        />
      </div>
    </div>
  );
}

// ─── JIT tab ──────────────────────────────────────────────────────────────────

function JitTab({ insns, unavailableReason }: { insns: JitedInsn[] | null; unavailableReason?: string }) {
  const [copied, setCopied] = useState(false);

  const copyAll = useCallback(() => {
    if (!insns) return;
    const text = insns.map(i => `${i.pc.padStart(18)}:  ${i.disasm}`).join("\n");
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
          <p className="text-sm text-slate-300 font-medium mb-2">JIT assembly not available</p>
          <p className="text-xs text-slate-500 max-w-md leading-relaxed">{unavailableReason}</p>
        </div>
        <div className="mt-2 p-3 bg-slate-900/60 rounded-lg border border-white/5 text-left max-w-md">
          <p className="text-xs text-slate-500 font-mono">
            # To enable JIT compilation:<br />
            sudo sysctl -w net.core.bpf_jit_enable=1<br />
            sudo sysctl -w kernel.kptr_restrict=0
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2 border-b border-white/5 shrink-0">
        <span className="text-xs text-slate-400">{insns.length} native instructions</span>
        <button
          onClick={copyAll}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors px-2 py-1 rounded hover:bg-white/5"
        >
          {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
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

function SourceTab({ insns, hasLineInfo }: { insns: XlatedInsn[]; hasLineInfo: boolean }) {
  if (!hasLineInfo) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 p-8 text-center">
        <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center">
          <FileCode size={20} className="text-slate-500" />
        </div>
        <div>
          <p className="text-sm text-slate-300 font-medium mb-2">C source not available</p>
          <p className="text-xs text-slate-500 max-w-md leading-relaxed">
            No source annotations found in the bytecode dump. Source annotations require programs compiled with clang -g and loaded with BTF enabled.
          </p>
        </div>
        <div className="mt-2 p-3 bg-slate-900/60 rounded-lg border border-white/5 text-left max-w-md">
          <p className="text-xs text-slate-500 font-mono">
            # Compile with BTF + debug info:<br />
            clang -O2 -g -target bpf \<br />
            {"  "}-D__TARGET_ARCH_x86 \<br />
            {"  "}-c prog.bpf.c -o prog.bpf.o
          </p>
        </div>
      </div>
    );
  }

  // Extract unique source lines in order of appearance
  const sourceLines: string[] = [];
  const seen = new Set<string>();
  for (const insn of insns) {
    if (insn.linum && !seen.has(insn.linum)) {
      seen.add(insn.linum);
      sourceLines.push(insn.linum);
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-white/5 shrink-0">
        <AlertTriangle size={12} className="text-amber-400 shrink-0" />
        <span className="text-xs text-slate-400">
          Reconstructed from BPF bytecode annotations — not the original source file.
          Fragments may be incomplete or reordered by the compiler.
        </span>
      </div>
      <div className="flex-1 overflow-auto font-mono text-sm leading-relaxed p-4">
        {sourceLines.map((line, idx) => (
          <div
            key={idx}
            className="py-0.5 flex gap-3 hover:bg-white/[0.03] transition-colors rounded px-2"
          >
            <span className="text-slate-600 select-none w-8 text-right shrink-0">{idx + 1}</span>
            <span className="text-emerald-400/90">{line}</span>
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

  const { data: dump, isLoading, error } = trpc.ebpf.progDump.useQuery(
    { id: program.id },
    { staleTime: 30_000, retry: 1 }
  );

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  const tabs: Array<{ id: Tab; label: string; icon: React.ReactNode; available: boolean; badge?: string }> = [
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
      badge: dump?.hasLineInfo ? (dump?.hasBtf ? "BTF" : "annotations") : undefined,
    },
  ];

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: "oklch(0.04 0.01 240 / 0.85)", backdropFilter: "blur(4px)" }}
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
              <span className="text-sm font-semibold text-white truncate">{program.name}</span>
              <span className="text-xs text-slate-500 font-mono">id:{program.id}</span>
              <span
                className="text-xs px-1.5 py-0.5 rounded font-mono"
                style={{ background: program.color + "22", color: program.color }}
              >
                {program.rawType}
              </span>
            </div>
            <div className="text-xs text-slate-500 font-mono mt-0.5">tag: {program.tag}</div>
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
                  <AlertTriangle size={14} className="text-amber-400 shrink-0" />
                  <span className="text-xs text-amber-300">{dump.error}</span>
                </div>
              )}
              {activeTab === "bytecode" && (
                <BytecodeTab insns={dump.xlated} />
              )}
              {activeTab === "cfg" && (
                <CfgTab dot={dump.cfgDot} />
              )}
              {activeTab === "jit" && (
                <JitTab insns={dump.jited} unavailableReason={dump.jitedUnavailableReason} />
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
            {dump.hasBtf && <span className="text-emerald-600">BTF id:{dump.btfId}</span>}
            {dump.hasLineInfo && <span className="text-emerald-600">source annotations</span>}
            {!dump.jited && <span className="text-amber-600/60">JIT not available</span>}
          </div>
        )}
      </div>
    </div>
  );
}

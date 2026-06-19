import type {
  XlatedInsn,
  XlatedSideEffect,
  XlatedSideEffectKind,
  XlatedSideEffectSummary,
} from "../shared/ebpf-types";

const SIDE_EFFECT_LABELS: Record<XlatedSideEffectKind, string> = {
  "map-write": "updates maps",
  "direct-memory-write": "writes through pointer",
  "packet-mutation": "mutates packet",
  "redirect-helper": "redirect helper",
  "telemetry-output": "emits events",
  "tail-call": "tail calls",
  "socket-mutation": "updates sockets",
};

const SIDE_EFFECT_ORDER: XlatedSideEffectKind[] = [
  "packet-mutation",
  "redirect-helper",
  "map-write",
  "socket-mutation",
  "direct-memory-write",
  "telemetry-output",
  "tail-call",
];

const EMPTY_SIDE_EFFECT_SUMMARY: XlatedSideEffectSummary = {
  hasSideEffects: false,
  labels: [],
  effects: [],
  hasMapWrites: false,
  hasDirectMemoryWrites: false,
  hasPacketMutations: false,
  hasRedirects: false,
  hasTelemetryOutput: false,
  hasTailCalls: false,
  hasSocketMutations: false,
};

function sourceEvidence(
  insn: XlatedInsn
): Pick<
  XlatedSideEffect,
  "source" | "sourceFile" | "sourceLine" | "sourceColumn"
> {
  const evidence: Pick<
    XlatedSideEffect,
    "source" | "sourceFile" | "sourceLine" | "sourceColumn"
  > = {};
  if (insn.source) evidence.source = insn.source;
  if (insn.linum && !evidence.source) evidence.source = insn.linum;
  if (insn.sourceFile) evidence.sourceFile = insn.sourceFile;
  if (insn.sourceLine !== undefined) evidence.sourceLine = insn.sourceLine;
  if (insn.sourceColumn !== undefined)
    evidence.sourceColumn = insn.sourceColumn;
  return evidence;
}

function normalizeHelperName(disasm: string): string | null {
  const body = disasm.trim().replace(/^\([0-9a-fA-F]+\)\s+/, "");
  const match = body.match(/^call\s+(\S+)/);
  if (!match) return null;

  const target = match[1];
  if (target.startsWith("pc+") || target.startsWith("pc-")) return null;
  if (/^-?\d+$/.test(target)) return null;

  return target
    .split("#")[0]
    .replace(/^bpf_/, "")
    .replace(/\..*$/, "")
    .toLowerCase();
}

function helperKind(helper: string): XlatedSideEffectKind | null {
  if (helper.includes("tail_call")) return "tail-call";

  if (
    helper === "map_update_elem" ||
    helper === "map_delete_elem" ||
    helper === "map_push_elem" ||
    helper === "map_pop_elem" ||
    helper === "map_freeze"
  ) {
    return "map-write";
  }

  if (helper === "sock_map_update" || helper === "sock_hash_update") {
    return "socket-mutation";
  }

  if (
    helper === "skb_store_bytes" ||
    helper === "skb_adjust_room" ||
    helper === "skb_change_proto" ||
    helper === "skb_change_tail" ||
    helper === "skb_change_head" ||
    helper === "skb_change_type" ||
    helper === "skb_vlan_push" ||
    helper === "skb_vlan_pop" ||
    helper === "l3_csum_replace" ||
    helper === "l4_csum_replace" ||
    helper === "csum_update" ||
    helper === "xdp_adjust_head" ||
    helper === "xdp_adjust_tail" ||
    helper === "xdp_adjust_meta"
  ) {
    return "packet-mutation";
  }

  if (
    helper === "redirect" ||
    helper === "redirect_map" ||
    helper === "clone_redirect" ||
    helper === "skb_redirect_map" ||
    helper === "skb_redirect_hash" ||
    helper === "sk_redirect_map" ||
    helper === "sk_redirect_hash" ||
    helper === "msg_redirect_map" ||
    helper === "msg_redirect_hash" ||
    helper === "sk_assign"
  ) {
    return "redirect-helper";
  }

  if (
    helper === "perf_event_output" ||
    helper === "ringbuf_output" ||
    helper === "ringbuf_submit" ||
    helper === "ringbuf_discard" ||
    helper === "skb_output" ||
    helper === "trace_printk" ||
    helper === "seq_printf" ||
    helper === "seq_write"
  ) {
    return "telemetry-output";
  }

  return null;
}

function directMemoryWriteKind(disasm: string): XlatedSideEffectKind | null {
  const body = disasm.trim().replace(/^\([0-9a-fA-F]+\)\s+/, "");
  const match = body.match(
    /^\*\((?:u\d+|\w+)\s+\*\)\(([rw](?:10|[0-9]))\s*[+-]\s*\d+\)\s*=/
  );
  if (!match) return null;

  // r10-relative stores are stack spills and local variables, not external side effects.
  return match[1] === "r10" || match[1] === "w10"
    ? null
    : "direct-memory-write";
}

function effectFromInsn(
  insn: XlatedInsn,
  kind: XlatedSideEffectKind,
  helper?: string
): XlatedSideEffect {
  return {
    kind,
    label: SIDE_EFFECT_LABELS[kind],
    insnIndex: insn.index,
    disasm: insn.disasm,
    helper,
    ...sourceEvidence(insn),
  };
}

function labelsForEffects(effects: XlatedSideEffect[]): string[] {
  const kinds = new Set(effects.map(effect => effect.kind));
  return SIDE_EFFECT_ORDER.filter(kind => kinds.has(kind)).map(
    kind => SIDE_EFFECT_LABELS[kind]
  );
}

export function emptySideEffectSummary(): XlatedSideEffectSummary {
  return {
    ...EMPTY_SIDE_EFFECT_SUMMARY,
    labels: [],
    effects: [],
  };
}

export function analyzeXlatedSideEffects(
  insns: XlatedInsn[]
): XlatedSideEffectSummary {
  const effects: XlatedSideEffect[] = [];

  for (const insn of insns) {
    const helper = normalizeHelperName(insn.disasm);
    const kind = helper
      ? helperKind(helper)
      : directMemoryWriteKind(insn.disasm);
    if (!kind) continue;
    effects.push(effectFromInsn(insn, kind, helper ?? undefined));
  }

  if (effects.length === 0) {
    return emptySideEffectSummary();
  }

  return {
    hasSideEffects: true,
    labels: labelsForEffects(effects),
    effects,
    hasMapWrites: effects.some(effect => effect.kind === "map-write"),
    hasDirectMemoryWrites: effects.some(
      effect => effect.kind === "direct-memory-write"
    ),
    hasPacketMutations: effects.some(
      effect => effect.kind === "packet-mutation"
    ),
    hasRedirects: effects.some(effect => effect.kind === "redirect-helper"),
    hasTelemetryOutput: effects.some(
      effect => effect.kind === "telemetry-output"
    ),
    hasTailCalls: effects.some(effect => effect.kind === "tail-call"),
    hasSocketMutations: effects.some(
      effect => effect.kind === "socket-mutation"
    ),
  };
}

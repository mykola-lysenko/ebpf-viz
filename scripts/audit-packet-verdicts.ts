#!/usr/bin/env tsx
import { execFileSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseXlatedJson } from "../server/ebpf-dump";
import { analyzeXlatedReturns } from "../server/xlated-return-analysis";
import type {
  PacketActionSemantics,
  PacketDirection,
  PacketHookFamily,
  PacketVerdict,
  ProgArrayTarget,
  RawBpfProg,
  RawCgroupEntry,
  XlatedReturnAnalysis,
  XlatedReturnExit,
} from "../shared/ebpf-types";
import { classifyPacketReturnConstant } from "../shared/packet-chain-prediction";

interface ProgramInfo {
  id: number;
  rawType: string;
  name: string;
}

export interface VerdictAuditContext {
  key: string;
  source: "tc" | "cgroup" | "raw-type";
  family: PacketHookFamily;
  direction: PacketDirection;
  attachType: string;
  summary: string;
  semantics: PacketActionSemantics;
}

export interface VerdictAuditObservation {
  id: number;
  name: string;
  rawType: string;
  context: VerdictAuditContext;
  verdicts: PacketVerdict[];
  issueReasons: string[];
  observedConstants: Array<{ value: number; exitCount: number }>;
  unknownExitReasons: Record<string, number>;
  tailCallCount: number;
}

interface VerdictAuditResult {
  input: string;
  root: string;
  dumpedProgramCount: number;
  auditedObservationCount: number;
  issueObservationCount: number;
  issueReasons: Record<string, number>;
  byFamily: Record<string, { observations: number; issues: number }>;
  byProgramType: Record<string, { observations: number; issues: number }>;
  observations: VerdictAuditObservation[];
}

const EMPTY_SEMANTICS: PacketActionSemantics = {
  pass: [],
  drop: [],
  redirect: [],
  other: [],
};

const TC_SEMANTICS: PacketActionSemantics = {
  pass: ["TC_ACT_OK (0)", "TC_ACT_UNSPEC (-1)"],
  passValues: [0, -1],
  drop: ["TC_ACT_SHOT (2)"],
  dropValues: [2],
  redirect: ["TC_ACT_REDIRECT (7)"],
  redirectValues: [7],
  other: [
    "TC_ACT_RECLASSIFY (1)",
    "TC_ACT_PIPE (3)",
    "TC_ACT_STOLEN (4)",
    "TC_ACT_QUEUED (5)",
    "TC_ACT_REPEAT (6)",
  ],
  otherValues: [1, 3, 4, 5, 6],
};

const CGROUP_ALLOW_DENY_SEMANTICS: PacketActionSemantics = {
  pass: ["1 (allow/pass)"],
  passValues: [1],
  drop: ["0 (drop/deny)"],
  dropValues: [0],
  redirect: [],
  other: [],
};

const XDP_SEMANTICS: PacketActionSemantics = {
  pass: ["XDP_PASS (2)"],
  passValues: [2],
  drop: ["XDP_ABORTED (0)", "XDP_DROP (1)"],
  dropValues: [0, 1],
  redirect: ["XDP_TX (3)", "XDP_REDIRECT (4)"],
  redirectValues: [3, 4],
  other: [],
};

const NETFILTER_SEMANTICS: PacketActionSemantics = {
  pass: ["NF_ACCEPT (1)"],
  passValues: [1],
  drop: ["NF_DROP (0)"],
  dropValues: [0],
  redirect: [],
  other: ["NF_STOLEN (2)", "NF_QUEUE (3)", "NF_REPEAT (4)"],
  otherValues: [2, 3, 4],
};

const CGROUP_SOCK_ADDR_TYPES = new Set([
  "cgroup_inet4_bind",
  "cgroup_inet6_bind",
  "cgroup_bind4",
  "cgroup_bind6",
  "cgroup_inet4_connect",
  "cgroup_inet6_connect",
  "cgroup_connect4",
  "cgroup_connect6",
  "cgroup_inet4_getpeername",
  "cgroup_inet6_getpeername",
  "cgroup_inet4_getsockname",
  "cgroup_inet6_getsockname",
  "cgroup_udp4_sendmsg",
  "cgroup_udp6_sendmsg",
  "cgroup_sendmsg4",
  "cgroup_sendmsg6",
  "cgroup_udp4_recvmsg",
  "cgroup_udp6_recvmsg",
  "cgroup_recvmsg4",
  "cgroup_recvmsg6",
]);

const CGROUP_SOCKET_SIDE_EFFECT_TYPES = new Set([
  "cgroup_inet4_post_bind",
  "cgroup_inet6_post_bind",
  "cgroup_sock_create",
  "cgroup_inet_sock_create",
  "cgroup_sock_ops",
  "cgroup_sockops",
  "cgroup_sock_release",
  "cgroup_getsockopt",
  "cgroup_setsockopt",
]);

function usage(): never {
  console.error(
    [
      "Usage:",
      "  pnpm audit:packet-verdicts -- <archive.tar.gz|extracted-dir> [--json] [--issues-only]",
      "",
      "Examples:",
      "  pnpm audit:packet-verdicts -- captures/network.tar.gz",
      "  pnpm audit:packet-verdicts -- /tmp/ebpf-viz-l3-capture --issues-only",
    ].join("\n")
  );
  process.exit(2);
}

function readJson<T>(path: string, fallback: T): T {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return fallback;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function jsonItems(path: string, keys: string[]): Record<string, unknown>[] {
  const parsed = readJson<unknown>(path, []);
  if (Array.isArray(parsed)) {
    return parsed.filter(isRecord);
  }
  if (!isRecord(parsed)) return [];
  for (const key of keys) {
    const value = parsed[key];
    if (Array.isArray(value)) return value.filter(isRecord);
  }
  const result = parsed.result;
  return Array.isArray(result) ? result.filter(isRecord) : [];
}

function findCaptureRoot(baseDir: string): string {
  const queue = [baseDir];
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const dir = queue[cursor];
    const names = readdirSync(dir);
    if (names.includes("prog-show.json") && names.includes("prog")) {
      return dir;
    }
    for (const name of names) {
      const path = join(dir, name);
      if (lstatSync(path).isDirectory()) queue.push(path);
    }
  }
  throw new Error(`Could not find collector root under ${baseDir}`);
}

function resolveCaptureRoot(inputPath: string): {
  root: string;
  cleanup: () => void;
} {
  const absolutePath = resolve(inputPath);
  if (!existsSync(absolutePath)) {
    throw new Error(`Archive or directory does not exist: ${absolutePath}`);
  }

  if (lstatSync(absolutePath).isDirectory()) {
    return { root: findCaptureRoot(absolutePath), cleanup: () => {} };
  }

  const tempDir = mkdtempSync(join(tmpdir(), "ebpf-viz-verdict-audit-"));
  execFileSync("tar", ["-xzf", absolutePath, "-C", tempDir], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  return {
    root: findCaptureRoot(tempDir),
    cleanup: () => rmSync(tempDir, { recursive: true, force: true }),
  };
}

function contextKey(context: VerdictAuditContext): string {
  return `${context.source}:${context.attachType}:${context.family}:${context.direction}`;
}

function hasModeledSemantics(semantics: PacketActionSemantics): boolean {
  return (
    (semantics.passValues?.length ?? semantics.pass.length) > 0 ||
    (semantics.dropValues?.length ?? semantics.drop.length) > 0 ||
    (semantics.redirectValues?.length ?? semantics.redirect.length) > 0 ||
    (semantics.otherValues?.length ?? semantics.other.length) > 0
  );
}

function cgroupContext(attachType: string): VerdictAuditContext {
  if (
    attachType === "cgroup_inet_ingress" ||
    attachType === "cgroup_inet_egress"
  ) {
    return {
      key: `cgroup:${attachType}`,
      source: "cgroup",
      family: "cgroup_skb",
      direction: attachType.endsWith("_ingress") ? "ingress" : "egress",
      attachType,
      summary: "cgroup_skb allow/drop packet hook",
      semantics: CGROUP_ALLOW_DENY_SEMANTICS,
    };
  }

  if (CGROUP_SOCK_ADDR_TYPES.has(attachType)) {
    return {
      key: `cgroup:${attachType}`,
      source: "cgroup",
      family: "cgroup_sock_addr",
      direction: "unknown",
      attachType,
      summary: "cgroup socket-address allow/drop hook",
      semantics: CGROUP_ALLOW_DENY_SEMANTICS,
    };
  }

  return {
    key: `cgroup:${attachType}`,
    source: "cgroup",
    family:
      CGROUP_SOCKET_SIDE_EFFECT_TYPES.has(attachType) ||
      attachType.includes("sock")
        ? "cgroup_sock"
        : "unknown",
    direction: "unknown",
    attachType,
    summary: "return-value semantics are not modeled as packet verdicts",
    semantics: EMPTY_SEMANTICS,
  };
}

function rawTypeContext(rawType: string): VerdictAuditContext | null {
  if (rawType === "sched_cls" || rawType === "sched_act") {
    return {
      key: `raw-type:${rawType}`,
      source: "raw-type",
      family: "tc",
      direction: "unknown",
      attachType: rawType,
      summary: "TC classifier/action return values",
      semantics: TC_SEMANTICS,
    };
  }
  if (rawType === "xdp") {
    return {
      key: "raw-type:xdp",
      source: "raw-type",
      family: "xdp",
      direction: "ingress",
      attachType: rawType,
      summary: "XDP return values",
      semantics: XDP_SEMANTICS,
    };
  }
  if (rawType === "netfilter") {
    return {
      key: "raw-type:netfilter",
      source: "raw-type",
      family: "netfilter",
      direction: "unknown",
      attachType: rawType,
      summary: "netfilter return values",
      semantics: NETFILTER_SEMANTICS,
    };
  }
  if (rawType === "cgroup_skb") {
    return {
      key: "raw-type:cgroup_skb",
      source: "raw-type",
      family: "cgroup_skb",
      direction: "unknown",
      attachType: rawType,
      summary: "cgroup_skb allow/drop packet hook",
      semantics: CGROUP_ALLOW_DENY_SEMANTICS,
    };
  }
  if (rawType === "cgroup_sock_addr") {
    return {
      key: "raw-type:cgroup_sock_addr",
      source: "raw-type",
      family: "cgroup_sock_addr",
      direction: "unknown",
      attachType: rawType,
      summary: "cgroup socket-address allow/drop hook",
      semantics: CGROUP_ALLOW_DENY_SEMANTICS,
    };
  }
  if (
    rawType === "cgroup_sock" ||
    rawType === "cgroup_sockopt" ||
    rawType === "sock_ops"
  ) {
    return {
      key: `raw-type:${rawType}`,
      source: "raw-type",
      family: "cgroup_sock",
      direction: "unknown",
      attachType: rawType,
      summary: "socket hook does not model return value as a packet verdict",
      semantics: EMPTY_SEMANTICS,
    };
  }
  return null;
}

function collectProgramInfo(root: string): Map<number, ProgramInfo> {
  const rawProgs = jsonItems(join(root, "prog-show.json"), [
    "programs",
    "progs",
  ]) as RawBpfProg[];
  return new Map(
    rawProgs.flatMap(prog => {
      const id = asNumber(prog.id);
      if (id === undefined) return [];
      return [
        [
          id,
          {
            id,
            rawType: asString(prog.type) ?? "unknown",
            name: asString(prog.name) ?? `prog_${id}`,
          },
        ],
      ];
    })
  );
}

function addContext(
  contextsByProgram: Map<number, Map<string, VerdictAuditContext>>,
  id: number,
  context: VerdictAuditContext
) {
  const contexts = contextsByProgram.get(id) ?? new Map();
  contexts.set(contextKey(context), context);
  contextsByProgram.set(id, contexts);
}

function collectCgroupContexts(
  root: string,
  contextsByProgram: Map<number, Map<string, VerdictAuditContext>>
) {
  const entries = [
    ...jsonItems(join(root, "cgroup-tree.json"), ["cgroups"]),
    ...jsonItems(join(root, "cgroup-tree-effective.json"), ["cgroups"]),
  ] as RawCgroupEntry[];

  for (const entry of entries) {
    for (const program of entry.programs ?? []) {
      const id = asNumber(program.id);
      const attachType = asString(program.attach_type);
      if (id === undefined || !attachType) continue;
      addContext(contextsByProgram, id, cgroupContext(attachType));
    }
  }
}

function directionFromTcFilename(file: string): PacketDirection {
  if (file.includes(".ingress.")) return "ingress";
  if (file.includes(".egress.")) return "egress";
  return "unknown";
}

function collectTcContexts(
  root: string,
  contextsByProgram: Map<number, Map<string, VerdictAuditContext>>
) {
  const tcDir = join(root, "tc");
  if (!existsSync(tcDir)) return;

  for (const file of readdirSync(tcDir)) {
    if (!file.endsWith(".json")) continue;
    const direction = directionFromTcFilename(file);
    const filters = jsonItems(join(tcDir, file), []);
    for (const filter of filters) {
      const options = isRecord(filter.options) ? filter.options : undefined;
      const prog = isRecord(options?.prog) ? options.prog : undefined;
      const id = asNumber(prog?.id);
      if (id === undefined) continue;
      addContext(contextsByProgram, id, {
        key: `tc:${file}:${direction}`,
        source: "tc",
        family: "tc",
        direction,
        attachType: direction === "unknown" ? "tc" : `clsact/${direction}`,
        summary: "TC classifier/action return values",
        semantics: TC_SEMANTICS,
      });
    }
  }
}

function collectContexts(root: string): Map<number, Map<string, VerdictAuditContext>> {
  const contextsByProgram = new Map<number, Map<string, VerdictAuditContext>>();
  collectCgroupContexts(root, contextsByProgram);
  collectTcContexts(root, contextsByProgram);
  return contextsByProgram;
}

function xlatedCandidatesForProgram(progDir: string, id: number): string[] {
  const prefix = `${id}_`;
  const files = readdirSync(progDir)
    .filter(
      file =>
        file.startsWith(prefix) &&
        (file.endsWith(".xlated-linum.json") || file.endsWith(".xlated.json"))
    )
    .sort((a, b) => {
      const aLinum = a.endsWith(".xlated-linum.json") ? 0 : 1;
      const bLinum = b.endsWith(".xlated-linum.json") ? 0 : 1;
      return aLinum - bLinum || a.localeCompare(b);
    });
  return files.map(file => join(progDir, file));
}

function collectAnalyses(root: string): Map<number, XlatedReturnAnalysis> {
  const progDir = join(root, "prog");
  if (!existsSync(progDir)) return new Map();

  const ids = new Set<number>();
  for (const file of readdirSync(progDir)) {
    const match = file.match(/^(\d+)_.*\.xlated(?:-linum)?\.json$/);
    if (match) ids.add(Number.parseInt(match[1], 10));
  }

  const analyses = new Map<number, XlatedReturnAnalysis>();
  for (const id of Array.from(ids).sort((a, b) => a - b)) {
    for (const candidate of xlatedCandidatesForProgram(progDir, id)) {
      const xlated = parseXlatedJson(readFileSync(candidate, "utf8"));
      if (xlated.length === 0) continue;
      analyses.set(id, analyzeXlatedReturns(xlated));
      break;
    }
  }
  return analyses;
}

function collectProgArrayTargets(root: string): ProgArrayTarget[] {
  const path = join(root, "tail-call-targets.tsv");
  if (!existsSync(path)) return [];

  return readFileSync(path, "utf8")
    .split(/\r?\n/)
    .flatMap((line): ProgArrayTarget[] => {
      const [mapId, slot, targetProgId, entryIndex] = line.split("\t");
      const parsed = {
        mapId: Number.parseInt(mapId ?? "", 10),
        slot: Number.parseInt(slot ?? "", 10),
        targetProgId: Number.parseInt(targetProgId ?? "", 10),
        entryIndex: Number.parseInt(entryIndex ?? "", 10),
      };
      return Object.values(parsed).every(Number.isFinite) ? [parsed] : [];
    });
}

function modeledHelperExit(
  exit: XlatedReturnExit,
  context: VerdictAuditContext
): boolean {
  const disasm = exit.assignmentDisasm ?? exit.exitDisasm;
  const body = disasm.trim().replace(/^\([0-9a-fA-F]+\)\s+/, "");
  const helper = body.match(/^call\s+(\S+)/)?.[1]
    ?.split("#")[0]
    .replace(/^bpf_/, "")
    .toLowerCase();
  return (
    context.family === "tc" &&
    (helper === "redirect" || helper === "redirect_map")
  );
}

function increment(map: Map<string, number>, key: string, amount = 1) {
  map.set(key, (map.get(key) ?? 0) + amount);
}

function uniqueVerdicts(verdicts: PacketVerdict[]): PacketVerdict[] {
  const order: PacketVerdict[] = ["drop", "redirect", "other", "unknown", "pass"];
  const seen = new Set(verdicts);
  return order.filter(verdict => seen.has(verdict));
}

function tailCallIssues(
  analysis: XlatedReturnAnalysis,
  analysesById: Map<number, XlatedReturnAnalysis>,
  progArrayTargets: ProgArrayTarget[]
): string[] {
  const issues: string[] = [];
  const tailCalls =
    analysis.tailCalls ??
    analysis.tailCallIndices.map(insnIndex => ({
      insnIndex,
      disasm: "bpf_tail_call",
    }));

  for (const tailCall of tailCalls) {
    if (tailCall.mapId === undefined || tailCall.slot === undefined) {
      issues.push("tail-call:unresolved-site");
      continue;
    }
    const target = progArrayTargets.find(
      entry => entry.mapId === tailCall.mapId && entry.slot === tailCall.slot
    );
    if (!target) {
      issues.push("tail-call:unresolved-target");
      continue;
    }
    if (!analysesById.has(target.targetProgId)) {
      issues.push("tail-call:target-analysis-missing");
    }
  }
  return issues;
}

export function auditProgramVerdict(
  analysis: XlatedReturnAnalysis | undefined,
  context: VerdictAuditContext,
  analysesById: Map<number, XlatedReturnAnalysis> = new Map(),
  progArrayTargets: ProgArrayTarget[] = []
): Pick<
  VerdictAuditObservation,
  "verdicts" | "issueReasons" | "unknownExitReasons" | "tailCallCount"
> {
  if (!analysis) {
    return {
      verdicts: ["unknown"],
      issueReasons: ["missing-analysis"],
      unknownExitReasons: {},
      tailCallCount: 0,
    };
  }

  const issueReasons = new Map<string, number>();
  const unknownExitReasons = new Map<string, number>();
  const verdicts: PacketVerdict[] = [];
  const modeledSemantics = hasModeledSemantics(context.semantics);

  if (analysis.exitCount === 0) {
    increment(issueReasons, "no-reachable-exits");
  }
  if (!modeledSemantics) {
    increment(issueReasons, "unmodeled-hook-semantics");
  }

  if (modeledSemantics) {
    for (const observed of analysis.observedConstants) {
      const verdict = classifyPacketReturnConstant(
        observed.value,
        context.semantics
      );
      verdicts.push(verdict);
      if (verdict === "unknown") {
        increment(
          issueReasons,
          `unmodeled-return-constant:${observed.value}`,
          observed.exitCount
        );
      }
    }
  }

  for (const exit of analysis.unknownExits) {
    const reason = exit.reason ?? "unknown";
    increment(unknownExitReasons, reason);
    if (modeledHelperExit(exit, context)) {
      verdicts.push("redirect");
      continue;
    }
    verdicts.push("unknown");
    increment(issueReasons, `unknown-exit:${reason}`);
  }

  for (const issue of tailCallIssues(analysis, analysesById, progArrayTargets)) {
    increment(issueReasons, issue);
    verdicts.push("unknown");
  }

  if (issueReasons.size > 0) verdicts.push("unknown");
  if (verdicts.length === 0 && analysis.exitCount > 0 && !modeledSemantics) {
    verdicts.push("unknown");
  }

  return {
    verdicts: uniqueVerdicts(verdicts.length > 0 ? verdicts : ["pass"]),
    issueReasons: Array.from(issueReasons.entries()).flatMap(([reason, count]) =>
      count > 1 ? [`${reason} (${count})`] : [reason]
    ),
    unknownExitReasons: Object.fromEntries(unknownExitReasons.entries()),
    tailCallCount: analysis.tailCallIndices.length,
  };
}

function buildObservations(
  root: string,
  analysesById: Map<number, XlatedReturnAnalysis>,
  progArrayTargets: ProgArrayTarget[]
): VerdictAuditObservation[] {
  const programs = collectProgramInfo(root);
  const contextsByProgram = collectContexts(root);
  const observations: VerdictAuditObservation[] = [];

  for (const [id, analysis] of Array.from(analysesById.entries()).sort(
    ([a], [b]) => a - b
  )) {
    const meta = programs.get(id) ?? {
      id,
      rawType: "unknown",
      name: `prog_${id}`,
    };
    const contexts = contextsByProgram.get(id);
    const auditContexts =
      contexts && contexts.size > 0
        ? Array.from(contexts.values())
        : rawTypeContext(meta.rawType)
          ? [rawTypeContext(meta.rawType)!]
          : [];

    for (const context of auditContexts) {
      const verdict = auditProgramVerdict(
        analysis,
        context,
        analysesById,
        progArrayTargets
      );
      observations.push({
        id,
        name: meta.name,
        rawType: meta.rawType,
        context,
        observedConstants: analysis.observedConstants,
        ...verdict,
      });
    }
  }

  return observations;
}

function mapToObject(map: Map<string, number>): Record<string, number> {
  return Object.fromEntries(
    Array.from(map.entries()).sort(([a], [b]) => a.localeCompare(b))
  );
}

function summarize(
  input: string,
  root: string,
  dumpedProgramCount: number,
  observations: VerdictAuditObservation[]
): VerdictAuditResult {
  const issueReasons = new Map<string, number>();
  const byFamily = new Map<string, { observations: number; issues: number }>();
  const byProgramType = new Map<
    string,
    { observations: number; issues: number }
  >();

  for (const observation of observations) {
    const hasIssue = observation.issueReasons.length > 0;
    const familySummary = byFamily.get(observation.context.family) ?? {
      observations: 0,
      issues: 0,
    };
    familySummary.observations += 1;
    if (hasIssue) familySummary.issues += 1;
    byFamily.set(observation.context.family, familySummary);

    const typeSummary = byProgramType.get(observation.rawType) ?? {
      observations: 0,
      issues: 0,
    };
    typeSummary.observations += 1;
    if (hasIssue) typeSummary.issues += 1;
    byProgramType.set(observation.rawType, typeSummary);

    for (const reason of observation.issueReasons) {
      increment(issueReasons, reason);
    }
  }

  return {
    input,
    root,
    dumpedProgramCount,
    auditedObservationCount: observations.length,
    issueObservationCount: observations.filter(
      observation => observation.issueReasons.length > 0
    ).length,
    issueReasons: mapToObject(issueReasons),
    byFamily: Object.fromEntries(byFamily.entries()),
    byProgramType: Object.fromEntries(byProgramType.entries()),
    observations,
  };
}

function constantsText(
  constants: Array<{ value: number; exitCount: number }>
): string {
  return constants.length > 0
    ? constants
        .map(
          constant =>
            `${constant.value}:${constant.exitCount} exit${constant.exitCount === 1 ? "" : "s"}`
        )
        .join(", ")
    : "none";
}

function printTextReport(result: VerdictAuditResult, issuesOnly: boolean) {
  console.log("Packet Verdict Audit");
  console.log(`Input: ${result.input}`);
  console.log(`Root: ${result.root}`);
  console.log(`Dumped programs with xlated bytecode: ${result.dumpedProgramCount}`);
  console.log(`Audited packet observations: ${result.auditedObservationCount}`);
  console.log(`Observations with issues: ${result.issueObservationCount}`);
  if (result.dumpedProgramCount === 0) {
    console.log("");
    console.log(
      "No xlated program dumps were found. Re-run the collector with PROFILE=network, cgroup, or all and INCLUDE_XLATED=1."
    );
    return;
  }
  console.log("");

  console.log("Issue Reasons");
  const issueEntries = Object.entries(result.issueReasons);
  if (issueEntries.length === 0) {
    console.log("  none");
  } else {
    for (const [reason, count] of issueEntries) {
      console.log(`  ${reason}: ${count}`);
    }
  }
  console.log("");

  console.log("By Hook Family");
  for (const [family, summary] of Object.entries(result.byFamily).sort()) {
    console.log(
      `  ${family}: observations=${summary.observations}, issues=${summary.issues}`
    );
  }
  console.log("");

  const observations = issuesOnly
    ? result.observations.filter(observation => observation.issueReasons.length > 0)
    : result.observations;
  console.log(issuesOnly ? "Issue Examples" : "Observations");
  for (const observation of observations.slice(0, 40)) {
    console.log(
      [
        `  #${observation.id}`,
        observation.name,
        `type=${observation.rawType}`,
        `hook=${observation.context.attachType}`,
        `family=${observation.context.family}`,
        `verdicts=${observation.verdicts.join(",")}`,
        `constants=[${constantsText(observation.observedConstants)}]`,
        `issues=${observation.issueReasons.join("; ") || "none"}`,
      ].join("  ")
    );
  }
  if (observations.length > 40) {
    console.log(`  ... ${observations.length - 40} more`);
  }
}

function runAudit(input: string): VerdictAuditResult {
  const { root, cleanup } = resolveCaptureRoot(input);
  try {
    const analysesById = collectAnalyses(root);
    const progArrayTargets = collectProgArrayTargets(root);
    const observations = buildObservations(root, analysesById, progArrayTargets);
    return summarize(input, root, analysesById.size, observations);
  } finally {
    cleanup();
  }
}

function main() {
  const args = process.argv.slice(2).filter(arg => arg !== "--");
  const json = args.includes("--json");
  const issuesOnly = args.includes("--issues-only");
  const positional = args.filter(arg => arg !== "--json" && arg !== "--issues-only");
  if (positional.includes("-h") || positional.includes("--help")) usage();
  if (positional.length !== 1) usage();

  const result = runAudit(positional[0]);
  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printTextReport(result, issuesOnly);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}

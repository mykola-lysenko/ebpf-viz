import type { BpfMap, BpfProgram } from "../../../shared/ebpf-types";

export type StructOpsKind =
  | "tcp_congestion_ops"
  | "sched_ext_ops"
  | "unknown";

export interface StructOpsProgramDescriptor {
  kind: StructOpsKind;
  kindLabel: string;
  kindDescription: string;
  networkRelated: boolean;
  algorithm: string;
  callback: string;
  callbackLabel: string;
  mapNames: string[];
}

export interface StructOpsCallbackSummary<
  TProgram extends StructOpsProgram = StructOpsProgram,
> {
  program: TProgram;
  descriptor: StructOpsProgramDescriptor;
  callsPerSec: number;
}

export interface StructOpsAlgorithmSummary<
  TProgram extends StructOpsProgram = StructOpsProgram,
> {
  kind: StructOpsKind;
  kindLabel: string;
  kindDescription: string;
  networkRelated: boolean;
  algorithm: string;
  count: number;
  activeCount: number;
  totalMemlock: number;
  totalCallsPerSec: number;
  callbacks: StructOpsCallbackSummary<TProgram>[];
  examples: string[];
  mapNames: string[];
}

export interface StructOpsKindSummary<
  TProgram extends StructOpsProgram = StructOpsProgram,
> {
  kind: StructOpsKind;
  label: string;
  description: string;
  networkRelated: boolean;
  count: number;
  activeCount: number;
  totalMemlock: number;
  totalCallsPerSec: number;
  algorithms: StructOpsAlgorithmSummary<TProgram>[];
}

export type StructOpsProgram = Pick<
  BpfProgram,
  "id" | "name" | "memlock" | "btfId"
>;

type StructOpsMap = Pick<BpfMap, "type" | "rawType" | "name" | "btfId">;

const KNOWN_TCP_ALGORITHMS: Array<[RegExp, string]> = [
  [/\bd2tcp\b/, "D2TCP"],
  [/\bdctcp\b/, "DCTCP"],
  [/\bcubic\b/, "CUBIC"],
  [/\bbbr\b/, "BBR"],
  [/\breno\b/, "TCP Reno"],
];

const TCP_CONGESTION_CALLBACKS = new Set([
  "acked",
  "cong_avoid",
  "cong_control",
  "cwnd_event",
  "cwnd_undo",
  "in_ack_event",
  "min_tso_segs",
  "pkts_acked",
  "ssthresh",
  "undo_cwnd",
  "update_alpha",
]);

const STRUCT_OPS_KIND_META: Record<
  StructOpsKind,
  {
    label: string;
    description: string;
    networkRelated: boolean;
  }
> = {
  tcp_congestion_ops: {
    label: "TCP congestion control",
    description:
      "TCP congestion-control struct_ops callbacks; affects socket pacing and congestion-window behavior, not packet classifier verdicts.",
    networkRelated: true,
  },
  sched_ext_ops: {
    label: "Scheduler extension",
    description: "sched_ext struct_ops callbacks for CPU scheduler behavior.",
    networkRelated: false,
  },
  unknown: {
    label: "Other struct_ops",
    description: "Kernel struct_ops callbacks whose registered struct kind is not inferred yet.",
    networkRelated: false,
  },
};

function normalizeName(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function titleCase(value: string): string {
  return value
    .split(/[_\-\s]+/)
    .filter(Boolean)
    .map(part => part[0].toUpperCase() + part.slice(1))
    .join(" ");
}

function compactName(value: string): string {
  return normalizeName(value).replace(/_/g, " ");
}

function structOpsMapsByBtfId(maps: StructOpsMap[]): Map<number, string[]> {
  const byBtfId = new Map<number, string[]>();

  for (const map of maps) {
    if (
      map.btfId == null ||
      (map.type !== "struct_ops" && map.rawType !== "struct_ops")
    ) {
      continue;
    }
    const names = byBtfId.get(map.btfId) ?? [];
    if (!names.includes(map.name)) names.push(map.name);
    byBtfId.set(map.btfId, names);
  }

  return byBtfId;
}

function inferTcpAlgorithm(
  programName: string,
  mapNames: string[]
): string | null {
  for (const name of [...mapNames, programName]) {
    const normalized = compactName(name);
    for (const [pattern, label] of KNOWN_TCP_ALGORITHMS) {
      if (pattern.test(normalized)) return label;
    }
  }

  const mapName = mapNames.find(name => {
    const normalized = normalizeName(name);
    return normalized.includes("tcp");
  });
  if (mapName) {
    const candidate = normalizeName(mapName)
      .replace(/^(?:bpf_)?(?:struct_ops_)?/, "")
      .replace(/^(?:ned_)?tcp_/, "")
      .replace(/_?ops$/, "")
      .replace(/[0-9]+$/, "");

    return candidate ? titleCase(candidate).toUpperCase() : "TCP";
  }

  return normalizeName(programName).startsWith("tcp_") ? "TCP" : null;
}

function inferCallback(programName: string, algorithm: string): string {
  let normalized = normalizeName(programName);
  if (!normalized) return "callback";

  const algorithmToken = normalizeName(algorithm.replace(/^TCP /, ""));
  const prefixes = [
    "tcp_reno_",
    "tcp_",
    algorithmToken ? `${algorithmToken}_` : "",
  ].filter(Boolean);

  for (const prefix of prefixes) {
    if (normalized.startsWith(prefix)) {
      normalized = normalized.slice(prefix.length);
      break;
    }
  }

  return normalized || "callback";
}

function inferKind(
  programName: string,
  mapNames: string[],
  callback: string,
  algorithm: string | null
): StructOpsKind {
  const names = [programName, ...mapNames].map(normalizeName);
  if (
    algorithm ||
    names.some(name => name.includes("tcp")) ||
    TCP_CONGESTION_CALLBACKS.has(callback)
  ) {
    return "tcp_congestion_ops";
  }
  if (names.some(name => name.startsWith("scx_") || name.includes("sched_ext"))) {
    return "sched_ext_ops";
  }
  return "unknown";
}

export function describeStructOpsProgram(
  program: StructOpsProgram,
  maps: StructOpsMap[] = []
): StructOpsProgramDescriptor {
  const byBtfId = structOpsMapsByBtfId(maps);
  const mapNames = program.btfId == null ? [] : byBtfId.get(program.btfId) ?? [];
  const inferredAlgorithm = inferTcpAlgorithm(program.name, mapNames);
  const callback = inferCallback(program.name, inferredAlgorithm ?? "Unknown");
  const kind = inferKind(program.name, mapNames, callback, inferredAlgorithm);
  const meta = STRUCT_OPS_KIND_META[kind];

  return {
    kind,
    kindLabel: meta.label,
    kindDescription: meta.description,
    networkRelated: meta.networkRelated,
    algorithm:
      kind === "tcp_congestion_ops" ? (inferredAlgorithm ?? "TCP") : "Unknown",
    callback,
    callbackLabel: callback.replace(/_/g, " "),
    mapNames,
  };
}

export function buildStructOpsKindSummaries<
  TProgram extends StructOpsProgram,
>(
  programs: TProgram[],
  maps: StructOpsMap[] = [],
  callsPerSecById: Map<number, number> = new Map()
): StructOpsKindSummary<TProgram>[] {
  const kinds = new Map<StructOpsKind, StructOpsKindSummary<TProgram>>();
  const algorithms = new Map<string, StructOpsAlgorithmSummary<TProgram>>();

  for (const program of programs) {
    const descriptor = describeStructOpsProgram(program, maps);
    const kindMeta = STRUCT_OPS_KIND_META[descriptor.kind];
    const kind =
      kinds.get(descriptor.kind) ??
      ({
        kind: descriptor.kind,
        label: kindMeta.label,
        description: kindMeta.description,
        networkRelated: kindMeta.networkRelated,
        count: 0,
        activeCount: 0,
        totalMemlock: 0,
        totalCallsPerSec: 0,
        algorithms: [],
      } satisfies StructOpsKindSummary<TProgram>);
    const algorithmKey = `${descriptor.kind}:${descriptor.algorithm}`;
    const algorithm =
      algorithms.get(algorithmKey) ??
      ({
        kind: descriptor.kind,
        kindLabel: kindMeta.label,
        kindDescription: kindMeta.description,
        networkRelated: kindMeta.networkRelated,
        algorithm: descriptor.algorithm,
        count: 0,
        activeCount: 0,
        totalMemlock: 0,
        totalCallsPerSec: 0,
        callbacks: [],
        examples: [],
        mapNames: [],
      } satisfies StructOpsAlgorithmSummary<TProgram>);
    const callsPerSec = callsPerSecById.get(program.id) ?? 0;

    kind.count += 1;
    kind.totalMemlock += program.memlock;
    kind.totalCallsPerSec += callsPerSec;
    if (callsPerSec > 0) kind.activeCount += 1;

    algorithm.count += 1;
    algorithm.totalMemlock += program.memlock;
    algorithm.totalCallsPerSec += callsPerSec;
    if (callsPerSec > 0) algorithm.activeCount += 1;
    if (
      !algorithm.examples.includes(descriptor.callbackLabel) &&
      algorithm.examples.length < 4
    ) {
      algorithm.examples.push(descriptor.callbackLabel);
    }
    for (const mapName of descriptor.mapNames) {
      if (!algorithm.mapNames.includes(mapName)) algorithm.mapNames.push(mapName);
    }
    algorithm.callbacks.push({ program, descriptor, callsPerSec });

    algorithms.set(algorithmKey, algorithm);
    kinds.set(descriptor.kind, kind);
  }

  const sortedAlgorithms = Array.from(algorithms.values()).sort(
    (a, b) =>
      b.totalCallsPerSec - a.totalCallsPerSec ||
      b.count - a.count ||
      b.totalMemlock - a.totalMemlock ||
      a.algorithm.localeCompare(b.algorithm)
  );

  for (const algorithm of sortedAlgorithms) {
    const kind = kinds.get(algorithm.kind);
    if (kind) kind.algorithms.push(algorithm);
    algorithm.callbacks.sort(
      (a, b) =>
        b.callsPerSec - a.callsPerSec ||
        b.program.memlock - a.program.memlock ||
        a.descriptor.callback.localeCompare(b.descriptor.callback)
    );
  }

  return Array.from(kinds.values()).sort(
    (a, b) =>
      Number(b.networkRelated) - Number(a.networkRelated) ||
      b.totalCallsPerSec - a.totalCallsPerSec ||
      b.count - a.count ||
      b.totalMemlock - a.totalMemlock ||
      a.label.localeCompare(b.label)
  );
}

export function buildTcpCongestionControlSummaries<
  TProgram extends StructOpsProgram,
>(
  programs: TProgram[],
  maps: StructOpsMap[] = [],
  callsPerSecById: Map<number, number> = new Map()
): StructOpsAlgorithmSummary<TProgram>[] {
  return buildStructOpsKindSummaries(programs, maps, callsPerSecById).flatMap(
    kind => (kind.kind === "tcp_congestion_ops" ? kind.algorithms : [])
  );
}

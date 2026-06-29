import type { BpfProgram } from "../../../shared/ebpf-types";

export interface StructOpsGroupSummary {
  family: string;
  count: number;
  totalMemlock: number;
  totalCallsPerSec: number;
  examples: string[];
}

type StructOpsProgram = Pick<BpfProgram, "id" | "name" | "memlock">;

function titleCase(value: string): string {
  return value
    .split(/[_\-\s]+/)
    .filter(Boolean)
    .map(part => part[0].toUpperCase() + part.slice(1))
    .join(" ");
}

export function structOpsProgramFamily(name: string): string {
  const normalized = name.trim().toLowerCase();
  if (!normalized) return "Unknown callbacks";

  if (normalized.includes("dctcp")) return "DCTCP";
  if (normalized.includes("reno")) return "TCP Reno";
  if (normalized.includes("cubic")) return "CUBIC";
  if (normalized.includes("bbr")) return "BBR";
  if (normalized.startsWith("tcp_")) return "TCP";

  if (
    /\b(?:cong|cwnd|ssthresh|undo|acked|alpha)\b/.test(
      normalized.replace(/_/g, " ")
    )
  ) {
    return "Congestion control";
  }

  if (/\b(?:init|release|set state|state)\b/.test(normalized.replace(/_/g, " "))) {
    return "Lifecycle/state";
  }

  const prefix = normalized.split(/[_\-.]/)[0];
  return prefix ? titleCase(prefix) : "Other callbacks";
}

export function buildStructOpsGroups(
  programs: StructOpsProgram[],
  callsPerSecById: Map<number, number> = new Map()
): StructOpsGroupSummary[] {
  const groups = new Map<string, StructOpsGroupSummary>();

  for (const program of programs) {
    const family = structOpsProgramFamily(program.name);
    const group =
      groups.get(family) ??
      ({
        family,
        count: 0,
        totalMemlock: 0,
        totalCallsPerSec: 0,
        examples: [],
      } satisfies StructOpsGroupSummary);

    group.count += 1;
    group.totalMemlock += program.memlock;
    group.totalCallsPerSec += callsPerSecById.get(program.id) ?? 0;
    if (!group.examples.includes(program.name) && group.examples.length < 3) {
      group.examples.push(program.name);
    }
    groups.set(family, group);
  }

  return Array.from(groups.values()).sort(
    (a, b) =>
      b.totalCallsPerSec - a.totalCallsPerSec ||
      b.count - a.count ||
      b.totalMemlock - a.totalMemlock ||
      a.family.localeCompare(b.family)
  );
}

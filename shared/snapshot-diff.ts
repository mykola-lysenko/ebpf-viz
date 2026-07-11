// Pure diff between two captured snapshots. Shared (no DOM/server deps) so it
// is unit-testable and could run server-side later.
//
// Identity: programs are matched by name + bytecode tag (so the same program
// reloaded with a new kernel id still matches, while genuinely new bytecode
// shows as removed+added — it IS a different program). Maps are matched by
// name + type (maps carry no bytecode hash). Multiple instances that share a
// key (clones) are paired by ascending id; extras become added/removed.

import type { BpfProgram, BpfMap, EbpfSnapshot } from "./ebpf-types";

export interface DiffEntry {
  /** Match key (name#tag or name#type). */
  key: string;
  name: string;
  /** rawType, for display. */
  type: string;
  /** Representative kernel id (from B for added/changed, from A for removed). */
  id: number;
  /** Human-readable field changes; present only on "changed" entries. */
  changes?: string[];
}

export interface SnapshotDiffSection {
  added: DiffEntry[];
  removed: DiffEntry[];
  changed: DiffEntry[];
}

export interface SnapshotDiff {
  programs: SnapshotDiffSection;
  maps: SnapshotDiffSection;
  summary: {
    programsAdded: number;
    programsRemoved: number;
    programsChanged: number;
    mapsAdded: number;
    mapsRemoved: number;
    mapsChanged: number;
    /** True when nothing differs. */
    identical: boolean;
  };
}

function programKey(p: BpfProgram): string {
  return `${p.name}#${p.tag}`;
}

function mapKey(m: BpfMap): string {
  return `${m.name}#${m.rawType}`;
}

function groupBy<T>(items: T[], key: (t: T) => string): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    const list = groups.get(k);
    if (list) list.push(item);
    else groups.set(k, [item]);
  }
  return groups;
}

/** Sorted, deduped attachment fingerprints — the netns suffix is kept because
 *  a program moving namespaces IS a meaningful change. */
function attachmentSet(p: BpfProgram): string[] {
  return Array.from(new Set(p.attachments.map(a => `${a.kind}:${a.detail}`))).sort();
}

function setDiff(a: string[], b: string[]): { added: string[]; removed: string[] } {
  const bSet = new Set(b);
  const aSet = new Set(a);
  return {
    added: b.filter(x => !aSet.has(x)),
    removed: a.filter(x => !bSet.has(x)),
  };
}

/** Field-level changes between two instances of the same program. */
function programChanges(a: BpfProgram, b: BpfProgram): string[] {
  const changes: string[] = [];

  const att = setDiff(attachmentSet(a), attachmentSet(b));
  if (att.added.length) changes.push(`+${att.added.length} attachment${att.added.length === 1 ? "" : "s"}`);
  if (att.removed.length) changes.push(`-${att.removed.length} attachment${att.removed.length === 1 ? "" : "s"}`);

  if (a.mapIds.length !== b.mapIds.length) {
    changes.push(`maps ${a.mapIds.length} → ${b.mapIds.length}`);
  }
  if (a.orphaned !== b.orphaned) {
    changes.push(b.orphaned ? "became orphaned" : "no longer orphaned");
  }
  const aOwner = ownerLabel(a);
  const bOwner = ownerLabel(b);
  if (aOwner !== bOwner) changes.push(`owner ${aOwner} → ${bOwner}`);

  const aPins = new Set(a.pinnedPaths ?? []);
  const bPins = new Set(b.pinnedPaths ?? []);
  if (aPins.size !== bPins.size) changes.push(`pins ${aPins.size} → ${bPins.size}`);

  return changes;
}

function ownerLabel(p: BpfProgram): string {
  if (p.pids && p.pids.length > 0) return p.pids.map(x => x.comm).join(",");
  return p.ownerHint?.label ?? "none";
}

function mapChanges(a: BpfMap, b: BpfMap): string[] {
  const changes: string[] = [];
  if (a.maxEntries !== b.maxEntries) changes.push(`max entries ${a.maxEntries} → ${b.maxEntries}`);
  if (a.bytesValue !== b.bytesValue) changes.push(`value ${a.bytesValue}B → ${b.bytesValue}B`);
  if (a.bytesKey !== b.bytesKey) changes.push(`key ${a.bytesKey}B → ${b.bytesKey}B`);
  if (a.frozen !== b.frozen) changes.push(b.frozen ? "became frozen" : "no longer frozen");
  if (a.usedByProgIds.length !== b.usedByProgIds.length) {
    changes.push(`used by ${a.usedByProgIds.length} → ${b.usedByProgIds.length} progs`);
  }
  const aPins = new Set(a.pinnedPaths);
  const bPins = new Set(b.pinnedPaths);
  if (aPins.size !== bPins.size) changes.push(`pins ${aPins.size} → ${bPins.size}`);
  return changes;
}

/** Diff one item category. `a`/`b` are grouped by key; instances sharing a key
 *  are paired by ascending id, extras become added/removed. */
function diffSection<T extends { id: number }>(
  aGroups: Map<string, T[]>,
  bGroups: Map<string, T[]>,
  makeEntry: (item: T) => Omit<DiffEntry, "changes">,
  compare: (a: T, b: T) => string[]
): SnapshotDiffSection {
  const section: SnapshotDiffSection = { added: [], removed: [], changed: [] };
  const keys = new Set([...Array.from(aGroups.keys()), ...Array.from(bGroups.keys())]);

  for (const key of Array.from(keys)) {
    const aItems = [...(aGroups.get(key) ?? [])].sort((x, y) => x.id - y.id);
    const bItems = [...(bGroups.get(key) ?? [])].sort((x, y) => x.id - y.id);
    const paired = Math.min(aItems.length, bItems.length);

    for (let i = 0; i < paired; i++) {
      const changes = compare(aItems[i], bItems[i]);
      if (changes.length > 0) {
        section.changed.push({ ...makeEntry(bItems[i]), changes });
      }
    }
    for (let i = paired; i < aItems.length; i++) {
      section.removed.push(makeEntry(aItems[i]));
    }
    for (let i = paired; i < bItems.length; i++) {
      section.added.push(makeEntry(bItems[i]));
    }
  }

  const byName = (x: DiffEntry, y: DiffEntry) => x.name.localeCompare(y.name);
  section.added.sort(byName);
  section.removed.sort(byName);
  section.changed.sort(byName);
  return section;
}

export function diffSnapshots(a: EbpfSnapshot, b: EbpfSnapshot, aMaps: BpfMap[] = [], bMaps: BpfMap[] = []): SnapshotDiff {
  const programs = diffSection(
    groupBy(a.programs, programKey),
    groupBy(b.programs, programKey),
    p => ({ key: programKey(p), name: p.name || `prog_${p.id}`, type: p.rawType, id: p.id }),
    programChanges
  );
  const maps = diffSection(
    groupBy(aMaps, mapKey),
    groupBy(bMaps, mapKey),
    m => ({ key: mapKey(m), name: m.name || `map_${m.id}`, type: m.rawType, id: m.id }),
    mapChanges
  );

  const summary = {
    programsAdded: programs.added.length,
    programsRemoved: programs.removed.length,
    programsChanged: programs.changed.length,
    mapsAdded: maps.added.length,
    mapsRemoved: maps.removed.length,
    mapsChanged: maps.changed.length,
    identical: false,
  };
  summary.identical =
    summary.programsAdded === 0 &&
    summary.programsRemoved === 0 &&
    summary.programsChanged === 0 &&
    summary.mapsAdded === 0 &&
    summary.mapsRemoved === 0 &&
    summary.mapsChanged === 0;

  return { programs, maps, summary };
}

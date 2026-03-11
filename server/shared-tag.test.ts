/**
 * Tests for shared-bytecode highlighting logic:
 * - tagCount computation (Option A: Programs table clone badge)
 * - collectTagSiblings (Option C: Cgroups tree colour dots)
 */
import { describe, it, expect } from "vitest";
import type { BpfProgram, CgroupNode } from "../shared/ebpf-types";

// ── Helpers mirrored from the client (pure functions, no React) ──────────────

function buildTagCount(programs: BpfProgram[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const p of programs) m.set(p.tag, (m.get(p.tag) ?? 0) + 1);
  return m;
}

function collectTagSiblings(
  nodes: CgroupNode[],
  acc: Map<string, Array<{ id: number; cgroupPath: string }>>
) {
  for (const node of nodes) {
    for (const p of node.programs) {
      const entry = acc.get(p.tag) ?? [];
      if (!entry.some(e => e.id === p.id && e.cgroupPath === node.path)) {
        entry.push({ id: p.id, cgroupPath: node.path });
      }
      acc.set(p.tag, entry);
    }
    collectTagSiblings(node.children, acc);
  }
}

function buildSharedTagMap(
  nodes: CgroupNode[]
): Map<string, Array<{ id: number; cgroupPath: string }>> {
  const raw = new Map<string, Array<{ id: number; cgroupPath: string }>>();
  collectTagSiblings(nodes, raw);
  const shared = new Map<string, Array<{ id: number; cgroupPath: string }>>();
  Array.from(raw.entries()).forEach(([tag, entries]) => {
    if (entries.length > 1) shared.set(tag, entries);
  });
  return shared;
}

const SHARED_TAG_PALETTE = [
  "#f59e0b", "#10b981", "#f43f5e", "#8b5cf6", "#06b6d4",
  "#f97316", "#84cc16", "#ec4899", "#14b8a6", "#a855f7",
];

function buildTagColorMap(sharedTagMap: Map<string, unknown>): Map<string, string> {
  const tagColorMap = new Map<string, string>();
  const sortedTags = Array.from(sharedTagMap.keys()).sort();
  sortedTags.forEach((tag, i) => {
    tagColorMap.set(tag, SHARED_TAG_PALETTE[i % SHARED_TAG_PALETTE.length]);
  });
  return tagColorMap;
}

// ── Minimal BpfProgram factory ───────────────────────────────────────────────

function prog(id: number, tag: string): BpfProgram {
  return {
    id,
    name: `prog_${id}`,
    type: "cgroup_skb",
    rawType: "cgroup_skb",
    tag,
    gplCompatible: true,
    jited: false,
    bytesXlated: 64,
    loadedAt: 0,
    orphaned: false,
    attachments: [],
    mapIds: [],
  };
}

function cgroupNode(
  path: string,
  programs: BpfProgram[],
  children: CgroupNode[] = []
): CgroupNode {
  const parts = path.replace("/sys/fs/cgroup/", "").split("/");
  return {
    path,
    name: parts[parts.length - 1] || "/",
    depth: parts.length - 1,
    programs,
    children,
  };
}

// ── Option A: tagCount ───────────────────────────────────────────────────────

describe("buildTagCount", () => {
  it("returns count 1 for unique tags", () => {
    const progs = [prog(1, "aaa"), prog(2, "bbb"), prog(3, "ccc")];
    const m = buildTagCount(progs);
    expect(m.get("aaa")).toBe(1);
    expect(m.get("bbb")).toBe(1);
    expect(m.get("ccc")).toBe(1);
  });

  it("counts shared tags correctly", () => {
    const SHARED = "6deef7357e7b4530";
    const progs = [
      prog(51, SHARED),
      prog(52, SHARED),
      prog(54, SHARED),
      prog(55, SHARED),
      prog(413, SHARED),
      prog(414, SHARED),
      prog(49, "ee0e253c78993a24"),
    ];
    const m = buildTagCount(progs);
    expect(m.get(SHARED)).toBe(6);
    expect(m.get("ee0e253c78993a24")).toBe(1);
  });

  it("returns empty map for empty program list", () => {
    expect(buildTagCount([]).size).toBe(0);
  });

  it("badge should show for count > 1 only", () => {
    const progs = [prog(1, "aaa"), prog(2, "aaa"), prog(3, "bbb")];
    const m = buildTagCount(progs);
    expect((m.get("aaa") ?? 1) > 1).toBe(true);
    expect((m.get("bbb") ?? 1) > 1).toBe(false);
  });
});

// ── Option C: collectTagSiblings ─────────────────────────────────────────────

describe("collectTagSiblings", () => {
  const SHARED = "6deef7357e7b4530";

  it("collects siblings from flat list of cgroup nodes", () => {
    const nodes = [
      cgroupNode("/sys/fs/cgroup/system.slice/systemd-logind.service", [
        prog(51, SHARED),
        prog(52, SHARED),
      ]),
      cgroupNode("/sys/fs/cgroup/system.slice/systemd-udevd.service", [
        prog(54, SHARED),
        prog(55, SHARED),
      ]),
    ];
    const acc = new Map<string, Array<{ id: number; cgroupPath: string }>>();
    collectTagSiblings(nodes, acc);
    const entries = acc.get(SHARED)!;
    expect(entries).toHaveLength(4);
    expect(entries.map(e => e.id).sort()).toEqual([51, 52, 54, 55]);
  });

  it("collects siblings from nested cgroup tree", () => {
    const child1 = cgroupNode("/sys/fs/cgroup/system.slice/svc-a.service", [prog(10, SHARED)]);
    const child2 = cgroupNode("/sys/fs/cgroup/system.slice/svc-b.service", [prog(11, SHARED)]);
    const parent = cgroupNode("/sys/fs/cgroup/system.slice", [], [child1, child2]);
    const acc = new Map<string, Array<{ id: number; cgroupPath: string }>>();
    collectTagSiblings([parent], acc);
    const entries = acc.get(SHARED)!;
    expect(entries).toHaveLength(2);
    expect(entries.map(e => e.id).sort()).toEqual([10, 11]);
  });

  it("does not duplicate entries for the same id+path", () => {
    const node = cgroupNode("/sys/fs/cgroup/system.slice/svc.service", [prog(1, SHARED)]);
    const acc = new Map<string, Array<{ id: number; cgroupPath: string }>>();
    // Call twice to simulate re-render
    collectTagSiblings([node], acc);
    collectTagSiblings([node], acc);
    expect(acc.get(SHARED)!).toHaveLength(1);
  });

  it("keeps unique tags separate", () => {
    const nodes = [
      cgroupNode("/sys/fs/cgroup/a.service", [prog(1, "tag_aaa"), prog(2, "tag_bbb")]),
      cgroupNode("/sys/fs/cgroup/b.service", [prog(3, "tag_aaa")]),
    ];
    const acc = new Map<string, Array<{ id: number; cgroupPath: string }>>();
    collectTagSiblings(nodes, acc);
    expect(acc.get("tag_aaa")!).toHaveLength(2);
    expect(acc.get("tag_bbb")!).toHaveLength(1);
  });
});

// ── buildSharedTagMap ────────────────────────────────────────────────────────

describe("buildSharedTagMap", () => {
  it("excludes tags that appear only once", () => {
    const nodes = [
      cgroupNode("/sys/fs/cgroup/a.service", [prog(1, "unique_tag")]),
      cgroupNode("/sys/fs/cgroup/b.service", [prog(2, "shared_tag"), prog(3, "shared_tag")]),
    ];
    const shared = buildSharedTagMap(nodes);
    expect(shared.has("unique_tag")).toBe(false);
    expect(shared.has("shared_tag")).toBe(true);
    expect(shared.get("shared_tag")!).toHaveLength(2);
  });

  it("returns empty map when no tags are shared", () => {
    const nodes = [
      cgroupNode("/sys/fs/cgroup/a.service", [prog(1, "tag1")]),
      cgroupNode("/sys/fs/cgroup/b.service", [prog(2, "tag2")]),
    ];
    expect(buildSharedTagMap(nodes).size).toBe(0);
  });

  it("handles empty cgroup tree", () => {
    expect(buildSharedTagMap([]).size).toBe(0);
  });
});

// ── buildTagColorMap ─────────────────────────────────────────────────────────

describe("buildTagColorMap", () => {
  it("assigns deterministic colours sorted by tag string", () => {
    const shared = new Map([
      ["zzz_tag", [{ id: 1, cgroupPath: "/a" }]],
      ["aaa_tag", [{ id: 2, cgroupPath: "/b" }]],
    ]);
    const colorMap = buildTagColorMap(shared);
    // "aaa_tag" sorts first → gets palette[0], "zzz_tag" → palette[1]
    expect(colorMap.get("aaa_tag")).toBe(SHARED_TAG_PALETTE[0]);
    expect(colorMap.get("zzz_tag")).toBe(SHARED_TAG_PALETTE[1]);
  });

  it("wraps around the palette for more than 10 shared tags", () => {
    const shared = new Map<string, unknown>();
    for (let i = 0; i < 12; i++) shared.set(`tag_${String(i).padStart(2, "0")}`, []);
    const colorMap = buildTagColorMap(shared as Map<string, Array<{ id: number; cgroupPath: string }>>);
    expect(colorMap.get("tag_10")).toBe(SHARED_TAG_PALETTE[0]);
    expect(colorMap.get("tag_11")).toBe(SHARED_TAG_PALETTE[1]);
  });

  it("returns empty map for no shared tags", () => {
    expect(buildTagColorMap(new Map()).size).toBe(0);
  });
});

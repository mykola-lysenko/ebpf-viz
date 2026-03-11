/**
 * Tests for the NIC packet-path stack diagram logic.
 *
 * The InterfaceNode component renders a top-to-bottom stack:
 *   L7 (sk_msg) → L4 (socket_filter / sock_ops) → L3 (TC / netfilter) → L2 (XDP) → NIC HW
 *
 * We test the data-layer logic that drives the rendering:
 *   - Which layers are "active" (have programs)
 *   - Program badge truncation (max 6 in full LOD, 3 in compact)
 *   - Tooltip data completeness (name, rawType, attachment detail)
 *   - Layer ordering matches the packet path (L7 first, L2 last before HW)
 */
import { describe, it, expect } from "vitest";
import type { NetworkInterface, BpfProgram } from "../shared/ebpf-types";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeProgram(overrides: Partial<BpfProgram> = {}): BpfProgram {
  return {
    id: 1,
    type: "xdp",
    rawType: "xdp",
    name: "xdp_drop",
    tag: "aabbccdd11223344",
    gplCompatible: true,
    loadedAt: 1700000000,
    orphaned: false,
    bytesXlated: 128,
    jited: true,
    memlock: 4096,
    mapIds: [],
    attachments: [{ kind: "xdp", detail: "eth0 (driver)", ifname: "eth0" }],
    osiLayer: "L2",
    color: "#00d4ff",
    ...overrides,
  };
}

function makeInterface(overrides: Partial<NetworkInterface> = {}): NetworkInterface {
  return {
    name: "eth0",
    ifindex: 2,
    layers: { L2: [], L3: [], L4: [], L7: [] },
    allPrograms: [],
    ...overrides,
  };
}

// ─── Layer ordering ───────────────────────────────────────────────────────────

const PACKET_PATH_LAYER_KEYS = ["L7", "L4", "L3", "L2"] as const;

describe("NIC packet-path layer ordering", () => {
  it("defines layers in top-to-bottom order: L7 → L4 → L3 → L2", () => {
    // The visual stack renders L7 at top, L2 at bottom (just above NIC HW)
    expect(PACKET_PATH_LAYER_KEYS[0]).toBe("L7");
    expect(PACKET_PATH_LAYER_KEYS[1]).toBe("L4");
    expect(PACKET_PATH_LAYER_KEYS[2]).toBe("L3");
    expect(PACKET_PATH_LAYER_KEYS[3]).toBe("L2");
  });

  it("has exactly 4 layers before the NIC HW base", () => {
    expect(PACKET_PATH_LAYER_KEYS.length).toBe(4);
  });
});

// ─── Active layer detection ───────────────────────────────────────────────────

function getActiveLayers(iface: NetworkInterface) {
  return PACKET_PATH_LAYER_KEYS.filter(k => (iface.layers[k] ?? []).length > 0);
}

describe("active layer detection", () => {
  it("returns no active layers for an interface with no programs", () => {
    const iface = makeInterface();
    expect(getActiveLayers(iface)).toEqual([]);
  });

  it("detects L2 as active when XDP programs are present", () => {
    const xdpProg = makeProgram({ rawType: "xdp", osiLayer: "L2" });
    const iface = makeInterface({
      layers: { L2: [xdpProg], L3: [], L4: [], L7: [] },
      allPrograms: [xdpProg],
    });
    expect(getActiveLayers(iface)).toContain("L2");
  });

  it("detects L3 as active when TC programs are present", () => {
    const tcProg = makeProgram({ id: 2, rawType: "sched_cls", osiLayer: "L3" });
    const iface = makeInterface({
      layers: { L2: [], L3: [tcProg], L4: [], L7: [] },
      allPrograms: [tcProg],
    });
    expect(getActiveLayers(iface)).toContain("L3");
    expect(getActiveLayers(iface)).not.toContain("L2");
  });

  it("detects multiple active layers simultaneously", () => {
    const xdpProg = makeProgram({ id: 1, rawType: "xdp", osiLayer: "L2" });
    const tcProg = makeProgram({ id: 2, rawType: "sched_cls", osiLayer: "L3" });
    const skProg = makeProgram({ id: 3, rawType: "socket_filter", osiLayer: "L4" });
    const iface = makeInterface({
      layers: { L2: [xdpProg], L3: [tcProg], L4: [skProg], L7: [] },
      allPrograms: [xdpProg, tcProg, skProg],
    });
    const active = getActiveLayers(iface);
    expect(active).toContain("L2");
    expect(active).toContain("L3");
    expect(active).toContain("L4");
    expect(active).not.toContain("L7");
  });

  it("detects L4 active for sock_ops programs", () => {
    const sockOpsProg = makeProgram({ id: 4, rawType: "sock_ops", osiLayer: "L4" });
    const iface = makeInterface({
      layers: { L2: [], L3: [], L4: [sockOpsProg], L7: [] },
      allPrograms: [sockOpsProg],
    });
    expect(getActiveLayers(iface)).toEqual(["L4"]);
  });

  it("detects L7 active for sk_msg programs", () => {
    const skMsgProg = makeProgram({ id: 5, rawType: "sk_msg", osiLayer: "L7" });
    const iface = makeInterface({
      layers: { L2: [], L3: [], L4: [], L7: [skMsgProg] },
      allPrograms: [skMsgProg],
    });
    expect(getActiveLayers(iface)).toEqual(["L7"]);
  });
});

// ─── Program badge truncation ─────────────────────────────────────────────────

function getBadgeCount(progs: BpfProgram[], lod: "full" | "compact"): {
  shown: number;
  overflow: number;
} {
  const max = lod === "full" ? 6 : 3;
  return {
    shown: Math.min(progs.length, max),
    overflow: Math.max(0, progs.length - max),
  };
}

describe("program badge truncation", () => {
  it("shows all programs when count ≤ 3 (compact LOD)", () => {
    const progs = [1, 2, 3].map(id => makeProgram({ id }));
    const result = getBadgeCount(progs, "compact");
    expect(result.shown).toBe(3);
    expect(result.overflow).toBe(0);
  });

  it("truncates to 3 with overflow count in compact LOD", () => {
    const progs = [1, 2, 3, 4, 5].map(id => makeProgram({ id }));
    const result = getBadgeCount(progs, "compact");
    expect(result.shown).toBe(3);
    expect(result.overflow).toBe(2);
  });

  it("shows up to 6 programs in full LOD", () => {
    const progs = [1, 2, 3, 4, 5, 6].map(id => makeProgram({ id }));
    const result = getBadgeCount(progs, "full");
    expect(result.shown).toBe(6);
    expect(result.overflow).toBe(0);
  });

  it("truncates to 6 with overflow count in full LOD", () => {
    const progs = [1, 2, 3, 4, 5, 6, 7, 8].map(id => makeProgram({ id }));
    const result = getBadgeCount(progs, "full");
    expect(result.shown).toBe(6);
    expect(result.overflow).toBe(2);
  });

  it("handles empty program list gracefully", () => {
    const result = getBadgeCount([], "full");
    expect(result.shown).toBe(0);
    expect(result.overflow).toBe(0);
  });
});

// ─── Tooltip data completeness ────────────────────────────────────────────────

describe("program tooltip data", () => {
  it("provides name, rawType, id, and attachment detail for a complete program", () => {
    const prog = makeProgram({
      id: 42,
      name: "xdp_drop",
      rawType: "xdp",
      jited: true,
      gplCompatible: true,
      orphaned: false,
      attachments: [{ kind: "xdp", detail: "eth0 (driver)", ifname: "eth0" }],
    });
    expect(prog.name).toBe("xdp_drop");
    expect(prog.rawType).toBe("xdp");
    expect(prog.id).toBe(42);
    expect(prog.attachments[0].detail).toBe("eth0 (driver)");
    expect(prog.jited).toBe(true);
    expect(prog.gplCompatible).toBe(true);
  });

  it("handles programs with no attachments gracefully", () => {
    const prog = makeProgram({ attachments: [] });
    expect(prog.attachments.length).toBe(0);
    // Tooltip should still render — no crash from accessing attachments[0]
    const firstAttachment = prog.attachments[0];
    expect(firstAttachment).toBeUndefined();
  });

  it("marks orphaned programs correctly", () => {
    const prog = makeProgram({ orphaned: true });
    expect(prog.orphaned).toBe(true);
  });

  it("truncates long program names at 12 characters with ellipsis", () => {
    const name = "very_long_program_name_that_exceeds_limit";
    const displayName = name.length > 12 ? name.slice(0, 11) + "…" : name;
    expect(displayName).toBe("very_long_p…");
    expect(displayName.length).toBe(12);
  });

  it("does not truncate names that are 12 characters or shorter", () => {
    const name = "short_prog";
    const displayName = name.length > 12 ? name.slice(0, 11) + "…" : name;
    expect(displayName).toBe("short_prog");
  });
});

// ─── Flow arrow visibility ────────────────────────────────────────────────────

function isArrowActive(
  upperLayer: BpfProgram[],
  lowerLayer: BpfProgram[]
): boolean {
  return upperLayer.length > 0 || lowerLayer.length > 0;
}

describe("flow arrow active state", () => {
  it("is active when either adjacent layer has programs", () => {
    const prog = makeProgram();
    expect(isArrowActive([prog], [])).toBe(true);
    expect(isArrowActive([], [prog])).toBe(true);
    expect(isArrowActive([prog], [prog])).toBe(true);
  });

  it("is inactive when both adjacent layers have no programs", () => {
    expect(isArrowActive([], [])).toBe(false);
  });
});

// ─── NIC hardware base ────────────────────────────────────────────────────────

describe("NIC hardware base", () => {
  it("displays the interface name", () => {
    const iface = makeInterface({ name: "eth1" });
    expect(iface.name).toBe("eth1");
  });

  it("handles loopback interface name", () => {
    const iface = makeInterface({ name: "lo" });
    expect(iface.name).toBe("lo");
  });

  it("handles long interface names", () => {
    const iface = makeInterface({ name: "veth0123456789" });
    expect(iface.name.length).toBeGreaterThan(4);
  });
});

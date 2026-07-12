// @vitest-environment happy-dom
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render } from "@testing-library/react";
import type { BpfProgram, EbpfSnapshot } from "../../../shared/ebpf-types";

function prog(id: number, name: string, tag: string): BpfProgram {
  return {
    id, type: "sched_cls", rawType: "sched_cls", name, tag,
    gplCompatible: true, loadedAt: 1, orphaned: false, bytesXlated: 0, jited: true,
    memlock: 0, mapIds: [], attachments: [], osiLayer: "L3", color: "#fff",
  };
}
function snap(programs: BpfProgram[]): EbpfSnapshot {
  return {
    timestamp: 0, hostname: "h", kernelVersion: "6", bpftoolVersion: "7", demoMode: false,
    programs, networkInterfaces: [], cgroupTree: [], kernelZones: [], programChains: [],
    stats: { total: programs.length, byType: {}, jited: programs.length, orphaned: 0 },
  };
}
const A = snap([prog(1, "keep", "t"), prog(2, "gone", "g")]);
const B = snap([prog(1, "keep", "t"), prog(9, "fresh", "f")]);

vi.mock("@/contexts/EbpfContext", () => ({
  useEbpf: () => ({
    parseSnapshotFile: async (file: File) => ({
      snapshot: file.name === "a.json" ? A : B,
      maps: [],
      meta: { filename: file.name, capturedAt: "t", hostname: "h", kernelVersion: "6" },
    }),
  }),
}));

import DiffView from "./DiffView";

afterEach(cleanup);

describe("DiffView", () => {
  it("loads two snapshots and renders the program diff", async () => {
    const r = render(<DiffView />);
    const inputs = r.container.querySelectorAll('input[type="file"]');
    expect(inputs).toHaveLength(2);

    await act(async () => {
      fireEvent.change(inputs[0], { target: { files: [new File(["{}"], "a.json")] } });
    });
    await act(async () => {
      fireEvent.change(inputs[1], { target: { files: [new File(["{}"], "b.json")] } });
    });

    const text = r.container.textContent ?? "";
    // Added / removed programs surface by name.
    expect(text).toContain("fresh"); // added in B
    expect(text).toContain("gone"); // removed from A
    // "keep" is unchanged → not listed as a diff row beyond the file summary.
    // Summary tiles reflect +1 / -1 program.
    expect(text).toContain("Progs +");
    expect(text).toContain("Progs −");
  });

  it("shows the empty state before both snapshots are loaded", () => {
    const r = render(<DiffView />);
    expect(r.container.textContent).toContain("Load two snapshots");
  });
});

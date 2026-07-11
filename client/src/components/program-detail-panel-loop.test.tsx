// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render } from "@testing-library/react";
import { Router } from "wouter";
import { TooltipProvider } from "@/components/ui/tooltip";
import type { BpfProgram, BpfMap, EbpfSnapshot, ProgHistory } from "../../../shared/ebpf-types";

const focusMap = vi.fn();
const focusProgram = vi.fn();

function prog(id: number, mapIds: number[]): BpfProgram {
  return {
    id, type: "sched_cls", rawType: "sched_cls", name: `cil_${id}`, tag: `${id}`.padStart(16, "0"),
    gplCompatible: true, loadedAt: 1, orphaned: false, bytesXlated: 10, jited: true,
    memlock: 0, mapIds, attachments: [{ kind: "tcx", detail: "eth0 tcx/ingress" }],
    osiLayer: "L3", color: "#fff", pids: [{ pid: 1, comm: "cilium" }],
  };
}
function sharedMap(id: number): BpfMap {
  return {
    id, type: "hash", rawType: "lru_hash", name: `cilium_lb4_${id}`, flags: 0,
    bytesKey: 8, bytesValue: 16, maxEntries: 1024, bytesMemlock: 0, frozen: false,
    pinnedPaths: [], usedByProgIds: [1, 2, 3], color: "#fff", category: "data",
  };
}

// churn identities each render (per-poll behavior)
function ctx() {
  const programs = [prog(1, [10]), prog(2, [10]), prog(3, [10])];
  const snapshot = {
    timestamp: Math.random(), hostname: "h", kernelVersion: "6", bpftoolVersion: "7", demoMode: false,
    programs, networkInterfaces: [], cgroupTree: [], kernelZones: [], programChains: [],
    stats: { total: 3, byType: {}, jited: 3, orphaned: 0 },
  } as EbpfSnapshot;
  return { maps: [sharedMap(10)], snapshot, focusMap, focusProgram };
}
vi.mock("@/contexts/EbpfContext", () => ({ useEbpf: () => ctx() }));

import { ProgramDetailPanel } from "./ProgramDetailPanel";

afterEach(cleanup);

const history: ProgHistory = {
  id: 1, samples: [{ ts: 1, runCnt: 0, runTimeNs: 0, recursionMisses: 0 }],
  latest: null, peakCallsPerSec: 0, peakAvgLatencyNs: 0,
};

describe("ProgramDetailPanel", () => {
  it("renders a program with a shared map (SharedMapBadge tooltip) without looping", () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const view = (
      <Router>
        <TooltipProvider>
          <ProgramDetailPanel program={prog(1, [10])} history={history} onClose={vi.fn()} />
        </TooltipProvider>
      </Router>
    );
    const { rerender } = render(view);
    for (let i = 0; i < 5; i++) rerender(view);
    const looped = errSpy.mock.calls.some(args =>
      args.some(a => typeof a === "string" && a.includes("Maximum update depth"))
    );
    errSpy.mockRestore();
    expect(looped, "ProgramDetailPanel update loop").toBe(false);
  });
});

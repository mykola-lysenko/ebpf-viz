// @vitest-environment happy-dom
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render } from "@testing-library/react";
import { Router } from "wouter";
import { TooltipProvider } from "@/components/ui/tooltip";
import type { BpfProgram, ProgHistory, EbpfSnapshot } from "../../../shared/ebpf-types";

const setSelectedProgram = vi.fn();

function prog(id: number): BpfProgram {
  return {
    id, type: "kprobe", rawType: "kprobe", name: `p${id}`, tag: `${id}`.padStart(16, "0"),
    gplCompatible: true, loadedAt: 1, orphaned: false, bytesXlated: 10, jited: true,
    memlock: 0, mapIds: [], attachments: [], osiLayer: "kernel", color: "#fff",
  };
}
function history(id: number): ProgHistory {
  const samples = Array.from({ length: 6 }, (_, i) => ({
    ts: 1000 + i * 1000, runCnt: i * 10, runTimeNs: i * 1_000_000, recursionMisses: 0,
  }));
  return { id, samples, latest: { callsPerSec: 10, avgLatencyNs: 100, cpuFraction: 0.01, recursionRate: 0 }, peakCallsPerSec: 10, peakAvgLatencyNs: 100 };
}

// Fresh object identities every call — simulates the per-poll churn the real
// SSE stream produces (new snapshot, new historyMap, new program objects).
function freshContext() {
  const programs = [prog(1), prog(2), prog(3)];
  const snapshot = {
    timestamp: Math.random(), hostname: "h", kernelVersion: "6", bpftoolVersion: "7", demoMode: false,
    programs, networkInterfaces: [], cgroupTree: [], kernelZones: [], programChains: [],
    stats: { total: 3, byType: {}, jited: 3, orphaned: 0 },
  } as EbpfSnapshot;
  const historyMap = new Map(programs.map(p => [p.id, history(p.id)]));
  return {
    snapshot, filteredPrograms: programs, typeFilter: [] as string[],
    setTypeFilter: vi.fn(), historyMap, statsEnabled: true, setSelectedProgram,
  };
}

vi.mock("@/contexts/EbpfContext", () => ({
  useEbpf: () => freshContext(),
}));

import ProgramsView from "./ProgramsView";

afterEach(cleanup);

describe("ProgramsView", () => {
  it("mounts and re-renders without an update loop", () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { rerender } = render(
      <Router>
        <TooltipProvider>
          <ProgramsView />
        </TooltipProvider>
      </Router>
    );
    // Simulate several poll-driven re-renders.
    for (let i = 0; i < 5; i++) {
      rerender(
        <Router>
          <TooltipProvider>
            <ProgramsView />
          </TooltipProvider>
        </Router>
      );
    }
    const looped = errSpy.mock.calls.some(args =>
      args.some(a => typeof a === "string" && a.includes("Maximum update depth"))
    );
    errSpy.mockRestore();
    expect(looped, "ProgramsView update loop").toBe(false);
  });
});

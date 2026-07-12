// @vitest-environment happy-dom
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render } from "@testing-library/react";
import { Router } from "wouter";
import { TooltipProvider } from "@/components/ui/tooltip";
import type { BpfProgram, ProgHistory, EbpfSnapshot } from "../../../shared/ebpf-types";

const program: BpfProgram = {
  id: 1, type: "kprobe", rawType: "kprobe", name: "p1", tag: "0000000000000001",
  gplCompatible: true, loadedAt: 1, orphaned: false, bytesXlated: 0, jited: true,
  memlock: 0, mapIds: [], attachments: [], osiLayer: "kernel", color: "#fff",
};

// Two intervals with very different call rates:
//   offset 0 (latest): 105-100 = 5 calls/s
//   offset 1         : 100-0   = 100 calls/s
const history: ProgHistory = {
  id: 1,
  samples: [
    { ts: 1000, runCnt: 0, runTimeNs: 0, recursionMisses: 0 },
    { ts: 2000, runCnt: 100, runTimeNs: 0, recursionMisses: 0 },
    { ts: 3000, runCnt: 105, runTimeNs: 0, recursionMisses: 0 },
  ],
  latest: { callsPerSec: 5, avgLatencyNs: 0, cpuFraction: 0, recursionRate: 0 },
  peakCallsPerSec: 100, peakAvgLatencyNs: 0,
};

const snapshot = {
  timestamp: 0, hostname: "h", kernelVersion: "6", bpftoolVersion: "7", demoMode: false,
  programs: [program], networkInterfaces: [], cgroupTree: [], kernelZones: [],
  programChains: [], stats: { total: 1, byType: {}, jited: 1, orphaned: 0 },
} as EbpfSnapshot;

vi.mock("@/contexts/EbpfContext", () => ({
  useEbpf: () => ({
    snapshot, filteredPrograms: [program], typeFilter: [], setTypeFilter: vi.fn(),
    historyMap: new Map([[1, history]]), statsEnabled: true, setSelectedProgram: vi.fn(),
  }),
}));

import ProgramsView from "./ProgramsView";

afterEach(cleanup);

function renderView() {
  return render(
    <Router>
      <TooltipProvider>
        <ProgramsView />
      </TooltipProvider>
    </Router>
  );
}

describe("ProgramsView time scrubber", () => {
  it("shows live rates, then the historical interval's rates when scrubbed back", async () => {
    const r = renderView();
    // Live: latest interval = 5.0/s
    expect(r.container.textContent).toContain("5.0/s");
    expect(r.container.textContent).toContain("live");

    const slider = r.container.querySelector('input[type="range"]') as HTMLInputElement;
    expect(slider).toBeTruthy();
    // value = maxScrub - offset; maxScrub is 1 here, so value 0 => offset 1 (oldest).
    expect(slider.max).toBe("1");
    await act(async () => fireEvent.change(slider, { target: { value: "0" } }));

    // Scrubbed one interval back = 100.0/s, and the label leaves "live".
    expect(r.container.textContent).toContain("100.0/s");
    expect(r.container.textContent).not.toContain("5.0/s");
    expect(r.getByText("Live")).toBeTruthy(); // reset button appears
  });

  it("the Live button resets to the latest interval", async () => {
    const r = renderView();
    const slider = r.container.querySelector('input[type="range"]') as HTMLInputElement;
    await act(async () => fireEvent.change(slider, { target: { value: "0" } }));
    expect(r.container.textContent).toContain("100.0/s");
    await act(async () => r.getByText("Live").click());
    expect(r.container.textContent).toContain("5.0/s");
  });
});

describe("ProgramsView sort deep-link", () => {
  function renderAt(search: string) {
    window.history.replaceState(null, "", `/programs${search}`);
    return render(
      <Router>
        <TooltipProvider>
          <ProgramsView />
        </TooltipProvider>
      </Router>
    );
  }

  it("clicking a sortable header writes ?sort/&dir and toggles direction", async () => {
    const r = renderAt("");
    // Sort by name ascending, then descending on a second click. Re-query the
    // header each time — it re-renders, so a cached node would fire a stale handler.
    await act(async () => r.getByText("Name").click());
    expect(new URLSearchParams(window.location.search).get("sort")).toBe("name");
    expect(new URLSearchParams(window.location.search).get("dir")).toBe("asc");
    await act(async () => r.getByText("Name").click());
    expect(new URLSearchParams(window.location.search).get("dir")).toBe("desc");
  });

  it("returning to the default (id/asc) clears the sort params", async () => {
    const r = renderAt("?sort=name&dir=asc");
    // id is the default column; clicking it once sorts id asc → params dropped.
    await act(async () => r.getByText("ID").click());
    expect(new URLSearchParams(window.location.search).get("sort")).toBeNull();
    expect(new URLSearchParams(window.location.search).get("dir")).toBeNull();
  });
});

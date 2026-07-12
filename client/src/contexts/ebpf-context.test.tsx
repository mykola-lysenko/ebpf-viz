// @vitest-environment happy-dom
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render } from "@testing-library/react";
import { Router } from "wouter";
import type { BpfProgram, EbpfSnapshot } from "../../../shared/ebpf-types";

// ── Mock the provider's external dependencies (SSE stream + tRPC) ────────────
function prog(id: number): BpfProgram {
  return {
    id, type: "kprobe", rawType: "kprobe", name: `p${id}`, tag: `${id}`.padStart(16, "0"),
    gplCompatible: true, loadedAt: 1, orphaned: false, bytesXlated: 0, jited: true,
    memlock: 0, mapIds: [], attachments: [], osiLayer: "kernel", color: "#fff",
  };
}
const streamSnapshot = {
  timestamp: 1, hostname: "h", kernelVersion: "6", bpftoolVersion: "7", demoMode: false,
  programs: [prog(3), prog(9)], networkInterfaces: [], cgroupTree: [], kernelZones: [],
  programChains: [], stats: { total: 2, byType: {}, jited: 2, orphaned: 0 },
} as EbpfSnapshot;

vi.mock("@/hooks/useEbpfStream", () => ({
  useEbpfStream: () => ({
    snapshot: streamSnapshot, maps: [], allHistories: [], activity: null,
    status: "live", lastEventAt: 1,
  }),
}));
vi.mock("@/lib/trpc", () => ({
  trpc: {
    ebpf: {
      status: { useQuery: () => ({ data: { statsEnabled: true }, refetch: vi.fn() }) },
      refresh: { useMutation: () => ({ mutate: vi.fn() }) },
      parseSnapshot: { useMutation: () => ({ mutateAsync: vi.fn() }) },
      parseMapDumps: { useMutation: () => ({ mutateAsync: vi.fn() }) },
    },
  },
}));

import { EbpfProvider, useEbpf } from "./EbpfContext";

afterEach(cleanup);

function Probe() {
  const {
    selectedProgram, selectedMapId, setSelectedProgram, setSelectedMapId, focusProgram, focusMap,
    searchQuery, setSearchQuery, typeFilter, setTypeFilter,
  } = useEbpf();
  return (
    <div>
      <div data-testid="sel">{`${selectedProgram?.id ?? "none"}|${selectedMapId ?? "none"}`}</div>
      <div data-testid="filters">{`${searchQuery || "-"}|${typeFilter.join(",") || "-"}`}</div>
      <button data-testid="sp" onClick={() => setSelectedProgram(prog(9))}>select prog</button>
      <button data-testid="sp-null" onClick={() => setSelectedProgram(null)}>clear prog</button>
      <button data-testid="sm" onClick={() => setSelectedMapId(42)}>select map</button>
      <button data-testid="fp" onClick={() => focusProgram(3)}>focus prog</button>
      <button data-testid="fm" onClick={() => focusMap(7)}>focus map</button>
      <button data-testid="sq" onClick={() => setSearchQuery("xdp")}>search</button>
      <button data-testid="tf" onClick={() => setTypeFilter(["kprobe", "xdp"])}>filter</button>
      <button data-testid="tf-clear" onClick={() => setTypeFilter([])}>clear filter</button>
    </div>
  );
}

function mountAt(url: string) {
  window.history.replaceState(null, "", url);
  return render(
    <Router>
      <EbpfProvider>
        <Probe />
      </EbpfProvider>
    </Router>
  );
}

const url = () => new URLSearchParams(window.location.search);

/** True if React reported an update loop while running fn (sync or async). */
async function loopedDuring(fn: () => void | Promise<void>): Promise<boolean> {
  const spy = vi.spyOn(console, "error").mockImplementation(() => {});
  const seen: string[] = [];
  const onErr = (e: ErrorEvent) => seen.push(String(e.message));
  window.addEventListener("error", onErr);
  try { await act(async () => { await fn(); }); } catch (e) { seen.push(String(e)); }
  window.removeEventListener("error", onErr);
  const hit = (s: unknown) => typeof s === "string" && s.includes("Maximum update depth");
  const looped = seen.some(hit) || spy.mock.calls.some(a => a.some(hit));
  spy.mockRestore();
  return looped;
}

describe("EbpfProvider selection ↔ URL", () => {
  it("resolves a live program from ?prog=<id>", () => {
    const r = mountAt("/programs?prog=3");
    expect(r.getByTestId("sel").textContent).toBe("3|none");
  });

  it("setSelectedProgram writes ?prog and resolves the live object", async () => {
    const r = mountAt("/programs");
    await act(async () => r.getByTestId("sp").click());
    expect(url().get("prog")).toBe("9");
    expect(r.getByTestId("sel").textContent).toBe("9|none");
  });

  it("setSelectedMapId writes ?map and clearing removes it", async () => {
    const r = mountAt("/maps");
    await act(async () => r.getByTestId("sm").click());
    expect(url().get("map")).toBe("42");
    expect(r.getByTestId("sel").textContent).toBe("none|42");
  });

  it("focusMap navigates to /maps with the map selected and clears any program", async () => {
    const r = mountAt("/programs?prog=3");
    await act(async () => r.getByTestId("fm").click());
    expect(window.location.pathname).toBe("/maps");
    expect(url().get("map")).toBe("7");
    expect(url().get("prog")).toBeNull();
    expect(r.getByTestId("sel").textContent).toBe("none|7");
  });

  it("derives search + type filters from the URL and writes them back", async () => {
    const r = mountAt("/programs?q=drop&type=kprobe,xdp");
    // Initial state comes straight from the query string.
    expect(r.getByTestId("filters").textContent).toBe("drop|kprobe,xdp");

    await act(async () => r.getByTestId("sq").click());
    expect(url().get("q")).toBe("xdp");
    await act(async () => r.getByTestId("tf").click());
    expect(url().get("type")).toBe("kprobe,xdp");
    expect(r.getByTestId("filters").textContent).toBe("xdp|kprobe,xdp");
  });

  it("removes the type param entirely when the filter is cleared", async () => {
    const r = mountAt("/programs?type=kprobe");
    expect(r.getByTestId("filters").textContent).toBe("-|kprobe");
    await act(async () => r.getByTestId("tf-clear").click());
    expect(url().get("type")).toBeNull(); // not left as an empty "type="
    expect(r.getByTestId("filters").textContent).toBe("-|-");
  });

  it("does not loop across a sequence of selections and clears", async () => {
    const r = mountAt("/programs");
    const looped = await loopedDuring(() => {
      r.getByTestId("sp").click();
      r.getByTestId("sm").click();
      r.getByTestId("fp").click();
      r.getByTestId("sp-null").click();
    });
    expect(looped).toBe(false);
  });
});

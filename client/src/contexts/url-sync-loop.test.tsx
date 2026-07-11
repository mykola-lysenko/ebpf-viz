// @vitest-environment happy-dom
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render } from "@testing-library/react";
import { Router, useSearchParams, useLocation } from "wouter";

afterEach(cleanup);

/** Detect an "update loop" whether React logs it via console.error or throws
 *  it asynchronously in a queued effect flush. */
async function withLoopDetection(fn: () => void | Promise<void>): Promise<boolean> {
  const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  const seen: string[] = [];
  const onErr = (e: ErrorEvent) => seen.push(String(e.message ?? e.error));
  window.addEventListener("error", onErr);
  try {
    await act(async () => {
      await fn();
    });
  } catch (e) {
    seen.push(String(e));
  }
  window.removeEventListener("error", onErr);
  const hit = (s: unknown) => typeof s === "string" && s.includes("Maximum update depth");
  const looped =
    seen.some(hit) || errSpy.mock.calls.some(args => args.some(hit));
  errSpy.mockRestore();
  return looped;
}

/** URL-as-single-source-of-truth (mirrors EbpfContext): selection is DERIVED
 *  from the query, and setters write the query. No selection state, no sync
 *  effects — nothing can fight the URL, so navigation (which drops the query)
 *  can't loop. */
function paramId(sp: URLSearchParams, key: string): number | null {
  const raw = sp.get(key);
  const n = raw != null && raw !== "" ? Number(raw) : NaN;
  return Number.isFinite(n) ? n : null;
}

function UrlSyncHarness() {
  const [, navigate] = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedProgramId = paramId(searchParams, "prog");
  const selectedMapId = paramId(searchParams, "map");

  const setParam = (key: string, value: number | null) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev);
      if (value != null) next.set(key, String(value));
      else next.delete(key);
      return next;
    }, { replace: true });
  };

  return (
    <div>
      <div data-testid="state">{`${selectedProgramId}|${selectedMapId}`}</div>
      <button data-testid="select-map" onClick={() => setParam("map", 42)}>select map</button>
      <button data-testid="nav-programs" onClick={() => navigate("/programs")}>go programs</button>
    </div>
  );
}

function mountAt(url: string) {
  window.history.replaceState(null, "", url);
  return render(
    <Router>
      <UrlSyncHarness />
    </Router>
  );
}

describe("EbpfContext URL<->selection sync", () => {
  it("does not loop when mounted on a clean URL", async () => {
    let r!: ReturnType<typeof render>;
    const looped = await withLoopDetection(() => { r = mountAt("/maps"); });
    expect(looped).toBe(false);
    expect(r.getByTestId("state").textContent).toBe("null|null");
  });

  it("resolves selection from ?map=5 without looping", async () => {
    let r!: ReturnType<typeof render>;
    const looped = await withLoopDetection(() => { r = mountAt("/maps?map=5"); });
    expect(looped, "update loop on ?map=5").toBe(false);
    expect(r.getByTestId("state").textContent).toBe("null|5");
  });

  it("resolves both selections from ?prog=7&map=3 without looping", async () => {
    let r!: ReturnType<typeof render>;
    const looped = await withLoopDetection(() => { r = mountAt("/maps?prog=7&map=3"); });
    expect(looped, "update loop on ?prog=7&map=3").toBe(false);
    expect(r.getByTestId("state").textContent).toBe("7|3");
  });

  it("keeps a selection made at runtime and writes it to the URL", async () => {
    const r = mountAt("/maps");
    const looped = await withLoopDetection(() => { r.getByTestId("select-map").click(); });
    expect(looped, "update loop after selecting a map").toBe(false);
    expect(r.getByTestId("state").textContent).toBe("null|42");
    expect(new URLSearchParams(window.location.search).get("map")).toBe("42");
  });

  it("does not loop when navigating to another tab with a selection active", async () => {
    // Reproduces "going around tabs": a map is selected on /maps, then the
    // user navigates to /programs (which drops the query). A two-way state<->URL
    // sync used to fight itself here; deriving selection from the URL doesn't.
    const r = mountAt("/maps?map=5");
    const looped = await withLoopDetection(() => { r.getByTestId("nav-programs").click(); });
    expect(looped, "update loop when navigating tabs with a selection").toBe(false);
    expect(r.getByTestId("state").textContent).toBe("null|null"); // selection cleared
  });
});

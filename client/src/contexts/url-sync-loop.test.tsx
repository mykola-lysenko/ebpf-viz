// @vitest-environment happy-dom
import React, { useEffect, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render } from "@testing-library/react";
import { Router, useSearchParams } from "wouter";

afterEach(cleanup);

/** id from a URL query param, or null. */
function initIdFromUrl(key: string): number | null {
  const v = new URLSearchParams(window.location.search).get(key);
  const n = v != null && v !== "" ? Number(v) : NaN;
  return Number.isFinite(n) ? n : null;
}

/** Replica of EbpfContext's URL<->selection sync, in isolation. State is
 *  initialized FROM the URL so the write effect never runs with stale nulls. */
function UrlSyncHarness() {
  const [selectedProgramId, setSelectedProgramId] = useState<number | null>(() => initIdFromUrl("prog"));
  const [selectedMapId, setSelectedMapId] = useState<number | null>(() => initIdFromUrl("map"));
  const [searchParams, setSearchParams] = useSearchParams();
  const progParam = searchParams.get("prog");
  const mapParam = searchParams.get("map");

  useEffect(() => {
    const id = progParam != null && progParam !== "" ? Number(progParam) : null;
    if (id != null && Number.isNaN(id)) return;
    setSelectedProgramId(prev => (prev === id ? prev : id));
  }, [progParam]);
  useEffect(() => {
    const id = mapParam != null && mapParam !== "" ? Number(mapParam) : null;
    if (id != null && Number.isNaN(id)) return;
    setSelectedMapId(prev => (prev === id ? prev : id));
  }, [mapParam]);
  useEffect(() => {
    const desired = new URLSearchParams(searchParams);
    if (selectedProgramId != null) desired.set("prog", String(selectedProgramId));
    else desired.delete("prog");
    if (selectedMapId != null) desired.set("map", String(selectedMapId));
    else desired.delete("map");
    if (desired.toString() !== searchParams.toString()) {
      setSearchParams(desired, { replace: true });
    }
  }, [selectedProgramId, selectedMapId, searchParams, setSearchParams]);

  return (
    <div>
      <div data-testid="state">{`${selectedProgramId}|${selectedMapId}`}</div>
      <button data-testid="select-map" onClick={() => setSelectedMapId(42)}>
        select map
      </button>
    </div>
  );
}

function renderAt(url: string) {
  window.history.replaceState(null, "", url);
  const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  const r = render(
    <Router>
      <UrlSyncHarness />
    </Router>
  );
  const looped = errSpy.mock.calls.some(args =>
    args.some(a => typeof a === "string" && a.includes("Maximum update depth"))
  );
  errSpy.mockRestore();
  return { looped, text: r.getByTestId("state").textContent };
}

describe("EbpfContext URL<->selection sync", () => {
  it("does not loop when mounted on a clean URL", () => {
    const { looped } = renderAt("/maps");
    expect(looped).toBe(false);
  });
  it("does not loop when mounted with ?map=5", () => {
    const { looped, text } = renderAt("/maps?map=5");
    expect(looped, "update loop on ?map=5").toBe(false);
    expect(text).toBe("null|5");
  });
  it("does not loop when mounted with ?prog=7&map=3", () => {
    const { looped, text } = renderAt("/maps?prog=7&map=3");
    expect(looped, "update loop on ?prog=7&map=3").toBe(false);
    expect(text).toBe("7|3");
  });

  it("keeps a selection made at runtime and writes it to the URL", async () => {
    window.history.replaceState(null, "", "/maps");
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const r = render(
      <Router>
        <UrlSyncHarness />
      </Router>
    );
    r.getByTestId("select-map").click();
    // let effects flush
    await new Promise(resolve => setTimeout(resolve, 0));
    const looped = errSpy.mock.calls.some(args =>
      args.some(a => typeof a === "string" && a.includes("Maximum update depth"))
    );
    errSpy.mockRestore();
    expect(looped, "update loop after selecting a map").toBe(false);
    // selection persisted (panel does NOT force-close) and the URL reflects it
    expect(r.getByTestId("state").textContent).toBe("null|42");
    expect(new URLSearchParams(window.location.search).get("map")).toBe("42");
  });
});

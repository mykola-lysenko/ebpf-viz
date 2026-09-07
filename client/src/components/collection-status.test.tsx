import { COLLECTION_SOURCE_LABELS } from "../../../shared/collection-status";
// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render } from "@testing-library/react";
import { CollectionStatus } from "./CollectionStatus";

afterEach(cleanup);

describe("collection status display", () => {
  it("explains stale and unavailable sources, shows freshness and limits, and clears on recovery", () => {
    const r = render(<CollectionStatus collection={{ sources: {
      progs: { label: "Programs", state: "error", attemptedAt: 2000, lastSuccessAt: 1000, error: "permission denied" },
      links: { label: "Links", state: "unsupported", attemptedAt: 2000, lastSuccessAt: null },
    }, namespaces: { limit: 64, discovered: 70, scanned: 64, skipped: 0, omitted: 6, discoveryAt: 1000 } }} />);
    fireEvent.click(r.getByText(/Collection has gaps/));
    expect(r.container.querySelector("details")?.open).toBe(true);
    expect(r.container.textContent).toContain("last-known data");
    expect(r.container.textContent).toContain("no successful collection recorded");
    expect(r.container.textContent).toContain("1970-01-01T00:00:01.000Z");
    expect(r.container.textContent).toContain("6 omitted");
    r.rerender(<CollectionStatus collection={{ sources: {
      ...Object.fromEntries(Object.entries(COLLECTION_SOURCE_LABELS).map(([key, label]) => [key, { label, state: "ok" as const, attemptedAt: 3000, lastSuccessAt: 3000, count: 0 }])),
    } }} />);
    expect(r.container.textContent).toContain("Collection complete");
    expect(r.container.textContent).toContain("0 records");
    expect(r.container.textContent).not.toContain("permission denied");
  });

  it("marks legacy coverage unknown and does not claim demo data was collected", () => {
    const r = render(<CollectionStatus />);
    expect(r.container.textContent).toContain("Collection coverage unknown");
    r.rerender(<CollectionStatus demo />);
    expect(r.container.textContent).toBe("");
  });
});

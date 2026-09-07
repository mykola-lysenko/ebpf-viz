// @vitest-environment happy-dom
import React from "react";
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render } from "@testing-library/react";
import { ChainOrderEvidence } from "./ChainOrderEvidence";
import type { ProgramChain } from "../../../shared/ebpf-types";

const chain: ProgramChain = { hookId: "tc:eth0:tcx/ingress", hookLabel: "eth0 ingress", hookType: "tc", attachPoint: "eth0",
  attachType: "tcx/ingress", programs: [], canShortCircuit: true, mechanism: "tcx", ordering: "kernel-query" };
afterEach(cleanup);
describe("chain ordering evidence", () => {
  it("labels TCX query order and unavailable revision without inventing a revision", () => {
    const r = render(<ChainOrderEvidence chain={chain} />);
    expect(r.container.textContent).toContain("TCX · kernel query order · revision unavailable");
    expect(r.container.textContent).toContain("NEXT (-1) continues");
    expect(r.container.textContent).toContain("PASS (0)");
    expect(r.container.textContent).toContain("prediction is not yet modeled");
  });
  it("labels insufficient evidence as unknown even for older parsed captures", () => {
    const r = render(<ChainOrderEvidence chain={{ ...chain, ordering: undefined }} />);
    expect(r.container.textContent).toContain("Order unknown");
    expect(r.container.textContent).toContain("positions and path predictions are unverified");
  });
  it("labels the conditional legacy stage separately", () => {
    const r = render(<ChainOrderEvidence chain={{ ...chain, mechanism: "legacy-tc", attachType: "clsact/ingress", ordering: "tc-priority", afterTcx: true }} />);
    expect(r.container.textContent).toContain("Legacy TC · classifier priority order");
    expect(r.container.textContent).toContain("Reached only if all preceding TCX programs return NEXT");
  });
});

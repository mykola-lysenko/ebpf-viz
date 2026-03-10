/**
 * Standalone mode: the auth router has been removed.
 * This test file is kept as a placeholder to avoid breaking the test runner.
 * It verifies that the ebpf router is present and the app compiles correctly.
 */
import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";

describe("standalone mode", () => {
  it("has no auth router (standalone mode — no OAuth)", () => {
    const router = appRouter as Record<string, unknown>;
    expect(router).not.toHaveProperty("auth");
  });

  it("has the ebpf router with expected procedures", () => {
    const caller = appRouter.createCaller({
      req: {} as never,
      res: {} as never,
      user: null,
    });
    // snapshot procedure should exist and return null when no data is available yet
    expect(typeof caller.ebpf.snapshot).toBe("function");
    expect(typeof caller.ebpf.status).toBe("function");
    expect(typeof caller.ebpf.activity).toBe("function");
  });
});

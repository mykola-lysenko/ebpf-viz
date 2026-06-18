import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import {
  checkRateLimit,
  getRequestAdminToken,
  hasOperatorAccess,
  resetRateLimitsForTests,
} from "./_core/security";

function mockReq(remoteAddress: string, headers: Record<string, string> = {}) {
  return {
    headers,
    socket: { remoteAddress },
  };
}

describe("operator access guard", () => {
  const oldAdminToken = process.env.ADMIN_TOKEN;
  const oldEbpfAdminToken = process.env.EBPF_VIZ_ADMIN_TOKEN;

  beforeEach(() => {
    delete process.env.ADMIN_TOKEN;
    delete process.env.EBPF_VIZ_ADMIN_TOKEN;
    resetRateLimitsForTests();
  });

  afterEach(() => {
    if (oldAdminToken === undefined) delete process.env.ADMIN_TOKEN;
    else process.env.ADMIN_TOKEN = oldAdminToken;
    if (oldEbpfAdminToken === undefined) delete process.env.EBPF_VIZ_ADMIN_TOKEN;
    else process.env.EBPF_VIZ_ADMIN_TOKEN = oldEbpfAdminToken;
    resetRateLimitsForTests();
  });

  it("allows loopback requests without an admin token", () => {
    expect(hasOperatorAccess(mockReq("127.0.0.1"))).toBe(true);
    expect(hasOperatorAccess(mockReq("::1"))).toBe(true);
    expect(hasOperatorAccess(mockReq("::ffff:127.0.0.1"))).toBe(true);
  });

  it("denies remote requests without an admin token", () => {
    expect(hasOperatorAccess(mockReq("203.0.113.10"))).toBe(false);
  });

  it("allows remote requests with the configured bearer token", () => {
    process.env.ADMIN_TOKEN = "secret-token";
    const req = mockReq("203.0.113.10", {
      authorization: "Bearer secret-token",
    });

    expect(getRequestAdminToken(req)).toBe("secret-token");
    expect(hasOperatorAccess(req)).toBe(true);
  });

  it("rate-limits by client, path, and bucket key", () => {
    const req = mockReq("203.0.113.10");
    const options = { key: "test", max: 2, windowMs: 60_000 };

    expect(checkRateLimit(req, "ebpf.mapDump", options)).toBeNull();
    expect(checkRateLimit(req, "ebpf.mapDump", options)).toBeNull();
    expect(checkRateLimit(req, "ebpf.mapDump", options)).toBeGreaterThan(0);
    expect(checkRateLimit(req, "ebpf.progDump", options)).toBeNull();
  });
});

describe("protected tRPC procedures", () => {
  beforeEach(() => {
    delete process.env.ADMIN_TOKEN;
    delete process.env.EBPF_VIZ_ADMIN_TOKEN;
    resetRateLimitsForTests();
  });

  afterEach(() => {
    resetRateLimitsForTests();
  });

  it("keeps read-only status public", async () => {
    const caller = appRouter.createCaller({
      req: mockReq("203.0.113.10") as never,
      res: {} as never,
    });

    await expect(caller.ebpf.status()).resolves.toHaveProperty("running");
  });

  it("blocks remote operational procedures without token", async () => {
    const caller = appRouter.createCaller({
      req: mockReq("203.0.113.10") as never,
      res: {} as never,
    });

    await expect(caller.ebpf.refresh()).rejects.toMatchObject({ code: "FORBIDDEN" });
    await expect(caller.ebpf.mapEntryCounts({ ids: [] })).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("allows protected procedures from loopback", async () => {
    const caller = appRouter.createCaller({
      req: mockReq("127.0.0.1") as never,
      res: {} as never,
    });

    await expect(caller.ebpf.mapEntryCounts({ ids: [] })).resolves.toEqual([]);
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({ readdir: vi.fn(), readlink: vi.fn(), stat: vi.fn(), exec: vi.fn(), execFile: vi.fn() }));
vi.mock("fs/promises", () => ({ ...mocks, readFile: vi.fn(async () => "container") }));
vi.mock("child_process", async () => {
  const { promisify } = await import("util");
  return { exec: Object.assign(vi.fn(), { [promisify.custom]: mocks.exec }),
    execFile: Object.assign(vi.fn(), { [promisify.custom]: mocks.execFile }) };
});
import { clearNetnsDiscoveryCache, discoverNetNamespaces } from "./ebpf-netns";
beforeEach(() => {
  vi.clearAllMocks();
  clearNetnsDiscoveryCache();
  mocks.readdir.mockResolvedValue([]);
  mocks.readlink.mockResolvedValue("net:[1]");
  mocks.exec.mockResolvedValue({ stdout: "" });
});

describe("namespace discovery coverage", () => {
  it("reports the cap even when all namespaces are named, and retains discovery time when cached", async () => {
    mocks.readdir.mockImplementation(async (path: string) => path === "/var/run/netns" ? Array.from({ length: 70 }, (_, i) => `ns${i}`) : []);
    mocks.stat.mockImplementation(async (path: string) => ({ ino: Number(path.match(/ns(\d+)$/)![1]) + 10 }));
    const result = await discoverNetNamespaces();
    expect(result.refs).toHaveLength(64);
    expect(result).toMatchObject({ discovered: 70, omitted: 6, issues: [] });
    expect(await discoverNetNamespaces()).toBe(result);
  });

  it("reports inaccessible process discovery and unavailable Docker rather than successful empty coverage", async () => {
    mocks.readdir.mockImplementation(async (path: string) => {
      if (path === "/proc") throw Object.assign(new Error("permission denied"), { code: "EACCES" });
      return [];
    });
    mocks.exec.mockRejectedValue(Object.assign(new Error("docker: not found"), { code: 127 }));
    const result = await discoverNetNamespaces();
    expect(result.refs).toEqual([]);
    expect(result.issues).toEqual(expect.arrayContaining([
      expect.objectContaining({ label: "Process namespace discovery", state: "error" }),
      expect.objectContaining({ label: "Docker namespace discovery", state: "unsupported" }),
    ]));
  });

  it("rejects missing host namespace identity rather than treating the scan as empty", async () => {
    mocks.readlink.mockRejectedValue(new Error("no proc"));
    await expect(discoverNetNamespaces()).rejects.toThrow("Cannot discover network namespaces");
  });
});

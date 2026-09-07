import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ execFile: vi.fn(), exec: vi.fn(), discovery: vi.fn() }));
vi.mock("child_process", async () => {
  const { promisify } = await import("util");
  return {
    execSync: vi.fn(() => "/mock/bpftool"),
    execFile: Object.assign(vi.fn(), { [promisify.custom]: mocks.execFile }),
    exec: Object.assign(vi.fn(), { [promisify.custom]: mocks.exec }),
  };
});
vi.mock("./ebpf-netns", async importOriginal => ({
  ...await importOriginal<typeof import("./ebpf-netns")>(),
  discoverNetNamespaces: mocks.discovery,
}));

let poller: typeof import("./ebpf-poller");
let outputs: Record<string, string | Error>;
const program = (count: number) => JSON.stringify([{ id: 7, type: "xdp", name: "test", run_cnt: count, run_time_ns: count * 100 }]);

beforeEach(async () => {
  vi.resetModules();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(1000);
  outputs = {
    "prog list": program(10),
    "map list": '[{"id":9,"type":"hash","name":"data"}]',
    "net": '[]', "cgroup tree": '[]', "cgroup tree /sys/fs/cgroup effective": '[]', "link list": '[]',
  };
  mocks.execFile.mockImplementation(async (_cmd: string, args: string[]) => {
    const index = args.indexOf("-f");
    const key = index >= 0 ? args.slice(index + 1).join(" ") : args.join(" ");
    const result = outputs[key] ?? new Error(`Unexpected command: ${key}`);
    if (result instanceof Error) throw result;
    return { stdout: result, stderr: "" };
  });
  mocks.discovery.mockResolvedValue({ refs: [], at: 1000, discovered: 0, omitted: 0, issues: [] });
  poller = await import("./ebpf-poller");
});
afterEach(() => { poller.stopPoller(); vi.useRealTimers(); });

describe("live collection failures and recovery", () => {
  it("retains last-good programs, stops sampling stale counters, and recovers", async () => {
    const notify = vi.fn();
    poller.subscribe(notify);
    await poller.triggerPoll();
    expect(poller.getHistory(7)?.samples).toHaveLength(1);
    vi.setSystemTime(2000);
    outputs["prog list"] = new Error("permission denied");
    await poller.triggerPoll();
    const failed = poller.getLatestSnapshot()!;
    expect(failed.programs.map(p => p.id)).toEqual([7]);
    expect(failed.collection?.sources.progs).toMatchObject({ state: "error", attemptedAt: 2000, lastSuccessAt: 1000 });
    expect(poller.getPollerStatus().lastError).toContain("permission denied");
    expect(poller.getHistory(7)?.samples).toHaveLength(1);
    expect(notify).toHaveBeenCalledTimes(2);
    vi.setSystemTime(3000);
    outputs["prog list"] = program(30);
    await poller.triggerPoll();
    expect(poller.getLatestSnapshot()?.collection?.sources.progs).toMatchObject({ state: "ok", lastSuccessAt: 3000 });
    expect(poller.getPollerStatus().lastError).toBeNull();
    expect(poller.getHistory(7)?.latest?.callsPerSec).toBe(10);
    // Earlier metadata must not be mutated by recovery.
    expect(failed.collection?.sources.progs.state).toBe("error");
  });

  it.each(["", "not JSON", '{"error":"failed"}', "null", '[{"type":"xdp"}]'])("rejects malformed program output %s without losing inventory", async output => {
    await poller.triggerPoll();
    outputs["prog list"] = output;
    await poller.triggerPoll();
    expect(poller.getLatestSnapshot()?.programs).toHaveLength(1);
    expect(poller.getLatestSnapshot()?.collection?.sources.progs.state).toBe("error");
  });

  it("accepts a successful empty array, clears old data, and prunes history", async () => {
    await poller.triggerPoll();
    outputs["prog list"] = "libbpf: warning\n[]";
    await poller.triggerPoll();
    expect(poller.getLatestSnapshot()?.programs).toEqual([]);
    expect(poller.getLatestSnapshot()?.collection?.sources.progs).toMatchObject({ state: "ok", count: 0 });
    expect(poller.getHistory(7)).toBeNull();
  });

  it("reports first-poll failures without presenting demo data or healthy empty sources", async () => {
    for (const key of Object.keys(outputs)) outputs[key] = new Error("access denied");
    await poller.triggerPoll();
    expect(poller.isDemoMode()).toBe(false);
    expect(poller.getLatestSnapshot()?.collection?.sources.progs).toMatchObject({ state: "error", lastSuccessAt: null });
    expect(poller.getPollerStatus().lastError).toContain("access denied");
  });

  it("preserves maps independently while programs update and recognizes unsupported commands", async () => {
    await poller.triggerPoll();
    outputs["map list"] = new Error("map permission denied");
    outputs["prog list"] = program(20);
    outputs["link list"] = new Error("Operation not supported");
    await poller.triggerPoll();
    expect(poller.getLatestMaps().map(m => m.id)).toEqual([9]);
    expect(poller.getLatestSnapshot()?.programs[0].runCnt).toBe(20);
    expect(poller.getLatestSnapshot()?.collection?.sources.links.state).toBe("unsupported");
    expect(poller.getLatestSnapshot()?.collection?.sources.maps.state).toBe("error");
  });

  it("clears retained data and histories when the collection configuration changes", async () => {
    await poller.triggerPoll();
    outputs["prog list"] = new Error("new collector unavailable");
    poller.updateConfig({ bpftoolPath: "/different/bpftool" });
    await vi.waitFor(() => expect(poller.getLatestSnapshot()?.collection?.sources.progs.state).toBe("error"));
    expect(poller.getLatestSnapshot()?.programs).toEqual([]);
    expect(poller.getLatestSnapshot()?.collection?.sources.progs.lastSuccessAt).toBeNull();
    expect(poller.getHistory(7)).toBeNull();
  });

  it("reports namespace caps and retries failed scans rather than suppressing them", async () => {
    mocks.discovery.mockResolvedValue({
      refs: [{ id: "42", label: "pod", reach: { via: "nsenter", nsPath: "/proc/42/ns/net" } }],
      at: 1000, discovered: 70, omitted: 6, issues: [],
    });
    await poller.triggerPoll();
    const first = mocks.execFile.mock.calls.length;
    await poller.triggerPoll();
    expect(mocks.execFile.mock.calls.length - first).toBe(8); // six host commands + two namespace commands
    expect(poller.getLatestSnapshot()?.collection?.namespaces).toMatchObject({ limit: 64, discovered: 70, omitted: 6, skipped: 0 });
    expect(poller.getLatestSnapshot()?.collection?.sources["netns:42:net"].state).toBe("error");
    expect(poller.getLatestSnapshot()?.collection?.sources.namespaceDiscovery.state).toBe("partial");
  });

  it("marks successful empty namespace scans as deferred and exposes their original freshness", async () => {
    mocks.discovery.mockResolvedValue({ refs: [{ id: "42", label: "pod", reach: { via: "nsenter", nsPath: "/proc/42/ns/net" } }], at: 1000, discovered: 1, omitted: 0, issues: [] });
    outputs["nsenter --net=/proc/42/ns/net -- /mock/bpftool -j net show"] = "[{}]";
    outputs["nsenter --net=/proc/42/ns/net -- ip -d -j link show"] = "[]";
    await poller.triggerPoll();
    vi.setSystemTime(2000);
    await poller.triggerPoll();
    expect(poller.getLatestSnapshot()?.collection?.sources["netns:42:net"]).toMatchObject({ state: "skipped", lastSuccessAt: 1000, attemptedAt: null });
    expect(poller.getLatestSnapshot()?.collection?.namespaces?.skipped).toBe(1);
  });
});

import { describe, expect, it, vi } from "vitest";

vi.mock("./ebpf-parser", async importOriginal => {
  const actual = await importOriginal<typeof import("./ebpf-parser")>();
  return {
    ...actual,
    buildSnapshot: vi.fn(() => {
      throw new Error("boom: simulated snapshot build failure");
    }),
  };
});

import {
  getLatestSnapshot,
  getPollerStatus,
  isDemoMode,
  parseBpftoolVersion,
  triggerPoll,
} from "./ebpf-poller";

describe("parseBpftoolVersion", () => {
  it("detects skeleton support from the features line", () => {
    const out = "bpftool v7.8.0\nusing libbpf v1.8\nfeatures: llvm, crypto, skeletons\n";
    expect(parseBpftoolVersion(out)).toEqual({
      version: "bpftool v7.8.0",
      hasSkeletons: true,
    });
  });

  it("flags builds without skeleton support (empty features line)", () => {
    // Ubuntu's linux-tools bpftool prints an empty features list.
    const out = "bpftool v7.4.0\nusing libbpf v1.4\nfeatures:\n";
    expect(parseBpftoolVersion(out)).toEqual({
      version: "bpftool v7.4.0",
      hasSkeletons: false,
    });
  });

  it("flags builds whose features list lacks skeletons", () => {
    const out = "bpftool v7.2.0\nusing libbpf v1.2\nfeatures: libbfd, llvm\n";
    expect(parseBpftoolVersion(out).hasSkeletons).toBe(false);
  });

  it("returns null for old builds that print no features line", () => {
    const out = "bpftool v5.4.0\n";
    expect(parseBpftoolVersion(out)).toEqual({
      version: "bpftool v5.4.0",
      hasSkeletons: null,
    });
  });
});

describe("poll failure handling", () => {
  it("does not swap in mock data or enter demo mode when a live poll throws", async () => {
    // buildSnapshot is mocked to throw (see vi.mock above), simulating an
    // unexpected failure mid-poll in live mode.
    await triggerPoll();

    // Previously this fell back to a MOCK_PROGS snapshot with demoMode
    // still false — synthetic data presented as live.
    expect(getLatestSnapshot()).toBeNull();
    expect(isDemoMode()).toBe(false);
    expect(getPollerStatus().lastError).toContain("boom");
  });
});

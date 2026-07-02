import { describe, expect, it } from "vitest";
import { parseBpftoolVersion } from "./ebpf-poller";

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

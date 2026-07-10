import { describe, expect, it } from "vitest";
import {
  dedupeNetnsLabels,
  parseNsInode,
  pickNetnsLabel,
} from "./ebpf-netns";

describe("parseNsInode", () => {
  it("parses the readlink target of /proc/<pid>/ns/net", () => {
    expect(parseNsInode("net:[4026531840]")).toBe("4026531840");
    expect(parseNsInode("net:[4026533042]\n")).toBe("4026533042");
  });

  it("rejects non-netns links", () => {
    expect(parseNsInode("pid:[4026531836]")).toBeNull();
    expect(parseNsInode("")).toBeNull();
    expect(parseNsInode("net:[]")).toBeNull();
  });
});

describe("pickNetnsLabel", () => {
  it("prefers the lowest-pid non-pause process", () => {
    expect(
      pickNetnsLabel([
        { pid: 100, comm: "pause" },
        { pid: 250, comm: "nginx" },
        { pid: 300, comm: "nginx" },
      ])
    ).toBe("nginx");
  });

  it("falls back to pause when nothing else lives there", () => {
    expect(pickNetnsLabel([{ pid: 100, comm: "pause" }])).toBe("pause");
  });

  it("handles empty process lists", () => {
    expect(pickNetnsLabel([])).toBe("unknown");
  });
});

describe("dedupeNetnsLabels", () => {
  const reach = (nsPath: string) => ({ via: "nsenter" as const, nsPath });

  it("suffixes duplicate labels with the inode tail", () => {
    const refs = dedupeNetnsLabels([
      { id: "4026533042", label: "systemd", reach: reach("/proc/100/ns/net") },
      { id: "4026533108", label: "systemd", reach: reach("/proc/200/ns/net") },
      { id: "4026533200", label: "bpflab", reach: reach("/var/run/netns/bpflab") },
    ]);
    expect(refs.map(r => r.label)).toEqual([
      "systemd#3042",
      "systemd#3108",
      "bpflab",
    ]);
  });

  it("leaves unique labels untouched", () => {
    const refs = dedupeNetnsLabels([
      { id: "1", label: "a", reach: reach("x") },
      { id: "2", label: "b", reach: reach("y") },
    ]);
    expect(refs.map(r => r.label)).toEqual(["a", "b"]);
  });
});

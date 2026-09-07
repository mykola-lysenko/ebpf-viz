import { describe, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({ execFile: vi.fn() }));
vi.mock("child_process", async () => {
  const { promisify } = await import("util");
  return {
    execFile: Object.assign(vi.fn(), { [promisify.custom]: mocks.execFile }),
  };
});
import {
  dumpMapEntries,
  parseMapDumpOutput,
  parseEntry,
} from "./ebpf-map-dump";
import { diffMapEntries } from "../shared/snapshot-diff";

describe("map dump failures", () => {
  it.each(["[]", '[{"key":["0x01"],"value":["0x02"]}]'])(
    "preserves nonzero exit with valid stdout %s",
    async stdout => {
      mocks.execFile.mockRejectedValueOnce(
        Object.assign(new Error("permission denied"), {
          stdout,
          stderr: "EPERM",
          code: 1,
        })
      );
      const result = await dumpMapEntries(1, "hash", "m", "bpftool", false);
      expect(result.complete).toBe(false);
      expect(result.error).toContain("permission denied");
      expect(result.entries.length).toBe(JSON.parse(stdout).length);
      expect(diffMapEntries(result, result).identical).toBe(false);
    }
  );
  it.each(["null", "", '{"error":"permission denied"}', "[null]", "[{}]"])(
    "rejects malformed output %s as an unavailable dump",
    stdout => {
      const result = parseMapDumpOutput(stdout, "", 1, "hash", "m");
      expect(result.error).toBeTruthy();
      expect(diffMapEntries(result, result).identical).toBe(false);
    }
  );
  it("surfaces per-CPU read errors", () => {
    const entry = parseEntry(
      {
        key: ["0x01"],
        values: [
          { cpu: 0, value: ["0x01"] },
          { cpu: 1, value: { error: "EFAULT" } },
        ],
      },
      0
    );
    expect(entry.valueError).toContain("CPU 1: EFAULT");
    expect(diffMapEntries([entry], [entry]).identical).toBe(false);
  });
});

it("compares BTF arrays without treating numeric elements as hex-byte strings", () => {
  const a = parseMapDumpOutput(
    '[{"key":[1,2],"value":[3,4]}]',
    "",
    1,
    "hash",
    "m"
  );
  const b = parseMapDumpOutput(
    '[{"key":[1,2],"value":[3,5]}]',
    "",
    1,
    "hash",
    "m"
  );
  expect(a.error).toBeNull();
  expect(a.entries[0]).toMatchObject({ keyBtf: "[1,2]", valueBtf: "[3,4]" });
  expect(diffMapEntries(a, b).changed).toHaveLength(1);
});

import { describe, expect, it } from "vitest";
import {
  compatibleOptions,
  defaultKeyInterpret,
  interpretHex,
  loadInterpretPrefs,
  saveInterpretPrefs,
} from "./interpretation";

describe("map entry byte interpretation", () => {
  it("passes through raw, missing, structured, and malformed values", () => {
    expect(interpretHex("aa bb", "raw")).toBe("aa bb");
    expect(interpretHex("", "ipv4")).toBe("");
    expect(interpretHex("—", "ipv4")).toBe("—");
    expect(interpretHex('{"decoded":true}', "ipv4")).toBe('{"decoded":true}');
    expect(interpretHex("not hex", "ipv4")).toBe("not hex");
  });

  it("interprets common network byte layouts", () => {
    expect(interpretHex("c0 a8 01 01", "ipv4")).toBe("192.168.1.1");
    expect(
      interpretHex("20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01", "ipv6")
    ).toBe("2001:db8::1");
    expect(interpretHex("aa bb cc dd ee ff", "mac")).toBe("aa:bb:cc:dd:ee:ff");
    expect(interpretHex("01 bb", "port")).toBe("443 (https)");
    expect(interpretHex("06", "proto")).toBe("6 (TCP)");
  });

  it("validates byte lengths for narrow interpretation modes", () => {
    expect(interpretHex("c0 a8 01", "ipv4")).toBe("(need 4B, got 3B)");
    expect(interpretHex("01", "port")).toBe("(need 2B, got 1B)");
    expect(interpretHex("aa bb cc dd ee", "mac")).toBe("(need 6B, got 5B)");
    expect(interpretHex("06 11", "proto")).toBe("(need 1B, got 2B)");
  });

  it("interprets little-endian and big-endian integer toggles", () => {
    expect(interpretHex("01 00 00 00", "u32")).toBe("1");
    expect(interpretHex("00 00 00 01", "u32", true)).toBe("1");
    expect(interpretHex("01 00 00 00 00 00 00 00", "u64")).toBe("1");
    expect(interpretHex("00 00 00 00 00 00 00 01", "u64", true)).toBe("1");
  });

  it("interprets cgroup storage keys and timestamps", () => {
    expect(interpretHex("01 00 00 00 00 00 00 00", "cgroupid")).toBe(
      "inode: 1"
    );
    expect(
      interpretHex("01 00 00 00 00 00 00 00 07 00 00 00", "cgroupid")
    ).toBe("inode: 1, attach: inet_connect");
    expect(interpretHex("00 00 00 00 00 00 00 00", "ts")).toBe("0 (never)");
    expect(interpretHex("e8 03 00 00 00 00 00 00", "ts")).toBe("1000ns");
  });

  it("selects safe default key interpretations by map type", () => {
    expect(defaultKeyInterpret("array")).toBe("u32");
    expect(defaultKeyInterpret("percpu_array")).toBe("u32");
    expect(defaultKeyInterpret("cgroup_storage")).toBe("cgroupid");
    expect(defaultKeyInterpret("percpu_cgroup_storage")).toBe("cgroupid");
    expect(defaultKeyInterpret("hash")).toBe("raw");
  });

  it("filters compatible interpretation options by byte length", () => {
    expect(compatibleOptions(undefined).length).toBeGreaterThan(
      compatibleOptions(4).length
    );
    expect(compatibleOptions(4).map(option => option.value)).toEqual([
      "raw",
      "ipv4",
      "u32",
    ]);
    expect(compatibleOptions(12).map(option => option.value)).toEqual([
      "raw",
      "cgroupid",
    ]);
  });

  it("handles missing localStorage defensively in node tests", () => {
    expect(loadInterpretPrefs("hash")).toBeNull();
    expect(() => saveInterpretPrefs("hash", "ipv4", "u64")).not.toThrow();
  });
});

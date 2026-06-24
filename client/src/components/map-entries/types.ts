export type DisplayMode = "hex" | "decimal" | "btf";

export type InterpretMode =
  | "raw"
  | "ipv4"
  | "ipv6"
  | "mac"
  | "port"
  | "u32"
  | "u64"
  | "cgroupid"
  | "proto"
  | "ts";

export interface InterpretPrefs {
  key: InterpretMode;
  val: InterpretMode;
}

export const PAGE_SIZE = 50;

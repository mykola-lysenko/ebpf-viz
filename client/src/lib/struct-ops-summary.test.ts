import { describe, expect, it } from "vitest";
import {
  buildStructOpsGroups,
  structOpsProgramFamily,
} from "./struct-ops-summary";

describe("struct ops summary helpers", () => {
  it("classifies common TCP struct_ops callback names", () => {
    expect(structOpsProgramFamily("tcp_init")).toBe("TCP");
    expect(structOpsProgramFamily("tcp_reno_cong_avoid")).toBe("TCP Reno");
    expect(structOpsProgramFamily("dctcp_update_alpha")).toBe("DCTCP");
    expect(structOpsProgramFamily("ssthresh")).toBe("Congestion control");
    expect(structOpsProgramFamily("set_state")).toBe("Lifecycle/state");
  });

  it("groups programs by callback family and totals runtime/memory", () => {
    const groups = buildStructOpsGroups(
      [
        { id: 1, name: "tcp_init", memlock: 100 },
        { id: 2, name: "tcp_reno_cong_avoid", memlock: 200 },
        { id: 3, name: "tcp_reno_ssthresh", memlock: 300 },
      ],
      new Map([
        [1, 1],
        [2, 7],
        [3, 3],
      ])
    );

    expect(groups).toEqual([
      {
        family: "TCP Reno",
        count: 2,
        totalMemlock: 500,
        totalCallsPerSec: 10,
        examples: ["tcp_reno_cong_avoid", "tcp_reno_ssthresh"],
      },
      {
        family: "TCP",
        count: 1,
        totalMemlock: 100,
        totalCallsPerSec: 1,
        examples: ["tcp_init"],
      },
    ]);
  });
});

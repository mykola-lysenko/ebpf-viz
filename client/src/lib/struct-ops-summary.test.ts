import { describe, expect, it } from "vitest";
import {
  buildStructOpsKindSummaries,
  buildTcpCongestionControlSummaries,
  describeStructOpsProgram,
} from "./struct-ops-summary";

const structOpsMaps = [
  {
    id: 100,
    type: "struct_ops",
    rawType: "struct_ops",
    name: "tcp_d2tcp_ops",
    btfId: 10,
  },
  {
    id: 101,
    type: "struct_ops",
    rawType: "struct_ops",
    name: "tcp_dctcp_ops",
    btfId: 11,
  },
  {
    id: 102,
    type: "struct_ops",
    rawType: "struct_ops",
    name: "tcp_d2tcp_ops",
    btfId: 12,
  },
] as const;

describe("struct ops summary helpers", () => {
  it("uses struct_ops map BTF IDs to classify bare TCP callbacks", () => {
    expect(
      describeStructOpsProgram(
        { id: 1, name: "ssthresh", memlock: 100, btfId: 10 },
        [...structOpsMaps]
      )
    ).toMatchObject({
      kind: "tcp_congestion_ops",
      kindLabel: "TCP congestion control",
      algorithm: "D2TCP",
      callback: "ssthresh",
      confidence: "high",
      sourceLabel: "struct_ops map",
      sourceDetail: "tcp_d2tcp_ops · BTF id 10",
    });

    expect(
      describeStructOpsProgram(
        { id: 2, name: "set_state", memlock: 100, btfId: 11 },
        [...structOpsMaps]
      )
    ).toMatchObject({
      kind: "tcp_congestion_ops",
      algorithm: "DCTCP",
      callback: "set_state",
      confidence: "high",
      sourceLabel: "struct_ops map",
    });
  });

  it("separates struct_ops kind, algorithm, and callback role", () => {
    expect(
      describeStructOpsProgram({
        id: 1,
        name: "tcp_init",
        memlock: 100,
      })
    ).toMatchObject({
      kind: "tcp_congestion_ops",
      algorithm: "TCP",
      callback: "init",
      confidence: "low",
      sourceLabel: "program name",
    });

    expect(
      describeStructOpsProgram({
        id: 2,
        name: "tcp_reno_cong_avoid",
        memlock: 100,
      })
    ).toMatchObject({
      kind: "tcp_congestion_ops",
      algorithm: "TCP Reno",
      callback: "cong_avoid",
      confidence: "medium",
      sourceLabel: "program name",
    });

    expect(
      describeStructOpsProgram({
        id: 3,
        name: "dctcp_update_alpha",
        memlock: 100,
      })
    ).toMatchObject({
      kind: "tcp_congestion_ops",
      algorithm: "DCTCP",
      callback: "update_alpha",
      confidence: "medium",
      sourceLabel: "program name",
    });
  });

  it("groups TCP congestion control by algorithm instead of callback family", () => {
    const summaries = buildStructOpsKindSummaries(
      [
        { id: 1, name: "ssthresh", memlock: 100, btfId: 10 },
        { id: 2, name: "d2tcp_acked", memlock: 200, btfId: 10 },
        { id: 3, name: "dctcp_update_alpha", memlock: 300, btfId: 11 },
        { id: 4, name: "ssthresh", memlock: 400, btfId: 12 },
      ],
      [...structOpsMaps],
      new Map([
        [1, 1],
        [2, 7],
        [3, 3],
        [4, 0],
      ])
    );

    expect(summaries).toHaveLength(1);
    expect(summaries[0]).toMatchObject({
      kind: "tcp_congestion_ops",
      label: "TCP congestion control",
      count: 4,
      activeCount: 3,
      totalMemlock: 1000,
      totalCallsPerSec: 11,
    });
    expect(
      summaries[0].algorithms.map(algorithm => ({
        algorithm: algorithm.algorithm,
        count: algorithm.count,
        examples: algorithm.examples,
        confidence: algorithm.confidence,
        sourceLabel: algorithm.sourceLabel,
        btfIds: algorithm.btfIds,
        callbackRoleCount: algorithm.callbackRoleCount,
        instanceCount: algorithm.instanceCount,
        duplicateInstanceCount: algorithm.duplicateInstanceCount,
      }))
    ).toEqual([
      {
        algorithm: "D2TCP",
        count: 3,
        examples: ["ssthresh", "acked"],
        confidence: "high",
        sourceLabel: "struct_ops map",
        btfIds: [10, 12],
        callbackRoleCount: 2,
        instanceCount: 2,
        duplicateInstanceCount: 1,
      },
      {
        algorithm: "DCTCP",
        count: 1,
        examples: ["update alpha"],
        confidence: "high",
        sourceLabel: "struct_ops map",
        btfIds: [11],
        callbackRoleCount: 1,
        instanceCount: 1,
        duplicateInstanceCount: 0,
      },
    ]);
  });

  it("returns only TCP congestion control algorithms for network rendering", () => {
    const algorithms = buildTcpCongestionControlSummaries(
      [
        { id: 1, name: "tcp_reno_cong_avoid", memlock: 100 },
        { id: 2, name: "other_callback", memlock: 200 },
      ],
      [],
      new Map([[1, 4]])
    );

    expect(algorithms).toHaveLength(1);
    expect(algorithms[0]).toMatchObject({
      algorithm: "TCP Reno",
      count: 1,
      totalCallsPerSec: 4,
    });
  });
});

import type { ProgramChain } from "./ebpf-types";

export function isTcxChain(chain: ProgramChain): boolean {
  return chain.mechanism === "tcx" || chain.attachType.startsWith("tcx/");
}

/** Older TC captures without explicit ordering evidence stay unverified. */
export function hasKnownChainOrder(chain: ProgramChain): boolean {
  if (chain.ordering) return chain.ordering !== "unknown";
  return chain.hookType !== "tc" || chain.chainSource === "tc-filter";
}

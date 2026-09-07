import type { ProgramChain } from "../../../shared/ebpf-types";
import { hasKnownChainOrder, isTcxChain } from "../../../shared/chain-order";

export function ChainOrderEvidence({ chain }: { chain: ProgramChain }) {
  if (chain.hookType !== "tc") return null;
  const tcx = isTcxChain(chain), known = hasKnownChainOrder(chain);
  return <div className="mb-2 text-[10px] leading-relaxed text-muted-foreground" role="status">
    <p className={known ? "text-cyan-300/80" : "text-amber-300"}>
      {tcx ? "TCX" : "Legacy TC"} · {known ? tcx ? "kernel query order" : "classifier priority order" : "Order unknown"}
      {tcx && ` · ${chain.revision === undefined ? "revision unavailable" : `revision ${chain.revision}`}`}
    </p>
    {!known && <p>Captured rows do not establish execution order; positions and path predictions are unverified.</p>}
    {tcx && <p>NEXT (-1) continues to the next TCX program; PASS (0), DROP (2), or REDIRECT (7) ends this stage. TCX continuation prediction is not yet modeled.</p>}
    {chain.afterTcx && <p>Reached only if all preceding TCX programs return NEXT (-1).</p>}
  </div>;
}

import {
  buildCfgSummary,
  computeCfgSummaryFingerprint,
} from "@/lib/cfg-summary";
import type { CfgSummary, ProgDump } from "../../../shared/ebpf-types";

const CFG_SUMMARY_CACHE_LIMIT = 24;
const cfgSummaryCache = new Map<string, CfgSummary>();

type CfgSummaryDump = Pick<
  ProgDump,
  "progId" | "cfgDot" | "xlated" | "cfgSummary"
>;

function touchCacheEntry(key: string, summary: CfgSummary): CfgSummary {
  cfgSummaryCache.delete(key);
  cfgSummaryCache.set(key, summary);
  while (cfgSummaryCache.size > CFG_SUMMARY_CACHE_LIMIT) {
    const oldestKey = cfgSummaryCache.keys().next().value;
    if (oldestKey === undefined) break;
    cfgSummaryCache.delete(oldestKey);
  }
  return summary;
}

export function getCachedCfgSummary(dump: CfgSummaryDump): CfgSummary {
  const serverSummary = dump.cfgSummary;
  const fingerprint =
    serverSummary?.fingerprint ??
    computeCfgSummaryFingerprint(dump.cfgDot, dump.xlated);
  const key = `${dump.progId}:${fingerprint}`;

  const cached = cfgSummaryCache.get(key);
  if (cached) {
    return touchCacheEntry(key, cached);
  }

  return touchCacheEntry(
    key,
    serverSummary ?? buildCfgSummary(dump.cfgDot, dump.xlated, fingerprint)
  );
}

export function clearCfgSummaryCacheForTests() {
  cfgSummaryCache.clear();
}

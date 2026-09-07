/** Collection evidence travels with a snapshot. All times are Unix milliseconds.
 * Missing metadata means unknown coverage (older captures), never success. */
export interface CollectionSourceStatus {
  label: string;
  state: "ok" | "partial" | "error" | "unsupported" | "skipped" | "unknown";
  attemptedAt: number | null;
  lastSuccessAt: number | null;
  error?: string;
  detail?: string;
  count?: number;
}

export interface CollectionStatus {
  sources: Record<string, CollectionSourceStatus>;
  namespaces?: {
    limit: number;
    discovered: number;
    scanned: number;
    skipped: number;
    omitted: number;
    discoveryAt: number;
  };
}

export const COLLECTION_SOURCE_LABELS: Record<string, string> = {
  progs: "Programs", maps: "Maps", net: "Host network attachments",
  cgroups: "Cgroup attachments", cgroupsEffective: "Effective cgroup attachments",
  links: "BPF links", namespaceDiscovery: "Namespace discovery",
};

export function collectionSources(collection: CollectionStatus): Record<string, CollectionSourceStatus> {
  const sources = { ...collection.sources };
  for (const [key, label] of Object.entries(COLLECTION_SOURCE_LABELS)) {
    sources[key] ??= { label, state: "unknown", attemptedAt: null, lastSuccessAt: null,
      detail: "This source has no collection metadata" };
  }
  return sources;
}

export function hasCollectionGaps(collection?: CollectionStatus): boolean {
  return !collection || !!collection.namespaces?.omitted || !!collection.namespaces?.skipped ||
    Object.values(collectionSources(collection)).some(source => source.state !== "ok");
}

export function collectionError(collection: CollectionStatus): string | null {
  const failed = Object.values(collection.sources).filter(s => s.state === "error" || s.state === "partial");
  return failed.length ? failed.map(s => `${s.label}: ${s.error ?? s.detail ?? s.state}`).join("; ") : null;
}

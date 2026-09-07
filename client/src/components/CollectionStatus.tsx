import type { CollectionStatus as Status } from "../../../shared/collection-status";
import { hasCollectionGaps, collectionSources } from "../../../shared/collection-status";

function time(value: number | null) {
  return value === null ? "never" : new Date(value).toISOString();
}

/** Shared by the live shell and both sides of the snapshot diff. */
export function CollectionStatus({ collection, demo = false }: { collection?: Status; demo?: boolean }) {
  if (demo) return null;
  if (!collection || Object.keys(collection.sources).length === 0) {
    return <div className="rounded border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-200" role="status">
      Collection coverage unknown — this snapshot has no collection metadata.
    </div>;
  }
  const gaps = hasCollectionGaps(collection);
  const sources = Object.entries(collectionSources(collection));
  return <details className={`rounded border px-3 py-2 text-xs ${gaps ? "border-amber-500/30 bg-amber-500/5 text-amber-200" : "border-border text-muted-foreground"}`}>
    <summary className="cursor-pointer">
      {gaps ? "Collection has gaps — some data is stale, unavailable, or unverified" : "Collection complete"}
      {` (${sources.filter(([, s]) => s.state === "ok").length}/${sources.length} sources successful)`}
    </summary>
    {collection.namespaces && <p className="mt-2">
      Namespaces: {collection.namespaces.discovered} discovered, {collection.namespaces.scanned} scanned,
      {" "}{collection.namespaces.skipped} deferred, {collection.namespaces.omitted} omitted;
      limit {collection.namespaces.limit}. Discovery: {time(collection.namespaces.discoveryAt)}.
    </p>}
    <ul className="mt-2 space-y-2">
      {sources.map(([key, source]) => <li key={key}>
        <strong>{source.label}</strong>: {source.state}
        {source.count !== undefined && ` (${source.count} records)`}
        {source.state !== "ok" && ` — ${source.lastSuccessAt !== null ? "last-known data" : "no successful collection recorded"}`}
        <div>Last success: {time(source.lastSuccessAt)}; attempted: {time(source.attemptedAt)}.</div>
        {(source.error || source.detail) && <div className="break-words">{source.error ?? source.detail}</div>}
      </li>)}
    </ul>
  </details>;
}

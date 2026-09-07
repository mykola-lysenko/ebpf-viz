import type { CollectionSourceStatus } from "../shared/collection-status";

export function describeCollectionError(error: unknown): { state: "error" | "unsupported"; error: string } {
  const message = error instanceof Error ? error.message : String(error);
  const code = (error as { code?: unknown } | null)?.code;
  return {
    state: code === "ENOENT" || code === 127 || /operation not supported|not supported|command not found|executable file not found|unrecognized (command|option)/i.test(message)
      ? "unsupported" : "error",
    error: message.slice(0, 2048),
  };
}

/** One cache per source; a failed attempt never replaces successful data.
 * Callers validate inside read(), before accepting a result. */
export class SourceCollector {
  private cache = new Map<string, { value: unknown; at: number }>();
  sources: Record<string, CollectionSourceStatus> = {};

  begin() { this.sources = {}; }
  clear() { this.cache.clear(); this.begin(); }
  prune() {
    for (const key of Array.from(this.cache.keys())) if (!(key in this.sources)) this.cache.delete(key);
  }

  async read<T>(key: string, label: string, read: () => Promise<T>, fallback: T, successAt: (value: T) => number = () => Date.now()): Promise<T> {
    const attemptedAt = Date.now();
    try {
      const value = await read();
      const at = successAt(value);
      this.cache.set(key, { value: JSON.parse(JSON.stringify(value)), at });
      this.sources[key] = { label, state: "ok", attemptedAt, lastSuccessAt: at,
        ...(Array.isArray(value) ? { count: value.length } : {}) };
      return value;
    } catch (error) {
      const previous = this.cache.get(key);
      this.sources[key] = { label, ...describeCollectionError(error), attemptedAt,
        lastSuccessAt: previous?.at ?? null };
      return previous ? JSON.parse(JSON.stringify(previous.value)) as T : fallback;
    }
  }

  skip<T>(key: string, label: string, detail: string, fallback: T): T {
    const previous = this.cache.get(key);
    this.sources[key] = { label, state: "skipped", attemptedAt: null,
      lastSuccessAt: previous?.at ?? null, detail };
    return previous ? JSON.parse(JSON.stringify(previous.value)) as T : fallback;
  }
}

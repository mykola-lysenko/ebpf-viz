import { z } from "zod";
import { expensiveProcedure, operatorProcedure, publicProcedure, router } from "./_core/trpc";
import {
  getLatestSnapshot,
  getLatestMaps,
  getPollerStatus,
  triggerPoll,
  updateConfig,
  getAllHistories,
  getHistory,
  buildActivitySummary,
  isStatsEnabled,
  getBpftoolPath,
  isDemoMode,
  isSudoEnabled,
} from "./ebpf-poller";
import { fetchProgDump } from "./ebpf-dump";
import { buildSnapshot } from "./ebpf-parser";
import { parseMaps } from "./ebpf-map-parser";
import { buildMockProgDump } from "./ebpf-mock-dump";
import { dumpMapEntries, parseEntry, MAX_DUMP_ENTRIES } from "./ebpf-map-dump";
import type { RawMapEntry, MapDumpResult } from "../shared/ebpf-types";
import { buildMockMapDump } from "./ebpf-mock-map-dump";

export const appRouter = router({
  ebpf: router({
    // ── Core snapshot ──────────────────────────────────────────────────────
    /** Full snapshot — all programs, interfaces, cgroup tree, kernel zones */
    snapshot: publicProcedure.query(() => {
      return getLatestSnapshot();
    }),

    /** Poller status and config */
    status: publicProcedure.query(() => {
      return getPollerStatus();
    }),

    /** Single program by ID */
    program: publicProcedure
      .input(z.object({ id: z.number() }))
      .query(({ input }) => {
        const snap = getLatestSnapshot();
        if (!snap) return null;
        return snap.programs.find(p => p.id === input.id) ?? null;
      }),

    /** Update polling configuration */
    updateConfig: operatorProcedure
      .input(
        z.object({
          intervalMs: z.number().min(1000).max(60000).optional(),
          demoMode: z.boolean().optional(),
          bpftoolPath: z.string().regex(/^\/[a-zA-Z0-9/_.-]+$/, "bpftoolPath must be an absolute path (starting with /) containing only alphanumeric characters, slashes, dots, underscores, and hyphens").refine(s => !s.includes(".."), "bpftoolPath must not contain '..'").optional(),
          sudo: z.boolean().optional(),
        })
      )
      .mutation(({ input }) => {
        updateConfig(input);
        return { success: true };
      }),

    /** Force an immediate poll */
    refresh: operatorProcedure.mutation(async () => {
      await triggerPoll();
      return getLatestSnapshot();
    }),

    /** Lightweight summary stats */
    stats: publicProcedure.query(() => {
      const snap = getLatestSnapshot();
      if (!snap) return null;
      return {
        timestamp: snap.timestamp,
        total: snap.stats.total,
        byType: snap.stats.byType,
        jited: snap.stats.jited,
        orphaned: snap.stats.orphaned,
        demoMode: snap.demoMode,
        hostname: snap.hostname,
        kernelVersion: snap.kernelVersion,
      };
    }),

    // ── BPF Maps ───────────────────────────────────────────────────────────
    /** All BPF maps with program relationships */
    maps: publicProcedure.query(() => {
      return getLatestMaps();
    }),

    /** Single map by ID */
    map: publicProcedure
      .input(z.object({ id: z.number() }))
      .query(({ input }) => {
        return getLatestMaps().find(m => m.id === input.id) ?? null;
      }),

    /**
     * Dump entries from a BPF map by ID.
     * Calls `bpftool -jp map dump id N` and returns parsed key-value pairs.
     * Returns up to 1000 entries; truncated flag is set if more exist.
     */
    mapDump: expensiveProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const snap = getLatestSnapshot();
        const maps = getLatestMaps();
        const map = maps.find(m => m.id === input.id);
        const mapType = map?.rawType ?? "unknown";
        const mapName = map?.name ?? `map#${input.id}`;
        // In demo mode, return realistic mock entries — real map IDs don't exist in the kernel
        if (isDemoMode()) {
          return buildMockMapDump(input.id, mapType, mapName);
        }
        const bpftoolPath = getBpftoolPath();
        return dumpMapEntries(input.id, mapType, mapName, bpftoolPath, isSudoEnabled());
      }),
    // ── Map entry counts ──────────────────────────────────────────────────────────────────
    /**
     * Returns the live entry count for every dumpable map in one batch call.
     * Unsupported map types (ringbuf, perf_event_array, etc.) are marked with
     * unsupported: true and count: null.
     */
    mapEntryCounts: expensiveProcedure.query(async () => {
      const maps = getLatestMaps();
      const bpftoolPath = getBpftoolPath();
      const sudo = isSudoEnabled();
      const demo = isDemoMode();

      // Process maps in batches to avoid spawning hundreds of concurrent
      // bpftool processes on systems with many maps (each has 20MB maxBuffer).
      const BATCH_SIZE = 8;
      const results: { mapId: number; count: number | null; unsupported: boolean }[] = [];

      for (let i = 0; i < maps.length; i += BATCH_SIZE) {
        const batch = maps.slice(i, i + BATCH_SIZE);
        const batchResults = await Promise.all(
          batch.map(async (map) => {
            const result = demo
              ? buildMockMapDump(map.id, map.rawType, map.name)
              : await dumpMapEntries(map.id, map.rawType, map.name, bpftoolPath, sudo);
            return {
              mapId: map.id,
              count: result.unsupported || result.error ? null : result.totalEntries,
              unsupported: result.unsupported ?? false,
            };
          }),
        );
        results.push(...batchResults);
      }

      return results;
    }),

    // ── Code Inspector ──────────────────────────────────────────────────────────────────
    /**
     * Fetch the full code dump for a single BPF program:
     * xlated bytecode, CFG DOT, jited assembly (when available),
     * and BTF line-number info (when available).
     */
    progDump: expensiveProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const snap = getLatestSnapshot();
        const prog = snap?.programs.find(p => p.id === input.id);
        if (!prog) return null;
        // In demo mode, use mock dump — real bpftool IDs don't exist in the kernel
        if (snap?.demoMode) {
          return buildMockProgDump(input.id, prog.rawType, !!prog.btfId, prog.jited);
        }
        try {
          const dump = await fetchProgDump(input.id, !!prog.btfId, prog.jited);
          if (prog.btfId) dump.btfId = prog.btfId;
          return dump;
        } catch (err) {
          console.error("[progDump] failed for id", input.id, err);
          return null;
        }
      }),

    // ── Snapshot parsing ───────────────────────────────────────────────────
    /**
     * Parse a raw bpftool snapshot (from capture-snapshot.sh) into a full EbpfSnapshot.
     * Accepts the raw JSON envelope with { raw: { progs, maps, net, cgroups }, hostname, kernelVersion, ... }
     * and runs the full server-side buildSnapshot() pipeline.
     */
    parseSnapshot: publicProcedure
      .input(z.object({
        raw: z.object({
          progs: z.array(z.any()),
          maps: z.array(z.any()).optional(),
          net: z.array(z.any()).optional(),
          cgroups: z.array(z.any()).optional(),
        }),
        hostname: z.string().optional(),
        kernelVersion: z.string().optional(),
        bpftoolVersion: z.string().optional(),
        capturedAt: z.string().optional(),
        timestamp: z.number().optional(),
      }))
      .mutation(({ input }) => {
        const snap = buildSnapshot(
          input.raw.progs,
          input.raw.net ?? [],
          input.raw.cgroups ?? [],
          {
            hostname: input.hostname ?? "unknown",
            kernelVersion: input.kernelVersion ?? "unknown",
            bpftoolVersion: input.bpftoolVersion ?? "unknown",
            demoMode: false,
          }
        );
        // Preserve the original capture timestamp if provided
        if (input.timestamp) snap.timestamp = input.timestamp;
        // Parse maps from raw data and cross-reference with programs
        const maps = parseMaps((input.raw.maps ?? []) as import("../shared/ebpf-types").RawBpfMap[], snap.programs);
        return { snapshot: snap, maps };
      }),

    /**
     * Parse a map dump file produced by `capture-snapshot.sh --dump-maps`.
     * Accepts { _ebpfVizMapDumps: true, mapDumps: { [mapId]: RawMapEntry[] } }
     * and returns a Record<number, MapDumpResult> keyed by map ID.
     * The client stores this in EbpfContext and uses it to serve mapDump queries
     * in snapshot mode without calling the live bpftool.
     */
    parseMapDumps: publicProcedure
      .input(z.object({
        mapDumps: z.record(z.string(), z.array(z.any())),
        // Optional: BpfMap metadata to enrich the results
        maps: z.array(z.object({
          id: z.number(),
          rawType: z.string(),
          name: z.string(),
        })).optional(),
      }))
      .mutation(({ input }) => {
        const result: Record<number, MapDumpResult> = {};
        const mapsById = new Map((input.maps ?? []).map(m => [m.id, m]));

        for (const [idStr, rawEntries] of Object.entries(input.mapDumps)) {
          const mapId = parseInt(idStr, 10);
          if (isNaN(mapId)) continue;

          const mapMeta = mapsById.get(mapId);
          const mapType = mapMeta?.rawType ?? "unknown";
          const mapName = mapMeta?.name ?? `map#${mapId}`;

          const entries = (rawEntries as RawMapEntry[]).slice(0, MAX_DUMP_ENTRIES).map((r, i) => parseEntry(r, i));
          const btfDecoded = entries.length > 0 && (
            (rawEntries[0] as RawMapEntry).key !== undefined &&
            !Array.isArray((rawEntries[0] as RawMapEntry).key) &&
            typeof (rawEntries[0] as RawMapEntry).key === "object"
          );

          result[mapId] = {
            mapId,
            mapType,
            mapName,
            totalEntries: entries.length,
            truncated: (rawEntries as unknown[]).length > MAX_DUMP_ENTRIES,
            maxReturned: MAX_DUMP_ENTRIES,
            btfDecoded,
            error: null,
            unsupported: false,
            entries,
          };
        }

        return result;
      }),

    // ── Runtime statistics ─────────────────────────────────────────────────
    /**
     * Full ring-buffer history for all programs.
     * Returns up to RING_SIZE samples per program with derived rates.
     */
    allHistory: publicProcedure.query(() => {
      return getAllHistories();
    }),

    /**
     * Ring-buffer history for a single program.
     */
    programHistory: publicProcedure
      .input(z.object({ id: z.number() }))
      .query(({ input }) => {
        return getHistory(input.id);
      }),

    /**
     * Activity summary — top-N programs by calls/sec, total CPU fraction.
     * Lightweight — suitable for polling every second from the dashboard.
     */
    activity: publicProcedure.query(() => {
      const snap = getLatestSnapshot();
      if (!snap) {
        return {
          topByCallsPerSec: [],
          totalCallsPerSec: 0,
          totalCpuFraction: 0,
          statsEnabled: isStatsEnabled(),
        };
      }
      return buildActivitySummary(snap.programs, isStatsEnabled());
    }),
  }),
});

export type AppRouter = typeof appRouter;

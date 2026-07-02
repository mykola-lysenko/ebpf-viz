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
import { fetchProgDump, fetchProgReturnAnalysis } from "./ebpf-dump";
import { buildSnapshot } from "./ebpf-parser";
import { parseMaps } from "./ebpf-map-parser";
import { buildMockProgDump } from "./ebpf-mock-dump";
import {
  dumpMapEntries,
  parseEntry,
  parseProgArrayTargets,
  MAX_DUMP_ENTRIES,
} from "./ebpf-map-dump";
import type { RawBpfLink, RawBpfMap, RawBpfProg, RawCgroupEntry, RawMapEntry, RawNetSnapshot, MapDumpResult, ProgramReturnAnalysisResult } from "../shared/ebpf-types";
import { parseMapDumpsInputSchema, rawSnapshotInputSchema } from "../shared/snapshot-validation";
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
     * Returns live entry counts for a bounded set of map IDs.
     * Each count still requires a bpftool dump, so callers must request only
     * maps the user is looking at instead of polling the whole system.
     */
    mapEntryCounts: expensiveProcedure
      .input(z.object({ ids: z.array(z.number().int().nonnegative()).max(32) }))
      .query(async ({ input }) => {
        const requestedIds = new Set(input.ids);
        const maps = getLatestMaps().filter(map => requestedIds.has(map.id));
        const bpftoolPath = getBpftoolPath();
        const sudo = isSudoEnabled();
        const demo = isDemoMode();

        // Process maps in batches to avoid spawning too many concurrent
        // bpftool processes (each has 20MB maxBuffer).
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

    /**
     * Lightweight return-value analysis for multiple programs.
     * Dumps only xlated bytecode, not CFG/JIT, so the Network chain can show
     * packet verdict hints without rendering full code inspectors.
     */
    progReturnAnalysis: expensiveProcedure
      .input(z.object({ ids: z.array(z.number().int().nonnegative()).min(1).max(64) }))
      .query(async ({ input }) => {
        const snap = getLatestSnapshot();
        if (!snap) return [];

        const programsById = new Map(snap.programs.map(prog => [prog.id, prog]));
        const ids = Array.from(new Set(input.ids));
        const results: ProgramReturnAnalysisResult[] = [];

        for (const id of ids) {
          const prog = programsById.get(id);
          if (!prog) {
            results.push({ progId: id, returnAnalysis: null, error: "program not found" });
            continue;
          }

          if (snap.demoMode) {
            const dump = buildMockProgDump(id, prog.rawType, !!prog.btfId, prog.jited);
            results.push({ progId: id, returnAnalysis: dump.returnAnalysis ?? null });
            continue;
          }

          try {
            results.push(await fetchProgReturnAnalysis(id, !!prog.btfId));
          } catch (err) {
            results.push({
              progId: id,
              returnAnalysis: null,
              error: err instanceof Error ? err.message : String(err),
            });
          }
        }

        return results;
      }),

    // ── Snapshot parsing ───────────────────────────────────────────────────
    /**
     * Parse a raw bpftool snapshot (from capture-snapshot.sh) into a full EbpfSnapshot.
     * Accepts the raw JSON envelope with { raw: { progs, maps, net, cgroups }, hostname, kernelVersion, ... }
     * and runs the full server-side buildSnapshot() pipeline.
     */
    parseSnapshot: publicProcedure
      .input(rawSnapshotInputSchema)
      .mutation(({ input }) => {
        const rawNet = (input.raw.net ?? []) as RawNetSnapshot[];
        const rawTcFilters = input.raw.tcFilters as
          | RawNetSnapshot["tcFilters"]
          | undefined;
        const net =
          rawTcFilters && rawTcFilters.length > 0
            ? [
                { ...(rawNet[0] ?? {}), tcFilters: rawTcFilters },
                ...rawNet.slice(1),
              ]
            : rawNet;
        const snap = buildSnapshot(
          input.raw.progs as RawBpfProg[],
          net,
          (input.raw.cgroups ?? []) as RawCgroupEntry[],
          {
            hostname: input.hostname ?? "unknown",
            kernelVersion: input.kernelVersion ?? "unknown",
            bpftoolVersion: input.bpftoolVersion ?? "unknown",
            demoMode: false,
          },
          (input.raw.cgroupsEffective ?? []) as RawCgroupEntry[],
          (input.raw.links ?? []) as RawBpfLink[]
        );
        // Preserve the original capture timestamp if provided
        if (input.timestamp !== undefined) snap.timestamp = input.timestamp;
        // Parse maps from raw data and cross-reference with programs
        const maps = parseMaps((input.raw.maps ?? []) as RawBpfMap[], snap.programs);
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
      .input(parseMapDumpsInputSchema)
      .mutation(({ input }) => {
        const result: Record<number, MapDumpResult> = {};
        const mapsById = new Map((input.maps ?? []).map(m => [m.id, m]));

        for (const [idStr, rawEntries] of Object.entries(input.mapDumps)) {
          const mapId = parseInt(idStr, 10);
          if (isNaN(mapId)) continue;

          const mapMeta = mapsById.get(mapId);
          const mapType = mapMeta?.rawType ?? "unknown";
          const mapName = mapMeta?.name ?? `map#${mapId}`;

          const totalEntries = rawEntries.length;
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
            totalEntries,
            truncated: totalEntries > MAX_DUMP_ENTRIES,
            maxReturned: MAX_DUMP_ENTRIES,
            btfDecoded,
            error: null,
            unsupported: false,
            entries,
            ...(mapType.toLowerCase().replace(/-/g, "_") === "prog_array"
              ? {
                  progArrayTargets: parseProgArrayTargets(
                    (rawEntries as RawMapEntry[]).slice(0, MAX_DUMP_ENTRIES),
                    mapId,
                  ),
                }
              : {}),
          };
        }

        return result;
      }),

    // ── Runtime statistics ─────────────────────────────────────────────────
    /**
     * Full ring-buffer history for all programs.
     * Returns up to PROG_HISTORY_RING_SIZE samples per program with derived rates.
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

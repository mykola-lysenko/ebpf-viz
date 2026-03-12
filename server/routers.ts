import { z } from "zod";
import { publicProcedure, router } from "./_core/trpc";
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
} from "./ebpf-poller";
import { fetchProgDump } from "./ebpf-dump";
import { buildSnapshot } from "./ebpf-parser";
import { parseMaps } from "./ebpf-map-parser";
import { buildMockProgDump } from "./ebpf-mock-dump";
import { dumpMapEntries } from "./ebpf-map-dump";
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
    updateConfig: publicProcedure
      .input(
        z.object({
          intervalMs: z.number().min(1000).max(60000).optional(),
          demoMode: z.boolean().optional(),
          bpftoolPath: z.string().optional(),
          sudo: z.boolean().optional(),
        })
      )
      .mutation(({ input }) => {
        updateConfig(input);
        return { success: true };
      }),

    /** Force an immediate poll */
    refresh: publicProcedure.mutation(async () => {
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
    mapDump: publicProcedure
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
        return dumpMapEntries(input.id, mapType, mapName, bpftoolPath);
      }),
    // ── Map entry counts ──────────────────────────────────────────────────────────────────
    /**
     * Returns the live entry count for every dumpable map in one batch call.
     * Unsupported map types (ringbuf, perf_event_array, etc.) are marked with
     * unsupported: true and count: null.
     */
    mapEntryCounts: publicProcedure.query(async () => {
      const maps = getLatestMaps();
      const bpftoolPath = getBpftoolPath();
      const demo = isDemoMode();

      const results = await Promise.all(
        maps.map(async (map) => {
          const result = demo
            ? buildMockMapDump(map.id, map.rawType, map.name)
            : await dumpMapEntries(map.id, map.rawType, map.name, bpftoolPath);
          return {
            mapId: map.id,
            count: result.unsupported || result.error ? null : result.totalEntries,
            unsupported: result.unsupported ?? false,
          };
        }),
      );
      return results;
    }),

    // ── Code Inspector ──────────────────────────────────────────────────────────────────
    /**
     * Fetch the full code dump for a single BPF program:
     * xlated bytecode, CFG DOT, jited assembly (when available),
     * and BTF line-number info (when available).
     */
    progDump: publicProcedure
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

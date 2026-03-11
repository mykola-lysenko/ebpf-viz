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
} from "./ebpf-poller";
import { fetchProgDump } from "./ebpf-dump";

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
    // ── BPF Maps ───────────────────────────────────────────────────────────────────
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

    // ── Code Inspector ─────────────────────────────────────────────────────────
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
        try {
          const dump = await fetchProgDump(input.id, !!prog.btfId, prog.jited);
          if (prog.btfId) dump.btfId = prog.btfId;
          return dump;
        } catch (err) {
          console.error("[progDump] failed for id", input.id, err);
          return null;
        }
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

import { z } from "zod";
import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router } from "./_core/trpc";
import {
  getLatestSnapshot,
  getPollerStatus,
  triggerPoll,
  updateConfig,
  getAllHistories,
  getHistory,
  buildActivitySummary,
  isStatsEnabled,
} from "./ebpf-poller";

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),

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

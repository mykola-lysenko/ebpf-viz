import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import type { TrpcContext } from "./context";
import { checkRateLimit, hasOperatorAccess } from "./security";

const t = initTRPC.context<TrpcContext>().create({
  transformer: superjson,
});

export const router = t.router;
export const publicProcedure = t.procedure;

const operatorAccessMiddleware = t.middleware(({ ctx, path, next }) => {
  if (!hasOperatorAccess(ctx.req)) {
    throw new TRPCError({
      code: "FORBIDDEN",
      message: `Operator access required for ${path}. Use loopback access or send an admin token.`,
    });
  }
  return next();
});

const operatorRateLimitMiddleware = t.middleware(({ ctx, path, next }) => {
  const retryAfterMs = checkRateLimit(ctx.req, path, {
    key: "operator",
    max: 30,
    windowMs: 60_000,
  });
  if (retryAfterMs !== null) {
    throw new TRPCError({
      code: "TOO_MANY_REQUESTS",
      message: `Rate limit exceeded for ${path}. Retry in ${Math.ceil(retryAfterMs / 1000)}s.`,
    });
  }
  return next();
});

const expensiveRateLimitMiddleware = t.middleware(({ ctx, path, next }) => {
  const retryAfterMs = checkRateLimit(ctx.req, path, {
    key: "expensive",
    max: 20,
    windowMs: 60_000,
  });
  if (retryAfterMs !== null) {
    throw new TRPCError({
      code: "TOO_MANY_REQUESTS",
      message: `Rate limit exceeded for ${path}. Retry in ${Math.ceil(retryAfterMs / 1000)}s.`,
    });
  }
  return next();
});

export const operatorProcedure = publicProcedure
  .use(operatorAccessMiddleware)
  .use(operatorRateLimitMiddleware);

export const expensiveProcedure = publicProcedure
  .use(operatorAccessMiddleware)
  .use(expensiveRateLimitMiddleware);

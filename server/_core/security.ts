import { createHash, timingSafeEqual } from "crypto";

type RequestLike = {
  headers?: Record<string, string | string[] | undefined>;
  ip?: string;
  socket?: { remoteAddress?: string | null };
  connection?: { remoteAddress?: string | null };
};

type RateLimitOptions = {
  key: string;
  max: number;
  windowMs: number;
};

type RateLimitBucket = {
  count: number;
  resetAt: number;
};

const rateLimitBuckets = new Map<string, RateLimitBucket>();
let lastRateLimitSweep = 0;

function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function normalizeAddress(address: string | null | undefined): string {
  if (!address) return "";
  if (address.startsWith("::ffff:")) return address.slice("::ffff:".length);
  return address;
}

function hashToken(token: string): Buffer {
  return createHash("sha256").update(token).digest();
}

function safeTokenEqual(a: string, b: string): boolean {
  return timingSafeEqual(hashToken(a), hashToken(b));
}

export function getClientAddress(req: RequestLike): string {
  return normalizeAddress(
    req.socket?.remoteAddress ??
    req.connection?.remoteAddress ??
    req.ip
  );
}

export function isLoopbackAddress(address: string): boolean {
  const normalized = normalizeAddress(address);
  return normalized === "::1" ||
    normalized === "0:0:0:0:0:0:0:1" ||
    normalized === "localhost" ||
    normalized.startsWith("127.");
}

export function isLoopbackRequest(req: RequestLike): boolean {
  return isLoopbackAddress(getClientAddress(req));
}

export function getConfiguredAdminToken(): string | null {
  return process.env.EBPF_VIZ_ADMIN_TOKEN || process.env.ADMIN_TOKEN || null;
}

export function getRequestAdminToken(req: RequestLike): string | null {
  const headerToken =
    firstHeader(req.headers?.["x-ebpf-viz-admin-token"]) ??
    firstHeader(req.headers?.["x-admin-token"]);
  if (headerToken) return headerToken;

  const authorization = firstHeader(req.headers?.authorization);
  const match = authorization?.match(/^Bearer\s+(.+)$/i);
  return match?.[1] ?? null;
}

export function hasOperatorAccess(req: RequestLike): boolean {
  if (isLoopbackRequest(req)) return true;

  const configuredToken = getConfiguredAdminToken();
  if (!configuredToken) return false;

  const requestToken = getRequestAdminToken(req);
  if (!requestToken) return false;

  return safeTokenEqual(requestToken, configuredToken);
}

export function checkRateLimit(
  req: RequestLike,
  path: string,
  options: RateLimitOptions,
): number | null {
  const now = Date.now();
  const client = getClientAddress(req) || "unknown";
  const bucketKey = `${options.key}:${client}:${path}`;

  // Opportunistic cleanup keeps the map bounded without a background timer.
  if (now - lastRateLimitSweep > options.windowMs) {
    lastRateLimitSweep = now;
    for (const [key, bucket] of Array.from(rateLimitBuckets.entries())) {
      if (bucket.resetAt <= now) rateLimitBuckets.delete(key);
    }
  }

  const current = rateLimitBuckets.get(bucketKey);
  if (!current || current.resetAt <= now) {
    rateLimitBuckets.set(bucketKey, { count: 1, resetAt: now + options.windowMs });
    return null;
  }

  if (current.count >= options.max) {
    return current.resetAt - now;
  }

  current.count += 1;
  return null;
}

export function resetRateLimitsForTests(): void {
  rateLimitBuckets.clear();
  lastRateLimitSweep = 0;
}

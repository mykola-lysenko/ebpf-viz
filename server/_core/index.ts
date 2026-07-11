import "../polyfill"; // Must be first — installs Web API globals on Node < 18
import "dotenv/config";
import express from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { serveStatic, setupVite } from "./vite";
import { restoreKernelSettings, startPoller, stopPoller } from "../ebpf-poller";
import { sseHandler } from "../sse";
import { isAllowedHost } from "./security";

function isPortAvailable(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const server = net.createServer();
    server.listen(port, () => {
      server.close(() => resolve(true));
    });
    server.on("error", () => resolve(false));
  });
}

async function findAvailablePort(startPort: number = 3000): Promise<number> {
  for (let port = startPort; port < startPort + 20; port++) {
    if (await isPortAvailable(port)) {
      return port;
    }
  }
  throw new Error(`No available port found starting from ${startPort}`);
}

async function startServer() {
  const app = express();
  const server = createServer(app);

  // Health check endpoint — exempt from the Host guard below (it exposes only
  // uptime, and load-balancer probes hit it by IP with a non-matching Host).
  app.get("/healthz", (_req, res) => {
    res.json({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() });
  });

  // Host-header allowlist — rejects DNS-rebinding / cross-origin requests
  // before anything sensitive runs (see server/_core/security.ts). Applies to
  // every route below so a rebound page can't reach the API, SSE, or the SPA
  // that would then XHR the API. Add trusted hostnames via EBPF_VIZ_ALLOWED_HOSTS.
  app.use((req, res, next) => {
    if (isAllowedHost(req)) return next();
    res
      .status(403)
      .type("text/plain")
      .send(
        "Forbidden: untrusted Host header. Reach the dashboard at " +
        "http://localhost:<port>/, or set EBPF_VIZ_ALLOWED_HOSTS to trust " +
        "additional hostnames."
      );
  });

  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ limit: "50mb", extended: true }));

  // SSE live-stream endpoint (must be before Vite catch-all)
  app.get("/api/sse", sseHandler);

  // tRPC API
  //
  // Node 16 compatibility shim
  // ─────────────────────────
  // tRPC's Express adapter uses the Fetch API internally (Response, ReadableStream,
  // WritableStream). On Node 16, several issues arise:
  //
  //   1. The 'close' event fires synchronously inside res.end(), causing tRPC's
  //      AbortController to abort mid-stream and truncate the response body.
  //
  //   2. The 'aborted' event (deprecated in Node 17) also fires independently,
  //      bypassing any 'close' event deferral.
  //
  //   3. Both events can interrupt pipeTo() before all chunks are written,
  //      resulting in "Unexpected end of JSON input" on the client.
  //
  // Root fix: intercept res.write() to buffer all chunks in memory, then send
  // the complete buffer in a single res.end(buffer) call. This:
  //   - Sets Content-Length automatically (no chunked transfer encoding)
  //   - Eliminates all mid-stream abort races
  //   - Works identically on Node 16, 18, and 22
  //
  // Additionally:
  //   - Make res.end() idempotent to guard against double-end races
  //   - Swallow ERR_STREAM_WRITE_AFTER_END errors to prevent process crashes
  //   - Defer 'close' listeners by one tick as a belt-and-suspenders measure
  const trpcMiddleware = createExpressMiddleware({ router: appRouter, createContext });
  app.use("/api/trpc", (req, res, next) => {
    // ── Node 16 tRPC response buffering shim ──────────────────────────────────
    //
    // Problem: tRPC's writeResponse() uses pipeTo() internally. On Node 16,
    // the AbortController fires synchronously inside res.end(), aborting the
    // stream mid-write and truncating the JSON body ("Unexpected end of JSON").
    //
    // Additionally, tRPC's internal_exceptionHandler calls res.end(errorJson)
    // to send error responses, but writeResponse()'s `finally { res.end() }`
    // block fires first (with no body). Our `ended` guard was blocking the
    // subsequent error JSON call, producing 500 with Content-Length: 0.
    //
    // Fix strategy:
    //   1. Buffer all res.write() chunks in memory.
    //   2. On res.end(): if called with no body AND no prior write() chunks,
    //      treat it as a "finish signal" — mark as pendingEmpty and defer.
    //      If a subsequent res.end(body) arrives with actual content, use that.
    //   3. Flush the complete buffer in a single originalEnd() call.
    //   4. Log all 500 errors with stack traces for debugging.
    const chunks: Buffer[] = [];
    const originalEnd = res.end.bind(res);
    let ended = false;
    let pendingEmptyEnd = false;
    let pendingEmptyCallback: (() => void) | undefined;

    function flush(extraChunk?: Buffer, callback?: () => void) {
      if (ended) return;
      ended = true;
      if (extraChunk && extraChunk.length > 0) chunks.push(extraChunk);
      const combined = Buffer.concat(chunks);
      if (combined.length > 0 && !res.headersSent) {
        res.setHeader("Content-Length", combined.length);
      }
      if (combined.length > 0) {
        (originalEnd as (...a: unknown[]) => unknown)(combined, callback);
      } else {
        (originalEnd as (...a: unknown[]) => unknown)(callback);
      }
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (res as any).write = function bufferedWrite(
      chunk: Buffer | string,
      encodingOrCb?: BufferEncoding | ((err?: Error | null) => void),
      cb?: (err?: Error | null) => void
    ) {
      if (ended) return false;
      const buf = Buffer.isBuffer(chunk)
        ? chunk
        : Buffer.from(chunk, typeof encodingOrCb === "string" ? encodingOrCb : "utf8");
      chunks.push(buf);
      const callback = typeof encodingOrCb === "function" ? encodingOrCb : cb;
      if (callback) setImmediate(callback);
      return true;
    };

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (res as any).end = function bufferedEnd(
      chunkOrCb?: Buffer | string | (() => void),
      encodingOrCb?: BufferEncoding | (() => void),
      cb?: () => void
    ) {
      if (ended) return res;

      const callback = typeof chunkOrCb === "function"
        ? chunkOrCb
        : typeof encodingOrCb === "function"
          ? encodingOrCb
          : cb;

      // Determine if this call carries actual body content
      const hasBody = chunkOrCb != null && typeof chunkOrCb !== "function";
      const bodyBuf = hasBody
        ? (Buffer.isBuffer(chunkOrCb)
            ? chunkOrCb as Buffer
            : Buffer.from(chunkOrCb as string, typeof encodingOrCb === "string" ? encodingOrCb : "utf8"))
        : undefined;
      const bodyLen = bodyBuf ? bodyBuf.length : 0;

      if (bodyLen === 0 && chunks.length === 0) {
        // This is tRPC's `finally { res.end() }` finish signal — no body yet.
        // Defer it: a subsequent end(errorJson) from internal_exceptionHandler
        // may arrive with the actual error body.
        if (!pendingEmptyEnd) {
          pendingEmptyEnd = true;
          pendingEmptyCallback = callback;
          setImmediate(() => {
            // If nothing else flushed us, send the empty end now
            if (!ended) flush(undefined, pendingEmptyCallback);
          });
        }
        return res;
      }

      // We have real content — flush immediately (cancels the deferred empty end)
      flush(bodyBuf, callback);
      return res;
    };

    // Defer 'close' listeners by one tick (belt-and-suspenders for Node 16)
    const originalOnce = res.once.bind(res);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (res as any).once = function patchedOnce(event: string, listener: (...args: unknown[]) => void) {
      if (event === "close") {
        return originalOnce(event, (...args: unknown[]) => {
          setImmediate(() => listener(...args));
        });
      }
      return originalOnce(event, listener);
    };

    // Log all 500 errors with the request path for easier debugging
    const origSetHeader = res.setHeader.bind(res);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (res as any).setHeader = function loggedSetHeader(name: string, value: string | number | readonly string[]) {
      return origSetHeader(name, value);
    };

    // Intercept writeHead to log 500s
    const origWriteHead = res.writeHead.bind(res);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (res as any).writeHead = function loggedWriteHead(statusCode: number, ...args: unknown[]) {
      if (statusCode >= 500) {
        console.error(`[trpc] ${statusCode} on ${req.method} ${req.path}`);
      }
      return (origWriteHead as (...a: unknown[]) => unknown)(statusCode, ...args);
    };

    // Swallow write-after-end errors so they don't kill the process
    res.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ERR_STREAM_WRITE_AFTER_END") return; // expected on Node 16
      console.error(`[trpc] response stream error on ${req.method} ${req.path}:`, err.message);
    });

    trpcMiddleware(req, res, next);
  });

  // Development mode uses Vite, production mode uses static files
  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  const preferredPort = parseInt(process.env.PORT || "3000");
  const port = await findAvailablePort(preferredPort);

  if (port !== preferredPort) {
    console.log(`Port ${preferredPort} is busy, using port ${port} instead`);
  }

  // HOST controls the network interface to bind on.
  // Defaults to loopback (127.0.0.1) so an accidental run never exposes the
  // dashboard — and the kernel BPF state it serves — to the LAN/WSL bridge.
  // Set HOST explicitly to bind wider: "0.0.0.0" (all IPv4), "::" (all IPv6,
  // also IPv4 on dual-stack). When binding beyond loopback, also set
  // EBPF_VIZ_ALLOWED_HOSTS or the Host-header guard will 403 those clients.
  const host = process.env.HOST || "127.0.0.1";
  const displayHost = host.includes(":") ? `[${host}]` : host;
  server.listen(port, host, () => {
    console.log(`Server running on http://${displayHost}:${port}/`);
  });
}

startServer().catch(console.error);

// Start eBPF polling service. The first poll runs in the background so
// the HTTP server is ready immediately — SSE clients get data as soon
// as the first poll completes.
startPoller().catch(err => {
  console.error("[ebpf-poller] Failed to start:", err);
});

// Restore kernel settings we changed (bpf_stats_enabled) before exiting.
let shuttingDown = false;
async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) {
    // Second signal: the restore is stuck (e.g. sudo prompting after its
    // cached credentials expired) — exit now rather than trapping the user.
    console.error("[server] repeated signal — exiting without restore");
    process.exit(1);
  }
  shuttingDown = true;
  console.log(`[server] ${signal} received — shutting down`);
  stopPoller();
  try {
    // Bounded: never let a blocking sudo hold the process open forever.
    await Promise.race([
      restoreKernelSettings(),
      new Promise(resolve => setTimeout(resolve, 5_000)),
    ]);
  } catch { /* best-effort */ }
  process.exit(0);
}
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

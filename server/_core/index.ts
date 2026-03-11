import "../polyfill"; // Must be first — installs Web API globals on Node < 18
import "dotenv/config";
import express from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { serveStatic, setupVite } from "./vite";
import { startPoller } from "../ebpf-poller";
import { sseHandler } from "../sse";

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

  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ limit: "50mb", extended: true }));

  // SSE live-stream endpoint (must be before Vite catch-all)
  app.get("/api/sse", sseHandler);

  // tRPC API
  //
  // Node 16 compatibility shim
  // ─────────────────────────
  // On Node 16, ServerResponse emits 'close' synchronously *inside* res.end().
  // tRPC's incomingMessageToRequest() listens for res.once('close', onAbort) and
  // uses it to abort the AbortController that guards pipeTo(). Because 'close'
  // fires while the async microtask queue is still unwinding after pipeTo(), the
  // abort can fire *before* pipeTo() has fully resolved, causing two problems:
  //
  //   1. Truncated JSON body — pipeTo() is interrupted mid-stream, writeResponseBody
  //      catches the AbortError and returns early, then finally{} calls res.end()
  //      with only partial data written → client sees "Unexpected end of JSON input".
  //
  //   2. ERR_STREAM_WRITE_AFTER_END crash — internal_exceptionHandler calls
  //      res.end(errorJson) after writeResponse's finally{} already called res.end().
  //
  // Fix: intercept res.once('close', cb) and defer the callback by one event-loop
  // tick (setImmediate). By the time the deferred callback runs, pipeTo() has
  // already resolved and the full body has been written. This is safe because a
  // 1-tick delay still properly aborts genuinely disconnected clients.
  // Additionally, make res.end() idempotent to guard against the double-end race.
  const trpcMiddleware = createExpressMiddleware({ router: appRouter, createContext });
  app.use("/api/trpc", (req, res, next) => {
    // Defer 'close' listeners by one tick so pipeTo() resolves before abort fires
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
    // Make res.end() idempotent to guard against the double-end race
    const originalEnd = res.end.bind(res);
    let ended = false;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (res as any).end = function patchedEnd(...args: unknown[]) {
      if (ended) return res; // already ended — swallow the second call
      ended = true;
      return (originalEnd as (...a: unknown[]) => unknown)(...args);
    };
    // Swallow write-after-end errors so they don't kill the process
    res.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ERR_STREAM_WRITE_AFTER_END") return; // expected on Node 16
      console.error("[trpc] unexpected response stream error:", err.message);
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
  // Use "::" to listen on all IPv6 interfaces (also accepts IPv4 on dual-stack
  // systems via IPv4-mapped addresses). Use "0.0.0.0" for IPv4-only. When HOST
  // is unset Node.js defaults to 0.0.0.0 (all IPv4 interfaces).
  const host = process.env.HOST;

  if (host) {
    const displayHost = host.includes(":") ? `[${host}]` : host;
    server.listen(port, host, () => {
      console.log(`Server running on http://${displayHost}:${port}/`);
    });
  } else {
    server.listen(port, () => {
      console.log(`Server running on http://localhost:${port}/`);
    });
  }
}

startServer().catch(console.error);

// Start eBPF polling service
startPoller().catch(err => {
  console.error("[ebpf-poller] Failed to start:", err);
});

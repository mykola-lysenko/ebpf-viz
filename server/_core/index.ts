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

  // Health check endpoint — useful for monitoring and load-balancer probes
  app.get("/healthz", (_req, res) => {
    res.json({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() });
  });

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
    // Buffer all res.write() calls; flush everything in res.end()
    const chunks: Buffer[] = [];
    const originalWrite = res.write.bind(res);
    const originalEnd = res.end.bind(res);
    let ended = false;

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
      // Call the callback if provided (signals backpressure resolved)
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
      ended = true;

      // Collect any final chunk passed directly to end()
      if (chunkOrCb && typeof chunkOrCb !== "function") {
        const buf = Buffer.isBuffer(chunkOrCb)
          ? chunkOrCb
          : Buffer.from(chunkOrCb, typeof encodingOrCb === "string" ? encodingOrCb : "utf8");
        chunks.push(buf);
      }

      // Combine all buffered chunks into one buffer and send
      const combined = Buffer.concat(chunks);
      if (combined.length > 0 && !res.headersSent) {
        res.setHeader("Content-Length", combined.length);
      }

      const callback = typeof chunkOrCb === "function"
        ? chunkOrCb
        : typeof encodingOrCb === "function"
          ? encodingOrCb
          : cb;

      if (combined.length > 0) {
        return (originalEnd as (...a: unknown[]) => unknown)(combined, callback);
      }
      return (originalEnd as (...a: unknown[]) => unknown)(callback);
    };

    // Defer 'close' listeners by one tick (belt-and-suspenders)
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

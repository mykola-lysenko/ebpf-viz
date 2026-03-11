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
  app.use(
    "/api/trpc",
    createExpressMiddleware({
      router: appRouter,
      createContext,
    })
  );

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

/**
 * Web API polyfill for Node.js < 18.
 *
 * Node 18 added fetch, Headers, Request, Response, and FormData as globals.
 * Node 16 does not have them. tRPC's Express adapter uses `new Headers()`
 * internally, so without this polyfill every tRPC call throws
 * "ReferenceError: Headers is not defined" on Node 16.
 *
 * This module must be imported BEFORE any other server code.
 * It installs the missing globals from `undici` (v5, Node 16 compatible)
 * only when they are not already present, so it is a no-op on Node 18+.
 */

const nodeMajor = parseInt(process.versions.node.split(".")[0], 10);

if (nodeMajor < 18) {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const undici = require("undici") as typeof import("undici");

  const g = globalThis as Record<string, unknown>;

  if (!g.fetch)     g.fetch     = undici.fetch;
  if (!g.Headers)   g.Headers   = undici.Headers;
  if (!g.Request)   g.Request   = undici.Request;
  if (!g.Response)  g.Response  = undici.Response;
  if (!g.FormData)  g.FormData  = undici.FormData;

  console.log(`[polyfill] Installed Web API globals from undici (Node ${process.versions.node})`);
}

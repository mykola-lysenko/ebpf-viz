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
 *
 * Node 16 pipeTo abort fix
 * ─────────────────────────
 * On Node 16, the HTTP ServerResponse emits 'close' synchronously inside
 * res.end(). tRPC's incomingMessageToRequest() wires both res.once('close')
 * and req.once('aborted') to an AbortController that is passed as the signal
 * to ReadableStream.pipeTo(). When either event fires while pipeTo() is still
 * draining its microtask queue, the abort interrupts the stream mid-write and
 * the client receives a truncated JSON body ("Unexpected end of JSON input").
 *
 * Fix: patch ReadableStream.prototype.pipeTo (from stream/web, available since
 * Node 16.5) to silently strip the signal option before delegating to the
 * original implementation. This ensures the response body is always written
 * completely before the stream closes, regardless of when the abort fires.
 * The trade-off is that genuinely disconnected clients on Node 16 will still
 * receive the full body (wasted work), but this is acceptable for a dev/internal
 * tool where correctness matters more than early-disconnect optimisation.
 */

const nodeMajor = parseInt(process.versions.node.split(".")[0], 10);

if (nodeMajor < 18) {
  // undici provides fetch/Headers/etc. for Node 16.
  // The require is wrapped in try/catch so the standalone esbuild bundle
  // (which inlines all deps) doesn't fail at bundle time if undici isn't
  // installed — the standalone tarball ships a separate copy via npm.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let undici: Record<string, any> | null = null;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    undici = require("undici");
  } catch {
    console.error("[polyfill] undici not found — install it for Node 16 support: npm install undici@5");
  }

  const g = globalThis as Record<string, unknown>;

  if (undici) {
    if (!g.fetch)     g.fetch     = undici.fetch;
    if (!g.Headers)   g.Headers   = undici.Headers;
    if (!g.Request)   g.Request   = undici.Request;
    if (!g.Response)  g.Response  = undici.Response;
    if (!g.FormData)  g.FormData  = undici.FormData;
  }

  // Patch ReadableStream.prototype.pipeTo to strip the abort signal.
  // stream/web is available since Node 16.5.0 (the user is on 16.20.2).
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { ReadableStream } = require("stream/web") as typeof import("stream/web");
    // Also install ReadableStream / WritableStream / TransformStream as globals
    // so tRPC's internal checks (instanceof ReadableStream) work correctly.
    if (!g.ReadableStream)  g.ReadableStream  = ReadableStream;
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { WritableStream, TransformStream } = require("stream/web") as typeof import("stream/web");
    if (!g.WritableStream)  g.WritableStream  = WritableStream;
    if (!g.TransformStream) g.TransformStream = TransformStream;

    const origPipeTo = ReadableStream.prototype.pipeTo as (
      dest: WritableStream,
      options?: { signal?: AbortSignal; preventClose?: boolean; preventAbort?: boolean; preventCancel?: boolean }
    ) => Promise<void>;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (ReadableStream.prototype as any).pipeTo = function patchedPipeTo(
      dest: WritableStream,
      options?: Record<string, unknown>
    ) {
      // Strip the signal so a premature abort (Node 16 'close'/'aborted' events
      // firing synchronously inside res.end()) cannot truncate the response body.
      if (options && "signal" in options) {
        const { signal: _signal, ...rest } = options;
        return origPipeTo.call(this, dest, rest);
      }
      return origPipeTo.call(this, dest, options);
    };

    const what = undici ? "Web API globals + " : "";
    console.log(`[polyfill] Installed ${what}pipeTo abort-signal fix (Node ${process.versions.node})`);
  } catch {
    // stream/web unavailable (Node < 16.5) — skip the pipeTo patch
    if (undici) {
      console.log(`[polyfill] Installed Web API globals from undici (Node ${process.versions.node})`);
    }
  }
}

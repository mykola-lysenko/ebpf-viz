/**
 * Web API polyfill for Node.js < 18.
 *
 * Node 18 added fetch, Headers, Request, Response, and FormData as globals.
 * Node 16 does not have them. tRPC's Express adapter uses Headers, Request,
 * Response, and Web Streams internally, so without this polyfill every tRPC
 * call fails on Node 16.
 *
 * This module must be imported BEFORE any other server code.
 *
 * Node 16 pipeTo abort fix
 * --------------------------
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
 */

const nodeMajor = parseInt(process.versions.node.split(".")[0], 10);

if (nodeMajor < 18) {
  const g = globalThis as Record<string, unknown>;

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { ReadableStream, WritableStream, TransformStream } = require("stream/web") as typeof import("stream/web");

  g.ReadableStream = ReadableStream;
  g.WritableStream = WritableStream;
  g.TransformStream = TransformStream;

  let pipeToPatched = false;

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
  pipeToPatched = true;

  type HeaderInit = HeadersInit | LocalHeaders;

  const normalizeHeaderName = (name: string): string => name.trim().toLowerCase();

  const normalizeHeaderValue = (value: unknown): string => String(value).trim();

  const isIterableHeaders = (init: unknown): init is Iterable<[string, unknown]> => {
    return typeof init === "object" && init !== null && Symbol.iterator in init;
  };

  class LocalHeaders {
    private readonly headerValues = new Map<string, string[]>();

    constructor(init?: HeaderInit) {
      if (!init) return;

      if (init instanceof LocalHeaders) {
        for (const [name, value] of Array.from(init.rawEntries())) {
          this.append(name, value);
        }
        return;
      }

      if (isIterableHeaders(init)) {
        for (const [name, value] of Array.from(init)) {
          this.append(name, value);
        }
        return;
      }

      for (const [name, value] of Object.entries(init)) {
        this.append(name, value);
      }
    }

    append(name: string, value: unknown): void {
      const key = normalizeHeaderName(name);
      const normalizedValue = normalizeHeaderValue(value);
      const existing = this.headerValues.get(key);
      if (existing) {
        existing.push(normalizedValue);
      } else {
        this.headerValues.set(key, [normalizedValue]);
      }
    }

    delete(name: string): void {
      this.headerValues.delete(normalizeHeaderName(name));
    }

    get(name: string): string | null {
      const values = this.headerValues.get(normalizeHeaderName(name));
      if (!values || values.length === 0) return null;
      return values.join(", ");
    }

    getSetCookie(): string[] {
      return [...(this.headerValues.get("set-cookie") ?? [])];
    }

    has(name: string): boolean {
      return this.headerValues.has(normalizeHeaderName(name));
    }

    set(name: string, value: unknown): void {
      this.headerValues.set(normalizeHeaderName(name), [normalizeHeaderValue(value)]);
    }

    forEach(
      callbackfn: (value: string, key: string, parent: LocalHeaders) => void,
      thisArg?: unknown
    ): void {
      for (const [name, value] of Array.from(this.entries())) {
        callbackfn.call(thisArg, value, name, this);
      }
    }

    *entries(): IterableIterator<[string, string]> {
      for (const [name, values] of Array.from(this.headerValues.entries())) {
        yield [name, values.join(", ")];
      }
    }

    *keys(): IterableIterator<string> {
      for (const [name] of Array.from(this.headerValues.entries())) {
        yield name;
      }
    }

    *valuesIterator(): IterableIterator<string> {
      for (const [, values] of Array.from(this.headerValues.entries())) {
        yield values.join(", ");
      }
    }

    values(): IterableIterator<string> {
      return this.valuesIterator();
    }

    [Symbol.iterator](): IterableIterator<[string, string]> {
      return this.entries();
    }

    private *rawEntries(): IterableIterator<[string, string]> {
      for (const [name, values] of Array.from(this.headerValues.entries())) {
        for (const value of values) {
          yield [name, value];
        }
      }
    }
  }

  const isReadableStream = (value: unknown): value is ReadableStream<Uint8Array> => {
    return typeof value === "object"
      && value !== null
      && typeof (value as { getReader?: unknown }).getReader === "function";
  };

  const toBytes = (value: unknown): Uint8Array => {
    if (value == null) return new Uint8Array();
    if (typeof value === "string") return Buffer.from(value);
    if (Buffer.isBuffer(value)) return value;
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    return Buffer.from(String(value));
  };

  const toReadableStream = (value: unknown): ReadableStream<Uint8Array> | null => {
    if (value == null) return null;
    if (isReadableStream(value)) return value;

    const bytes = toBytes(value);
    return new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    }) as unknown as ReadableStream<Uint8Array>;
  };

  const readStream = async (stream: ReadableStream<Uint8Array>): Promise<Uint8Array> => {
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    let totalLength = 0;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const bytes = toBytes(value);
        chunks.push(bytes);
        totalLength += bytes.byteLength;
      }
    } finally {
      reader.releaseLock();
    }

    const merged = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return merged;
  };

  const copyArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);
    return copy.buffer;
  };

  abstract class BodyMixin {
    body: ReadableStream<Uint8Array> | null = null;
    bodyUsed = false;

    protected async consumeBody(): Promise<Uint8Array> {
      if (this.bodyUsed) {
        throw new TypeError("Body is unusable");
      }
      this.bodyUsed = true;
      if (!this.body) return new Uint8Array();
      return readStream(this.body);
    }

    async arrayBuffer(): Promise<ArrayBuffer> {
      return copyArrayBuffer(await this.consumeBody());
    }

    async text(): Promise<string> {
      return Buffer.from(await this.consumeBody()).toString("utf8");
    }

    async json(): Promise<unknown> {
      return JSON.parse(await this.text());
    }
  }

  type LocalRequestInit = {
    body?: unknown;
    duplex?: string;
    headers?: HeaderInit;
    method?: string;
    signal?: AbortSignal;
  };

  class LocalRequest extends BodyMixin {
    readonly headers: LocalHeaders;
    readonly method: string;
    readonly signal: AbortSignal;
    readonly url: string;

    constructor(input: string | URL | LocalRequest, init: LocalRequestInit = {}) {
      super();

      const base = input instanceof LocalRequest ? input : undefined;
      this.url = base?.url ?? input.toString();
      this.method = (init.method ?? base?.method ?? "GET").toUpperCase();
      this.headers = new LocalHeaders(init.headers ?? base?.headers);
      this.signal = init.signal ?? base?.signal ?? new AbortController().signal;
      this.body = toReadableStream("body" in init ? init.body : base?.body);
    }

    clone(): LocalRequest {
      if (this.bodyUsed) {
        throw new TypeError("Body is unusable");
      }
      return new LocalRequest(this, { body: this.body });
    }

    async formData(): Promise<LocalFormData> {
      throw new TypeError("[polyfill] multipart/form-data is not supported on the Node 16 standalone server.");
    }
  }

  type LocalResponseInit = {
    headers?: HeaderInit;
    status?: number;
    statusText?: string;
  };

  class LocalResponse extends BodyMixin {
    readonly headers: LocalHeaders;
    readonly status: number;
    readonly statusText: string;

    constructor(body?: unknown, init: LocalResponseInit = {}) {
      super();
      this.status = init.status ?? 200;
      this.statusText = init.statusText ?? "";
      this.headers = new LocalHeaders(init.headers);
      this.body = toReadableStream(body);
    }

    get ok(): boolean {
      return this.status >= 200 && this.status <= 299;
    }

    clone(): LocalResponse {
      if (this.bodyUsed) {
        throw new TypeError("Body is unusable");
      }
      return new LocalResponse(this.body, {
        headers: this.headers,
        status: this.status,
        statusText: this.statusText,
      });
    }

    static json(data: unknown, init: LocalResponseInit = {}): LocalResponse {
      const headers = new LocalHeaders(init.headers);
      if (!headers.has("content-type")) {
        headers.set("content-type", "application/json");
      }
      return new LocalResponse(JSON.stringify(data), { ...init, headers });
    }
  }

  class LocalFormData {
    private readonly values = new Map<string, unknown[]>();

    append(name: string, value: unknown): void {
      const key = String(name);
      const existing = this.values.get(key);
      if (existing) {
        existing.push(value);
      } else {
        this.values.set(key, [value]);
      }
    }

    delete(name: string): void {
      this.values.delete(String(name));
    }

    get(name: string): unknown | null {
      return this.values.get(String(name))?.[0] ?? null;
    }

    getAll(name: string): unknown[] {
      return [...(this.values.get(String(name)) ?? [])];
    }

    has(name: string): boolean {
      return this.values.has(String(name));
    }

    set(name: string, value: unknown): void {
      this.values.set(String(name), [value]);
    }

    *entries(): IterableIterator<[string, unknown]> {
      for (const [name, values] of Array.from(this.values.entries())) {
        for (const value of values) {
          yield [name, value];
        }
      }
    }

    [Symbol.iterator](): IterableIterator<[string, unknown]> {
      return this.entries();
    }
  }

  const fetchNotAvailable = (): Promise<never> => {
    return Promise.reject(new Error("[polyfill] fetch is not implemented on the Node 16 standalone server."));
  };

  g.fetch = fetchNotAvailable;
  g.Headers = LocalHeaders;
  g.Request = LocalRequest;
  g.Response = LocalResponse;
  g.FormData = LocalFormData;

  const installed = [
    "local Web API globals",
    pipeToPatched ? "pipeTo abort-signal fix" : "",
  ].filter(Boolean);

  console.log(`[polyfill] Installed ${installed.join(" + ")} (Node ${process.versions.node})`);
}

// @synsema/wasm — Synsema embebido en JS/TS (navegador, Node ≥ 18, Bun, Deno).
//
// Glue de la ABI cruda de `synsema-wasm-web` (ver engine/crates/synsema-wasm-web):
//   exports  synsema_alloc / synsema_free / synsema_call(json) -> [u32 len][json]
//   imports  synsema_host.{host_call, host_random_fill, host_now_ms}
//
// Dos modos:
//  - SÍNCRONO (`Synsema.run/test/check/handle`): el host que le pasás (http/kv/llm/log/
//    sleep) debe responder de forma síncrona. Ideal en Node con un KV en memoria o un
//    archivo JSON, o sin host.
//  - ASÍNCRONO (`Synsema.runAsync/handleAsync`): el intérprete corre en un Worker y
//    bloquea con Atomics.wait sobre un SharedArrayBuffer mientras tu `http`/`kv`/`llm`
//    async resuelven en el main thread (fetch del navegador, IndexedDB, un SDK de LLM).
//    En el navegador requiere cross-origin isolation (COOP/COEP) para SharedArrayBuffer.
//
// No hay estado global: cada `load()` es una instancia (memoria lineal propia).

const te = new TextEncoder();
const td = new TextDecoder();

const IS_NODE = typeof process !== "undefined" && process.versions && process.versions.node;

/** Lee el .wasm desde bytes, Module, URL/path o Response. */
export async function readModule(src) {
  if (src instanceof WebAssembly.Module) return src;
  if (src instanceof Uint8Array || src instanceof ArrayBuffer) return WebAssembly.compile(src);
  if (typeof Response !== "undefined" && src instanceof Response) {
    return WebAssembly.compile(await src.arrayBuffer());
  }
  const isFileLike =
    IS_NODE && (typeof src === "string" ? !/^https?:/.test(src) : src instanceof URL && src.protocol === "file:");
  if (isFileLike) {
    const { readFile } = await import("node:fs/promises");
    const { fileURLToPath } = await import("node:url");
    const p = typeof src === "string" ? src : fileURLToPath(src);
    return WebAssembly.compile(await readFile(p));
  }
  const res = await fetch(src);
  if (!res.ok) throw new Error(`synsema: cannot fetch ${src}: ${res.status}`);
  if (WebAssembly.compileStreaming) return WebAssembly.compileStreaming(res);
  return WebAssembly.compile(await res.arrayBuffer());
}

function randomFill(bytes) {
  const c = globalThis.crypto;
  if (!c || !c.getRandomValues) throw new Error("synsema: no crypto.getRandomValues in this host");
  // getRandomValues acepta hasta 65536 bytes por llamada.
  for (let i = 0; i < bytes.length; i += 65536) c.getRandomValues(bytes.subarray(i, Math.min(i + 65536, bytes.length)));
}

/** Qué ofrece un host: derivado de las funciones presentes. */
export function offersOf(host) {
  if (!host) return {};
  const o = {};
  if (typeof host.http === "function") o.http = true;
  if (host.kv && typeof host.kv.get === "function") o.kv = true;
  if (typeof host.llm === "function") o.llm = true;
  if (typeof host.log === "function") o.log = true;
  if (typeof host.sleep === "function" || host.sleep === true) o.sleep = true;
  return o;
}

/** Un hook async usado desde la API síncrona devolvería una Promise donde el intérprete
 *  espera un valor: en vez de un `{status: 0}` mudo, un error que nombra el fix. */
function syncOnly(kind, r) {
  if (r && typeof r.then === "function") {
    throw new Error(`synsema: the host \`${kind}\` hook returned a Promise — use runAsync/handleAsync (Worker + Atomics) or make the hook synchronous`);
  }
  return r;
}

/** Despacha un `host_call` (kind, payload) a un host SÍNCRONO. Devuelve un objeto
 *  JSON-serializable, o `undefined` si el host no ofrece ese hook. Un hook que devuelve
 *  una Promise es un error (lo ve el programa como `{error}` / lo lanza `synsema_call`). */
export function dispatchHostSync(host, kind, payload) {
  if (!host) return undefined;
  switch (kind) {
    case "http":
      return typeof host.http === "function" ? normalizeHttp(syncOnly("http", host.http(payload))) : undefined;
    case "kv_get":
      return host.kv ? { value: syncOnly("kv.get", host.kv.get(payload.ns, payload.key)) ?? null } : undefined;
    case "kv_set":
      if (!host.kv) return undefined;
      syncOnly("kv.set", host.kv.set(payload.ns, payload.key, payload.value));
      return {};
    case "kv_delete":
      if (!host.kv) return undefined;
      syncOnly("kv.delete", host.kv.delete?.(payload.ns, payload.key));
      return {};
    case "kv_list":
      return host.kv ? { keys: host.kv.list ? syncOnly("kv.list", host.kv.list(payload.ns)) : [] } : undefined;
    case "llm":
      return typeof host.llm === "function" ? normalizeLlm(syncOnly("llm", host.llm(payload.op, payload.prompt))) : undefined;
    case "log":
      if (typeof host.log !== "function") return undefined;
      host.log(payload.line);
      return {};
    case "sleep":
      if (typeof host.sleep === "function") {
        host.sleep(payload.secs);
        return {};
      }
      if (host.sleep === true) {
        sleepSync(payload.secs);
        return {};
      }
      return undefined;
    default:
      return undefined;
  }
}

/** Igual que dispatchHostSync pero el host puede devolver Promises. */
export async function dispatchHostAsync(host, kind, payload) {
  if (!host) return undefined;
  switch (kind) {
    case "http":
      return typeof host.http === "function" ? normalizeHttp(await host.http(payload)) : undefined;
    case "kv_get":
      return host.kv ? { value: (await host.kv.get(payload.ns, payload.key)) ?? null } : undefined;
    case "kv_set":
      if (!host.kv) return undefined;
      await host.kv.set(payload.ns, payload.key, payload.value);
      return {};
    case "kv_delete":
      if (!host.kv) return undefined;
      await host.kv.delete?.(payload.ns, payload.key);
      return {};
    case "kv_list":
      return host.kv ? { keys: host.kv.list ? await host.kv.list(payload.ns) : [] } : undefined;
    case "llm":
      return typeof host.llm === "function" ? normalizeLlm(await host.llm(payload.op, payload.prompt)) : undefined;
    case "log":
      if (typeof host.log !== "function") return undefined;
      await host.log(payload.line);
      return {};
    case "sleep":
      if (typeof host.sleep === "function") {
        await host.sleep(payload.secs);
        return {};
      }
      if (host.sleep === true) {
        await new Promise((r) => setTimeout(r, payload.secs * 1000));
        return {};
      }
      return undefined;
    default:
      return undefined;
  }
}

function normalizeHttp(r) {
  if (!r || typeof r !== "object") return { error: "host http returned nothing" };
  const out = { status: r.status | 0, headers: [] };
  if (r.error) out.error = String(r.error);
  if (r.headers) {
    if (Array.isArray(r.headers)) out.headers = r.headers;
    else if (typeof r.headers.forEach === "function" && !(r.headers instanceof Array)) {
      // Headers de fetch
      r.headers.forEach((v, k) => out.headers.push([k, v]));
    } else out.headers = Object.entries(r.headers);
  }
  if (r.body instanceof Uint8Array || r.body instanceof ArrayBuffer) {
    out.body_base64 = b64(r.body instanceof Uint8Array ? r.body : new Uint8Array(r.body));
  } else if (r.body != null) out.body = String(r.body);
  return out;
}

function normalizeLlm(r) {
  if (typeof r === "string") return { content: r, tokens: 0 };
  if (r && typeof r === "object") return { content: String(r.content ?? ""), tokens: r.tokens | 0 };
  return { content: "", tokens: 0 };
}

function b64(bytes) {
  if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function sleepSync(secs) {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, secs * 1000));
  } catch {
    // Main thread del navegador: Atomics.wait no está permitido. Espera activa acotada.
    const until = Date.now() + Math.min(secs, 5) * 1000;
    while (Date.now() < until) { /* busy */ }
  }
}

/**
 * Instancia el módulo con un `hostCall(kind, payload) -> objeto | undefined` SÍNCRONO
 * (el bridge async lo implementa con Atomics). Devuelve `{ call(request) -> response }`.
 */
export async function instantiate(module, hostCall) {
  let exports = null;
  const mem = () => new Uint8Array(exports.memory.buffer);
  const writeBytes = (bytes) => {
    const ptr = exports.synsema_alloc(bytes.length);
    mem().set(bytes, ptr);
    return ptr;
  };
  const imports = {
    synsema_host: {
      host_call(kp, kl, pp, pl) {
        const kind = td.decode(mem().subarray(kp, kp + kl));
        const payload = JSON.parse(td.decode(mem().subarray(pp, pp + pl)));
        let result;
        try {
          result = hostCall(kind, payload);
        } catch (e) {
          result = { error: String(e && e.message ? e.message : e) };
        }
        if (result === undefined) return 0;
        const bytes = te.encode(JSON.stringify(result ?? null));
        const ptr = exports.synsema_alloc(4 + bytes.length);
        const m = mem();
        new DataView(m.buffer).setUint32(ptr, bytes.length, true);
        m.set(bytes, ptr + 4);
        return ptr;
      },
      host_random_fill(ptr, len) {
        try {
          randomFill(mem().subarray(ptr, ptr + len));
          return 0;
        } catch {
          return 1;
        }
      },
      host_now_ms() {
        return Date.now();
      },
    },
  };
  const instance = await WebAssembly.instantiate(module, imports);
  exports = instance.exports;
  return {
    exports,
    call(request) {
      const req = te.encode(JSON.stringify(request));
      const rp = writeBytes(req);
      let out;
      try {
        out = exports.synsema_call(rp, req.length);
      } finally {
        exports.synsema_free(rp, req.length);
      }
      const m = mem();
      const len = new DataView(m.buffer).getUint32(out, true);
      const json = td.decode(m.subarray(out + 4, out + 4 + len));
      exports.synsema_free(out, 4 + len);
      return JSON.parse(json);
    },
  };
}

function requestOf(op, source, opts = {}) {
  const r = { op, source, filename: opts.filename ?? "<embedded>" };
  if (opts.env) r.env = opts.env;
  if (opts.ceiling) r.ceiling = opts.ceiling;
  if (opts.host) r.host = offersOf(opts.host);
  return r;
}

function normalizeRequest(request) {
  const headers = Array.isArray(request.headers)
    ? request.headers
    : request.headers && typeof request.headers.forEach === "function"
      ? (() => { const h = []; request.headers.forEach((v, k) => h.push([k, v])); return h; })()
      : Object.entries(request.headers ?? {});
  const out = { method: request.method ?? "GET", path: request.path ?? "/", headers, ip: request.ip ?? "" };
  if (request.body instanceof Uint8Array || request.body instanceof ArrayBuffer) {
    out.body_base64 = b64(request.body instanceof Uint8Array ? request.body : new Uint8Array(request.body));
  } else out.body = request.body == null ? "" : String(request.body);
  return out;
}

export class Synsema {
  /** @param {WebAssembly.Module} module */
  constructor(module) {
    this.module = module;
    this._inst = null;
  }

  /** Carga el .wasm (bytes, Module, URL/path, Response). */
  static async load(src) {
    return new Synsema(await readModule(src));
  }

  async _instance() {
    if (!this._inst) {
      // Cada llamada síncrona lleva su host; la instancia es una y despacha al host
      // de la llamada en curso.
      const self = this;
      this._inst = await instantiate(this.module, (kind, payload) => dispatchHostSync(self._host, kind, payload));
    }
    return this._inst;
  }

  _callSync(request, host) {
    const inst = this._instSync();
    this._host = host;
    try {
      return inst.call(request);
    } catch (e) {
      // Un trap deja la instancia inservible: se reinstancia en la próxima llamada.
      this._inst = null;
      this._ready = null;
      throw new Error(`synsema: the module trapped (${e && e.message ? e.message : e}); the instance was discarded`);
    } finally {
      this._host = null;
    }
  }

  _instSync() {
    if (!this._inst) throw new Error("synsema: call `await syn.ready()` (or use the *Async methods) before the first call");
    return this._inst;
  }

  /** Prepara la instancia síncrona. Idempotente. */
  async ready() {
    if (!this._ready) this._ready = this._instance();
    await this._ready;
    return this;
  }

  version() {
    return this._callSync({ op: "version" }).version;
  }
  run(source, opts = {}) {
    return this._callSync(requestOf("run", source, opts), opts.host);
  }
  test(source, opts = {}) {
    return this._callSync(requestOf("test", source, opts), opts.host);
  }
  check(source, opts = {}) {
    return this._callSync({ op: "check", source, filename: opts.filename ?? "<embedded>" });
  }
  handle(source, request, opts = {}) {
    return this._callSync({ ...requestOf("handle", source, opts), request: normalizeRequest(request) }, opts.host);
  }

  // ---- modo asíncrono (Worker + Atomics) ----

  async _bridge() {
    if (!this._worker) {
      const { createBridge } = await import("./bridge.mjs");
      this._worker = await createBridge(this.module);
    }
    return this._worker;
  }
  async runAsync(source, opts = {}) {
    return (await this._bridge()).call(requestOf("run", source, opts), opts.host);
  }
  async testAsync(source, opts = {}) {
    return (await this._bridge()).call(requestOf("test", source, opts), opts.host);
  }
  async handleAsync(source, request, opts = {}) {
    return (await this._bridge()).call({ ...requestOf("handle", source, opts), request: normalizeRequest(request) }, opts.host);
  }
  /** Termina el Worker del modo asíncrono (si se creó). */
  async close() {
    if (this._worker) {
      await this._worker.close();
      this._worker = null;
    }
  }
}

export default Synsema;

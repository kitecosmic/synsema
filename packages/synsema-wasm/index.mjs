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
  // v0.6.45: comparar-y-cambiar, lo que hace atómicos state_merge/state_cas con un KV compartido.
  if (host.kv && typeof host.kv.cas === "function") o.kv_cas = true;
  if (typeof host.llm === "function") o.llm = true;
  if (typeof host.log === "function") o.log = true;
  if (typeof host.sleep === "function" || host.sleep === true) o.sleep = true;
  return o;
}

/**
 * v0.6.45 (ronda 4, M6) — el texto de un error que NUNCA lanza: un hook puede lanzar
 * `Object.create(null)` o un objeto cuyo `message` es un getter que lanza, y un `String(e)` lanzaba
 * fuera del manejo (el proceso caía o el Worker quedaba esperando para siempre).
 */
export function safeMsg(e) {
  try {
    if (e && typeof e.message === "string") return e.message;
    return String(e);
  } catch {
    return "the host hook threw a value that cannot be shown";
  }
}

/** `JSON.stringify` de la respuesta de un hook, o un `{error}` si no es JSON (un BigInt, un ciclo). */
export function safeJson(result, kind) {
  try {
    return JSON.stringify(result ?? null);
  } catch (e) {
    return JSON.stringify({ error: `host ${kind} returned a non-JSON value: ${safeMsg(e)}` });
  }
}

/** Un hook async usado desde la API síncrona devolvería una Promise donde el intérprete
 *  espera un valor: en vez de un `{status: 0}` mudo, un error que nombra el fix. */
function syncOnly(kind, r) {
  if (r && typeof r.then === "function") {
    // Ronda 3 (M9): la Promise queda con un handler; si no, al rechazar tiraba el proceso
    // (unhandledRejection) después de que la corrida ya había devuelto.
    r.then(undefined, () => {});
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
    case "kv_cas":
      return host.kv && typeof host.kv.cas === "function"
        ? casReply(syncOnly("kv.cas", host.kv.cas(payload.ns, payload.key, payload.expected ?? null, payload.value)))
        : undefined;
    case "llm":
      return typeof host.llm === "function" ? normalizeLlm(syncOnly("llm", host.llm(payload.op, payload.prompt, { principals: payload.principals ?? [] }))) : undefined;
    case "log":
      if (typeof host.log !== "function") return undefined;
      syncOnly("log", host.log(payload.line));
      return {};
    case "sleep":
      if (typeof host.sleep === "function") {
        syncOnly("sleep", host.sleep(payload.secs));
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
    case "kv_cas":
      return host.kv && typeof host.kv.cas === "function"
        ? casReply(await host.kv.cas(payload.ns, payload.key, payload.expected ?? null, payload.value))
        : undefined;
    case "llm":
      return typeof host.llm === "function" ? normalizeLlm(await host.llm(payload.op, payload.prompt, { principals: payload.principals ?? [] })) : undefined;
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
  const { imports, bind } = hostImports(hostCall);
  const instance = await WebAssembly.instantiate(module, imports);
  return bind(instance.exports);
}

/**
 * v0.6.45 (D4) — lo mismo, SÍNCRONO (`new WebAssembly.Instance`): con el `Module` ya compilado es
 * barato, y es lo que deja a la API síncrona recrear la instancia después de un trap sin pedirle
 * al usuario un `await syn.ready()`. (En el main thread de un navegador puede estar acotado por
 * tamaño; ahí se cae al camino de siempre.)
 */
export function instantiateSync(module, hostCall) {
  const { imports, bind } = hostImports(hostCall);
  return bind(new WebAssembly.Instance(module, imports).exports);
}

function hostImports(hostCall) {
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
          result = { error: safeMsg(e) };
        }
        if (result === undefined) return 0;
        // Ronda 4 (B1): un valor que no es JSON vuelve como error del hook (antes hacía trapear el
        // módulo y se perdía la corrida).
        const bytes = te.encode(safeJson(result, kind));
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
  const bind = (ex) => {
    exports = ex;
    return callable(ex, mem, writeBytes);
  };
  return { imports, bind };
}

function callable(exports, mem, writeBytes) {
  return {
    exports,
    call(request) {
      const req = te.encode(JSON.stringify(request));
      const rp = writeBytes(req);
      let out;
      try {
        out = exports.synsema_call(rp, req.length);
      } catch (e) {
        // v0.6.45 (D2): el allocator del módulo rechazó una reserva por `maxMemoryMb` y Rust hizo
        // trap. La instancia igual se descarta (lo hace quien llama), pero la corrida no "trapeó":
        // se pasó del tope que el host pidió, y eso vuelve como un error de la corrida.
        if (typeof exports.synsema_limit_hit === "function" && exports.synsema_limit_hit() === 1) {
          e.synsemaResult = limitResult(request);
        }
        throw e;
      } finally {
        try {
          exports.synsema_free(rp, req.length);
        } catch {
          // instancia rota por el trap: se descarta entera
        }
      }
      const m = mem();
      const len = new DataView(m.buffer).getUint32(out, true);
      const json = td.decode(m.subarray(out + 4, out + 4 + len));
      exports.synsema_free(out, 4 + len);
      return JSON.parse(json);
    },
  };
}

const MEMORY_LIMIT = "Runtime error: memory limit reached: the run reserved more than maxMemoryMb";

/** El resultado de una corrida cortada por `maxMemoryMb`, con la forma de su `op`. */
function limitResult(request) {
  if (request.op === "handle") {
    return {
      status: 500,
      content_type: "application/json",
      headers: [["content-type", "application/json"]],
      body: JSON.stringify({ error: "memory limit reached", status: 500 }),
      log: [],
      errors: [MEMORY_LIMIT],
      audit: [],
    };
  }
  if (request.op === "test") return { ok: false, passed: 0, failed: 0, lines: [MEMORY_LIMIT], audit: [] };
  return { ok: false, output: [], errors: [MEMORY_LIMIT], audit: [], llm_tokens: 0, exit: 1 };
}

/**
 * v0.6.45 (ronda 2, B2): `kv.cas` del host tiene que contestar `true` o `false`. Un `cas` sin
 * `return` (undefined) contaba como `false` y el motor reintentaba 64 veces hasta "kept changing".
 */
function casReply(v) {
  return typeof v === "boolean" ? { swapped: v } : { error: `kv.cas must return true or false, got ${v === undefined ? "undefined" : JSON.stringify(v)}` };
}

function requestOf(op, source, opts = {}) {
  const r = { op, source, filename: opts.filename ?? "<embedded>" };
  if (opts.env) r.env = opts.env;
  if (opts.ceiling) r.ceiling = opts.ceiling;
  if (opts.host) r.host = offersOf(opts.host);
  // v0.6.45 (D1): etiquetas de flujo. Antes no se reenviaban y el motor las tenía apagadas aunque
  // el host las pidiera.
  if (opts.labels) r.labels = true;
  if (opts.result) r.result = opts.result;
  if (opts.input) r.input = { var: opts.input.var, value: opts.input.value, sources: opts.input.sources ?? {} };
  // v0.6.45 (D2): límites de la corrida (los mide el motor: pasos deterministas y la memoria del módulo).
  // `!= null`: un 0 (o un valor inválido) llega al motor, que lo rechaza con un error claro; antes
  // se descartaba por falsy y la corrida quedaba sin límite.
  if (opts.maxSteps != null) r.max_steps = opts.maxSteps;
  if (opts.maxMemoryMb != null) r.max_memory_mb = opts.maxMemoryMb;
  // v0.6.46 (E3b): módulos de confianza del embebedor y su techo.
  if (opts.trusted) r.trusted = opts.trusted;
  if (opts.trustedCeiling) r.trusted_ceiling = opts.trustedCeiling;
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
  /**
   * @param {WebAssembly.Module} module
   * @param {{workers?: number}} [opts] `workers`: cuántos Workers usa el modo asíncrono (default 1).
   */
  constructor(module, opts = {}) {
    this.module = module;
    this._inst = null;
    this._workers = Math.max(1, opts.workers | 0 || 1);
    // Ronda 4 (B1): cuánto puede tardar un Worker en arrancar (default 30 s). Validado como
    // `timeoutMs`: un valor fuera del rango de los timers vencía en 1 ms y ningún Worker arrancaba.
    if (opts.startMs != null && !(Number.isFinite(opts.startMs) && opts.startMs > 0 && opts.startMs <= 2147483647)) {
      throw new Error("synsema: startMs must be a number of milliseconds between 1 and 2147483647");
    }
    this._startMs = opts.startMs;
    this._bridges = [];
  }

  /** Carga el .wasm (bytes, Module, URL/path, Response). */
  static async load(src, opts = {}) {
    return new Synsema(await readModule(src), opts);
  }

  /**
   * v0.6.45 (D5) — Node: carga el `synsema.wasm` que viene en el paquete, sin que el que lo usa
   * resuelva la ruta. Lo lee del directorio de este archivo y, si un bundler lo movió (Turbopack,
   * webpack), de `node_modules/@synsema/wasm`: anda en un script, en una ruta `/api` y en una
   * Server Action de Next.
   */
  static async loadNode(opts = {}) {
    const { readFile } = await import("node:fs/promises");
    const { fileURLToPath } = await import("node:url");
    const { dirname, join } = await import("node:path");
    const candidates = [];
    try {
      candidates.push(join(dirname(fileURLToPath(import.meta.url)), "synsema.wasm"));
    } catch {
      // import.meta.url reescrito a algo que no es file:
    }
    candidates.push(join(process.cwd(), "node_modules", "@synsema", "wasm", "synsema.wasm"));
    let lastErr;
    for (const p of candidates) {
      try {
        return new Synsema(await WebAssembly.compile(await readFile(p)), opts);
      } catch (e) {
        lastErr = e;
      }
    }
    throw new Error(`synsema: cannot find synsema.wasm (tried ${candidates.join(", ")}): ${lastErr && lastErr.message}`);
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
      // Un trap deja la instancia inservible: se recrea ya (sincrónico, con el Module compilado),
      // así la próxima llamada anda sin `await syn.ready()` (v0.6.45, D4). Si el host no deja
      // instanciar sincrónico, queda descartada y `ready()` la recrea.
      this._inst = null;
      this._ready = null;
      try {
        const self = this;
        this._inst = instantiateSync(this.module, (kind, payload) => dispatchHostSync(self._host, kind, payload));
        this._ready = Promise.resolve(this._inst);
      } catch {
        // sin instancia: la próxima llamada pide `ready()`
      }
      if (e && e.synsemaResult) return e.synsemaResult;
      throw new Error(`synsema: the module trapped (${safeMsg(e)}); the instance was recreated`);
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

  /**
   * v0.6.45 (ronda 2, M8) — una cola CENTRAL: cada llamada asíncrona entra acá y `_pump()` (sin
   * `await`, así no hay carreras) la entrega a un Worker libre, o crea uno mientras no se llegó a
   * `workers`. Un Worker corre una llamada a la vez. Antes cada llamada elegía Worker por su cuenta
   * después de un `await`: una ráfaga de 4 con `workers: 2` quedaba toda en uno.
   */
  _pump() {
    this._queue = this._queue ?? [];
    this._bridges = (this._bridges ?? []).filter((b) => !b.closed());
    this._spawning = this._spawning ?? 0;
    while (this._queue.length > 0 && !this._closed) {
      const idle = this._bridges.find((b) => !b.busy());
      if (idle) {
        this._dispatch(idle, this._queue.shift());
        continue;
      }
      if (this._bridges.length + this._spawning < this._workers) {
        // Ronda 4 (B1): después de un arranque fallido con Workers sanos, no se reintenta antes de un
        // segundo (cada intento instancia el .wasm entero, y el motivo suele ser falta de memoria).
        // El timer se arma ACÁ, por lo que falta (revisión H1: armado sólo al fallar, un segundo fallo
        // o un timer que vencía unos ms antes dejaban la cola sin nadie que la despertara). Sin
        // Workers sanos no se espera: o arranca uno, o la cola falla.
        const wait = (this._spawnRetryAt ?? 0) - performance.now();
        if (wait > 0 && this._bridges.length > 0) {
          if (!this._retryTimer) {
            this._retryTimer = setTimeout(() => {
              this._retryTimer = null;
              this._pump();
            }, Math.ceil(wait) + 1);
            if (typeof this._retryTimer.unref === "function") this._retryTimer.unref();
          }
          break;
        }
        this._spawning++;
        this._spawnAbort = this._spawnAbort ?? new AbortController();
        const signal = this._spawnAbort.signal;
        import("./bridge.mjs")
          .then(({ createBridge }) => createBridge(this.module, { signal, startMs: this._startMs }))
          .then(
            (b) => {
              this._spawning--;
              // `close()` llegó mientras nacía: se cierra, no queda vivo.
              if (this._closed) return b.close();
              this._bridges.push(b);
              this._pump();
            },
            (err) => {
              this._spawning--;
              // No se pudo crear un Worker (ronda 4, revisión: sin esto, con `workers` ≥ 2 el arranque
              // fallido se reintentaba sin pausa y la cola no fallaba nunca). Tres casos:
              // - hay Workers sanos: lo encolado sigue con ellos y el próximo arranque espera un
              //   segundo (un solo timer, que no retiene el proceso);
              // - no hay sanos pero otro arranque está en vuelo: se espera a ése;
              // - no queda ninguno: lo encolado falla con esta causa, sin colgarse.
              if (this._bridges.filter((b) => !b.closed()).length > 0) {
                this._spawnRetryAt = performance.now() + 1000;
                return this._pump(); // arma el timer de la espera
              }
              if (this._spawning > 0) return;
              const q = this._queue.splice(0);
              for (const it of q) it.reject(err);
            },
          );
      }
      break;
    }
  }

  _dispatch(b, it) {
    b.call(it.request, it.host, it.timeoutMs).then(it.resolve, (e) => {
      // No se llegó a mandar (el Worker se cerró antes): vuelve al principio de la cola. Lo que sí
      // corrió (un timeout, un Worker que murió en el medio) NO se reintenta: pudo tener efectos.
      if (e && e.synsemaWorkerClosed && !this._closed) {
        this._queue.unshift(it);
      } else {
        it.reject(e);
      }
    }).finally(() => this._pump());
  }

  /**
   * v0.6.45 (D2) — `timeoutMs`: si la llamada no terminó en ese plazo (contado desde que EMPIEZA
   * a correr, no desde que entró a la cola), su Worker se termina (el código corría en otro hilo:
   * el del servidor nunca se bloquea) y la llamada falla con un error claro. Los hooks del host que
   * ya estaban en curso (un `fetch`) no se cortan: terminan solos y su resultado se descarta.
   */
  _callAsync(request, opts) {
    if (this._closed) return Promise.reject(new Error("synsema: closed (close() is final; load a new instance)"));
    // Ronda 3 (B1): un plazo fuera del rango de los timers (o `Infinity`) vencía en 1 ms. `0` sigue
    // siendo "sin plazo", como antes (ronda 4).
    if (opts.timeoutMs != null && !(Number.isFinite(opts.timeoutMs) && opts.timeoutMs >= 0 && opts.timeoutMs <= 2147483647)) {
      return Promise.reject(new Error("synsema: timeoutMs must be 0 (no deadline) or a number of milliseconds up to 2147483647"));
    }
    return new Promise((resolve, reject) => {
      this._queue = this._queue ?? [];
      this._queue.push({ request, host: opts.host, timeoutMs: opts.timeoutMs > 0 ? opts.timeoutMs : 0, resolve, reject });
      this._pump();
    });
  }
  async runAsync(source, opts = {}) {
    return this._callAsync(requestOf("run", source, opts), opts);
  }
  async testAsync(source, opts = {}) {
    return this._callAsync(requestOf("test", source, opts), opts);
  }
  async handleAsync(source, request, opts = {}) {
    return this._callAsync({ ...requestOf("handle", source, opts), request: normalizeRequest(request) }, opts);
  }
  /**
   * Termina los Workers del modo asíncrono. Es FINAL (ronda 2, B1): lo que esperaba en la cola falla
   * con "closed", un Worker que estaba naciendo se cierra al nacer, y una llamada asíncrona posterior
   * falla. La API síncrona sigue andando.
   */
  async close() {
    this._closed = true;
    if (this._retryTimer) clearTimeout(this._retryTimer);
    // Los Workers que están naciendo se abortan (ronda 3, M9).
    this._spawnAbort?.abort();
    const q = (this._queue ?? []).splice(0);
    for (const it of q) it.reject(new Error("synsema: closed (close() is final; load a new instance)"));
    const bs = this._bridges ?? [];
    this._bridges = [];
    await Promise.all(bs.map((b) => b.close()));
  }
}

export default Synsema;

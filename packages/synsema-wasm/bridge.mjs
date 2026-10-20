// Bridge asíncrono: el intérprete (síncrono) corre en un Worker; cuando necesita al
// host (http/kv/llm/log/sleep) manda el pedido al main thread y se bloquea con
// Atomics.wait sobre un SharedArrayBuffer hasta que la Promise del host resuelve.
//
// Layout del SAB: Int32Array ctrl = [estado, len_chunk, restante]; datos desde el
// byte 16. Estados: 0 = esperando, 1 = último chunk listo, 2 = chunk listo (hay más),
// 3 = el host no ofrece ese hook. Respuestas más grandes que el SAB viajan en chunks:
// el worker copia, pone 0, avisa con `ack` y el main escribe el siguiente.
//
// Navegador: SharedArrayBuffer requiere cross-origin isolation (headers
// Cross-Origin-Opener-Policy: same-origin + Cross-Origin-Embedder-Policy: require-corp).
// Node/Bun/Deno: funciona sin más.

import { dispatchHostAsync, safeMsg, safeJson } from "./index.mjs";

const te = new TextEncoder();
const IS_NODE = typeof process !== "undefined" && process.versions && process.versions.node;
const DATA_OFFSET = 16;

async function spawnWorker() {
  const url = new URL("./worker.mjs", import.meta.url);
  if (IS_NODE) {
    const { Worker } = await import("node:worker_threads");
    const w = new Worker(url);
    return {
      post: (m) => w.postMessage(m),
      onMessage: (fn) => w.on("message", fn),
      onError: (fn) => w.on("error", fn),
      onExit: (fn) => w.on("exit", fn),
      terminate: () => w.terminate(),
    };
  }
  const w = new Worker(url, { type: "module" });
  return {
    post: (m) => w.postMessage(m),
    onMessage: (fn) => (w.onmessage = (e) => fn(e.data)),
    // Ronda 4 (B1): si el script del Worker no carga, `e.message` puede no estar.
    onError: (fn) => (w.onerror = (e) => fn(e.error ?? new Error(e.message || "the worker script failed to load"))),
    onExit: () => {},
    terminate: () => w.terminate(),
  };
}

/** Cuánto puede tardar un Worker en arrancar antes de darlo por perdido (ronda 3, M9). */
const START_MS = 30_000;

export async function createBridge(module, { bridgeBytes = 4 * 1024 * 1024, signal, startMs = START_MS } = {}) {
  if (typeof SharedArrayBuffer === "undefined") {
    throw new Error(
      "synsema: the async mode needs SharedArrayBuffer (in browsers, serve the page cross-origin isolated: COOP same-origin + COEP require-corp); use the sync API with a sync host instead",
    );
  }
  const sab = new SharedArrayBuffer(DATA_OFFSET + bridgeBytes);
  const ctrl = new Int32Array(sab, 0, 4);
  const data = new Uint8Array(sab, DATA_OFFSET);
  const w = await spawnWorker();

  let pending = null; // { resolve, reject, host }
  let sending = null; // { bytes, offset }

  function writeChunk() {
    const { bytes } = sending;
    const n = Math.min(bytes.length - sending.offset, data.length);
    data.set(bytes.subarray(sending.offset, sending.offset + n));
    sending.offset += n;
    const remaining = bytes.length - sending.offset;
    Atomics.store(ctrl, 1, n);
    Atomics.store(ctrl, 2, remaining);
    Atomics.store(ctrl, 0, remaining > 0 ? 2 : 1);
    Atomics.notify(ctrl, 0);
    if (remaining === 0) sending = null;
  }

  function reply(result, kind) {
    if (result === undefined) {
      Atomics.store(ctrl, 0, 3);
      Atomics.notify(ctrl, 0);
      return;
    }
    // Ronda 3 (M7): un hook que devuelve algo que no es JSON (un BigInt, un objeto circular) contesta
    // un error; antes la excepción salía fuera del handler y el Worker quedaba esperando para siempre.
    sending = { bytes: te.encode(safeJson(result, kind)), offset: 0 };
    writeChunk();
  }

  let closed = false;
  let started = false;
  // v0.6.45 (ronda 2, M8): si el Worker muere (un error no atrapado, `exit`, el heap del Worker),
  // el bridge queda cerrado: la llamada en curso falla con un error que NO se reintenta (pudo tener
  // efectos) y ninguna llamada nueva va a un Worker muerto.
  const died = (why) => {
    if (closed) return;
    closed = true;
    const p = pending;
    pending = null;
    p?.reject(Object.assign(new Error(`synsema: the worker stopped while running the call (${why})`), { synsemaWorkerDied: true }));
    // En el navegador `onerror` no termina el Worker (ronda 3, B1).
    w.terminate();
  };
  const ready = new Promise((resolve, reject) => {
    w.onError((e) => {
      if (!started) return reject(e);
      died(safeMsg(e));
    });
    w.onExit((code) => {
      if (!started) return reject(new Error(`synsema: the worker exited before starting (code ${code})`));
      died(`exit ${code}`);
    });
    w.onMessage(async (m) => {
      switch (m.type) {
        case "ready":
          started = true;
          resolve();
          break;
        case "init-error":
          reject(new Error(`synsema: the worker could not instantiate the module: ${m.message}`));
          break;
        case "fatal":
          died(m.message);
          w.terminate();
          break;
        case "host": {
          // Ronda 4 (M6): el Worker espera esta respuesta en `Atomics.wait`; contesta SIEMPRE.
          let result;
          try {
            result = await dispatchHostAsync(pending?.host, m.kind, m.payload);
          } catch (e) {
            result = { error: safeMsg(e) };
          } finally {
            reply(result, m.kind);
          }
          break;
        }
        case "ack":
          if (sending) writeChunk();
          break;
        case "result": {
          const p = pending;
          pending = null;
          p?.resolve(m.response);
          break;
        }
        case "error": {
          const p = pending;
          pending = null;
          p?.reject(new Error(m.message));
          break;
        }
      }
    });
  });
  // Ronda 3 (M8, M9): si el Worker no arranca (init-error, un `post` que falla, nunca llega `ready`,
  // o `close()` lo aborta), se termina: no queda vivo ni retiene el proceso.
  let startTimer;
  let onAbort = null;
  // `ready` puede rechazar DESPUÉS de que el plazo o el aborto ganaron la carrera (el Worker sale
  // al terminarlo): queda manejada para que no sea un rechazo suelto.
  ready.catch(() => {});
  try {
    if (signal?.aborted) throw new Error("synsema: closed while the worker was starting");
    w.post({ type: "init", module, sab });
    await Promise.race([
      ready,
      new Promise((_, reject) => {
        startTimer = setTimeout(() => reject(new Error(`synsema: the worker did not start in ${startMs} ms`)), startMs);
        onAbort = () => reject(new Error("synsema: closed while the worker was starting"));
        signal?.addEventListener("abort", onAbort, { once: true });
      }),
    ]);
  } catch (e) {
    closed = true;
    w.terminate();
    throw e;
  } finally {
    clearTimeout(startTimer);
    // Ronda 4 (M2): el listener se saca; si no, cada Worker reemplazado dejaba el suyo (y su SAB de
    // 4 MB) colgado de la señal compartida hasta `close()`.
    if (onAbort) signal?.removeEventListener("abort", onAbort);
  }

  // v0.6.45 (D3): las llamadas a un mismo worker se ENCOLAN (antes la segunda fallaba con "one call
  // at a time per instance": un servidor con dos requests a la vez se rompía). Para correr en
  // paralelo, varios workers: `Synsema.load(src, { workers: n })`.
  let tail = Promise.resolve();
  let queued = 0;
  // `synsemaWorkerClosed` = la llamada NO se llegó a mandar: quien llama la puede reintentar en otro
  // Worker. La que estaba corriendo cuando se cerró recibe otro error (ronda 2, B1).
  const closedError = () => Object.assign(new Error("synsema: the worker was closed"), { synsemaWorkerClosed: true });
  function terminate() {
    if (closed) return Promise.resolve();
    closed = true;
    const p = pending;
    pending = null;
    p?.reject(Object.assign(new Error("synsema: the worker was closed while running the call"), { synsemaWorkerDied: true }));
    return w.terminate();
  }
  // v0.6.45 (D2) — el reloj de `timeoutMs` arranca acá, cuando la llamada empieza a correr (antes
  // corría desde que entraba a la cola, y el timeout de una llamada encolada mataba a la que estaba
  // corriendo). Al vencer se termina el Worker: las encoladas detrás reciben "worker closed" y
  // quien llama las manda a otro.
  function callNow(request, host, timeoutMs) {
    if (closed) return Promise.reject(closedError());
    return new Promise((resolve, reject) => {
      let timer = null;
      const done = (f) => (v) => {
        if (timer) clearTimeout(timer);
        f(v);
      };
      pending = { resolve: done(resolve), reject: done(reject), host };
      if (timeoutMs > 0) {
        timer = setTimeout(() => {
          const p = pending;
          pending = null;
          p?.reject(new Error(`synsema: the call did not finish in ${timeoutMs} ms; its worker was stopped`));
          terminate();
        }, timeoutMs);
      }
      Atomics.store(ctrl, 0, 0);
      w.post({ type: "call", request });
    });
  }

  return {
    call(request, host, timeoutMs = 0) {
      queued++;
      const run = () => callNow(request, host, timeoutMs);
      const p = tail.then(run, run).finally(() => queued--);
      tail = p.catch(() => {});
      return p;
    },
    /** Llamadas en curso + encoladas (para elegir el worker menos ocupado). */
    load() {
      return queued;
    },
    /** ¿Tiene una llamada en curso o encolada? */
    busy() {
      return queued > 0;
    },
    /** Si el Worker ya se terminó (por un timeout o por `close`). */
    closed() {
      return closed;
    },
    async close() {
      await terminate();
    },
  };
}

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

import { dispatchHostAsync } from "./index.mjs";

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
      terminate: () => w.terminate(),
    };
  }
  const w = new Worker(url, { type: "module" });
  return {
    post: (m) => w.postMessage(m),
    onMessage: (fn) => (w.onmessage = (e) => fn(e.data)),
    onError: (fn) => (w.onerror = (e) => fn(e.error ?? new Error(e.message))),
    terminate: () => w.terminate(),
  };
}

export async function createBridge(module, { bridgeBytes = 4 * 1024 * 1024 } = {}) {
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

  function reply(result) {
    if (result === undefined) {
      Atomics.store(ctrl, 0, 3);
      Atomics.notify(ctrl, 0);
      return;
    }
    sending = { bytes: te.encode(JSON.stringify(result ?? null)), offset: 0 };
    writeChunk();
  }

  const ready = new Promise((resolve, reject) => {
    w.onError((e) => {
      const p = pending;
      pending = null;
      if (p) p.reject(e);
      else reject(e);
    });
    w.onMessage(async (m) => {
      switch (m.type) {
        case "ready":
          resolve();
          break;
        case "host": {
          let result;
          try {
            result = await dispatchHostAsync(pending?.host, m.kind, m.payload);
          } catch (e) {
            result = { error: String(e && e.message ? e.message : e) };
          }
          reply(result);
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
  w.post({ type: "init", module, sab });
  await ready;

  return {
    call(request, host) {
      if (pending) return Promise.reject(new Error("synsema: one call at a time per instance"));
      return new Promise((resolve, reject) => {
        pending = { resolve, reject, host };
        Atomics.store(ctrl, 0, 0);
        w.post({ type: "call", request });
      });
    },
    async close() {
      await w.terminate();
    },
  };
}

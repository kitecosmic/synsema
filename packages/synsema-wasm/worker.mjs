// Lado Worker del bridge asíncrono (ver bridge.mjs). Corre en Node (worker_threads)
// y en el navegador (module Worker). Instancia el .wasm con un hostCall que manda el
// pedido al main thread y se bloquea con Atomics.wait hasta la respuesta.

import { instantiate, safeMsg } from "./index.mjs";

const td = new TextDecoder();
const DATA_OFFSET = 16;
const IS_NODE = typeof process !== "undefined" && process.versions && process.versions.node;

let post;
let onMessage;
if (IS_NODE) {
  const { parentPort } = await import("node:worker_threads");
  post = (m) => parentPort.postMessage(m);
  onMessage = (fn) => parentPort.on("message", fn);
} else {
  post = (m) => self.postMessage(m);
  onMessage = (fn) => (self.onmessage = (e) => fn(e.data));
}

let module = null;
let ctrl = null;
let data = null;
let inst = null;

function hostCall(kind, payload) {
  Atomics.store(ctrl, 0, 0);
  post({ type: "host", kind, payload });
  const parts = [];
  for (;;) {
    Atomics.wait(ctrl, 0, 0);
    const state = Atomics.load(ctrl, 0);
    if (state === 3) {
      Atomics.store(ctrl, 0, 0);
      return undefined;
    }
    const len = Atomics.load(ctrl, 1);
    parts.push(data.slice(0, len));
    if (state === 2) {
      Atomics.store(ctrl, 0, 0);
      post({ type: "ack" });
      continue;
    }
    Atomics.store(ctrl, 0, 0);
    break;
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const bytes = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    bytes.set(p, off);
    off += p.length;
  }
  return JSON.parse(td.decode(bytes));
}

onMessage(async (m) => {
  if (m.type === "init") {
    module = m.module;
    ctrl = new Int32Array(m.sab, 0, 4);
    data = new Uint8Array(m.sab, DATA_OFFSET);
    // v0.6.45 (ronda 2, M8): un fallo al instanciar se avisa (en el navegador no dispara `onerror`
    // y el main esperaba `ready` para siempre).
    try {
      inst = await instantiate(module, hostCall);
    } catch (e) {
      post({ type: "init-error", message: safeMsg(e) });
      return;
    }
    post({ type: "ready" });
    return;
  }
  if (m.type === "call") {
    try {
      const response = inst.call(m.request);
      post({ type: "result", response });
    } catch (e) {
      // v0.6.45: la instancia nueva se arma ANTES de avisar, así la próxima llamada (que el main
      // manda al recibir la respuesta) no entra mientras se instancia.
      try {
        inst = await instantiate(module, hostCall);
      } catch (e2) {
        post({ type: "fatal", message: `the module trapped and could not be instantiated again: ${safeMsg(e2)}` });
        return;
      }
      if (e && e.synsemaResult) post({ type: "result", response: e.synsemaResult });
      else post({ type: "error", message: `synsema: the module trapped (${safeMsg(e)}); the instance was recreated` });
    }
  }
});

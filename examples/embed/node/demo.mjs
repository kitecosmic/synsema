// Demo: un agente Synsema dentro de una app Node/Bun — sin backend Synsema.
//
//   node examples/embed/node/demo.mjs [ruta/al/synsema_wasm_web.wasm]
//
// Usa el paquete @synsema/wasm (packages/synsema-wasm) en los dos modos:
//  - síncrono: host con `kv` en memoria + `llm` mock (todo síncrono);
//  - asíncrono (Worker + Atomics): host con `http` = fetch real de Node (async).
// El programa sigue declarando `require net/memory/llm`; el `ceiling` de la app manda.
// Termina con exit 1 si algo no da lo esperado.

import { createServer } from "node:http";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Synsema } from "../../../packages/synsema-wasm/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const wasm = process.argv[2] ?? resolve(here, "../../../engine/target/wasm32-unknown-unknown/wasm/synsema_wasm_web.wasm");

let failed = 0;
const check = (name, ok, detail) => {
  console.log((ok ? "  ok  " : "FAIL  ") + name + (ok ? "" : " -- " + JSON.stringify(detail).slice(0, 400)));
  if (!ok) failed++;
};

const syn = await Synsema.load(wasm);
await syn.ready();
console.log("synsema", syn.version());

// Un KV de la app (acá un Map; en producción: Redis, SQLite, KV del edge…).
const store = new Map();
const kv = {
  get: (ns, k) => store.get(`${ns}/${k}`) ?? null,
  set: (ns, k, v) => void store.set(`${ns}/${k}`, v),
  delete: (ns, k) => void store.delete(`${ns}/${k}`),
  list: (ns) => [...store.keys()].filter((x) => x.startsWith(ns + "/")).map((x) => x.slice(ns.length + 1)),
};
const llm = (op, prompt) => ({ content: `[${op}] ${prompt.slice(0, 40)}`, tokens: 12 });
const host = { kv, llm, log: (line) => console.log("   [host]", line) };

// 1. Cómputo puro con secreto desde `env` (reemplaza al .env).
let r = syn.run('require secret("KEY")\nprint(keccak256("hola"))\nprint(type_of(secret("KEY")))', { env: { KEY: "abc" } });
check("run: keccak + secret desde env", r.ok && r.output[1] === "secret", r);

// 2. Memoria persistente en el KV de la app: una corrida recuerda, otra recuerda.
r = syn.run('require memory("agenda")\nremember("preference", "responder en español", ["idioma"])\nprint(memory_summary())', { host, filename: "agenda.syn" });
check("memoria: remember -> kv", r.ok && r.output.join("\n").includes("Backend: host-kv"), r);
r = syn.run('require memory("agenda")\nprint(recall(search="español")[0]["content"])', { host, filename: "agenda.syn" });
check("memoria: recall en otra corrida", r.ok && r.output[0] === "responder en español", r);

// 3. LLM de la app (conectá tu SDK en `llm`).
r = syn.run('require llm\nprint(reason about "el clima")\nprint(llm_usage())', { host });
check("llm: reason va al host", r.ok && r.output[0].startsWith("[reason]") && r.output[1] === "12", r);

// 4. serve en modo handler: la app entrega el request y recibe la respuesta.
const app = `require serve(8080)
serve on 8080
    route "GET /saludo/:nombre"
        give {"hola": params.nombre, "visitas": state_incr("visitas")}
    route "GET /doc"
        give content(page([heading(1, "Doc"), prose("hola")], {"title": "Doc"}))
`;
const a = syn.handle(app, { method: "GET", path: "/saludo/ana" }, { host });
const b = syn.handle(app, { method: "GET", path: "/saludo/ana" }, { host });
check("handle: ruta + state_incr durable", a.status === 200 && a.body.includes('"visitas": 1') && b.body.includes('"visitas": 2'), [a, b]);
const md = syn.handle(app, { method: "GET", path: "/doc", headers: { accept: "text/markdown" } }, { host });
check("handle: content() negociado para agentes (markdown)", md.content_type.startsWith("text/markdown") && md.body.includes("# Doc"), md);

// 5. Modo asíncrono: `http` = fetch real, contra un server local de la app.
const server = createServer((req, res) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ path: req.url })); });
await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
const port = server.address().port;
const asyncHost = {
  async http(req) {
    const res = await fetch(req.url, { method: req.method, headers: Object.fromEntries(req.headers), body: req.body ?? undefined });
    return { status: res.status, headers: res.headers, body: await res.text() };
  },
  kv,
};
r = await syn.runAsync(`require net("127.0.0.1")\nlet r be http_get("http://127.0.0.1:${port}/ping")\nprint(r["status"])\nprint(r["body"])`, { host: asyncHost });
check("async: fetch de la app resuelve mientras el Worker espera", r.ok && r.output[0] === "200" && r.output[1].includes('"/ping"'), r);
r = await syn.runAsync(`let r be http_get("http://127.0.0.1:${port}/ping")`, { host: asyncHost });
check("async: sin `require net` el gate deniega antes del host", !r.ok && r.errors[0].includes("Capability not granted: net"), r);
server.close();
await syn.close();

// 6. El techo de la app manda aunque el host ofrezca todo.
r = syn.run('require llm\nprint(reason about "x")', { host, ceiling: "stdout" });
check("ceiling: la app deniega llm aunque lo ofrezca", !r.ok && r.errors[0].includes("Capability not granted: llm"), r);

console.log(failed ? `${failed} FAIL` : "all ok");
process.exit(failed ? 1 : 0);

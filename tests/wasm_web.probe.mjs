// Sonda viva del artefacto embebible (synsema-wasm-web + @synsema/wasm) bajo Node.
//
//   node tests/wasm_web.probe.mjs [ruta/al/synsema_wasm_web.wasm] [ruta/al/synsema nativo]
//
// Cubre, de punta a punta y por la API (no la CLI):
//  1. paridad byte a byte con el binario nativo en las sondas puras (si se pasa el nativo);
//  2. techo del embebedor (`ceiling`) + audit exportado;
//  3. red PROVISTA por el host (F3): fetch → un http.Server local, gateado por `require net`;
//  4. LLM provisto por el host (F3): reason/decide + llm_usage;
//  5. memoria persistente sobre el KV del host (F4): remember en una corrida, recall en otra;
//  6. serve en modo handler (F5): rutas, params, 404/405, auth, content(), errors with,
//     state_* durable entre requests;
//  7. modo asíncrono (Worker + Atomics) con un `http` async (fetch real de Node);
//  8. lo que el host NO ofrece falla diciendo por qué (sin host: http/memoria).
// Cualquier aserción fallida termina con exit 1.

import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Synsema } from "../packages/synsema-wasm/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const wasmPath = process.argv[2] ?? resolve(root, "engine/target/wasm32-unknown-unknown/wasm/synsema_wasm_web.wasm");
const nativeBin = process.argv[3] ?? null;

let failures = 0;
function check(name, cond, detail) {
  if (cond) console.log(`  ok  ${name}`);
  else {
    failures++;
    console.log(`FAIL  ${name}${detail !== undefined ? " — " + JSON.stringify(detail).slice(0, 600) : ""}`);
  }
}
const src = (rel) => readFileSync(resolve(root, rel), "utf8");

const syn = await Synsema.load(wasmPath);
await syn.ready();
console.log(`== synsema-wasm-web ${syn.version()} (${wasmPath})`);

// 1. Paridad nativo ↔ wasm (mismas sondas que el CI de wasip1; la línea fetch_error se
//    excluye: nativo deniega por capability, el host dice que no hay transporte).
const ETH_KEY = "0000000000000000000000000000000000000000000000000000000000000001";
for (const name of ["wasm_pure", "wasm_agents", "wasm_respond", "wasm_sandbox", "wasm_math"]) {
  const file = `tests/${name}.probe.syn`;
  const r = syn.run(src(file), { filename: file, env: { ETH_KEY } });
  check(`${name}: corre sin errores`, r.ok, r.errors);
  if (nativeBin && existsSync(nativeBin)) {
    const native = execFileSync(nativeBin, ["run", file], { cwd: root, env: { ...process.env, ETH_KEY }, encoding: "utf8" })
      .split(/\r?\n/).filter((l) => l.length && !l.startsWith("fetch_error="));
    const wasm = r.output.filter((l) => !l.startsWith("fetch_error="));
    check(`${name}: paridad byte a byte con nativo`, JSON.stringify(native) === JSON.stringify(wasm), { native: native.slice(0, 5), wasm: wasm.slice(0, 5) });
  }
}
{
  const r = syn.run(src("tests/wasm_pure.probe.syn"), { env: { ETH_KEY } });
  check("wasm_pure: keccak256('') vector", r.output.includes("keccak_vacio=c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"));
  check("wasm_pure: eth_address(clave 0x…01)", r.output.includes("addr_key1=0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"));
  check("wasm_pure: fetch sin `require net` → capability (igual que nativo)", r.output.some((l) => l.startsWith("fetch_error=Capability not granted: net")), r.output);
  const nohost = syn.run('require net("example.com")\nlet r be fetch("https://example.com")\nprint(r["error"])');
  check("wasm_pure: con net pero sin host, fetch dice que no hay transporte", nohost.ok && nohost.output[0].includes("provides no http transport"), nohost);
}

// 2. Techo del embebedor + audit.
{
  const r = syn.run(src("tests/wasm_sandbox.probe.syn"), { env: { ETH_KEY }, ceiling: "sandbox" });
  check("ceiling sandbox: `require random` denegado", !r.ok && r.errors[0].includes("Capability not granted: random"), r.errors);
  check("ceiling sandbox: el audit registra la denegación", r.audit.some((a) => a.capability.includes("random") && a.granted === false), r.audit);
  if (nativeBin && existsSync(nativeBin)) {
    // Paridad del AUDIT con el binario nativo (`run --format json` = la forma de `syn.run()`):
    // misma secuencia de {capability, granted, source, reason, origin}, incluidos los
    // grants ambientales que el techo rechaza (origin "runtime") y los `require` por
    // encima del techo (source "ceiling").
    // El programa falla bajo --sandbox (require random denegado) → exit 1; execFileSync
    // lanza en exit ≠0 pero el informe JSON igual sale por stdout (lo capturamos del throw).
    let natOut;
    try {
      natOut = execFileSync(nativeBin, ["run", "--format", "json", "--sandbox", "--no-env-file", "tests/wasm_sandbox.probe.syn"],
        { cwd: root, env: { ...process.env, ETH_KEY }, encoding: "utf8" });
    } catch (e) {
      natOut = e.stdout;
    }
    const nat = JSON.parse(natOut);
    const proj = (a) => a.map((e) => [e.capability, e.granted, e.source, e.reason, e.origin]);
    check("ceiling sandbox: audit idéntico nativo ↔ wasm", JSON.stringify(proj(nat.audit)) === JSON.stringify(proj(r.audit)), { native: proj(nat.audit), wasm: proj(r.audit) });
    check("ceiling sandbox: informe nativo con la forma de syn.run()", nat.ok === false && Array.isArray(nat.output) && Array.isArray(nat.errors) && nat.exit === 1 && typeof nat.llm_tokens === "number", nat);
  }
  const r2 = syn.run(src("tests/wasm_sandbox.probe.syn"), { env: { ETH_KEY }, ceiling: "stdout,random,secret=ETH_KEY" });
  check("ceiling cap-set suficiente: corre", r2.ok && r2.output.includes("after_task=secret"), r2.errors);
  const r3 = syn.run("print(now() > 1700000000)");
  check("now() viene del reloj del host (Date.now)", r3.ok && r3.output[0] === "true", r3);
  const r4 = syn.run("require random\nlet a be random_int(1, 1000000)\nlet b be random_int(1, 1000000)\nprint(a == b)");
  check("random() viene de crypto.getRandomValues", r4.ok && r4.output[0] === "false", r4);
}

// 3. Red provista por el host: un http.Server local + fetch síncrono del host (vía
//    child_process + curl no; usamos un mini cliente síncrono sobre el bridge async en 7).
//    Acá el host `http` es SÍNCRONO y responde él mismo (simula un backend).
{
  const host = {
    http(req) {
      if (req.url === "https://api.example/ping") return { status: 200, headers: [["content-type", "application/json"]], body: JSON.stringify({ pong: true, method: req.method, auth: (req.headers.find(([k]) => k.toLowerCase() === "authorization") ?? [])[1] ?? null }) };
      return { status: 0, error: "host: unknown url " + req.url };
    },
  };
  const program = `require net("api.example")
require secret("API_KEY")
let r be fetch("https://api.example/ping", "GET", {"Authorization": bearer(secret("API_KEY"))})
print(r["status"])
print(r["body"])
let bad be fetch("https://api.example/nope")
print(bad["error"])`;
  const r = syn.run(program, { host, env: { API_KEY: "s3cr3t" } });
  check("host http: fetch pasa por el host", r.ok && r.output[0] === "200" && r.output[1].includes('"pong":true'), r);
  check("host http: el secret se materializa en el header (bearer)", r.output[1].includes('"auth":"Bearer s3cr3t"'), r.output);
  check("host http: error de transporte del host → {error}", r.output[2].startsWith("host: unknown url"), r.output);
  const denied = syn.run('let r be fetch("https://api.example/ping")\nprint(r["status"])', { host });
  check("host http: sin `require net` el gate deniega ANTES de llamar al host", !denied.ok && denied.errors[0].includes("Capability not granted: net"), denied);
  const ceilinged = syn.run('require net("api.example")\nlet r be fetch("https://api.example/ping")', { host, ceiling: "stdout" });
  check("host http: el ceiling del embebedor manda sobre lo que el host ofrece", !ceilinged.ok && ceilinged.errors[0].includes("Capability not granted: net"), ceilinged);
}

// 4. LLM provisto por el host.
{
  const calls = [];
  const host = { llm(op, prompt) { calls.push([op, prompt]); return { content: `mock:${op}`, tokens: 7 }; } };
  const program = `require llm
print(llm_available())
let x be reason about "the weather"
print(x)
let d be decide between ["a", "b"] given "x"
print(d)
print(llm_usage())`;
  const r = syn.run(program, { host });
  check("host llm: llm_available() y reason/decide van al host", r.ok && r.output[0] === "true" && r.output[1] === "mock:reason" && r.output[2] === "mock:decide", r);
  check("host llm: llm_usage suma los tokens reportados", r.output[3] === "14" && r.llm_tokens >= 14, r.output);
  check("host llm: el prompt lleva el subject", calls[0][1].includes("the weather"), calls);
  const offline = syn.run('print(llm_available())\nprint(reason about "x")');
  check("sin host llm: placeholders offline del core", offline.ok && offline.output[0] === "false" && offline.output[1].startsWith("[reasoning about"), offline);
}

// 5. Memoria persistente sobre el KV del host (dos corridas, mismo store).
{
  const store = new Map();
  const kv = {
    get: (ns, k) => store.get(ns + "\0" + k) ?? null,
    set: (ns, k, v) => { store.set(ns + "\0" + k, v); },
    delete: (ns, k) => { store.delete(ns + "\0" + k); },
    list: (ns) => [...store.keys()].filter((x) => x.startsWith(ns + "\0")).map((x) => x.slice(ns.length + 1)),
  };
  const host = { kv };
  const first = syn.run(`require memory("agenda")\nremember("preference", "prefers dark mode", ["ui"])\nprint(memory_summary())`, { host, filename: "agenda.syn" });
  check("host kv: remember persiste en el KV del host", first.ok && store.has("memory:agenda\0memory"), first);
  check("host kv: memory_summary reporta el backend", first.output.join("\n").includes("Backend: host-kv"), first.output);
  const second = syn.run(`require memory("agenda")\nlet hits be recall(search="dark")\nprint(length(hits))\nprint(hits[0]["content"])\ncreate_progress("job", ["a", "b"])\nstart_step("job", "a")\ncomplete_step("job", "a")\nprint(resume_point("job"))`, { host, filename: "agenda.syn" });
  check("host kv: recall en otra corrida encuentra lo recordado", second.ok && second.output[0] === "1" && second.output[1] === "prefers dark mode", second);
  check("host kv: progress persiste (resume point)", second.output[2] === "b" && store.has("memory:agenda\0progress"), second);
  const undeclared = syn.run(`remember("preference", "x")`, { host, filename: "agenda.syn" });
  check("host kv: sin `require memory` → capability + sugerencia", !undeclared.ok && undeclared.errors[0].includes('require memory("agenda")'), undeclared);
  const nokv = syn.run(`require memory("agenda")\nremember("preference", "x")`, { filename: "agenda.syn" });
  check("sin host kv: la memoria declarada dice que no hay almacenamiento", !nokv.ok && nokv.errors[0].includes("provides no durable storage"), nokv);
  const ceil = syn.run(`require memory("agenda")\nremember("preference", "x")`, { host, ceiling: "stdout", filename: "agenda.syn" });
  check("host kv: el ceiling deniega memory aunque el host lo ofrezca", !ceil.ok && ceil.errors[0].includes("Capability not granted: memory"), ceil);
}

// 6. serve en modo handler.
{
  const store = new Map();
  const kv = {
    get: (ns, k) => store.get(ns + "\0" + k) ?? null,
    set: (ns, k, v) => { store.set(ns + "\0" + k, v); },
    delete: (ns, k) => { store.delete(ns + "\0" + k); },
    list: (ns) => [...store.keys()].filter((x) => x.startsWith(ns + "\0")).map((x) => x.slice(ns.length + 1)),
  };
  const app = `require serve(8080)
task check_token(token)
    when token == "abc"
        give {"id": "ana"}
    give nothing

task shape_error(status, message, request)
    give {"custom": message, "path": request.path}

serve on 8080
    auth with check_token
    errors with shape_error
    route "GET /hello/:name"
        print(\`hello {params.name}\`)
        give {"hi": params.name, "q": query}
    route "POST /items" requires auth
        let n be state_incr("items")
        give created({"n": n, "by": request.user.id, "body": request.json})
    route "GET /doc/:id"
        give content(page([heading(1, "Doc"), prose(\`id {params.id}\`)], {"title": "Doc"}))
    route "GET /go"
        give redirect("/hello/x")
    route "POST /shape"
        expect body {name: text, price: number}
        give ok(json of request)
    route "GET /hdr"
        give with_header(ok({"x": 1}), "X-Trace", "abc")
    route "GET /list"
        give [1, 2, 3, 4, 5]
`;
  const host = { kv };
  const r1 = syn.handle(app, { method: "GET", path: "/hello/ana?x=1", headers: [["accept", "application/json"]] }, { host });
  check("handle: ruta con :param + query + log de print", r1.status === 200 && r1.body === '{"hi": "ana", "q": {"x": "1"}}' && r1.log[0] === "hello ana", r1);
  const r404 = syn.handle(app, { method: "GET", path: "/nope" }, { host });
  check("handle: 404 pasa por `errors with`", r404.status === 404 && r404.body.includes('"custom": "no route for GET /nope"'), r404);
  const r405 = syn.handle(app, { method: "DELETE", path: "/hello/ana" }, { host });
  check("handle: 405 con Allow", r405.status === 405 && r405.headers.some(([k, v]) => k === "Allow" && v === "GET"), r405);
  const r401 = syn.handle(app, { method: "POST", path: "/items", headers: { authorization: "Bearer nope" }, body: "{}" }, { host });
  check("handle: auth rechaza (401)", r401.status === 401, r401);
  const rA = syn.handle(app, { method: "POST", path: "/items", headers: { authorization: "Bearer abc", "content-type": "application/json" }, body: '{"k": 1}' }, { host });
  const rB = syn.handle(app, { method: "POST", path: "/items", headers: { authorization: "Bearer abc", "content-type": "application/json" }, body: '{"k": 2}' }, { host });
  check("handle: auth + created() + request.json", rA.status === 201 && rA.body.includes('"by": "ana"') && rA.body.includes('"k": 1'), rA);
  check("handle: state_incr durable en el KV del host entre requests", rB.body.includes('"n": 2') && store.has("state\0items"), rB);
  const bad = syn.handle(app, { method: "POST", path: "/items", headers: { authorization: "Bearer abc", "content-type": "application/json" }, body: "{not json" }, { host });
  check("handle: JSON malformado declarado → 400", bad.status === 400, bad);
  const md = syn.handle(app, { method: "GET", path: "/doc/7", headers: { accept: "text/markdown" } }, { host });
  const html = syn.handle(app, { method: "GET", path: "/doc/7.html" }, { host });
  check("handle: content() negocia por Accept (md)", md.status === 200 && md.content_type.startsWith("text/markdown") && md.body.includes("# Doc"), md);
  check("handle: content() negocia por sufijo (.html)", html.content_type.startsWith("text/html") && html.body.includes("<h1"), html);
  const go = syn.handle(app, { method: "GET", path: "/go" }, { host });
  check("handle: redirect() → 3xx + Location", go.status >= 300 && go.status < 400 && go.headers.some(([k, v]) => k === "Location" && v === "/hello/x"), go);
  const badShape = syn.handle(app, { method: "POST", path: "/shape", headers: { "content-type": "application/json" }, body: '{"name": "x", "price": "cheap"}' }, { host });
  const goodShape = syn.handle(app, { method: "POST", path: "/shape", headers: { "content-type": "application/json" }, body: '{"name": "x", "price": 3}' }, { host });
  check("handle: expect → 400 con field", badShape.status === 400 && badShape.body.includes('"field": "price"'), badShape);
  check("handle: expect ok → 200", goodShape.status === 200 && goodShape.body.includes('"price": 3'), goodShape);
  const hdr = syn.handle(app, { method: "GET", path: "/hdr" }, { host });
  check("handle: with_header() emite el header extra", hdr.status === 200 && hdr.headers.some(([k, v]) => k === "X-Trace" && v === "abc"), hdr);
  const list = syn.handle(app, { method: "GET", path: "/list?limit=2&cursor=1" }, { host });
  check("handle: paginación de colecciones (?limit&cursor)", list.status === 200 && list.body.includes('"items": [2, 3]') && list.body.includes('"total": 5'), list);
  const noserve = syn.handle("print(1)", { method: "GET", path: "/" });
  check("handle: sin bloque serve → 500 con el error", noserve.status === 500 && noserve.errors[0].includes("no `serve` block"), noserve);
  const nocap = syn.handle('serve on 9\n    route "GET /"\n        give 1', { method: "GET", path: "/" });
  check("handle: `serve on` sin `require serve(puerto)` se exige como en nativo", nocap.status === 500 && nocap.errors[0].includes("missing capability serve(9)"), nocap);
  // Aislamiento entre requests: un `set` sobre un global NO persiste (snapshot por request,
  // como el serve nativo); el estado compartido va por state_*.
  const iso = 'require serve(9)\nlet contador be 0\nlet lista be []\nserve on 9\n    route "GET /n"\n        set contador to contador + 1\n        set lista to append(lista, 1)\n        give {"n": contador, "l": length(lista), "s": state_incr("hits")}';
  const i1 = syn.handle(iso, { method: "GET", path: "/n" }, { host });
  const i2 = syn.handle(iso, { method: "GET", path: "/n" }, { host });
  check("handle: `set` sobre un global no persiste al request siguiente (snapshot)", i1.body === '{"n": 1, "l": 1, "s": 1}' && i2.body === '{"n": 1, "l": 1, "s": 2}', [i1.body, i2.body, i1.errors, i2.errors]);
}

// 7. Modo asíncrono: Worker + Atomics, con un `http` async (fetch real contra un server local).
{
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ path: req.url, method: req.method, echo: body }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const host = {
    async http(req) {
      const res = await fetch(req.url, { method: req.method, headers: Object.fromEntries(req.headers), body: req.body ?? undefined });
      return { status: res.status, headers: res.headers, body: await res.text() };
    },
    kv: { get: async () => null, set: async () => {} },
    log: (line) => console.log("     [host log]", line),
    sleep: true,
  };
  const program = `require net("127.0.0.1")
let r be http_post("http://127.0.0.1:${port}/echo", "hola")
print(r["status"])
print(r["body"])
sleep(0.05)
print("slept")`;
  const r = await syn.runAsync(program, { host });
  check("async: fetch real del host resuelve mientras el Worker espera", r.ok && r.output[0] === "200" && r.output[1].includes('"echo":"hola"'), r);
  check("async: sleep() usa la pausa del host", r.output[2] === "slept", r.output);
  const big = await syn.runAsync(`require net("127.0.0.1")\nlet r be http_get("http://127.0.0.1:${port}/big")\nprint(length(r["body"]))`, {
    host: { async http() { return { status: 200, body: "x".repeat(5 * 1024 * 1024) }; } },
  });
  check("async: respuestas más grandes que el SAB viajan en chunks", big.ok && big.output[0] === String(5 * 1024 * 1024), big);
  const h = await syn.handleAsync('require serve(1)\nserve on 1\n    route "GET /"\n        give {"ok": true}', { method: "GET", path: "/" }, { host });
  check("async: handleAsync", h.status === 200 && h.body === '{"ok": true}', h);
  server.close();
  await syn.close();
}

// 8. Errores del programa son datos, nunca traps.
{
  const r = syn.run("let x be");
  check("parse error → errors[]", !r.ok && r.errors[0].startsWith("Parse error"), r);
  const r2 = syn.run("print(1 / 0)");
  check("runtime error → errors[]", !r2.ok && r2.errors[0].startsWith("Runtime error"), r2);
  const r3 = syn.run('print(read_file("x.txt"))');
  check("sin FS: read_file lo dice", !r3.ok && r3.errors[0].includes("this host has no filesystem"), r3);
  const r4 = syn.run('sql("select 1")');
  check("sin DB: sql lo dice", !r4.ok && r4.errors[0].includes("not available in the pure profile"), r4);
  const t = syn.test('test "suma"\n    assert_eq(1 + 1, 2)\ntest "falla"\n    assert(1 == 2, "nope")');
  check("test(): cuenta pasados/fallados", t.passed === 1 && t.failed === 1, t);
  const c = syn.check('require memory("a")\nrequire memory("b")');
  check("check(): valida la declaración de memoria sin ejecutar", !c.ok && c.errors[0].includes("Multiple memory declarations"), c);
}

console.log(failures ? `\n${failures} FAIL` : "\nall ok");
process.exit(failures ? 1 : 0);

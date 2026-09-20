//! synsema-vela-guest — Synsema corriendo como **guest de Vela** (Horizen), el coprocesador
//! confidencial: un módulo WebAssembly que el Executor de Vela instancia una vez y al que llama
//! por su ABI con punteros a memoria lineal. Este crate es el adaptador fino que la regla de dos
//! ejes pide: el motor expone UN ABI genérico de embebido (`synsema-wasm-web`: `call_json` con
//! operaciones JSON) y cada host es una traducción de ida y vuelta FUERA de `engine/crates`.
//!
//! # El ABI de Vela (leído del Executor, `vela/pkg/wasm/wasmtime_runtime.go`, y de
//! `vela-common-go/wasm`)
//!
//! Exports que el Executor llama (todos los punteros son `i32` en la memoria del guest; los
//! buffers de ENTRADA son bytes crudos escritos con `allocate`, `ptr = 0` cuando están vacíos; los
//! de SALIDA son `[u32 LE len][json]` que el host lee y libera con `deallocate(ptr, 4 + len)`):
//!
//! | export | firma | cuándo |
//! |---|---|---|
//! | `memory` | (export de memoria) | siempre |
//! | `allocate(size: i32) -> i32` / `deallocate(ptr: i32, size: i32)` | | host ↔ guest |
//! | `load_module(app_id: i64) -> i32` | | cache warm-up del Executor |
//! | `deploy(app_id: i64, params_ptr, params_len) -> i32` | `constructorParams` JSON | una vez, al desplegar |
//! | `deposit(app_id: i64, sender_ptr, sender_len, token_ptr, token_len, value_ptr, value_len, state_ptr, state_len) -> i32` | sender/token = 20 bytes; value = big-endian de un big.Int | cuando `assetAmount > 0` |
//! | `process_request(app_id: i64, sender_ptr, sender_len, request_type: i32, payload_ptr, payload_len, state_ptr, state_len) -> i32` | `request_type` 1 = PROCESS, 2 = DEANONYMIZATION | cada request |
//! | `trusted_request(app_id: i64, payload_ptr, payload_len, state_ptr, state_len) -> i32` | sin sender | TRUSTPROCESS (4) desde un trigger contract |
//! | `get_allocated_memory_stats(ret_ptr)` / `get_memory_stats() -> i32` | opcionales | debug |
//!
//! Resultados (JSON con las etiquetas de Go; `[]byte` va en **base64**, `Address` en hex `0x…`,
//! `Uint256` en hex `0x…` sin ceros a la izquierda, `[32]byte` como array de 32 números):
//! `DeployResult`/`LoadModuleResult` `{state, fuel, error?}`; `DepositResult`
//! `{state, events, appEvents, fuel, error?}`; `ProcessResult`
//! `{state, events, appEvents, withdrawals, report?, fuel, error?}`. `PlainEvent`
//! `{userId, eventSubType, data}`, `AppEvent` `{eventSubType, data}`, `Withdrawal`
//! `{tokenAddress, destinationAddress, amount}`. Un `error` no vacío es un fallo del request.
//!
//! # El contrato del `.syn` embebido (ver README.md)
//!
//! El programa define tasks por nombre; cada una recibe UN mapa y devuelve UN mapa:
//! `deploy(ctx)`, `deposit(ctx)`, `process(ctx)`, y opcionalmente `deanonymize(ctx)`,
//! `trusted(ctx)`, `load_module(ctx)` (si faltan, caen en `process` / `deploy`) e
//! `invariants(ctx)` (: corre tras cada transición con `{kind, before, after, deposit?,
//! Withdrawals, events}` y falla la request si devuelve descripciones). El adaptador decodifica las
//! entradas de Vela a valores Synsema (direcciones en hex, montos como texto decimal exacto, estado
//! Y payload ya parseados de JSON, y el payload crudo también como `payload_hex` porque un trigger
//! contract manda bytes ABI, no JSON) y codifica la respuesta al formato exacto de Vela. Cada
//! campo de bytes de la respuesta (`state`, `report`, `data` de un evento) se acepta en tres
//! formas: `<campo>` (texto tal cual o JSON compacto), `<campo>_hex` (`0x…`, binario exacto — lo
//! que un contrato decodifica con `abi.decode`) o `<campo>_base64`. `subtype` es `0x` + 64 hex o
//! una etiqueta ASCII corta (≤ 32 bytes, alineada a la izquierda, la convención del starter kit
//! para trigger contracts).
//!
//! # Salidas públicas
//!
//! `RequestCompleted(…, applicationFees, errorMsg)` es público on-chain: el fee **es** el fuel y
//! `errorMsg` es el texto del `error`. Por eso el adaptador:
//! - publica `error` sólo como **código** (`^[a-z0-9_]{1,32}$`): un `{"error": código}` de la app
//!   sale tal cual; cualquier otro texto sale como `app_error`, y todo error del motor o del
//!   contrato del adaptador como `runtime_error`; el texto completo va al log del Executor
//!   (`WRN`/`ERR`, el canal del operador), nunca a la cadena. `{"error": código, "error_detail":
//!   Texto}` manda el detalle sólo al log;
//! - reporta **un solo fuel por app** en toda respuesta (política `fuel` > mayor literal del
//!   fuente > `SYNSEMA_VELA_FUEL` al compilar > 50). El `fuel` de una task se acepta pero no sale;
//!   `steps()` jamás sale: ambos van al log (`INF fuel: …`);
//! - con la política `reject: "private"` convierte, sólo en PROCESS (tipo 1), un `{"error": …}`
//!   Deliberado de la app en un resultado exitoso —con el estado que la app ve intacto— y UN
//!   evento cifrado al `sender` (`{"rejected": código, "detail": …}`);
//! - con `events_pad: N` rellena el `data` JSON de cada evento privado hasta un múltiplo de N y
//!   con `events_min: K` agrega eventos de relleno al `sender` hasta K;
//! - con `state_pad: N` (encendido por default bajo `reject: "private"`) rellena el ESTADO entero
//!   hasta un múltiplo de N y le suma un contador `n` que sube en toda transición, así el tamaño
//!   y el state root no separan una request aceptada de una rechazada.
//!
//! La política la devuelve `deploy` (o `load_module`) en `"policy"` y viaja dentro del estado
//! firmado bajo la clave `"_vela"`, que la app nunca ve.
//!
//! El programa corre bajo el techo `stdout` del ABI genérico: sin `time`, sin `random`, sin red —
//! Determinista por construcción, que es lo que el state root firmado exige. `print` va al stdout
//! De WASI con prefijo `INF`, que es el canal de logs de Vela.

use std::cell::{Cell, OnceCell};

use serde_json::{json, Map, Value};

/// El programa de la app vive en un SLOT de tamaño fijo dentro de los datos del módulo
/// (`build.rs` lo llena con `SYNSEMA_VELA_APP`, default `app.syn`). La cabecera lo hace
/// localizable en el `.wasm` ya compilado: `tools/embed.syn` lo sobreescribe con otro programa sin
/// compilador de por medio — mismo intérprete, y el SHA-256 que Vela verifica cubre a los dos.
/// Layout: magic (16) · largo del nombre (1) · nombre (63) · largo u32 LE (4) · programa · relleno.
const SLOT_MAGIC: &[u8; 16] = b"SYNSEMA.APPSLOT1";
const SLOT_SIZE: usize = 524_288;
const SLOT_HEADER: usize = 16 + 1 + 63 + 4;
/// `static mut` a propósito: un `static` inmutable es una constante para LLVM, que podría plegar
/// lecturas con el contenido del build; así siempre se lee lo que hay en memoria (lo parcheado).
#[no_mangle]
#[used]
static mut APP_SLOT: [u8; SLOT_SIZE] = *include_bytes!(concat!(env!("OUT_DIR"), "/app.slot"));

fn app_slot() -> &'static [u8] {
    // SAFETY: el slot nunca se escribe en runtime; sólo se lee a través del puntero.
    unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(APP_SLOT) as *const u8, SLOT_SIZE) }
}

/// El programa (texto) que hay en el slot; vacío si la cabecera no es la esperada.
fn app_source() -> &'static str {
    let s = app_slot();
    if &s[..16] != SLOT_MAGIC {
        return "";
    }
    let len = u32::from_le_bytes([s[80], s[81], s[82], s[83]]) as usize;
    if len > SLOT_SIZE - SLOT_HEADER {
        return "";
    }
    core::str::from_utf8(&s[SLOT_HEADER..SLOT_HEADER + len]).unwrap_or("")
}

/// El nombre del archivo del programa (para logs y errores), o `app.syn`.
fn app_name() -> &'static str {
    let s = app_slot();
    let n = s[16] as usize;
    if &s[..16] != SLOT_MAGIC || n == 0 || n > 63 {
        return "app.syn";
    }
    core::str::from_utf8(&s[17..17 + n]).unwrap_or("app.syn")
}

/// Techo del programa: sólo `stdout` (los `print` se recogen como logs). Sin `time` ni `random`
/// ni nada del host: el mismo input da siempre los mismos bytes.
const CEILING: &str = "stdout";

const REQUEST_PROCESS: i32 = 1;
const REQUEST_DEANONYMIZATION: i32 = 2;
const REQUEST_TRUSTPROCESS: i32 = 4;

/// Fuel por app si ni la política ni el fuente lo dicen: fijado al compilar
/// (`SYNSEMA_VELA_FUEL=80 cargo build …`) o 50.
const BUILD_FUEL: Option<&str> = option_env!("SYNSEMA_VELA_FUEL");
const DEFAULT_FUEL: u128 = 50;

/// La clave del estado donde viaja la política (`deploy` la declara; la app no la ve).
const POLICY_KEY: &str = "_vela";

/// Dentro de `_vela`: el contador anti-repetición y el relleno del estado. Los escribe el
/// ADAPTADOR, no la app, así que `state_in` los saca antes de parsear la política (si no,
/// `Policy::parse` los vería como claves desconocidas, que es justo lo que debe rechazar).
const STATE_COUNTER_KEY: &str = "n";
const STATE_PAD_KEY: &str = "_";

/// El bucket de relleno del estado que rige cuando la app declara `reject: "private"` y no fija
/// `state_pad`. No es un default cosmético: sin relleno, `reject: private` no esconde NADA de lo
/// que promete contra quien mira la cadena (auditoría ronda 4/V3), así que el modo se enciende
/// con el relleno puesto y `state_pad` sólo afina el bucket.
const DEFAULT_STATE_PAD: usize = 256;
const MAX_STATE_PAD: u64 = 1 << 20;

// =========================================================
// memoria: allocate / deallocate / stats (el mismo modelo que la app de referencia en TinyGo)
// =========================================================

thread_local! {
    static LIVE_ALLOCS: Cell<i64> = const { Cell::new(0) };
    static LIVE_BYTES: Cell<i64> = const { Cell::new(0) };
    /// El escaneo de literales de fuel del slot se hace una vez: el slot no cambia en runtime.
    static SLOT_FUEL: OnceCell<Option<u128>> = const { OnceCell::new() };
    /// Aviso único: `events_pad` sobre un `data` que no es un objeto JSON.
    static PAD_WARNED: Cell<bool> = const { Cell::new(false) };
    /// Aviso único: `events_min` declarado sin `events_pad` (los rellenos se distinguen por tamaño).
    static MIN_WARNED: Cell<bool> = const { Cell::new(false) };
    /// Aviso único: `reject: private` con el relleno del estado apagado a mano (`state_pad: 0`).
    static STATE_PAD_WARNED: Cell<bool> = const { Cell::new(false) };
    /// Sólo en tests: lo que se imprimió al log del Executor, para poder afirmar que un saldo
    /// NO está ahí . En producción `log` sólo hace `println!`.
    #[cfg(test)]
    static LOG_CAPTURE: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn note_alloc(bytes: i64) {
    LIVE_ALLOCS.with(|c| c.set(c.get() + 1));
    LIVE_BYTES.with(|c| c.set(c.get() + bytes));
}

fn note_free(bytes: i64) {
    LIVE_ALLOCS.with(|c| c.set((c.get() - 1).max(0)));
    LIVE_BYTES.with(|c| c.set((c.get() - bytes).max(0)));
}

/// Reserva `size` bytes para que el host escriba. `0` para tamaños no positivos (el host
/// representa un buffer vacío como `ptr = 0, len = 0`).
#[no_mangle]
pub extern "C" fn allocate(size: i32) -> i32 {
    if size <= 0 {
        return 0;
    }
    let mut v: Vec<u8> = Vec::with_capacity(size as usize);
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    note_alloc(i64::from(size));
    ptr as i32
}

/// Libera un buffer de `allocate` o un resultado (`size = 4 + len`).
///
/// # Safety
/// `ptr`/`size` deben venir de `allocate(size)` o de un resultado de este módulo, una sola vez.
#[no_mangle]
pub unsafe extern "C" fn deallocate(ptr: i32, size: i32) {
    if ptr == 0 || size <= 0 {
        return;
    }
    drop(Vec::from_raw_parts(ptr as *mut u8, 0, size as usize));
    note_free(i64::from(size));
}

/// Opcional (TinyGo: retorno múltiple por puntero): escribe `mapSize` y `cumulativeMemorySize`
/// como dos `i64` little-endian en `ret_ptr`.
///
/// # Safety
/// `ret_ptr` debe apuntar a 16 bytes escribibles reservados con `allocate(16)`.
#[no_mangle]
pub unsafe extern "C" fn get_allocated_memory_stats(ret_ptr: *mut u8) {
    if ret_ptr.is_null() {
        return;
    }
    let (n, bytes) = (LIVE_ALLOCS.with(Cell::get), LIVE_BYTES.with(Cell::get));
    std::ptr::copy_nonoverlapping(n.to_le_bytes().as_ptr(), ret_ptr, 8);
    std::ptr::copy_nonoverlapping(bytes.to_le_bytes().as_ptr(), ret_ptr.add(8), 8);
}

/// Opcional (la app de referencia lo exporta así): `MemoryStats` como JSON.
#[no_mangle]
pub extern "C" fn get_memory_stats() -> i32 {
    let (n, bytes) = (LIVE_ALLOCS.with(Cell::get), LIVE_BYTES.with(Cell::get));
    pack(json!({"mapSize": n, "cumulativeMemorySize": bytes}).to_string().as_bytes())
}

/// Empaqueta `bytes` como `[u32 LE len][bytes]`; el host lo libera con `deallocate(ptr, 4 + len)`.
fn pack(bytes: &[u8]) -> i32 {
    let total = 4 + bytes.len();
    let mut v: Vec<u8> = Vec::with_capacity(total);
    v.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    v.extend_from_slice(bytes);
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    note_alloc(total as i64);
    ptr as i32
}

/// Bytes de entrada escritos por el host (`ptr = 0` o `len <= 0` = vacío).
unsafe fn input(ptr: i32, len: i32) -> &'static [u8] {
    if ptr == 0 || len <= 0 {
        return &[];
    }
    std::slice::from_raw_parts(ptr as *const u8, len as usize)
}

// =========================================================
// los exports de Vela: decodifican punteros y delegan en los flujos (testeables con una app inline)
// =========================================================

/// `load_module(appId)`: cache warm-up. Si la app define `load_module`, se llama; si no, el estado
/// inicial es el de `deploy` sin parámetros (lo que hace la app de referencia).
#[no_mangle]
pub extern "C" fn load_module(app_id: i64) -> i32 {
    pack(load_module_flow(&App::production(), app_id).to_string().as_bytes())
}

/// `deploy(appId, paramsPtr, paramsLen)`: una vez, con `constructorParams` (JSON o vacío).
///
/// # Safety
/// los punteros/longitudes los escribió el host con `allocate`.
#[no_mangle]
pub unsafe extern "C" fn deploy(app_id: i64, params_ptr: i32, params_len: i32) -> i32 {
    pack(deploy_flow(&App::production(), app_id, input(params_ptr, params_len)).to_string().as_bytes())
}

/// `deposit(appId, sender, token, value, state)`: llega cuando el request trae `assetAmount > 0`.
///
/// # Safety
/// los punteros/longitudes los escribió el host con `allocate`.
#[no_mangle]
pub unsafe extern "C" fn deposit(
    app_id: i64,
    sender_ptr: i32,
    sender_len: i32,
    token_ptr: i32,
    token_len: i32,
    value_ptr: i32,
    value_len: i32,
    state_ptr: i32,
    state_len: i32,
) -> i32 {
    let r = deposit_flow(
        &App::production(),
        app_id,
        input(sender_ptr, sender_len),
        input(token_ptr, token_len),
        input(value_ptr, value_len),
        input(state_ptr, state_len),
    );
    pack(r.to_string().as_bytes())
}

/// `process_request(appId, sender, requestType, payload, state)`: PROCESS (1) y DEANONYMIZATION (2).
/// Con 2 la app debe devolver `report`; con 1 no debe (si lo trae, se descarta con aviso).
///
/// # Safety
/// los punteros/longitudes los escribió el host con `allocate`.
#[no_mangle]
pub unsafe extern "C" fn process_request(
    app_id: i64,
    sender_ptr: i32,
    sender_len: i32,
    request_type: i32,
    payload_ptr: i32,
    payload_len: i32,
    state_ptr: i32,
    state_len: i32,
) -> i32 {
    let r = process_flow(
        &App::production(),
        app_id,
        input(sender_ptr, sender_len),
        request_type,
        input(payload_ptr, payload_len),
        input(state_ptr, state_len),
    );
    pack(r.to_string().as_bytes())
}

/// `trusted_request(appId, payload, state)`: TRUSTPROCESS desde un trigger contract, sin sender.
///
/// # Safety
/// los punteros/longitudes los escribió el host con `allocate`.
#[no_mangle]
pub unsafe extern "C" fn trusted_request(app_id: i64, payload_ptr: i32, payload_len: i32, state_ptr: i32, state_len: i32) -> i32 {
    let r = trusted_flow(&App::production(), app_id, input(payload_ptr, payload_len), input(state_ptr, state_len));
    pack(r.to_string().as_bytes())
}

// =========================================================
// los flujos: una función por entry point, con la app como parámetro
// =========================================================

fn load_module_flow(app: &App, app_id: i64) -> Value {
    log("INF", &format!("synsema-vela-guest: engine {}, app {}", engine_version(), app.name));
    let ctx = json!({"app_id": app_id, "kind": "load_module", "params": Value::Null});
    let own_task = app.defines("load_module");
    let result = deploy_like(app, "load_module", Some("deploy"), ctx);
    // Sin `load_module` propia, un `deploy` que exige params (p. ej. la dirección de un trigger
    // contract) no debe tumbar el warm-up: el Executor descarta este estado (sigue con el
    // persistido, `getOrLoadModule` ignora lo devuelto) y sólo mira `error` — y un `error` acá
    // deja la app sin poder cargarse tras un reinicio del Executor. Estado vacío, y se avisa.
    if !own_task {
        if let Some(e) = result.get("error").and_then(Value::as_str) {
            log("WRN", &format!("load_module: deploy(params: nothing) failed ({}); answering an empty state — the Executor only warms its cache here and keeps the persisted state. Define `task load_module(ctx)` to control this.", e));
            return json!({"state": b64(&[]), "fuel": fuel_hex(app, &Policy::default())});
        }
    }
    result
}

fn deploy_flow(app: &App, app_id: i64, params: &[u8]) -> Value {
    log("INF", &format!("synsema-vela-guest: deploy app {} (engine {}, program {})", app_id, engine_version(), app.name));
    let ctx = json!({"app_id": app_id, "kind": "deploy", "params": decode_json_or_text(params)});
    deploy_like(app, "deploy", None, ctx)
}

fn deposit_flow(app: &App, app_id: i64, sender: &[u8], token: &[u8], value: &[u8], state: &[u8]) -> Value {
    let sender = address_hex(sender);
    let token = address_hex(token);
    // ANTES de decodificar nada (auditoría R3/M5): `value` son los bytes big-endian de un
    // `big.Int` que el host escribe, y la conversión a decimal es cuadrática en su largo
    // (32 B → 3 ms, 8 KB → 152 ms, 32 KB → 2,4 s, 64 KB → 9,4 s): ~120 KB cuelgan la request
    // dentro del enclave contra el timeout de 30 s del Executor. Un monto de Vela es un Uint256,
    // 32 bytes; todo lo demás es entrada malformada y se rechaza acá, en O(1).
    if value.len() > 32 {
        return failure_result(
            &Failure::Runtime(format!("deposit: the value is {} bytes; a Uint256 is at most 32", value.len())),
            &fuel_hex(app, &Policy::default()),
        );
    }
    let (dec, hex) = (be_bytes_to_decimal(value), u256_hex_of_bytes(value));
    let mut ctx = Map::new();
    ctx.insert("app_id".into(), json!(app_id));
    ctx.insert("kind".into(), json!("deposit"));
    ctx.insert("sender".into(), sender.clone());
    ctx.insert("token".into(), token.clone());
    ctx.insert("value".into(), json!(dec));
    ctx.insert("value_hex".into(), json!(hex));
    let call = Call {
        kind: "deposit",
        request_type: 0,
        shape: ResultShape::Deposit,
        sender: sender.as_str().map(str::to_string),
        prev: state,
        deposit: Some(json!({"token": token, "value": dec, "value_hex": hex})),
        task: "deposit",
        fallback: None,
    };
    transition(app, &call, ctx)
}

fn process_flow(app: &App, app_id: i64, sender: &[u8], request_type: i32, payload: &[u8], state: &[u8]) -> Value {
    let (kind, task, fallback): (&'static str, &'static str, Option<&'static str>) = match request_type {
        REQUEST_DEANONYMIZATION => ("deanonymize", "deanonymize", Some("process")),
        REQUEST_TRUSTPROCESS => ("trusted", "trusted", Some("process")),
        // PROCESS (1) y cualquier tipo futuro: la task `process` recibe `request_type` y decide.
        _ => ("process", "process", None),
    };
    let sender = address_hex(sender);
    let mut ctx = Map::new();
    ctx.insert("app_id".into(), json!(app_id));
    ctx.insert("kind".into(), json!(kind));
    ctx.insert("request_type".into(), json!(request_type));
    ctx.insert("sender".into(), sender.clone());
    ctx.insert("payload".into(), decode_json_or_text(payload));
    ctx.insert("payload_hex".into(), hex_value(payload));
    let shape = if request_type == REQUEST_DEANONYMIZATION { ResultShape::Deanonymize } else { ResultShape::Process };
    let call = Call {
        kind,
        request_type,
        shape,
        sender: sender.as_str().map(str::to_string),
        prev: state,
        deposit: None,
        task,
        fallback,
    };
    transition(app, &call, ctx)
}

fn trusted_flow(app: &App, app_id: i64, payload: &[u8], state: &[u8]) -> Value {
    // El payload lo produjo el trigger contract (`getTrustProcessPayload`), en claro y en ABI:
    // Como texto se perdería, por eso viaja también en `payload_hex`.
    let mut ctx = Map::new();
    ctx.insert("app_id".into(), json!(app_id));
    ctx.insert("kind".into(), json!("trusted"));
    ctx.insert("request_type".into(), json!(REQUEST_TRUSTPROCESS));
    ctx.insert("sender".into(), Value::Null);
    ctx.insert("payload".into(), decode_json_or_text(payload));
    ctx.insert("payload_hex".into(), hex_value(payload));
    let call = Call {
        kind: "trusted",
        request_type: REQUEST_TRUSTPROCESS,
        shape: ResultShape::Process,
        sender: None,
        prev: state,
        deposit: None,
        task: "trusted",
        fallback: Some("process"),
    };
    transition(app, &call, ctx)
}

// =========================================================
// El programa: fuente, nombre y el fuel escaneado
// =========================================================

/// El programa que el adaptador corre. En producción es el del slot (`App::production`); los
/// tests inyectan programas inline (`App::inline`) — por eso los flujos reciben la app en vez de
/// leer el slot.
struct App<'a> {
    source: &'a str,
    name: &'a str,
    /// El mayor literal de fuel del fuente (`"fuel": "N"`, `"fuel": N`, `let FUEL be "N"`), si hay.
    fuel_literal: Option<u128>,
}

impl App<'static> {
    fn production() -> Self {
        let fuel_literal = SLOT_FUEL.with(|c| *c.get_or_init(|| max_fuel_literal(app_source())));
        App { source: app_source(), name: app_name(), fuel_literal }
    }
}

impl<'a> App<'a> {
    #[cfg(test)]
    fn inline(source: &'a str) -> Self {
        App { source, name: "inline.syn", fuel_literal: max_fuel_literal(source) }
    }

    fn defines(&self, task: &str) -> bool {
        defines_task(self.source, task)
    }
}

/// El mayor literal de fuel del fuente: `"fuel": "N"` / `"fuel": N` en cualquier mapa, y la
/// constante `let FUEL be "N"` / `let FUEL be N` que las apps usan en todas sus ramas. Decimal o
/// hex (`0x50`). Textual, como `defines_task`: no hace falta parsear para leer un literal.
///
/// Que sea TEXTUAL tiene dos consecuencias que la app debe conocer (auditoría R2/M4, documentadas
/// En el README): (a) el escaneo no sabe qué código es alcanzable, así que un literal grande en
/// una task muerta —o en un `test`— fija el fee de TODA la app; (b) un literal que no parsea
/// limpio (`"3.5"`, `"abc"`, `-3`) se avisa por el log y se ignora, nunca se aproxima. Si querés
/// El valor exacto y nada más, declaralo en la política: `"policy": {"fuel": "50"}` manda sobre
/// el escaneo.
fn max_fuel_literal(source: &str) -> Option<u128> {
    let mut best: Option<u128> = None;
    let mut bad: Vec<String> = Vec::new();
    // Los comentarios (`-- …`) no cuentan; un literal no numérico se avisa.
    for line in source.lines() {
        let code = match line.find("--") {
            Some(i) => &line[..i],
            None => line,
        };
        for (i, _) in code.match_indices("\"fuel\"") {
            let rest = code[i + "\"fuel\"".len()..].trim_start();
            if let Some(rest) = rest.strip_prefix(':') {
                match leading_uint(rest) {
                    Some(n) => best = Some(best.map_or(n, |b| b.max(n))),
                    // Un identificador (`"fuel": FUEL`) no es un literal: la constante ya se
                    // escanea por su `let`. Sólo un literal no numérico (`"abc"`, `-3`) se avisa.
                    None if looks_like_literal(rest) => bad.push(rest.trim().chars().take(24).collect()),
                    None => {}
                }
            }
        }
        if let Some(rest) = code.trim_start().strip_prefix("let FUEL be") {
            match leading_uint(rest) {
                Some(n) => best = Some(best.map_or(n, |b| b.max(n))),
                None if looks_like_literal(rest) => bad.push(rest.trim().chars().take(24).collect()),
                None => {}
            }
        }
    }
    for b in bad {
        log("WRN", &format!("fuel: literal {:?} is not a non-negative integer; ignored for the uniform fuel", b));
    }
    if let Some(env) = BUILD_FUEL {
        if parse_fuel_value(&json!(env)).is_err() {
            log("WRN", &format!("fuel: SYNSEMA_VELA_FUEL={:?} (build time) is not a non-negative integer; ignored", env));
        }
    }
    best
}

/// ¿Lo que sigue empieza como un literal (comilla, dígito o signo) y no como un identificador?
fn looks_like_literal(s: &str) -> bool {
    matches!(s.trim_start().chars().next(), Some(c) if c == '"' || c == '-' || c.is_ascii_digit())
}

/// El literal de fuel al inicio de `s` (tras espacios), entre comillas o desnudo, decimal o
/// hexadecimal: `"50"`, `50`, `"0x50"`, `0x50`. El token ENTERO tiene que ser el número
/// antes esto cortaba en el primer no-dígito, así que `let FUEL be "0x50"`
/// Daba 0 —fee 0 on-chain, en silencio— y `"3.5"` daba 3. Lo que no parsea limpio devuelve
/// `None` y el caller lo avisa por el log.
fn leading_uint(s: &str) -> Option<u128> {
    let t = s.trim_start();
    // Entre comillas: el token es todo lo que hay hasta la comilla de cierre.
    let token = match t.strip_prefix('"') {
        Some(rest) => rest.split('"').next().unwrap_or(""),
        // Desnudo: hasta el primer delimitador de un mapa/expresión.
        None => t.split([',', '}', ')', ']', ' ', '\t']).next().unwrap_or(""),
    }
    .trim();
    if token.is_empty() {
        return None;
    }
    let (digits, radix) = match token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
        Some(h) => (h, 16),
        None => (token, 10),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u128::from_str_radix(digits, radix).ok()
}

// =========================================================
// política por app (`"policy"` de deploy → `_vela` en el estado)
// =========================================================

/// Lo que la app declara sobre sus salidas públicas. Viaja en el estado firmado bajo `_vela`.
#[derive(Clone, Debug, Default, PartialEq)]
struct Policy {
    /// `reject: "private"`: en PROCESS, un `{"error": …}` de la app es un éxito con evento al sender.
    reject_private: bool,
    /// `events_pad: N`: el `data` JSON de cada evento privado se rellena hasta un múltiplo de N.
    events_pad: Option<usize>,
    /// `events_min: K`: eventos de relleno al sender hasta llegar a K.
    events_min: Option<usize>,
    /// `state_pad: N`: el estado entero (con `_vela`) se rellena hasta un múltiplo de N bytes.
    /// `Some(0)` = apagado explícito. Ver `state_bucket`.
    state_pad: Option<usize>,
    /// `fuel: N`: el fuel uniforme de la app (manda sobre los literales del fuente).
    fuel: Option<u128>,
}

/// Techos de sanidad: un bucket o una cantidad absurdos no deben poder agotar la memoria del guest.
const MAX_EVENTS_PAD: u64 = 1 << 20;
const MAX_EVENTS_MIN: u64 = 1024;

impl Policy {
    fn parse(v: &Value) -> Result<Policy, String> {
        let Value::Object(m) = v else {
            return Err(format!("policy must be a map, got {}", v));
        };
        let mut p = Policy::default();
        for (k, val) in m {
            match k.as_str() {
                "reject" => match val.as_str() {
                    Some("private") => p.reject_private = true,
                    Some("public") => p.reject_private = false,
                    _ => return Err(format!("policy.reject must be \"private\" or \"public\", got {}", val)),
                },
                "events_pad" => {
                    let n = uint_value(val).filter(|n| *n > 0 && *n <= MAX_EVENTS_PAD).ok_or_else(|| {
                        format!("policy.events_pad must be an integer in 1..={}, got {}", MAX_EVENTS_PAD, val)
                    })?;
                    p.events_pad = Some(n as usize);
                }
                "events_min" => {
                    let n = uint_value(val)
                        .filter(|n| *n <= MAX_EVENTS_MIN)
                        .ok_or_else(|| format!("policy.events_min must be an integer in 0..={}, got {}", MAX_EVENTS_MIN, val))?;
                    p.events_min = Some(n as usize);
                }
                "state_pad" => {
                    let n = uint_value(val).filter(|n| *n <= MAX_STATE_PAD).ok_or_else(|| {
                        format!("policy.state_pad must be an integer in 0..={} (0 turns it off), got {}", MAX_STATE_PAD, val)
                    })?;
                    p.state_pad = Some(n as usize);
                }
                "fuel" => p.fuel = Some(parse_fuel_value(val).map_err(|e| format!("policy.fuel: {}", e))?),
                other => {
                    return Err(format!(
                        "policy: unknown key {:?} (valid: reject, events_pad, events_min, state_pad, fuel)",
                        other
                    ))
                }
            }
        }
        Ok(p)
    }

    /// La forma canónica que se guarda en el estado (sólo lo que difiere del default, orden fijo).
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        if self.reject_private {
            m.insert("reject".into(), json!("private"));
        }
        if let Some(n) = self.events_pad {
            m.insert("events_pad".into(), json!(n));
        }
        if let Some(n) = self.events_min {
            m.insert("events_min".into(), json!(n));
        }
        if let Some(n) = self.state_pad {
            m.insert("state_pad".into(), json!(n));
        }
        if let Some(f) = self.fuel {
            m.insert("fuel".into(), json!(f.to_string()));
        }
        Value::Object(m)
    }

    fn is_empty(&self) -> bool {
        *self == Policy::default()
    }

    /// El bucket efectivo de relleno del estado, o `None` si no se rellena. `reject: "private"`
    /// lo enciende con `DEFAULT_STATE_PAD`; `state_pad: 0` lo apaga a mano (y entonces el modo
    /// deja de esconder el tamaño, que es lo que avisa `warn_unpadded_reject`).
    fn state_bucket(&self) -> Option<usize> {
        match self.state_pad {
            Some(0) => None,
            Some(n) => Some(n),
            None if self.reject_private => Some(DEFAULT_STATE_PAD),
            None => None,
        }
    }

    /// ¿Hay que escribir el contador anti-repetición? Sólo bajo `reject: "private"`: es ahí donde
    /// "el state root no cambió" es, por sí solo, el bit que el modo promete tapar.
    fn needs_counter(&self) -> bool {
        self.reject_private
    }
}

/// `reject: "private"` con el relleno apagado a mano: se avisa UNA vez, como el resto de los
/// avisos de política. No es "esconde poco": medido en la ronda 4, 49 sondas contra el dark pool
/// recuperan el monto exacto de una puja sellada leyendo sólo el tamaño del estado on-chain.
fn warn_unpadded_reject(policy: &Policy) {
    if policy.reject_private && policy.state_bucket().is_none() && !STATE_PAD_WARNED.with(Cell::get) {
        STATE_PAD_WARNED.with(|c| c.set(true));
        log(
            "WRN",
            "reject: private with state_pad: 0 hides nothing on-chain: the rejected state is returned byte for byte and the accepted one grew, so its SIZE is one bit per request (49 probes recover an exact sealed bid). Drop `state_pad` to take the default bucket, or set one that fits your state (warned once)",
        );
    }
}

/// Un entero no negativo dado como número JSON, float entero o texto decimal.
fn uint_value(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64().or_else(|| n.as_f64().filter(|f| *f >= 0.0 && f.fract() == 0.0 && *f < 1.8e19).map(|f| f as u64)),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

/// Un fuel (entero, texto decimal o `0x…`) como `u128`.
fn parse_fuel_value(v: &Value) -> Result<u128, String> {
    let h = u256_hex(v)?;
    let digits = &h[2..];
    if digits.len() > 32 {
        return Err("exceeds 128 bits".to_string());
    }
    u128::from_str_radix(digits, 16).map_err(|e| e.to_string())
}

/// El fuel uniforme de la app: política > mayor literal del fuente > `SYNSEMA_VELA_FUEL` > 50.
fn fuel_hex(app: &App, policy: &Policy) -> String {
    let n = policy
        .fuel
        .or(app.fuel_literal)
        .or_else(|| BUILD_FUEL.and_then(|s| parse_fuel_value(&json!(s)).ok()))
        .unwrap_or(DEFAULT_FUEL);
    format!("0x{:x}", n)
}

/// Lo que la task devolvió como `fuel` y los pasos del intérprete van al log, nunca a la cadena.
fn log_fuel(reported: &str, _declared: Option<&Value>, _steps: u64) {
    // Acá va UNA línea, siempre la misma para la misma app, y nada más. Lo que no se imprime y
    // por qué (el log del Executor está FUERA del enclave bajo Nitro, así que todo lo que pase por
    // acá es tan público como la cadena):
    //   · `steps`: un paso por nodo del AST, o sea lineal en lo que el bucle recorrió
    //     (1962/3473/5009/8156 pasos para 1/2/3/5 pujas selladas) — anula el `events_min` que T1
    //     construye para que la cantidad de eventos no se pueda contar. Ni bucketizado: el bucket
    //     sigue ordenando las requests por tamaño.
    //   · `app declared …`: el mismo canal con menos resolución (auditoría R3/B2). Ninguna de las
    //     apps devuelve `fuel` en un camino de error, así que `0x50` contra `none` era UN BIT
    //     uniforme —éxito o rechazo— justo el que `reject: private` existe para tapar. Y el valor
    //     no le sirve a nadie: el adaptador lo ignora, reporta el suyo.
    log("INF", &format!("fuel: reported {}", reported));
}

/// El estado previo separado en lo que la app ve y la política que traía.
struct StateIn {
    /// El valor que la app recibe en `ctx["state"]` (sin `_vela`).
    value: Value,
    policy: Policy,
    /// La política canónica a reinsertar en el estado de salida, si había.
    policy_value: Option<Value>,
    /// El contador anti-repetición que traía `_vela` (0 si no traía).
    counter: u64,
}

fn state_in(raw: &[u8]) -> Result<StateIn, String> {
    let mut value = decode_json_or_text(raw);
    let policy_raw = value.as_object_mut().and_then(|m| m.remove(POLICY_KEY));
    let (policy, policy_value, counter) = match policy_raw {
        Some(mut pv) => {
            // El contador y el relleno los escribe el ADAPTADOR: se sacan antes de parsear para
            // que `Policy::parse` siga rechazando toda clave que no declare la app.
            let counter = pv
                .as_object_mut()
                .and_then(|m| m.remove(STATE_COUNTER_KEY))
                .as_ref()
                .and_then(uint_value)
                .unwrap_or(0);
            if let Some(m) = pv.as_object_mut() {
                m.remove(STATE_PAD_KEY);
            }
            let p = Policy::parse(&pv).map_err(|e| format!("the state carries an invalid `{}` policy: {}", POLICY_KEY, e))?;
            let canonical = if p.is_empty() { None } else { Some(p.to_value()) };
            (p, canonical, counter)
        }
        None => (Policy::default(), None, 0),
    };
    Ok(StateIn { value, policy, policy_value, counter })
}

/// Cómo se cierra el estado de salida: la política canónica, el contador anti-repetición de ESTA
/// transición (si el modo lo pide) y el bucket de relleno.
///
/// Auditoría ronda 4/V3 — bajo `reject: "private"` la request rechazada salía con el estado
/// previo BYTE A BYTE, y la aceptada con uno que había crecido: el tamaño del estado on-chain era
/// un bit por request, y 49 sondas recuperaban el monto exacto de una puja sellada sin leer una
/// sola línea de log. El adaptador rellenaba los eventos y no el estado. Se cierra con las dos
/// mitades juntas, porque cada una sola deja la otra abierta:
///   · `n`, un contador que sube en TODA transición, así que el state root cambia siempre y
///     "el root quedó igual" deja de ser la señal;
///   · el relleno hasta un múltiplo de `state_bucket()`, que iguala el TAMAÑO. Lo que sigue
///     siendo observable es en qué bucket cayó el estado —o sea, que el estado cruzó los 256
///     bytes—, no un bit por request: la misma propiedad, y el mismo límite, que `events_pad`.
#[derive(Clone)]
struct Sealer {
    policy: Option<Value>,
    counter: Option<u64>,
    bucket: Option<usize>,
}

impl Sealer {
    /// El sellado de una transición: el contador de entrada + 1.
    fn next(st: &StateIn) -> Sealer {
        Sealer {
            policy: st.policy_value.clone(),
            counter: st.policy.needs_counter().then(|| st.counter.wrapping_add(1)),
            bucket: st.policy.state_bucket(),
        }
    }

    /// El sellado inicial (`deploy`/`load_module`): el contador arranca en 0.
    fn first(policy: &Policy, policy_value: Option<Value>) -> Sealer {
        Sealer {
            policy: policy_value,
            counter: policy.needs_counter().then_some(0),
            bucket: policy.state_bucket(),
        }
    }

    /// ¿Escribe algo en `_vela`? Si no, el estado sale tal cual (sin `_vela`, como siempre).
    fn writes(&self) -> bool {
        self.policy.is_some() || self.counter.is_some() || self.bucket.is_some()
    }

    /// Cierra el estado de la app: `_vela` como ÚLTIMA clave (política + contador + relleno) y
    /// el JSON compacto resultante rellenado hasta el múltiplo del bucket. Determinista.
    fn seal(&self, app_state: &Map<String, Value>) -> Vec<u8> {
        let mut m = app_state.clone();
        m.remove(POLICY_KEY);
        if !self.writes() {
            return Value::Object(m).to_string().into_bytes();
        }
        let mut vela = match &self.policy {
            Some(Value::Object(p)) => p.clone(),
            _ => Map::new(),
        };
        if let Some(n) = self.counter {
            vela.insert(STATE_COUNTER_KEY.into(), json!(n));
        }
        let Some(bucket) = self.bucket else {
            m.insert(POLICY_KEY.into(), Value::Object(vela));
            return Value::Object(m).to_string().into_bytes();
        };
        // Dos pasadas, como `pad_event_data`: se mide con el relleno vacío y se completa. El
        // relleno son espacios dentro de un string JSON, así que cada uno pesa exactamente un
        // byte y la segunda pasada da justo `target`.
        vela.insert(STATE_PAD_KEY.into(), Value::String(String::new()));
        m.insert(POLICY_KEY.into(), Value::Object(vela.clone()));
        let base = Value::Object(m.clone()).to_string().len();
        let target = base.div_ceil(bucket.max(1)) * bucket.max(1);
        vela.insert(STATE_PAD_KEY.into(), Value::String(" ".repeat(target - base)));
        m.insert(POLICY_KEY.into(), Value::Object(vela));
        Value::Object(m).to_string().into_bytes()
    }

    /// Re-sella unos bytes de estado que ya existen (el previo, cuando la task no devuelve
    /// `state` o cuando la request se rechaza en privado): se les saca el `_vela` viejo —con su
    /// contador y su relleno— y se vuelven a cerrar con los de esta transición. Si no son un
    /// objeto JSON no hay nada que sellar y salen tal cual (un estado así no puede llevar
    /// política: `out_state_bytes` ya lo rechaza).
    fn reseal(&self, prev: &[u8]) -> Vec<u8> {
        if !self.writes() {
            return prev.to_vec();
        }
        match decode_json_or_text(prev) {
            Value::Object(m) => self.seal(&m),
            _ => prev.to_vec(),
        }
    }
}

/// Un valor de estado sin la política (lo que `invariants` compara).
fn strip_policy(mut v: Value) -> Value {
    if let Some(m) = v.as_object_mut() {
        m.remove(POLICY_KEY);
    }
    v
}

/// Los bytes del estado de salida: el `state` de la app sellado con `_vela` como última clave
/// cuando es un objeto JSON; `state_hex`/`state_base64`/texto tal cual (la política no puede
/// viajar ahí: error); sin `state`, los bytes previos RE-SELLADOS (el contador de esta transición
/// tiene que subir igual). `None` sólo cuando no hay `state` ni previo.
fn out_state_bytes(out: &Map<String, Value>, sealer: &Sealer, prev: Option<&[u8]>) -> Result<Option<Vec<u8>>, String> {
    let explicit = out.get("state_hex").filter(|v| !v.is_null()).is_some() || out.get("state_base64").filter(|v| !v.is_null()).is_some();
    if !explicit {
        if let Some(Value::Object(m)) = out.get("state") {
            return Ok(Some(sealer.seal(m)));
        }
    }
    match bytes_field(out, "state")? {
        Some(b) => {
            // Perder la política en silencio dejaría la siguiente request pública
            // (sin `reject: private`, sin padding). Es un error de la app, no un aviso.
            if sealer.writes() {
                return Err(format!(
                    "the `{}` policy cannot be persisted: `state` must be a JSON object (got state_hex/state_base64/text) while the app has an output policy",
                    POLICY_KEY
                ));
            }
            Ok(Some(b))
        }
        None => Ok(prev.map(|p| sealer.reseal(p))),
    }
}

// =========================================================
// fallos: códigos on-chain, texto al log
// =========================================================

/// Por qué falla una request. On-chain sale sólo el código; el texto va al log.
#[derive(Debug)]
enum Failure {
    /// `{"error": código}` de la app (o texto libre → `app_error`), con el detalle para el log.
    /// `detail_private`: el detalle NO se imprime en el log del Executor (va `(private)`). Lo
    /// enciende el caller con `release.detail_private || run.private_seen` (y
    /// R2/B2: alcanza con que la corrida haya tocado privados). El evento cifrado al sender bajo
    /// `reject: private` sí lleva el texto: ese sumidero acepta `{app}`.
    App { code: String, detail: Option<String>, detail_private: bool },
    /// Error del motor o del contrato del adaptador: on-chain `runtime_error`.
    Runtime(String),
    /// `invariants(ctx)` devolvió descripciones o lanzó: on-chain `invariant_violation`.
    /// `private`: la corrida de `invariants` tocó datos privados, así que la CANTIDAD de
    /// descripciones no puede salir al log (auditoría ronda 4/V4). Ver `Failure::log`.
    Invariant { descriptions: Vec<String>, private: bool },
    /// Un valor `private` llegó a un sumidero que no acepta su etiqueta (p. ej. un saldo en
    /// `app_events`). On-chain `label_violation`; el camino y la etiqueta (nunca el valor) al log.
    Label { path: String, label: Vec<String>, accepts: &'static str },
}

impl Failure {
    fn code(&self) -> &str {
        match self {
            Failure::App { code, .. } => code,
            Failure::Runtime(_) => "runtime_error",
            Failure::Invariant { .. } => "invariant_violation",
            Failure::Label { .. } => "label_violation",
        }
    }

    fn log(&self) {
        match self {
            Failure::App { code, detail, detail_private } => {
                let shown = if *detail_private { "(private)" } else { detail.as_deref().unwrap_or("(no detail)") };
                log("WRN", &format!("app error {}: {}", code, shown))
            }
            Failure::Runtime(m) => log("ERR", &format!("runtime_error: {}", m)),
            // Auditoría ronda 4/V4: UNA descripción por línea era un canal NUMÉRICO. Los textos
            // ya salían redactados (la raíz de `invariants` es `Sink::Log`), pero la cuenta no:
            // cuatro de las siete apps arman la lista dentro de un bucle sobre el estado, así que
            // `n líneas` es `n` calculado sobre datos privados, contado por quien lee el log del
            // Executor — que bajo Nitro está FUERA del enclave. Cuando la corrida tocó privados
            // sale UNA línea fija, la misma que para `Failure::App` con detalle privado; cuando
            // no los tocó, la cuenta no dice nada de nadie y el diagnóstico completo se conserva.
            Failure::Invariant { descriptions, private } => {
                if *private {
                    log("ERR", "invariant_violation: (private)");
                } else {
                    for d in descriptions {
                        log("ERR", &format!("invariant_violation: {}", d));
                    }
                }
            }
            Failure::Label { path, label, accepts } => log(
                "ERR",
                &format!(
                    "label_violation: {} is private to {}, the sink accepts {} (declassify it, or keep it in state/events)",
                    path,
                    label.join(","),
                    accepts
                ),
            ),
        }
    }
}

/// `^[a-z0-9_]{1,32}$`: lo único que sale on-chain como `error`.
fn is_error_code(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// `{"error": …}` de la app clasificado: un código sale tal cual (con `error_detail` al log);
/// Cualquier otro texto es `app_error` y el texto entero es el detalle.
fn app_failure(out: &Map<String, Value>, detail_private: bool) -> Option<Failure> {
    let raw = match out.get("error") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(Value::Null) | None | Some(Value::String(_)) => return None,
        Some(other) => other.to_string(),
    };
    let extra = out.get("error_detail").filter(|v| !v.is_null()).map(|v| match v {
        Value::String(s) => s.clone(),
        o => o.to_string(),
    });
    if is_error_code(&raw) {
        Some(Failure::App { code: raw, detail: extra, detail_private })
    } else {
        // Texto libre: el texto ENTERO es el detalle y viene de la app (pudo computarse desde
        // datos privados): sólo se muestra si la corrida no tocó privados (lo decide el caller).
        let detail = match extra {
            Some(e) => format!("{} ({})", raw, e),
            None => raw,
        };
        Some(Failure::App { code: "app_error".to_string(), detail: Some(detail), detail_private })
    }
}

/// El resultado de una request fallida: `{state: null, fuel, error: código}`.
fn failure_result(f: &Failure, fuel: &str) -> Value {
    f.log();
    json!({"state": Value::Null, "fuel": fuel, "error": f.code()})
}

// =========================================================
// correr la app por el ABI genérico
// =========================================================

/// Lo que una corrida deja: el valor que devolvió la task de la app (ya pasado por los
/// sumideros, sin etiquetas) o el fallo clasificado, y los pasos.
struct AppRun {
    result: Result<Value, Failure>,
    steps: u64,
    /// La corrida desenvolvió algún valor privado : los textos de error no salen.
    private_seen: bool,
    /// `error_detail` venía privado: al log va `(private)`; al sender (cifrado) el texto.
    detail_private: bool,
}

/// El único principal de Vela: lo que viene cifrado al enclave y el estado son `{app}`.
const PRINCIPAL_APP: &str = "app";

/// Las FUENTES: claves de `ctx` que el driver marca `private(…, "app")` antes de llamar a la
/// task. `sender`, `token`, `value`, `app_id`, `params` y `deposit` son públicos (están on-chain).
const PRIVATE_SOURCES: &[&str] = &["state", "payload", "payload_hex", "before", "after", "events"];

/// El programa "app + driver": una sola línea, `let __vela_out be <task>(__vela_in)`. El contexto
/// NO se inyecta al fuente: viaja por la op `run` como `input` : el motor liga
/// `__vela_in` desde Rust y marca las FUENTES (`sources`) también desde Rust, así una `task
/// private` del programa no puede sombrear el etiquetado y no hay literal que escapar.
fn driver_source(app: &App, task: &str) -> String {
    format!("{}\n\nlet __vela_out be {}(__vela_in)\n", app.source, task)
}

/// Corre la task por el ABI genérico con las etiquetas de flujo encendidas, manda los `print`
/// De la app al log de Vela, y pasa el resultado por los sumideros (`release`). `root` es el
/// sumidero del valor entero: `Sink::App` para las tasks de entrada (deploy/transition), de modo
/// que la forma granular compile y cada campo se compruebe por separado, y `Sink::Log` para
/// `invariants`, cuyas descripciones van al log del Executor.
fn run_app_with(app: &App, task: &str, fallback: Option<&str>, ctx: &Value, root: Sink) -> AppRun {
    // Auditoría R2/M6: el programa no puede nombrar los ligados del driver. Fail-closed y antes
    // De correr nada: un `let __vela_in be …` sombreaba el ctx etiquetado.
    if let Some(line) = mentions_driver_name(app.source) {
        return AppRun {
            result: Err(Failure::Runtime(format!(
                "{}:{}: the program may not name `{}…`: `__vela_in` (the context) and `__vela_out` (the result) are the adapter's own bindings; rename yours",
                app.name, line, DRIVER_PREFIX
            ))),
            steps: 1,
            private_seen: false,
            detail_private: false,
        };
    }
    let name = if app.defines(task) {
        task
    } else if let Some(fb) = fallback.filter(|fb| app.defines(fb)) {
        fb
    } else {
        return AppRun { result: Err(Failure::Runtime(format!("the program defines no task '{}'", task))), steps: 1, private_seen: false, detail_private: false };
    };
    let sources: Map<String, Value> = PRIVATE_SOURCES.iter().map(|k| (k.to_string(), json!([PRINCIPAL_APP]))).collect();
    let req = json!({
        "op": "run",
        "source": driver_source(app, name),
        "filename": app.name,
        "ceiling": CEILING,
        "labels": true,
        "result": "__vela_out",
        "input": {"var": "__vela_in", "value": ctx, "sources": sources},
    });
    let raw = synsema_wasm_web::call_json(&req.to_string());
    let resp: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return AppRun { result: Err(Failure::Runtime(format!("engine response is not JSON: {}", e))), steps: 1, private_seen: false, detail_private: false },
    };
    let steps = resp.get("steps").and_then(Value::as_u64).unwrap_or(1).max(1);
    let private_seen = resp.get("private_seen").and_then(Value::as_bool).unwrap_or(false);
    let output: Vec<String> = resp
        .get("output")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect())
        .unwrap_or_default();
    let errors: Vec<String> = resp
        .get("errors")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect())
        .unwrap_or_default();
    let ok = resp.get("ok").and_then(Value::as_bool).unwrap_or(false);
    // Todo `print` de la app es log (un `print` de un valor privado ya llega redactado).
    for line in &output {
        log("INF", line);
    }
    if !ok || !errors.is_empty() {
        // El log del Executor está FUERA del enclave. El MOTOR ya redacta el texto de todo error
        // de runtime producido bajo control privado o tras desenvolver un privado: sale
        // `private(<los principales DECLARADOS>)` y **nada más** — desde la ronda 7 tampoco viaja
        // `file:line:col`, porque si el secreto elige cuál de N sitios falla la ubicación vale
        // log₂(N) bits, y acá cada request es una corrida. Sólo deja en claro sus propios
        // diagnósticos de etiquetas (el CAMINO del valor, que es lo que hay que ir a arreglar).
        // Acá se loguea ese texto tal cual, UNA sola vez (en `Failure::log`, L21).
        let msg = if errors.is_empty() { "the program failed".to_string() } else { errors.join("; ") };
        return AppRun { result: Err(Failure::Runtime(msg)), steps, private_seen, detail_private: false };
    }
    // El trazo de los `declassify` que CORRIERON no se loguea (auditoría R3/B2): lleva la línea
    // exacta, así que nombra la instrucción que se ejecutó — no es un bucket, es un identificador,
    // y el log del Executor está fuera del enclave. La revisión que un auditor hace es estática y
    // no necesita este canal: `synsema code check app.syn --json` lista TODOS los sitios con su
    // motivo, su línea y si el argumento es constante, sin correr nada ni mirar una request.
    let Some(result) = resp.get("result").cloned() else {
        return AppRun {
            result: Err(Failure::Runtime("the engine returned no result (an engine without labels/result support)".to_string())),
            steps,
            private_seen,
            detail_private: false,
        };
    };
    match release(result, root) {
        Ok((v, info)) => AppRun { result: Ok(v), steps, private_seen, detail_private: info.detail_private },
        Err(f) => AppRun { result: Err(f), steps, private_seen, detail_private: false },
    }
}


// =========================================================
// sumideros: qué campo del resultado puede llevar qué etiqueta
// =========================================================

/// Quién acepta un campo del resultado. `Public` = la cadena lo ve (nada privado sale ahí sin
/// `declassify`); `App` = viaja cifrado al usuario o queda en el estado sellado (acepta `{app}`);
/// `Log` = el log del Executor, que bajo Nitro está FUERA del enclave: acepta `{app}` pero todo
/// valor privado se reemplaza por `(private)` antes de imprimirse ;
/// `Ignored` = el adaptador no lo emite (no hay flujo que chequear).
#[derive(Clone, Copy, PartialEq)]
enum Sink {
    Public,
    App,
    Log,
    Ignored,
}

impl Sink {
    fn accepts(self) -> &'static str {
        match self {
            Sink::Public => "(public)",
            Sink::App | Sink::Log => "app",
            Sink::Ignored => "anything",
        }
    }
}

/// El sumidero de un camino, por su raíz (y, en `events`, por el campo del evento): `state`,
/// `report`, `error_detail` y los `data`/`user` de los eventos privados aceptan `{app}`; los
/// app events, las withdrawals, el código de `error`, `fuel` y `policy` son públicos on-chain.
/// `[]` es un índice de lista en el patrón.
fn sink_of(pattern: &[&str]) -> Sink {
    match pattern.first().copied().unwrap_or("") {
        "state" | "state_hex" | "state_base64" | "report" | "report_hex" | "report_base64" | "error_detail" => Sink::App,
        "events" => match pattern.get(2).copied() {
            Some("subtype") | Some("eventSubType") => Sink::Public,
            _ => Sink::App,
        },
        "app_events" | "appEvents" | "withdrawals" | "error" | "fuel" | "policy" => Sink::Public,
        _ => Sink::Ignored,
    }
}

/// ¿Este objeto es el marcador `{"$private": [...], "value": …}` que el motor emite?
fn private_marker(v: &Value) -> Option<(Vec<String>, &Value)> {
    let m = v.as_object()?;
    if m.len() != 2 {
        return None;
    }
    let label = m.get("$private")?.as_array()?.iter().map(|p| p.as_str().unwrap_or("?").to_string()).collect();
    Some((label, m.get("value")?))
}

/// Pasa el resultado por los sumideros y quita los marcadores.
///
/// La RAÍZ del resultado de una task de entrada es `Sink::App`, no `Sink::Public` (auditoría
/// R2/B2): un `give` bajo una rama que dependió del estado o del payload etiqueta el mapa entero
/// con `{app}`, y exigir que ESE mapa fuera público obligaba a la app a `declassify` el mapa
/// completo — con lo que salían saldos y pujas selladas por dentro de `error_detail`. Ahora el
/// mapa entero viaja como `{app}` y son los sumideros POR CAMPO los que deciden: lo que se
/// publica (`error`, `fuel`, `withdrawals`, `app_events`, `policy`) sigue exigiendo un
/// `declassify` del valor concreto, y lo que viaja cifrado o sellado (`state`, `report`, `events`,
/// `error_detail`) acepta `{app}` sin ceremonia. La forma granular que queremos:
///   `give {"error": declassify("insufficient_balance", "the outcome code is public on-chain"),
///          "error_detail": "have " + text(balance) + ", need " + text(amount)}`
/// `root` es lo que acepta el valor entero (`App` para una task de entrada; `Log` para
/// `invariants`, cuyas descripciones van al log del operador).
/// Los `error_detail` y las descripciones de `invariants` que vengan privados se reemplazan por
/// `"(private)"` (: el log del Executor está fuera del enclave). Los bytes
/// (`{"$bytes": base64}`) vuelven a la forma de `json_encode` (texto base64) y las claves de
/// programa escapadas (`$$x`) recuperan su nombre .
/// Lo que `release` aprendió además del valor: si `error_detail` venía privado (el log del
/// Executor lo recibe como `(private)`; el evento cifrado al sender bajo `reject: private` sí
/// lleva el texto, porque ese sumidero acepta `{app}`).
#[derive(Debug, Default)]
struct Released {
    detail_private: bool,
}

fn release(result: Value, root: Sink) -> Result<(Value, Released), Failure> {
    let mut pattern: Vec<String> = Vec::new();
    let mut shown: Vec<String> = Vec::new();
    let mut info = Released::default();
    let v = release_at(result, root, &mut pattern, &mut shown, &mut info)?;
    Ok((v, info))
}

fn release_at(v: Value, root: Sink, pattern: &mut Vec<String>, shown: &mut Vec<String>, info: &mut Released) -> Result<Value, Failure> {
    if let Some((label, inner)) = private_marker(&v) {
        let pat: Vec<&str> = pattern.iter().map(String::as_str).collect();
        let sink = if pat.is_empty() { root } else { sink_of(&pat) };
        let violates = match sink {
            Sink::Public => !label.is_empty(),
            Sink::App | Sink::Log => label.iter().any(|p| p != PRINCIPAL_APP),
            Sink::Ignored => false,
        };
        if violates {
            return Err(Failure::Label { path: shown_path(shown), label, accepts: sink.accepts() });
        }
        if !label.is_empty() {
            if pat.first().copied() == Some("error_detail") {
                info.detail_private = true;
            }
            // Todo el resultado de `invariants` va al log del operador (fuera del enclave bajo
            // Nitro): cualquier privado, a cualquier profundidad — la lista entera o UNA
            // descripción suelta, que es donde el saldo se colaba — se redacta (M1, R2/B2).
            if root == Sink::Log {
                return Ok(redact_private(inner));
            }
        }
        return release_at(inner.clone(), root, pattern, shown, info);
    }
    match v {
        Value::Object(m) => {
            if m.len() == 1 {
                if let Some(Value::String(b)) = m.get("$bytes") {
                    return Ok(Value::String(b.clone()));
                }
            }
            let mut out = Map::with_capacity(m.len());
            for (k, val) in m {
                let key = synsema_wasm_web::unescape_marker_key(&k);
                pattern.push(key.clone());
                shown.push(key.clone());
                let r = release_at(val, root, pattern, shown, info);
                pattern.pop();
                shown.pop();
                out.insert(key, r?);
            }
            Ok(Value::Object(out))
        }
        Value::Array(a) => {
            let mut out = Vec::with_capacity(a.len());
            for (i, val) in a.into_iter().enumerate() {
                pattern.push("[]".to_string());
                shown.push(format!("[{}]", i));
                let r = release_at(val, root, pattern, shown, info);
                pattern.pop();
                shown.pop();
                out.push(r?);
            }
            Ok(Value::Array(out))
        }
        other => Ok(other),
    }
}

/// Un valor privado destinado al log del operador: se reemplaza por `"(private)"` (una lista de
/// descripciones, elemento a elemento; lo demás, entero).
fn redact_private(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(|_| Value::String("(private)".to_string())).collect()),
        _ => Value::String("(private)".to_string()),
    }
}

/// `events[0].data.amount` desde los segmentos mostrados.
fn shown_path(shown: &[String]) -> String {
    let mut s = String::new();
    for seg in shown {
        if seg.starts_with('[') {
            s.push_str(seg);
        } else {
            if !s.is_empty() {
                s.push('.');
            }
            s.push_str(seg);
        }
    }
    if s.is_empty() {
        "result".to_string()
    } else {
        s
    }
}

/// El mapa que una task de entrada debe devolver.
fn as_map(v: Value, task: &str) -> Result<Map<String, Value>, String> {
    match v {
        Value::Object(m) => Ok(m),
        Value::Null => Err(format!("task '{}' returned nothing; a map is required", task)),
        other => Err(format!("task '{}' must return a map, got {}", task, other)),
    }
}

/// Los nombres del driver (`__vela_in`, el ctx que el motor liga desde Rust, y `__vela_out`, el
/// resultado que el adaptador lee) son RESERVADOS para el programa de la app: un `let __vela_in
/// Be {...}` al tope del archivo sombreaba el contexto y la task corría con uno público fabricado
/// por el propio programa .
/// Nombres más difíciles de colisionar no alcanzan: acá se rechaza el programa entero, como hace
/// El motor con sus nombres protegidos. La regla es simple y sin agujeros: el código de la app no
/// nombra `__vela` (los comentarios sí pueden).
const DRIVER_PREFIX: &str = "__vela";

/// `Some(línea)` con la primera línea de código que nombra `__vela…`, si la hay.
fn mentions_driver_name(source: &str) -> Option<usize> {
    source.lines().enumerate().find_map(|(i, line)| {
        let code = match line.find("--") {
            Some(at) => &line[..at],
            None => line,
        };
        code.contains(DRIVER_PREFIX).then_some(i + 1)
    })
}

/// ¿El programa define `task <name>(`? Textual y suficiente: el nombre es un identificador y la
/// definición va al inicio de línea (con o sin `export`).
fn defines_task(source: &str, name: &str) -> bool {
    source.lines().any(|l| {
        let t = l.trim_start();
        let t = t.strip_prefix("export ").unwrap_or(t);
        t.strip_prefix("task ")
            .map(|rest| rest.trim_start().starts_with(name) && rest.trim_start()[name.len()..].trim_start().starts_with('('))
            .unwrap_or(false)
    })
}

/// Escapa texto para un literal `"…"` de Synsema (que no interpola): sólo `\` y `"`; un JSON
/// compacto no trae saltos de línea ni controles crudos (serde los escapa a `\uXXXX`).
fn syn_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

fn engine_version() -> String {
    serde_json::from_str::<Value>(&synsema_wasm_web::call_json(r#"{"op":"version"}"#))
        .ok()
        .and_then(|v| v.get("version").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| "?".to_string())
}

/// Stdout de WASI con el prefijo que el Executor reconoce (`INF`/`WRN`/`ERR`). Bajo Nitro este
/// canal está FUERA del enclave: lo que pase por acá es tan público como la cadena (R2/B2).
fn log(level: &str, line: &str) {
    println!("{} {}", level, line);
    #[cfg(test)]
    LOG_CAPTURE.with(|c| c.borrow_mut().push(format!("{} {}", level, line)));
}

// =========================================================
// del mapa de la app al resultado exacto de Vela
// =========================================================

#[derive(Clone, Copy, PartialEq)]
enum ResultShape {
    Deposit,
    Process,
    Deanonymize,
}

/// Una transición de estado: lo que el export sabe de la llamada y el resultado necesita.
struct Call<'a> {
    kind: &'static str,
    request_type: i32,
    shape: ResultShape,
    /// El sender normalizado (`0x…`), o `None` (`trusted_request`, sender vacío).
    sender: Option<String>,
    /// El estado previo, byte a byte (con `_vela` si lo trae).
    prev: &'a [u8],
    /// Sólo en deposit: `{token, value, value_hex}` para `invariants`.
    deposit: Option<Value>,
    task: &'static str,
    fallback: Option<&'static str>,
}

/// `DeployResult` / `LoadModuleResult`: `{state, fuel, error?}`. `deploy` puede devolver
/// `"policy"`, que se valida y se guarda en el estado bajo `_vela`.
fn deploy_like(app: &App, task: &str, fallback: Option<&str>, ctx: Value) -> Value {
    let base_fuel = fuel_hex(app, &Policy::default());
    let run = run_app_with(app, task, fallback, &ctx, Sink::App);
    let out = match run.result.and_then(|v| as_map(v, task).map_err(Failure::Runtime)) {
        Ok(m) => m,
        Err(f) => return failure_result(&f, &base_fuel),
    };
    // El detalle no se imprime en el log si vino privado O si la corrida tocó privados
    // `private_seen`): el log del Executor está fuera del enclave .
    if let Some(f) = app_failure(&out, run.detail_private || run.private_seen) {
        return failure_result(&f, &base_fuel);
    }
    let policy = match out.get("policy").filter(|v| !v.is_null()) {
        Some(v) => match Policy::parse(v) {
            Ok(p) => p,
            Err(e) => return failure_result(&Failure::Runtime(format!("policy: {}", e)), &base_fuel),
        },
        None => Policy::default(),
    };
    let fuel = fuel_hex(app, &policy);
    log_fuel(&fuel, out.get("fuel"), run.steps);
    let policy_value = if policy.is_empty() { None } else { Some(policy.to_value()) };
    warn_unpadded_reject(&policy);
    let sealer = Sealer::first(&policy, policy_value);
    let state = match out_state_bytes(&out, &sealer, None) {
        Ok(Some(b)) => b,
        Ok(None) => return failure_result(&Failure::Runtime(format!("{} must return {{\"state\": …}}", task)), &fuel),
        Err(e) => return failure_result(&Failure::Runtime(e), &fuel),
    };
    if app.defines("invariants") {
        let ictx = invariants_ctx(task, Value::Null, strip_policy(decode_json_or_text(&state)), None, Vec::new(), Value::Array(Vec::new()));
        if let Err(f) = run_invariants(app, &ictx) {
            return failure_result(&f, &fuel);
        }
    }
    let mut m = Map::new();
    m.insert("state".into(), json!(b64(&state)));
    m.insert("fuel".into(), json!(fuel));
    Value::Object(m)
}

/// `DepositResult` / `ProcessResult`: corre la task, clasifica el fallo (o lo rechaza en privado),
/// Arma el resultado con la política del estado y corre `invariants`.
fn transition(app: &App, call: &Call, mut ctx: Map<String, Value>) -> Value {
    let st = match state_in(call.prev) {
        Ok(s) => s,
        Err(e) => return failure_result(&Failure::Runtime(e), &fuel_hex(app, &Policy::default())),
    };
    warn_unpadded_reject(&st.policy);
    let fuel = fuel_hex(app, &st.policy);
    ctx.insert("state".into(), st.value.clone());
    let run = run_app_with(app, call.task, call.fallback, &Value::Object(ctx), Sink::App);
    let steps = run.steps;
    let out = match run.result.and_then(|v| as_map(v, call.task).map_err(Failure::Runtime)) {
        Ok(m) => m,
        Err(f) => return failure_result(&f, &fuel),
    };
    log_fuel(&fuel, out.get("fuel"), steps);
    // `detail_private || private_seen`: lo que va al LOG. El evento cifrado al sender bajo
    // `reject: private` sí lleva el texto (ese sumidero acepta `{app}`) — ver `rejected_result`.
    if let Some(f) = app_failure(&out, run.detail_private || run.private_seen) {
        // Rechazo privado: sólo PROCESS (tipo 1), sólo un `{"error": …}` deliberado de la app, y
        // sólo con un sender al que mandarle el motivo. Un depósito fallido debe fallar (el
        // contrato tendría fondos sin saldo), y trusted/deanonymize no tienen a quién avisar.
        if call.shape == ResultShape::Process && call.request_type == REQUEST_PROCESS && st.policy.reject_private {
            match &call.sender {
                Some(sender) => return rejected_result(&f, sender, call.prev, &st, &fuel),
                None => log("WRN", "reject: private, but the request has no sender; failing publicly"),
            }
        }
        return failure_result(&f, &fuel);
    }
    if out.contains_key("policy") {
        log("WRN", "`policy` is declared by deploy/load_module only; ignored here");
    }
    match build_transition(app, call, &st, &out, &fuel) {
        Ok(v) => v,
        Err(f) => failure_result(&f, &fuel),
    }
}

fn build_transition(app: &App, call: &Call, st: &StateIn, out: &Map<String, Value>, fuel: &str) -> Result<Value, Failure> {
    let rt = Failure::Runtime;
    let sealer = Sealer::next(st);
    // Sin `state` (o `nothing`): el estado queda como vino, con el `_vela` de esta transición
    // (el contador sube igual — si no, "el root no cambió" volvería a ser un bit).
    let state = out_state_bytes(out, &sealer, Some(call.prev)).map_err(rt)?.unwrap_or_else(|| sealer.reseal(call.prev));
    let raw_events = out.get("events").cloned();
    let shaped = shape_events(raw_events.as_ref(), &st.policy, call.sender.as_deref()).map_err(rt)?;
    let mut m = Map::new();
    m.insert("state".into(), json!(b64(&state)));
    m.insert("events".into(), Value::Array(events_of(shaped.as_ref(), true).map_err(rt)?));
    m.insert("appEvents".into(), Value::Array(events_of(out.get("app_events").or_else(|| out.get("appEvents")), false).map_err(rt)?));
    let mut withdrawals_norm = Vec::new();
    if call.shape != ResultShape::Deposit {
        let w = withdrawals_of(out.get("withdrawals")).map_err(rt)?;
        withdrawals_norm = normalized_withdrawals(&w);
        m.insert("withdrawals".into(), Value::Array(w));
        match (call.shape, bytes_field(out, "report").map_err(rt)?) {
            (ResultShape::Deanonymize, Some(r)) => {
                m.insert("report".into(), json!(b64(&r)));
            }
            (ResultShape::Deanonymize, None) => {
                return Err(rt("a DEANONYMIZATION request (type 2) must return {\"report\": …}".to_string()));
            }
            (_, Some(_)) => {
                log("WRN", "the program returned a report on a non-deanonymization request; dropped (Vela refuses it)");
            }
            (_, None) => {}
        }
    }
    m.insert("fuel".into(), json!(fuel));
    // `invariants(ctx)` sobre la transición ya armada. Una deanonimización no cambia el
    // estado (el `state` que devuelva es el mismo de siempre): no se corre ahí.
    if call.shape != ResultShape::Deanonymize && app.defines("invariants") {
        let events = match raw_events {
            Some(Value::Array(a)) => Value::Array(a),
            _ => Value::Array(Vec::new()),
        };
        let ictx = invariants_ctx(
            call.kind,
            strip_policy(decode_json_or_text(call.prev)),
            strip_policy(decode_json_or_text(&state)),
            call.deposit.clone(),
            withdrawals_norm,
            events,
        );
        run_invariants(app, &ictx)?;
    }
    Ok(Value::Object(m))
}

/// Rechazo privado: la request "sale bien" con el estado de la app intacto, sin withdrawals ni
/// app events, y UN evento cifrado al sender con el motivo (más el relleno que la política pida).
/// No corre `invariants`: la transición es la identidad sobre lo que la app ve. Lo que NO es la
/// identidad es el `_vela`: el contador sube y el relleno se recalcula, que es lo que impide leer
/// el rechazo en la cadena (ver `Sealer`).
fn rejected_result(f: &Failure, sender: &str, prev: &[u8], st: &StateIn, fuel: &str) -> Value {
    let policy = &st.policy;
    let (code, detail) = match f {
        Failure::App { code, detail, .. } => (code.as_str(), detail.clone()),
        other => (other.code(), None),
    };
    // NADA se loguea acá (auditoría R3/B2). El código de error era el último canal: bajo
    // `reject: private` la request sale on-chain como un éxito con el estado byte a byte intacto,
    // así que el log era la ÚNICA señal, y `insufficient_balance` es justo la que distingue "sin
    // saldo" de "aceptada" — con el `state` elegido por el Executor, cada reejecución del mismo
    // payload sellado contra un saldo distinto era un bit, y con 50 sondas sale el monto exacto.
    // Tampoco se loguea "rechazada en privado" a secas: la presencia de la línea ya era el bit.
    // Una request rechazada en privado es indistinguible EN EL LOG de una que pasó, y desde la
    // ronda 4 también EN LA CADENA: hasta entonces el estado rechazado volvía byte a byte y el
    // aceptado había crecido, así que su TAMAÑO era un bit por request (49 sondas daban el monto
    // exacto de una puja sellada). Ahora las dos salidas pasan por el mismo `Sealer` — contador
    // que sube siempre y relleno al mismo bucket —, así que coinciden en tamaño y ninguna deja
    // el root quieto. Para depurar está el evento cifrado al sender (y `reject: "public"`, que
    // es el default).
    let ev = json!({"user": sender, "data": {"rejected": code, "detail": detail}});
    let events = match shape_events(Some(&Value::Array(vec![ev])), policy, Some(sender)).and_then(|shaped| events_of(shaped.as_ref(), true)) {
        Ok(e) => e,
        Err(e) => return failure_result(&Failure::Runtime(e), fuel),
    };
    let mut m = Map::new();
    m.insert("state".into(), json!(b64(&Sealer::next(st).reseal(prev))));
    m.insert("events".into(), Value::Array(events));
    m.insert("appEvents".into(), Value::Array(Vec::new()));
    m.insert("withdrawals".into(), Value::Array(Vec::new()));
    m.insert("fuel".into(), json!(fuel));
    Value::Object(m)
}

// ---- padding de eventos privados ----

/// Aplica `events_pad` y `events_min` a la lista `events` de la app (no a `app_events`, que son
/// públicos por diseño). Devuelve la lista a codificar; algo que no sea lista se deja tal cual
/// para que `events_of` dé su error.
fn shape_events(v: Option<&Value>, policy: &Policy, sender: Option<&str>) -> Result<Option<Value>, String> {
    if policy.events_pad.is_none() && policy.events_min.is_none() {
        return Ok(v.cloned());
    }
    // `events_min` solo rellena la CUENTA (auditoría R3/M6): con `{"events_min": 3}` salen un
    // evento real de 42 bytes y dos rellenos de 12, y el tamaño dice cuál es cuál. Los dos juntos
    // o ninguno; se avisa una vez, como el resto de los avisos de política.
    if policy.events_min.is_some() && policy.events_pad.is_none() && !MIN_WARNED.with(Cell::get) {
        MIN_WARNED.with(|c| c.set(true));
        log("WRN", "events_min without events_pad hides little: the filler events differ in size from the real ones, so the count is padded but the sizes still tell them apart — set events_pad too (warned once)");
    }
    let mut items: Vec<Value> = match v {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(other) => return Ok(Some(other.clone())),
    };
    if let Some(bucket) = policy.events_pad {
        for (i, ev) in items.iter_mut().enumerate() {
            if let Value::Object(m) = ev {
                let padded = pad_event_data(m, bucket).map_err(|e| format!("event {}: {}", i, e))?;
                if !padded && !PAD_WARNED.with(Cell::get) {
                    PAD_WARNED.with(|c| c.set(true));
                    log("WRN", "events_pad: an event's `data` is not a JSON object (data_hex/data_base64/text); it is sent unpadded (warned once)");
                }
            }
        }
    }
    if let Some(min) = policy.events_min {
        if items.len() < min {
            match sender {
                Some(sender) => {
                    while items.len() < min {
                        let mut m = Map::new();
                        m.insert("user".into(), json!(sender));
                        // Un relleno reconocible para el cliente; el `_` lo pone el padding.
                        m.insert("data".into(), json!({"pad": true}));
                        if let Some(bucket) = policy.events_pad {
                            pad_event_data(&mut m, bucket)?;
                        }
                        items.push(Value::Object(m));
                    }
                }
                None => log("WRN", &format!("events_min: {} events wanted, {} emitted, and no sender to pad to", min, items.len())),
            }
        }
    }
    Ok(Some(Value::Array(items)))
}

/// Rellena el `data` de un evento (un objeto JSON, o texto que parsea a uno) con una clave `"_"`
/// De espacios hasta que el JSON compacto mida el menor múltiplo de `bucket` que lo contiene.
/// Determinista. `false` si `data` no es un objeto (o viene en `data_hex`/`data_base64`).
fn pad_event_data(ev: &mut Map<String, Value>, bucket: usize) -> Result<bool, String> {
    let explicit = ev.get("data_hex").filter(|v| !v.is_null()).is_some() || ev.get("data_base64").filter(|v| !v.is_null()).is_some();
    if explicit {
        return Ok(false);
    }
    let mut obj = match ev.get("data") {
        Some(Value::Object(m)) => m.clone(),
        Some(Value::String(s)) => match serde_json::from_str::<Value>(s) {
            Ok(Value::Object(m)) => m,
            _ => return Ok(false),
        },
        _ => return Ok(false),
    };
    // `_` es la clave del relleno. Si la app la usa, alterarla en silencio (o
    // descartar un valor no textual) corrompería el evento: error claro.
    if let Some(v) = obj.get("_") {
        let is_blank = v.as_str().map(|t| t.chars().all(|c| c == ' ')).unwrap_or(false);
        if !is_blank {
            return Err(format!("events_pad reserves the key \"_\" of an event's data (found {}); rename it", v));
        }
    }
    obj.insert("_".into(), Value::String(String::new()));
    let base = Value::Object(obj.clone()).to_string().len();
    let target = base.div_ceil(bucket) * bucket;
    obj.insert("_".into(), Value::String(" ".repeat(target - base)));
    ev.insert("data".into(), Value::Object(obj));
    Ok(true)
}

// ---- invariantes por transición  ----

/// El `ctx` de `invariants`: `{kind, before, after, deposit?, withdrawals, events}`.
fn invariants_ctx(kind: &str, before: Value, after: Value, deposit: Option<Value>, withdrawals: Vec<Value>, events: Value) -> Value {
    let mut m = Map::new();
    m.insert("kind".into(), json!(kind));
    m.insert("before".into(), before);
    m.insert("after".into(), after);
    if let Some(d) = deposit {
        m.insert("deposit".into(), d);
    }
    m.insert("withdrawals".into(), Value::Array(withdrawals));
    m.insert("events".into(), events);
    Value::Object(m)
}

/// Las withdrawals ya codificadas para Vela, en la forma de la app: `{token, to, amount (texto
/// decimal exacto), amount_hex}`.
fn normalized_withdrawals(vela: &[Value]) -> Vec<Value> {
    vela.iter()
        .map(|w| {
            let hex = w.get("amount").and_then(Value::as_str).unwrap_or("0x0");
            let dec = be_bytes_to_decimal(&u256_hex_bytes(hex));
            json!({
                "token": w.get("tokenAddress").cloned().unwrap_or(Value::Null),
                "to": w.get("destinationAddress").cloned().unwrap_or(Value::Null),
                "amount": dec,
                "amount_hex": hex,
            })
        })
        .collect()
}

/// Corre `invariants(ctx)`: `nothing` o lista vacía = OK; una lista de descripciones o un error
/// = `invariant_violation` (las descripciones al log, y sólo si la corrida no tocó privados:
/// ver `Failure::log`).
fn run_invariants(app: &App, ctx: &Value) -> Result<(), Failure> {
    let run = run_app_with(app, "invariants", None, ctx, Sink::Log);
    let private = run.private_seen;
    let fail = |descriptions: Vec<String>| Failure::Invariant { descriptions, private };
    match run.result {
        Err(Failure::Runtime(e)) => Err(fail(vec![format!("invariants raised: {}", e)])),
        Err(other) => Err(other),
        Ok(Value::Null) => Ok(()),
        Ok(Value::Array(a)) if a.is_empty() => Ok(()),
        Ok(Value::Array(a)) => Err(fail(
            a.iter().map(|d| d.as_str().map(str::to_string).unwrap_or_else(|| d.to_string())).collect(),
        )),
        Ok(other) => Err(fail(vec![format!("invariants must return a list of descriptions or nothing, got {}", other)])),
    }
}

// ---- codificación de campos ----

/// El estado (o el reporte) como bytes: un texto va tal cual; cualquier otro valor, como JSON
/// compacto con el orden de claves del programa (determinista).
fn state_bytes(v: &Value) -> Vec<u8> {
    match v {
        Value::String(s) => s.clone().into_bytes(),
        other => other.to_string().into_bytes(),
    }
}

/// `events` (con `user`) o `app_events` (sin él): `[{user, subtype?, data}]` → Vela.
fn events_of(v: Option<&Value>, with_user: bool) -> Result<Vec<Value>, String> {
    let items = match v {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(a)) => a,
        Some(other) => return Err(format!("events must be a list, got {}", other)),
    };
    items
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let Value::Object(e) = ev else {
                return Err(format!("event {} must be a map", i));
            };
            let mut m = Map::new();
            if with_user {
                let user = e
                    .get("user")
                    .or_else(|| e.get("userId"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("event {}: missing \"user\" (a 0x… address)", i))?;
                m.insert("userId".into(), json!(normalize_address(user).map_err(|err| format!("event {}: user: {}", i, err))?));
            }
            m.insert(
                "eventSubType".into(),
                subtype_array(e.get("subtype").or_else(|| e.get("eventSubType"))).map_err(|err| format!("event {}: subtype: {}", i, err))?,
            );
            let data = bytes_field(e, "data").map_err(|err| format!("event {}: {}", i, err))?.unwrap_or_default();
            m.insert("data".into(), json!(b64(&data)));
            Ok(Value::Object(m))
        })
        .collect()
}

/// `withdrawals`: `[{token, to, amount}]` → `{tokenAddress, destinationAddress, amount}`.
fn withdrawals_of(v: Option<&Value>) -> Result<Vec<Value>, String> {
    let items = match v {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(a)) => a,
        Some(other) => return Err(format!("withdrawals must be a list, got {}", other)),
    };
    items
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let Value::Object(w) = w else {
                return Err(format!("withdrawal {} must be a map", i));
            };
            let token = w.get("token").or_else(|| w.get("tokenAddress")).and_then(Value::as_str).unwrap_or(ZERO_ADDRESS);
            let to = w
                .get("to")
                .or_else(|| w.get("destinationAddress"))
                .and_then(Value::as_str)
                .ok_or_else(|| format!("withdrawal {}: missing \"to\"", i))?;
            let amount = w.get("amount").ok_or_else(|| format!("withdrawal {}: missing \"amount\"", i))?;
            let mut m = Map::new();
            m.insert("tokenAddress".into(), json!(normalize_address(token).map_err(|e| format!("withdrawal {}: token: {}", i, e))?));
            m.insert("destinationAddress".into(), json!(normalize_address(to).map_err(|e| format!("withdrawal {}: to: {}", i, e))?));
            m.insert("amount".into(), json!(u256_hex(amount).map_err(|e| format!("withdrawal {}: amount: {}", i, e))?));
            Ok(Value::Object(m))
        })
        .collect()
}

/// Los bytes de un campo `<name>` en la forma que la app eligió: `<name>_hex` (`0x…`, binario
/// exacto — lo que un trigger contract decodifica con `abi.decode`), `<name>_base64`, o `<name>`
/// (un texto va tal cual; un mapa/lista, como JSON compacto con el orden de claves del programa).
/// `None` si no está o es `nothing`.
fn bytes_field(out: &Map<String, Value>, name: &str) -> Result<Option<Vec<u8>>, String> {
    let hex_key = format!("{}_hex", name);
    if let Some(v) = out.get(&hex_key).filter(|v| !v.is_null()) {
        let s = v.as_str().ok_or_else(|| format!("{} must be a 0x… text, got {}", hex_key, v))?;
        return hex_bytes(s).map(Some).map_err(|e| format!("{}: {}", hex_key, e));
    }
    let b64_key = format!("{}_base64", name);
    if let Some(v) = out.get(&b64_key).filter(|v| !v.is_null()) {
        let s = v.as_str().ok_or_else(|| format!("{} must be a text, got {}", b64_key, v))?;
        return Ok(Some(synsema_wasm_web::base64_decode(s)));
    }
    Ok(out.get(name).filter(|v| !v.is_null()).map(state_bytes))
}

/// `eventSubType` es `[32]byte` en Go → array de 32 números. La app lo da como `0x` + 64 hex,
/// como una etiqueta ASCII corta (≤ 32 bytes, alineada a la izquierda y rellenada con ceros: la
/// convención `subtypeToBytes32` del starter kit para que un trigger contract la compare), o lo
/// omite (32 ceros; en los eventos por usuario el Executor lo reemplaza por el HMAC de la seed).
fn subtype_array(v: Option<&Value>) -> Result<Value, String> {
    let bytes: Vec<u8> = match v {
        None | Some(Value::Null) => vec![0u8; 32],
        Some(Value::String(s)) if s.trim_start().starts_with("0x") || s.trim_start().starts_with("0X") => {
            let b = hex_bytes(s)?;
            if b.len() != 32 {
                return Err(format!("expected 32 bytes (0x + 64 hex), got {}", b.len()));
            }
            b
        }
        Some(Value::String(label)) => {
            let raw = label.as_bytes();
            if raw.is_empty() || raw.len() > 32 {
                return Err(format!("a subtype label is 1–32 bytes (or 0x + 64 hex), got {} bytes", raw.len()));
            }
            let mut b = vec![0u8; 32];
            b[..raw.len()].copy_from_slice(raw);
            b
        }
        Some(other) => return Err(format!("expected a 0x… hex text or a short label, got {}", other)),
    };
    Ok(Value::Array(bytes.into_iter().map(|b| json!(b)).collect()))
}

// =========================================================
// direcciones, enteros de 256 bits, base64
// =========================================================

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// 20 bytes → `0x…` (vacío → `nothing`; la app de referencia trata sender nulo como error, acá
/// la task decide).
fn address_hex(bytes: &[u8]) -> Value {
    if bytes.is_empty() {
        return Value::Null;
    }
    let mut b = [0u8; 20];
    let n = bytes.len().min(20);
    b[20 - n..].copy_from_slice(&bytes[bytes.len() - n..]);
    json!(format!("0x{}", hex_lower(&b)))
}

/// Bytes crudos como `0x…` (vacío → `nothing`): la forma exacta de un payload binario.
fn hex_value(bytes: &[u8]) -> Value {
    if bytes.is_empty() {
        return Value::Null;
    }
    json!(format!("0x{}", hex_lower(bytes)))
}

fn normalize_address(s: &str) -> Result<String, String> {
    let b = hex_bytes(s)?;
    if b.len() != 20 {
        return Err(format!("an address is 20 bytes (0x + 40 hex), got {} bytes", b.len()));
    }
    Ok(format!("0x{}", hex_lower(&b)))
}

fn hex_lower(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

fn hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    let h = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).ok_or_else(|| format!("expected a 0x… hex text, got {:?}", t))?;
    // Un carácter multibyte haría que el corte por índices de abajo panique (= trap): error limpio.
    if !h.is_ascii() {
        return Err(format!("not hex: {:?}", h));
    }
    if h.len() % 2 != 0 {
        return Err("odd number of hex digits".to_string());
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|_| format!("not hex: {:?}", &h[i..i + 2])))
        .collect()
}

/// Un `Uint256` para Vela: `0x` + hex sin ceros a la izquierda (`0x0` para cero), como
/// `Uint256.ToHex()`. Acepta un entero JSON, un texto decimal o un texto `0x…`.
fn u256_hex(v: &Value) -> Result<String, String> {
    match v {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                return Ok(format!("0x{:x}", u));
            }
            if let Some(f) = n.as_f64() {
                if f >= 0.0 && f.fract() == 0.0 && f < 9007199254740992.0 {
                    return Ok(format!("0x{:x}", f as u64));
                }
            }
            Err(format!("{} is not a non-negative integer; pass big amounts as decimal text", n))
        }
        Value::String(s) => {
            let t = s.trim();
            if t.starts_with("0x") || t.starts_with("0X") {
                let b = hex_bytes(t)?;
                if b.len() > 32 {
                    return Err("exceeds 256 bits".to_string());
                }
                Ok(u256_hex_of_bytes(&b))
            } else if !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit()) {
                decimal_to_u256_hex(t)
            } else {
                Err(format!("expected a decimal or 0x… text, got {:?}", t))
            }
        }
        other => Err(format!("expected an integer or a decimal text, got {}", other)),
    }
}

/// Un `Uint256` hex ya normalizado (`0x12c`, sin ceros a la izquierda: puede tener una cantidad
/// impar de dígitos) → big-endian. Vacío si no es hex.
fn u256_hex_bytes(hex: &str) -> Vec<u8> {
    let t = hex.trim();
    let digits = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    let padded = if digits.len() % 2 == 1 { format!("0x0{}", digits) } else { format!("0x{}", digits) };
    hex_bytes(&padded).unwrap_or_default()
}

/// Big-endian → `0x…` normalizado.
fn u256_hex_of_bytes(bytes: &[u8]) -> String {
    let h = hex_lower(bytes);
    let trimmed = h.trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".to_string()
    } else {
        format!("0x{}", trimmed)
    }
}

/// Texto decimal → `0x…` (división larga en base 10, sin dependencias; ≤ 78 dígitos).
fn decimal_to_u256_hex(dec: &str) -> Result<String, String> {
    let mut digits: Vec<u8> = dec.trim_start_matches('0').bytes().map(|c| c - b'0').collect();
    if digits.is_empty() {
        return Ok("0x0".to_string());
    }
    if digits.len() > 78 {
        return Err("exceeds 256 bits".to_string());
    }
    let mut nibbles: Vec<u8> = Vec::new();
    while !digits.is_empty() {
        let mut rem: u32 = 0;
        let mut next: Vec<u8> = Vec::with_capacity(digits.len());
        for d in &digits {
            let cur = rem * 10 + u32::from(*d);
            let q = (cur / 16) as u8;
            rem = cur % 16;
            if !(next.is_empty() && q == 0) {
                next.push(q);
            }
        }
        nibbles.push(rem as u8);
        digits = next;
    }
    if nibbles.len() > 64 {
        return Err("exceeds 256 bits".to_string());
    }
    const H: &[u8; 16] = b"0123456789abcdef";
    let s: String = nibbles.iter().rev().map(|n| H[*n as usize] as char).collect();
    Ok(format!("0x{}", s))
}

/// big-endian → texto decimal exacto (multiplicación larga en base 10).
fn be_bytes_to_decimal(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];
    for b in bytes {
        let mut carry: u32 = u32::from(*b);
        for d in digits.iter_mut() {
            let cur = u32::from(*d) * 256 + carry;
            *d = (cur % 10) as u8;
            carry = cur / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    while digits.len() > 1 && *digits.last().unwrap() == 0 {
        digits.pop();
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

fn b64(bytes: &[u8]) -> String {
    synsema_wasm_web::base64_encode(bytes)
}

/// Un buffer de entrada como valor Synsema: JSON si parsea, texto si no, `nothing` si está vacío.
fn decode_json_or_text(bytes: &[u8]) -> Value {
    if bytes.is_empty() {
        return Value::Null;
    }
    match serde_json::from_slice::<Value>(bytes) {
        Ok(v) => v,
        Err(_) => Value::String(String::from_utf8_lossy(bytes).into_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `release` con la raíz que usa una task de entrada .
    fn rel(v: Value) -> Result<Value, Failure> {
        release(v, Sink::App).map(|(v, _)| v)
    }

    /// Lo que se imprimió al log del Executor desde acá (y lo vacía). El log está fuera del
    /// enclave: los tests de R2/B2 afirman sobre su contenido exacto.
    fn taken_log() -> String {
        LOG_CAPTURE.with(|c| {
            let lines = std::mem::take(&mut *c.borrow_mut());
            lines.join("\n")
        })
    }

    fn pad_event_data_ok(ev: &mut Map<String, Value>, bucket: usize) -> bool {
        pad_event_data(ev, bucket).unwrap()
    }

    #[test]
    fn numbers_round_trip() {
        assert_eq!(be_bytes_to_decimal(&[]), "0");
        assert_eq!(be_bytes_to_decimal(&[1, 0]), "256");
        assert_eq!(be_bytes_to_decimal(&[0xff; 32]), "115792089237316195423570985008687907853269984665640564039457584007913129639935");
        assert_eq!(decimal_to_u256_hex("0").unwrap(), "0x0");
        assert_eq!(decimal_to_u256_hex("256").unwrap(), "0x100");
        assert_eq!(decimal_to_u256_hex("1000000000000000000").unwrap(), "0xde0b6b3a7640000");
        assert_eq!(u256_hex(&json!("0x00ff")).unwrap(), "0xff");
        assert_eq!(u256_hex(&json!(5)).unwrap(), "0x5");
        assert!(u256_hex(&json!(1.5)).is_err());
        assert!(decimal_to_u256_hex(&"9".repeat(79)).is_err());
    }

    #[test]
    fn addresses_and_subtypes() {
        assert_eq!(normalize_address("0xABCDEFabcdef0123456789ABCDEFabcdef012345").unwrap(), "0xabcdefabcdef0123456789abcdefabcdef012345");
        assert!(normalize_address("0x1234").is_err());
        // Un carácter no ASCII en el hex es un error, nunca un panic (= trap en wasm).
        assert!(hex_bytes("0xñ1").is_err());
        assert!(hex_bytes("0xabcñ").is_err());
        assert_eq!(subtype_array(None).unwrap().as_array().unwrap().len(), 32);
        assert!(subtype_array(Some(&json!("0x01"))).is_err());
        // Etiqueta corta → bytes32 alineado a la izquierda (subtypeToBytes32 del starter kit).
        let label = subtype_array(Some(&json!("execute_requested"))).unwrap();
        let arr = label.as_array().unwrap();
        assert_eq!(arr.len(), 32);
        assert_eq!(arr[0], json!(b'e'));
        assert_eq!(arr[16], json!(b'd'));
        assert_eq!(arr[17], json!(0));
        assert!(subtype_array(Some(&json!(""))).is_err());
        assert!(subtype_array(Some(&json!("a".repeat(33)))).is_err());
        assert_eq!(subtype_array(Some(&json!("a".repeat(32)))).unwrap().as_array().unwrap()[31], json!(b'a'));
    }

    #[test]
    fn bytes_fields_take_hex_base64_or_value() {
        let mut m = Map::new();
        m.insert("data".into(), json!({"a": 1}));
        assert_eq!(bytes_field(&m, "data").unwrap().unwrap(), br#"{"a":1}"#.to_vec());
        m.insert("data".into(), json!("plain"));
        assert_eq!(bytes_field(&m, "data").unwrap().unwrap(), b"plain".to_vec());
        m.insert("data_hex".into(), json!("0x00ff"));
        assert_eq!(bytes_field(&m, "data").unwrap().unwrap(), vec![0, 255]);
        m.insert("data_hex".into(), json!("0xzz"));
        assert!(bytes_field(&m, "data").is_err());
        m.remove("data_hex");
        m.insert("data_base64".into(), json!("aGk="));
        assert_eq!(bytes_field(&m, "data").unwrap().unwrap(), b"hi".to_vec());
        let mut none = Map::new();
        none.insert("state".into(), Value::Null);
        assert_eq!(bytes_field(&none, "state").unwrap(), None);
        assert_eq!(bytes_field(&none, "report").unwrap(), None);
    }

    #[test]
    fn task_detection_and_escaping() {
        assert!(defines_task("task deploy(ctx)\n    give 1\n", "deploy"));
        assert!(defines_task("export task process (ctx)\n", "process"));
        assert!(!defines_task("task deployment(ctx)\n", "deploy"));
        assert!(!defines_task("-- task deploy(ctx)\n", "deploy"));
        assert_eq!(syn_escape(r#"{"a":"x\"y\\z"}"#), r#"{\"a\":\"x\\\"y\\\\z\"}"#);
    }

    // ---- T1/salidas públicas seguras, con programas inline ----

    const ALICE: &str = "0x1111111111111111111111111111111111111111";
    const BOB: &str = "0x2222222222222222222222222222222222222222";

    fn addr(hex: &str) -> Vec<u8> {
        hex_bytes(hex).unwrap()
    }

    fn state_of(v: &Value) -> Value {
        serde_json::from_slice(&synsema_wasm_web::base64_decode(v.get("state").unwrap().as_str().unwrap())).unwrap()
    }

    fn state_bytes_of(v: &Value) -> Vec<u8> {
        synsema_wasm_web::base64_decode(v.get("state").unwrap().as_str().unwrap())
    }

    /// Lo que la APP ve del estado: sin `_vela` (ni política, ni contador, ni relleno).
    fn app_part(raw: &[u8]) -> Value {
        strip_policy(decode_json_or_text(raw))
    }

    /// El contador anti-repetición que lleva ese estado.
    fn counter_of(raw: &[u8]) -> u64 {
        decode_json_or_text(raw)[POLICY_KEY][STATE_COUNTER_KEY].as_u64().unwrap_or(0)
    }

    fn event_data(ev: &Value) -> Vec<u8> {
        synsema_wasm_web::base64_decode(ev.get("data").unwrap().as_str().unwrap())
    }

    /// Un libro mínimo: `deploy` acepta `params.policy`; `process` tiene una rama por caso.
    const LEDGER: &str = r#"
let FUEL be "5"

task deploy(ctx)
    let r be {"state": {"balances": {}, "nonce": 0}, "fuel": FUEL}
    when ctx["params"] != nothing and contains(ctx["params"], "policy")
        set r["policy"] to ctx["params"]["policy"]
    give r

task deposit(ctx)
    let s be ctx["state"]
    set s["nonce"] to s["nonce"] + 1
    give {"state": s, "events": [{"user": ctx["sender"], "data": {"type": "deposit", "amount": ctx["value"]}}], "fuel": 80}

task process(ctx)
    let p be ctx["payload"]
    let kind be declassify(text(p["type"]), "the instruction kind is public")
    match kind
        is "code"
            give {"error": "insufficient_balance", "error_detail": "have 0, need 10"}
        is "free"
            give {"error": "Insufficient balance 0 for transfer 10"}
        is "boom"
            raise("index 7 out of range")
        is "ok"
            let s be ctx["state"]
            set s["nonce"] to s["nonce"] + 1
            give {"state": s, "events": [{"user": ctx["sender"], "data": {"type": "ok", "seen": keys(ctx["state"])}}], "fuel": "20"}
        is "hex"
            give {"state": ctx["state"], "events": [{"user": ctx["sender"], "data_hex": "0x0102"}]}
        otherwise
            give {"error": "unknown_type", "error_detail": text(p["type"])}

task deanonymize(ctx)
    give {"report": {"keys": keys(ctx["state"])}}
"#;

    fn deployed(app: &App, policy: Option<&str>) -> Vec<u8> {
        let params = match policy {
            Some(p) => format!(r#"{{"policy": {}}}"#, p),
            None => String::new(),
        };
        let r = deploy_flow(app, 1, params.as_bytes());
        assert!(r.get("error").is_none(), "deploy failed: {}", r);
        synsema_wasm_web::base64_decode(r["state"].as_str().unwrap())
    }

    fn process(app: &App, sender: &str, payload: &str, state: &[u8]) -> Value {
        process_flow(app, 1, &addr(sender), REQUEST_PROCESS, payload.as_bytes(), state)
    }

    #[test]
    fn error_codes_pass_free_text_becomes_app_error_and_raise_is_runtime_error() {
        let app = App::inline(LEDGER);
        let s0 = deployed(&app, None);
        let coded = process(&app, ALICE, r#"{"type": "code"}"#, &s0);
        assert_eq!(coded["error"], json!("insufficient_balance"), "{}", coded);
        assert_eq!(coded["state"], Value::Null);
        let free = process(&app, ALICE, r#"{"type": "free"}"#, &s0);
        assert_eq!(free["error"], json!("app_error"), "{}", free);
        let boom = process(&app, ALICE, r#"{"type": "boom"}"#, &s0);
        assert_eq!(boom["error"], json!("runtime_error"), "{}", boom);
        // Un contrato roto del adaptador (report en un PROCESS no falla; un tipo 2 sin report sí).
        let no_task = process_flow(&App::inline("task deploy(ctx)\n    give {\"state\": {}}\n"), 1, &addr(ALICE), REQUEST_PROCESS, b"{}", b"{}");
        assert_eq!(no_task["error"], json!("runtime_error"));
        // El texto libre nunca llega a la respuesta.
        for r in [&coded, &free, &boom] {
            assert!(!r.to_string().contains("Insufficient") && !r.to_string().contains("out of range"), "{}", r);
        }
    }

    #[test]
    fn app_failure_classification() {
        let mut m = Map::new();
        m.insert("error".into(), json!("unknown_auction"));
        assert!(matches!(app_failure(&m, false), Some(Failure::App { code, detail: None, .. }) if code == "unknown_auction"));
        m.insert("error_detail".into(), json!("id 9"));
        assert!(matches!(app_failure(&m, false), Some(Failure::App { code, detail: Some(d), .. }) if code == "unknown_auction" && d == "id 9"));
        m.insert("error".into(), json!("Unknown auction 9"));
        assert!(matches!(app_failure(&m, false), Some(Failure::App { code, detail: Some(d), .. }) if code == "app_error" && d == "Unknown auction 9 (id 9)"));
        m.insert("error".into(), json!(""));
        assert!(app_failure(&m, false).is_none());
        assert!(is_error_code("a_1") && !is_error_code("A") && !is_error_code("") && !is_error_code(&"a".repeat(33)) && !is_error_code("has space"));
    }

    #[test]
    fn private_rejection_is_a_success_with_an_event_to_the_sender_and_the_state_intact() {
        let app = App::inline(LEDGER);
        let s0 = deployed(&app, Some(r#"{"reject": "private"}"#));
        let r = process(&app, ALICE, r#"{"type": "code"}"#, &s0);
        assert!(r.get("error").is_none(), "{}", r);
        // Lo que la app ve queda intacto — la transición es la identidad sobre SU estado …
        let out = state_bytes_of(&r);
        assert_eq!(app_part(&out), app_part(&s0), "the app-visible state is untouched");
        // … y lo que la CADENA ve cambia igual (auditoría ronda 4/V3): el contador sube, así que
        // el root nunca se queda quieto, y el tamaño es el mismo bucket que el de un éxito.
        assert_ne!(out, s0, "the root has to move: 'the state came back identical' was the bit");
        assert_eq!(counter_of(&out), counter_of(&s0) + 1);
        assert_eq!(out.len() % DEFAULT_STATE_PAD, 0, "padded to the bucket: {}", out.len());
        assert_eq!(r["withdrawals"], json!([]));
        assert_eq!(r["appEvents"], json!([]));
        let events = r["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["userId"], json!(ALICE));
        let data: Value = serde_json::from_slice(&event_data(&events[0])).unwrap();
        assert_eq!(data, json!({"rejected": "insufficient_balance", "detail": "have 0, need 10"}));
        // Texto libre: el evento lleva `app_error` y el texto como detalle (cifrado al sender).
        let free = process(&app, ALICE, r#"{"type": "free"}"#, &s0);
        let data: Value = serde_json::from_slice(&event_data(&free["events"][0])).unwrap();
        assert_eq!(data["rejected"], json!("app_error"));
        // Un error de runtime NO se convierte: sigue siendo público.
        let boom = process(&app, ALICE, r#"{"type": "boom"}"#, &s0);
        assert_eq!(boom["error"], json!("runtime_error"));
        // Ni un depósito fallido, ni una deanonimización, ni una trusted.
        let bad_deposit = deposit_flow(&App::inline("task deploy(ctx)\n    give {\"state\": {}, \"policy\": {\"reject\": \"private\"}}\ntask deposit(ctx)\n    give {\"error\": \"token_not_allowed\"}\n"), 1, &addr(ALICE), &[0u8; 20], &[5], br#"{"_vela":{"reject":"private"}}"#);
        assert_eq!(bad_deposit["error"], json!("token_not_allowed"));
        let trusted = trusted_flow(&App::inline("task process(ctx)\n    give {\"error\": \"nope\"}\n"), 1, b"", br#"{"_vela":{"reject":"private"}}"#);
        assert_eq!(trusted["error"], json!("nope"));
    }

    #[test]
    fn fuel_is_uniform_per_app_and_never_the_steps() {
        // Dos ramas con literales distintos (5, 80, "20") → siempre el máximo, en toda respuesta.
        assert_eq!(max_fuel_literal(LEDGER), Some(80));
        let app = App::inline(LEDGER);
        let dep = deploy_flow(&app, 1, b"");
        assert_eq!(dep["fuel"], json!("0x50"));
        let s0 = deployed(&app, None);
        let d = deposit_flow(&app, 1, &addr(ALICE), &[0u8; 20], &[1], &s0);
        assert_eq!(d["fuel"], json!("0x50"), "{}", d);
        let ok = process(&app, ALICE, r#"{"type": "ok"}"#, &s0);
        assert_eq!(ok["fuel"], json!("0x50"));
        let err = process(&app, ALICE, r#"{"type": "free"}"#, &s0);
        assert_eq!(err["fuel"], json!("0x50"));
        let de = process_flow(&app, 1, &addr(ALICE), REQUEST_DEANONYMIZATION, b"{}", &s0);
        assert_eq!(de["fuel"], json!("0x50"), "{}", de);
        let lm = load_module_flow(&app, 1);
        assert_eq!(lm["fuel"], json!("0x50"));
        // Sin literal alguno: 50 (o SYNSEMA_VELA_FUEL al compilar). La política manda sobre todo.
        let bare = App::inline("task deploy(ctx)\n    give {\"state\": {}}\n");
        assert_eq!(bare.fuel_literal, None);
        let expected = BUILD_FUEL.and_then(|s| parse_fuel_value(&json!(s)).ok()).unwrap_or(DEFAULT_FUEL);
        assert_eq!(deploy_flow(&bare, 1, b"")["fuel"], json!(format!("0x{:x}", expected)));
        let with_policy = App::inline("task deploy(ctx)\n    give {\"state\": {}, \"policy\": {\"fuel\": \"1000\"}}\ntask process(ctx)\n    give {\"state\": ctx[\"state\"]}\n");
        let dep = deploy_flow(&with_policy, 1, b"");
        assert_eq!(dep["fuel"], json!("0x3e8"));
        let st = synsema_wasm_web::base64_decode(dep["state"].as_str().unwrap());
        assert_eq!(process(&with_policy, ALICE, "{}", &st)["fuel"], json!("0x3e8"));
        // `let FUEL be "N"` también cuenta como literal.
        assert_eq!(max_fuel_literal("let FUEL be \"35\"\ntask deploy(ctx)\n    give {\"state\": {}, \"fuel\": FUEL}\n"), Some(35));
        assert_eq!(max_fuel_literal("let FUEL be 7\n"), Some(7));
        assert_eq!(max_fuel_literal("assert_eq(r[\"fuel\"], \"5\")\n"), None);
    }

    #[test]
    fn events_are_padded_to_the_bucket_and_filled_to_the_minimum() {
        let app = App::inline(LEDGER);
        let s0 = deployed(&app, Some(r#"{"events_pad": 64, "events_min": 3}"#));
        let ok = process(&app, ALICE, r#"{"type": "ok"}"#, &s0);
        assert!(ok.get("error").is_none(), "{}", ok);
        let events = ok["events"].as_array().unwrap();
        assert_eq!(events.len(), 3, "{}", ok);
        for ev in events {
            let data = event_data(ev);
            assert_eq!(data.len() % 64, 0, "{} bytes: {}", data.len(), String::from_utf8_lossy(&data));
            assert_eq!(ev["userId"], json!(ALICE));
        }
        let first: Value = serde_json::from_slice(&event_data(&events[0])).unwrap();
        assert_eq!(first["type"], json!("ok"));
        assert!(first["_"].as_str().unwrap().trim().is_empty());
        let filler: Value = serde_json::from_slice(&event_data(&events[1])).unwrap();
        assert_eq!(filler["pad"], json!(true));
        assert!(filler["_"].as_str().unwrap().trim().is_empty());
        assert_eq!(filler.as_object().unwrap().len(), 2);
        // Determinista: la misma llamada da los mismos bytes.
        assert_eq!(process(&app, ALICE, r#"{"type": "ok"}"#, &s0).to_string(), ok.to_string());
        // `data_hex` no es un objeto: sin relleno, pero el mínimo se cumple igual.
        let hex = process(&app, ALICE, r#"{"type": "hex"}"#, &s0);
        let events = hex["events"].as_array().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(event_data(&events[0]), vec![1, 2]);
        // Sin sender (trusted) no hay a quién rellenar: la lista queda como la app la dio.
        let tr = trusted_flow(&App::inline("task trusted(ctx)\n    give {\"state\": ctx[\"state\"]}\n"), 1, b"", br#"{"a":1,"_vela":{"events_min":2}}"#);
        assert_eq!(tr["events"], json!([]), "{}", tr);
        // La unidad: `{"a":1,"_":""}` mide 14 → bucket 16 → 2 espacios.
        let mut ev = Map::new();
        ev.insert("data".into(), json!({"a": 1}));
        assert!(pad_event_data_ok(&mut ev, 16));
        assert_eq!(ev["data"].to_string(), r#"{"a":1,"_":"  "}"#);
        assert_eq!(ev["data"].to_string().len(), 16);
        // Ya en el bucket (16) → el siguiente múltiplo que contiene la clave `_` (32).
        let mut ev = Map::new();
        ev.insert("data".into(), json!({"ab": 123456789}));
        assert_eq!(ev["data"].to_string().len(), 16);
        assert!(pad_event_data_ok(&mut ev, 16));
        assert_eq!(ev["data"].to_string().len(), 32);
        assert_eq!(be_bytes_to_decimal(&u256_hex_bytes("0x12c")), "300");
        assert_eq!(be_bytes_to_decimal(&u256_hex_bytes("0x0")), "0");
    }

    #[test]
    fn policy_lives_under_vela_in_the_state_and_the_app_never_sees_it() {
        let app = App::inline(LEDGER);
        let s0 = deployed(&app, Some(r#"{"reject": "private", "events_pad": 256, "events_min": 2}"#));
        let v: Value = serde_json::from_slice(&s0).unwrap();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["balances", "nonce", "_vela"], "the policy is the last key");
        // `_vela` lleva la política tal cual la declaró la app, más lo que pone el adaptador: el
        // contador anti-repetición (`n`, porque `reject: private`) y el relleno (`_`).
        let vela = v["_vela"].as_object().unwrap();
        assert_eq!(vela["reject"], json!("private"));
        assert_eq!(vela["events_pad"], json!(256));
        assert_eq!(vela["events_min"], json!(2));
        assert_eq!(vela["n"], json!(0), "el contador arranca en 0 en el deploy");
        assert!(vela["_"].as_str().unwrap().bytes().all(|b| b == b' '), "el relleno son espacios");
        assert_eq!(s0.len() % DEFAULT_STATE_PAD, 0, "{} bytes", s0.len());
        // La app ve el estado sin `_vela` …
        let ok = process(&app, ALICE, r#"{"type": "ok"}"#, &s0);
        let data: Value = serde_json::from_slice(&event_data(&ok["events"][0])).unwrap();
        assert_eq!(data["seen"], json!(["balances", "nonce"]));
        // … y el estado que devuelve la trae de vuelta, última.
        let s1 = state_of(&ok);
        assert_eq!(s1["nonce"], json!(1));
        assert_eq!(s1.as_object().unwrap().keys().last().unwrap(), "_vela");
        assert_eq!(s1["_vela"]["reject"], json!("private"), "la política declarada sobrevive");
        assert_eq!(s1["_vela"]["n"], json!(1), "y el contador subió");
        // Deanonymize: tampoco la ve; el estado se re-sella (no cambia lo que la app ve).
        let de = process_flow(&app, 1, &addr(ALICE), REQUEST_DEANONYMIZATION, b"{}", &s0);
        let report: Value = serde_json::from_slice(&synsema_wasm_web::base64_decode(de["report"].as_str().unwrap())).unwrap();
        assert_eq!(report["keys"], json!(["balances", "nonce"]));
        assert_eq!(app_part(&state_bytes_of(&de)), app_part(&s0));
        // Una `_vela` inválida en el estado es un error claro (runtime_error), no un pánico.
        let bad = process(&app, ALICE, r#"{"type": "ok"}"#, br#"{"balances":{},"nonce":0,"_vela":{"reject":"maybe"}}"#);
        assert_eq!(bad["error"], json!("runtime_error"), "{}", bad);
        let bad = process(&app, ALICE, r#"{"type": "ok"}"#, br#"{"balances":{},"nonce":0,"_vela":{"events_pad":0}}"#);
        assert_eq!(bad["error"], json!("runtime_error"));
        // Una política inválida en deploy también.
        let dep = deploy_flow(&app, 1, br#"{"policy": {"colour": "blue"}}"#);
        assert_eq!(dep["error"], json!("runtime_error"), "{}", dep);
        let dep = deploy_flow(&app, 1, br#"{"policy": {"reject": "private", "fuel": 1.5}}"#);
        assert_eq!(dep["error"], json!("runtime_error"));
        // Una política vacía o toda por default no deja rastro.
        let plain = deployed(&app, Some(r#"{"reject": "public"}"#));
        assert!(!String::from_utf8_lossy(&plain).contains("_vela"));
        assert_eq!(Policy::parse(&json!({"fuel": "0x50", "events_min": "2"})).unwrap(), Policy { fuel: Some(80), events_min: Some(2), ..Policy::default() });
        assert!(Policy::parse(&json!([])).is_err());
    }

    #[test]
    fn invariants_run_after_each_transition_and_fail_the_request() {
        let broken = format!("{}\ntask invariants(ctx)\n    give [\"conservation broken\"]\n", LEDGER);
        let app = App::inline(&broken);
        // También tras deploy (before = nothing).
        let dep = deploy_flow(&app, 1, b"");
        assert_eq!(dep["error"], json!("invariant_violation"), "{}", dep);
        // Un estado a mano para seguir: process y deposit fallan; deanonymize no corre invariants.
        let s0 = br#"{"balances":{},"nonce":0}"#;
        let ok = process(&app, ALICE, r#"{"type": "ok"}"#, s0);
        assert_eq!(ok["error"], json!("invariant_violation"));
        assert_eq!(ok["state"], Value::Null, "state intact (not applied)");
        let d = deposit_flow(&app, 1, &addr(ALICE), &[0u8; 20], &[1], s0);
        assert_eq!(d["error"], json!("invariant_violation"));
        let de = process_flow(&app, 1, &addr(ALICE), REQUEST_DEANONYMIZATION, b"{}", s0);
        assert!(de.get("error").is_none(), "{}", de);
        // Un fallo de la app no llega a invariants (ya falló), y con un código propio.
        assert_eq!(process(&app, ALICE, r#"{"type": "code"}"#, s0)["error"], json!("insufficient_balance"));
        // Una lista vacía o `nothing`: OK. Lanzar: violación.
        let fine = format!("{}\ntask invariants(ctx)\n    give []\n", LEDGER);
        assert!(process(&App::inline(&fine), ALICE, r#"{"type": "ok"}"#, s0).get("error").is_none());
        let none = format!("{}\ntask invariants(ctx)\n    give nothing\n", LEDGER);
        assert!(process(&App::inline(&none), ALICE, r#"{"type": "ok"}"#, s0).get("error").is_none());
        let raises = format!("{}\ntask invariants(ctx)\n    raise(\"no\")\n", LEDGER);
        assert_eq!(process(&App::inline(&raises), ALICE, r#"{"type": "ok"}"#, s0)["error"], json!("invariant_violation"));
    }

    #[test]
    fn invariants_see_the_transition_without_the_policy() {
        // La task devuelve lo que vio: kind, claves de before/after, deposit y withdrawals normalizadas.
        let spy = r#"
task deploy(ctx)
    give {"state": {"n": 0}, "policy": {"events_min": 1}}

task deposit(ctx)
    give {"state": {"n": 1}, "events": [{"user": ctx["sender"], "data": {"t": "d"}}]}

task process(ctx)
    give {"state": {"n": 2}, "withdrawals": [{"to": ctx["sender"], "amount": "300"}], "events": [{"user": ctx["sender"], "data": {"t": "p"}}]}

task invariants(ctx)
    let seen be private({"kind": ctx["kind"], "before": ctx["before"], "after": ctx["after"], "withdrawals": ctx["withdrawals"], "events": length(ctx["events"])}, "app")
    when contains(ctx, "deposit")
        set seen["deposit"] to ctx["deposit"]
    give [json_encode(seen)]
"#;
        let app = App::inline(spy);
        // Deploy: before nothing, after sin `_vela`.
        let dep = deploy_flow(&app, 1, b"");
        assert_eq!(dep["error"], json!("invariant_violation"));
        // Para leer lo que vio, se corre `invariants` directo con el mismo ctx que arma el adaptador.
        let s0 = br#"{"n":0,"_vela":{"events_min":1}}"#;
        let d = deposit_flow(&app, 1, &addr(ALICE), &addr(BOB), &[0x01, 0x00], s0);
        assert_eq!(d["error"], json!("invariant_violation"));
        let ictx = invariants_ctx(
            "deposit",
            strip_policy(decode_json_or_text(s0)),
            json!({"n": 1}),
            Some(json!({"token": BOB, "value": "256", "value_hex": "0x100"})),
            Vec::new(),
            json!([{"user": ALICE, "data": {"t": "d"}}]),
        );
        let run = run_app_with(&app, "invariants", None, &ictx, Sink::Public);
        let seen: Value = serde_json::from_str(run.result.unwrap()[0].as_str().unwrap()).unwrap();
        assert_eq!(seen["kind"], json!("deposit"));
        assert_eq!(seen["before"], json!({"n": 0}), "before without _vela");
        assert_eq!(seen["deposit"]["value"], json!("256"));
        assert_eq!(seen["events"], json!(1));
        // Withdrawals normalizadas: {token, to, amount decimal, amount_hex}.
        let w = withdrawals_of(Some(&json!([{"to": ALICE, "amount": "300"}]))).unwrap();
        assert_eq!(normalized_withdrawals(&w), json!([{"token": ZERO_ADDRESS, "to": ALICE, "amount": "300", "amount_hex": "0x12c"}]).as_array().unwrap().clone());
    }

    // ---- fuentes {app} y sumideros por campo ----

    /// Un libro que, a propósito, deja escapar valores privados por sumideros públicos en unas
    /// ramas y los declassifica en otras.
    const LEAKY: &str = r#"
task deploy(ctx)
    give {"state": {"balances": {}, "secret_total": 42}}

task process(ctx)
    let p be ctx["payload"]
    let s be ctx["state"]
    let kind be declassify(text(p["type"]), "the instruction kind is public")
    match kind
        is "leak"
            give {"state": s, "app_events": [{"subtype": "total", "data": {"total": s["secret_total"]}}]}
        is "declassified"
            give {"state": s, "app_events": [declassify({"subtype": "total", "data": {"total": s["secret_total"]}}, "the total is public by policy")]}
        is "withdraw_leak"
            give {"state": s, "withdrawals": [{"to": p["to"], "amount": "1"}]}
        is "withdraw"
            give {"state": s, "withdrawals": [declassify({"to": p["to"], "amount": "1"}, "settlement is public")]}
        is "computed_code"
            give {"error": "unknown_" + text(p["what"])}
        is "credit"
            let b be s["balances"]
            set b[p["to"]] to "5"
            set s["balances"] to b
            print(s)
            give {"state": s, "events": [{"user": p["to"], "data": {"balance": b[p["to"]]}}]}
        otherwise
            give {"error": "unknown_type", "error_detail": "type " + text(p["type"])}
"#;

    #[test]
    fn private_values_reach_public_sinks_only_through_declassify() {
        let app = App::inline(LEAKY);
        let s0 = deployed(&app, None);
        // Un valor del estado (privado) en un app event público: label_violation, estado no aplicado.
        let leak = process(&app, ALICE, r#"{"type": "leak"}"#, &s0);
        assert_eq!(leak["error"], json!("label_violation"), "{}", leak);
        assert_eq!(leak["state"], Value::Null);
        assert!(!leak.to_string().contains("42"));
        // El mismo valor declassificado con motivo: sale.
        let ok = process(&app, ALICE, r#"{"type": "declassified"}"#, &s0);
        assert!(ok.get("error").is_none(), "{}", ok);
        let data: Value = serde_json::from_slice(&event_data(&ok["appEvents"][0])).unwrap();
        assert_eq!(data["total"], json!(42));
        // El destinatario del payload (privado) en una withdrawal pública: violación; declassificado, pasa.
        let wl = process(&app, ALICE, &format!(r#"{{"type": "withdraw_leak", "to": "{}"}}"#, BOB), &s0);
        assert_eq!(wl["error"], json!("label_violation"), "{}", wl);
        let w = process(&app, ALICE, &format!(r#"{{"type": "withdraw", "to": "{}"}}"#, BOB), &s0);
        assert_eq!(w["withdrawals"][0]["destinationAddress"], json!(BOB), "{}", w);
        // Un código de error CALCULADO desde el payload delata el payload: violación. Un literal
        // dentro de una rama privada es el canal de terminación (se admite; T1 lo cubre).
        let cc = process(&app, ALICE, r#"{"type": "computed_code", "what": "x"}"#, &s0);
        assert_eq!(cc["error"], json!("label_violation"), "{}", cc);
        let lit = process(&app, ALICE, r#"{"type": "zzz"}"#, &s0);
        assert_eq!(lit["error"], json!("unknown_type"), "{}", lit);
        // Escribir en el estado con una clave que viene del payload (privada) es lo normal de un
        // ledger: procede; el evento al usuario (sumidero {app}) también.
        let credit = process(&app, ALICE, &format!(r#"{{"type": "credit", "to": "{}"}}"#, BOB), &s0);
        assert!(credit.get("error").is_none(), "{}", credit);
        assert_eq!(state_of(&credit)["balances"][BOB], json!("5"));
        assert_eq!(credit["events"][0]["userId"], json!(BOB));
        let data: Value = serde_json::from_slice(&event_data(&credit["events"][0])).unwrap();
        assert_eq!(data["balance"], json!("5"));
    }

    /// Auditoría R2/B2: la forma GRANULAR — sin `declassify` del mapa entero y sin declassificar
    /// El despacho (`match payload["type"]` a secas, con el payload privado).
    const GRANULAR: &str = r#"
let FUEL be "0x32"

task deploy(ctx)
    let r be {"state": {"balances": {"0x1111111111111111111111111111111111111111": "1"}}, "fuel": FUEL}
    when ctx["params"] != nothing and contains(ctx["params"], "policy")
        set r["policy"] to ctx["params"]["policy"]
    give r

task process(ctx)
    let p be ctx["payload"]
    let s be ctx["state"]
    match p["type"]
        is "withdraw"
            let balance be decimal(s["balances"][ctx["sender"]])
            let amount be decimal(p["amount"])
            when balance < amount
                give {"error": declassify("insufficient_balance", "the outcome code is public on-chain"),
                      "error_detail": "withdrawal: have " + text(balance) + ", need " + text(amount),
                      "fuel": FUEL}
            set s["balances"][ctx["sender"]] to text(balance - amount)
            give {"state": s,
                  "events": [{"user": ctx["sender"], "data": {"type": "withdrawal", "balance": text(balance - amount)}}],
                  "withdrawals": [declassify({"to": p["to"], "amount": text(amount)}, "a pull-payment is settled on-chain: payee and amount are public")],
                  "fuel": FUEL}
        otherwise
            give {"error": declassify("unknown_type", "the outcome code is public on-chain"), "error_detail": "type " + text(p["type"]), "fuel": FUEL}
"#;

    #[test]
    fn the_granular_form_compiles_and_the_balance_never_reaches_the_log() {
        let app = App::inline(GRANULAR);
        let s0 = deployed(&app, None);
        taken_log();
        // 1. El rechazo: on-chain sale el CÓDIGO; el saldo y el monto NO están en la respuesta…
        let over = process(&app, ALICE, &format!(r#"{{"type": "withdraw", "to": "{}", "amount": "999999"}}"#, BOB), &s0);
        assert_eq!(over["error"], json!("insufficient_balance"), "la forma granular compila: {}", over);
        assert_eq!(over["state"], Value::Null);
        // …ni en el log del Executor (que bajo Nitro está fuera del enclave): éste es el texto
        // exacto que antes salía en claro ("have 1, need 999999").
        let logged = taken_log();
        assert!(logged.contains("WRN app error insufficient_balance: (private)"), "{}", logged);
        assert!(!logged.contains("999999") && !logged.contains("have 1"), "el saldo/monto no puede estar en el log:\n{}", logged);
        // 2. El camino feliz: el estado y el evento (sumidero {app}) llevan el saldo sin ceremonia,
        // Y la withdrawal declassificada —que SÍ se liquida on-chain— sale.
        let ok = process(&app, ALICE, &format!(r#"{{"type": "withdraw", "to": "{}", "amount": "1"}}"#, BOB), &s0);
        assert!(ok.get("error").is_none(), "{}", ok);
        assert_eq!(state_of(&ok)["balances"][ALICE], json!("0"));
        assert_eq!(ok["withdrawals"][0]["destinationAddress"], json!(BOB));
        assert_eq!(ok["withdrawals"][0]["amount"], json!("0x1"));
        let data: Value = serde_json::from_slice(&event_data(&ok["events"][0])).unwrap();
        assert_eq!(data["balance"], json!("0"));
        // 3. El despacho NO se declassifica y aun así el `otherwise` sale con su código.
        let unknown = process(&app, ALICE, r#"{"type": "mint"}"#, &s0);
        assert_eq!(unknown["error"], json!("unknown_type"), "{}", unknown);
        // 4. `fuel` viene de una constante pública bajo rama privada: se publica sin declassify,
        // Y el literal hex del fuente se lee (M4: antes `"0x32"` daba fee 0).
        assert_eq!(unknown["fuel"], json!("0x32"));
        assert_eq!(app.fuel_literal, Some(50));
    }

    #[test]
    fn under_reject_private_the_sender_still_gets_the_text_the_log_does_not() {
        let app = App::inline(GRANULAR);
        let s0 = deployed(&app, Some(r#"{"reject": "private"}"#));
        taken_log();
        let rej = process(&app, ALICE, &format!(r#"{{"type": "withdraw", "to": "{}", "amount": "999999"}}"#, BOB), &s0);
        // On-chain: un éxito sin rastro, con el estado de la app intacto y el `_vela` renovado.
        assert!(rej.get("error").is_none(), "{}", rej);
        let out = state_bytes_of(&rej);
        assert_eq!(app_part(&out), app_part(&s0));
        assert_eq!(counter_of(&out), counter_of(&s0) + 1);
        // Al sender, cifrado: el motivo COMPLETO (ese sumidero acepta {app}).
        let data: Value = serde_json::from_slice(&event_data(&rej["events"][0])).unwrap();
        assert_eq!(data["rejected"], json!("insufficient_balance"));
        assert_eq!(data["detail"], json!("withdrawal: have 1, need 999999"));
        // Al log del operador: nada del monto. Éste es el oráculo de replay del dark pool — el
        // Executor elige el `state`, así que reejecutar una puja contra saldo 0 fuerza el rechazo;
        // Lo que el operador ve ya no incluye la puja sellada.
        let logged = taken_log();
        assert!(!logged.contains("999999"), "la puja sellada no puede estar en el log:\n{}", logged);
        // Auditoría R3/B2: tampoco el CÓDIGO, ni la línea "rechazada en privado", ni nada que
        // separe este rechazo de un éxito. Bajo `reject: private` la request sale on-chain como un
        // éxito, así que el log era la única señal que quedaba.
        assert!(!logged.contains("insufficient_balance"), "el código de error no puede salir al log:\n{}", logged);
        assert!(!logged.contains("rejected"), "ni siquiera 'rejected privately':\n{}", logged);
    }

    /// Auditoría R3/B2: la sonda del auditor. El Executor elige el `state`, así que reejecutar la
    /// MISMA puja sellada contra saldos distintos es una búsqueda binaria sobre el monto… si el
    /// log dice algo distinto cuando pasa y cuando no. Acá se corren 50 reejecuciones (la misma
    /// cuenta que el informe) y se exige que el log sea **idéntico** en las 50.
    #[test]
    fn fifty_replays_against_different_balances_leave_the_same_log() {
        let app = App::inline(GRANULAR);
        let sealed = format!(r#"{{"type": "withdraw", "to": "{}", "amount": "8675309"}}"#, BOB);
        let mut logs: Vec<String> = Vec::new();
        let mut outcomes: Vec<bool> = Vec::new();
        for i in 0..50u64 {
            // El atacante elige el saldo: por debajo del monto en las primeras, por encima después.
            let balance = if i < 25 { i * 100_000 } else { 8_000_000 + i * 100_000 };
            let state = format!(r#"{{"balances":{{"{}":"{}"}},"_vela":{{"reject":"private"}}}}"#, ALICE, balance);
            taken_log();
            let r = process(&app, ALICE, &sealed, state.as_bytes());
            assert!(r.get("error").is_none(), "replay {}: on-chain debe verse como un éxito: {}", i, r);
            outcomes.push(balance >= 8_675_309);
            logs.push(taken_log());
        }
        // Las 50 corridas cubren los dos resultados reales…
        assert!(outcomes.contains(&true) && outcomes.contains(&false), "la sonda tiene que ejercitar los dos casos");
        // …y el log no los distingue: una sola línea, la misma, 50 veces.
        let first = &logs[0];
        for (i, l) in logs.iter().enumerate() {
            assert_eq!(l, first, "replay {} (aceptada: {}) dejó un log distinto:\n{}\n---\n{}", i, outcomes[i], l, first);
        }
        assert_eq!(first.trim(), "INF fuel: reported 0x32", "el log de una request es una sola línea de costo: {:?}", first);
        assert!(!first.contains("8675309"), "{}", first);
    }

    /// Auditoría ronda 4 / V3: **la misma sonda, sin leer una sola línea de log**. El auditor
    /// recuperó el monto exacto de una puja sellada en 49 reejecuciones mirando sólo el estado
    /// que vuelve on-chain: el rechazado salía byte a byte igual al previo y el aceptado había
    /// crecido, así que el TAMAÑO —y de yapa "el root no se movió"— era un bit por request.
    /// Acá se corre la búsqueda entera y se exige que las dos señales estén cerradas.
    #[test]
    fn fifty_replays_do_not_separate_accepted_from_rejected_by_the_state_on_chain() {
        let app = App::inline(GRANULAR);
        let sealed = format!(r#"{{"type": "withdraw", "to": "{}", "amount": "8675309"}}"#, BOB);
        let mut sizes: Vec<usize> = Vec::new();
        let mut outcomes: Vec<bool> = Vec::new();
        for i in 0..50u64 {
            let balance = if i < 25 { i * 100_000 } else { 8_000_000 + i * 100_000 };
            let prev = format!(r#"{{"balances":{{"{}":"{}"}},"_vela":{{"reject":"private"}}}}"#, ALICE, balance);
            let r = process(&app, ALICE, &sealed, prev.as_bytes());
            assert!(r.get("error").is_none(), "replay {}: on-chain se ve como un éxito: {}", i, r);
            let out = state_bytes_of(&r);
            // 1) El root SIEMPRE se mueve: el contador sube se acepte o se rechace.
            assert_ne!(out, prev.as_bytes(), "replay {}: el estado no puede volver idéntico", i);
            assert_eq!(counter_of(&out), 1, "replay {}: el contador sube en toda transición", i);
            // 2) El tamaño cae en el mismo bucket en los dos casos.
            assert_eq!(out.len() % DEFAULT_STATE_PAD, 0, "replay {}: {} bytes", i, out.len());
            outcomes.push(balance >= 8_675_309);
            sizes.push(out.len());
        }
        assert!(outcomes.contains(&true) && outcomes.contains(&false), "la sonda ejercita los dos casos");
        // La medida que recuperaba la puja: un único tamaño para las 50, acepten o rechacen.
        let uniform = sizes.iter().all(|n| *n == sizes[0]);
        assert!(uniform, "el tamaño del estado separa aceptadas de rechazadas: {:?} vs {:?}", sizes, outcomes);
    }

    /// `state_pad: 0` apaga el relleno a mano — el modo deja de esconder el tamaño y se avisa UNA
    /// vez, como `events_min` sin `events_pad`. El contador sigue puesto (eso no es opcional).
    #[test]
    fn state_pad_zero_turns_the_padding_off_and_warns_once() {
        let app = App::inline(GRANULAR);
        STATE_PAD_WARNED.with(|c| c.set(false));
        taken_log();
        let s0 = deployed(&app, Some(r#"{"reject": "private", "state_pad": 0}"#));
        assert!(taken_log().contains("hides nothing on-chain"), "el aviso nombra lo que no se esconde");
        assert_ne!(s0.len() % DEFAULT_STATE_PAD, 0, "sin relleno el tamaño es el que salga");
        assert_eq!(counter_of(&s0), 0);
        // Y un bucket propio se respeta tal cual.
        let s1 = deployed(&App::inline(GRANULAR), Some(r#"{"reject": "private", "state_pad": 64}"#));
        assert_eq!(s1.len() % 64, 0, "{} bytes", s1.len());
        assert_eq!(Policy::parse(&json!({"state_pad": 64})).unwrap().state_bucket(), Some(64));
        assert_eq!(Policy::parse(&json!({"reject": "private"})).unwrap().state_bucket(), Some(DEFAULT_STATE_PAD));
        assert_eq!(Policy::default().state_bucket(), None, "sin `reject: private` no se rellena nada");
        assert!(Policy::parse(&json!({"state_pad": -1})).is_err());
    }

    /// Auditoría ronda 4 / V4: la CANTIDAD de líneas de log era un canal numérico. Las
    /// descripciones ya salían redactadas, pero `n` descripciones calculadas sobre el estado
    /// privado son `n` líneas que el operador cuenta.
    #[test]
    fn the_number_of_invariant_lines_is_not_a_channel() {
        // Un invariante que arma UNA descripción POR SALDO: el texto ya salía redactado, pero
        // la cuenta de líneas es `length(balances)` calculado sobre el estado privado. Tres
        // saldos = tres líneas, y con eso el operador cuenta lo que no puede leer.
        const LEAKY: &str = r#"
task deploy(ctx)
    give {"state": {"balances": {}}}

task process(ctx)
    give {"state": {"balances": {"a": 1, "b": 2, "c": 3}}}

task invariants(ctx)
    let out be []
    each k in keys(ctx["after"]["balances"])
        set out to append(out, "an account is off")
    give out
"#;
        let app = App::inline(LEAKY);
        let s0 = deployed(&app, None);
        taken_log();
        let r = process(&app, ALICE, r#"{"type": "x"}"#, &s0);
        assert_eq!(r["error"], json!("invariant_violation"), "{}", r);
        let logged = taken_log();
        let lines: Vec<&str> = logged.lines().filter(|l| l.contains("invariant_violation")).collect();
        assert_eq!(lines.len(), 1, "tres descripciones, UNA línea:
{}", logged);
        assert!(lines[0].ends_with("(private)"), "{}", lines[0]);
        // Sin privados de por medio la cuenta no dice nada de nadie: el diagnóstico va entero.
        const PUBLIC: &str = r#"
task deploy(ctx)
    give {"state": {}}

task invariants(ctx)
    give ["first thing", "second thing"]
"#;
        taken_log();
        let dep = deploy_flow(&App::inline(PUBLIC), 1, b"");
        assert_eq!(dep["error"], json!("invariant_violation"), "{}", dep);
        let logged = taken_log();
        assert!(logged.contains("first thing") && logged.contains("second thing"), "{}", logged);
    }

    /// Auditoría R3/M5 y M6: la cota del `value` del depósito y el aviso de `events_min` solo.
    #[test]
    fn a_huge_deposit_value_is_refused_before_it_is_decoded_and_events_min_warns_alone() {
        let app = App::inline(GRANULAR);
        let s0 = deployed(&app, None);
        // 32 bytes es un Uint256: pasa (el valor es 2^256-1).
        let ok = deposit_flow(&app, 1, &addr(ALICE), &[0u8; 20], &[0xffu8; 32], &s0);
        assert_eq!(ok["error"], json!("runtime_error"), "la app de prueba no define deposit: llega igual al programa");
        // 64 KB tardaban 9,4 s en convertirse a decimal ANTES de cualquier validación (cuadrático);
        // ~120 KB colgaban la request contra el timeout de 30 s. Ahora es O(1) y un error claro.
        let t0 = std::time::Instant::now();
        let big = deposit_flow(&app, 1, &addr(ALICE), &[0u8; 20], &vec![0xffu8; 64 * 1024], &s0);
        assert_eq!(big["error"], json!("runtime_error"), "{}", big);
        assert!(t0.elapsed().as_millis() < 500, "la cota tiene que cortar antes de decodificar: {} ms", t0.elapsed().as_millis());
        assert!(taken_log().contains("the value is 65536 bytes; a Uint256 is at most 32"), "el log dice qué pasó");
        // M6: `events_min` sin `events_pad` rellena la cuenta pero no los tamaños; se avisa una vez.
        MIN_WARNED.with(|c| c.set(false));
        let app2 = App::inline(LEDGER);
        let s = deployed(&app2, Some(r#"{"events_min": 3}"#));
        taken_log();
        let r = process(&app2, ALICE, r#"{"type": "ok"}"#, &s);
        assert_eq!(r["events"].as_array().unwrap().len(), 3);
        let logged = taken_log();
        assert!(logged.contains("events_min without events_pad hides little"), "{}", logged);
        // Una segunda request no repite el aviso.
        taken_log();
        process(&app2, ALICE, r#"{"type": "ok"}"#, &s);
        assert!(!taken_log().contains("events_min without"), "el aviso es una sola vez");
    }

    #[test]
    fn the_program_may_not_name_the_drivers_bindings() {
        // Auditoría R2/M6: un `let __vela_in` top-level sombreaba el ctx etiquetado.
        let shadow = App::inline("let __vela_in be {\"state\": {}, \"payload\": {}}\ntask process(ctx)\n    give {\"state\": {}}\n");
        let r = process_flow(&shadow, 1, &addr(ALICE), REQUEST_PROCESS, b"{}", b"{}");
        assert_eq!(r["error"], json!("runtime_error"), "{}", r);
        assert!(mentions_driver_name("let __vela_out be 1\n").is_some());
        assert_eq!(mentions_driver_name("-- __vela_in is the adapter's\ntask process(ctx)\n    give {}\n"), None);
    }

    #[test]
    fn the_fuel_scan_reads_hex_and_refuses_what_it_cannot_parse() {
        // M4: `"0x50"` valía 0 (fee 0 on-chain, en silencio) y `"3.5"` valía 3.
        assert_eq!(max_fuel_literal("let FUEL be \"0x50\"\n"), Some(80));
        assert_eq!(max_fuel_literal("task t(c)\n    give {\"fuel\": 0x10}\n"), Some(16));
        assert_eq!(max_fuel_literal("let FUEL be \"3.5\"\n"), None);
        assert_eq!(max_fuel_literal("let FUEL be \"abc\"\n"), None);
        assert_eq!(max_fuel_literal("let FUEL be -3\n"), None);
        assert_eq!(max_fuel_literal("let FUEL be \"50\"\ntask t(c)\n    give {\"fuel\": \"80\"}\n"), Some(80));
        assert_eq!(max_fuel_literal("-- let FUEL be \"999\"\nlet FUEL be \"50\"\n"), Some(50));
        // Lo que no parsea se avisa por el log y se ignora (nunca se aproxima).
        taken_log();
        assert_eq!(max_fuel_literal("let FUEL be \"3.5\"\n"), None);
        assert!(taken_log().contains("fuel: literal \"\\\"3.5\\\"\" is not a non-negative integer"), "avisa el literal roto");
    }

    #[test]
    fn release_applies_the_sink_table_and_strips_markers() {
        let private = |label: &[&str], v: Value| json!({"$private": label, "value": v});
        // Sumidero público con etiqueta → violación con el camino real.
        let r = rel(json!({"app_events": [{"subtype": "x", "data": private(&["app"], json!({"amount": 5}))}]}));
        match r {
            Err(Failure::Label { path, label, .. }) => {
                assert_eq!(path, "app_events[0].data");
                assert_eq!(label, vec!["app".to_string()]);
            }
            other => panic!("expected a label violation, got {:?}", other),
        }
        assert!(matches!(rel(json!({"withdrawals": [private(&["app"], json!({"to": "0x"}))]})), Err(Failure::Label { .. })));
        assert!(matches!(rel(json!({"error": private(&["app"], json!("code"))})), Err(Failure::Label { .. })));
        assert!(matches!(rel(json!({"events": [{"user": "0x", "subtype": private(&["app"], json!("s")), "data": {}}]})), Err(Failure::Label { .. })));
        // Sumidero {app}: acepta app, rechaza otro principal.
        let ok = rel(json!({"state": private(&["app"], json!({"balances": {"a": private(&["app"], json!("1"))}})), "events": [{"user": private(&["app"], json!("0xab")), "data": private(&["app"], json!({"k": 1}))}], "error_detail": private(&["app"], json!("have 0"))})).unwrap();
        assert_eq!(ok, json!({"state": {"balances": {"a": "1"}}, "events": [{"user": "0xab", "data": {"k": 1}}], "error_detail": "have 0"}));
        assert!(matches!(rel(json!({"state": private(&["bank"], json!({}))})), Err(Failure::Label { path, .. }) if path == "state"));
        // Auditoría R2/B2: la RAÍZ de una task de entrada es `Sink::App`. Un `give` bajo rama
        // privada etiqueta el mapa entero con {app} y eso está bien: son los sumideros POR CAMPO
        // los que mandan. Otro principal en la raíz sí es violación.
        let root = rel(private(&["app"], json!({"error": "insufficient_balance", "fuel": "5"}))).unwrap();
        assert_eq!(root, json!({"error": "insufficient_balance", "fuel": "5"}));
        assert!(matches!(rel(private(&["bank"], json!({}))), Err(Failure::Label { path, .. }) if path == "result"));
        // …y los campos publicados que SÍ siguen privados adentro del mapa etiquetado se rechazan:
        // El `declassify` del mapa entero (el que mandaba saldos al log) ya no compra nada.
        assert!(matches!(
            rel(private(&["app"], json!({"error": private(&["app"], json!("insufficient_balance"))}))),
            Err(Failure::Label { path, .. }) if path == "error"
        ));
        // La forma granular: el código declassificado (sin marcador) sale; el detalle privado
        // viaja y queda marcado para que el log lo redacte.
        let (v, info) = release(
            private(&["app"], json!({"error": "insufficient_balance", "error_detail": private(&["app"], json!("have 1, need 2"))})),
            Sink::App,
        )
        .unwrap();
        assert_eq!(v, json!({"error": "insufficient_balance", "error_detail": "have 1, need 2"}));
        assert!(info.detail_private);
        // La raíz de `invariants` es `Sink::Log`: TODO privado se redacta, la lista entera…
        assert_eq!(release(private(&["app"], json!(["broken"])), Sink::Log).unwrap().0, json!(["(private)"]));
        // …y también UNA descripción suelta (donde el saldo se colaba: el elemento no tiene sumidero).
        assert_eq!(
            release(json!([private(&["app"], json!("balance is 1234")), "public reason"]), Sink::Log).unwrap().0,
            json!(["(private)", "public reason"])
        );
        assert_eq!(release(json!(["broken"]), Sink::Log).unwrap().0, json!(["broken"]));
        assert!(matches!(release(private(&["bank"], json!([])), Sink::Log), Err(Failure::Label { .. })));
        // M12: una clave `$$bytes` del programa vuelve a `$bytes` y NO se interpreta.
        assert_eq!(rel(json!({"state": {"$$bytes": "aGk=", "$$private": ["x"]}})).unwrap(), json!({"state": {"$bytes": "aGk=", "$private": ["x"]}}));
        // El detalle privado se marca para el log.
        let (v, info) = release(json!({"error": "code", "error_detail": private(&["app"], json!("have 3"))}), Sink::Public).unwrap();
        assert_eq!(v["error_detail"], json!("have 3"));
        assert!(info.detail_private);
        // Bytes vuelven a la forma de json_encode (base64 en texto); claves desconocidas no se chequean.
        assert_eq!(rel(json!({"extra": private(&["app"], json!(1)), "blob": {"$bytes": "aGk="}})).unwrap(), json!({"extra": 1, "blob": "aGk="}));
        // Un objeto con más claves que el marcador no es marcador.
        assert_eq!(rel(json!({"app_events": [{"$private": ["app"], "value": 1, "x": 2}]})).unwrap(), json!({"app_events": [{"$private": ["app"], "value": 1, "x": 2}]}));
        assert_eq!(shown_path(&["events".into(), "[1]".into(), "data".into(), "amount".into()]), "events[1].data.amount");
    }

    // ---- Las tres apps de ejemplo REALES, con las etiquetas encendidas y las fuentes marcadas:
    // El ledger completo debe pasar por todos los sumideros sin `label_violation`. ----

    fn go(app: &App, kind: i32, sender: &str, payload: &str, state: &[u8]) -> Value {
        process_flow(app, 1, &addr(sender), kind, payload.as_bytes(), state)
    }

    fn state_b(v: &Value) -> Vec<u8> {
        synsema_wasm_web::base64_decode(v["state"].as_str().unwrap())
    }

    fn ok(v: &Value, what: &str) -> Value {
        assert!(v.get("error").is_none(), "{} failed: {}", what, v);
        v.clone()
    }

    #[test]
    fn example_app_ledger_runs_end_to_end_under_labels() {
        let app = App::inline(include_str!("../app.syn"));
        let s0 = deployed(&app, None);
        let d = ok(&deposit_flow(&app, 1, &addr(ALICE), &[0u8; 20], &[100], &s0), "deposit");
        let s1 = state_b(&d);
        let t = ok(&go(&app, REQUEST_PROCESS, ALICE, &format!(r#"{{"type": "transfer", "to": "{}", "amount": "30"}}"#, BOB), &s1), "transfer");
        assert_eq!(t["events"].as_array().unwrap().len(), 2);
        let s2 = state_b(&t);
        let w = ok(&go(&app, REQUEST_PROCESS, BOB, &format!(r#"{{"type": "withdraw", "to": "{}", "amount": "10"}}"#, BOB), &s2), "withdraw");
        assert_eq!(w["withdrawals"][0]["amount"], json!("0xa"));
        assert_eq!(w["appEvents"].as_array().unwrap().len(), 1);
        let s3 = state_b(&w);
        let bad = go(&app, REQUEST_PROCESS, BOB, &format!(r#"{{"type": "withdraw", "to": "{}", "amount": "999"}}"#, BOB), &s3);
        assert_eq!(bad["error"], json!("insufficient_balance"), "{}", bad);
        let unknown = go(&app, REQUEST_PROCESS, BOB, r#"{"type": "mint"}"#, &s3);
        assert_eq!(unknown["error"], json!("unknown_type"), "{}", unknown);
        let de = ok(&go(&app, REQUEST_DEANONYMIZATION, ALICE, "{}", &s3), "deanonymize");
        assert!(de.get("report").is_some());
        // Trusted: abi.encode(address, address, uint256) = 3 palabras
        let mut payload = vec![0u8; 96];
        payload[12..32].copy_from_slice(&addr(BOB));
        payload[95] = 7;
        let tr = ok(&trusted_flow(&app, 1, &payload, &s3), "trusted");
        assert_eq!(state_of(&tr)["balances"][BOB][ZERO_ADDRESS], json!("27"));
        let empty = trusted_flow(&app, 1, b"", &s3);
        assert_eq!(empty["error"], json!("missing_payload"), "{}", empty);
    }

    #[test]
    fn example_payment_app_runs_end_to_end_under_labels() {
        let app = App::inline(include_str!("../examples/payment_app.syn"));
        let s0 = deployed(&app, None);
        let d = ok(&deposit_flow(&app, 1, &addr(ALICE), &[0u8; 20], &[100], &s0), "deposit");
        let s1 = state_b(&d);
        let t = ok(&go(&app, REQUEST_PROCESS, ALICE, &format!(r#"{{"type": "transfer", "transfer": {{"to": "{}", "amount": "0x1e", "invoice_id": "INV-1"}}}}"#, BOB), &s1), "transfer with invoice");
        assert_eq!(t["appEvents"].as_array().unwrap().len(), 1, "{}", t);
        let s2 = state_b(&t);
        let plain = ok(&go(&app, REQUEST_PROCESS, ALICE, &format!(r#"{{"type": "transfer", "transfer": {{"to": "{}", "amount": "0x1"}}}}"#, BOB), &s2), "transfer");
        assert_eq!(plain["appEvents"].as_array().unwrap().len(), 0);
        let s3 = state_b(&plain);
        let w = ok(&go(&app, REQUEST_PROCESS, BOB, &format!(r#"{{"type": "withdraw", "withdraw": {{"to": "{}", "amount": "0x5"}}}}"#, BOB), &s3), "withdraw");
        assert_eq!(w["withdrawals"][0]["amount"], json!("0x5"));
        let s4 = state_b(&w);
        let bad = go(&app, REQUEST_PROCESS, BOB, &format!(r#"{{"type": "withdraw", "withdraw": {{"to": "{}", "amount": "0xffff"}}}}"#, BOB), &s4);
        assert_eq!(bad["error"], json!("insufficient_balance"), "{}", bad);
        let de = ok(&go(&app, REQUEST_DEANONYMIZATION, ALICE, r#"{"deanonymize": {"report_type": "balances"}}"#, &s4), "report");
        assert!(de.get("report").is_some());
    }

    #[test]
    fn example_trigger_app_runs_end_to_end_under_labels() {
        let app = App::inline(include_str!("../examples/trigger_app.syn"));
        const TRIGGER: &str = "0x3333333333333333333333333333333333333333";
        let s0 = deployed_with(&app, &format!(r#"{{"triggerContract": "{}"}}"#, TRIGGER));
        let d = ok(&deposit_flow(&app, 1, &addr(ALICE), &[0u8; 20], &[200], &s0), "deposit");
        let s1 = state_b(&d);
        let ex = ok(&go(&app, REQUEST_PROCESS, ALICE, &format!(r#"{{"command": "execute", "execute": {{"target": "{}", "value": "50", "data": "0x"}}}}"#, BOB), &s1), "execute");
        assert_eq!(ex["withdrawals"][0]["destinationAddress"], json!(TRIGGER));
        assert_eq!(ex["appEvents"].as_array().unwrap().len(), 1);
        let s2 = state_b(&ex);
        let bad = go(&app, REQUEST_PROCESS, ALICE, &format!(r#"{{"command": "execute", "execute": {{"target": "{}", "value": "5000", "data": "0x"}}}}"#, BOB), &s2);
        assert_eq!(bad["error"], json!("insufficient_balance"), "{}", bad);
        let empty = trusted_flow(&app, 1, b"", &s2);
        assert_eq!(empty["error"], json!("missing_payload"), "{}", empty);
    }

    fn deployed_with(app: &App, params: &str) -> Vec<u8> {
        let r = deploy_flow(app, 1, params.as_bytes());
        assert!(r.get("error").is_none(), "deploy failed: {}", r);
        synsema_wasm_web::base64_decode(r["state"].as_str().unwrap())
    }

    // ---- Harness para una app EXTERNA (los kits, repos aparte): `SYNSEMA_KIT_APP=<ruta app.syn>`,
    // `SYNSEMA_KIT_STEPS=<ruta json>` con `{"deploy": <params|null>, "steps": [{"kind": "deposit"|
    // "process"|"trusted"|"deanonymize", "sender": "0x…", "token": "0x…", "value": "<dec>",
    // "payload": <json>, "payload_hex": "0x…", "expect_error": "<code>"|null}]}`. Ignorado por
    // defecto (no hay kits en el repo); se corre a mano con `-- --ignored`. Cada paso corre bajo
    // etiquetas con las fuentes marcadas, como en el guest; un `label_violation` inesperado falla.

    /// Lo que un paso del plan puede afirmar del resultado, además del `error` (auditoría R3:
    /// los planes sólo miraban `error`, por eso no atraparon que dos kits cambiaron la firma ABI
    /// de su recibo y sus lectores quedaron rotos). `expect` es un mapa, todo opcional:
    ///
    /// ```json
    /// "expect": {
    ///   "app_events": 1,                       // cuántos hay
    ///   "app_event_bytes": [96],               // largo exacto del `data` de cada uno: PINEA la firma ABI
    ///   "app_event_subtypes": ["cleared"],     // etiqueta ASCII del subtype (o "0x…" para los 32 bytes)
    ///   "withdrawals": 1,
    ///   "withdrawal_amounts": ["0x12c"],       // Uint256 hex, como Vela los emite
    ///   "events": 2,                           // eventos privados (con el relleno de events_min)
    ///   "event_bytes_multiple_of": 256,        // cada `data` cifrado mide un múltiplo de N
    ///   "state_contains": "\"nonce\":1"        // subcadena del estado devuelto (JSON compacto)
    /// }
    /// ```
    fn check_expectations(i: usize, kind: &str, expect: &Value, r: &Value) {
        let Some(exp) = expect.as_object() else { return };
        let at = |what: &str| format!("step {} ({}) {}", i, kind, what);
        let arr = |k: &str| r.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
        let data_len = |e: &Value| synsema_wasm_web::base64_decode(e.get("data").and_then(Value::as_str).unwrap_or("")).len();
        for (key, want) in exp {
            match key.as_str() {
                "app_events" => assert_eq!(arr("appEvents").len() as u64, want.as_u64().unwrap(), "{}: {}", at("app_events"), r),
                "withdrawals" => assert_eq!(arr("withdrawals").len() as u64, want.as_u64().unwrap(), "{}: {}", at("withdrawals"), r),
                "events" => assert_eq!(arr("events").len() as u64, want.as_u64().unwrap(), "{}: {}", at("events"), r),
                "app_event_bytes" => {
                    let got: Vec<usize> = arr("appEvents").iter().map(data_len).collect();
                    let want: Vec<usize> = want.as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as usize).collect();
                    assert_eq!(got, want, "{} (the ABI signature of the receipt changed; update the kit's readers): {}", at("app_event_bytes"), r);
                }
                "app_event_subtypes" => {
                    let got: Vec<String> = arr("appEvents")
                        .iter()
                        .map(|e| {
                            let b: Vec<u8> = e["eventSubType"].as_array().unwrap().iter().map(|n| n.as_u64().unwrap() as u8).collect();
                            if b.iter().all(|c| *c == 0 || c.is_ascii_graphic()) {
                                String::from_utf8_lossy(&b).trim_end_matches('\0').to_string()
                            } else {
                                format!("0x{}", hex_lower(&b))
                            }
                        })
                        .collect();
                    let want: Vec<String> = want.as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
                    assert_eq!(got, want, "{}: {}", at("app_event_subtypes"), r);
                }
                "withdrawal_amounts" => {
                    let got: Vec<String> = arr("withdrawals").iter().map(|w| w["amount"].as_str().unwrap_or("").to_string()).collect();
                    let want: Vec<String> = want.as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
                    assert_eq!(got, want, "{}: {}", at("withdrawal_amounts"), r);
                }
                "event_bytes_multiple_of" => {
                    let n = want.as_u64().unwrap() as usize;
                    for (j, e) in arr("events").iter().enumerate() {
                        assert_eq!(data_len(e) % n, 0, "{}: event {} is {} bytes", at("event_bytes_multiple_of"), j, data_len(e));
                    }
                }
                "state_contains" => {
                    let st = String::from_utf8_lossy(&synsema_wasm_web::base64_decode(r["state"].as_str().unwrap_or(""))).to_string();
                    assert!(st.contains(want.as_str().unwrap()), "{}: {}", at("state_contains"), st);
                }
                other => panic!("step {}: unknown expectation {:?}", i, other),
            }
        }
    }

    #[test]
    #[ignore]
    fn external_kit_runs_its_flow_under_labels() {
        let app_path = std::env::var("SYNSEMA_KIT_APP").expect("SYNSEMA_KIT_APP");
        let steps_path = std::env::var("SYNSEMA_KIT_STEPS").expect("SYNSEMA_KIT_STEPS");
        let source = std::fs::read_to_string(&app_path).unwrap();
        let plan: Value = serde_json::from_str(&std::fs::read_to_string(&steps_path).unwrap()).unwrap();
        let app = App::inline(&source);
        let params = match &plan["deploy"] {
            Value::Null => String::new(),
            v => v.to_string(),
        };
        let mut state = deployed_with(&app, &params);
        for (i, step) in plan["steps"].as_array().unwrap().iter().enumerate() {
            let kind = step["kind"].as_str().unwrap();
            let sender = step["sender"].as_str().unwrap_or(ALICE);
            let expect = step["expect_error"].as_str();
            let r = match kind {
                "deposit" => {
                    let token = step["token"].as_str().unwrap_or(ZERO_ADDRESS);
                    let dec = step["value"].as_str().unwrap();
                    let hex = decimal_to_u256_hex(dec).unwrap();
                    deposit_flow(&app, 1, &addr(sender), &addr(token), &u256_hex_bytes(&hex), &state)
                }
                "process" => go(&app, REQUEST_PROCESS, sender, &step["payload"].to_string(), &state),
                "deanonymize" => go(&app, REQUEST_DEANONYMIZATION, sender, &step["payload"].to_string(), &state),
                "trusted" => trusted_flow(&app, 1, &hex_bytes(step["payload_hex"].as_str().unwrap()).unwrap(), &state),
                other => panic!("step {}: unknown kind {}", i, other),
            };
            match expect {
                Some("*") => {
                    let e = r["error"].as_str().unwrap_or("");
                    assert!(!e.is_empty() && e != "label_violation" && e != "runtime_error", "step {} ({}) expected an app error: {}", i, kind, r);
                }
                Some(code) => assert_eq!(r["error"], json!(code), "step {} ({}) expected error {}: {}", i, kind, code, r),
                None => {
                    assert!(r.get("error").is_none(), "step {} ({}) failed: {}", i, kind, r);
                    if r["state"].as_str().is_some() {
                        state = state_b(&r);
                    }
                }
            }
            check_expectations(i, kind, &step["expect"], &r);
            eprintln!("step {} ({}) ok", i, kind);
        }
    }
}

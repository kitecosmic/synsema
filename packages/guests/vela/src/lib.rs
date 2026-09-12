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
//! `trusted(ctx)`, `load_module(ctx)` (si faltan, caen en `process` / `deploy`). El adaptador
//! decodifica las entradas de Vela a valores Synsema (direcciones en hex, montos como texto
//! decimal exacto, estado y payload ya parseados de JSON, y el payload crudo también como
//! `payload_hex` porque un trigger contract manda bytes ABI, no JSON) y codifica la respuesta al
//! formato exacto de Vela. Cada campo de bytes de la respuesta (`state`, `report`, `data` de un
//! evento) se acepta en tres formas: `<campo>` (texto tal cual o JSON compacto), `<campo>_hex`
//! (`0x…`, binario exacto — lo que un contrato decodifica con `abi.decode`) o `<campo>_base64`.
//! `subtype` es `0x` + 64 hex o una etiqueta ASCII corta (≤ 32 bytes, alineada a la izquierda,
//! la convención del starter kit para trigger contracts). `fuel` lo declara la app (`"fuel"`) o,
//! si no, son los pasos deterministas del intérprete (`steps`). El programa corre bajo el techo
//! `stdout` del ABI genérico: sin `time`, sin `random`, sin red — determinista por construcción,
//! que es lo que el state root firmado exige. `print` va al stdout de WASI con prefijo `INF`, que
//! es el canal de logs de Vela.

use std::cell::Cell;

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

// =========================================================
// Memoria: allocate / deallocate / stats (el mismo modelo que la app de referencia en TinyGo)
// =========================================================

thread_local! {
    static LIVE_ALLOCS: Cell<i64> = const { Cell::new(0) };
    static LIVE_BYTES: Cell<i64> = const { Cell::new(0) };
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
// Los exports de Vela
// =========================================================

/// `load_module(appId)`: cache warm-up. Si la app define `load_module`, se llama; si no, el estado
/// inicial es el de `deploy` sin parámetros (lo que hace la app de referencia).
#[no_mangle]
pub extern "C" fn load_module(app_id: i64) -> i32 {
    log("INF", &format!("synsema-vela-guest: engine {}, app {}", engine_version(), app_name()));
    let ctx = json!({"app_id": app_id, "kind": "load_module", "params": Value::Null});
    let r = run_app("load_module", Some("deploy"), &ctx);
    let steps = r.steps;
    let own_task = defines_task(app_source(), "load_module");
    let result = deploy_like_result(r);
    // Sin `load_module` propia, un `deploy` que exige params (p. ej. la dirección de un trigger
    // contract) no debe tumbar el warm-up: el Executor descarta este estado (sigue con el
    // persistido, `getOrLoadModule` ignora lo devuelto) y sólo mira `error` — y un `error` acá
    // deja la app sin poder cargarse tras un reinicio del Executor. Estado vacío, y se avisa.
    if !own_task {
        if let Some(e) = result.get("error").and_then(Value::as_str) {
            log("WRN", &format!("load_module: deploy(params: nothing) failed ({}); answering an empty state — the Executor only warms its cache here and keeps the persisted state. Define `task load_module(ctx)` to control this.", e));
            return pack(json!({"state": b64(&[]), "fuel": steps_hex(steps)}).to_string().as_bytes());
        }
    }
    pack(result.to_string().as_bytes())
}

/// `deploy(appId, paramsPtr, paramsLen)`: una vez, con `constructorParams` (JSON o vacío).
///
/// # Safety
/// Los punteros/longitudes los escribió el host con `allocate`.
#[no_mangle]
pub unsafe extern "C" fn deploy(app_id: i64, params_ptr: i32, params_len: i32) -> i32 {
    log("INF", &format!("synsema-vela-guest: deploy app {} (engine {}, program {})", app_id, engine_version(), app_name()));
    let params = decode_json_or_text(input(params_ptr, params_len));
    let ctx = json!({"app_id": app_id, "kind": "deploy", "params": params});
    let r = run_app("deploy", None, &ctx);
    pack(deploy_like_result(r).to_string().as_bytes())
}

/// `deposit(appId, sender, token, value, state)`: llega cuando el request trae `assetAmount > 0`.
///
/// # Safety
/// Los punteros/longitudes los escribió el host con `allocate`.
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
    let value = input(value_ptr, value_len);
    let state = input(state_ptr, state_len);
    let ctx = json!({
        "app_id": app_id,
        "kind": "deposit",
        "sender": address_hex(input(sender_ptr, sender_len)),
        "token": address_hex(input(token_ptr, token_len)),
        "value": be_bytes_to_decimal(value),
        "value_hex": u256_hex_of_bytes(value),
        "state": decode_json_or_text(state),
    });
    let r = run_app("deposit", None, &ctx);
    pack(process_like_result(r, state, ResultShape::Deposit).to_string().as_bytes())
}

/// `process_request(appId, sender, requestType, payload, state)`: PROCESS (1) y DEANONYMIZATION (2).
/// Con 2 la app debe devolver `report`; con 1 no debe (si lo trae, se descarta con aviso).
///
/// # Safety
/// Los punteros/longitudes los escribió el host con `allocate`.
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
    let state = input(state_ptr, state_len);
    let payload = input(payload_ptr, payload_len);
    let kind = match request_type {
        REQUEST_DEANONYMIZATION => "deanonymize",
        REQUEST_TRUSTPROCESS => "trusted",
        _ => "process",
    };
    let ctx = json!({
        "app_id": app_id,
        "kind": kind,
        "request_type": request_type,
        "sender": address_hex(input(sender_ptr, sender_len)),
        "payload": decode_json_or_text(payload),
        "payload_hex": hex_value(payload),
        "state": decode_json_or_text(state),
    });
    let (task, fallback) = match request_type {
        REQUEST_DEANONYMIZATION => ("deanonymize", Some("process")),
        REQUEST_TRUSTPROCESS => ("trusted", Some("process")),
        // PROCESS (1) y cualquier tipo futuro: la task `process` recibe `request_type` y decide.
        REQUEST_PROCESS | _ => ("process", None),
    };
    let r = run_app(task, fallback, &ctx);
    let shape = if request_type == REQUEST_DEANONYMIZATION { ResultShape::Deanonymize } else { ResultShape::Process };
    pack(process_like_result(r, state, shape).to_string().as_bytes())
}

/// `trusted_request(appId, payload, state)`: TRUSTPROCESS desde un trigger contract, sin sender.
///
/// # Safety
/// Los punteros/longitudes los escribió el host con `allocate`.
#[no_mangle]
pub unsafe extern "C" fn trusted_request(app_id: i64, payload_ptr: i32, payload_len: i32, state_ptr: i32, state_len: i32) -> i32 {
    let state = input(state_ptr, state_len);
    // El payload lo produjo el trigger contract (`getTrustProcessPayload`), en claro y en ABI:
    // como texto se perdería, por eso viaja también en `payload_hex`.
    let payload = input(payload_ptr, payload_len);
    let ctx = json!({
        "app_id": app_id,
        "kind": "trusted",
        "request_type": REQUEST_TRUSTPROCESS,
        "sender": Value::Null,
        "payload": decode_json_or_text(payload),
        "payload_hex": hex_value(payload),
        "state": decode_json_or_text(state),
    });
    let r = run_app("trusted", Some("process"), &ctx);
    pack(process_like_result(r, state, ResultShape::Process).to_string().as_bytes())
}

// =========================================================
// Correr la app por el ABI genérico
// =========================================================

/// Lo que una corrida deja: el mapa que devolvió la task de la app (o un error) y los pasos.
struct AppRun {
    /// `Ok(mapa)` = lo que la task devolvió; `Err(msg)` = error del programa o contrato roto.
    result: Result<Map<String, Value>, String>,
    steps: u64,
}

/// Construye el programa "app + driver", lo corre con `{"op": "run"}` bajo el techo y separa
/// logs de resultado: la ÚLTIMA línea impresa es el JSON del resultado (la imprime el driver);
/// todo lo anterior son `print` de la app y van a los logs de Vela.
fn run_app(task: &str, fallback: Option<&str>, ctx: &Value) -> AppRun {
    let call = if defines_task(app_source(), task) {
        format!("set __vela_out to {}(__vela_in)", task)
    } else if let Some(fb) = fallback.filter(|fb| defines_task(app_source(), fb)) {
        format!("set __vela_out to {}(__vela_in)", fb)
    } else {
        let mut m = Map::new();
        m.insert("error".into(), json!(format!("the program defines no task '{}'", task)));
        return AppRun { result: Ok(m), steps: 1 };
    };
    let source = format!(
        "{}\n\nlet __vela_in be json_decode(\"{}\")\nlet __vela_out be nothing\n{}\nprint(json_encode(__vela_out))\n",
        app_source(),
        syn_escape(&ctx.to_string()),
        call
    );
    let req = json!({"op": "run", "source": source, "filename": app_name(), "ceiling": CEILING});
    let raw = synsema_wasm_web::call_json(&req.to_string());
    let resp: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return AppRun { result: Err(format!("engine response is not JSON: {}", e)), steps: 1 },
    };
    let steps = resp.get("steps").and_then(Value::as_u64).unwrap_or(1).max(1);
    let mut output: Vec<String> = resp
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
    // Con un fallo el último print puede no ser del driver: todo es log.
    let result_line = if ok && errors.is_empty() { output.pop() } else { None };
    for line in &output {
        log("INF", line);
    }
    for e in &errors {
        log("ERR", e);
    }
    if !ok || !errors.is_empty() {
        let msg = if errors.is_empty() { "the program failed".to_string() } else { errors.join("; ") };
        return AppRun { result: Err(msg), steps };
    }
    let Some(line) = result_line else {
        return AppRun { result: Err("the program printed nothing (driver output missing)".to_string()), steps };
    };
    match serde_json::from_str::<Value>(&line) {
        Ok(Value::Object(m)) => AppRun { result: Ok(m), steps },
        Ok(Value::Null) => AppRun { result: Err(format!("task '{}' returned nothing; a map is required", task)), steps },
        Ok(other) => AppRun { result: Err(format!("task '{}' must return a map, got {}", task, other)), steps },
        Err(e) => AppRun { result: Err(format!("task '{}' result is not JSON: {}", task, e)), steps },
    }
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

/// stdout de WASI con el prefijo que el Executor reconoce (`INF`/`WRN`/`ERR`).
fn log(level: &str, line: &str) {
    println!("{} {}", level, line);
}

// =========================================================
// Del mapa de la app al resultado exacto de Vela
// =========================================================

#[derive(Clone, Copy, PartialEq)]
enum ResultShape {
    Deposit,
    Process,
    Deanonymize,
}

fn error_result(msg: &str, steps: u64) -> Value {
    log("ERR", msg);
    let mut m = Map::new();
    m.insert("state".into(), Value::Null);
    m.insert("fuel".into(), json!(steps_hex(steps)));
    m.insert("error".into(), json!(msg));
    Value::Object(m)
}

/// `DeployResult` / `LoadModuleResult`: `{state, fuel, error?}`.
fn deploy_like_result(run: AppRun) -> Value {
    let out = match run.result {
        Ok(m) => m,
        Err(e) => return error_result(&e, run.steps),
    };
    if let Some(e) = app_error(&out) {
        return error_result(&e, run.steps);
    }
    let state = match bytes_field(&out, "state") {
        Ok(Some(b)) => b,
        Ok(None) => return error_result("deploy must return {\"state\": …}", run.steps),
        Err(e) => return error_result(&e, run.steps),
    };
    let fuel = match fuel_of(&out, run.steps) {
        Ok(f) => f,
        Err(e) => return error_result(&e, run.steps),
    };
    let mut m = Map::new();
    m.insert("state".into(), json!(b64(&state)));
    m.insert("fuel".into(), json!(fuel));
    Value::Object(m)
}

/// `DepositResult` / `ProcessResult`. Sin `state` en la respuesta, el estado queda como estaba.
fn process_like_result(run: AppRun, prev_state: &[u8], shape: ResultShape) -> Value {
    let out = match run.result {
        Ok(m) => m,
        Err(e) => return error_result(&e, run.steps),
    };
    if let Some(e) = app_error(&out) {
        return error_result(&e, run.steps);
    }
    let build = || -> Result<Map<String, Value>, String> {
        let mut m = Map::new();
        // Sin `state` (o `nothing`): el estado queda como vino, byte a byte.
        let state = bytes_field(&out, "state")?.unwrap_or_else(|| prev_state.to_vec());
        m.insert("state".into(), json!(b64(&state)));
        m.insert("events".into(), Value::Array(events_of(out.get("events"), true)?));
        m.insert("appEvents".into(), Value::Array(events_of(out.get("app_events").or_else(|| out.get("appEvents")), false)?));
        if shape != ResultShape::Deposit {
            m.insert("withdrawals".into(), Value::Array(withdrawals_of(out.get("withdrawals"))?));
            match (shape, bytes_field(&out, "report")?) {
                (ResultShape::Deanonymize, Some(r)) => {
                    m.insert("report".into(), json!(b64(&r)));
                }
                (ResultShape::Deanonymize, None) => {
                    return Err("a DEANONYMIZATION request (type 2) must return {\"report\": …}".to_string());
                }
                (_, Some(_)) => {
                    log("WRN", "the program returned a report on a non-deanonymization request; dropped (Vela refuses it)");
                }
                (_, None) => {}
            }
        }
        m.insert("fuel".into(), json!(fuel_of(&out, run.steps)?));
        Ok(m)
    };
    match build() {
        Ok(m) => Value::Object(m),
        Err(e) => error_result(&e, run.steps),
    }
}

/// `{"error": "texto no vacío"}` de la app = fallo del request.
fn app_error(out: &Map<String, Value>) -> Option<String> {
    match out.get("error") {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Null) | None => None,
        Some(Value::String(_)) => None,
        Some(other) => Some(other.to_string()),
    }
}

/// El estado (o el reporte) como bytes: un texto va tal cual; cualquier otro valor, como JSON
/// compacto con el orden de claves del programa (determinista).
fn state_bytes(v: &Value) -> Vec<u8> {
    match v {
        Value::String(s) => s.clone().into_bytes(),
        other => other.to_string().into_bytes(),
    }
}

/// `fuel`: lo que declaró la app (entero o texto decimal/hex) o los pasos del intérprete.
fn fuel_of(out: &Map<String, Value>, steps: u64) -> Result<String, String> {
    match out.get("fuel") {
        None | Some(Value::Null) => Ok(steps_hex(steps)),
        Some(v) => u256_hex(v).map_err(|e| format!("fuel: {}", e)),
    }
}

fn steps_hex(steps: u64) -> String {
    format!("0x{:x}", steps.max(1))
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
// Direcciones, enteros de 256 bits, base64
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

/// big-endian → `0x…` normalizado.
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
}

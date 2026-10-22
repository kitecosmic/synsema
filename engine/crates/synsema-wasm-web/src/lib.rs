//! synsema-wasm-web — el intérprete Synsema como módulo WebAssembly EMBEBIBLE
//! (`wasm32-unknown-unknown`): navegador, Node/Bun/Deno, Python (wasmtime-py), Go
//! (wazero), .NET, Java… cualquier runtime que cargue un `.wasm` y provea tres
//! imports. WASM fase 2, F1 + F2.
//!
//! # ABI (cruda, JSON en memoria lineal — sin wasm-bindgen)
//!
//! Exports:
//! - `synsema_alloc(len) -> ptr`, `synsema_free(ptr, len)`: el heap del guest, para
//!   que el host escriba/lea buffers.
//! - `synsema_call(req_ptr, req_len) -> ptr`: UNA entrada. `req` es JSON
//!   `{"op": "run"|"test"|"check"|"handle"|"version", ...}`; devuelve un buffer
//!   `[u32 LE len][json]` que el host lee y libera con `synsema_free(ptr, 4 + len)`.
//!
//! Imports (módulo `synsema_host`; el glue del host los provee SIEMPRE — los que no
//! ofrece devuelven "no provisto"):
//! - `host_call(kind_ptr, kind_len, payload_ptr, payload_len) -> ptr`: el protocolo
//!   `HostProvider` (kinds `http`/`kv_get`/`kv_set`/`kv_delete`/`kv_list`/`llm`/`log`/
//!   `sleep`) con payload y respuesta JSON. `0` = no provisto. La respuesta la escribe
//!   el host en memoria del guest vía `synsema_alloc` (buffer `[u32 LE len][json]`)
//!   y el guest la libera.
//! - `host_random_fill(ptr, len) -> i32`: entropía del host (crypto.getRandomValues /
//!   os.urandom / crypto/rand). Backend de `getrandom` para `random()`, `token()`,
//!   `mnemonic_generate`, firmas ECDSA con nonce…: la doctrina no cambia (cripto).
//! - `host_now_ms() -> f64`: reloj (`Date.now()`); alimenta `synsema_core::clock`.
//!
//! Por qué ABI cruda y no wasm-bindgen: el MISMO `.wasm` sirve a todos los hosts (no
//! sólo JS), el glue por lenguaje son ~80 líneas, y no hay CLI de post-proceso que
//! pinear. Los tipos TS del paquete npm describen esta frontera.
//!
//! El intérprete es SÍNCRONO: un host cuyo `http` es async (fetch del navegador) corre
//! `synsema_call` en un Worker y bloquea con `Atomics.wait` hasta que el main thread
//! resuelve — patrón del paquete npm (`worker.mjs`). Un host síncrono (Python
//! `urllib`, Go `net/http`, Node con `kv` en memoria) llama directo.
//!
//! Qué ofrece el host lo declara el request (`"host": {"http": true, "kv": true, …}`):
//! el wiring cablea sólo eso (`HostProvider::offers`). El programa sigue declarando
//! `require net/llm/memory` y el `ceiling` del embebedor sigue mandando; el `audit`
//! de la respuesta lista cada chequeo de capability.
//!
//! Un panic en wasm es un trap (`panic = "abort"`): el mensaje va al `log` del host y
//! el glue reinstancia el módulo. Los errores del PROGRAMA nunca panican: van en
//! `errors`.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use serde_json::{json, Map, Value};
use synsema_core::interpreter::Interpreter;
use synsema_stdlib::hostcap::{self, HostHttpRequest, HostLlmResult, HostProvider, HttpResult};
use synsema_wasm::{HttpRequestIn, RunOptions};
/// El host que consume `result` revierte el escape de claves `$` con esto.
pub use synsema_wasm::{escape_marker_key, labelled_json, unescape_marker_key};

// =========================================================
// imports del host (con fallbacks nativos para `cargo test --workspace`)
// =========================================================

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod imports {
    #[link(wasm_import_module = "synsema_host")]
    extern "C" {
        pub fn host_call(kind_ptr: *const u8, kind_len: u32, payload_ptr: *const u8, payload_len: u32) -> *mut u8;
        pub fn host_random_fill(ptr: *mut u8, len: u32) -> i32;
        pub fn host_now_ms() -> f64;
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[allow(dead_code)]
mod imports {
    /// Nativo: ningún host. `host_call` = no provisto; el reloj y la entropía del SO.
    pub unsafe fn host_call(_k: *const u8, _kl: u32, _p: *const u8, _pl: u32) -> *mut u8 {
        std::ptr::null_mut()
    }
    pub unsafe fn host_random_fill(_ptr: *mut u8, _len: u32) -> i32 {
        1
    }
    pub unsafe fn host_now_ms() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64() * 1000.0)
            .unwrap_or(0.0)
    }
}

// =========================================================
// v0.6.45 (D2): el allocator que cuenta (maxMemoryMb)
// =========================================================

/// El allocator del módulo: el del sistema (dlmalloc en wasm32), contando los bytes vivos en
/// `wasm_limits::LIVE`. Con `maxMemoryMb` armado, una reserva que pasaría el techo se RECHAZA
/// (devuelve null): Rust no sigue sin esa memoria y el módulo hace trap, pero `HIT` queda prendido y
/// el paquete JS lo traduce en un error de la corrida. Sin límite armado el costo es una suma
/// atómica relajada por reserva (un hilo: no hay contención).
#[cfg(target_arch = "wasm32")]
struct CountingAlloc;

#[cfg(target_arch = "wasm32")]
unsafe impl std::alloc::GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if !synsema_core::wasm_limits::reserve(layout.size()) {
            return std::ptr::null_mut();
        }
        let p = std::alloc::System.alloc(layout);
        if p.is_null() {
            synsema_core::wasm_limits::release(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        if !synsema_core::wasm_limits::reserve(layout.size()) {
            return std::ptr::null_mut();
        }
        let p = std::alloc::System.alloc_zeroed(layout);
        if p.is_null() {
            synsema_core::wasm_limits::release(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        std::alloc::System.dealloc(ptr, layout);
        synsema_core::wasm_limits::release(layout.size());
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        let old = layout.size();
        if new_size > old && !synsema_core::wasm_limits::reserve(new_size - old) {
            return std::ptr::null_mut();
        }
        let p = std::alloc::System.realloc(ptr, layout, new_size);
        if p.is_null() {
            if new_size > old {
                synsema_core::wasm_limits::release(new_size - old);
            }
        } else if new_size < old {
            synsema_core::wasm_limits::release(old - new_size);
        }
        p
    }
}

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// v0.6.45 (D2) — `1` si la última corrida pasó `maxMemoryMb` (el allocator rechazó una reserva y
/// el módulo hizo trap). El host lo pregunta DESPUÉS del trap, sobre la misma instancia, para
/// devolver un error en vez del trap; no reserva nada.
#[no_mangle]
pub extern "C" fn synsema_limit_hit() -> u32 {
    #[cfg(target_arch = "wasm32")]
    return synsema_core::wasm_limits::HIT.load(std::sync::atomic::Ordering::Relaxed) as u32;
    #[cfg(not(target_arch = "wasm32"))]
    0
}

// =========================================================
// memoria: buffers `[u32 LE len][bytes]`
// =========================================================

/// Reserva `len` bytes en el heap del guest (el host escribe ahí). Se libera con
/// `synsema_free(ptr, len)`.
#[no_mangle]
pub extern "C" fn synsema_alloc(len: u32) -> *mut u8 {
    let mut v: Vec<u8> = Vec::with_capacity(len.max(1) as usize);
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ptr
}

/// Libera un buffer reservado por `synsema_alloc` (o devuelto por `synsema_call`,
/// con `len = 4 + json_len`).
///
/// # Safety
/// `ptr`/`len` deben venir de `synsema_alloc(len)` o de `synsema_call`, una sola vez.
#[no_mangle]
pub unsafe extern "C" fn synsema_free(ptr: *mut u8, len: u32) {
    if ptr.is_null() {
        return;
    }
    drop(Vec::from_raw_parts(ptr, 0, len.max(1) as usize));
}

/// Empaqueta `bytes` como `[u32 LE len][bytes]` en un buffer del guest y lo filtra
/// (el caller lo libera con `synsema_free(ptr, 4 + len)`).
fn pack(bytes: &[u8]) -> *mut u8 {
    let len = bytes.len() as u32;
    let total = 4 + bytes.len();
    let mut v: Vec<u8> = Vec::with_capacity(total);
    v.extend_from_slice(&len.to_le_bytes());
    v.extend_from_slice(bytes);
    // capacity == total: synsema_free reconstruye con esa capacity.
    debug_assert_eq!(v.capacity(), total);
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ptr
}

/// Lee un buffer `[u32 LE len][bytes]` devuelto por el host y lo libera.
///
/// # Safety
/// `ptr` debe ser un buffer que el host reservó con `synsema_alloc(4 + len)`.
unsafe fn unpack_and_free(ptr: *mut u8) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let mut lb = [0u8; 4];
    std::ptr::copy_nonoverlapping(ptr, lb.as_mut_ptr(), 4);
    let len = u32::from_le_bytes(lb) as usize;
    let body = std::slice::from_raw_parts(ptr.add(4), len).to_vec();
    synsema_free(ptr, (4 + len) as u32);
    Some(body)
}

// =========================================================
// El provider: cada método = un `host_call` con JSON
// =========================================================

fn host_call_json(kind: &str, payload: &Value) -> Option<Value> {
    let p = serde_json::to_vec(payload).ok()?;
    let raw = unsafe {
        imports::host_call(kind.as_ptr(), kind.len() as u32, p.as_ptr(), p.len() as u32)
    };
    tick_fenced_clock();
    let bytes = unsafe { unpack_and_free(raw) }?;
    if bytes.is_empty() {
        return Some(Value::Null);
    }
    serde_json::from_slice(&bytes).ok()
}

struct WebHost {
    offers: HashSet<String>,
}

fn pairs_to_json(pairs: &[(String, String)]) -> Value {
    Value::Array(pairs.iter().map(|(k, v)| json!([k, v])).collect())
}

fn json_to_pairs(v: Option<&Value>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    match v {
        Some(Value::Array(items)) => {
            for it in items {
                if let Value::Array(kv) = it {
                    if kv.len() == 2 {
                        out.push((str_of(&kv[0]), str_of(&kv[1])));
                    }
                }
            }
        }
        Some(Value::Object(m)) => {
            for (k, v) in m {
                out.push((k.clone(), str_of(v)));
            }
        }
        _ => {}
    }
    out
}

/// El tipo JSON de un valor, para un mensaje.
fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn str_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

impl HostProvider for WebHost {
    /// El audit fail-loud (reveal/sign/wallet/spend) vive en el kv del embebedor:
    /// `audit` / `<log>` → texto append-only. Sin `kv` → None → la operación se niega.
    fn audit_append(&self, log: &str, line: &str) -> Option<Result<(), String>> {
        if !self.offers("kv") {
            return None;
        }
        // v0.6.46 (ronda 1 de cf1, M2): lo anterior se lee por `kv_get`, que dice si la lectura
        // falló. Antes un `kv.get` que lanzaba contaba como "no hay log": se pisaba el log entero con
        // una línea y la operación seguía autorizada. Ahora se niega, como cuando falla el `kv_set`.
        let prev = match self.kv_get("audit", log)? {
            Ok(prev) => prev.unwrap_or_default(),
            Err(e) => return Some(Err(format!("reading the audit log failed: {}", e))),
        };
        let r = host_call_json("kv_set", &json!({"ns": "audit", "key": log, "value": format!("{}{}", prev, line)}))?;
        Some(match r.get("error").and_then(Value::as_str) {
            Some(e) if !e.is_empty() => Err(e.to_string()),
            _ => Ok(()),
        })
    }
    fn offers(&self, what: &str) -> bool {
        self.offers.contains(what)
    }

    fn http(&self, req: &HostHttpRequest<'_>) -> Option<Result<HttpResult, String>> {
        if !self.offers("http") {
            return None;
        }
        let mut payload = Map::new();
        payload.insert("method".into(), json!(req.method));
        payload.insert("url".into(), json!(req.url));
        payload.insert("headers".into(), pairs_to_json(req.headers));
        payload.insert("timeout".into(), json!(req.timeout_secs));
        // v0.6.46 (E1): con un secret en la request, el glue de JS pasa esto a `fetch`.
        if req.forbid_redirects {
            payload.insert("redirect".into(), json!("error"));
        }
        match req.body {
            None => {
                payload.insert("body".into(), Value::Null);
            }
            Some(b) => match std::str::from_utf8(b) {
                Ok(s) => {
                    payload.insert("body".into(), json!(s));
                }
                Err(_) => {
                    payload.insert("body_base64".into(), json!(base64_encode(b)));
                }
            },
        }
        let r = host_call_json("http", &Value::Object(payload))?;
        if let Some(e) = r.get("error").and_then(Value::as_str) {
            if !e.is_empty() {
                return Some(Err(e.to_string()));
            }
        }
        let status = r.get("status").and_then(Value::as_i64).unwrap_or(0);
        // v0.6.20 — se conservan los bytes exactos (`body_base64` del host, o el texto).
        let (body, body_bytes) = match r.get("body_base64").and_then(Value::as_str) {
            Some(b64) => {
                let bytes = base64_decode(b64);
                (String::from_utf8_lossy(&bytes).to_string(), bytes)
            }
            None => {
                let s = r.get("body").map(str_of).unwrap_or_default();
                let bytes = s.as_bytes().to_vec();
                (s, bytes)
            }
        };
        Some(Ok(HttpResult {
            status,
            ok: (200..300).contains(&status),
            body,
            body_bytes,
            headers: json_to_pairs(r.get("headers")),
            error: None,
            attested: None,
        }))
    }

    fn kv_get(&self, ns: &str, key: &str) -> Option<Result<Option<String>, String>> {
        if !self.offers("kv") {
            return None;
        }
        let r = host_call_json("kv_get", &json!({"ns": ns, "key": key}))?;
        // v0.6.46: un hook que lanza llega como `{error}` (como en `kv_set`): es un error, no "no está".
        if let Some(e) = r.get("error").and_then(Value::as_str).filter(|e| !e.is_empty()) {
            return Some(Err(e.to_string()));
        }
        // v0.6.46 (ronda 1 de cf1, B7): un valor que no es texto ni `null` (un número, un objeto ya
        // parseado) también es un error del host: contarlo como "no está" hacía que `state_incr`
        // arrancara de 0 y que la memoria cargara vacía y pisara la guardada.
        Some(match r.get("value") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(other) => Err(format!("kv.get must return a string or null, got {}", json_kind(other))),
        })
    }
    fn kv_set(&self, ns: &str, key: &str, value: &str) -> Option<Result<(), String>> {
        if !self.offers("kv") {
            return None;
        }
        let r = host_call_json("kv_set", &json!({"ns": ns, "key": key, "value": value}))?;
        Some(match r.get("error").and_then(Value::as_str) {
            Some(e) if !e.is_empty() => Err(e.to_string()),
            _ => Ok(()),
        })
    }
    fn kv_delete(&self, ns: &str, key: &str) -> Option<Result<(), String>> {
        if !self.offers("kv") {
            return None;
        }
        let r = host_call_json("kv_delete", &json!({"ns": ns, "key": key}))?;
        Some(match r.get("error").and_then(Value::as_str) {
            Some(e) if !e.is_empty() => Err(e.to_string()),
            _ => Ok(()),
        })
    }
    fn kv_cas(&self, ns: &str, key: &str, expected: Option<&str>, value: &str) -> Option<Result<bool, String>> {
        if !self.offers("kv_cas") {
            return None;
        }
        let r = host_call_json("kv_cas", &json!({"ns": ns, "key": key, "expected": expected, "value": value}))?;
        Some(match r.get("error").and_then(Value::as_str) {
            Some(e) if !e.is_empty() => Err(e.to_string()),
            // v0.6.45: un `swapped` que no es booleano es un host roto, no "otro escribió" (antes
            // contaba como false y se reintentaba 64 veces hasta "kept changing").
            _ => match r.get("swapped") {
                Some(Value::Bool(b)) => Ok(*b),
                other => Err(format!("kv.cas must answer {{swapped: true|false}}, got {}", other.map(|v| v.to_string()).unwrap_or_else(|| "nothing".to_string()))),
            },
        })
    }
    fn kv_list(&self, ns: &str) -> Option<Result<Vec<String>, String>> {
        if !self.offers("kv") {
            return None;
        }
        let r = host_call_json("kv_list", &json!({"ns": ns}))?;
        // v0.6.46 (ronda 1 de cf1): un hook que lanza es un error, no "no hay claves".
        if let Some(e) = r.get("error").and_then(Value::as_str).filter(|e| !e.is_empty()) {
            return Some(Err(e.to_string()));
        }
        // v0.6.46 (ronda 2 de cf1, R2-B2): como en `kv_get` (B7), lo que no es una lista de textos (la
        // forma `{keys: [{name}]}` de Cloudflare KV, `undefined`, un número) es un error del host: se
        // leía como "no hay claves" y `state_all()` daba `{}`.
        Some(match r.get("keys") {
            Some(Value::Array(a)) if a.iter().all(Value::is_string) => Ok(a.iter().map(str_of).collect()),
            Some(Value::Array(_)) => Err("kv.list must return a list of strings, got a list with other values".to_string()),
            Some(other) => Err(format!("kv.list must return a list of strings, got {}", json_kind(other))),
            None => Err("kv.list must return a list of strings, got nothing".to_string()),
        })
    }
    fn llm(&self, op: &str, prompt: &str, principals: &[String]) -> Option<Result<HostLlmResult, String>> {
        if !self.offers("llm") {
            return None;
        }
        let r = host_call_json("llm", &json!({"op": op, "prompt": prompt, "principals": principals}))?;
        // v0.6.46 (E5, §0.13): un hook que lanza vuelve como `{error}`; antes contaba como una
        // respuesta vacía con `ok: true`.
        if let Some(e) = r.get("error") {
            let m = str_of(e);
            return Some(Err(if m.is_empty() { "the host's llm hook threw".to_string() } else { m }));
        }
        let content = match &r {
            Value::String(s) => s.clone(),
            other => other.get("content").map(str_of).unwrap_or_default(),
        };
        let tokens = r.get("tokens").and_then(Value::as_u64).unwrap_or(0);
        Some(Ok(HostLlmResult { content, tokens }))
    }
    fn log(&self, line: &str) -> bool {
        if !self.offers("log") {
            return false;
        }
        host_call_json("log", &json!({"line": line})).is_some()
    }
    fn sleep(&self, secs: f64) -> bool {
        if !self.offers("sleep") {
            return false;
        }
        host_call_json("sleep", &json!({"secs": secs})).is_some()
    }
}

// =========================================================
// entropía + reloj + pausa del host
// =========================================================

// v0.6.45 (auditoría, ronda 2, B2) — el host ve la FORMA de lo que se le pide, no sólo el contenido:
// `random_bytes(n)` le pedía `n` bytes (y con `n` privado, el host leía `n`), y `now()` dentro de una
// rama privada le avisaba que la rama se tomó. Ahora:
// - **Entropía:** al empezar cada llamada se le piden al host 32 bytes fijos, que siembran un
//   generador ChaCha propio de la corrida; `random_bytes`/`token`/`random()` y el cegado de RSA salen
//   de ahí y nunca vuelven a llamar al host. Fuera de una llamada (al iniciar la instancia, sin
//   programa corriendo) se le pide directo, como antes.
// - **Reloj, con etiquetas:** `now()` devuelve la última lectura, que se toma al empezar y en cada
//   interacción con el host (que ya es pública: un sumidero no corre en una rama privada). Cuándo y
//   cuántas veces se llamó a `now()` no sale. Sin etiquetas, el reloj de siempre.

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
thread_local! {
    static RUN_RNG: RefCell<Option<rand::rngs::StdRng>> = const { RefCell::new(None) };
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn host_fill(buf: &mut [u8]) -> bool {
    unsafe { imports::host_random_fill(buf.as_mut_ptr(), buf.len() as u32) == 0 }
}

/// Siembra el generador de la corrida (una consulta de 32 bytes al host). Sin entropía del host,
/// la corrida no tiene generador y lo que lo necesite falla con un error claro.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn seed_run_rng() {
    use rand::SeedableRng;
    let mut seed = [0u8; 32];
    let rng = host_fill(&mut seed).then(|| rand::rngs::StdRng::from_seed(seed));
    RUN_RNG.with(|r| *r.borrow_mut() = rng);
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn end_run_rng() {
    RUN_RNG.with(|r| *r.borrow_mut() = None);
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn host_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    use rand::RngCore;
    // Dentro de una llamada: el generador de la corrida (el host no ve cuánto se pide).
    let in_run = RUN_RNG.with(|r| r.borrow_mut().as_mut().map(|g| g.fill_bytes(buf)).is_some());
    if in_run || (!IN_CALL.with(|c| c.get()) && host_fill(buf)) {
        Ok(())
    } else {
        // Código custom (getrandom reserva el rango ≥ CUSTOM_START para el embebedor).
        let code = core::num::NonZeroU32::new(getrandom::Error::CUSTOM_START + 1).expect("non-zero");
        Err(getrandom::Error::from(code))
    }
}

thread_local! {
    /// ¿Hay una llamada en curso? (`call_json` la marca.)
    static IN_CALL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Reloj cercado (con etiquetas): la última lectura del host, en segundos.
    static FENCED_CLOCK: std::cell::Cell<Option<f64>> = const { std::cell::Cell::new(None) };
}

fn host_now_secs() -> f64 {
    let ms = unsafe { imports::host_now_ms() };
    ms / 1000.0
}

/// Con etiquetas encendidas, el reloj de la corrida es una lectura en un momento público.
fn fence_clock(on: bool) {
    FENCED_CLOCK.with(|c| c.set(on.then(host_now_secs)));
}

/// Una interacción con el host (pública): el reloj cercado avanza acá.
fn tick_fenced_clock() {
    FENCED_CLOCK.with(|c| {
        if c.get().is_some() {
            c.set(Some(host_now_secs()));
        }
    });
}
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
getrandom::register_custom_getrandom!(host_getrandom);

thread_local! {
    static INIT: RefCell<bool> = const { RefCell::new(false) };
}

/// Una vez por instancia: reloj y pausa del host, y el hook de panic → log del host.
fn init_once() {
    let done = INIT.with(|i| std::mem::replace(&mut *i.borrow_mut(), true));
    if done {
        return;
    }
    synsema_core::clock::set_clock(Some(Box::new(|| FENCED_CLOCK.with(|c| c.get()).unwrap_or_else(host_now_secs))));
    synsema_core::clock::set_sleep(Some(Box::new(|secs: f64| {
        if let Some(p) = hostcap::provider() {
            p.sleep(secs);
        }
    })));
    // Sólo en wasm: en nativo (tests) el hook default imprime a stderr, que es lo útil.
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("synsema-wasm: panic: {}", info);
        let _ = host_call_json("log", &json!({"line": msg}));
    }));
}

// =========================================================
// La entrada
// =========================================================

fn err_response(msg: &str) -> Value {
    json!({"ok": false, "output": [], "errors": [msg], "audit": []})
}

fn opts_from(req: &Map<String, Value>) -> Result<RunOptions, String> {
    let filename = req
        .get("filename")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("<embedded>")
        .to_string();
    let env: Option<HashMap<String, String>> = match req.get("env") {
        Some(Value::Object(m)) => Some(m.iter().map(|(k, v)| (k.clone(), str_of(v))).collect()),
        // Sin `env`: mapa vacío (NO el `.env`/environ del proceso — no hay proceso).
        _ => Some(HashMap::new()),
    };
    let ceiling = match req.get("ceiling") {
        Some(Value::String(s)) => synsema_wasm::parse_ceiling(s).map_err(|e| format!("ceiling: {}", e))?,
        Some(Value::Bool(true)) => synsema_wasm::parse_ceiling("sandbox").map_err(|e| format!("ceiling: {}", e))?,
        _ => None,
    };
    // `"labels": true` enciende las etiquetas de flujo; `"result": "<var>"` pide
    // El valor final de esa variable global CON etiquetas (ver `labelled_json`).
    let labels = req.get("labels").and_then(Value::as_bool).unwrap_or(false);
    let result = req.get("result").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    // La entrada del host por API: `"input": {"var": "x", "value": <json>,
    // "sources": {"clave": ["principal", …]}}`; el motor la liga como global y etiqueta las
    // fuentes desde Rust (nada inyectado al fuente).
    let (input, sources) = match req.get("input") {
        None | Some(Value::Null) => (None, Vec::new()),
        Some(Value::Object(inp)) => {
            let var = inp.get("var").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| "input.var (the variable name) is required".to_string())?.to_string();
            let value = inp.get("value").cloned().unwrap_or(Value::Null);
            let mut sources = Vec::new();
            if let Some(Value::Object(src)) = inp.get("sources") {
                for (k, v) in src {
                    let principals: Vec<String> = v
                        .as_array()
                        .ok_or_else(|| format!("input.sources.{}: expected a list of principals", k))?
                        .iter()
                        .map(|p| p.as_str().map(str::to_string).ok_or_else(|| format!("input.sources.{}: principals are texts", k)))
                        .collect::<Result<_, _>>()?;
                    sources.push((k.clone(), principals));
                }
            }
            (Some((var, value)), sources)
        }
        Some(_) => return Err("input must be an object {var, value, sources?}".to_string()),
    };
    // Este artefacto no tiene FS en ningún host (los archivos van por `env`/fuente).
    // v0.6.45 (D2): `"max_steps"` y `"max_memory_mb"` (enteros positivos) — los límites de la corrida.
    let limit = |k: &str| -> Result<Option<u64>, String> {
        match req.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v.as_u64().filter(|n| *n > 0).map(Some).ok_or_else(|| format!("{} must be a positive integer", k)),
        }
    };
    let max_steps = limit("max_steps")?;
    let max_memory_mb = limit("max_memory_mb")?;
    // v0.6.46 (E3b): `"trusted": {"nombre": "fuente"}` y `"trusted_ceiling": "<cap-set>"`.
    let trusted: Vec<(String, String)> = match req.get("trusted") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(m)) => m
            .iter()
            .map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())).ok_or_else(|| format!("trusted.{}: expected the module source as text", k)))
            .collect::<Result<_, _>>()?,
        Some(_) => return Err("trusted must be an object {name: source}".to_string()),
    };
    let trusted_ceiling = match req.get("trusted_ceiling") {
        Some(Value::String(s)) => synsema_wasm::parse_ceiling(s).map_err(|e| format!("trusted_ceiling: {}", e))?,
        _ => None,
    };
    // v0.6.46 (E6): `"auditor": "<pública X25519 en base64url>"` y `"sealed_bytes": n` — el recibo
    // sellado de la corrida, en `receipt`.
    let auditor = match req.get("auditor") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(synsema_stdlib::sealed::parse_auditor_key(s).map_err(|e| format!("auditor: {}", e))?),
        Some(_) => return Err("auditor must be the X25519 public key in base64url".to_string()),
    };
    let sealed_bytes = match req.get("sealed_bytes") {
        None | Some(Value::Null) => None,
        Some(v) => Some(synsema_stdlib::sealed::sealed_bytes_from(Some(&v.to_string())).map_err(|e| e.replace("SYNSEMA_RECEIPT_SEALED_BYTES", "sealed_bytes"))?),
    };
    Ok(RunOptions { filename, env, ceiling, no_fs: true, labels, result, input, sources, max_steps, max_memory_mb, trusted, trusted_ceiling, auditor, sealed_bytes })
}

fn install_host(req: &Map<String, Value>) {
    let mut offers = HashSet::new();
    if let Some(Value::Object(h)) = req.get("host") {
        for (k, v) in h {
            if v.as_bool().unwrap_or(false) {
                offers.insert(k.clone());
            }
        }
    }
    hostcap::install(Some(Rc::new(WebHost { offers })));
}

fn audit_json(audit: &[synsema_wasm::AuditEntry]) -> Value {
    Value::Array(
        audit
            .iter()
            .map(|a| json!({"capability": a.capability, "granted": a.granted, "source": a.source, "reason": a.reason, "origin": a.origin}))
            .collect(),
    )
}

fn source_of(req: &Map<String, Value>) -> Result<String, String> {
    match req.get("source") {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err("missing `source` (the program text)".to_string()),
    }
}

fn dispatch(req: &Map<String, Value>) -> Value {
    let op = req.get("op").and_then(Value::as_str).unwrap_or("run");
    match op {
        "version" => json!({"version": synsema_wasm::version()}),
        "check" => {
            let source = match source_of(req) {
                Ok(s) => s,
                Err(e) => return err_response(&e),
            };
            let filename = req.get("filename").and_then(Value::as_str).unwrap_or("<embedded>");
            let r = synsema_wasm::check(&source, filename);
            json!({"ok": r.ok, "errors": r.errors})
        }
        "run" | "test" | "handle" => {
            let source = match source_of(req) {
                Ok(s) => s,
                Err(e) => return err_response(&e),
            };
            let opts = match opts_from(req) {
                Ok(o) => o,
                // El prefijo lo pone cada opción (`ceiling: …`, `max_steps must be …`).
                Err(e) => return err_response(&e),
            };
            fence_clock(opts.labels);
            install_host(req);
            match op {
                "run" => {
                    let r = synsema_wasm::run(&source, &opts);
                    let mut out = Map::new();
                    // v0.6.46 (E6): el recibo sellado va primero (el host lo entrega antes que la salida).
                    if let Some(receipt) = &r.receipt {
                        out.insert("receipt".into(), receipt.clone());
                    }
                    out.insert("ok".into(), json!(r.ok));
                    out.insert("output".into(), json!(r.output));
                    out.insert("errors".into(), json!(r.errors));
                    out.insert("audit".into(), audit_json(&r.audit));
                    out.insert("llm_tokens".into(), json!(r.llm_tokens));
                    // Ronda 3 (M3): con una rama o un valor privado en la corrida, `steps` no se
                    // publica (cuántos pasos dio dependía del dato), como en el nativo.
                    out.insert(
                        "steps".into(),
                        if opts.labels && r.private_seen { Value::Null } else { json!(r.steps) },
                    );
                    // v0.6.42 — el código de salida, con el mismo nombre que `run --format json`:
                    // el de `exit(code)` si lo pidió, si no 0/1 según `ok`.
                    out.insert("exit".into(), json!(r.exit_code.unwrap_or(if r.ok { 0 } else { 1 })));
                    // Sólo cuando el host lo pidió (`"result"`), y `null` si la
                    // variable no quedó ligada o la corrida falló.
                    if opts.result.is_some() {
                        out.insert("result".into(), r.result.clone().unwrap_or(Value::Null));
                    }
                    if opts.labels {
                        out.insert("declassify".into(), Value::Array(r.declassify.iter().map(|d| d.to_json()).collect()));
                        out.insert("private_seen".into(), json!(r.private_seen));
                    }
                    Value::Object(out)
                }
                "test" => {
                    let r = synsema_wasm::test(&source, &opts);
                    json!({"ok": r.failed == 0, "passed": r.passed, "failed": r.failed, "lines": r.lines, "audit": audit_json(&r.audit)})
                }
                _ => {
                    let Some(Value::Object(rq)) = req.get("request") else {
                        return err_response("handle: missing `request` {method, path, headers, body}");
                    };
                    let body: Vec<u8> = match (rq.get("body_base64"), rq.get("body")) {
                        (Some(Value::String(b64)), _) => base64_decode(b64),
                        (_, Some(Value::String(s))) => s.clone().into_bytes(),
                        _ => Vec::new(),
                    };
                    let hreq = HttpRequestIn {
                        method: rq.get("method").and_then(Value::as_str).unwrap_or("GET").to_string(),
                        path: rq.get("path").and_then(Value::as_str).unwrap_or("/").to_string(),
                        headers: json_to_pairs(rq.get("headers")),
                        body,
                        client_ip: rq.get("ip").and_then(Value::as_str).unwrap_or("").to_string(),
                    };
                    let r = synsema_wasm::handle(&source, &opts, &hreq);
                    let mut out = Map::new();
                    out.insert("status".into(), json!(r.response.status));
                    out.insert("content_type".into(), json!(r.response.content_type));
                    out.insert("headers".into(), pairs_to_json(&r.response.headers));
                    match String::from_utf8(r.response.body.clone()) {
                        Ok(s) => {
                            out.insert("body".into(), json!(s));
                        }
                        Err(_) => {
                            out.insert("body_base64".into(), json!(base64_encode(&r.response.body)));
                        }
                    }
                    out.insert("log".into(), json!(r.log));
                    out.insert("errors".into(), json!(r.errors));
                    out.insert("audit".into(), audit_json(&r.audit));
                    Value::Object(out)
                }
            }
        }
        other => err_response(&format!("unknown op {:?} (expected run|test|check|handle|version)", other)),
    }
}

/// Procesa un request JSON y devuelve la respuesta como JSON (la lógica de
/// `synsema_call`, usable desde Rust nativo en los tests).
pub fn call_json(request: &str) -> String {
    init_once();
    // v0.6.45 (D2; ronda 2, M1): ninguna llamada hereda los límites de otra. Se desarman al entrar y
    // al salir: `test` y un error de `bind_input` volvían sin desarmar, y la llamada siguiente (aun
    // sin límites, o el `synsema_alloc` del host para escribirle el pedido) moría por el tope de la
    // anterior. Este artefacto cuenta la memoria (el allocator de arriba): `maxMemoryMb` se cumple,
    // también cuando el embebedor llama acá sin pasar por `synsema_call` (el guest de Vela).
    #[cfg(target_arch = "wasm32")]
    {
        synsema_core::wasm_limits::COUNTING.store(true, std::sync::atomic::Ordering::Relaxed);
        synsema_core::wasm_limits::disarm();
        synsema_core::wasm_limits::HIT.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    seed_run_rng();
    // v0.6.46 (E6.4): en wasip1 (el guest de Vela), el mismo generador por llamada.
    synsema_stdlib::webauth::begin_call_entropy();
    IN_CALL.with(|c| c.set(true));
    let resp = match serde_json::from_str::<Value>(request) {
        Ok(Value::Object(m)) => dispatch(&m),
        Ok(_) => err_response("the request must be a JSON object"),
        Err(e) => err_response(&format!("invalid request JSON: {}", e)),
    };
    #[cfg(target_arch = "wasm32")]
    synsema_core::wasm_limits::disarm();
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    end_run_rng();
    synsema_stdlib::webauth::end_call_entropy();
    IN_CALL.with(|c| c.set(false));
    fence_clock(false);
    hostcap::install(None);
    resp.to_string()
}

/// La entrada del módulo: `req` = JSON UTF-8; devuelve `[u32 LE len][json]` (liberar
/// con `synsema_free(ptr, 4 + len)`).
///
/// # Safety
/// `req_ptr`/`req_len` deben describir bytes válidos en la memoria del guest.
#[no_mangle]
pub unsafe extern "C" fn synsema_call(req_ptr: *const u8, req_len: u32) -> *mut u8 {
    let bytes = std::slice::from_raw_parts(req_ptr, req_len as usize);
    let req = String::from_utf8_lossy(bytes);
    let out = call_json(&req);
    pack(out.as_bytes())
}

// =========================================================
// base64 (estándar, con padding) — para bodies binarios en la frontera
// =========================================================

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn base64_decode(s: &str) -> Vec<u8> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let Some(v) = val(c) else { continue };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    out
}

// Silencia el warning de `Interpreter` no usado en el build nativo (documental).
#[allow(dead_code)]
fn _ty(_: &Interpreter) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", &[0u8, 255, 128, 7]] {
            assert_eq!(base64_decode(&base64_encode(data)), data);
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn abi_run_collects_output_and_audit() {
        let r = call_json(r#"{"op":"run","source":"print(1 + 2)\nrequire random\nprint(random_int(1, 1))","filename":"t.syn"}"#);
        let v: Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["ok"], true, "{}", r);
        assert_eq!(v["output"], json!(["3", "1"]));
        let caps: Vec<String> = v["audit"].as_array().unwrap().iter().map(|a| a["capability"].as_str().unwrap().to_string()).collect();
        assert!(caps.iter().any(|c| c.contains("random")), "{:?}", caps);
    }

    #[test]
    fn abi_ceiling_denies_and_errors_are_data() {
        let r = call_json(r#"{"op":"run","source":"require random\nprint(random())","ceiling":"sandbox"}"#);
        let v: Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["errors"][0].as_str().unwrap().contains("Capability not granted: random"), "{}", r);
        let r = call_json(r#"{"op":"run","source":"let x be"}"#);
        let v: Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["errors"][0].as_str().unwrap().contains("error"), "{}", r);
    }

    #[test]
    fn abi_check_test_version_and_no_host() {
        let v: Value = serde_json::from_str(&call_json(r#"{"op":"check","source":"print(1)"}"#)).unwrap();
        assert_eq!(v["ok"], true);
        // Con `labels` y `result`, el valor final vuelve CON etiquetas y el
        // `print` de un privado sale redactado; la lista de declassify acompaña.
        let src = "let s be private({\"amount\": 5, \"note\": \"x\"}, \"app\")
let out be {\"state\": s, \"fee\": 3, \"pub\": declassify(s[\"amount\"] + 1, \"fee is public\")}
print(s)";
        let req = json!({"op":"run","source":src,"labels":true,"result":"out","ceiling":"stdout,declassify=app"});
        let v: Value = serde_json::from_str(&call_json(&req.to_string())).unwrap();
        assert_eq!(v["ok"], json!(true), "{}", v);
        assert_eq!(v["output"][0], json!("private(app)"));
        assert_eq!(v["result"]["state"]["$private"], json!(["app"]));
        assert_eq!(v["result"]["state"]["value"]["amount"], json!(5));
        assert_eq!(v["result"]["fee"], json!(3));
        assert_eq!(v["result"]["pub"], json!(6));
        assert_eq!(v["declassify"][0]["reason"], json!("fee is public"));
        assert_eq!(v["declassify"][0]["from"], json!(["app"]));
        // Entrada por API con fuentes etiquetadas desde Rust; una `task private` del programa
        // No puede sombrear el etiquetado. M12: una clave `$bytes` del usuario viaja escapada.
        let src = "task private(v, p)\n    give v\n";
        let req = json!({"op":"run","source":"let out be {\"st\": __in[\"state\"], \"pub\": __in[\"sender\"], \"note\": __in[\"payload\"], \"n\": __in[\"state\"][\"balances\"][\"a\"] + 1}","labels":true,"result":"out","input":{"var":"__in","value":{"state":{"balances":{"a":1}},"sender":"0xab","payload":{"$bytes":"aGk=","$private":["x"]}},"sources":{"state":["app"],"payload":["app"]}}});
        let v: Value = serde_json::from_str(&call_json(&req.to_string())).unwrap();
        assert_eq!(v["ok"], json!(true), "{}", v);
        assert_eq!(v["result"]["st"]["$private"], json!(["app"]));
        assert_eq!(v["result"]["pub"], json!("0xab"));
        assert_eq!(v["result"]["note"]["$private"], json!(["app"]));
        assert_eq!(v["result"]["note"]["value"]["$$bytes"], json!("aGk="), "{}", v);
        assert_eq!(v["result"]["note"]["value"]["$$private"], json!(["x"]));
        assert_eq!(v["result"]["n"]["$private"], json!(["app"]));
        assert_eq!(v["result"]["n"]["value"], json!(2));
        assert_eq!(v["private_seen"], json!(true), "{}", v);
        let _ = src;
        // Ronda 2, MEDIO 5: la ruta `SynValue::Server` (`ok(...)`) tampoco puede fabricar un
        // marcador: un mapa del sender con claves `$` sale escapado igual que por el brazo Map.
        let req = json!({"op":"run","source":"let out be ok({\"$private\": [\"x\"], \"value\": 1, \"$bytes\": \"aGk=\"})","labels":true,"result":"out"});
        let v: Value = serde_json::from_str(&call_json(&req.to_string())).unwrap();
        assert_eq!(v["ok"], json!(true), "{}", v);
        let body = v["result"]["value"].clone();
        assert_eq!(body["$$private"], json!(["x"]), "{}", v["result"]);
        assert_eq!(body["$$bytes"], json!("aGk="));
        assert!(body.get("$private").is_none());
        // Fuentes sin labels → error, no silencio.
        let v: Value = serde_json::from_str(&call_json(r#"{"op":"run","source":"print(1)","input":{"var":"x","value":{"a":1},"sources":{"a":["p"]}}}"#)).unwrap();
        assert_eq!(v["ok"], json!(false));
        assert!(v["errors"][0].as_str().unwrap().contains("labels"), "{}", v);
        // Sin `labels`, `private` es un error claro y no hay `result` si no se pidió.
        let v: Value = serde_json::from_str(&call_json(r#"{"op":"run","source":"let x be private(1, \"a\")"}"#)).unwrap();
        assert_eq!(v["ok"], json!(false));
        assert!(v["errors"][0].as_str().unwrap().contains("labels are off"), "{}", v);
        assert!(v.get("result").is_none());
        let v: Value = serde_json::from_str(&call_json(r#"{"op":"version"}"#)).unwrap();
        assert!(v["version"].as_str().unwrap().starts_with('v'));
        let v: Value = serde_json::from_str(&call_json(r#"{"op":"test","source":"test \"suma\"\n    assert(1 + 1 == 2)"}"#)).unwrap();
        assert_eq!(v["passed"], 1, "{}", v);
        // Sin host: fetch pasa el gate net y falla en el transporte, con la verdad. OJO:
        // bajo `cargo test --workspace` las features se unifican y este crate linkea el
        // http.rs REAL (sockets) — el destino es 127.0.0.1:9 (connection refused), nunca
        // la red pública: el test no depende del entorno y en ambos transportes la
        // respuesta trae `error` y `ok = false`.
        let v: Value = serde_json::from_str(&call_json(r#"{"op":"run","source":"require net(\"127.0.0.1\")\nlet r be http_get(\"http://127.0.0.1:9/\")\nprint(contains(keys(r), \"error\"))\nprint(r[\"ok\"])"}"#)).unwrap();
        assert_eq!(v["ok"], true, "{}", v);
        assert_eq!(v["output"], json!(["true", "false"]), "{}", v);
    }

    #[test]
    fn abi_handle_routes_a_request() {
        let src = "require serve(8080)\nserve on 8080\n    route \"GET /hello/:name\"\n        give {\"hi\": params.name}\n";
        let req = json!({"op":"handle","source":src,"request":{"method":"GET","path":"/hello/ana?x=1","headers":[["accept","application/json"]],"body":""}});
        let v: Value = serde_json::from_str(&call_json(&req.to_string())).unwrap();
        assert_eq!(v["status"], 200, "{}", v);
        assert_eq!(v["body"], json!("{\"hi\": \"ana\"}"));
        let req = json!({"op":"handle","source":src,"request":{"method":"POST","path":"/hello/ana","headers":[],"body":""}});
        let v: Value = serde_json::from_str(&call_json(&req.to_string())).unwrap();
        assert_eq!(v["status"], 405, "{}", v);
    }
}

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

// =========================================================
// Imports del host (con fallbacks nativos para `cargo test --workspace`)
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
// Memoria: buffers `[u32 LE len][bytes]`
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

fn str_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

impl HostProvider for WebHost {
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
        let body = match r.get("body_base64").and_then(Value::as_str) {
            Some(b64) => String::from_utf8_lossy(&base64_decode(b64)).to_string(),
            None => r.get("body").map(str_of).unwrap_or_default(),
        };
        Some(Ok(HttpResult {
            status,
            ok: (200..300).contains(&status),
            body,
            headers: json_to_pairs(r.get("headers")),
            error: None,
        }))
    }

    fn kv_get(&self, ns: &str, key: &str) -> Option<Option<String>> {
        if !self.offers("kv") {
            return None;
        }
        let r = host_call_json("kv_get", &json!({"ns": ns, "key": key}))?;
        Some(r.get("value").and_then(Value::as_str).map(|s| s.to_string()))
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
    fn kv_list(&self, ns: &str) -> Option<Vec<String>> {
        if !self.offers("kv") {
            return None;
        }
        let r = host_call_json("kv_list", &json!({"ns": ns}))?;
        Some(
            r.get("keys")
                .and_then(Value::as_array)
                .map(|a| a.iter().map(str_of).collect())
                .unwrap_or_default(),
        )
    }
    fn llm(&self, op: &str, prompt: &str) -> Option<HostLlmResult> {
        if !self.offers("llm") {
            return None;
        }
        let r = host_call_json("llm", &json!({"op": op, "prompt": prompt}))?;
        let content = match &r {
            Value::String(s) => s.clone(),
            other => other.get("content").map(str_of).unwrap_or_default(),
        };
        let tokens = r.get("tokens").and_then(Value::as_u64).unwrap_or(0);
        Some(HostLlmResult { content, tokens })
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
// Entropía + reloj + pausa del host
// =========================================================

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn host_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    let rc = unsafe { imports::host_random_fill(buf.as_mut_ptr(), buf.len() as u32) };
    if rc == 0 {
        Ok(())
    } else {
        // Código custom (getrandom reserva el rango ≥ CUSTOM_START para el embebedor).
        let code = core::num::NonZeroU32::new(getrandom::Error::CUSTOM_START + 1).expect("non-zero");
        Err(getrandom::Error::from(code))
    }
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
    synsema_core::clock::set_clock(Some(Box::new(|| unsafe { imports::host_now_ms() } / 1000.0)));
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
        Some(Value::String(s)) => synsema_wasm::parse_ceiling(s)?,
        Some(Value::Bool(true)) => synsema_wasm::parse_ceiling("sandbox")?,
        _ => None,
    };
    // Este artefacto no tiene FS en ningún host (los archivos van por `env`/fuente).
    Ok(RunOptions { filename, env, ceiling, no_fs: true })
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
            .map(|a| json!({"capability": a.capability, "granted": a.granted, "source": a.source, "reason": a.reason}))
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
                Err(e) => return err_response(&format!("ceiling: {}", e)),
            };
            install_host(req);
            match op {
                "run" => {
                    let r = synsema_wasm::run(&source, &opts);
                    json!({"ok": r.ok, "output": r.output, "errors": r.errors, "audit": audit_json(&r.audit), "llm_tokens": r.llm_tokens})
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
    let resp = match serde_json::from_str::<Value>(request) {
        Ok(Value::Object(m)) => dispatch(&m),
        Ok(_) => err_response("the request must be a JSON object"),
        Err(e) => err_response(&format!("invalid request JSON: {}", e)),
    };
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
        let v: Value = serde_json::from_str(&call_json(r#"{"op":"version"}"#)).unwrap();
        assert!(v["version"].as_str().unwrap().starts_with('v'));
        let v: Value = serde_json::from_str(&call_json(r#"{"op":"test","source":"test \"suma\"\n    assert 1 + 1 == 2"}"#)).unwrap();
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

//! Protocolo host ↔ intérprete (WASM fase 2, F2): lo que un host embebedor puede
//! OFRECER al programa — transporte HTTP, un KV durable, un LLM, un log, el reloj —
//! sin que Synsema implemente el transporte. El intérprete gatea cada uso con el
//! MISMO CapabilitySet de siempre: el host ofrece, el programa declara (`require
//! net("host")`, `require memory("x")`, `require llm`) y el techo del embebedor
//! (`ceiling`) sigue mandando. Ningún método del provider se llama sin pasar antes
//! por `caps.require`.
//!
//! Todo es opcional: un método no implementado devuelve `None` y el builtin falla
//! con la verdad del entorno ("this host provides no http transport"), exactamente
//! como los stubs del perfil puro. Módulo PURO (sin sockets, sin FS): compila en los
//! dos perfiles; el nativo simplemente no instala provider.
//!
//! Instalación: `hostcap::install(Rc<dyn HostProvider>)` — por hilo (thread_local),
//! porque el intérprete es single-thread y los hosts wasm también.

use std::cell::RefCell;
use std::rc::Rc;

pub use crate::http_common::HttpResult;

/// Una request HTTP tal como la ve el host: ya pasó el gate `net(host)` y la query
/// ya está incorporada al URL. `body` son bytes crudos (texto o binario).
pub struct HostHttpRequest<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    pub body: Option<&'a [u8]>,
    pub timeout_secs: u64,
}

/// Respuesta de una op LLM del host: contenido + tokens consumidos (0 si el host
/// no los reporta) — alimenta `llm_usage()` igual que un provider nativo.
pub struct HostLlmResult {
    pub content: String,
    pub tokens: u64,
}

/// Lo que el host puede prestar. Cada método tiene default `None` (= "no lo
/// ofrezco"): un host implementa sólo lo que quiere prestar.
pub trait HostProvider {
    /// ¿El host ofrece `what`? (`"http"`, `"kv"`, `"llm"`, `"log"`, `"sleep"`). Lo
    /// consulta el wiring al arrancar para cablear (o no) el callback LLM y los
    /// stores de memoria — sin hacer una llamada real. Default: nada.
    fn offers(&self, _what: &str) -> bool {
        false
    }
    /// Transporte HTTP. `None` = el host no ofrece red; `Some(Err)` = error de
    /// transporte (DNS, timeout…) que el builtin devuelve como `{error: …}`.
    fn http(&self, _req: &HostHttpRequest<'_>) -> Option<Result<HttpResult, String>> {
        None
    }
    /// KV durable por namespace (`ns` = nombre declarado en `require memory("x")`, o
    /// `"state"` para `state_*`). `None` = sin almacenamiento durable.
    fn kv_get(&self, _ns: &str, _key: &str) -> Option<Option<String>> {
        None
    }
    fn kv_set(&self, _ns: &str, _key: &str, _value: &str) -> Option<Result<(), String>> {
        None
    }
    fn kv_delete(&self, _ns: &str, _key: &str) -> Option<Result<(), String>> {
        None
    }
    /// Claves de un namespace (para `state_all`).
    fn kv_list(&self, _ns: &str) -> Option<Vec<String>> {
        None
    }
    /// Op LLM (`reason`/`decide`/`analyze`/`generate`/`step`…) → contenido.
    fn llm(&self, _op: &str, _prompt: &str) -> Option<HostLlmResult> {
        None
    }
    /// Una línea de diagnóstico (los `warning:` que en nativo van a stderr).
    /// `false` = el host no ofrece log (se descarta).
    fn log(&self, _line: &str) -> bool {
        false
    }
    /// Pausa (segundos). `false` = el host no ofrece pausa (no-op).
    fn sleep(&self, _secs: f64) -> bool {
        false
    }
    /// Sink del audit fail-loud de `reveal`/`sign`/`wallet`/`spend` (una línea append-only
    /// por evento en el log `log`, p. ej. `sign.log`). Un host sin filesystem (browser,
    /// edge) lo respalda con lo que tenga (kv); `None` = no lo ofrece → esas operaciones
    /// se niegan, porque sin audit no hay firma/gasto/revelación (§7).
    fn audit_append(&self, _log: &str, _line: &str) -> Option<Result<(), String>> {
        None
    }
}

thread_local! {
    static PROVIDER: RefCell<Option<Rc<dyn HostProvider>>> = const { RefCell::new(None) };
}

/// Instala el provider del host para este hilo (reemplaza al anterior).
pub fn install(p: Option<Rc<dyn HostProvider>>) {
    PROVIDER.with(|s| *s.borrow_mut() = p);
}

/// El provider instalado, si hay.
pub fn provider() -> Option<Rc<dyn HostProvider>> {
    PROVIDER.with(|s| s.borrow().clone())
}

/// Log de diagnóstico: al host si lo ofrece; si no, a stderr (que en un host sin SO
/// simplemente se pierde — mejor que un panic).
pub fn log(line: &str) {
    if let Some(p) = provider() {
        if p.log(line) {
            return;
        }
    }
    eprintln!("{}", line);
}

/// Mensaje canónico cuando el host no ofrece una capacidad — nombra el builtin, la
/// causa real y el fix (el embebedor la ofrece, o el binario nativo).
pub fn not_offered(builtin: &str, what: &str, hook: &str) -> String {
    format!(
        "{}: not available in this host — it provides no {} (the embedder can offer it \
         through the `{}` host hook, or run the program with the native `synsema` binary)",
        builtin, what, hook
    )
}

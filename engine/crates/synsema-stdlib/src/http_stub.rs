//! Stub del transporte HTTP para el build SIN `native` (perfil wasm: sin sockets).
//! Mismas firmas que los símbolos de http.rs que consumen los módulos puros
//! (blockchain_rpc/blockchain_btc_rpc) → esos módulos compilan enteros y sus
//! builtins PUROS (tx_eip1559, builders, etc.) siguen completos; los de red fallan
//! en runtime con un error claro en vez de desaparecer del lenguaje.
//! Sin `register_http_builtins`: este módulo no registra http_get/http_post/fetch. El
//! front-end wasm (synsema-wasm) los registra como stubs que fallan con un error claro
//! ("not available in the wasm profile — this build has no network sockets"), igual
//! que la familia de memoria: el nombre existe, el entorno no otorga `net`.

use synsema_core::types::SynValue;

pub const NO_SOCKETS: &str =
    "this build has no network sockets (wasm profile) — network builtins are unavailable";

/// Espeja `http::HttpResult` (mismos campos).
pub struct HttpResult {
    pub status: i64,
    pub ok: bool,
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub error: Option<String>,
}

fn no_sockets() -> HttpResult {
    HttpResult {
        status: 0,
        ok: false,
        body: String::new(),
        headers: Vec::new(),
        error: Some(NO_SOCKETS.to_string()),
    }
}

pub fn http_request(
    _method: &str,
    _url: &str,
    _headers: Option<&[(String, String)]>,
    _query: Option<&[(String, String)]>,
    _body: Option<&str>,
    _timeout_secs: u64,
) -> HttpResult {
    no_sockets()
}

pub(crate) fn http_request_body_bytes(
    _method: &str,
    _url: &str,
    _headers: Option<&[(String, String)]>,
    _body: &[u8],
    _timeout_secs: u64,
) -> HttpResult {
    no_sockets()
}

/// Idéntico al de http.rs (es puro): mapa de headers → pares, materializando
/// secrets (el borde del socket es donde el secret se expone; acá no hay socket,
/// pero el contrato de la firma se preserva para los callers compartidos).
pub(crate) fn header_pairs(v: Option<&SynValue>) -> Option<Vec<(String, String)>> {
    match v {
        Some(SynValue::Map(m)) => Some(
            m.borrow()
                .iter()
                .map(|(k, val)| match val {
                    SynValue::Secret(s) => (k.clone(), s.expose().to_string()),
                    other => (k.clone(), other.to_string()),
                })
                .collect(),
        ),
        _ => None,
    }
}

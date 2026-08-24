//! Transporte HTTP del build SIN `native` (perfil wasm: sin sockets). Mismas firmas
//! que los símbolos de http.rs que consumen los módulos puros (blockchain_rpc/
//! blockchain_btc_rpc/oidc) → esos módulos compilan enteros.
//!
//! WASM fase 2 (F3): el transporte es el `http` del HOST vía `hostcap` — si el
//! embebedor lo ofrece, `fetch`/`http_*`/RPC read-side funcionan de verdad; si no,
//! fallan con la verdad del entorno. El gate `net(host)` corre ANTES, en los
//! builtins compartidos de http_common (misma canonización que nativo). Los seis
//! builtins cliente se registran acá con `register_http_builtins`, igual que en el
//! perfil nativo — un solo registro, dos transportes.

use std::cell::RefCell;
use std::rc::Rc;

use synsema_capabilities::model::CapabilitySet;
use synsema_core::interpreter::Interpreter;

pub use crate::http_common::{err_result, header_pairs, require_net, HttpResult};
use crate::http_common::{register_http_client_builtins, url_with_query};
use crate::hostcap::{self, HostHttpRequest};

pub const NO_SOCKETS: &str =
    "this build has no network sockets (wasm profile) — network builtins are unavailable";

/// Sin transporte del host: la verdad del entorno, con el fix.
fn no_transport() -> HttpResult {
    err_result(
        "this host provides no http transport (wasm profile) — the embedder can offer one \
         through the `http` host hook, or run the program with the native `synsema` binary"
            .to_string(),
    )
}

fn via_host(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    body: Option<&[u8]>,
    timeout_secs: u64,
) -> HttpResult {
    let Some(p) = hostcap::provider() else { return no_transport() };
    let empty: [(String, String); 0] = [];
    let req = HostHttpRequest {
        method,
        url,
        headers: headers.unwrap_or(&empty),
        body,
        timeout_secs,
    };
    match p.http(&req) {
        None => no_transport(),
        Some(Ok(r)) => r,
        Some(Err(e)) => err_result(e),
    }
}

pub fn http_request(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    query: Option<&[(String, String)]>,
    body: Option<&str>,
    timeout_secs: u64,
) -> HttpResult {
    let full = url_with_query(url, query);
    via_host(method, &full, headers, body.map(str::as_bytes), timeout_secs)
}

pub(crate) fn http_request_body_bytes(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    body: &[u8],
    timeout_secs: u64,
) -> HttpResult {
    via_host(method, url, headers, Some(body), timeout_secs)
}

/// Los seis builtins cliente (`http`/`http_get`/`http_post`/`http_put`/`http_delete`/
/// `fetch`) sobre el transporte del host. Sin `mtls_identity` (identidad TLS del
/// proceso: no hay proceso ni TLS propio en este perfil).
pub fn register_http_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    register_http_client_builtins(interp, caps, http_request);
}

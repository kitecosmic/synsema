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
    // v0.6.54 (R3-3 de la ronda 3): los builtins http hablan http y https, como en nativo
    // (`connect_and_send`); `ftp://…` o `foo:bar://…` llegaban al hook, que puede hablarlos.
    // R4-1 de la ronda 4: adelante se quita lo que quita WHATWG (C0 y el espacio), no todo el
    // White_Space de Unicode: con `trim_start`, `"\u{3000}http://…"` llegaba al hook y el nativo
    // lo niega.
    let scheme = url
        .trim_start_matches(|c: char| c <= ' ')
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return err_result(format!("unsupported scheme '{}': only http and https are supported", scheme));
    }
    // v0.6.54 (§D de v0.6.51): una IP literal se juzga acá, con la misma regla que en nativo (una
    // dirección privada la tiene que nombrar cada capa); antes llegaba al hook sin chequeo, y el
    // hook no sabe si el programa la nombró. Un nombre que resuelve a una privada sigue siendo del hook.
    match crate::http_common::literal_ip_dest(url) {
        Ok(Some((host, port, ip))) => {
            if let Err(e) = crate::http_common::dest_check(&host, port, ip) {
                return err_result(e);
            }
        }
        Ok(None) => {}
        Err(e) => return err_result(e),
    }
    // v0.6.54 (R2-1 de la ronda 2): el host que chequeó `net` es el que va a leer el host; si un
    // navegador lo lee distinto (`http://evil\@good/`), es un error antes del hook. Va después
    // del chequeo de la IP literal, para que una privada diga por qué se niega.
    if let Err(e) = crate::http_common::host_reads_alike(url) {
        return err_result(e);
    }
    let empty: [(String, String); 0] = [];
    let req = HostHttpRequest {
        method,
        url,
        headers: headers.unwrap_or(&empty),
        body,
        timeout_secs,
        forbid_redirects: crate::http_common::request_forbids_redirects(),
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

/// v0.6.20 — transporte de los builtins cliente (body en bytes), vía el host.
fn host_transport(
    method: &str,
    url: &str,
    headers: Option<&[(String, String)]>,
    query: Option<&[(String, String)]>,
    body: Option<&[u8]>,
    timeout_secs: u64,
    tls: Option<&crate::http_common::TlsCheck>,
) -> HttpResult {
    // El `http` del embebedor no expone el certificado ni la conexión: no puede fijar la clave
    // ni atestar el servidor. Falla cerrado en vez de mandar el pedido sin eso.
    if tls.is_some() {
        return err_result("tls_pin and attested are not supported by the host transport of this profile (the embedder's http cannot see the server key)".to_string());
    }
    let full = url_with_query(url, query);
    via_host(method, &full, headers, body, timeout_secs)
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
    register_http_client_builtins(interp, caps, host_transport);
}

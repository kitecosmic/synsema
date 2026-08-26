//! Router y contrato de respuesta de `serve` — la parte PURA (sin sockets, sin FS,
//! sin threads): parseo de URL/query, match de rutas por especificidad, negociación
//! de formato, forma de la respuesta (`give` → status + body), `Ctx` del request,
//! form bodies (urlencoded/multipart), tipos del dispatch, identidad del sujeto,
//! árbol de contenido + renderers HTML/MD/JSON, cookies entrantes y las bindings
//! (`request`/`query`/`params`/`read_body`) que ve un handler.
//!
//! Extraído verbatim de server.rs (y de runtime/serve.rs para las bindings) en la
//! fase 2 de WASM (F5): el handler-mode del perfil wasm (`handle(request) →
//! response`, edge/Workers) despacha con ESTE código — el mismo que el server
//! nativo — sin arrastrar hyper/tokio. server.rs lo re-exporta (`pub use
//! routing::*`) así que los callers no cambian.

#![allow(unused_imports)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use indexmap::IndexMap;
use synsema_core::interpreter::{BuiltinTask, Control, Interpreter, RuntimeError};
use synsema_core::types::{
    syn_bool, syn_bytes, syn_int, syn_map, syn_nothing, syn_text, ServerValue, SynValue,
};

use crate::json::{
    dumps, esc, is_node, json_to_syn, list_field, meta_get, node_field, node_int, node_str,
    node_to_json, obj, syn_to_json, Json,
};

// ---- constantes (movido verbatim desde server.rs) ----
pub const DEFAULT_LIMIT: i64 = 100;
pub const MAX_LIMIT: i64 = 1000;

// ---- RawResponse (movido verbatim desde server.rs) ----
pub struct RawResponse {
    pub body: Vec<u8>,
    pub content_type: String,
    pub status: u16,
}

impl RawResponse {
    pub fn text(body: impl Into<String>, content_type: impl Into<String>, status: u16) -> Self {
        RawResponse { body: body.into().into_bytes(), content_type: content_type.into(), status }
    }
}


// ---- URL + routing (movido verbatim desde server.rs) ----
// =========================================================
// URL helpers (unquote, query parse)
// =========================================================

pub fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodifica percent-encoding (`%XX`) como `urllib.parse.unquote` (UTF-8, lossy).
/// No toca `+` (eso es `unquote_plus`).
pub fn unquote(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Separa una URL en (path, query-map). Espeja `urlparse` + `parse_qs` con
/// `{k: v[-1]}` (último valor gana para claves repetidas).
pub fn parse_path_query(raw: &str) -> (String, IndexMap<String, String>) {
    let (path_part, query_part) = match raw.split_once('?') {
        Some((p, q)) => (p, q),
        None => (raw, ""),
    };
    // urlparse separa también el fragmento (#...); el path es hasta '?' o '#'.
    let path_part = path_part.split('#').next().unwrap_or(path_part);
    let mut query: IndexMap<String, String> = IndexMap::new();
    if !query_part.is_empty() {
        for pair in query_part.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            // parse_qs ignora claves vacías y reemplaza '+' por espacio.
            let key = unquote(&k.replace('+', " "));
            if key.is_empty() {
                continue;
            }
            let val = unquote(&v.replace('+', " "));
            query.insert(key, val); // último gana (parse_qs v[-1])
        }
    }
    (path_part.to_string(), query)
}

// =========================================================
// Routing / match (subsistema 1)
// =========================================================

/// Segmentos no vacíos de un path (split por '/').
pub fn segments(pattern: &str) -> Vec<&str> {
    pattern.split('/').filter(|s| !s.is_empty()).collect()
}

/// Rango de especificidad de cada segmento: estático(0) < :param(1) < *catchall(2).
/// Ordenar rutas por esta lista ascendente pone la más específica primero.
pub fn specificity(pattern: &str) -> Vec<i32> {
    segments(pattern)
        .iter()
        .map(|seg| {
            if seg.starts_with('*') {
                2
            } else if seg.starts_with(':') {
                1
            } else {
                0
            }
        })
        .collect()
}

/// True si el último segmento del patrón es un `:param` (puede tragarse un sufijo
/// de formato). Un literal o `*catchall` mantiene el valor con punto.
pub fn param_last_segment(pattern: &str) -> bool {
    segments(pattern).last().is_some_and(|s| s.starts_with(':'))
}

/// Devuelve los params capturados si `path` matchea `pattern`, o None.
/// Un `*name` es catch-all: debe ir último y captura el resto (≥1 segmento).
pub fn path_match(pattern: &str, path: &str) -> Option<IndexMap<String, String>> {
    let actual = segments(path);
    let segs = segments(pattern);
    let mut params: IndexMap<String, String> = IndexMap::new();
    for (i, pat_seg) in segs.iter().enumerate() {
        if let Some(name) = pat_seg.strip_prefix('*') {
            let rest = &actual[i..];
            if rest.is_empty() {
                return None;
            }
            let joined = rest.iter().map(|s| unquote(s)).collect::<Vec<_>>().join("/");
            params.insert(name.to_string(), joined);
            return Some(params);
        }
        if i >= actual.len() {
            return None;
        }
        let act_seg = actual[i];
        if let Some(name) = pat_seg.strip_prefix(':') {
            params.insert(name.to_string(), unquote(act_seg));
        } else if *pat_seg != act_seg {
            return None;
        }
    }
    if actual.len() != segs.len() {
        return None;
    }
    Some(params)
}

/// Sufijos de formato que seleccionan una representación de un valor `content()`.
pub const FORMAT_SUFFIXES: [(&str, &str); 3] = [("md", "md"), ("json", "json"), ("html", "html")];

/// Quita un `.md`/`.json`/`.html` final, devolviendo (path_lógico, formato|None).
pub fn split_format_suffix(path: &str) -> (String, Option<String>) {
    for (ext, fmt) in FORMAT_SUFFIXES {
        let dotted = format!(".{}", ext);
        if path.ends_with(&dotted)
            && path.len() > dotted.len()
            && !path[..path.len() - dotted.len()].ends_with('/')
        {
            return (path[..path.len() - dotted.len()].to_string(), Some(fmt.to_string()));
        }
    }
    (path.to_string(), None)
}

/// Mapea un header Accept a un formato de contenido. Default (incl. */*) = HTML.
pub fn negotiate_format(accept: &str) -> String {
    let a = accept.to_lowercase();
    if a.contains("text/markdown") && !a.contains("text/html") {
        return "md".to_string();
    }
    if a.contains("application/json") && !a.contains("text/html") {
        return "json".to_string();
    }
    "html".to_string()
}


// ---- contrato de respuesta, Ctx, forms, tipos del dispatch (movido verbatim desde server.rs) ----
// =========================================================
// Contrato de respuesta (paginación de colecciones)
// =========================================================

pub fn page_window(query: &IndexMap<String, String>) -> (i64, i64) {
    let mut limit = query.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(DEFAULT_LIMIT);
    if limit <= 0 {
        limit = DEFAULT_LIMIT;
    }
    if limit > MAX_LIMIT {
        limit = MAX_LIMIT;
    }
    let raw_cursor = query.get("cursor").or_else(|| query.get("offset"));
    let mut offset = raw_cursor.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    if offset < 0 {
        offset = 0;
    }
    (limit, offset)
}

pub fn envelope_from_page(items: Vec<Json>, count: i64, total: i64, limit: i64, offset: i64) -> Json {
    let next = offset + limit;
    let cursor = if next < total { Json::Int(next) } else { Json::Null };
    obj(vec![
        ("items", Json::Array(items)),
        ("count", Json::Int(count)),
        ("total", Json::Int(total)),
        ("cursor", cursor),
    ])
}

pub fn paginate(items: &[SynValue], query: &IndexMap<String, String>) -> Json {
    let total = items.len() as i64;
    let (limit, offset) = page_window(query);
    let start = offset.min(total).max(0) as usize;
    let end = (offset + limit).min(total).max(0) as usize;
    let page = &items[start..end];
    let page_json: Vec<Json> = page.iter().map(syn_to_json).collect();
    envelope_from_page(page_json, page.len() as i64, total, limit, offset)
}

/// Paginación lazy de `paged()`: sólo se trae la página (LIMIT/OFFSET) y `total`
/// viene de un COUNT(*), sin materializar la colección entera.
pub fn paginate_lazy(
    fetch: &synsema_core::types::PagedFetch,
    query: &IndexMap<String, String>,
) -> Result<Json, String> {
    let (limit, offset) = page_window(query);
    let (rows, total) = fetch(Some(limit), offset)?;
    let count = rows.len() as i64;
    let items: Vec<Json> = rows.iter().map(syn_to_json).collect();
    Ok(envelope_from_page(items, count, total, limit, offset))
}

/// Da forma a un give-value según el contrato (`_shape` del oráculo).
pub fn shape(value: Option<&SynValue>, query: &IndexMap<String, String>) -> Result<Json, String> {
    match value {
        None | Some(SynValue::Nothing) => Ok(Json::Null),
        Some(SynValue::Server(s)) if matches!(&**s, ServerValue::Paged(_)) => {
            if let ServerValue::Paged(fetch) = &**s {
                paginate_lazy(&**fetch, query)
            } else {
                unreachable!()
            }
        }
        Some(SynValue::List(l)) => Ok(paginate(&l.borrow(), query)),
        Some(v) => Ok(syn_to_json(v)),
    }
}

/// Convierte un give-value en (status, cuerpo) según el contrato. `_RAW` (html/
/// respond/render) se escribe verbatim; `_ENVELOPE` (ok/created/…) lleva status
/// explícito; el resto sigue la forma JSON (paginación de colecciones).
pub fn build_response(
    give: Option<&SynValue>,
    query: &IndexMap<String, String>,
) -> Result<(u16, ResponseBody), String> {
    if let Some(SynValue::Server(s)) = give {
        match &**s {
            ServerValue::Raw { body, content_type, status } => {
                return Ok((
                    *status as u16,
                    ResponseBody::Raw(RawResponse {
                        body: body.clone().into_bytes(),
                        content_type: content_type.clone(),
                        status: *status as u16,
                    }),
                ));
            }
            // binary(): body crudo verbatim al socket, sin negociación (ya es final).
            ServerValue::RawBytes { body, content_type, status } => {
                return Ok((
                    *status as u16,
                    ResponseBody::Raw(RawResponse {
                        body: body.clone(),
                        content_type: content_type.clone(),
                        status: *status as u16,
                    }),
                ));
            }
            ServerValue::Envelope { status, value } => {
                return Ok((*status as u16, ResponseBody::Json(shape(Some(value), query)?)));
            }
            ServerValue::Redirect { location, status } => {
                return Ok((
                    *status as u16,
                    ResponseBody::Redirect { location: location.clone(), status: *status as u16 },
                ));
            }
            _ => {}
        }
    }
    // `give bytes(...)` directo (sin binary()): octet-stream 200 (ergonomía). Para fijar
    // otro content-type se usa binary(). NO pasa por la forma JSON (sería base64).
    if let Some(SynValue::Bytes(b)) = give {
        return Ok((
            200,
            ResponseBody::Raw(RawResponse {
                body: b.to_vec(),
                content_type: "application/octet-stream".to_string(),
                status: 200,
            }),
        ));
    }
    Ok((200, ResponseBody::Json(shape(give, query)?)))
}

// =========================================================
// Tipos del dispatch (handlers inyectados por el motor)
// =========================================================

/// Contexto de una request (lo arma `dispatch`, lo consume el handler del motor).
pub struct Ctx {
    pub method: String,
    pub path: String,
    pub query: IndexMap<String, String>,
    pub params: IndexMap<String, String>,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// Body crudo (bytes exactos) para los casos en memoria — habilita `read_body_bytes`
    /// byte-exacto sin pasar por la decodificación lossy de `body`. Vacío cuando el body
    /// spilleó a disco (entonces `body_file` es la fuente cruda; ver §8.1).
    pub body_raw: Vec<u8>,
    pub body_file: Option<String>,
    pub json: Option<serde_json::Value>,
    pub client_ip: String,
    pub user: Option<SynValue>,
    /// Token de cancelación cooperativa de la request (timeout de handler / shutdown):
    /// el intérprete del handler lo adopta antes de correr el cuerpo.
    pub cancel: synsema_core::interpreter::CancelToken,
}

/// Ctx mínimo para el `errors with` de 404/405 (el error ocurre ANTES de armar el
/// ctx del handler): method/path/query/headers reales, params vacíos, user nothing.
#[allow(clippy::too_many_arguments)]
pub fn min_ctx(
    method: &str,
    path: &str,
    query: &IndexMap<String, String>,
    headers: &[(String, String)],
    body_str: &str,
    body_raw: &[u8],
    body_file: Option<&str>,
    client_ip: &str,
) -> Ctx {
    Ctx {
        method: method.to_string(),
        path: path.to_string(),
        query: query.clone(),
        params: IndexMap::new(),
        headers: headers.to_vec(),
        body: body_str.to_string(),
        body_raw: body_raw.to_vec(),
        body_file: body_file.map(|s| s.to_string()),
        json: None,
        client_ip: client_ip.to_string(),
        user: None,
        cancel: synsema_core::interpreter::CancelToken::new(),
    }
}

// =========================================================
// Form bodies (application/x-www-form-urlencoded + multipart/form-data)
// =========================================================

/// Parsea un body `application/x-www-form-urlencoded` → map (último valor gana,
/// como el query string). `+` → espacio, percent-decoding UTF-8 lossy.
pub fn parse_form_urlencoded(body: &str) -> IndexMap<String, String> {
    let mut out = IndexMap::new();
    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let key = unquote(&k.replace('+', " "));
        if key.is_empty() {
            continue;
        }
        out.insert(key, unquote(&v.replace('+', " ")));
    }
    out
}

/// Una parte de un body `multipart/form-data`: campo de texto (filename=None) o
/// archivo subido (filename + content_type + bytes crudos).
#[derive(Debug)]
pub struct FormPart {
    pub name: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

/// Extrae el boundary de un `Content-Type: multipart/form-data; boundary=...`.
pub fn multipart_boundary(content_type: &str) -> Option<String> {
    let ct = content_type.trim();
    if !ct.to_ascii_lowercase().starts_with("multipart/form-data") {
        return None;
    }
    for param in ct.split(';').skip(1) {
        let param = param.trim();
        if let Some(v) = param.strip_prefix("boundary=") {
            let v = v.trim().trim_matches('"');
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Parsea un body `multipart/form-data` (RFC 7578). Devuelve las partes en orden;
/// partes malformadas se saltean (un browser real no las produce). Los bytes de un
/// archivo se conservan EXACTOS (sin decodificación lossy).
pub fn parse_multipart(boundary: &str, body: &[u8]) -> Vec<FormPart> {
    let delim: Vec<u8> = [b"--", boundary.as_bytes()].concat();
    let mut parts = Vec::new();
    // Segmentos entre delimitadores.
    let mut sections: Vec<&[u8]> = Vec::new();
    let mut pos = 0usize;
    let mut starts: Vec<usize> = Vec::new();
    while pos + delim.len() <= body.len() {
        if &body[pos..pos + delim.len()] == delim.as_slice() {
            starts.push(pos);
            pos += delim.len();
        } else {
            pos += 1;
        }
    }
    for w in starts.windows(2) {
        sections.push(&body[w[0] + delim.len()..w[1]]);
    }
    for sec in sections {
        // Tras el delimitador viene \r\n (o `--` en el cierre, que no llega acá).
        let sec = sec.strip_prefix(b"\r\n").unwrap_or(sec);
        // Headers hasta \r\n\r\n.
        let hdr_end = match sec.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(i) => i,
            None => continue,
        };
        let head = String::from_utf8_lossy(&sec[..hdr_end]);
        let mut content = &sec[hdr_end + 4..];
        // El contenido termina en \r\n antes del próximo delimitador.
        if content.ends_with(b"\r\n") {
            content = &content[..content.len() - 2];
        }
        let mut name: Option<String> = None;
        let mut filename: Option<String> = None;
        let mut ctype: Option<String> = None;
        for line in head.split("\r\n") {
            let low = line.to_ascii_lowercase();
            if low.starts_with("content-disposition:") {
                for param in line.split(';').skip(1) {
                    let param = param.trim();
                    if let Some(v) = param.strip_prefix("name=") {
                        name = Some(v.trim_matches('"').to_string());
                    } else if let Some(v) = param.strip_prefix("filename=") {
                        filename = Some(v.trim_matches('"').to_string());
                    }
                }
            } else if low.starts_with("content-type:") {
                ctype = Some(line[13..].trim().to_string());
            }
        }
        if let Some(name) = name {
            parts.push(FormPart { name, filename, content_type: ctype, data: content.to_vec() });
        }
    }
    parts
}

/// Resultado de correr el cuerpo de una ruta.
pub enum GiveOutcome {
    /// `give <valor>` (o None si el handler no dio nada → nothing).
    Give(Option<SynValue>),
    /// Violación de `expect` → 400.
    Validation { message: String, field: Option<String> },
    /// Error no capturado → 500.
    Error(String),
}

pub type Handler = Arc<dyn Fn(&Ctx) -> GiveOutcome + Send + Sync>;
/// Hook de `auth with`: recibe el bearer token Y el contexto de la request (para
/// tasks de 2 parámetros — sesiones por cookie; ítem C de la tanda web-auth). El
/// motor decide por la aridad declarada del task si le pasa 1 o 2 argumentos.
pub type AuthHandler = Arc<dyn Fn(&str, &Ctx) -> Option<SynValue> + Send + Sync>;

/// `errors with <task>` — recibe (status, message, request-ctx) y devuelve el valor
/// que da FORMA al body del error (html()/render()/content()/map/redirect), o None
/// para el JSON por defecto. El runtime lo cablea igual que `auth with`.
pub type ErrorHandler = Arc<dyn Fn(i64, &str, &Ctx) -> Option<SynValue> + Send + Sync>;

/// El cliente del SSE se desconectó (escribir al socket falló).
pub struct StreamGone;
/// Emisor de eventos SSE: owned (posee un clone del socket + formatea data:/event:).
/// El motor lo recibe por valor y lo envuelve en su `stream_emit` hook.
pub type Emitter = Box<dyn FnMut(&SynValue, Option<&str>) -> Result<(), StreamGone>>;
/// Cómo terminó un stream (para el evento de error best-effort).
pub enum StreamEnd {
    Done,
    ClientGone,
    Error(String),
}
pub type StreamHandler = Arc<dyn Fn(&Ctx, Emitter) -> StreamEnd + Send + Sync>;
/// Handler de una ruta `socket` (WebSocket entrante): recibe el enlace al transporte
/// (un `ServerSocketLink` del server nativo, type-erased para que este módulo siga
/// siendo puro/compartido con wasm) y corre el cuerpo con el binding `socket`.
pub type SocketHandler = Arc<dyn Fn(&Ctx, Box<dyn std::any::Any + Send>) -> StreamEnd + Send + Sync>;

pub struct RouteSpec {
    pub method: String,
    pub path: String,
    pub param_names: Vec<String>,
    pub requires_auth: bool,
    pub streaming: bool,
    /// Ruta `socket` (WebSocket entrante).
    pub socket: bool,
    pub rate_limit: Option<(i64, f64)>,
    pub rate_zone: Option<String>,
    pub handler: Handler,
    pub stream_handler: Option<StreamHandler>,
    pub socket_handler: Option<SocketHandler>,
    /// Techo de vida del handler en segundos (`timeout` de la route o del serve);
    /// `None` = sin límite.
    pub timeout: Option<f64>,
    /// Lote 2 — reverse proxy: si está, la route forwardea al upstream (URL base).
    pub proxy_target: Option<String>,
    /// `rate_limit unlimited` explícito (para `/openapi.json`; el limiter ya lo trata como None).
    pub rate_unlimited: bool,
    /// Metadatos estáticos (expect/respuesta/capabilities) para `/openapi.json` y `/docs`.
    pub meta: synsema_core::route_meta::RouteMeta,
}

/// Cuerpo de una respuesta HTTP.
pub enum ResponseBody {
    Json(Json),
    Raw(RawResponse),
    /// `redirect()` — 3xx + header `Location` (sin body). El `Location` lo inyecta
    /// el dispatch en los headers extra; acá viaja solo el destino + status.
    Redirect { location: String, status: u16 },
}


// ---- header_value, identidad del sujeto, árbol de contenido + renderers (movido verbatim desde server.rs) ----
pub fn header_value(headers: &[(String, String)], name: &str) -> String {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(name) {
            return v.clone();
        }
    }
    String::new()
}

/// La IDENTIDAD del sujeto autenticado, desde el valor que devolvió el `auth with`
/// (T6). Convención — deliberadamente la forma que ya devuelven las piezas del
/// lenguaje, para que el caso feliz no requiera adaptadores:
///   - map con `id`  → `captoken_verify` devuelve exactamente eso;
///   - map con `sub` → un JWT/OIDC verificado (`jwt_verify`/`oidc_verify`);
///   - map con `keyid` → `http_signature_verify` (firma de request, T2);
///   - texto → se usa tal cual (el caso simple: el auth devuelve el nombre).
///
/// Cualquier otra forma → sin identidad: las cuotas caen al escudo por IP y el
/// gasto se imputa al proceso. Nunca se inventa un id (dos sujetos distintos no
/// pueden colapsar en el mismo bucket por una heurística).
pub fn identity_of(user: &SynValue) -> Option<String> {
    match user {
        SynValue::Text(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        SynValue::Map(m) => {
            let m = m.borrow();
            for key in ["id", "sub", "keyid"] {
                if let Some(v) = m.get(key) {
                    let s = v.to_string();
                    if !s.trim().is_empty() && !matches!(v, SynValue::Nothing) {
                        return Some(s.trim().to_string());
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// El techo de gasto DELEGADO al sujeto, si su `request.user` lo trae: el caveat
/// `spend` de un captoken verificado (`{caveats: {spend: {"USD": "10"}}}`). Lo
/// aplica el ledger además del techo del host (T6.4).
pub fn delegated_spend_of(user: &SynValue) -> Vec<(String, String)> {
    let SynValue::Map(m) = user else { return Vec::new() };
    let Some(SynValue::Map(cav)) = m.borrow().get("caveats").cloned() else {
        return Vec::new();
    };
    let Some(SynValue::Map(sp)) = cav.borrow().get("spend").cloned() else {
        return Vec::new();
    };
    let out: Vec<(String, String)> = sp
        .borrow()
        .iter()
        .map(|(unit, amount)| (unit.clone(), amount.to_string()))
        .collect();
    out
}

pub fn bearer_token(headers: &[(String, String)]) -> String {
    let auth = header_value(headers, "authorization");
    if auth.is_empty() {
        return String::new();
    }
    let mut parts = auth.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or("");
    if let Some(rest) = parts.next() {
        if scheme.eq_ignore_ascii_case("bearer") {
            return rest.trim().to_string();
        }
    }
    auth.trim().to_string()
}

// =========================================================
// Árbol de contenido semántico (vocabulario content()) + renderers
// =========================================================

// -- HTML (semántico + <head> desde la metadata) --

pub fn render_li(item: &SynValue) -> String {
    if is_node(item) {
        format!("<li>{}</li>", render_node_html(item))
    } else {
        format!("<li>{}</li>", esc(&item.to_string()))
    }
}

pub fn render_node_html(node: &SynValue) -> String {
    let kind = node_str(node, "kind");
    match kind.as_str() {
        "heading" => {
            let lvl = node_int(node, "level", 1).clamp(1, 6);
            format!("<h{0}>{1}</h{0}>\n", lvl, esc(&node_str(node, "text")))
        }
        "prose" => format!("<p>{}</p>\n", esc(&node_str(node, "text"))),
        "list" | "ordered_list" => {
            let tag = if kind == "ordered_list" { "ol" } else { "ul" };
            let inner: String = list_field(node, "items").iter().map(render_li).collect();
            format!("<{0}>{1}</{0}>\n", tag, inner)
        }
        "link" => format!(
            "<a href=\"{}\">{}</a>\n",
            esc(&node_str(node, "href")),
            esc(&node_str(node, "text"))
        ),
        "image" => format!(
            "<img src=\"{}\" alt=\"{}\">\n",
            esc(&node_str(node, "src")),
            esc(&node_str(node, "alt"))
        ),
        "section" => {
            let inner: String =
                list_field(node, "nodes").iter().filter(|n| is_node(n)).map(render_node_html).collect();
            format!("<section>\n{}</section>\n", inner)
        }
        "code" => {
            let lang = node_str(node, "lang");
            let cls = if lang.is_empty() {
                String::new()
            } else {
                format!(" class=\"language-{}\"", esc(&lang))
            };
            format!("<pre><code{}>{}</code></pre>\n", cls, esc(&node_str(node, "text")))
        }
        "raw" => node_str(node, "html"), // escape hatch: NO escapado
        // chart() (Batch 8): el SVG inline pre-renderizado por el MISMO renderer de
        // chart_svg (mismos bytes); todo texto de datos ya viene escapado (G4).
        "chart" => format!("{}\n", node_str(node, "svg").trim_end()),
        "page" => list_field(node, "nodes").iter().filter(|n| is_node(n)).map(render_node_html).collect(),
        _ => String::new(),
    }
}

pub fn render_html(tree: &SynValue) -> String {
    let is_page = node_str(tree, "kind") == "page";
    let meta = if is_page { node_field(tree, "meta") } else { None };
    let title = meta.as_ref().and_then(|m| meta_get(m, "title"));
    let description = meta.as_ref().and_then(|m| meta_get(m, "description"));
    // Optional stylesheet for the HTML representation only (head-only; the
    // Markdown/JSON representations of the same content() are unaffected).
    let stylesheet = meta.as_ref().and_then(|m| meta_get(m, "stylesheet"));
    let mut head = vec![
        "<meta charset=\"utf-8\">".to_string(),
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">".to_string(),
    ];
    if let Some(t) = &title {
        head.push(format!("<title>{}</title>", esc(t)));
    }
    if let Some(d) = &description {
        head.push(format!("<meta name=\"description\" content=\"{}\">", esc(d)));
    }
    if let Some(s) = &stylesheet {
        head.push(format!("<link rel=\"stylesheet\" href=\"{}\">", esc(s)));
    }
    if title.is_some() || description.is_some() {
        let mut ld: Vec<(&str, Json)> = vec![
            ("@context", Json::Str("https://schema.org".into())),
            ("@type", Json::Str("WebPage".into())),
        ];
        if let Some(t) = &title {
            ld.push(("name", Json::Str(t.clone())));
        }
        if let Some(d) = &description {
            ld.push(("description", Json::Str(d.clone())));
        }
        // Escapar < > & como \uXXXX para no romper el <script> (XSS-safe).
        let ld_json = dumps(&obj(ld))
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026");
        head.push(format!("<script type=\"application/ld+json\">{}</script>", ld_json));
    }
    // Optional site chrome (raw HTML) for the HTML representation only: a header
    // (nav) before the content and a footer after. Markdown/JSON stay clean. The
    // site passes the SAME nav/footer partials it uses elsewhere via `body of render(...)`.
    let header = meta.as_ref().and_then(|m| meta_get(m, "header")).unwrap_or_default();
    let footer = meta.as_ref().and_then(|m| meta_get(m, "footer")).unwrap_or_default();
    // The content container class is overridable (default "prose") so the page author —
    // not the language — controls styling. The Markdown/JSON representations ignore it.
    let css_class = meta.as_ref().and_then(|m| meta_get(m, "class")).unwrap_or_else(|| "prose".to_string());
    let body = if is_page {
        list_field(tree, "nodes").iter().filter(|n| is_node(n)).map(render_node_html).collect::<String>()
    } else {
        render_node_html(tree)
    };
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n{}\n</head>\n<body>\n{}<main class=\"{}\">\n{}</main>\n{}</body>\n</html>\n",
        head.join("\n"),
        header,
        css_class,
        body,
        footer
    )
}

// -- Markdown (para agentes) --

pub fn md_inline(item: &SynValue) -> String {
    if is_node(item) {
        render_node_md(item).trim().to_string()
    } else {
        item.to_string()
    }
}

pub fn render_node_md(node: &SynValue) -> String {
    let kind = node_str(node, "kind");
    match kind.as_str() {
        "heading" => {
            let lvl = node_int(node, "level", 1).clamp(1, 6) as usize;
            format!("{} {}", "#".repeat(lvl), node_str(node, "text"))
        }
        "prose" => node_str(node, "text"),
        "list" => list_field(node, "items")
            .iter()
            .map(|i| format!("- {}", md_inline(i)))
            .collect::<Vec<_>>()
            .join("\n"),
        "ordered_list" => list_field(node, "items")
            .iter()
            .enumerate()
            .map(|(n, i)| format!("{}. {}", n + 1, md_inline(i)))
            .collect::<Vec<_>>()
            .join("\n"),
        "link" => format!("[{}]({})", node_str(node, "text"), node_str(node, "href")),
        "image" => format!("![{}]({})", node_str(node, "alt"), node_str(node, "src")),
        "section" => list_field(node, "nodes")
            .iter()
            .filter(|n| is_node(n))
            .map(render_node_md)
            .collect::<Vec<_>>()
            .join("\n\n"),
        "code" => format!("```{}\n{}\n```", node_str(node, "lang"), node_str(node, "text")),
        "raw" => node_str(node, "html"),
        // chart() (Batch 8): tabla Markdown de los datos normalizados (no píxeles).
        "chart" => crate::charts::render_chart_md(node),
        "page" => list_field(node, "nodes")
            .iter()
            .filter(|n| is_node(n))
            .map(render_node_md)
            .collect::<Vec<_>>()
            .join("\n\n"),
        _ => String::new(),
    }
}

pub fn render_markdown(tree: &SynValue) -> String {
    let body = if node_str(tree, "kind") == "page" {
        list_field(tree, "nodes")
            .iter()
            .filter(|n| is_node(n))
            .map(render_node_md)
            .collect::<Vec<_>>()
            .join("\n\n")
    } else {
        render_node_md(tree)
    };
    format!("{}\n", body.trim_end())
}

/// Renderiza un valor `content()` en el formato elegido como RawResponse.
pub fn render_content(content_value: &SynValue, fmt: &str) -> RawResponse {
    let tree = match content_value {
        SynValue::Server(s) => match &**s {
            ServerValue::Content(inner) => inner.as_ref(),
            _ => content_value,
        },
        _ => content_value,
    };
    match fmt {
        "json" => RawResponse::text(dumps(&node_to_json(tree)), "application/json; charset=utf-8", 200),
        "md" => RawResponse::text(render_markdown(tree), "text/markdown; charset=utf-8", 200),
        _ => RawResponse::text(render_html(tree), "text/html; charset=utf-8", 200),
    }
}


// ---- parse_cookies (movido verbatim desde server.rs) ----
/// Parsea el header `Cookie` entrante (RFC 6265 §5.4) → pares (nombre, valor) SIN
/// decodificar nada: split por `;`, trim, el primer `=` separa nombre/valor.
/// Nombre duplicado: gana la PRIMERA aparición (orden RFC). Sin header → vacío.
/// Segmentos malformados (sin `=` o sin nombre) se saltean — el lado de lectura
/// es tolerante; el de escritura (set_cookie) es el estricto.
pub fn parse_cookies(headers: &[(String, String)]) -> Vec<(String, String)> {
    let raw = header_value(headers, "cookie");
    let mut out: Vec<(String, String)> = Vec::new();
    for part in raw.split(';') {
        let part = part.trim();
        let Some((name, value)) = part.split_once('=') else { continue };
        let name = name.trim();
        if name.is_empty() || out.iter().any(|(n, _)| n == name) {
            continue;
        }
        out.push((name.to_string(), value.trim().to_string()));
    }
    out
}




// ---- bindings del request del handler (movido verbatim desde synsema-runtime/src/serve.rs) ----
pub fn str_map(m: &IndexMap<String, String>) -> SynValue {
    let mut out = IndexMap::new();
    for (k, v) in m {
        out.insert(k.clone(), syn_text(v.as_str()));
    }
    syn_map(out)
}

pub fn headers_map(headers: &[(String, String)]) -> SynValue {
    let mut out = IndexMap::new();
    for (k, v) in headers {
        out.insert(k.clone(), syn_text(v.as_str())); // último gana (como dict de Python)
    }
    syn_map(out)
}

/// El map `request` que ve el handler (paridad con `_build_request`).
pub fn build_request_syn(ctx: &Ctx) -> SynValue {
    let mut m = IndexMap::new();
    m.insert("method".to_string(), syn_text(ctx.method.as_str()));
    m.insert("path".to_string(), syn_text(ctx.path.as_str()));
    m.insert("body".to_string(), syn_text(ctx.body.as_str()));
    m.insert(
        "body_file".to_string(),
        match &ctx.body_file {
            Some(p) => syn_text(p.as_str()),
            None => syn_nothing(),
        },
    );
    m.insert(
        "json".to_string(),
        match &ctx.json {
            Some(v) => json_to_syn(v),
            None => syn_nothing(),
        },
    );
    m.insert("headers".to_string(), headers_map(&ctx.headers));
    // Cookies entrantes (RFC 6265 §5.4), SIN decodificar; nombre duplicado: gana
    // la primera aparición. Sin header `Cookie` → map VACÍO (nunca nothing:
    // `request.cookies.sid` siempre es navegable).
    let mut cookies = IndexMap::new();
    for (k, v) in parse_cookies(&ctx.headers) {
        cookies.insert(k, syn_text(v.as_str()));
    }
    m.insert("cookies".to_string(), syn_map(cookies));
    m.insert("query".to_string(), str_map(&ctx.query));
    m.insert("params".to_string(), str_map(&ctx.params));
    // `form of request` — body de formulario parseado según Content-Type:
    //   application/x-www-form-urlencoded → {campo: texto}
    //   multipart/form-data → campo de texto → texto; archivo → {filename,
    //     content_type, data (bytes exactos)}
    // Sin form body → map VACÍO (como cookies: siempre navegable, nunca nothing).
    m.insert("form".to_string(), build_form_syn(ctx));
    m.insert("ip".to_string(), syn_text(ctx.client_ip.as_str()));
    m.insert("user".to_string(), ctx.user.clone().unwrap_or_else(syn_nothing));
    syn_map(m)
}

/// Parsea el body de formulario del request (urlencoded o multipart) → SynMap.
/// Para bodies spilled a disco (grandes uploads multipart) lee el temp file.
pub fn build_form_syn(ctx: &Ctx) -> SynValue {
    let ctype = ctx
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let mut out = IndexMap::new();
    if ctype.to_ascii_lowercase().contains("application/x-www-form-urlencoded") {
        let body = if let Some(bf) = &ctx.body_file {
            std::fs::read_to_string(bf).unwrap_or_default()
        } else {
            ctx.body.clone()
        };
        for (k, v) in parse_form_urlencoded(&body) {
            out.insert(k, syn_text(v.as_str()));
        }
    } else if let Some(boundary) = multipart_boundary(ctype) {
        let raw: Vec<u8> = if let Some(bf) = &ctx.body_file {
            std::fs::read(bf).unwrap_or_default()
        } else {
            ctx.body_raw.clone()
        };
        for part in parse_multipart(&boundary, &raw) {
            let value = match &part.filename {
                None => syn_text(String::from_utf8_lossy(&part.data).as_ref()),
                Some(fname) => {
                    let mut f = IndexMap::new();
                    f.insert("filename".to_string(), syn_text(fname.as_str()));
                    f.insert(
                        "content_type".to_string(),
                        match &part.content_type {
                            Some(ct) => syn_text(ct.as_str()),
                            None => syn_nothing(),
                        },
                    );
                    f.insert("data".to_string(), syn_bytes(part.data.clone()));
                    syn_map(f)
                }
            };
            out.insert(part.name, value);
        }
    }
    syn_map(out)
}

/// Las bindings que ve un handler, LOCALES al scope hijo del request (no globales →
/// no se filtran al siguiente request al reusar el intérprete): `request`, `query`,
/// `params` y el builtin `read_body` (lee el cuerpo, en memoria o del temp file spilled).
pub fn request_bindings(ctx: &Ctx) -> Vec<(String, SynValue)> {
    let body_text = ctx.body.clone();
    let body_file = ctx.body_file.clone();
    let read_body = SynValue::Builtin(Rc::new(BuiltinTask {
        name: "read_body".to_string(),
        param_count: 0,
        param_names: None,
        func: Rc::new(move |_i, _a, _l| match &body_file {
            Some(bf) => Ok(syn_text(std::fs::read_to_string(bf).unwrap_or_default())),
            None => Ok(syn_text(body_text.as_str())),
        }),
    }));
    // read_body_bytes() → bytes crudos (NO lossy). Prefiere el temp file spilled
    // (`std::fs::read`, no `read_to_string`); para bodies en memoria usa `body_raw` (los
    // bytes exactos), no `body` (que pasó por from_utf8_lossy aguas arriba). Cierra el
    // punto lossy de read_body para binario; exactitud byte-a-byte (A4).
    let body_raw = ctx.body_raw.clone();
    let body_file_b = ctx.body_file.clone();
    let read_body_bytes = SynValue::Builtin(Rc::new(BuiltinTask {
        name: "read_body_bytes".to_string(),
        param_count: 0,
        param_names: None,
        func: Rc::new(move |_i, _a, _l| match &body_file_b {
            Some(bf) => Ok(syn_bytes(std::fs::read(bf).unwrap_or_default())),
            None => Ok(syn_bytes(body_raw.clone())),
        }),
    }));
    vec![
        ("request".to_string(), build_request_syn(ctx)),
        ("query".to_string(), str_map(&ctx.query)),
        ("params".to_string(), str_map(&ctx.params)),
        ("read_body".to_string(), read_body),
        ("read_body_bytes".to_string(), read_body_bytes),
    ]
}


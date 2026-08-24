//! Servidor HTTP nativo. Port de `synsema/stdlib/server.py`.
//!
//! Implementa el constructo `serve on PORT`. La lógica del lenguaje (capability,
//! aislamiento por request, auth, validación) la pone el engine vía closures
//! inyectados; este módulo es el plumbing HTTP + el *contrato de respuesta*.
//!
//! Concurrencia: thread-per-connection con `std::thread` (paridad con
//! `ThreadingHTTPServer`). Los recursos compartidos (db/blackboard) se envuelven
//! en `Arc`/`Mutex` antes de wirearse a los handlers.
//!
//! Este archivo cubre, por subsistemas (cada uno gateado con su differential):
//!   1. routing/match  — `specificity`, `path_match`, `match_route`, `methods_for_path`
//!   2. contrato de respuesta — pendiente (envelopes/paginación)
//!      … y siguen: static, negotiation, rate-limit, SSE, discovery, CORS, max_body

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use indexmap::IndexMap;

// Lote 2 — rewrite async (hyper/tokio/rustls). El intérprete sigue sync (spawn_blocking).
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};

use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::types::{
    syn_int, syn_list, syn_map, syn_nothing, syn_text, ServerValue, SynValue,
};

// =========================================================
// Constantes
// =========================================================

pub const DEFAULT_LIMIT: i64 = 100;
pub const MAX_LIMIT: i64 = 1000;
/// Tope por defecto del body bufferizado en memoria (no es tope duro: `max_body`
/// lo overridea y los bodies grandes spillean a disco).
pub const MAX_BODY: i64 = 1_048_576;
/// Sobre este tamaño el body se streamea a un temp file en vez de memoria.
pub const MEM_SPILL: usize = 1_048_576;
/// Tope por defecto de streams SSE concurrentes.
pub const DEFAULT_MAX_STREAMS: i64 = 100;

/// Content-types pinneados para servir estáticos: el resultado nunca depende del
/// registro de mimetypes del host (p.ej. Windows mapea .js → text/plain).
pub fn web_content_type(ext: &str) -> Option<&'static str> {
    Some(match ext {
        ".html" | ".htm" => "text/html; charset=utf-8",
        ".css" => "text/css; charset=utf-8",
        ".js" | ".mjs" => "text/javascript; charset=utf-8",
        ".json" | ".map" => "application/json; charset=utf-8",
        ".svg" => "image/svg+xml",
        ".png" => "image/png",
        ".jpg" | ".jpeg" => "image/jpeg",
        ".gif" => "image/gif",
        ".webp" => "image/webp",
        ".ico" => "image/x-icon",
        ".woff" => "font/woff",
        ".woff2" => "font/woff2",
        ".ttf" => "font/ttf",
        ".txt" => "text/plain; charset=utf-8",
        ".xml" => "application/xml; charset=utf-8",
        ".wasm" => "application/wasm",
        ".pdf" => "application/pdf",
        _ => return None,
    })
}

/// Una respuesta escrita verbatim (no JSON), con Content-Type explícito.
/// Producida por html()/respond()/render() y por el servido de estáticos.
#[derive(Clone, Debug)]
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

/// Resultado de servir un estático de producción: status + body + content-type +
/// headers extra (ETag, Accept-Ranges, Content-Range, Content-Encoding, Vary).
struct StaticResp {
    status: u16,
    body: Vec<u8>,
    content_type: String,
    extra: Vec<(String, String)>,
}

/// ETag débil-equivalente derivado de tamaño + mtime (como hace nginx por defecto).
fn etag_for(path: &Path, size: usize) -> String {
    let mtime = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("\"{:x}-{:x}\"", size, mtime)
}

/// Tipos comprimibles con gzip (html/css/js/json/svg/txt + xml por extensión común).
fn is_compressible(content_type: &str) -> bool {
    let c = content_type.split(';').next().unwrap_or("").trim();
    matches!(
        c,
        "text/html"
            | "text/css"
            | "text/javascript"
            | "application/javascript"
            | "application/json"
            | "image/svg+xml"
            | "text/plain"
            | "application/xml"
            | "text/xml"
    )
}

/// Comprime con gzip (flate2 / miniz_oxide puro-Rust). None si falla.
fn gzip_bytes(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::{write::GzEncoder, Compression};
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).ok()?;
    e.finish().ok()
}

/// Parsea un header `Range: bytes=START-END` (un solo rango). Soporta sufijo
/// `bytes=-N`. Devuelve `(start, end)` inclusivos, o None si el rango es inválido.
fn parse_range(range: &str, size: usize) -> Option<(usize, usize)> {
    if size == 0 {
        return None;
    }
    let r = range.trim().strip_prefix("bytes=")?;
    let (s, e) = r.split_once('-')?;
    let (s, e) = (s.trim(), e.trim());
    let (start, end) = if s.is_empty() {
        // Sufijo: últimos N bytes.
        let n: usize = e.parse().ok()?;
        if n == 0 {
            return None;
        }
        (size.saturating_sub(n), size - 1)
    } else {
        let start: usize = s.parse().ok()?;
        let end = if e.is_empty() {
            size - 1
        } else {
            e.parse::<usize>().ok()?.min(size - 1)
        };
        (start, end)
    };
    if start > end || start >= size {
        return None;
    }
    Some((start, end))
}

// =========================================================
// URL helpers (unquote, query parse)
// =========================================================

fn hex_val(b: u8) -> Option<u8> {
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
fn segments(pattern: &str) -> Vec<&str> {
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
const FORMAT_SUFFIXES: [(&str, &str); 3] = [("md", "md"), ("json", "json"), ("html", "html")];

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

// =========================================================
// max_body
// =========================================================

/// Resuelve un setting de max-body a bytes, o None para ilimitado.
/// Acepta número (bytes) o string con unidad ("512kb", "10mb", "1gb") o
/// "unlimited"/"none" para desactivar.
pub fn parse_body_size_str(value: &str) -> Option<i64> {
    let s = value.trim().to_lowercase();
    if matches!(s.as_str(), "unlimited" | "none" | "off" | "0") {
        return None;
    }
    // ^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$
    let mut end = 0;
    let mut seen_dot = false;
    for (idx, c) in s.char_indices() {
        if c.is_ascii_digit() {
            end = idx + 1;
        } else if c == '.' && !seen_dot {
            seen_dot = true;
            end = idx + 1;
        } else {
            break;
        }
    }
    if end == 0 {
        return Some(MAX_BODY);
    }
    let num = &s[..end];
    let rest = s[end..].trim_start();
    let mult: i64 = match rest {
        "" | "b" => 1,
        "kb" => 1024,
        "mb" => 1024 * 1024,
        "gb" => 1024 * 1024 * 1024,
        _ => return Some(MAX_BODY),
    };
    match num.parse::<f64>() {
        Ok(n) => Some((n * mult as f64) as i64),
        Err(_) => Some(MAX_BODY),
    }
}

// =========================================================
// JSON de salida + árbol de contenido como data: EXTRAÍDOS a json.rs (módulo puro,
// compartido con el perfil wasm; server.rs conserva los renderers HTML/Markdown).
// Re-export público: los callers externos (runtime, tests) siguen usando
// server::{Json, dumps, syn_to_json, json_to_syn} sin cambios.
// =========================================================

pub use crate::json::{dumps, json_to_syn, syn_to_json, Json};
use crate::json::{
    esc, is_node, list_field, make_node, meta_get, node_field, node_int, node_str,
    node_to_json, num_i64, obj,
};

// =========================================================
// Contrato de respuesta (paginación de colecciones)
// =========================================================

fn page_window(query: &IndexMap<String, String>) -> (i64, i64) {
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

fn envelope_from_page(items: Vec<Json>, count: i64, total: i64, limit: i64, offset: i64) -> Json {
    let next = offset + limit;
    let cursor = if next < total { Json::Int(next) } else { Json::Null };
    obj(vec![
        ("items", Json::Array(items)),
        ("count", Json::Int(count)),
        ("total", Json::Int(total)),
        ("cursor", cursor),
    ])
}

fn paginate(items: &[SynValue], query: &IndexMap<String, String>) -> Json {
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
fn paginate_lazy(
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
fn shape(value: Option<&SynValue>, query: &IndexMap<String, String>) -> Result<Json, String> {
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
}

/// Ctx mínimo para el `errors with` de 404/405 (el error ocurre ANTES de armar el
/// ctx del handler): method/path/query/headers reales, params vacíos, user nothing.
#[allow(clippy::too_many_arguments)]
fn min_ctx(
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

pub struct RouteSpec {
    pub method: String,
    pub path: String,
    pub param_names: Vec<String>,
    pub requires_auth: bool,
    pub streaming: bool,
    pub rate_limit: Option<(i64, f64)>,
    pub rate_zone: Option<String>,
    pub handler: Handler,
    pub stream_handler: Option<StreamHandler>,
    /// Lote 2 — reverse proxy: si está, la route forwardea al upstream (URL base).
    pub proxy_target: Option<String>,
}

/// Cuerpo de una respuesta HTTP.
pub enum ResponseBody {
    Json(Json),
    Raw(RawResponse),
    /// `redirect()` — 3xx + header `Location` (sin body). El `Location` lo inyecta
    /// el dispatch en los headers extra; acá viaja solo el destino + status.
    Redirect { location: String, status: u16 },
}

// =========================================================
// Rate limiter (token bucket, paridad con RateLimiter del oráculo)
// =========================================================

pub struct RateLimiter {
    buckets: Mutex<HashMap<String, (f64, Instant, f64)>>,
    cleanup_interval: f64,
    last_cleanup: Mutex<Option<Instant>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            buckets: Mutex::new(HashMap::new()),
            cleanup_interval: 30.0,
            last_cleanup: Mutex::new(None),
        }
    }

    /// (allowed, remaining, retry_after, reset_seconds).
    pub fn check(&self, key: &str, capacity: i64, window: f64) -> (bool, i64, f64, f64) {
        let now = Instant::now();
        let rate = capacity as f64 / window;
        let mut buckets = self.buckets.lock().unwrap();
        // limpieza perezosa de buckets stale (no vistos por > 2× su ventana)
        {
            let mut lc = self.last_cleanup.lock().unwrap();
            let due = match *lc {
                None => true,
                Some(t) => now.duration_since(t).as_secs_f64() >= self.cleanup_interval,
            };
            if due {
                *lc = Some(now);
                buckets.retain(|_, (_t, last, w)| now.duration_since(*last).as_secs_f64() <= 2.0 * *w);
            }
        }
        let (mut tokens, last, _w) =
            buckets.get(key).copied().unwrap_or((capacity as f64, now, window));
        tokens = (capacity as f64).min(tokens + now.duration_since(last).as_secs_f64() * rate);
        let allowed;
        let retry_after;
        if tokens >= 1.0 {
            tokens -= 1.0;
            allowed = true;
            retry_after = 0.0;
        } else {
            allowed = false;
            retry_after = (1.0 - tokens) / rate;
        }
        buckets.insert(key.to_string(), (tokens, now, window));
        let remaining = tokens as i64;
        let reset = (capacity as f64 - tokens) / rate;
        (allowed, remaining, retry_after, reset)
    }
}

// =========================================================
// ServeRuntime
// =========================================================

/// Spec de un mount estático tal como lo declara el programa: prefijo + dir +
/// las cláusulas opcionales `cache` (Cache-Control) y `fallback` (SPA).
#[derive(Clone, Debug)]
pub struct StaticMountSpec {
    pub prefix: String,
    pub dir: String,
    /// Valor YA resuelto de Cache-Control (el runtime valida la spec con
    /// `cache_control_value` al construir el serve — fail-fast).
    pub cache: Option<String>,
    /// Archivo relativo al mount servido con 200 cuando el path no existe
    /// (history-fallback de SPA, estilo `try_files ... /index.html`).
    pub fallback: Option<String>,
}

/// Traduce la spec de `cache "<...>"` a un valor de header `Cache-Control`.
/// Acepta: `"immutable"` (assets fingerprinteados), `"no-store"`, un número crudo
/// (segundos) o `<N><s|m|h|d>` (`"30s"`, `"5m"`, `"1h"`, `"7d"`). Cualquier otra
/// cosa es error (fail-loud al construir el serve, nunca en un request).
pub fn cache_control_value(spec: &str) -> Result<String, String> {
    let s = spec.trim().to_ascii_lowercase();
    match s.as_str() {
        "immutable" => return Ok("public, max-age=31536000, immutable".to_string()),
        "no-store" => return Ok("no-store".to_string()),
        _ => {}
    }
    let (digits, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        Some(c) if c.is_ascii_digit() => (s.as_str(), 1),
        _ => ("", 1),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "invalid cache spec '{}' — use \"immutable\", \"no-store\", raw seconds, or <N>s/m/h/d (e.g. \"1h\", \"7d\")",
            spec
        ));
    }
    let secs: u64 = digits.parse().map_err(|_| format!("invalid cache spec '{}'", spec))?;
    Ok(format!("public, max-age={}", secs * mult))
}

/// Un mount estático ya resuelto (realpath + prefijo normalizado).
struct Mount {
    prefix: String,
    base: PathBuf,
    cache: Option<String>,
    fallback: Option<String>,
}

/// Tabla de ruteo de un host: rutas + estáticos + auth propios. El host `default`
/// (pattern=None) es el comportamiento de siempre; los vhosts (Lote 1) agregan
/// dominios con su propia tabla, seleccionados por el header `Host`.
pub struct HostRouter {
    /// None = host default (serve-level). Some("a.com") exacto, Some("*.a.com") wildcard.
    pattern: Option<String>,
    routes: Vec<RouteSpec>,
    static_mounts: Vec<Mount>,
    auth_handler: Option<AuthHandler>,
}

impl HostRouter {
    fn new(
        pattern: Option<String>,
        mut routes: Vec<RouteSpec>,
        static_mounts: Vec<StaticMountSpec>,
        auth_handler: Option<AuthHandler>,
    ) -> Self {
        // Orden por especificidad (más específica primero): el primer match gana.
        routes.sort_by_key(|a| specificity(&a.path));
        // Mounts: prefijo normalizado + realpath del directorio, prefijo más largo primero.
        let mut mounts: Vec<Mount> = static_mounts
            .into_iter()
            .map(|m| {
                let real =
                    Path::new(&m.dir).canonicalize().unwrap_or_else(|_| PathBuf::from(&m.dir));
                Mount { prefix: norm_prefix(&m.prefix), base: real, cache: m.cache, fallback: m.fallback }
            })
            .collect();
        mounts.sort_by_key(|m| std::cmp::Reverse(m.prefix.len()));
        HostRouter { pattern, routes, static_mounts: mounts, auth_handler }
    }

    /// ¿Este host (con patrón exacto o `*.dominio`) cubre `host`?
    fn matches_host(&self, host: &str) -> bool {
        match &self.pattern {
            None => true,
            Some(p) => {
                if let Some(suffix) = p.strip_prefix("*.") {
                    let h = host.to_ascii_lowercase();
                    let s = suffix.to_ascii_lowercase();
                    h == s || h.ends_with(&format!(".{}", s))
                } else {
                    host.eq_ignore_ascii_case(p)
                }
            }
        }
    }

    fn match_route(&self, method: &str, path: &str) -> Option<(usize, IndexMap<String, String>)> {
        for (i, route) in self.routes.iter().enumerate() {
            if route.method != method {
                continue;
            }
            if let Some(params) = path_match(&route.path, path) {
                return Some((i, params));
            }
        }
        None
    }

    fn methods_for_path(&self, path: &str) -> Vec<String> {
        let mut methods: Vec<String> = Vec::new();
        for route in &self.routes {
            if path_match(&route.path, path).is_some() && !methods.contains(&route.method) {
                methods.push(route.method.clone());
            }
        }
        methods.sort();
        methods
    }

    /// Sirve un estático de producción: ETag + 304 (If-None-Match), Range/206, gzip
    /// (Accept-Encoding + tipo comprimible). Devuelve status + body + headers extra.
    fn serve_static_full(&self, url_path: &str, headers: &[(String, String)]) -> Option<StaticResp> {
        for mount in &self.static_mounts {
            let (prefix, base) = (&mount.prefix, &mount.base);
            let rel = if prefix == "/" {
                url_path.to_string()
            } else if url_path == prefix.trim_end_matches('/') {
                String::new()
            } else if url_path.starts_with(prefix.as_str()) {
                url_path[prefix.len()..].to_string()
            } else {
                continue;
            };
            // Miss dentro del mount + `fallback` declarado → servir ese archivo con
            // 200 (history-fallback de SPA, semántica try_files). Sin fallback, se
            // sigue probando el próximo mount (comportamiento histórico).
            let target = match resolve_in(base, &rel) {
                Some(t) => t,
                None => match &mount.fallback {
                    Some(fb) => match resolve_in(base, fb) {
                        Some(t) => t,
                        None => continue,
                    },
                    None => continue,
                },
            };
            let data = match std::fs::read(&target) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let ct = static_content_type(&target);
            let etag = etag_for(&target, data.len());
            // `cache "<...>"` del mount → header Cache-Control en 200/206/304.
            let finish = |mut sr: StaticResp| {
                if let Some(c) = &mount.cache {
                    if sr.status != 416 {
                        sr.extra.push(("Cache-Control".into(), c.clone()));
                    }
                }
                Some(sr)
            };

            // If-None-Match → 304 (sin body).
            let inm = header_value(headers, "if-none-match");
            if !inm.is_empty() && inm.trim() == etag {
                return finish(StaticResp {
                    status: 304,
                    body: Vec::new(),
                    content_type: ct,
                    extra: vec![("ETag".into(), etag), ("Accept-Ranges".into(), "bytes".into())],
                });
            }
            // Range → 206 (sin gzip).
            let range = header_value(headers, "range");
            if !range.is_empty() {
                return finish(match parse_range(&range, data.len()) {
                    Some((start, end)) => StaticResp {
                        status: 206,
                        body: data[start..=end].to_vec(),
                        content_type: ct,
                        extra: vec![
                            ("ETag".into(), etag),
                            ("Accept-Ranges".into(), "bytes".into()),
                            ("Content-Range".into(), format!("bytes {}-{}/{}", start, end, data.len())),
                        ],
                    },
                    None => StaticResp {
                        status: 416,
                        body: Vec::new(),
                        content_type: ct,
                        extra: vec![("Content-Range".into(), format!("bytes */{}", data.len()))],
                    },
                });
            }
            // gzip si el cliente lo acepta y el tipo es comprimible.
            let ae = header_value(headers, "accept-encoding").to_lowercase();
            if ae.contains("gzip") && is_compressible(&ct) {
                if let Some(gz) = gzip_bytes(&data) {
                    return finish(StaticResp {
                        status: 200,
                        body: gz,
                        content_type: ct,
                        extra: vec![
                            ("ETag".into(), etag),
                            ("Accept-Ranges".into(), "bytes".into()),
                            ("Content-Encoding".into(), "gzip".into()),
                            ("Vary".into(), "Accept-Encoding".into()),
                        ],
                    });
                }
            }
            return finish(StaticResp {
                status: 200,
                body: data,
                content_type: ct,
                extra: vec![("ETag".into(), etag), ("Accept-Ranges".into(), "bytes".into())],
            });
        }
        None
    }
}

/// Resumen de una aprobación pendiente para `GET /approvals` — NUNCA incluye el token
/// (el token se distribuye por la consola del server al encolar).
#[derive(Clone, Debug)]
pub struct ApprovalSummary {
    pub id: String,
    pub message: String,
    /// "approve" | "confirm" | "ask" | "review"
    pub ty: String,
    /// Vencimiento en epoch-segundos.
    pub expires_at: i64,
}

/// Resultado de un intento de respuesta vía `POST /approvals/{id}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// Token correcto: la pendiente se consumió (un solo uso) y el gate despertó.
    Accepted,
    /// id inexistente, ya consumido o vencido → 404.
    NotFound,
    /// Token incorrecto → 403 (la pendiente sigue viva).
    BadToken,
}

/// Backend de las rutas reservadas `/approvals` (cola de gates humanos bajo serve).
/// La cola real vive fuera de stdlib (en el runtime); acá sólo el contrato — el
/// runtime la cablea en `ServeRuntime.approvals` al armar el server.
pub trait ApprovalsGateway: Send + Sync {
    /// Pendientes actuales, sin tokens.
    fn list(&self) -> Vec<ApprovalSummary>;
    /// Respuesta humana: `decision` para approve/confirm/review, `value` para ask.
    fn respond(
        &self,
        id: &str,
        token: &str,
        decision: Option<bool>,
        value: Option<&str>,
    ) -> ApprovalOutcome;
}

pub struct ServeRuntime {
    pub port: u16,
    pub host: String,
    pub secure: bool,
    /// A2: TLS activo → se emite HSTS y los `redirect https` apuntan a https://.
    pub tls_enabled: bool,
    /// Cola de aprobaciones humanas (A1.v2) — `None` si el runtime no la cableó
    /// (las rutas `/approvals` no existen y todo sigue como antes).
    pub approvals: Option<Arc<dyn ApprovalsGateway>>,
    /// Host por defecto (rutas/estáticos/auth a nivel de `serve`).
    default_host: HostRouter,
    /// Hosts virtuales (Lote 1): seleccionados por el header `Host`.
    vhosts: Vec<HostRouter>,
    pub max_body: Option<i64>,
    pub max_streams: i64,
    cors_origin: Option<String>,
    intent: Option<String>,
    describe_about: Option<String>,
    describe_api: Vec<String>,
    private: bool,
    rate_limiter: RateLimiter,
    active_streams: Mutex<i64>,
    /// `errors with <task>` (serve-level): da forma a 401/404/405/500.
    error_handler: Option<ErrorHandler>,
}

/// El resultado de `dispatch`: una respuesta lista, o un hand-off a streaming SSE.
pub enum Dispatched {
    Response { status: u16, body: ResponseBody, headers: Vec<(String, String)> },
    Stream { stream_handler: Option<StreamHandler>, ctx: Box<Ctx> },
}

#[allow(clippy::too_many_arguments)]
impl ServeRuntime {
    pub fn new(
        port: u16,
        host: String,
        routes: Vec<RouteSpec>,
        auth_handler: Option<AuthHandler>,
        max_body: Option<i64>,
        max_streams: i64,
        static_mounts: Vec<StaticMountSpec>,
        cors_origin: Option<String>,
        intent: Option<String>,
        describe_about: Option<String>,
        describe_api: Vec<String>,
        private: bool,
        secure: bool,
    ) -> Self {
        ServeRuntime {
            port,
            host,
            secure,
            tls_enabled: false,
            approvals: None,
            default_host: HostRouter::new(None, routes, static_mounts, auth_handler),
            vhosts: Vec::new(),
            max_body,
            max_streams,
            cors_origin,
            intent,
            describe_about,
            describe_api,
            private,
            rate_limiter: RateLimiter::new(),
            active_streams: Mutex::new(0),
            error_handler: None,
        }
    }

    /// Cablea la task de `errors with` (el runtime la construye como el auth handler).
    pub fn set_error_handler(&mut self, h: ErrorHandler) {
        self.error_handler = Some(h);
    }

    /// Registra un vhost (Lote 1): dominio exacto o `*.dominio` con su propia tabla
    /// (rutas/estáticos/auth). Se selecciona por el header `Host`.
    pub fn add_vhost(
        &mut self,
        pattern: String,
        routes: Vec<RouteSpec>,
        static_mounts: Vec<StaticMountSpec>,
        auth_handler: Option<AuthHandler>,
    ) {
        self.vhosts.push(HostRouter::new(Some(pattern), routes, static_mounts, auth_handler));
    }

    /// Selecciona el host por el header `Host`: exacto → wildcard → default.
    fn select_host(&self, host_header: &str) -> &HostRouter {
        if self.vhosts.is_empty() {
            return &self.default_host;
        }
        let h = host_header.split(':').next().unwrap_or("").trim();
        for vh in &self.vhosts {
            if matches!(&vh.pattern, Some(p) if !p.starts_with("*.") && h.eq_ignore_ascii_case(p)) {
                return vh;
            }
        }
        for vh in &self.vhosts {
            if matches!(&vh.pattern, Some(p) if p.starts_with("*.")) && vh.matches_host(h) {
                return vh;
            }
        }
        &self.default_host
    }

    pub fn route_count(&self) -> usize {
        self.default_host.routes.len()
    }
    pub fn cors_origin(&self) -> Option<&str> {
        self.cors_origin.as_deref()
    }

    fn try_acquire_stream(&self) -> bool {
        let mut n = self.active_streams.lock().unwrap();
        if *n >= self.max_streams {
            return false;
        }
        *n += 1;
        true
    }
    fn release_stream(&self) {
        let mut n = self.active_streams.lock().unwrap();
        if *n > 0 {
            *n -= 1;
        }
    }

    /// Métodos permitidos en `path` para el host default (lo usa OPTIONS).
    pub fn methods_for_path(&self, path: &str) -> Vec<String> {
        self.default_host.methods_for_path(path)
    }

    // -- discoverability --

    fn llms_txt(&self) -> String {
        let title = self
            .describe_about
            .clone()
            .or_else(|| self.intent.clone())
            .unwrap_or_else(|| "Synsema service".to_string());
        let mut lines = vec![format!("# {}", title)];
        if let Some(intent) = &self.intent {
            if *intent != title {
                lines.push(String::new());
                lines.push(format!("> {}", intent));
            }
        }
        let mut endpoints: Vec<(String, String)> =
            self.default_host.routes.iter().map(|r| (r.method.clone(), r.path.clone())).collect();
        endpoints.sort_by_key(|a| (a.1.clone(), a.0.clone()));
        endpoints.dedup();
        if !endpoints.is_empty() {
            lines.push(String::new());
            lines.push("## Endpoints".to_string());
            for (m, p) in &endpoints {
                lines.push(format!("- {} {}", m, p));
            }
        }
        if !self.describe_api.is_empty() {
            lines.push(String::new());
            lines.push("## API".to_string());
            for item in &self.describe_api {
                lines.push(format!("- {}", item));
            }
        }
        lines.join("\n") + "\n"
    }

    fn robots_txt(&self) -> String {
        if self.private {
            "User-agent: *\nDisallow: /\n".to_string()
        } else {
            "User-agent: *\nAllow: /\n".to_string()
        }
    }

    /// T6.5 — descubrimiento máquina-a-máquina: qué formas de autenticación
    /// entiende este server, en JSON. `/llms.txt` le dice a un agente QUÉ hace el
    /// servicio; esto le dice CÓMO autenticarse, sin leer documentación humana.
    ///
    /// Se deriva de lo que el server realmente tiene cableado (no es una promesa
    /// declarativa): si ninguna ruta pide auth, la lista de mecanismos va vacía.
    fn auth_discovery(&self) -> String {
        let requires_auth = self.default_host.routes.iter().any(|r| r.requires_auth)
            || self.vhosts.iter().any(|h| h.routes.iter().any(|r| r.requires_auth));
        let has_handler = self.default_host.auth_handler.is_some()
            || self.vhosts.iter().any(|h| h.auth_handler.is_some());
        let mut mechanisms: Vec<Json> = Vec::new();
        if requires_auth && has_handler {
            // El transporte del credencial siempre es el mismo (Authorization:
            // Bearer o cookie de sesión); lo que varía es QUÉ se manda, y eso lo
            // resuelve el auth task del programa. Se anuncian las formas que el
            // engine sabe verificar de fábrica.
            mechanisms.push(obj(vec![
                ("scheme", Json::Str("bearer".into())),
                ("transport", Json::Str("Authorization: Bearer <token>".into())),
                (
                    "token_types",
                    Json::Array(vec![
                        Json::Str("captoken".into()),
                        Json::Str("jwt".into()),
                        Json::Str("opaque".into()),
                    ]),
                ),
            ]));
            mechanisms.push(obj(vec![
                ("scheme", Json::Str("cookie".into())),
                ("transport", Json::Str("Cookie: <name>=<session id>".into())),
            ]));
            mechanisms.push(obj(vec![
                ("scheme", Json::Str("http-message-signature".into())),
                ("profile", Json::Str("rfc9421-pinned".into())),
                (
                    "covered",
                    Json::Array(vec![
                        Json::Str("@method".into()),
                        Json::Str("@target-uri".into()),
                        Json::Str("content-digest".into()),
                    ]),
                ),
                (
                    "algorithms",
                    Json::Array(vec![Json::Str("ed25519".into()), Json::Str("hmac-sha256".into())]),
                ),
            ]));
        }
        // Rutas protegidas: un agente sabe adónde puede ir sin probar a ciegas.
        let mut protected: Vec<Json> = self
            .default_host
            .routes
            .iter()
            .filter(|r| r.requires_auth)
            .map(|r| Json::Str(format!("{} {}", r.method, r.path)))
            .collect();
        protected.sort_by(|a, b| match (a, b) {
            (Json::Str(x), Json::Str(y)) => x.cmp(y),
            _ => std::cmp::Ordering::Equal,
        });
        dumps(&obj(vec![
            ("service", Json::Str(self.describe_about.clone().or_else(|| self.intent.clone()).unwrap_or_else(|| "Synsema service".to_string()))),
            ("authentication", Json::Array(mechanisms)),
            ("protected_endpoints", Json::Array(protected)),
        ]))
    }

    fn discovery_response(&self, path: &str) -> Option<RawResponse> {
        if path == "/llms.txt" && !self.private {
            return Some(RawResponse::text(self.llms_txt(), "text/plain; charset=utf-8", 200));
        }
        // Mismo criterio de `private` que /llms.txt: un server interno no publica
        // su superficie de auth.
        if path == "/.well-known/synsema-auth" && !self.private {
            return Some(RawResponse::text(
                self.auth_discovery(),
                "application/json; charset=utf-8",
                200,
            ));
        }
        if path == "/robots.txt" {
            return Some(RawResponse::text(self.robots_txt(), "text/plain; charset=utf-8", 200));
        }
        None
    }

    /// 500 con `errors with`: el detalle SIEMPRE va al log del server (server_error);
    /// a la task le llega el mismo texto que vería el cliente (redactado bajo --secure,
    /// para que una página de error custom jamás re-filtre internals en producción).
    fn shape_500(
        &self,
        detail: &str,
        ctx: &Ctx,
        extra: &mut Vec<(String, String)>,
    ) -> (u16, ResponseBody) {
        let default_body = self.server_error(detail);
        let msg = if self.secure { "internal server error" } else { detail };
        if let Some((st, body, hdrs)) = self.custom_error(500, msg, ctx) {
            extra.extend(hdrs);
            return (st, body);
        }
        (500, default_body)
    }

    /// `errors with`: intenta dar forma custom a un error del runtime. El STATUS del
    /// error SE CONSERVA (jamás un 200 para un 404 — nada de soft-404), con una sola
    /// excepción: si la task devuelve `redirect()`, su 3xx + Location se respetan
    /// (patrón "401 → redirect al login"). `nothing` (o un error en la task) → None
    /// y el JSON por defecto sigue intacto.
    fn custom_error(
        &self,
        status: u16,
        message: &str,
        ctx: &Ctx,
    ) -> Option<(u16, ResponseBody, Vec<(String, String)>)> {
        let handler = self.error_handler.as_ref()?;
        let v = handler(i64::from(status), message, ctx)?;
        if matches!(v, SynValue::Nothing) {
            return None;
        }
        // with_header()/set_cookie(): desenvolver el wrapper, igual que en dispatch.
        let mut hdrs: Vec<(String, String)> = Vec::new();
        let v = match v {
            SynValue::Server(s) => match &*s {
                ServerValue::WithHeaders { inner, headers } => {
                    hdrs = headers.clone();
                    (**inner).clone()
                }
                _ => SynValue::Server(s),
            },
            other => other,
        };
        // content() → negociado por Accept: la misma página de error sale como HTML
        // al navegador y Markdown/JSON a un agente.
        let is_content =
            matches!(&v, SynValue::Server(s) if matches!(&**s, ServerValue::Content(_)));
        if is_content {
            let fmt = negotiate_format(&header_value(&ctx.headers, "accept"));
            let raw = render_content(&v, &fmt);
            return Some((status, ResponseBody::Raw(raw), hdrs));
        }
        match build_response(Some(&v), &ctx.query) {
            Ok((st, body)) => match body {
                ResponseBody::Redirect { .. } => Some((st, body, hdrs)),
                other => Some((status, other, hdrs)),
            },
            Err(_) => None,
        }
    }

    fn server_error(&self, detail: &str) -> ResponseBody {
        eprintln!("[serve:{}] 500 {}", self.port, detail);
        let body = if self.secure {
            obj(vec![("error", Json::Str("internal server error".into())), ("status", Json::Int(500))])
        } else {
            obj(vec![("error", Json::Str(detail.to_string())), ("status", Json::Int(500))])
        };
        ResponseBody::Json(body)
    }

    // -- dispatch --

    /// ¿La ruta que matchearía esta request está declarada como `stream`? Resuelve sólo
    /// vhost + match de ruta (mismo criterio que el primer match de `dispatch`), sin correr
    /// auth ni el handler. Sirve para elegir el hilo: streams → hilo dedicado; sized → pool.
    pub fn route_is_streaming(&self, method: &str, path: &str, headers: &[(String, String)]) -> bool {
        let host = self.select_host(&header_value(headers, "host"));
        match host.match_route(method, path) {
            Some((i, _)) => host.routes[i].streaming,
            None => false,
        }
    }

    /// ¿La request es de las rutas reservadas `/approvals`? (Sólo si el runtime cableó
    /// la cola.) Lo usa también el lado de conexión para atenderlas en un hilo DEDICADO
    /// (no el pool del intérprete): un gate bloqueado espera su respuesta ocupando un
    /// worker — la respuesta no puede quedar en cola detrás de él.
    /// Formas: `GET /approvals` (lista), `POST /approvals/{id}` (respuesta con token en
    /// el body), `GET /approvals/{id}/{token}` (link de decisión sí/no, A1.v3).
    pub fn is_approvals_route(&self, method: &str, path: &str) -> bool {
        if self.approvals.is_none() {
            return false;
        }
        if method == "GET" && path == "/approvals" {
            return true;
        }
        let Some(rest) = path.strip_prefix("/approvals/") else { return false };
        let segs: Vec<&str> = rest.split('/').collect();
        match (method, segs.as_slice()) {
            ("POST", [id]) => !id.is_empty(),
            ("GET", [id, token]) => !id.is_empty() && !token.is_empty(),
            _ => false,
        }
    }

    /// Página HTML mínima autocontenida de un link de aprobación (A1.v3) — para el
    /// humano que abrió la URL desde SMS/chat. NUNCA incluye el token.
    fn approval_link_page(status: u16, title: &str, detail: &str) -> Dispatched {
        let html = format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Synsema approval</title>\
             </head><body style=\"font-family: system-ui, sans-serif; max-width: 40rem; \
             margin: 4rem auto; padding: 0 1rem;\"><h1>{}</h1><p>{}</p></body></html>",
            title, detail
        );
        Dispatched::Response {
            status,
            body: ResponseBody::Raw(RawResponse::text(html, "text/html; charset=utf-8", status)),
            headers: vec![],
        }
    }

    /// Atiende las rutas reservadas `/approvals`. D4: `GET /approvals` lista las
    /// pendientes SIN tokens; `POST /approvals/{id}` con `{"token", "decision"}` (o
    /// `{"token", "value"}` para ask) responde el gate → 200/400/403/404; el link
    /// `GET /approvals/{id}/{token}?d=yes|no` (A1.v3) responde SOLO decisión sí/no
    /// (mismo camino: token de un solo uso) y devuelve HTML para el humano.
    fn approvals_response(
        &self,
        method: &str,
        path: &str,
        query: &IndexMap<String, String>,
        body_str: &str,
    ) -> Dispatched {
        let gw = self.approvals.as_ref().expect("is_approvals_route lo garantiza");
        let resp = |status, body| Dispatched::Response { status, body, headers: vec![] };
        let err = |status: u16, msg: &str| {
            resp(
                status,
                ResponseBody::Json(obj(vec![
                    ("error", Json::Str(msg.to_string())),
                    ("status", Json::Int(status as i64)),
                ])),
            )
        };
        if method == "GET" && path == "/approvals" {
            let items: Vec<Json> = gw
                .list()
                .into_iter()
                .map(|s| {
                    obj(vec![
                        ("id", Json::Str(s.id)),
                        ("message", Json::Str(s.message)),
                        ("type", Json::Str(s.ty)),
                        ("expires_at", Json::Int(s.expires_at)),
                    ])
                })
                .collect();
            return resp(200, ResponseBody::Json(obj(vec![("pending", Json::Array(items))])));
        }
        if method == "GET" {
            // Link de decisión (A1.v3): /approvals/{id}/{token}?d=yes|no. Respuestas
            // en HTML (el humano viene de un SMS/chat); sí/no solamente — `ask` con
            // `value` sigue siendo POST-only.
            let rest = path.strip_prefix("/approvals/").unwrap_or_default();
            let (id, token) = rest.split_once('/').unwrap_or((rest, ""));
            let approve = match query.get("d").map(String::as_str) {
                Some("yes") => true,
                Some("no") => false,
                _ => {
                    return Self::approval_link_page(
                        400,
                        "Missing decision",
                        "This approval link needs a decision parameter: append ?d=yes to \
                         approve or ?d=no to deny.",
                    )
                }
            };
            return match gw.respond(id, token, Some(approve), None) {
                ApprovalOutcome::Accepted => {
                    let (title, verb) =
                        if approve { ("Approved", "approved") } else { ("Denied", "denied") };
                    Self::approval_link_page(
                        200,
                        title,
                        &format!(
                            "The pending step was {}. This decision was recorded from a \
                             HUMAN following an approval link. You can close this tab.",
                            verb
                        ),
                    )
                }
                ApprovalOutcome::NotFound => Self::approval_link_page(
                    404,
                    "Not found",
                    "This approval link is no longer valid — the request may have expired, \
                     or a HUMAN already answered it.",
                ),
                ApprovalOutcome::BadToken => Self::approval_link_page(
                    403,
                    "Invalid link",
                    "The token in this link is not valid for this approval. The gate is \
                     still waiting for a HUMAN with the correct link.",
                ),
            };
        }
        let id = path.strip_prefix("/approvals/").unwrap_or_default();
        let parsed: serde_json::Value = match serde_json::from_str(body_str) {
            Ok(v) => v,
            Err(_) => {
                return err(
                    400,
                    "malformed body — expected JSON {\"token\": \"...\", \"decision\": true|false} \
                     or {\"token\": \"...\", \"value\": \"text\"}",
                )
            }
        };
        let token = match parsed.get("token").and_then(|t| t.as_str()) {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => return err(400, "missing \"token\" — the one-time token was printed on the server console when the approval was queued"),
        };
        let decision = parsed.get("decision").and_then(|d| d.as_bool());
        let value = parsed.get("value").and_then(|v| v.as_str());
        if decision.is_none() && value.is_none() {
            return err(
                400,
                "missing \"decision\" (true|false, for approve/confirm) or \"value\" (text, for ask)",
            );
        }
        match gw.respond(id, &token, decision, value) {
            ApprovalOutcome::Accepted => {
                resp(200, ResponseBody::Json(obj(vec![("ok", Json::Bool(true))])))
            }
            ApprovalOutcome::NotFound => err(
                404,
                "no pending approval with that id — it may have expired, or a HUMAN already answered it",
            ),
            ApprovalOutcome::BadToken => err(
                403,
                "invalid token for this approval — the gate is still waiting for a HUMAN with the correct token",
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &self,
        method: &str,
        path: &str,
        query: IndexMap<String, String>,
        headers: Vec<(String, String)>,
        body_str: &str,
        body_raw: &[u8],
        body_file: Option<&str>,
        client_ip: &str,
    ) -> Dispatched {
        let resp = |status, body| Dispatched::Response { status, body, headers: vec![] };

        // Rutas reservadas `/approvals` (A1.v2/v3): interceptadas ANTES de las rutas
        // de usuario (como `/llms.txt`); sólo existen si el runtime cableó la cola.
        if self.is_approvals_route(method, path) {
            return self.approvals_response(method, path, &query, body_str);
        }

        // vhost (Lote 1): elegir la tabla del host según el header `Host`. Sin vhosts
        // declarados, `host` es siempre el default → comportamiento idéntico al previo.
        let host = self.select_host(&header_value(&headers, "host"));

        let (mut route_idx, mut params) = match host.match_route(method, path) {
            Some((i, p)) => (Some(i), p),
            None => (None, IndexMap::new()),
        };

        // Negociación por sufijo de URL (.md/.json/.html): sólo si un :param se
        // tragó el sufijo. Un estático real en el path exacto gana primero.
        let mut explicit_fmt: Option<String> = None;
        let (logical_path, sfx) = split_format_suffix(path);
        if let (Some(s), Some(idx)) = (sfx, route_idx) {
            if param_last_segment(&host.routes[idx].path) {
                if method == "GET" && !host.static_mounts.is_empty() {
                    if let Some(sr) = host.serve_static_full(path, &headers) {
                        return Dispatched::Response {
                            status: sr.status,
                            body: ResponseBody::Raw(RawResponse {
                                body: sr.body,
                                content_type: sr.content_type,
                                status: sr.status,
                            }),
                            headers: sr.extra,
                        };
                    }
                }
                if let Some((lidx, lparams)) = host.match_route(method, &logical_path) {
                    route_idx = Some(lidx);
                    params = lparams;
                    explicit_fmt = Some(s);
                }
            }
        }

        let idx = match route_idx {
            Some(i) => i,
            None => {
                let allowed = host.methods_for_path(path);
                if !allowed.is_empty() {
                    // 405 — `errors with` puede darle forma; el header Allow se conserva.
                    if self.error_handler.is_some() {
                        let ectx = min_ctx(method, path, &query, &headers, body_str, body_raw, body_file, client_ip);
                        if let Some((st, body, mut hdrs)) = self.custom_error(405, "method not allowed", &ectx) {
                            hdrs.push(("Allow".to_string(), allowed.join(", ")));
                            return Dispatched::Response { status: st, body, headers: hdrs };
                        }
                    }
                    return Dispatched::Response {
                        status: 405,
                        body: ResponseBody::Json(obj(vec![
                            ("error", Json::Str("method not allowed".into())),
                            ("status", Json::Int(405)),
                        ])),
                        headers: vec![("Allow".to_string(), allowed.join(", "))],
                    };
                }
                if method == "GET" {
                    if !host.static_mounts.is_empty() {
                        if let Some(sr) = host.serve_static_full(path, &headers) {
                            return Dispatched::Response {
                                status: sr.status,
                                body: ResponseBody::Raw(RawResponse {
                                    body: sr.body,
                                    content_type: sr.content_type,
                                    status: sr.status,
                                }),
                                headers: sr.extra,
                            };
                        }
                    }
                    if let Some(disc) = self.discovery_response(path) {
                        return resp(disc.status, ResponseBody::Raw(disc));
                    }
                }
                let msg = format!("no route for {} {}", method, path);
                if self.error_handler.is_some() {
                    let ectx = min_ctx(method, path, &query, &headers, body_str, body_raw, body_file, client_ip);
                    if let Some((st, body, hdrs)) = self.custom_error(404, &msg, &ectx) {
                        return Dispatched::Response { status: st, body, headers: hdrs };
                    }
                }
                return resp(
                    404,
                    ResponseBody::Json(obj(vec![
                        ("error", Json::Str(msg)),
                        ("status", Json::Int(404)),
                    ])),
                );
            }
        };

        // Rate limit (tras matchear la ruta, antes de auth/handler).
        let mut rate_headers: Vec<(String, String)> = Vec::new();
        if let Some((capacity, window)) = host.routes[idx].rate_limit {
            let zone = host.routes[idx].rate_zone.clone().unwrap_or_else(|| "None".to_string());
            let key = format!("{}|{}", zone, client_ip);
            let (ok, remaining, retry_after, reset) = self.rate_limiter.check(&key, capacity, window);
            rate_headers = vec![
                ("RateLimit-Limit".to_string(), capacity.to_string()),
                ("RateLimit-Remaining".to_string(), remaining.to_string()),
                ("RateLimit-Reset".to_string(), (reset as i64 + 1).to_string()),
            ];
            if !ok {
                let headers_429 = vec![
                    ("RateLimit-Limit".to_string(), capacity.to_string()),
                    ("RateLimit-Remaining".to_string(), "0".to_string()),
                    ("RateLimit-Reset".to_string(), (reset as i64 + 1).to_string()),
                    ("Retry-After".to_string(), (retry_after as i64 + 1).to_string()),
                ];
                return Dispatched::Response {
                    status: 429,
                    body: ResponseBody::Json(obj(vec![
                        ("error", Json::Str("rate limit exceeded".into())),
                        ("status", Json::Int(429)),
                    ])),
                    headers: headers_429,
                };
            }
        }

        // Parse del body JSON (sólo error si el cliente declaró JSON).
        let mut json_obj: Option<serde_json::Value> = None;
        if !body_str.is_empty() {
            let ctype = header_value(&headers, "content-type").to_lowercase();
            match serde_json::from_str::<serde_json::Value>(body_str) {
                Ok(v) => json_obj = Some(v),
                Err(_) => {
                    if ctype.contains("json") {
                        return Dispatched::Response {
                            status: 400,
                            body: ResponseBody::Json(obj(vec![
                                ("error", Json::Str("malformed JSON body".into())),
                                ("status", Json::Int(400)),
                            ])),
                            headers: vec![],
                        };
                    }
                }
            }
        }

        let mut ctx = Ctx {
            method: method.to_string(),
            path: path.to_string(),
            query,
            params,
            headers: headers.clone(),
            body: body_str.to_string(),
            body_raw: body_raw.to_vec(),
            body_file: body_file.map(|s| s.to_string()),
            json: json_obj,
            client_ip: client_ip.to_string(),
            user: None,
        };

        // Auth. El `ctx` ya existe (user aún nothing) — el hook lo recibe entero
        // para tasks de 2 parámetros (sesiones por cookie, ítem C).
        if host.routes[idx].requires_auth {
            let token = bearer_token(&headers);
            let user = host.auth_handler.as_ref().and_then(|ah| ah(&token, &ctx));
            match &user {
                None | Some(SynValue::Nothing) => {
                    // 401 — `errors with` puede redirigir al login o dar una página.
                    if let Some((st, body, mut hdrs)) = self.custom_error(401, "unauthorized", &ctx) {
                        hdrs.extend(rate_headers);
                        return Dispatched::Response { status: st, body, headers: hdrs };
                    }
                    return Dispatched::Response {
                        status: 401,
                        body: ResponseBody::Json(obj(vec![
                            ("error", Json::Str("unauthorized".into())),
                            ("status", Json::Int(401)),
                        ])),
                        headers: rate_headers,
                    };
                }
                Some(_) => ctx.user = user,
            }
            // T6.4 — SEGUNDA etapa del rate limit: por IDENTIDAD del sujeto ya
            // autenticado, en su propio namespace de buckets.
            //
            // Por qué DOS etapas y no mover la primera acá: el chequeo por IP corre
            // antes del auth a propósito, porque el auth task ejecuta el intérprete
            // (un worker del pool por request). Si el único límite fuera por
            // identidad, un atacante sin credenciales válidas quemaría workers
            // gratis — el limitador dejaría de frenar justo el ataque que hoy sí
            // frena. Con las dos, el presupuesto efectivo es el mínimo de ambos:
            // la IP acota al anónimo, la identidad evita que agentes distintos
            // detrás del mismo NAT se roben la cuota entre sí.
            if let Some((capacity, window)) = host.routes[idx].rate_limit {
                if let Some(id) = ctx.user.as_ref().and_then(identity_of) {
                    let zone = host.routes[idx].rate_zone.as_deref().unwrap_or("None");
                    let key = format!("user:{}|{}", zone, id);
                    let (ok, remaining, retry_after, reset) =
                        self.rate_limiter.check(&key, capacity, window);
                    // Los headers reflejan el cupo de la identidad (el más
                    // informativo para un cliente autenticado).
                    rate_headers = vec![
                        ("RateLimit-Limit".to_string(), capacity.to_string()),
                        ("RateLimit-Remaining".to_string(), remaining.to_string()),
                        ("RateLimit-Reset".to_string(), (reset as i64 + 1).to_string()),
                    ];
                    if !ok {
                        let mut headers_429 = rate_headers.clone();
                        headers_429[1] = ("RateLimit-Remaining".to_string(), "0".to_string());
                        headers_429.push((
                            "Retry-After".to_string(),
                            (retry_after as i64 + 1).to_string(),
                        ));
                        return Dispatched::Response {
                            status: 429,
                            body: ResponseBody::Json(obj(vec![
                                ("error", Json::Str("rate limit exceeded".into())),
                                ("status", Json::Int(429)),
                            ])),
                            headers: headers_429,
                        };
                    }
                }
            }
        }

        // Reverse proxy (Lote 2): forwardea la request al upstream y devuelve su
        // respuesta (status + content-type + headers end-to-end + body).
        if let Some(target) = &host.routes[idx].proxy_target {
            return match proxy_forward(target, &ctx) {
                Ok((status, content_type, mut up_headers, body)) => {
                    // rate-limit (si hubo) + los end-to-end del upstream.
                    let mut headers = rate_headers;
                    headers.append(&mut up_headers);
                    Dispatched::Response {
                        status,
                        body: ResponseBody::Raw(RawResponse { body, content_type, status }),
                        headers,
                    }
                }
                Err(e) => Dispatched::Response {
                    status: 502,
                    body: self.server_error(&format!("proxy error: {}", e)),
                    headers: rate_headers,
                },
            };
        }

        // Streaming SSE: adquirir slot y delegar al camino de stream.
        if host.routes[idx].streaming {
            if !self.try_acquire_stream() {
                return Dispatched::Response {
                    status: 503,
                    body: ResponseBody::Json(obj(vec![
                        ("error", Json::Str("too many concurrent streams".into())),
                        ("status", Json::Int(503)),
                    ])),
                    headers: vec![("Retry-After".to_string(), "5".to_string())],
                };
            }
            return Dispatched::Stream {
                stream_handler: host.routes[idx].stream_handler.clone(),
                ctx: Box::new(ctx),
            };
        }

        // Correr el handler.
        let mut custom_headers: Vec<(String, String)> = Vec::new();
        let (status, body) = match (host.routes[idx].handler)(&ctx) {
            GiveOutcome::Give(v) => {
                // with_header()/set_cookie(): desenvolver el wrapper — `inner` se
                // procesa exactamente como cualquier give-value y los headers
                // acumulados se emiten al final (después de los de rate-limit).
                // Cubre TODOS los caminos de salida: respuesta directa, negociación
                // de contenido, envelope JSON y redirect.
                let v = match v {
                    Some(SynValue::Server(s)) => match &*s {
                        ServerValue::WithHeaders { inner, headers } => {
                            custom_headers = headers.clone();
                            Some((**inner).clone())
                        }
                        _ => Some(SynValue::Server(s)),
                    },
                    other => other,
                };
                let is_content = matches!(
                    v.as_ref(),
                    Some(SynValue::Server(s)) if matches!(&**s, ServerValue::Content(_))
                );
                if is_content {
                    // content() se negocia: sufijo explícito (.md/.json/.html) gana,
                    // si no el header Accept (default HTML).
                    let fmt = explicit_fmt
                        .clone()
                        .unwrap_or_else(|| negotiate_format(&header_value(&ctx.headers, "accept")));
                    let raw = render_content(v.as_ref().unwrap(), &fmt);
                    (raw.status, ResponseBody::Raw(raw))
                } else {
                    match build_response(v.as_ref(), &ctx.query) {
                        Ok(sb) => sb,
                        Err(e) => self.shape_500(&e, &ctx, &mut custom_headers),
                    }
                }
            }
            GiveOutcome::Validation { message, field } => (
                400,
                ResponseBody::Json(obj(vec![
                    ("error", Json::Str(message)),
                    ("status", Json::Int(400)),
                    ("field", field.map(Json::Str).unwrap_or(Json::Null)),
                ])),
            ),
            GiveOutcome::Error(msg) => self.shape_500(&msg, &ctx, &mut custom_headers),
        };
        let mut headers = rate_headers;
        headers.append(&mut custom_headers);
        Dispatched::Response { status, body, headers }
    }
}

// -- reverse proxy (Lote 2) --

/// Respuesta del upstream de un proxy: (status, content_type, headers, body).
type ProxyResponse = (u16, String, Vec<(String, String)>, Vec<u8>);

/// Forward sync de la request al upstream `http://host[:port][/base]`. Devuelve
/// (status, content_type, headers end-to-end, body). Cliente HTTP/1.1 mínimo
/// (Connection: close); corre dentro de spawn_blocking, así que bloquear está bien.
fn proxy_forward(target: &str, ctx: &Ctx) -> Result<ProxyResponse, String> {
    use std::io::Read;
    let rest = target
        .strip_prefix("http://")
        .ok_or_else(|| "proxy target must start with http://".to_string())?;
    let (authority, base) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let addr = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{}:80", authority)
    };
    let base = base.trim_end_matches('/');
    let mut fwd_path = format!("{}{}", base, ctx.path);
    if !ctx.query.is_empty() {
        let qs: Vec<String> = ctx.query.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        fwd_path.push('?');
        fwd_path.push_str(&qs.join("&"));
    }

    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("connect {}: {}", addr, e))?;
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let mut req = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", ctx.method, fwd_path, authority);
    for (k, v) in &ctx.headers {
        let lk = k.to_lowercase();
        // Saltar hop-by-hop / los que recalculamos.
        if matches!(
            lk.as_str(),
            "host" | "connection" | "content-length" | "transfer-encoding" | "accept-encoding"
        ) {
            continue;
        }
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    req.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", ctx.body.len()));
    stream.write_all(req.as_bytes()).map_err(|e| format!("write head: {}", e))?;
    stream.write_all(ctx.body.as_bytes()).map_err(|e| format!("write body: {}", e))?;
    let _ = stream.flush();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| format!("read: {}", e))?;
    parse_proxy_response(&raw)
}

fn parse_proxy_response(raw: &[u8]) -> Result<ProxyResponse, String> {
    let pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed upstream response".to_string())?;
    let head = String::from_utf8_lossy(&raw[..pos]);
    let body_start = pos + 4;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "bad upstream status line".to_string())?;
    let mut content_type = "application/octet-stream".to_string();
    let mut chunked = false;
    // Headers end-to-end del upstream a reenviar al cliente. Se excluyen: content-type
    // (se devuelve aparte y hyper lo emite desde head.content_type), los hop-by-hop
    // (RFC 7230 §6.1) y content-length (hyper lo recalcula, y tras dechunk cambia).
    let mut headers: Vec<(String, String)> = Vec::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let lk = k.trim().to_lowercase();
            let vv = v.trim();
            match lk.as_str() {
                "content-type" => content_type = vv.to_string(),
                "transfer-encoding" => {
                    if vv.to_lowercase().contains("chunked") {
                        chunked = true;
                    }
                }
                "content-length" | "connection" | "keep-alive" | "proxy-authenticate"
                | "proxy-authorization" | "te" | "trailer" | "upgrade" => {}
                // Todo lo demás end-to-end (Location, Set-Cookie [cada ocurrencia],
                // Cache-Control, ETag, Last-Modified, Vary, WWW-Authenticate,
                // Content-Encoding, X-*, …). Se preserva el casing original de la clave.
                _ => headers.push((k.trim().to_string(), vv.to_string())),
            }
        }
    }
    let body_raw = &raw[body_start..];
    let body = if chunked { dechunk(body_raw) } else { body_raw.to_vec() };
    Ok((status, content_type, headers, body))
}

/// De-chunk de un body `Transfer-Encoding: chunked`.
fn dechunk(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let nl = match data[i..].windows(2).position(|w| w == b"\r\n") {
            Some(n) => n,
            None => break,
        };
        let size_str = String::from_utf8_lossy(&data[i..i + nl]);
        let size = usize::from_str_radix(size_str.trim().split(';').next().unwrap_or("").trim(), 16)
            .unwrap_or(0);
        i += nl + 2;
        if size == 0 || i + size > data.len() {
            break;
        }
        out.extend_from_slice(&data[i..i + size]);
        i += size + 2; // chunk + CRLF
    }
    out
}

// -- helpers de matching/estáticos (libres) --

fn norm_prefix(prefix: &str) -> String {
    if prefix.is_empty() || prefix == "/" {
        return "/".to_string();
    }
    format!("/{}/", prefix.trim_matches('/'))
}

fn within(base: &Path, target: &Path) -> bool {
    target == base || target.starts_with(base)
}

/// Resuelve `rel` a un archivo real dentro de `base` (anti-traversal), o None.
fn resolve_in(base: &Path, rel: &str) -> Option<PathBuf> {
    let rel = unquote(rel);
    let rel = rel.trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    // Path absoluto o con drive-letter (C:) no puede estar dentro de uno relativo.
    if Path::new(rel).is_absolute() || (rel.len() > 1 && rel.as_bytes()[1] == b':') {
        return None;
    }
    let mut target = base.join(rel).canonicalize().ok()?;
    if !within(base, &target) {
        return None;
    }
    if target.is_dir() {
        target = target.join("index.html").canonicalize().ok()?;
        if !within(base, &target) {
            return None;
        }
    }
    if !target.is_file() {
        return None;
    }
    Some(target)
}

fn static_content_type(path: &Path) -> String {
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    // Web types pinneadas (el contrato, deterministas entre hosts).
    if let Some(t) = web_content_type(&ext) {
        return t.to_string();
    }
    // Fallback: mimetypes.guess_type (tabla incorporada + registro de Windows).
    match crate::mimetypes::guess(&ext) {
        None => "application/octet-stream".to_string(),
        Some(ct) => {
            if ct.starts_with("text/") && !ct.contains("charset") {
                format!("{}; charset=utf-8", ct)
            } else {
                ct
            }
        }
    }
}

fn header_value(headers: &[(String, String)], name: &str) -> String {
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

fn bearer_token(headers: &[(String, String)]) -> String {
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

fn render_li(item: &SynValue) -> String {
    if is_node(item) {
        format!("<li>{}</li>", render_node_html(item))
    } else {
        format!("<li>{}</li>", esc(&item.to_string()))
    }
}

fn render_node_html(node: &SynValue) -> String {
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

fn render_html(tree: &SynValue) -> String {
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

fn md_inline(item: &SynValue) -> String {
    if is_node(item) {
        render_node_md(item).trim().to_string()
    } else {
        item.to_string()
    }
}

fn render_node_md(node: &SynValue) -> String {
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

fn render_markdown(tree: &SynValue) -> String {
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

// =========================================================
// Builtins de respuesta + vocabulario de contenido
// =========================================================

fn text_arg(v: Option<&SynValue>) -> String {
    match v {
        None => String::new(),
        Some(SynValue::Text(s)) => s.to_string(),
        Some(o) => o.to_string(),
    }
}

fn make_raw_val(body: String, ct: &str, status: i64) -> SynValue {
    SynValue::Server(Rc::new(ServerValue::Raw { body, content_type: ct.to_string(), status }))
}

fn make_rawbytes_val(body: Vec<u8>, ct: &str, status: i64) -> SynValue {
    SynValue::Server(Rc::new(ServerValue::RawBytes { body, content_type: ct.to_string(), status }))
}

fn make_envelope(status: i64, value: SynValue) -> SynValue {
    SynValue::Server(Rc::new(ServerValue::Envelope { status, value }))
}

fn make_redirect_val(location: String, status: i64) -> SynValue {
    SynValue::Server(Rc::new(ServerValue::Redirect { location, status }))
}

// =========================================================
// Headers custom + cookies (tanda web-auth, ítems A/B)
// =========================================================

/// ¿`c` es un token char RFC 7230 §3.2.6? (los válidos en un nombre de header y
/// también en un nombre de cookie, RFC 6265).
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

/// Headers que NO se pueden fijar con `with_header` (los maneja el server o tienen
/// builtin propio). Cada uno con el porqué, para el mensaje de error.
fn forbidden_header_reason(lower: &str) -> Option<&'static str> {
    match lower {
        "content-length" | "transfer-encoding" => {
            Some("the server computes message framing itself")
        }
        "connection" | "keep-alive" | "upgrade" | "te" | "trailer" => {
            Some("hop-by-hop headers are managed by the server")
        }
        "content-type" => Some("set it with respond(body, content_type) instead"),
        _ => None,
    }
}

/// Valida nombre y valor de un header custom (fallar fuerte, G2). `who` es el
/// builtin que reporta el error (`with_header` / `set_cookie`).
fn validate_header(who: &str, name: &str, value: &str) -> Result<(), Control> {
    if name.is_empty() {
        return Err(serve_err(&format!("{}: the header name cannot be empty", who)));
    }
    if let Some(bad) = name.chars().find(|c| !is_token_char(*c)) {
        return Err(serve_err(&format!(
            "{}: invalid header name {:?} — {:?} is not allowed (RFC 7230 token chars only: A-Za-z0-9 and !#$%&'*+-.^_`|~)",
            who, name, bad
        )));
    }
    if let Some(reason) = forbidden_header_reason(&name.to_ascii_lowercase()) {
        return Err(serve_err(&format!(
            "{}: the header {:?} cannot be set here — {}",
            who, name, reason
        )));
    }
    // Header injection / response splitting: misma doctrina que redirect() —
    // rechazo explícito, jamás sanear en silencio. El resto de los controles
    // también se rechaza (la capa de emisión los descartaría en silencio).
    if value.contains('\r') || value.contains('\n') {
        return Err(serve_err(&format!(
            "{}: the value of {:?} must not contain CR or LF (header injection)",
            who, name
        )));
    }
    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(serve_err(&format!(
            "{}: the value of {:?} must not contain control characters",
            who, name
        )));
    }
    Ok(())
}

/// Envuelve (o acumula sobre) un `WithHeaders`. `with_header` repetido sobre el
/// mismo valor ACUMULA en el mismo wrapper — no anida; el orden se preserva y los
/// nombres repetidos son válidos (`Set-Cookie` múltiple).
fn append_header_val(resp: &SynValue, name: String, value: String) -> SynValue {
    if let SynValue::Server(s) = resp {
        if let ServerValue::WithHeaders { inner, headers } = &**s {
            let mut hs = headers.clone();
            hs.push((name, value));
            return SynValue::Server(Rc::new(ServerValue::WithHeaders {
                inner: inner.clone(),
                headers: hs,
            }));
        }
    }
    SynValue::Server(Rc::new(ServerValue::WithHeaders {
        inner: Box::new(resp.clone()),
        headers: vec![(name, value)],
    }))
}

/// ¿`c` es un cookie-octet RFC 6265 §4.1.1? (excluye controles, espacio, `"`,
/// coma, punto y coma y backslash).
fn is_cookie_octet(c: char) -> bool {
    matches!(c, '\x21' | '\x23'..='\x2b' | '\x2d'..='\x3a' | '\x3c'..='\x5b' | '\x5d'..='\x7e')
}

/// Opciones de `set_cookie`/`clear_cookie` ya validadas.
struct CookieOpts {
    max_age: Option<i64>,
    path: String,
    domain: Option<String>,
    secure: bool,
    http_only: bool,
    same_site: String,
}

/// Parsea y valida el map de opts (fallar fuerte: clave desconocida o valor
/// inválido → error con el fix). `allow_all=false` (clear_cookie) sólo acepta
/// `path`/`domain` — el resto de atributos no participa del borrado.
fn parse_cookie_opts(who: &str, opts: Option<&SynValue>, allow_all: bool) -> Result<CookieOpts, Control> {
    let mut out = CookieOpts {
        max_age: None,
        path: "/".to_string(),
        domain: None,
        secure: true,
        http_only: true,
        same_site: "Lax".to_string(),
    };
    let map = match opts {
        None | Some(SynValue::Nothing) => return Ok(out),
        Some(SynValue::Map(m)) => m.borrow().clone(),
        Some(other) => {
            return Err(serve_err(&format!(
                "{}: opts must be a map, got {}",
                who,
                other.type_name()
            )))
        }
    };
    for (k, v) in &map {
        match (k.as_str(), allow_all) {
            ("path", _) => out.path = v.to_string(),
            ("domain", _) => out.domain = Some(v.to_string()),
            ("max_age", true) => match v {
                SynValue::Number(n) => match n.to_i64_trunc() {
                    Some(ma) if ma >= 0 => out.max_age = Some(ma),
                    _ => {
                        return Err(serve_err(&format!(
                            "{}: max_age must be an integer >= 0 (seconds), got {}",
                            who, v
                        )))
                    }
                },
                _ => {
                    return Err(serve_err(&format!(
                        "{}: max_age must be an integer >= 0 (seconds), got {}",
                        who,
                        v.type_name()
                    )))
                }
            },
            ("secure", true) => match v {
                SynValue::Bool(b) => out.secure = *b,
                _ => {
                    return Err(serve_err(&format!(
                        "{}: secure must be a bool, got {}",
                        who,
                        v.type_name()
                    )))
                }
            },
            ("http_only", true) => match v {
                SynValue::Bool(b) => out.http_only = *b,
                _ => {
                    return Err(serve_err(&format!(
                        "{}: http_only must be a bool, got {}",
                        who,
                        v.type_name()
                    )))
                }
            },
            ("same_site", true) => {
                let s = v.to_string();
                match s.to_ascii_lowercase().as_str() {
                    "strict" => out.same_site = "Strict".to_string(),
                    "lax" => out.same_site = "Lax".to_string(),
                    "none" => out.same_site = "None".to_string(),
                    _ => {
                        return Err(serve_err(&format!(
                            "{}: same_site must be \"Strict\", \"Lax\" or \"None\", got {:?}",
                            who, s
                        )))
                    }
                }
            }
            (other, _) => {
                let valid = if allow_all {
                    "max_age, path, domain, secure, http_only, same_site"
                } else {
                    "path, domain"
                };
                return Err(serve_err(&format!(
                    "{}: unknown option {:?} (valid options: {})",
                    who, other, valid
                )));
            }
        }
    }
    Ok(out)
}

/// Valida nombre/valor de cookie y path/domain (RFC 6265, fallar fuerte).
fn validate_cookie(who: &str, name: &str, value: &str, o: &CookieOpts) -> Result<(), Control> {
    if name.is_empty() {
        return Err(serve_err(&format!("{}: the cookie name cannot be empty", who)));
    }
    if let Some(bad) = name.chars().find(|c| !is_token_char(*c)) {
        return Err(serve_err(&format!(
            "{}: invalid cookie name {:?} — {:?} is not allowed (token chars only: no spaces, '=', ';' or ',')",
            who, name, bad
        )));
    }
    if let Some(bad) = value.chars().find(|c| !is_cookie_octet(*c)) {
        return Err(serve_err(&format!(
            "{}: invalid cookie value — {:?} is not allowed (RFC 6265 forbids spaces, quotes, ';', ',', '\\' and control chars). Encode it first: decode(bytes(v), \"base64url\")",
            who, bad
        )));
    }
    // SameSite=None exige Secure: el browser rechaza la cookie si no — mejor
    // fallar acá con el porqué que debuggear cookies que "no llegan".
    if o.same_site == "None" && !o.secure {
        return Err(serve_err(&format!(
            "{}: same_site \"None\" requires secure: true (browsers reject SameSite=None cookies without Secure)",
            who
        )));
    }
    // El Path/Domain viajan dentro de un header: mismas reglas anti-injection.
    for (attr, val) in [("path", &o.path), ("domain", o.domain.as_ref().unwrap_or(&String::new()))] {
        if val.chars().any(|c| c.is_ascii_control() || c == ';') {
            return Err(serve_err(&format!(
                "{}: the {} option must not contain ';' or control characters",
                who, attr
            )));
        }
    }
    Ok(())
}

/// Arma el string `Set-Cookie` (tras `validate_cookie`).
fn build_set_cookie(who: &str, name: &str, value: &str, o: &CookieOpts) -> Result<String, Control> {
    validate_cookie(who, name, value, o)?;
    let mut s = format!("{}={}", name, value);
    if let Some(ma) = o.max_age {
        s.push_str(&format!("; Max-Age={}", ma));
    }
    s.push_str(&format!("; Path={}", o.path));
    if let Some(d) = &o.domain {
        s.push_str(&format!("; Domain={}", d));
    }
    if o.secure {
        s.push_str("; Secure");
    }
    if o.http_only {
        s.push_str("; HttpOnly");
    }
    s.push_str(&format!("; SameSite={}", o.same_site));
    Ok(s)
}

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

fn redirect_err(msg: &str) -> synsema_core::interpreter::Control {
    synsema_core::interpreter::Control::Error(synsema_core::interpreter::RuntimeError::new(
        msg.to_string(),
    ))
}

/// Error genérico de un builtin de servidor (sin ubicación).
fn serve_err(msg: &str) -> synsema_core::interpreter::Control {
    synsema_core::interpreter::Control::Error(synsema_core::interpreter::RuntimeError::new(
        msg.to_string(),
    ))
}

fn n_nodes(v: Option<&SynValue>) -> SynValue {
    match v {
        Some(SynValue::List(l)) => syn_list(l.borrow().clone()),
        _ => syn_list(Vec::new()),
    }
}

fn n_meta(v: Option<&SynValue>) -> SynValue {
    match v {
        Some(SynValue::Map(m)) => {
            let mut out = IndexMap::new();
            for (k, val) in m.borrow().iter() {
                out.insert(k.clone(), syn_text(text_arg(Some(val))));
            }
            syn_map(out)
        }
        _ => syn_map(IndexMap::new()),
    }
}

/// Registra los helpers de respuesta (ok/created/not_found/fail/html/respond) y el
/// vocabulario de contenido (page/heading/prose/list/…/content). El oráculo los
/// registra en el intérprete principal SIEMPRE → acá van en cada intérprete.
pub fn register_serve_builtins(interp: &Interpreter) {
    interp.register_builtin(
        "ok",
        1,
        Rc::new(|_i, a, _l| Ok(make_envelope(200, a.first().cloned().unwrap_or_else(syn_nothing)))),
    );
    interp.register_builtin(
        "created",
        1,
        Rc::new(|_i, a, _l| Ok(make_envelope(201, a.first().cloned().unwrap_or_else(syn_nothing)))),
    );
    interp.register_builtin(
        "not_found",
        1,
        Rc::new(|_i, a, _l| {
            let value = a.first().cloned().unwrap_or_else(|| syn_text("not found"));
            let value = if matches!(value, SynValue::Map(_)) {
                value
            } else {
                let mut m = IndexMap::new();
                m.insert("error".to_string(), syn_text(value.to_string()));
                m.insert("status".to_string(), syn_int(404));
                syn_map(m)
            };
            Ok(make_envelope(404, value))
        }),
    );
    interp.register_builtin(
        "fail",
        -1,
        Rc::new(|_i, a, _l| {
            let mut code = 400i64;
            let mut msg = "error".to_string();
            if a.len() >= 2 {
                if matches!(a[0], SynValue::Number(_)) {
                    code = num_i64(&a[0]);
                    msg = a[1].to_string();
                } else {
                    msg = a[0].to_string();
                    if matches!(a[1], SynValue::Number(_)) {
                        code = num_i64(&a[1]);
                    }
                }
            } else if a.len() == 1 {
                if matches!(a[0], SynValue::Number(_)) {
                    code = num_i64(&a[0]);
                } else {
                    msg = a[0].to_string();
                }
            }
            let mut body = IndexMap::new();
            body.insert("error".to_string(), syn_text(msg));
            body.insert("status".to_string(), syn_int(code));
            Ok(make_envelope(code, syn_map(body)))
        }),
    );
    interp.register_builtin(
        "html",
        1,
        Rc::new(|_i, a, _l| Ok(make_raw_val(text_arg(a.first()), "text/html; charset=utf-8", 200))),
    );
    // redirect(url, status?) — respuesta 3xx con header Location. status default 301.
    interp.register_builtin(
        "redirect",
        -1,
        Rc::new(|_i, a, _l| {
            let url = text_arg(a.first());
            // URL vacía → `Location:` vacío, inútil. Falla fuerte.
            if url.is_empty() {
                return Err(redirect_err("redirect(url): la URL no puede estar vacía"));
            }
            // Seguridad: un Location con CR/LF permitiría header injection / response
            // splitting. Se rechaza explícito (falla fuerte, no se sanea en silencio).
            if url.contains('\r') || url.contains('\n') {
                return Err(redirect_err("redirect(url): la URL no puede contener CR ni LF"));
            }
            // status opcional (default 301 permanente); fuera de 3xx → error explícito
            // (no se clampea en silencio, para no enmascarar un bug del programa).
            let status = match a.get(1) {
                Some(n @ SynValue::Number(_)) => num_i64(n),
                _ => 301,
            };
            if !(300..=399).contains(&status) {
                return Err(redirect_err(&format!(
                    "redirect(url, status): status debe ser 3xx, recibido {}",
                    status
                )));
            }
            Ok(make_redirect_val(url, status))
        }),
    );
    interp.register_builtin(
        "respond",
        -1,
        Rc::new(|_i, a, _l| {
            let content = text_arg(a.first());
            let ct = if a.len() > 1 {
                text_arg(a.get(1))
            } else {
                "text/plain; charset=utf-8".to_string()
            };
            let status = match a.get(2) {
                Some(n @ SynValue::Number(_)) => num_i64(n),
                _ => 200,
            };
            Ok(make_raw_val(content, &ct, status))
        }),
    );
    // binary(bytes, content_type?, status?) — respuesta binaria cruda. content_type
    // default "application/octet-stream", status default 200. El body se escribe verbatim
    // al socket sin negociación. El primer arg DEBE ser bytes (error claro si no).
    interp.register_builtin(
        "binary",
        -1,
        Rc::new(|_i, a, _l| {
            let body = match a.first() {
                Some(SynValue::Bytes(b)) => b.to_vec(),
                Some(other) => {
                    return Err(serve_err(&format!(
                        "binary() expects bytes as the first argument, got {}",
                        other.type_name()
                    )))
                }
                None => return Err(serve_err("binary() requires a bytes argument")),
            };
            let ct = if a.len() > 1 {
                let c = text_arg(a.get(1));
                if c.is_empty() { "application/octet-stream".to_string() } else { c }
            } else {
                "application/octet-stream".to_string()
            };
            let status = match a.get(2) {
                Some(n @ SynValue::Number(_)) => num_i64(n),
                _ => 200,
            };
            Ok(make_rawbytes_val(body, &ct, status))
        }),
    );
    // with_header(resp, name, value) — header de respuesta custom sobre CUALQUIER
    // valor que un handler pueda devolver (tanda web-auth, ítem A). Acumula sobre
    // el mismo wrapper si el valor ya viene envuelto; los repetidos se emiten como
    // líneas separadas (`Set-Cookie` múltiple).
    interp.register_builtin(
        "with_header",
        3,
        Rc::new(|_i, a, _l| {
            let resp = a
                .first()
                .ok_or_else(|| serve_err("with_header(resp, name, value) requires a response"))?;
            let name = text_arg(a.get(1));
            let value = text_arg(a.get(2));
            validate_header("with_header", &name, &value)?;
            Ok(append_header_val(resp, name, value))
        }),
    );
    // set_cookie(resp, name, value, opts?) — emite `Set-Cookie` con defaults
    // seguros: Path=/; HttpOnly; Secure; SameSite=Lax (ítem B). opts: max_age
    // (segundos), path, domain, secure (bool), http_only (bool), same_site
    // ("Strict"|"Lax"|"None").
    interp.register_builtin(
        "set_cookie",
        -1,
        Rc::new(|_i, a, _l| {
            if !(3..=4).contains(&a.len()) {
                return Err(serve_err(
                    "set_cookie(resp, name, value, opts?) takes 3 or 4 arguments",
                ));
            }
            let name = text_arg(a.get(1));
            let value = text_arg(a.get(2));
            let opts = parse_cookie_opts("set_cookie", a.get(3), true)?;
            let cookie = build_set_cookie("set_cookie", &name, &value, &opts)?;
            Ok(append_header_val(&a[0], "Set-Cookie".to_string(), cookie))
        }),
    );
    // clear_cookie(resp, name, opts?) — borra la cookie: Max-Age=0 + Expires en
    // el pasado. `path`/`domain` deben coincidir con los del set para que el
    // browser la borre (por eso son las únicas opts válidas acá).
    interp.register_builtin(
        "clear_cookie",
        -1,
        Rc::new(|_i, a, _l| {
            if !(2..=3).contains(&a.len()) {
                return Err(serve_err("clear_cookie(resp, name, opts?) takes 2 or 3 arguments"));
            }
            let name = text_arg(a.get(1));
            let opts = parse_cookie_opts("clear_cookie", a.get(2), false)?;
            validate_cookie("clear_cookie", &name, "", &opts)?;
            // Expiración doble: Max-Age=0 (browsers modernos) + Expires en la
            // época (los viejos). Path/Domain deben coincidir con los del set.
            let mut cookie = format!(
                "{}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path={}",
                name, opts.path
            );
            if let Some(d) = &opts.domain {
                cookie.push_str(&format!("; Domain={}", d));
            }
            Ok(append_header_val(&a[0], "Set-Cookie".to_string(), cookie))
        }),
    );
    // Vocabulario de contenido semántico.
    interp.register_builtin(
        "page",
        -1,
        Rc::new(|_i, a, _l| {
            Ok(make_node(
                "page",
                vec![("nodes", n_nodes(a.first())), ("meta", n_meta(a.get(1)))],
            ))
        }),
    );
    interp.register_builtin(
        "heading",
        2,
        Rc::new(|_i, a, _l| {
            let level = match a.first() {
                Some(n @ SynValue::Number(_)) => num_i64(n),
                _ => 1,
            };
            Ok(make_node(
                "heading",
                vec![("level", syn_int(level)), ("text", syn_text(text_arg(a.get(1))))],
            ))
        }),
    );
    interp.register_builtin(
        "prose",
        1,
        Rc::new(|_i, a, _l| Ok(make_node("prose", vec![("text", syn_text(text_arg(a.first())))]))),
    );
    interp.register_builtin(
        "list",
        1,
        Rc::new(|_i, a, _l| Ok(make_node("list", vec![("items", n_nodes(a.first()))]))),
    );
    interp.register_builtin(
        "ordered_list",
        1,
        Rc::new(|_i, a, _l| Ok(make_node("ordered_list", vec![("items", n_nodes(a.first()))]))),
    );
    interp.register_builtin(
        "link",
        2,
        Rc::new(|_i, a, _l| {
            Ok(make_node(
                "link",
                vec![("text", syn_text(text_arg(a.first()))), ("href", syn_text(text_arg(a.get(1))))],
            ))
        }),
    );
    interp.register_builtin(
        "image",
        2,
        Rc::new(|_i, a, _l| {
            Ok(make_node(
                "image",
                vec![("src", syn_text(text_arg(a.first()))), ("alt", syn_text(text_arg(a.get(1))))],
            ))
        }),
    );
    interp.register_builtin(
        "section",
        1,
        Rc::new(|_i, a, _l| Ok(make_node("section", vec![("nodes", n_nodes(a.first()))]))),
    );
    interp.register_builtin(
        "code",
        -1,
        Rc::new(|_i, a, _l| {
            let lang = if a.len() > 1 { syn_text(text_arg(a.get(1))) } else { syn_nothing() };
            Ok(make_node("code", vec![("text", syn_text(text_arg(a.first()))), ("lang", lang)]))
        }),
    );
    interp.register_builtin(
        "raw",
        1,
        Rc::new(|_i, a, _l| Ok(make_node("raw", vec![("html", syn_text(text_arg(a.first())))]))),
    );
    // Charts nativos (Batch 8): chart_svg (texto SVG) + chart (nodo negociable).
    // PUROS y sin capability (G9): al registrarse acá quedan en TODOS los modos
    // (run/test/conform/serve) y funcionan dentro de `sandbox`.
    crate::charts::register_chart_builtins(interp);
    // Export PNG/PDF (Batch 9): svg_to_png / svg_to_pdf. Mismo patrón: puros,
    // sin capability, disponibles en todos los modos y dentro de `sandbox`.
    crate::raster::register_raster_builtins(interp);
    interp.register_builtin(
        "content",
        1,
        Rc::new(|_i, a, _l| {
            let tree = a
                .first()
                .cloned()
                .unwrap_or_else(|| make_node("page", vec![("nodes", syn_list(Vec::new())), ("meta", syn_map(IndexMap::new()))]));
            Ok(SynValue::Server(Rc::new(ServerValue::Content(Box::new(tree)))))
        }),
    );
}

// =========================================================
// Servidor HTTP (thread-per-connection, std::net)
// =========================================================

/// A2 batch 2 — Mapa compartido token→key-authorization que el listener HTTP sirve
/// para los challenges ACME HTTP-01.
pub type ChallengeStore = std::sync::Arc<std::sync::Mutex<HashMap<String, String>>>;

/// A2 batch 2 — Config TLS compartida y mutable (renovación ACME hace hot-swap).
pub type SharedServerConfig = std::sync::Arc<std::sync::RwLock<Arc<rustls::ServerConfig>>>;

// =========================================================
// Lote 2 — Servidor async (tokio/hyper/rustls)
// =========================================================
//
// Cáscara async: tokio acepta, hyper hace el framing HTTP/1.1+HTTP/2 (ALPN), y el
// intérprete corre SYNC por request en `spawn_blocking` (igual modelo snapshot-globales
// que antes). El `dispatch` se reusa intacto → mismas respuestas (byte-paridad sobre
// HTTP/1.1; el harness compara status+headers+body parseados).

/// Cuerpo de respuesta unificado (Full para sized, canal para SSE).
type RespBody = BoxBody<Bytes, std::convert::Infallible>;

/// Stack grande para los hilos que corren el intérprete: el tree-walker tiene guard de
/// recursión, pero le damos holgura como el viejo thread-per-conn (fib, tasks recursivas
/// profundas). Vive SOLO en el pool del intérprete y en los hilos de stream — NO en los
/// workers async de I/O de tokio (esos usan stack default).
const SERVE_STACK_SIZE: usize = 64 * 1024 * 1024;

/// Pool dedicado y ACOTADO para correr el intérprete sync por request.
///
/// Reemplaza el `spawn_blocking` por-request, que crecía contra el blocking pool de tokio
/// (hasta 512 hilos) heredando el stack de 64 MB → bajo keep-alive, N requests en vuelo =
/// N × 64 MB → OOM. Acá el tope es fijo: `#workers × 64 MB`, sin importar la concurrencia.
/// El exceso de requests **espera en la cola** (no se rechaza). El intérprete sigue sync.
///
/// Streams (SSE) NO usan este pool: corren en un hilo dedicado (acotado por `max_streams`)
/// para no agotar los workers — si no, unos pocos streams taparían el pool entero.
type InterpJob = Box<dyn FnOnce() + Send + 'static>;

struct InterpreterPool {
    tx: std::sync::mpsc::Sender<InterpJob>,
}

impl InterpreterPool {
    fn new(workers: usize) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<InterpJob>();
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..workers {
            let rx = rx.clone();
            let _ = std::thread::Builder::new()
                .name(format!("synsema-interp-{}", i))
                .stack_size(SERVE_STACK_SIZE)
                .spawn(move || loop {
                    // El lock se sostiene solo durante el `recv` (handoff instantáneo);
                    // el job corre fuera del lock → los workers ejecutan en paralelo.
                    let job = {
                        let guard = match rx.lock() {
                            Ok(g) => g,
                            Err(_) => return,
                        };
                        guard.recv()
                    };
                    match job {
                        // Un panic del handler NO debe matar al worker: se traga acá; los
                        // canales del job se dropean y el lado async responde 500. Seguimos.
                        Ok(job) => {
                            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                        }
                        Err(_) => return, // canal cerrado: el proceso termina
                    }
                });
        }
        InterpreterPool { tx }
    }

    fn submit(&self, job: InterpJob) {
        let _ = self.tx.send(job);
    }
}

static INTERP_POOL: std::sync::OnceLock<InterpreterPool> = std::sync::OnceLock::new();

/// El pool del intérprete, inicializado una vez. Tamaño: `SYNSEMA_SERVE_WORKERS` si está
/// seteado (>=1), si no `#cores` (mín. 2). El env es el escape hatch para deploys con
/// handlers I/O-bound (más workers = más concurrencia de I/O, a costa de más RAM); el
/// default acota la memoria. La concurrencia real de I/O sin tope la dará el intérprete
/// async (diferido), no subir esto sin límite.
fn interp_pool() -> &'static InterpreterPool {
    INTERP_POOL.get_or_init(|| {
        let workers = std::env::var("SYNSEMA_SERVE_WORKERS")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(2)
                    .max(2)
            });
        InterpreterPool::new(workers)
    })
}

#[derive(Clone)]
enum TlsMode {
    Plain,
    Fixed(Arc<rustls::ServerConfig>),
    Swap(SharedServerConfig),
}

/// Loop de accept async. Bloquea para siempre (arma su propio runtime tokio).
pub fn serve_forever(rt: Arc<ServeRuntime>, listener: TcpListener) {
    run_async(rt, listener, TlsMode::Plain);
}

/// HTTPS con cert fijo (TLS manual). Bind/handshake fallido cierra esa conexión.
pub fn serve_forever_tls(rt: Arc<ServeRuntime>, listener: TcpListener, config: Arc<rustls::ServerConfig>) {
    run_async(rt, listener, TlsMode::Fixed(config));
}

/// HTTPS con cert hot-swappable (renovación ACME): lee la config por accept.
pub fn serve_forever_tls_auto(rt: Arc<ServeRuntime>, listener: TcpListener, config: SharedServerConfig) {
    run_async(rt, listener, TlsMode::Swap(config));
}

fn run_async(rt: Arc<ServeRuntime>, listener: TcpListener, tls: TlsMode) {
    let _ = listener.set_nonblocking(true);
    // Arranca el pool del intérprete (stack grande, acotado) ANTES de aceptar conexiones.
    let _ = interp_pool();
    // NO seteamos `thread_stack_size` acá: los workers async de I/O usan stack default
    // (~MBs), no 64 MB. El stack grande vive solo en el pool del intérprete. Además cap
    // explícito del blocking pool (ya casi no se usa: el intérprete migró a su pool) y
    // keep-alive corto de hilos ociosos, como pidió el reporte de la arena.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(4)
        .thread_keep_alive(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(r) => r,
        Err(_) => return,
    };
    runtime.block_on(async move {
        let listener = match tokio::net::TcpListener::from_std(listener) {
            Ok(l) => l,
            Err(_) => return,
        };
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => continue,
            };
            let _ = tcp.set_nodelay(true);
            let client_ip = peer.ip().to_string();
            let rt = rt.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                serve_conn(rt, tcp, client_ip, tls).await;
            });
        }
    });
}

async fn serve_conn(rt: Arc<ServeRuntime>, tcp: tokio::net::TcpStream, client_ip: String, tls: TlsMode) {
    let svc = {
        let rt = rt.clone();
        let ip = client_ip.clone();
        service_fn(move |req: Request<Incoming>| {
            let rt = rt.clone();
            let ip = ip.clone();
            async move { handle_request(rt, req, ip).await }
        })
    };
    // auto::Builder negocia HTTP/1.1 o HTTP/2 (ALPN h2 sobre TLS; h2c o 1.1 en claro).
    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    match tls {
        TlsMode::Plain => {
            let io = TokioIo::new(tcp);
            let _ = builder.serve_connection(io, svc).await;
        }
        TlsMode::Fixed(cfg) => {
            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
            if let Ok(stream) = acceptor.accept(tcp).await {
                let io = TokioIo::new(stream);
                let _ = builder.serve_connection(io, svc).await;
            }
        }
        TlsMode::Swap(cell) => {
            let cfg = match cell.read() {
                Ok(g) => g.clone(),
                Err(_) => return,
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
            if let Ok(stream) = acceptor.accept(tcp).await {
                let io = TokioIo::new(stream);
                let _ = builder.serve_connection(io, svc).await;
            }
        }
    }
}

/// Cabecera resuelta por el `spawn_blocking` (status + headers); el body llega aparte.
struct HeadInfo {
    status: u16,
    content_type: Option<String>,
    extra: Vec<(String, String)>,
    streaming: bool,
    close: bool,
    cors: Option<String>,
    hsts: bool,
}

/// Body respaldado por un canal mpsc (SSE: frames a medida que el handler emite).
struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
}
impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, std::convert::Infallible>>> {
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(b)) => std::task::Poll::Ready(Some(Ok(Frame::data(b)))),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

fn response_body_bytes(body: ResponseBody) -> (String, Bytes) {
    match body {
        ResponseBody::Json(j) => ("application/json".to_string(), Bytes::from(dumps(&j))),
        ResponseBody::Raw(r) => (r.content_type, Bytes::from(r.body)),
        // El destino va como header `Location` (inyectado en el dispatch); sin body.
        ResponseBody::Redirect { .. } => ("text/plain; charset=utf-8".to_string(), Bytes::new()),
    }
}

/// Emisor SSE respaldado por el canal: formatea `[event:..\n]data:<json>\n\n`.
fn channel_emitter(tx: tokio::sync::mpsc::Sender<Bytes>) -> Emitter {
    Box::new(move |value: &SynValue, event: Option<&str>| -> Result<(), StreamGone> {
        let mut payload = String::new();
        if let Some(e) = event {
            payload.push_str("event: ");
            payload.push_str(e);
            payload.push('\n');
        }
        payload.push_str("data: ");
        payload.push_str(&dumps(&syn_to_json(value)));
        payload.push_str("\n\n");
        tx.blocking_send(Bytes::from(payload)).map_err(|_| StreamGone)
    })
}

/// Construye un `Response` JSON sized (errores 4xx/5xx fuera del dispatch).
fn json_full(
    status: u16,
    body: String,
    extra: &[(String, String)],
    cors: Option<&str>,
    hsts: bool,
    close: bool,
) -> Response<RespBody> {
    let mut builder = Response::builder().status(status).header("Content-Type", "application/json");
    if close {
        builder = builder.header("Connection", "close");
    }
    if let Some(o) = cors {
        builder = builder.header("Access-Control-Allow-Origin", o);
    }
    if hsts {
        builder = builder.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    for (k, v) in extra {
        builder = builder.header(k, v);
    }
    builder.body(Full::new(Bytes::from(body)).boxed()).unwrap()
}

/// OPTIONS: 204 + Allow (+ CORS si está). Espeja `handle_options` del path viejo.
fn build_options_response(rt: &ServeRuntime, path: &str) -> Response<RespBody> {
    let allowed = rt.methods_for_path(path);
    if allowed.is_empty() {
        let body = obj(vec![
            ("error", Json::Str(format!("no route for {}", path))),
            ("status", Json::Int(404)),
        ]);
        return json_full(404, dumps(&body), &[], rt.cors_origin(), rt.tls_enabled, false);
    }
    let mut set = allowed;
    set.push("OPTIONS".to_string());
    set.push("HEAD".to_string());
    set.sort();
    set.dedup();
    let allow = set.join(", ");
    let mut builder = Response::builder()
        .status(204)
        .header("Allow", &allow)
        .header("Content-Length", "0");
    if let Some(o) = rt.cors_origin() {
        builder = builder
            .header("Access-Control-Allow-Origin", o)
            .header("Access-Control-Allow-Methods", &allow)
            .header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            .header("Access-Control-Max-Age", "86400");
    }
    if rt.tls_enabled {
        builder = builder.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    builder.body(Full::new(Bytes::new()).boxed()).unwrap()
}

/// Lee el body respetando `max_body` (excedido → Err → 413).
async fn read_req_body(body: Incoming, max: Option<i64>) -> Result<Bytes, ()> {
    match max {
        Some(m) => {
            let lim = m.max(0) as usize;
            match Limited::new(body, lim).collect().await {
                Ok(c) => Ok(c.to_bytes()),
                Err(_) => Err(()),
            }
        }
        None => match body.collect().await {
            Ok(c) => Ok(c.to_bytes()),
            Err(_) => Err(()),
        },
    }
}

/// Path único para un body spilled a disco (como tempfile del oráculo).
fn spill_path() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("syn_body_{}_{}", std::process::id(), n))
}

async fn handle_request(
    rt: Arc<ServeRuntime>,
    req: Request<Incoming>,
    client_ip: String,
) -> Result<Response<RespBody>, std::convert::Infallible> {
    let method = req.method().as_str().to_string();
    let target = match req.uri().path_and_query() {
        Some(pq) => pq.as_str().to_string(),
        None => req.uri().path().to_string(),
    };
    let (path, query) = parse_path_query(&target);
    let mut headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    // HTTP/2: el Host viaja en el pseudo-header `:authority` (vía `req.uri().authority()`),
    // no en `headers()`. Sin esto, la selección de vhost y `host of (headers of request)`
    // caen al host default para todo cliente h2 (los navegadores negocian h2 sobre TLS).
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        if let Some(auth) = req.uri().authority() {
            headers.push(("host".to_string(), auth.host().to_string()));
        }
    }

    if method == "OPTIONS" {
        return Ok(build_options_response(&rt, &path));
    }
    let is_head = method == "HEAD";
    let eff_method = if is_head { "GET".to_string() } else { method.clone() };

    let cors = rt.cors_origin().map(|s| s.to_string());
    let hsts = rt.tls_enabled;

    // Body con tope; excedido → 413 + cerrar.
    let body_bytes = match read_req_body(req.into_body(), rt.max_body).await {
        Ok(b) => b,
        Err(()) => {
            let body = obj(vec![
                ("error", Json::Str("payload too large".into())),
                ("status", Json::Int(413)),
            ]);
            return Ok(json_full(413, dumps(&body), &[], cors.as_deref(), hsts, true));
        }
    };
    // Spill a disco igual que el oráculo: bodies > MEM_SPILL no van en memoria (el
    // `body` string queda vacío; el handler lo lee del file vía body_file). El `body_raw`
    // conserva los bytes exactos en memoria (para `read_body_bytes` byte-exacto sin la
    // decodificación lossy de `body`); vacío cuando spilleó (el file es la fuente cruda).
    let (body_str, body_raw, body_file): (String, Vec<u8>, Option<PathBuf>) =
        if body_bytes.len() > MEM_SPILL {
            let p = spill_path();
            let _ = std::fs::write(&p, &body_bytes);
            (String::new(), Vec::new(), Some(p))
        } else {
            (String::from_utf8_lossy(&body_bytes).into_owned(), body_bytes.to_vec(), None)
        };

    // ¿La ruta que matchearía es un `stream`? Resolución barata (vhost + match de ruta,
    // sin auth ni handler) para decidir el hilo: los streams (long-lived, Ctx !Send) corren
    // en un hilo dedicado; los sized (caso común) van al pool acotado.
    // Las rutas `/approvals` (A1.v2) también van a hilo dedicado: un gate humano
    // bloqueado OCUPA un worker del pool esperando su respuesta — si la respuesta
    // (POST /approvals/{id}) tuviera que esperar un worker libre, con el pool lleno de
    // gates nadie podría aprobar nada hasta los timeouts.
    let streaming_route = rt.route_is_streaming(&eff_method, &path, &headers)
        || rt.is_approvals_route(&eff_method, &path);

    // dispatch + (si stream) correr el handler; head por oneshot, body por mpsc (1 frame
    // para sized, N frames para SSE).
    let (head_tx, head_rx) = tokio::sync::oneshot::channel::<HeadInfo>();
    let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Bytes>(16);
    let rt2 = rt.clone();
    let cors_b = cors.clone();

    // Un SOLO closure: corre el intérprete sync (dispatch + handler). El `Ctx` es !Send
    // pero queda LOCAL al job (nunca se captura) → el closure captura sólo inputs Send, así
    // sirve igual para el pool (sized) que para un hilo dedicado (stream).
    let job = move || {
        let bf = body_file.as_ref().map(|p| p.to_string_lossy().into_owned());
        let accept_gzip =
            header_value(&headers, "accept-encoding").to_ascii_lowercase().contains("gzip");
        match rt2.dispatch(
            &eff_method,
            &path,
            query,
            headers,
            &body_str,
            &body_raw,
            bf.as_deref(),
            &client_ip,
        ) {
            Dispatched::Response { status, body, headers: extra } => {
                let mut extra = extra;
                // redirect(): el destino se emite como header `Location`.
                if let ResponseBody::Redirect { location, .. } = &body {
                    extra.push(("Location".to_string(), location.clone()));
                }
                let (ct, bytes) = response_body_bytes(body);
                // gzip DINÁMICO (render()/html()/content()/JSON): los estáticos ya
                // vienen comprimidos desde serve_static_full (traen Content-Encoding
                // en `extra`, así que acá se saltean); 204/206/304 no llevan body
                // comprimible y un body chico no amortiza el overhead.
                let mut bytes = bytes;
                if accept_gzip
                    && bytes.len() >= 1024
                    && !matches!(status, 204 | 206 | 304)
                    && is_compressible(&ct)
                    && !extra.iter().any(|(k, _)| {
                        k.eq_ignore_ascii_case("content-encoding")
                            || k.eq_ignore_ascii_case("content-range")
                    })
                {
                    if let Some(gz) = gzip_bytes(&bytes) {
                        if gz.len() < bytes.len() {
                            bytes = Bytes::from(gz);
                            extra.push(("Content-Encoding".to_string(), "gzip".to_string()));
                            extra.push(("Vary".to_string(), "Accept-Encoding".to_string()));
                        }
                    }
                }
                let _ = head_tx.send(HeadInfo {
                    status,
                    content_type: Some(ct),
                    extra,
                    streaming: false,
                    close: false,
                    cors: cors_b,
                    hsts,
                });
                let _ = body_tx.blocking_send(bytes);
            }
            Dispatched::Stream { stream_handler, ctx } => {
                let _ = head_tx.send(HeadInfo {
                    status: 200,
                    content_type: Some("text/event-stream".to_string()),
                    extra: vec![
                        ("Cache-Control".to_string(), "no-cache".to_string()),
                        ("X-Accel-Buffering".to_string(), "no".to_string()),
                    ],
                    streaming: true,
                    close: true,
                    cors: cors_b,
                    hsts,
                });
                if let Some(sh) = stream_handler {
                    let emit = channel_emitter(body_tx.clone());
                    if let StreamEnd::Error(msg) = sh(&ctx, emit) {
                        let err = format!(
                            "event: error\ndata: {}\n\n",
                            dumps(&obj(vec![("error", Json::Str(msg))]))
                        );
                        let _ = body_tx.blocking_send(Bytes::from(err));
                    }
                }
                rt2.release_stream();
            }
        }
        // Limpia el body spilled a disco (si lo hubo).
        if let Some(p) = &body_file {
            let _ = std::fs::remove_file(p);
        }
    };

    if streaming_route {
        // Stream: hilo dedicado de stack grande (dispatch + handler juntos; el Ctx no cruza
        // hilos). Acotado por `max_streams` (el slot se adquiere/libera dentro del job).
        // NO ocupa un worker del pool → unas pocas conexiones SSE no lo agotan.
        if std::thread::Builder::new()
            .name("synsema-stream".to_string())
            .stack_size(SERVE_STACK_SIZE)
            .spawn(job)
            .is_err()
        {
            // Falló crear el hilo (sistema sin recursos): el job se dropeó → head_rx da Err
            // → el lado async responde 500. dispatch no corrió: no hay slot que liberar.
        }
    } else {
        // Sized (caso común): pool dedicado y ACOTADO (no el blocking pool de tokio). La
        // memoria es `#workers × 64 MB` pase lo que pase con la concurrencia → adiós OOM:
        // ya no hay N hilos × 64 MB por N requests en vuelo bajo keep-alive.
        interp_pool().submit(Box::new(job));
    }

    let head = match head_rx.await {
        Ok(h) => h,
        Err(_) => {
            let body = obj(vec![
                ("error", Json::Str("internal server error".into())),
                ("status", Json::Int(500)),
            ]);
            return Ok(json_full(500, dumps(&body), &[], cors.as_deref(), hsts, false));
        }
    };

    let mut builder = Response::builder().status(head.status);
    if let Some(ct) = &head.content_type {
        builder = builder.header("Content-Type", ct);
    }
    if head.close {
        builder = builder.header("Connection", "close");
    }
    if let Some(o) = &head.cors {
        builder = builder.header("Access-Control-Allow-Origin", o);
    }
    if head.hsts {
        builder = builder.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    // Validar cada header extra y saltear los inválidos: al reenviar headers
    // arbitrarios del upstream (reverse proxy), un valor malformado (p. ej. con un
    // byte de control) envenenaría el builder y haría panic en `.body(...).unwrap()`.
    // Un reverse proxy no debe caerse por datos del upstream → se descarta (como nginx).
    for (k, v) in &head.extra {
        if let (Ok(name), Ok(val)) = (
            hyper::http::header::HeaderName::try_from(k.as_str()),
            hyper::http::header::HeaderValue::try_from(v.as_str()),
        ) {
            builder = builder.header(name, val);
        }
    }

    let mut body_rx = body_rx;
    if head.streaming {
        let body = ChannelBody { rx: body_rx }.boxed();
        Ok(builder.body(body).unwrap())
    } else {
        // sized: 1 frame con el body completo → Full (hyper pone Content-Length).
        let bytes = body_rx.recv().await.unwrap_or_default();
        if is_head {
            // HEAD: mismo Content-Length, sin cuerpo.
            builder = builder.header("Content-Length", bytes.len().to_string());
            Ok(builder.body(Full::new(Bytes::new()).boxed()).unwrap())
        } else {
            Ok(builder.body(Full::new(bytes).boxed()).unwrap())
        }
    }
}

/// A2 batch 2 — Listener HTTP (típico :80) para auto-HTTPS: sirve el challenge
/// ACME HTTP-01 (`/.well-known/acme-challenge/<token>` → key-authorization desde
/// `store`) y redirige todo lo demás a https. Reúsa el rol del listener de redirect.
pub fn serve_acme_http(listener: TcpListener, https_port: u16, store: ChallengeStore) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let store = store.clone();
        let _ = std::thread::Builder::new()
            .stack_size(1024 * 1024)
            .spawn(move || {
                let _ = acme_http_one(stream, https_port, store);
            });
    }
}

fn acme_http_one(stream: TcpStream, https_port: u16, store: ChallengeStore) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let (_, target, _, headers) = match read_request_head(&mut reader) {
        Some(x) => x,
        None => return Ok(()),
    };
    let (path, _q) = parse_path_query(&target);
    const PFX: &str = "/.well-known/acme-challenge/";
    if let Some(token) = path.strip_prefix(PFX) {
        let body = store.lock().unwrap().get(token).cloned();
        let stream = reader.get_mut();
        match body {
            Some(key_auth) => {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    key_auth.len(),
                    key_auth
                );
                stream.write_all(resp.as_bytes())?;
            }
            None => {
                stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )?;
            }
        }
        return stream.flush();
    }
    // No es un challenge → 301 a https.
    let host_hdr = header_value(&headers, "host");
    let host = host_hdr.split(':').next().unwrap_or("").to_string();
    let authority = if https_port == 443 || host.is_empty() {
        host
    } else {
        format!("{}:{}", host, https_port)
    };
    let resp = format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        authority, target
    );
    let stream = reader.get_mut();
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

/// A2 — Construye una `ServerConfig` de rustls (ring) desde cert+key PEM. Defaults
/// seguros: TLS 1.2+ (versiones por defecto de rustls), sin auth de cliente.
pub fn build_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<rustls::ServerConfig>, String> {
    let cert_file =
        File::open(cert_path).map_err(|e| format!("could not read TLS cert {}: {}", cert_path, e))?;
    let mut cert_rd = BufReader::new(cert_file);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_rd)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid TLS cert {}: {}", cert_path, e))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", cert_path));
    }
    let key_file =
        File::open(key_path).map_err(|e| format!("could not read TLS key {}: {}", key_path, e))?;
    let mut key_rd = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_rd)
        .map_err(|e| format!("invalid TLS key {}: {}", key_path, e))?
        .ok_or_else(|| format!("no private key found in {}", key_path))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS config error: {}", e))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS cert/key mismatch: {}", e))?;
    // Lote 2 — HTTP/2: anunciar h2 (y http/1.1 fallback) por ALPN. El auto::Builder
    // sirve HTTP/2 cuando el cliente negocia h2; si no, HTTP/1.1.
    let mut config = config;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Carga un par cert(cadena)+key PEM en un `CertifiedKey` de rustls (para SNI por-host).
fn load_certified_key(cert_path: &str, key_path: &str) -> Result<rustls::sign::CertifiedKey, String> {
    let cert_file =
        File::open(cert_path).map_err(|e| format!("could not read TLS cert {}: {}", cert_path, e))?;
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("invalid TLS cert {}: {}", cert_path, e))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", cert_path));
    }
    let key_file =
        File::open(key_path).map_err(|e| format!("could not read TLS key {}: {}", key_path, e))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| format!("invalid TLS key {}: {}", key_path, e))?
        .ok_or_else(|| format!("no private key found in {}", key_path))?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("unsupported TLS key in {}: {}", key_path, e))?;
    Ok(rustls::sign::CertifiedKey::new(certs, signing_key))
}

/// Resolver SNI (vhost): elige el cert por server name del handshake; cae al default.
#[derive(Debug)]
struct SniResolver {
    default: std::sync::Arc<rustls::sign::CertifiedKey>,
    by_name: HashMap<String, std::sync::Arc<rustls::sign::CertifiedKey>>,
    wildcards: Vec<(String, std::sync::Arc<rustls::sign::CertifiedKey>)>,
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            let name = name.to_ascii_lowercase();
            if let Some(ck) = self.by_name.get(&name) {
                return Some(ck.clone());
            }
            for (suffix, ck) in &self.wildcards {
                if name.ends_with(suffix) {
                    return Some(ck.clone());
                }
            }
        }
        Some(self.default.clone())
    }
}

/// A2 — Config TLS con SNI por-host (vhost): `default_*` es el fallback; cada host
/// (exacto o `*.dominio`) presenta su propio cert. Defaults seguros (TLS 1.2+).
pub fn build_tls_config_sni(
    default_cert: &str,
    default_key: &str,
    hosts: Vec<(String, String, String)>,
) -> Result<Arc<rustls::ServerConfig>, String> {
    let default = std::sync::Arc::new(load_certified_key(default_cert, default_key)?);
    let mut by_name: HashMap<String, std::sync::Arc<rustls::sign::CertifiedKey>> = HashMap::new();
    let mut wildcards: Vec<(String, std::sync::Arc<rustls::sign::CertifiedKey>)> = Vec::new();
    for (pattern, cert, key) in hosts {
        let ck = std::sync::Arc::new(load_certified_key(&cert, &key)?);
        if let Some(suffix) = pattern.strip_prefix("*.") {
            wildcards.push((format!(".{}", suffix.to_ascii_lowercase()), ck));
        } else {
            by_name.insert(pattern.to_ascii_lowercase(), ck);
        }
    }
    let resolver = std::sync::Arc::new(SniResolver { default, by_name, wildcards });
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS config error: {}", e))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    let mut config = config;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A2 — Loop de redirección: escucha (típico :80) y responde 301 a https://host[:port].
/// Lee sólo la request line + headers; un hilo liviano por request.
pub fn serve_redirect(listener: TcpListener, https_port: u16) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let _ = std::thread::Builder::new()
            .stack_size(1024 * 1024)
            .spawn(move || {
                let _ = redirect_one(stream, https_port);
            });
    }
}

fn redirect_one(stream: TcpStream, https_port: u16) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let (_, target, _, headers) = match read_request_head(&mut reader) {
        Some(x) => x,
        None => return Ok(()),
    };
    let host_hdr = header_value(&headers, "host");
    let host = host_hdr.split(':').next().unwrap_or("").to_string();
    let authority = if https_port == 443 || host.is_empty() {
        host
    } else {
        format!("{}:{}", host, https_port)
    };
    let resp = format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        authority, target
    );
    let stream = reader.get_mut();
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

/// Head parseado de una request: (método, target, versión, headers).
type RequestHead = (String, String, String, Vec<(String, String)>);

fn read_request_head<R: BufRead>(reader: &mut R) -> Option<RequestHead> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None; // EOF / conexión cerrada
    }
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        return None;
    }
    let mut it = line.splitn(3, ' ');
    let method = it.next()?.to_string();
    let target = it.next()?.to_string();
    let version = it.next().unwrap_or("HTTP/1.1").to_string();
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).ok()? == 0 {
            break;
        }
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some((method, target, version, headers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::types::syn_bool;
    use std::io::Read; // GzDecoder::read_to_end en los tests de gzip

    #[test]
    fn specificity_ordering() {
        // estático < :param < catchall, por segmento.
        assert_eq!(specificity("/products"), vec![0]);
        assert_eq!(specificity("/products/:id"), vec![0, 1]);
        assert_eq!(specificity("/files/*path"), vec![0, 2]);
        assert_eq!(specificity("/"), Vec::<i32>::new());
        // El más específico ordena primero (lista ascendente).
        let mut routes = vec!["/a/*x", "/a/:id", "/a/b"];
        routes.sort_by_key(|p| specificity(p));
        assert_eq!(routes, vec!["/a/b", "/a/:id", "/a/*x"]);
    }

    #[test]
    fn path_match_exact_and_params() {
        assert!(path_match("/health", "/health").is_some());
        assert!(path_match("/health", "/other").is_none());

        let p = path_match("/products/:id", "/products/42").unwrap();
        assert_eq!(p.get("id").map(String::as_str), Some("42"));

        // longitudes distintas → no matchea
        assert!(path_match("/products/:id", "/products/42/extra").is_none());
        assert!(path_match("/products/:id", "/products").is_none());
    }

    #[test]
    fn path_match_catchall() {
        let p = path_match("/files/*path", "/files/a/b/c.txt").unwrap();
        assert_eq!(p.get("path").map(String::as_str), Some("a/b/c.txt"));
        // catchall necesita al menos un segmento
        assert!(path_match("/files/*path", "/files").is_none());
    }

    #[test]
    fn path_match_url_decodes_params() {
        let p = path_match("/u/:name", "/u/jos%C3%A9").unwrap();
        assert_eq!(p.get("name").map(String::as_str), Some("josé"));
    }

    #[test]
    fn param_last_segment_detection() {
        assert!(param_last_segment("/blog/:slug"));
        assert!(!param_last_segment("/blog/post"));
        assert!(!param_last_segment("/files/*path"));
    }

    // A1.v2/v3: formas de las rutas reservadas de aprobaciones. Sin gateway cableado
    // no existen; con él: GET lista, POST {id}, GET {id}/{token} (link) — y NUNCA
    // 3+ segmentos.
    #[test]
    fn approvals_route_shapes() {
        struct NoQueue;
        impl ApprovalsGateway for NoQueue {
            fn list(&self) -> Vec<ApprovalSummary> {
                Vec::new()
            }
            fn respond(
                &self,
                _id: &str,
                _token: &str,
                _decision: Option<bool>,
                _value: Option<&str>,
            ) -> ApprovalOutcome {
                ApprovalOutcome::NotFound
            }
        }
        let mut rt = ServeRuntime::new(
            0,
            "127.0.0.1".to_string(),
            Vec::new(),
            None,
            None,
            8,
            Vec::new(),
            None,
            None,
            None,
            Vec::new(),
            false,
            false,
        );
        assert!(!rt.is_approvals_route("GET", "/approvals"), "sin gateway no hay rutas");
        rt.approvals = Some(Arc::new(NoQueue));
        assert!(rt.is_approvals_route("GET", "/approvals"));
        assert!(rt.is_approvals_route("POST", "/approvals/interact_1"));
        assert!(rt.is_approvals_route("GET", "/approvals/interact_1/abc123"));
        assert!(!rt.is_approvals_route("GET", "/approvals/interact_1"), "GET de 1 segmento no es link");
        assert!(!rt.is_approvals_route("POST", "/approvals/interact_1/abc123"), "el link es GET-only");
        assert!(!rt.is_approvals_route("GET", "/approvals/x/y/z"), "3+ segmentos no matchean");
        assert!(!rt.is_approvals_route("GET", "/approvals/x/"), "token vacío no matchea");
        assert!(!rt.is_approvals_route("POST", "/approvals/"), "id vacío no matchea");
    }

    #[test]
    fn split_format_suffix_works() {
        assert_eq!(split_format_suffix("/blog/hola.json"), ("/blog/hola".into(), Some("json".into())));
        assert_eq!(split_format_suffix("/a.md"), ("/a".into(), Some("md".into())));
        assert_eq!(split_format_suffix("/plain"), ("/plain".into(), None));
        // un sufijo solo (".json") sin nombre no cuenta
        assert_eq!(split_format_suffix("/.json"), ("/.json".into(), None));
        // un sufijo tras '/' no cuenta
        assert_eq!(split_format_suffix("/dir/.md"), ("/dir/.md".into(), None));
    }

    #[test]
    fn negotiate_format_defaults_html() {
        assert_eq!(negotiate_format(""), "html");
        assert_eq!(negotiate_format("*/*"), "html");
        assert_eq!(negotiate_format("text/html"), "html");
        assert_eq!(negotiate_format("application/json"), "json");
        assert_eq!(negotiate_format("text/markdown"), "md");
        // html gana si está presente junto a otro
        assert_eq!(negotiate_format("application/json, text/html"), "html");
    }

    #[test]
    fn parse_body_size_units() {
        assert_eq!(parse_body_size_str("512kb"), Some(512 * 1024));
        assert_eq!(parse_body_size_str("10mb"), Some(10 * 1024 * 1024));
        assert_eq!(parse_body_size_str("1gb"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_body_size_str("2048"), Some(2048));
        assert_eq!(parse_body_size_str("unlimited"), None);
        assert_eq!(parse_body_size_str("none"), None);
        assert_eq!(parse_body_size_str("garbage"), Some(MAX_BODY));
    }

    #[test]
    fn parse_path_query_basic() {
        let (p, q) = parse_path_query("/search?q=hello+world&limit=10");
        assert_eq!(p, "/search");
        assert_eq!(q.get("q").map(String::as_str), Some("hello world"));
        assert_eq!(q.get("limit").map(String::as_str), Some("10"));
        let (p2, q2) = parse_path_query("/plain");
        assert_eq!(p2, "/plain");
        assert!(q2.is_empty());
    }

    // ===================== A2: estáticos de producción =====================

    #[test]
    fn parse_range_forms() {
        // bytes=START-END inclusivos
        assert_eq!(parse_range("bytes=0-3", 10), Some((0, 3)));
        // bytes=START- → hasta el final
        assert_eq!(parse_range("bytes=5-", 10), Some((5, 9)));
        // bytes=-N → últimos N
        assert_eq!(parse_range("bytes=-3", 10), Some((7, 9)));
        // END recortado a size-1
        assert_eq!(parse_range("bytes=2-999", 10), Some((2, 9)));
        // start fuera de rango → None (416)
        assert_eq!(parse_range("bytes=10-12", 10), None);
        assert_eq!(parse_range("bytes=20-", 10), None);
        // start > end → None
        assert_eq!(parse_range("bytes=5-2", 10), None);
        // size 0 → None
        assert_eq!(parse_range("bytes=0-0", 0), None);
        // sin prefijo bytes= → None
        assert_eq!(parse_range("0-3", 10), None);
    }

    #[test]
    fn compressible_types() {
        assert!(is_compressible("text/html"));
        assert!(is_compressible("text/html; charset=utf-8"));
        assert!(is_compressible("text/css"));
        assert!(is_compressible("application/json"));
        assert!(is_compressible("image/svg+xml"));
        assert!(is_compressible("text/plain"));
        assert!(!is_compressible("image/png"));
        assert!(!is_compressible("application/octet-stream"));
        assert!(!is_compressible("font/woff2"));
    }

    #[test]
    fn cache_control_specs() {
        assert_eq!(cache_control_value("immutable").unwrap(), "public, max-age=31536000, immutable");
        assert_eq!(cache_control_value("no-store").unwrap(), "no-store");
        assert_eq!(cache_control_value("30s").unwrap(), "public, max-age=30");
        assert_eq!(cache_control_value("5m").unwrap(), "public, max-age=300");
        assert_eq!(cache_control_value("1h").unwrap(), "public, max-age=3600");
        assert_eq!(cache_control_value("7d").unwrap(), "public, max-age=604800");
        assert_eq!(cache_control_value("120").unwrap(), "public, max-age=120");
        assert_eq!(cache_control_value(" 1H ").unwrap(), "public, max-age=3600");
        assert!(cache_control_value("rapido").is_err());
        assert!(cache_control_value("1w").is_err());
        assert!(cache_control_value("").is_err());
    }

    #[test]
    fn form_urlencoded_parses() {
        let m = parse_form_urlencoded("nombre=Jo%C3%ABl&email=a%40b.com&x=1+2&vacio=&=sin");
        assert_eq!(m.get("nombre").unwrap(), "Joël");
        assert_eq!(m.get("email").unwrap(), "a@b.com");
        assert_eq!(m.get("x").unwrap(), "1 2");
        assert_eq!(m.get("vacio").unwrap(), "");
        assert!(!m.contains_key("")); // clave vacía ignorada, como el query string
        // último valor gana
        let m2 = parse_form_urlencoded("a=1&a=2");
        assert_eq!(m2.get("a").unwrap(), "2");
    }

    #[test]
    fn multipart_boundary_and_parts() {
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=----abc123").as_deref(),
            Some("----abc123")
        );
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=\"quoted\"").as_deref(),
            Some("quoted")
        );
        assert!(multipart_boundary("application/json").is_none());

        let body = b"--B\r\nContent-Disposition: form-data; name=\"campo\"\r\n\r\nvalor\r\n--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n\x00\x01BIN\r\n--B--\r\n";
        let parts = parse_multipart("B", body);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name, "campo");
        assert!(parts[0].filename.is_none());
        assert_eq!(parts[0].data, b"valor");
        assert_eq!(parts[1].name, "f");
        assert_eq!(parts[1].filename.as_deref(), Some("a.bin"));
        assert_eq!(parts[1].content_type.as_deref(), Some("application/octet-stream"));
        assert_eq!(parts[1].data, b"\x00\x01BIN"); // bytes exactos, sin decodificar
    }

    #[test]
    fn static_fallback_serves_index_on_miss() {
        let dir = std::env::temp_dir().join("syn_static_fallback_test");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("index.html"), b"SHELL").unwrap();
        let rt = ServeRuntime::new(
            0,
            "0.0.0.0".to_string(),
            Vec::new(),
            None,
            None,
            64,
            vec![StaticMountSpec {
                prefix: "/".to_string(),
                dir: dir.to_string_lossy().into_owned(),
                cache: Some("public, max-age=60".to_string()),
                fallback: Some("index.html".to_string()),
            }],
            None,
            None,
            None,
            Vec::new(),
            false,
            false,
        );
        // Miss → fallback con 200 + Cache-Control del mount.
        let r = rt.default_host.serve_static_full("/ruta/spa/interna", &[]).expect("fallback");
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"SHELL");
        assert!(r.extra.iter().any(|(k, v)| k == "Cache-Control" && v == "public, max-age=60"));
    }

    #[test]
    fn gzip_roundtrip() {
        let data = b"hola mundo, esto se comprime bien bien bien bien bien".repeat(10);
        let gz = gzip_bytes(&data).expect("gzip");
        // El header gzip arranca con 0x1f 0x8b.
        assert_eq!(&gz[..2], &[0x1f, 0x8b]);
        let mut dec = flate2::read::GzDecoder::new(&gz[..]);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }

    /// Construye un ServeRuntime mínimo con un único static mount sobre `dir`.
    fn static_rt(dir: &str) -> ServeRuntime {
        ServeRuntime::new(
            0,
            "0.0.0.0".to_string(),
            Vec::new(),
            None,
            None,
            64,
            vec![StaticMountSpec {
                prefix: "/".to_string(),
                dir: dir.to_string(),
                cache: None,
                fallback: None,
            }],
            None,
            None,
            None,
            Vec::new(),
            false,
            false,
        )
    }

    #[test]
    fn serve_static_etag_range_gzip() {
        // dir temporal único para este test
        let dir = std::env::temp_dir().join("syn_static_a2_test");
        let _ = std::fs::create_dir_all(&dir);
        let body = b"<!doctype html><h1>hola</h1> contenido suficiente para comprimir".to_vec();
        std::fs::write(dir.join("index.html"), &body).unwrap();
        let rt = static_rt(&dir.to_string_lossy());

        // (1) GET normal → 200 + ETag + body completo.
        let r = rt.default_host.serve_static_full("/index.html", &[]).expect("estático");
        assert_eq!(r.status, 200);
        assert_eq!(r.body, body);
        let etag = r
            .extra
            .iter()
            .find(|(k, _)| k == "ETag")
            .map(|(_, v)| v.clone())
            .expect("ETag");
        assert!(etag.starts_with('"') && etag.ends_with('"'));

        // (2) If-None-Match con ese etag → 304 sin body.
        let h304 = vec![("If-None-Match".to_string(), etag.clone())];
        let r = rt.default_host.serve_static_full("/index.html", &h304).expect("estático");
        assert_eq!(r.status, 304);
        assert!(r.body.is_empty());

        // (3) Range bytes=0-3 → 206 + Content-Range + 4 bytes.
        let hr = vec![("Range".to_string(), "bytes=0-3".to_string())];
        let r = rt.default_host.serve_static_full("/index.html", &hr).expect("estático");
        assert_eq!(r.status, 206);
        assert_eq!(r.body, &body[0..=3]);
        let cr = r.extra.iter().find(|(k, _)| k == "Content-Range").map(|(_, v)| v.clone());
        assert_eq!(cr, Some(format!("bytes 0-3/{}", body.len())));

        // (4) Accept-Encoding: gzip sobre text/html → Content-Encoding gzip + Vary.
        let hg = vec![("Accept-Encoding".to_string(), "gzip, deflate".to_string())];
        let r = rt.default_host.serve_static_full("/index.html", &hg).expect("estático");
        assert_eq!(r.status, 200);
        assert!(r
            .extra
            .iter()
            .any(|(k, v)| k == "Content-Encoding" && v == "gzip"));
        assert!(r.extra.iter().any(|(k, v)| k == "Vary" && v == "Accept-Encoding"));
        let mut dec = flate2::read::GzDecoder::new(&r.body[..]);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, body);

        // (5) path inexistente → None.
        assert!(rt.default_host.serve_static_full("/nope.html", &[]).is_none());
    }

    // ---- Tanda web-auth, ítems A/B: with_header + cookies ----

    #[test]
    fn validate_header_rules() {
        assert!(validate_header("with_header", "X-Request-Id", "abc").is_ok());
        assert!(validate_header("with_header", "Cache-Control", "no-store").is_ok());
        // Nombre vacío, char inválido, prohibidos.
        assert!(validate_header("with_header", "", "v").is_err());
        assert!(validate_header("with_header", "X Header", "v").is_err(), "espacio");
        assert!(validate_header("with_header", "X:Y", "v").is_err());
        for banned in [
            "Content-Length",
            "transfer-encoding",
            "Connection",
            "keep-alive",
            "Upgrade",
            "TE",
            "Trailer",
            "Content-Type",
        ] {
            assert!(validate_header("with_header", banned, "v").is_err(), "{}", banned);
        }
        // CR/LF y controles en el valor → header injection, error.
        assert!(validate_header("with_header", "X-A", "a\r\nSet-Cookie: pwn=1").is_err());
        assert!(validate_header("with_header", "X-A", "a\nb").is_err());
        assert!(validate_header("with_header", "X-A", "a\x01b").is_err());
    }

    #[test]
    fn with_header_wraps_and_accumulates() {
        let inner = make_raw_val("hola".to_string(), "text/plain", 200);
        let w1 = append_header_val(&inner, "X-A".to_string(), "1".to_string());
        let w2 = append_header_val(&w1, "X-B".to_string(), "2".to_string());
        // Acumula en el MISMO wrapper (no anida) y preserva el orden.
        match &w2 {
            SynValue::Server(s) => match &**s {
                ServerValue::WithHeaders { inner, headers } => {
                    assert_eq!(
                        headers,
                        &vec![
                            ("X-A".to_string(), "1".to_string()),
                            ("X-B".to_string(), "2".to_string())
                        ]
                    );
                    assert!(
                        matches!(&**inner, SynValue::Server(i) if matches!(&**i, ServerValue::Raw { .. })),
                        "inner es el Raw original, sin anidar"
                    );
                }
                _ => panic!("expected WithHeaders"),
            },
            _ => panic!("expected Server value"),
        }
    }

    #[test]
    fn set_cookie_defaults_and_options() {
        let o = parse_cookie_opts("set_cookie", None, true).ok().unwrap();
        let c = build_set_cookie("set_cookie", "sid", "abc123", &o).ok().unwrap();
        // Defaults seguros: Path=/; Secure; HttpOnly; SameSite=Lax.
        assert_eq!(c, "sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax");
        // max_age + overrides.
        let mut m = IndexMap::new();
        m.insert("max_age".to_string(), syn_int(86400));
        m.insert("path".to_string(), syn_text("/app"));
        m.insert("same_site".to_string(), syn_text("Strict"));
        m.insert("http_only".to_string(), syn_bool(false));
        let o = parse_cookie_opts("set_cookie", Some(&syn_map(m)), true).ok().unwrap();
        let c = build_set_cookie("set_cookie", "sid", "v", &o).ok().unwrap();
        assert_eq!(c, "sid=v; Max-Age=86400; Path=/app; Secure; SameSite=Strict");
    }

    #[test]
    fn set_cookie_fail_strong() {
        let o = parse_cookie_opts("set_cookie", None, true).ok().unwrap();
        // Nombre/valor inválidos (RFC 6265): el error sugiere base64url.
        assert!(build_set_cookie("set_cookie", "s id", "v", &o).is_err());
        assert!(build_set_cookie("set_cookie", "", "v", &o).is_err());
        match build_set_cookie("set_cookie", "sid", "a b", &o) {
            Err(Control::Error(e)) => assert!(
                e.to_string().contains("base64url"),
                "el error sugiere el fix: {}",
                e
            ),
            _ => panic!("valor con espacio debe fallar"),
        }
        assert!(build_set_cookie("set_cookie", "sid", "a;b", &o).is_err());
        assert!(build_set_cookie("set_cookie", "sid", "a\"b", &o).is_err());
        // same_site None sin Secure → error (el browser la rechazaría).
        let mut m = IndexMap::new();
        m.insert("same_site".to_string(), syn_text("None"));
        m.insert("secure".to_string(), syn_bool(false));
        let o = parse_cookie_opts("set_cookie", Some(&syn_map(m)), true).ok().unwrap();
        assert!(build_set_cookie("set_cookie", "sid", "v", &o).is_err());
        // …con Secure sí vale.
        let mut m = IndexMap::new();
        m.insert("same_site".to_string(), syn_text("None"));
        let o = parse_cookie_opts("set_cookie", Some(&syn_map(m)), true).ok().unwrap();
        let c = build_set_cookie("set_cookie", "sid", "v", &o).ok().unwrap();
        assert!(c.ends_with("SameSite=None") && c.contains("Secure"));
        // Opt desconocida → error con las válidas.
        let mut m = IndexMap::new();
        m.insert("httponly".to_string(), syn_bool(true));
        assert!(parse_cookie_opts("set_cookie", Some(&syn_map(m)), true).is_err());
        // max_age negativo o no-entero → error.
        let mut m = IndexMap::new();
        m.insert("max_age".to_string(), syn_int(-1));
        assert!(parse_cookie_opts("set_cookie", Some(&syn_map(m)), true).is_err());
        // clear_cookie sólo acepta path/domain.
        let mut m = IndexMap::new();
        m.insert("max_age".to_string(), syn_int(5));
        assert!(parse_cookie_opts("clear_cookie", Some(&syn_map(m)), false).is_err());
    }

    #[test]
    fn parse_cookies_rfc6265() {
        let h = |v: &str| vec![("Cookie".to_string(), v.to_string())];
        // split por `;`, trim, primer `=` separa, SIN decodificar.
        assert_eq!(
            parse_cookies(&h("sid=abc; theme=dark")),
            vec![
                ("sid".to_string(), "abc".to_string()),
                ("theme".to_string(), "dark".to_string())
            ]
        );
        // El valor conserva `=` internos (primer `=` separa).
        assert_eq!(
            parse_cookies(&h("tok=a=b=c")),
            vec![("tok".to_string(), "a=b=c".to_string())]
        );
        // Duplicado: gana la PRIMERA aparición (orden RFC).
        assert_eq!(
            parse_cookies(&h("sid=first; sid=second")),
            vec![("sid".to_string(), "first".to_string())]
        );
        // Sin header → vacío; segmentos malformados se saltean.
        assert_eq!(parse_cookies(&[]), Vec::<(String, String)>::new());
        assert_eq!(
            parse_cookies(&h("junk; =nada; sid=ok")),
            vec![("sid".to_string(), "ok".to_string())]
        );
        // No se URL-decodea (los %XX quedan tal cual).
        assert_eq!(
            parse_cookies(&h("v=a%20b")),
            vec![("v".to_string(), "a%20b".to_string())]
        );
    }

    #[test]
    fn build_response_unwraps_nothing_for_with_headers() {
        // El dispatch pela el wrapper ANTES de build_response; este test fija que
        // el valor envuelto (inner) responde idéntico a como respondería solo.
        let inner = make_raw_val("hola".to_string(), "text/plain", 201);
        let q = IndexMap::new();
        let (st_direct, _) = build_response(Some(&inner), &q).unwrap();
        assert_eq!(st_direct, 201);
    }
}

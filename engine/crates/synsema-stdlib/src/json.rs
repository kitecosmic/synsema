//! JSON ↔ SynValue + árbol de contenido como data. Extraído de server.rs para que
//! los módulos PUROS (charts, oidc, webauth) no dependan del server nativo: este
//! módulo compila en el perfil wasm (sin `native`), server.rs no. server.rs
//! re-exporta los símbolos públicos → los callers externos no cambian.

use std::cell::RefCell;
use std::rc::Rc;

use indexmap::IndexMap;

use synsema_core::bytesutil::b64_encode;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::{py_float_str, Number};
use synsema_core::types::{
    syn_bool, syn_int, syn_list, syn_map, syn_nothing, syn_text, ServerValue, SynValue,
};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

/// Los builtins JSON del lenguaje (puros, SIN capability — como text/bytes/decode).
/// Vivían en register_database_builtins; acá también existen en el perfil wasm.
/// Wired desde wire_common_with_state (runtime) y desde synsema-wasm.
pub fn register_json_builtins(interp: &Interpreter) {
    // json_encode(value) → text: serializa CUALQUIER valor a un string JSON. Mismo
    // mapeo que los bodies de serve: secrets → "[redacted]" (seguro), bytes →
    // base64, decimal exacto.
    interp.register_builtin(
        "json_encode",
        1,
        Rc::new(|_i, args, _loc| {
            let v = args.first().ok_or_else(|| err("json_encode: missing argument"))?;
            Ok(syn_text(dumps(&syn_to_json(v))))
        }),
    );

    // json_for_script(value) → text: JSON seguro para incrustar en un <script> — igual que
    // json_encode pero con `<`, `>` y `&` escapados como \u00XX, así un valor que contenga
    // "</script>" no puede cerrar el tag ni inyectar HTML. Es el mismo escapado que el
    // runtime ya usa para su JSON-LD. Uso: <script>const D = { raw json_for_script(x) };</script>.
    interp.register_builtin(
        "json_for_script",
        1,
        Rc::new(|_i, args, _loc| {
            let v = args.first().ok_or_else(|| err("json_for_script: missing argument"))?;
            let json = dumps(&syn_to_json(v))
                .replace('<', "\\u003c")
                .replace('>', "\\u003e")
                .replace('&', "\\u0026");
            Ok(syn_text(json))
        }),
    );

    // json_decode(text) → value: parsea un string JSON a un valor de Synsema (map/list/
    // number/text/bool/nothing). Error claro si el JSON es inválido.
    interp.register_builtin(
        "json_decode",
        1,
        Rc::new(|_i, args, _loc| {
            let s = match args.first() {
                Some(SynValue::Text(s)) => s.to_string(),
                Some(other) => other.to_string(),
                None => return Err(err("json_decode: missing argument")),
            };
            let j: serde_json::Value = serde_json::from_str(&s)
                .map_err(|e| err(format!("json_decode: invalid JSON: {}", e)))?;
            Ok(json_to_syn(&j))
        }),
    );
}

// =========================================================
// JSON de salida (paridad byte-a-byte con `json.dumps` default de Python:
// separadores ", "/": ", ensure_ascii=True, orden de inserción)
// =========================================================

/// Árbol JSON para la salida. Controlamos el formateo nosotros (no serde) para
/// igualar exactamente a `json.dumps`.
#[derive(Clone, Debug)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    /// Entero de precisión arbitraria: dígitos verbatim (sin comillas).
    BigInt(String),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

pub(crate) fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Escapa un string como el encoder ascii de Python json: `"` `\` controles y
/// todo lo no-ASCII (≥0x7f) → `\uXXXX` (pares subrogados para >0xFFFF).
fn json_escape_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) < 0x7f => out.push(c),
            c => {
                let cp = c as u32;
                if cp <= 0xFFFF {
                    out.push_str(&format!("\\u{:04x}", cp));
                } else {
                    let v = cp - 0x10000;
                    let hi = 0xD800 + (v >> 10);
                    let lo = 0xDC00 + (v & 0x3FF);
                    out.push_str(&format!("\\u{:04x}\\u{:04x}", hi, lo));
                }
            }
        }
    }
    out.push('"');
}

fn dumps_into(j: &Json, out: &mut String) {
    match j {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(i) => out.push_str(&i.to_string()),
        Json::BigInt(s) => out.push_str(s),
        Json::Float(f) => {
            if f.is_nan() {
                out.push_str("NaN");
            } else if f.is_infinite() {
                out.push_str(if *f > 0.0 { "Infinity" } else { "-Infinity" });
            } else {
                out.push_str(&py_float_str(*f));
            }
        }
        Json::Str(s) => json_escape_str(s, out),
        Json::Array(items) => {
            out.push('[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                dumps_into(it, out);
            }
            out.push(']');
        }
        Json::Object(pairs) => {
            out.push('{');
            for (i, (k, v)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                json_escape_str(k, out);
                out.push_str(": ");
                dumps_into(v, out);
            }
            out.push('}');
        }
    }
}

/// Serializa como `json.dumps(obj)` (separadores con espacio, ensure_ascii).
pub fn dumps(j: &Json) -> String {
    let mut out = String::new();
    dumps_into(j, &mut out);
    out
}

/// `array` (Batch 5) → lista JSON anidada (row-major); el caso 0-D es un número.
fn array_view_to_json(a: &ndarray::ArrayViewD<f64>) -> Json {
    if a.ndim() == 0 {
        Json::Float(*a.first().unwrap())
    } else {
        Json::Array(a.outer_iter().map(|s| array_view_to_json(&s)).collect())
    }
}

/// SynValue → árbol JSON (como `syn_to_json` del oráculo).
pub fn syn_to_json(v: &SynValue) -> Json {
    match v {
        SynValue::Nothing => Json::Null,
        SynValue::Bool(b) => Json::Bool(*b),
        SynValue::Number(Number::Int(i)) => Json::Int(*i),
        SynValue::Number(Number::Float(f)) => Json::Float(*f),
        SynValue::Number(Number::Big(b)) => Json::BigInt(b.to_string()),
        // Decimal: número JSON exacto (string verbatim, preserva escala: 1.50d → 1.50).
        // Evita el drift de convertir a float; reusa el camino "número crudo".
        SynValue::Number(Number::Decimal(d)) => Json::BigInt(d.to_string()),
        SynValue::Text(s) => Json::Str(s.to_string()),
        SynValue::List(l) => Json::Array(l.borrow().iter().map(syn_to_json).collect()),
        SynValue::Map(m) => {
            Json::Object(m.borrow().iter().map(|(k, v)| (k.clone(), syn_to_json(v))).collect())
        }
        SynValue::Task(_) | SynValue::Builtin(_) => Json::Str(v.to_string()),
        // Secret en el body de una respuesta / evento SSE (#3/#7): se redacta a
        // "[redacted]" y se emite un warning al log del server (seguro pero visible;
        // no se tumba la API por un descuido). Este brazo SÓLO corre si hay un secret
        // en la respuesta → el request promedio (sin secretos) no paga nada (§8).
        SynValue::Secret(s) => {
            eprintln!(
                "[serve] warning: secret({}) was redacted in a serialized response/SSE body",
                s.name()
            );
            Json::Str("[redacted]".to_string())
        }
        // `bytes` dentro de un body JSON → string base64 (JSON no tiene tipo binario;
        // base64 es la convención estándar e interoperable). NO-lossy.
        SynValue::Bytes(b) => Json::Str(b64_encode(b)),
        // `complex` en un body JSON → objeto `{re, im}` (JSON no tiene tipo complejo;
        // self-describing y recuperable).
        SynValue::Complex(z) => {
            obj(vec![("re", Json::Float(z.re)), ("im", Json::Float(z.im))])
        }
        // `array` en un body JSON → lista anidada (NumPy-like). Batch 5.
        SynValue::Array(a) => array_view_to_json(&a.view()),
        SynValue::Server(s) => match &**s {
            // _RAW/_ENVELOPE serializados como data (fuera del contrato) → su dict.
            ServerValue::Raw { body, content_type, status } => obj(vec![
                ("body", Json::Str(body.clone())),
                ("content_type", Json::Str(content_type.clone())),
                ("status", Json::Int(*status)),
            ]),
            // _RAWBYTES serializado como data → body en base64 (decisión §8.3.3).
            ServerValue::RawBytes { body, content_type, status } => obj(vec![
                ("bytes", Json::Str(b64_encode(body))),
                ("content_type", Json::Str(content_type.clone())),
                ("status", Json::Int(*status)),
            ]),
            ServerValue::Envelope { status, value } => {
                obj(vec![("status", Json::Int(*status)), ("value", syn_to_json(value))])
            }
            // content()/nodo → su árbol JSON estructurado.
            ServerValue::Node(_) => node_to_json(v),
            ServerValue::Content(inner) => node_to_json(inner),
            // paged() fuera del contrato → materializa todo (sin LIMIT).
            ServerValue::Paged(fetch) => match (**fetch)(None, 0) {
                Ok((rows, _)) => Json::Array(rows.iter().map(syn_to_json).collect()),
                Err(_) => Json::Null,
            },
            ServerValue::Redirect { location, status } => obj(vec![
                ("redirect", Json::Str(location.clone())),
                ("status", Json::Int(*status)),
            ]),
            // Serializado como data (fuera del contrato de respuesta): el valor
            // envuelto — los headers son metadata del transporte, no data.
            ServerValue::WithHeaders { inner, .. } => syn_to_json(inner),
        },
    }
}

/// serde_json::Value (body entrante parseado) → SynValue (como `python_to_syn`).
pub fn json_to_syn(v: &serde_json::Value) -> SynValue {
    use serde_json::Value as V;
    match v {
        V::Null => syn_nothing(),
        V::Bool(b) => syn_bool(*b),
        V::Number(n) => {
            if let Some(i) = n.as_i64() {
                syn_int(i)
            } else if let Some(f) = n.as_f64() {
                SynValue::Number(Number::Float(f))
            } else {
                syn_int(0)
            }
        }
        V::String(s) => syn_text(s.as_str()),
        V::Array(a) => syn_list(a.iter().map(json_to_syn).collect()),
        V::Object(o) => {
            let mut m = IndexMap::new();
            for (k, val) in o {
                m.insert(k.clone(), json_to_syn(val));
            }
            syn_map(m)
        }
    }
}

// =========================================================
// Árbol de contenido semántico (vocabulario content()): accesores + su vista JSON.
// Los renderers HTML/Markdown del árbol viven en server.rs (los usa serve); estos
// accesores son puros y los comparten server, charts y el perfil wasm.
// =========================================================

pub(crate) fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

// Los usa server.rs (renderers HTML, sólo `native`) → dead_code legítimo en el perfil puro.
#[cfg_attr(not(feature = "native"), allow(dead_code))]
pub(crate) fn num_i64(v: &SynValue) -> i64 {
    match v {
        SynValue::Number(Number::Int(i)) => *i,
        SynValue::Number(Number::Float(f)) => *f as i64,
        SynValue::Number(Number::Big(b)) => b.to_string().parse().unwrap_or(0),
        _ => 0,
    }
}

pub(crate) fn is_node(v: &SynValue) -> bool {
    matches!(v, SynValue::Server(s) if matches!(&**s, ServerValue::Node(_)))
}

pub(crate) fn node_field(v: &SynValue, key: &str) -> Option<SynValue> {
    if let SynValue::Server(s) = v {
        s.get_field(key)
    } else {
        None
    }
}

pub(crate) fn node_str(v: &SynValue, key: &str) -> String {
    match node_field(v, key) {
        None | Some(SynValue::Nothing) => String::new(),
        Some(x) => x.to_string(),
    }
}

#[cfg_attr(not(feature = "native"), allow(dead_code))]
pub(crate) fn node_int(v: &SynValue, key: &str, default: i64) -> i64 {
    match node_field(v, key) {
        Some(n @ SynValue::Number(_)) => num_i64(&n),
        _ => default,
    }
}

pub(crate) fn list_field(v: &SynValue, key: &str) -> Vec<SynValue> {
    match node_field(v, key) {
        Some(SynValue::List(l)) => l.borrow().clone(),
        _ => Vec::new(),
    }
}

#[cfg_attr(not(feature = "native"), allow(dead_code))]
pub(crate) fn meta_get(meta: &SynValue, key: &str) -> Option<String> {
    if let SynValue::Map(m) = meta {
        m.borrow().get(key).map(|v| v.to_string())
    } else {
        None
    }
}

// -- JSON (el árbol como data) --

pub(crate) fn meta_to_json(meta: Option<&SynValue>) -> Json {
    match meta {
        Some(SynValue::Map(m)) => {
            Json::Object(m.borrow().iter().map(|(k, v)| (k.clone(), syn_to_json(v))).collect())
        }
        _ => Json::Object(Vec::new()),
    }
}

fn item_to_json(item: &SynValue) -> Json {
    if is_node(item) {
        node_to_json(item)
    } else {
        syn_to_json(item)
    }
}

pub(crate) fn node_to_json(node: &SynValue) -> Json {
    let kind = node_str(node, "kind");
    match kind.as_str() {
        "page" => obj(vec![
            ("type", Json::Str("page".into())),
            ("meta", meta_to_json(node_field(node, "meta").as_ref())),
            (
                "nodes",
                Json::Array(
                    list_field(node, "nodes").iter().filter(|n| is_node(n)).map(node_to_json).collect(),
                ),
            ),
        ]),
        "list" | "ordered_list" => obj(vec![
            ("type", Json::Str(kind.clone())),
            ("items", Json::Array(list_field(node, "items").iter().map(item_to_json).collect())),
        ]),
        "section" => obj(vec![
            ("type", Json::Str("section".into())),
            (
                "nodes",
                Json::Array(
                    list_field(node, "nodes").iter().filter(|n| is_node(n)).map(node_to_json).collect(),
                ),
            ),
        ]),
        // chart() (Batch 8/10): datos estructurados por kind — el agente obtiene
        // los DATOS (§3.7). Los campos por kind salen de charts::chart_data_fields
        // (match exhaustivo sobre Kind: un kind nuevo sin salida JSON no compila).
        "chart" => {
            let mut pairs: Vec<(String, Json)> = vec![
                ("type".to_string(), Json::Str("chart".into())),
                ("kind".to_string(), Json::Str(node_str(node, "chart_kind"))),
            ];
            for key in ["title", "x_label", "y_label"] {
                if let Some(val) = node_field(node, key) {
                    if !matches!(val, SynValue::Nothing) {
                        pairs.push((key.to_string(), syn_to_json(&val)));
                    }
                }
            }
            for (key, val) in crate::charts::chart_data_fields(node) {
                pairs.push((key.to_string(), syn_to_json(&val)));
            }
            Json::Object(pairs)
        }
        _ => {
            let mut pairs: Vec<(String, Json)> = vec![("type".to_string(), Json::Str(kind))];
            for key in ["level", "text", "href", "src", "alt", "lang", "html"] {
                if let Some(val) = node_field(node, key) {
                    if !matches!(val, SynValue::Nothing) {
                        pairs.push((key.to_string(), syn_to_json(&val)));
                    }
                }
            }
            Json::Object(pairs)
        }
    }
}

pub(crate) fn make_node(kind: &str, fields: Vec<(&str, SynValue)>) -> SynValue {
    let mut m: IndexMap<String, SynValue> = IndexMap::new();
    m.insert("kind".to_string(), syn_text(kind));
    for (k, v) in fields {
        m.insert(k.to_string(), v);
    }
    SynValue::Server(Rc::new(ServerValue::Node(Rc::new(RefCell::new(m)))))
}

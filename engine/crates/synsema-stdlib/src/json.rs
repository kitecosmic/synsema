//! JSON ↔ SynValue + árbol de contenido como data. Extraído de server.rs para que
//! los módulos PUROS (charts, oidc, webauth) no dependan del server nativo: este
//! módulo compila en el perfil wasm (sin `native`), server.rs no. server.rs
//! re-exporta los símbolos públicos → los callers externos no cambian.

use synsema_core::types::SynMap;
use std::rc::Rc;


use synsema_core::bytesutil::b64_encode;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::{py_float_str, Number};
use synsema_core::types::{
    syn_bool, syn_int, syn_list, syn_map, syn_nothing, syn_text, ServerValue, SynValue,
};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

/// Un task o un generador no es un dato: `json_encode` lo escribía como texto
/// (`"builtin:rng(1)"`, con la semilla y sin el estado) sin avisar. Es un error que nombra
/// dónde está, como `canonical_json` y el `TypeError` de Python. (Los bodies de `serve`
/// siguen su propio contrato, en `syn_to_json`.)
fn reject_code(v: &SynValue, who: &str, path: &str) -> Result<(), Control> {
    match v {
        SynValue::Task(_) | SynValue::Builtin(_) => Err(err(format!(
            "{}: {} is {}, not data — JSON cannot hold code; store what it computes, or leave it out",
            who,
            path,
            synsema_core::rng::code_noun(v)
        ))),
        SynValue::List(l) => {
            // Una lista sin caja tiene números, no código: leerla con `list_values` la pasaba a
            // valores para siempre (×3 de memoria) antes de escribir nada.
            let b = l.borrow();
            let Some(xs) = b.as_values() else { return Ok(()) };
            for (i, x) in xs.iter().enumerate() {
                if matches!(x, SynValue::Task(_) | SynValue::Builtin(_) | SynValue::List(_) | SynValue::Map(_)) {
                    reject_code(x, who, &format!("{}[{}]", path, i))?;
                }
            }
            Ok(())
        }
        SynValue::Map(m) => {
            for (k, x) in m.borrow().iter() {
                if matches!(x, SynValue::Task(_) | SynValue::Builtin(_) | SynValue::List(_) | SynValue::Map(_)) {
                    reject_code(x, who, &format!("{}[{:?}]", path, k))?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
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
            reject_code(v, "json_encode", "the value")?;
            Ok(syn_text(dumps_syn(v)))
        }),
    );

    // v0.6.29 (DATOS-16): JSON Lines — un valor JSON por línea (logs, datasets, exportes
    // de BigQuery/Spark). `jsonl_encode(items)` → texto con `\n` al final de cada línea;
    // `jsonl_decode(text)` → lista (las líneas vacías se saltean; un error dice la línea);
    // `jsonl_decode(text, default)` es la forma total.
    interp.register_builtin(
        "jsonl_encode",
        1,
        Rc::new(|_i, args, _loc| {
            let items = match args.first() {
                Some(SynValue::List(l)) => l.borrow().to_vec(),
                Some(other) => return Err(err(format!("jsonl_encode: expected a list, got {}", other.type_name()))),
                None => return Err(err("jsonl_encode(items)")),
            };
            let mut out = String::new();
            for (i, it) in items.iter().enumerate() {
                reject_code(it, "jsonl_encode", &format!("item {}", i))?;
                dumps_syn_into(it, &mut out);
                out.push('\n');
            }
            Ok(syn_text(out))
        }),
    );
    interp.register_builtin(
        "jsonl_decode",
        -1,
        synsema_core::interpreter::with_fallback(
            1,
            Rc::new(|i, args, _loc| {
                let allow_nan = allow_nan_kw(i, "jsonl_decode")?;
                let text: &str = match args.first() {
                    Some(SynValue::Text(t)) => t,
                    Some(other) => return Err(err(format!("jsonl_decode: expected text, got {}", other.type_name()))),
                    None => return Err(err("jsonl_decode(text)")),
                };
                // Las claves se comparten entre todas las líneas de la llamada (F4.4).
                let mut memo = crate::json_exact::Memo::default();
                let mut out = Vec::new();
                for (i, line) in text.lines().enumerate() {
                    let l = line.trim();
                    if l.is_empty() {
                        continue;
                    }
                    match crate::json_exact::parse_with(l, allow_nan, &mut memo) {
                        Ok(v) => out.push(v),
                        Err(e) => {
                            return Err(err(format!(
                                "jsonl_decode: line {}: invalid JSON: {}. To validate untrusted input without raising: jsonl_decode(text, nothing)",
                                i + 1,
                                e
                            )))
                        }
                    }
                }
                Ok(synsema_core::types::syn_list(out))
            }),
        ),
    );

    // json_for_script(value) → text: JSON seguro para incrustar en un <script> — igual que
    // json_encode pero con `<`, `>` y `&` escapados como \u00XX, así un valor que contenga
    // "</script>" no puede cerrar el tag ni inyectar HTML. Es el mismo escapado que el
    // runtime ya usa para su JSON-LD. Uso: <script>const D = { raw json_for_script(x) };</script>.
    interp.register_builtin(
        "json_for_script",
        1,
        Rc::new(|_i, args, _loc| {
            let v = args.first().ok_or_else(|| err("missing argument"))?;
            reject_code(v, "json_for_script", "the value")?;
            let json = dumps_syn(v)
                .replace('<', "\\u003c")
                .replace('>', "\\u003e")
                .replace('&', "\\u0026");
            Ok(syn_text(json))
        }),
    );

    // json_decode(text) → value: parsea un string JSON a un valor de Synsema (map/list/
    // number/text/bool/nothing). Error claro si el JSON es inválido.
    //
    // json_decode(text, default) → la variante TOTAL: devuelve `default` en vez de lanzar.
    // T5 (ronda 7) — bajo etiquetas un error causado por datos privados NO se atrapa (poder
    // recuperarse de un fallo es el bit), así que validar una carga no confiable —lo que un
    // enclave hace con todo lo que recibe— se quedaba sin ninguna frase que escribir: ni
    // `try/recover`, ni declarar privado el destino. Sin error no hay bit:
    // `let d be json_decode(payload, nothing)` y después `when d == nothing`.
    interp.register_builtin(
        "json_decode",
        -1,
        Rc::new(|i, args, _loc| {
            let allow_nan = allow_nan_kw(i, "json_decode")?;
            if args.is_empty() || args.len() > 2 {
                return Err(err("json_decode(text, default?) takes 1 or 2 arguments"));
            }
            // El texto se lee prestado: copiar el documento entero era un pico de memoria de más.
            let owned;
            let s: &str = match args.first() {
                Some(SynValue::Text(s)) => s,
                Some(other) => {
                    owned = other.to_string();
                    &owned
                }
                None => return Err(err("json_decode: missing argument")),
            };
            match crate::json_exact::parse_opts(s, allow_nan) {
                Ok(v) => Ok(v),
                Err(e) => match args.get(1) {
                    Some(d) => Ok(d.clone()),
                    None => Err(err(format!(
                        "json_decode: invalid JSON: {}. To validate untrusted input without raising, pass a fallback: json_decode(<text>, nothing)",
                        e
                    ))),
                },
            }
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

pub fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Escapa un string como el encoder ascii de Python json: `"` `\` controles y
/// todo lo no-ASCII (≥0x7f) → `\uXXXX` (pares subrogados para >0xFFFF).
fn json_escape_str(s: &str, out: &mut String) {
    // Lo común (claves, nombres): ASCII imprimible sin `"` ni `\` sale tal cual, de una vez.
    if s.bytes().all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\') {
        out.reserve(s.len() + 2);
        out.push('"');
        out.push_str(s);
        out.push('"');
        return;
    }
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
        Json::Int(i) => push_int(*i, out),
        Json::BigInt(s) => out.push_str(s),
        Json::Float(f) => push_float(*f, out),
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

/// Un entero como lo escribe `i.to_string()`, sin pedir un `String` aparte.
fn push_int(x: i64, out: &mut String) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    let mut u = x.unsigned_abs();
    loop {
        i -= 1;
        buf[i] = b'0' + (u % 10) as u8;
        u /= 10;
        if u == 0 {
            break;
        }
    }
    if x < 0 {
        out.push('-');
    }
    // Sólo dígitos ASCII.
    out.push_str(std::str::from_utf8(&buf[i..]).unwrap_or_default());
}

fn push_float(f: f64, out: &mut String) {
    if f.is_nan() {
        out.push_str("NaN");
    } else if f.is_infinite() {
        out.push_str(if f > 0.0 { "Infinity" } else { "-Infinity" });
    } else {
        out.push_str(&py_float_str(f));
    }
}

/// Serializa como `json.dumps(obj)` (separadores con espacio, ensure_ascii).
pub fn dumps(j: &Json) -> String {
    let mut out = String::new();
    dumps_into(j, &mut out);
    out
}

/// `dumps(&syn_to_json(v))` sin armar el árbol intermedio (un `String` por clave y por texto):
/// nada, booleanos, enteros, floats, texto, listas y mapas se escriben directo; cualquier otro
/// valor pasa por `syn_to_json` sólo para ese sub-valor. Mismo recorrido y mismos bytes.
pub fn dumps_syn(v: &SynValue) -> String {
    let mut out = String::new();
    dumps_syn_into(v, &mut out);
    out
}

pub fn dumps_syn_into(v: &SynValue, out: &mut String) {
    match v {
        SynValue::Nothing => out.push_str("null"),
        SynValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        SynValue::Number(Number::Int(i)) => push_int(*i, out),
        SynValue::Number(Number::Float(f)) => push_float(*f, out),
        SynValue::Text(s) => json_escape_str(s, out),
        SynValue::List(l) => {
            // Una lista sin caja se escribe desde sus números: sin copiarla ni pasarla a valores.
            out.push('[');
            let b = l.borrow();
            if let Some(xs) = b.as_ints() {
                for (i, x) in xs.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    push_int(*x, out);
                }
            } else if let Some(xs) = b.as_floats() {
                for (i, x) in xs.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    push_float(*x, out);
                }
            } else {
                for (i, it) in b.as_values().into_iter().flatten().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    dumps_syn_into(it, out);
                }
            }
            out.push(']');
        }
        SynValue::Map(m) => {
            out.push('{');
            for (i, (k, x)) in m.borrow().iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                json_escape_str(k.as_str(), out);
                out.push_str(": ");
                dumps_syn_into(x, out);
            }
            out.push('}');
        }
        _ => dumps_into(&syn_to_json(v), out),
    }
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
        // v0.6.29: fecha / instante / duración → su texto ISO 8601 (lo que lee cualquier API).
        SynValue::Time(t) => Json::Str(t.to_string()),
        SynValue::Bool(b) => Json::Bool(*b),
        SynValue::Number(Number::Int(i)) => Json::Int(*i),
        SynValue::Number(Number::Float(f)) => Json::Float(*f),
        SynValue::Number(Number::Big(b)) => Json::BigInt(b.to_string()),
        // Decimal: número JSON exacto (string verbatim, preserva escala: 1.50d → 1.50).
        // Evita el drift de convertir a float; reusa el camino "número crudo".
        SynValue::Number(n @ (Number::Decimal(_) | Number::BigDec(_))) => Json::BigInt(n.to_string()),
        SynValue::Text(s) => Json::Str(s.to_string()),
        // (Leer sin convertir: una lista sin caja sigue sin caja.)
        SynValue::List(l) => Json::Array(synsema_core::synlist::list_read(l).iter().map(syn_to_json).collect()),
        SynValue::Map(m) => {
            Json::Object(m.borrow().iter().map(|(k, v)| (k.to_string(), syn_to_json(v))).collect())
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
        // `private` en un body serializado: fail-closed, como el secret. Como BUILTIN,
        // `json_encode` nunca ve un Private (el despacho etiquetado del intérprete le entrega
        // El valor sin etiquetas y envuelve el texto resultante con ellas). Llegar acá con un
        // private significa que un sumidero del host (respuesta HTTP/SSE) serializó sin pasar
        // por `labels::check_flow` + `labels::strip_deep`: se redacta y se avisa, no se filtra.
        SynValue::Private(p) => {
            // T5 (ronda 8): el aviso nombra los principales DECLARADOS, no los de ESTE valor.
            let _ = p;
            eprintln!(
                "[serve] warning: {} was redacted in a serialized response/SSE body (the sink did not check_flow/strip_deep)",
                synsema_core::labels::redacted_display()
            );
            Json::Str("[redacted]".to_string())
        }
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
/// ¿Hay algún número que serde_json no pudo guardar como entero de 64 bits pero que en el
/// texto era un entero (sin punto ni exponente es imposible saberlo desde el `Value`: se
/// aproxima por "float entero de magnitud ≥ 2^63")? Entonces vale la pena re-parsear exacto.
pub fn has_wide_int(v: &serde_json::Value) -> bool {
    use serde_json::Value as V;
    match v {
        V::Number(n) => {
            !n.is_i64() && !n.is_u64() && n.as_f64().is_some_and(|f| f.fract() == 0.0 && f.abs() >= 9.2e18)
        }
        V::Array(a) => a.iter().any(has_wide_int),
        V::Object(o) => o.values().any(has_wide_int),
        _ => false,
    }
}

pub fn json_to_syn(v: &serde_json::Value) -> SynValue {
    use serde_json::Value as V;
    match v {
        V::Null => syn_nothing(),
        V::Bool(b) => syn_bool(*b),
        // Enteros exactos hasta u64 (un id de 64 bits sin signo no pasa por f64). Lo que el
        // programa decodifica él mismo (`json_decode`, `jsonl_decode`, el `json` de una
        // respuesta HTTP) va por `json_exact`, exacto a cualquier tamaño.
        V::Number(n) => {
            if let Some(i) = n.as_i64() {
                return syn_int(i);
            }
            if let Some(u) = n.as_u64() {
                return SynValue::Number(Number::from_bigint(num_bigint::BigInt::from(u)));
            }
            SynValue::Number(Number::Float(n.as_f64().unwrap_or(f64::NAN)))
        }
        V::String(s) => syn_text(s.as_str()),
        V::Array(a) => syn_list(a.iter().map(json_to_syn).collect()),
        V::Object(o) => {
            let mut m = SynMap::new();
            for (k, val) in o {
                m.insert(k.clone(), json_to_syn(val));
            }
            syn_map(m)
        }
    }
}

// =========================================================
// árbol de contenido semántico (vocabulario content()): accesores + su vista JSON.
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
        Some(SynValue::List(l)) => l.borrow().to_vec(),
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
            Json::Object(m.borrow().iter().map(|(k, v)| (k.to_string(), syn_to_json(v))).collect())
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
    let mut m: SynMap = SynMap::new();
    m.insert("kind", syn_text(kind));
    for (k, v) in fields {
        m.insert(k.to_string(), v);
    }
    SynValue::Server(Rc::new(ServerValue::Node(m.into_ref())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::tokens::SourceLocation;
    use synsema_core::types::syn_text;

    /// `Control` no es Debug a propósito (transporta valores del lenguaje): desempaquetar con
    /// el mensaje del error, no con `unwrap`.
    fn ok(r: Result<SynValue, Control>) -> SynValue {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("{}", e),
            Err(_) => panic!("control flow inesperado"),
        }
    }

    fn decode(args: &[SynValue]) -> Result<SynValue, Control> {
        let mut interp = Interpreter::new();
        register_json_builtins(&interp);
        let f = match interp.global_env.borrow().bindings.get("json_decode") {
            Some(SynValue::Builtin(bt)) => bt.func.clone(),
            _ => panic!("json_decode no registrado"),
        };
        let loc = SourceLocation { file: "<test>".into(), line: 1, column: 1, offset: 0 };
        f(&mut interp, args, &loc)
    }

    /// `dumps_syn` escribe sin el árbol intermedio: tiene que dar los mismos bytes que
    /// `dumps(&syn_to_json(v))` en todo lo que escribe directo y en lo que delega.
    #[test]
    fn dumps_syn_matches_the_tree() {
        let texts = [
            "", "plain", "with \"quotes\"", "back\\slash", "tab\tnl\ncr\r", "\u{08}\u{0c}\u{01}\u{1f}",
            "del\u{7f}", "ñandú", "emoji 😀", "\u{2028}", "</script>",
        ];
        let mut inner = SynMap::new();
        for (i, t) in texts.iter().enumerate() {
            inner.insert(*t, syn_text(*t));
            inner.insert(format!("k{}", i), syn_int(i as i64));
        }
        let ints = [0, 1, -1, 9, 10, -10, 99, 100, 1_000_000_007, -123_456_789_012, i64::MAX, i64::MIN, i64::MIN + 1];
        let floats = [0.0, -0.0, 0.5, -2.75, 1e16, 1e-7, 3.141592653589793, 1e300, f64::NAN, f64::INFINITY, f64::NEG_INFINITY];
        let mut row = SynMap::new();
        row.insert("id", syn_int(7));
        row.insert("name", syn_text("n7"));
        row.insert("score", synsema_core::types::syn_float(3.5));
        row.insert("none", syn_nothing());
        row.insert("flag", syn_bool(true));
        row.insert("dec", SynValue::Number(Number::parse_decimal("1.50").expect("decimal")));
        row.insert("big", SynValue::Number(Number::from_bigint(num_bigint::BigInt::from(u64::MAX) * 3)));
        row.insert("bytes", synsema_core::types::syn_bytes(vec![0u8, 255, 10]));
        row.insert("inner", syn_map(inner));
        row.insert("ints", syn_list(ints.iter().map(|x| syn_int(*x)).collect()));
        row.insert("floats", syn_list(floats.iter().map(|x| synsema_core::types::syn_float(*x)).collect()));
        row.insert("unboxed", synsema_core::types::syn_list_of(synsema_core::synlist::SynList::from_ints(ints.to_vec())));
        row.insert("unboxed_floats", synsema_core::types::syn_list_of(synsema_core::synlist::SynList::from_floats(floats.to_vec())));
        row.insert("empty_list", syn_list(vec![]));
        row.insert("empty_map", syn_map(SynMap::new()));
        let v = syn_list(vec![syn_map(row), syn_text("top"), syn_int(-5), syn_nothing()]);
        assert_eq!(dumps_syn(&v), dumps(&syn_to_json(&v)));
        for t in texts {
            assert_eq!(dumps_syn(&syn_text(t)), dumps(&syn_to_json(&syn_text(t))), "{:?}", t);
        }
        for x in ints {
            assert_eq!(dumps_syn(&syn_int(x)), x.to_string());
        }
    }

    /// Auditoría ronda 7: sin una variante TOTAL no quedaba forma de validar una carga
    /// malformada bajo etiquetas — el error causado por datos privados no se atrapa, así que
    /// `try/recover` no sirve y declarar privado el destino tampoco. Con el segundo argumento
    /// no hay error, así que no hay bit, y el programa valida sin excepciones.
    #[test]
    fn json_decode_has_a_total_variant() {
        // Sin fallback: error, y el mensaje enseña la salida.
        let e = match decode(&[syn_text("{roto")]) {
            Err(Control::Error(e)) => e.into_message(),
            _ => panic!("un JSON inválido sin fallback tiene que fallar"),
        };
        assert!(e.contains("json_decode(<text>, nothing)"), "{}", e);
        // Con fallback: lo devuelve en vez de lanzar.
        let v = ok(decode(&[syn_text("{roto"), SynValue::Nothing]));
        assert!(matches!(v, SynValue::Nothing));
        let v = ok(decode(&[syn_text("{roto"), syn_text("bad")]));
        assert_eq!(v.to_string(), "bad");
        // Y un JSON válido pasa igual, con o sin fallback.
        let a = ok(decode(&[syn_text("{\"a\": 1}")])).to_string();
        let b = ok(decode(&[syn_text("{\"a\": 1}"), SynValue::Nothing])).to_string();
        assert_eq!(a, b);
        // Aridad fuera de rango: error claro.
        assert!(decode(&[]).is_err());
        assert!(decode(&[syn_text("1"), SynValue::Nothing, SynValue::Nothing]).is_err());
    }
}

/// `allow_nan = true` de `json_decode`/`jsonl_decode`.
fn allow_nan_kw(i: &mut synsema_core::interpreter::Interpreter, who: &str) -> Result<bool, synsema_core::interpreter::Control> {
    match i.kwarg("allow_nan") {
        None | Some(SynValue::Nothing) => Ok(false),
        Some(SynValue::Bool(b)) => Ok(b),
        Some(other) => Err(err(format!("{}: allow_nan must be true or false, got {}", who, other.type_name()))),
    }
}

//! Builtins de respuesta (ok/created/not_found/fail/html/redirect/respond/binary/
//! with_header/set_cookie/clear_cookie) + vocabulario de contenido (page/heading/
//! prose/.../content). PUROS: construyen valores ServerValue sin tocar sockets --
//! extraidos de server.rs para que existan tambien en el perfil wasm (sin `native`).
//! server.rs los re-exporta (register_serve_builtins) y conserva el transporte y los
//! renderers HTML/Markdown del arbol de contenido.

use std::rc::Rc;

use indexmap::IndexMap;

use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::types::{
    syn_int, syn_list, syn_map, syn_nothing, syn_text, ServerValue, SynValue,
};

use crate::json::{make_node, num_i64};

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

pub(crate) fn make_raw_val(body: String, ct: &str, status: i64) -> SynValue {
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
pub(crate) fn validate_header(who: &str, name: &str, value: &str) -> Result<(), Control> {
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
pub(crate) fn append_header_val(resp: &SynValue, name: String, value: String) -> SynValue {
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
pub(crate) struct CookieOpts {
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
pub(crate) fn parse_cookie_opts(who: &str, opts: Option<&SynValue>, allow_all: bool) -> Result<CookieOpts, Control> {
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
pub(crate) fn build_set_cookie(who: &str, name: &str, value: &str, o: &CookieOpts) -> Result<String, Control> {
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

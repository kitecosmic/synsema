//! Lo PURO del cliente HTTP — compartido por el transporte nativo (`http.rs`, sockets +
//! rustls) y el del perfil wasm (`http_stub.rs`, transporte provisto por el host vía
//! `hostcap`). Acá viven: el gate `net(host)`, la forma de la respuesta, los parsers
//! de args de los builtins y el registro de los seis builtins cliente
//! (`http`/`http_get`/`http_post`/`http_put`/`http_delete`/`fetch`).
//!
//! Una sola verdad para los dos perfiles: el chequeo de capability corre ANTES del
//! transporte, con la MISMA canonización de host, en nativo y en wasm — el host
//! embebedor puede ofrecer `http`, pero el programa sigue teniendo que declarar
//! `require net("host")` y el techo del embebedor sigue mandando.

use synsema_core::types::SynMap;
use std::cell::RefCell;
use std::rc::Rc;

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_capabilities::secure::url_hostname;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use sha2::{Digest, Sha256};
use synsema_core::types::{syn_bool, syn_bytes, syn_int, syn_map, syn_nothing, syn_text, SynValue};

use crate::json::dumps_syn;

/// Chequea la capability `net(host)` del URL; convierte la violación en `Control::Error`
/// SIN ubicación (como secure.rs/database.rs). Scope = hostname (minúsculas, sin puerto);
/// si no se puede extraer, se usa el URL crudo (fail-closed). `net` NO es tipo-ruta →
/// `covers()` usa el glob de host (`net("*.example.com")` cubre `api.example.com`).
pub fn require_net(
    caps: &Rc<RefCell<CapabilitySet>>,
    url: &str,
    source: &str,
) -> Result<(), Control> {
    // Sin host extraíble no hay a qué darle permiso: error, y SIN ecoar el URL (puede llevar
    // `user:pass@` o la clave de un RPC en la ruta).
    let host = match url_hostname(url) {
        Some(h) if !h.is_empty() => h,
        _ => {
            return Err(Control::Error(RuntimeError::new(format!(
                "{}: the URL has no host (expected scheme://host/…)",
                source
            ))))
        }
    };
    let scope = synsema_capabilities::model::net_request_scope(url).unwrap_or(host);
    caps.borrow_mut()
        .require(&Capability::new(CapabilityType::Net, Some(scope)), source)
        .map_err(|v| Control::Error(v.into_error()))
}

/// Respuesta estructurada (espeja el dict del oráculo).
pub struct HttpResult {
    pub status: i64,
    pub ok: bool,
    pub body: String,
    /// v0.6.20 — el body exacto, byte a byte (`body` es su lectura como texto, lossy para
    /// binarios). Lo expone `http_bytes(...)` como `bytes of r`.
    pub body_bytes: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub error: Option<String>,
    /// T9: lo que se verificó del servidor atestado (sólo con `fetch(url, {"attested": …})`).
    pub attested: Option<crate::attested_client::AttestedInfo>,
}

pub fn err_result(error: String) -> HttpResult {
    HttpResult {
        status: 0,
        ok: false,
        body: String::new(),
        body_bytes: Vec::new(),
        headers: Vec::new(),
        error: Some(error),
        attested: None,
    }
}

/// Cómo se valida el servidor TLS de un pedido además de (o en lugar de) las raíces del SO.
#[derive(Clone, Debug)]
pub enum TlsCheck {
    /// T5: la SPKI DER exacta del servidor.
    Pin(Vec<u8>),
    /// T9: un `serve --attested` que tiene que probar, en la misma conexión, qué corre.
    Attested(crate::attested_client::AttestedSpec),
}

/// Transporte de una request: (method, url, headers, query, body, timeout_secs, tls).
/// Nativo = sockets; wasm = el `http` del host (o el stub "sin transporte").
/// v0.6.20 — el body va en BYTES: texto, binario o el JSON que `body_arg` ya serializó.
/// `tls` (sólo `fetch` con mapa de opciones): `tls_pin` o `attested`; un transporte que no puede
/// cumplirlo falla cerrado.
pub type Transport = fn(
    &str,
    &str,
    Option<&[(String, String)]>,
    Option<&[(String, String)]>,
    Option<&[u8]>,
    u64,
    Option<&TlsCheck>,
) -> HttpResult;

/// `tls_pin`: la SubjectPublicKeyInfo DER del servidor, como hex (el `public_key_hex` de
/// `/.well-known/attestation`), bytes o PEM `PUBLIC KEY`. Tiene que parsear como SPKI: un pin que
/// no es una clave se rechaza acá, no en el handshake.
pub fn parse_tls_pin(v: &SynValue, who: &str) -> Result<Vec<u8>, Control> {
    let der = match v {
        SynValue::Bytes(b) => b.to_vec(),
        SynValue::Text(t) if t.contains("-----BEGIN") => {
            let (label, der) = crate::webauth::pem_decode(t).map_err(|e| perr(format!("{}: tls_pin: {}", who, e)))?;
            if label != "PUBLIC KEY" {
                return Err(perr(format!("{}: tls_pin must be a PUBLIC KEY PEM, got {:?}", who, label)));
            }
            der
        }
        SynValue::Text(t) => {
            let h: String = t.chars().filter(|c| !c.is_whitespace()).collect();
            let h = h.trim_start_matches("0x").trim_start_matches("0X");
            synsema_core::bytesutil::hex_decode(h).map_err(|_| perr(format!("{}: tls_pin is not hex (pass the server's SubjectPublicKeyInfo as hex, bytes or a PUBLIC KEY PEM)", who)))?
        }
        other => return Err(perr(format!("{}: tls_pin must be hex text, bytes or a PUBLIC KEY PEM, got {}", who, other.type_name()))),
    };
    use x509_parser::prelude::FromDer;
    match x509_parser::x509::SubjectPublicKeyInfo::from_der(&der) {
        Ok((rest, _)) if rest.is_empty() => Ok(der),
        _ => Err(perr(format!("{}: tls_pin is not a DER SubjectPublicKeyInfo", who))),
    }
}

fn perr(msg: String) -> Control {
    Control::Error(RuntimeError::new(msg))
}

// =============================================================================================
// v0.6.46 (E1, HB5): un secret atado a un host. Cada request arma un `Outgoing` con el destino
// (sacado de la parte PÚBLICA de la URL) y cada secret que sale por ella pasa por `admit`: uno no
// atado sólo va en un header (como antes); uno atado va en cualquier posición (URL, query, header,
// body JSON, body form), pero sólo a sus hosts y sólo por https (por http, sólo a un loopback que la
// atadura nombre: D2, la regla de Secure Contexts). Lo que salió se recuerda para enmascarar el eco
// de la respuesta y para el audit.

/// Lo que una request lleva de secrets.
pub struct Outgoing {
    who: String,
    scheme: String,
    /// El destino como lo pide `net`: `host` o `host:puerto` (el puerto, si la URL lo escribe).
    dest: String,
    host: String,
    /// (nombre, texto) de cada secret materializado y de sus partes: el eco se enmascara con
    /// cada uno.
    sent: Vec<(String, String)>,
    /// Los nombres que salieron, en orden (audit).
    names: Vec<String>,
    /// `true` si salió algún secret: en wasm la request pide `redirect: "error"` (ronda 1, M1: antes
    /// sólo fuera de los headers, y un `X-Api-Key` atado seguía un redirect a otro host; el `fetch`
    /// sólo quita `Authorization`). El nativo no sigue redirects.
    forbid_redirects: bool,
    /// v0.6.46 (E7): los hosts de las ataduras de los secrets que salieron. Con uno atado, una IP
    /// privada exige además que la atadura la nombre.
    bindings: Vec<String>,
}

impl Drop for Outgoing {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for (_, v) in &mut self.sent {
            v.zeroize();
        }
    }
}

fn is_loopback_host(h: &str) -> bool {
    matches!(h, "localhost" | "127.0.0.1" | "::1")
}

impl Outgoing {
    /// El contexto de una request a `public_url` (la parte pública: nunca el material).
    pub fn for_url(public_url: &str, who: &str) -> Self {
        let scheme = public_url.split_once("://").map(|(s, _)| s.to_ascii_lowercase()).unwrap_or_default();
        let dest = synsema_capabilities::model::net_request_scope(public_url).unwrap_or_default();
        let host = synsema_core::capscope::split_host_port(&dest).0.to_string();
        Outgoing { who: who.to_string(), scheme, dest, host, sent: Vec::new(), names: Vec::new(), forbid_redirects: false, bindings: Vec::new() }
    }

    /// v0.6.46 (E7): los hosts de las ataduras de lo que salió (ver el campo).
    pub fn bindings(&self) -> &[String] {
        &self.bindings
    }

    /// ¿Salió algún secret?
    pub fn carries_secrets(&self) -> bool {
        !self.names.is_empty()
    }

    /// ¿La request tiene que pedir que no se sigan redirects? (Salió algún secret.)
    pub fn forbids_redirects(&self) -> bool {
        self.forbid_redirects
    }

    /// Un secret que sale en esta request por `what` ("header \"Authorization\"", "the URL", …).
    /// Devuelve su texto; o el error que dice qué escribir.
    pub fn admit(&mut self, s: &synsema_core::secret::SecretInner, what: &str, in_header: bool) -> Result<String, Control> {
        match s.bound() {
            None if in_header => {}
            None => {
                let place = if what.starts_with("the URL") {
                    "URL"
                } else if what.starts_with("query") {
                    "query"
                } else {
                    "body"
                };
                return Err(perr(format!(
                    "{}: {} is secret({}), and an unbound secret only goes in a header. If the API takes it in the {}, bind it to the host it goes to: `require secret(\"{}\") for net(\"{}\")`",
                    self.who,
                    what,
                    s.name(),
                    place,
                    s.name(),
                    if self.dest.is_empty() { "<the host>" } else { &self.dest }
                )));
            }
            Some(b) => {
                if self.dest.is_empty() || !b.iter().any(|p| synsema_core::capscope::bound_host_covers(p, &self.dest)) {
                    return Err(perr(format!(
                        "{}: secret({}) is bound to [{}]; this request goes to {} — it never goes to another host, not even in a header",
                        self.who,
                        s.name(),
                        b.join(", "),
                        if self.dest.is_empty() { "<no host>" } else { &self.dest }
                    )));
                }
                let secure = matches!(self.scheme.as_str(), "https" | "wss");
                let local_plain = matches!(self.scheme.as_str(), "http" | "ws") && is_loopback_host(&self.host);
                if !secure && !local_plain {
                    return Err(perr(format!(
                        "{}: secret({}) only travels over https; this request to {} is {}://",
                        self.who,
                        s.name(),
                        self.host,
                        self.scheme
                    )));
                }
            }
        }
        if let Some(b) = s.bound() {
            for h in b.iter() {
                if !self.bindings.contains(h) {
                    self.bindings.push(h.clone());
                }
            }
        }
        let text = crate::secrets::secret_text(s, &self.who, what)?;
        self.forbid_redirects = true;
        for n in s.names() {
            if !self.names.contains(&n) {
                self.names.push(n);
            }
        }
        self.sent.push((s.name().to_string(), text.clone()));
        self.sent.extend(s.atoms());
        Ok(text)
    }

    /// El audit: una entrada por secret que salió, `secret(K) → host`. Nunca la URL.
    pub fn audit(&self, caps: &Rc<RefCell<CapabilitySet>>) {
        for n in &self.names {
            caps.borrow_mut().push_audit(synsema_capabilities::model::CapabilityAuditEntry {
                capability: Capability::new(CapabilityType::Secret, Some(n.clone())),
                granted: true,
                source: "bound-send".to_string(),
                reason: format!("→ {}", self.dest),
                origin: "program",
            });
        }
    }

    /// El eco enmascarado (E1.6): en el body, los headers y el error de la respuesta, cada secret
    /// que salió — tal cual, en percent-encoding (hex en mayúscula y en minúscula, el de query y el
    /// de formulario), escapado como JSON y en base64/base64url — pasa a `[secret K]`. Es una
    /// defensa contra el eco accidental (`httpbin.org/anything`), no contra un servidor hostil: la
    /// garantía es la atadura.
    pub fn mask(&self, r: &mut HttpResult) {
        if self.sent.is_empty() {
            return;
        }
        let pats = self.patterns();
        if pats.is_empty() {
            return;
        }
        if let Some(b) = mask_bytes(r.body.as_bytes(), &pats) {
            r.body = String::from_utf8_lossy(&b).into_owned();
        }
        if let Some(b) = mask_bytes(&r.body_bytes, &pats) {
            r.body_bytes = b;
        }
        for (_, v) in r.headers.iter_mut() {
            if let Some(b) = mask_bytes(v.as_bytes(), &pats) {
                *v = String::from_utf8_lossy(&b).into_owned();
            }
        }
        if let Some(e) = r.error.as_mut() {
            if let Some(b) = mask_bytes(e.as_bytes(), &pats) {
                *e = String::from_utf8_lossy(&b).into_owned();
            }
        }
    }

    /// El enmascarado de un texto suelto (un frame de `ws_recv`, el error de un RPC).
    pub fn mask_text(&self, t: &str) -> String {
        if self.sent.is_empty() {
            return t.to_string();
        }
        match mask_bytes(t.as_bytes(), &self.patterns()) {
            Some(b) => String::from_utf8_lossy(&b).into_owned(),
            None => t.to_string(),
        }
    }

    fn patterns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for (name, v) in &self.sent {
            if v.len() < MIN_MASKED {
                note_short_secret(name);
                continue;
            }
            let rep = format!("[secret {}]", name).into_bytes();
            let q = pct(v);
            let f = crate::secrets::form_urlencode(v);
            let mut forms: Vec<String> = vec![v.clone(), lower_pct_hex(&q), lower_pct_hex(&f), q, f];
            if let Ok(j) = serde_json::to_string(v) {
                forms.push(j[1..j.len() - 1].to_string());
            }
            let b64 = synsema_core::bytesutil::b64_encode(v.as_bytes());
            forms.push(b64.trim_end_matches('=').to_string());
            forms.push(b64.replace('+', "-").replace('/', "_").trim_end_matches('=').to_string());
            forms.push(b64);
            for f in forms {
                if f.len() >= MIN_MASKED && !out.iter().any(|(p, _)| p == f.as_bytes()) {
                    out.push((f.into_bytes(), rep.clone()));
                }
            }
        }
        // El más largo primero: una forma que contiene a otra se reemplaza entera.
        out.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        out
    }
}

/// Un secret más corto que esto no se enmascara (sería ruido: GitHub Actions tampoco enmascara
/// valores triviales); la request avisa una vez por stderr.
const MIN_MASKED: usize = 4;

static SHORT_SECRET_NOTICED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cold]
#[inline(never)]
fn note_short_secret(name: &str) {
    if !SHORT_SECRET_NOTICED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!(
            "[synsema] warning: secret({}) is shorter than {} characters, so its echo in a response is not masked",
            name, MIN_MASKED
        );
    }
}

/// `%2F` → `%2f`: el mismo percent-encoding con el hex en minúscula.
fn lower_pct_hex(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push('%');
            out.push((b[i + 1] as char).to_ascii_lowercase());
            out.push((b[i + 2] as char).to_ascii_lowercase());
            i += 3;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// Reemplaza en una pasada cada aparición de un patrón (en cada posición, el más largo que
/// empieza ahí). `None` si no había ninguno.
fn mask_bytes(hay: &[u8], pats: &[(Vec<u8>, Vec<u8>)]) -> Option<Vec<u8>> {
    let mut first = [false; 256];
    for (p, _) in pats {
        first[p[0] as usize] = true;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut changed = false;
    let mut i = 0;
    let mut last = 0;
    while i < hay.len() {
        if first[hay[i] as usize] {
            if let Some((p, r)) = pats.iter().find(|(p, _)| hay[i..].starts_with(p)) {
                out.extend_from_slice(&hay[last..i]);
                out.extend_from_slice(r);
                i += p.len();
                last = i;
                changed = true;
                continue;
            }
        }
        i += 1;
    }
    if !changed {
        return None;
    }
    out.extend_from_slice(&hay[last..]);
    Some(out)
}

/// La URL de una request: un texto, o un secret ATADO cuyo esquema y autoridad están escritos
/// antes del secret (`` `https://h/v2/{key}` ``): el host sale de esa parte pública, nunca del
/// material. Devuelve (la URL pública para el gate y los mensajes, la URL real, el contexto).
pub fn request_url(v: &SynValue, who: &str) -> Result<(String, String, Outgoing), Control> {
    match v {
        SynValue::Secret(s) => {
            let prefix = s.public_prefix().unwrap_or("");
            let closed = prefix
                .split_once("://")
                .map(|(_, rest)| !rest.is_empty() && rest.find(['/', '?', '#']).is_some())
                .unwrap_or(false);
            if s.bound().is_some() && !closed {
                return Err(perr(format!(
                    "{}: the URL is secret({}) and its host is not written out before the secret; write the scheme and host first (`https://host/…{{key}}`): the host of a request never comes from a secret",
                    who,
                    s.name()
                )));
            }
            let public = if closed { format!("{}…", prefix) } else { String::new() };
            let mut out = Outgoing::for_url(&public, who);
            let real = out.admit(s, "the URL", false)?;
            Ok((public, real, out))
        }
        other => {
            let url = raw_str(other);
            let out = Outgoing::for_url(&url, who);
            Ok((url.clone(), url, out))
        }
    }
}

/// Un valor del programa con sus secrets materializados (cada uno pasa por `admit`), para un
/// body JSON: el texto de la clave reemplaza al secret en el mapa o la lista, a cualquier nivel.
fn materialize_body(v: &SynValue, out: &mut Outgoing) -> Result<SynValue, Control> {
    match v {
        SynValue::Secret(s) => Ok(syn_text(out.admit(s, "the body", false)?)),
        SynValue::List(l) if synsema_core::secret::contains_secret(v).is_some() => {
            let items = l.borrow().to_vec();
            let mut xs = Vec::with_capacity(items.len());
            for x in &items {
                xs.push(materialize_body(x, out)?);
            }
            Ok(synsema_core::types::syn_list(xs))
        }
        SynValue::Map(m) if synsema_core::secret::contains_secret(v).is_some() => {
            let mut nm = SynMap::new();
            for (k, x) in m.borrow().iter() {
                nm.insert(k.clone(), materialize_body(x, out)?);
            }
            Ok(syn_map(nm))
        }
        other => Ok(other.clone()),
    }
}

/// Query params → pares, con los secrets atados materializados (`admit`); uno no atado es error
/// con la línea a escribir. Texto, número o bool; `nothing`, bytes, listas y mapas son error (HB4).
pub fn map_pairs_to(v: Option<&SynValue>, out: &mut Outgoing) -> Result<Option<Vec<(String, String)>>, Control> {
    match v {
        Some(SynValue::Map(m)) => {
            let who = out.who.clone();
            let mut pairs = Vec::new();
            for (k, val) in m.borrow().iter() {
                let what = format!("query parameter {:?}", k.to_string());
                let text = match val {
                    SynValue::Secret(s) => out.admit(s, &what, false)?,
                    other => crate::secrets::edge_text(other, &who, &what)?,
                };
                pairs.push((k.to_string(), text));
            }
            Ok(Some(pairs))
        }
        _ => Ok(None),
    }
}

/// Mapa de headers → pares: un secret no atado va como siempre; uno atado, sólo a sus hosts.
pub fn header_pairs_to(v: Option<&SynValue>, out: &mut Outgoing) -> Result<Option<Vec<(String, String)>>, Control> {
    match v {
        Some(SynValue::Map(m)) => {
            let who = out.who.clone();
            let mut pairs = Vec::new();
            for (k, val) in m.borrow().iter() {
                let what = format!("header {:?}", k.to_string());
                let text = match val {
                    SynValue::Secret(s) => out.admit(s, &what, true)?,
                    other => crate::secrets::edge_text(other, &who, &what)?,
                };
                pairs.push((k.to_string(), text));
            }
            Ok(Some(pairs))
        }
        _ => Ok(None),
    }
}

/// El body de una request según su TIPO (v0.6.20): texto tal cual; bytes crudos; un map o una
/// lista → JSON con `Content-Type: application/json` si el caller no puso uno. Un secret atado
/// (suelto, o a cualquier nivel del JSON) se materializa para su host; uno no atado es error.
pub fn body_arg_to(v: Option<&SynValue>, out: &mut Outgoing) -> Result<(Option<Vec<u8>>, Option<&'static str>), Control> {
    Ok(match v {
        None | Some(SynValue::Nothing) => (None, None),
        Some(SynValue::Text(s)) => (Some(s.as_bytes().to_vec()), None),
        Some(SynValue::Bytes(b)) => (Some(b.to_vec()), None),
        Some(SynValue::Secret(s)) => (Some(out.admit(s, "the body", false)?.into_bytes()), None),
        Some(v @ SynValue::Map(_)) | Some(v @ SynValue::List(_)) => {
            let m = materialize_body(v, out)?;
            (Some(dumps_syn(&m).into_bytes()), Some("application/json"))
        }
        Some(other) => (Some(raw_str(other).into_bytes()), None),
    })
}

/// v0.6.46 (E1.5): un body `application/x-www-form-urlencoded` (el de OAuth `client_secret_post`)
/// desde un mapa: texto, número, bool o un secret atado. `nothing`, bytes, listas y mapas son error,
/// como en los headers. El mismo codificador que `oauth_basic` (WHATWG).
pub fn form_body_to(v: &SynValue, out: &mut Outgoing) -> Result<Vec<u8>, Control> {
    let SynValue::Map(m) = v else {
        return Err(perr(format!("{}: form must be a map of fields, got {}", out.who, v.type_name())));
    };
    let who = out.who.clone();
    let mut parts: Vec<String> = Vec::new();
    for (k, val) in m.borrow().iter() {
        let what = format!("form field {:?}", k.to_string());
        let text = match val {
            SynValue::Secret(s) => out.admit(s, &what, false)?,
            other => crate::secrets::edge_text(other, &who, &what)?,
        };
        parts.push(format!(
            "{}={}",
            crate::secrets::form_urlencode(&k.to_string()),
            crate::secrets::form_urlencode(&text)
        ));
    }
    Ok(parts.join("&").into_bytes())
}

/// La forma de mapa de `fetch(url, {method, headers, body, timeout, tls_pin})`: mismos tipos y
/// defaults que la posicional; una clave en `nothing` cuenta como ausente.
struct FetchOpts {
    method: String,
    headers: Option<Vec<(String, String)>>,
    body: (Option<Vec<u8>>, Option<&'static str>),
    timeout: u64,
    tls: Option<TlsCheck>,
}

/// v0.6.45 (A11, decisión V1-C6) — la forma posicional de `fetch` sale en v1: hasta entonces anda,
/// con un aviso por proceso (el `DeprecationWarning` de Python, el `#[deprecated]` de Rust). La regla
/// general: como mucho dos opcionales posicionales; más, un mapa de opciones como último argumento.
static FETCH_POSITIONAL_NOTICED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cold]
#[inline(never)]
fn notice_fetch_positional() {
    if !FETCH_POSITIONAL_NOTICED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!(
            "[synsema] deprecated: fetch(url, method, headers, body, timeout) goes away in v1 — write fetch(url, {{\"method\": …, \"headers\": …, \"body\": …, \"timeout\": …}})"
        );
    }
}

fn fetch_opts(args: &[SynValue], out: &mut Outgoing) -> Result<FetchOpts, Control> {
    let Some(SynValue::Map(m)) = args.get(1) else {
        // Forma posicional (corta): fetch(url, method?, headers?, body?, timeout?).
        if args.len() > 1 {
            notice_fetch_positional();
        }
        return Ok(FetchOpts {
            method: args.get(1).map(raw_str).unwrap_or_else(|| "GET".to_string()),
            headers: header_pairs_to(args.get(2), out)?,
            body: body_arg_to(args.get(3), out)?,
            timeout: timeout_arg(args.get(4)),
            tls: None,
        });
    };
    if args.len() > 2 {
        return Err(perr(format!(
            "fetch(url, opts): the options map is the last argument ({} more given); put method, headers, body and timeout inside it",
            args.len() - 2
        )));
    }
    let m = m.borrow().to_map();
    const VALID: &str = "method, headers, body, form, timeout, tls_pin, attested";
    let mut o = FetchOpts { method: "GET".to_string(), headers: None, body: (None, None), timeout: timeout_arg(None), tls: None };
    let (mut body_seen, mut form_seen) = (false, false);
    for (k, v) in &m {
        if matches!(v, SynValue::Nothing) {
            // `tls_pin`/`attested` en `nothing` (p. ej. `id["public_key_hex"]` que no estaba) NO
            // cuenta como ausente: sería volver en silencio a la validación normal.
            if k == "tls_pin" || k == "attested" {
                return Err(perr(format!("fetch: {} is nothing; pass the value, or leave the key out to use the usual certificate check", k)));
            }
            continue;
        }
        match k.as_str() {
            "method" => o.method = raw_str(v),
            "headers" => o.headers = header_pairs_to(Some(v), out)?,
            "body" => {
                if form_seen {
                    return Err(perr("fetch: pass body or form, not both (form is the body, encoded as a form)".to_string()));
                }
                body_seen = true;
                o.body = body_arg_to(Some(v), out)?
            }
            "form" => {
                if body_seen {
                    return Err(perr("fetch: pass body or form, not both (form is the body, encoded as a form)".to_string()));
                }
                form_seen = true;
                o.body = (Some(form_body_to(v, out)?), Some("application/x-www-form-urlencoded"))
            }
            "timeout" => o.timeout = timeout_arg(Some(v)),
            "tls_pin" | "attested" => {
                if o.tls.is_some() {
                    return Err(perr("fetch: tls_pin and attested are two ways of fixing the server key; pass one".to_string()));
                }
                o.tls = Some(if k == "tls_pin" {
                    TlsCheck::Pin(parse_tls_pin(v, "fetch")?)
                } else {
                    TlsCheck::Attested(crate::attested_client::parse_attested_spec(v, "fetch")?)
                });
            }
            other => return Err(perr(format!("fetch: unknown option {:?} (valid options: {})", other, VALID))),
        }
    }
    Ok(o)
}

pub fn urlencode(q: &[(String, String)]) -> String {
    q.iter()
        .map(|(k, v)| format!("{}={}", pct(k), pct(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// URL + query string (si hay pares). Compartido por los dos transportes.
pub fn url_with_query(url: &str, query: Option<&[(String, String)]>) -> String {
    match query {
        Some(q) if !q.is_empty() => {
            let sep = if url.contains('?') { "&" } else { "?" };
            format!("{}{}{}", url, sep, urlencode(q))
        }
        _ => url.to_string(),
    }
}

pub fn raw_str(v: &SynValue) -> String {
    match v {
        SynValue::Text(s) => s.to_string(),
        SynValue::Number(n) => n.to_string(),
        SynValue::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        SynValue::Nothing => "None".to_string(),
        other => other.to_string(),
    }
}

/// Query params → pares. HB4 (v0.6.44): texto, número o bool; un `secret` es ERROR (iría en la URL,
/// que termina en logs y proxies: va en un header) — antes salía la cadena `secret(NAME)` como si
/// fuera el valor; `nothing`, bytes, listas y mapas también son error (antes, su forma impresa).
pub fn map_pairs(v: Option<&SynValue>, who: &str) -> Result<Option<Vec<(String, String)>>, Control> {
    match v {
        Some(SynValue::Map(m)) => {
            let mut out = Vec::new();
            for (k, val) in m.borrow().iter() {
                if let SynValue::Secret(s) = val {
                    return Err(perr(format!(
                        "{}: query parameter {:?} is secret({}); a secret cannot go into the URL (it ends up in logs and proxies). If the API takes the key in a header, send it there (a secret in a header materializes at the socket); an API that only takes it in the URL has no way to receive a secret yet",
                        who,
                        k.to_string(),
                        s.name()
                    )));
                }
                out.push((k.to_string(), crate::secrets::edge_text(val, who, &format!("query parameter {:?}", k.to_string()))?));
            }
            Ok(Some(out))
        }
        _ => Ok(None),
    }
}

/// Mapa de headers → pares, MATERIALIZANDO secrets (el borde del socket es donde el
/// secret se expone: `{"Authorization": bearer(secret("KEY"))}`).
///
/// HB4 (v0.6.44): cada valor pasa por [`crate::secrets::edge_text`] — un secret sellado o de bytes
/// no UTF-8, `nothing`, bytes, listas o mapas son error en vez de su forma impresa.
pub fn header_pairs(v: Option<&SynValue>, who: &str) -> Result<Option<Vec<(String, String)>>, Control> {
    match v {
        Some(SynValue::Map(m)) => {
            let mut out = Vec::new();
            for (k, val) in m.borrow().iter() {
                // v0.6.46 (E1): sin la request no se sabe adónde va: un secret atado no sale por acá
                // (los builtins de red usan `header_pairs_to`, con el destino).
                if let SynValue::Secret(s) = val {
                    if let Some(b) = s.bound() {
                        return Err(perr(format!(
                            "{}: secret({}) is bound to [{}], and this call cannot check where the header goes",
                            who,
                            s.name(),
                            b.join(", ")
                        )));
                    }
                }
                out.push((k.to_string(), crate::secrets::edge_text(val, who, &format!("header {:?}", k.to_string()))?));
            }
            Ok(Some(out))
        }
        _ => Ok(None),
    }
}

pub fn timeout_arg(v: Option<&SynValue>) -> u64 {
    match v {
        Some(SynValue::Number(n)) => {
            let secs = n.to_f64();
            if secs > 0.0 && secs.is_finite() {
                (secs as u64).max(1)
            } else {
                30
            }
        }
        _ => 30,
    }
}

/// v0.6.20 — el body de una request según su TIPO: texto tal cual; bytes crudos; un map o
/// una lista → JSON, con `Content-Type: application/json` si el caller no puso uno. Antes
/// un map viajaba como su texto de display (`{name: Alice}`) y sin Content-Type: ninguna API
/// lo aceptaba. Un `secret` sigue redactado (fail-closed: el body no es canal de secretos).
pub fn body_arg(v: Option<&SynValue>, who: &str) -> Result<(Option<Vec<u8>>, Option<&'static str>), Control> {
    // HB4 (v0.6.44): un secret en el body (directo o dentro de un map/lista) es ERROR. Antes salía
    // su forma redactada `secret(NAME)` como si fuera el valor: el servidor recibía esa cadena.
    if let Some(name) = v.and_then(synsema_core::secret::contains_secret) {
        return Err(perr(format!(
            "{}: the body contains secret({}); in a body it would travel as the text \"secret({})\", not its value. Send the credential in a header: basic(user, secret) for HTTP Basic (OAuth client credentials accept it), bearer(secret), or the raw secret as a header value; an API that only takes it in the body has no way to receive a secret yet",
            who, name, name
        )));
    }
    Ok(match v {
        None | Some(SynValue::Nothing) => (None, None),
        Some(SynValue::Text(s)) => (Some(s.as_bytes().to_vec()), None),
        Some(SynValue::Bytes(b)) => (Some(b.to_vec()), None),
        Some(v @ SynValue::Map(_)) | Some(v @ SynValue::List(_)) => {
            (Some(dumps_syn(v).into_bytes()), Some("application/json"))
        }
        Some(other) => (Some(raw_str(other).into_bytes()), None),
    })
}

/// v0.6.20 — agrega el `Content-Type` por defecto si el caller no mandó uno (case-insensitive).
pub fn with_default_content_type(
    headers: Option<Vec<(String, String)>>,
    default: Option<&str>,
) -> Option<Vec<(String, String)>> {
    let Some(ct) = default else { return headers };
    let mut h = headers.unwrap_or_default();
    if !h.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
        h.push(("Content-Type".to_string(), ct.to_string()));
    }
    Some(h)
}

fn header_lookup<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// v0.6.20 — `json`: el body parseado cuando el Content-Type dice JSON y parsea; si no,
/// `nothing` (la misma convención que `json of request` en el servidor).
fn parsed_json(headers: &[(String, String)], body: &str) -> SynValue {
    let is_json = header_lookup(headers, "content-type")
        .map(|ct| ct.to_ascii_lowercase().contains("json"))
        .unwrap_or(false);
    if !is_json {
        return syn_nothing();
    }
    // El mismo parser exacto que `json_decode`: un uint256 del body llega entero.
    crate::json_exact::parse(body).unwrap_or_else(|_| syn_nothing())
}

/// v0.6.20 — la respuesta de `http_bytes`: `bytes` exactos en vez de `body` texto.
pub fn response_to_syn_bytes(r: HttpResult) -> SynValue {
    let mut m = SynMap::new();
    m.insert("status", syn_int(r.status));
    m.insert("ok", syn_bool(r.ok));
    m.insert("bytes", syn_bytes(r.body_bytes));
    if !r.headers.is_empty() {
        let mut hm = SynMap::new();
        for (k, v) in r.headers {
            hm.insert(k, syn_text(v));
        }
        m.insert("headers", syn_map(hm));
    }
    if let Some(e) = r.error {
        m.insert("error", syn_text(e));
    }
    syn_map(m)
}

pub fn response_to_syn(r: HttpResult) -> SynValue {
    let mut m = SynMap::new();
    m.insert("status", syn_int(r.status));
    m.insert("ok", syn_bool(r.ok));
    let json = parsed_json(&r.headers, &r.body);
    m.insert("body", syn_text(r.body));
    m.insert("json", json);
    if !r.headers.is_empty() {
        let mut hm = SynMap::new();
        for (k, v) in r.headers {
            hm.insert(k, syn_text(v));
        }
        m.insert("headers", syn_map(hm));
    }
    if let Some(e) = r.error {
        m.insert("error", syn_text(e));
    }
    if let Some(a) = r.attested {
        m.insert("attested", a.to_syn());
    }
    syn_map(m)
}

thread_local! {
    /// v0.6.46 (E1, regla 5): la request en curso lleva un secret. El transporte del perfil wasm lo
    /// pasa al host como `redirect: "error"` (el `fetch` del navegador sigue los redirects por
    /// defecto y sólo quita `Authorization` al cambiar de host); el nativo no sigue redirects.
    static SECRET_IN_REQUEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// ¿La request que está saliendo lleva un secret? (Lo lee el transporte del perfil wasm.)
pub fn request_forbids_redirects() -> bool {
    SECRET_IN_REQUEST.with(|c| c.get()) || rpc_forbids_redirects()
}

thread_local! {
    /// v0.6.46 (E1): el contexto de la llamada de RPC en curso (evm/solana/algod/btc). Esos
    /// builtins no pasan por los builtins cliente: `rpc_url` lo arma desde la URL, los headers lo
    /// usan, y el transporte (`http_request`) lo cierra con el audit y el eco enmascarado. Vive lo
    /// que dura el builtin ([`RpcCall`]).
    static RPC_OUT: RefCell<Option<(Outgoing, bool)>> = const { RefCell::new(None) };
    /// El set de capabilities del builtin de RPC en curso (para su audit), sin retenerlo.
    static RPC_CAPS: RefCell<std::rc::Weak<RefCell<CapabilitySet>>> = RefCell::new(std::rc::Weak::new());
}

/// v0.6.46 (ronda 1, B1): una llamada a un builtin de RPC. Abre el contexto con SU set de
/// capabilities y lo cierra al terminar, también por error. Antes quedaba cargado hasta el próximo
/// RPC: en wasm toda request posterior pedía `redirect: "error"`, y las copias en claro del secret
/// vivían en el hilo.
pub struct RpcCall(#[allow(dead_code)] NetCallerGuard);

impl RpcCall {
    pub fn open(caps: &Rc<RefCell<CapabilitySet>>) -> Self {
        Self::open_for(caps, "rpc")
    }

    /// v0.6.46 (E7): con el nombre del builtin, para el mensaje de una IP privada.
    pub fn open_for(caps: &Rc<RefCell<CapabilitySet>>, who: &str) -> Self {
        RPC_OUT.with(|o| *o.borrow_mut() = None);
        RPC_CAPS.with(|c| *c.borrow_mut() = Rc::downgrade(caps));
        RpcCall(program_request(caps, who, Vec::new()))
    }
}

impl Drop for RpcCall {
    fn drop(&mut self) {
        RPC_OUT.with(|o| *o.borrow_mut() = None);
        RPC_CAPS.with(|c| *c.borrow_mut() = std::rc::Weak::new());
    }
}

// =============================================================================================
// v0.6.46 (E7): una conexión a una IP privada. El cliente nativo resuelve una vez y, antes de
// conectar, pregunta acá por la IP que va a usar. Quién pide la conexión lo dice el contexto del
// hilo: el PROGRAMA (los builtins de red, con su set de capabilities) o el MOTOR (providers de LLM y
// del juez, webhooks de aprobación, `synsema update`: la configuración del host, fuera de la regla).
// Sin contexto se niega una IP privada: un camino del programa que se olvide de abrirlo falla
// cerrado, no abierto.

enum NetCaller {
    Host,
    Program { caps: Rc<RefCell<CapabilitySet>>, who: String, bindings: Vec<String> },
}

thread_local! {
    static NET_CALLER: RefCell<Option<NetCaller>> = const { RefCell::new(None) };
}

/// Restaura el contexto anterior al salir (también por error o pánico).
pub struct NetCallerGuard(Option<NetCaller>);

impl Drop for NetCallerGuard {
    fn drop(&mut self) {
        let prev = self.0.take();
        NET_CALLER.with(|c| *c.borrow_mut() = prev);
    }
}

fn enter_net(caller: NetCaller) -> NetCallerGuard {
    NetCallerGuard(NET_CALLER.with(|c| c.replace(Some(caller))))
}

/// Una request del MOTOR (la configuración del host): no pasa por la regla de E7.
pub fn host_request<T>(f: impl FnOnce() -> T) -> T {
    let _g = enter_net(NetCaller::Host);
    f()
}

/// Una conexión del PROGRAMA mientras viva el guard.
pub fn program_request(caps: &Rc<RefCell<CapabilitySet>>, who: &str, bindings: Vec<String>) -> NetCallerGuard {
    enter_net(NetCaller::Program { caps: caps.clone(), who: who.to_string(), bindings })
}

/// ¿Se puede conectar a `host:port`, que resolvió a `ip`? Lo llama el cliente nativo justo antes de
/// conectar, con la IP que va a usar.
pub fn dest_check(host: &str, port: u16, ip: std::net::IpAddr) -> Result<(), String> {
    if synsema_capabilities::model::is_public_ip(ip) && NET_CALLER.with(|c| !matches!(&*c.borrow(), Some(NetCaller::Program { .. }))) {
        return Ok(());
    }
    NET_CALLER.with(|c| match &*c.borrow() {
        Some(NetCaller::Host) => Ok(()),
        Some(NetCaller::Program { caps, who, bindings }) => {
            let mut all = bindings.clone();
            RPC_OUT.with(|o| {
                if let Some((out, _)) = o.borrow().as_ref() {
                    all.extend(out.bindings().iter().cloned());
                }
            });
            dest_check_with(&caps.borrow(), &all, who, &dest_scope(host, port), ip)
        }
        None => Err(format!(
            "`{}` resolved to {}, a private address, and nothing named it (this connection has no program grants to check)",
            host,
            ip.to_canonical()
        )),
    })
}

/// El destino como lo pide `net`: con el puerto siempre (un grant sin puerto cubre cualquiera).
fn dest_scope(host: &str, port: u16) -> String {
    let h = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    if h.contains(':') {
        format!("[{}]:{}", h, port)
    } else {
        format!("{}:{}", h, port)
    }
}

/// La decisión de E7 contra un set concreto (TCP y WebSocket la llaman con el suyo): las capas de
/// `net` (ver `NetLayers::admits`) y, si salió un secret atado, su atadura.
pub fn dest_check_with(caps: &CapabilitySet, bindings: &[String], who: &str, dest: &str, ip: std::net::IpAddr) -> Result<(), String> {
    use synsema_capabilities::model::{is_public_ip, net_scope_names, private_dest_message};
    caps.net_layers().admits(dest, ip).map_err(|cause| private_dest_message(who, dest, ip, &cause))?;
    if !is_public_ip(ip) && !bindings.is_empty() && !bindings.iter().any(|b| net_scope_names(b, dest, ip)) {
        return Err(format!(
            "{}: `{}` resolved to {}, a private address; a secret bound to [{}] goes there only if the binding names it (the host exactly, its address or its CIDR)",
            who,
            synsema_capabilities::model::split_net_scope(dest).0,
            ip.to_canonical(),
            bindings.join(", ")
        ));
    }
    Ok(())
}

/// v0.6.46 (E1): la URL de un builtin de RPC: texto, o un secret atado con el host escrito antes
/// (`` `https://eth-mainnet.g.alchemy.com/v2/{key}` ``). Devuelve la URL real; el host es el de la
/// parte pública, así que el gate de `net` sobre la real mira el mismo host.
pub fn rpc_url(v: &SynValue, fname: &str) -> Result<String, Control> {
    RPC_OUT.with(|o| *o.borrow_mut() = None);
    match v {
        SynValue::Text(s) => Ok(s.to_string()),
        SynValue::Secret(_) => {
            let (_public, real, out) = request_url(v, fname)?;
            RPC_OUT.with(|o| *o.borrow_mut() = Some((out, false)));
            Ok(real)
        }
        other => Err(perr(format!(
            "{}: the URL must be text (or a secret bound to its host: `require secret(\"K\") for net(\"host\")`), got {}",
            fname,
            other.type_name()
        ))),
    }
}

/// Un secret que va en un header de RPC (el token de algod, el `pass` de `btc_rpc`): no atado,
/// como siempre; atado, sólo al host de `url`.
pub fn rpc_admit_header(s: &synsema_core::secret::SecretInner, url: &str, fname: &str, what: &str) -> Result<String, Control> {
    RPC_OUT.with(|o| {
        let mut b = o.borrow_mut();
        let entry = b.get_or_insert_with(|| (Outgoing::for_url(url, fname), false));
        entry.0.admit(s, what, true)
    })
}

/// Los headers de una llamada de RPC (algod), con cada secret por `rpc_admit_header`.
pub fn rpc_header_pairs(v: Option<&SynValue>, url: &str, fname: &str) -> Result<Option<Vec<(String, String)>>, Control> {
    RPC_OUT.with(|o| {
        let mut b = o.borrow_mut();
        let entry = b.get_or_insert_with(|| (Outgoing::for_url(url, fname), false));
        header_pairs_to(v, &mut entry.0)
    })
}

/// El cierre de una request de RPC: la primera vez, el audit (`secret(K) → host`); siempre, el eco
/// enmascarado (un `evm_wait` hace varias). Sin secrets no hace nada.
pub fn rpc_finish(r: &mut HttpResult) {
    RPC_OUT.with(|o| {
        if let Some((out, audited)) = o.borrow_mut().as_mut() {
            if !out.carries_secrets() {
                return;
            }
            if !*audited {
                if let Some(c) = RPC_CAPS.with(|c| c.borrow().upgrade()) {
                    out.audit(&c);
                }
                *audited = true;
            }
            out.mask(r);
        }
    })
}

/// ¿La llamada de RPC en curso lleva un secret? (Para el transporte wasm.)
fn rpc_forbids_redirects() -> bool {
    RPC_OUT.with(|o| o.borrow().as_ref().is_some_and(|(out, _)| out.forbids_redirects()))
}

/// El enmascarado de un texto con lo que salió en la llamada de RPC en curso (el `message` de un
/// error del nodo).
pub fn rpc_mask_text(t: &str) -> String {
    RPC_OUT.with(|o| match o.borrow().as_ref() {
        Some((out, _)) => out.mask_text(t),
        None => t.to_string(),
    })
}

/// v0.6.46 (E1): manda la request ya armada: el audit de los secrets que salen, la marca para el
/// transporte y el eco enmascarado.
pub fn send(caps: &Rc<RefCell<CapabilitySet>>, out: &Outgoing, f: impl FnOnce() -> HttpResult) -> HttpResult {
    // v0.6.46 (E7): la conexión es del programa: una IP privada se chequea contra sus grants.
    let _net = program_request(caps, &out.who, out.bindings().to_vec());
    if !out.carries_secrets() {
        return f();
    }
    out.audit(caps);
    SECRET_IN_REQUEST.with(|c| c.set(out.forbids_redirects()));
    let mut r = f();
    SECRET_IN_REQUEST.with(|c| c.set(false));
    out.mask(&mut r);
    r
}

/// El body, o un body de formulario (`form = {...}`, E1.5): los dos juntos son error.
fn body_or_form(
    body: Option<&SynValue>,
    form: Option<&SynValue>,
    out: &mut Outgoing,
) -> Result<(Option<Vec<u8>>, Option<&'static str>), Control> {
    match form {
        None | Some(SynValue::Nothing) => body_arg_to(body, out),
        Some(f) => {
            if !matches!(body, None | Some(SynValue::Nothing)) {
                return Err(perr(format!("{}: pass body or form, not both (form is the body, encoded as a form)", out.who)));
            }
            Ok((Some(form_body_to(f, out)?), Some("application/x-www-form-urlencoded")))
        }
    }
}

/// Registra los seis builtins cliente sobre `transport`. Cada uno gatea `net(host)`
/// ANTES de tocar el transporte — misma firma y mismo retorno en los dos perfiles.
///
/// v0.6.45 (B8): con NOMBRES de parámetros (`register_builtin_named`): `http_get(url, timeout = 10)`,
/// `http_post(url, body, headers = {…})`. Un mapa de opciones habría sido ambiguo — el argumento
/// siguiente ya es un mapa (los headers, o un body JSON) —; los argumentos con nombre no (como
/// `requests` de Python, Swift o Kotlin), y la firma queda como dato que `synsema code` puede mostrar.
/// Regla: como mucho dos opcionales por posición; del tercero en adelante, por nombre (`synsema
/// check` avisa; la forma posicional sale en v1).
pub fn register_http_client_builtins(
    interp: &Interpreter,
    caps: Rc<RefCell<CapabilitySet>>,
    transport: Transport,
) {
    // v0.6.46 (E1): cada builtin arma su `Outgoing` desde la URL (texto, o un secret atado con el
    // host escrito antes), y cada secret de la URL, la query, los headers y el body pasa por él.
    // El gate de `net` mira la parte pública. Después: el audit (`secret(K) → host`), la request
    // y el eco enmascarado.

    // http(method, url, headers?, query?, body?, timeout?, form?)
    {
        let caps = caps.clone();
        interp.register_builtin_named(
            "http",
            vec!["method", "url", "headers", "query", "body", "timeout", "form"],
            Rc::new(move |_i, args, _loc| {
                let method = raw_str(args.first().unwrap_or(&SynValue::Nothing));
                let (url, real, mut out) = request_url(args.get(1).unwrap_or(&SynValue::Nothing), "http")?;
                require_net(&caps, &url, "http()")?;
                let query = map_pairs_to(args.get(3), &mut out)?;
                let (body, default_ct) = body_or_form(args.get(4), args.get(6), &mut out)?;
                let headers = with_default_content_type(header_pairs_to(args.get(2), &mut out)?, default_ct);
                let r = send(&caps, &out, || {
                    transport(&method, &real, headers.as_deref(), query.as_deref(), body.as_deref(), timeout_arg(args.get(5)), None)
                });
                Ok(response_to_syn(r))
            }),
        );
    }

    // http_get(url, headers?, query?, timeout?)
    {
        let caps = caps.clone();
        interp.register_builtin_named(
            "http_get",
            vec!["url", "headers", "query", "timeout"],
            Rc::new(move |_i, args, _loc| {
                let (url, real, mut out) = request_url(args.first().unwrap_or(&SynValue::Nothing), "http_get")?;
                require_net(&caps, &url, "http_get()")?;
                let headers = header_pairs_to(args.get(1), &mut out)?;
                let query = map_pairs_to(args.get(2), &mut out)?;
                let r = send(&caps, &out, || {
                    transport("GET", &real, headers.as_deref(), query.as_deref(), None, timeout_arg(args.get(3)), None)
                });
                Ok(response_to_syn(r))
            }),
        );
    }

    // http_post(url, body, headers?, timeout?, form?) — `form = {...}`: body de formulario (E1.5).
    {
        let caps = caps.clone();
        interp.register_builtin_named(
            "http_post",
            vec!["url", "body", "headers", "timeout", "form"],
            Rc::new(move |_i, args, _loc| {
                let (url, real, mut out) = request_url(args.first().unwrap_or(&SynValue::Nothing), "http_post")?;
                require_net(&caps, &url, "http_post()")?;
                let (body, default_ct) = body_or_form(args.get(1), args.get(4), &mut out)?;
                let headers = with_default_content_type(header_pairs_to(args.get(2), &mut out)?, default_ct);
                let r = send(&caps, &out, || {
                    transport("POST", &real, headers.as_deref(), None, body.as_deref(), timeout_arg(args.get(3)), None)
                });
                Ok(response_to_syn(r))
            }),
        );
    }

    // http_put(url, body, headers?, timeout?, form?)
    {
        let caps = caps.clone();
        interp.register_builtin_named(
            "http_put",
            vec!["url", "body", "headers", "timeout", "form"],
            Rc::new(move |_i, args, _loc| {
                let (url, real, mut out) = request_url(args.first().unwrap_or(&SynValue::Nothing), "http_put")?;
                require_net(&caps, &url, "http_put()")?;
                let (body, default_ct) = body_or_form(args.get(1), args.get(4), &mut out)?;
                let headers = with_default_content_type(header_pairs_to(args.get(2), &mut out)?, default_ct);
                let r = send(&caps, &out, || {
                    transport("PUT", &real, headers.as_deref(), None, body.as_deref(), timeout_arg(args.get(3)), None)
                });
                Ok(response_to_syn(r))
            }),
        );
    }

    // http_delete(url, headers?, timeout?)
    {
        let caps = caps.clone();
        interp.register_builtin_named(
            "http_delete",
            vec!["url", "headers", "timeout"],
            Rc::new(move |_i, args, _loc| {
                let (url, real, mut out) = request_url(args.first().unwrap_or(&SynValue::Nothing), "http_delete")?;
                require_net(&caps, &url, "http_delete()")?;
                let headers = header_pairs_to(args.get(1), &mut out)?;
                let r = send(&caps, &out, || {
                    transport("DELETE", &real, headers.as_deref(), None, None, timeout_arg(args.get(2)), None)
                });
                Ok(response_to_syn(r))
            }),
        );
    }

    // fetch(url, {method, headers, body, form, timeout, tls_pin}) — o la forma corta posicional
    // fetch(url, method?, headers?, body?, timeout?). Cliente HTTP real, gateado por net.
    // Default GET; mismo retorno que http_* (response_to_syn). `tls_pin` reemplaza la validación
    // contra las raíces del SO y el nombre por la igualdad exacta de la SPKI del servidor; sin él,
    // nada cambia.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "fetch",
            -1,
            Rc::new(move |_i, args, _loc| {
                let (url, real, mut out) = request_url(args.first().unwrap_or(&SynValue::Nothing), "fetch")?;
                require_net(&caps, &url, "fetch()")?;
                let o = fetch_opts(args, &mut out)?;
                let (body, default_ct) = o.body;
                let headers = with_default_content_type(o.headers, default_ct);
                let r = send(&caps, &out, || {
                    transport(&o.method, &real, headers.as_deref(), None, body.as_deref(), o.timeout, o.tls.as_ref())
                });
                Ok(response_to_syn(r))
            }),
        );
    }
    // v0.6.20 — http_bytes(method, url, headers?, query?, body?, timeout?): la misma request
    // que `http`, con la respuesta en `bytes` exactos en vez de `body` texto (fuentes,
    // imágenes, tarballs: un binario que pasa por texto se corrompe).
    {
        let caps = caps.clone();
        interp.register_builtin_named(
            "http_bytes",
            vec!["method", "url", "headers", "query", "body", "timeout", "form"],
            Rc::new(move |_i, args, _loc| {
                let method = raw_str(args.first().unwrap_or(&SynValue::Nothing));
                let (url, real, mut out) = request_url(args.get(1).unwrap_or(&SynValue::Nothing), "http_bytes")?;
                require_net(&caps, &url, "http_bytes()")?;
                let query = map_pairs_to(args.get(3), &mut out)?;
                let (body, default_ct) = body_or_form(args.get(4), args.get(6), &mut out)?;
                let headers = with_default_content_type(header_pairs_to(args.get(2), &mut out)?, default_ct);
                let r = send(&caps, &out, || {
                    transport(&method, &real, headers.as_deref(), query.as_deref(), body.as_deref(), timeout_arg(args.get(5)), None)
                });
                Ok(response_to_syn_bytes(r))
            }),
        );
    }
    // v0.6.20 — multipart_encode(parts) → {body: bytes, content_type}: puro, sin gate (no toca
    // la red); se manda con `http_post(url, body of m, {"Content-Type": content_type of m})`.
    interp.register_builtin("multipart_encode", 1, Rc::new(|_i, args, _loc| multipart_encode(args)));
}

fn merr(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

/// Valor de un parámetro de `Content-Disposition`: sin comillas, CR ni LF (RFC 7578 §4.2).
fn disposition_value(s: &str) -> String {
    s.replace('"', "%22").replace(['\r', '\n'], "")
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// v0.6.20 — cuerpo `multipart/form-data` (RFC 7578). `parts`: lista de mapas
/// `{name, value}` (un campo) o `{name, filename, bytes, content_type?}` (un archivo).
/// El boundary se deriva de un hash de las partes: puro y determinista (mismas partes →
/// mismos bytes); si por azar apareciera dentro de un dato, se re-deriva con una sal.
pub fn multipart_encode(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "multipart_encode";
    let parts = match args.first() {
        Some(SynValue::List(l)) => l.borrow().to_vec(),
        Some(other) => {
            return Err(merr(format!(
                "{}: parts must be a list of {{name, value}} or {{name, filename, bytes, content_type?}}, got {}",
                F,
                other.type_name()
            )))
        }
        None => return Err(merr(format!("{}(parts) takes the list of parts", F))),
    };
    if parts.is_empty() {
        return Err(merr(format!("{}: parts is empty (a multipart body needs at least one part)", F)));
    }
    let mut encoded: Vec<(String, Vec<u8>)> = Vec::with_capacity(parts.len());
    for (i, p) in parts.iter().enumerate() {
        let SynValue::Map(m) = p else {
            return Err(merr(format!("{}: part {} must be a map, got {}", F, i, p.type_name())));
        };
        let m = m.borrow();
        for k in m.keys() {
            if !matches!(k.as_str(), "name" | "value" | "bytes" | "filename" | "content_type") {
                return Err(merr(format!(
                    "{}: part {} has an unknown key {:?} (valid: name, value, bytes, filename, content_type)",
                    F, i, k
                )));
            }
        }
        let name = match m.get("name") {
            Some(SynValue::Text(s)) if !s.is_empty() => s.to_string(),
            _ => return Err(merr(format!("{}: part {} needs a non-empty text \"name\"", F, i))),
        };
        let text_opt = |k: &str| -> Result<Option<String>, Control> {
            match m.get(k) {
                None | Some(SynValue::Nothing) => Ok(None),
                Some(SynValue::Text(s)) => Ok(Some(s.to_string())),
                Some(other) => Err(merr(format!(
                    "{}: part {} {:?} must be text, got {}",
                    F,
                    i,
                    k,
                    other.type_name()
                ))),
            }
        };
        let filename = text_opt("filename")?;
        let content_type = text_opt("content_type")?;
        let data: Vec<u8> = match (m.get("bytes"), m.get("value")) {
            (Some(SynValue::Bytes(b)), None) => b.to_vec(),
            (Some(other), None) => {
                return Err(merr(format!("{}: part {} \"bytes\" must be bytes, got {}", F, i, other.type_name())))
            }
            (None, Some(SynValue::Secret(_))) => {
                return Err(merr(format!("{}: part {} value is a secret — a form body is not a channel for secrets", F, i)))
            }
            (None, Some(SynValue::Bytes(b))) => b.to_vec(),
            (None, Some(other)) => raw_str(other).into_bytes(),
            (Some(_), Some(_)) => return Err(merr(format!("{}: part {} has both \"bytes\" and \"value\"; pass one", F, i))),
            (None, None) => return Err(merr(format!("{}: part {} needs \"value\" or \"bytes\"", F, i))),
        };
        let mut head = format!("Content-Disposition: form-data; name=\"{}\"", disposition_value(&name));
        if let Some(f) = &filename {
            head.push_str(&format!("; filename=\"{}\"", disposition_value(f)));
        }
        head.push_str("\r\n");
        let ct = content_type.or_else(|| filename.as_ref().map(|_| "application/octet-stream".to_string()));
        if let Some(ct) = ct {
            head.push_str(&format!("Content-Type: {}\r\n", ct));
        }
        encoded.push((head, data));
    }
    let mut seed: Vec<u8> = Vec::new();
    for (h, d) in &encoded {
        seed.extend_from_slice(h.as_bytes());
        seed.extend_from_slice(d);
        seed.push(0);
    }
    let mut salt: u32 = 0;
    let boundary = loop {
        let mut hasher = Sha256::new();
        hasher.update(&seed);
        hasher.update(salt.to_le_bytes());
        let digest = hasher.finalize();
        let hex: String = digest[..16].iter().map(|b| format!("{:02x}", b)).collect();
        let b = format!("----synsema{}", hex);
        let collides = encoded.iter().any(|(h, d)| h.contains(&b) || contains_bytes(d, b.as_bytes()));
        if !collides {
            break b;
        }
        salt = salt.wrapping_add(1);
    };
    let mut body: Vec<u8> = Vec::new();
    for (h, d) in &encoded {
        body.extend_from_slice(format!("--{}\r\n{}\r\n", boundary, h).as_bytes());
        body.extend_from_slice(d);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    let mut out = SynMap::new();
    out.insert("body", syn_bytes(body));
    out.insert(
        "content_type".to_string(),
        syn_text(format!("multipart/form-data; boundary={}", boundary)),
    );
    Ok(syn_map(out))
}

#[cfg(test)]
mod v0620_tests {
    use super::*;
    use synsema_core::types::syn_list;

    fn map(pairs: &[(&str, SynValue)]) -> SynValue {
        let mut m = SynMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v.clone());
        }
        syn_map(m)
    }

    /// §5.1a — el body según su tipo: texto tal cual; map → JSON + Content-Type por defecto;
    /// bytes crudos; un Content-Type del caller gana.
    #[test]
    fn body_by_type_and_default_content_type() {
        let (b, ct) = body_arg(Some(&syn_text("hola")), "t").ok().unwrap();
        assert_eq!(b.as_deref(), Some(&b"hola"[..]));
        assert_eq!(ct, None);
        let m = map(&[("email", syn_text("a@b.c")), ("n", syn_int(1))]);
        let (b, ct) = body_arg(Some(&m), "t").ok().unwrap();
        assert_eq!(String::from_utf8(b.unwrap()).unwrap(), "{\"email\": \"a@b.c\", \"n\": 1}");
        assert_eq!(ct, Some("application/json"));
        let (b, ct) = body_arg(Some(&syn_bytes(vec![0, 255])), "t").ok().unwrap();
        assert_eq!(b, Some(vec![0, 255]));
        assert_eq!(ct, None);
        assert_eq!(body_arg(None, "t").ok().unwrap(), (None, None));
        let h = with_default_content_type(None, Some("application/json")).unwrap();
        assert_eq!(h, vec![("Content-Type".to_string(), "application/json".to_string())]);
        let mine = vec![("content-type".to_string(), "text/plain".to_string())];
        let h = with_default_content_type(Some(mine.clone()), Some("application/json")).unwrap();
        assert_eq!(h, mine, "el Content-Type del caller gana");
    }

    /// §5.1b — `json` parseado sólo con Content-Type JSON; `error` sólo si falló el transporte.
    #[test]
    fn response_has_json_key_and_conditional_error() {
        let r = HttpResult {
            status: 200,
            ok: true,
            body: "{\"a\": [1, 2]}".to_string(),
            body_bytes: b"{\"a\": [1, 2]}".to_vec(),
            headers: vec![("Content-Type".to_string(), "application/json; charset=utf-8".to_string())],
            error: None,
            attested: None,
        };
        let v = response_to_syn(r);
        let SynValue::Map(m) = &v else { panic!() };
        let keys: Vec<String> = m.borrow().keys().map(|k| k.to_string()).collect();
        assert_eq!(keys, vec!["status", "ok", "body", "json", "headers"]);
        assert_eq!(m.borrow().get("json").unwrap().to_string(), "{a: [1, 2]}");
        let r = HttpResult {
            status: 200,
            ok: true,
            body: "plain".to_string(),
            body_bytes: b"plain".to_vec(),
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            error: None,
            attested: None,
        };
        let SynValue::Map(m) = response_to_syn(r) else { panic!() };
        assert!(matches!(m.borrow().get("json"), Some(SynValue::Nothing)));
        let SynValue::Map(m) = response_to_syn(err_result("connection refused".into())) else { panic!() };
        assert_eq!(m.borrow().get("error").unwrap().to_string(), "connection refused");
        assert_eq!(m.borrow().get("status").unwrap().to_string(), "0");
    }

    /// §5.1c — `http_bytes` devuelve los bytes exactos.
    #[test]
    fn bytes_response_is_exact() {
        let r = HttpResult {
            status: 200,
            ok: true,
            body: String::from_utf8_lossy(&[0xff, 0x00, 0x89]).to_string(),
            body_bytes: vec![0xff, 0x00, 0x89],
            headers: Vec::new(),
            error: None,
            attested: None,
        };
        let SynValue::Map(m) = response_to_syn_bytes(r) else { panic!() };
        assert!(matches!(m.borrow().get("bytes"), Some(SynValue::Bytes(b)) if b.to_vec() == vec![0xff, 0x00, 0x89]));
        assert!(m.borrow().get("body").is_none());
    }

    /// §5.1d — multipart: determinista, con el formato RFC 7578, y el parser del servidor lo lee.
    #[test]
    fn multipart_round_trips_through_the_server_parser() {
        let parts = syn_list(vec![
            map(&[("name", syn_text("title")), ("value", syn_text("hola \"mundo\""))]),
            map(&[
                ("name", syn_text("file")),
                ("filename", syn_text("a.bin")),
                ("content_type", syn_text("application/octet-stream")),
                ("bytes", syn_bytes(vec![1, 2, 3, 13, 10, 45, 45])),
            ]),
        ]);
        let SynValue::Map(m1) = multipart_encode(&[parts.clone()]).ok().unwrap() else { panic!() };
        let SynValue::Map(m2) = multipart_encode(&[parts]).ok().unwrap() else { panic!() };
        let body = match m1.borrow().get("body") { Some(SynValue::Bytes(b)) => b.to_vec(), _ => panic!() };
        let body2 = match m2.borrow().get("body") { Some(SynValue::Bytes(b)) => b.to_vec(), _ => panic!() };
        assert_eq!(body, body2, "determinista");
        let ct = m1.borrow().get("content_type").unwrap().to_string();
        let boundary = crate::routing::multipart_boundary(&ct).expect("boundary");
        let parsed = crate::routing::parse_multipart(&boundary, &body);
        assert_eq!(parsed.len(), 2, "{:?}", String::from_utf8_lossy(&body));
        let e = multipart_encode(&[syn_list(vec![map(&[("name", syn_text("x"))])])]);
        assert!(matches!(e, Err(_)), "una parte sin value ni bytes es error");
    }
}

#[cfg(test)]
mod v0646_r1_tests {
    use super::*;

    /// v0.6.46 (ronda 1, M1): un secret en un header también pide que no se sigan redirects (el
    /// `fetch` sólo quita `Authorization` al cambiar de host). B1: el contexto de un RPC se cierra
    /// al terminar la llamada; después, una request sin secrets sigue redirects.
    #[test]
    fn a_secret_in_a_header_forbids_redirects_and_the_rpc_context_closes() {
        let s = synsema_core::secret::SecretInner::new("K", "valor");
        let mut out = Outgoing::for_url("https://api.example.com/x", "http_get");
        assert!(!out.forbids_redirects());
        assert!(out.admit(&s, "header \"X-Api-Key\"", true).is_ok());
        assert!(out.forbids_redirects());
        let caps = Rc::new(RefCell::new(CapabilitySet::new("t")));
        {
            let _call = RpcCall::open(&caps);
            RPC_OUT.with(|o| *o.borrow_mut() = Some((out, false)));
            assert!(request_forbids_redirects());
        }
        assert!(!request_forbids_redirects());
        assert!(RPC_CAPS.with(|c| c.borrow().upgrade().is_none()));
    }
}

#[cfg(test)]
mod v0646_e7_tests {
    use super::*;

    fn net(s: Option<&str>) -> Capability {
        Capability::new(CapabilityType::Net, s.map(str::to_string))
    }

    /// Un secret atado con glob no va a una IP privada aunque `net` nombre el host: la atadura
    /// también la tiene que nombrar.
    #[test]
    fn a_glob_binding_does_not_reach_a_private_address() {
        let mut caps = CapabilitySet::new("t");
        caps.grant(net(Some("a.x.com")));
        let ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let e = dest_check_with(&caps, &["*.x.com".to_string()], "http_get()", "a.x.com:443", ip).unwrap_err();
        assert!(e.contains("a secret bound to [*.x.com]"), "{}", e);
        assert!(dest_check_with(&caps, &["a.x.com".to_string()], "http_get()", "a.x.com:443", ip).is_ok());
        let public: std::net::IpAddr = "93.184.216.34".parse().unwrap();
        assert!(dest_check_with(&caps, &["*.x.com".to_string()], "http_get()", "a.x.com:443", public).is_ok());
    }

    /// Sin contexto, una IP privada se niega (un camino del programa sin contexto falla cerrado);
    /// el motor (`host_request`) llega; el programa, según sus grants.
    #[test]
    fn the_caller_context_decides() {
        let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert!(dest_check("localhost", 11434, lo).unwrap_err().contains("nothing named it"));
        assert!(dest_check("api.x.com", 443, "93.184.216.34".parse().unwrap()).is_ok());
        assert!(host_request(|| dest_check("localhost", 11434, lo)).is_ok());
        let caps = Rc::new(RefCell::new(CapabilitySet::new("t")));
        caps.borrow_mut().grant(net(None));
        {
            let _p = program_request(&caps, "http_get()", Vec::new());
            assert!(dest_check("localhost", 11434, lo).unwrap_err().contains("require net(\"localhost:11434\")"));
            // El motor adentro de una llamada del programa, y al salir vuelve el del programa.
            assert!(host_request(|| dest_check("localhost", 11434, lo)).is_ok());
            assert!(dest_check("localhost", 11434, lo).is_err());
        }
        caps.borrow_mut().grant(net(Some("localhost")));
        let _p = program_request(&caps, "http_get()", Vec::new());
        assert!(dest_check("localhost", 11434, lo).is_ok());
    }
}

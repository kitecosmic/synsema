//! Feature `secret` / `env` / `.env` — config por entorno y secretos a prueba de LLMs.
//!
//! Builtins (todos siguen el idiom de `secure.rs`/`database.rs`):
//!   - `env(name, default?)`    → texto plano. Capability `env(name)`.
//!   - `secret(name, default?)` → `secret` opaco. Capability `secret(name)`.
//!   - `reveal(s)`              → plaintext. Capability `reveal` + audit persistente.
//!   - `bearer(s)`             → `secret` "Bearer <s>" (header de auth tainted).
//!   - `hmac_sha256(data, s)`  → hex (la MAC, NO secreta).
//!   - `verify_hmac(data, sig, s, algo?)` → bool, constant-time (SHA-256/512).
//!   - `constant_time_eq(a, b)` → bool, constant-time (acepta secret en cualquier lado).
//!
//! Resolución de `env`/`secret` (§2): environ del proceso > `.env` del cwd > default.
//! Ausencia total → error claro (fail-loud), nunca `nothing` silencioso.
//!
//! Crypto puro-Rust (RustCrypto), sin deps C → preserva el binario único.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::secret::constant_time_eq;
use synsema_core::tokens::SourceLocation;
use synsema_core::types::{syn_bool, syn_bytes, syn_secret, syn_secret_bytes, syn_text, SynValue};

// =========================================================
// EnvStore — el `.env` parseado (la fuente; environ se lee en vivo)
// =========================================================

/// Variables provenientes del archivo `.env`. El environ del proceso NO vive acá:
/// se lee con `std::env::var` en cada resolución (precedencia §2.1, gana siempre).
#[derive(Default)]
pub struct EnvStore {
    vars: HashMap<String, String>,
}

impl EnvStore {
    pub fn empty() -> Self {
        Self { vars: HashMap::new() }
    }

    pub fn get(&self, name: &str) -> Option<String> {
        self.vars.get(name).cloned()
    }

    /// Carga el `.env` según el spec §2:
    /// - `SYNSEMA_ENV_FILE=<path>` → ese archivo.
    /// - `SYNSEMA_ENV_FILE=` (vacío) → desactivado (≡ `--no-env-file`).
    /// - sin la var → `./.env` si existe; si no, vacío (clonar y correr sin setup).
    pub fn load_default() -> Self {
        match std::env::var("SYNSEMA_ENV_FILE") {
            Ok(p) if p.is_empty() => EnvStore::empty(),
            Ok(p) => EnvStore::from_file(&p),
            Err(_) => {
                if std::path::Path::new(".env").exists() {
                    EnvStore::from_file(".env")
                } else {
                    EnvStore::empty()
                }
            }
        }
    }

    /// Lee y parsea un archivo `.env`. Si no se puede leer → warning a stderr (no
    /// crashea: el programa puede igual resolver desde el environ o defaults).
    pub fn from_file(path: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(c) => EnvStore::parse(&c),
            Err(e) => {
                eprintln!("synsema: warning: cannot read env file '{}': {}", path, e);
                EnvStore::empty()
            }
        }
    }

    /// Parsea contenido dotenv minimalista: `KEY=VALUE` por línea; `#` comentario
    /// (línea completa o tras el valor precedido de espacio); comillas opcionales
    /// (`"..."`/`'...'`) sin interpolación; líneas en blanco ignoradas; claves
    /// inválidas → warning (no crash).
    pub fn parse(content: &str) -> Self {
        let mut vars = HashMap::new();
        for (i, raw) in content.lines().enumerate() {
            let line = raw.trim_start();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let eq = match line.find('=') {
                Some(p) => p,
                None => {
                    eprintln!("synsema: warning: ignoring malformed .env line {}: no '='", i + 1);
                    continue;
                }
            };
            let key = line[..eq].trim();
            if !is_valid_key(key) {
                eprintln!("synsema: warning: ignoring invalid .env key on line {}: '{}'", i + 1, key);
                continue;
            }
            let value = parse_value(&line[eq + 1..]);
            vars.insert(key.to_string(), value);
        }
        Self { vars }
    }
}

/// Nombre de variable válido: empieza con letra/`_`, luego alfanumérico/`_`.
fn is_valid_key(k: &str) -> bool {
    let mut cs = k.chars();
    match cs.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    cs.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parsea el lado derecho de `KEY=`: comillas opcionales o valor crudo con comentario
/// `#` final (sólo si va precedido de espacio). Sin interpolación de variables.
fn parse_value(rhs: &str) -> String {
    let s = rhs.trim_start();
    let bytes = s.as_bytes();
    if let Some(&q) = bytes.first() {
        if q == b'"' || q == b'\'' {
            let quote = q as char;
            if let Some(close) = s[1..].find(quote) {
                return s[1..1 + close].to_string();
            }
            // Sin comilla de cierre: literal del resto (tolerante, no crashea).
            return s[1..].trim().to_string();
        }
    }
    // Sin comillas: cortar en el primer `#` precedido de espacio/tab.
    let mut cut = s.len();
    let mut prev_ws = false;
    for (idx, c) in s.char_indices() {
        if c == '#' && prev_ws {
            cut = idx;
            break;
        }
        prev_ws = c == ' ' || c == '\t';
    }
    s[..cut].trim_end().to_string()
}

// =========================================================
// Helpers de builtins
// =========================================================

fn arg(args: &[SynValue], i: usize) -> Result<&SynValue, Control> {
    args.get(i).ok_or_else(|| Control::Error(RuntimeError::new("missing argument")))
}

/// `str(value.raw)` estilo Python (un secret → su Display redactado).
fn raw_str(v: &SynValue) -> String {
    match v {
        SynValue::Text(s) => s.to_string(),
        SynValue::Number(n) => n.to_string(),
        SynValue::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        SynValue::Nothing => "None".to_string(),
        other => other.to_string(),
    }
}

/// Bytes para crypto: un secret aporta su plaintext (uso interno; la salida es una
/// MAC/bool, no filtra). Texto → sus bytes; resto → su Display.
fn crypto_bytes(v: &SynValue) -> Vec<u8> {
    match v {
        SynValue::Secret(s) => s.expose_bytes().to_vec(),
        SynValue::Text(s) => s.as_bytes().to_vec(),
        other => other.to_string().into_bytes(),
    }
}

/// Resuelve una variable: environ del proceso > `.env` > default (§2). `None` si
/// ninguna fuente la define.
fn resolve(env: &EnvStore, name: &str, default: Option<&SynValue>) -> Option<String> {
    // El environ gana siempre (incluso seteado vacío: systemd `Environment=X=`).
    if let Ok(v) = std::env::var(name) {
        return Some(v);
    }
    if let Some(v) = env.get(name) {
        return Some(v);
    }
    default.map(raw_str)
}

/// Error de capability faltante que **sugiere el fix** (§1/§3), incl. el prefijo.
fn cap_denied(kind: &str, name: &str) -> Control {
    let prefix_hint = name
        .split_once('_')
        .map(|(p, _)| format!(" (or a prefix: `require {}(\"{}_*\")`)", kind, p))
        .unwrap_or_default();
    Control::Error(RuntimeError::new(format!(
        "{kind}(\"{name}\") not permitted: missing capability — add `require {kind}(\"{name}\")`{prefix_hint}"
    )))
}

/// Denegación de `reveal` SCOPED por nombre/label (§6.5): el mensaje nombra el secret
/// concreto y sugiere el `require reveal("NAME")` exacto. Mantiene el substring
/// `reveal() not permitted` (contrato de error histórico) y aporta `Capability not
/// granted: reveal("NAME")` para el scope.
fn reveal_denied(name: &str) -> Control {
    Control::Error(RuntimeError::new(format!(
        "reveal() not permitted: Capability not granted: reveal(\"{name}\") — \
         add `require reveal(\"{name}\")` (reveal is loud and writes a persistent audit entry)"
    )))
}

fn undefined_var(kind: &str, name: &str) -> Control {
    Control::Error(RuntimeError::new(format!(
        "{kind}(\"{name}\"): variable not defined (not in the process environ, .env, or a default)"
    )))
}

fn check_cap(caps: &Rc<RefCell<CapabilitySet>>, cap: Capability) -> bool {
    caps.borrow_mut().check(&cap, "secret-builtin")
}

// =========================================================
// Crypto (HMAC-SHA256/512, hex/base64, constant-time)
// =========================================================

#[derive(Clone, Copy)]
enum Algo {
    Sha256,
    Sha512,
}

impl Algo {
    fn mac_len(self) -> usize {
        match self {
            Algo::Sha256 => 32,
            Algo::Sha512 => 64,
        }
    }
}

/// Algoritmo soportado. SHA-1 se rechaza a propósito (débil, §4).
fn parse_algo(s: &str) -> Result<Algo, Control> {
    match s.trim().to_lowercase().as_str() {
        "" | "sha256" => Ok(Algo::Sha256),
        "sha512" => Ok(Algo::Sha512),
        "sha1" => Err(Control::Error(RuntimeError::new(
            "verify_hmac: SHA-1 is not supported (weak); use sha256 or sha512",
        ))),
        other => Err(Control::Error(RuntimeError::new(format!(
            "verify_hmac: unknown algorithm '{}' (use sha256 or sha512)",
            other
        )))),
    }
}

fn hmac_compute(algo: Algo, key: &[u8], data: &[u8]) -> Vec<u8> {
    match algo {
        Algo::Sha256 => {
            // HMAC acepta cualquier longitud de clave → new_from_slice no falla.
            let mut m = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC takes any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        Algo::Sha512 => {
            let mut m = <Hmac<Sha512>>::new_from_slice(key).expect("HMAC takes any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
    }
}

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        out.push((hexval(bytes[i])? << 4) | hexval(bytes[i + 1])?);
        i += 2;
    }
    Some(out)
}

/// base64 estándar (alfabeto `A-Za-z0-9+/`), padding `=` opcional. Hand-rolled para
/// no sumar una dep (decodificar la firma entrante no es sensible: la seguridad está
/// en la comparación constant-time).
fn from_base64(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for &c in s.trim().as_bytes() {
        match c {
            b'=' => break,
            b'\n' | b'\r' | b' ' => continue,
            _ => {
                let v = val(c)? as u32;
                bits = (bits << 6) | v;
                nbits += 6;
                if nbits >= 8 {
                    nbits -= 8;
                    out.push((bits >> nbits) as u8);
                }
            }
        }
    }
    Some(out)
}

/// Decodifica la firma entrante de forma robusta: quita un prefijo `sha256=`/`sha512=`
/// (estilo GitHub), prueba hex (Stripe/GitHub) y base64 (Shopify), prefiriendo la
/// decodificación cuya longitud coincide con la MAC.
fn decode_signature(sig: &str, mac_len: usize) -> Option<Vec<u8>> {
    let s = sig.trim();
    let s = s
        .strip_prefix("sha256=")
        .or_else(|| s.strip_prefix("sha512="))
        .unwrap_or(s);
    let hex = from_hex(s);
    if let Some(h) = &hex {
        if h.len() == mac_len {
            return hex;
        }
    }
    let b64 = from_base64(s);
    if let Some(b) = &b64 {
        if b.len() == mac_len {
            return b64;
        }
    }
    hex.or(b64)
}

// =========================================================
// Audit de reveal() — append-only, fail-loud (§7)
// =========================================================

/// Directorio del audit: `$SYNSEMA_AUDIT_DIR` o `~/.synsema/audit`.
fn audit_dir() -> Result<PathBuf, String> {
    if let Ok(d) = std::env::var("SYNSEMA_AUDIT_DIR") {
        if !d.is_empty() {
            return Ok(PathBuf::from(d));
        }
    }
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
        .ok_or_else(|| "no home directory (set SYNSEMA_AUDIT_DIR)".to_string())?;
    Ok(PathBuf::from(home).join(".synsema").join("audit"))
}

fn iso_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    match chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, d.subsec_nanos()) {
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        None => d.as_secs().to_string(),
    }
}

/// Escribe una entrada de audit (append-only). **Nunca** el valor revelado: sólo
/// timestamp, resultado (concedido/denegado), nombre de la var, `file:line` y nombre
/// del programa. Se audita TODO intento de `reveal` — concedido O denegado (§6.5c) —
/// para que una redirección de variable hacia un secret fuera de scope quede registrada.
/// Devuelve Err si no se puede escribir → en el camino CONCEDIDO `reveal()` falla (sin
/// auditoría no hay revelación, §7).
fn write_audit_entry(name: &str, loc: &SourceLocation, granted: bool) -> Result<(), String> {
    let dir = audit_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("reveal.log");
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    let program = std::path::Path::new(&loc.file)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| loc.file.clone());
    let result = if granted { "granted" } else { "denied" };
    let line = format!(
        "{} reveal result={} name={} at={}:{} program={}\n",
        iso_now(),
        result,
        name,
        loc.file,
        loc.line,
        program
    );
    f.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    Ok(())
}

// =========================================================
// Registro de builtins
// =========================================================

/// Registra los builtins de secretos/env, compartiendo el `CapabilitySet` y el
/// `EnvStore` cargado del `.env`.
pub fn register_secret_builtins(
    interp: &Interpreter,
    caps: Rc<RefCell<CapabilitySet>>,
    env: Rc<EnvStore>,
) {
    // env(name, default?) → texto plano. Requiere env(name).
    {
        let caps = caps.clone();
        let env = env.clone();
        interp.register_builtin(
            "env",
            -1,
            Rc::new(move |_i, args, _loc| {
                let name = raw_str(arg(args, 0)?);
                if !check_cap(&caps, Capability::new(CapabilityType::Env, Some(name.clone()))) {
                    return Err(cap_denied("env", &name));
                }
                match resolve(&env, &name, args.get(1)) {
                    Some(v) => Ok(syn_text(v)),
                    None => Err(undefined_var("env", &name)),
                }
            }),
        );
    }

    // secret(name, default?) → secret opaco. Requiere secret(name).
    {
        let caps = caps.clone();
        let env = env.clone();
        interp.register_builtin(
            "secret",
            -1,
            Rc::new(move |_i, args, _loc| {
                let name = raw_str(arg(args, 0)?);
                if !check_cap(&caps, Capability::new(CapabilityType::Secret, Some(name.clone()))) {
                    return Err(cap_denied("secret", &name));
                }
                match resolve(&env, &name, args.get(1)) {
                    Some(v) => Ok(syn_secret(name, v)),
                    None => Err(undefined_var("secret", &name)),
                }
            }),
        );
    }

    // reveal(s) → plaintext. SCOPED por nombre/label (§6.5): exige `reveal("<name>")`
    // donde <name> es el name/label del secret pasado — NO un `reveal` grueso. Audita
    // TODO intento (concedido o denegado); en el camino concedido, sin auditoría no hay
    // revelación (fail-loud). Un secret de bytes se revela como `bytes`; uno de texto
    // como `text`.
    {
        let caps = caps.clone();
        interp.register_builtin(
            "reveal",
            1,
            Rc::new(move |_i, args, loc| {
                let inner = match arg(args, 0)? {
                    SynValue::Secret(inner) => inner,
                    other => {
                        return Err(Control::Error(RuntimeError::new(format!(
                            "reveal() expects a secret, got {}",
                            other.type_name()
                        ))))
                    }
                };
                let name = inner.name().to_string();
                // El chequeo evalúa el name del secret QUE SE PASA: redirigir la variable
                // a otro secret pasa a revelar ESE (con su propio name) y vuelve a chequear.
                let granted =
                    check_cap(&caps, Capability::new(CapabilityType::Reveal, Some(name.clone())));
                if !granted {
                    // Auditar el intento DENEGADO (best-effort: ya se rechaza igual).
                    let _ = write_audit_entry(&name, loc, false);
                    return Err(reveal_denied(&name));
                }
                // Concedido: sin auditoría no hay revelación (§7).
                write_audit_entry(&name, loc, true).map_err(|e| {
                    Control::Error(RuntimeError::new(format!(
                        "reveal(\"{}\") failed: cannot write the audit log ({}). \
                         Refusing to reveal without an audit trail.",
                        name, e
                    )))
                })?;
                if inner.is_bytes() {
                    Ok(syn_bytes(inner.expose_bytes().to_vec()))
                } else {
                    Ok(syn_text(inner.expose().into_owned()))
                }
            }),
        );
    }

    // as_secret(value, label?) → sella un valor de runtime YA en mano como `secret`
    // (taint en el punto de entrada). PURO y sin `require`: no hace I/O y sólo FORTALECE
    // (no hay acceso nuevo que gatear). Idempotente sobre un secret. Acepta text/bytes;
    // otros tipos → error claro (sellá el campo sensible, no la estructura). Label NO
    // sensible para la redacción `secret(<label>)`; default `sealed`.
    interp.register_builtin(
        "as_secret",
        -1,
        Rc::new(move |_i, args, _loc| {
            let v = arg(args, 0)?;
            // Idempotente: un secret se devuelve tal cual (no re-anida, no cambia label).
            if matches!(v, SynValue::Secret(_)) {
                return Ok(v.clone());
            }
            let label = match args.get(1) {
                None | Some(SynValue::Nothing) => "sealed".to_string(),
                Some(l) => raw_str(l),
            };
            match v {
                SynValue::Text(s) => Ok(syn_secret(label, s.to_string())),
                SynValue::Bytes(b) => Ok(syn_secret_bytes(label, b.to_vec())),
                other => Err(Control::Error(RuntimeError::new(format!(
                    "as_secret() expects text or bytes, got {} — seal the sensitive field, \
                     not the whole structure",
                    other.type_name()
                )))),
            }
        }),
    );

    // bearer(s) → secret "Bearer <s>". Produce SIEMPRE un secret (tainted), aunque el
    // input sea texto plano: el header Authorization queda redactado en toda salida.
    interp.register_builtin(
        "bearer",
        1,
        Rc::new(move |_i, args, _loc| {
            let (name, plaintext) = match arg(args, 0)? {
                SynValue::Secret(s) => (s.name().to_string(), format!("Bearer {}", s.expose())),
                other => ("bearer".to_string(), format!("Bearer {}", raw_str(other))),
            };
            Ok(syn_secret(name, plaintext))
        }),
    );

    // hmac_sha256(data, s) → hex (la MAC, no es secreta).
    interp.register_builtin(
        "hmac_sha256",
        2,
        Rc::new(move |_i, args, _loc| {
            let data = crypto_bytes(arg(args, 0)?);
            let key = crypto_bytes(arg(args, 1)?);
            Ok(syn_text(to_hex(&hmac_compute(Algo::Sha256, &key, &data))))
        }),
    );

    // verify_hmac(data, signature, s, algo?) → bool, constant-time.
    interp.register_builtin(
        "verify_hmac",
        -1,
        Rc::new(move |_i, args, _loc| {
            let data = crypto_bytes(arg(args, 0)?);
            let signature = raw_str(arg(args, 1)?);
            let key = crypto_bytes(arg(args, 2)?);
            let algo = match args.get(3) {
                Some(v) => parse_algo(&raw_str(v))?,
                None => Algo::Sha256,
            };
            let mac = hmac_compute(algo, &key, &data);
            let provided = match decode_signature(&signature, algo.mac_len()) {
                Some(b) => b,
                None => return Ok(syn_bool(false)),
            };
            Ok(syn_bool(constant_time_eq(&mac, &provided)))
        }),
    );

    // constant_time_eq(a, b) → bool, constant-time. Acepta secret en cualquier lado.
    interp.register_builtin(
        "constant_time_eq",
        2,
        Rc::new(move |_i, args, _loc| {
            let a = crypto_bytes(arg(args, 0)?);
            let b = crypto_bytes(arg(args, 1)?);
            Ok(syn_bool(constant_time_eq(&a, &b)))
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serializa los tests que tocan env-vars del proceso (SYNSEMA_ENV_FILE/AUDIT_DIR y
    // las vars de precedencia) para que no se pisen entre sí.
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn unique() -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        format!("{}_{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed))
    }

    #[test]
    fn resolve_precedence_environ_dotenv_default_none() {
        let _g = lock();
        let key = "SYN_TEST_PREC_VAR";
        let store = EnvStore::parse(&format!("{}=from_dotenv", key));
        // 1) environ del proceso gana siempre.
        std::env::set_var(key, "from_environ");
        assert_eq!(resolve(&store, key, None).as_deref(), Some("from_environ"));
        // 2) sin environ → .env gana sobre el default.
        std::env::remove_var(key);
        let def = syn_text("from_default");
        assert_eq!(resolve(&store, key, Some(&def)).as_deref(), Some("from_dotenv"));
        // 3) sin environ ni .env → default.
        let empty = EnvStore::empty();
        assert_eq!(resolve(&empty, key, Some(&def)).as_deref(), Some("from_default"));
        // 4) ninguna fuente → None (el builtin lo vuelve error fail-loud).
        assert_eq!(resolve(&empty, key, None), None);
    }

    #[test]
    fn load_default_uses_env_file_and_disables_on_empty() {
        let _g = lock();
        let dir = std::env::temp_dir().join(format!("syn_env_{}", unique()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("custom.env");
        std::fs::write(&path, "FROM_FILE=yes\n").unwrap();

        std::env::set_var("SYNSEMA_ENV_FILE", &path);
        assert_eq!(EnvStore::load_default().get("FROM_FILE").as_deref(), Some("yes"));

        // --no-env-file ≡ SYNSEMA_ENV_FILE vacío → desactivado.
        std::env::set_var("SYNSEMA_ENV_FILE", "");
        assert_eq!(EnvStore::load_default().get("FROM_FILE"), None);

        std::env::remove_var("SYNSEMA_ENV_FILE");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_writes_name_not_value_appends_and_fails_when_unwritable() {
        let _g = lock();
        use synsema_core::tokens::SourceLocation;
        let loc = SourceLocation { file: "app.syn".to_string(), line: 7, column: 0, offset: 0 };

        // Dir escribible: entrada con nombre + file:line + programa. (No hay valor que
        // escribir: write_audit_entry no recibe el plaintext — garantía estructural.)
        let dir = std::env::temp_dir().join(format!("syn_audit_{}", unique()));
        std::env::set_var("SYNSEMA_AUDIT_DIR", &dir);
        write_audit_entry("STRIPE_KEY", &loc, true).expect("audit should write");
        let log = std::fs::read_to_string(dir.join("reveal.log")).unwrap();
        assert!(log.contains("name=STRIPE_KEY"), "log: {}", log);
        assert!(log.contains("result=granted"), "log: {}", log);
        assert!(log.contains("app.syn:7"), "log: {}", log);
        assert!(log.contains("program=app"), "log: {}", log);
        // Un intento DENEGADO también se audita (con result=denied).
        write_audit_entry("ADMIN_KEY", &loc, false).unwrap();
        let logd = std::fs::read_to_string(dir.join("reveal.log")).unwrap();
        assert!(logd.contains("result=denied name=ADMIN_KEY"), "log: {}", logd);
        // Append-only: una segunda entrada se agrega (no sobreescribe).
        write_audit_entry("STRIPE_KEY", &loc, true).unwrap();
        let log2 = std::fs::read_to_string(dir.join("reveal.log")).unwrap();
        assert_eq!(log2.matches("name=STRIPE_KEY").count(), 2);
        let _ = std::fs::remove_dir_all(&dir);

        // Audit no escribible (padre es un archivo) → Err → reveal() fallará (fail-loud).
        let file_path = std::env::temp_dir().join(format!("syn_audit_file_{}", unique()));
        std::fs::write(&file_path, "x").unwrap();
        std::env::set_var("SYNSEMA_AUDIT_DIR", file_path.join("sub"));
        assert!(write_audit_entry("X", &loc, true).is_err());
        let _ = std::fs::remove_file(&file_path);
        std::env::remove_var("SYNSEMA_AUDIT_DIR");
    }

    #[test]
    fn hmac_sha512_supported_and_sha1_rejected() {
        // sha512 produce 64 bytes.
        let mac = hmac_compute(Algo::Sha512, b"key", b"data");
        assert_eq!(mac.len(), 64);
        assert!(parse_algo("sha512").is_ok());
        assert!(parse_algo("sha256").is_ok());
        assert!(parse_algo("").is_ok());
        assert!(parse_algo("sha1").is_err()); // débil, rechazado a propósito (§4)
        assert!(parse_algo("md5").is_err());
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab")); // longitudes distintas → false
    }

    #[test]
    fn env_parse_basic() {
        let s = EnvStore::parse("PORT=8080\nDB=postgres://x\n");
        assert_eq!(s.get("PORT").as_deref(), Some("8080"));
        assert_eq!(s.get("DB").as_deref(), Some("postgres://x"));
    }

    #[test]
    fn env_parse_quotes_comments_blanks_invalid() {
        let s = EnvStore::parse(
            "# comment line\n\
             A=\"has spaces\"  # trailing comment\n\
             B='literal'\n\
             C=plain # comment\n\
             \n\
             1BAD=x\n\
             D=nocomment#notacomment\n",
        );
        assert_eq!(s.get("A").as_deref(), Some("has spaces"));
        assert_eq!(s.get("B").as_deref(), Some("literal"));
        assert_eq!(s.get("C").as_deref(), Some("plain"));
        // clave inválida ignorada (warning, no crash)
        assert_eq!(s.get("1BAD"), None);
        // `#` sin espacio previo NO es comentario
        assert_eq!(s.get("D").as_deref(), Some("nocomment#notacomment"));
    }

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 Test Case 2: key="Jefe", data="what do ya want for nothing?"
        let mac = hmac_compute(Algo::Sha256, b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            to_hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn verify_hmac_hex_and_base64() {
        let key = b"key";
        let data = b"hello";
        let mac = hmac_compute(Algo::Sha256, key, data);
        let hex = to_hex(&mac);
        assert_eq!(decode_signature(&hex, 32).unwrap(), mac);
        // base64 estándar del MAC
        let b64 = base64_encode_for_test(&mac);
        assert_eq!(decode_signature(&b64, 32).unwrap(), mac);
        // prefijo estilo GitHub
        assert_eq!(decode_signature(&format!("sha256={}", hex), 32).unwrap(), mac);
    }

    #[test]
    fn from_hex_rejects_bad() {
        assert!(from_hex("zz").is_none());
        assert!(from_hex("abc").is_none()); // longitud impar
    }

    // base64 encode sólo para el test (la lib sólo decodifica firmas entrantes).
    fn base64_encode_for_test(b: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in b.chunks(3) {
            let n = chunk.len();
            let b0 = chunk[0] as u32;
            let b1 = if n > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if n > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(A[((triple >> 18) & 63) as usize] as char);
            out.push(A[((triple >> 12) & 63) as usize] as char);
            out.push(if n > 1 { A[((triple >> 6) & 63) as usize] as char } else { '=' });
            out.push(if n > 2 { A[(triple & 63) as usize] as char } else { '=' });
        }
        out
    }
}

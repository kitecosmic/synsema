//! T4 — Tokens de capacidad ATENUABLES (estilo macaroons/biscuits).
//!
//! Bearer/JWT responde "¿quién sos?"; un captoken responde "¿qué podés hacer?" y
//! —la parte que no tiene ningún runtime mainstream— **el portador puede emitir
//! una versión más débil sin hablar con el emisor**: el orquestador con
//! `{db: "…", spend: "USD"}` delega a un subagente `{db: "…"}` con TTL corto, sin
//! la clave raíz. Es la proyección de red del modelo de capabilities del lenguaje
//! (P2 del diseño): *capabilities que cruzan la red*.
//!
//! **Cómo se sostiene criptográficamente (cadena HMAC, macaroons):**
//! ```text
//! sig_0 = HMAC(root_key, canonical(bloque_0))
//! sig_i = HMAC(sig_{i-1}, canonical(bloque_i))       // la firma previa ES la clave
//! ```
//! El portador conoce `sig_n` (viaja en el token) pero NO la raíz: puede AGREGAR
//! un bloque (atenuar) porque `sig_{n+1} = HMAC(sig_n, bloque)`, y no puede quitar
//! ni editar bloques (no sabe re-derivar las firmas intermedias sin la raíz).
//!
//! **Álgebra de scopes = el vocabulario del `CapabilitySet`.** Los permisos del
//! token son las MISMAS formas de `require` (net/db/file/sign/spend/… con sus
//! scopes) y la atenuación es intersección, verificada con el MISMO `covers()` que
//! gatea los `require` — así no hay una segunda lógica de scopes que pueda
//! divergir, y un futuro `require from_token(t)` es mapeo 1:1.
//!
//! **La atenuación jamás amplía**, y eso se comprueba dos veces: al atenuar (error
//! claro) y al verificar (rechazo) — un token forjado a mano tampoco puede ampliar.
//!
//! **Serialización canónica:** el msgpack canónico que ya está en el árbol (el
//! writer de `blockchain_algorand.rs`); firmar maps exige bytes canónicos y no se
//! inventa un encoding nuevo. El árbol se construye acá (sin la poda de
//! zero-values de Algorand, que al firmar permisos sería un agujero).
//!
//! **Revocación — dicho explícito:** la atenuación es offline, así que NO hay
//! chequeo central. Mitigación de diseño: TTL corto por defecto + denylist de `id`
//! (`opts.revoked`, típicamente leída de redis/sql). Sin esto, el primer incidente
//! lo improvisa mal.

use std::rc::Rc;

use indexmap::IndexMap;

use synsema_capabilities::model::{capability_type_from_name, Capability};
use synsema_core::bytesutil::{b64url_decode, b64url_encode};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::secret::constant_time_eq;
use synsema_core::types::{syn_int, syn_list, syn_map, syn_nothing, syn_text, SynValue};

use crate::blockchain_algorand::{mp_write, Mp};
use crate::secrets::{hmac_compute, Algo};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

/// Versión del formato. Un token de otra versión se rechaza (no se adivina).
const FORMAT_VERSION: u64 = 1;

/// Profundidad máxima de la cadena: cada atenuación agrega un bloque. 32 niveles
/// de delegación es holgado para cualquier árbol de agentes real y acota el costo
/// de verificación de un token hostil.
const MAX_DEPTH: usize = 32;

/// TTL por defecto de un token recién acuñado, en segundos. Corto A PROPÓSITO:
/// sin revocación central (ver el doc del módulo), el TTL es la mitigación
/// principal. El emisor lo sube explícitamente si lo necesita.
const DEFAULT_TTL: i64 = 900;

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// =========================================================
// Modelo
// =========================================================

/// Un bloque de la cadena: permisos + caveats. El bloque 0 lo firma la raíz; cada
/// atenuación agrega uno.
#[derive(Clone, Debug, PartialEq)]
struct Block {
    /// `nombre_capability -> scopes`. Un scope vacío (`[]`) significa "la
    /// capability sin scope" (poder máximo de ese tipo, como `require reveal`).
    caps: Vec<(String, Vec<String>)>,
    /// Condiciones contextuales evaluadas en el verify.
    caveats: Caveats,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Caveats {
    /// Instante de expiración (unix). El más chico de la cadena manda.
    exp: Option<i64>,
    /// Audiencia: el verificador debe presentarse con este `aud`.
    aud: Option<String>,
    /// IP del cliente permitida.
    ip: Option<String>,
    /// Método HTTP permitido (mayúsculas).
    method: Option<String>,
    /// Techo de gasto delegado (unidad → monto máximo, en texto decimal exacto).
    spend: Vec<(String, String)>,
}

/// El token completo, ya parseado.
struct Token {
    id: String,
    blocks: Vec<Block>,
    sig: Vec<u8>,
}

// =========================================================
// Serialización canónica (msgpack del árbol)
// =========================================================

/// Un map canónico: claves ordenadas bytewise, SIN podar zero-values (a
/// diferencia del `to_mp` de Algorand — ver el doc del módulo).
fn mp_map(mut entries: Vec<(String, Mp)>) -> Mp {
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Mp::Map(entries)
}

fn caps_to_mp(caps: &[(String, Vec<String>)]) -> Mp {
    let entries: Vec<(String, Mp)> = caps
        .iter()
        .map(|(name, scopes)| {
            let mut sorted = scopes.clone();
            sorted.sort();
            (
                name.clone(),
                Mp::List(sorted.into_iter().map(Mp::Str).collect()),
            )
        })
        .collect();
    mp_map(entries)
}

fn caveats_to_mp(c: &Caveats) -> Mp {
    let mut entries: Vec<(String, Mp)> = Vec::new();
    if let Some(e) = c.exp {
        entries.push(("exp".to_string(), Mp::Uint(e.max(0) as u64)));
    }
    if let Some(a) = &c.aud {
        entries.push(("aud".to_string(), Mp::Str(a.clone())));
    }
    if let Some(i) = &c.ip {
        entries.push(("ip".to_string(), Mp::Str(i.clone())));
    }
    if let Some(m) = &c.method {
        entries.push(("method".to_string(), Mp::Str(m.clone())));
    }
    if !c.spend.is_empty() {
        let mut sp = c.spend.clone();
        sp.sort();
        entries.push((
            "spend".to_string(),
            mp_map(sp.into_iter().map(|(u, a)| (u, Mp::Str(a))).collect()),
        ));
    }
    mp_map(entries)
}

/// Los bytes canónicos de un bloque: lo que se firma. El índice entra en el
/// preimagen para que un bloque no pueda moverse de posición en la cadena.
fn block_bytes(index: usize, b: &Block) -> Vec<u8> {
    let tree = mp_map(vec![
        ("i".to_string(), Mp::Uint(index as u64)),
        ("c".to_string(), caps_to_mp(&b.caps)),
        ("v".to_string(), caveats_to_mp(&b.caveats)),
    ]);
    let mut out = Vec::new();
    mp_write(&tree, &mut out);
    out
}

/// La firma de la cadena entera: `sig_i = HMAC(sig_{i-1}, bloque_i)`, con la clave
/// raíz como semilla. Devuelve la firma final.
fn chain_signature(root_key: &[u8], id: &str, blocks: &[Block]) -> Vec<u8> {
    // El id entra en la semilla: dos tokens con los mismos permisos pero distinto
    // id tienen firmas distintas (y el id es lo que se revoca).
    let mut sig = hmac_compute(Algo::Sha256, root_key, id.as_bytes());
    for (i, b) in blocks.iter().enumerate() {
        sig = hmac_compute(Algo::Sha256, &sig, &block_bytes(i, b));
    }
    sig
}

/// Serializa el token a texto transportable: `base64url(msgpack canónico)`.
fn encode_token(t: &Token) -> String {
    let blocks: Vec<Mp> = t
        .blocks
        .iter()
        .map(|b| {
            mp_map(vec![
                ("c".to_string(), caps_to_mp(&b.caps)),
                ("v".to_string(), caveats_to_mp(&b.caveats)),
            ])
        })
        .collect();
    let tree = mp_map(vec![
        ("b".to_string(), Mp::List(blocks)),
        ("i".to_string(), Mp::Str(t.id.clone())),
        ("s".to_string(), Mp::Bytes(t.sig.clone())),
        ("z".to_string(), Mp::Uint(FORMAT_VERSION)),
    ]);
    let mut out = Vec::new();
    mp_write(&tree, &mut out);
    b64url_encode(&out)
}

// =========================================================
// Decodificación (msgpack — el árbol no tiene decoder; este es acotado al formato)
// =========================================================

/// Cursor de lectura msgpack, estricto y acotado al subset que emite este módulo.
/// Cualquier byte inesperado corta con `None` (el token se rechaza).
struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn byte(&mut self) -> Option<u8> {
        let v = *self.b.get(self.i)?;
        self.i += 1;
        Some(v)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        let s = self.b.get(self.i..end)?;
        self.i = end;
        Some(s)
    }
    fn be(&mut self, n: usize) -> Option<u64> {
        let s = self.take(n)?;
        Some(s.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64))
    }
    fn uint(&mut self) -> Option<u64> {
        match self.byte()? {
            v if v <= 0x7f => Some(v as u64),
            0xcc => self.be(1),
            0xcd => self.be(2),
            0xce => self.be(4),
            0xcf => self.be(8),
            _ => None,
        }
    }
    fn str_(&mut self) -> Option<String> {
        let len = match self.byte()? {
            v if (0xa0..=0xbf).contains(&v) => (v & 0x1f) as usize,
            0xd9 => self.be(1)? as usize,
            0xda => self.be(2)? as usize,
            _ => return None,
        };
        String::from_utf8(self.take(len)?.to_vec()).ok()
    }
    fn bytes_(&mut self) -> Option<Vec<u8>> {
        let len = match self.byte()? {
            0xc4 => self.be(1)? as usize,
            0xc5 => self.be(2)? as usize,
            _ => return None,
        };
        Some(self.take(len)?.to_vec())
    }
    fn map_len(&mut self) -> Option<usize> {
        match self.byte()? {
            v if (0x80..=0x8f).contains(&v) => Some((v & 0x0f) as usize),
            0xde => Some(self.be(2)? as usize),
            _ => None,
        }
    }
    fn list_len(&mut self) -> Option<usize> {
        match self.byte()? {
            v if (0x90..=0x9f).contains(&v) => Some((v & 0x0f) as usize),
            0xdc => Some(self.be(2)? as usize),
            _ => None,
        }
    }
}

fn decode_caps(c: &mut Cur) -> Option<Vec<(String, Vec<String>)>> {
    let n = c.map_len()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let name = c.str_()?;
        let sn = c.list_len()?;
        let mut scopes = Vec::with_capacity(sn);
        for _ in 0..sn {
            scopes.push(c.str_()?);
        }
        out.push((name, scopes));
    }
    Some(out)
}

fn decode_caveats(c: &mut Cur) -> Option<Caveats> {
    let n = c.map_len()?;
    let mut out = Caveats::default();
    for _ in 0..n {
        match c.str_()?.as_str() {
            "exp" => out.exp = Some(c.uint()? as i64),
            "aud" => out.aud = Some(c.str_()?),
            "ip" => out.ip = Some(c.str_()?),
            "method" => out.method = Some(c.str_()?),
            "spend" => {
                let sn = c.map_len()?;
                let mut sp = Vec::with_capacity(sn);
                for _ in 0..sn {
                    let unit = c.str_()?;
                    sp.push((unit, c.str_()?));
                }
                out.spend = sp;
            }
            // Clave desconocida → el token viene de otra versión/implementación:
            // rechazo (nunca ignorar un caveat que no se entiende, sería aceptar
            // una restricción que el emisor SÍ puso).
            _ => return None,
        }
    }
    Some(out)
}

fn decode_token(s: &str) -> Option<Token> {
    let raw = b64url_decode(s.trim()).ok()?;
    let mut c = Cur { b: &raw, i: 0 };
    let n = c.map_len()?;
    if n != 4 {
        return None;
    }
    let mut blocks: Option<Vec<Block>> = None;
    let mut id: Option<String> = None;
    let mut sig: Option<Vec<u8>> = None;
    let mut version: Option<u64> = None;
    for _ in 0..4 {
        match c.str_()?.as_str() {
            "b" => {
                let bn = c.list_len()?;
                if bn == 0 || bn > MAX_DEPTH {
                    return None;
                }
                let mut bs = Vec::with_capacity(bn);
                for _ in 0..bn {
                    if c.map_len()? != 2 {
                        return None;
                    }
                    let mut caps = None;
                    let mut caveats = None;
                    for _ in 0..2 {
                        match c.str_()?.as_str() {
                            "c" => caps = Some(decode_caps(&mut c)?),
                            "v" => caveats = Some(decode_caveats(&mut c)?),
                            _ => return None,
                        }
                    }
                    bs.push(Block { caps: caps?, caveats: caveats? });
                }
                blocks = Some(bs);
            }
            "i" => id = Some(c.str_()?),
            "s" => sig = Some(c.bytes_()?),
            "z" => version = Some(c.uint()?),
            _ => return None,
        }
    }
    // Sobras al final = no canónico (o input manipulado) → rechazo.
    if c.i != raw.len() || version? != FORMAT_VERSION {
        return None;
    }
    Some(Token { id: id?, blocks: blocks?, sig: sig? })
}

// =========================================================
// Álgebra: la atenuación jamás amplía
// =========================================================

/// Una capability concreta desde `(nombre, scope)`. El nombre debe existir en el
/// vocabulario del lenguaje — un typo (`"nett"`) es error, no una capability
/// desconocida que después no gatea nada.
fn to_capability(name: &str, scope: Option<&str>, who: &str) -> Result<Capability, Control> {
    let ty = capability_type_from_name(name).ok_or_else(|| {
        err(format!(
            "{}: unknown capability {:?} — use the same names as `require` \
             (net, file, file.read, file.write, exec, env, time, random, stdout, stdin, \
             llm, db, serve, secret, reveal, sign, wallet, spend, memory)",
            who, name
        ))
    })?;
    Ok(Capability::new(ty, scope.map(|s| s.to_string())))
}

/// ¿`child` está cubierto por `parent`? Es la MISMA relación que gatea los
/// `require` (`Capability::covers`), con su canonización de rutas/URLs y sus globs.
fn caps_cover(parent: &[(String, Vec<String>)], child: &[(String, Vec<String>)], who: &str) -> Result<bool, Control> {
    for (name, scopes) in child {
        let entry = parent.iter().find(|(n, _)| n == name);
        let Some((_, parent_scopes)) = entry else {
            // La capability no está en el padre → ampliaría.
            return Ok(false);
        };
        if scopes.is_empty() {
            // El hijo pide la capability SIN scope (poder máximo del tipo): sólo
            // vale si el padre también la tiene sin scope.
            if !parent_scopes.is_empty() {
                return Ok(false);
            }
            continue;
        }
        for s in scopes {
            let want = to_capability(name, Some(s), who)?;
            let covered = if parent_scopes.is_empty() {
                true // padre sin scope = wildcard: cubre cualquier scope
            } else {
                let mut any = false;
                for ps in parent_scopes {
                    if to_capability(name, Some(ps), who)?.covers(&want) {
                        any = true;
                        break;
                    }
                }
                any
            };
            if !covered {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// ¿Los caveats del hijo son iguales o MÁS restrictivos que los del padre?
fn caveats_narrow(parent: &Caveats, child: &Caveats) -> bool {
    // exp: el hijo no puede extender la vida del padre.
    if let Some(pe) = parent.exp {
        match child.exp {
            Some(ce) if ce <= pe => {}
            _ => return false,
        }
    }
    // aud/ip/method: si el padre fijó uno, el hijo debe repetir EXACTAMENTE ese
    // (no puede cambiar de audiencia ni ampliar a otro método/IP).
    for (p, c) in [
        (&parent.aud, &child.aud),
        (&parent.ip, &child.ip),
        (&parent.method, &child.method),
    ] {
        if let Some(pv) = p {
            match c {
                Some(cv) if cv == pv => {}
                _ => return false,
            }
        }
    }
    // spend: cada unidad del hijo debe existir en el padre con monto >= (y el
    // hijo no puede introducir una unidad que el padre no delegó).
    for (unit, amount) in &child.spend {
        let Some((_, pamount)) = parent.spend.iter().find(|(u, _)| u == unit) else {
            return false;
        };
        let (Ok(c), Ok(p)) = (
            amount.parse::<rust_decimal::Decimal>(),
            pamount.parse::<rust_decimal::Decimal>(),
        ) else {
            return false;
        };
        if c > p {
            return false;
        }
    }
    true
}

// =========================================================
// Lectura de args
// =========================================================

fn key_material(v: &SynValue, who: &str) -> Result<Vec<u8>, Control> {
    match v {
        SynValue::Secret(s) => Ok(s.expose_bytes().to_vec()),
        SynValue::Text(s) => Ok(s.as_bytes().to_vec()),
        SynValue::Bytes(b) => Ok(b.to_vec()),
        other => Err(err(format!(
            "{}: the root key must be a secret, text or bytes, got {}",
            who,
            other.type_name()
        ))),
    }
}

fn as_map(v: &SynValue, who: &str, what: &str) -> Result<IndexMap<String, SynValue>, Control> {
    match v {
        SynValue::Map(m) => Ok(m.borrow().clone()),
        other => Err(err(format!(
            "{}: {} must be a map, got {}",
            who,
            what,
            other.type_name()
        ))),
    }
}

/// `{"net": "api.example.com", "db": ["a", "b"], "reveal": nothing}` → caps.
/// `nothing` (o lista vacía) = la capability SIN scope (poder máximo del tipo).
fn parse_caps(m: &IndexMap<String, SynValue>, who: &str) -> Result<Vec<(String, Vec<String>)>, Control> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for (name, v) in m {
        // Valida el nombre contra el vocabulario del lenguaje (falla en el typo).
        to_capability(name, None, who)?;
        let scopes = match v {
            SynValue::Nothing => Vec::new(),
            SynValue::Text(s) => vec![s.to_string()],
            SynValue::List(l) => {
                let mut ss = Vec::new();
                for item in l.borrow().iter() {
                    match item {
                        SynValue::Text(s) => ss.push(s.to_string()),
                        other => {
                            return Err(err(format!(
                                "{}: the scopes of {:?} must be text, got {}",
                                who,
                                name,
                                other.type_name()
                            )))
                        }
                    }
                }
                ss
            }
            other => {
                return Err(err(format!(
                    "{}: the scope of {:?} must be text, a list of text, or nothing (no scope), got {}",
                    who,
                    name,
                    other.type_name()
                )))
            }
        };
        out.push((name.clone(), scopes));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Opciones de caveats compartidas por mint y attenuate.
fn parse_caveats(
    m: &IndexMap<String, SynValue>,
    who: &str,
    default_ttl: Option<i64>,
) -> Result<Caveats, Control> {
    let mut c = Caveats::default();
    let mut ttl: Option<i64> = None;
    for (k, v) in m {
        match k.as_str() {
            "ttl" => match v {
                SynValue::Number(n) => match n.to_i64_trunc() {
                    Some(t) if t > 0 => ttl = Some(t),
                    _ => return Err(err(format!("{}: ttl must be a positive integer (seconds)", who))),
                },
                other => {
                    return Err(err(format!(
                        "{}: ttl must be an integer (seconds), got {}",
                        who,
                        other.type_name()
                    )))
                }
            },
            "aud" => c.aud = Some(v.to_string()),
            "ip" => c.ip = Some(v.to_string()),
            "method" => c.method = Some(v.to_string().to_ascii_uppercase()),
            "spend" => {
                let sm = as_map(v, who, "the spend caveat")?;
                let mut sp = Vec::new();
                for (unit, amount) in &sm {
                    let text = match amount {
                        SynValue::Number(n) => n.to_string(),
                        SynValue::Text(s) => s.to_string(),
                        other => {
                            return Err(err(format!(
                                "{}: the spend limit of {:?} must be a number, got {}",
                                who,
                                unit,
                                other.type_name()
                            )))
                        }
                    };
                    let dec: rust_decimal::Decimal = text.trim().parse().map_err(|_| {
                        err(format!(
                            "{}: the spend limit of {:?} is not a valid decimal amount: {:?}",
                            who, unit, text
                        ))
                    })?;
                    if dec.is_sign_negative() {
                        return Err(err(format!(
                            "{}: the spend limit of {:?} cannot be negative",
                            who, unit
                        )));
                    }
                    sp.push((unit.clone(), dec.normalize().to_string()));
                }
                sp.sort();
                c.spend = sp;
            }
            other => {
                return Err(err(format!(
                    "{}: unknown caveat {:?} (valid caveats: ttl, aud, ip, method, spend)",
                    who, other
                )))
            }
        }
    }
    // TTL → exp absoluto (el token viaja con el instante, no con la duración).
    if let Some(t) = ttl.or(default_ttl) {
        c.exp = Some(unix_now() + t);
    }
    Ok(c)
}

// =========================================================
// captoken_mint
// =========================================================

fn b_captoken_mint(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "captoken_mint";
    if !(2..=3).contains(&args.len()) {
        return Err(err(format!("{}(caps, root_key, opts?) takes 2 or 3 arguments", F)));
    }
    let caps = parse_caps(&as_map(&args[0], F, "caps")?, F)?;
    if caps.is_empty() {
        return Err(err(format!(
            "{}: caps cannot be empty — a token that grants nothing is a bug, not a restriction",
            F
        )));
    }
    let key = key_material(&args[1], F)?;

    let opts = match args.get(2) {
        None | Some(SynValue::Nothing) => IndexMap::new(),
        Some(v) => as_map(v, F, "opts")?,
    };
    // `id` es lo que se revoca: explícito o aleatorio (OsRng, como `token()`).
    let mut id: Option<String> = None;
    let mut caveat_opts = IndexMap::new();
    for (k, v) in &opts {
        match k.as_str() {
            "id" => id = Some(v.to_string()),
            _ => {
                caveat_opts.insert(k.clone(), v.clone());
            }
        }
    }
    // El TTL por defecto es corto a propósito (sin revocación central).
    let caveats = parse_caveats(&caveat_opts, F, Some(DEFAULT_TTL))?;
    let id = match id {
        Some(i) if !i.trim().is_empty() => i,
        Some(_) => return Err(err(format!("{}: id cannot be empty", F))),
        None => {
            let mut raw = [0u8; 16];
            rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut raw)
                .map_err(|_| err(format!("{}: the OS random source is unavailable", F)))?;
            b64url_encode(&raw)
        }
    };

    let blocks = vec![Block { caps, caveats }];
    let sig = chain_signature(&key, &id, &blocks);
    Ok(syn_text(encode_token(&Token { id, blocks, sig })))
}

// =========================================================
// captoken_attenuate — SIN la clave raíz
// =========================================================

fn b_captoken_attenuate(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "captoken_attenuate";
    if !(2..=3).contains(&args.len()) {
        return Err(err(format!(
            "{}(token, caps, opts?) takes 2 or 3 arguments — note it does NOT take the root key: \
             attenuating is offline, that is the point",
            F
        )));
    }
    let token_text = match &args[0] {
        SynValue::Text(s) => s.to_string(),
        other => {
            return Err(err(format!(
                "{}: the token must be text, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let mut t = decode_token(&token_text)
        .ok_or_else(|| err(format!("{}: the token is malformed or of an unknown version", F)))?;
    if t.blocks.len() >= MAX_DEPTH {
        return Err(err(format!(
            "{}: the delegation chain already has {} blocks (max {})",
            F,
            t.blocks.len(),
            MAX_DEPTH
        )));
    }
    let caps = parse_caps(&as_map(&args[1], F, "caps")?, F)?;
    let opts = match args.get(2) {
        None | Some(SynValue::Nothing) => IndexMap::new(),
        Some(v) => as_map(v, F, "opts")?,
    };
    // Sin TTL propio, el bloque hereda el `exp` del padre (no lo extiende).
    let mut caveats = parse_caveats(&opts, F, None)?;
    let parent = t.blocks.last().expect("decode garantiza >= 1 bloque").clone();
    if caveats.exp.is_none() {
        caveats.exp = parent.caveats.exp;
    }
    for (field, inherited) in [
        (&mut caveats.aud, &parent.caveats.aud),
        (&mut caveats.ip, &parent.caveats.ip),
        (&mut caveats.method, &parent.caveats.method),
    ] {
        if field.is_none() {
            *field = inherited.clone();
        }
    }
    if caveats.spend.is_empty() {
        caveats.spend = parent.caveats.spend.clone();
    }

    // La atenuación JAMÁS amplía: se comprueba acá con un error que dice qué
    // sobra (y de nuevo en el verify, para un token forjado a mano).
    if !caps_cover(&parent.caps, &caps, F)? {
        return Err(err(format!(
            "{}: the new caps are not covered by the token's — attenuation can only narrow. \
             Check the capability names and scopes against the ones the token already carries \
             (captoken_verify shows them).",
            F
        )));
    }
    if !caveats_narrow(&parent.caveats, &caveats) {
        return Err(err(format!(
            "{}: the new caveats are wider than the token's (a longer ttl, a different aud/ip/method, \
             or a higher spend limit) — attenuation can only narrow",
            F
        )));
    }

    let block = Block { caps, caveats };
    // `sig_{n+1} = HMAC(sig_n, bloque)`: la firma actual ES la clave. Por eso el
    // portador puede atenuar sin la raíz, y sólo puede AGREGAR.
    let new_sig = hmac_compute(Algo::Sha256, &t.sig, &block_bytes(t.blocks.len(), &block));
    t.blocks.push(block);
    t.sig = new_sig;
    Ok(syn_text(encode_token(&t)))
}

// =========================================================
// captoken_verify
// =========================================================

fn caps_to_syn(caps: &[(String, Vec<String>)]) -> SynValue {
    let mut m = IndexMap::new();
    for (name, scopes) in caps {
        m.insert(
            name.clone(),
            syn_list(scopes.iter().map(|s| syn_text(s.as_str())).collect()),
        );
    }
    syn_map(m)
}

fn b_captoken_verify(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "captoken_verify";
    if !(2..=3).contains(&args.len()) {
        return Err(err(format!("{}(token, root_key, opts?) takes 2 or 3 arguments", F)));
    }
    let token_text = match &args[0] {
        SynValue::Text(s) => s.to_string(),
        // Un no-texto no puede ser un token → `nothing` (mismo contrato uniforme).
        _ => return Ok(syn_nothing()),
    };
    let key = key_material(&args[1], F)?;

    let opts = match args.get(2) {
        None | Some(SynValue::Nothing) => IndexMap::new(),
        Some(v) => as_map(v, F, "opts")?,
    };
    let mut ctx_aud: Option<String> = None;
    let mut ctx_ip: Option<String> = None;
    let mut ctx_method: Option<String> = None;
    let mut at: i64 = unix_now();
    let mut revoked: Vec<String> = Vec::new();
    for (k, v) in &opts {
        match k.as_str() {
            "aud" => ctx_aud = Some(v.to_string()),
            "ip" => ctx_ip = Some(v.to_string()),
            "method" => ctx_method = Some(v.to_string().to_ascii_uppercase()),
            "at" => match v {
                SynValue::Number(n) => {
                    at = n.to_i64_trunc().ok_or_else(|| {
                        err(format!("{}: at must be a unix timestamp (integer)", F))
                    })?
                }
                other => {
                    return Err(err(format!(
                        "{}: at must be a unix timestamp (integer), got {}",
                        F,
                        other.type_name()
                    )))
                }
            },
            "revoked" => match v {
                SynValue::List(l) => revoked = l.borrow().iter().map(|x| x.to_string()).collect(),
                other => {
                    return Err(err(format!(
                        "{}: revoked must be a list of token ids, got {}",
                        F,
                        other.type_name()
                    )))
                }
            },
            other => {
                return Err(err(format!(
                    "{}: unknown option {:?} (valid options: aud, ip, method, at, revoked)",
                    F, other
                )))
            }
        }
    }

    // Toda falla → `nothing`, sin detalle de la causa (mismo contrato que
    // `jwt_verify`/`http_signature_verify`).
    Ok(
        verify_inner(&token_text, &key, ctx_aud.as_deref(), ctx_ip.as_deref(), ctx_method.as_deref(), at, &revoked, F)?
            .unwrap_or_else(syn_nothing),
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_inner(
    token_text: &str,
    key: &[u8],
    aud: Option<&str>,
    ip: Option<&str>,
    method: Option<&str>,
    at: i64,
    revoked: &[String],
    who: &str,
) -> Result<Option<SynValue>, Control> {
    let Some(t) = decode_token(token_text) else {
        return Ok(None);
    };
    // 1. Firma de la cadena entera (constant-time). Un bloque editado, quitado o
    //    reordenado no reproduce la cadena.
    let expected = chain_signature(key, &t.id, &t.blocks);
    if !constant_time_eq(&expected, &t.sig) {
        return Ok(None);
    }
    // 2. Denylist de ids (revocación explícita — ver el doc del módulo).
    if revoked.iter().any(|r| r == &t.id) {
        return Ok(None);
    }
    // 3. La cadena debe ser monótona decreciente: cada bloque atenúa al anterior.
    //    Un token forjado con un bloque que amplía se rechaza acá aunque la firma
    //    cierre (la firma sólo prueba autoría de la cadena, no que sea legal).
    for i in 1..t.blocks.len() {
        if !caps_cover(&t.blocks[i - 1].caps, &t.blocks[i].caps, who)? {
            return Ok(None);
        }
        if !caveats_narrow(&t.blocks[i - 1].caveats, &t.blocks[i].caveats) {
            return Ok(None);
        }
    }
    // 4. Caveats efectivos: el más restrictivo de toda la cadena (defensa en
    //    profundidad — no se confía en que el último bloque los herede bien).
    let mut eff = Caveats::default();
    for b in &t.blocks {
        if let Some(e) = b.caveats.exp {
            eff.exp = Some(eff.exp.map_or(e, |cur: i64| cur.min(e)));
        }
        for (field, src) in [
            (&mut eff.aud, &b.caveats.aud),
            (&mut eff.ip, &b.caveats.ip),
            (&mut eff.method, &b.caveats.method),
        ] {
            if src.is_some() {
                *field = src.clone();
            }
        }
        for (unit, amount) in &b.caveats.spend {
            let dec: rust_decimal::Decimal = match amount.parse() {
                Ok(d) => d,
                Err(_) => return Ok(None),
            };
            match eff.spend.iter_mut().find(|(u, _)| u == unit) {
                Some((_, cur)) => {
                    let cur_dec: rust_decimal::Decimal = match cur.parse() {
                        Ok(d) => d,
                        Err(_) => return Ok(None),
                    };
                    if dec < cur_dec {
                        *cur = amount.clone();
                    }
                }
                None => eff.spend.push((unit.clone(), amount.clone())),
            }
        }
    }
    // 5. Evaluación contextual.
    if let Some(exp) = eff.exp {
        if at > exp {
            return Ok(None);
        }
    }
    // Un caveat presente en el token EXIGE que el verificador aporte el contexto:
    // si no lo aporta, no puede afirmar que se cumple → rechazo (fail-closed).
    for (required, provided) in [
        (&eff.aud, aud),
        (&eff.ip, ip),
        (&eff.method, method),
    ] {
        if let Some(r) = required {
            match provided {
                Some(p) if p == r => {}
                _ => return Ok(None),
            }
        }
    }

    // Los caps efectivos son los del último bloque (ya validado como el más
    // restrictivo de la cadena).
    let last = t.blocks.last().expect("decode garantiza >= 1 bloque");
    let mut out = IndexMap::new();
    out.insert("id".to_string(), syn_text(t.id.as_str()));
    out.insert("caps".to_string(), caps_to_syn(&last.caps));
    out.insert("depth".to_string(), syn_int(t.blocks.len() as i64));
    let mut cav = IndexMap::new();
    cav.insert(
        "exp".to_string(),
        eff.exp.map(syn_int).unwrap_or_else(syn_nothing),
    );
    for (k, v) in [("aud", &eff.aud), ("ip", &eff.ip), ("method", &eff.method)] {
        cav.insert(
            k.to_string(),
            v.as_ref().map(|s| syn_text(s.as_str())).unwrap_or_else(syn_nothing),
        );
    }
    let mut sp = IndexMap::new();
    for (unit, amount) in &eff.spend {
        sp.insert(unit.clone(), syn_text(amount.as_str()));
    }
    cav.insert("spend".to_string(), syn_map(sp));
    out.insert("caveats".to_string(), syn_map(cav));
    Ok(Some(syn_map(out)))
}

// =========================================================
// captoken_allows — el chequeo puntual (¿este token habilita esta operación?)
// =========================================================

fn b_captoken_allows(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "captoken_allows";
    if !(2..=3).contains(&args.len()) {
        return Err(err(format!(
            "{}(verified, capability, scope?) takes 2 or 3 arguments",
            F
        )));
    }
    // Toma la SALIDA de captoken_verify (ya verificada): así es imposible
    // preguntar por permisos de un token sin haberlo validado antes.
    let verified = match &args[0] {
        SynValue::Map(m) => m.borrow().clone(),
        SynValue::Nothing => return Ok(SynValue::Bool(false)),
        other => {
            return Err(err(format!(
                "{}: the first argument must be the map returned by captoken_verify (or nothing), got {}",
                F,
                other.type_name()
            )))
        }
    };
    let name = match verified.get("caps") {
        Some(SynValue::Map(_)) => args[1].to_string(),
        _ => {
            return Err(err(format!(
                "{}: the first argument must be the map returned by captoken_verify",
                F
            )))
        }
    };
    let caps_map = match verified.get("caps") {
        Some(SynValue::Map(m)) => m.borrow().clone(),
        _ => unreachable!("chequeado arriba"),
    };
    let scope = match args.get(2) {
        None | Some(SynValue::Nothing) => None,
        Some(v) => Some(v.to_string()),
    };
    let Some(entry) = caps_map.get(&name) else {
        return Ok(SynValue::Bool(false));
    };
    let scopes: Vec<String> = match entry {
        SynValue::List(l) => l.borrow().iter().map(|s| s.to_string()).collect(),
        other => vec![other.to_string()],
    };
    // Sin scopes = la capability sin scope (wildcard): cubre cualquier pedido.
    if scopes.is_empty() {
        return Ok(SynValue::Bool(true));
    }
    let Some(want_scope) = scope else {
        // Se pide la capability SIN scope pero el token la tiene scopeada → no.
        return Ok(SynValue::Bool(false));
    };
    let want = to_capability(&name, Some(&want_scope), F)?;
    for s in &scopes {
        if to_capability(&name, Some(s), F)?.covers(&want) {
            return Ok(SynValue::Bool(true));
        }
    }
    Ok(SynValue::Bool(false))
}

// =========================================================
// Registro
// =========================================================

/// Registra `captoken_mint`/`captoken_attenuate`/`captoken_verify`/
/// `captoken_allows`. Todos PUROS (sin capability): acuñar y verificar son
/// transforms criptográficos locales — el poder está en la clave raíz, que es un
/// `secret` sellado, y lo que un token concede sigue gateado por el
/// `CapabilitySet` del proceso que lo usa. Wired en `wire_common_with_state`.
pub fn register_captoken_builtins(interp: &Interpreter) {
    interp.register_builtin("captoken_mint", -1, Rc::new(|_i, a, _l| b_captoken_mint(a)));
    interp.register_builtin(
        "captoken_attenuate",
        -1,
        Rc::new(|_i, a, _l| b_captoken_attenuate(a)),
    );
    interp.register_builtin("captoken_verify", -1, Rc::new(|_i, a, _l| b_captoken_verify(a)));
    interp.register_builtin("captoken_allows", -1, Rc::new(|_i, a, _l| b_captoken_allows(a)));
}

/// Nota de diseño: la conversión de los caps del token a `Capability`s del modelo
/// (el puente hacia un futuro `require from_token(t)`) NO vive acá todavía a
/// propósito — sería código sin llamador. El consumo real de un token verificado
/// hoy es `captoken_allows` (consulta puntual) y, del lado del serve,
/// `identity_of`/`delegated_spend_of` de `server.rs` (identidad y techo de gasto,
/// T6.4). Cuando el volcado al CapabilitySet exista, es una función de tres
/// líneas sobre `caps`.
#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> SynValue {
        syn_text(s)
    }

    fn map(pairs: Vec<(&str, SynValue)>) -> SynValue {
        let mut m = IndexMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        syn_map(m)
    }

    fn ok(r: Result<SynValue, Control>) -> SynValue {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("unexpected error: {}", e),
            Err(_) => panic!("unexpected control flow"),
        }
    }

    fn verified_map(v: &SynValue) -> IndexMap<String, SynValue> {
        match v {
            SynValue::Map(m) => m.borrow().clone(),
            other => panic!("expected a verification map, got {}", other),
        }
    }

    const KEY: &str = "root-key";

    fn mint(caps: SynValue, opts: SynValue) -> String {
        ok(b_captoken_mint(&[caps, text(KEY), opts])).to_string()
    }

    #[test]
    fn mint_and_verify_roundtrip() {
        let t = mint(
            map(vec![
                ("net", text("api.example.com")),
                ("db", text("postgres://localhost/appdb")),
            ]),
            SynValue::Nothing,
        );
        let v = ok(b_captoken_verify(&[text(&t), text(KEY)]));
        let m = verified_map(&v);
        assert_eq!(m.get("depth").unwrap().to_string(), "1");
        let caps = verified_map(&m.get("caps").unwrap().clone());
        assert!(caps.contains_key("net") && caps.contains_key("db"));
        // Clave equivocada → nothing.
        assert!(matches!(
            ok(b_captoken_verify(&[text(&t), text("otra")])),
            SynValue::Nothing
        ));
        // Un TTL corto por defecto vino puesto.
        let cav = verified_map(&m.get("caveats").unwrap().clone());
        assert!(!matches!(cav.get("exp"), Some(SynValue::Nothing)), "exp por defecto");
    }

    #[test]
    fn attenuate_narrows_without_the_root_key() {
        // El orquestador tiene net(*.example.com) + db(rw) + spend 100 USD.
        let t = mint(
            map(vec![
                ("net", text("*.example.com")),
                ("db", text("postgres://localhost/appdb")),
                ("spend", text("USD")),
            ]),
            map(vec![("ttl", syn_int(3600)), ("spend", map(vec![("USD", syn_int(100))]))]),
        );
        // Delega al subagente: sólo un host concreto, sin db, spend 10, ttl 300.
        // NOTA: no se pasa la clave raíz — ese es el punto.
        let t2 = ok(b_captoken_attenuate(&[
            text(&t),
            map(vec![("net", text("api.example.com")), ("spend", text("USD"))]),
            map(vec![("ttl", syn_int(300)), ("spend", map(vec![("USD", syn_int(10))]))]),
        ]))
        .to_string();
        assert_ne!(t, t2);

        let v = ok(b_captoken_verify(&[text(&t2), text(KEY)]));
        let m = verified_map(&v);
        assert_eq!(m.get("depth").unwrap().to_string(), "2");
        let caps = verified_map(&m.get("caps").unwrap().clone());
        assert!(!caps.contains_key("db"), "la db quedó fuera de la delegación");
        let cav = verified_map(&m.get("caveats").unwrap().clone());
        let sp = verified_map(&cav.get("spend").unwrap().clone());
        assert_eq!(sp.get("USD").unwrap().to_string(), "10", "el techo bajó");

        // El token atenuado ya NO habilita la db, pero sí su host.
        assert!(matches!(
            ok(b_captoken_allows(&[v.clone(), text("net"), text("api.example.com")])),
            SynValue::Bool(true)
        ));
        assert!(matches!(
            ok(b_captoken_allows(&[v.clone(), text("db"), text("postgres://localhost/appdb")])),
            SynValue::Bool(false)
        ));
        // Y tampoco un host distinto del delegado (aunque el padre lo cubría).
        assert!(matches!(
            ok(b_captoken_allows(&[v, text("net"), text("otro.example.com")])),
            SynValue::Bool(false)
        ));
    }

    #[test]
    fn attenuation_can_never_widen() {
        let t = mint(
            map(vec![("net", text("api.example.com"))]),
            map(vec![("ttl", syn_int(300))]),
        );
        // (1) Capability nueva que el padre no tiene.
        assert!(b_captoken_attenuate(&[
            text(&t),
            map(vec![("net", text("api.example.com")), ("exec", SynValue::Nothing)]),
            SynValue::Nothing
        ])
        .is_err());
        // (2) Scope más ancho (glob que cubre más que el padre).
        assert!(b_captoken_attenuate(&[
            text(&t),
            map(vec![("net", text("*.example.com"))]),
            SynValue::Nothing
        ])
        .is_err());
        // (3) Host distinto.
        assert!(b_captoken_attenuate(&[
            text(&t),
            map(vec![("net", text("evil.com"))]),
            SynValue::Nothing
        ])
        .is_err());
        // (4) Quitar el scope (pedir la capability entera).
        assert!(b_captoken_attenuate(&[
            text(&t),
            map(vec![("net", SynValue::Nothing)]),
            SynValue::Nothing
        ])
        .is_err());
        // (5) TTL más largo que el del padre.
        assert!(b_captoken_attenuate(&[
            text(&t),
            map(vec![("net", text("api.example.com"))]),
            map(vec![("ttl", syn_int(86400))])
        ])
        .is_err());
        // (6) Subir el techo de gasto.
        let t_spend = mint(
            map(vec![("spend", text("USD"))]),
            map(vec![("spend", map(vec![("USD", syn_int(10))]))]),
        );
        assert!(b_captoken_attenuate(&[
            text(&t_spend),
            map(vec![("spend", text("USD"))]),
            map(vec![("spend", map(vec![("USD", syn_int(1000))]))])
        ])
        .is_err());
        // (7) Lo LEGAL sí pasa: mismo scope, ttl menor.
        assert!(b_captoken_attenuate(&[
            text(&t),
            map(vec![("net", text("api.example.com"))]),
            map(vec![("ttl", syn_int(60))])
        ])
        .is_ok());
    }

    #[test]
    fn tampering_breaks_the_chain() {
        let t = mint(map(vec![("net", text("api.example.com"))]), SynValue::Nothing);
        let raw = b64url_decode(&t).unwrap();

        // (1) Un byte cambiado en cualquier posición → nothing (nunca un panic).
        for i in 0..raw.len() {
            let mut bad = raw.clone();
            bad[i] ^= 0xff;
            let out = ok(b_captoken_verify(&[text(&b64url_encode(&bad)), text(KEY)]));
            assert!(
                matches!(out, SynValue::Nothing),
                "byte {} alterado no fue rechazado",
                i
            );
        }
        // (2) Truncado.
        let out = ok(b_captoken_verify(&[text(&b64url_encode(&raw[..raw.len() / 2])), text(KEY)]));
        assert!(matches!(out, SynValue::Nothing));
        // (3) Basura y vacío.
        assert!(matches!(ok(b_captoken_verify(&[text("no-es-token"), text(KEY)])), SynValue::Nothing));
        assert!(matches!(ok(b_captoken_verify(&[text(""), text(KEY)])), SynValue::Nothing));
    }

    #[test]
    fn forged_widening_block_is_rejected_at_verify() {
        // Un portador que conoce sig_n PUEDE firmar un bloque nuevo (así funciona
        // la delegación). Si forja uno que AMPLÍA, la firma cierra pero el verify
        // lo rechaza igual: la cadena debe ser monótona decreciente.
        let t = mint(map(vec![("net", text("api.example.com"))]), SynValue::Nothing);
        let mut tok = decode_token(&t).unwrap();
        let wide = Block {
            caps: vec![("exec".to_string(), vec![])],
            caveats: tok.blocks[0].caveats.clone(),
        };
        let sig = hmac_compute(Algo::Sha256, &tok.sig, &block_bytes(tok.blocks.len(), &wide));
        tok.blocks.push(wide);
        tok.sig = sig;
        let forged = encode_token(&tok);
        assert!(
            matches!(ok(b_captoken_verify(&[text(&forged), text(KEY)])), SynValue::Nothing),
            "un bloque que amplía debe rechazarse aunque la firma cierre"
        );
    }

    #[test]
    fn expiry_and_revocation() {
        let t = mint(map(vec![("net", text("x.com"))]), map(vec![("ttl", syn_int(60))]));
        // Dentro de la ventana.
        assert!(matches!(
            ok(b_captoken_verify(&[text(&t), text(KEY)])),
            SynValue::Map(_)
        ));
        // Pasado el exp → nothing.
        let future = map(vec![("at", syn_int(unix_now() + 3600))]);
        assert!(matches!(
            ok(b_captoken_verify(&[text(&t), text(KEY), future])),
            SynValue::Nothing
        ));
        // Revocado por id (denylist).
        let v = ok(b_captoken_verify(&[text(&t), text(KEY)]));
        let id = verified_map(&v).get("id").unwrap().to_string();
        let revoked = map(vec![("revoked", syn_list(vec![text(&id)]))]);
        assert!(matches!(
            ok(b_captoken_verify(&[text(&t), text(KEY), revoked])),
            SynValue::Nothing
        ));
        // Otra id en la denylist no lo afecta.
        let other = map(vec![("revoked", syn_list(vec![text("otra-id")]))]);
        assert!(matches!(
            ok(b_captoken_verify(&[text(&t), text(KEY), other])),
            SynValue::Map(_)
        ));
    }

    #[test]
    fn contextual_caveats_are_fail_closed() {
        let t = mint(
            map(vec![("net", text("x.com"))]),
            map(vec![("aud", text("api-1")), ("method", text("post"))]),
        );
        // Contexto correcto → vale.
        let good = map(vec![("aud", text("api-1")), ("method", text("POST"))]);
        assert!(matches!(
            ok(b_captoken_verify(&[text(&t), text(KEY), good])),
            SynValue::Map(_)
        ));
        // Audiencia equivocada → nothing.
        let bad_aud = map(vec![("aud", text("api-2")), ("method", text("POST"))]);
        assert!(matches!(
            ok(b_captoken_verify(&[text(&t), text(KEY), bad_aud])),
            SynValue::Nothing
        ));
        // Método equivocado → nothing.
        let bad_m = map(vec![("aud", text("api-1")), ("method", text("GET"))]);
        assert!(matches!(
            ok(b_captoken_verify(&[text(&t), text(KEY), bad_m])),
            SynValue::Nothing
        ));
        // Contexto AUSENTE con caveat presente → nothing (fail-closed: no se puede
        // afirmar que se cumple lo que no se chequeó).
        assert!(matches!(
            ok(b_captoken_verify(&[text(&t), text(KEY)])),
            SynValue::Nothing
        ));
    }

    #[test]
    fn effective_caveats_take_the_strictest_of_the_chain() {
        let t = mint(
            map(vec![("net", text("*.example.com")), ("spend", text("USD"))]),
            map(vec![("ttl", syn_int(3600)), ("spend", map(vec![("USD", syn_int(100))]))]),
        );
        let t2 = ok(b_captoken_attenuate(&[
            text(&t),
            map(vec![("net", text("a.example.com")), ("spend", text("USD"))]),
            map(vec![("ttl", syn_int(60)), ("spend", map(vec![("USD", syn_int(5))]))]),
        ]))
        .to_string();
        let t3 = ok(b_captoken_attenuate(&[
            text(&t2),
            map(vec![("net", text("a.example.com")), ("spend", text("USD"))]),
            SynValue::Nothing,
        ]))
        .to_string();
        // El tercer bloque no declara nada: hereda lo más restrictivo (5 USD, 60 s).
        let m = verified_map(&ok(b_captoken_verify(&[text(&t3), text(KEY)])));
        let cav = verified_map(&m.get("caveats").unwrap().clone());
        let sp = verified_map(&cav.get("spend").unwrap().clone());
        assert_eq!(sp.get("USD").unwrap().to_string(), "5");
        assert_eq!(m.get("depth").unwrap().to_string(), "3");
    }

    #[test]
    fn mint_fails_strong_on_bad_input() {
        // Capability inexistente (typo) → error, no una cap muda.
        assert!(b_captoken_mint(&[map(vec![("nett", text("x"))]), text(KEY)]).is_err());
        // Caps vacíos.
        assert!(b_captoken_mint(&[map(vec![]), text(KEY)]).is_err());
        // Caveat desconocido.
        assert!(b_captoken_mint(&[
            map(vec![("net", text("x"))]),
            text(KEY),
            map(vec![("expires", syn_int(5))])
        ])
        .is_err());
        // Monto de spend inválido / negativo.
        assert!(b_captoken_mint(&[
            map(vec![("spend", text("USD"))]),
            text(KEY),
            map(vec![("spend", map(vec![("USD", text("mucho"))]))])
        ])
        .is_err());
        assert!(b_captoken_mint(&[
            map(vec![("spend", text("USD"))]),
            text(KEY),
            map(vec![("spend", map(vec![("USD", syn_int(-1))]))])
        ])
        .is_err());
        // Atenuar exige texto (y NO acepta la clave raíz como 2º argumento).
        assert!(b_captoken_attenuate(&[syn_int(5), map(vec![("net", text("x"))])]).is_err());
    }

    #[test]
    fn depth_is_bounded() {
        let mut t = mint(map(vec![("net", text("x.com"))]), map(vec![("ttl", syn_int(600))]));
        for _ in 1..MAX_DEPTH {
            t = ok(b_captoken_attenuate(&[
                text(&t),
                map(vec![("net", text("x.com"))]),
                SynValue::Nothing,
            ]))
            .to_string();
        }
        // El bloque MAX_DEPTH+1 se rechaza con un error claro.
        assert!(b_captoken_attenuate(&[
            text(&t),
            map(vec![("net", text("x.com"))]),
            SynValue::Nothing
        ])
        .is_err());
        // Y el token de profundidad máxima sigue verificando.
        assert!(matches!(
            ok(b_captoken_verify(&[text(&t), text(KEY)])),
            SynValue::Map(_)
        ));
    }

    #[test]
    fn canonical_encoding_is_stable() {
        // El mismo contenido con las claves en otro orden produce los MISMOS bytes
        // canónicos (si no, la firma dependería del orden de inserción del map).
        let a = Block {
            caps: vec![
                ("db".to_string(), vec!["x".to_string()]),
                ("net".to_string(), vec!["a".to_string(), "b".to_string()]),
            ],
            caveats: Caveats { exp: Some(10), ..Default::default() },
        };
        let b = Block {
            caps: vec![
                ("net".to_string(), vec!["b".to_string(), "a".to_string()]),
                ("db".to_string(), vec!["x".to_string()]),
            ],
            caveats: Caveats { exp: Some(10), ..Default::default() },
        };
        assert_eq!(block_bytes(0, &a), block_bytes(0, &b));
        // Y el índice entra en la preimagen (un bloque no puede moverse de lugar).
        assert_ne!(block_bytes(0, &a), block_bytes(1, &a));
    }

    #[test]
    fn allows_handles_nothing_and_wildcards() {
        // captoken_allows sobre `nothing` (token rechazado) es false, no un error:
        // el idioma `when captoken_allows(captoken_verify(t, k), "net", h)` fluye.
        assert!(matches!(
            ok(b_captoken_allows(&[SynValue::Nothing, text("net"), text("x")])),
            SynValue::Bool(false)
        ));
        // Capability sin scope en el token = wildcard de ese tipo.
        let t = mint(map(vec![("reveal", SynValue::Nothing)]), SynValue::Nothing);
        let v = ok(b_captoken_verify(&[text(&t), text(KEY)]));
        assert!(matches!(
            ok(b_captoken_allows(&[v.clone(), text("reveal"), text("CUALQUIERA")])),
            SynValue::Bool(true)
        ));
        assert!(matches!(
            ok(b_captoken_allows(&[v, text("net"), text("x")])),
            SynValue::Bool(false)
        ));
    }
}

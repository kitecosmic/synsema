//! v0.6.46 (E6) — el sobre del recibo sellado: HPKE (RFC 9180) en modo base, con
//! `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256` y `AES-128-GCM`. Es el estándar de MLS, ECH y OHTTP,
//! y la crate `hpke` se fija con los vectores oficiales del RFC (apéndice A.1.1, test de abajo).
//!
//! **De tamaño fijo:** el texto plano es `largo (u32 BE) ‖ contenido ‖ ceros` hasta `size` bytes, así
//! que el sobre mide siempre `32 (enc) + size + 16 (tag)`, entre cero y la capacidad entera de
//! entradas. Quien arma el contenido trunca ADENTRO (y lo anota) antes de llegar al tope: pasarse acá
//! es un error del motor, no del programa.
//!
//! La clave del auditor es una pública X25519 de 32 bytes en base64url (`--auditor`,
//! `SYNSEMA_AUDITOR_KEY`). El auditor guarda la privada: con ella, `open_fixed` devuelve el contenido.

use hpke::aead::AesGcm128;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};

use synsema_core::bytesutil::{b64url_decode, b64url_encode};

/// El nombre de la suite, tal cual va en el header del recibo.
pub const SUITE: &str = "HPKE-Base-X25519-SHA256-AES128GCM";
/// El `info` de HPKE: separa este uso de cualquier otro sobre a la misma clave.
pub const INFO: &[u8] = b"synsema-receipt-v1";
/// El tamaño del texto plano por defecto (`SYNSEMA_RECEIPT_SEALED_BYTES`).
pub const DEFAULT_SEALED_BYTES: usize = 64 * 1024;
/// Lo que ocupa el largo al principio del texto plano.
pub const LEN_PREFIX: usize = 4;

/// Un sobre: la clave encapsulada (`enc`) y el texto cifrado con su tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub enc: [u8; 32],
    pub ct: Vec<u8>,
}

impl Envelope {
    /// `enc ‖ ct`, que es lo que viaja (en base64url).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.ct.len());
        out.extend_from_slice(&self.enc);
        out.extend_from_slice(&self.ct);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Envelope, String> {
        if b.len() < 32 + LEN_PREFIX + 16 {
            return Err(format!("sealed envelope too short ({} bytes)", b.len()));
        }
        let mut enc = [0u8; 32];
        enc.copy_from_slice(&b[..32]);
        Ok(Envelope { enc, ct: b[32..].to_vec() })
    }
}

/// El RNG de HPKE (los traits de `rand_core` 0.9 que re-exporta la crate) sobre una función que
/// llena bytes: la entropía del SO en el uso real, bytes fijos en el test de los vectores.
struct FillRng<F: FnMut(&mut [u8])>(F);

impl<F: FnMut(&mut [u8])> hpke::rand_core::RngCore for FillRng<F> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        (self.0)(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        (self.0)(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        (self.0)(dst)
    }
}

impl<F: FnMut(&mut [u8])> hpke::rand_core::CryptoRng for FillRng<F> {}

fn os_fill(buf: &mut [u8]) {
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, buf);
}

/// La pública del auditor (base64url, 32 bytes).
pub fn parse_auditor_key(b64: &str) -> Result<[u8; 32], String> {
    let raw = b64url_decode(b64.trim()).map_err(|e| format!("the auditor key is not base64url: {}", e))?;
    let key: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("the auditor key must be an X25519 public key of 32 bytes, got {}", raw.len()))?;
    <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&key).map_err(|_| "the auditor key is not a valid X25519 public key".to_string())?;
    // Ronda 1 (E6-B1): una clave de orden bajo (todos ceros) pasa `from_bytes` y falla recién al
    // sellar, con el programa ya corrido: se prueba ahora con un sobre mínimo.
    seal_fixed(&key, b"", LEN_PREFIX, b"probe").map_err(|_| "the auditor key cannot seal (a low-order X25519 point, such as all zeros): ask the auditor for the public key of `synsema receipt keygen`".to_string())?;
    Ok(key)
}

/// Un par de claves nuevo para un auditor: `(privada, pública)` en base64url.
pub fn generate_keypair() -> (String, String) {
    let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut FillRng(os_fill));
    (b64url_encode(&sk.to_bytes()), b64url_encode(&pk.to_bytes()))
}

fn seal_with<F: FnMut(&mut [u8])>(pk: &[u8; 32], content: &[u8], size: usize, aad: &[u8], rng: F) -> Result<Envelope, String> {
    if size < LEN_PREFIX || content.len() > size - LEN_PREFIX {
        return Err(format!("sealed content of {} bytes does not fit in {} (the engine truncates before sealing)", content.len(), size));
    }
    let pk = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(pk).map_err(|_| "the auditor key is not a valid X25519 public key".to_string())?;
    let mut plain = vec![0u8; size];
    plain[..LEN_PREFIX].copy_from_slice(&(content.len() as u32).to_be_bytes());
    plain[LEN_PREFIX..LEN_PREFIX + content.len()].copy_from_slice(content);
    let (enc, ct) = hpke::single_shot_seal::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(&OpModeS::Base, &pk, INFO, &plain, aad, &mut FillRng(rng))
        .map_err(|e| format!("sealing the receipt failed: {:?}", e))?;
    let mut e = [0u8; 32];
    e.copy_from_slice(&enc.to_bytes());
    Ok(Envelope { enc: e, ct })
}

/// Sella `content` para la pública `pk` en un texto plano de exactamente `size` bytes. `aad` lo ata a
/// lo que va afuera (el hash del header).
pub fn seal_fixed(pk: &[u8; 32], content: &[u8], size: usize, aad: &[u8]) -> Result<Envelope, String> {
    seal_with(pk, content, size, aad, os_fill)
}

/// Abre un sobre con la privada del auditor (32 bytes) y devuelve el contenido sin el relleno.
pub fn open_fixed(sk: &[u8], env: &Envelope, aad: &[u8]) -> Result<Vec<u8>, String> {
    let sk = <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(sk).map_err(|_| "the auditor private key must be 32 bytes".to_string())?;
    let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&env.enc).map_err(|_| "the envelope's encapsulated key is not valid".to_string())?;
    let plain = hpke::single_shot_open::<AesGcm128, HkdfSha256, X25519HkdfSha256>(&OpModeR::Base, &sk, &enc, INFO, &env.ct, aad)
        .map_err(|_| "the envelope does not open with this key (wrong key, or the envelope or the header was changed)".to_string())?;
    if plain.len() < LEN_PREFIX {
        return Err("the envelope's plaintext is shorter than its length prefix".to_string());
    }
    let n = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
    if n > plain.len() - LEN_PREFIX {
        return Err("the envelope's length prefix is larger than its plaintext".to_string());
    }
    Ok(plain[LEN_PREFIX..LEN_PREFIX + n].to_vec())
}

// =========================================================
// El recibo (E6.3): header + public + sealed, encadenado y firmado
// =========================================================

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use synsema_core::bytesutil::hex_encode;
use synsema_core::sealed::{RunLog, SharedLog};

/// El dominio de la cadena y de la firma.
pub const DOMAIN: &str = "synsema-receipt-v1";
/// El tope de `SYNSEMA_RECEIPT_SEALED_BYTES`: el sobre viaja entero en el recibo.
pub const MAX_SEALED_BYTES: usize = 16 * 1024 * 1024;

/// Una lectura del reloj como texto, en la forma más corta que vuelve al mismo f64 (la de `ryu`, la
/// que escribe `serde_json`). `str::parse` la lee de vuelta exacta.
fn clock_text(c: f64) -> String {
    serde_json::Number::from_f64(c).map(|n| n.to_string()).unwrap_or_else(|| "0".to_string())
}

/// JSON canónico (RFC 8785) de lo que escribe el motor: claves ordenadas, sin espacios. El
/// `serde_json` del árbol conserva el orden de inserción (`preserve_order`), así que sin esto un
/// verificador que vuelve a serializar el recibo obtendría otros bytes. Las claves son ASCII y los
/// números los escribe `serde_json` (enteros): coinciden con JCS. El reloj va como texto.
pub fn jcs(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::String(k.clone()), jcs(&m[k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(jcs).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// `SYNSEMA_RECEIPT_SEALED_BYTES` (el host, nunca el programa): el tamaño del texto plano del sobre.
pub fn sealed_bytes_from(raw: Option<&str>) -> Result<usize, String> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(DEFAULT_SEALED_BYTES);
    };
    let n: usize = raw.parse().map_err(|_| format!("SYNSEMA_RECEIPT_SEALED_BYTES must be a number of bytes, got {:?}", raw))?;
    let min = synsema_core::sealed::ENVELOPE_RESERVE * 4;
    if !(min..=MAX_SEALED_BYTES).contains(&n) {
        return Err(format!("SYNSEMA_RECEIPT_SEALED_BYTES must be between {} and {}, got {}", min, MAX_SEALED_BYTES, n));
    }
    Ok(n)
}

/// Un registro nuevo para una corrida con auditor, con su semilla ya fijada (el header se compromete
/// con ella aunque el programa no llame a `random()`: la forma no cambia).
pub fn new_run_log(capacity: usize) -> SharedLog {
    let mut log = RunLog::new(capacity);
    let mut s = [0u8; 32];
    os_fill(&mut s);
    log.seed = Some(hex_encode(&s));
    std::sync::Arc::new(std::sync::Mutex::new(log))
}

/// La clave que firma el recibo: la de identidad del host (`SYNSEMA_IDENTITY_KEY`, Ed25519) o una
/// efímera de la corrida. La efímera prueba integridad, no identidad, y el header lo dice.
/// Bajo `serve --attested`, la clave atestada (P-256): la que firma la Agent Card y la que nombra
/// el documento de la plataforma.
pub struct RunKey {
    sk: RunSigner,
    pub identity: &'static str,
}

enum RunSigner {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl RunKey {
    pub fn ephemeral() -> RunKey {
        let mut seed = [0u8; 32];
        os_fill(&mut seed);
        RunKey { sk: RunSigner::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed)), identity: "ephemeral" }
    }

    pub fn from_identity_seed(seed: &[u8; 32]) -> RunKey {
        RunKey { sk: RunSigner::Ed25519(ed25519_dalek::SigningKey::from_bytes(seed)), identity: "identity" }
    }

    /// El escalar P-256 de la identidad atestada de `serve --attested`.
    pub fn from_attested_scalar(scalar: &[u8]) -> Result<RunKey, String> {
        let sk = p256::ecdsa::SigningKey::from_slice(scalar).map_err(|_| "the attested key is not a valid P-256 scalar".to_string())?;
        Ok(RunKey { sk: RunSigner::P256(sk), identity: "attested" })
    }

    /// `Ed25519` o `P-256`, como va en `header.run_key.alg`.
    pub fn alg(&self) -> &'static str {
        match self.sk {
            RunSigner::Ed25519(_) => "Ed25519",
            RunSigner::P256(_) => "P-256",
        }
    }

    /// La pública: 32 bytes (Ed25519) o el punto SEC1 comprimido de 33 (P-256).
    pub fn public_bytes(&self) -> Vec<u8> {
        match &self.sk {
            RunSigner::Ed25519(k) => k.verifying_key().to_bytes().to_vec(),
            RunSigner::P256(k) => k.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
        }
    }

    /// Ed25519: 64 bytes. P-256: ECDSA sobre SHA-256, `r ‖ s` de 64 bytes.
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match &self.sk {
            RunSigner::Ed25519(k) => ed25519_dalek::Signer::sign(k, msg).to_bytes().to_vec(),
            RunSigner::P256(k) => {
                let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(k, msg);
                sig.to_bytes().to_vec()
            }
        }
    }
}

/// Verifica la firma de `msg` con la pública del header según su `alg`.
fn verify_run_signature(alg: &str, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    const BAD: &str = "the receipt's signature does not verify (the header, the public part, the envelope or the root was changed)";
    match alg {
        "Ed25519" => {
            let pk: [u8; 32] = pk.try_into().map_err(|_| "run_key.public is not 32 bytes")?;
            let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_| "run_key.public is not an Ed25519 key")?;
            let sig: [u8; 64] = sig.try_into().map_err(|_| "the signature is not 64 bytes")?;
            pk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig)).map_err(|_| BAD.to_string())
        }
        "P-256" => {
            let pk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk).map_err(|_| "run_key.public is not a P-256 key")?;
            let sig = p256::ecdsa::Signature::from_slice(sig).map_err(|_| "the signature is not 64 bytes of r ‖ s")?;
            p256::ecdsa::signature::Verifier::verify(&pk, msg, &sig).map_err(|_| BAD.to_string())
        }
        other => Err(format!("unknown run_key.alg {:?}", other)),
    }
}

/// Lo que el host sabe de la corrida y va al header.
pub struct ReceiptContext<'a> {
    pub auditor: [u8; 32],
    pub key: &'a RunKey,
    pub program_sha: Option<String>,
    pub config_sha: Option<String>,
    /// v0.6.49 (ronda 1, M3): el sha256 de cada módulo `--trusted` (`{nombre: sha}`), o `None` si
    /// la corrida no tuvo. `--replay` lo compara como a `program_sha`.
    pub trusted: Option<serde_json::Value>,
    pub started: String,
}

/// Todas las entradas en el orden de la corrida: cada sellada lleva `after`, cuántas públicas la
/// preceden (la parte pública no lleva posiciones: un número de secuencia afuera diría cuántas
/// selladas hubo antes). Devuelve `(sellada, entrada)`.
fn merged(public: &[Value], sealed: &[(u64, Value)]) -> Vec<(bool, Value)> {
    let mut out = Vec::with_capacity(public.len() + sealed.len());
    let mut s = sealed.iter().peekable();
    for (k, p) in public.iter().enumerate() {
        while let Some((_, e)) = s.next_if(|(after, _)| *after as usize <= k) {
            out.push((true, e.clone()));
        }
        out.push((false, p.clone()));
    }
    out.extend(s.map(|(_, e)| (true, e.clone())));
    out
}

/// `h_0 = sha256(DOMAIN ‖ jcs(header))`, `h_i = sha256(h_{i-1} ‖ tipo_i ‖ jcs(entrada_i))`, con
/// `tipo` = `P` (pública) o `S` (sellada).
fn chain_root(header: &Value, entries: &[(bool, Value)]) -> [u8; 32] {
    let mut h = sha(&[DOMAIN.as_bytes(), jcs(header).as_bytes()].concat());
    for (sealed, e) in entries {
        let tag: &[u8] = if *sealed { b"S" } else { b"P" };
        h = Sha256::new().chain_update(h).chain_update(tag).chain_update(jcs(e).as_bytes()).finalize().into();
    }
    h
}

/// Lo que firma la clave de la corrida: `DOMAIN ‖ sha256(jcs(header)) ‖ sha256(jcs(public)) ‖
/// sha256(sobre) ‖ raíz`.
fn signed_message(header: &Value, public: &Value, sealed: &[u8], root: &[u8; 32]) -> Vec<u8> {
    let mut m = DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(&sha(jcs(header).as_bytes()));
    m.extend_from_slice(&sha(jcs(public).as_bytes()));
    m.extend_from_slice(&sha(sealed));
    m.extend_from_slice(root);
    m
}

fn parse_entries(list: &[(u64, String)]) -> Vec<(u64, Value)> {
    list.iter()
        .map(|(s, e)| (*s, serde_json::from_str(e).unwrap_or_else(|_| Value::String(e.clone()))))
        .collect()
}

/// v0.6.49 (ronda 1, M3): el `trusted` del encabezado: el sha256 de cada módulo de confianza
/// (`{nombre: sha}`), o `None` si la corrida no tuvo.
pub fn trusted_shas(modules: &[(String, String)], templates: &[(String, Vec<(String, String)>)]) -> Option<Value> {
    if modules.is_empty() {
        return None;
    }
    let map: Map<String, Value> = modules
        .iter()
        .map(|(name, src)| {
            let tpl = templates.iter().find(|(n, _)| n == name).map(|(_, f)| f.as_slice()).filter(|f| !f.is_empty());
            (name.clone(), Value::String(hex_encode(&trusted_tool_sha(src, tpl))))
        })
        .collect();
    Some(Value::Object(map))
}

/// v0.6.50 (D15): el sha de una tool. Sin templates, el de su fuente (como siempre); con templates
/// (`--trusted-templates`, parte de su política), el de fuente y templates en una codificación
/// canónica: un prefijo de versión y cada campo con su longitud, los templates por nombre.
fn trusted_tool_sha(source: &str, templates: Option<&[(String, String)]>) -> [u8; 32] {
    let Some(files) = templates else {
        return Sha256::digest(source.as_bytes()).into();
    };
    let mut h = Sha256::new();
    let field = |h: &mut Sha256, b: &[u8]| {
        h.update((b.len() as u64).to_be_bytes());
        h.update(b);
    };
    h.update(b"synsema-trusted-tool-v1\0");
    field(&mut h, source.as_bytes());
    let mut sorted: Vec<&(String, String)> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, text) in sorted {
        field(&mut h, name.as_bytes());
        field(&mut h, text.as_bytes());
    }
    h.finalize().into()
}

/// Arma el recibo sellado de la corrida que registró `log`.
pub fn build_receipt(log: &RunLog, ctx: &ReceiptContext<'_>) -> Result<Value, String> {
    let public_seq = parse_entries(&log.public);
    let public: Vec<Value> = public_seq.iter().map(|(_, e)| e.clone()).collect();
    // La posición de cada sellada, en públicas que la preceden.
    let sealed: Vec<(u64, Value)> = parse_entries(&log.sealed)
        .into_iter()
        .map(|(s, e)| (public_seq.iter().filter(|(ps, _)| *ps < s).count() as u64, e))
        .collect();
    let seed = log.seed.clone().unwrap_or_default();
    let seed_raw = synsema_core::bytesutil::hex_decode(&seed).unwrap_or_default();
    let size = log.capacity();
    let header = json!({
        "v": 1,
        "suite": SUITE,
        "engine": crate::attest::engine_version(),
        "program_sha": ctx.program_sha,
        "config_sha": ctx.config_sha,
        "trusted": ctx.trusted,
        "started": ctx.started,
        "run_key": {"alg": ctx.key.alg(), "public": b64url_encode(&ctx.key.public_bytes()), "identity": ctx.key.identity},
        "auditor": b64url_encode(&ctx.auditor),
        "seed_sha256": hex_encode(&sha(&seed_raw)),
        "public_entries": public.len(),
        "sealed_bytes": size,
    });
    let public_v = Value::Array(public.clone());
    // Lo que no entra se corta ADENTRO y se cuenta: el tamaño de afuera no cambia nunca. El registro
    // ya cortó al anotar (el reloj con tope propio); esto cubre lo que la estimación no vio. v0.6.46
    // (ronda 1, E6-M1): primero el reloj y después las entradas, de las últimas para atrás (son lo que
    // el auditor necesita ver), en una pasada con los tamaños de cada una: re-serializar en cada vuelta
    // era cuadrático.
    let entry_v = |(a, e): &(u64, Value)| json!({"after": a, "entry": e});
    let entry_sizes: Vec<usize> = sealed.iter().map(|x| jcs(&entry_v(x)).len() + 1).collect();
    // Ronda final de v0.6.46: cada lectura va como TEXTO (la forma más corta que vuelve al mismo
    // f64). Como número, `serde_json` la leía de vuelta a veces con un bit de diferencia (sin
    // `float_roundtrip`) y `--replay` daba otra hora; `str::parse` redondea bien.
    let clock: Vec<Value> = log.clock.iter().map(|c| Value::String(clock_text(*c))).collect();
    let clock_sizes: Vec<usize> = clock.iter().map(|c| jcs(c).len() + 1).collect();
    let empty = json!({"entries": [], "seed": seed, "clock": [], "truncated": u64::MAX, "clock_truncated": u64::MAX});
    let budget = size.saturating_sub(LEN_PREFIX);
    let mut total = jcs(&empty).len() + entry_sizes.iter().sum::<usize>() + clock_sizes.iter().sum::<usize>();
    let (mut n_entries, mut n_clock) = (sealed.len(), log.clock.len());
    while total > budget && n_clock > 0 {
        n_clock -= 1;
        total -= clock_sizes[n_clock];
    }
    while total > budget && n_entries > 0 {
        n_entries -= 1;
        total -= entry_sizes[n_entries];
    }
    let content_of = |n_entries: usize, n_clock: usize| {
        let mut c = json!({
            "entries": sealed[..n_entries].iter().map(entry_v).collect::<Vec<_>>(),
            "seed": seed,
            "clock": &clock[..n_clock],
            "truncated": log.truncated + (sealed.len() - n_entries) as u64,
        });
        let clock_cut = log.clock_dropped + (log.clock.len() - n_clock) as u64;
        if clock_cut > 0 {
            c["clock_truncated"] = json!(clock_cut);
        }
        c
    };
    let mut content = content_of(n_entries, n_clock);
    // La estimación es por arriba (los contadores con su largo máximo): si igual no entra, se sigue
    // de a una, como antes.
    while jcs(&content).len() + LEN_PREFIX > size {
        if n_clock > 0 {
            n_clock -= 1;
        } else if n_entries > 0 {
            n_entries -= 1;
        } else {
            return Err("the sealed receipt does not fit even empty: raise SYNSEMA_RECEIPT_SEALED_BYTES".to_string());
        }
        content = content_of(n_entries, n_clock);
    }
    let kept = &sealed[..n_entries];
    let aad = sha(jcs(&header).as_bytes());
    let env = seal_fixed(&ctx.auditor, jcs(&content).as_bytes(), size, &aad)?;
    let env_bytes = env.to_bytes();
    let root = chain_root(&header, &merged(&public, kept));
    let msg = signed_message(&header, &public_v, &env_bytes, &root);
    let sig = ctx.key.sign(&msg);
    let mut out = Map::new();
    out.insert("synsema_receipt".into(), json!(1));
    out.insert("header".into(), header);
    out.insert("public".into(), public_v);
    out.insert("sealed".into(), json!(b64url_encode(&env_bytes)));
    out.insert("root".into(), json!(hex_encode(&root)));
    out.insert("signature".into(), json!(b64url_encode(&sig)));
    Ok(Value::Object(out))
}

struct Parts {
    header: Value,
    public: Value,
    env_bytes: Vec<u8>,
    root: [u8; 32],
}

fn parts(receipt: &Value) -> Result<Parts, String> {
    let header = receipt.get("header").cloned().ok_or("not a sealed receipt: no header")?;
    if receipt.get("synsema_receipt") != Some(&json!(1)) || header.get("v") != Some(&json!(1)) {
        return Err("not a sealed receipt of version 1".to_string());
    }
    let public = receipt.get("public").cloned().ok_or("not a sealed receipt: no public part")?;
    let env_bytes = b64url_decode(receipt.get("sealed").and_then(Value::as_str).ok_or("not a sealed receipt: no sealed part")?)
        .map_err(|e| format!("the sealed part is not base64url: {}", e))?;
    let root_hex = receipt.get("root").and_then(Value::as_str).ok_or("not a sealed receipt: no root")?;
    let root: [u8; 32] = synsema_core::bytesutil::hex_decode(root_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("the root is not 32 bytes of hex")?;
    let pk_b64 = header.pointer("/run_key/public").and_then(Value::as_str).ok_or("the header has no run_key.public")?;
    let pk = b64url_decode(pk_b64).map_err(|_| "run_key.public is not base64url")?;
    let alg = header.pointer("/run_key/alg").and_then(Value::as_str).ok_or("the header has no run_key.alg")?;
    let sig = b64url_decode(receipt.get("signature").and_then(Value::as_str).ok_or("not a sealed receipt: no signature")?)
        .map_err(|_| "the signature is not base64url")?;
    let msg = signed_message(&header, &public, &env_bytes, &root);
    verify_run_signature(alg, &pk, &msg, &sig)?;
    Ok(Parts { header, public, env_bytes, root })
}

/// Verifica la firma de un recibo sellado (lo puede hacer cualquiera, sin la privada del auditor).
/// Devuelve el header.
pub fn verify_receipt(receipt: &Value) -> Result<Value, String> {
    Ok(parts(receipt)?.header)
}

/// Abre un recibo con la privada del auditor: verifica la firma, descifra, recalcula la cadena sobre
/// las entradas públicas y selladas en orden y la compara con la raíz firmada. Devuelve
/// `{header, entries: [{seq, sealed, entry}], seed, clock, truncated}` (`seq`: la posición en la
/// corrida).
pub fn open_receipt(receipt: &Value, auditor_sk: &[u8]) -> Result<Value, String> {
    let p = parts(receipt)?;
    let aad = sha(jcs(&p.header).as_bytes());
    let content = open_fixed(auditor_sk, &Envelope::from_bytes(&p.env_bytes)?, &aad)?;
    let content: Value = serde_json::from_slice(&content).map_err(|e| format!("the envelope's content is not JSON: {}", e))?;
    let public: Vec<Value> = p.public.as_array().ok_or("the public part is not a list")?.clone();
    let sealed: Vec<(u64, Value)> = content
        .get("entries")
        .and_then(Value::as_array)
        .ok_or("the envelope has no entries")?
        .iter()
        .map(|v| -> Result<(u64, Value), String> {
            Ok((v.get("after").and_then(Value::as_u64).ok_or("a sealed entry has no position")?, v.get("entry").cloned().unwrap_or(Value::Null)))
        })
        .collect::<Result<_, _>>()?;
    let all = merged(&public, &sealed);
    if chain_root(&p.header, &all) != p.root {
        return Err("the chain does not verify: the entries are not the ones the run signed".to_string());
    }
    let seed = content.get("seed").cloned().unwrap_or(Value::Null);
    let seed_raw = seed.as_str().and_then(|s| synsema_core::bytesutil::hex_decode(s).ok()).unwrap_or_default();
    if p.header.get("seed_sha256").and_then(Value::as_str) != Some(hex_encode(&sha(&seed_raw)).as_str()) {
        return Err("the seed in the envelope is not the one the header commits to".to_string());
    }
    let mut out = Map::new();
    out.insert("header".into(), p.header);
    out.insert(
        "entries".into(),
        Value::Array(all.into_iter().enumerate().map(|(s, (sealed, e))| json!({"seq": s, "sealed": sealed, "entry": e})).collect()),
    );
    out.insert("seed".into(), seed);
    out.insert("clock".into(), content.get("clock").cloned().unwrap_or(json!([])));
    out.insert("truncated".into(), content.get("truncated").cloned().unwrap_or(json!(0)));
    if let Some(t) = content.get("clock_truncated") {
        out.insert("clock_truncated".into(), t.clone());
    }
    Ok(Value::Object(out))
}

// =========================================================
// E6-h: `serve --auditor` — un recibo por request, antes del body
// =========================================================

/// Adónde van los recibos de `serve`: una línea JSON por request.
enum ReceiptDest {
    Stderr,
    /// v0.6.49 (B11): la RUTA, que se abre para agregar en cada recibo. Con el archivo abierto una
    /// vez, borrarlo dejaba a `serve` escribiendo en un archivo sin nombre: los recibos se perdían
    /// en silencio. Abrir por request cuesta poco al lado de sellar el recibo.
    File(String),
    #[cfg(unix)]
    Fd(i32),
}

/// El recibo de `serve`: lo instala el runtime al arrancar, uno por proceso.
pub struct ServeReceipts {
    auditor: [u8; 32],
    size: usize,
    key: RunKey,
    program_sha: Option<String>,
    config_sha: Option<String>,
    dest: std::sync::Mutex<ReceiptDest>,
}

static SERVE_RECEIPTS: std::sync::OnceLock<ServeReceipts> = std::sync::OnceLock::new();

/// El registro de la request que atiende este hilo: `Some` desde que corrió código del programa
/// (auth, handler, handler de error) hasta que el job la cierra.
struct RequestLog {
    log: SharedLog,
    _guard: synsema_core::sealed::ThreadGuard,
    started: String,
}

thread_local! {
    static ARMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static REQUEST: std::cell::RefCell<Option<RequestLog>> = const { std::cell::RefCell::new(None) };
}

/// `serve --auditor`: instala los recibos del proceso. `dest`: `None` (stderr), `fd:N` (Unix) o una
/// ruta, que se abre para AGREGAR (cada request suma una línea).
pub fn install_serve_receipts(
    auditor: [u8; 32],
    size: usize,
    key: RunKey,
    program_sha: Option<String>,
    config_sha: Option<String>,
    dest: Option<&str>,
) -> Result<(), String> {
    let dest = match dest {
        None => ReceiptDest::Stderr,
        Some(fd) if fd.starts_with("fd:") => {
            let n: i32 = fd[3..].parse().map_err(|_| format!("--receipt: invalid fd '{}'", fd))?;
            #[cfg(unix)]
            {
                if n < 3 {
                    return Err("--receipt fd:N needs N >= 3 (0-2 are stdin/stdout/stderr)".to_string());
                }
                ReceiptDest::Fd(n)
            }
            #[cfg(not(unix))]
            {
                let _ = n;
                return Err("--receipt fd:N is only available on Unix; use --receipt <path>".to_string());
            }
        }
        Some(path) => {
            open_append(path).map_err(|e| format!("--receipt: cannot open {}: {}", path, e))?;
            ReceiptDest::File(path.to_string())
        }
    };
    SERVE_RECEIPTS
        .set(ServeReceipts { auditor, size, key, program_sha, config_sha, dest: std::sync::Mutex::new(dest) })
        .map_err(|_| "the serve receipts are already installed in this process".to_string())
}

fn open_append(path: &str) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().create(true).append(true).open(path)
}

/// ¿Corre `serve` con auditor?
#[inline]
pub fn serve_receipts_on() -> bool {
    SERVE_RECEIPTS.get().is_some()
}

/// El job de una request la abre (antes de `dispatch`): todavía no hay registro, nace con el primer
/// código del programa que corre para ella.
#[cold]
#[inline(never)]
pub fn request_arm() {
    ARMED.with(|a| a.set(true));
    REQUEST.with(|r| *r.borrow_mut() = None);
}

/// El runtime lo llama antes de correr código del programa en este hilo: si es el de una request
/// abierta y todavía no tiene registro, se lo instala. Fuera de una request (cron, agentes) no hace
/// nada: ahí no hay recibo, y lo que pide uno (un `audit` dentro de una rama privada) se rechaza.
#[cold]
#[inline(never)]
pub fn request_touch() {
    let Some(r) = SERVE_RECEIPTS.get() else { return };
    if !ARMED.with(|a| a.get()) {
        return;
    }
    REQUEST.with(|cell| {
        let mut cell = cell.borrow_mut();
        if cell.is_none() {
            let log = new_run_log(r.size);
            let guard = synsema_core::sealed::install_thread(log.clone());
            *cell = Some(RequestLog { log, _guard: guard, started: crate::receipt::rfc3339_utc(synsema_core::clock::now_secs()) });
        }
    });
}

/// Cierra la request de este hilo: si corrió código del programa, arma su recibo y lo escribe en el
/// destino. Se llama ANTES de mandar la respuesta: si falla, la respuesta no sale (el job manda un
/// 500 en su lugar).
#[cold]
#[inline(never)]
pub fn request_finish() -> Result<(), String> {
    ARMED.with(|a| a.set(false));
    let Some(req) = REQUEST.with(|r| r.borrow_mut().take()) else { return Ok(()) };
    let Some(r) = SERVE_RECEIPTS.get() else { return Ok(()) };
    let receipt = {
        let mut log = req.log.lock().unwrap_or_else(|p| p.into_inner());
        // v0.6.46 (ronda 1, E6-M2): un agente que lanzó la request lo sigue teniendo instalado.
        log.close();
        build_receipt(
            &log,
            &ReceiptContext {
                auditor: r.auditor,
                key: &r.key,
                program_sha: r.program_sha.clone(),
                config_sha: r.config_sha.clone(),
                trusted: None,
                started: req.started.clone(),
            },
        )?
    };
    drop(req);
    let line = format!("{}\n", receipt);
    use std::io::Write;
    let mut dest = r.dest.lock().unwrap_or_else(|p| p.into_inner());
    match &mut *dest {
        ReceiptDest::Stderr => {
            let mut e = std::io::stderr().lock();
            e.write_all(line.as_bytes()).and_then(|_| e.flush())
        }
        ReceiptDest::File(path) => open_append(path).and_then(|mut f| f.write_all(line.as_bytes()).and_then(|_| f.flush())),
        #[cfg(unix)]
        ReceiptDest::Fd(n) => {
            use std::os::unix::io::FromRawFd;
            // SAFETY: `n` es el descriptor de `--receipt fd:N` (N >= 3, abierto por el proceso padre);
            // el `File` va en `ManuallyDrop`, así que no se cierra ni se toma como propio.
            let mut f = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(*n) });
            f.write_all(line.as_bytes()).and_then(|_| f.flush())
        }
    }
    .map_err(|e| format!("the sealed receipt could not be written: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v0.6.50 (D15): el sha de una tool sin templates es el de su fuente (los recibos de antes
    /// siguen comparando); con templates los cubre, y cambiar uno lo cambia (el orden no).
    #[test]
    fn a_trusted_tool_sha_covers_its_templates() {
        let m = vec![("h".to_string(), "export task f()\n    give 1\n".to_string())];
        let plain = trusted_shas(&m, &[]).unwrap();
        assert_eq!(plain["h"], hex_encode(&Sha256::digest(m[0].1.as_bytes())));
        let t = |a: &str| vec![("h".to_string(), vec![("a.html".to_string(), a.to_string()), ("b.html".to_string(), "b".to_string())])];
        let with = trusted_shas(&m, &t("a")).unwrap();
        assert_ne!(with["h"], plain["h"]);
        assert_ne!(trusted_shas(&m, &t("a2")).unwrap()["h"], with["h"]);
        let reversed = vec![("h".to_string(), vec![("b.html".to_string(), "b".to_string()), ("a.html".to_string(), "a".to_string())])];
        assert_eq!(trusted_shas(&m, &reversed).unwrap()["h"], with["h"]);
        // Los templates de otra tool no cuentan.
        assert_eq!(trusted_shas(&m, &[("x".to_string(), vec![("a.html".to_string(), "a".to_string())])]).unwrap()["h"], plain["h"]);
    }

    /// Ronda final de v0.6.46: el CI vio `--replay` devolver `…7256043` donde la corrida leyó
    /// `…7256045`. Como texto, cada lectura vuelve bit a bit; como número, `serde_json` (sin
    /// `float_roundtrip`) no siempre.
    #[test]
    fn clock_readings_come_back_bit_for_bit() {
        let mut lossy = 0;
        let mut x = 1_792_711_237.725_604_5_f64;
        for i in 0..20_000u32 {
            let t = clock_text(x);
            assert_eq!(t.parse::<f64>().unwrap().to_bits(), x.to_bits(), "{}", t);
            let as_number: Value = serde_json::from_str(&serde_json::Number::from_f64(x).unwrap().to_string()).unwrap();
            if as_number.as_f64().unwrap().to_bits() != x.to_bits() {
                lossy += 1;
            }
            x += 0.000_123_457 * f64::from(i % 97 + 1);
        }
        assert!(lossy > 0, "control: como número JSON alguna lectura vuelve distinta");
    }
    use synsema_core::bytesutil::hex_decode;

    fn h(s: &str) -> Vec<u8> {
        hex_decode(s).unwrap()
    }

    /// RFC 9180, apéndice A.1.1 (modo base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM):
    /// con la efímera derivada de `ikmE` (la crate la deriva de 32 bytes del RNG), la clave
    /// encapsulada y el primer texto cifrado son los del RFC. Sobre el `info` y el `aad` del RFC, no
    /// los nuestros: lo que se fija es la primitiva.
    #[test]
    fn e6_hpke_vectors() {
        let info = h("4f6465206f6e2061204772656369616e2055726e");
        let ikm_e = h("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
        let ikm_r = h("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
        let (sk_r, pk_r) = X25519HkdfSha256::derive_keypair(&ikm_r);
        assert_eq!(pk_r.to_bytes().to_vec(), h("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"));
        assert_eq!(sk_r.to_bytes().to_vec(), h("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"));
        let pt = h("4265617574792069732074727574682c20747275746820626561757479");
        let aad = h("436f756e742d30");
        let mut fixed = ikm_e.clone();
        let rng = FillRng(move |b: &mut [u8]| {
            let n = b.len().min(fixed.len());
            b[..n].copy_from_slice(&fixed[..n]);
            fixed.drain(..n);
        });
        let (enc, ct) = hpke::single_shot_seal::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(&OpModeS::Base, &pk_r, &info, &pt, &aad, &mut { rng }).unwrap();
        assert_eq!(enc.to_bytes().to_vec(), h("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"));
        assert_eq!(ct, h("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"));
        let back = hpke::single_shot_open::<AesGcm128, HkdfSha256, X25519HkdfSha256>(&OpModeR::Base, &sk_r, &enc, &info, &ct, &aad).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn e6_envelope_is_fixed_size_and_opens() {
        let (sk, pk) = generate_keypair();
        let pk = parse_auditor_key(&pk).unwrap();
        let sk = b64url_decode(&sk).unwrap();
        let small = seal_fixed(&pk, b"{}", 1024, b"hdr").unwrap();
        let big = seal_fixed(&pk, &vec![7u8; 1020], 1024, b"hdr").unwrap();
        assert_eq!(small.to_bytes().len(), big.to_bytes().len(), "el largo no depende del contenido");
        assert_eq!(small.to_bytes().len(), 32 + 1024 + 16);
        assert_eq!(open_fixed(&sk, &small, b"hdr").unwrap(), b"{}");
        assert_eq!(open_fixed(&sk, &big, b"hdr").unwrap(), vec![7u8; 1020]);
        // Otro header (aad), otro byte del sobre u otra clave: no abre.
        assert!(open_fixed(&sk, &small, b"otro").is_err());
        let mut tampered = small.clone();
        tampered.ct[10] ^= 1;
        assert!(open_fixed(&sk, &tampered, b"hdr").is_err());
        let (other, _) = generate_keypair();
        assert!(open_fixed(&b64url_decode(&other).unwrap(), &small, b"hdr").is_err());
        // Ida y vuelta por bytes.
        assert_eq!(Envelope::from_bytes(&small.to_bytes()).unwrap(), small);
        // Lo que no entra es un error (el motor trunca antes).
        assert!(seal_fixed(&pk, &vec![0u8; 1021], 1024, b"hdr").is_err());
    }

    fn receipt_of(sealed_entries: usize, auditor: [u8; 32], key: &RunKey) -> Value {
        let log = new_run_log(16 * 1024);
        {
            let mut l = log.lock().unwrap();
            l.push_public(json!({"kind": "capability", "capability": "stdout", "granted": true}).to_string());
            for i in 0..sealed_entries {
                l.push_sealed(json!({"kind": "op", "line": format!("sign {}", i)}).to_string());
            }
            l.push_public(json!({"kind": "capability", "capability": "time", "granted": true}).to_string());
            l.clock.push(1_760_000_000.5);
        }
        let l = log.lock().unwrap();
        build_receipt(
            &l,
            &ReceiptContext { auditor, key, program_sha: Some("ab".repeat(32)), config_sha: None, trusted: None, started: "2026-10-21T00:00:00Z".into() },
        )
        .unwrap()
    }

    fn auditor() -> (Vec<u8>, [u8; 32]) {
        let (sk, pk) = generate_keypair();
        (b64url_decode(&sk).unwrap(), parse_auditor_key(&pk).unwrap())
    }

    /// Dos corridas que difieren sólo en cuántas operaciones auditadas hubo en la rama privada (0 y
    /// 50): el mismo largo, las mismas entradas públicas.
    #[test]
    fn e6_shape_is_fixed() {
        let (_, pk) = auditor();
        let key = RunKey::ephemeral();
        let a = receipt_of(0, pk, &key);
        let b = receipt_of(50, pk, &key);
        assert_eq!(a.to_string().len(), b.to_string().len(), "el recibo no puede decir cuántas entradas selladas hubo");
        assert_eq!(a["public"], b["public"]);
        assert_eq!(a["header"]["public_entries"], json!(2));
        assert_eq!(a["sealed"].as_str().unwrap().len(), b["sealed"].as_str().unwrap().len());
    }

    /// Ronda 1 (E6-M1): si al armar algo no entra, sale primero el reloj y no lo firmado, y en una
    /// pasada (el reloj se carga sin el tope del registro, como si la estimación hubiera fallado).
    #[test]
    fn e6_build_trims_the_clock_first_in_one_pass() {
        let (sk, pk) = auditor();
        let key = RunKey::ephemeral();
        let log = new_run_log(16 * 1024);
        {
            let mut l = log.lock().unwrap();
            l.push_sealed(json!({"kind": "op", "line": "sign firmado"}).to_string());
            for i in 0..200_000 {
                l.clock.push(1_760_000_000.0 + i as f64 / 7.0);
            }
        }
        let t0 = std::time::Instant::now();
        let l = log.lock().unwrap();
        let ctx = ReceiptContext { auditor: pk, key: &key, program_sha: None, config_sha: None, trusted: None, started: "2026-10-21T00:00:00Z".into() };
        let r = build_receipt(&l, &ctx).unwrap();
        assert!(t0.elapsed() < std::time::Duration::from_secs(20), "{:?}", t0.elapsed());
        let o = open_receipt(&r, &sk).unwrap();
        assert!(o["entries"].as_array().unwrap().iter().any(|e| e["entry"]["line"] == "sign firmado"), "{}", o);
        assert!(o["clock_truncated"].as_u64().unwrap() > 190_000, "{}", o["clock_truncated"]);
    }

    #[test]
    fn e6_auditor_can_open() {
        let (sk, pk) = auditor();
        let key = RunKey::ephemeral();
        let r = receipt_of(3, pk, &key);
        verify_receipt(&r).unwrap();
        let o = open_receipt(&r, &sk).unwrap();
        let entries = o["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 5);
        let seqs: Vec<u64> = entries.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
        assert_eq!(entries[0]["sealed"], json!(false));
        assert_eq!(entries[2]["entry"]["line"], json!("sign 1"));
        assert_eq!(entries[2]["sealed"], json!(true));
        assert_eq!(o["clock"], json!(["1760000000.5"]));
        assert_eq!(o["truncated"], json!(0));
        // La JCS de lo que se re-serializa no depende del orden en que vino.
        let back: Value = serde_json::from_str(&r.to_string()).unwrap();
        open_receipt(&back, &sk).unwrap();
        // Otra clave de auditor no abre.
        let (other, _) = auditor();
        assert!(open_receipt(&r, &other).is_err());
    }

    #[test]
    fn e6_tamper_is_detected() {
        let (sk, pk) = auditor();
        let key = RunKey::ephemeral();
        let r = receipt_of(2, pk, &key);
        let mut env = b64url_decode(r["sealed"].as_str().unwrap()).unwrap();
        env[100] ^= 1;
        let mut t = r.clone();
        t["sealed"] = json!(b64url_encode(&env));
        assert!(verify_receipt(&t).unwrap_err().contains("signature"));
        let mut t = r.clone();
        t["public"][0]["granted"] = json!(false);
        assert!(verify_receipt(&t).is_err());
        let mut t = r.clone();
        t["header"]["public_entries"] = json!(3);
        assert!(verify_receipt(&t).is_err());
        let mut t = r.clone();
        t["root"] = json!("00".repeat(32));
        assert!(verify_receipt(&t).is_err());
        // Una entrada sellada cambiada con la firma rehecha por otro: la cadena no da la raíz firmada.
        // (Se arma a mano: cambiar el sobre exige la pública del auditor, y re-firmar, la clave.)
        let mut l = RunLog::new(16 * 1024);
        l.seed = Some("00".repeat(32));
        l.push_sealed(json!({"kind": "op", "line": "x"}).to_string());
        let ctx = ReceiptContext { auditor: pk, key: &key, program_sha: None, config_sha: None, trusted: None, started: "s".into() };
        let good = build_receipt(&l, &ctx).unwrap();
        let mut forged = good.clone();
        forged["root"] = json!(hex_encode(&[7u8; 32]));
        let public = forged["public"].clone();
        let env = b64url_decode(forged["sealed"].as_str().unwrap()).unwrap();
        let msg = signed_message(&forged["header"], &public, &env, &[7u8; 32]);
        forged["signature"] = json!(b64url_encode(&key.sign(&msg)));
        verify_receipt(&forged).unwrap();
        assert!(open_receipt(&forged, &sk).unwrap_err().contains("chain"));
    }

    /// E6-h: bajo `serve --attested` firma la clave atestada (P-256). Verifica, abre, y una firma
    /// tocada o la pública de otra curva no pasan.
    #[test]
    fn e6_attested_key_signs_p256() {
        let (sk, pk) = auditor();
        let key = RunKey::from_attested_scalar(&[0x11u8; 32]).unwrap();
        assert_eq!((key.alg(), key.identity, key.public_bytes().len()), ("P-256", "attested", 33));
        let r = receipt_of(2, pk, &key);
        assert_eq!(r["header"]["run_key"]["alg"], json!("P-256"));
        verify_receipt(&r).unwrap();
        assert_eq!(open_receipt(&r, &sk).unwrap()["entries"].as_array().unwrap().len(), 4);
        let mut t = r.clone();
        let mut sig = b64url_decode(t["signature"].as_str().unwrap()).unwrap();
        sig[10] ^= 1;
        t["signature"] = json!(b64url_encode(&sig));
        assert!(verify_receipt(&t).unwrap_err().contains("signature"));
        // El header dice Ed25519 con una pública P-256: no verifica (el `alg` va firmado).
        let mut t = r.clone();
        t["header"]["run_key"]["alg"] = json!("Ed25519");
        assert!(verify_receipt(&t).is_err());
        assert!(RunKey::from_attested_scalar(&[0u8; 32]).is_err());
    }

    #[test]
    fn e6_sealed_bytes_knob() {
        assert_eq!(sealed_bytes_from(None).unwrap(), DEFAULT_SEALED_BYTES);
        assert_eq!(sealed_bytes_from(Some("8192")).unwrap(), 8192);
        assert!(sealed_bytes_from(Some("10")).is_err());
        assert!(sealed_bytes_from(Some("mucho")).is_err());
    }

    #[test]
    fn e6_auditor_key_is_checked() {
        assert!(parse_auditor_key("no es base64url!").is_err());
        assert!(parse_auditor_key(&b64url_encode(&[1u8; 31])).unwrap_err().contains("32 bytes"));
        let (_, pk) = generate_keypair();
        assert!(parse_auditor_key(&pk).is_ok());
    }
}

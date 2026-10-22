//! El tipo `secret` — un valor opaco, tainted, redactado en toda salida.
//!
//! `SecretInner` es el payload de la variante **aislada** `SynValue::Secret`
//! (ver `types.rs`). Decisión de diseño no-negociable (§8 del spec): `secret` es
//! una variante de enum más, NO un bit de taint en todos los valores. Agregar la
//! variante no cuesta nada al manejo de los demás valores (el match del enum es un
//! jump table O(1)); las ramas de redacción sólo corren cuando hay un secret.
//!
//! Invariante de seguridad: el plaintext **nunca** se expone por el `Display`/`Debug`
//! ni por los accessors normales. Sólo escapa por tres puntos bordeados y
//! deliberados (todos fuera de user-space del programa Synsema):
//!   1. `reveal()` — con capability `require reveal` y audit persistente.
//!   2. el borde del socket HTTP (materializar un header `Authorization`).
//!   3. el borde de la DB (persistir vía SQL parametrizado).
//!
//! En el core, ese acceso es `SecretInner::expose()` — pensado para el runtime, no
//! para el lenguaje.

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// El valor sensible de un `secret`: texto (la forma normal — key/token) o bytes
/// (un blob binario sellado con `as_secret`). El payload determina qué devuelve
/// `reveal()` (texto vs bytes); ambas formas se redactan idéntico en toda salida.
enum SecretPayload {
    Text(String),
    Bytes(Vec<u8>),
}

/// Payload de un `secret`: el valor sensible + el nombre de origen (para mostrar
/// `secret(NAME)` al redactar). Vive detrás de un `Rc` en `SynValue::Secret`.
pub struct SecretInner {
    /// El valor sensible. Se borra de memoria al drop (best-effort, §5).
    value: SecretPayload,
    /// Nombre/label de origen — NO sensible; se muestra al redactar. Para
    /// `secret(NAME)` es el nombre del config; para `as_secret(v, label)` es el label.
    name: String,
    /// `true` = SELLADO. Jamás se materializa por `reveal`, ni con
    /// La capability; sólo lo consumen los bordes criptográficos del runtime (`expose_bytes`:
    /// ECDH, firma, AEAD). Es el caso de la clave de identidad de `serve --attested`, que ancla
    /// TLS y el documento de attestation: exportarla anularía lo que la attestation prueba.
    sealed: bool,
    /// v0.6.46 (E1): los hosts a los que puede ir (`require secret("K") for net("h")`, normalizados
    /// como un scope de `net`). `None` = no atado: como antes, sólo en un header.
    bound: Option<Arc<[String]>>,
    /// v0.6.46 (E1): el texto PÚBLICO que va antes del primer secret de una concatenación
    /// (`` `https://h/v2/{key}` `` → `https://h/v2/`). Es de donde sale el host de una URL que es
    /// un secret: el host nunca sale del material.
    public_prefix: Option<Box<str>>,
    /// v0.6.46 (E1): los secrets de los que se armó (nombre, texto), en una concatenación o un
    /// `bearer`/`basic`. El audit los nombra a todos y el eco de una respuesta se enmascara con
    /// cada uno. Vacío = es él mismo.
    parts: Vec<(String, String)>,
}

impl SecretInner {
    /// Construye un secret de TEXTO a partir de su nombre de origen y su plaintext.
    pub fn new(name: impl Into<String>, plaintext: impl Into<String>) -> Self {
        Self { value: SecretPayload::Text(plaintext.into()), name: name.into(), sealed: false, bound: None, public_prefix: None, parts: Vec::new() }
    }

    /// Construye un secret de BYTES (blob binario sellado con `as_secret`).
    pub fn new_bytes(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self { value: SecretPayload::Bytes(bytes), name: name.into(), sealed: false, bound: None, public_prefix: None, parts: Vec::new() }
    }

    /// Construye un secret de BYTES **sellado**: `reveal()` lo rechaza siempre y los bordes
    /// genéricos también (`expose_bytes_checked`, `expose`); sólo los usos legítimos del material
    /// —firma/MAC y ECDH con la clave propia— lo leen por `expose_bytes`. Ver `sealed`.
    pub fn new_bytes_sealed(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self { value: SecretPayload::Bytes(bytes), name: name.into(), sealed: true, bound: None, public_prefix: None, parts: Vec::new() }
    }

    /// `true` si el secret está sellado (no revelable).
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Nombre de origen (para redacción: `secret(NAME)`). NO es el valor.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// v0.6.46 (E1): el mismo secret con su atadura, su prefijo público y sus partes.
    pub fn with_binding(mut self, bound: Option<Arc<[String]>>, public_prefix: Option<Box<str>>, parts: Vec<(String, String)>) -> Self {
        self.bound = bound;
        self.public_prefix = public_prefix;
        self.parts = parts;
        self
    }

    /// Los hosts a los que puede ir (`None` = no atado).
    pub fn bound(&self) -> Option<&Arc<[String]>> {
        self.bound.as_ref()
    }

    /// El texto público antes del primer secret (ver el campo).
    pub fn public_prefix(&self) -> Option<&str> {
        self.public_prefix.as_deref()
    }

    /// Los secrets de los que se armó, como `(nombre, texto)`: sus partes, o él mismo. Un secret
    /// sellado o de bytes que no son texto no tiene forma de texto y no aparece.
    pub fn atoms(&self) -> Vec<(String, String)> {
        if !self.parts.is_empty() {
            return self.parts.clone();
        }
        match (&self.value, self.sealed) {
            (SecretPayload::Text(t), false) => vec![(self.name.clone(), t.clone())],
            (SecretPayload::Bytes(b), false) => match std::str::from_utf8(b) {
                Ok(t) => vec![(self.name.clone(), t.to_string())],
                Err(_) => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    /// Los nombres de los secrets de los que se armó (para el audit y los mensajes).
    pub fn names(&self) -> Vec<String> {
        if self.parts.is_empty() {
            return vec![self.name.clone()];
        }
        let mut out: Vec<String> = Vec::new();
        for (n, _) in &self.parts {
            if !out.contains(n) {
                out.push(n.clone());
            }
        }
        out
    }

    /// `true` si el payload es bytes (no texto) — decide el tipo que devuelve `reveal()`.
    pub fn is_bytes(&self) -> bool {
        matches!(self.value, SecretPayload::Bytes(_))
    }

    /// **Borde de materialización**: devuelve el plaintext como texto. Pensado SÓLO
    /// para el runtime en los tres puntos bordeados (reveal/socket/DB) — nunca
    /// alcanzable desde el lenguaje Synsema. No usar para logging/errores/serialización.
    /// Para un secret de bytes devuelve su vista UTF-8 (lossy): los bordes de texto
    /// (header HTTP/SQL/concat) son para secrets de texto; sellar bytes y materializarlos
    /// como texto es un uso atípico. La forma fiel de bytes es `expose_bytes`.
    ///
    /// Un secret **sellado** jamás se materializa como texto —
    /// Devuelve su forma REDACTADA (`secret(NAME)`, la misma que `Display`). Así todos los
    /// bordes de texto (SQL de los cinco drivers, headers HTTP, concatenación, WebSocket,
    /// Nombre de archivo) quedan cerrados de una sola vez, sin depender de que cada uno se
    /// acuerde de chequear: la clave que ancla TLS y el documento de attestation no puede
    /// salir ni siquiera mutilada por un `from_utf8_lossy`.
    pub fn expose(&self) -> Cow<'_, str> {
        if self.sealed {
            return Cow::Owned(format!("secret({})", self.name));
        }
        match &self.value {
            SecretPayload::Text(s) => Cow::Borrowed(s),
            SecretPayload::Bytes(b) => String::from_utf8_lossy(b),
        }
    }

    /// Igual que `expose`, en bytes (para crypto / comparación constant-time / reveal de
    /// bytes). Fiel para ambos payloads (texto → sus bytes UTF-8; bytes → tal cual).
    ///
    /// ⚠️ Es el borde CRUDO: para un secret sellado devuelve el material tal cual, así que
    /// sólo puede llamarlo un uso legítimo de ese material — **MAC/hash de una vía** y **ECDH
    /// con la clave propia**. Todo lo demás (AES-GCM, HKDF como IKM, ruido, comparaciones
    /// ad-hoc, custodia) tiene que pasar por `expose_bytes_checked`, que rechaza lo sellado con
    /// un error claro.
    ///
    /// El criterio, después de la ronda 4: **la clave de identidad atestada es un escalar P-256
    /// cuya pública se PUBLICA** en `/.well-known/attestation`, así que la línea no es
    /// "exportar vs. usar" sino *¿produce esto algo que un tercero verifique contra esa
    /// pública?*. Si la respuesta es sí, es SUPLANTACIÓN del enclave y va por el borde
    /// comprobado, aunque la clave no salga. Inventario COMPLETO de los llamadores crudos que
    /// quedan (el anti-rot es este comentario: un `expose_bytes()` nuevo fuera de esta lista es
    /// una decisión sin tomar):
    ///
    /// | Sitio | Primitiva | Por qué es legítimo |
    /// |---|---|---|
    /// | `crypto.rs::private_key_arg` | ECDH con la clave propia | el uso para el que se sella |
    /// | `captoken.rs::key_material` | HMAC (token de capabilities) | simétrica, de una vía |
    /// | `httpsig.rs` (firmar/verificar HMAC-SHA256) | HMAC | simétrica, de una vía |
    /// | `webauth.rs::key_material` | argon2id, HS256, TOTP | simétricas, de una vía |
    /// | `secrets.rs::crypto_bytes` | HMAC, `constant_time_eq` | simétricas, de una vía |
    /// | `types.rs` (truthiness, `==`) | vacío / comparación const-time | no produce artefacto |
    /// | `tabular.rs::canon_key` | SHA-256 como clave de agrupación (`group_by`/`unique`) | de una vía, interna: nunca sale |
    ///
    /// Comprobados (rechazan lo sellado): `blockchain.rs::key_material` — toda la familia de
    /// custodia, firma secp256k1/ed25519 incluida —, `webauth.rs::pem_text` (RS256/ES256),
    /// `webpush.rs::vapid_private_key` (ES256), `crypto.rs` genérico, `privacy.rs`, `reveal`,
    /// `secrets.rs::secret_text`/`edge_text` (headers, query, body, `bearer`, `basic`, auth de
    /// `btc_rpc`, mnemónico/passphrase de `blockchain_hd.rs`), `database.rs::reject_sealed` (entradas
    /// de `sql`/`execute*`/`mongo_*`) y `database.rs::syn_to_redis_arg` (v0.6.44, HB4).
    ///
    /// Crudo SÓLO si no está sellado (el brazo lo comprueba con `!is_sealed()`; un sellado cae a
    /// `expose()`, el marcador): `database.rs::syn_to_value`/`syn_to_pg`/`syn_to_mysql`/`syn_to_bson`
    /// — un secret de bytes como parámetro de DB va con sus bytes (v0.6.44); y
    /// `interpreter.rs::secret_concat` (`+` con un secret: sellado → error antes de leerlo). La comprobación va en
    /// el brazo y no sólo en la entrada: así la conversión es segura aunque una entrada nueva
    /// olvide el guardia (auditoría v0.6.44, A1: `mongo_find` sort/fields no lo tenía).
    pub fn expose_bytes(&self) -> &[u8] {
        match &self.value {
            SecretPayload::Text(s) => s.as_bytes(),
            SecretPayload::Bytes(b) => b,
        }
    }

    /// `expose_bytes` **comprobado**: rechaza un secret sellado con el error canónico. Es lo
    /// que usan los bordes criptográficos genéricos (`crypto.rs`) para que la clave de
    /// identidad atestada no se pueda cifrar, derivar ni exportar. `who` nombra al builtin.
    pub fn expose_bytes_checked(&self, who: &str) -> Result<&[u8], String> {
        if self.sealed {
            return Err(format!(
                "{}: secret({}) is sealed: the attested identity key stays inside the process. It can be used for the ECDH handshake (and, inside the engine, for MAC/signature primitives that cannot reverse it); it is never exported, encrypted, derived, used as chain key material, or turned into a wallet",
                who, self.name
            ));
        }
        Ok(self.expose_bytes())
    }
}

impl Drop for SecretInner {
    fn drop(&mut self) {
        // Borra el valor de memoria (best-effort; los String intermedios de
        // concatenación/format no se cubren, como aclara el spec §5).
        match &mut self.value {
            SecretPayload::Text(s) => s.zeroize(),
            SecretPayload::Bytes(b) => b.zeroize(),
        }
        for (_, v) in &mut self.parts {
            v.zeroize();
        }
    }
}

thread_local! {
    /// v0.6.46 (E2): cuántas veces se escribió el marcador `secret(K)` en este hilo. El hueco de un
    /// template lo lee antes y después de formatear una lista o un mapa: si cambió, adentro había un
    /// secret. Es más barato que recorrer el contenedor (que el `Display` ya recorre).
    static PLACEHOLDERS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// v0.6.46 (E2): el contador de marcadores escritos en este hilo (ver `PLACEHOLDERS`).
#[inline]
pub fn placeholders_written() -> u32 {
    PLACEHOLDERS.with(|c| c.get())
}

/// `Display` redactado — defensa de fondo: ningún `format!`/`to_string()`/log
/// accidental puede filtrar el valor. Muestra el nombre, nunca el plaintext.
impl fmt::Display for SecretInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        PLACEHOLDERS.with(|c| c.set(c.get().wrapping_add(1)));
        write!(f, "secret({})", self.name)
    }
}

impl fmt::Debug for SecretInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Debug también redacta (un `{:?}` accidental no debe filtrar).
        write!(f, "Secret({})", self.name)
    }
}

/// Comparación de bytes en tiempo constante (no filtra por timing). La diferencia
/// de longitud sí es observable (la longitud no se considera secreta), igual que
/// las implementaciones estándar.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// v0.6.46 (E2): el nombre del primer secret dentro de un valor, a cualquier profundidad (listas,
/// mapas, valores privados). Vivía en stdlib (`http_common::secret_inside`); el hueco de un template
/// la necesita en core. Una lista sin caja (sólo números) no tiene secrets.
pub fn contains_secret(v: &crate::types::SynValue) -> Option<String> {
    use crate::types::SynValue;
    match v {
        SynValue::Secret(s) => Some(s.name().to_string()),
        SynValue::List(l) => l.borrow().as_values()?.iter().find_map(contains_secret),
        SynValue::Map(m) => m.borrow().iter().find_map(|(_, x)| contains_secret(x)),
        SynValue::Private(p) => contains_secret(&p.value),
        _ => None,
    }
}

/// v0.6.46 (E1.7): los nombres de los secrets que van en los argumentos de una llamada (la URL, los
/// headers, el body), a cualquier profundidad. Para el linaje: `inputs[].secrets`.
pub fn secret_names_in(vs: &[crate::types::SynValue]) -> Vec<String> {
    use crate::types::SynValue;
    fn walk(v: &SynValue, out: &mut Vec<String>) {
        match v {
            SynValue::Secret(s) => {
                for n in s.names() {
                    if !out.contains(&n) {
                        out.push(n);
                    }
                }
            }
            SynValue::List(l) => {
                if let Some(xs) = l.borrow().as_values() {
                    for x in xs {
                        walk(x, out);
                    }
                }
            }
            SynValue::Map(m) => {
                for (_, x) in m.borrow().iter() {
                    walk(x, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for v in vs {
        walk(v, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::types::{syn_list, syn_map, syn_secret, syn_text, Obj, ServerValue, SynMap, SynValue};

    /// v0.6.46 (ronda 1, N1): el chequeo de E2 (un secret en el hueco de un template) cuenta los
    /// marcadores que escribe el `Display` de un contenedor. Si un cambio en cómo se imprime una
    /// lista, un mapa o un valor de servidor dejara de pasar por `SecretInner::fmt`, el chequeo se
    /// apagaría sin que fallara nada; esto lo ata.
    #[test]
    fn every_container_prints_its_secrets_through_the_counter() {
        let s = syn_secret("K", "valor-en-claro");
        let mut inner = SynMap::new();
        inner.insert("k", s.clone());
        let mut outer = SynMap::new();
        outer.insert("m", syn_map(inner.clone()));
        let cases = vec![
            syn_list(vec![syn_text("a"), s.clone()]),
            syn_map(inner),
            syn_map(outer),
            SynValue::Server(Obj::new(ServerValue::Envelope { status: 200, value: syn_list(vec![s.clone()]) })),
        ];
        for v in cases {
            let before = super::placeholders_written();
            let shown = v.to_string();
            assert!(
                super::placeholders_written() != before && shown.contains("secret(K)") && !shown.contains("valor-en-claro"),
                "{}",
                shown
            );
        }
    }
}

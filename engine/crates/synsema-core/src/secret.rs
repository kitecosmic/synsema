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
}

impl SecretInner {
    /// Construye un secret de TEXTO a partir de su nombre de origen y su plaintext.
    pub fn new(name: impl Into<String>, plaintext: impl Into<String>) -> Self {
        Self { value: SecretPayload::Text(plaintext.into()), name: name.into(), sealed: false }
    }

    /// Construye un secret de BYTES (blob binario sellado con `as_secret`).
    pub fn new_bytes(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self { value: SecretPayload::Bytes(bytes), name: name.into(), sealed: false }
    }

    /// Construye un secret de BYTES **sellado**: `reveal()` lo rechaza siempre y los bordes
    /// genéricos también (`expose_bytes_checked`, `expose`); sólo los usos legítimos del material
    /// —firma/MAC y ECDH con la clave propia— lo leen por `expose_bytes`. Ver `sealed`.
    pub fn new_bytes_sealed(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self { value: SecretPayload::Bytes(bytes), name: name.into(), sealed: true }
    }

    /// `true` si el secret está sellado (no revelable).
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Nombre de origen (para redacción: `secret(NAME)`). NO es el valor.
    pub fn name(&self) -> &str {
        &self.name
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
    ///
    /// Comprobados (rechazan lo sellado): `blockchain.rs::key_material` — toda la familia de
    /// custodia, firma secp256k1/ed25519 incluida —, `webauth.rs::pem_text` (RS256/ES256),
    /// `webpush.rs::vapid_private_key` (ES256), `crypto.rs` genérico, `privacy.rs`, `reveal`.
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
    }
}

/// `Display` redactado — defensa de fondo: ningún `format!`/`to_string()`/log
/// accidental puede filtrar el valor. Muestra el nombre, nunca el plaintext.
impl fmt::Display for SecretInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

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
}

impl SecretInner {
    /// Construye un secret de TEXTO a partir de su nombre de origen y su plaintext.
    pub fn new(name: impl Into<String>, plaintext: impl Into<String>) -> Self {
        Self { value: SecretPayload::Text(plaintext.into()), name: name.into() }
    }

    /// Construye un secret de BYTES (blob binario sellado con `as_secret`).
    pub fn new_bytes(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self { value: SecretPayload::Bytes(bytes), name: name.into() }
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
    pub fn expose(&self) -> Cow<'_, str> {
        match &self.value {
            SecretPayload::Text(s) => Cow::Borrowed(s),
            SecretPayload::Bytes(b) => String::from_utf8_lossy(b),
        }
    }

    /// Igual que `expose`, en bytes (para crypto / comparación constant-time / reveal de
    /// bytes). Fiel para ambos payloads (texto → sus bytes UTF-8; bytes → tal cual).
    pub fn expose_bytes(&self) -> &[u8] {
        match &self.value {
            SecretPayload::Text(s) => s.as_bytes(),
            SecretPayload::Bytes(b) => b,
        }
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

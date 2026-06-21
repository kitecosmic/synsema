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

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Payload de un `secret`: el plaintext + el nombre de origen (para mostrar
/// `secret(NAME)` al redactar). Vive detrás de un `Rc` en `SynValue::Secret`.
pub struct SecretInner {
    /// El valor sensible. Se borra de memoria al drop (best-effort, §5).
    plaintext: String,
    /// Nombre de la variable de origen — NO sensible; se muestra al redactar.
    name: String,
}

impl SecretInner {
    /// Construye un secret a partir de su nombre de origen y su plaintext.
    pub fn new(name: impl Into<String>, plaintext: impl Into<String>) -> Self {
        Self { plaintext: plaintext.into(), name: name.into() }
    }

    /// Nombre de origen (para redacción: `secret(NAME)`). NO es el valor.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// **Borde de materialización**: devuelve el plaintext. Pensado SÓLO para el
    /// runtime en los tres puntos bordeados (reveal/socket/DB) — nunca alcanzable
    /// desde el lenguaje Synsema. No usar para logging, errores ni serialización.
    pub fn expose(&self) -> &str {
        &self.plaintext
    }

    /// Igual que `expose`, en bytes (para crypto / comparación constant-time).
    pub fn expose_bytes(&self) -> &[u8] {
        self.plaintext.as_bytes()
    }
}

impl Drop for SecretInner {
    fn drop(&mut self) {
        // Borra el plaintext de memoria (best-effort; los String intermedios de
        // concatenación/format no se cubren, como aclara el spec §5).
        self.plaintext.zeroize();
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

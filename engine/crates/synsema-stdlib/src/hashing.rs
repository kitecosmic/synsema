//! Hashing SHA (feature `bytes`, Batch 1).
//!
//! Builtins **PUROS** (sin capability — hashing es cómputo, como `text`/`number`):
//!   - `sha256(x)` → bytes (digest crudo de 32 bytes).
//!   - `sha512(x)` → bytes (digest crudo de 64 bytes).
//!
//! Devuelven **bytes** (no hex): ahora que `bytes` es de primera clase, el digest crudo
//! es lo más componible. El hex se obtiene con `decode(sha256(x), "hex")`; base64 con
//! `decode(sha256(x), "base64")`.
//!
//! `x`: si es `bytes`, hashea los bytes crudos; si es `text`, hashea su UTF-8; si es
//! `secret`, **ERROR** (G6: el plaintext no se materializa en user-space; el hashing
//! de secrets ya existe gateado vía `hmac_sha256`). Reusa `sha2` (ya dep de stdlib →
//! sin cambios de Cargo).

use std::rc::Rc;

use sha2::{Digest, Sha256, Sha512};

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_bytes, SynValue};

/// Bytes a hashear de `x`: bytes crudos o UTF-8 del texto. Error para `secret` (G6) y
/// para cualquier otro tipo.
fn hash_input<'a>(x: &'a SynValue, fname: &str) -> Result<&'a [u8], Control> {
    match x {
        SynValue::Bytes(b) => Ok(&b[..]),
        SynValue::Text(s) => Ok(s.as_bytes()),
        SynValue::Secret(_) => Err(Control::Error(RuntimeError::new(format!(
            "Cannot hash a secret with {}() (use hmac_sha256 for secret-keyed MACs)",
            fname
        )))),
        other => Err(Control::Error(RuntimeError::new(format!(
            "{}() expects bytes or text, got {}",
            fname,
            other.type_name()
        )))),
    }
}

fn arg0(args: &[SynValue]) -> Result<&SynValue, Control> {
    args.first()
        .ok_or_else(|| Control::Error(RuntimeError::new("missing argument")))
}

/// Registra `sha256`/`sha512`. Wired en `engine.rs` junto a los demás builtins de stdlib.
pub fn register_hash_builtins(interp: &Interpreter) {
    interp.register_builtin(
        "sha256",
        1,
        Rc::new(|_i, args, _l| {
            let data = hash_input(arg0(args)?, "sha256")?;
            Ok(syn_bytes(Sha256::digest(data).to_vec()))
        }),
    );
    interp.register_builtin(
        "sha512",
        1,
        Rc::new(|_i, args, _l| {
            let data = hash_input(arg0(args)?, "sha512")?;
            Ok(syn_bytes(Sha512::digest(data).to_vec()))
        }),
    );
}

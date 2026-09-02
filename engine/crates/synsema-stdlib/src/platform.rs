//! `platform()` → `{os, arch}` (tanda escritorio). Un hecho del binario, como `args()` y
//! `self_path()`: **sin capability** (no revela nada que `self_path()` no revele ya). Sirve para
//! que el MISMO `.syn` construido para tres sistemas ramifique en runtime — abrir el navegador
//! con `cmd`/`open`/`xdg-open` — sin hacks como `env("OS")` (sólo Windows) o mirar si
//! `self_path()` termina en `.exe`.
//!
//! Valores de `os`: `"windows"`, `"macos"`, `"linux"`, otros tal como los nombra Rust
//! (`"freebsd"`, …); bajo wasm `"wasm"`. `arch`: `"x86_64"`, `"aarch64"`, …; bajo wasm `"wasm32"`.

use std::rc::Rc;

use indexmap::IndexMap;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_map, syn_text};

/// Nombre canónico del SO a partir de `std::env::consts::OS`.
pub fn os_name(raw: &str) -> &str {
    match raw {
        "windows" => "windows",
        "macos" => "macos",
        "linux" => "linux",
        other => other,
    }
}

/// Registra `platform()` con los valores dados (el host nativo pasa los de `std::env::consts`;
/// wasm pasa `"wasm"`/`"wasm32"`).
pub fn register_platform_builtin(interp: &Interpreter, os: &'static str, arch: &'static str) {
    interp.register_builtin(
        "platform",
        -1,
        Rc::new(move |_i, args, _loc| {
            if !args.is_empty() {
                return Err(Control::Error(RuntimeError::new(format!(
                    "platform expects no arguments, got {}",
                    args.len()
                ))));
            }
            let mut m = IndexMap::new();
            m.insert("os".to_string(), syn_text(os_name(os)));
            m.insert("arch".to_string(), syn_text(arch));
            Ok(syn_map(m))
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::os_name;

    #[test]
    fn os_names_are_the_documented_ones() {
        assert_eq!(os_name("windows"), "windows");
        assert_eq!(os_name("macos"), "macos");
        assert_eq!(os_name("linux"), "linux");
        assert_eq!(os_name("freebsd"), "freebsd");
        assert_eq!(os_name(std::env::consts::OS), os_name(std::env::consts::OS));
    }
}

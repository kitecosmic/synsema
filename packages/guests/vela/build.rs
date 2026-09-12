//! Embebe el programa `.syn` de la app en el módulo: `SYNSEMA_VELA_APP=/ruta/a/mi_app.syn cargo build …`
//! (default: `app.syn` junto a este Cargo.toml). Así el SHA-256 del `.wasm` que Vela verifica onchain
//! cubre intérprete + lógica, y un `.wasm` es exactamente una app.
use std::path::{Path, PathBuf};

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let src = std::env::var("SYNSEMA_VELA_APP").unwrap_or_else(|_| format!("{}/app.syn", manifest));
    let text = std::fs::read_to_string(&src).unwrap_or_else(|e| {
        panic!("SYNSEMA_VELA_APP: cannot read the .syn program at {}: {}", src, e)
    });
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("app.syn");
    std::fs::write(&out, text).expect("write app.syn to OUT_DIR");
    let name = Path::new(&src).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "app.syn".to_string());
    println!("cargo:rustc-env=SYNSEMA_VELA_APP_NAME={}", name);
    println!("cargo:rerun-if-env-changed=SYNSEMA_VELA_APP");
    println!("cargo:rerun-if-changed={}", src);
    println!("cargo:rerun-if-changed=build.rs");
}

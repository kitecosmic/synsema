//! Embebe el programa `.syn` de la app en el módulo, dentro de un SLOT de tamaño fijo con cabecera
//! (`SYNSEMA_VELA_APP=/ruta/a/mi_app.syn cargo build …`; default: `app.syn` junto a este Cargo.toml).
//! El slot es un bloque de datos que se puede encontrar y sobreescribir en el `.wasm` ya compilado
//! (`tools/embed.syn`), así que un programa nuevo entra SIN compilador: mismo módulo, mismo
//! intérprete, y el SHA-256 que Vela verifica onchain cubre intérprete + lógica. Un `.wasm` es
//! exactamente una app.
//!
//! Layout del slot (SLOT_SIZE bytes, v0.6.58): magic `SYNSEMA.APPSLOT2` (16) · largo del bundle u32
//! LE (4) · un bundle de `synsema build` (`payload ‖ trailer`, ver `synsema_core::bundle`) · relleno
//! 0x20 hasta el final. Acá el bundle lleva sólo el programa; uno con su `synsema.json` y sus
//! paquetes lo escribe `embed.syn` a partir de lo que arma `synsema build`. El guest sigue leyendo
//! el formato de antes (`APPSLOT1`, el programa en texto).
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const SLOT_MAGIC: &[u8; 16] = b"SYNSEMA.APPSLOT2";
const SLOT_SIZE: usize = 524_288;
const HEADER: usize = 16 + 4;
/// El trailer del bundle (`synsema_core::bundle`): offset u64 · largo del payload u64 · sha256 · magic.
const BUNDLE_MAGIC: &[u8; 16] = b"SYNSEMA-BUNDLE-1";

/// Un bundle de un solo archivo, con el mismo formato que escribe `synsema build`.
fn bundle(name: &str, program: &[u8]) -> Vec<u8> {
    let manifest = serde_json::json!({
        "format": 1,
        "engine": "vela-build.rs",
        "main": name,
        "ceiling": null,
        "profile": "native",
        "built_at": "",
    })
    .to_string();
    let mut payload = Vec::new();
    payload.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    payload.extend_from_slice(manifest.as_bytes());
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(&(program.len() as u64).to_le_bytes());
    payload.extend_from_slice(program);
    let sha = Sha256::digest(&payload);
    let mut out = payload.clone();
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(&sha);
    out.extend_from_slice(BUNDLE_MAGIC);
    out
}

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let src = std::env::var("SYNSEMA_VELA_APP").unwrap_or_else(|_| format!("{}/app.syn", manifest));
    let text = std::fs::read_to_string(&src).unwrap_or_else(|e| {
        panic!("SYNSEMA_VELA_APP: cannot read the .syn program at {}: {}", src, e)
    });
    let name = Path::new(&src).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "app.syn".to_string());
    let b = bundle(&name, text.as_bytes());
    assert!(
        b.len() <= SLOT_SIZE - HEADER,
        "SYNSEMA_VELA_APP: the program and its bundle are {} bytes; the app slot holds at most {}",
        b.len(),
        SLOT_SIZE - HEADER
    );
    let mut slot = Vec::with_capacity(SLOT_SIZE);
    slot.extend_from_slice(SLOT_MAGIC);
    slot.extend_from_slice(&(b.len() as u32).to_le_bytes());
    slot.extend_from_slice(&b);
    // El relleno no es cero a propósito: un bloque con ceros largos podría terminar en .bss o en un
    // segmento partido, y el slot debe ser UN tramo contiguo de bytes en el archivo.
    slot.resize(SLOT_SIZE, 0x20);
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("app.slot");
    std::fs::write(&out, slot).expect("write app.slot to OUT_DIR");
    println!("cargo:rerun-if-env-changed=SYNSEMA_VELA_APP");
    println!("cargo:rerun-if-changed={}", src);
    println!("cargo:rerun-if-changed=build.rs");
}

//! Embebe el programa `.syn` de la app en el módulo, dentro de un SLOT de tamaño fijo con cabecera
//! (`SYNSEMA_VELA_APP=/ruta/a/mi_app.syn cargo build …`; default: `app.syn` junto a este Cargo.toml).
//! El slot es un bloque de datos que se puede encontrar y sobreescribir en el `.wasm` ya compilado
//! (`tools/embed.syn`), así que un programa nuevo entra SIN compilador: mismo módulo, mismo
//! intérprete, y el SHA-256 que Vela verifica onchain cubre intérprete + lógica. Un `.wasm` es
//! exactamente una app.
//!
//! Layout del slot (SLOT_SIZE bytes): magic (16) · largo del nombre (1) · nombre (63) ·
//! largo del programa u32 LE (4) · programa UTF-8 · relleno 0x20 hasta el final.
use std::path::{Path, PathBuf};

const SLOT_MAGIC: &[u8; 16] = b"SYNSEMA.APPSLOT1";
const SLOT_SIZE: usize = 524_288;
const HEADER: usize = 16 + 1 + 63 + 4;

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let src = std::env::var("SYNSEMA_VELA_APP").unwrap_or_else(|_| format!("{}/app.syn", manifest));
    let text = std::fs::read_to_string(&src).unwrap_or_else(|e| {
        panic!("SYNSEMA_VELA_APP: cannot read the .syn program at {}: {}", src, e)
    });
    let name = Path::new(&src).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "app.syn".to_string());
    let name_bytes: Vec<u8> = name.bytes().take(63).collect();
    let program = text.as_bytes();
    assert!(
        program.len() <= SLOT_SIZE - HEADER,
        "SYNSEMA_VELA_APP: the program is {} bytes; the app slot holds at most {}",
        program.len(),
        SLOT_SIZE - HEADER
    );
    let mut slot = Vec::with_capacity(SLOT_SIZE);
    slot.extend_from_slice(SLOT_MAGIC);
    slot.push(name_bytes.len() as u8);
    slot.extend_from_slice(&name_bytes);
    slot.resize(16 + 1 + 63, 0x20);
    slot.extend_from_slice(&(program.len() as u32).to_le_bytes());
    slot.extend_from_slice(program);
    // El relleno no es cero a propósito: un bloque con ceros largos podría terminar en .bss o en un
    // segmento partido, y el slot debe ser UN tramo contiguo de bytes en el archivo.
    slot.resize(SLOT_SIZE, 0x20);
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("app.slot");
    std::fs::write(&out, slot).expect("write app.slot to OUT_DIR");
    println!("cargo:rerun-if-env-changed=SYNSEMA_VELA_APP");
    println!("cargo:rerun-if-changed={}", src);
    println!("cargo:rerun-if-changed=build.rs");
}

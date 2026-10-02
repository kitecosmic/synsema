//! Dónde hay `unsafe` en el motor (spec §F4.2): el nivel nativo lo tiene sólo en
//! `synsema-jit/src/abi.rs`, el texto sólo en `synsema-text/src/lib.rs` (F4.6b), core no tiene
//! nada, y cualquier `unsafe` nuevo en otro archivo rompe este test (para agregarlo hay que sumarlo
//! acá, a la vista del que revisa).

use std::path::{Path, PathBuf};

/// Los archivos que pueden tener `unsafe`, y por qué.
const ALLOWED: &[&str] = &[
    // El texto (F4.6b): en línea hasta 15 B, cuenta no atómica, capacidad y `realloc`. Revisado
    // con Miri (64 y 32 bits, little y big endian) y un fuzz contra `String`.
    "engine/crates/synsema-text/src/lib.rs",
    // El nivel nativo: el contexto, la salida a la VM y la llamada al código generado.
    "engine/crates/synsema-jit/src/abi.rs",
    // Handles del sistema (descriptores heredados, consola de Windows, Job Objects, ioctl de Nitro).
    "engine/crates/synsema-cli/src/main.rs",
    "engine/crates/synsema-cli/src/stdio.rs",
    "engine/crates/synsema-stdlib/src/proc.rs",
    "engine/crates/synsema-stdlib/src/attest.rs",
    // Archivos de pesos mapeados en memoria y SIMD de la inferencia local.
    "engine/crates/synsema-infer/src/backend_rust.rs",
    "engine/crates/synsema-infer/src/mapped.rs",
    // La ABI de wasm (memoria lineal compartida con el host).
    "engine/crates/synsema-wasm-web/src/lib.rs",
    "packages/guests/vela/src/lib.rs",
    // Tests: un allocator que cuenta, y un handle de prueba.
    "engine/crates/synsema-core/tests/alloc_counts.rs",
    "engine/crates/synsema-jit/tests/alloc_native.rs",
    "engine/crates/synsema-stdlib/tests/agentic_hub.rs",
    "engine/crates/synsema-runtime/tests/module_envs_freed.rs",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().expect("raíz del repo")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name();
        if p.is_dir() {
            if name != "target" && name != "node_modules" && name != ".git" {
                walk(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") && !p.ends_with("tests/unsafe_allowlist.rs") {
            out.push(p);
        }
    }
}

/// `unsafe` como palabra en código (no en comentarios ni en el nombre del lint `unsafe_code`).
fn has_unsafe(src: &str) -> bool {
    src.lines().any(|l| {
        let code = l.split("//").next().unwrap_or("");
        code.match_indices("unsafe").any(|(i, _)| {
            let before = code[..i].chars().next_back();
            let after = code[i + 6..].chars().next();
            let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
            !word(before) && !word(after)
        })
    })
}

#[test]
fn unsafe_only_where_allowed() {
    let root = repo_root();
    let mut files = Vec::new();
    walk(&root.join("engine/crates"), &mut files);
    walk(&root.join("packages/guests"), &mut files);
    let mut found = Vec::new();
    for f in &files {
        let Ok(src) = std::fs::read_to_string(f) else { continue };
        if has_unsafe(&src) {
            found.push(f.strip_prefix(&root).unwrap_or(f).display().to_string().replace('\\', "/"));
        }
    }
    let extra: Vec<&String> = found.iter().filter(|f| !ALLOWED.contains(&f.as_str())).collect();
    assert!(extra.is_empty(), "`unsafe` fuera de la lista permitida: {:?}", extra);
    assert!(found.iter().any(|f| f.ends_with("synsema-jit/src/abi.rs")), "el test no ve abi.rs: ¿cambió la ruta?");
    assert!(!found.iter().any(|f| f.contains("synsema-core/src/")), "core tiene `unsafe`");
}

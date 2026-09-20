//! Los fragmentos de la skill que dicen ser programas TIENEN que parsear.
//!
//! Auditoría externa (ronda 6): "seis fragmentos de la documentación no parsean, dos ya
//! reportados en la ronda anterior". Encontrarlos a mano es lo que falla: un bloque cerrado con
//! ``` puede ser Synsema, salida de consola, una tabla o un `.fsyn`, y adivinarlo con heurísticas
//! da falsos positivos a montones. Así que la convención es explícita: un bloque etiquetado
//! **```synsema** es un programa completo y este test lo carga. Lo que no está etiquetado no se
//! mira — es opt-in, y crece.
//!
//! Se comprueba la CARGA (lexer + parser + nombres protegidos), no la ejecución: un fragmento de
//! la documentación habla de red, disco o LLMs y no se puede correr acá.

use std::fs;
use std::path::{Path, PathBuf};

use synsema_core::interpreter::check_protected_names;
use synsema_core::parser::parse_source;

fn skill_dir() -> Option<PathBuf> {
    // `CARGO_MANIFEST_DIR` = engine/crates/synsema-core
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3)?.to_path_buf();
    let d = root.join(".synsema-skill");
    d.is_dir().then_some(d)
}

/// Los bloques ```synsema de un archivo Markdown, con la línea donde empieza cada uno.
fn synsema_blocks(md: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut lines = md.lines().enumerate();
    while let Some((i, l)) = lines.next() {
        if l.trim_end() != "```synsema" {
            continue;
        }
        let mut body = String::new();
        for (_, b) in lines.by_ref() {
            if b.trim_end() == "```" {
                break;
            }
            body.push_str(b);
            body.push('\n');
        }
        out.push((i + 2, body));
    }
    out
}

#[test]
fn every_tagged_snippet_in_the_skill_loads() {
    let Some(dir) = skill_dir() else {
        // El crate se puede publicar solo; sin la skill al lado no hay nada que comprobar.
        return;
    };
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("leer .synsema-skill")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("md"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no hay .md en {}", dir.display());

    let mut checked = 0usize;
    let mut bad: Vec<String> = Vec::new();
    for f in &files {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        let md = fs::read_to_string(f).unwrap_or_default();
        for (line, body) in synsema_blocks(&md) {
            checked += 1;
            let origin = format!("{}:{}", name, line);
            match parse_source(&body, &origin) {
                Err(e) => bad.push(format!("{} — {}", origin, e)),
                Ok(program) => {
                    if let Err(synsema_core::interpreter::Control::Error(e)) = check_protected_names(&program) {
                        bad.push(format!("{} — {}", origin, e.message));
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{} fragmento(s) de la skill no cargan:\n{}", bad.len(), bad.join("\n"));
    // Anti-rot: si alguien borra la etiqueta de todos los bloques, el test no debe pasar vacío.
    assert!(checked >= 75, "sólo {} fragmentos etiquetados: ¿se perdieron las etiquetas?", checked);
}

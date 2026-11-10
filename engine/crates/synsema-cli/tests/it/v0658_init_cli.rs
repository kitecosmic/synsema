//! v0.6.58 (§3, I1, I2): `synsema init` escribe `synsema.json` sólo si no existe.

use std::path::PathBuf;

use serde_json::{json, Value};

use super::v0646_tanda_e_cli::synsema_env;

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("synsema-v0658-init-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn version() -> String {
    let (a, b, c) = synsema_core::project::engine_version();
    format!("{}.{}.{}", a, b, c)
}

/// I1: `init` (y `--pwa`, `--desktop`) escribe `{"synsema": "<esta versión>", "modules": {}}`, sin
/// `.new`; y el programa del scaffold corre con ese proyecto.
#[test]
fn i1_init_writes_the_project_manifest() {
    for flags in [&[][..], &["--pwa"][..], &["--desktop"][..]] {
        let d = dir(&format!("i1{}", flags.len() + flags.first().map_or(0, |f| f.len())));
        let mut args = vec!["init", "."];
        args.extend_from_slice(flags);
        let (code, out, err) = synsema_env(&d, &args, None, &[]);
        assert_eq!(code, 0, "{:?}: {}{}", flags, out, err);
        let m: Value = serde_json::from_str(&std::fs::read_to_string(d.join("synsema.json")).unwrap()).unwrap();
        assert_eq!(m, json!({"synsema": version(), "modules": {}}), "{:?}", flags);
        assert!(!d.join("synsema.json.new").exists());
        if flags.is_empty() {
            let (code, out, err) = synsema_env(&d, &["check", "hello.syn"], None, &[]);
            assert_eq!(code, 0, "{}{}", out, err);
        }
    }
}

/// I2: con un `synsema.json` ya escrito (de fábrica o editado), `init` no lo toca ni deja `.new`.
#[test]
fn i2_init_leaves_an_existing_manifest_alone() {
    let d = dir("i2");
    let (code, _, err) = synsema_env(&d, &["init", "."], None, &[]);
    assert_eq!(code, 0, "{}", err);
    let factory = std::fs::read(d.join("synsema.json")).unwrap();
    let (code, out, err) = synsema_env(&d, &["init", "."], None, &[]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("synsema.json ya existe (no se toca)"), "{}", out);
    assert_eq!(std::fs::read(d.join("synsema.json")).unwrap(), factory);
    let edited = "{\"synsema\": \"0.6.58\", \"modules\": {\"tok\": {\"url\": \"https://example.com/tok\"}}}\n";
    std::fs::write(d.join("synsema.json"), edited).unwrap();
    let (code, _, err) = synsema_env(&d, &["init", "."], None, &[]);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(std::fs::read_to_string(d.join("synsema.json")).unwrap(), edited);
    assert!(!d.join("synsema.json.new").exists());
}

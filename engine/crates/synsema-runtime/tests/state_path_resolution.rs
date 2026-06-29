//! DE-031 — el estado persistente (memoria/planes) es **project-local** por default.
//!
//! Antes vivía en `~/.synsema/state/<stem>.db` (global, keyed por nombre de archivo) →
//! dos proyectos con `main.syn` compartían DB. Ahora: `<dir-del-programa>/.synsema/state/
//! <name>.db`, con overrides `SYNSEMA_STATE_DIR` y `SYNSEMA_STATE_NAME`.
//!
//! Un único `#[test]` con chequeos secuenciales: muta variables de entorno del proceso
//! (globales), así que vive en su propio binario y no corre en paralelo con otros tests.

use std::path::PathBuf;

use synsema_runtime::engine::run_source;

fn unique_tmp(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("synsema_de031_{}_{}", std::process::id(), tag))
}

#[test]
fn state_path_is_project_local_with_overrides() {
    std::env::remove_var("SYNSEMA_STATE_DIR");
    std::env::remove_var("SYNSEMA_STATE_NAME");

    // ── 1. Default project-local: <dir-del-programa>/.synsema/state/<stem>.db ──────
    let proj = unique_tmp("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let prog = proj.join("myprog.syn");
    let r = run_source("remember(\"context\", \"v\")", prog.to_str().unwrap());
    assert!(r.success, "1: errors: {:?}", r.errors);
    let local_db = proj.join(".synsema").join("state").join("myprog.db");
    assert!(
        local_db.is_file(),
        "1: esperaba DB project-local en {}",
        local_db.display()
    );

    // ── 2. SYNSEMA_STATE_DIR pisa la ubicación (escape hatch) ─────────────────────
    let override_dir = unique_tmp("override");
    std::env::set_var("SYNSEMA_STATE_DIR", &override_dir);
    let r2 = run_source("remember(\"context\", \"v\")", prog.to_str().unwrap());
    assert!(r2.success, "2: errors: {:?}", r2.errors);
    let override_db = override_dir.join("myprog.db");
    assert!(
        override_db.is_file(),
        "2: esperaba DB en SYNSEMA_STATE_DIR {}",
        override_db.display()
    );
    std::env::remove_var("SYNSEMA_STATE_DIR");

    // ── 3. SYNSEMA_STATE_NAME: dos archivos de entrada comparten UNA DB ───────────
    let name_dir = unique_tmp("named");
    std::env::set_var("SYNSEMA_STATE_DIR", &name_dir);
    std::env::set_var("SYNSEMA_STATE_NAME", "alfred");
    let ra = run_source("remember(\"context\", \"v\")", proj.join("alfred_web.syn").to_str().unwrap());
    let rb = run_source("remember(\"context\", \"v\")", proj.join("alfred_cli.syn").to_str().unwrap());
    assert!(ra.success && rb.success, "3: errors: {:?} {:?}", ra.errors, rb.errors);
    assert!(
        name_dir.join("alfred.db").is_file(),
        "3: esperaba alfred.db compartido en {}",
        name_dir.display()
    );
    // y NO se crean DBs por-stem cuando STATE_NAME está fijo
    assert!(!name_dir.join("alfred_web.db").exists(), "3: no debía crearse alfred_web.db");
    assert!(!name_dir.join("alfred_cli.db").exists(), "3: no debía crearse alfred_cli.db");
    std::env::remove_var("SYNSEMA_STATE_DIR");
    std::env::remove_var("SYNSEMA_STATE_NAME");

    // ── 4. Dos proyectos con el MISMO nombre de archivo → DBs distintas (sin colisión)
    let proj_b = unique_tmp("projB");
    std::fs::create_dir_all(&proj_b).unwrap();
    let _ = run_source("remember(\"context\", \"v\")", proj_b.join("myprog.syn").to_str().unwrap());
    let local_db_b = proj_b.join(".synsema").join("state").join("myprog.db");
    assert!(local_db_b.is_file(), "4: esperaba DB propia en {}", local_db_b.display());
    assert_ne!(local_db, local_db_b, "4: dos proyectos no deben compartir DB");

    // cleanup
    for d in [&proj, &override_dir, &name_dir, &proj_b] {
        let _ = std::fs::remove_dir_all(d);
    }
}

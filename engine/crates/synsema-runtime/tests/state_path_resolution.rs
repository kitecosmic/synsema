//! DB-M1 — la identidad del estado persistente es la memoria DECLARADA
//! (`require memory("<nombre>")`), no el nombre del archivo.
//!
//! Antes (DE-031): `<dir-del-programa>/.synsema/state/<stem>.db`, con overrides
//! `SYNSEMA_STATE_DIR` y `SYNSEMA_STATE_NAME`. Ahora: `<dir>/.synsema/state/<nombre>.db`
//! donde `<nombre>` es el declarado; `SYNSEMA_STATE_DIR` sigue vivo (relocaliza el dir);
//! `SYNSEMA_STATE_NAME` queda deprecado e IGNORADO (la declaración es la identidad).
//!
//! Un único `#[test]` con chequeos secuenciales: muta variables de entorno del proceso
//! (globales), así que vive en su propio binario y no corre en paralelo con otros tests.

use std::path::PathBuf;

use synsema_runtime::engine::run_source;

fn unique_tmp(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("synsema_dbm1_{}_{}", std::process::id(), tag))
}

const DECLARED: &str = "require memory(\"brain\")\nremember(\"context\", \"v\")";

#[test]
fn state_path_follows_declared_identity() {
    std::env::remove_var("SYNSEMA_STATE_DIR");
    std::env::remove_var("SYNSEMA_STATE_NAME");

    // ── 1. Declarado + project-local: <dir-del-programa>/.synsema/state/<nombre>.db ──
    let proj = unique_tmp("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let prog = proj.join("myprog.syn");
    let r = run_source(DECLARED, prog.to_str().unwrap());
    assert!(r.success, "1: errors: {:?}", r.errors);
    let brain_db = proj.join(".synsema").join("state").join("brain.db");
    assert!(brain_db.is_file(), "1: esperaba DB declarada en {}", brain_db.display());
    // El stem del archivo YA NO define la identidad: no se crea myprog.db.
    assert!(
        !proj.join(".synsema").join("state").join("myprog.db").exists(),
        "1: no debía crearse myprog.db (la identidad es el nombre declarado)"
    );

    // ── 2. Renombrar el .syn no cambia nada (decisión #3): mismo brain.db ──────────
    let renamed = proj.join("otro_nombre.syn");
    let r2 = run_source(
        "require memory(\"brain\")\nprint(length(recall(\"context\")))",
        renamed.to_str().unwrap(),
    );
    assert!(r2.success, "2: errors: {:?}", r2.errors);
    assert_eq!(r2.output, vec!["1"], "2: el archivo renombrado debe ver la misma memoria");
    assert!(
        !proj.join(".synsema").join("state").join("otro_nombre.db").exists(),
        "2: no debía crearse otro_nombre.db"
    );

    // ── 3. SYNSEMA_STATE_DIR pisa la ubicación (escape hatch, sigue vivo) ──────────
    let override_dir = unique_tmp("override");
    std::env::set_var("SYNSEMA_STATE_DIR", &override_dir);
    let r3 = run_source(DECLARED, prog.to_str().unwrap());
    assert!(r3.success, "3: errors: {:?}", r3.errors);
    let override_db = override_dir.join("brain.db");
    assert!(override_db.is_file(), "3: esperaba DB en SYNSEMA_STATE_DIR {}", override_db.display());
    std::env::remove_var("SYNSEMA_STATE_DIR");

    // ── 4. SYNSEMA_STATE_NAME deprecado e IGNORADO con declaración (decisión #6) ───
    let name_dir = unique_tmp("named");
    std::env::set_var("SYNSEMA_STATE_DIR", &name_dir);
    std::env::set_var("SYNSEMA_STATE_NAME", "alfred");
    let r4 = run_source(DECLARED, proj.join("alfred_web.syn").to_str().unwrap());
    assert!(r4.success, "4: errors: {:?}", r4.errors);
    assert!(
        name_dir.join("brain.db").is_file(),
        "4: la identidad declarada manda: esperaba brain.db en {}",
        name_dir.display()
    );
    assert!(!name_dir.join("alfred.db").exists(), "4: SYNSEMA_STATE_NAME debe ignorarse");
    assert!(!name_dir.join("alfred_web.db").exists(), "4: el stem tampoco define identidad");
    std::env::remove_var("SYNSEMA_STATE_DIR");
    std::env::remove_var("SYNSEMA_STATE_NAME");

    // ── 5. Dos proyectos con el MISMO nombre declarado → DBs distintas (project-local)
    let proj_b = unique_tmp("projB");
    std::fs::create_dir_all(&proj_b).unwrap();
    let rb = run_source(DECLARED, proj_b.join("myprog.syn").to_str().unwrap());
    assert!(rb.success, "5: errors: {:?}", rb.errors);
    let brain_db_b = proj_b.join(".synsema").join("state").join("brain.db");
    assert!(brain_db_b.is_file(), "5: esperaba DB propia en {}", brain_db_b.display());
    assert_ne!(brain_db, brain_db_b, "5: dos proyectos no deben compartir DB");

    // ── 6. Dos ARCHIVOS del mismo proyecto con el mismo nombre declarado → UNA DB ──
    // (lo que antes exigía SYNSEMA_STATE_NAME hoy es el comportamiento natural).
    let rc = run_source(
        "require memory(\"brain\")\nprint(length(recall(\"context\")))",
        proj_b.join("cli.syn").to_str().unwrap(),
    );
    assert!(rc.success, "6: errors: {:?}", rc.errors);
    assert_eq!(rc.output, vec!["1"], "6: mismo nombre declarado = misma memoria");

    // cleanup
    for d in [&proj, &override_dir, &name_dir, &proj_b] {
        let _ = std::fs::remove_dir_all(d);
    }
}

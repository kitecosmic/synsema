//! Integración Rust de la base de datos a nivel motor (capa 6).
//! db usa el motor normal (no-secure); db_open/sql/… no están gateados.

use synsema_runtime::engine::run_source;

/// Persistencia a archivo entre dos runs (engines) distintos.
#[test]
fn db_file_persistence_cross_run() {
    let mut path = std::env::temp_dir();
    path.push("synsema_rust_db_gate.db");
    let _ = std::fs::remove_file(&path);
    // Backslashes escapados para el literal de string Synsema.
    let p = path.to_string_lossy().replace('\\', "\\\\");

    let src1 = format!(
        "require db\ndb_open(\"{p}\")\nsql_exec(\"CREATE TABLE IF NOT EXISTS test (val TEXT)\")\nsql_exec(\"INSERT INTO test VALUES (?)\", [\"hello\"])\ndb_close()"
    );
    let r1 = run_source(&src1, "<t>");
    assert!(r1.success, "run1: {:?}", r1.errors);

    // Engine nuevo: lee de vuelta.
    let src2 = format!(
        "require db\ndb_open(\"{p}\")\nlet rows be sql(\"SELECT * FROM test\")\nprint(text(length(rows)))\ndb_close()"
    );
    let r2 = run_source(&src2, "<t>");
    assert!(r2.success, "run2: {:?}", r2.errors);
    assert_eq!(r2.output, vec!["1"]);

    let _ = std::fs::remove_file(&path);
}

/// sql sin db_open → error limpio "No database connection…".
/// (Sin conexión no hay scope que autorizar → el op da su error, no una violación.)
#[test]
fn db_no_connection_error() {
    let r = run_source("let rows be sql(\"SELECT 1\")", "<t>");
    assert!(!r.success);
    assert!(
        r.errors.iter().any(|e| e.contains("No database connection")),
        "got {:?}",
        r.errors
    );
}

// =========================================================
// DE-025 — la capacidad `db` es deny-by-default (gateada)
// =========================================================

/// Sin `require db` → violación con string exacto. run_source es modo `run` (no-secure):
/// confirma además que `db` NO se auto-otorga (a diferencia de stdout/time).
#[test]
fn db_deny_by_default_in_run() {
    let r = run_source("db_open(\":memory:\", \"memory\")", "<t>");
    assert!(!r.success, "db debe ser deny-by-default incluso en run");
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: db(\":memory:\")".to_string()]
    );
}

/// Con `require db(scope)` adecuado las ops funcionan.
#[test]
fn db_grant_works() {
    let r = run_source(
        "require db(\":memory:\")\ndb_open(\":memory:\", \"memory\")\nsql_exec(\"CREATE TABLE t(x)\")\nlet rows be sql(\"SELECT * FROM t\")\nprint(text(length(rows)))",
        "<t>",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["0".to_string()]);
}

/// El scope no cubre otra base: `db("a.db")` no autoriza `db_open("b.db")`.
#[test]
fn db_scope_mismatch_violates() {
    let r = run_source(
        "require db(\"a.db\")\ndb_open(\"b.db\", \"readwrite\")",
        "<t>",
    );
    assert!(!r.success);
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: db(\"b.db\")".to_string()]
    );
}

/// `sandbox` despoja la capability `db`: una op de datos dentro viola, aunque la conexión
/// siga abierta (el sandbox quita caps, no conexiones).
#[test]
fn db_sandbox_strips_capability() {
    let r = run_source(
        "require db(\":memory:\")\ndb_open(\":memory:\", \"memory\")\nsandbox\n    let r be sql(\"SELECT 1\")",
        "<t>",
    );
    assert!(!r.success, "el sandbox debería denegar db");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted: db")),
        "got {:?}",
        r.errors
    );
}

// =========================================================
// MF-010 — round-trip bytes ↔ BLOB byte-exacto
// =========================================================

#[test]
fn db_blob_bytes_roundtrip() {
    // bytes("hi") → BLOB → bytes; type_of es "bytes" y decode recupera el texto.
    let r = run_source(
        "require db\n\
         db_open(\":memory:\", \"memory\")\n\
         sql_exec(\"CREATE TABLE b(d BLOB)\")\n\
         sql_exec(\"INSERT INTO b VALUES (?)\", [bytes(\"hi\")])\n\
         let rows be sql(\"SELECT d FROM b\")\n\
         let d be rows[0][\"d\"]\n\
         print(type_of(d))\n\
         print(decode(d))\n",
        "<t>",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["bytes".to_string(), "hi".to_string()]);
}

#[test]
fn db_blob_non_utf8_roundtrip() {
    // Un blob no-UTF8 (255,254,0) hace round-trip exacto (antes se corrompía a hex-text).
    let r = run_source(
        "require db\n\
         db_open(\":memory:\", \"memory\")\n\
         sql_exec(\"CREATE TABLE b(d BLOB)\")\n\
         sql_exec(\"INSERT INTO b VALUES (?)\", [bytes([255, 254, 0])])\n\
         let rows be sql(\"SELECT d FROM b\")\n\
         let d be rows[0][\"d\"]\n\
         print(type_of(d))\n\
         print(text(length(d)))\n\
         print(text(d[0]) + \",\" + text(d[1]) + \",\" + text(d[2]))\n",
        "<t>",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["bytes".to_string(), "3".to_string(), "255,254,0".to_string()]
    );
}

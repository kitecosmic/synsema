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
        "db_open(\"{p}\")\nsql_exec(\"CREATE TABLE IF NOT EXISTS test (val TEXT)\")\nsql_exec(\"INSERT INTO test VALUES (?)\", [\"hello\"])\ndb_close()"
    );
    let r1 = run_source(&src1, "<t>");
    assert!(r1.success, "run1: {:?}", r1.errors);

    // Engine nuevo: lee de vuelta.
    let src2 = format!(
        "db_open(\"{p}\")\nlet rows be sql(\"SELECT * FROM test\")\nprint(text(length(rows)))\ndb_close()"
    );
    let r2 = run_source(&src2, "<t>");
    assert!(r2.success, "run2: {:?}", r2.errors);
    assert_eq!(r2.output, vec!["1"]);

    let _ = std::fs::remove_file(&path);
}

/// sql sin db_open → error limpio "No database connection…".
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

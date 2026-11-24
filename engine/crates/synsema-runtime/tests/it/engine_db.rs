//! Verifica persistencia entre dos motores distintos (contrato del host).

use synsema_runtime::engine::run_source;

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

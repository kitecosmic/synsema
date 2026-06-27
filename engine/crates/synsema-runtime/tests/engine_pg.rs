//! Conformidad de Postgres (M1) bajo la API universal `db_open`/`sql`.
//!
//! Los tests de **capability/routing** corren SIEMPRE (sin servidor): el chequeo de
//! `db(scope)` precede a la conexión, y un connstring a un puerto muerto falla con un
//! error de red (no de capability), lo que prueba que el gate pasó y el ruteo a Postgres
//! funciona. Los de **tipos/pgvector** necesitan un Postgres real → `#[ignore]`, gated por
//! `DATABASE_URL` (mismo patrón que `acme_pebble`). Corre: `cargo test -- --ignored` con
//! `DATABASE_URL=postgres://…` seteada.

use synsema_runtime::engine::run_source;

fn pg_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok()
}

// =========================================================
// Capability + routing (sin servidor)
// =========================================================

/// `db_open("postgres://…")` sin `require db` → violación con el scope canónico
/// (sin credenciales/puerto). Tampoco se auto-otorga en run.
#[test]
fn pg_db_open_deny_without_require() {
    let r = run_source(
        "db_open(\"postgres://user:pw@localhost:5432/appdb\")",
        "<t>",
    );
    assert!(!r.success);
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: db(\"postgres://localhost/appdb\")".to_string()]
    );
}

/// El scope URL es fiel: una grant a una base no cubre otra.
#[test]
fn pg_scope_mismatch_deny() {
    let r = run_source(
        "require db(\"postgres://localhost/appdb\")\ndb_open(\"postgres://localhost/otra\")",
        "<t>",
    );
    assert!(!r.success);
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: db(\"postgres://localhost/otra\")".to_string()]
    );
}

/// Con el grant adecuado el gate pasa y se rutea a Postgres; el puerto muerto da un error
/// de RED (no de capability) → prueba "pasó el gate + ruteo a PG" sin un servidor real.
#[test]
fn pg_gate_passes_routing_to_postgres() {
    let r = run_source(
        "require db\ndb_open(\"postgres://postgres@127.0.0.1:59999/nope?sslmode=disable\")",
        "<t>",
    );
    assert!(!r.success, "conectar a un puerto muerto debe fallar");
    assert!(
        !r.errors.iter().any(|e| e.contains("Capability not granted")),
        "no debe ser violación de capability (el gate pasó): {:?}",
        r.errors
    );
}

// =========================================================
// Tipos + pgvector (requieren Postgres real → #[ignore])
// =========================================================

#[test]
#[ignore = "requiere un Postgres real (DATABASE_URL)"]
fn pg_types_roundtrip() {
    let url = pg_url().expect("DATABASE_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         sql_exec(\"DROP TABLE IF EXISTS syn_m1\")\n\
         sql_exec(\"CREATE TABLE syn_m1 (i int, f float8, n numeric, t text, b bytea, j jsonb, flag bool)\")\n\
         sql_exec(\"INSERT INTO syn_m1 VALUES (?, ?, ?, ?, ?, ?::jsonb, ?)\", [42, 3.5, 9.99, \"hola\", bytes(\"hi\"), \"{{\\\"k\\\":1}}\", true])\n\
         let rows be sql(\"SELECT i, f, n, t, b, j, flag FROM syn_m1\")\n\
         let r be rows[0]\n\
         print(text(r[\"i\"]))\n\
         print(text(r[\"f\"]))\n\
         print(type_of(r[\"n\"]))\n\
         print(r[\"t\"])\n\
         print(type_of(r[\"b\"]))\n\
         print(decode(r[\"b\"]))\n\
         print(type_of(r[\"j\"]))\n\
         print(text(r[\"flag\"]))\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["42", "3.5", "decimal", "hola", "bytes", "hi", "map", "true"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
    );
}

#[test]
#[ignore = "requiere un Postgres real con pgvector (DATABASE_URL)"]
fn pg_pgvector_knn() {
    let url = pg_url().expect("DATABASE_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         sql_exec(\"CREATE EXTENSION IF NOT EXISTS vector\")\n\
         sql_exec(\"DROP TABLE IF EXISTS syn_vec\")\n\
         sql_exec(\"CREATE TABLE syn_vec (id int, emb vector(3))\")\n\
         sql_exec(\"INSERT INTO syn_vec VALUES (1, ?::vector), (2, ?::vector), (3, ?::vector)\", [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.9, 0.1, 0.0]])\n\
         let q be [1.0, 0.0, 0.0]\n\
         let rows be sql(\"SELECT id FROM syn_vec ORDER BY emb <-> ?::vector LIMIT ?\", [q, 2])\n\
         print(text(length(rows)))\n\
         print(text(rows[0][\"id\"]))\n\
         let one be sql(\"SELECT emb FROM syn_vec WHERE id = 1\")\n\
         print(type_of(one[0][\"emb\"]))\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    // El más cercano a [1,0,0] es id 1; el retorno de la columna vector es una list.
    assert_eq!(
        r.output,
        vec!["2", "1", "list"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
    );
}

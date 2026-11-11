//! Conformidad de Postgres (M1) bajo la API universal `db_open`/`sql`.
//!
//! Los tests de **capability/routing** corren SIEMPRE (sin servidor): el chequeo de
//! `db(scope)` precede a la conexión, y un connstring a un puerto muerto falla con un
//! error de red (no de capability), lo que prueba que el gate pasó y el ruteo a Postgres
//! funciona. Los de **tipos/pgvector** necesitan un Postgres real → `#[ignore]`, gated por
//! `DATABASE_URL` (mismo patrón que `acme_pebble`). Corre: `cargo test -- --ignored` con
//! `DATABASE_URL=postgres://…` seteada.

use synsema_runtime::engine::run_source;

/// Un puerto local donde no escucha nadie: se pide al sistema y se suelta (un número fijo, como el
/// 59999 de antes, cae en el rango que el sistema reparte y otro proceso lo puede tener abierto).
fn dead_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

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
        vec!["Runtime error: Capability not granted: db(\"postgres://localhost/appdb\") — this is a permission, not a bug: add `require db(\"postgres://localhost/appdb\")` to the program's preamble (or to the importing file, when this code runs in a module)".to_string()]
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
        vec!["Runtime error: Capability not granted: db(\"postgres://localhost/otra\") — this is a permission, not a bug: add `require db(\"postgres://localhost/otra\")` to the program's preamble (or to the importing file, when this code runs in a module)".to_string()]
    );
}

/// Con el grant adecuado el gate pasa y se rutea a Postgres; el puerto muerto da un error
/// de RED (no de capability) → prueba "pasó el gate + ruteo a PG" sin un servidor real.
#[test]
fn pg_gate_passes_routing_to_postgres() {
    let r = run_source(
        &format!("require db\ndb_open(\"postgres://postgres@127.0.0.1:{}/nope?sslmode=disable\")", dead_port()),
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

/// v0.6.59 — `sql_transaction` en Postgres: deshace si la task falla y confirma si devuelve;
/// adentro de otra es un savepoint; el DDL es transaccional (una tabla creada en una transacción
/// que falla no queda); el control a mano es un error; y un statement que falla hace fallar la
/// transacción aunque la task lo atrape (Postgres la deja abortada: un `COMMIT` ahí contesta
/// `ROLLBACK` sin dar error, así que no se manda).
#[test]
#[ignore = "requiere un Postgres real (DATABASE_URL)"]
fn pg_transactions() {
    let url = pg_url().expect("DATABASE_URL no seteada");
    let src = format!(
        r#"require db("{url}")
db_open("{url}")
sql_exec("DROP TABLE IF EXISTS syn_m1_tx")
sql_exec("DROP TABLE IF EXISTS syn_m1_tx2")
sql_exec("CREATE TABLE syn_m1_tx (v int)")
task count()
    let rows be sql("SELECT COUNT(*) AS c FROM syn_m1_tx")
    give text(rows[0]["c"])
task fails()
    sql_exec("INSERT INTO syn_m1_tx VALUES (1)")
    raise("no")
try
    sql_transaction(fails)
recover e
    print(e + " " + count())
sql_transaction(() => sql_exec("INSERT INTO syn_m1_tx VALUES (2)"))
print(count())
task nested()
    sql_exec("INSERT INTO syn_m1_tx VALUES (3)")
    try
        sql_transaction(fails)
    recover e
        print("inner " + e)
    give "outer"
print(sql_transaction(nested) + " " + count())
task ddl_inside()
    sql_exec("CREATE TABLE syn_m1_tx2 (v int)")
    sql_exec("INSERT INTO syn_m1_tx2 VALUES (1)")
    raise("after ddl")
try
    sql_transaction(ddl_inside)
recover e
    print(e)
print(text(length(sql("SELECT tablename FROM pg_tables WHERE tablename = 'syn_m1_tx2'"))))
try
    sql_exec("BEGIN")
recover e
    print(e)
task caught_error()
    try
        sql_exec("INSERT INTO syn_m1_missing VALUES (1)")
    recover e
        print("ignored")
    sql_exec("INSERT INTO syn_m1_tx VALUES (5)")
try
    sql_transaction(caught_error)
recover e
    print(e)
task caught_and_silent()
    sql_exec("INSERT INTO syn_m1_tx VALUES (6)")
    try
        sql_exec("INSERT INTO syn_m1_missing VALUES (1)")
    recover e
        print("ignored")
    give "returned"
try
    print(sql_transaction(caught_and_silent))
recover e
    print(e)
print(count())
db_close()
"#
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    let o = r.output;
    assert_eq!(o.len(), 12, "{:?}", o);
    assert_eq!(&o[..6], ["no 0", "1", "inner no", "outer 2", "after ddl", "0"], "{:?}", o);
    assert!(o[6].starts_with("BEGIN, COMMIT, ROLLBACK and SAVEPOINT are not run by hand"), "{:?}", o);
    assert_eq!(o[7], "ignored");
    assert!(o[8].starts_with("sql_transaction: a statement failed inside this transaction"), "{:?}", o);
    assert_eq!(o[9], "ignored");
    assert!(o[10].starts_with("sql_transaction: a statement failed inside this transaction"), "la task devolvió, pero no se confirma: {:?}", o);
    assert_eq!(o[11], "2", "{:?}", o);
}

/// v0.6.59 — lo que el motor no ve por las primeras palabras, medido contra un Postgres real: un
/// `CALL` o un `DO` con `COMMIT` adentro. Postgres lo cierra solo: adentro de una transacción da
/// «invalid transaction termination» (y la transacción falla, como con cualquier statement), y
/// afuera confirma lo suyo sin dejar nada abierto. Una llamada lleva un solo statement. `total()`
/// reabre la conexión: lo que hubiera quedado en una transacción abierta se pierde y no suma.
#[test]
#[ignore = "requiere un Postgres real (DATABASE_URL)"]
fn pg_procedures_and_transactions() {
    let url = pg_url().expect("DATABASE_URL no seteada");
    let src = format!(
        r#"require db("{url}")
db_open("{url}")
sql_exec("DROP TABLE IF EXISTS syn_m1_p")
sql_exec("CREATE TABLE syn_m1_p (v int)")
sql_exec("CREATE OR REPLACE PROCEDURE syn_m1_commit() LANGUAGE plpgsql AS 'BEGIN INSERT INTO syn_m1_p VALUES (1); COMMIT; INSERT INTO syn_m1_p VALUES (2); END'")
task total()
    db_close()
    db_open("{url}")
    let rows be sql("SELECT COALESCE(SUM(v), 0)::int AS s FROM syn_m1_p")
    give text(rows[0]["s"])
sql_exec("CALL syn_m1_commit()")
sql_exec("INSERT INTO syn_m1_p VALUES (4)")
print("A " + total())
task call_inside()
    sql_exec("INSERT INTO syn_m1_p VALUES (8)")
    sql_exec("CALL syn_m1_commit()")
try
    sql_transaction(call_inside)
recover e
    print(e)
print("B " + total())
task do_inside()
    sql_exec("INSERT INTO syn_m1_p VALUES (16)")
    sql_exec("DO 'BEGIN COMMIT; END'")
try
    sql_transaction(do_inside)
recover e
    print(e)
print("C " + total())
sql_exec("DO 'BEGIN INSERT INTO syn_m1_p VALUES (32); COMMIT; END'")
sql_exec("INSERT INTO syn_m1_p VALUES (64)")
print("D " + total())
try
    sql_exec("INSERT INTO syn_m1_p VALUES (128); COMMIT")
recover e
    print("E refused")
print("E " + total())
db_close()
"#
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    let o = r.output;
    assert_eq!(o.len(), 8, "{:?}", o);
    assert_eq!(o[0], "A 7", "afuera, el procedimiento confirma lo suyo y no deja nada abierto: {:?}", o);
    assert!(o[1].contains("invalid transaction termination"), "{:?}", o);
    assert_eq!(o[2], "B 7", "{:?}", o);
    assert!(o[3].contains("invalid transaction termination"), "{:?}", o);
    assert_eq!(&o[4..], ["C 7", "D 103", "E refused", "E 103"], "{:?}", o);
}

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

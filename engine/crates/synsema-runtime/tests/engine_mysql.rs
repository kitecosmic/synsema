//! Conformidad de MySQL (M2) bajo la API universal `db_open`/`sql`.
//!
//! Los tests de **capability/routing** corren SIEMPRE (sin servidor): el chequeo de
//! `db(scope)` precede a la conexión, y un connstring a un puerto muerto falla con un error
//! de red (no de capability), lo que prueba que el gate pasó y el ruteo a MySQL funciona.
//! Los de **tipos/last_id/tx** necesitan un MySQL real → `#[ignore]`, gated por `MYSQL_URL`
//! (o `DATABASE_URL` como fallback). Corre: `cargo test -- --ignored` con
//! `MYSQL_URL=mysql://synsema:synsema@localhost:3306/appdb` seteada.

use synsema_runtime::engine::run_source;

fn mysql_url() -> Option<String> {
    std::env::var("MYSQL_URL")
        .ok()
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .filter(|u| u.starts_with("mysql://"))
}

// =========================================================
// Capability + routing (sin servidor)
// =========================================================

/// `db_open("mysql://…")` sin `require db` → violación con el scope canónico (sin
/// credenciales/puerto). Tampoco se auto-otorga en run.
#[test]
fn mysql_db_open_deny_without_require() {
    let r = run_source("db_open(\"mysql://user:pw@localhost:3306/appdb\")", "<t>");
    assert!(!r.success);
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: db(\"mysql://localhost/appdb\")".to_string()]
    );
}

/// El scope URL es fiel: una grant a una base no cubre otra.
#[test]
fn mysql_scope_mismatch_deny() {
    let r = run_source(
        "require db(\"mysql://localhost/appdb\")\ndb_open(\"mysql://localhost/otra\")",
        "<t>",
    );
    assert!(!r.success);
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: db(\"mysql://localhost/otra\")".to_string()]
    );
}

/// Con el grant adecuado el gate pasa y se rutea a MySQL; el puerto muerto da un error de
/// RED (no de capability) → prueba "pasó el gate + ruteo a MySQL" sin un servidor real.
#[test]
fn mysql_gate_passes_routing_to_mysql() {
    let r = run_source(
        "require db\ndb_open(\"mysql://root@127.0.0.1:59999/nope\")",
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
// Tipos + last_id + transacciones (requieren MySQL real → #[ignore])
// =========================================================

/// Round-trip de tipos con `?` **nativo** (sin reescritura): int/double/decimal/text/
/// blob→bytes (flag BINARY)/json→map/tinyint. DECIMAL → `type_of` "decimal"; BLOB → bytes
/// (round-trip MF-010); JSON → map. MySQL no tiene bool real → el flag se lee como número.
#[test]
#[ignore = "requiere un MySQL real (MYSQL_URL)"]
fn mysql_types_roundtrip() {
    let url = mysql_url().expect("MYSQL_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         sql_exec(\"DROP TABLE IF EXISTS syn_m2\")\n\
         sql_exec(\"CREATE TABLE syn_m2 (i INT, f DOUBLE, n DECIMAL(10,2), t TEXT, b BLOB, j JSON, flag TINYINT)\")\n\
         sql_exec(\"INSERT INTO syn_m2 VALUES (?, ?, ?, ?, ?, ?, ?)\", [42, 3.5, 9.99, \"hola\", bytes(\"hi\"), \"{{\\\"k\\\":1}}\", true])\n\
         let rows be sql(\"SELECT i, f, n, t, b, j, flag FROM syn_m2\")\n\
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
        vec!["42", "3.5", "decimal", "hola", "bytes", "hi", "map", "1"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
    );
}

/// `last_id` = `last_insert_id()` real (a diferencia de PG, que da 0). DROP previo → el
/// AUTO_INCREMENT arranca en 1 → `last_id == 1` determinístico.
#[test]
#[ignore = "requiere un MySQL real (MYSQL_URL)"]
fn mysql_last_insert_id() {
    let url = mysql_url().expect("MYSQL_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         sql_exec(\"DROP TABLE IF EXISTS syn_m2_ai\")\n\
         sql_exec(\"CREATE TABLE syn_m2_ai (id INT AUTO_INCREMENT PRIMARY KEY, v INT)\")\n\
         let r be sql_exec(\"INSERT INTO syn_m2_ai (v) VALUES (?)\", [100])\n\
         print(text(r[\"rows_affected\"]))\n\
         print(text(r[\"last_id\"]))\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["1", "1"].into_iter().map(String::from).collect::<Vec<_>>()
    );
}

/// Transacciones en la conexión única: ROLLBACK descarta, COMMIT persiste.
#[test]
#[ignore = "requiere un MySQL real (MYSQL_URL)"]
fn mysql_transactions() {
    let url = mysql_url().expect("MYSQL_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         sql_exec(\"DROP TABLE IF EXISTS syn_m2_tx\")\n\
         sql_exec(\"CREATE TABLE syn_m2_tx (v INT) ENGINE=InnoDB\")\n\
         sql_exec(\"START TRANSACTION\")\n\
         sql_exec(\"INSERT INTO syn_m2_tx VALUES (1)\")\n\
         sql_exec(\"ROLLBACK\")\n\
         let a be sql(\"SELECT COUNT(*) AS c FROM syn_m2_tx\")\n\
         print(text(a[0][\"c\"]))\n\
         sql_exec(\"START TRANSACTION\")\n\
         sql_exec(\"INSERT INTO syn_m2_tx VALUES (2)\")\n\
         sql_exec(\"COMMIT\")\n\
         let b be sql(\"SELECT COUNT(*) AS c FROM syn_m2_tx\")\n\
         print(text(b[0][\"c\"]))\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["0", "1"].into_iter().map(String::from).collect::<Vec<_>>()
    );
}

/// `sql_tables()` lista las tablas del esquema actual (vía information_schema).
#[test]
#[ignore = "requiere un MySQL real (MYSQL_URL)"]
fn mysql_tables_lists_created() {
    let url = mysql_url().expect("MYSQL_URL no seteada");
    let src = format!(
        "require db(\"{url}\")\n\
         db_open(\"{url}\")\n\
         sql_exec(\"DROP TABLE IF EXISTS syn_m2_t1\")\n\
         sql_exec(\"CREATE TABLE syn_m2_t1 (id INT)\")\n\
         let ts be sql_tables()\n\
         print(text(contains(ts, \"syn_m2_t1\")))\n\
         db_close()\n"
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["true".to_string()]);
}

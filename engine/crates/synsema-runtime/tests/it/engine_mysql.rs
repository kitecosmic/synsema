//! Conformidad de MySQL (M2) bajo la API universal `db_open`/`sql`.
//!
//! Los tests de **capability/routing** corren SIEMPRE (sin servidor): el chequeo de
//! `db(scope)` precede a la conexión, y un connstring a un puerto muerto falla con un error
//! de red (no de capability), lo que prueba que el gate pasó y el ruteo a MySQL funciona.
//! Los de **tipos/last_id/tx** necesitan un MySQL real → `#[ignore]`, gated por `MYSQL_URL`
//! (o `DATABASE_URL` como fallback). Corre: `cargo test -- --ignored` con
//! `MYSQL_URL=mysql://synsema:synsema@localhost:3306/appdb` seteada.

use synsema_runtime::engine::run_source;

/// Un puerto local donde no escucha nadie: se pide al sistema y se suelta (un número fijo, como el
/// 59999 de antes, cae en el rango que el sistema reparte y otro proceso lo puede tener abierto).
fn dead_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

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
        vec!["Runtime error: Capability not granted: db(\"mysql://localhost/appdb\") — this is a permission, not a bug: add `require db(\"mysql://localhost/appdb\")` to the program's preamble (or to the importing file, when this code runs in a module)".to_string()]
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
        vec!["Runtime error: Capability not granted: db(\"mysql://localhost/otra\") — this is a permission, not a bug: add `require db(\"mysql://localhost/otra\")` to the program's preamble (or to the importing file, when this code runs in a module)".to_string()]
    );
}

/// Con el grant adecuado el gate pasa y se rutea a MySQL; el puerto muerto da un error de
/// RED (no de capability) → prueba "pasó el gate + ruteo a MySQL" sin un servidor real.
#[test]
fn mysql_gate_passes_routing_to_mysql() {
    let r = run_source(
        &format!("require db\ndb_open(\"mysql://root@127.0.0.1:{}/nope\")", dead_port()),
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

/// v0.6.59 — `sql_transaction` en MySQL (antes, `START TRANSACTION`/`COMMIT` a mano): deshace si la
/// task falla y confirma si devuelve; adentro de otra es un savepoint; un DDL adentro se rechaza
/// (en MySQL confirmaría la transacción abierta); el control a mano es un error; y un statement
/// que falla hace fallar la transacción aunque la task lo atrape.
#[test]
#[ignore = "requiere un MySQL real (MYSQL_URL)"]
fn mysql_transactions() {
    let url = mysql_url().expect("MYSQL_URL no seteada");
    let src = format!(
        r#"require db("{url}")
db_open("{url}")
sql_exec("DROP TABLE IF EXISTS syn_m2_tx")
sql_exec("DROP TABLE IF EXISTS syn_m2_tx2")
sql_exec("CREATE TABLE syn_m2_tx (v INT) ENGINE=InnoDB")
task count()
    let rows be sql("SELECT COUNT(*) AS c FROM syn_m2_tx")
    give text(rows[0]["c"])
task fails()
    sql_exec("INSERT INTO syn_m2_tx VALUES (1)")
    raise("no")
try
    sql_transaction(fails)
recover e
    print(e + " " + count())
sql_transaction(() => sql_exec("INSERT INTO syn_m2_tx VALUES (2)"))
print(count())
task nested()
    sql_exec("INSERT INTO syn_m2_tx VALUES (3)")
    try
        sql_transaction(fails)
    recover e
        print("inner " + e)
    give "outer"
print(sql_transaction(nested) + " " + count())
task ddl_inside()
    sql_exec("INSERT INTO syn_m2_tx VALUES (4)")
    sql_exec("CREATE TABLE syn_m2_tx2 (v INT)")
try
    sql_transaction(ddl_inside)
recover e
    print(e)
print(count())
try
    sql_exec("START TRANSACTION")
recover e
    print(e)
task caught_error()
    try
        sql_exec("INSERT INTO syn_m2_missing VALUES (1)")
    recover e
        print("ignored")
    sql_exec("INSERT INTO syn_m2_tx VALUES (5)")
try
    sql_transaction(caught_error)
recover e
    print(e)
print(count())
print(text(length(sql("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'syn_m2_tx2'"))))
db_close()
"#
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    let o = r.output;
    assert_eq!(o.len(), 11, "{:?}", o);
    assert_eq!(&o[..4], ["no 0", "1", "inner no", "outer 2"], "{:?}", o);
    assert!(o[4].starts_with("sql_transaction: in MySQL a CREATE statement commits the open transaction"), "{:?}", o);
    assert_eq!(o[5], "2", "el INSERT de antes del DDL rechazado se deshizo: {:?}", o);
    assert!(o[6].starts_with("BEGIN, COMMIT, ROLLBACK and SAVEPOINT are not run by hand"), "{:?}", o);
    assert_eq!(o[7], "ignored");
    assert!(o[8].starts_with("sql_transaction: a statement failed inside this transaction"), "{:?}", o);
    assert_eq!(&o[9..], ["2", "0"], "{:?}", o);
}

/// v0.6.59 — lo que el motor no ve por las primeras palabras, medido contra un MySQL real: un
/// `CALL` corre el cuerpo de un procedimiento, que puede confirmar, deshacer o abrir una
/// transacción. Adentro de `sql_transaction` el `CALL` va entre un savepoint y su `RELEASE` (un
/// savepoint muere con su transacción); afuera, después del `CALL` se mira si quedó una abierta.
/// Además: `PREPARE`/`EXECUTE` de SQL se rechazan, `completion_type` no encadena el `COMMIT` del
/// motor, y una llamada lleva un solo statement. `total()` reabre la conexión: lo que hubiera
/// quedado en una transacción abierta se pierde y no suma.
#[test]
#[ignore = "requiere un MySQL real (MYSQL_URL)"]
fn mysql_procedures_and_transactions() {
    let url = mysql_url().expect("MYSQL_URL no seteada");
    let src = format!(
        r#"require db("{url}")
db_open("{url}")
sql_exec("DROP TABLE IF EXISTS syn_m2_p")
sql_exec("CREATE TABLE syn_m2_p (v INT) ENGINE=InnoDB")
sql_exec("DROP PROCEDURE IF EXISTS syn_m2_plain")
sql_exec("DROP PROCEDURE IF EXISTS syn_m2_commit")
sql_exec("DROP PROCEDURE IF EXISTS syn_m2_open")
sql_exec("DROP PROCEDURE IF EXISTS syn_m2_own")
sql_exec("DROP PROCEDURE IF EXISTS syn_m2_ac0")
sql_exec("CREATE PROCEDURE syn_m2_plain(IN n INT) INSERT INTO syn_m2_p VALUES (n)")
sql_exec("CREATE PROCEDURE syn_m2_commit() COMMIT")
sql_exec("CREATE PROCEDURE syn_m2_open() BEGIN START TRANSACTION; INSERT INTO syn_m2_p VALUES (64); END")
sql_exec("CREATE PROCEDURE syn_m2_own() BEGIN START TRANSACTION; INSERT INTO syn_m2_p VALUES (16); COMMIT; END")
sql_exec("CREATE PROCEDURE syn_m2_ac0() SET autocommit = 0")
sql_exec("DROP PROCEDURE IF EXISTS syn_m2_legacy")
sql_exec("DROP PROCEDURE IF EXISTS syn_m2_pending")
sql_exec("CREATE PROCEDURE syn_m2_legacy(IN n INT) BEGIN SET autocommit = 0; START TRANSACTION; INSERT INTO syn_m2_p VALUES (n); COMMIT; END")
sql_exec("CREATE PROCEDURE syn_m2_pending(IN n INT) BEGIN SET autocommit = 0; INSERT INTO syn_m2_p VALUES (n); END")
task total()
    db_close()
    db_open("{url}")
    let rows be sql("SELECT CAST(COALESCE(SUM(v), 0) AS SIGNED) AS s FROM syn_m2_p")
    give text(rows[0]["s"])
sql_transaction(() => sql_exec("CALL syn_m2_plain(1)"))
print("A " + total())
task plain_then_fail()
    sql_exec("CALL syn_m2_plain(?)", [2])
    raise("no")
try
    sql_transaction(plain_then_fail)
recover e
    print("B " + e + " " + total())
task commits_inside()
    sql_exec("INSERT INTO syn_m2_p VALUES (4)")
    sql_exec("CALL syn_m2_commit()")
    sql_exec("INSERT INTO syn_m2_p VALUES (8)")
    give "returned"
try
    print(sql_transaction(commits_inside))
recover e
    print(e)
print("C " + total())
task commits_inside_caught()
    try
        sql_exec("CALL syn_m2_commit()")
    recover e
        print("ignored")
    sql_exec("INSERT INTO syn_m2_p VALUES (8)")
try
    sql_transaction(commits_inside_caught)
recover e
    print(e)
print("C2 " + total())
sql_exec("CALL syn_m2_own()")
sql_exec("INSERT INTO syn_m2_p VALUES (32)")
print("D " + total())
try
    sql_exec("CALL syn_m2_open()")
recover e
    print(e)
sql_exec("INSERT INTO syn_m2_p VALUES (128)")
print("E " + total())
task ac0_inside()
    sql_exec("CALL syn_m2_ac0()")
    sql_exec("INSERT INTO syn_m2_p VALUES (256)")
sql_transaction(ac0_inside)
let inside be sql("SELECT @@autocommit AS a")
print("F " + text(inside[0]["a"]))
sql_exec("INSERT INTO syn_m2_p VALUES (512)")
print("F " + total())
sql_exec("CALL syn_m2_ac0()")
let outside be sql("SELECT @@autocommit AS a")
print("G " + text(outside[0]["a"]))
sql_exec("CALL syn_m2_legacy(?)", [16384])
let after_legacy be sql("SELECT @@autocommit AS a")
print("L " + text(after_legacy[0]["a"]) + " " + total())
try
    sql_exec("CALL syn_m2_pending(32768)")
recover e
    print(e)
sql_exec("INSERT INTO syn_m2_p VALUES (65536)")
print("M " + total())
try
    sql_exec("PREPARE s FROM 'COMMIT'")
recover e
    print(e)
sql_exec("SET completion_type = 1")
sql_transaction(() => sql_exec("INSERT INTO syn_m2_p VALUES (1024)"))
sql_exec("INSERT INTO syn_m2_p VALUES (2048)")
print("I " + total())
try
    sql_exec("INSERT INTO syn_m2_p VALUES (4096); COMMIT")
recover e
    print(e)
print("J " + total())
task two_inside()
    sql_exec("INSERT INTO syn_m2_p VALUES (8192); COMMIT")
try
    sql_transaction(two_inside)
recover e
    print("K refused")
print("K " + total())
db_close()
"#
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    let o = r.output;
    assert_eq!(o.len(), 22, "{:?}", o);
    assert_eq!(&o[..2], ["A 1", "B no 1"], "un procedimiento que sólo escribe confirma y se deshace con la transacción: {:?}", o);
    assert!(o[2].starts_with("sql_transaction: this CALL ended the transaction"), "{:?}", o);
    assert_eq!(o[3], "C 5", "lo que el procedimiento confirmó (4) queda, y lo de después no corre: {:?}", o);
    assert_eq!(o[4], "ignored");
    assert!(o[5].starts_with("sql_transaction: a statement failed inside this transaction"), "{:?}", o);
    assert_eq!(&o[6..8], ["C2 5", "D 53"], "afuera, un procedimiento que abre y confirma la suya no es un error: {:?}", o);
    assert!(o[8].starts_with("this CALL left a transaction open"), "{:?}", o);
    assert_eq!(o[9], "E 181", "el 64 se deshizo y el 128 de después quedó: la conexión está limpia: {:?}", o);
    assert_eq!(&o[10..12], ["F 1", "F 949"], "autocommit vuelve a 1 al cerrar la transacción: {:?}", o);
    // Ronda 2 (M-r2-1): apagar `autocommit` sin dejar nada pendiente no es un error; el motor lo
    // repone. El patrón de siempre (`SET autocommit = 0; START TRANSACTION; …; COMMIT`) anda, y
    // su fila queda una sola vez.
    assert_eq!(o[12], "G 1", "un procedimiento que sólo apaga autocommit lo encuentra repuesto: {:?}", o);
    assert_eq!(o[13], "L 1 17333", "el patrón clásico confirma lo suyo (16384) sin error: {:?}", o);
    assert!(o[14].starts_with("this CALL left a transaction open"), "{:?}", o);
    assert!(o[14].contains("what it had already committed stays"), "el mensaje no promete deshacer lo confirmado: {:?}", o);
    assert_eq!(o[15], "M 82869", "el 32768 sin confirmar se deshizo y el 65536 de después quedó: {:?}", o);
    assert!(o[16].starts_with("MySQL PREPARE and EXECUTE are not run from here"), "{:?}", o);
    assert_eq!(o[17], "I 85941", "con completion_type = 1 el COMMIT del motor no abre otra transacción: {:?}", o);
    // Un statement por llamada: antes, `INSERT …; COMMIT` corría los dos (el driver negocia
    // multi-statements) y el `COMMIT` no pasaba por el guardián.
    assert!(o[18].contains("one SQL statement per call"), "{:?}", o);
    assert_eq!(&o[19..], ["J 85941", "K refused", "K 85941"], "nada del texto con dos statements corrió: {:?}", o);
}

/// v0.6.59, ronda 2 (N-r2-1) — un `sql_exec` sin valores va por el protocolo de texto cuando el
/// texto no tiene un `;` (aparte del final): es un statement solo y cuesta una ida y vuelta, como
/// antes. Con un `;` adentro lo decide el servidor al prepararlo. `Com_stmt_prepare` cuenta los
/// prepares de la sesión; la consulta que lo lee se prepara una sola vez (el driver la guarda) y
/// ya está contada en `base`.
#[test]
#[ignore = "requiere un MySQL real (MYSQL_URL)"]
fn mysql_exec_without_values_prepares_only_a_text_with_a_semicolon() {
    let url = mysql_url().expect("MYSQL_URL no seteada");
    let src = format!(
        r#"require db("{url}")
db_open("{url}")
sql_exec("DROP TABLE IF EXISTS syn_m2_ps")
sql_exec("CREATE TABLE syn_m2_ps (id INT AUTO_INCREMENT PRIMARY KEY, v INT) ENGINE=InnoDB")
task prepares()
    let r be sql("SHOW SESSION STATUS LIKE 'Com_stmt_prepare'")
    give number(r[0]["Value"])
let base be prepares()
print("P0 " + text(prepares() == base))
let one be sql_exec("INSERT INTO syn_m2_ps (v) VALUES (1)")
let two be sql_exec("INSERT INTO syn_m2_ps (v) VALUES (2), (3);")
sql_exec("INSERT INTO syn_m2_ps (v) VALUES (4) ;  ")
print("P1 " + text(prepares() == base) + " " + text(one["rows_affected"]) + " " + text(one["last_id"]) + " " + text(two["rows_affected"]) + " " + text(two["last_id"]))
sql_exec("INSERT INTO syn_m2_ps (v) VALUES (5) /* a;b */")
print("P2 " + text(prepares() == base + 1))
try
    sql_exec("INSERT INTO syn_m2_ps (v) VALUES (6); INSERT INTO syn_m2_ps (v) VALUES (7)")
recover e
    print("P3 refused")
let rows be sql("SELECT CAST(SUM(v) AS SIGNED) AS s, COUNT(*) AS n FROM syn_m2_ps")
print("P4 " + text(rows[0]["s"]) + " " + text(rows[0]["n"]))
sql_exec("DROP TABLE syn_m2_ps")
db_close()
"#
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    let o = r.output;
    assert_eq!(o.len(), 5, "{:?}", o);
    assert_eq!(o[0], "P0 true", "leer el contador dos veces no prepara de nuevo: {:?}", o);
    assert_eq!(o[1], "P1 true 1 1 2 2", "sin `;` (o sólo el final) no se prepara nada, y da las mismas cuentas: {:?}", o);
    assert_eq!(o[2], "P2 true", "con un `;` adentro, aunque sea de un comentario, lo decide el servidor: {:?}", o);
    assert_eq!(&o[3..], ["P3 refused", "P4 15 5"], "el texto con dos statements no corrió ninguno: {:?}", o);
}

/// v0.6.59, ronda 3 (B-r3-1) — después de un `CALL` de afuera, lo que quedó en la conexión lo dice
/// el servidor en la respuesta del propio `CALL` (el seguimiento de estado de sesión). Es un error
/// lo que un `ROLLBACK` deshace y lo que se abrió con `START TRANSACTION`; una lectura con
/// `autocommit = 0` (el patrón de siempre seguido de un `SELECT`) no lo es. `total()` reabre la
/// conexión: lo que hubiera quedado en una transacción abierta se pierde y no suma.
///
/// Y la respuesta se lee hasta el final: un procedimiento que falla después de dar un resultado
/// es un error (hasta v0.6.58 pasaba por bueno), y un `CALL` corre una sola vez aunque el
/// procedimiento dé el número de error que el motor usa para elegir el protocolo.
#[test]
#[ignore = "requiere un MySQL real (MYSQL_URL)"]
fn mysql_call_outside_a_transaction_reads_what_the_server_reports() {
    let url = mysql_url().expect("MYSQL_URL no seteada");
    let src = format!(
        r#"require db("{url}")
db_open("{url}")
sql_exec("DROP TABLE IF EXISTS syn_m2_r3")
sql_exec("DROP TABLE IF EXISTS syn_m2_r3_my")
sql_exec("CREATE TABLE syn_m2_r3 (v INT) ENGINE=InnoDB")
sql_exec("CREATE TABLE syn_m2_r3_my (v INT) ENGINE=MyISAM")
each name in ["legacy_read", "open_empty", "open_read", "fail_open", "late_fail", "ac0_my", "two", "errno", "pending", "once", "ac0", "late_plain"]
    sql_exec("DROP PROCEDURE IF EXISTS syn_m2_r3_" + name)
sql_exec("CREATE PROCEDURE syn_m2_r3_legacy_read(IN n INT) BEGIN SET autocommit = 0; START TRANSACTION; INSERT INTO syn_m2_r3 VALUES (n); COMMIT; SELECT v FROM syn_m2_r3 WHERE v = n; END")
sql_exec("CREATE PROCEDURE syn_m2_r3_open_empty() START TRANSACTION")
sql_exec("CREATE PROCEDURE syn_m2_r3_open_read() BEGIN START TRANSACTION; SELECT v FROM syn_m2_r3; END")
sql_exec("CREATE PROCEDURE syn_m2_r3_fail_open(IN n INT) BEGIN START TRANSACTION; INSERT INTO syn_m2_r3 VALUES (n); SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'r3 fails'; END")
sql_exec("CREATE PROCEDURE syn_m2_r3_late_fail(IN n INT) BEGIN SET autocommit = 0; INSERT INTO syn_m2_r3 VALUES (n); SELECT n AS a; SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'r3 fails late'; END")
sql_exec("CREATE PROCEDURE syn_m2_r3_ac0_my(IN n INT) BEGIN SET autocommit = 0; INSERT INTO syn_m2_r3_my VALUES (n); END")
sql_exec("CREATE PROCEDURE syn_m2_r3_two(IN n INT) BEGIN SET autocommit = 0; INSERT INTO syn_m2_r3 VALUES (n); SELECT 1 AS a; SELECT 2 AS b; END")
sql_exec("CREATE PROCEDURE syn_m2_r3_errno(IN s VARCHAR(8)) BEGIN INSERT INTO syn_m2_r3 VALUES (1024); SIGNAL SQLSTATE '45000' SET MYSQL_ERRNO = 1295, MESSAGE_TEXT = 'r3 errno'; END")
sql_exec("CREATE PROCEDURE syn_m2_r3_pending(IN n INT) BEGIN SET autocommit = 0; INSERT INTO syn_m2_r3 VALUES (n); END")
sql_exec("CREATE PROCEDURE syn_m2_r3_once(IN n INT) BEGIN IF n = 16384 THEN SET autocommit = 0; END IF; INSERT INTO syn_m2_r3 VALUES (n); END")
sql_exec("CREATE PROCEDURE syn_m2_r3_ac0() SET autocommit = 0")
sql_exec("CREATE PROCEDURE syn_m2_r3_late_plain(IN n INT) BEGIN INSERT INTO syn_m2_r3 VALUES (n); SELECT n AS a; SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'r3 fails late inside'; END")
task total()
    db_close()
    db_open("{url}")
    let rows be sql("SELECT CAST(COALESCE(SUM(v), 0) AS SIGNED) AS s FROM syn_m2_r3")
    give text(rows[0]["s"])
task autocommit()
    give text(sql("SELECT @@autocommit AS a")[0]["a"])
task refused(label, call)
    try
        sql(call)
        print(label + " ran")
    recover e
        print(label + " " + e)
let rows be sql("CALL syn_m2_r3_legacy_read(?)", [1])
print("A " + text(length(rows)) + " " + text(rows[0]["v"]) + " " + autocommit())
sql_exec("INSERT INTO syn_m2_r3 VALUES (2)")
print("A " + total())
refused("B", "CALL syn_m2_r3_open_empty()")
refused("C", "CALL syn_m2_r3_open_read()")
sql_exec("INSERT INTO syn_m2_r3 VALUES (4)")
print("C " + total())
refused("D", "CALL syn_m2_r3_fail_open(8)")
sql_exec("INSERT INTO syn_m2_r3 VALUES (16)")
print("D " + total())
refused("E", "CALL syn_m2_r3_late_fail(32)")
try
    sql_exec("CALL syn_m2_r3_late_fail(32)")
    print("E2 ran")
recover e
    print("E2 " + e)
try
    sql_exec("CALL syn_m2_r3_late_fail(?)", [32])
    print("E3 ran")
recover e
    print("E3 " + e)
print("E " + autocommit())
sql_exec("INSERT INTO syn_m2_r3 VALUES (64)")
print("E " + total())
sql_exec("CALL syn_m2_r3_ac0_my(?)", [7])
print("F " + autocommit() + " " + text(sql("SELECT COUNT(*) AS c FROM syn_m2_r3_my")[0]["c"]))
sql_exec("INSERT INTO syn_m2_r3 VALUES (128)")
print("F " + total())
refused("G", "CALL syn_m2_r3_two(256)")
sql_exec("INSERT INTO syn_m2_r3 VALUES (512)")
print("G " + total())
try
    sql_exec("CALL syn_m2_r3_errno(';')")
    print("H ran")
recover e
    print("H " + e)
print("H " + total())
try
    sql_batch("CALL syn_m2_r3_once(?)", [[16384], [32768]])
    print("L ran")
recover e
    print("L " + e)
sql_exec("INSERT INTO syn_m2_r3 VALUES (65536)")
print("L " + total())
task late_inside()
    sql("CALL syn_m2_r3_late_plain(131072)")
try
    sql_transaction(late_inside)
    print("N committed")
recover e
    print("N " + e)
print("N " + total())
sql_exec("SET SESSION session_track_transaction_info = 'OFF'")
refused("I", "CALL syn_m2_r3_legacy_read(2048)")
print("I " + autocommit())
sql_exec("CALL syn_m2_r3_ac0()")
print("M " + autocommit())
refused("J", "CALL syn_m2_r3_pending(4096)")
refused("K", "CALL syn_m2_r3_open_empty()")
sql_exec("INSERT INTO syn_m2_r3 VALUES (8192)")
print("K " + total())
each name in ["legacy_read", "open_empty", "open_read", "fail_open", "late_fail", "ac0_my", "two", "errno", "pending", "once", "ac0", "late_plain"]
    sql_exec("DROP PROCEDURE syn_m2_r3_" + name)
sql_exec("DROP TABLE syn_m2_r3")
sql_exec("DROP TABLE syn_m2_r3_my")
db_close()
"#
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    let o = r.output;
    assert_eq!(o.len(), 28, "{:?}", o);
    // B-r3-1: el patrón de siempre con una lectura después del `COMMIT` da sus filas, sin error.
    assert_eq!(&o[..2], ["A 1 1 1", "A 3"], "confirma lo suyo, devuelve la fila y deja autocommit en 1: {:?}", o);
    // Un `START TRANSACTION` que queda abierto es un error aunque no tenga nada adentro.
    assert!(o[2].starts_with("B this CALL left a transaction open"), "{:?}", o);
    assert!(o[3].starts_with("C this CALL left a transaction open"), "{:?}", o);
    assert_eq!(o[4], "C 7", "la conexión quedó limpia: lo de después se confirma solo: {:?}", o);
    // Un `CALL` que falla da SU error, y lo que dejó abierto se deshace igual.
    assert!(o[5].starts_with("D ") && o[5].contains("r3 fails") && !o[5].contains("left a transaction"), "{:?}", o);
    assert_eq!(o[6], "D 23", "el 8 se deshizo y el 16 de después quedó: {:?}", o);
    // Un procedimiento que falla después de dar un resultado: es un error, no sus filas. Por
    // `sql`, por `sql_exec` sin valores (protocolo de texto) y con valores (preparado).
    for (i, label) in [(7, "E "), (8, "E2 "), (9, "E3 ")] {
        assert!(o[i].starts_with(label) && o[i].contains("r3 fails late"), "{:?}", o);
    }
    assert_eq!(&o[10..12], ["E 1", "E 87"], "el 32 se deshizo las tres veces, autocommit volvió a 1 y el 64 quedó: {:?}", o);
    // `autocommit = 0` y una escritura en una tabla sin transacciones: no hay nada que deshacer.
    assert_eq!(&o[12..14], ["F 1 1", "F 215"], "{:?}", o);
    // Con dos resultados, el estado viene en la última respuesta.
    assert!(o[14].starts_with("G this CALL left a transaction open"), "{:?}", o);
    assert_eq!(o[15], "G 727", "el 256 se deshizo y el 512 quedó: {:?}", o);
    // El procedimiento da el error 1295, el que el motor mira al PREPARAR: corre una sola vez.
    assert!(o[16].starts_with("H ") && o[16].contains("r3 errno"), "{:?}", o);
    assert_eq!(o[17], "H 1751", "un solo 1024: {:?}", o);
    // `sql_batch`: la primera ejecución apaga `autocommit` y deja su fila pendiente; la segunda
    // suma otra, y su respuesta no repite ni una cosa ni la otra.
    assert!(o[18].starts_with("L this CALL left a transaction open"), "{:?}", o);
    assert_eq!(o[19], "L 67287", "ni el 16384 ni el 32768 quedaron; el 65536 de después, sí: {:?}", o);
    // Adentro de `sql_transaction`, el procedimiento que falla después de dar un resultado hace
    // fallar la transacción: lo que había escrito no se confirma.
    assert!(o[20].starts_with("N ") && o[20].contains("r3 fails late inside"), "{:?}", o);
    assert_eq!(o[21], "N 67287", "el 131072 no quedó: {:?}", o);
    // Un `SET` del programa que cambia el seguimiento deja la conexión sin él: se pregunta con
    // la sonda, que no distingue una lectura de una escritura pendiente (el límite conocido).
    assert!(o[22].starts_with("I this CALL left a transaction open"), "sin seguimiento, la lectura cuenta como abierta: {:?}", o);
    assert_eq!(&o[23..25], ["I 1", "M 1"], "sin seguimiento, autocommit se repone siempre: {:?}", o);
    assert!(o[25].starts_with("J this CALL left a transaction open"), "{:?}", o);
    assert!(o[26].starts_with("K this CALL left a transaction open"), "{:?}", o);
    assert_eq!(o[27], "K 77527", "el 2048 quedó (lo confirmó el procedimiento), el 4096 no, el 8192 sí: {:?}", o);
}

/// v0.6.59, ronda 4 — lo que el texto de un statement no muestra, medido contra MySQL 8.0.46.
/// `total()` reabre la conexión: lo que hubiera quedado en una transacción abierta se pierde y no
/// suma.
/// - **X (B-r4-1):** un procedimiento que deja una transacción XA activa. El `ROLLBACK` del motor
///   falla (ERROR 1399) y la conexión seguiría adentro: se cierra, y el error lo dice.
/// - **S (B-r4-2):** una tabla con `session_track` en el nombre no le quita el seguimiento a la
///   conexión, y un `SET` que la nombra tampoco (se lee cómo quedaron las variables).
/// - **N (N-r4-1):** el servidor iguala letras con tilde y otras a su letra base en el nombre de
///   una variable. `SET autocommít = 0` es un error y `autocommit` vuelve a 1, afuera y adentro de
///   una transacción; apagar el seguimiento escrito así deja la conexión sin él, y un `CALL` que
///   deja una escritura pendiente sigue siendo un error.
///   Con seguimiento, lo que el texto no muestra lo dice el estado que informa el servidor
///   después de cada statement (N6); sin él, o si el mismo `SET` lo apaga, la lectura (N7, N8).
/// - **L:** un `CALL` con tablas bloqueadas por `LOCK TABLES` no es una transacción abierta.
/// - **G:** `autocommit` entre comillas invertidas, un comentario con una versión que el
///   servidor no ejecuta delante de un `COMMIT` o de un `CALL`, y un `START TRANSACTION` partido
///   por el cierre de un comentario ejecutable.
#[test]
#[ignore = "requiere un MySQL real (MYSQL_URL)"]
fn mysql_what_the_text_of_a_statement_does_not_show() {
    let url = mysql_url().expect("MYSQL_URL no seteada");
    let src = format!(
        r#"require db("{url}")
db_open("{url}")
sql_exec("DROP TABLE IF EXISTS syn_m2_r4")
sql_exec("DROP TABLE IF EXISTS syn_m2_session_tracking")
sql_exec("CREATE TABLE syn_m2_r4 (v INT) ENGINE=InnoDB")
sql_exec("CREATE TABLE syn_m2_session_tracking (v INT) ENGINE=InnoDB")
each name in ["xa", "legacy_read", "pending", "open", "ac0", "noop"]
    sql_exec("DROP PROCEDURE IF EXISTS syn_m2_r4_" + name)
sql_exec("CREATE PROCEDURE syn_m2_r4_ac0() SET autocommit = 0")
sql_exec("CREATE PROCEDURE syn_m2_r4_noop() DO 0")
sql_exec("CREATE PROCEDURE syn_m2_r4_xa(IN n INT) BEGIN XA START 'syn_m2_r4'; INSERT INTO syn_m2_r4 VALUES (n); END")
sql_exec("CREATE PROCEDURE syn_m2_r4_legacy_read(IN n INT) BEGIN SET autocommit = 0; START TRANSACTION; INSERT INTO syn_m2_r4 VALUES (n); COMMIT; SELECT v FROM syn_m2_r4 WHERE v = n; END")
sql_exec("CREATE PROCEDURE syn_m2_r4_pending(IN n INT) BEGIN SET autocommit = 0; INSERT INTO syn_m2_r4 VALUES (n); END")
sql_exec("CREATE PROCEDURE syn_m2_r4_open(IN n INT) BEGIN START TRANSACTION; INSERT INTO syn_m2_r4 VALUES (n); END")
task total()
    db_close()
    db_open("{url}")
    let rows be sql("SELECT CAST(COALESCE(SUM(v), 0) AS SIGNED) AS s FROM syn_m2_r4")
    give text(rows[0]["s"])
task autocommit()
    give text(sql("SELECT @@autocommit AS a")[0]["a"])
task refused(label, stmt)
    try
        sql_exec(stmt)
        print(label + " ran")
    recover e
        print(label + " " + e)
task legacy_read(label, n)
    let rows be sql("CALL syn_m2_r4_legacy_read(?)", [n])
    print(label + " " + text(length(rows)) + " " + autocommit())
refused("X", "CALL syn_m2_r4_xa(1)")
refused("X", "INSERT INTO syn_m2_r4 VALUES (2)")
db_open("{url}")
sql_exec("INSERT INTO syn_m2_r4 VALUES (4)")
print("X " + total())
sql_exec("INSERT INTO syn_m2_session_tracking VALUES (1)")
sql("SELECT COUNT(*) AS c FROM syn_m2_session_tracking")
legacy_read("S", 8)
sql_exec("SET @n = (SELECT COUNT(*) FROM syn_m2_session_tracking)")
legacy_read("S", 16)
print("S " + total())
refused("N1", "SET autocommít = 0")
print("N1 " + autocommit())
sql_exec("INSERT INTO syn_m2_r4 VALUES (32)")
print("N1 " + total())
refused("N2", "SET SESSION sessión_track_transaction_info = 'OFF'")
refused("N2", "CALL syn_m2_r4_pending(64)")
print("N2 " + autocommit() + " " + total())
refused("N3", "SET ſession_track_system_variables = ''")
refused("N3", "CALL syn_m2_r4_pending(128)")
sql_exec("INSERT INTO syn_m2_r4 VALUES (256)")
print("N3 " + total())
task in_tx()
    sql_exec("INSERT INTO syn_m2_r4 VALUES (512)")
    sql_exec("SET autocommít = 0")
try
    sql_transaction(in_tx)
    print("N4 committed")
recover e
    print("N4 " + e)
print("N4 " + autocommit())
sql_exec("INSERT INTO syn_m2_r4 VALUES (1024)")
print("N4 " + total())
sql_exec("SET @año = 5")
print("N5 " + text(sql("SELECT @año AS a")[0]["a"]))
legacy_read("N5", 2048)
print("N5 " + total())
refused("G1", "SET `autocommit` = 0")
print("G1 " + autocommit())
task by_hand()
    sql_exec("INSERT INTO syn_m2_r4 VALUES (4096)")
    sql_exec("/*!99999 SELECT */ COMMIT")
try
    sql_transaction(by_hand)
    print("G2 committed")
recover e
    print("G2 " + e)
print("G2 " + total())
refused("G3", "/*!99999 SELECT */ CALL syn_m2_r4_open(8192)")
sql_exec("INSERT INTO syn_m2_r4 VALUES (16384)")
print("G3 " + total())
print("G4 " + text(sql("SELECT /*!50000 DISTINCT */ 7 AS a")[0]["a"]) + " " + text(sql("SELECT /*! DISTINCT */ 8 AS a")[0]["a"]))
refused("G5", "/*! START */ TRANSACTION")
sql_exec("INSERT INTO syn_m2_r4 VALUES (32768)")
print("G5 " + total())
task ends_it()
    sql_exec("INSERT INTO syn_m2_r4 VALUES (65536)")
    sql_exec("CALL syn_m2_r4_ac0()")
    sql_exec("SET autocommít = 1")
    sql_exec("INSERT INTO syn_m2_r4 VALUES (131072)")
try
    sql_transaction(ends_it)
    print("N6 committed")
recover e
    print("N6 " + e)
print("N6 " + autocommit() + " " + total())
sql_exec("SET SESSION session_track_transaction_info = 'OFF'")
refused("N7", "SET autocommít = 0")
print("N7 " + autocommit())
sql_exec("INSERT INTO syn_m2_r4 VALUES (262144)")
print("N7 " + total())
refused("N8", "SET ſession_track_system_variables = '', autocommít = 0")
print("N8 " + autocommit())
sql_exec("INSERT INTO syn_m2_r4 VALUES (524288)")
print("N8 " + total())
sql_exec("LOCK TABLES syn_m2_r4 WRITE")
sql_exec("INSERT INTO syn_m2_r4 VALUES (1048576)")
refused("L", "CALL syn_m2_r4_noop()")
sql_exec("UNLOCK TABLES")
print("L " + total())
each name in ["xa", "legacy_read", "pending", "open", "ac0", "noop"]
    sql_exec("DROP PROCEDURE syn_m2_r4_" + name)
sql_exec("DROP TABLE syn_m2_r4")
sql_exec("DROP TABLE syn_m2_session_tracking")
db_close()
"#
    );
    let r = run_source(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    let o = r.output;
    assert_eq!(o.len(), 40, "{:?}", o);
    // X: el error dice que no se pudo deshacer y que la conexión se cerró; el statement siguiente
    // no corre adentro de la XA (no hay conexión); al reabrir, lo del procedimiento no quedó.
    assert!(o[0].starts_with("X this CALL left a transaction open on the connection and it could not be rolled back") && o[0].contains("the connection was closed"), "{:?}", o);
    assert!(o[1].starts_with("X No database connection"), "{:?}", o);
    assert_eq!(o[2], "X 4", "ni el 1 del procedimiento ni el 2: sólo lo escrito después de reabrir: {:?}", o);
    // S: con seguimiento, el patrón de siempre + SELECT da su fila (sin él daría error).
    assert_eq!(&o[3..6], ["S 1 1", "S 1 1", "S 28"], "{:?}", o);
    // N1: el `SET` con tilde es un error, `autocommit` vuelve a 1 y lo de después se confirma.
    assert!(o[6].starts_with("N1 this statement turned autocommit off") && o[6].contains("are not run by hand"), "{:?}", o);
    assert_eq!(&o[7..9], ["N1 1", "N1 60"], "{:?}", o);
    // N2 y N3: apagar el seguimiento con otra letra pasa, y la conexión queda sin él: lo que deja
    // un `CALL` se pregunta. La escritura pendiente es un error y no se confirma.
    assert_eq!(o[9], "N2 ran", "{:?}", o);
    assert!(o[10].starts_with("N2 this CALL left a transaction open on the connection, and it was rolled back"), "{:?}", o);
    assert_eq!(o[11], "N2 1 60", "el 64 no quedó: {:?}", o);
    assert_eq!(o[12], "N3 ran", "{:?}", o);
    assert!(o[13].starts_with("N3 this CALL left a transaction open on the connection, and it was rolled back"), "{:?}", o);
    assert_eq!(o[14], "N3 316", "el 128 no quedó; el 256 de después, sí: {:?}", o);
    // N4: adentro de una transacción, hace fallar la transacción; `autocommit` se repone al cerrarla.
    assert!(o[15].starts_with("N4 ") && o[15].contains("this statement turned autocommit off"), "{:?}", o);
    assert_eq!(&o[16..18], ["N4 1", "N4 1340"], "el 512 se deshizo y el 1024 de después quedó: {:?}", o);
    // N5: un `SET` con una letra que no es ASCII y que no toca nada anda, y no quita el seguimiento.
    assert_eq!(&o[18..21], ["N5 5", "N5 1 1", "N5 3388"], "{:?}", o);
    // G1: entre comillas invertidas también es `SET autocommit`.
    assert!(o[21].starts_with("G1 BEGIN, COMMIT, ROLLBACK and SAVEPOINT are not run by hand"), "{:?}", o);
    assert_eq!(o[22], "G1 1", "{:?}", o);
    // G2: el `COMMIT` detrás del comentario no llega al servidor; la transacción se deshace.
    assert!(o[23].starts_with("G2 ") && o[23].contains("BEGIN, COMMIT, ROLLBACK and SAVEPOINT are not run by hand"), "{:?}", o);
    assert_eq!(o[24], "G2 3388", "el 4096 no quedó: {:?}", o);
    // G3: con el comentario delante el motor no sabe si es un `CALL`, y no lo corre: nada queda
    // abierto, y lo de después se confirma.
    assert!(o[25].starts_with("G3 a MySQL comment that only some servers run"), "{:?}", o);
    assert_eq!(o[26], "G3 19772", "el 8192 no corrió y el 16384 quedó: {:?}", o);
    // G4: después de la primera palabra, un comentario ejecutable sigue andando.
    assert_eq!(o[27], "G4 7 8", "{:?}", o);
    // G5: el cierre del comentario no corta el statement: es un `START TRANSACTION` a mano.
    assert!(o[28].starts_with("G5 BEGIN, COMMIT, ROLLBACK and SAVEPOINT are not run by hand"), "{:?}", o);
    assert_eq!(o[29], "G5 52540", "el 32768 de después se confirmó solo: {:?}", o);
    // N6: adentro de una transacción en la que un procedimiento apagó `autocommit`, prenderlo
    // confirma la transacción. El texto no lo muestra (`autocommít`); lo dice el estado que
    // informa el servidor, y la transacción falla en ese statement: el que sigue no corre.
    assert!(o[30].starts_with("N6 ") && o[30].contains("this statement ended the transaction"), "{:?}", o);
    assert_eq!(o[31], "N6 1 118076", "el 65536 quedó confirmado por ese SET (el error lo dice) y el 131072 no corrió: {:?}", o);
    // N7: sin seguimiento (el programa lo apagó), `autocommit` se lee después del `SET`.
    assert!(o[32].starts_with("N7 this statement turned autocommit off"), "{:?}", o);
    assert_eq!(&o[33..35], ["N7 1", "N7 380220"], "{:?}", o);
    // N8: un solo `SET` que primero vacía la lista del seguimiento y después apaga `autocommit`:
    // el servidor ya no informa el cambio, y lo ve la lectura.
    assert!(o[35].starts_with("N8 this statement turned autocommit off"), "{:?}", o);
    assert_eq!(&o[36..38], ["N8 1", "N8 904508"], "{:?}", o);
    // L: con tablas bloqueadas por `LOCK TABLES` el servidor informa `_______L`: no es una
    // transacción, y un `CALL` en el medio no es un error.
    assert_eq!(&o[38..40], ["L ran", "L 1953084"], "{:?}", o);
}

/// v0.6.59, ronda 3 (N-r3-1) — un `CALL` de afuera no pisa el nivel de aislamiento que el
/// programa fijó «para la próxima transacción» (`SET TRANSACTION ISOLATION LEVEL …`, sin
/// `SESSION`): el motor ya no manda nada después del `CALL`. En SERIALIZABLE una lectura común
/// toma un lock compartido, así que otra conexión no puede escribir esa fila mientras la
/// transacción sigue; en REPEATABLE READ (el nivel de la sesión) sí puede.
#[test]
#[ignore = "requiere un MySQL real (MYSQL_URL)"]
fn mysql_call_keeps_the_isolation_level_set_for_the_next_transaction() {
    let url = mysql_url().expect("MYSQL_URL no seteada");
    let setup = format!(
        r#"require db("{url}")
db_open("{url}")
sql_exec("DROP TABLE IF EXISTS syn_m2_iso")
sql_exec("CREATE TABLE syn_m2_iso (id INT PRIMARY KEY, v INT) ENGINE=InnoDB")
sql_exec("INSERT INTO syn_m2_iso VALUES (1, 0), (2, 0)")
sql_exec("DROP PROCEDURE IF EXISTS syn_m2_iso_noop")
sql_exec("CREATE PROCEDURE syn_m2_iso_noop() DO 0")
db_close()
"#
    );
    let r = run_source(&setup, "<t>");
    assert!(r.success, "{:?}", r.errors);
    // `with_level`: fija SERIALIZABLE para la próxima transacción y lee la fila `id`.
    let reader = |id: i64, with_level: bool| {
        let level = if with_level { r#"sql_exec("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")"# } else { "" };
        let src = format!(
            r#"require db("{url}")
require time
db_open("{url}")
{level}
sql_exec("CALL syn_m2_iso_noop()")
task read_and_hold()
    sql("SELECT v FROM syn_m2_iso WHERE id = {id}")
    sleep(8)
sql_transaction(read_and_hold)
db_close()
"#
        );
        std::thread::Builder::new()
            .stack_size(32 << 20)
            .spawn(move || {
                let r = run_source(&src, "<t>");
                assert!(r.success, "{:?}", r.errors);
            })
            .unwrap()
    };
    let (serializable, repeatable) = (reader(1, true), reader(2, false));
    let writer = format!(
        r#"require db("{url}")
require time
db_open("{url}")
sleep(3)
sql_exec("SET SESSION innodb_lock_wait_timeout = 1")
each id in [1, 2]
    try
        sql_exec("UPDATE syn_m2_iso SET v = 1 WHERE id = ?", [id])
        print(text(id) + " wrote")
    recover e
        print(text(id) + " " + e)
db_close()
"#
    );
    let w = run_source(&writer, "<t>");
    serializable.join().unwrap();
    repeatable.join().unwrap();
    let cleanup = format!(
        r#"require db("{url}")
db_open("{url}")
sql_exec("DROP PROCEDURE syn_m2_iso_noop")
sql_exec("DROP TABLE syn_m2_iso")
db_close()
"#
    );
    assert!(run_source(&cleanup, "<t>").success);
    assert!(w.success, "{:?}", w.errors);
    assert_eq!(w.output.len(), 2, "{:?}", w.output);
    assert!(w.output[0].starts_with("1 ") && w.output[0].contains("Lock wait timeout"), "la fila que leyó la transacción SERIALIZABLE está bloqueada: {:?}", w.output);
    assert_eq!(w.output[1], "2 wrote", "el control: sin fijar el nivel, la lectura no bloquea: {:?}", w.output);
}

/// v0.6.59, caso 19 del diseño, medido: un deadlock deshace la transacción ENTERA del perdedor
/// (también lo de antes del savepoint). Dos conexiones se cruzan (`1→2` y `2→1`) dentro de una
/// transacción anidada; el perdedor atrapa el error de la de adentro y sigue: su `INSERT` siguiente
/// no puede correr (sin transacción, se confirmaría solo) y la de afuera falla citando el deadlock.
#[test]
#[ignore = "requiere un MySQL real (MYSQL_URL)"]
fn mysql_deadlock_fails_the_whole_transaction() {
    let url = mysql_url().expect("MYSQL_URL no seteada");
    let setup = format!(
        r#"require db("{url}")
db_open("{url}")
sql_exec("DROP TABLE IF EXISTS syn_m2_dl")
sql_exec("DROP TABLE IF EXISTS syn_m2_dl_log")
sql_exec("CREATE TABLE syn_m2_dl (id INT PRIMARY KEY, v INT) ENGINE=InnoDB")
sql_exec("CREATE TABLE syn_m2_dl_log (v INT) ENGINE=InnoDB")
sql_exec("INSERT INTO syn_m2_dl VALUES (1, 0), (2, 0)")
db_close()
"#
    );
    let r = run_source(&setup, "<t>");
    assert!(r.success, "{:?}", r.errors);
    let worker = |first: i64, second: i64, marker: i64| {
        let src = format!(
            r#"require db("{url}")
require time
db_open("{url}")
task inner()
    sql_exec("UPDATE syn_m2_dl SET v = v + 1 WHERE id = {first}")
    sleep(5)
    sql_exec("UPDATE syn_m2_dl SET v = v + 1 WHERE id = {second}")
task outer()
    sql_exec("INSERT INTO syn_m2_dl_log VALUES ({marker})")
    try
        sql_transaction(inner)
    recover e
        print("inner: " + e)
    sql_exec("INSERT INTO syn_m2_dl_log VALUES ({marker} + 100)")
    give "committed"
try
    print(sql_transaction(outer))
recover e
    print("outer: " + e)
db_close()
"#
        );
        std::thread::Builder::new()
            .stack_size(32 << 20)
            .spawn(move || {
                let r = run_source(&src, "<t>");
                assert!(r.success, "{:?}", r.errors);
                (marker, r.output)
            })
            .unwrap()
    };
    let (a, b) = (worker(1, 2, 1), worker(2, 1, 2));
    let outs = [a.join().unwrap(), b.join().unwrap()];
    let losers: Vec<_> = outs.iter().filter(|(_, o)| o.first().is_some_and(|l| l.starts_with("inner: "))).collect();
    assert_eq!(losers.len(), 1, "una de las dos pierde el deadlock: {:?}", outs);
    let (_, lost) = losers[0];
    assert_eq!(lost.len(), 2, "{:?}", outs);
    assert!(lost[0].contains("Deadlock"), "{:?}", outs);
    assert!(lost[1].starts_with("outer: sql_transaction: a statement failed inside this transaction"), "{:?}", outs);
    assert!(lost[1].contains("Deadlock"), "la de afuera cita el error que empezó todo: {:?}", outs);
    let (winner, won) = outs.iter().find(|(_, o)| o.first().is_some_and(|l| !l.starts_with("inner: "))).unwrap();
    assert_eq!(won, &["committed".to_string()], "{:?}", outs);
    let check = format!(
        r#"require db("{url}")
db_open("{url}")
let log be sql("SELECT CAST(COALESCE(SUM(v), 0) AS SIGNED) AS s, COUNT(*) AS c FROM syn_m2_dl_log")
print(text(log[0]["s"]) + " " + text(log[0]["c"]))
let rows be sql("SELECT CAST(SUM(v) AS SIGNED) AS s FROM syn_m2_dl")
print(text(rows[0]["s"]))
db_close()
"#
    );
    let r = run_source(&check, "<t>");
    assert!(r.success, "{:?}", r.errors);
    // Sólo quedó lo del ganador: su marca y su marca + 100, y sus dos UPDATE.
    assert_eq!(r.output, [format!("{} 2", 2 * winner + 100), "2".to_string()], "{:?}", outs);
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

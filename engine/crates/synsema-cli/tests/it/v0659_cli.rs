//! v0.6.59: los restos chicos de v0.6.58 que se ven desde la CLI (faltantes, «Restos chicos de
//! v0.6.58», puntos 2 y 3) y `sql_transaction` con el binario.

use serde_json::json;

use super::v0646_tanda_e_cli::{project, synsema};
use super::v0658_get_cli::{modules, Proj};

/// Punto 2: una entrada con el `hash` puesto a mano no tiene versión, y el mensaje salía con dos
/// espacios («notes  is not in the cache»).
#[test]
fn get_check_names_a_module_without_a_version_with_one_space() {
    let hash = format!("tree-sha256:{}", "0".repeat(64));
    let p = Proj::new("v0659-d2", modules(&[("notes", json!({"url": "http://127.0.0.1:9/notes/synsema.json", "hash": hash}))]));
    assert_eq!(p.fails(&["--check"]), "get --check: notes is not in the cache: run synsema get");
}

/// Punto 3: lo que imprime un job de `cron` bajo `synsema run` sale como lo imprime el programa;
/// salía con el prefijo `[serve] ` del log de un servidor. Y su `log` va a stderr, como el del
/// programa (auditoría, N-1: sin el prefijo seguía saliendo por stdout).
#[test]
fn a_cron_job_under_run_prints_without_the_serve_prefix() {
    let dir = project("v0659-d3");
    std::fs::write(
        dir.join("c.syn"),
        "require time\ntask tick()\n    print(\"tick from cron\")\n    log \"log from cron\"\ncron_every(0.2, tick)\nsleep(2.5)\nprint(\"main done\")\nlog \"main log\"\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "c.syn"], None);
    assert_eq!(code, 0, "stdout:\n{}\nstderr:\n{}", out, err);
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines.contains(&"tick from cron"), "{}", out);
    assert!(lines.contains(&"main done"), "{}", out);
    assert!(!out.contains("[serve]"), "{}", out);
    assert!(!err.contains("[serve]"), "{}", err);
    let err_lines: Vec<&str> = err.lines().collect();
    assert!(err_lines.contains(&"[LOG] main log"), "{}", err);
    assert!(err_lines.contains(&"[LOG] log from cron"), "el log del job va a stderr, como el del programa: {}", err);
    assert!(!out.contains("[LOG]"), "stdout queda para el resultado: {}", out);
}

/// Auditoría, B-2: `db_close()` y después `db_open()` de la misma base adentro de una transacción.
/// Lo último que pidió el programa fue abrirla: al terminar sigue abierta (quedaba sin conexión).
#[test]
fn reopening_the_database_inside_a_transaction_keeps_it_open() {
    let dir = project("v0659-reopen");
    std::fs::write(
        dir.join("t.syn"),
        r#"require db("app.db")
db_open("app.db")
sql_exec("CREATE TABLE IF NOT EXISTS t (who TEXT)")
task reopen()
    sql_exec("INSERT INTO t VALUES ('k')")
    db_close()
    db_open("app.db")
    sql_exec("INSERT INTO t VALUES ('k2')")
sql_transaction(reopen)
print(length(sql("SELECT who FROM t")))
"#,
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "t.syn"], None);
    assert_eq!((code, out.trim()), (0, "2"), "stderr:\n{}", err);
}

/// `sql_transaction` de punta a punta con el binario: un archivo SQLite, una transacción que
/// falla a la mitad no deja nada escrito, y el control a mano es un error que nombra la primitiva.
#[test]
fn sql_transaction_with_the_binary_and_a_database_file() {
    let dir = project("v0659-tx");
    std::fs::write(
        dir.join("t.syn"),
        r#"require db("app.db")
db_open("app.db")
sql_exec("CREATE TABLE IF NOT EXISTS t (who TEXT)")
sql_exec("PRAGMA foreign_keys = ON")
task half()
    sql_exec("INSERT INTO t VALUES ('a')")
    raise("stopped half way")
try
    sql_transaction(half)
recover e
    print(e)
print(length(sql("SELECT who FROM t")))
print(sql_transaction(() => sql_exec("INSERT INTO t VALUES ('b')").rows_affected))
print(sql_transaction(() => sql("PRAGMA foreign_keys")[0].foreign_keys))
print(sql("SELECT who FROM t"))
try
    sql_exec("BEGIN")
recover e
    print(e)
"#,
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "t.syn"], None);
    assert_eq!(code, 0, "stdout:\n{}\nstderr:\n{}", out, err);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 6, "{}", out);
    assert_eq!(&lines[..5], ["stopped half way", "0", "1", "1", "[{who: \"b\"}]"], "{}", out);
    assert!(lines[5].starts_with("BEGIN, COMMIT, ROLLBACK and SAVEPOINT are not run by hand"), "{}", out);
}

/// Caso 3 del diseño: sólo confirma una task que devuelve. Un `exit` adentro termina el programa
/// y lo que la transacción escribió no queda.
#[test]
fn exit_inside_a_transaction_commits_nothing() {
    let dir = project("v0659-exit");
    let open = "require db(\"app.db\")\ndb_open(\"app.db\")\nsql_exec(\"CREATE TABLE IF NOT EXISTS t (who TEXT)\")\n";
    std::fs::write(
        dir.join("a.syn"),
        format!("{open}task leave()\n    sql_exec(\"INSERT INTO t VALUES ('a')\")\n    exit(3)\nsql_transaction(leave)\nprint(\"not reached\")\n"),
    )
    .unwrap();
    std::fs::write(dir.join("b.syn"), format!("{open}print(length(sql(\"SELECT who FROM t\")))\n")).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "a.syn"], None);
    assert_eq!(code, 3, "stdout:\n{}\nstderr:\n{}", out, err);
    assert!(!out.contains("not reached"), "{}", out);
    let (code, out, err) = synsema(&dir, &["run", "b.syn"], None);
    assert_eq!((code, out.trim()), (0, "0"), "stderr:\n{}", err);
}

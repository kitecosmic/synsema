//! v0.6.59: `sql_transaction(task)`. La tabla de casos está en el diseño
//! (`specs/v0.6.59-transacciones-diseno.md`); acá van los que se ven desde un programa, en `run` y
//! en `serve`. Los del mecanismo (savepoints, la espera, el guard) están en `database.rs`.
//!
//! El caso de `serve` es el de la auditoría de v0.6.58 (M-r9-1): el `ROLLBACK` de una ruta borraba
//! la fila que otra ruta ya había confirmado al cliente.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use synsema_runtime::engine::run_program;
use synsema_runtime::serve::run_serve_program;

const BY_HAND: &str = "BEGIN, COMMIT, ROLLBACK and SAVEPOINT are not run by hand";
const FAILED: &str = "sql_transaction: a statement failed inside this transaction";

/// El preámbulo de los programas de `run`: una base en memoria, una tabla y dos tasks.
const PRELUDE: &str = r#"require db(":memory:")
db_open(":memory:", "memory")
sql_exec("CREATE TABLE t (who TEXT)")
task add(who)
    sql_exec("INSERT INTO t VALUES (?)", [who])
    give who
task everyone()
    give "[" + join(collect(sql("SELECT who FROM t ORDER BY rowid"), "who"), ",") + "]"
"#;

fn out(body: &str) -> Vec<String> {
    let src = format!("{PRELUDE}{body}");
    let r = run_program(&src, "tx.syn");
    assert!(r.success, "falló: {:?}\n{}", r.errors, src);
    r.output
}

/// Casos 1 y 2: devuelve lo que devuelve la task y confirma; si la task da error, deshace y el
/// error sale tal cual.
#[test]
fn a_transaction_commits_when_its_task_returns_and_rolls_back_when_it_fails() {
    let o = out(r#"print(sql_transaction(() => add("a")))
task fails()
    add("x")
    raise("boom")
try
    sql_transaction(fails)
recover e
    print("caught: " + e)
print(everyone())
"#);
    assert_eq!(o, ["a", "caught: boom", "[a]"]);
}

/// Casos 5 y 6: adentro de otra es un savepoint. La de adentro que falla se deshace sola, y la de
/// afuera, que atrapó el error, sigue y confirma.
#[test]
fn a_transaction_inside_another_is_a_savepoint() {
    let o = out(r#"task inner_fails()
    add("b")
    raise("inner")
task outer()
    add("a")
    try
        sql_transaction(inner_fails)
    recover e
        add("after " + e)
    give sql_transaction(() => add("c"))
print(sql_transaction(outer))
print(everyone())
"#);
    assert_eq!(o, ["c", "[a,after inner,c]"]);
}

/// Caso 7: si la de afuera falla después de que la de adentro devolvió, se deshace todo.
#[test]
fn an_outer_failure_undoes_the_inner_transaction_too() {
    let o = out(r#"task outer()
    sql_transaction(() => add("inner"))
    raise("outer")
try
    sql_transaction(outer)
recover e
    print(e)
print(everyone())
"#);
    assert_eq!(o, ["outer", "[]"]);
}

/// Caso 4 (regla 2): un statement que falla hace fallar la transacción aunque la task lo atrape y
/// siga; el error cita el primero.
#[test]
fn a_statement_that_fails_inside_fails_the_transaction() {
    let o = out(r#"task sloppy()
    add("a")
    try
        sql_exec("INSERT INTO no_such_table VALUES (1)")
    recover e
        print("ignored")
    try
        add("b")
    recover e
        print(e)
    give "done"
try
    print(sql_transaction(sloppy))
recover e
    print(e)
print(everyone())
"#);
    assert_eq!(o.len(), 4, "{:?}", o);
    assert_eq!(o[0], "ignored");
    assert!(o[1].starts_with(FAILED) && o[1].contains("no_such_table"), "{:?}", o);
    assert_eq!(o[2], o[1], "al terminar da el mismo error: {:?}", o);
    assert_eq!(o[3], "[]");
}

/// Casos 8 y 9: el control de transacciones a mano es un error en `run` también, por los tres
/// builtins, y no llega a la base: lo que sigue se confirma solo.
#[test]
fn hand_made_transaction_control_is_an_error_under_run() {
    let o = out(r#"each stmt in ["BEGIN", "commit", "ROLLBACK", "SAVEPOINT a", "  -- nota\n begin immediate", "/* x */ END"]
    try
        sql_exec(stmt)
        print("ran: " + stmt)
    recover e
        print(e)
try
    sql("BEGIN")
recover e
    print(e)
try
    sql_batch("COMMIT", [[]])
recover e
    print(e)
task by_hand_inside()
    add("in")
    try
        sql_exec("COMMIT")
    recover e
        print(e)
    give "ok"
print(sql_transaction(by_hand_inside))
add("out")
print(everyone())
"#);
    assert_eq!(o.len(), 11, "{:?}", o);
    for line in &o[..9] {
        assert!(line.starts_with(BY_HAND) && line.contains("sql_transaction(task)"), "{:?}", o);
    }
    assert_eq!(o[9], "ok", "adentro de una transacción el rechazo no la hace fallar");
    assert_eq!(o[10], "[in,out]");
}

/// Caso 24: algo que no es una task, y una task o una lambda que pide argumentos (una llamada
/// interna no chequea la aridad: sin esto corría con `nothing` y confirmaba). Nada se escribe y
/// la conexión queda libre para lo que sigue; un parámetro con default sí se acepta.
#[test]
fn a_bad_argument_writes_nothing_and_leaves_the_connection_free() {
    let o = out(r#"try
    sql_transaction(5)
recover e
    print(e)
try
    sql_transaction(add)
recover e
    print(e)
try
    sql_transaction((who) => add(who))
recover e
    print(e)
print(everyone())
task with_default(who = "d")
    give add(who)
print(sql_transaction(with_default))
add("z")
print(everyone())
"#);
    assert_eq!(o.len(), 6, "{:?}", o);
    assert!(o[0].starts_with("sql_transaction expects a task with no parameters"), "{:?}", o);
    assert_eq!(o[1], "sql_transaction calls its task with no arguments, and task 'add' needs 'who' — pass the values in a lambda: sql_transaction(() => my_task(a, b))");
    assert!(o[2].starts_with("sql_transaction calls its task with no arguments, and this lambda needs 'who'"), "{:?}", o);
    assert_eq!(&o[3..], ["[]", "d", "[d,z]"]);
}

/// Caso 21: sin conexión, el error de siempre.
#[test]
fn a_transaction_without_a_connection_says_so() {
    let r = run_program("sql_transaction(() => 1)", "tx.syn");
    assert!(!r.success);
    let e = r.errors.join("\n");
    assert!(e.contains("No database connection"), "{}", e);
}

// ---- serve ----

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn request(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let body = out.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or(out);
    body.trim().trim_matches('"').to_string()
}

fn start(port: u16) {
    let src = format!(
        r#"require serve({port})
require db(":memory:")
require time
db_open(":memory:", "memory")
sql_exec("CREATE TABLE t (who TEXT)")

task write_then_fail(seconds)
    sql_exec("INSERT INTO t VALUES ('a')")
    sleep(seconds)
    raise("rolled back")

task own()
    sql_exec("INSERT INTO t VALUES ('b2')")
    give "ok"

serve on {port}
    route "GET /a/:seconds"
        let seconds be number(params.seconds)
        try
            sql_transaction(() => write_then_fail(seconds))
        recover e
            give e
        give "committed"
    route "GET /b/:who"
        try
            sql_exec("INSERT INTO t VALUES (?)", [params.who])
        recover e
            give e
        give "inserted"
    route "GET /b2"
        give sql_transaction(own)
    route "GET /hand"
        try
            sql_exec("BEGIN")
        recover e
            give e
        give "began"
    route "GET /rows"
        give "[" + join(collect(sql("SELECT who FROM t ORDER BY rowid"), "who"), ",") + "]"
"#
    );
    thread::spawn(move || {
        let _ = run_serve_program(&src, "tx_serve.syn", false);
    });
    for _ in 0..150 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo");
}

/// Caso 11, la prueba de cierre: mientras `/a` está en su transacción, `/b` escribe. `/b` espera a
/// que `/a` termine, su fila NO entra en la transacción de `/a` y sobrevive a su `ROLLBACK`; `/b2`
/// hace su propia transacción sin error. Y un `BEGIN` a mano en una ruta es un error.
#[test]
fn a_routes_write_survives_another_routes_rollback() {
    let port = free_port();
    start(port);
    assert_eq!(request(port, "/rows"), "[]");
    let a = thread::spawn(move || request(port, "/a/2"));
    thread::sleep(Duration::from_millis(700));
    let t0 = Instant::now();
    assert_eq!(request(port, "/b/b"), "inserted");
    let waited = t0.elapsed();
    assert!(waited >= Duration::from_millis(500), "/b esperó a la transacción de /a: {:?}", waited);
    assert_eq!(request(port, "/b2"), "ok");
    assert_eq!(a.join().unwrap(), "rolled back");
    assert_eq!(request(port, "/rows"), "[b,b2]", "la fila de /a se deshizo; las de /b y /b2 quedaron");
    let hand = request(port, "/hand");
    assert!(hand.starts_with(BY_HAND), "{}", hand);
    assert_eq!(request(port, "/b/c"), "inserted", "el BEGIN rechazado no dejó nada abierto");
    assert_eq!(request(port, "/rows"), "[b,b2,c]");
}

/// Caso 12: una transacción que dura más que la espera (5 s). La otra ruta recibe un error que
/// dice por qué, no un cuelgue; la transacción sigue y termina.
#[test]
fn waiting_for_another_routes_transaction_has_a_limit() {
    let port = free_port();
    start(port);
    let a = thread::spawn(move || request(port, "/a/6.5"));
    thread::sleep(Duration::from_millis(700));
    let t0 = Instant::now();
    let b = request(port, "/b/late");
    let waited = t0.elapsed();
    assert!(b.contains("inside another task's transaction (sql_transaction) for more than 5 s"), "{}", b);
    assert!(waited >= Duration::from_millis(4500) && waited < Duration::from_millis(6200), "{:?}", waited);
    assert_eq!(a.join().unwrap(), "rolled back");
    assert_eq!(request(port, "/rows"), "[]");
    assert_eq!(request(port, "/b/after"), "inserted");
}

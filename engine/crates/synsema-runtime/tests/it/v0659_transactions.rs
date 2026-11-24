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
/// Casos 5 y 6: adentro de otra es un savepoint. La de adentro que falla se deshace sola, y la de
/// afuera, que atrapó el error, sigue y confirma.
/// Caso 7: si la de afuera falla después de que la de adentro devolvió, se deshace todo.
/// Caso 4 (regla 2): un statement que falla hace fallar la transacción aunque la task lo atrape y
/// siga; el error cita el primero.
/// Casos 8 y 9: el control de transacciones a mano es un error en `run` también, por los tres
/// builtins, y no llega a la base: lo que sigue se confirma solo.
/// Caso 24: algo que no es una task, y una task o una lambda que pide argumentos (una llamada
/// interna no chequea la aridad: sin esto corría con `nothing` y confirmaba). Nada se escribe y
/// la conexión queda libre para lo que sigue; un parámetro con default sí se acepta.
/// Caso 21: sin conexión, el error de siempre.
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

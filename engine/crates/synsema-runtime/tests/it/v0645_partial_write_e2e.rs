//! v0.6.45 (A4): escribir sin esperar sabiendo cuánto entró. `pipe_send`/`tcp_send` son todo-o-
//! timeout (el `write_all`); el túnel necesitaba el `write` de Rust y Go: aceptar lo que entra y
//! devolver el número, para acreditar por stream sin leer el texto de un error. Y `pipe_stats`.

use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::run_program;

#[test]
fn pipe_write_takes_what_fits_and_says_how_much() {
    let src = r#"let p be pipe({"max_buffer": 10})
print(pipe_write(p["a"], "0123456789ABCDEF"))
print(pipe_write(p["a"], "mas"))
print(pipe_stats(p["a"])["queued_out"])
print(pipe_stats(p["b"])["queued_in"])
print(pipe_stats(p["b"])["status"])
let got be pipe_recv(p["b"], 1)
print(got["type"])
print(pipe_write(p["a"], "mas") > 0)
pipe_close(p["b"])
let failed be "no"
try
    pipe_write(p["a"], "x")
recover e
    set failed to "si"
print(failed)
"#;
    let r = run_program(src, "<a4-pipe>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["10", "0", "10", "10", "open", "data", "true", "si"], "{:?}", r.output);
}

#[test]
fn tcp_write_never_waits_on_a_peer_that_does_not_read() {
    // Un par que acepta y nunca lee: el kernel y el buffer de salida se llenan, y `tcp_write`
    // sigue volviendo enseguida con lo que entró (al final, 0) en vez de esperar.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((sock, _)) = listener.accept() {
            thread::sleep(Duration::from_secs(10));
            drop(sock);
        }
    });
    let src = format!(
        r#"require net("127.0.0.1:{port}")
let c be tcp_connect("127.0.0.1", {port}, {{"max_buffer": 65536}})
let s be "x"
each _ in range(16)
    set s to s + s
let chunk be bytes(s)
let total be 0
let zero be false
let rounds be 0
while not zero and rounds < 2000
    let n be tcp_write(c, chunk)
    set total to total + n
    set zero to n == 0
    set rounds to rounds + 1
print(zero)
print(total > 0)
print(tcp_stats(c)["queued_out"] <= 65536)
tcp_close(c)
"#
    );
    let t0 = std::time::Instant::now();
    let r = run_program(&src, "<a4-tcp>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["true", "true", "true"], "{:?}", r.output);
    assert!(t0.elapsed() < Duration::from_secs(8), "tcp_write esperó: {:?}", t0.elapsed());
}

//! v0.6.42 (M4) — el pool de `serve` como permisos + hilos elásticos: con 2 permisos y 6 rutas
//! esperando (`sleep`), una ruta normal contesta al toque. Antes esperaba en la cola detrás de
//! las que dormían (REDSYN AP-25: con 2 núcleos y dos listeners de long polling, synsema.com
//! entero tardaba 25 s por pedido). Binario propio: el pool es del proceso y se arma una vez.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn get(port: u16, path: &str) -> (u16, String) {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    sock.write_all(format!("GET {} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", path).as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    let status = resp.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, resp)
}

#[test]
fn a_route_that_waits_does_not_hold_the_pool() {
    std::env::set_var("SYNSEMA_SERVE_WORKERS", "2");
    let port = free_port();
    let prog = format!(
        "require serve({p})\nrequire time\nserve on {p}\n    route \"GET /slow\"\n        sleep(2)\n        give \"slow\"\n    route \"GET /fast\"\n        give \"fast\"\n    route \"GET /cut\"\n        timeout 1\n        sleep(5)\n        give \"never\"\n",
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "v0642_pool.syn", false);
    });
    for _ in 0..120 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    thread::sleep(Duration::from_millis(200));
    // Calentar: el primer request de cada worker arma su intérprete.
    assert_eq!(get(port, "/fast").0, 200);

    let t0 = Instant::now();
    let slow: Vec<_> = (0..6).map(|_| thread::spawn(move || get(port, "/slow"))).collect();
    thread::sleep(Duration::from_millis(300)); // los 6 ya están durmiendo
    let t_fast = Instant::now();
    let (status, body) = get(port, "/fast");
    let fast = t_fast.elapsed();
    assert_eq!(status, 200, "{}", body);
    assert!(fast < Duration::from_millis(1000), "la ruta rápida esperó detrás de las que duermen: {:?}", fast);

    // Las 6 que duermen terminan juntas (~2 s), no de a 2 (que serían ~6 s).
    for h in slow {
        assert_eq!(h.join().unwrap().0, 200);
    }
    let all = t0.elapsed();
    assert!(all < Duration::from_millis(4500), "las rutas que esperan no corrieron a la vez: {:?}", all);

    // Un `timeout` de ruta sigue cortando una ruta que espera (aunque haya soltado su permiso).
    let t = Instant::now();
    let (status, _) = get(port, "/cut");
    assert_eq!(status, 504);
    assert!(t.elapsed() < Duration::from_millis(3000), "el timeout no cortó la espera: {:?}", t.elapsed());
}

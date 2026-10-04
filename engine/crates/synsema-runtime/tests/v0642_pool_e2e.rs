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

/// Los dos tests miden tiempos sobre EL pool del proceso: corren de a uno.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn a_route_that_waits_does_not_hold_the_pool() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
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

/// Un Redis falso que habla RESP: cada `GET` tarda 300 ms (una base de red lenta); el resto de
/// los comandos (`PING`, `CLIENT SETINFO`, `SELECT`…) contesta enseguida. Cuenta los `GET`.
fn slow_resp_server(gets: std::sync::Arc<std::sync::atomic::AtomicUsize>) -> u16 {
    use std::io::BufRead;
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let gets = gets.clone();
            thread::spawn(move || {
                let mut r = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut w = stream;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let n: usize = line.trim().trim_start_matches('*').parse().unwrap_or(0);
                    let mut args = Vec::new();
                    for _ in 0..n {
                        let mut len = String::new();
                        if r.read_line(&mut len).unwrap_or(0) == 0 {
                            return;
                        }
                        let l: usize = len.trim().trim_start_matches('$').parse().unwrap_or(0);
                        let mut buf = vec![0u8; l + 2];
                        if r.read_exact(&mut buf).is_err() {
                            return;
                        }
                        args.push(String::from_utf8_lossy(&buf[..l]).to_ascii_uppercase());
                    }
                    let reply: &[u8] = match args.first().map(|s| s.as_str()) {
                        Some("PING") => b"+PONG\r\n",
                        Some("GET") => {
                            gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            thread::sleep(Duration::from_millis(300));
                            b"$5\r\nvalor\r\n"
                        }
                        _ => b"+OK\r\n",
                    };
                    if w.write_all(reply).is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

/// Auditoría ronda 2: el N+1 contra una base de RED, de punta a punta. Con 2 permisos, 5
/// requests que hacen 2 consultas cada una a un Redis lento (300 ms por `GET`) terminan todas
/// (sin deadlock: la conexión compartida tiene su mutex tomado mientras el hilo espera la red y
/// suelta el permiso), y una ruta que no toca la base contesta mientras tanto.
#[test]
fn n_plus_one_queries_to_a_network_database_do_not_block_the_server() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("SYNSEMA_SERVE_WORKERS", "2");
    let gets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let redis = slow_resp_server(gets.clone());
    let port = free_port();
    let url = format!("redis://127.0.0.1:{}", redis);
    let prog = format!(
        "require serve({p})\nrequire db(\"{url}\")\ndb_open(\"{url}\")\nserve on {p}\n    route \"GET /n1\"\n        let a be redis_get(\"k1\")\n        let b be redis_get(\"k2\")\n        give {{\"a\": a, \"b\": b}}\n    route \"GET /fast\"\n        give \"fast\"\n",
        p = port,
        url = url
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "v0642_pool_db.syn", false);
    });
    for _ in 0..120 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    thread::sleep(Duration::from_millis(200));
    assert_eq!(get(port, "/fast").0, 200);

    let t0 = Instant::now();
    let n1: Vec<_> = (0..5).map(|_| thread::spawn(move || get(port, "/n1"))).collect();
    thread::sleep(Duration::from_millis(400));
    let t_fast = Instant::now();
    let (status, body) = get(port, "/fast");
    assert_eq!(status, 200, "{}", body);
    assert!(t_fast.elapsed() < Duration::from_millis(1000), "la ruta sin base esperó a la base: {:?}", t_fast.elapsed());
    for h in n1 {
        let (status, body) = h.join().unwrap();
        assert_eq!(status, 200, "{}", body);
        assert!(body.contains("\"a\":\"valor\"") || body.contains("\"a\": \"valor\""), "{}", body);
    }
    assert!(t0.elapsed() < Duration::from_secs(15), "{:?}", t0.elapsed());
    assert!(gets.load(std::sync::atomic::Ordering::SeqCst) >= 10, "las 10 consultas llegaron a la base");
}

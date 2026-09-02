//! Tanda escritorio, motor (specs/build-serve-desktop.md §3.3–§3.5) contra el binario real:
//! `shutdown(reason?)` dispara el drain ordenado desde el programa (ruta, cron sólo), es
//! idempotente y falla claro bajo `run` o antes de que haya algo corriendo; la cláusula
//! `bind "…"` del serve block decide dónde escucha el listener (y `--bind` le gana);
//! `platform()` dice la verdad del host.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn project(tag: &str, source: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-desktop-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.syn"), source).unwrap();
    dir
}

fn synsema(cwd: &PathBuf, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(args)
        .current_dir(cwd)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .expect("spawn synsema");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn spawn_serve(cwd: &PathBuf, extra: &[&str]) -> Child {
    let mut args = vec!["serve", "app.syn"];
    args.extend_from_slice(extra);
    Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(&args)
        .current_dir(cwd)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .env("SYNSEMA_SHUTDOWN_GRACE", "5")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn synsema serve")
}

fn http(addr: &str, path: &str) -> Option<(u16, String)> {
    let mut s = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(3)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    s.write_all(format!("GET {} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", path).as_bytes()).ok()?;
    let mut raw = String::new();
    let _ = s.read_to_string(&mut raw);
    let status: u16 = raw.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    Some((status, raw))
}

fn wait_ready(port: u16) {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(60) {
        if let Some((200, _)) = http(&format!("127.0.0.1:{}", port), "/ping") {
            return;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    panic!("el server no levantó en 60 s");
}

/// Espera la salida del hijo (con tope) y devuelve (código, stderr).
fn wait_exit(child: &mut Child, secs: u64) -> (i32, String) {
    let t0 = Instant::now();
    loop {
        if let Ok(Some(st)) = child.try_wait() {
            let mut err = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = e.read_to_string(&mut err);
            }
            return (st.code().unwrap_or(-1), err);
        }
        if t0.elapsed() > Duration::from_secs(secs) {
            let _ = child.kill();
            panic!("el proceso no terminó en {} s", secs);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// La IP no-loopback de esta máquina (sin mandar tráfico), o None si no hay red.
fn lan_ip() -> Option<String> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    let ip = s.local_addr().ok()?.ip();
    if ip.is_loopback() { None } else { Some(ip.to_string()) }
}

#[test]
fn shutdown_from_a_route_drains_and_exits_zero() {
    let port = free_port();
    let dir = project(
        "route",
        &format!(
            "require serve({p})\n\nserve on {p}\n    route \"GET /ping\"\n        give ok({{\"pong\": true}})\n    route \"GET /quit\"\n        shutdown(\"window closed\")\n        shutdown(\"again\")\n        give ok({{\"bye\": true}})\n",
            p = port
        ),
    );
    let mut child = spawn_serve(&dir, &[]);
    wait_ready(port);
    let (st, body) = http(&format!("127.0.0.1:{}", port), "/quit").unwrap();
    assert_eq!(st, 200, "{}", body);
    assert!(body.contains("\"bye\": true"), "{}", body);
    let (code, err) = wait_exit(&mut child, 20);
    assert_eq!(code, 0, "{}", err);
    assert!(err.contains("[serve] shutdown requested by the program: window closed"), "{}", err);
    assert_eq!(err.matches("shutdown requested by the program").count(), 1, "idempotente: {}", err);
    assert!(err.contains("[serve] stopped"), "{}", err);
    assert!(TcpStream::connect_timeout(&format!("127.0.0.1:{}", port).parse().unwrap(), Duration::from_secs(2)).is_err(), "ya no escucha");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn shutdown_from_a_cron_only_program_exits_zero() {
    let dir = project(
        "cron",
        "require time\n\ntask done()\n    shutdown(\"job finished\")\n\ncron_after(0, done)\n",
    );
    let mut child = spawn_serve(&dir, &[]);
    let (code, err) = wait_exit(&mut child, 30);
    assert_eq!(code, 0, "{}", err);
    assert!(err.contains("shutdown requested by the program: job finished"), "{}", err);
    assert!(err.contains("[serve] stopped"), "{}", err);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn shutdown_is_a_clear_error_under_run_and_before_anything_listens() {
    let dir = project("run", "shutdown(\"x\")\n");
    let (code, _, err) = synsema(&dir, &["run", "app.syn"]);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("shutdown() is only available under serve"), "{}", err);

    let port = free_port();
    std::fs::write(
        dir.join("app.syn"),
        format!("require serve({p})\nshutdown(\"too early\")\nserve on {p}\n    route \"GET /ping\"\n        give ok(1)\n", p = port),
    )
    .unwrap();
    let (code, _, err) = synsema(&dir, &["serve", "app.syn"]);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("shutdown(): nothing is running yet"), "{}", err);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bind_clause_decides_the_listener_and_the_flag_wins() {
    let port = free_port();
    let dir = project(
        "bind",
        &format!(
            "require serve({p})\n\nserve on {p}\n    bind \"127.0.0.1\"\n    route \"GET /ping\"\n        give ok({{\"pong\": true}})\n",
            p = port
        ),
    );
    let mut child = spawn_serve(&dir, &[]);
    wait_ready(port);
    if let Some(ip) = lan_ip() {
        // Escucha SÓLO en loopback: por la IP de la LAN nadie entra.
        assert!(
            TcpStream::connect_timeout(&format!("{}:{}", ip, port).parse().unwrap(), Duration::from_secs(2)).is_err(),
            "bind \"127.0.0.1\" no debe escuchar en {}",
            ip
        );
    }
    let _ = child.kill();
    let _ = child.wait();

    // `--bind 0.0.0.0` le gana a la cláusula.
    let mut child = spawn_serve(&dir, &["--bind", "0.0.0.0"]);
    wait_ready(port);
    if let Some(ip) = lan_ip() {
        assert!(
            TcpStream::connect_timeout(&format!("{}:{}", ip, port).parse().unwrap(), Duration::from_secs(2)).is_ok(),
            "--bind 0.0.0.0 escucha en {}",
            ip
        );
    }
    let _ = child.kill();
    let _ = child.wait();

    // `bind` dentro de un `host` es error de parse, con la explicación.
    std::fs::write(
        dir.join("app.syn"),
        format!("require serve({p})\nserve on {p}\n    host \"a.example\"\n        bind \"127.0.0.1\"\n        route \"GET /\"\n            give ok(1)\n", p = port),
    )
    .unwrap();
    let (code, _, err) = synsema(&dir, &["check", "app.syn"]);
    assert_ne!(code, 0);
    assert!(err.contains("'bind' belongs to the serve block"), "{}", err);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn platform_reports_this_host() {
    let dir = project("platform", "let p be platform()\nprint(p[\"os\"])\nprint(p[\"arch\"])\n");
    let (code, out, err) = synsema(&dir, &["run", "app.syn"]);
    assert_eq!(code, 0, "{}", err);
    let lines: Vec<&str> = out.lines().collect();
    let expected_os = match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        "linux" => "linux",
        other => other,
    };
    assert_eq!(lines[0], expected_os);
    assert_eq!(lines[1], std::env::consts::ARCH);
    // Sin capability: corre igual bajo --sandbox.
    let (code, out, _) = synsema(&dir, &["run", "--sandbox", "app.syn"]);
    assert_eq!(code, 0);
    assert!(out.contains(expected_os));
    let _ = std::fs::remove_dir_all(&dir);
}

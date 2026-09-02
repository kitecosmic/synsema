//! `synsema init --desktop` (tanda escritorio, v0.6.19): el scaffold PWA modular (app.syn monta
//! api.syn) más desk.syn y public/desk.js. Se verifica contra el binario real: los archivos,
//! `check` de las dos entradas, `serve desk.syn` con DESK_NO_WINDOW=1 (index con /desk.js, el
//! API montado con sus rate_limit por ruta), y el build de escritorio corriendo desde otro cwd.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-init-desktop-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
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

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn http(port: u16, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    let mut s = TcpStream::connect_timeout(&format!("127.0.0.1:{}", port).parse().unwrap(), Duration::from_secs(3)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let b = body.unwrap_or("");
    let req = format!(
        "{} {} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        method, path, b.len(), b
    );
    s.write_all(req.as_bytes()).unwrap();
    // Bytes, no texto: un PNG no es UTF-8 y `read_to_string` devolvería vacío.
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let raw = String::from_utf8_lossy(&buf).into_owned();
    (raw.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0), raw)
}

fn wait_ready(port: u16) {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(60) {
        if let Ok(mut s) = TcpStream::connect_timeout(&format!("127.0.0.1:{}", port).parse().unwrap(), Duration::from_millis(500)) {
            let _ = s.write_all(b"GET /api/ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let mut raw = String::new();
            let _ = s.read_to_string(&mut raw);
            if raw.contains(" 200 ") {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    panic!("el server no levantó en 60 s");
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Cambia el puerto horneado en un `.syn` del scaffold (8123 / 8080) por uno libre.
fn set_port(dir: &PathBuf, file: &str, from: u16, to: u16) {
    let p = dir.join(file);
    let s = std::fs::read_to_string(&p).unwrap();
    std::fs::write(&p, s.replace(&from.to_string(), &to.to_string())).unwrap();
}

#[test]
fn init_desktop_scaffolds_checks_serves_and_builds() {
    let dir = tmp("scaffold");
    let (code, out, err) = synsema(&dir, &["init", "--desktop"]);
    assert_eq!(code, 0, "{}\n{}", out, err);
    for f in ["app.syn", "api.syn", "desk.syn", "index.html", "public/desk.js", "public/app.js", "public/sw.js", "public/icon-192.png"] {
        assert!(dir.join(f).is_file(), "falta {}", f);
    }
    assert!(out.contains("synsema serve desk.syn"), "próximos pasos de escritorio: {}", out);
    assert!(out.contains("--no-console --icon"), "{}", out);
    // Las dos entradas pasan `check` (módulo + templates validados).
    for entry in ["app.syn", "desk.syn"] {
        let (code, out, err) = synsema(&dir, &["check", entry]);
        assert_eq!(code, 0, "{}: {}", entry, err);
        assert!(out.contains("1 module(s)"), "{}: {}", entry, out);
    }
    // El API compartido conserva sus rate_limit por ruta (los muestra el mapa de código).
    let (code, out, _) = synsema(&dir, &["code", "routes", "app.syn"]);
    assert_eq!(code, 0);
    assert!(out.contains("/api/push/subscribe"), "{}", out);

    // serve desk.syn sin abrir navegador: index con /desk.js, API montado, rate_limit vivo.
    let port = free_port();
    set_port(&dir, "desk.syn", 8123, port);
    let mut child = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["serve", "desk.syn"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .env("DESK_NO_WINDOW", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_ready(port);
    let (st, raw) = http(port, "GET", "/", None);
    assert_eq!(st, 200, "{}", raw);
    assert!(raw.contains("<script src=\"/desk.js\"></script>"), "el bloque desktop del template: {}", raw);
    let (st, raw) = http(port, "GET", "/desk.js", None);
    assert_eq!(st, 200, "{}", raw);
    assert!(raw.contains("new WebSocket("), "{}", raw);
    let (st, raw) = http(port, "GET", "/api/push/config", None);
    assert_eq!(st, 200, "{}", raw);
    assert!(raw.contains("\"vapid_public\""), "{}", raw);
    // rate_limit 2 per minute en /api/push/test dentro del grupo montado: 503 (sin VAPID), 503, 429.
    let sub = "{\"endpoint\": \"https://example.invalid/x\", \"keys\": {}}";
    let (st, _) = http(port, "POST", "/api/push/subscribe", Some(sub));
    assert_eq!(st, 201);
    let (a, _) = http(port, "POST", "/api/push/test", Some("{}"));
    let (b, _) = http(port, "POST", "/api/push/test", Some("{}"));
    let (c, raw) = http(port, "POST", "/api/push/test", Some("{}"));
    assert_eq!((a, b), (503, 503), "push no configurado: 503");
    assert_eq!(c, 429, "el tercero en el minuto: {}", raw);
    kill(&mut child);

    // app.syn (servidor/PWA) sirve la misma página SIN el bloque desktop.
    let port2 = free_port();
    set_port(&dir, "app.syn", 8080, port2);
    let mut child2 = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["serve", "app.syn"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_ready(port2);
    let (st, raw) = http(port2, "GET", "/", None);
    assert_eq!(st, 200, "{}", raw);
    assert!(!raw.contains("/desk.js"), "sin bloque desktop bajo app.syn: {}", raw);
    kill(&mut child2);

    // El build de escritorio: api.syn, index.html y public/ viajan dentro; corre desde otro cwd.
    let (code, out, err) = synsema(&dir, &["build", "desk.syn", "-o", "desk", "--serve"]);
    assert_eq!(code, 0, "{}\n{}", out, err);
    assert!(out.contains("serve · bind 127.0.0.1"), "{}", out);
    let exe = dir.join(if cfg!(windows) { "desk.exe" } else { "desk" });
    let elsewhere = tmp("elsewhere");
    let mut child3 = Command::new(&exe)
        .current_dir(&elsewhere)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .env("DESK_NO_WINDOW", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_ready(port);
    let (st, raw) = http(port, "GET", "/", None);
    assert_eq!(st, 200, "{}", raw);
    assert!(raw.contains("/desk.js"), "{}", raw);
    let (st, _) = http(port, "GET", "/icon-192.png", None);
    assert_eq!(st, 200);
    kill(&mut child3);

    // Volver a correr `init --pwa` en el proyecto: nada se pisa, desk.syn queda.
    let (code, out, _) = synsema(&dir, &["init", "--pwa"]);
    assert_eq!(code, 0);
    assert!(!out.contains("desk.syn.new"), "{}", out);
    assert!(dir.join("desk.syn").is_file());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&elsewhere);
}

/// `--desktop` sobre un proyecto `--pwa` de fábrica: app.syn ya es el modular (al día), se
/// agregan desk.syn y desk.js. Y `--synfide --desktop` se rechaza como `--synfide --pwa`.
#[test]
fn init_desktop_on_top_of_a_pwa_project_and_flag_conflicts() {
    let dir = tmp("on-pwa");
    let (code, _, err) = synsema(&dir, &["init", "--pwa"]);
    assert_eq!(code, 0, "{}", err);
    assert!(!dir.join("desk.syn").exists());
    let (code, out, err) = synsema(&dir, &["init", "--desktop"]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("app.syn ya está al día"), "{}", out);
    assert!(dir.join("desk.syn").is_file() && dir.join("public/desk.js").is_file());
    let (code, _, err) = synsema(&dir, &["init", "--synfide", "--desktop"]);
    assert_eq!(code, 2);
    assert!(err.contains("starters distintos"), "{}", err);
    let _ = std::fs::remove_dir_all(&dir);
}

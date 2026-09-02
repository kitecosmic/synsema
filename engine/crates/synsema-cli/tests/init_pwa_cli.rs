//! E2E de `synsema init --pwa` sobre el binario real (tanda PWA, specs/pwa-mobile.md):
//! el scaffold se escribe entero (sin hello.syn), los PNG se derivan de icon.svg con las
//! dimensiones prometidas y se regeneran sólo cuando corresponde, los flags inválidos
//! fallan con exit 2, y el `app.syn` generado SIRVE lo que una PWA necesita con los
//! content-types correctos (manifest, service worker, íconos, API, rutas de push).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-init-pwa-{}-{}", tag, std::process::id()));
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

fn png_dims(bytes: &[u8]) -> (u32, u32) {
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n", "no es un PNG");
    (
        u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
        u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
    )
}

#[test]
fn init_pwa_scaffolds_and_generates_icons() {
    let dir = tmp("scaffold");
    let (code, out, err) = synsema(&dir, &["init", "--pwa"]);
    assert_eq!(code, 0, "{}\n{}", out, err);
    for name in ["app.syn", "push_keys.syn", "index.html", "public/manifest.webmanifest", "public/sw.js", "public/app.js", "public/icon.svg", "public/icon-maskable.svg", "public/badge.svg", ".env.example", ".gitignore", ".mcp.json"] {
        assert!(dir.join(name).is_file(), "falta {}", name);
        assert!(out.contains(&format!("{} creado", dir.join(name).display())) || name.starts_with('.') || out.contains("creado"), "{}", out);
    }
    assert!(!dir.join("hello.syn").exists(), "el starter de --pwa es app.syn, no el tour");
    assert!(out.contains("generados desde los SVG"), "{}", out);
    assert!(out.contains("Próximos pasos"), "{}", out);
    for (name, px) in [("public/icon-192.png", 192), ("public/icon-512.png", 512), ("public/apple-touch-icon.png", 180), ("public/icon-maskable-512.png", 512), ("public/badge-96.png", 96)] {
        let bytes = std::fs::read(dir.join(name)).unwrap();
        assert_eq!(png_dims(&bytes), (px, px), "{}", name);
    }
    let manifest = std::fs::read_to_string(dir.join("public/manifest.webmanifest")).unwrap();
    assert!(manifest.contains("\"id\": \"/\"") && manifest.contains("\"purpose\": \"maskable\""), "{}", manifest);

    // Segunda corrida: nada cambia, nada se pisa, los PNG no se regeneran.
    let before = std::fs::read(dir.join("public/icon-192.png")).unwrap();
    let badge_before = std::fs::read(dir.join("public/badge-96.png")).unwrap();
    let (code, out, err) = synsema(&dir, &["init", "--pwa"]);
    assert_eq!(code, 0, "{}\n{}", out, err);
    assert!(out.contains("ya está al día"), "{}", out);
    assert!(out.contains("los PNG de los íconos ya están"), "{}", out);
    assert_eq!(std::fs::read(dir.join("public/icon-192.png")).unwrap(), before);

    // El usuario edita icon.svg → SUS PNG se regeneran (y cambian); los de los otros SVG no.
    let svg = std::fs::read_to_string(dir.join("public/icon.svg")).unwrap();
    std::fs::write(dir.join("public/icon.svg"), svg.replace("#111111", "#2266aa")).unwrap();
    let (code, out, err) = synsema(&dir, &["init", "--pwa"]);
    assert_eq!(code, 0, "{}\n{}", out, err);
    assert!(out.contains("icon-192.png, icon-512.png, apple-touch-icon.png generados"), "{}", out);
    assert!(!out.contains("badge-96.png generados"), "el badge no se toca: {}", out);
    assert!(out.contains("icon.svg tiene cambios tuyos"), "el svg editado se conserva: {}", out);
    assert!(dir.join("public/icon.svg.new").is_file(), "y la versión de fábrica queda al lado");
    let after = std::fs::read(dir.join("public/icon-192.png")).unwrap();
    assert_ne!(after, before, "el PNG refleja el svg editado");
    assert_eq!(std::fs::read(dir.join("public/badge-96.png")).unwrap(), badge_before);

    // Sin icon.svg (el usuario trajo sus PNG) → no se toca nada y se dice.
    std::fs::remove_file(dir.join("public/icon.svg")).unwrap();
    std::fs::remove_file(dir.join("public/icon.svg.new")).unwrap();
    let (code, out, err) = synsema(&dir, &["init", "--pwa"]);
    assert_eq!(code, 0, "{}\n{}", out, err);
    // init vuelve a escribir icon.svg de fábrica (es parte del scaffold) — pero ese
    // archivo recién creado ES de fábrica y los PNG ya existen → no se regeneran.
    assert!(out.contains("los PNG de los íconos ya están"), "{}", out);
    assert_eq!(std::fs::read(dir.join("public/icon-192.png")).unwrap(), after);

    // El directorio puede ir antes o después del flag (bug histórico: `--pwa miapp`
    // escribía en el cwd).
    let (code, out, err) = synsema(&dir, &["init", "--pwa", "sub"]);
    assert_eq!(code, 0, "{}\n{}", out, err);
    assert!(dir.join("sub").join("app.syn").is_file() && dir.join("sub").join("public/icon-512.png").is_file());
    let (code, out, err) = synsema(&dir, &["init", "sub2", "--pwa"]);
    assert_eq!(code, 0, "{}\n{}", out, err);
    assert!(dir.join("sub2").join("app.syn").is_file());

    // Flags inválidos: exit 2 y mensaje.
    let (code, _, err) = synsema(&dir, &["init", "--pwa", "--synfide"]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("elegí uno"), "{}", err);
    let (code, _, err) = synsema(&dir, &["init", "--bogus"]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("flag desconocido"), "{}", err);
    let _ = std::fs::remove_dir_all(&dir);
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Una request HTTP/1.1 cruda → (status, head, body).
fn http(port: u16, method: &str, path: &str, body: Option<&str>) -> (u16, String, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut req = format!("{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n", method, path);
    if let Some(b) = body {
        req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    (status, head.to_string(), body.to_string())
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

fn wait_ready(port: u16) {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(60) {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = s.write_all(b"GET /api/ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            if buf.starts_with("HTTP/1.1 200") {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    panic!("el server del scaffold no levantó en 60 s");
}

#[test]
fn init_pwa_app_serves_manifest_sw_icons_and_api() {
    let dir = tmp("serve");
    let (code, out, err) = synsema(&dir, &["init", "--pwa"]);
    assert_eq!(code, 0, "{}\n{}", out, err);
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["serve", "app.syn", "--port", &port.to_string()])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn synsema serve");
    wait_ready(port);

    let (st, head, body) = http(port, "GET", "/manifest.webmanifest", None);
    assert_eq!(st, 200, "{}", head);
    assert_eq!(header(&head, "content-type").as_deref(), Some("application/manifest+json"));
    assert!(body.contains("\"display\": \"standalone\""), "{}", body);

    let (st, head, body) = http(port, "GET", "/sw.js", None);
    assert_eq!(st, 200, "{}", head);
    assert!(header(&head, "content-type").unwrap().starts_with("text/javascript"), "{}", head);
    assert!(body.contains("addEventListener(\"push\""), "{}", body);

    let (st, head, body) = http(port, "GET", "/", None);
    assert_eq!(st, 200, "{}", head);
    assert!(header(&head, "content-type").unwrap().starts_with("text/html"), "{}", head);
    assert!(body.contains("rel=\"manifest\"") && body.contains("<title>My app</title>"), "{}", body);
    assert!(body.contains("body { margin: 0;"), "el bloque raw del CSS llega verbatim: {}", body);

    for icon in ["/icon-192.png", "/icon-512.png", "/apple-touch-icon.png", "/icon-maskable-512.png", "/badge-96.png"] {
        let (st, head, _) = http(port, "GET", icon, None);
        assert_eq!(st, 200, "{} {}", icon, head);
        assert_eq!(header(&head, "content-type").as_deref(), Some("image/png"), "{}", icon);
    }
    // El manifest que el navegador lee: id estable + purpose separados.
    let (_, _, body) = http(port, "GET", "/manifest.webmanifest", None);
    assert!(body.contains("\"id\": \"/\"") && body.contains("\"purpose\": \"maskable\""), "{}", body);
    // Un archivo bajo un directorio con punto (assetlinks de la Play Store) también se sirve, como JSON.
    std::fs::create_dir_all(dir.join("public/.well-known")).unwrap();
    std::fs::write(dir.join("public/.well-known/assetlinks.json"), "[]").unwrap();
    let (st, head, body) = http(port, "GET", "/.well-known/assetlinks.json", None);
    assert_eq!(st, 200, "{}", head);
    assert!(header(&head, "content-type").unwrap().starts_with("application/json"), "{}", head);
    assert_eq!(body.trim(), "[]");
    let (st, head, _) = http(port, "GET", "/icon.svg", None);
    assert_eq!(st, 200, "{}", head);
    assert_eq!(header(&head, "content-type").as_deref(), Some("image/svg+xml"));

    // API + rutas de push: sin claves VAPID, config vacía y test → 503 con el fix.
    let (st, _, body) = http(port, "GET", "/api/ping", None);
    assert_eq!(st, 200);
    assert!(body.contains("\"pong\": true"), "{}", body);
    let (st, _, body) = http(port, "GET", "/api/push/config", None);
    assert_eq!(st, 200);
    assert!(body.contains("\"vapid_public\": \"\""), "{}", body);
    let (st, _, body) = http(port, "POST", "/api/push/test", None);
    assert_eq!(st, 503, "{}", body);
    assert!(body.contains("push_keys.syn"), "{}", body);
    let sub = "{\"endpoint\": \"https://push.example.com/v1/x\", \"keys\": {\"p256dh\": \"a\", \"auth\": \"b\"}}";
    let (st, _, body) = http(port, "POST", "/api/push/subscribe", Some(sub));
    assert_eq!(st, 201, "{}", body);
    assert!(body.contains("\"subscriptions\": 1"), "{}", body);
    // La misma suscripción dos veces no se duplica.
    let (st, _, body) = http(port, "POST", "/api/push/subscribe", Some(sub));
    assert_eq!(st, 201, "{}", body);
    assert!(body.contains("\"subscriptions\": 1"), "{}", body);
    // Un body que no cumple el contrato → 400, no un 500.
    let (st, _, _) = http(port, "POST", "/api/push/subscribe", Some("{\"endpoint\": 1}"));
    assert_eq!(st, 400);

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

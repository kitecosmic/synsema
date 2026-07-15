//! E2E del Batch 9 (export PNG/PDF): `svg_to_png`/`svg_to_pdf` por el runtime REAL.
//! - Dogfood §3.4: chart_svg → svg_to_png → write_file → read_file_bytes, y
//!   chart → pdf → serve (`GET /chart.pdf` responde application/pdf).
//! - G8: la conversión funciona DENTRO de `sandbox`; write_file adentro sigue denegado.
//! - G9: SVG malformado se atrapa con try/recover; en serve un handler con SVG inválido
//!   responde error HTTP y el server sigue vivo.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::{run_source, run_tests};
use synsema_runtime::serve::run_serve_program;

fn out(source: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

// =========================================================
// Disponibles en `run` + composición con charts (Batch 8)
// =========================================================

#[test]
fn png_and_pdf_from_chart_in_run_mode() {
    let o = out(
        r#"let svg be chart_svg("bar", {"ene": 10, "feb": 25}, {"title": "Ventas"})
let png be svg_to_png(svg, {"scale": 2})
let pdf be svg_to_pdf(svg)
print(type_of(png))
print(contains(decode(png, "hex"), "89504e470d0a1a0a"))
print(type_of(pdf))
print(contains(decode(pdf, "hex"), "255044462d"))"#,
    );
    // magic PNG (89 50 4E 47 0D 0A 1A 0A) y magic PDF ("%PDF-" = 25 50 44 46 2d).
    assert_eq!(o, vec!["bytes", "true", "bytes", "true"]);
}

// =========================================================
// G8 — sandbox: convertir adentro funciona; write_file sigue denegado
// =========================================================

#[test]
fn raster_works_inside_sandbox() {
    let o = out(
        r#"let png be bytes("", "hex")
sandbox
    let svg be chart_svg("line", [1, 2, 3])
    set png to svg_to_png(svg)
print(type_of(png))
print(contains(decode(png, "hex"), "89504e470d0a1a0a"))"#,
    );
    assert_eq!(o, vec!["bytes", "true"]);
}

#[test]
fn sandbox_still_denies_write_file() {
    let r = run_source(
        r#"require file
let svg be chart_svg("bar", [1])
sandbox
    write_file("no-deberia-escribirse.png", svg_to_png(svg))"#,
        "<test>",
    );
    assert!(!r.success, "write_file dentro de sandbox debería fallar");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted")),
        "esperaba violación de capability, got {:?}",
        r.errors
    );
}

// =========================================================
// G9 — try/recover atrapa SVG inválido
// =========================================================

#[test]
fn invalid_svg_recoverable() {
    let o = out(
        r#"let msg be ""
try
    svg_to_png("<not-svg")
recover err
    set msg to err
print(contains(msg, "invalid SVG"))
let msg2 be ""
try
    svg_to_png(chart_svg("bar", [1]), {"width": 10000000})
recover err
    set msg2 to err
print(contains(msg2, "max_pixels"))
print("sigue vivo")"#,
    );
    assert_eq!(o, vec!["true", "true", "sigue vivo"]);
}

// =========================================================
// Dogfood §3.4 completo vía `synsema test`: chart → png → file → bytes
// =========================================================

#[test]
fn dogfood_chart_to_png_to_file() {
    let dir = std::env::temp_dir().join("synsema_batch9_dogfood");
    let _ = std::fs::create_dir_all(&dir);
    let png_path = dir.join("ventas.png");
    let _ = std::fs::remove_file(&png_path);
    let path_syn = png_path.to_string_lossy().replace('\\', "/");
    let src = format!(
        r#"require file
let filas be [{{"mes": "ene", "total": 10}}, {{"mes": "feb", "total": 25}}]

test "chart -> png -> file -> bytes"
    let svg be chart_svg("bar", filas, {{"x": "mes", "y": "total", "title": "Ventas"}})
    let png be svg_to_png(svg, {{"scale": 2}})
    write_file("{path_syn}", png)
    let back be read_file_bytes("{path_syn}")
    assert_eq(back, png)
    assert(contains(decode(back, "hex"), "89504e470d0a1a0a"))
"#
    );
    let r = run_tests(&src, "<dogfood9>.syn");
    assert_eq!(
        r.passed, 1,
        "dogfood falló: {:?}",
        r.outcomes.iter().map(|o| (&o.name, &o.message)).collect::<Vec<_>>()
    );
    // El archivo escrito es un PNG de verdad (magic verificado desde Rust).
    let bytes = std::fs::read(&png_path).expect("el PNG debería existir");
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
    let _ = std::fs::remove_file(&png_path);
}

// =========================================================
// serve — PNG/PDF por HTTP + server vivo tras un SVG inválido
// =========================================================

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start(port: u16) {
    let prog = format!(
        r#"require serve({p})
serve on {p}
    route "GET /chart.png"
        let svg be chart_svg("bar", {{"ene": 10, "feb": 25}}, {{"title": "Ventas"}})
        give binary(svg_to_png(svg, {{"scale": 2}}), "image/png")
    route "GET /chart.pdf"
        let svg be chart_svg("bar", {{"ene": 10, "feb": 25}})
        give binary(svg_to_pdf(svg), "application/pdf")
    route "GET /roto"
        give binary(svg_to_png("<not-svg"), "image/png")
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "batch9_e2e.syn", false);
    });
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
}

/// Request cruda; devuelve (status_line+headers como texto, body como bytes).
fn request_bytes(port: u16, target: &str) -> (String, Vec<u8>) {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req =
        format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    let _ = sock.read_to_end(&mut resp);
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("headers completos");
    let head = String::from_utf8_lossy(&resp[..split]).to_string();
    (head, resp[split + 4..].to_vec())
}

#[test]
fn serve_png_pdf_and_survives_invalid_svg() {
    let port = free_port();
    start(port);

    let (head, body) = request_bytes(port, "/chart.png");
    assert!(head.starts_with("HTTP/1.1 200"), "png status: {}", head);
    assert!(head.to_lowercase().contains("content-type: image/png"), "png ct: {}", head);
    assert_eq!(&body[..8], b"\x89PNG\r\n\x1a\n", "magic PNG en el socket");

    let (head, body) = request_bytes(port, "/chart.pdf");
    assert!(head.starts_with("HTTP/1.1 200"), "pdf status: {}", head);
    assert!(
        head.to_lowercase().contains("content-type: application/pdf"),
        "pdf ct: {}",
        head
    );
    assert_eq!(&body[..5], b"%PDF-", "magic PDF en el socket");

    // Handler con SVG inválido → error HTTP (no caída del proceso)…
    let (head, _) = request_bytes(port, "/roto");
    assert!(head.starts_with("HTTP/1.1 500"), "roto status: {}", head);
    // …y el server sigue vivo.
    let (head, _) = request_bytes(port, "/chart.png");
    assert!(head.starts_with("HTTP/1.1 200"), "el server debería seguir vivo: {}", head);
}

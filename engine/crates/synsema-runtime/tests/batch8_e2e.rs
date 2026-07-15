//! E2E del Batch 8 (dataviz de negocio): charts nativos + CSV + estadística por el
//! runtime REAL. Cubre los guardrails del spec:
//! - G2: mismos datos vía literal / csv_parse / sql (SQLite :memory:) → MISMO SVG.
//! - G9: los builtins puros (csv_parse/median/chart_svg) funcionan en `run`, en
//!   `synsema test` y DENTRO de `sandbox` (donde sql sigue denegado).
//! - G10: los errores de chart/csv se atrapan con try/recover; en serve un handler
//!   con chart inválido responde error HTTP y el server sigue vivo.
//! - §5.2: `chart()` negociado — HTML con <svg, .md con la tabla de datos, .json con
//!   las series estructuradas. XSS-safe en todas (G4).

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
// G9 — disponibles en `run` (no sólo en serve)
// =========================================================

#[test]
fn chart_svg_available_in_run_mode() {
    let o = out(
        "let svg be chart_svg(\"bar\", {\"ene\": 10, \"feb\": 25})\n\
         print(contains(svg, \"<svg\"))\n\
         print(contains(svg, \"viewBox\"))",
    );
    assert_eq!(o, vec!["true", "true"]);
}

#[test]
fn chart_svg_available_in_synsema_test_mode() {
    // El MISMO builtin bajo el runner de `synsema test` (G9).
    let src = "test \"chart en test mode\"\n    assert(contains(chart_svg(\"line\", [1, 2, 3]), \"<svg\"))\n";
    let r = run_tests(src, "<t>.syn");
    assert_eq!(r.passed, 1, "outcomes: {:?}", r.outcomes);
}

// =========================================================
// G2 — agnóstico de fuente: literal / csv_parse / sql → mismo SVG
// =========================================================

#[test]
fn same_svg_from_literal_csv_and_sql() {
    let o = out(
        "require db(\":memory:\")\n\
         db_open(\":memory:\", \"memory\")\n\
         sql_exec(\"CREATE TABLE ventas (mes TEXT, total REAL)\")\n\
         sql_exec(\"INSERT INTO ventas VALUES ('ene', 10.5), ('feb', 25.0)\")\n\
         let de_sql be sql(\"SELECT mes, total FROM ventas ORDER BY mes\")\n\
         let literal be [{\"mes\": \"ene\", \"total\": 10.5}, {\"mes\": \"feb\", \"total\": 25.0}]\n\
         let de_csv be csv_parse(\"mes,total\\nene,10.5\\nfeb,25.0\\n\", {\"numbers\": true})\n\
         let opts be {\"x\": \"mes\", \"y\": \"total\", \"title\": \"Ventas\"}\n\
         let s1 be chart_svg(\"bar\", literal, opts)\n\
         let s2 be chart_svg(\"bar\", de_csv, opts)\n\
         let s3 be chart_svg(\"bar\", de_sql, opts)\n\
         print(s1 == s2)\n\
         print(s2 == s3)\n\
         print(contains(s1, \"<svg\"))",
    );
    assert_eq!(o, vec!["true", "true", "true"], "el chart no debe saber de dónde vienen los datos");
}

// =========================================================
// G9 — sandbox: lo puro adentro funciona; sql sigue denegado
// =========================================================

#[test]
fn pure_builtins_work_inside_sandbox() {
    let o = out(
        r#"let med be 0
let p95 be 0
let svg be ""
let filas be []
sandbox
    set filas to csv_parse("v\n1\n2\n3\n4\n", {"numbers": true})
    set med to median([1, 2, 3, 4])
    set p95 to percentile([1, 2, 3, 4], 95)
    set svg to chart_svg("bar", [1, 2])
print(text(med))
print(length(filas))
print(contains(svg, "<svg"))
print(text(p95 > 3))"#,
    );
    assert_eq!(o, vec!["2.5", "4", "true", "true"]);
}

#[test]
fn sandbox_still_denies_capabilities() {
    // El sandbox no se abrió de más: sql adentro sigue denegado aunque el programa
    // tenga la capability afuera.
    let r = run_source(
        r#"require db(":memory:")
db_open(":memory:", "memory")
sandbox
    let x be sql("SELECT 1")"#,
        "<test>",
    );
    assert!(!r.success, "sql dentro de sandbox debería fallar");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted")),
        "esperaba violación de capability, got {:?}",
        r.errors
    );
}

// =========================================================
// G10 — try/recover atrapa los errores de chart
// =========================================================

#[test]
fn chart_errors_recoverable() {
    let o = out(
        r#"let msg be ""
try
    chart_svg("bar", [])
recover err
    set msg to err
print(contains(msg, "data is empty"))
let msg2 be ""
try
    chart_svg("area", [1])
recover err
    set msg2 to err
print(contains(msg2, "bar, line, pie, scatter"))
print("sigue vivo")"#,
    );
    assert_eq!(o, vec!["true", "true", "sigue vivo"]);
}

// =========================================================
// G8 — secret jamás se filtra (csv_encode y chart)
// =========================================================

#[test]
fn secret_never_leaks_in_csv_or_chart() {
    let o = out(
        r#"let s be as_secret("hunter2", "API_KEY")
let enc be csv_encode([{"k": s, "v": "x"}])
print(contains(enc, "[redacted]"))
print(contains(enc, "hunter2"))
let svg be chart_svg("bar", [{"k": s, "v": 1}], {"x": "k", "y": "v"})
print(contains(svg, "hunter2"))
let msg be ""
try
    chart_svg("bar", [{"k": "a", "v": s}], {"x": "k", "y": "v"})
recover err
    set msg to err
print(contains(msg, "secret"))
print(contains(msg, "hunter2"))"#,
    );
    assert_eq!(o, vec!["true", "false", "false", "true", "false"]);
}

// =========================================================
// Dogfood (§7.5): pipeline completo EN EL LENGUAJE, vía `synsema test`
// =========================================================

#[test]
fn dogfood_pipeline_via_synsema_test() {
    // csv_parse → filtrado/colección → median/percentile/histogram → chart_svg,
    // con asserts sobre el SVG — todo en Synsema.
    let src = r#"let crudo be "mes,total\nene,10\nfeb,25\nmar,17\nabr,25\n"
task totales(filas)
    let acc be []
    each fila in filas
        set acc to acc + [fila["total"]]
    give acc

test "pipeline csv -> stats -> chart"
    let filas be csv_parse(crudo, {"numbers": true})
    assert_eq(length(filas), 4)
    let ts be totales(filas)
    assert_eq(median(ts), 21.0)
    assert_eq(percentile(ts, 100), 25.0)
    let h be histogram(ts, 3)
    assert_eq(length(h["edges"]), 4)
    let svg be chart_svg("bar", filas, {"x": "mes", "y": "total", "title": "Ventas"})
    assert(contains(svg, "<svg"))
    assert(contains(svg, "Ventas"))
    assert(contains(svg, "ene"))
    -- determinista (G7): mismo input, mismos bytes
    assert_eq(svg, chart_svg("bar", filas, {"x": "mes", "y": "total", "title": "Ventas"}))

test "csv round-trip en el lenguaje"
    let filas be csv_parse(crudo, {"numbers": true})
    assert_eq(csv_parse(csv_encode(filas), {"numbers": true}), filas)
"#;
    let r = run_tests(src, "<dogfood>.syn");
    assert_eq!(
        r.passed, 2,
        "dogfood falló: {:?}",
        r.outcomes.iter().map(|o| (&o.name, &o.message)).collect::<Vec<_>>()
    );
}

// =========================================================
// serve — chart() negociado en las tres salidas + server vivo tras error
// =========================================================

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start(port: u16) {
    // La negociación por sufijo (.md/.json) sólo re-interpreta un path capturado por
    // un :param (doctrina existente de serve) → la ruta del reporte usa :name.
    let prog = format!(
        r#"require serve({p})
serve on {p}
    route "GET /r/:name"
        let filas be [{{"mes": "ene", "total": 10}}, {{"mes": "feb", "total": 25}}]
        give content(page([heading(1, "Ventas 2026"), prose("Mediana mensual: " + text(median([10, 25]))), chart("bar", filas, {{"x": "mes", "y": "total", "title": "Ventas por mes"}})], {{"title": "Reporte"}}))
    route "GET /xss"
        give content(page([chart("pie", {{"<script>alert(1)</script>": 4, "b": 2}})]))
    route "GET /roto"
        give content(page([chart("bar", [])]))
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "batch8_e2e.syn", false);
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

/// Request cruda con Accept opcional; devuelve la respuesta completa (case original).
fn request(port: u16, target: &str, accept: Option<&str>) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let accept_h = accept.map(|a| format!("Accept: {}\r\n", a)).unwrap_or_default();
    let req = format!(
        "GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n{accept_h}Connection: close\r\n\r\n"
    );
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

#[test]
fn chart_negotiated_three_ways_and_server_survives_errors() {
    let port = free_port();
    start(port);

    // HTML (default): la página trae heading/prose Y el SVG inline del chart.
    let html = request(port, "/r/ventas", None);
    assert!(html.starts_with("HTTP/1.1 200"), "html status: {}", html);
    assert!(html.contains("text/html"), "html ct: {}", html);
    assert!(html.contains("<h1>Ventas 2026</h1>"), "heading: {}", html);
    assert!(html.contains("Mediana mensual: 17.5"), "prose+median: {}", html);
    assert!(html.contains("<svg"), "svg inline: {}", html);
    assert!(html.contains("Ventas por mes"), "título del chart: {}", html);

    // Markdown (.md): el agente recibe los DATOS como tabla, no píxeles.
    let md = request(port, "/r/ventas.md", None);
    assert!(md.starts_with("HTTP/1.1 200"), "md status: {}", md);
    assert!(md.contains("text/markdown"), "md ct: {}", md);
    assert!(md.contains("# Ventas 2026"), "md heading: {}", md);
    assert!(md.contains("**Ventas por mes**"), "md título: {}", md);
    assert!(md.contains("| mes | total |"), "md cabecera de tabla: {}", md);
    assert!(md.contains("| ene | 10"), "md fila de datos: {}", md);
    assert!(!md.contains("<svg"), "el MD no debe traer píxeles: {}", md);

    // La MISMA ruta con header Accept (sin sufijo) también negocia.
    let md2 = request(port, "/r/ventas", Some("text/markdown"));
    assert!(md2.contains("| mes | total |"), "Accept negotiation: {}", md2);

    // JSON (.json): estructura §5.2 — type/kind/title/series con puntos [x, y].
    let json = request(port, "/r/ventas.json", None);
    assert!(json.starts_with("HTTP/1.1 200"), "json status: {}", json);
    assert!(json.contains("\"type\": \"chart\""), "json type: {}", json);
    assert!(json.contains("\"kind\": \"bar\""), "json kind: {}", json);
    assert!(json.contains("\"title\": \"Ventas por mes\""), "json title: {}", json);
    assert!(json.contains("\"series\""), "json series: {}", json);
    assert!(json.contains("\"name\": \"total\""), "json serie name: {}", json);
    assert!(json.contains("[\"ene\", 10.0]"), "json points: {}", json);
    assert!(!json.contains("<svg"), "el JSON no debe traer píxeles: {}", json);

    // XSS (G4): el label hostil sale escapado en HTML y MD (nunca <script> ejecutable).
    let xss_html = request(port, "/xss", None);
    assert!(!xss_html.contains("<script>alert"), "XSS en HTML: {}", xss_html);
    assert!(xss_html.contains("&lt;script&gt;"), "escape visible: {}", xss_html);
    let xss_md = request(port, "/xss", Some("text/markdown"));
    assert!(!xss_md.contains("<script>alert"), "XSS en MD: {}", xss_md);

    // G10: un handler con chart inválido responde error HTTP (no tumba el proceso)…
    let broken = request(port, "/roto", None);
    assert!(broken.starts_with("HTTP/1.1 500"), "roto status: {}", broken);
    // …y el server sigue vivo para el siguiente request.
    let again = request(port, "/r/ventas", None);
    assert!(again.starts_with("HTTP/1.1 200"), "el server debería seguir vivo: {}", again);
}

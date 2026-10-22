//! E2E del Batch 10 (catálogo de charts de negocio) por el runtime REAL.
//! Espeja la estructura del batch8_e2e y cubre los guardrails del spec:
//! - G2: mismos datos vía literal / csv_parse / sql (SQLite :memory:) → MISMO SVG
//!   para los kinds nuevos (heatmap/boxplot/waterfall).
//! - G9: los kinds nuevos funcionan en `run`, `synsema test` y DENTRO de `sandbox`.
//! - G10: errores atrapables con try/recover; en serve un kind inválido responde
//!   error HTTP y el server sigue vivo.
//! - §3.7: contrato de 3 salidas por kind — HTML con <svg, .md con tabla/matriz,
//!   .json con la estructura por kind. XSS-safe en las tres (G4).
//! - §7.5: dogfood EN EL LENGUAJE — pipeline csv → chart de cada kind nuevo con
//!   asserts estructurales sobre el SVG (conteo de <rect>/<path>, colores default).

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
// G9 — kinds nuevos disponibles en `run`
// =========================================================

#[test]
fn new_kinds_available_in_run_mode() {
    let o = out(
        r#"print(contains(chart_svg("area", [1, 2, 3]), "<svg"))
print(contains(chart_svg("donut", {"a": 4, "b": 2}), "<svg"))
print(contains(chart_svg("histogram", [1, 2, 2, 3]), "<svg"))
print(contains(chart_svg("boxplot", [1, 2, 3, 4]), "<svg"))
print(contains(chart_svg("waterfall", {"alta": 5, "baja": -2}), "<svg"))
print(contains(chart_svg("heatmap", [[1, 2], [3, 4]]), "<svg"))"#,
    );
    assert_eq!(o, vec!["true", "true", "true", "true", "true", "true"]);
}

// =========================================================
// G2 — agnóstico de fuente: literal / csv_parse / sql → mismo SVG
// =========================================================

#[test]
fn same_svg_from_literal_csv_and_sql_for_new_kinds() {
    let o = out(
        r#"require db(":memory:")
db_open(":memory:", "memory")
sql_exec("CREATE TABLE t (dia TEXT, hora TEXT, v REAL)")
sql_exec("INSERT INTO t VALUES ('lun', '9', 5.0), ('lun', '10', 8.0), ('mar', '9', 3.0), ('mar', '10', 4.0)")
let de_sql be sql("SELECT dia, hora, v FROM t")
let literal be [{"dia": "lun", "hora": "9", "v": 5.0}, {"dia": "lun", "hora": "10", "v": 8.0}, {"dia": "mar", "hora": "9", "v": 3.0}, {"dia": "mar", "hora": "10", "v": 4.0}]
let de_csv be csv_parse("dia,hora,v\nlun,9,5.0\nlun,10,8.0\nmar,9,3.0\nmar,10,4.0\n", {"numbers": true})
let hm be {"x": "hora", "y": "dia", "value": "v"}
print(chart_svg("heatmap", literal, hm) == chart_svg("heatmap", de_csv, hm))
print(chart_svg("heatmap", de_csv, hm) == chart_svg("heatmap", de_sql, hm))
let bx be {"x": "dia", "y": "v"}
print(chart_svg("boxplot", literal, bx) == chart_svg("boxplot", de_sql, bx))
let wf be {"x": "dia", "y": "v"}
print(chart_svg("waterfall", literal, wf) == chart_svg("waterfall", de_sql, wf))"#,
    );
    assert_eq!(
        o,
        vec!["true", "true", "true", "true"],
        "el chart no debe saber de dónde vienen los datos (G2)"
    );
}

// =========================================================
// G9 — sandbox: kinds nuevos adentro; sql sigue denegado
// =========================================================

#[test]
fn new_kinds_work_inside_sandbox() {
    let o = out(
        r#"let svg be ""
let caja be ""
sandbox
    set svg to chart_svg("heatmap", [[1, 2], [3, 4]], {"legend": false})
    set caja to chart_svg("boxplot", [1, 2, 3, 4, 5])
print(contains(svg, "<svg"))
print(contains(caja, "<svg"))"#,
    );
    assert_eq!(o, vec!["true", "true"]);
}

#[test]
fn sandbox_still_denies_sql_with_new_kinds_around() {
    let r = run_source(
        r#"require db(":memory:")
db_open(":memory:", "memory")
sandbox
    let filas be sql("SELECT 1")
    let svg be chart_svg("heatmap", [[1]], {})"#,
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
// G10 — try/recover atrapa los errores de los kinds nuevos
// =========================================================

#[test]
fn new_kind_errors_recoverable() {
    let o = out(
        r#"let m1 be ""
try
    chart_svg("boxplot", [])
recover err
    set m1 to err
print(contains(m1, "data is empty"))
let m2 be ""
try
    chart_svg("pie", {"a": 1}, {"stack": true})
recover err
    set m2 to err
print(contains(m2, "stack"))
let m3 be ""
try
    chart_svg("treemap", {"a": 1})
recover err
    set m3 to err
print(contains(m3, "valid kinds"))
let m4 be ""
try
    chart_svg("boxplot", {"solo": [7]})
recover err
    set m4 to err
print(contains(m4, "at least 2"))
print("sigue vivo")"#,
    );
    assert_eq!(o, vec!["true", "true", "true", "true", "sigue vivo"]);
}

// =========================================================
// G8 — secret jamás se filtra en los kinds nuevos
// =========================================================

#[test]
fn secret_never_leaks_in_new_kinds() {
    let o = out(
        r#"let s be as_secret("hunter2", "API_KEY")
let svg be chart_svg("boxplot", [{"g": s, "v": 1}, {"g": s, "v": 2}], {"x": "g", "y": "v"})
print(contains(svg, "hunter2"))
print(contains(svg, "[redacted]"))
let wfv be chart_svg("waterfall", [{"c": s, "d": 5}], {"x": "c", "y": "d"})
print(contains(wfv, "hunter2"))
let msg be ""
try
    chart_svg("waterfall", [{"c": "a", "d": s}], {"x": "c", "y": "d"})
recover err
    set msg to err
print(contains(msg, "secret"))
print(contains(msg, "hunter2"))"#,
    );
    assert_eq!(o, vec!["false", "true", "false", "true", "false"]);
}

// =========================================================
// Dogfood (§7.5): pipeline completo EN EL LENGUAJE, vía `synsema test`
// =========================================================

#[test]
fn dogfood_all_new_kinds_via_synsema_test() {
    // csv_parse → chart de cada kind nuevo, con asserts estructurales sobre el SVG
    // (conteo de <rect>/<path>/<circle>/<polygon>, colores default en orden) — todo
    // en Synsema. `legend: false` donde el conteo debe ser sólo de datos.
    let src = r##"let crudo be "mes,a,b\nene,10,4\nfeb,25,9\nmar,17,12\n"

task cuenta(svg, tag)
    give length(split(svg, tag)) - 1

test "area apilada: 2 polígonos + 2 líneas, colores en orden"
    let filas be csv_parse(crudo, {"numbers": true})
    let o be {"x": "mes", "y": ["a", "b"], "stack": true, "legend": false}
    let svg be chart_svg("area", filas, o)
    assert(contains(svg, "<svg"))
    assert_eq(cuenta(svg, "<polygon"), 2)
    assert_eq(cuenta(svg, "<polyline"), 2)
    assert(contains(svg, "#2a78d6"))
    assert(contains(svg, "#008300"))
    -- determinista (G7)
    assert_eq(svg, chart_svg("area", filas, o))

test "bar apilado: una columna por mes, un tramo por serie"
    let filas be csv_parse(crudo, {"numbers": true})
    let svg be chart_svg("bar", filas, {"x": "mes", "y": ["a", "b"], "stack": true, "legend": false})
    assert_eq(cuenta(svg, "<rect"), 6)

test "heatmap: una celda por fila tidy, stops secuenciales en los extremos"
    let celdas be [{"d": "lun", "h": "9", "v": 1}, {"d": "lun", "h": "10", "v": 5}, {"d": "mar", "h": "9", "v": 9}]
    let svg be chart_svg("heatmap", celdas, {"x": "h", "y": "d", "value": "v", "legend": false})
    assert_eq(cuenta(svg, "<rect"), 3)
    assert(contains(svg, "#f1f6fd"))
    assert(contains(svg, "#123c6b"))

test "histogram: un rect por bin y composición con histogram()"
    let datos be [1, 2, 2, 3, 3, 3, 9]
    let svg be chart_svg("histogram", datos, {"bins": 4})
    assert_eq(cuenta(svg, "<rect"), 4)
    assert(contains(svg, "#2a78d6"))
    -- comparten el binning: el mapa de histogram() da el MISMO SVG (test de guardia)
    assert_eq(svg, chart_svg("histogram", histogram(datos, 4)))

test "boxplot: una caja por grupo, outlier como marker"
    let grupos be {"web": [1, 2, 3, 4, 5, 100], "tel": [2, 2, 3, 8, 9]}
    let svg be chart_svg("boxplot", grupos)
    assert_eq(cuenta(svg, "<rect"), 2)
    assert_eq(cuenta(svg, "<circle"), 1)
    assert(contains(svg, ">web<"))
    assert(contains(svg, ">tel<"))

test "donut: un path por slice, paleta en orden"
    let svg be chart_svg("donut", {"a": 4, "b": 2, "c": 1}, {"legend": false})
    assert_eq(cuenta(svg, "<path"), 3)
    assert(contains(svg, "#2a78d6"))
    assert(contains(svg, "#008300"))
    assert(contains(svg, "#e87ba4"))

test "waterfall: un rect por paso + total, colores semánticos CVD-safe"
    let svg be chart_svg("waterfall", {"ventas": 100, "costos": -40, "gastos": -25}, {"total": true})
    assert_eq(cuenta(svg, "<rect"), 4)
    assert(contains(svg, "#2a78d6"))
    assert(contains(svg, "#eb6834"))
    assert(contains(svg, "#52514e"))
    assert(contains(svg, ">Total<"))
"##;
    let r = run_tests(src, "<dogfood10>.syn");
    assert_eq!(
        r.passed,
        7,
        "dogfood falló: {:?}",
        r.outcomes.iter().map(|o| (&o.name, &o.message)).collect::<Vec<_>>()
    );
}

// =========================================================
// serve — contrato de 3 salidas por kind + server vivo tras error
// =========================================================

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start(port: u16) {
    let prog = format!(
        r#"require serve({p})
serve on {p}
    route "GET /r/:name"
        let celdas be [{{"d": "lun", "h": "9", "v": 5}}, {{"d": "lun", "h": "10", "v": 8}}, {{"d": "mar", "h": "9", "v": 3}}]
        let tiempos be [{{"canal": "web", "t": 1}}, {{"canal": "web", "t": 2}}, {{"canal": "web", "t": 3}}, {{"canal": "web", "t": 4}}, {{"canal": "web", "t": 5}}, {{"canal": "web", "t": 100}}]
        let flujo be {{"ventas": 100, "costos": -40, "gastos": -25}}
        give content(page([
            heading(1, "Operaciones"),
            chart("heatmap", celdas, {{"x": "h", "y": "d", "value": "v", "title": "Actividad"}}),
            chart("boxplot", tiempos, {{"x": "canal", "y": "t", "title": "Tiempos"}}),
            chart("waterfall", flujo, {{"total": true, "title": "Puente"}})
        ], {{"title": "Reporte"}}))
    route "GET /xss"
        give content(page([
            chart("boxplot", [{{"g": "<script>alert(1)</script>", "v": 1}}, {{"g": "<script>alert(1)</script>", "v": 2}}], {{"x": "g", "y": "v"}}),
            chart("heatmap", [{{"x": "<script>alert(1)</script>", "y": "a", "v": 1}}], {{"x": "x", "y": "y", "value": "v"}}),
            chart("waterfall", {{"<script>alert(1)</script>": 5}})
        ]))
    route "GET /roto"
        give content(page([chart("gauge", [1])]))
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "batch10_e2e.syn", false);
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
fn new_kinds_negotiated_three_ways_and_server_survives_errors() {
    let port = free_port();
    start(port);

    // HTML: SVG inline de los tres charts.
    let html = request(port, "/r/ops", None);
    assert!(html.starts_with("HTTP/1.1 200"), "html status: {}", html);
    assert!(html.contains("<svg"), "svg inline: {}", html);
    assert!(html.contains("Actividad") && html.contains("Puente"), "títulos: {}", html);

    // Markdown: el agente recibe DATOS — matriz del heatmap, cuartiles del boxplot,
    // acumulados del waterfall. Jamás píxeles.
    let md = request(port, "/r/ops.md", None);
    assert!(md.starts_with("HTTP/1.1 200"), "md status: {}", md);
    assert!(!md.contains("<svg"), "el MD no debe traer píxeles: {}", md);
    // heatmap → matriz (filas = y, columnas = x); celda ausente (mar, 10) → vacía
    assert!(md.contains("| 9 | 10 |"), "cabecera de matriz: {}", md);
    assert!(md.contains("| lun | 5.0 | 8.0 |"), "fila lun: {}", md);
    assert!(md.contains("| mar | 3.0 |  |"), "celda ausente vacía: {}", md);
    // boxplot → cuartiles con nombre (percentile lineal: q1 2.25, mediana 3.5, q3 4.75)
    assert!(md.contains("| group | min | q1 | median | q3 | max | outliers |"), "cabecera boxplot: {}", md);
    assert!(md.contains("| web | 1.0 | 2.25 | 3.5 | 4.75 | 5.0 | 100.0 |"), "cuartiles web: {}", md);
    // waterfall → deltas y acumulados + fila de total
    assert!(md.contains("| label | delta | running |"), "cabecera waterfall: {}", md);
    assert!(md.contains("| ventas | 100.0 | 100.0 |"), "paso 1: {}", md);
    assert!(md.contains("| costos | -40.0 | 60.0 |"), "paso 2 acumulado: {}", md);
    assert!(md.contains("| Total |  | 35.0 |"), "fila total: {}", md);

    // JSON: estructura §3.7 por kind.
    let json = request(port, "/r/ops.json", None);
    assert!(json.starts_with("HTTP/1.1 200"), "json status: {}", json);
    assert!(!json.contains("<svg"), "el JSON no debe traer píxeles: {}", json);
    assert!(json.contains("\"kind\": \"heatmap\""), "kind heatmap: {}", json);
    assert!(json.contains("\"x_labels\": [\"9\", \"10\"]"), "x_labels: {}", json);
    assert!(json.contains("\"y_labels\": [\"lun\", \"mar\"]"), "y_labels: {}", json);
    assert!(json.contains("[[5.0, 8.0], [3.0, null]]"), "values con celda null: {}", json);
    assert!(json.contains("\"kind\": \"boxplot\""), "kind boxplot: {}", json);
    assert!(json.contains("\"median\": 3.5"), "mediana estructurada: {}", json);
    assert!(json.contains("\"outliers\": [100.0]"), "outliers: {}", json);
    assert!(json.contains("\"kind\": \"waterfall\""), "kind waterfall: {}", json);
    assert!(json.contains("\"running\": 60.0"), "acumulado: {}", json);
    assert!(json.contains("\"total\": 35.0"), "total: {}", json);

    // XSS (G4): labels hostiles en boxplot/heatmap/waterfall → escapados en las tres.
    let xss_html = request(port, "/xss", None);
    assert!(!xss_html.contains("<script>alert"), "XSS en HTML: {}", xss_html);
    assert!(xss_html.contains("&lt;script&gt;"), "escape visible: {}", xss_html);
    let xss_md = request(port, "/xss", Some("text/markdown"));
    assert!(!xss_md.contains("<script>alert"), "XSS en MD: {}", xss_md);
    // En JSON el label hostil es DATO dentro de un string JSON (encoding correcto,
    // no ejecutable); lo que jamás debe pasar es que aparezca fuera de un string.
    // (La negociación por sufijo sólo aplica a rutas con :param → header Accept.)
    let xss_json = request(port, "/xss", Some("application/json"));
    assert!(xss_json.contains("\"<script>alert(1)</script>\""), "label como dato JSON: {}", xss_json);

    // G10: kind inválido → error HTTP, jamás caída…
    let broken = request(port, "/roto", None);
    assert!(broken.starts_with("HTTP/1.1 500"), "roto status: {}", broken);
    // …y el server sigue vivo.
    let again = request(port, "/r/ops", None);
    assert!(again.starts_with("HTTP/1.1 200"), "el server debería seguir vivo: {}", again);
}

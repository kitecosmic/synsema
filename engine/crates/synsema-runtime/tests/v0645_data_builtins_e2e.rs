//! v0.6.45 (B1–B3): `gzip`/`gunzip`, `url_encode`/`url_decode` y `header(r, nombre)` desde un
//! programa, contra un servidor HTTP local (sin red externa).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use synsema_runtime::engine::run_program;

/// Un servidor que contesta un 429 con `Retry-After` (capitalización propia) y, en `/data.gz`, un
/// gzip de `{"n": 7}` hecho por el propio motor en el test.
fn server(gz: Vec<u8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { continue };
            let gz = gz.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                if req.starts_with("GET /data.gz") {
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        gz.len()
                    );
                    let _ = s.write_all(head.as_bytes());
                    let _ = s.write_all(&gz);
                } else {
                    let _ = s.write_all(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 3\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                }
            });
        }
    });
    port
}

#[test]
fn gzip_url_and_header_from_a_program() {
    // El .gz lo arma el motor mismo (gzip determinista) y el servidor lo devuelve tal cual.
    let make = run_program("print(hex(gzip(\"{\\\"n\\\": 7}\")))\n", "<mk>");
    assert!(make.success, "{:?}", make.errors);
    let hex = make.output[0].trim_start_matches("0x").to_string();
    let gz: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
    let port = server(gz);
    let src = format!(
        r#"require net("127.0.0.1:{port}")
let r be http_get("http://127.0.0.1:{port}/api")
print(r["status"])
print(get(r["headers"], "retry-after", "sin"))
print(header(r, "retry-after"))
print(header(r["headers"], "RETRY-AFTER"))
print(header(r, "x-nada") == nothing)
let d be http_bytes("GET", "http://127.0.0.1:{port}/data.gz")
let data be json_decode(decode(gunzip(d["bytes"])))
print(data["n"])
print(url_encode("a b&c=d/é"))
print(url_decode(url_encode("ñandú & co")))
"#
    );
    let r = run_program(&src, "<b123>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        ["429", "sin", "3", "3", "true", "7", "a%20b%26c%3Dd%2F%C3%A9", "ñandú & co"],
        "{:?}",
        r.output
    );
}

/// v0.6.45 (B5): `x_axis` desde un programa — fechas con `format` (el strftime de `format_time`),
/// y los errores dirigidos: un kind sin eje de categorías, una clave desconocida, un especificador
/// inválido.
#[test]
fn chart_x_axis_from_a_program() {
    let src = r#"let rows be apply(range(0, 30), (i) => {"dia": add_days(date(2026, 1, 1), i), "n": i})
let svg be chart_svg("bar", rows, {"x": "dia", "y": "n", "x_axis": {"angle": 30, "every": 7, "format": "%d/%m"}})
print(contains(svg, ">08/01<"))
print(contains(svg, ">02/01<"))
print(contains(svg, "rotate(-30 "))
let e1 be "ok"
try
    chart_svg("pie", {"a": 1}, {"x_axis": {"angle": 45}})
recover e
    set e1 to e
print(contains(e1, "x_axis"))
let e2 be "ok"
try
    chart_svg("bar", rows, {"x": "dia", "y": "n", "x_axis": {"rotate": 45}})
recover e
    set e2 to e
print(contains(e2, "unknown x_axis key"))
let e3 be "ok"
try
    chart_svg("bar", rows, {"x": "dia", "y": "n", "x_axis": {"format": "%Q"}})
recover e
    set e3 to e
print(contains(e3, "not a strftime specifier"))
"#;
    let r = run_program(src, "<b5>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["true", "false", "true", "true", "true", "true"], "{:?}", r.output);
}

/// v0.6.45 (B9): HTML real desde un programa (el caso con etiquetas está en `v0645_html_labels_e2e`).
#[test]
fn html_from_a_program() {
    let src = r#"let page be "<ul><li class=item><a href=/a>Uno &amp; dos</a><li class=item><a href=/b>Dos</a></ul><script>x()</script>"
let links be html_select(page, "li.item > a")
print(length(links))
print(links[0]["attrs"]["href"])
print(links[0]["text"])
print(html_text(page))
print(html_unescape("&lt;b&gt; &eacute;"))
"#;
    let r = run_program(src, "<b9>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["2", "/a", "Uno & dos", "Uno & dos\nDos", "<b> é"], "{:?}", r.output);
}

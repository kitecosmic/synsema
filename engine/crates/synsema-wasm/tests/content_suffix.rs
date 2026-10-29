//! v0.6.51: `content()` en el handler embebible, con la misma regla que `serve` nativo — el sufijo
//! `.md`/`.json` vale en una ruta literal, el `lang` de la meta llega a `<html lang>` y el JSON no
//! lleva la presentación.

use synsema_wasm::{handle, HttpRequestIn, RunOptions};

fn get(src: &str, path: &str) -> (u16, String, String) {
    let req = HttpRequestIn { method: "GET".into(), path: path.into(), headers: vec![], body: vec![], client_ip: "127.0.0.1".into() };
    let r = handle(src, &RunOptions::new("c.syn"), &req);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    (r.response.status, r.response.content_type, String::from_utf8_lossy(&r.response.body).into_owned())
}

#[test]
fn content_takes_a_suffix_on_a_literal_route_in_wasm_too() {
    let src = "require serve(8080)\nserve on 8080\n    route \"GET /historial\"\n        give content(page([heading(1, \"Hola\")], {\"title\": \"T\", \"lang\": \"es\", \"stylesheet\": \"/s.css\"}))\n";
    let (st, _, body) = get(src, "/historial");
    assert!(st == 200 && body.contains("<html lang=\"es\">"), "{} {}", st, body);
    let (st, ct, body) = get(src, "/historial.md");
    assert!(st == 200 && ct.contains("text/markdown") && body.contains("# Hola"), "{} {} {}", st, ct, body);
    let (st, ct, body) = get(src, "/historial.json");
    assert!(st == 200 && ct.contains("application/json") && body.contains("\"lang\"") && !body.contains("stylesheet"), "{} {} {}", st, ct, body);
    assert_eq!(get(src, "/nada.md").0, 404);
}

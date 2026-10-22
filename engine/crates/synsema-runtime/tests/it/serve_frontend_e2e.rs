//! E2E de la tanda FRONTEND:
//! - Motor de templates: bloque verbatim `{ raw }…{ end }`, `{ otherwise when }`
//!   encadenado, rama vacía de `each`, `enumerate`, `include … with` (props),
//!   slots nombrados (`{ slot "x" }` + `{ fill "x" }`), comentarios `{ -- }`,
//!   error fuerte en `each` sobre no-lista, `json_for_script`.
//! - Serve: `mount` de un grupo `export routes` (con y sin prefijo, helper privado
//!   del módulo, `expect` → 400), `errors with` (404 HTML negociado / JSON default /
//!   401 redirect), `form of request` (urlencoded), `static … cache … fallback`,
//!   gzip dinámico y validación de `render("literal")` al arranque.
//! - Lexer: línea en blanco CRLF dentro de un bloque (bug de Windows).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::run_source;
use synsema_runtime::serve::run_serve_program;

fn fixtures_main() -> String {
    format!("{}/tests/fixtures/serve_frontend_main.syn", env!("CARGO_MANIFEST_DIR"))
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn wait_ready(port: u16) {
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
}

/// Request crudo; devuelve la respuesta completa (head + body) como texto lossy.
fn raw_request(port: u16, req: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = sock.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

fn get(port: u16, target: &str, extra_headers: &str) -> String {
    raw_request(
        port,
        &format!(
            "GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Connection: close\r\n\r\n",
            target, extra_headers
        ),
    )
}

fn post(port: u16, target: &str, ctype: &str, body: &str) -> String {
    raw_request(
        port,
        &format!(
            "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            target,
            ctype,
            body.len(),
            body
        ),
    )
}

// =========================================================
// Motor de templates (render bajo el engine, sin serve)
// =========================================================

#[test]
fn template_features_render() {
    let r = run_source(
        "require file.read(\"tests/fixtures/tpl/*\")\n\
         let items be [\"a\", \"b</script>\"]\n\
         print(body of render(\"tests/fixtures/tpl/feat.html\", {\"n\": 2, \"items\": items, \"vacio\": []}))",
        "t.syn",
    );
    assert!(r.success, "errs: {:?}", r.errors);
    let out = r.output.join("\n");
    // comentario no aparece
    assert!(!out.contains("comentario: no debe aparecer"), "out: {}", out);
    // verbatim: CSS con llaves, intacto
    assert!(out.contains("body { margin: 0; }"), "out: {}", out);
    assert!(out.contains(".card:hover { transform: translateY(-4px); }"));
    // elif encadenado
    assert!(out.contains("dos"));
    assert!(!out.contains("uno") && !out.contains("otro"));
    // enumerate con índice + escape del item
    assert!(out.contains("[0:a][1:b&lt;/script&gt;]"), "out: {}", out);
    assert!(!out.contains("SIN-ITEMS"));
    // rama vacía del each
    assert!(out.contains("VACIO"));
    // include con props (aislados)
    assert!(out.contains("<article>Props</article>"));
    // json_for_script: el </script> del dato NO puede cerrar el tag
    assert!(out.contains("b\\u003c/script\\u003e"), "out: {}", out);
    assert!(!out.contains("window.__D__ = [\"a\", \"b</script>"));
}

#[test]
fn template_named_slots() {
    let r = run_source(
        "require file.read(\"tests/fixtures/tpl/*\")
print(body of render(\"tests/fixtures/tpl/page_fill.html\", {\"title\": \"Hola\"}))",
        "t.syn",
    );
    assert!(r.success, "errs: {:?}", r.errors);
    let out = r.output.join("\n");
    assert!(out.contains("<head><meta name=\"x\" content=\"Hola\"></head>"), "out: {}", out);
    assert!(out.contains("<h1>Hola</h1>"));
}

#[test]
fn template_each_non_list_fails_loud() {
    let r = run_source(
        "require file.read(\"tests/fixtures/tpl/badeach.html\")
print(body of render(\"tests/fixtures/tpl/badeach.html\", {\"numero\": 7}))",
        "t.syn",
    );
    assert!(!r.success);
    let msg = r.errors.join(" ");
    assert!(msg.contains("Cannot iterate over"), "msg: {}", msg);
}

#[test]
fn json_for_script_escapes_html_chars() {
    let r = run_source(
        "print(json_for_script({\"x\": \"</script><b>&\"}))\nprint(json_for_script([1, 2]))",
        "t.syn",
    );
    assert!(r.success, "errs: {:?}", r.errors);
    assert_eq!(r.output[1], "[1, 2]");
    assert!(r.output[0].contains("\\u003c/script\\u003e"));
    assert!(r.output[0].contains("\\u0026"));
    assert!(!r.output[0].contains('<') && !r.output[0].contains('>'));
}

#[test]
fn enumerate_builtin() {
    let r = run_source(
        "each e in enumerate([\"x\", \"y\"])\n    print(text(e.index) + \"-\" + e.item)\nprint(text(length(enumerate([]))))",
        "t.syn",
    );
    assert!(r.success, "errs: {:?}", r.errors);
    assert_eq!(r.output, vec!["0-x", "1-y", "0"]);
}

#[test]
fn lexer_crlf_blank_line_in_block() {
    // Línea en blanco CRLF dentro de un bloque indentado (archivo de Windows).
    let src = "task f()\r\n    let a be 1\r\n\r\n    give a\r\nprint(text(f()))\r\n";
    let r = run_source(src, "t.syn");
    assert!(r.success, "errs: {:?}", r.errors);
    assert_eq!(r.output, vec!["1"]);
}

// =========================================================
// Serve: mount + errors with + form + static cache/fallback + gzip
// =========================================================

fn start_frontend_serve(port: u16, static_dir: &str) {
    let prog = format!(
        r#"require serve({p})
require time
require file.read("{d}/**")
use "./mount_shop.syn" as shop

task pagina_error(status, message, request)
    when status == 401
        give redirect("/login")
    let accept be accept of (headers of request)
    when accept == nothing
        set accept to ""
    when contains(accept, "text/html")
        give html("<h1>" + text(status) + " personalizada</h1>")
    give nothing

task check_token(token)
    when token == "clave"
        give {{"name": "ana"}}
    give nothing

serve on {p}
    auth with check_token
    errors with pagina_error

    mount shop.tienda
    mount shop.tienda at "/v2"

    static "/app" from "{d}" cache "1h" fallback "index.html"

    route "GET /login"
        give html("<p>login</p>")

    route "GET /privado" requires auth
        give {{"ok": true}}

    route "POST /contacto"
        let f be form of request
        give {{"nombre": f.nombre}}

    route "GET /grande"
        let cuerpo be ""
        each i in range(300)
            set cuerpo to cuerpo + "<p>fila " + text(i) + " con contenido repetitivo</p>"
        give html(cuerpo)
"#,
        p = port,
        d = static_dir.replace('\\', "/"),
    );
    let importer = fixtures_main();
    thread::spawn(move || {
        let _ = run_serve_program(&prog, &importer, false);
    });
    wait_ready(port);
}

fn make_static_dir(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!("syn_frontend_e2e_{}", tag));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(dir.join("index.html"), b"<title>SPA</title>SPA-SHELL").unwrap();
    dir.to_string_lossy().into_owned()
}

#[test]
fn serve_frontend_full_stack() {
    let port = free_port();
    let dir = make_static_dir("full");
    start_frontend_serve(port, &dir);

    // mount: ruta simple con helper privado del módulo
    let r = get(port, "/shop", "");
    assert!(r.contains("200"), "r: {}", r);
    assert!(r.contains("<h1>Shop $99</h1>"));

    // mount: path param
    let r = get(port, "/shop/42", "");
    assert!(r.contains("\"producto\": \"42\""), "r: {}", r);

    // mount con prefijo
    let r = get(port, "/v2/shop", "");
    assert!(r.contains("<h1>Shop $99</h1>"), "r: {}", r);

    // mount: expect → 400 con field
    let r = post(port, "/shop/buy", "application/json", "{}");
    assert!(r.contains("400"), "r: {}", r);
    assert!(r.contains("\"field\": \"item\""));

    // mount: expect OK → 201
    let r = post(port, "/shop/buy", "application/json", "{\"item\": \"gorra\"}");
    assert!(r.contains("201"), "r: {}", r);
    assert!(r.contains("\"comprado\": \"gorra\""));

    // mount: rate_limit POR RUTA del grupo (v0.6.19) — zona propia; el prefijo es otra zona
    let r = get(port, "/shop/limited", "");
    assert!(r.starts_with("HTTP/1.1 200"), "r: {}", r);
    let r = get(port, "/shop/limited", "");
    assert!(r.starts_with("HTTP/1.1 429"), "segundo request en el minuto: {}", r);
    let r = get(port, "/v2/shop/limited", "");
    assert!(r.starts_with("HTTP/1.1 200"), "el mount con prefijo tiene su propia zona: {}", r);
    // mount: timeout POR RUTA del grupo → 504 con cancelación real
    let r = get(port, "/shop/slow", "");
    assert!(r.starts_with("HTTP/1.1 504"), "r: {}", r);

    // errors with: 404 HTML para Accept text/html, con status 404
    let r = get(port, "/nada", "Accept: text/html\r\n");
    assert!(r.starts_with("HTTP/1.1 404"), "r: {}", r);
    assert!(r.contains("<h1>404 personalizada</h1>"));

    // errors with: nothing → JSON default
    let r = get(port, "/nada", "");
    assert!(r.starts_with("HTTP/1.1 404"), "r: {}", r);
    assert!(r.contains("\"error\": \"no route for GET /nada\""));

    // errors with: 401 → redirect (el 3xx del handler se respeta)
    let r = get(port, "/privado", "");
    assert!(r.contains("301"), "r: {}", r);
    assert!(r.to_lowercase().contains("location: /login"), "r: {}", r);

    // form of request: urlencoded con percent-decoding
    let r = post(port, "/contacto", "application/x-www-form-urlencoded", "nombre=Jo%C3%ABl");
    assert!(r.contains("Jo\\u00ebl") || r.contains("Joël"), "r: {}", r);

    // static: Cache-Control del mount
    let r = get(port, "/app/index.html", "");
    assert!(r.contains("200"), "r: {}", r);
    assert!(r.to_lowercase().contains("cache-control: public, max-age=3600"), "r: {}", r);

    // static: fallback SPA (miss → index.html con 200)
    let r = get(port, "/app/ruta/interna", "");
    assert!(r.contains("200"), "r: {}", r);
    assert!(r.contains("SPA-SHELL"));

    // gzip dinámico en html() grande
    let r = get(port, "/grande", "Accept-Encoding: gzip\r\n");
    assert!(r.to_lowercase().contains("content-encoding: gzip"), "r: {}", r);
    assert!(r.to_lowercase().contains("vary: accept-encoding"));
}

/// v0.6.46 (ronda 1 de cf1, M3): con el permiso de leerlo; sin él, el arranque no lo abre y lo
/// chequea `render()` (ver `serve_startup_template_check_needs_file_read`).
#[test]
fn serve_validates_render_literal_at_startup() {
    let port = free_port();
    let prog = format!(
        "require serve({p})\nrequire file.read(\"tests/fixtures/tpl/*\")\nserve on {p}\n    route \"GET /\"\n        give render(\"tests/fixtures/tpl/no_existe.html\", {{}})\n",
        p = port
    );
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let r = run_serve_program(&prog, "startup_probe.syn", false);
        let _ = tx.send((r.success, r.errors.join(" | ")));
    });
    let (success, errors) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("el serve con template roto debió fallar al arranque, no quedarse sirviendo");
    assert!(!success);
    assert!(errors.contains("template validation failed"), "errors: {}", errors);
    assert!(errors.contains("no_existe.html"));
}

/// v0.6.46 (backlog §10): la validación de los `render("…")` literales al arrancar leía cada template
/// y sus `include`/`layout` sin `file.read`; ahora pasa por el mismo gate que `render()`. Ronda 1 de
/// cf1 (M3): lo que el arranque no puede leer no lo lee, pero tampoco frena el server: el `require`
/// puede estar dentro de la ruta (vale en el request, como en v0.6.45) y `render()` lo chequea ahí.
#[test]
fn serve_startup_template_check_needs_file_read() {
    let start = |pre: &str, tpl: &str, route_pre: &str| {
        let port = free_port();
        let prog = format!(
            "require serve({p})\n{pre}serve on {p}\n    route \"GET /\"\n{route_pre}        give render(\"{tpl}\", {{\"title\": \"Hola\"}})\n",
            p = port,
            pre = pre,
            tpl = tpl,
            route_pre = route_pre
        );
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let r = run_serve_program(&prog, "startup_gate.syn", false);
            let _ = tx.send((r.success, r.errors.join(" | ")));
        });
        (port, rx)
    };
    let page = "tests/fixtures/tpl/page_fill.html";
    let broken = "tests/fixtures/tpl_unread/broken.html";
    // Sin `file.read`, el arranque no lee el template: uno roto que no puede leer no lo frena (si lo
    // leyera, fallaría con el error de sintaxis, que dice lo que tiene adentro).
    let (port, rx) = start("", broken, "");
    wait_ready(port);
    assert!(rx.try_recv().is_err(), "arrancó sin leer el template");
    let r = get(port, "/", "");
    assert!(r.contains("500"), "render() lo niega en el request: {}", r.replace('\n', " "));
    // Con permiso, el roto sí se valida al arrancar.
    let (_, rx) = start("require file.read(\"tests/fixtures/tpl_unread/*\")\n", broken, "");
    let (ok, errors) = rx.recv_timeout(Duration::from_secs(10)).expect("debió fallar al arrancar");
    assert!(!ok && errors.contains("template validation failed") && errors.contains("without a matching block"), "{}", errors);
    // El `require` dentro de la ruta: arranca y sirve (en v0.6.45 también).
    let (port, _rx) = start("", page, "        require file.read(\"tests/fixtures/tpl/*\")\n");
    wait_ready(port);
    let r = get(port, "/", "");
    assert!(r.contains("200") && r.contains("<h1>Hola</h1>"), "r: {}", r.replace('\n', " "));
    // Con el permiso en el preámbulo, arranca y sirve.
    let (port, _rx) = start("require file.read(\"tests/fixtures/tpl/*\")\n", page, "");
    wait_ready(port);
    let r = get(port, "/", "");
    assert!(r.contains("200") && r.contains("<h1>Hola</h1>"), "r: {}", r.replace('\n', " "));
}

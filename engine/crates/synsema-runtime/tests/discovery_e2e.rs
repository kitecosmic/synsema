//! E2E de discovery (spec `specs/discovery-openapi.md`): `/openapi.json`, `/sitemap.xml`,
//! `/docs` (negociado), `Sitemap:` en `/robots.txt` y las secciones nuevas de
//! `/llms.txt` — contra un server REAL (`run_serve_program`), y las tres reglas
//! comunes: gate `private`, `docs off`, override por route declarada.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::serve::run_serve_program;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start(prog: String, port: u16) {
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "discovery_e2e.syn", false);
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
}

fn get(port: u16, target: &str, extra: &str) -> (u16, String, String) {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let req = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n{extra}\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    let status: u16 = resp.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let (head, body) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
    (status, head.to_lowercase(), body.to_string())
}

fn full_program(port: u16, extra_clauses: &str) -> String {
    format!(
        r#"intent: "Sell books"
require serve({p})

task charge(n)
    require net("api.example")
    give n

task check_token(token)
    give when token == "ok" then {{"id": 1}} otherwise nothing

serve on {p}
    auth with check_token
    describe
        about: "Bookshop API"
        api: ["GET /books/:id -- one book"]
        version: "2.0.0"
{extra}
    route "GET /"
        give content(page([heading("Bookshop")]))
    route "GET /books/:id"
        give {{"id": params.id}}
    route "POST /orders" requires auth
        rate_limit 5 per minute
        expect body {{book: text, qty: number}}
        let r be charge(1)
        give {{"ok": true}}
    route "GET /events"
        stream
            send {{"tick": 1}}
    route "GET /health"
        give html("<p>ok</p>")
"#,
        p = port,
        extra = extra_clauses
    )
}

#[test]
fn openapi_sitemap_docs_llms_and_robots() {
    let port = free_port();
    start(full_program(port, ""), port);

    // /openapi.json: 3.1, paths derivadas, expect → requestBody, auth → security +
    // securitySchemes, rate → 429, stream → text/event-stream, capabilities.
    let (st, head, body) = get(port, "/openapi.json", "");
    assert_eq!(st, 200, "{}", body);
    assert!(head.contains("content-type: application/json"), "{}", head);
    let j: serde_json::Value = serde_json::from_str(&body).expect("json válido");
    assert_eq!(j["openapi"], "3.1.0");
    assert_eq!(j["info"]["title"], "Bookshop API");
    assert_eq!(j["info"]["description"], "Sell books");
    assert_eq!(j["info"]["version"], "2.0.0");
    assert_eq!(j["servers"][0]["url"], format!("http://127.0.0.1:{}", port));
    let orders = &j["paths"]["/orders"]["post"];
    assert_eq!(orders["operationId"], "post_orders");
    assert_eq!(orders["requestBody"]["content"]["application/json"]["schema"]["properties"]["qty"]["type"], "number");
    assert_eq!(orders["requestBody"]["content"]["application/json"]["schema"]["required"], serde_json::json!(["book", "qty"]));
    assert!(orders["responses"]["400"].is_object() && orders["responses"]["401"].is_object() && orders["responses"]["429"].is_object());
    assert_eq!(orders["x-synsema-rate-limit"]["count"], 5);
    assert_eq!(orders["x-synsema-capabilities"], serde_json::json!([{"name": "net", "scope": "api.example"}]));
    assert_eq!(orders["security"][0], serde_json::json!({"bearer": []}));
    assert!(j["components"]["securitySchemes"]["bearer"].is_object());
    assert_eq!(j["paths"]["/books/{id}"]["get"]["parameters"][0]["name"], "id");
    assert_eq!(j["paths"]["/books/{id}"]["get"]["description"], "one book");
    assert!(j["paths"]["/events"]["get"]["responses"]["200"]["content"]["text/event-stream"].is_object());
    assert_eq!(j["paths"]["/events"]["get"]["x-synsema-streaming"], true);
    assert!(j["paths"]["/"]["get"]["responses"]["200"]["content"]["text/markdown"].is_object(), "content() negociado");
    assert!(j["paths"]["/health"]["get"]["responses"]["200"]["content"]["text/html"].is_object());
    assert_eq!(j["paths"]["/health"]["get"]["x-synsema-capabilities"], serde_json::json!([]), "presente, vacía");
    // Determinismo: dos GET, mismo byte.
    assert_eq!(body, get(port, "/openapi.json", "").2);

    // /sitemap.xml: sólo GET sin params/auth/stream → `/` y `/health`.
    let (st, head, body) = get(port, "/sitemap.xml", "");
    assert_eq!(st, 200);
    assert!(head.contains("application/xml"));
    assert_eq!(
        body,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n  <url><loc>http://127.0.0.1:{p}/</loc></url>\n  <url><loc>http://127.0.0.1:{p}/health</loc></url>\n</urlset>\n",
            p = port
        )
    );
    // Detrás de un proxy TLS: X-Forwarded-Proto manda el esquema.
    let (_, _, body) = get(port, "/sitemap.xml", "X-Forwarded-Proto: https\r\n");
    assert!(body.contains(&format!("https://127.0.0.1:{}/health", port)), "{}", body);
    // `X-Forwarded-Host` NO manda: es inyectable por cualquier cliente y un proxy genérico lo
    // deja pasar (host header injection). Detrás de un proxy la base URL se declara con `domain`.
    let (_, _, body) = get(port, "/sitemap.xml", "X-Forwarded-Host: evil.example\r\n");
    assert!(body.contains(&format!("http://127.0.0.1:{}/health", port)), "{}", body);
    assert!(!body.contains("evil.example"), "{}", body);

    // /robots.txt apunta al sitemap.
    let (_, _, body) = get(port, "/robots.txt", "");
    assert_eq!(body, format!("User-agent: *\nAllow: /\nSitemap: http://127.0.0.1:{}/sitemap.xml\n", port));

    // /docs: HTML por defecto (sin CDN, lee /openapi.json), Markdown para agentes.
    let (st, head, body) = get(port, "/docs", "");
    assert_eq!(st, 200);
    assert!(head.contains("text/html"));
    assert!(body.contains("fetch('/openapi.json')") && body.contains("Bookshop API"));
    assert!(!body.contains("cdn.") && !body.contains("unpkg"), "sin scripts de terceros");
    let (st, head, body) = get(port, "/docs", "Accept: text/markdown\r\n");
    assert_eq!(st, 200);
    assert!(head.contains("text/markdown"), "{}", head);
    assert!(body.starts_with("# Bookshop API — API reference"), "{}", body);
    assert!(body.contains("## POST /orders") && body.contains("- `qty`: number") && body.contains("requires auth"));
    assert!(body.contains("## GET /books/{id}"));

    // /llms.txt: sufijo de capabilities por endpoint + sección Machine-readable.
    let (_, _, body) = get(port, "/llms.txt", "");
    assert!(body.contains("- POST /orders  [net:api.example]"), "{}", body);
    assert!(body.contains("- GET /health\n"), "{}", body);
    assert!(body.contains("## Machine-readable\n- /openapi.json\n- /docs\n- /sitemap.xml\n- /.well-known/synsema-auth\n"), "{}", body);
}

#[test]
fn private_hides_everything_but_robots() {
    let port = free_port();
    start(full_program(port, "    private\n"), port);
    for p in ["/openapi.json", "/sitemap.xml", "/docs", "/llms.txt"] {
        assert_eq!(get(port, p, "").0, 404, "{} debe ser 404 con private", p);
    }
    let (_, _, body) = get(port, "/robots.txt", "");
    assert_eq!(body, "User-agent: *\nDisallow: /\n");
}

#[test]
fn docs_off_keeps_openapi() {
    let port = free_port();
    start(full_program(port, "    docs off\n"), port);
    assert_eq!(get(port, "/docs", "").0, 404);
    assert_eq!(get(port, "/openapi.json", "").0, 200);
    let (_, _, body) = get(port, "/llms.txt", "");
    assert!(body.contains("- /openapi.json\n- /sitemap.xml\n"), "sin /docs en la lista: {}", body);
}

#[test]
fn declared_route_and_domain_win() {
    let port = free_port();
    let prog = format!(
        r#"require serve({p})
serve on {p}
    domain "books.example"
    route "GET /docs"
        give {{"mine": true}}
    route "GET /openapi.json"
        give {{"mine": "spec"}}
    route "GET /about"
        give "hi"
"#,
        p = port
    );
    start(prog, port);
    let (st, _, body) = get(port, "/docs", "");
    assert_eq!(st, 200);
    assert!(body.contains("\"mine\": true") || body.contains("\"mine\":true"), "{}", body);
    let (_, _, body) = get(port, "/openapi.json", "");
    assert!(body.contains("spec"), "la route declarada gana: {}", body);
    // `domain` fija la base URL (sin TLS → http); los paths reservados no entran.
    let (_, _, body) = get(port, "/sitemap.xml", "");
    assert!(body.contains("<loc>http://books.example/about</loc>"), "{}", body);
    assert!(!body.contains("/docs") && !body.contains("openapi"), "{}", body);
    let (_, _, body) = get(port, "/robots.txt", "");
    assert!(body.contains("Sitemap: http://books.example/sitemap.xml"), "{}", body);
}

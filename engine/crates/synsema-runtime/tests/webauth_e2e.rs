//! E2E de la tanda web-auth: login con contraseña → cookie de sesión → ruta
//! protegida (auth de 2 parámetros con `request.cookies`) → logout. Además:
//! `Set-Cookie` múltiple, `with_header` sobre redirect, CR/LF y headers
//! prohibidos → error, y la REGRESIÓN del auth de 1 parámetro (bearer token).
//! Corre programas .syn REALES y verifica los bytes en el socket.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::run_source;
use synsema_runtime::serve::run_serve_program;

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

/// Request cruda con headers extra y body opcional. Devuelve la respuesta ENTERA
/// tal cual (case preservado — los asserts de headers usan la forma canónica).
fn request(port: u16, method: &str, target: &str, extra: &[(&str, &str)], body: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    req.push_str(body);
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

/// Extrae el valor de la cookie `sid` del primer `Set-Cookie` de la respuesta.
fn extract_sid(resp: &str) -> String {
    for line in resp.lines() {
        if let Some(rest) = line.strip_prefix("set-cookie: ").or_else(|| line.strip_prefix("Set-Cookie: ")) {
            if let Some(v) = rest.strip_prefix("sid=") {
                let v = v.split(';').next().unwrap_or("");
                if !v.is_empty() {
                    return v.to_string();
                }
            }
        }
    }
    panic!("no hay Set-Cookie sid= en la respuesta: {}", resp);
}

/// Server de sesiones por cookie: auth de 2 parámetros (token, request).
fn start_session_server(port: u16) {
    let prog = format!(
        r#"require serve({p})
require random

let phc be password_hash("hunter2")

task check_session(token, request)
    let sid be request.cookies.sid
    when sid == nothing
        give nothing
    give state_get("sess:" + sid)

serve on {p}
    auth with check_session
    route "POST /login"
        let user be request.json.user
        let pw be request.json.pw
        when user == "admin" and password_verify(pw, phc)
            let sid be token()
            state_set("sess:" + sid, {{"name": user}})
            give set_cookie(ok({{"ok": true}}), "sid", sid, {{"max_age": 86400}})
        give fail(401, "bad credentials")
    route "GET /me" requires auth
        give request.user
    route "POST /logout" requires auth
        give clear_cookie(ok({{"bye": true}}), "sid")
    route "GET /two"
        give set_cookie(set_cookie(respond("dos", "text/plain"), "a", "1"), "b", "2")
    route "GET /reqid"
        give with_header(redirect("/panel"), "X-Request-Id", "rid-42")
    route "GET /crlf"
        give with_header(respond("x", "text/plain"), "X-Evil", "a\r\nInjected: 1")
    route "GET /banned"
        give with_header(ok(1), "Content-Length", "999")
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "webauth_e2e.syn", false);
    });
    wait_ready(port);
}

#[test]
fn session_login_cookie_me_logout_e2e() {
    let port = free_port();
    start_session_server(port);

    // (1) Login con credenciales malas → 401 y sin cookie.
    let r = request(port, "POST", "/login", &[], r#"{"user": "admin", "pw": "wrong"}"#);
    assert!(r.starts_with("HTTP/1.1 401"), "login malo: {}", r);
    assert!(!r.contains("Set-Cookie"), "401 no debe setear cookie: {}", r);

    // (2) Login OK → 200 + Set-Cookie con los defaults seguros.
    let r = request(port, "POST", "/login", &[], r#"{"user": "admin", "pw": "hunter2"}"#);
    assert!(r.starts_with("HTTP/1.1 200"), "login ok: {}", r);
    assert!(
        r.contains("Path=/") && r.contains("HttpOnly") && r.contains("Secure")
            && r.contains("SameSite=Lax") && r.contains("Max-Age=86400"),
        "defaults de la cookie: {}",
        r
    );
    let sid = extract_sid(&r);
    assert_eq!(sid.len(), 43, "token() de 32 bytes → 43 chars base64url");

    // (3) /me con cookie → 200 con el user de la sesión (auth de 2 parámetros
    //     leyó request.cookies).
    let cookie = format!("sid={}", sid);
    let r = request(port, "GET", "/me", &[("Cookie", &cookie)], "");
    assert!(r.starts_with("HTTP/1.1 200"), "/me con cookie: {}", r);
    assert!(r.contains("admin"), "/me devuelve el user: {}", r);

    // (4) /me sin cookie → 401. Cookie inventada → 401.
    let r = request(port, "GET", "/me", &[], "");
    assert!(r.starts_with("HTTP/1.1 401"), "/me sin cookie: {}", r);
    let r = request(port, "GET", "/me", &[("Cookie", "sid=forjada")], "");
    assert!(r.starts_with("HTTP/1.1 401"), "/me cookie forjada: {}", r);

    // (5) Logout → clear_cookie con expiración doble.
    let r = request(port, "POST", "/logout", &[("Cookie", &cookie)], "");
    assert!(r.starts_with("HTTP/1.1 200"), "logout: {}", r);
    assert!(
        r.contains("sid=;") && r.contains("Max-Age=0")
            && r.contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT"),
        "clear_cookie: {}",
        r
    );

    // (6) Dos set_cookie → DOS líneas Set-Cookie separadas.
    let r = request(port, "GET", "/two", &[], "");
    let set_cookies = r.lines().filter(|l| l.starts_with("set-cookie:") || l.starts_with("Set-Cookie:")).count();
    assert_eq!(set_cookies, 2, "dos líneas Set-Cookie: {}", r);
    assert!(r.contains("a=1") && r.contains("b=2"), "ambas cookies: {}", r);

    // (7) with_header sobre redirect: header custom + Location conviven.
    let r = request(port, "GET", "/reqid", &[], "");
    assert!(r.starts_with("HTTP/1.1 301"), "redirect con header: {}", r);
    let lower = r.to_ascii_lowercase();
    assert!(lower.contains("location: /panel"), "location: {}", r);
    assert!(lower.contains("x-request-id: rid-42"), "header custom: {}", r);

    // (8) CR/LF en el valor → 500 y JAMÁS se inyecta el header (G2).
    let r = request(port, "GET", "/crlf", &[], "");
    assert!(r.starts_with("HTTP/1.1 500"), "crlf: {}", r);
    assert!(!r.contains("Injected"), "CRLF inyectado: {}", r);

    // (9) Header prohibido (Content-Length) → 500 con error claro.
    let r = request(port, "GET", "/banned", &[], "");
    assert!(r.starts_with("HTTP/1.1 500"), "banned: {}", r);
}

/// REGRESIÓN ítem C: el auth de 1 parámetro (bearer token) se comporta idéntico.
#[test]
fn auth_one_param_bearer_regression() {
    let port = free_port();
    let prog = format!(
        r#"require serve({p})

task check_token(token)
    when token == "k1"
        give {{"role": "admin"}}
    give nothing

serve on {p}
    auth with check_token
    route "GET /secure" requires auth
        give request.user
"#,
        p = port
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "webauth_e2e_1p.syn", false);
    });
    wait_ready(port);

    let r = request(port, "GET", "/secure", &[("Authorization", "Bearer k1")], "");
    assert!(r.starts_with("HTTP/1.1 200"), "bearer válido: {}", r);
    assert!(r.contains("admin"), "user en la respuesta: {}", r);

    let r = request(port, "GET", "/secure", &[("Authorization", "Bearer nope")], "");
    assert!(r.starts_with("HTTP/1.1 401"), "bearer inválido: {}", r);

    let r = request(port, "GET", "/secure", &[], "");
    assert!(r.starts_with("HTTP/1.1 401"), "sin auth: {}", r);
}

/// `random_bytes`/`token` están gateados por `random` — la MISMA puerta
/// deny-by-default de `random()`/`random_int()`. Sin `require random` → error de
/// capability; con él → funcionan. Los puros (password/jwt/totp) NO llevan gate.
#[test]
fn random_capability_gates_token_and_random_bytes() {
    let r = run_source("let t be token()\nprint(t)\n", "t.syn");
    assert!(!r.success, "token() sin require random debió fallar");
    assert!(r.errors.join(" ").contains("random"), "err: {:?}", r.errors);

    let r = run_source("let b be random_bytes(8)\nprint(length(b))\n", "t.syn");
    assert!(!r.success, "random_bytes() sin require random debió fallar");

    let r = run_source("require random\nlet t be token()\nprint(length(t))\n", "t.syn");
    assert!(r.success, "con require random debió andar: {:?}", r.errors);
    assert_eq!(r.output.last().map(String::as_str), Some("43"));

    // Los transforms puros no llevan gate (la salt interna de password_hash no
    // cuenta como "producir aleatoriedad" — precedente redis_lock).
    let r = run_source(
        "let p be password_hash(\"x\")\nprint(password_verify(\"x\", p))\n",
        "t.syn",
    );
    assert!(r.success, "password_hash sin capability debió andar: {:?}", r.errors);
}

/// Aridad inválida del auth task → error claro al CONSTRUIR el serve (no en runtime).
#[test]
fn auth_bad_arity_fails_at_build() {
    let port = free_port();
    let prog = format!(
        r#"require serve({p})

task three(a, b, c)
    give nothing

serve on {p}
    auth with three
    route "GET /x" requires auth
        give 1
"#,
        p = port
    );
    let res = run_serve_program(&prog, "webauth_e2e_arity.syn", false);
    assert!(!res.success, "un auth task de 3 parámetros debe fallar al construir el serve");
    let all_errors = res.errors.join("\n");
    assert!(
        all_errors.contains("auth task must take 1 (token) or 2 (token, request) parameters"),
        "mensaje de aridad: {}",
        all_errors
    );
}

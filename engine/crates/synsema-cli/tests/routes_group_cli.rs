//! Grupos `export routes` (v0.6.19): `rate_limit` y `timeout` por ruta viajan con el grupo y
//! `synsema check` rechaza ESTÁTICAMENTE lo que serve rechazaría al arrancar (`stream`/`socket`
//! dentro de un grupo), con el mismo mensaje — nada de "OK" en check y error en producción.

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
fn check_rejects_stream_and_socket_inside_a_routes_group_like_serve_does() {
    let dir = project(
        "socket",
        "export routes routes\n    route \"GET /ws\"\n        socket\n            give 1\n",
    );
    let (code, _, err) = synsema(&dir, &["check", "app.syn"]);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("routes.syn:2:5: a 'routes' group cannot contain 'socket' routes yet"), "{}", err);

    let dir2 = project(
        "stream",
        "export routes routes\n    route \"GET /events\"\n        stream\n            send \"x\"\n",
    );
    let (code, _, err) = synsema(&dir2, &["check", "app.syn"]);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("a 'routes' group cannot contain 'stream' routes yet"), "{}", err);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

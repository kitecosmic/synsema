//! v0.6.45 (A5): `synsema serve` con un `exit(code)` antes de escuchar sale con ese código y sin
//! "Runtime error" en stderr (el patrón de una app de escritorio de una sola instancia).

use std::process::Command;

fn serve_exit(code: u8) -> (i32, String) {
    let dir = std::env::temp_dir().join(format!("synsema-v0645-a5-{}-{}", std::process::id(), code));
    std::fs::create_dir_all(&dir).unwrap();
    let src = format!(
        "require serve(18645)\nprint(\"ya hay otra instancia\")\nexit({code})\nserve on 18645\n    route \"GET /\"\n        give \"x\"\n"
    );
    std::fs::write(dir.join("app.syn"), src).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["serve", "app.syn"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .expect("spawn synsema serve");
    let _ = std::fs::remove_dir_all(&dir);
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn serve_exits_with_the_code_of_an_exit_before_listening() {
    let (code, err) = serve_exit(0);
    assert_eq!(code, 0, "{}", err);
    assert!(!err.contains("Runtime error"), "{}", err);
    let (code, err) = serve_exit(4);
    assert_eq!(code, 4, "{}", err);
    assert!(!err.contains("Runtime error"), "{}", err);
}

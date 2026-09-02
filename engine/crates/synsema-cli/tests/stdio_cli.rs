//! Salidas honestas (src/stdio.rs): un stdout/stderr sin lector NO es un pánico — el proceso
//! termina en silencio con 0 (el análogo de SIGPIPE), en todos los SO. Y en Windows, un build
//! `--no-console` bajo `--engine` respeta una salida redirigida (archivo/tubería) tal cual.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-stdio-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_closed_stdout_is_a_quiet_exit_zero_not_a_panic() {
    let dir = project("pipe");
    // 20 000 líneas > cualquier buffer de tubería: alguna escritura encuentra la tubería cerrada.
    std::fs::write(dir.join("loud.syn"), "each i in range(20000)\n    print(\"line \" + text(i))\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["run", "loud.syn"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Cerramos NUESTRO extremo de lectura enseguida: el hijo escribe a una tubería muerta.
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("panicked") && !err.contains("failed printing"), "stderr: {}", err);
    assert_eq!(out.status.code(), Some(0), "salida silenciosa con 0, no un pánico: {}", err);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_closed_stderr_is_quiet_too() {
    let dir = project("pipe-err");
    // Un error de runtime va a stderr; con stderr muerto no hay a quién contárselo.
    std::fs::write(dir.join("bad.syn"), "each i in range(20000)\n    print(\"x\")\nprint(nope)\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["run", "bad.syn"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    drop(child.stderr.take());
    let status = child.wait().unwrap();
    assert!(status.code().is_some(), "terminó por sí mismo, no por una señal: {:?}", status);
    assert_ne!(status.code(), Some(101), "101 es el código de un pánico de Rust");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Windows: un build `--no-console` usado como CLI respeta un stdout redirigido a archivo (no lo
/// pisa con la consola), y un pánico de tubería no aparece.
#[cfg(windows)]
#[test]
fn no_console_build_respects_a_redirected_stdout_under_engine_mode() {
    let dir = project("nocon");
    std::fs::write(dir.join("app.syn"), "print(\"hi\")\n").unwrap();
    let synsema = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_synsema"))
            .args(args)
            .current_dir(&dir)
            .env("SYNSEMA_NO_UPDATE_CHECK", "1")
            .output()
            .unwrap()
    };
    let out = synsema(&["build", "app.syn", "-o", "app", "--no-console"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let exe = dir.join("app.exe");
    // cmd redirige la salida a un archivo: el handle es válido → se respeta, la versión va al archivo.
    // (`.\` explícito: bajo Git Bash `NoDefaultCurrentDirectoryInExePath=1` hace que cmd no busque en el cwd.)
    let st = Command::new("cmd")
        .args(["/c", ".\\app.exe --engine version > out.txt 2>&1"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .status()
        .unwrap();
    assert!(st.success());
    let txt = std::fs::read_to_string(dir.join("out.txt")).unwrap();
    assert!(txt.starts_with("Synsema "), "la versión va al archivo redirigido: {:?}", txt);
    // Capturado por una tubería que se cierra: silencio y 0, nunca "failed printing".
    let mut child = Command::new(&exe)
        .args(["--engine", "run", "app.syn"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("failed printing"), "{}", err);
    assert_eq!(out.status.code(), Some(0), "{}", err);
    let _ = std::fs::remove_dir_all(&dir);
}

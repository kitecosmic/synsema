//! v0.6.45 (A11, decisión V1-C6): `fetch(url, method, headers, body, timeout)` posicional queda
//! deprecada y sale en v1. `check` lo avisa cuando el segundo argumento es un literal que no es un
//! mapa; al correr, una sola línea a stderr por proceso. La forma con mapa no avisa nada.

use std::process::Command;

fn synsema(name: &str, src: &str, args: &[&str]) -> (i32, String) {
    let dir = std::env::temp_dir().join(format!("synsema-v0645-a11-{}-{}", std::process::id(), name));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.syn"), src).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(args)
        .arg("app.syn")
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .expect("spawn synsema");
    let _ = std::fs::remove_dir_all(&dir);
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// Dos `fetch` posicionales a un puerto cerrado (fallan, pero el aviso sale antes de conectar) y uno
/// con mapa.
const SRC: &str = r#"require net("127.0.0.1:9")
let opts be {"method": "GET"}
each i in range(2)
    try
        fetch("http://127.0.0.1:9/", "GET", nothing, nothing, 1)
    recover e
        print("falló")
try
    fetch("http://127.0.0.1:9/", {"method": "GET", "timeout": 1})
recover e
    print("falló")
try
    fetch("http://127.0.0.1:9/", opts)
recover e
    print("falló")
"#;

#[test]
fn check_warns_the_positional_form_only() {
    let (code, err) = synsema("check", SRC, &["check"]);
    assert_eq!(code, 0, "{}", err);
    let warns: Vec<&str> = err.lines().filter(|l| l.contains("deprecated")).collect();
    assert_eq!(warns.len(), 1, "sólo el posicional, no el mapa literal ni la variable: {:?}", warns);
    assert!(warns[0].contains("app.syn:5:"), "{:?}", warns);
}

#[test]
fn run_says_it_once_per_process() {
    let (_, err) = synsema("run", SRC, &["run"]);
    let n = err.lines().filter(|l| l.contains("[synsema] deprecated: fetch(")).count();
    assert_eq!(n, 1, "{}", err);
}

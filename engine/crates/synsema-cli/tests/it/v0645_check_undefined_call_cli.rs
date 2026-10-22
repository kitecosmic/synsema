//! v0.6.45 (A10): `synsema check` avisa una llamada a un nombre que no existe en ningún lado. El caso
//! real: el edge de túneles hacía `set streams to without(streams, k)` sin ninguna `task without`;
//! `check` daba OK y fallaba recién al cerrar el primer stream. Aviso a stderr: el exit code no cambia.

use std::process::Command;

fn check(name: &str, src: &str) -> (i32, String) {
    let dir = std::env::temp_dir().join(format!("synsema-v0645-a10-{}-{}", std::process::id(), name));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.syn"), src).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["check", "app.syn"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .expect("spawn synsema check");
    let _ = std::fs::remove_dir_all(&dir);
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn a_call_to_a_name_that_exists_nowhere_is_a_warning() {
    let (code, err) = check("missing", "let streams be {\"a\": 1}\nset streams to without(streams, \"a\")\nprint(streams)\n");
    assert_eq!(code, 0, "un aviso no cambia el exit code: {}", err);
    assert!(err.contains("app.syn:2: warning: `without(...)`"), "{}", err);
}

#[test]
fn a_python_reflex_gets_its_hint() {
    let (_, err) = check("reflex", "print(len([1, 2]))\n");
    assert!(err.contains("`len(...)`") && err.contains("length"), "{}", err);
}

#[test]
fn defined_names_builtins_and_request_names_are_not_warned() {
    let src = r#"require serve(18646)
type Pedido
    id: number
    total: number
enum Forma
    circulo(r)
task doble(x)
    give x * 2
agent Worker
    share 1 as "x"
let f be (x) => x + 1
let g be doble
print(doble(2))
print(f(1))
print(g(3))
print(Pedido(1, 2))
print(circulo(1))
each h in [doble]
    print(h(1))
try
    print(length([1]))
recover e
    print(e)
serve on 18646
    route "POST /x"
        give read_body()
"#;
    let (code, err) = check("clean", src);
    assert_eq!(code, 0, "{}", err);
    assert!(!err.contains("there is no task"), "falso positivo: {}", err);
}

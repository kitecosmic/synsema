//! v0.6.50 (A): un módulo de archivo resuelve sus nombres en lo suyo y en el preludio, nunca en el
//! programa que lo importa (`specs/v0.6.50-a-modelo.md`). Acá, lo que sólo ve un embebedor: lo que
//! el host puso antes de correr (filas 7 y 8) y un intérprete que no entra por `execute` (fila 21).
//! El resto de la tabla, contra el binario, en `synsema-cli/tests/it/v0650_cli.rs`.

use std::path::PathBuf;
use std::rc::Rc;
use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::parser::parse_source;
use synsema_core::types::{syn_int, syn_text};

fn dir(tag: &str, lib: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("synsema-v0650-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("lib.syn"), lib).unwrap();
    d
}

/// Filas 7 y 8: lo que el host registró antes de la primera sentencia es preludio, y el módulo lo ve;
/// lo que el programa define después, no.
#[test]
fn what_the_host_set_before_the_run_is_prelude() {
    let d = dir("host", "export task f()\n    give text(HOST) + doble(2)\nexport task g()\n    give PROG\n");
    let main = d.join("main.syn");
    let program = parse_source("use \"./lib.syn\" as lib\nlet PROG be 1\nprint(lib.f())\nprint(lib.g())\n", &main.to_string_lossy()).unwrap();
    let mut interp = Interpreter::new();
    interp.set_global("HOST", syn_int(7));
    interp.register_builtin("doble", 1, Rc::new(|_i, _a, _l| Ok(syn_text("22"))));
    let r = interp.execute(&program);
    assert_eq!(interp.output, vec!["722".to_string()]);
    let Err(Control::Error(e)) = r else { panic!("PROG no es del módulo") };
    let e = e.to_string();
    assert!(e.contains("Undefined variable: 'PROG'") && e.contains("is a name of the program that imports this module"), "{}", e);
}

/// Fila 21: sin `execute` (la REPL, un embebedor con `run_block`), el módulo ve los builtins y las
/// constantes, y no lo del programa.
#[test]
fn without_execute_the_module_sees_builtins_and_constants() {
    let d = dir("block", "export task f(x)\n    give upper(x) + text(round(pi))\nexport task g()\n    give PROG\n");
    let main = d.join("main.syn");
    let program = parse_source("let PROG be 1\nlet upper be 3\nuse \"./lib.syn\" as lib\nprint(lib.f(\"a\"))\nprint(lib.g())\n", &main.to_string_lossy()).unwrap();
    let mut interp = Interpreter::new();
    let r = interp.run_block(&program.statements);
    let msg = match &r {
        Err(Control::Error(e)) => e.to_string(),
        _ => String::new(),
    };
    assert_eq!(interp.output, vec!["A3".to_string()], "{}", msg);
    let Err(Control::Error(e)) = r else { panic!("PROG no es del módulo") };
    assert!(e.to_string().contains("Undefined variable: 'PROG'"), "{}", e);
}

/// Fila 18, del lado del embebedor: `run_test_blocks` toma la misma foto que `execute`.
#[test]
fn test_blocks_see_what_the_host_set_before_the_run() {
    let d = dir("tests", "export task f()\n    give HOST\n");
    let main = d.join("main.syn");
    let program = parse_source("use \"./lib.syn\" as lib\ntest \"host\"\n    assert_eq(lib.f(), 7)\n", &main.to_string_lossy()).unwrap();
    let mut interp = Interpreter::new();
    interp.set_global("HOST", syn_int(7));
    let out = interp.run_test_blocks(&program);
    assert!(out.len() == 1 && out[0].passed, "{:?}", out.iter().map(|o| o.message.clone()).collect::<Vec<_>>());
}

/// §3.6: sin foto (un `use` al que se llega sin `execute`, `run_test_blocks`, `run_block` ni
/// `rebuild_globals`), la base trae los builtins con su nombre y las constantes, no lo del programa.
#[test]
fn the_base_without_a_snapshot_has_the_builtins_and_the_constants() {
    let mut interp = Interpreter::new();
    interp.set_global("upper", syn_int(3));
    interp.set_global("PROG", syn_int(1));
    let base = interp.module_base();
    let get = |n: &str| synsema_core::interpreter::env_get(&base, n);
    assert!(get("pi").is_some() && get("inf").is_some() && get("length").is_some());
    assert!(matches!(get("upper"), None), "un builtin que el programa religó no es un builtin");
    assert!(get("PROG").is_none());
}

/// Ronda 1 (M1): un embebedor que llama `execute` dos veces: el módulo del segundo no ve lo que ligó
/// el primero (sin foto en el segundo, los builtins).
#[test]
fn a_second_execute_does_not_lend_the_first_one_names() {
    let d = dir("two", "export task cobrar(n)\n    give n * TASA\n");
    let main = d.join("main.syn").to_string_lossy().into_owned();
    let mut interp = Interpreter::new();
    assert!(interp.execute(&parse_source("let TASA be 2\n", &main).unwrap()).is_ok());
    let r = interp.execute(&parse_source("use \"./lib.syn\" as lib\nprint(lib.cobrar(10))\n", &main).unwrap());
    let Err(Control::Error(e)) = r else { panic!("TASA no es del módulo: {:?}", interp.output) };
    assert!(e.to_string().contains("Undefined variable: 'TASA'"), "{}", e);
}

/// Ronda 2 (N1): `run_block` después de un `execute` sigue la misma regla: el módulo no ve lo que ligó
/// el `execute`.
#[test]
fn run_block_after_execute_does_not_lend_the_names() {
    let d = dir("block", "export task g()\n    give PROG\n");
    let main = d.join("main.syn").to_string_lossy().into_owned();
    let mut interp = Interpreter::new();
    assert!(interp.execute(&parse_source("let PROG be 1\n", &main).unwrap()).is_ok());
    let block = parse_source("use \"./lib.syn\" as lib\nprint(lib.g())\n", &main).unwrap();
    let Err(Control::Error(e)) = interp.run_block(&block.statements) else { panic!("PROG no es del módulo: {:?}", interp.output) };
    assert!(e.to_string().contains("Undefined variable: 'PROG'"), "{}", e);
}

/// Ronda 2 (N3): `read_template_dir` da el nombre normalizado, como wasm (un archivo `a\b.html` en
/// Linux es `a/b.html`). En Windows un nombre no lleva `\`.
#[cfg(unix)]
#[test]
fn read_template_dir_normalizes_the_names() {
    let d = std::env::temp_dir().join(format!("synsema-v0650-tpldir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("sub")).unwrap();
    std::fs::write(d.join("a\\b.html"), "x").unwrap();
    std::fs::write(d.join("sub/c.html"), "y").unwrap();
    let names: Vec<String> = synsema_core::templates::read_template_dir(&d).unwrap().into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, vec!["a/b.html".to_string(), "sub/c.html".to_string()]);
    std::fs::create_dir_all(d.join("a")).unwrap();
    std::fs::write(d.join("a/b.html"), "z").unwrap();
    let e = synsema_core::templates::read_template_dir(&d).unwrap_err();
    assert!(e.contains("are the same template (a/b.html)"), "{}", e);
}

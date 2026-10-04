//! v0.6.42 — Tanda core: `eprint`, `exit(code)` y los avisos nuevos de `synsema check` (un nombre
//! local que tapa un alias de `use`, y `alias.x` que el módulo no exporta). Los comentarios al
//! principio de un bloque `socket`/`stream`/`reason` se prueban en los tests del parser.

use std::path::PathBuf;
use synsema_core::interpreter::{run_source, Control, Interpreter};
use synsema_core::parser::parse_source;

fn run_labels(source: &str) -> (Interpreter, Result<synsema_core::types::SynValue, Control>) {
    let program = parse_source(source, "<v0642>").unwrap_or_else(|e| panic!("parse: {}\n{}", e, source));
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    let r = interp.execute(&program);
    (interp, r)
}

// ---------------------------------------------------------------------------------
// eprint: stderr, fuera de la salida del programa
// ---------------------------------------------------------------------------------

#[test]
fn eprint_does_not_go_to_the_program_output() {
    let r = run_source("print(\"out\")\neprint(\"diag\", 1)\nprint(\"end\")\n", "<test>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["out".to_string(), "end".to_string()]);
}

#[test]
fn eprint_is_a_public_sink_under_labels() {
    // Bajo una rama privada la llamada misma es la fuga (cuántas líneas salen).
    let (_i, r) = run_labels("let s be private(true, \"a\")\nwhen s\n    eprint(\"x\")\n");
    let Err(Control::Error(e)) = r else { panic!("se esperaba label_violation") };
    assert!(e.to_string().contains("eprint under private control flow"), "{}", e);
    // Un valor privado con el PC público sale redactado, como en `print`.
    let (i, r) = run_labels("let s be private(\"clave\", \"a\")\neprint(s)\nprint(\"ok\")\n");
    assert!(r.is_ok(), "{:?}", r.err().map(|c| matches!(c, Control::Error(_))));
    assert_eq!(i.output, vec!["ok".to_string()]);
}

// ---------------------------------------------------------------------------------
// exit(code)
// ---------------------------------------------------------------------------------

fn exit_code_of(source: &str) -> Option<i32> {
    let program = parse_source(source, "<v0642>").unwrap_or_else(|e| panic!("parse: {}\n{}", e, source));
    let mut interp = Interpreter::new();
    match interp.execute(&program) {
        Err(Control::Error(e)) => e.exit_code,
        _ => None,
    }
}

#[test]
fn exit_ends_the_program_with_its_code() {
    assert_eq!(exit_code_of("print(1)\nexit(3)\nprint(2)\n"), Some(3));
    assert_eq!(exit_code_of("exit()\n"), Some(0));
    assert_eq!(exit_code_of("exit(255)\n"), Some(255));
    let r = run_source("print(1)\nexit(3)\nprint(2)\n", "<test>");
    assert_eq!(r.output, vec!["1".to_string()], "nada después de exit");
}

#[test]
fn exit_is_not_caught_by_try_assert_error_or_a_fallback() {
    let src = "try\n    exit(4)\nrecover e\n    print(\"caught\")\nprint(\"after\")\n";
    assert_eq!(exit_code_of(src), Some(4));
    let r = run_source(src, "<test>");
    assert!(r.output.is_empty(), "el recover no corre: {:?}", r.output);
    assert_eq!(exit_code_of("assert_error(() => exit(5))\nprint(\"after\")\n"), Some(5));
    assert_eq!(exit_code_of("task f()\n    exit(6)\nlet x be f()\nprint(x)\n"), Some(6));
}

#[test]
fn exit_rejects_a_code_outside_0_255_or_not_an_integer() {
    for (arg, needle) in [("256", "from 0 to 255"), ("-1", "from 0 to 255"), ("3.5", "from 0 to 255"), ("\"1\"", "got text")] {
        let r = run_source(&format!("exit({})\n", arg), "<test>");
        assert!(!r.success);
        assert!(r.errors.iter().any(|e| e.contains(needle)), "exit({}): {:?}", arg, r.errors);
        assert_eq!(exit_code_of(&format!("exit({})\n", arg)), None, "exit({}) no es un exit", arg);
    }
}

#[test]
fn exit_is_a_public_sink_under_labels() {
    // El código de salida son 8 bits públicos: ni bajo una rama privada ni con un código privado.
    let (_i, r) = run_labels("let s be private(true, \"a\")\nwhen s\n    exit(1)\n");
    let Err(Control::Error(e)) = r else { panic!("se esperaba label_violation") };
    assert!(e.exit_code.is_none() && e.to_string().contains("label_violation"), "{}", e);
    let (_i, r) = run_labels("let c be private(7, \"a\")\nexit(c)\n");
    let Err(Control::Error(e)) = r else { panic!("se esperaba label_violation") };
    assert!(e.exit_code.is_none() && e.to_string().contains("label_violation"), "{}", e);
}

// ---------------------------------------------------------------------------------
// check: nombres locales que tapan un alias, y `alias.x` no exportado
// ---------------------------------------------------------------------------------

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(tag: &str) -> Tree {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!("synsema-v0642-{}-{}-{}", std::process::id(), tag, nanos));
        std::fs::create_dir_all(&root).unwrap();
        Tree { root }
    }
    fn write(&self, rel: &str, content: &str) {
        let p = self.root.join(rel);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }
    fn path(&self, rel: &str) -> String {
        self.root.join(rel).to_string_lossy().replace('\\', "/")
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn check_warnings(t: &Tree, entry_rel: &str) -> Vec<String> {
    let entry = t.path(entry_rel);
    let src = std::fs::read_to_string(&entry).unwrap();
    let program = parse_source(&src, &entry).unwrap_or_else(|e| panic!("{}", e));
    let load = |resolved: &str, raw: &str| -> Result<synsema_core::ast::Program, String> {
        let s = std::fs::read_to_string(resolved).map_err(|_| format!("module not found: {}", raw))?;
        parse_source(&s, resolved).map_err(|e| e.to_string())
    };
    let ((_m, _t), warnings) = synsema_core::templates::check_program_static_with_warnings(&program, &entry, &load)
        .unwrap_or_else(|e| panic!("check falló: {}", e));
    warnings
}

#[test]
fn check_warns_when_a_local_name_shadows_a_use_alias() {
    let t = Tree::new("local");
    t.write("base.syn", "export task body_json(x)\n    give x\n");
    t.write(
        "main.syn",
        "use \"./base.syn\" as base\n\
         task f(base)\n    give base\n\
         task g()\n    let base be \"x\"\n    give base\n\
         each base in [1]\n    print(base)\n\
         let h be (base) => base\n\
         print(base.body_json(1))\n",
    );
    let w = check_warnings(&t, "main.syn");
    for kind in ["task parameter 'base'", "variable 'base'", "`each` variable 'base'", "lambda parameter 'base'"] {
        assert!(w.iter().any(|x| x.contains(kind) && x.contains("shadows the module alias")), "falta {}: {:?}", kind, w);
    }
    // Sombreado: el aviso de exports no juzga ese alias (no hay falso positivo encima).
    assert!(!w.iter().any(|x| x.contains("does not export")), "{:?}", w);
}

#[test]
fn check_warns_when_a_module_member_is_not_exported() {
    let t = Tree::new("exports");
    t.write(
        "signing.syn",
        "export task sign(x)\n    give x\ntask ensure_key(a)\n    give a\nexport let VERSION be 1\nexport enum Kind\n    a\n    b\n",
    );
    t.write(
        "main.syn",
        "use \"./signing.syn\" as signing\n\
         print(signing.sign(1))\nprint(signing.VERSION)\nprint(signing.Kind)\n\
         print(signing.ensure_key(1))\nprint(signing.ensure_key(2))\n",
    );
    let w = check_warnings(&t, "main.syn");
    let hits: Vec<&String> = w.iter().filter(|x| x.contains("does not export")).collect();
    assert_eq!(hits.len(), 1, "un aviso por nombre, no por uso: {:?}", w);
    assert!(hits[0].contains("`signing.ensure_key`"), "{}", hits[0]);
    assert!(hits[0].contains(":5:"), "la línea del primer uso: {}", hits[0]);
}

#[test]
fn check_does_not_judge_an_alias_hidden_by_a_top_level_let() {
    let t = Tree::new("toplet");
    t.write("util.syn", "export let ago be 1\n");
    t.write("main.syn", "use \"./util.syn\" as util\nlet util be {\"x\": 1}\nprint(util.x)\n");
    let w = check_warnings(&t, "main.syn");
    assert_eq!(w.len(), 1, "sólo el aviso (a) de siempre: {:?}", w);
}

#[test]
fn check_warns_on_a_wildcard_domain_without_tls_dns() {
    let t = Tree::new("wild");
    t.write(
        "a.syn",
        "serve on 443\n    tls auto \"a@b.c\"\n    domain [\"x.app\", \"*.x.app\"]\n    route \"GET /\"\n        give 1\n",
    );
    let w = check_warnings(&t, "a.syn");
    assert_eq!(w.iter().filter(|x| x.contains("is a wildcard")).count(), 1, "{:?}", w);
    t.write(
        "b.syn",
        "task publish(name, value, action)\n    give true\nserve on 443\n    tls auto \"a@b.c\"\n    domain [\"x.app\", \"*.x.app\"]\n    tls dns publish\n    route \"GET /\"\n        give 1\n",
    );
    let w = check_warnings(&t, "b.syn");
    assert!(!w.iter().any(|x| x.contains("is a wildcard")), "{:?}", w);
}

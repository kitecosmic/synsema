//! v0.6.20 — Tanda 1 (synsema-core): `reverse`, `split(t, "")` como caracteres, `steps()`,
//! `use "../"` acotado a la raíz del proyecto, y los avisos nuevos del check estático.
//! Programas `.syn` reales por el intérprete (`run_source`), como el resto de las suites.

use std::path::{Path, PathBuf};
use synsema_core::interpreter::run_source;

fn out(source: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

fn shows(expr: &str, expected: &str) {
    assert_eq!(out(&format!("print({})", expr)), vec![expected.to_string()], "expr: {}", expr);
}

fn fails_with(source: &str, needle: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(!r.success, "esperaba fallo.\nfuente:\n{}", source);
    assert!(
        r.errors.iter().any(|e| e.contains(needle)),
        "esperaba error con '{}', got {:?}",
        needle,
        r.errors
    );
    r.errors
}

/// Árbol temporal propio por test (sin dep nueva): `<tmp>/synsema-v0620-<pid>-<tag>/`.
struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(tag: &str) -> Tree {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!("synsema-v0620-{}-{}-{}", std::process::id(), tag, nanos));
        std::fs::create_dir_all(&root).unwrap();
        Tree { root }
    }
    fn write(&self, rel: &str, content: &str) -> PathBuf {
        let p = self.root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, content).unwrap();
        p
    }
    fn path(&self, rel: &str) -> String {
        self.root.join(rel).to_string_lossy().to_string()
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// ---------------------------------------------------------------------------------
// §3.1 reverse / split("")
// ---------------------------------------------------------------------------------

#[test]
fn reverse_list_and_text() {
    shows("reverse([1, 2, 3])", "[3, 2, 1]");
    shows("reverse([])", "[]");
    shows("reverse(\"abc\")", "cba");
    // Por scalar Unicode: la ñ es un scalar, se conserva entera.
    shows("reverse(\"añb\")", "bña");
    // Valor nuevo: el original no se toca.
    assert_eq!(out("let xs be [1, 2]\nlet ys be reverse(xs)\nprint(xs)\nprint(ys)"), vec!["[1, 2]", "[2, 1]"]);
    fails_with("print(reverse(42))", "reverse");
}

#[test]
fn split_with_empty_separator_yields_characters() {
    shows("split(\"abc\", \"\")", "[\"a\", \"b\", \"c\"]");
    shows("length(split(\"añb\", \"\"))", "3");
    shows("split(\"\", \"\")", "[]");
    // El separador no vacío no cambia.
    shows("split(\"a,b\", \",\")", "[\"a\", \"b\"]");
}

// ---------------------------------------------------------------------------------
// §3.5 steps()
// ---------------------------------------------------------------------------------

#[test]
fn steps_is_deterministic_and_counts_work() {
    let a = out("print(steps())");
    let b = out("print(steps())");
    assert_eq!(a, b, "el mismo programa da el mismo número de pasos");
    let n: i64 = a[0].parse().expect("steps() es un entero");
    assert!(n > 0);
    // Un bucle de 100 vueltas suma al menos 100 pasos entre dos lecturas.
    assert_eq!(
        out("let s1 be steps()\neach i in range(100)\n    let x be i\nlet s2 be steps()\nprint(s2 - s1 > 100)"),
        vec!["true"]
    );
}

// ---------------------------------------------------------------------------------
// §3.3 use "../" acotado a la raíz del proyecto
// ---------------------------------------------------------------------------------

#[test]
fn use_can_climb_inside_the_project_root() {
    let t = Tree::new("climb");
    t.write("src/b/two.syn", "export let v be 42\n");
    t.write("src/a/one.syn", "use \"../b/two.syn\" as two\nexport let v2 be two.v + 1\n");
    let main = "use \"./src/a/one.syn\" as one\nprint(one.v2)\n";
    let main_path = t.write("main.syn", main);
    let r = run_source(main, &main_path.to_string_lossy());
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["43"]);
}

#[test]
fn use_cannot_escape_the_project_root() {
    let t = Tree::new("escape");
    // Un módulo real fuera de la raíz: la contención es léxica, pero el archivo existe para
    // que el único motivo del fallo sea la raíz.
    t.write("proj/inner.syn", "export let v be 1\n");
    let outside = t.root.join("outside.syn");
    std::fs::write(&outside, "export let v be 7\n").unwrap();
    let main = "use \"../outside.syn\" as o\nprint(o.v)\n";
    let main_path = t.write("proj/main.syn", main);
    let r = run_source(main, &main_path.to_string_lossy());
    assert!(!r.success, "esperaba fallo, salida: {:?}", r.output);
    // Desde la ENTRADA, importador y raíz coinciden: el mensaje histórico se conserva (paridad
    // con el oráculo y con el corpus de conformidad `modules/022`).
    assert!(
        r.errors.iter().any(|e| e.contains("escapes the importing directory")),
        "esperaba 'escapes the importing directory', got {:?}",
        r.errors
    );
    // Y un módulo que sube desde una subcarpeta hasta fuera de la raíz también falla.
    t.write("proj/src/deep.syn", "use \"../../outside.syn\" as o\nexport let v be o.v\n");
    let main2 = "use \"./src/deep.syn\" as d\nprint(d.v)\n";
    let main2_path = t.write("proj/main2.syn", main2);
    let r = run_source(main2, &main2_path.to_string_lossy());
    assert!(!r.success);
    assert!(r.errors.iter().any(|e| e.contains("escapes the project root")), "{:?}", r.errors);
}

// ---------------------------------------------------------------------------------
// §3.4 avisos del check estático (no fallan el check)
// ---------------------------------------------------------------------------------

fn check_warnings(t: &Tree, entry_rel: &str) -> Vec<String> {
    let entry = t.path(entry_rel);
    let src = std::fs::read_to_string(&entry).unwrap();
    let program = synsema_core::parser::parse_source(&src, &entry).unwrap_or_else(|e| panic!("{}", e));
    let load = |resolved: &str, raw: &str| -> Result<synsema_core::ast::Program, String> {
        let s = std::fs::read_to_string(resolved).map_err(|_| format!("module not found: {}", raw))?;
        synsema_core::parser::parse_source(&s, resolved).map_err(|e| e.to_string())
    };
    let ((_modules, _templates), warnings) =
        synsema_core::templates::check_program_static_with_warnings(&program, &entry, &load)
            .unwrap_or_else(|e| panic!("check falló: {}", e));
    warnings
}

#[test]
fn check_warns_when_a_group_or_let_shadows_a_use_alias() {
    let t = Tree::new("shadow");
    t.write("util.syn", "export let ago be 1\n");
    t.write(
        "main.syn",
        "use \"./util.syn\" as util\nlet util be 2\nprint(util)\n",
    );
    let w = check_warnings(&t, "main.syn");
    assert_eq!(w.len(), 1, "{:?}", w);
    assert!(w[0].contains("let 'util' shadows the module alias"), "{}", w[0]);

    t.write(
        "mod.syn",
        "use \"./util.syn\" as util\nexport routes util\n    route \"GET /x\"\n        give 1\n",
    );
    t.write("main2.syn", "use \"./mod.syn\" as m\nprint(1)\n");
    let w = check_warnings(&t, "main2.syn");
    assert!(w.iter().any(|x| x.contains("routes group 'util' shadows the module alias")), "{:?}", w);
}

#[test]
fn check_warns_when_a_one_segment_param_route_covers_reserved_urls() {
    let t = Tree::new("reserved");
    t.write(
        "main.syn",
        "require serve(8080)\n\nserve on 8080\n    route \"GET /:lang\"\n        give lang\n",
    );
    let w = check_warnings(&t, "main.syn");
    assert_eq!(w.len(), 1, "{:?}", w);
    assert!(w[0].contains("would capture /openapi.json, /docs, /llms.txt, /sitemap.xml, /robots.txt"), "{}", w[0]);

    // Una ruta literal declarada para una de ellas sale de la lista; un `/a/:b` no avisa.
    t.write(
        "main2.syn",
        "require serve(8080)\n\nserve on 8080\n    route \"GET /openapi.json\"\n        give 1\n    route \"GET /:lang\"\n        give lang\n    route \"GET /a/:b\"\n        give b\n",
    );
    let w = check_warnings(&t, "main2.syn");
    assert_eq!(w.len(), 1, "{:?}", w);
    assert!(!w[0].contains("/openapi.json,"), "{}", w[0]);
    assert!(w[0].contains("/docs, /llms.txt, /sitemap.xml, /robots.txt"), "{}", w[0]);
}

#[test]
fn check_does_not_reject_stream_routes_inside_a_group_anymore() {
    let t = Tree::new("stream-group");
    t.write(
        "live.syn",
        "export routes live\n    route \"GET /events\"\n        stream\n            send \"tick\"\n",
    );
    t.write(
        "main.syn",
        "require serve(8080)\nuse \"./live.syn\" as live\n\nserve on 8080\n    mount live.live\n",
    );
    let entry = t.path("main.syn");
    let src = std::fs::read_to_string(&entry).unwrap();
    let program = synsema_core::parser::parse_source(&src, &entry).unwrap_or_else(|e| panic!("{}", e));
    let r = synsema_core::templates::check_program_static(&program, &entry);
    assert!(r.is_ok(), "{:?}", r);
    let _ = Path::new(&entry);
}

// ---------------------------------------------------------------------------------
// §3.6 `private` por ruta y por grupo: parsea y viaja en la meta del grupo
// ---------------------------------------------------------------------------------

#[test]
fn private_clause_parses_in_a_route_and_in_a_group() {
    // En una ruta directa del serve: parsea (la publicación la decide serve en la Tanda 3).
    let src = "require serve(8080)\n\nserve on 8080\n    route \"GET /secret\"\n        private\n        give 1\n";
    let p = synsema_core::parser::parse_source(src, "<test>");
    assert!(p.is_ok(), "{:?}", p.err());
    // Dos veces es error claro.
    let twice = "require serve(8080)\n\nserve on 8080\n    route \"GET /secret\"\n        private\n        private\n        give 1\n";
    let e = synsema_core::parser::parse_source(twice, "<test>").err().map(|e| e.to_string()).unwrap_or_default();
    assert!(e.contains("'private' at most once"), "{}", e);
    // `private` como nombre PARSEA como un nombre (la cláusula es SOLO la línea `private`),
    // Pero desde T5 es un builtin protegido: ligarlo es error de CARGA , con
    // etiquetas apagadas también.
    // Ronda 3: la regla de nombres protegidos aplica SOLO a valores invocables, asi que
    // `private` vuelve a ser una palabra clave blanda ligable a un valor comun.
    assert_eq!(out("let private be 3\nprint(private + 1)"), vec!["4"]);
}

#[test]
fn private_in_a_group_reaches_the_routes_meta() {
    // El grupo se ejecuta a un map con `_routes_meta`; `private` viaja ahí (por ruta y por grupo).
    let src = "export routes g\n    route \"GET /a\"\n        private\n        give 1\n    route \"GET /b\"\n        give 2\n\nlet metas be g._routes_meta\nprint(metas[0].private)\nprint(metas[1].private)\nprint(metas[0].streaming)\n";
    assert_eq!(out(src), vec!["true", "false", "false"]);
    let grp = "export routes g\n    private\n    route \"GET /a\"\n        give 1\n    route \"GET /b\"\n        give 2\n\nprint(g._routes_meta[0].private)\nprint(g._routes_meta[1].private)\n";
    assert_eq!(out(grp), vec!["true", "true"]);
}

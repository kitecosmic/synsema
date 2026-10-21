//! El resolver (F3.0 de specs/compute-rendimiento.md): dónde vive cada variable. Estos casos fijan
//! las reglas difíciles una por una; el oráculo del resolver (`oracle_run --resolver-check`, en
//! synsema-runtime) las contrasta además con lo que hace el tree-walker en todo el corpus.

use synsema_core::parser::parse_source;
use synsema_core::resolve::{resolve_program, AccessKind, Resolution, ScopeKind, Target};

fn resolve(src: &str) -> Resolution {
    let p = parse_source(src, "<resolver>").expect("parsea");
    resolve_program(&p)
}

/// El acceso a `name` de ese tipo en esa línea (1 = la primera).
fn at(r: &Resolution, line: usize, name: &str, kind: AccessKind) -> Target {
    let found: Vec<_> = r.accesses.iter().filter(|a| a.line == line && &*a.name == name && a.kind == kind).collect();
    assert!(!found.is_empty(), "no hay {:?} de '{}' en la línea {}", kind, name, line);
    found[0].target
}

fn read(r: &Resolution, line: usize, name: &str) -> Target {
    at(r, line, name, AccessKind::Read)
}

fn slot(depth: u16, slot: u16, definite: bool) -> impl Fn(Target) -> bool {
    move |t| matches!(t, Target::Slot { depth: d, slot: s, definite: f, .. } if d == depth && s == slot && f == definite)
}

fn scope_named<'a>(r: &'a Resolution, kind: ScopeKind, first: &str) -> &'a synsema_core::resolve::Scope {
    r.scopes
        .iter()
        .find(|s| s.kind == kind && s.names.first().is_some_and(|n| &**n == first))
        .unwrap_or_else(|| panic!("no hay un scope {:?} que empiece con '{}'", kind, first))
}

#[test]
fn params_then_locals_in_order() {
    let r = resolve("task f(a, b)\n    let c be a + b\n    give c\n");
    assert!(slot(0, 0, true)(read(&r, 2, "a")));
    assert!(slot(0, 1, true)(read(&r, 2, "b")));
    assert!(slot(0, 2, true)(read(&r, 3, "c")));
    let s = scope_named(&r, ScopeKind::Call, "a");
    let names: Vec<&str> = s.names.iter().map(|n| &**n).collect();
    assert_eq!(names, ["a", "b", "c"]);
    assert!(!s.escapes && !s.opaque && !s.dynamic);
}

#[test]
fn repeated_param_takes_one_slot() {
    let r = resolve("task f(a, a)\n    let b be 1\n    give b\n");
    // Si los dos `a` contaran como dos parámetros, `b` quedaría "ligado seguro" desde la entrada.
    assert!(slot(0, 1, true)(read(&r, 3, "b")));
    let r = resolve("task f(a, a)\n    when a\n        let b be 1\n    give b\n");
    assert!(slot(0, 1, false)(read(&r, 4, "b")));
}

#[test]
fn let_inside_when_is_not_sure() {
    // `when` no abre scope: el `let` liga en el frame de la llamada sólo si la rama corre.
    let r = resolve("let x be 1\ntask f(c)\n    when c\n        let x be 2\n    give x\n");
    assert!(slot(0, 1, false)(read(&r, 5, "x")));
    // En las dos ramas: seguro.
    let r = resolve("task f(c)\n    when c\n        let y be 1\n    otherwise\n        let y be 2\n    give y\n");
    assert!(slot(0, 1, true)(read(&r, 6, "y")));
}

#[test]
fn read_before_a_later_let_is_not_sure() {
    let r = resolve("let z be 0\ntask f()\n    print(z)\n    let z be 1\n    give z\n");
    assert!(slot(0, 0, false)(read(&r, 3, "z")));
    assert!(slot(0, 0, true)(read(&r, 5, "z")));
    // `print` es del global: por nombre.
    assert_eq!(read(&r, 3, "print"), Target::Free);
}

#[test]
fn loop_bodies_bind_nothing_sure_after_the_loop() {
    let r = resolve("task f(n)\n    while n > 0\n        let last be n\n        set n to n - 1\n    give last\n");
    assert!(slot(0, 1, false)(read(&r, 5, "last")));
    assert!(slot(0, 0, true)(at(&r, 4, "n", AccessKind::Write)));
    assert_eq!(r.loops.len(), 1);
}

#[test]
fn each_opens_a_frame() {
    let src = "task f(xs)\n    let total be 0\n    each x in xs\n        set total to total + x\n    give total\n";
    let r = resolve(src);
    assert!(slot(0, 0, true)(read(&r, 4, "x")));
    assert!(slot(1, 1, true)(read(&r, 4, "total")));
    assert!(slot(1, 1, true)(at(&r, 4, "total", AccessKind::Write)));
    assert!(slot(0, 0, true)(at(&r, 3, "x", AccessKind::Bind)));
    assert!(slot(0, 0, true)(read(&r, 3, "xs")));
    let e = scope_named(&r, ScopeKind::Each, "x");
    assert_eq!(e.kind.frame_name(), "each");
    assert!(r.loops[0].is_each);
}

#[test]
fn globals_and_top_level_are_free() {
    let r = resolve("let total be 0\nlet i be 0\nwhile i < 10\n    set total to total + i\n    set i to i + 1\n");
    assert_eq!(read(&r, 3, "i"), Target::Free);
    assert_eq!(at(&r, 4, "total", AccessKind::Write), Target::Free);
    let r = resolve("task fib(n)\n    when n < 2\n        give n\n    give fib(n - 1) + fib(n - 2)\n");
    assert_eq!(read(&r, 4, "fib"), Target::Free);
    assert!(slot(0, 0, true)(read(&r, 4, "n")));
}

#[test]
fn nested_task_captures_what_it_uses() {
    let src = "task outer(n)\n    let k be 10\n    let unused be 0\n    task inner(m)\n        give m + k + n\n    give inner(1)\n";
    let r = resolve(src);
    assert!(slot(0, 0, true)(read(&r, 5, "m")));
    assert!(slot(1, 1, true)(read(&r, 5, "k")));
    assert!(slot(1, 0, true)(read(&r, 5, "n")));
    assert!(slot(0, 3, true)(read(&r, 6, "inner")));
    let o = scope_named(&r, ScopeKind::Call, "n");
    assert!(o.escapes, "la closure retiene el frame de afuera");
    assert!(!o.opaque, "definir una task no hace buscar por nombre");
    let captured: Vec<&str> = o.names.iter().zip(&o.captured).filter(|(_, c)| **c).map(|(n, _)| &**n).collect();
    assert_eq!(captured, ["n", "k"]);
    let i = scope_named(&r, ScopeKind::Call, "m");
    assert!(!i.escapes);
}

#[test]
fn recursion_inside_a_task_sees_its_own_name() {
    let src = "task outer()\n    task go(n)\n        when n == 0\n            give 0\n        give go(n - 1)\n    give go(3)\n";
    let r = resolve(src);
    // `go` se liga en `outer` al definirse, antes de que nadie pueda llamarla: seguro.
    assert!(slot(1, 0, true)(read(&r, 5, "go")));
}

#[test]
fn defaults_resolve_where_the_task_is_defined() {
    let src = "task outer()\n    let base be 5\n    task inner(x = base)\n        give x\n    give inner()\n";
    let r = resolve(src);
    assert!(slot(0, 0, true)(read(&r, 3, "base")));
    // Un default corre en el tree-walker en cada llamada: el frame que lo define es opaco.
    assert!(scope_named(&r, ScopeKind::Call, "base").opaque);
}

#[test]
fn lambdas_are_call_frames() {
    let src = "task f(k)\n    let g be (x) => x + k\n    give g(1)\n";
    let r = resolve(src);
    assert!(slot(0, 0, true)(read(&r, 2, "x")));
    assert!(slot(1, 0, true)(read(&r, 2, "k")));
    let f = scope_named(&r, ScopeKind::Call, "k");
    assert!(f.escapes && !f.opaque);
    assert!(f.captured[0]);
}

#[test]
fn match_arms_bind_in_their_own_frame() {
    let src = "task f(v)\n    match v\n        is [a, b]\n            give a + b\n        is Shape.circle(r)\n            give r\n        is v\n            give 0\n";
    let r = resolve(src);
    assert!(slot(0, 0, true)(read(&r, 4, "a")));
    assert!(slot(0, 1, true)(read(&r, 4, "b")));
    // Una variante puede resultar ser una comparación por valor que no liga nada.
    assert!(slot(0, 0, false)(read(&r, 6, "r")));
    // A nivel top, un identificador compara con la variable de afuera: no liga.
    assert!(slot(0, 0, true)(read(&r, 7, "v")));
    // El objeto de la variante se evalúa afuera del brazo.
    assert_eq!(read(&r, 5, "Shape"), Target::Free);
}

#[test]
fn try_and_recover() {
    let src = "task f()\n    try\n        let t be 1\n    recover e\n        give e\n    give t\n";
    let r = resolve(src);
    assert!(slot(0, 0, true)(read(&r, 5, "e")));
    // Un error pudo cortar el `try` antes del `let`.
    assert!(slot(0, 0, false)(read(&r, 6, "t")));
    assert_eq!(scope_named(&r, ScopeKind::Recover, "e").kind.frame_name(), "recover");
    assert!(scope_named(&r, ScopeKind::Call, "t").opaque, "try/recover corre en el tree-walker");
}

#[test]
fn cold_statements_make_the_frame_opaque() {
    let r = resolve("task f(p)\n    show p\n    give p\n");
    let s = scope_named(&r, ScopeKind::Call, "p");
    assert!(s.escapes && s.opaque);
    let r = resolve("task f(p)\n    give p + 1\n");
    let s = scope_named(&r, ScopeKind::Call, "p");
    assert!(!s.escapes && !s.opaque);
}

#[test]
fn a_dynamic_frame_stops_resolution() {
    // `spawn` le pasa el frame a un hook: nada se resuelve a través de él.
    let src = "task f(p)\n    spawn Worker with x = p\n    give p\n";
    let r = resolve(src);
    assert_eq!(read(&r, 3, "p"), Target::Free);
    assert!(scope_named(&r, ScopeKind::Call, "p").dynamic);
}

#[test]
fn require_at_the_top_of_a_task_resolves_outside() {
    let src = "task outer(dir)\n    task inner()\n        require net(dir)\n        give 1\n    give inner()\n";
    let r = resolve(src);
    assert!(slot(0, 0, true)(read(&r, 3, "dir")));
}

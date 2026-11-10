//! v0.6.58 (§3, §8; filas P de `specs/v0.6.58-diseno.md`): el proyecto de un programa. La raíz es la
//! carpeta del `synsema.json` más cercano hacia arriba; su mínimo y sus claves se revisan antes de la
//! primera sentencia.
//!
//! El chequeo real del dueño vive en la stdlib (`project_owner.rs`, con su test). Acá el binario
//! registra uno de prueba: un `synsema.json` de exactamente [`FOREIGN_LEN`] bytes es «de otro usuario».

use std::path::PathBuf;
use synsema_core::interpreter::run_source;
use synsema_core::project::{self, DEV_VERSION};

const FOREIGN_LEN: u64 = 4099;

fn test_owner(f: &std::fs::File) -> Result<bool, String> {
    Ok(f.metadata().map_err(|e| e.to_string())?.len() != FOREIGN_LEN)
}

fn hook() {
    project::set_owner_check(test_owner);
}

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(tag: &str) -> Tree {
        hook();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!("synsema-v0658-{}-{}-{}", std::process::id(), tag, nanos));
        std::fs::create_dir_all(&root).unwrap();
        Tree { root }
    }
    fn write(&self, rel: &str, content: &str) -> String {
        let p = self.root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().to_string()
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn ok(src: &str, entry: &str) -> Vec<String> {
    let r = run_source(src, entry);
    assert!(r.success, "esperaba éxito: {:?}", r.errors);
    r.output
}

fn fails(src: &str, entry: &str, needle: &str) {
    let r = run_source(src, entry);
    assert!(!r.success, "esperaba fallo, salida: {:?}", r.output);
    assert!(r.errors.iter().any(|e| e.contains(needle)), "esperaba '{}', got {:?}", needle, r.errors);
    assert!(r.output.is_empty(), "nada corre antes del error: {:?}", r.output);
}

/// P2: `synsema.json` en el padre; la entrada en `scripts/` sube a `lib/` porque la raíz es el padre.
#[test]
fn p2_the_root_is_the_folder_of_the_nearest_synsema_json() {
    let t = Tree::new("p2");
    t.write("synsema.json", "{}");
    t.write("lib/y.syn", "export let v be 7\n");
    let src = "use \"../lib/y.syn\" as y\nprint(y.v)\n";
    let entry = t.write("scripts/x.syn", src);
    assert_eq!(ok(src, &entry), vec!["7"]);
    // Sin el `synsema.json`, la raíz vuelve a ser la carpeta de la entrada, como antes (P1).
    std::fs::remove_file(t.root.join("synsema.json")).unwrap();
    fails(src, &entry, "escapes the importing directory");
}

/// P3 y P6: un mínimo que este motor no cumple, antes de parsear las claves y antes de correr nada.
#[test]
fn p3_p6_a_newer_minimum_stops_before_the_first_statement() {
    let t = Tree::new("p3");
    t.write("synsema.json", "{\"synsema\": \"99.1.2\", \"module\": {}}");
    let src = "print(\"no\")\n";
    let entry = t.write("x.syn", src);
    fails(src, &entry, &format!("this project needs synsema >= 99.1.2; this is {}: synsema update", DEV_VERSION));
}

/// P4: el mínimo igual a este motor (un build `-dev` cuenta como su versión).
#[test]
fn p4_the_same_version_runs() {
    let t = Tree::new("p4");
    t.write("synsema.json", &format!("{{\"synsema\": \"{}\"}}", DEV_VERSION));
    let src = "print(\"sí\")\n";
    let entry = t.write("x.syn", src);
    assert_eq!(ok(src, &entry), vec!["sí"]);
}

/// P5: el mínimo es `X.Y.Z`, sin `v`, sin operadores y con tres números.
#[test]
fn p5_the_minimum_is_three_numbers() {
    for bad in ["v0.6.58", ">=0.6.58", "0.6"] {
        let t = Tree::new("p5");
        t.write("synsema.json", &format!("{{\"synsema\": \"{}\"}}", bad));
        let src = "print(1)\n";
        let entry = t.write("x.syn", src);
        fails(
            src,
            &entry,
            &format!("synsema.json: \"synsema\" is a minimum version like \"0.6.58\" (three numbers), not \"{}\"", bad),
        );
    }
}

/// P7 y P8: una clave desconocida y un JSON roto, con la línea y la columna.
#[test]
fn p7_p8_unknown_key_and_broken_json() {
    let t = Tree::new("p7");
    t.write("synsema.json", "{\"module\": {}}");
    let src = "print(1)\n";
    let entry = t.write("x.syn", src);
    fails(
        src,
        &entry,
        "synsema.json: unknown key \"module\" (known: \"synsema\", \"modules\", \"indirect\"; a package also has \"id\", \"version\", \"main\", \"files\")",
    );
    t.write("synsema.json", "{\n  \"modules\": {,}\n}");
    fails(src, &entry, "synsema.json:2:");
}

/// P9: un `synsema.json` de otro usuario se ignora (con aviso) y la raíz vuelve a ser la carpeta de
/// la entrada: su mínimo imposible no corta nada.
#[test]
fn p9_a_synsema_json_of_another_user_is_ignored() {
    let t = Tree::new("p9");
    let body = "{\"synsema\": \"99.0.0\"}";
    let pad = " ".repeat(FOREIGN_LEN as usize - body.len());
    t.write("synsema.json", &format!("{}{}", body, pad));
    let src = "print(\"corre\")\n";
    let entry = t.write("x.syn", src);
    assert_eq!(ok(src, &entry), vec!["corre"]);
    let p = project::resolve(&entry).unwrap();
    assert!(p.manifest.is_none());
    assert_eq!(p.warnings.len(), 1, "{:?}", p.warnings);
    assert!(
        p.warnings[0].starts_with("ignoring synsema.json in ")
            && p.warnings[0].ends_with(" if it is yours)")
            && p.warnings[0].contains(": it belongs to another user (set SYNSEMA_SAFE_PROJECT="),
        "{}",
        p.warnings[0]
    );
}

/// B11 (ronda 1): un `synsema.json` más arriba que no se puede abrir se ignora con aviso (P9), no corta
/// el programa de abajo.
#[test]
fn b11_an_unreadable_synsema_json_is_ignored_with_a_warning() {
    let t = Tree::new("b11");
    let sj = t.write("synsema.json", "{\"synsema\": \"99.0.0\"}");
    let src = "print(\"corre\")\n";
    let entry = t.write("sub/x.syn", src);
    #[cfg(windows)]
    let locked = std::process::Command::new("icacls").arg(&sj).args(["/deny", "*S-1-1-0:(R)"]).output().is_ok_and(|o| o.status.success());
    #[cfg(unix)]
    let locked = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sj, std::fs::Permissions::from_mode(0o000)).is_ok() && std::fs::File::open(&sj).is_err()
    };
    if !locked {
        eprintln!("b11: no se pudo quitar el permiso de lectura (¿root?): se saltea");
        return;
    }
    let p = project::resolve(&entry);
    let out = run_source(src, &entry);
    #[cfg(windows)]
    let _ = std::process::Command::new("icacls").arg(&sj).args(["/remove:d", "*S-1-1-0"]).output();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sj, std::fs::Permissions::from_mode(0o644));
    }
    let p = p.unwrap();
    assert!(p.manifest.is_none());
    assert_eq!(p.warnings.len(), 1, "{:?}", p.warnings);
    assert!(p.warnings[0].starts_with("ignoring synsema.json in ") && p.warnings[0].contains(": it cannot be opened ("), "{}", p.warnings[0]);
    assert!(out.success && out.output == vec!["corre"], "{:?} {:?}", out.output, out.errors);
}

/// P10: un programa sin archivo no tiene proyecto.
#[test]
fn p10_a_program_without_a_file_has_no_project() {
    hook();
    let p = project::resolve("<stdin>").unwrap();
    assert_eq!(p, project::Project::default());
    assert_eq!(ok("print(2)\n", "<stdin>"), vec!["2"]);
}

/// La búsqueda no sigue después del primer `synsema.json`: el más cercano gana aunque el de arriba
/// tenga un mínimo imposible.
#[test]
fn the_nearest_synsema_json_wins() {
    let t = Tree::new("near");
    t.write("synsema.json", "{\"synsema\": \"99.0.0\"}");
    t.write("app/synsema.json", "{}");
    let src = "print(3)\n";
    let entry = t.write("app/src/x.syn", src);
    assert_eq!(ok(src, &entry), vec!["3"]);
    let p = project::resolve(&entry).unwrap();
    assert_eq!(p.root.as_deref(), Some(t.root.join("app").as_path()));
}

/// §5.2: el recorrido de la tabla parsea cada módulo una vez y el cargador usa ese AST (antes se
/// parseaba dos veces: +71 % al cargar 50 módulos). Con otros bytes bajo el mismo nombre, la tabla no
/// da un AST viejo: el cargador vuelve a parsear.
#[test]
fn the_loader_reuses_the_ast_of_the_table() {
    use synsema_core::interpreter::{module_reparses, Interpreter};
    use synsema_core::parser::parse_source;
    let t = Tree::new("ast");
    t.write("synsema.json", "{}");
    let lib = "export task f()\n    give 41\n";
    let lib_path = t.write("lib/a.syn", lib);
    t.write("lib/b.syn", "use \"./a.syn\" as a\nexport task g()\n    give a.f() + 1\n");
    let src = "use \"./lib/b.syn\" as b\nprint(b.g())\n";
    let entry = t.write("main.syn", src);
    let program = parse_source(src, &entry).unwrap();
    let before = module_reparses();
    let mut interp = Interpreter::new();
    interp.execute(&program).unwrap_or_else(|_| panic!("corre"));
    assert_eq!(interp.output, vec!["42".to_string()]);
    assert_eq!(module_reparses() - before, 0, "el cargador volvió a parsear un módulo de la tabla");

    let proj = project::resolve(&entry).unwrap();
    let table = synsema_core::modtable::build(&proj, &entry, synsema_core::loaded_modules::use_paths(&program)).unwrap();
    let key = table.parsed.keys().find(|k| k.replace('\\', "/").ends_with("lib/a.syn")).cloned().unwrap_or_else(|| panic!("{:?} {}", table.parsed.keys().collect::<Vec<_>>(), lib_path));
    assert!(table.parsed_for(&key, lib).is_some());
    assert!(table.parsed_for(&key, "export task f()\n    give 0\n").is_none(), "otros bytes, otro AST");
}

/// B14 (ronda 1): el proyecto se resuelve una vez por programa: lo que corre después del chequeo previo
/// ve el mismo `synsema.json` que se revisó (no lo vuelve a buscar). `check` (para un proceso que vive)
/// mira el disco cada vez.
#[test]
fn b14_the_run_uses_the_project_the_preflight_resolved() {
    let t = Tree::new("b14");
    t.write("synsema.json", "{\"synsema\": \"0.0.1\"}");
    let src = "print(\"corre\")\n";
    let entry = t.write("x.syn", src);
    let p = project::preflight(&entry).unwrap();
    assert!(p.manifest.is_some());
    t.write("synsema.json", "{\"synsema\": \"99.0.0\"}");
    assert_eq!(ok(src, &entry), vec!["corre"]);
    assert!(project::resolve(&entry).unwrap().manifest.is_some());
    let e = project::check(&entry).unwrap_err();
    assert!(e.contains("this project needs synsema >= 99.0.0"), "{}", e);
}

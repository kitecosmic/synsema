//! Conformidad de las primitivas de I/O (spec IO-P1): navegación + lectura por rango
//! + fix de seguridad del scope de ruta (`covers()` normaliza, cierra el bypass `..`).
//! También IO-P2: `grep` (búsqueda streaming), `edit_file` (edición quirúrgica),
//! `append_file` (agregar al final). Y IO-P3: `run` (ejecutar procesos del SO, cap `exec`).
//! Los tests de ejecución real de `run` están cfg-gateados por SO (acá corren los de
//! Windows; los de unix son para CI). El deny-by-default es portable.
//!
//! Corre en modo `secure` (sin auto-grants): cada sonda lleva su `require file...`.
//! Patrón calcado de `engine_security.rs` / `engine_db.rs` (temp_dir + pid; sin
//! `tempfile`). Las rutas se pasan con `/` (normalize_path unifica separadores igual,
//! pero `/` evita escapes en los literales de string Synsema).

use std::path::{Path, PathBuf};

use synsema_runtime::engine::run_source_secure as run;

/// Crea un directorio temporal único por test (mismo pid en el binario de tests → el
/// `tag` lo desambigua entre tests que corren en paralelo). Limpio antes de crear.
fn tdir(tag: &str) -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!("syn_io_{}_{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Ruta como string apto para un literal Synsema (separadores `/`).
fn syn(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

// =========================================================
// Capability: deny-by-default (sin require → violación, string exacto)
// =========================================================

#[test]
fn io_builtins_deny_by_default() {
    // Las 4 primitivas exigen file.read; sin grant violan con el string exacto
    // (la ruta "X" normaliza a "X").
    let cases = [
        "list_dir(\"X\")",
        "file_info(\"X\")",
        "file_exists(\"X\")",
        "read_file(\"X\", 1, 5)",
    ];
    for call in cases {
        let r = run(call, "<t>");
        assert_eq!(
            r.errors,
            vec!["Runtime error: Capability not granted: file_read(\"X\")".to_string()],
            "call: {}",
            call
        );
    }
}

// =========================================================
// Fix #5: el scope de ruta es FIEL (el bypass `..` queda cerrado)
// =========================================================

#[test]
fn fix5_scope_is_faithful_no_traversal_bypass() {
    let d = tdir("fix5");
    std::fs::write(d.join("secret.txt"), "SECRET").unwrap();
    let sb = d.join("sandbox");
    std::fs::create_dir_all(&sb).unwrap();
    std::fs::write(sb.join("ok.txt"), "OK").unwrap();
    let base = syn(&d);

    // Dentro del scope → OK. (Uso `require file(scope)`: File cubre FileRead y pasa por
    // la misma rama `is_file` normalizada de covers(); la forma `file.read(...)` no es
    // sintaxis válida — el lexer corta el identificador en el `.`.)
    let r = run(
        &format!("require file(\"{base}/sandbox/*\")\nprint(read_file(\"{base}/sandbox/ok.txt\"))"),
        "<t>",
    );
    assert!(r.success, "dentro del scope debe leer: {:?}", r.errors);
    assert_eq!(r.output, vec!["OK".to_string()]);

    // Escape con `..` → VIOLATION (normaliza a <base>/secret.txt, fuera del scope).
    let r = run(
        &format!(
            "require file(\"{base}/sandbox/*\")\nlet c be read_file(\"{base}/sandbox/../secret.txt\")"
        ),
        "<t>",
    );
    assert!(!r.success, "el bypass `..` debe violar el scope");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted")),
        "debe ser violación de capability, got {:?}",
        r.errors
    );

    // Poder total intacto: wildcard cubre cualquier ruta, incluso vía `..`.
    let r = run(
        &format!("require file(\"*\")\nprint(read_file(\"{base}/sandbox/../secret.txt\"))"),
        "<t>",
    );
    assert!(r.success, "wildcard debe cubrir todo: {:?}", r.errors);
    assert_eq!(r.output, vec!["SECRET".to_string()]);

    let _ = std::fs::remove_dir_all(&d);
}

// =========================================================
// list_dir: enumera ordenado, metadata correcta, errores
// =========================================================

#[test]
fn list_dir_enumerates_sorted_with_metadata() {
    let d = tdir("listdir");
    std::fs::write(d.join("b.txt"), "bb").unwrap();
    std::fs::write(d.join("a.txt"), "hello").unwrap(); // 5 bytes
    std::fs::create_dir_all(d.join("d")).unwrap();
    let base = syn(&d);

    let src = format!(
        "require file\n\
         let e be list_dir(\"{base}\")\n\
         print(text(length(e)))\n\
         let a be e[0]\n\
         let bb be e[1]\n\
         let dd be e[2]\n\
         print(a[\"name\"])\n\
         print(text(a[\"is_dir\"]))\n\
         print(text(a[\"size\"]))\n\
         print(bb[\"name\"])\n\
         print(dd[\"name\"])\n\
         print(text(dd[\"is_dir\"]))\n\
         print(text(dd[\"size\"]))\n"
    );
    let r = run(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec![
            "3".to_string(),     // length
            "a.txt".to_string(), // ordenado: a.txt, b.txt, d
            "false".to_string(), // a.txt no es dir
            "5".to_string(),     // size de a.txt ("hello")
            "b.txt".to_string(),
            "d".to_string(),
            "true".to_string(), // d es dir
            "0".to_string(),    // dir → size 0
        ]
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn list_dir_errors_on_file_or_missing() {
    let d = tdir("listdir_err");
    let f = d.join("file.txt");
    std::fs::write(&f, "x").unwrap();
    let fpath = syn(&f);
    let missing = format!("{}/nope", syn(&d));

    let r = run(&format!("require file\nlet x be list_dir(\"{fpath}\")"), "<t>");
    assert!(!r.success, "list_dir sobre un archivo debe fallar");
    assert!(
        r.errors.iter().any(|e| e.contains("Not a directory")),
        "got {:?}",
        r.errors
    );

    let r = run(&format!("require file\nlet x be list_dir(\"{missing}\")"), "<t>");
    assert!(!r.success, "list_dir sobre ruta inexistente debe fallar");
    assert!(
        r.errors.iter().any(|e| e.contains("Not a directory")),
        "got {:?}",
        r.errors
    );

    let _ = std::fs::remove_dir_all(&d);
}

// =========================================================
// file_info / file_exists
// =========================================================

#[test]
fn file_info_and_exists() {
    let d = tdir("fileinfo");
    let f = d.join("data.txt");
    std::fs::write(&f, "hello").unwrap(); // 5 bytes
    let fpath = syn(&f);
    let missing = format!("{}/nope.txt", syn(&d));

    // Existente: exists/is_dir/size correctos, modified entero (type_of "number").
    let src = format!(
        "require file\n\
         let i be file_info(\"{fpath}\")\n\
         print(text(i[\"exists\"]))\n\
         print(text(i[\"is_dir\"]))\n\
         print(text(i[\"size\"]))\n\
         print(type_of(i[\"modified\"]))\n\
         print(text(file_exists(\"{fpath}\")))\n"
    );
    let r = run(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["true", "false", "5", "number", "true"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
    );

    // Inexistente: forma estable, SIN error; modified = nothing; file_exists coherente.
    let src = format!(
        "require file\n\
         let i be file_info(\"{missing}\")\n\
         print(text(i[\"exists\"]))\n\
         print(text(i[\"is_dir\"]))\n\
         print(text(i[\"size\"]))\n\
         print(type_of(i[\"modified\"]))\n\
         print(text(file_exists(\"{missing}\")))\n"
    );
    let r = run(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec!["false", "false", "0", "nothing", "false"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
    );

    let _ = std::fs::remove_dir_all(&d);
}

// =========================================================
// read_file: rango por líneas 1-based, fin observable, EOL preservado, errores
// =========================================================

#[test]
fn read_file_line_ranges() {
    let d = tdir("readrange");
    let f = d.join("five.txt");
    std::fs::write(&f, "L1\nL2\nL3\nL4\nL5\n").unwrap();
    let fpath = syn(&f);

    // [1,2): líneas 1-2.
    let r = run(&format!("require file\nprint(read_file(\"{fpath}\", 1, 2))"), "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["L1\nL2\n".to_string()]);

    // desde 4 al final.
    let r = run(&format!("require file\nprint(read_file(\"{fpath}\", 4))"), "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["L4\nL5\n".to_string()]);

    // limit mayor que las líneas restantes → fin observable (solo 2 líneas).
    let r = run(&format!("require file\nprint(read_file(\"{fpath}\", 4, 10))"), "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["L4\nL5\n".to_string()]);

    // 1 arg → archivo completo (idéntico a hoy).
    let r = run(&format!("require file\nprint(read_file(\"{fpath}\"))"), "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["L1\nL2\nL3\nL4\nL5\n".to_string()]);

    // offset < 1 → error.
    let r = run(&format!("require file\nlet x be read_file(\"{fpath}\", 0)"), "<t>");
    assert!(!r.success);
    assert!(
        r.errors.iter().any(|e| e.contains("offset must be >= 1")),
        "got {:?}",
        r.errors
    );

    // limit < 0 → error.
    let r = run(&format!("require file\nlet x be read_file(\"{fpath}\", 1, -1)"), "<t>");
    assert!(!r.success);
    assert!(
        r.errors.iter().any(|e| e.contains("limit must be >= 0")),
        "got {:?}",
        r.errors
    );

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn read_file_preserves_crlf() {
    let d = tdir("crlf");
    let f = d.join("crlf.txt");
    std::fs::write(&f, "X\r\nY\r\n").unwrap();
    let fpath = syn(&f);

    let r = run(&format!("require file\nprint(read_file(\"{fpath}\", 1, 1))"), "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["X\r\n".to_string()]);

    let _ = std::fs::remove_dir_all(&d);
}

// =========================================================
// write_file: atómico (round-trip + sin .synsema.tmp residual)
// =========================================================

#[test]
fn write_file_atomic_roundtrip() {
    let d = tdir("write");
    let f = d.join("out.txt");
    let fpath = syn(&f);

    let r = run(
        &format!(
            "require file\n\
             write_file(\"{fpath}\", \"hello world\")\n\
             print(read_file(\"{fpath}\"))\n"
        ),
        "<t>",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["hello world".to_string()]);

    // El destino existe y NO quedó el temporal.
    assert!(f.exists(), "el archivo destino debe existir");
    assert!(
        !d.join("out.txt.synsema.tmp").exists(),
        "no debe quedar .synsema.tmp residual"
    );

    let _ = std::fs::remove_dir_all(&d);
}

// =========================================================
// Least-privilege de archivo: `require file.read(...)` / `file.write(...)`
// (DE-023 / MF-009 — la capacidad punteada ya parsea y concede grano fino)
// =========================================================

#[test]
fn dotted_capability_grants_least_privilege() {
    let d = tdir("leastpriv");
    let x = d.join("x.txt");
    let y = d.join("y.txt");
    let z = d.join("z.txt");
    std::fs::write(&x, "X").unwrap();
    std::fs::write(&z, "Z").unwrap();
    let (xp, yp, zp) = (syn(&x), syn(&y), syn(&z));

    // file.read concede SOLO lectura.
    let r = run(&format!("require file.read(\"{xp}\")\nprint(read_file(\"{xp}\"))"), "<t>");
    assert!(r.success, "file.read debe permitir leer: {:?}", r.errors);
    assert_eq!(r.output, vec!["X".to_string()]);

    let r = run(&format!("require file.read(\"{xp}\")\nwrite_file(\"{xp}\", \"no\")"), "<t>");
    assert!(!r.success, "file.read NO debe permitir escribir");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted: file_write")),
        "debe violar file_write, got {:?}",
        r.errors
    );

    // file.write concede SOLO escritura.
    let r = run(&format!("require file.write(\"{yp}\")\nwrite_file(\"{yp}\", \"ok\")"), "<t>");
    assert!(r.success, "file.write debe permitir escribir: {:?}", r.errors);

    let r = run(&format!("require file.write(\"{yp}\")\nlet c be read_file(\"{yp}\")"), "<t>");
    assert!(!r.success, "file.write NO debe permitir leer");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted: file_read")),
        "debe violar file_read, got {:?}",
        r.errors
    );

    // file (coarse) sigue cubriendo AMBAS (back-compat).
    let r = run(
        &format!(
            "require file(\"{zp}\")\nwrite_file(\"{zp}\", \"ok\")\nprint(read_file(\"{zp}\"))"
        ),
        "<t>",
    );
    assert!(r.success, "file (coarse) debe cubrir lectura y escritura: {:?}", r.errors);
    assert_eq!(r.output, vec!["ok".to_string()]);

    let _ = std::fs::remove_dir_all(&d);
}

// =========================================================
// IO-P2: deny-by-default (string exacto)
// =========================================================

#[test]
fn iop2_builtins_deny_by_default() {
    let r = run("let x be grep(\"X\", \"y\")", "<t>");
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: file_read(\"X\")".to_string()]
    );

    let r = run("let x be edit_file(\"X\", \"a\", \"b\")", "<t>");
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: file_write(\"X\")".to_string()]
    );

    let r = run("append_file(\"X\", \"y\")", "<t>");
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: file_write(\"X\")".to_string()]
    );
}

// =========================================================
// grep
// =========================================================

#[test]
fn grep_searches_dir_recursively_sorted() {
    let d = tdir("grep_dir");
    std::fs::write(d.join("a.txt"), "alpha\nhello\n").unwrap(); // hello en línea 2, col 1
    std::fs::write(d.join("b.txt"), "say hello now\n").unwrap(); // hello en línea 1, col 5
    let sub = d.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("c.txt"), "nope\n").unwrap(); // sin match
    let base = syn(&d);

    let src = format!(
        "require file\n\
         let r be grep(\"{base}\", \"hello\")\n\
         let ms be r[\"matches\"]\n\
         print(text(length(ms)))\n\
         print(text(r[\"truncated\"]))\n\
         let m0 be ms[0]\n\
         print(m0[\"file\"])\n\
         print(text(m0[\"line\"]))\n\
         print(text(m0[\"col\"]))\n\
         print(m0[\"text\"])\n\
         let m1 be ms[1]\n\
         print(m1[\"file\"])\n\
         print(text(m1[\"line\"]))\n\
         print(text(m1[\"col\"]))\n\
         print(m1[\"text\"])\n"
    );
    let r = run(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec![
            "2".to_string(),
            "false".to_string(),
            format!("{base}/a.txt"),
            "2".to_string(),
            "1".to_string(),
            "hello".to_string(),
            format!("{base}/b.txt"),
            "1".to_string(),
            "5".to_string(),
            "say hello now".to_string(),
        ]
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn grep_literal_vs_regex() {
    let d = tdir("grep_re");
    let f = d.join("x.txt");
    std::fs::write(&f, "abc123\n").unwrap();
    let fp = syn(&f);

    // literal: "[0-9]+" como texto crudo no aparece → 0 matches.
    let r = run(&format!("require file\nlet r be grep(\"{fp}\", \"[0-9]+\")\nprint(text(length(r[\"matches\"])))"), "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["0".to_string()]);

    // regex: matchea "123" en col 4.
    let src = format!(
        "require file\n\
         let r be grep(\"{fp}\", \"[0-9]+\", {{\"regex\": true}})\n\
         let ms be r[\"matches\"]\n\
         print(text(length(ms)))\n\
         let m be ms[0]\n\
         print(text(m[\"line\"]))\n\
         print(text(m[\"col\"]))\n\
         print(m[\"text\"])\n"
    );
    let r = run(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["1", "1", "4", "abc123"].into_iter().map(String::from).collect::<Vec<_>>());

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn grep_ignore_case() {
    let d = tdir("grep_ic");
    let f = d.join("x.txt");
    std::fs::write(&f, "Hello\n").unwrap();
    let fp = syn(&f);

    // sensible a may/min → 0.
    let r = run(&format!("require file\nlet r be grep(\"{fp}\", \"hello\")\nprint(text(length(r[\"matches\"])))"), "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["0".to_string()]);

    // ignore_case → 1, text conserva el casing original.
    let src = format!(
        "require file\n\
         let r be grep(\"{fp}\", \"hello\", {{\"ignore_case\": true}})\n\
         let ms be r[\"matches\"]\n\
         print(text(length(ms)))\n\
         print(ms[0][\"text\"])\n"
    );
    let r = run(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["1".to_string(), "Hello".to_string()]);

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn grep_glob_and_max_results() {
    let d = tdir("grep_glob");
    std::fs::write(d.join("a.syn"), "match\n").unwrap();
    std::fs::write(d.join("b.txt"), "match\n").unwrap();
    std::fs::write(d.join("c.syn"), "match\n").unwrap();
    let base = syn(&d);

    // glob "*.syn" → solo a.syn y c.syn (2 matches).
    let r = run(&format!("require file\nlet r be grep(\"{base}\", \"match\", {{\"glob\": \"*.syn\"}})\nprint(text(length(r[\"matches\"])))"), "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["2".to_string()]);

    // max_results 1 → 1 match + truncated true.
    let src = format!(
        "require file\n\
         let r be grep(\"{base}\", \"match\", {{\"max_results\": 1}})\n\
         print(text(length(r[\"matches\"])))\n\
         print(text(r[\"truncated\"]))\n"
    );
    let r = run(&src, "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["1".to_string(), "true".to_string()]);

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn grep_errors() {
    let d = tdir("grep_err");
    let f = d.join("x.txt");
    std::fs::write(&f, "data\n").unwrap();
    let fp = syn(&f);
    let missing = format!("{}/nope", syn(&d));

    let r = run(&format!("require file\nlet r be grep(\"{fp}\", \"\")"), "<t>");
    assert!(!r.success);
    assert!(
        r.errors.iter().any(|e| e.contains("grep: empty pattern")),
        "got {:?}",
        r.errors
    );

    let r = run(&format!("require file\nlet r be grep(\"{missing}\", \"x\")"), "<t>");
    assert!(!r.success);
    assert!(
        r.errors.iter().any(|e| e.contains("grep: path not found")),
        "got {:?}",
        r.errors
    );

    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn grep_respects_target_scope() {
    let d = tdir("grep_scope");
    std::fs::write(d.join("a.txt"), "hello\n").unwrap();
    let sub = d.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("c.txt"), "hello\n").unwrap();
    let base = syn(&d);

    // Scope a la carpeta target → permite grepear el subárbol bajo UN chequeo.
    let r = run(&format!("require file(\"{base}\")\nlet r be grep(\"{base}\", \"hello\")\nprint(text(length(r[\"matches\"])))"), "<t>");
    assert!(r.success, "grep bajo scope del target debe funcionar: {:?}", r.errors);
    assert_eq!(r.output, vec!["2".to_string()]);

    // Scope a OTRA carpeta (subdir) → no autoriza grepear el padre.
    let r = run(&format!("require file(\"{base}/sub\")\nlet r be grep(\"{base}\", \"hello\")"), "<t>");
    assert!(!r.success, "un scope acotado a sub/ no debe autorizar el padre");
    assert!(
        r.errors.iter().any(|e| e.contains("Capability not granted: file_read")),
        "got {:?}",
        r.errors
    );

    let _ = std::fs::remove_dir_all(&d);
}

// =========================================================
// edit_file
// =========================================================

#[test]
fn edit_file_unique_and_replace_all() {
    let d = tdir("edit");
    let uniq = d.join("uniq.txt");
    let ambig = d.join("ambig.txt");
    let notf = d.join("notf.txt");
    std::fs::write(&uniq, "foo bar baz\n").unwrap();
    std::fs::write(&ambig, "a a a\n").unwrap();
    std::fs::write(&notf, "xyz\n").unwrap();
    let (up, ap, np) = (syn(&uniq), syn(&ambig), syn(&notf));
    let missing = format!("{}/missing.txt", syn(&d));

    // match único → replaced 1 + round-trip.
    let r = run(&format!(
        "require file\nlet r be edit_file(\"{up}\", \"bar\", \"QUX\")\nprint(text(r[\"replaced\"]))\nprint(read_file(\"{up}\"))"
    ), "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["1".to_string(), "foo QUX baz\n".to_string()]);

    // 0 ocurrencias → pattern not found.
    let r = run(&format!("require file\nlet r be edit_file(\"{np}\", \"nope\", \"x\")"), "<t>");
    assert!(!r.success);
    assert!(r.errors.iter().any(|e| e.contains("edit_file: pattern not found")), "got {:?}", r.errors);

    // >1 sin replace_all → ambiguo.
    let r = run(&format!("require file\nlet r be edit_file(\"{ap}\", \"a\", \"b\")"), "<t>");
    assert!(!r.success);
    assert!(r.errors.iter().any(|e| e.contains("edit_file: ambiguous, 3 occurrences")), "got {:?}", r.errors);

    // replace_all → reemplaza las 3.
    let r = run(&format!(
        "require file\nlet r be edit_file(\"{ap}\", \"a\", \"b\", true)\nprint(text(r[\"replaced\"]))\nprint(read_file(\"{ap}\"))"
    ), "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["3".to_string(), "b b b\n".to_string()]);

    // old vacío → empty pattern.
    let r = run(&format!("require file\nlet r be edit_file(\"{up}\", \"\", \"x\")"), "<t>");
    assert!(!r.success);
    assert!(r.errors.iter().any(|e| e.contains("edit_file: empty pattern")), "got {:?}", r.errors);

    // inexistente → File not found.
    let r = run(&format!("require file\nlet r be edit_file(\"{missing}\", \"a\", \"b\")"), "<t>");
    assert!(!r.success);
    assert!(r.errors.iter().any(|e| e.contains("File not found")), "got {:?}", r.errors);

    // sin .synsema.tmp residual.
    assert!(!d.join("uniq.txt.synsema.tmp").exists());
    assert!(!d.join("ambig.txt.synsema.tmp").exists());

    let _ = std::fs::remove_dir_all(&d);
}

// =========================================================
// append_file
// =========================================================

#[test]
fn append_file_creates_and_appends() {
    let d = tdir("append");
    let a = d.join("log.txt");
    let b = d.join("raw.bin");
    let (ap, bp) = (syn(&a), syn(&b));

    // crea si no existe, luego agrega al final.
    let r = run(&format!(
        "require file\nappend_file(\"{ap}\", \"line1\\n\")\nappend_file(\"{ap}\", \"line2\\n\")\nprint(read_file(\"{ap}\"))"
    ), "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["line1\nline2\n".to_string()]);

    // bytes crudos.
    let r = run(&format!(
        "require file\nappend_file(\"{bp}\", bytes(\"AB\"))\nappend_file(\"{bp}\", bytes(\"CD\"))\nprint(read_file(\"{bp}\"))"
    ), "<t>");
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["ABCD".to_string()]);

    let _ = std::fs::remove_dir_all(&d);
}

// =========================================================
// IO-P3: run — deny-by-default + validación de args (portable, sin comando real)
// =========================================================

#[test]
fn run_deny_by_default() {
    // Sin require exec → violación con el string exacto (también en modo run/secure).
    let r = run("let r be run(\"echo\", [])", "<t>");
    assert_eq!(
        r.errors,
        vec!["Runtime error: Capability not granted: exec(\"echo\")".to_string()]
    );
}

#[test]
fn run_args_must_be_a_list() {
    // El 2º arg, si está, debe ser lista (la validación precede al spawn).
    let r = run("require exec(\"echo\")\nlet r be run(\"echo\", \"notalist\")", "<t>");
    assert!(!r.success);
    assert!(
        r.errors.iter().any(|e| e.contains("run: args must be a list")),
        "got {:?}",
        r.errors
    );
}

// =========================================================
// IO-P3: run — ejecución real en Windows (corre acá)
// =========================================================

#[cfg(windows)]
mod run_windows {
    use super::*;

    #[test]
    fn run_echo_exit_zero() {
        let r = run(
            "require exec(\"cmd\")\n\
             let r be run(\"cmd\", [\"/C\", \"echo\", \"hi\"])\n\
             print(text(r[\"exit_code\"]))\n\
             print(text(contains(r[\"stdout\"], \"hi\")))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["0".to_string(), "true".to_string()]);
    }

    #[test]
    fn run_nonzero_exit_is_data_not_error() {
        // exit ≠ 0 NO es raise: es dato en exit_code.
        let r = run(
            "require exec(\"cmd\")\n\
             let r be run(\"cmd\", [\"/C\", \"exit\", \"3\"])\n\
             print(text(r[\"exit_code\"]))\n",
            "<t>",
        );
        assert!(r.success, "exit≠0 no debe ser error: {:?}", r.errors);
        assert_eq!(r.output, vec!["3".to_string()]);
    }

    #[test]
    fn run_stdin_is_piped() {
        let r = run(
            "require exec(\"sort\")\n\
             let r be run(\"sort\", [], 10, {\"stdin\": \"abc\\n\"})\n\
             print(text(contains(r[\"stdout\"], \"abc\")))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
    }

    #[test]
    fn run_cwd_opt() {
        let d = tdir("run_cwd");
        let base = syn(&d);
        let dirname = d.file_name().unwrap().to_string_lossy().into_owned();
        let r = run(
            &format!(
                "require exec(\"cmd\")\n\
                 let r be run(\"cmd\", [\"/C\", \"cd\"], 10, {{\"cwd\": \"{base}\"}})\n\
                 print(text(contains(r[\"stdout\"], \"{dirname}\")))\n"
            ),
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn run_env_override() {
        let r = run(
            "require exec(\"cmd\")\n\
             let r be run(\"cmd\", [\"/C\", \"echo\", \"%MYV%\"], 10, {\"env\": {\"MYV\": \"hello123\"}})\n\
             print(text(contains(r[\"stdout\"], \"hello123\")))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
    }

    #[test]
    fn run_timeout_raises() {
        // ping -n 10 tarda ~9s; timeout 1s → mata + raise.
        let r = run(
            "require exec(\"ping\")\n\
             let r be run(\"ping\", [\"-n\", \"10\", \"127.0.0.1\"], 1)\n",
            "<t>",
        );
        assert!(!r.success, "debería expirar");
        assert!(
            r.errors.iter().any(|e| e.contains("timed out")),
            "got {:?}",
            r.errors
        );
    }

    #[test]
    fn run_output_truncation() {
        let r = run(
            "require exec(\"cmd\")\n\
             let r be run(\"cmd\", [\"/C\", \"echo\", \"abcdef\"], 10, {\"max_output\": 2})\n\
             print(text(r[\"stdout_truncated\"]))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
    }

    #[test]
    fn run_command_not_found_raises() {
        let r = run(
            "require exec(\"*\")\n\
             let r be run(\"definitely_not_a_cmd_xyz_123\", [])\n",
            "<t>",
        );
        assert!(!r.success);
        assert!(
            r.errors.iter().any(|e| e.contains("cannot start")),
            "got {:?}",
            r.errors
        );
    }
}

// =========================================================
// IO-P3: run — ejecución real en unix (para CI; cfg-gated)
// =========================================================

#[cfg(unix)]
mod run_unix {
    use super::*;

    #[test]
    fn run_echo_exit_zero() {
        let r = run(
            "require exec(\"echo\")\n\
             let r be run(\"echo\", [\"hi\"])\n\
             print(text(r[\"exit_code\"]))\n\
             print(text(contains(r[\"stdout\"], \"hi\")))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["0".to_string(), "true".to_string()]);
    }

    #[test]
    fn run_nonzero_exit_is_data_not_error() {
        let r = run(
            "require exec(\"false\")\n\
             let r be run(\"false\", [])\n\
             print(text(r[\"exit_code\"]))\n",
            "<t>",
        );
        assert!(r.success, "exit≠0 no debe ser error: {:?}", r.errors);
        assert_eq!(r.output, vec!["1".to_string()]);
    }

    #[test]
    fn run_stdin_is_piped() {
        let r = run(
            "require exec(\"cat\")\n\
             let r be run(\"cat\", [], 10, {\"stdin\": \"abc\"})\n\
             print(r[\"stdout\"])\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["abc".to_string()]);
    }

    #[test]
    fn run_cwd_opt() {
        let d = tdir("run_cwd");
        let base = syn(&d);
        let dirname = d.file_name().unwrap().to_string_lossy().into_owned();
        let r = run(
            &format!(
                "require exec(\"pwd\")\n\
                 let r be run(\"pwd\", [], 10, {{\"cwd\": \"{base}\"}})\n\
                 print(text(contains(r[\"stdout\"], \"{dirname}\")))\n"
            ),
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn run_env_override() {
        let r = run(
            "require exec(\"sh\")\n\
             let r be run(\"sh\", [\"-c\", \"echo $MYV\"], 10, {\"env\": {\"MYV\": \"hello123\"}})\n\
             print(text(contains(r[\"stdout\"], \"hello123\")))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
    }

    #[test]
    fn run_timeout_raises() {
        let r = run(
            "require exec(\"sleep\")\n\
             let r be run(\"sleep\", [\"5\"], 1)\n",
            "<t>",
        );
        assert!(!r.success, "debería expirar");
        assert!(
            r.errors.iter().any(|e| e.contains("timed out")),
            "got {:?}",
            r.errors
        );
    }

    #[test]
    fn run_output_truncation() {
        // seq produce salida grande pero FINITA → drena + trunca (sin colgar).
        let r = run(
            "require exec(\"seq\")\n\
             let r be run(\"seq\", [\"1\", \"50000\"], 30, {\"max_output\": 10})\n\
             print(text(r[\"stdout_truncated\"]))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
    }

    #[test]
    fn run_command_not_found_raises() {
        let r = run(
            "require exec(\"*\")\n\
             let r be run(\"definitely_not_a_cmd_xyz_123\", [])\n",
            "<t>",
        );
        assert!(!r.success);
        assert!(
            r.errors.iter().any(|e| e.contains("cannot start")),
            "got {:?}",
            r.errors
        );
    }
}

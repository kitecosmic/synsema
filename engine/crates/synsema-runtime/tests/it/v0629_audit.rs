//! v0.6.29, ronda 2 de auditoría: un test por hallazgo, con el comportamiento que quedó.
//! (Los de rendimiento miden que el idioma documentado es lineal, con márgenes amplios.)

use std::time::{Duration, Instant};
use synsema_runtime::engine::run_program;

fn out(src: &str) -> Vec<String> {
    let r = run_program(src, "audit.syn");
    assert!(r.success, "falló: {:?}\n{}", r.errors, src);
    r.output
}

fn fails(src: &str) -> String {
    let r = run_program(src, "audit.syn");
    assert!(!r.success, "tenía que fallar:\n{}\nsalida: {:?}", src, r.output);
    r.errors.join("\n")
}

/// Un programa con módulos en un directorio temporal propio. El contador hace único el nombre:
/// en Windows el reloj tiene 100 ns de resolución y dos tests en paralelo podían compartir el
/// directorio (y pisarse `lib.syn`).
fn run_with_files(files: &[(&str, &str)], main: &str) -> Vec<String> {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "synsema-audit-{}-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, src) in files {
        std::fs::write(dir.join(name), src).unwrap();
    }
    let path = dir.join("main.syn");
    std::fs::write(&path, main).unwrap();
    let r = run_program(main, path.to_str().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    assert!(r.success, "falló: {:?}", r.errors);
    r.output
}

fn fast(label: &str, limit: Duration, src: &str) {
    let t = Instant::now();
    out(src);
    let e = t.elapsed();
    assert!(e < limit, "{} tardó {:?} (límite {:?}): ¿volvió a ser cuadrático?", label, e, limit);
}


// B2 — el estado de un módulo es uno: lo que escribe un task se ve por el campo y al revés,
// y una foto (`let s be m.STATE`) es un valor.
#[test]
fn b2_module_state_is_coherent() {
    let lib = "export let STATE be {\"n\": 0}\nexport let ITEMS be []\nexport task bump()\n    set STATE[\"n\"] to STATE[\"n\"] + 1\n    give STATE[\"n\"]\nexport task add(x)\n    set ITEMS to append(ITEMS, x)\nexport task items()\n    give ITEMS\nexport task state()\n    give STATE\n";
    let main = "use \"./lib.syn\" as lib\nlib.bump()\nlet snap be lib.STATE\nset lib.STATE[\"n\"] to 100\nprint(lib.state(), snap)\nlib.add(1)\nprint(lib.ITEMS, lib.items())\nset lib.ITEMS to [7]\nprint(lib.items())\nlet h be {\"f\": lib.bump}\nlet h2 be h\nset h2[\"f\"] to 1\nprint(type_of(h[\"f\"]))\n";
    assert_eq!(
        run_with_files(&[("lib.syn", lib)], main),
        vec!["{n: 100} {n: 1}", "[1] [1]", "[7]", "task"]
    );
    let theme = "export let CONFIG be {\"theme\": \"light\"}\nexport task set_theme(t)\n    set CONFIG[\"theme\"] to t\nexport task theme()\n    give CONFIG[\"theme\"]\n";
    let a = "use \"./state.syn\" as st\nexport task go()\n    st.set_theme(\"dark\")\n";
    let main = "use \"./state.syn\" as st\nuse \"./a.syn\" as a\na.go()\nprint(st.theme(), st.CONFIG[\"theme\"])\nset st.CONFIG[\"theme\"] to \"blue\"\nprint(st.theme())\n";
    assert_eq!(run_with_files(&[("state.syn", theme), ("a.syn", a)], main), vec!["dark dark", "blue"]);
}

// B2 — un módulo no se reemplaza ni gana nombres desde afuera.
#[test]
fn b2_module_names_are_its_exports() {
    let lib = "export let X be 1\nexport task f()\n    give X\n";
    let dir_main = "use \"./lib.syn\" as lib\nset lib.X to 5\nprint(lib.f())\ntry\n    set lib.Y to 1\nrecover e\n    print(e)\ntry\n    set lib.f to 1\nrecover e\n    print(e)\n";
    let o = run_with_files(&[("lib.syn", lib)], dir_main);
    assert_eq!(o[0], "5");
    assert!(o[1].contains("module has no export 'Y'"), "{:?}", o);
    assert!(o[2].contains("cannot replace the module task 'f'"), "{:?}", o);
}

// B3 — `set m[k]`, `set x.f to append(x.f, v)`, `merge` e `insert` en un bucle son lineales.
#[test]
fn b3_in_place_updates_are_linear() {
    fast("set m[k]", Duration::from_secs(20), "let m be {}\nlet i be 0\nwhile i < 40000\n    set m[text(i)] to i\n    set i to i + 1\nprint(length(keys(m)))");
    fast("set s.items", Duration::from_secs(20), "let s be {\"items\": []}\nlet i be 0\nwhile i < 40000\n    set s.items to append(s.items, i)\n    set i to i + 1\nprint(length(s.items))");
    fast("set xs[0]", Duration::from_secs(20), "let xs be [[]]\nlet i be 0\nwhile i < 40000\n    set xs[0] to append(xs[0], i)\n    set i to i + 1\nprint(length(xs[0]))");
    fast("merge", Duration::from_secs(20), "let m be {}\nlet i be 0\nwhile i < 20000\n    set m to merge(m, {text(i): i})\n    set i to i + 1\nprint(length(keys(m)))");
    fast("insert", Duration::from_secs(20), "let xs be []\nlet i be 0\nwhile i < 40000\n    set xs to insert(xs, length(xs), i)\n    set i to i + 1\nprint(length(xs))");
    assert_eq!(out("print(insert([1, 3], 1, 2), insert([1], -1, 0), insert([], 0, 9))"), vec!["[1, 2, 3] [0, 1] [9]"]);
    assert!(fails("print(insert([1], 5, 0))").contains("out of range"));
}

// B4 — `log`, `show` y `print` salen en orden (el orden en vivo lo prueba el CLI).
#[test]
fn b4_log_show_print_keep_order() {
    assert_eq!(out("log \"one\"\nprint(\"two\")\nshow \"three\"\nprint(\"four\")"), vec!["[LOG] one", "two", "three", "four"]);
}



// B7 — el linaje no publica credenciales ni registra lecturas que no llegaron.
// B8 — `evm_tx_raw` recalcula el digest, exige `from` en una creación y re-deriva la dirección.
// Medios de datos: join por hash con todas las columnas, semi/anti/right; columnas mal
// escritas son error; summarize/pivot no pisan ni mezclan columnas.
#[test]
fn tables_no_silent_loss() {
    let src = "let a be [{\"id\": 1, \"x\": \"a\"}, {\"id\": 2, \"x\": \"b\"}, {\"id\": nothing, \"x\": \"n\"}]\nlet b be [{\"id\": 2, \"y\": 20, \"x\": \"B\"}, {\"id\": 3, \"y\": 30, \"x\": \"C\"}]\nprint(join(a, b, \"id\", \"outer\"))\nprint(join(a, b, \"id\", \"semi\"), join(a, b, \"id\", \"anti\"))";
    assert_eq!(
        out(src),
        vec![
            "[{id: 1, x: \"a\", y: nothing, x_right: nothing}, {id: 2, x: \"b\", y: 20, x_right: \"B\"}, {id: nothing, x: \"n\", y: nothing, x_right: nothing}, {id: 3, x: nothing, y: 30, x_right: \"C\"}]",
            "[{id: 2, x: \"b\"}] [{id: 1, x: \"a\"}, {id: nothing, x: \"n\"}]",
        ]
    );
    let rows = "let rows be [{\"g\": \"a\", \"v\": 1}, {\"g\": \"a\", \"v\": 2}, {\"g\": \"b\", \"v\": 5}]\n";
    assert!(fails(&format!("{}print(summarize(rows, \"g\", {{\"t\": sum_of(\"vv\")}}))", rows)).contains("no row has a column \"vv\""));
    assert!(fails(&format!("{}print(summarize(rows, \"g\", {{\"g\": count()}}))", rows)).contains("overwrite the key"));
    assert!(fails(&format!("{}print(group_by(rows, \"G\"))", rows)).contains("no row has a column \"G\""));
    assert!(fails("print(pivot([{\"i\": 1, \"c\": 1, \"v\": 1}, {\"i\": 1, \"c\": \"1\", \"v\": 2}], \"i\", \"c\", \"v\"))").contains("would both become the column"));
    fast("join", Duration::from_secs(20), "let a be apply(range(0, 20000), (i) => {\"id\": i, \"x\": i})\nlet b be apply(range(0, 20000), (i) => {\"id\": i, \"y\": i})\nprint(length(join(a, b, \"id\")))");
}




// `set f(x)[k]` escribe a través de un valor, no de una variable: error.
// Reflejos de Python con su pista.
#[test]
fn python_reflexes_have_hints() {
    let cases = [
        ("let x be 1\nx += 1", "compound assignment"),
        ("let x be 1\nprint(f\"a {x}\")", "backticks"),
        ("let f be lambda y: y", "(y) => y"),
        ("let x be 1\nprint(x is None)", "is_missing"),
        ("let x be 1\nprint(1 if x else 0)", "when c then a otherwise b"),
        ("let xs be [1]\nprint(xs[1:])", "slice(xs"),
        ("let x be 1\nprint(type(x))", "type_of"),
        ("let d be {}\nprint(d.get(\"a\"))", "get(m, key"),
        ("print(\"%d\" % 1)", "%-formatting"),
    ];
    for (src, hint) in cases {
        let e = fails(src);
        assert!(e.contains(hint), "{} → {}", src, e);
    }
    assert_eq!(out("print(max(\n    1,\n    2,\n))"), vec!["2"]);
}

// =========================================================================================
// Ronda 3 de auditoría
// =========================================================================================

// Módulos: dos alias, re-export, un módulo dentro de un mapa y `parallel_map` ven el MISMO
// estado; `set lib["X"]` sigue las reglas de `set lib.X`.
#[test]
fn r3_module_aliases_everywhere() {
    let lib = "export let STATE be {\"n\": 0}\nexport task bump()\n    set STATE[\"n\"] to STATE[\"n\"] + 1\n    give STATE[\"n\"]\nexport task state()\n    give STATE\n";
    let mid = "use \"./lib.syn\" as lib\nexport let L be lib\nexport task mid_state()\n    give lib.STATE\n";
    let main = "use \"./lib.syn\" as lib\nuse \"./mid.syn\" as mid\nmid.L.bump()\nprint(lib.STATE[\"n\"], mid.mid_state()[\"n\"], mid.L.STATE[\"n\"])\nlet mods be {\"l\": lib}\nset mods.l.STATE[\"n\"] to 5\nprint(lib.state()[\"n\"], mods.l.STATE[\"n\"])\ntask work(x)\n    lib.bump()\n    give [lib.STATE[\"n\"], lib.state()[\"n\"], mid.mid_state()[\"n\"]]\nprint(parallel_map(work, [1, 2]))\ntry\n    set lib[\"NEW\"] to 1\nrecover e\n    print(e)\ntry\n    set lib[\"bump\"] to 1\nrecover e\n    print(e)\n";
    let o = run_with_files(&[("lib.syn", lib), ("mid.syn", mid)], main);
    assert_eq!(o[0], "1 1 1");
    assert_eq!(o[1], "5 5");
    assert_eq!(o[2], "[[6, 6, 6], [6, 6, 6]]");
    assert!(o[3].contains("module has no export 'NEW'"), "{:?}", o);
    assert!(o[4].contains("cannot replace the module task 'bump'"), "{:?}", o);
}

// Un `%` seguido de un carácter multibyte en la URL no tumba el motor; un URL sin host es
// error sin ecoar la credencial.
#[test]
fn r3_urls_with_odd_userinfo() {
    let o = out("require net(\"127.0.0.1\")\nlet r be http_get(\"http://u%aé:p@127.0.0.1:1/x\")\nprint(r.status)");
    assert_eq!(o, vec!["0"]);
    let e = fails("require net(\"http://alice:hunter2@/rpc\")\nprint(http_get(\"http://alice:hunter2@/rpc\"))");
    assert!(e.contains("the URL has no host") && !e.contains("hunter2"), "{}", e);
}



// Generadores: cruzan a los workers (numpy `spawn` exacto) y el mismo generador en dos items
// es error; `rng_spawn` masivo es lineal.
#[test]
fn r3_generators_in_workers() {
    // numpy 2.2.1: [[k.random(), k.integers(0, 10)] for k in default_rng(5).spawn(2)]
    assert_eq!(
        out("task use(g)\n    give [g(), random_int(g, 0, 9)]\nprint(parallel_map(use, rng_spawn(rng(5), 2)))"),
        vec!["[[0.4031184756244418, 9], [0.2531538239071238, 9]]"]
    );
    assert!(fails("let g be rng(9)\nprint(parallel_map((i) => random_int(i, 1, 6), [g, g]))").contains("the same generator reaches more than one item"));
    fast("rng_spawn", Duration::from_secs(20), "let i be 0\nwhile i < 40000\n    let g be rng_spawn(rng(1), 1)\n    set i to i + 1\nprint(1)");
}

// Parquet: una página que declara 2 GiB se rechaza ANTES de reservarlos; nanosegundos exactos.
// Linaje: un resultado con enteros > 2^53 se hashea como json_encode y lo dice.
// Números: divmod de floats como CPython/numpy; literales con `_` sólo entre dígitos; `0o`.
#[test]
fn r3_numbers_like_python() {
    assert_eq!(
        out("print(7 // 0.1, 7 % 0.1, -7 // 0.1, 7 % -0.1, 0o17, 0x_1f, number(\"1_000.5\"))"),
        vec!["69.0 0.09999999999999962 -70.0 -3.885780586188048e-16 15 31 1000.5"]
    );
    for lit in ["1__0", "1_", "0x1_", "1_.5", "1e3_", "0o8"] {
        let r = run_program(&format!("print({})", lit), "audit.syn");
        assert!(!r.success, "{} tenía que ser error", lit);
    }
}


// Menores: fmt con `{a.b}` y espacios, join y `+` estrictos, chunk entero, pistas.
#[test]
fn r3_minor_edges() {
    assert_eq!(out("print(fmt(\"{a.b} { c }\", {\"a\": {\"b\": 1}, \"c\": 2}))"), vec!["1 { c }"]);
    assert!(fails("print(join([\"a\", nothing], \",\"))").contains("join: item 2 is nothing"));
    assert!(fails("print(\"x\" + ((v) => v))").contains("Cannot add text and task"));
    assert!(fails("print(chunk([1, 2, 3], 1.5))").contains("must be an integer"));
    let cases = [
        ("let x be 1\nwhen x > 0\n    print(1)\nelse\n    print(2)", "the fallback branch is `otherwise`"),
        ("let x be 1\nlet y be x > 1 ? 1 : 2", "when c then a otherwise b"),
        ("let xs be [1]\nlet y be [v * 2 for v in xs]", "no comprehensions"),
        ("print(round(2.555, 2))", "round_to(x, n)"),
        ("let x be 1\nprint(x --1)", "`--` starts a comment"),
    ];
    for (src, hint) in cases {
        let e = fails(src);
        assert!(e.contains(hint), "{} → {}", src, e);
    }
    assert_eq!(
        out("print(length(group_by([{\"k\": array([-0.0])}, {\"k\": array([0.0])}], \"k\")))"),
        vec!["1"]
    );
}

// JSON-RPC 1.0 (Bitcoin Core): `"error": null` en una respuesta buena no es un error.
#[test]
fn r3_jsonrpc_error_null_is_success() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf);
        let body = r#"{"result": {"blocks": 840000}, "error": null, "id": 1}"#;
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
        let _ = s.write_all(resp.as_bytes());
    });
    let o = out(&format!(
        "require net(\"127.0.0.1\")\nprint(btc_rpc(\"http://127.0.0.1:{port}/\", \"getblockchaininfo\"))"
    ));
    let _ = server.join();
    assert_eq!(o, vec!["{blocks: 840000}"]);
}

// Un generador global no llega a un worker como copia que repite: es un error que dice qué hacer.
#[test]
fn r3_global_generator_in_workers() {
    let e = fails("let g be rng(1)\ntask w(i)\n    give g()\nprint(parallel_map(w, [1, 2]))");
    assert!(e.contains("was created at the top level"), "{}", e);
    let e = fails("let cfg be {\"g\": rng(2)}\ntask w(i)\n    give cfg.g()\nprint(parallel_map(w, [1]))");
    assert!(e.contains("was created at the top level"), "{}", e);
}

// `except`/`catch` tras un try y `finally` tienen pista; `sql_exec` con RETURNING no ejecuta nada.
#[test]
fn r3_try_reflexes_and_returning() {
    assert!(fails("try\n    print(1)\nexcept\n    print(2)").contains("write `recover err`"));
    assert!(fails("try\n    print(1)\nrecover e\n    print(2)\nfinally\n    print(3)").contains("there is no `finally`"));
    let dir = std::env::temp_dir().join(format!("synsema-ret-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("r.db").to_string_lossy().replace('\\', "/");
    let o = out(&format!(
        "require db(\"{db}\")\ndb_open(\"{db}\")\nsql_exec(\"CREATE TABLE t (a INTEGER)\")\ntry\n    sql_exec(\"INSERT INTO t VALUES (1) RETURNING a\")\nrecover e\n    print(e)\nprint(sql(\"SELECT count(*) AS n FROM t\"))"
    ));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(o[0].contains("nothing was executed"), "{:?}", o);
    assert_eq!(o[1], "[{n: 0}]");
}






// Un generador dentro de una LISTA global tampoco llega a un worker como copia.
#[test]
fn r4_generator_in_global_list() {
    let e = fails("let gs be [rng(1)]\ntask w(i)\n    give gs[0]()\nprint(parallel_map(w, [1]))");
    assert!(e.contains("was created at the top level"), "{}", e);
}

// parallel_map avanza los generadores del padre como `apply`; el duplicado se ve a cualquier profundidad.
// sql_exec: la palabra returning dentro de un texto no es RETURNING.
// Detalles: nombres de evento repetidos, más de 4 topics, nonce ≥ 2^64 − 1, export que falta.
// Linaje: consultas y prompts como compromiso con sal (SD-JWT). La sal queda en `lineage()`, no en
// el recibo; con ella y la consulta cualquiera recalcula el compromiso.
// Ronda 6 — B1: `--` dentro de `{`, `[` o `(` es un comentario salvo que todo apunte a restar un
// negativo (`print(x --1)`): dígito o `(` después, un operando antes en la misma línea, y el
// bracket más interno es un paréntesis.
#[test]
fn r6_comment_inside_brackets() {
    assert_eq!(
        out("let m be {\n    \"a\": 1,  --TODO revisar\n    \"b\": 2, -- nota\n}\nlet xs be [\n    1,  --TODO x\n    2, -- nota\n]\nprint(m, xs)\nprint(1) --comentario"),
        vec!["{a: 1, b: 2} [1, 2]", "1"]
    );
    assert_eq!(out("let f be [\n    1 --2 no es una resta\n]\nprint(f)"), vec!["[1]"]);
    assert!(fails("let x be 1\nprint(x --1)").contains("`--` starts a comment"));
    assert!(fails("let x be 1\nprint(x --(1))").contains("`--` starts a comment"));
    assert!(fails("print(5--1)").contains("right after a value"));
}



// Ronda 6 — B4: el `what` del linaje (que el recibo firmado publica) sólo lleva una ruta que el
// programa pasó como texto, un host sin credenciales, un compromiso con sal o un tamaño; nunca
// bytes de un archivo (`parquet_read(bytes)` ponía el hex del archivo), el patrón de `grep` ni un
// "host" sacado del medio de una consulta SQL.
#[test]
fn r6_lineage_publishes_no_data() {
    let dir = std::env::temp_dir().join(format!("synsema-r6lin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.txt"), "hola MARCADOR-123-45\n").unwrap();
    let d = dir.to_string_lossy().replace('\\', "/");
    let o = out(&format!(
        r#"require file.read("{d}/*")
require db("{d}/s.db")
let pq be parquet_write([{{"ssn": "MARCADOR-123-45"}}], {{"compression": "none"}})
let rows be parquet_read(pq)
let g be grep("{d}/a.txt", "MARCADOR-123-45")
db_open("{d}/s.db")
let s be sql("SELECT 'https://MARCADOR-123-45/' AS u")
let l be lineage()
print(l[0].what == "bytes " + text(length(pq)), l[1].what == "{d}/a.txt", starts_with(l[2].what, "query sha256-salted:"))
let pub be lower(json_encode(receipt().credentialSubject.inputs))
let loc be lower(json_encode(apply(l, (e) => e.what)))
print(contains(pub, "marcador"), contains(pub, "4d41524341444f52"), contains(loc, "marcador"), contains(loc, "4d41524341444f52"), contains(pub, "\"salt\""))"#
    ));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(o, vec!["true true true", "false false false false false"]);
}

// Ronda 6 — M1: el rechazo de `sql_exec` con RETURNING es sólo de SQLite (que escribe la fila y
// después falla); ahí `\` es un carácter más dentro de un literal, así que `'a\'` cierra.
// Ronda 6 — m1: el aviso de `synsema check` para `each r in rows` + `set r[…]`. Avisa cuando lo
// escrito en `r` se pierde: leer campos de la fila para calcular (`set r["t"] to r["p"] * 2`,
// `when r.p > 1`) no salva la escritura. No avisa si `r` sale entera del bucle (se pasa, se agrega,
// se imprime), si después se lee un campo que el bucle escribió, o si `set r to …` la religa.
#[test]
fn r6_check_each_set_warning() {
    let warns = |body: &str| -> bool {
        let src = format!("let rows be [{{\"p\": 1}}]\nlet out be []\nlet total be 0\nlet k be \"x\"\neach r in rows\n{}\n", body);
        let program = synsema_core::parser::parse_source(&src, "w.syn").unwrap();
        let mut w = Vec::new();
        synsema_core::deprecated::check_warnings(&program, "w.syn", &mut w);
        w.iter().any(|x| x.contains("changes the loop's copy"))
    };
    for body in [
        "    set r[\"total\"] to r[\"p\"] * 2",
        "    set r.total to r.p * 2",
        "    when r.p > 1\n        set r[\"big\"] to true",
        "    set r[\"n\"] to r[\"n\"] + 1",
        "    set r[\"t\"] to 5",
        "    set r[\"a\"][\"b\"] to 1",
    ] {
        assert!(warns(body), "tenía que avisar:\n{}", body);
    }
    for body in [
        "    set r[\"t\"] to 1\n    print(r)",
        "    set r[\"t\"] to 1\n    set out to append(out, r)",
        "    set r[\"t\"] to 1\n    print(r[\"t\"])",
        "    set r.t to 1\n    print(r.t + 1)",
        "    set r[k] to 1\n    print(r.x)",
        "    set total to total + r[\"p\"]",
        "    set r to merge(r, {\"t\": 1})",
        "    set out[r.p] to 1",
    ] {
        assert!(!warns(body), "no tenía que avisar:\n{}", body);
    }
}

// Ronda 6 — m3: mensajes que confundían (sondas r4lang de la ronda 4). `if (x)` con cuerpo da la
// pista de `when` (era "Unexpected token: INDENT" en la línea siguiente); el driver de SQLite ya no
// habla en su idioma; un error dentro de un hueco de template apunta al hueco (era 1:1).
#[test]
fn r6_confusing_messages() {
    let e = fails("let m be {\"k\": 1}\nif (1 > 0) --comentario\n    print(\"si\")");
    assert!(e.contains("audit.syn:2:1") && e.contains("`if` is not a Synsema statement"), "{}", e);
    let e = fails("let x be 1\nprint(x)\nprint(`hola {zz}`)");
    assert!(e.contains("audit.syn:3:14") && e.contains("'zz'"), "{}", e);
    let e = fails("print(`a\n{ x + zz }`)");
    assert!(e.contains("audit.syn:2:3") && e.contains("'x'"), "{}", e);
    let o = out(r#"require db(":memory:")
db_open(":memory:", "memory")
sql_exec("CREATE TABLE t (id INTEGER PRIMARY KEY, n TEXT)")
try
    print(sql_batch("INSERT INTO t (n) VALUES (?) RETURNING id", [["a"], ["b"]]))
recover e
    print(e)
try
    print(sql_exec("INSERT INTO t (n) VALUES ($$returning$$)"))
recover e
    print(e)
try
    print(sql("SELECT * FROM t WHERE n = ?"))
recover e
    print(e)"#);
    assert!(o[0].starts_with("sql_batch: this statement returns rows"), "{:?}", o);
    assert!(o[1].starts_with("sql_exec: the statement has 1 parameter(s) but 0 value(s) were passed"), "{:?}", o);
    assert!(o[2].starts_with("sql: the statement has 1 parameter(s) but 0 value(s) were passed"), "{:?}", o);
}

// Ronda 7 — R1: dentro de una llamada de VARIAS líneas, `4 --nota` es un comentario: la pista de
// `x --1` salta sólo si el `)` que cierra ese paréntesis está en la misma línea, después del `--`.
#[test]
fn r7_comment_in_multiline_call() {
    assert_eq!(out("let r be max(\n    3,\n    4 --4 es el mayor\n)\nprint(r)"), vec!["4"]);
    assert_eq!(out("let xs be [\n    3,\n    4 --comentario\n]\nlet m be {\n    \"a\": 4 --comentario\n}\nprint(xs, m)"), vec!["[3, 4] {a: 4}"]);
    assert_eq!(out("print(max(\n    3, 4 --1 no es resta\n))"), vec!["4"]);
    assert!(fails("let x be 1\nprint(x --1)").contains("`--` starts a comment"));
    assert!(fails("let x be 1\nprint(max(x --1, 2))").contains("`--` starts a comment"));
}



// Ronda 7 — R5: `require net(...)` con un puerto EXPLÍCITO concede sólo ese puerto; sin puerto,
// el host entero (como en v0.6.28). IPv6 con puerto también.
#[test]
fn r7_net_port_is_part_of_the_grant() {
    let probe = |req: &str, url: &str| -> String {
        let r = run_program(
            &format!("require net(\"{}\")\ntry\n    let r be http_get(\"{}\")\n    print(\"allowed\", r.status)\nrecover e\n    print(\"denied\", e)", req, url),
            "audit.syn",
        );
        assert!(r.success, "{:?}", r.errors);
        r.output.join("\n")
    };
    assert!(probe("http://127.0.0.1:1/", "http://127.0.0.1:2/x").starts_with("denied"), "otro puerto");
    assert!(probe("http://127.0.0.1:1/", "http://127.0.0.1:1/x").starts_with("allowed 0"), "el mismo puerto");
    assert!(probe("http://127.0.0.1:1/", "http://127.0.0.1/x").starts_with("denied"), "puerto por defecto 80");
    assert!(probe("127.0.0.1:1", "http://127.0.0.1:2/x").starts_with("denied"));
    assert!(probe("127.0.0.1:1", "http://127.0.0.1:1/x").starts_with("allowed 0"));
    assert!(probe("127.0.0.1", "http://127.0.0.1:2/x").starts_with("allowed 0"), "sin puerto, cualquier puerto");
    assert!(probe("http://127.0.0.1/", "http://127.0.0.1:2/x").starts_with("allowed 0"), "URL sin puerto: el host");
    assert!(probe("http://[::1]:1/", "http://[::1]:2/x").starts_with("denied"));
    assert!(probe("http://[::1]:1/", "http://[::1]:1/x").starts_with("allowed 0"));
    assert!(probe("[::1]", "http://[::1]:2/x").starts_with("allowed 0"));
}




// Ronda 7 — R11: `sql_batch` con RETURNING en SQLite se rechaza ANTES de ejecutar ninguna fila (el
// mismo pre-chequeo de `sql_exec`); antes escribía la primera y después fallaba.
// Ronda 7 — D1: `csv_encode(rows, {"missing": "NA"})` escribe cada `nothing` como la marca, sin
// comillas (el `na_rep` de pandas); con `csv_parse(text, {"missing": ["NA"]})` la ida y vuelta es
// exacta con una columna o con varias. Un texto igual a la marca va entre comillas.
#[test]
fn r7_csv_encode_missing_marker() {
    let o = out(r#"let one be [{"a": nothing}, {"a": "NA"}, {"a": "x"}]
let many be [{"a": nothing, "b": 1}, {"a": "NA", "b": nothing}]
print(csv_encode(one, {"missing": "NA"}) == "a\r\nNA\r\n\"NA\"\r\nx\r\n")
print(csv_parse(csv_encode(one, {"missing": "NA"}), {"missing": ["NA"]}) == one)
print(csv_parse(csv_encode(many, {"missing": "NA"}), {"missing": ["NA"], "numbers": true}) == many)
print(csv_encode([[nothing, "NA"]], {"missing": "NA"}) == "NA,\"NA\"\r\n")
print(csv_encode(one) == "a\r\n\"\"\r\nNA\r\nx\r\n")"#);
    assert_eq!(o, vec!["true", "true", "true", "true", "true"]);
    assert!(fails(r#"print(csv_encode([{"a": 1}], {"missing": 0}))"#).contains("option \"missing\" must be a text"));
    assert!(fails(r#"print(csv_encode([{"a": 1}], {"missing": "a,b"}))"#).contains("option \"missing\""));
    assert!(synsema_core::csv::ONE_COLUMN_NOTHING_WARNING.contains("pass {\"missing\": \"NA\"}"));
}

// Ronda 7 — D2: `--` pegado a un valor es error SÓLO si lo que sigue es un número o `(` (la
// ambigüedad real: `5--1`, `x--(y)`). `print(1)--nota`, `x--nota`, `"a"--nota` y `]--nota` son un
// comentario, como en v0.6.28.
#[test]
fn r7_glued_dashes_only_before_a_number() {
    assert_eq!(out("print(1)--nota"), vec!["1"]);
    assert_eq!(out("let x be 2\nprint(x)--nota\nlet y be x--nota\nprint(y)"), vec!["2", "2"]);
    assert_eq!(out("let s be \"a\"--nota\nlet xs be [1]--nota\nprint(s, xs)"), vec!["a [1]"]);
    assert!(fails("print(5--1)").contains("right after a value"));
    assert!(fails("let x be 2\nlet y be 3\nprint(x--(y))").contains("right after a value"));
    assert!(fails("let x be 2\nprint(x--1)").contains("right after a value"));
}



// Ronda 8 — `==` corta en la primera diferencia (una lista de 100k que difiere en [0] es O(1)) y
// `match`/`contains`/`index_of` dan el mismo error decimal/float que `==` (antes: "distinto" en
// silencio).
#[test]
fn r8_equality_one_pass_and_everywhere() {
    fast(
        "== con la diferencia en [0]",
        Duration::from_secs(20),
        "let a be range(0, 100000)\nlet b be range(0, 100000)\nset b[0] to -1\nlet i be 0\nwhile i < 2000\n  when a == b\n    print(\"igual\")\n  set i to i + 1",
    );
    assert_eq!(out("print([\"a\", 1d] == [\"b\", 1.0], {\"a\": 1d, \"b\": 1} == {\"a\": 1.0, \"c\": 1}, [1, 2] == [1, 2])"), vec!["false false true"]);
    assert!(fails("print([1d] == [1.0])").contains("cannot mix decimal and float"));
    assert!(fails("print(contains([1.5d], 1.5))").contains("cannot mix decimal and float"));
    assert!(fails("print(index_of([1d, 2.0], 1.0))").contains("cannot mix decimal and float"));
    assert!(fails("let d be 1.5d\nmatch d\n    is 1.5\n        print(\"f\")\n    otherwise\n        print(\"o\")").contains("cannot mix decimal and float"));
    assert_eq!(out("print(contains([1d, 2d], 2), \"a\" in [\"a\", 1.5, 1d])"), vec!["true true"]);
}

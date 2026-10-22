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

// B1 — un hueco `{x}` de un template pega el texto de cualquier valor; `+` sigue estricto.
#[test]
fn b1_template_holes_take_any_value() {
    assert_eq!(
        out("let xs be [1, \"a\"]\nlet m be {\"k\": nothing}\nprint(`xs={xs} m={m} n={nothing} b={bytes(\"01\", \"hex\")}`)"),
        vec!["xs=[1, \"a\"] m={k: nothing} n=nothing b=bytes(01)"]
    );
    assert!(fails("print(\"x\" + [1])").contains("interpolate it"));
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

// B5 — `set xs to append(xs, f())` lee `xs` antes de evaluar `f()`, como el camino normal.
#[test]
fn b5_append_reads_the_list_first() {
    let src = "let xs be [1]\ntask side()\n    set xs to [9, 9]\n    give 5\nset xs to append(xs, side())\nprint(xs)\nlet ys be [1]\ntask side2()\n    set ys to [9]\n    give [5]\nset ys to ys + side2()\nprint(ys)\nlet zs be [1]\ntask side3()\n    set zs[0] to 7\n    give 5\nset zs to append(zs, side3())\nprint(zs)";
    assert_eq!(out(src), vec!["[1, 5]", "[1, 5]", "[1, 5]"]);
}

// B6 — JSON: enteros exactos de cualquier tamaño hasta 4300 dígitos, `1e400` es error.
#[test]
fn b6_json_exact_with_limits() {
    assert_eq!(
        out("print(json_decode(\"18446744073709551615\") + 1, json_decode(\"[1.5, 2e3, -0]\"))"),
        vec!["18446744073709551616 [1.5, 2000.0, 0]"]
    );
    assert!(fails("print(json_decode(\"1e400\"))").contains("out of range for a float"));
    let big = "9".repeat(4301);
    assert!(fails(&format!("print(json_decode(\"{}\"))", big)).contains("the limit is 4300"));
    assert!(fails(&format!("print(int(\"{}\"))", big)).contains("the limit is 4300"));
    assert_eq!(out(&format!("print(length(text(json_decode(\"{}\"))))", "9".repeat(4300))), vec!["4300"]);
    assert_eq!(out("print(jsonl_decode(\"{\\\"a\\\": 12345678901234567890123}\\n\\n[1]\\n\"))"), vec!["[{a: 12345678901234567890123}, [1]]"]);
}

// B7 — el linaje no publica credenciales ni registra lecturas que no llegaron.
#[test]
fn b7_lineage_host_without_credentials() {
    let r = run_program(
        "require net(\"127.0.0.1\")\nlet r be http_get(\"http://alice:pw@127.0.0.1:1/x?api_key=K\")\nprint(length(lineage()))",
        "audit.syn",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["0"]);
}

// B8 — `evm_tx_raw` recalcula el digest, exige `from` en una creación y re-deriva la dirección.
#[test]
fn b8_evm_tx_raw_checks_what_is_signed() {
    let pre = "require sign(\"K\")\nlet k be as_secret(bytes(\"4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318\", \"hex\"), \"K\")\nlet k2 be as_secret(bytes(\"0000000000000000000000000000000000000000000000000000000000000001\", \"hex\"), \"K\")\nlet tx be evm_tx_create({\"chain_id\": 7960, \"nonce\": 3, \"from\": evm_address(k), \"value\": 0, \"gas\": 100000, \"max_fee\": 10, \"max_priority\": 1, \"data\": bytes(\"6000\", \"hex\")})\nlet sig be secp256k1_sign(tx[\"digest\"], k)\n";
    assert_eq!(out(&format!("{}print(length(evm_tx_raw(tx, sig)))", pre)), vec!["86"]);
    assert!(fails(&format!("{}print(evm_tx_raw(remove(tx, \"from\"), secp256k1_sign(tx[\"digest\"], k2)))", pre)).contains("must carry \"from\""));
    assert!(fails(&format!("{}let t be tx\nset t[\"fields\"][1] to 99\nprint(evm_tx_raw(t, sig))", pre)).contains("\"digest\" does not match"));
    assert!(fails(&format!("{}let t be tx\nset t[\"nonce\"] to 7\nprint(evm_tx_raw(t, sig))", pre)).contains("\"nonce\" does not match"));
    assert!(fails(&format!("{}let t be tx\nset t[\"from\"] to evm_address(k2)\nprint(evm_tx_raw(t, secp256k1_sign(tx[\"digest\"], k2)))", pre)).contains("contract_address"));
    assert!(fails(&format!("{}let t be tx\nset t[\"digest\"] to keccak256(bytes(\"x\", \"utf8\"))\nprint(evm_tx_raw(t, secp256k1_sign(t[\"digest\"], k)))", pre)).contains("\"digest\" does not match"));
}

// B9 — `lstsq` es el de numpy (SVD, norma mínima); `polyfit` sin datos suficientes es error.
#[test]
fn b9_least_squares_like_numpy() {
    // numpy: lstsq([[1,2],[2,4],[3,6]], [1,2,3.5]) = [0.22142857, 0.44285714]
    let o = out("let x be lstsq(array([[1, 2], [2, 4], [3, 6]]), [1, 2, 3.5])\nprint(round_to(x[0], 8), round_to(x[1], 8))\nlet y be lstsq(array([[1, 1, 1]]), [3])\nprint(round_to(y[0], 12), round_to(y[2], 12))");
    assert_eq!(o, vec!["0.22142857 0.44285714", "1.0 1.0"]);
    assert!(fails("print(polyfit([1, 1, 1, 2], [1, 2, 3, 4], 2))").contains("not determined by the data"));
    assert_eq!(out("let c be polyfit([1, 2, 3, 4], [2.1, 3.9, 6.2, 7.8], 1)\nprint(round_to(c[0], 10), round_to(c[1], 10))"), vec!["1.94 0.15"]);
}

// B10 — lo que `==` iguala es un solo grupo (mapas en otro orden, el mismo instante en otra
// zona, 1 y 1.0); el texto "1" es otro. Los NaN, un grupo.
#[test]
fn b10_group_keys_follow_equality() {
    let src = "let rows be [{\"k\": {\"a\": 1, \"b\": 2}}, {\"k\": {\"b\": 2, \"a\": 1}}, {\"k\": 1}, {\"k\": 1.0}, {\"k\": \"1\"}]\nprint(length(group_by(rows, \"k\")))\nlet t1 be datetime(\"2024-01-01T12:00:00\", \"UTC\")\nprint(count_by([{\"t\": t1}, {\"t\": to_timezone(t1, \"America/Buenos_Aires\")}], \"t\")[0].count)\nprint(unique([1, 1.0, \"1\", nothing, nothing, float(\"nan\"), float(\"nan\")]))";
    assert_eq!(out(src), vec!["3", "2", "[1, \"1\", nothing, nan]"]);
}

// B11 — `rng(seed)` da la secuencia de `numpy.random.default_rng(seed)` (numpy 2.2.1).
#[test]
fn b11_rng_matches_numpy() {
    // np.random.default_rng(42): random() ×2, integers(0, 10), normal(), permutation(5)
    assert_eq!(
        out("let g be rng(42)\nprint(g(), random(g))\nlet h be rng(42)\nprint(g() != h())"),
        vec!["0.7739560485559633 0.4388784397520523", "true"]
    );
    // numpy 2.2.1: rng(12345).integers(0, 10) ×3, rng(0).normal(), rng(1).permutation(10),
    // rng(2).choice(20, 5, replace=False), rng(3).spawn(2)[i].random().
    let o = out("let g be rng(12345)\nprint(random_int(g, 0, 9), random_int(g, 0, 9), random_int(g, 0, 9))\nlet n be rng(0)\nprint(random_normal(n))\nprint(shuffle(rng(1), [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]))\nprint(sample(rng(2), range(20), 5))\nlet kids be rng_spawn(rng(3), 2)\nprint(kids[0](), kids[1]())");
    assert_eq!(
        o,
        vec![
            "6 2 7",
            "0.1257302210933933",
            "[8, 4, 7, 0, 1, 2, 5, 9, 6, 3]",
            "[5, 1, 13, 4, 8]",
            "0.5413696492633944 0.10033602866159974",
        ]
    );
    // Un generador es un proceso: `let h be g` es el mismo generador.
    assert_eq!(out("let g be rng(5)\nlet h be g\nlet a be h()\nlet b be rng(5)\nb()\nprint(g() == b())"), vec!["true"]);
}

// B12 — el constructor de una variante cuenta sus campos con su propio mensaje.
#[test]
fn b12_constructor_arity_message() {
    let e = fails("enum Order\n    paid(amount)\n    open\nprint(Order.paid(1, 2))");
    assert!(e.contains("variant Order.paid expects 1 fields, got 2"), "{}", e);
    let e = fails("type Point\n    x: number\n    y: number\nprint(Point(1))");
    assert!(e.contains("Type Point expects 2 fields, got 1"), "{}", e);
}

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

// Fechas: un día sin medianoche empieza cuando empieza; la serie diaria es de calendario;
// truncar en la hora repetida conserva cuál de las dos es.
#[test]
fn dates_across_daylight_saving() {
    let src = "print(truncate(datetime(\"2024-09-08T15:00:00\", \"America/Santiago\"), \"day\"))\nprint(date_range(datetime(\"2024-03-09T12:00:00\", \"America/New_York\"), datetime(\"2024-03-11T12:00:00\", \"America/New_York\"), \"day\"))\nlet a be datetime(\"2026-10-25T02:30:00\", \"Europe/Madrid\")\nprint(truncate(a, \"hour\"), truncate(a + duration(hours = 1), \"hour\"))";
    assert_eq!(
        out(src),
        vec![
            "2024-09-08T01:00:00-03:00[America/Santiago]",
            "[2024-03-09T12:00:00-05:00[America/New_York], 2024-03-10T12:00:00-04:00[America/New_York], 2024-03-11T12:00:00-04:00[America/New_York]]",
            "2026-10-25T02:00:00+02:00[Europe/Madrid] 2026-10-25T02:00:00+01:00[Europe/Madrid]",
        ]
    );
}

// CSV: `""` es texto vacío, un campo vacío es `nothing`, y la ida y vuelta es exacta — salvo en
// una tabla de UNA columna (ronda 6, B3): ahí `nothing` se escribe `""` para no escribir una línea
// en blanco (que al leer se ignora siempre), y vuelve como texto vacío, o `nothing` si la columna
// tiene tipo.
#[test]
fn csv_quoted_empty_is_text() {
    let src = "print(csv_parse(\"a,b\\n\\\"\\\",\\n\"))\nlet rows be [{\"a\": \"\", \"b\": nothing, \"c\": \"x,y\"}]\nprint(csv_encode(rows) == \"a,b,c\\r\\n\\\"\\\",,\\\"x,y\\\"\\r\\n\", csv_parse(csv_encode(rows)) == rows)\nlet one be [{\"a\": 1}, {\"a\": nothing}]\nprint(csv_parse(csv_encode(one), {\"numbers\": true}), csv_parse(csv_encode(one), {\"types\": {\"a\": \"int\"}}) == one)";
    assert_eq!(out(src), vec!["[{a: \"\", b: nothing}]", "true true", "[{a: 1}, {a: \"\"}] true"]);
}

// Números y conteos.
#[test]
fn numeric_edges_and_counts() {
    assert_eq!(
        out("print(-9223372036854775808 % -1, -9223372036854775808 // -1)\nprint(argmin([3, nothing, 1, 2]), argmax([nothing, 5, 7]))\nprint(count([1, nothing, 3]), count_missing([1, nothing, nothing]))\nprint(int(\"ff\", base = 16), int(\"-0x10\"), int(\"z\", nothing, base = 36))"),
        vec!["0 9223372036854775808", "2 2", "2 2", "255 -16 35"]
    );
    assert!(fails("print(int(\"ff\", 16))").contains("not the base"));
}

// `set f(x)[k]` escribe a través de un valor, no de una variable: error.
#[test]
fn set_target_must_start_from_a_variable() {
    assert!(fails("let m be {\"a\": {\"b\": 0}}\nset get(m, \"a\")[\"b\"] to 1").contains("must start from a variable"));
}

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

// `summarize` sobre filas desparejas: la columna existe en la tabla aunque falte en un grupo.
#[test]
fn r3_summarize_ragged_rows() {
    assert_eq!(
        out("print(summarize([{\"k\": 1, \"v\": 1}, {\"k\": 2}], \"k\", {\"s\": sum_of(\"v\"), \"m\": mean_of(\"v\")}))"),
        vec!["[{k: 1, s: 1, m: 1.0}, {k: 2, s: 0, m: nothing}]"]
    );
    assert!(fails("print(sum_of(\"x\")([{\"v\": 2}]))").contains("no row has a column \"x\""));
}

// `join`: un `x_right` que ya existe es error; un outer con la izquierda vacía conserva la clave.
#[test]
fn r3_join_names_and_empty_left() {
    assert!(fails("print(join([{\"k\": 1, \"x\": 1, \"x_right\": 2}], [{\"k\": 1, \"x\": 3}], \"k\"))").contains("already has"));
    assert!(fails("print(join([{\"k\": 1, \"x\": 1}], [{\"k\": 1, \"x\": 3, \"x_right\": 4}], \"k\"))").contains("would both be named"));
    assert_eq!(out("print(join([], [{\"k\": 1, \"b\": 1}], \"k\", \"outer\"))"), vec!["[{k: 1, b: 1}]"]);
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
#[test]
fn r3_parquet_expansion_cap() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/parquet_page_bomb.parquet");
    let dir = fixture.parent().unwrap().to_string_lossy().replace('\\', "/");
    let e = fails(&format!(
        "require file.read(\"{dir}/*\")\nprint(parquet_read(read_file_bytes(\"{dir}/parquet_page_bomb.parquet\")))"
    ));
    assert!(e.contains("refusing to allocate"), "{}", e);
    assert_eq!(
        out("let t be datetime(\"2023-11-14T22:13:20.123456789Z\")\nprint(parquet_read(parquet_write([{\"t\": t}]))[0].t == t)"),
        vec!["true"]
    );
}

// Fechas: un día con la medianoche repetida (Havana) no se parte en dos.
#[test]
fn r3_truncate_day_with_repeated_midnight() {
    let src = "let a be truncate(datetime(\"2024-11-03T12:00:00\", \"America/Havana\"), \"day\")\nlet b be truncate(datetime(\"2024-11-03T00:30:00\", \"America/Havana\") + duration(hours = 1), \"day\")\nprint(a == b, a)";
    assert_eq!(out(src), vec!["true 2024-11-03T00:00:00-04:00[America/Havana]"]);
}

// Decimales: var, std, quantile y percentile en decimal (como `statistics` de Python).
#[test]
fn r3_decimal_statistics() {
    assert_eq!(
        out("print(var([1000000000000000000001d, 1000000000000000000003d]), std([1.5d, 2.5d, 3.5d]), percentile([1.10d, 2.20d, 3.30d, 4.40d], 0.9), quantile([1d, 2d, 3d, 4d], 0.9))"),
        vec!["2 1 1.1297 3.7"]
    );
}

// Linaje: un resultado con enteros > 2^53 se hashea como json_encode y lo dice.
#[test]
fn r3_lineage_encoding_for_wide_ints() {
    let dir = std::env::temp_dir().join(format!("synsema-lin3-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("t.db").to_string_lossy().replace('\\', "/");
    let src = format!(
        "require db(\"{db}\")\ndb_open(\"{db}\")\nsql_exec(\"CREATE TABLE t (a INTEGER)\")\nsql_exec(\"INSERT INTO t VALUES (9007199254740993)\")\nlet rows be sql(\"SELECT * FROM t\")\nlet l be lineage()[0]\nprint(l.encoding, \"0x\" + l.sha256 == hex(sha256(json_encode(rows))))"
    );
    let o = out(&src);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(o, vec!["json true"]);
}

// `int`: el 2º posicional es el fallback; una base (2..36) ahí es error; `fallback =` por nombre.
#[test]
fn r3_int_fallback_and_base() {
    assert!(fails("print(int(\"abc\", 10))").contains("name it: int(x, fallback = 10)"));
    assert_eq!(
        out("print(int(\"abc\", fallback = 10), int(\"0o17\"), int(\"0x_ff\"), int(\"x\", 100))"),
        vec!["10 15 255 100"]
    );
}

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

// JSON: `NaN`/`Infinity` (lo que escribe json_encode) se leen con allow_nan; un BOM al principio se ignora.
#[test]
fn r3_json_round_trip_of_special_floats() {
    assert_eq!(
        out("let t be json_encode([float(\"nan\"), float(\"inf\"), -float(\"inf\")])\nprint(t, json_decode(t, allow_nan = true))\nprint(json_decode(\"\\u{FEFF}{\\\"a\\\": 1}\"))"),
        vec!["[NaN, Infinity, -Infinity] [nan, inf, -inf]", "{a: 1}"]
    );
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

// Ronda 4 — `\x` no es escape (rutas y regex quedan); en un backtick `\u{…}` no se come la
// interpolación; `\uXXXX` sí, y `synsema check` lo avisa.
#[test]
fn r4_escapes_keep_valid_text() {
    let o = out(r#"let a be 1
print("C:\build\x64\Release")
print(`x\u{a}y`)
print("\u00e9" == "é", length("a\x2eb"), length("\uD83D\uDE00"))"#);
    assert_eq!(o, vec![r"C:\build\x64\Release", r"x\u1y", "true 6 1"]);
}

// `fmt`: la clave exacta "a.b" gana; `{ x }` y `{obj.prop}` sin `obj` quedan literales.
#[test]
fn r4_fmt_keys_and_literals() {
    let o = out(r#"print(fmt("{a.b}", {"a.b": 5}))
print(fmt("{a.b}", {"a": {"b": 2}}))
print(fmt("p { x } {obj.prop}", {"x": 1}))"#);
    assert_eq!(o, vec!["5", "2", "p { x } {obj.prop}"]);
}

// Estadísticas exactas con decimales y enteros de cualquier tamaño.
#[test]
fn r4_exact_decimal_stats() {
    let o = out(r#"print(median([1d, 2d, 10**30]))
print(median([1d, 10**30]))
print(var([1d, 3d]), quantile([1d, 2d, 10**30], 0.5))
print(std([1.000000000000001d, 1.000000000000003d]) > 0)
print(1d < 10**30, sort([10**30, 1d, 0]))"#);
    assert_eq!(o[0], "2");
    assert_eq!(o[1], "500000000000000000000000000000.5");
    assert_eq!(o[2], "2 2");
    assert_eq!(o[3], "true");
    assert_eq!(o[4], "true [0, 1, 1000000000000000000000000000000]");
}

// JSON estricto: NaN/Infinity sólo con allow_nan.
#[test]
fn r4_json_nan_is_opt_in() {
    assert!(fails(r#"print(json_decode("[NaN]"))"#).contains("allow_nan"));
    assert!(fails(r#"print(jsonl_decode("-Infinity"))"#).contains("allow_nan"));
    let o = out(r#"let v be json_decode("[NaN, Infinity]", allow_nan = true)
print(length(v), is_nan(v[0]))"#);
    assert_eq!(o, vec!["2 true"]);
}

// `int(x, 10)` es error sea cual sea `x` (no depende del dato).
#[test]
fn r4_int_positional_base_always_errors() {
    assert!(fails("print(int(nothing, 10))").contains("base = 10"));
    assert!(fails("print(int(\"5\", 10))").contains("base = 10"));
    assert_eq!(out("print(int(nothing, fallback = 10))"), vec!["10"]);
}

// Un generador dentro de una LISTA global tampoco llega a un worker como copia.
#[test]
fn r4_generator_in_global_list() {
    let e = fails("let gs be [rng(1)]\ntask w(i)\n    give gs[0]()\nprint(parallel_map(w, [1]))");
    assert!(e.contains("was created at the top level"), "{}", e);
}

// parallel_map avanza los generadores del padre como `apply`; el duplicado se ve a cualquier profundidad.
#[test]
fn r4_parallel_map_advances_parent_generators() {
    let o = out(r#"task w(h)
    give h()
let g be rng(7)
let a be parallel_map(w, [g])
let x be g()
let g2 be rng(7)
let b be apply([g2], w)
let y be g2()
print(a == b, x == y, a[0] == x)
let kids be rng_spawn(rng(3), 2)
let k1 be parallel_map(w, kids)
let k2 be parallel_map(w, kids)
print(k1 == k2)"#);
    assert_eq!(o, vec!["true true false", "false"]);
    let e = fails("let g be rng(1)\nprint(parallel_map((i) => 1, [[[[[{\"a\": g}]]]], [[[[[{\"b\": g}]]]]]]))");
    assert!(e.contains("the same generator"), "{}", e);
}

// Decimal con float: `sort` y `join` son error en cualquier orden.
#[test]
fn r4_decimal_float_sort_and_join() {
    assert!(fails("print(sort([1.5d, 1.0]))").contains("decimal"));
    assert!(fails("print(sort_by([{\"a\": 2.0}, {\"a\": 1.5d}], (r) => r.a))").contains("decimal"));
    assert!(fails("print(join([{\"k\": 1.5d}], [{\"k\": 1.5}], \"k\"))").contains("decimal on one side"));
}

// `add_days(t, 0)` en la hora repetida es `t`; `date_range` con "hour".
#[test]
fn r4_calendar_in_repeated_hour() {
    let o = out(r#"let s be datetime("2026-10-25T02:30:00", "Europe/Madrid") + duration(hours = 1)
print(add_days(s, 0) == s, add_months(s, 0) == s)
print(length(date_range(s, s + duration(hours = 2), "hour")))"#);
    assert_eq!(o, vec!["true true", "3"]);
    assert!(fails("print(date_range(date(\"2026-01-01\"), date(\"2026-01-02\"), \"hour\"))").contains("a date has no hours"));
}

// sql_exec: la palabra returning dentro de un texto no es RETURNING.
#[test]
fn r4_sql_exec_returning_inside_string() {
    let dir = std::env::temp_dir().join(format!("synsema-ret4-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("r.db").to_string_lossy().replace('\\', "/");
    let o = out(&format!(
        "require db(\"{db}\")\ndb_open(\"{db}\")\nsql_exec(\"CREATE TABLE t (a TEXT)\")\nsql_exec(\"INSERT INTO t VALUES ('returning soon') -- returning\")\nprint(sql(\"SELECT a FROM t\"))"
    ));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(o, vec!["[{a: \"returning soon\"}]"]);
}

// Detalles: nombres de evento repetidos, más de 4 topics, nonce ≥ 2^64 − 1, export que falta.
#[test]
fn r4_minor_messages() {
    let e = fails(&format!(
        r#"let ev be {{"name": "E", "inputs": [{{"name": "a", "type": "uint256", "indexed": false}}, {{"name": "a", "type": "uint256", "indexed": false}}]}}
print(abi_decode_log(ev, {{"topics": [abi_event_topic(ev)], "data": "0x{}"}}))"#,
        "0".repeat(128)
    ));
    assert!(e.contains("would both be named"), "{}", e);
    let e = fails("print(evm_create_address(\"0x0000000000000000000000000000000000000001\", 2**64))");
    assert!(e.contains("EIP-2681"), "{}", e);
    let e = fails(&format!(
        "require net(\"127.0.0.1\")\nlet z be \"0x{}\"\nprint(evm_logs(\"http://127.0.0.1:1/\", {{\"topics\": [z, z, z, z, z]}}))",
        "0".repeat(64)
    ));
    assert!(e.contains("at most 4 topics"), "{}", e);
}

// Ronda 5 — el decimal es de precisión arbitraria y de tipo estable: `+ - *` exactos a cualquier
// tamaño (Java/Postgres), `/` con 28 cifras significativas sin truncar la parte entera
// (Python/Postgres), y un decimal nunca pasa a float ni a entero en silencio.
#[test]
fn r5_decimal_arbitrary_precision() {
    let o = out(r#"print(1d + 10**30, type_of(1d + 10**30))
print(123456789012345678901234567890.123456789d)
print(1d / 3d, 0.00000000000000000001d / 10000000000d, decimal(10**40) / 3d)
print(1.1d ** 30, 2d ** -2, 7.5d // 2d, -7.5d % 2d, decimal(10**40) % 7d)
print(1d < 10**30, decimal(10**40) == 10**40, json_encode([decimal(10**30) + 0.5d]))
print(decimal("123456789012345678901234567890.5"), round_to(decimal(10**30) + 0.125d, 2))
print(length(group_by([{"k": decimal(10**30) + 0.5d}, {"k": decimal("1000000000000000000000000000000.50")}], "k")))"#);
    assert_eq!(o[0], "1000000000000000000000000000001 decimal");
    assert_eq!(o[1], "123456789012345678901234567890.123456789");
    assert_eq!(o[2], "0.3333333333333333333333333333 0.000000000000000000000000000001 3333333333333333333333333333333333333333");
    assert_eq!(o[3], "17.449402268886407318558803753801 0.25 3 0.5 4");
    assert_eq!(o[4], "true true [1000000000000000000000000000000.5]");
    assert_eq!(o[5], "123456789012345678901234567890.5 1000000000000000000000000000000.12");
    assert_eq!(o[6], "1");
}

// `floor`/`ceil`/`round`/`trunc` de un decimal dan el entero exacto (antes lo devolvían igual).
#[test]
fn r5_decimal_rounding_to_integer() {
    assert_eq!(
        out("print(floor(2.5d), ceil(2.5d), round(2.5d), round(3.5d), trunc(-2.5d), floor(-2.5d), type_of(floor(2.5d)))"),
        vec!["2 3 2 4 -2 -3 number"]
    );
}

// Las estadísticas de decimales son SIEMPRE decimales: una varianza de 1e-30 no da 0 ni float.
#[test]
fn r5_decimal_stats_stay_decimal() {
    let o = out(r#"let xs be [1.000000000000001d, 1.000000000000002d, 1.000000000000004d]
print(std(xs), type_of(std(xs)))
print(var(xs))
print(median([1d, 10**30]), mean([1d, 2d, 10**30]), std([1d, 2d]))"#);
    assert_eq!(o[0], "0.000000000000001527525231651946668862682398 decimal");
    assert_eq!(o[1], "0.000000000000000000000000000002333333333333333333333333333");
    assert_eq!(o[2], "500000000000000000000000000000.5 333333333333333333333333333334 0.7071067811865475244008443621");
}

// Linaje: consultas y prompts como compromiso con sal (SD-JWT). La sal queda en `lineage()`, no en
// el recibo; con ella y la consulta cualquiera recalcula el compromiso.
#[test]
fn r5_lineage_salted_commitment() {
    let dir = std::env::temp_dir().join(format!("synsema-salt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("s.db").to_string_lossy().replace('\\', "/");
    let o = out(&format!(
        r#"require db("{db}")
db_open("{db}")
sql_exec("CREATE TABLE t (a INTEGER)")
let q be "SELECT count(*) AS n FROM t WHERE a > ?"
let r1 be sql(q, [5])
let r2 be sql(q, [5])
let l be lineage()
print(starts_with(l[0].what, "query sha256-salted:"), l[0].what == l[1].what, l[0].committed_encoding)
let c be hex(sha256(bytes(l[0].salt, "hex") + bytes(canonical_json([q, [5]]), "utf8")))
print("query sha256-salted:" + slice(c, 2) == l[0].what)"#
    ));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(o, vec!["true false jcs", "true"]);
}

// CSV: marcas de faltante, float fuera de rango, delimitador inválido, fórmulas y decimales largos.
#[test]
fn r5_csv_top_of_class() {
    let o = out(r#"print(csv_parse("a,b\nNA,1\n\"NA\",2\n", {"missing": ["NA"]}))
print(csv_parse("x\nnan\n", {"types": {"x": "float"}}))
print(csv_encode([{"f": "=SUM(A1)", "n": -5, "g": "@cmd"}], {"escape_formulas": true, "eol": "\n"}))
print(csv_parse("x\n123456789012345678901234567890.5\n", {"types": {"x": "decimal"}}))"#);
    assert_eq!(o[0], r#"[{a: nothing, b: "1"}, {a: "NA", b: "2"}]"#);
    assert_eq!(o[1], "[{x: nan}]");
    assert_eq!(o[2], "f,n,g\n'=SUM(A1),-5,'@cmd\n");
    assert_eq!(o[3], "[{x: 123456789012345678901234567890.5}]");
    assert!(fails(r#"print(csv_parse("x\n1e400\n", {"types": {"x": "float"}}))"#).contains("out of range for a float"));
    assert!(fails(r#"print(csv_parse("a", {"delimiter": "\""}))"#).contains("cannot be"));
    let big = "9".repeat(5000);
    assert!(fails(&format!("print(csv_parse(\"x\\n{}\\n\", {{\"types\": {{\"x\": \"int\"}}}}))", big)).contains("the limit is 4300"));
}

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

// Ronda 6 — B2: un hueco de `fmt` es un nombre (`letra|_` y después alfanuméricos), con `.` entre
// nombres. Los cuantificadores de regex (`{3}`, `{3,5}`) y lo mal formado (`{a..b}`, `{a.}`) quedan
// literales.
#[test]
fn r6_fmt_regex_quantifiers_are_literal() {
    let o = out(r#"print(fmt("^[0-9]{3}-{n}$", {"n": 1}))
print(fmt("{3,5}", {}))
print(fmt("{3}{ x }{}", {"x": 1}))
print(fmt("x{a..b}y {a.} {_k}", {"a": {"b": 1}, "_k": 2}))
print(fmt("{{n}} {n}", {"n": 3}))"#);
    assert_eq!(o, vec!["^[0-9]{3}-1$", "{3,5}", "{3}{ x }{}", "x{a..b}y {a.} 2", "{n} 3"]);
    assert!(fails(r#"print(fmt("{a.b}", {"a": {"c": 1}}))"#).contains("no value for {a.b}"));
}

// Ronda 6 — B3: una línea en blanco se ignora SIEMPRE al leer (Python `csv`, pandas), también en un
// CSV de una columna; al escribir, una fila de un solo campo `nothing` se escribe `""`.
#[test]
fn r6_csv_blank_lines_are_skipped() {
    let o = out(r#"print(length(csv_parse("x\n1\n2\n\n")), length(csv_parse("x\n1\n\n2\n")), length(csv_parse("x,y\n1,2\n\n3,4\n")))
print(csv_encode([{"a": nothing}]) == "a\r\n\"\"\r\n", csv_encode([[nothing]]) == "\"\"\r\n")
print(csv_parse("x\n\"a\n\nb\"\n"))"#);
    assert_eq!(o, vec!["2 2 2", "true true", "[{x: \"a\\n\\nb\"}]"]);
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
#[test]
fn r6_sql_exec_returning_sqlite_only() {
    let dir = std::env::temp_dir().join(format!("synsema-ret6-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("r.db").to_string_lossy().replace('\\', "/");
    let o = out(&format!(
        r#"require db("{db}")
db_open("{db}")
sql_exec("CREATE TABLE t (a TEXT, b TEXT)")
sql_exec("INSERT INTO t VALUES ('a\\', 'returning')")
try
    sql_exec("INSERT INTO t VALUES ('a\\', 'x') RETURNING a")
recover e
    print(contains(e, "nothing was executed"))
print(sql("SELECT a, b FROM t"))"#
    ));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(o, vec!["true", r#"[{a: "a\\", b: "returning"}]"#]);
}

// Ronda 6 — M2: un especificador strftime inválido (`%Q`), o uno que pide lo que el valor no tiene
// (`%H` de una fecha), es un error atrapable que lo nombra; antes chrono entraba en pánico.
#[test]
fn r6_format_time_bad_specifier_is_catchable() {
    let o = out(r#"let d be date("2026-01-02")
let t be datetime("2026-01-02T10:30:00Z")
each p in ["%Q", "%Y-%Q-%d", "abc %", "%.9"]
    try
        print(format_time(t, p))
    recover e
        print(e)
try
    print(format_time(d, "%H:%M"))
recover e
    print(e)
try
    print(format_time(0, "%Q"))
recover e
    print(e)
print(format_time(t, "%Y-%m-%d %H:%M %% %-d %.3f"), format_time(d, "%d/%m/%Y"), format_time(0, "%Y"))"#);
    assert!(o[0].contains("\"%Q\" is not a strftime specifier"), "{:?}", o);
    assert!(o[1].contains("\"%Q\""), "{:?}", o);
    assert!(o[2].contains("\"%\""), "{:?}", o);
    assert!(o[3].contains("is not a strftime specifier"), "{:?}", o);
    assert!(o[4].contains("a date has no time of day or zone"), "{:?}", o);
    assert!(o[5].contains("\"%Q\" is not a strftime specifier"), "{:?}", o);
    assert_eq!(o[6], "2026-01-02 10:30 % 2 .000 02/01/2026 1970");
}

// Ronda 6 — M3: `1.5d == 1.5` es error, así que una clave (o una lista) que mezcla decimal y float
// no puede separar `1.5d` de `1.5` en silencio: `group_by`, `count_by`, `summarize`, `unique`,
// `mode`, `pivot` e `in` dan el mismo error que `==`. Sólo decimales o sólo floats funcionan; un
// NaN no cuenta como float.
#[test]
fn r6_decimal_float_keys_error() {
    let mixed = [
        r#"print(group_by([{"k": 1.5d}, {"k": 1.5}], "k"))"#,
        r#"print(count_by([1.5d, 1.5]))"#,
        r#"print(count_by([{"k": 1.5d}, {"k": 1.5}], "k"))"#,
        r#"print(summarize([{"k": 1.5d, "v": 1}, {"k": 1.5, "v": 2}], "k", {"n": count()}))"#,
        r#"print(summarize([{"a": 1, "k": 1.5d}, {"a": 1, "k": 1.5}], ["a", "k"], {"n": count()}))"#,
        r#"print(unique([1.5d, 1.5]))"#,
        r#"print(unique([[1.5d], [1.5]]))"#,
        r#"print(mode([1.5d, 1.5]))"#,
        r#"print(pivot([{"i": 1.5d, "c": "a", "v": 1}, {"i": 1.5, "c": "b", "v": 2}], "i", "c", "v"))"#,
        r#"print(pivot([{"i": 1, "c": 1.5d, "v": 1}, {"i": 2, "c": 1.5, "v": 2}], "i", "c", "v"))"#,
        r#"print(1.5d in [1.5])"#,
        r#"print(1.5 in [1.5d, 2])"#,
        // Ronda 7 (R3): `in` compara par a par; `2 not in [1.5d, 1.5]` ya no es error, porque 2
        // nunca se compara con un decimal y un float a la vez. `1.5 not in [1.5d]` sí.
        r#"print(1.5 not in [1.5d])"#,
    ];
    for src in mixed {
        let e = fails(src);
        assert!(e.contains("cannot mix decimal and float"), "{}\n{}", src, e);
    }
    let o = out(r#"print(length(group_by([{"k": 1.5d}, {"k": 1.50d}], "k")), length(unique([1.5, 1.5, 2])), mode([1.5d, 1.5d, 2d]))
print(count_by([1.5, 1.5, nan]), 1.5d in [1.50d], 1.5 in [nan, 1.5], nan in [1.5d], "a" in ["a", 1.5d])
print(length(summarize([{"a": 1.5d, "k": 1.5}, {"a": 1.5d, "k": 1.5}], ["a", "k"], {"n": count()})))"#);
    assert_eq!(o, vec!["1 2 1.5", "[{key: 1.5, count: 2}, {key: nan, count: 1}] true true false true", "1"]);
}

// Ronda 6 — M4: `semi` y `anti` no emiten columnas de la derecha, así que no hay colisión de
// nombres (`x_right`) que chequear.
#[test]
fn r6_join_semi_anti_no_false_collision() {
    let o = out(r#"print(join([{"k": 1, "x_right": 0}], [{"k": 1, "x": 2}], "k", "semi"))
print(join([{"k": 1, "x": 1, "x_right": 0}], [{"k": 2, "x": 3}], "k", "anti"))
print(join([{"k": 1, "x": 1}], [{"k": 1, "x": 3, "x_right": 4}], "k", "semi"))"#);
    assert_eq!(o, vec!["[{k: 1, x_right: 0}]", "[{k: 1, x: 1, x_right: 0}]", "[{k: 1, x: 1}]"]);
    assert!(fails(r#"print(join([{"k": 1, "x": 1, "x_right": 2}], [{"k": 1, "x": 3}], "k", "left"))"#).contains("already has"));
}

/// Lee un fixture de `tests/fixtures` con `parquet_read`; `Ok(salida)` o `Err(error)`.
fn read_parquet_fixture(name: &str) -> Result<Vec<String>, String> {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
    let dir = fixture.parent().unwrap().to_string_lossy().replace('\\', "/");
    let r = run_program(
        &format!("require file.read(\"{dir}/*\")\nprint(parquet_read(read_file_bytes(\"{dir}/{name}\")))"),
        "audit.syn",
    );
    if r.success { Ok(r.output) } else { Err(r.errors.join("\n")) }
}

// Ronda 6 — M5: un entero más allá de 2^53 en una columna que mezcla enteros y floats (se escribe
// DOUBLE) es error con la columna y la fila; antes se redondeaba sin aviso.
#[test]
fn r6_parquet_int_beyond_2_53_in_float_column() {
    let e = fails(r#"print(parquet_write([{"a": 1.5}, {"a": 2**53 + 1}]))"#);
    assert!(e.contains("column \"a\", row 2") && e.contains("convert the column to decimal or to text"), "{}", e);
    assert_eq!(
        out(r#"let r be parquet_read(parquet_write([{"a": 1.5}, {"a": 2**53}, {"b": -(2**53)}]))
print(r[1].a == 2**53, parquet_read(parquet_write([{"a": 2**53 + 1}]))[0].a)"#),
        vec!["true 9007199254740993"]
    );
}

// Ronda 6 — M5: dos columnas con el mismo nombre (fixture del auditor, ronda 4) son
// un error con el nombre; antes una se perdía sin aviso.
#[test]
fn r6_parquet_duplicate_columns() {
    let e = read_parquet_fixture("parquet_dup_columns.parquet").unwrap_err();
    assert!(e.contains("two columns named \"a\""), "{}", e);
}

// Ronda 6 — M5: sin `synsema.timezones`, la zona sale del esquema Arrow (`ARROW:schema`) que
// escriben polars y pyarrow; un offset fijo (`+05:30`) se conserva (ronda 8) y una columna sin
// zona es UTC.
#[test]
fn r6_parquet_arrow_timezones() {
    assert_eq!(
        read_parquet_fixture("parquet_tz_polars.parquet").unwrap(),
        vec!["[{t: 2026-01-03T10:00:00-03:00[America/Sao_Paulo], u: 2026-01-03T10:00:00Z, n: 2026-01-03T10:00:00+09:00[Asia/Tokyo], k: 1}]"]
    );
    assert_eq!(
        read_parquet_fixture("parquet_tz_arrow.parquet").unwrap(),
        vec!["[{t: 2026-01-03T04:00:00-05:00[America/New_York], o: 2026-01-03T14:30:00+05:30, n: 2026-01-03T09:00:00Z}]"]
    );
    // Lo que escribe `parquet_write` sigue volviendo con su zona.
    assert_eq!(
        out(r#"print(parquet_read(parquet_write([{"w": datetime("2026-01-03T10:00:00", "Europe/Madrid")}]))[0].w)"#),
        vec!["2026-01-03T10:00:00+01:00[Europe/Madrid]"]
    );
}

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

// Ronda 7 — R2: en `fmt`, un texto entre llaves que es EXACTAMENTE una clave del mapa se sustituye
// siempre, tenga la forma que tenga; recién después vale la regla de forma de B2.
#[test]
fn r7_fmt_exact_keys_first() {
    let o = out(r#"print(fmt("[{0}] {a-b}", {"0": "z", "a-b": 1}))
print(fmt("^[0-9]{3}-{n}$", {"n": 1}))
print(fmt("{ x }|{3,5}|{a b}", {"x": 1}))
print(fmt("{ x }", {" x ": 9}))"#);
    assert_eq!(o, vec!["[z] 1", "^[0-9]{3}-1$", "{ x }|{3,5}|{a b}", "9"]);
    assert!(fails(r#"print(fmt("{n}", {}))"#).contains("no value for {n}"));
}

// Ronda 7 — R3: el error decimal/float sale sólo en una comparación real. `in` compara elemento
// por elemento (sin recorrer antes la lista); `unique`/`group_by`/… sólo cuando dos claves caen en el
// mismo grupo numérico (1.5 con 1.5d), no cuando la lista tiene los dos tipos en valores distintos.
#[test]
fn r7_decimal_float_only_on_real_comparisons() {
    let o = out(r#"print("a" in ["a", 1.5, 1d], 2 in [1.5, 1d, 2], 3 in [1.5, 1d])
print(unique(["a", 1.5, 1d]), length(group_by([{"k": 1.5}, {"k": 1d}], "k")), count_by([1.5, 2d, 1.5]))
print(mode([1.5, 2d, 2d]), length(summarize([{"k": 1.5}, {"k": 2d}], "k", {"n": count()})))
print(length(pivot([{"i": 1.5, "c": "a", "v": 1}, {"i": 2d, "c": 2d, "v": 2}], "i", "c", "v")))
print(length(join([{"k": 1.5}], [{"k": 2d}], "k", "left")))"#);
    assert_eq!(o, vec![
        "true true false",
        "[\"a\", 1.5, 1] 2 [{key: 1.5, count: 2}, {key: 2, count: 1}]",
        "2 2",
        "2",
        "1",
    ]);
    for src in [
        "print(1.5 in [1.5d])",
        "print(1.5d in [\"a\", 1.5])",
        "print(unique([1.5, 1.5d]))",
        "print(unique([1.0, 1d]))",
        "print(group_by([{\"k\": 1.5}, {\"k\": 1.5d}], \"k\"))",
        "print(count_by([[1.5d], [1.5]]))",
    ] {
        assert!(fails(src).contains("cannot mix decimal and float"), "{}", src);
    }
    assert!(fails("print(join([{\"k\": 1.5}], [{\"k\": 1.5d}], \"k\"))").contains("decimal on one side and float on the other"));
}

// Ronda 7 — R4: `sort`/`sort_by` dan el error decimal/float sólo si una comparación real junta un
// decimal y un float en la misma posición; listas anidadas con los dos tipos en lugares distintos
// ordenan.
#[test]
fn r7_sort_nested_decimal_float() {
    assert_eq!(
        out("print(sort([[2d, 2.5], [1d, 1.5]]), sort_by([[2d, 2.5], [1d, 1.5]], (r) => r), sort([[1d, 1.5], [1d, 0.5]]))"),
        vec!["[[1, 1.5], [2, 2.5]] [[1, 1.5], [2, 2.5]] [[1, 0.5], [1, 1.5]]"]
    );
    for src in ["print(sort([[1.5d], [1.0]]))", "print(sort([1.5d, 1.0]))", "print(sort_by([1.5d, 1.0], (x) => x))", "print(sort([[1d, 1.5], [1d, 1.5d]]))"] {
        assert!(fails(src).contains("cannot mix decimal and float"), "{}", src);
    }
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

// Ronda 7 — R6: `==` de listas y mapas compara elemento a elemento; un decimal contra un float en
// la misma posición (o clave) da el mismo error que `1d == 1.0`; `in` también. `match` y
// `contains` quedaron como estaban (sin error): los fija un unit test del core — ver Dudas.
#[test]
fn r7_container_equality_decimal_float() {
    for src in [
        "print([1d] == [1.0])",
        "print({\"a\": 1d} == {\"a\": 1.0})",
        "print([[1d]] != [[1.5]])",
        "print([1d] in [[1.0]])",
    ] {
        assert!(fails(src).contains("cannot mix decimal and float"), "{}", src);
    }
    assert_eq!(
        out("print([1d] == [1], {\"a\": 1d} == {\"a\": 1}, [1d, \"x\"] == [1d, \"x\"], [1d] == [1d, 1.0], contains([1d, 2d], 2))\nmatch [1d]\n    is [1]\n        print(\"int\")\n    otherwise\n        print(\"no\")"),
        vec!["true true true false true", "int"]
    );
}

// Ronda 8 — una columna Parquet con zona de offset fijo en el esquema Arrow (`+05:30`, que escriben
// pyarrow y pandas) se lee CON su offset, como en Arrow, pandas, Python y Temporal: el mismo instante
// y la misma hora local, sin aviso. (polars no escribe offsets fijos: el fixture es del auditor.)
#[test]
fn r8_parquet_fixed_offset_is_kept() {
    assert_eq!(
        read_parquet_fixture("parquet_tz_arrow.parquet").unwrap(),
        vec!["[{t: 2026-01-03T04:00:00-05:00[America/New_York], o: 2026-01-03T14:30:00+05:30, n: 2026-01-03T09:00:00Z}]"]
    );
}

// Ronda 7 — R8: una comilla sin cerrar en un CSV con fin de línea `\r` (o mezclado) se detecta y el
// error dice la línea correcta: `\r`, `\r\n` y `\n` cuentan igual que en el tokenizador.
#[test]
fn r7_csv_unclosed_quote_cr_lines() {
    for (src, line) in [
        (r#"csv_parse("a\r\"x\r")"#, 2),
        (r#"csv_parse("a\rb\r\"x")"#, 3),
        (r#"csv_parse("a\r\nb\r\n\"x\r\n")"#, 3),
        (r#"csv_parse("a,b\r\"x\ry\",2\r3,\"z\r")"#, 4),
        (r#"csv_parse("a\n\"x\ry\"\n\"z")"#, 4),
    ] {
        let e = fails(&format!("print({})", src));
        assert!(e.contains(&format!("unclosed quote in the field that starts on line {}", line)), "{}\n{}", src, e);
    }
    assert_eq!(out(r#"print(csv_parse("a,b\r1,2\r\"x\ry\",3\r"))"#), vec![r#"[{a: "1", b: "2"}, {a: "x\ry", b: "3"}]"#]);
}

// Ronda 7 — R9: `date_range` con pasos de calendario en Pacific/Apia no repite el 31/12/2011 (el
// 30/12 no existió): un paso que cae en el mismo instante que el anterior se saltea. `add_days`
// solo queda como está.
#[test]
fn r7_date_range_skips_a_day_that_did_not_exist() {
    let o = out(r#"let s be datetime("2011-12-28T10:00:00", "Pacific/Apia")
let r be date_range(s, datetime("2012-01-01T10:00:00", "Pacific/Apia"), "day")
print(length(r), length(unique(r)))
print(r[2])
print(add_days(datetime("2011-12-29T10:00:00", "Pacific/Apia"), 1))"#);
    assert_eq!(o, vec!["4 4", "2011-12-31T10:00:00+14:00[Pacific/Apia]", "2011-12-31T10:00:00+14:00[Pacific/Apia]"]);
}

// Ronda 7 — R10: una columna Parquet `TIME` (hora del día) se lee como `duration` desde medianoche,
// en nanosegundos (lo que escribe polars), microsegundos o milisegundos; Synsema no tiene un tipo
// "hora del día". (Antes: ns → entero, ms/µs → texto.)
#[test]
fn r7_parquet_time_of_day_is_a_duration() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/parquet_time_ns_polars.parquet");
    let dir = fixture.parent().unwrap().to_string_lossy().replace('\\', "/");
    let o = out(&format!(
        "require file.read(\"{dir}/*\")\nlet r be parquet_read(read_file_bytes(\"{dir}/parquet_time_ns_polars.parquet\"))\nprint(type_of(r[0].t), in_units(r[0].t, \"milliseconds\"), r[1].t, r[2].t == duration(seconds = 0))\nprint(r[0].t > duration(hours = 13, minutes = 10, seconds = 45), r[0].t < duration(hours = 13, minutes = 10, seconds = 46))"
    ));
    assert_eq!(o, vec!["duration 47445123.456 nothing true", "true true"]);
}

// Ronda 7 — R11: `sql_batch` con RETURNING en SQLite se rechaza ANTES de ejecutar ninguna fila (el
// mismo pre-chequeo de `sql_exec`); antes escribía la primera y después fallaba.
#[test]
fn r7_sql_batch_returning_writes_nothing() {
    let o = out(r#"require db(":memory:")
db_open(":memory:", "memory")
sql_exec("CREATE TABLE t (id INTEGER PRIMARY KEY, n TEXT)")
try
    print(sql_batch("INSERT INTO t (n) VALUES (?) RETURNING id", [["a"], ["b"]]))
recover e
    print(e)
print(sql("SELECT count(*) AS c FROM t"))
print(sql_batch("INSERT INTO t (n) VALUES (?)", [["returning"], ["b"]]))"#);
    assert!(o[0].starts_with("sql_batch: this statement returns rows (RETURNING)") && o[0].contains("nothing was executed"), "{:?}", o);
    assert_eq!(o[1], "[{c: 0}]");
    assert_eq!(o[2], "{rows_affected: 2}");
}

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

// Ronda 8 — un datetime con offset lo CONSERVA (Python, java.time, Temporal, Arrow, pandas): la hora
// local de una fecha RFC 3339 no se pierde. Igualdad y orden, por instante.
#[test]
fn r8_fixed_offset_is_kept() {
    let a = "let a be datetime(\"2026-09-24T02:00:00+05:30\")\n";
    assert_eq!(out(&format!("{}print(a)", a)), vec!["2026-09-24T02:00:00+05:30"]);
    assert_eq!(
        out(&format!("{}let p be date_parts(a)\nprint(p.hour, p.day, p.zone, date(a), truncate(a, \"day\"))", a)),
        vec!["2 24 +05:30 2026-09-24 2026-09-24T00:00:00+05:30"]
    );
    assert_eq!(out(&format!("{}print(format_time(a, \"%d %H:%M %z\"))", a)), vec!["24 02:00 +0530"]);
    assert_eq!(
        out("print(add_months(datetime(\"2026-01-31T02:00:00+05:30\"), 1))"),
        vec!["2026-02-28T02:00:00+05:30"]
    );
    assert_eq!(out(&format!("{}print(a == datetime(\"2026-09-23T20:30:00Z\"), datetime(text(a)) == a)", a)), vec!["true true"]);
    assert_eq!(
        out("print(sort([datetime(\"2026-01-01T10:00:00+05:30\"), datetime(\"2026-01-01T05:00:00Z\"), datetime(\"2026-01-01T01:00:00-03:00\")]))"),
        vec!["[2026-01-01T01:00:00-03:00, 2026-01-01T10:00:00+05:30, 2026-01-01T05:00:00Z]"]
    );
    assert_eq!(out(&format!("{}print(json_encode({{\"t\": a}}))", a)), vec!["{\"t\": \"2026-09-24T02:00:00+05:30\"}"]);
    assert_eq!(
        out(&format!("{}print(csv_parse(csv_encode([{{\"t\": a}}]), {{\"types\": {{\"t\": \"datetime\"}}}}))", a)),
        vec!["[{t: 2026-09-24T02:00:00+05:30}]"]
    );
    assert_eq!(
        out(&format!("{}print(parquet_read(parquet_write([{{\"t\": a}}])))", a)),
        vec!["[{t: 2026-09-24T02:00:00+05:30}]"]
    );
    // Un offset como zona en todas partes; sin dos puntos también; cero es UTC.
    assert_eq!(
        out(&format!("{}print(to_timezone(a, \"-03:00\"), datetime(\"2026-09-24T02:00:00+0530\") == a, datetime(\"2026-09-24T02:00:00+00:00\"))", a)),
        vec!["2026-09-23T17:30:00-03:00 true 2026-09-24T02:00:00Z"]
    );
    assert_eq!(
        out("print(parse_datetime(\"24/09/2026 02:00 +0530\", \"%d/%m/%Y %H:%M %z\"))"),
        vec!["2026-09-24T02:00:00+05:30"]
    );
    assert!(fails("print(datetime(\"x\", \"+25:00\"))").contains("unknown time zone"));
}

// Ronda 8 — RFC 9557 con el criterio de Temporal: `[Zona]` sin offset es la hora LOCAL en esa zona
// (antes se leía como UTC: 10:00[Asia/Kolkata] daba 15:30); un hueco de horario de verano es error;
// un offset que no coincide con la zona es error.
#[test]
fn r8_bracketed_zone_is_local_time() {
    assert_eq!(
        out("print(datetime(\"2026-09-24T10:00:00[Asia/Kolkata]\"), datetime(\"2026-09-24T10:00:00[+05:30]\"))"),
        vec!["2026-09-24T10:00:00+05:30[Asia/Kolkata] 2026-09-24T10:00:00+05:30"]
    );
    assert_eq!(
        out("print(datetime(\"2026-09-24T10:00:00+05:30[Asia/Kolkata]\"))"),
        vec!["2026-09-24T10:00:00+05:30[Asia/Kolkata]"]
    );
    assert!(fails("print(datetime(\"2026-03-29T02:30:00[Europe/Madrid]\"))").contains("does not exist in Europe/Madrid"));
    assert!(fails("print(datetime(\"2026-09-24T10:00:00+05:30[Europe/Madrid]\"))").contains("does not match Europe/Madrid"));
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

// Ronda 8 (auditoría de la ronda 8) — un offset con segundos (hora solar de una zona IANA antes de
// ~1920) se escribe con sus segundos y se vuelve a leer, como Python y java.time; `Z[Zona]` es el
// instante visto en la zona (RFC 9557, Temporal); `+05` sin minutos se lee; `==` entre mapas no
// depende del orden de las claves; una duración de más de 292 años se muestra y se mide bien.
#[test]
fn r8_offsets_seconds_z_zone_and_long_durations() {
    let h = "let h be datetime(\"1900-01-01T00:00:00[America/Buenos_Aires]\")\n";
    assert_eq!(
        out(&format!("{}print(h, datetime(text(h)) == h, datetime(\"1900-01-01T00:00:00-04:16:48\"))", h)),
        vec!["1900-01-01T00:00:00-04:16:48[America/Buenos_Aires] true 1900-01-01T00:00:00-04:16:48"]
    );
    assert_eq!(
        out("print(datetime(\"2026-01-03T10:00:00Z[Europe/Madrid]\"), datetime(\"2026-09-24T10:00:00+05\"))"),
        vec!["2026-01-03T11:00:00+01:00[Europe/Madrid] 2026-09-24T10:00:00+05:00"]
    );
    assert_eq!(
        out("let A be {\"a\": 1, \"b\": 1d}\nlet B be {\"b\": 1.0, \"a\": 2}\nprint(A == B, B == A, [1d, \"a\"] == [1.0, \"b\"])"),
        vec!["false false false"]
    );
    assert_eq!(
        out("let d be datetime(\"2400-01-01T00:00:00Z\") - datetime(\"2000-01-01T00:00:00Z\")\nprint(d, in_units(d, \"days\"), date(2000, 1, 1) + d)"),
        vec!["P146097D 146097.0 2400-01-01"]
    );
}

// Ronda 8 — `csv_encode(…, {"missing": ""})` escribía líneas en blanco en una tabla de una columna
// y la lectura las salteaba: se perdían filas. Una marca vacía es error.
#[test]
fn r8_csv_empty_missing_mark_is_an_error() {
    assert!(fails("print(csv_encode([{\"a\": nothing}, {\"a\": \"x\"}], {\"missing\": \"\"}))").contains("cannot be empty"));
    assert_eq!(
        out("print(csv_parse(csv_encode([{\"a\": nothing}, {\"a\": \"x\"}], {\"missing\": \"NA\"}), {\"missing\": [\"NA\"]}))"),
        vec!["[{a: nothing}, {a: \"x\"}]"]
    );
}

//! v0.6.30: pendientes de la auditoría de v0.6.29. Un test por ítem, con el comportamiento que
//! quedó; cada uno falla con el código de v0.6.29.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
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

/// Un programa con módulos en un directorio temporal propio (el contador hace único el nombre).
fn run_files(files: &[(&str, &[u8])], main: &str) -> synsema_core::interpreter::RunResult {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "synsema-audit630-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, src) in files {
        std::fs::write(dir.join(name), src).unwrap();
    }
    let path = dir.join("main.syn");
    std::fs::write(&path, main).unwrap();
    let r = run_program(main, path.to_str().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    r
}

/// Los avisos de `synsema check` de un programa.
fn check_warnings(src: &str) -> Vec<String> {
    let program = synsema_core::parser::parse_source(src, "w.syn").unwrap();
    let mut w = Vec::new();
    synsema_core::deprecated::check_warnings(&program, "w.syn", &mut w);
    w
}

// A1 — `%Z` al parsear: una abreviatura no identifica una zona (IST es India, Irlanda o
// Israel). Antes daba 10:00 UTC sin avisar; ahora es un error, salvo UTC/GMT, que no son ambiguas.
#[test]
fn a1_parse_datetime_zone_abbreviation_is_an_error() {
    let e = fails("print(parse_datetime(\"24/09/2026 10:00 IST\", \"%d/%m/%Y %H:%M %Z\"))");
    assert!(e.contains("does not identify a zone") && e.contains("%z"), "{}", e);
    assert!(fails("print(parse_datetime(\"24/09/2026 10:00 IST\", \"%d/%m/%Y %H:%M %Z\", \"Asia/Kolkata\"))").contains("%Z"));
    assert_eq!(
        out("print(parse_datetime(\"24/09/2026 10:00 UTC\", \"%d/%m/%Y %H:%M %Z\"))\nprint(parse_datetime(\"Thu, 24 Sep 2026 10:00:00 GMT\", \"%a, %d %b %Y %H:%M:%S %Z\", \"-03:00\"))\nprint(parse_datetime(\"24/09/2026 10:00 +05:30\", \"%d/%m/%Y %H:%M %z\"))\nprint(parse_datetime(\"2026-09-24 10:00 %Z\", \"%Y-%m-%d %H:%M %%Z\"))"),
        vec!["2026-09-24T10:00:00Z", "2026-09-24T07:00:00-03:00", "2026-09-24T10:00:00+05:30", "2026-09-24T10:00:00Z"]
    );
}

// A2 — `nothing` (faltante) no es NaN (inválido): un coeficiente faltante es un error; un x
// faltante queda `nothing` en su lugar, como en `cumsum`.
#[test]
fn a2_polyval_keeps_missing_apart_from_nan() {
    let e = fails("print(polyval([2.0, nothing], 1))");
    assert!(e.contains("position 1 is nothing") && e.contains("drop_missing"), "{}", e);
    assert_eq!(
        out("print(polyval([2.0, 1.0], [1, nothing, 3]))\nprint(polyval([2.0, 1.0], nothing))\nprint(cumsum([1, nothing, 3]))\nprint(polyval([1, 0, -1], 3))"),
        vec!["[3.0, nothing, 7.0]", "nothing", "[1, nothing, 4]", "8.0"]
    );
    assert!(fails("print(lstsq(array([[1.0], [2.0]]), [1.0, nothing]))").contains("nothing"));
    // polyfit sigue salteando los pares con un faltante.
    assert_eq!(out("print(apply(polyfit([0, 1, nothing, 3], [1, 3, 99, 7], 1), (c) => round_to(c, 6)))"), vec!["[2.0, 1.0]"]);
}

// A3 — un array 0-D es un escalar: no tiene largo (numpy da TypeError en `len()`).
#[test]
fn a3_length_of_0d_array_is_an_error() {
    let e = fails("print(length(array(5)))");
    assert!(e.contains("0-d array has no length") && e.contains("size(a)"), "{}", e);
    assert_eq!(out("print(size(array(5)), shape(array(5)), length(array([1, 2])), length(zeros([3, 2])))"), vec!["1 [] 2 3"]);
}

// A4 — un task o un generador no es un dato: json_encode lo decía como texto (y revelaba la
// semilla). Ahora es un error que nombra dónde está, y canonical_json usa el sustantivo correcto.
#[test]
fn a4_json_encode_rejects_code() {
    let e = fails("print(json_encode(rng(1)))");
    assert!(e.contains("json_encode: the value is a generator") && e.contains("not data"), "{}", e);
    let e = fails("print(json_encode({\"f\": (x) => x}))");
    assert!(e.contains("json_encode: the value[\"f\"] is a task"), "{}", e);
    let e = fails("print(json_encode([1, {\"g\": [rng(2)]}]))");
    assert!(e.contains("the value[1][\"g\"][0] is a generator"), "{}", e);
    assert!(fails("print(jsonl_encode([{\"a\": 1}, {\"f\": print}]))").contains("jsonl_encode: item 1[\"f\"] is a task"));
    assert!(fails("print(json_for_script({\"f\": print}))").contains("json_for_script"));
    let e = fails("print(canonical_json(rng(1)))");
    assert!(e.contains("canonical_json: the value is a generator"), "{}", e);
    assert!(fails("print(canonical_json({\"f\": (x) => x}))").contains("the value.f is a task"));
    assert_eq!(out("print(json_encode({\"a\": [1, nothing, \"x\"]}))"), vec!["{\"a\": [1, null, \"x\"]}"]);
}

// A5 — `int(x, 2.0)` es el mismo tropiezo que `int(x, 2)`.
#[test]
fn a5_int_fallback_float_base_like_int() {
    for src in ["print(int(\"abc\", 2.0))", "print(int(\"abc\", 16.0))", "print(int(\"abc\", 2))"] {
        let e = fails(src);
        assert!(e.contains("the second argument is the fallback value, not the base"), "{}: {}", src, e);
    }
    assert!(fails("print(int(\"abc\", 2.0))").contains("int(x, base = 2)"));
    assert_eq!(out("print(int(\"abc\", 2.5), int(\"abc\", 40.0), int(\"abc\", fallback = 2.0), int(\"7\", 2.0 + 0.5))"), vec!["2.5 40.0 2.0 7"]);
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn post(port: u16, body: &[u8]) -> String {
    for _ in 0..100 {
        if let Ok(mut sock) = TcpStream::connect(("127.0.0.1", port)) {
            let mut req = format!(
                "POST /j HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            req.extend_from_slice(body);
            sock.write_all(&req).unwrap();
            let mut resp = String::new();
            let _ = sock.read_to_string(&mut resp);
            if !resp.is_empty() {
                return resp;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no respondió en :{}", port);
}

// A6 — `request.json` y `json_decode(request.body)` salen del mismo parser: `-0` es `0` en los
// dos y un BOM al principio no es un 400.
#[test]
fn a6_request_json_matches_json_decode() {
    let port = free_port();
    let prog = format!(
        "require serve({p})\nserve on {p}\n    route \"POST /j\"\n        give {{\"v\": text(request.json.v), \"same\": text(request.json) == text(json_decode(request.body))}}\n",
        p = port
    );
    std::thread::spawn(move || {
        let _ = synsema_runtime::serve::run_serve_program(&prog, "a6.syn", false);
    });
    let r = post(port, br#"{"v": -0}"#);
    assert!(r.contains("{\"v\": \"0\", \"same\": true}"), "{}", r);
    let r = post(port, "\u{feff}{\"v\": 1.50}".as_bytes());
    assert!(r.starts_with("HTTP/1.1 200") && r.contains("{\"v\": \"1.5\", \"same\": true}"), "{}", r);
    let r = post(port, br#"{"v": 115792089237316195423570985008687907853269984665640564039457584007913129639935}"#);
    assert!(r.contains("115792089237316195423570985008687907853269984665640564039457584007913129639935"), "{}", r);
    assert!(post(port, b"{\"v\": NaN}").starts_with("HTTP/1.1 400"));
}

// A7 — Parquet: una duration se escribe (INT64 con su unidad en `synsema.durations`) y vuelve
// igual; la duration de Arrow (pyarrow, polars) se lee como duration, no como un entero sin unidad.
#[test]
fn a7_parquet_durations_round_trip() {
    assert_eq!(
        out("let rows be [{\"d\": duration(seconds = 5), \"n\": 1}, {\"d\": nothing, \"n\": 2}, {\"d\": duration(days = -2, seconds = 0.000007), \"n\": 3}]\nlet back be parquet_read(parquet_write(rows))\nprint(back == rows)\nprint(back[2][\"d\"])\nlet fine be [{\"d\": duration(seconds = 0.0000015)}]\nprint(parquet_read(parquet_write(fine)) == fine)\nprint(parquet_read(parquet_write([{\"n\": 7}])))"),
        vec!["true", "-P1DT23H59M59.999993S", "true", "[{n: 7}]"]
    );
    // Escrito con pyarrow 25: columnas duration[s], [ms], [us], [ns] y un int64 común.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").to_string_lossy().replace('\\', "/");
    let r = run_program(
        &format!("require file.read(\"{dir}/*\")\nlet rows be parquet_read(read_file_bytes(\"{dir}/parquet_duration_arrow.parquet\"))\neach r in rows\n    print(r)\nprint(parquet_read(parquet_write(rows)) == rows)\n"),
        "audit.syn",
    );
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(
        r.output,
        vec![
            "{s: PT5S, ms: PT1.5S, us: PT1H0.000007S, ns: PT0.000000001S, n: 1}",
            "{s: nothing, ms: PT0S, us: nothing, ns: PT2.000000001S, n: 2}",
            "{s: -PT2S, ms: nothing, us: PT0S, ns: nothing, n: 3}",
            "true",
        ]
    );
}

// B1 — index_of no copia la lista: un acierto temprano es O(1), como `in` y `contains`.
#[test]
fn b1_index_of_early_hit_is_constant() {
    let t = Instant::now();
    assert_eq!(
        out("let xs be range(100000)\nlet hits be 0\neach i in range(2000)\n    set hits to hits + index_of(xs, 0)\nprint(hits)\nprint(index_of(xs, (x) => x == 3))\nprint(index_of(xs, -1))"),
        vec!["0", "3", "nothing"]
    );
    let e = t.elapsed();
    assert!(e < Duration::from_secs(2), "2000 búsquedas tardaron {:?}", e);
}

// C1 — un alias deprecado en un módulo importado avisa al cargarlo, igual que en el principal.
#[test]
fn c1_deprecated_alias_in_imported_module_warns() {
    let r = run_files(&[("lib.syn", b"export task f()\n    give eth_rpc\n")], "use \"./lib.syn\" as lib\nprint(\"ok\")\n");
    assert!(r.success, "{:?}", r.errors);
    assert!(synsema_core::deprecated::warned_at_load().contains(&"eth_rpc".to_string()));
}

// C2 — el error nombra la función que el programa llamó, no la nueva.
#[test]
fn c2_old_blockchain_names_speak_for_themselves() {
    let e = fails("print(solana_message(1, 2))");
    assert!(e.contains("solana_message(params) takes 1 argument") && !e.contains("since v0.6.29"), "{}", e);
    let e = fails("print(algorand_tx_encode({}, 1))");
    assert!(e.contains("algorand_tx_encode(txn) takes 1 argument") && !e.contains("since v0.6.29"), "{}", e);
    assert!(fails("print(solana_tx(1, 2))").contains("since v0.6.29 solana_tx builds"));
}

// C3 — `//` como comentario: al principio de una línea es un error de parser con la pista; en
// `x // palabra` con una palabra indefinida, el error lo dice. `//` sigue siendo división entera.
#[test]
fn c3_c_style_comment_gets_a_hint() {
    let e = fails("let x be 1\n// comentario\nprint(x)\n");
    assert!(e.contains("comments in Synsema start with `--`"), "{}", e);
    let e = fails("let x be 1 // comentario\nprint(x)\n");
    assert!(e.contains("Undefined variable: 'comentario'") && e.contains("comments in Synsema start with `--`"), "{}", e);
    let e = fails("let x be 1 //comentario\nprint(x)\n");
    assert!(e.contains("Undefined variable") && !e.contains("comments"), "{}", e);
    assert_eq!(out("let comentario be 2\nprint(7 // comentario, 7 // 2, -7 // 2)"), vec!["3 3 -4"]);
}

// C4 — asignar fuera de rango dice dónde y el largo, como la lectura.
#[test]
fn c4_set_index_out_of_range_says_where() {
    let e = fails("let xs be [1, 2, 3]\nset xs[10] to 1\n");
    assert!(e.contains("audit.syn:2:") && e.contains("Index 10 out of bounds (list length 3)"), "{}", e);
    assert!(fails("let xs be [1, 2, 3]\nset xs[-4] to 1\n").contains("Index -4 out of bounds (list length 3)"));
    assert_eq!(out("let xs be [1, 2, 3]\nset xs[-1] to 9\nprint(xs)"), vec!["[1, 2, 9]"]);
}

// C5 — `bytes(33)` sugiere las dos formas.
#[test]
fn c5_bytes_of_number_hints() {
    let e = fails("print(bytes(33))");
    assert!(e.contains("int_to_bytes(33, size)") && e.contains("bytes([33])"), "{}", e);
    assert!(!fails("print(bytes(300))").contains("bytes([300])"));
}

// C6 — `Infinityx` y `NaNa` son basura, no un NaN.
#[test]
fn c6_json_garbage_is_not_nan() {
    for src in ["Infinityx", "NaNa", "[1, NaN_x]"] {
        let e = fails(&format!("print(json_decode(\"{}\"))", src));
        assert!(e.contains("invalid JSON: expected value at line 1") && !e.contains("NaN/Infinity"), "{}: {}", src, e);
    }
    assert!(fails("print(json_decode(\"NaN\"))").contains("NaN/Infinity is not JSON"));
    assert!(fails("print(json_decode(\"[Infinity]\"))").contains("NaN/Infinity is not JSON"));
    assert_eq!(out("print(json_decode(\"[NaN]\", allow_nan = true))"), vec!["[nan]"]);
}

// C7 — `%#z` sólo existe para parsear.
#[test]
fn c7_format_time_parse_only_specifier() {
    let e = fails("print(format_time(datetime(2026, 1, 1), \"%#z\"))");
    assert!(e.contains("%#z is a parsing-only specifier") && e.contains("%:z"), "{}", e);
    assert_eq!(out("print(format_time(datetime(2026, 1, 1), \"%%#z %:z\"))"), vec!["%#z +00:00"]);
}

// C8 — el aviso de `\u` sólo cuando el escape de verdad se decodifica.
#[test]
fn c8_check_unicode_escape_warning_only_when_decoded() {
    let bs = '\\';
    let warns = |lit: &str| check_warnings(&format!("print(\"{}\")\n", lit)).iter().any(|w| w.contains("is now an escape"));
    assert!(!warns(&format!("{}uD800", bs)), "un sustituto suelto queda literal");
    assert!(!warns(&format!("{}u{{110000}}", bs)), "fuera de Unicode queda literal");
    assert!(!warns(&format!("{}u{{1234567}}", bs)));
    assert!(warns(&format!("{}u00e9", bs)));
    assert!(warns(&format!("{}u{{1F600}}", bs)));
    assert!(warns(&format!("{}uD83D{}uDE00", bs, bs)));
}

// C9 — un task que escribe en su parámetro y no lo devuelve pierde la escritura (semántica de
// valor): `check` lo dice, como para `each r` + `set r[…]`.
#[test]
fn c9_check_task_param_write_lost() {
    let warns = |src: &str| check_warnings(src).iter().any(|w| w.contains("own copy of the argument"));
    assert!(warns("task touch(cfg)\n    set cfg[\"x\"] to 1\nlet c be {\"x\": 0}\ntouch(c)\n"));
    assert!(warns("task touch(cfg, n)\n    set cfg.x to n\n    give n\n"));
    // No avisa: lo devuelve, lo pasa a otra llamada, lo religa o lee lo que escribió.
    assert!(!warns("task touch(cfg)\n    set cfg[\"x\"] to 1\n    give cfg\n"));
    assert!(!warns("task touch(cfg)\n    set cfg[\"x\"] to 1\n    print(cfg)\n"));
    assert!(!warns("task touch(cfg)\n    set cfg[\"x\"] to 1\n    give cfg[\"x\"] + 1\n"));
    assert!(!warns("task touch(cfg)\n    set cfg to {}\n    give 1\n"));
    assert_eq!(out("task touch(cfg)\n    set cfg[\"x\"] to 1\nlet c be {\"x\": 0}\ntouch(c)\nprint(c)"), vec!["{x: 0}"]);
}

// C10 — la pista para un enum no exportado es `export enum`.
#[test]
fn c10_module_hint_for_enum() {
    let lib: &[u8] = b"enum Color\n    red\n    green\ntask helper()\n    give 1\nlet k be 2\nexport task f()\n    give 1\n";
    let e = run_files(&[("lib.syn", lib)], "use \"./lib.syn\" as lib\nprint(lib.Color)\n").errors.join("\n");
    assert!(e.contains("write `export enum Color` there"), "{}", e);
    let e = run_files(&[("lib.syn", lib)], "use \"./lib.syn\" as lib\nprint(lib.helper)\n").errors.join("\n");
    assert!(e.contains("write `export task helper` there"), "{}", e);
    let e = run_files(&[("lib.syn", lib)], "use \"./lib.syn\" as lib\nprint(lib.k)\n").errors.join("\n");
    assert!(e.contains("export let"), "{}", e);
}

// A1 (segunda vuelta) — `%Z`: UTC/GMT en cualquier caja (como Python); con `%z` en el mismo
// formato el offset identifica el instante y la abreviatura es texto; y si lo que no encaja es
// otra cosa, el error es el de siempre, no el de la abreviatura.
#[test]
fn a1b_parse_datetime_zone_abbreviation_edges() {
    assert_eq!(
        out("print(parse_datetime(\"24/09/2026 10:00 utc\", \"%d/%m/%Y %H:%M %Z\"))\nprint(parse_datetime(\"24/09/2026 10:00 +0530 (IST)\", \"%d/%m/%Y %H:%M %z %Z\"))\nprint(parse_datetime(\"2026-09-24 GMT\", \"%Y-%m-%d %Z\"))"),
        vec!["2026-09-24T10:00:00Z", "2026-09-24T10:00:00+05:30", "2026-09-24T00:00:00Z"]
    );
    let e = fails("print(parse_datetime(\"2026-13-24 10:00 UTC\", \"%Y-%m-%d %H:%M %Z\"))");
    assert!(e.contains("does not match") && !e.contains("abbreviation"), "{}", e);
}

// Un formato de sólo fecha es la medianoche de ese día (como `strptime` de Python y
// `parse_time`); con zona, la medianoche de esa zona.
#[test]
fn parse_datetime_date_only_format_is_midnight() {
    assert_eq!(
        out("print(parse_datetime(\"03/01/2026\", \"%d/%m/%Y\"))\nprint(parse_datetime(\"03/01/2026\", \"%d/%m/%Y\", \"Europe/Madrid\"))"),
        vec!["2026-01-03T00:00:00Z", "2026-01-03T00:00:00+01:00[Europe/Madrid]"]
    );
}

// C3 (segunda vuelta) — un comentario de C de varias palabras (el caso común) no parsea por
// lo que sigue al `//`; el error lo nombra igual. Un `//` dentro de un string o después de `--`
// no cuenta.
#[test]
fn c3b_c_style_comment_hint_on_parse_and_lex_errors() {
    for src in [
        "let x be 10 // this is a note\nprint(x)\n",
        "let x be 10\n    // indented note\nprint(x)\n",
        "print(1) // don't\n",
        "let x be 10 // TODO: fix\n",
    ] {
        let e = fails(src);
        assert!(e.contains("comments in Synsema start with `--`"), "{:?}: {}", src, e);
    }
    let e = fails("print(\"a // b\" is)\n");
    assert!(!e.contains("comments in Synsema"), "{}", e);
    assert_eq!(out("print(\"https://x.com\") -- note // not code"), vec!["https://x.com"]);
}

// D1 — cron con zona IANA: se registra, `cron_list` muestra la zona y el próximo disparo es
// el de esa zona (la regla de los cambios de hora está en los tests de `cronexpr`).
#[test]
fn d1_cron_every_with_an_iana_zone() {
    let o = out("require time\ntask a()\n    print(\"a\")\ncron_every(\"0 9 * * *\", a, {\"tz\": \"America/Santiago\"})\nlet j be cron_list()[0]\nprint(j.tz)\nlet next be to_timezone(datetime(j.next_run), \"America/Santiago\")\nprint(format_time(next, \"%H:%M\"))\ncron_cancel(\"a\")");
    assert_eq!(o, vec!["America/Santiago", "09:00"]);
    let e = fails("require time\ntask a()\n    print(\"a\")\ncron_every(\"0 9 * * *\", a, {\"tz\": \"Mars/Olympus\"})");
    assert!(e.contains("unknown time zone \"Mars/Olympus\""), "{}", e);
}

// D2 — un decimal con exponente es el valor exacto (mantisa × 10^exp), como `numeric` de
// Postgres: `decimal()`, las columnas `decimal` de CSV y el literal `…d` van por el mismo camino.
#[test]
fn d2_decimal_accepts_an_exponent() {
    assert_eq!(
        out("print(decimal(\"1e5\"), decimal(\"1.5E-3\"), decimal(\"1.50e1\"), decimal(\"-2.5e+2\"), decimal(\".5e1\"), 1.5e-3d, 2e3d)\nprint(decimal(\"1.5e-3\") == decimal(\"0.0015\"))\nprint(csv_parse(\"a\\n1.5e2\\n\", {\"types\": {\"a\": \"decimal\"}}))"),
        vec!["100000 0.0015 15.0 -250 5 0.0015 2000", "true", "[{a: 150}]"]
    );
    // Un exponente que pediría más de 4300 dígitos es un error, no memoria sin tope.
    for src in ["1e999999999", "1e4300", "1e-4301", "e5", "1e", "1e5.5", "1e+"] {
        assert!(fails(&format!("print(decimal(\"{}\"))", src)).contains("Cannot parse"), "{}", src);
    }
}

// Parquet — el esquema Arrow va en el archivo (`ARROW:schema`), como lo escriben pyarrow,
// polars y arrow-rs: pandas lee una duration como timedelta y un datetime con su zona IANA.
// (Verificado con pyarrow 25, pandas y polars; acá, que la clave está y Synsema la relee.)
#[test]
fn parquet_writes_the_arrow_schema() {
    let o = out("let rows be [{\"d\": duration(seconds = 90), \"w\": datetime(\"2026-01-03T10:00:00\", \"Europe/Madrid\"), \"n\": 1}]\nlet bin be parquet_write(rows)\nprint(contains(hex(bin), replace(hex(bytes(\"ARROW:schema\")), \"0x\", \"\")))\nprint(parquet_read(bin) == rows)");
    assert_eq!(o, vec!["true", "true"]);
}

// Parquet — una columna con nanosegundos y un valor que no entra en nanosegundos (±292 años) no
// se escribe en microsegundos perdiéndolos en silencio: es un error que nombra la columna.
#[test]
fn parquet_refuses_to_drop_nanoseconds() {
    let far = "let far be datetime(\"2400-01-01T00:00:00Z\") - datetime(\"1800-01-01T00:00:00Z\")\n";
    let e = fails(&format!("{far}print(parquet_write([{{\"d\": duration(seconds = 0.0000015)}}, {{\"d\": far}}]))"));
    assert!(e.contains("column \"d\" has a duration with nanoseconds and one beyond ±292 years") && e.contains("text(x)"), "{}", e);
    let e = fails("print(parquet_write([{\"t\": datetime(\"2026-01-03T10:00:00.000000001Z\")}, {\"t\": datetime(\"2400-01-01T00:00:00Z\")}]))");
    assert!(e.contains("column \"t\" has a datetime with nanoseconds and one outside 1677-2262"), "{}", e);
    // Sin nanosegundos, lo lejano va en microsegundos como siempre; con todo en rango, en nanosegundos.
    assert_eq!(
        out(&format!("{far}let a be [{{\"d\": far}}, {{\"d\": duration(seconds = 1)}}]\nprint(parquet_read(parquet_write(a)) == a)\nlet b be [{{\"t\": datetime(\"2026-01-03T10:00:00.000000001Z\")}}]\nprint(parquet_read(parquet_write(b)) == b)")),
        vec!["true", "true"]
    );
}

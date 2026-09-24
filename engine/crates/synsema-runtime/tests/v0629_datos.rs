//! v0.6.29 — datos (specs/lenguaje/datos.md): reducciones con `nothing`/NaN/eje/ddof/decimal,
//! arrays (elemento a elemento, slicing, máscaras, combinar, ubicar, acumular), estadística y
//! ajuste, tablas (group_by, summarize, count_by, join, pivot, faltantes), azar con semilla,
//! fechas/instantes/duraciones, CSV tipado, JSON Lines y el linaje del recibo.

use synsema_runtime::engine::run_program;

fn out(src: &str) -> Vec<String> {
    let r = run_program(src, "v0629_datos.syn");
    assert!(r.success, "falló: {:?}\n{}", r.errors, src);
    r.output
}

fn fails(src: &str) -> String {
    let r = run_program(src, "v0629_datos.syn");
    assert!(!r.success, "tenía que fallar:\n{}\nsalida: {:?}", src, r.output);
    r.errors.join("\n")
}

#[test]
fn reductions_missing_nan_ddof_decimal() {
    assert_eq!(
        out("print(std([1,2,3,4]), std([1,2,3,4], ddof = 0), var([1,2,3,4]))\nprint(mean([1.5d, 2.5d]), median([1d, 2d, 4d, 8d]), sum([0.1d, 0.2d]))\nprint(mean([1, nothing, 3]), sum([1, nan]), min([nan, 3]), max([3, nan]), median([3, nothing, 1]))"),
        vec!["1.2909944487358056 1.118033988749895 1.6666666666666667", "2.0 3 0.3", "2.0 nan nan nan 2.0"]
    );
    assert_eq!(out("print(quantile([1,2,3,4], 0.5), percentile([1,2,3,4], 50), round_to(2.675, 2), round_to(1.005d, 2), round_to(0.125, 2))"), vec!["2.5 2.5 2.67 1.00 0.12"]);
    assert!(fails("print(mean([nothing]))").contains("every value is missing"));
    assert!(fails("print(quantile([1], 50))").contains("between 0 and 1"));
    assert!(fails("print(sum([1], axis = 0))").contains("axis applies to arrays"));
}

#[test]
fn arrays() {
    assert_eq!(
        out("let m be array([[1,2],[3,4]])\nprint(sum(m, axis = 0), sum(m, 1), mean(m, axis = -1), std(m, axis = 0, ddof = 0))\nprint(sqrt(array([4, 9])), m ** 2, m // 3, length(m), size(m), slice(m, -1), m[-1])\nprint(apply(array([1,2,3]), (x) => x * 10), where(array([1,5,2,8]), (x) => x > 2), abs(array([-1, 2])), floor(array([1.5, -1.5])))"),
        vec!["[4, 6] [3, 7] [1.5, 3.5] [1, 1]", "[2, 3] [[1, 4], [9, 16]] [[0, 0], [1, 1]] 2 4 [[3, 4]] [3, 4]", "[10, 20, 30] [5, 8] [1, 2] [1, -2]"]
    );
    assert_eq!(
        out("print(concat([array([1,2]), array([3])]), stack([array([1,2]), array([3,4])]), concat([array([[1],[2]]), array([[3],[4]])], axis = 1))\nprint(argmax([3,9,2]), argmin(array([3,9,2])), argmax(array([[1,5],[7,2]]), axis = 1), cumsum([1,2,3]), cumsum(array([1,2,3])), diff([1,4,9]), diff(array([1,4,9])))"),
        vec!["[1, 2, 3] [[1, 2], [3, 4]] [[1, 3], [2, 4]]", "1 2 [1, 0] [1, 3, 6] [1, 3, 6] [3, 5] [3, 5]"]
    );
    assert!(fails("print(dot(array([[1]]), array([[1]])))").contains("matmul"));
    assert_eq!(out("print(dot(array([1,2]), array([3,4])))"), vec!["11.0"]);
}

#[test]
fn statistics_and_fitting() {
    assert_eq!(
        out("print(corr([1,2,3],[2,4,6]), cov([1,2,3],[1,2,3]), cov([1,2,3],[1,2,3], ddof = 0), mode([1,2,2,3]), mode([\"a\", \"b\", \"a\"]))\nlet c be polyfit([0,1,2,3],[1,3,5,7],1)\nprint(round_to(c[0], 9), round_to(c[1], 9), round_to(polyval(c, 10), 6))\nlet x be lstsq(array([[1,0],[0,1],[1,1]]), array([1,2,3]))\nprint(round_to(x[0], 9), round_to(x[1], 9))"),
        vec!["1.0 1.0 0.6666666666666666 2 a", "2.0 1.0 21.0", "1.0 2.0"]
    );
}

#[test]
fn tables() {
    let rows = r#"let rows be [{"r": "n", "m": 10}, {"r": "s", "m": 5}, {"r": "n", "m": 1}, {"r": "s", "m": nothing}]
"#;
    assert_eq!(
        out(&format!(r#"{}print(group_by(rows, "r"))
print(summarize(rows, "r", {{"total": sum_of("m"), "n": count(), "avg": mean_of("m"), "top": max_of("m")}}))
print(count_by(rows, "r"), count_by(["x", "y", "x"]))
print(group_by([1, 1.0, 2], (v) => v))"#, rows)),
        vec![
            r#"[{key: "n", items: [{r: "n", m: 10}, {r: "n", m: 1}]}, {key: "s", items: [{r: "s", m: 5}, {r: "s", m: nothing}]}]"#,
            r#"[{r: "n", total: 11, n: 2, avg: 5.5, top: 10}, {r: "s", total: 5, n: 2, avg: 5.0, top: 5}]"#,
            r#"[{key: "n", count: 2}, {key: "s", count: 2}] [{key: "x", count: 2}, {key: "y", count: 1}]"#,
            "[{key: 1, items: [1, 1.0]}, {key: 2, items: [2]}]",
        ]
    );
    assert_eq!(
        out(r#"print(join([{"id": 1, "a": "x"}, {"id": 2, "a": "y"}], [{"id": 1, "a": "z"}], "id", "left"))
print(join([{"id": 1}], [{"id": 1, "v": 2}, {"id": 3, "v": 4}], "id", "outer"))
print(join(["a", "b"], "-"))
print(pivot([{"d": "lu", "p": "a", "v": 1}, {"d": "lu", "p": "b", "v": 2}, {"d": "ma", "p": "a", "v": 3}], "d", "p", "v"))"#),
        vec![
            r#"[{id: 1, a: "x", a_right: "z"}, {id: 2, a: "y", a_right: nothing}]"#,
            "[{id: 1, v: 2}, {id: 3, v: 4}]",
            "a-b",
            r#"[{d: "lu", a: 1, b: 2}, {d: "ma", a: 3, b: nothing}]"#,
        ]
    );
    assert!(fails(r#"print(pivot([{"d": 1, "p": "a", "v": 1}, {"d": 1, "p": "a", "v": 2}], "d", "p", "v"))"#).contains("pass agg"));
    assert_eq!(
        out(&format!(r#"{}print(fill_missing([1, nothing], 0), drop_missing(rows, "m"), fill_missing(rows, {{"m": 0}})[3], is_missing(nothing), fill_nan([nan, 1], 0))"#, rows)),
        vec![r#"[1, 0] [{r: "n", m: 10}, {r: "s", m: 5}, {r: "n", m: 1}] {r: "s", m: 0} true [0, 1]"#]
    );
}

#[test]
fn seeded_random_is_reproducible() {
    assert_eq!(
        out("let g be rng(42)\nlet h be rng(42)\nprint(g() == h(), random_normal(g) == random_normal(h), shuffle(rng(1), [1,2,3,4,5]) == shuffle(rng(1), [1,2,3,4,5]))\nlet s be sample(rng(7), range(0, 100), 5)\nprint(length(s), length(unique(s)), choice(rng(3), [\"a\"]))\nlet u be rng(9)\nlet v be u()\nprint(v >= 0 and v < 1)"),
        vec!["true true true", "5 5 a", "true"]
    );
    // Sin semilla sigue pidiendo la capability `random`; con semilla es puro.
    assert!(fails("print(random())").contains("random"));
    assert_eq!(
        out("let a be rng(5)\nlet b be rng(5)\nprint(random(a) == random(b), random_int(a, 1, 6) == random_int(b, 1, 6))\nlet k be random_int(rng(1), 1, 6)\nprint(k >= 1 and k <= 6)"),
        vec!["true true", "true"]
    );
    assert!(fails("print(random_int(rng(1), 1.5, 6))").contains("integer"));
}

#[test]
fn dates_datetimes_durations() {
    assert_eq!(
        out(r#"let d be date(2026, 1, 31)
print(d, add_months(d, 1), d + duration(days = 1), date("2026-03-01") - d, type_of(d))
let t be datetime("2026-03-29T01:30:00", "Europe/Madrid")
print(t, t + duration(hours = 1), to_timezone(t, "UTC"), truncate(t, "month"))
print(date_parts(d).weekday, date_range(date(2026,1,1), date(2026,1,3)), sort([date(2026,2,1), date(2026,1,1)]))
print(in_units(duration(hours = 1, minutes = 30), "minutes"), timestamp(datetime("1970-01-01T00:01:00Z")), datetime(60) == datetime("1970-01-01T00:01:00Z"))
print(format_time(d, "%d/%m/%Y"), parse_time("2026-01-03", "%Y-%m-%d"), json_encode({"when": d}))"#),
        vec![
            "2026-01-31 2026-02-28 2026-02-01 P29D date",
            "2026-03-29T01:30:00+01:00[Europe/Madrid] 2026-03-29T03:30:00+02:00[Europe/Madrid] 2026-03-29T00:30:00Z 2026-03-01T00:00:00+01:00[Europe/Madrid]",
            "6 [2026-01-01, 2026-01-02, 2026-01-03] [2026-01-01, 2026-02-01]",
            "90.0 60.0 true",
            r#"31/01/2026 1767398400.0 {"when": "2026-01-31"}"#,
        ]
    );
    // min/max de fechas; días de calendario vs 24 h exactas alrededor del cambio de hora.
    assert_eq!(
        out(r#"print(min([date(2026,2,1), date(2026,1,1)]), max([date(2026,2,1), date(2026,1,1)]))
let noon be datetime("2026-03-28T12:00:00", "Europe/Madrid")
print(add_days(noon, 1), noon + duration(days = 1), date_parts(0).weekday)"#),
        vec![
            "2026-01-01 2026-02-01",
            "2026-03-29T12:00:00+02:00[Europe/Madrid] 2026-03-29T13:00:00+02:00[Europe/Madrid] 4",
        ]
    );
    assert!(fails("print(std([1, 2, 3], 0))").contains("ddof = 0"));
    assert!(fails(r#"print(datetime("2026-03-29T02:30:00", "Europe/Madrid"))"#).contains("daylight-saving gap"));
    assert!(fails(r#"print(date(2026, 2, 30))"#).contains("not a valid calendar date"));
    assert!(fails(r#"print(date(2026, 1, 1) + duration(hours = 1))"#).contains("whole days"));
    assert!(fails(r#"print(datetime("2026-01-01T00:00:00", "Mars/Olympus"))"#).contains("IANA"));
}

#[test]
fn csv_and_json_lines() {
    assert_eq!(
        out("print(csv_parse(\"a,b,c,d\\n007,,2026-01-02,1.50\\n\", {\"types\": {\"a\": \"int\", \"c\": \"date\", \"d\": \"decimal\"}}))\nprint(csv_parse(\"a,b\\n007,\\n\"))\nprint(jsonl_decode(jsonl_encode([{\"a\": 1}, [2]])), jsonl_decode(\"{\\n\", nothing))"),
        vec![r#"[{a: 7, b: nothing, c: 2026-01-02, d: 1.50}]"#, r#"[{a: "007", b: nothing}]"#, "[{a: 1}, [2]] nothing"]
    );
    assert!(fails("print(csv_parse(\"a\\nx\\n\", {\"types\": {\"a\": \"int\"}}))").contains("line 2"));
}

#[test]
fn lineage_is_recorded_by_the_engine() {
    let dir = std::env::temp_dir().join(format!("syn_lineage_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let f = dir.join("in.csv");
    std::fs::write(&f, "a\n1\n").unwrap();
    let path = f.to_string_lossy().replace('\\', "/");
    let src = format!(
        "require file.read(\"{dir}/*\")\nlet t be read_file(\"{path}\")\nlet l be lineage()\nprint(length(l), l[0].source, \"0x\" + l[0].sha256 == hex(sha256(t)), l[0].bytes)\nlet r be receipt()\nprint(length(r.credentialSubject.inputs))",
        dir = dir.to_string_lossy().replace('\\', "/"),
        path = path
    );
    let o = out(&src);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(o, vec!["1 read_file true 4".to_string(), "1".to_string()]);
}

#[test]
fn parquet_round_trip_and_polars_interop() {
    // Escrito por polars 1.44 (zstd, su default): Int64, String, Float64, Boolean, Date,
    // Datetime(µs, UTC), Decimal(10,2), con nulos.
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/polars_1_44_zstd.parquet");
    let dir = fixture.parent().unwrap().to_string_lossy().replace('\\', "/");
    let src = format!(
        r#"require file.read("{dir}/*")
let rows be parquet_read(read_file_bytes("{dir}/polars_1_44_zstd.parquet"))
print(rows[0])
print(rows[2].id, rows[1].name, type_of(rows[0].d), type_of(rows[0].amt))
print(parquet_read(parquet_write(rows)) == rows, parquet_read(parquet_write(rows, {{"compression": "zstd"}})) == rows)
let mine be [{{"n": 10**18, "t": "hé", "b": bytes([1, 2]), "dec": 12.345d}}, {{"n": nothing, "t": "x", "b": nothing, "dec": 1d}}]
print(parquet_read(parquet_write(mine, {{"compression": "gzip"}})))"#,
        dir = dir
    );
    assert_eq!(
        out(&src),
        vec![
            r#"{id: 1, name: "a", x: 1.5, ok: true, d: 2026-01-02, ts: 2026-01-02T03:04:05Z, amt: 1.50}"#,
            "nothing nothing date decimal",
            "true true",
            r#"[{n: 1000000000000000000, t: "hé", b: bytes(0102), dec: 12.345}, {n: nothing, t: "x", b: nothing, dec: 1.000}]"#,
        ]
    );
    assert!(fails(r#"print(parquet_write([{"a": 1}, {"a": "x"}]))"#).contains("mixes"));
    assert!(fails(r#"print(parquet_write([{"a": [1]}]))"#).contains("json_encode"));
    assert!(fails(r#"print(parquet_read(bytes("nope")))"#).contains("not a Parquet file"));
}

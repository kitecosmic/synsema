//! v0.6.65 — tablas por columnas: los builtins de stdlib (`hash`, `json_encode`) sobre una
//! tabla. El tipo y sus operaciones viven en los tests de core (`v0665_tables.rs`); acá van
//! los cruces con lo que se registra en runtime.

use synsema_runtime::engine::run_program;

fn out(body: &str) -> Vec<String> {
    let r = run_program(body, "tables.syn");
    assert!(r.success, "falló: {:?}\n{}", r.errors, body);
    r.output
}

fn t(expr: &str) {
    assert_eq!(
        out(&format!("print(text({}))", expr)),
        vec!["true".to_string()],
        "expr: {}",
        expr
    );
}

const ROWS: &str = r#"[{"k": 1, "v": 1.5}, {"k": 2, "v": 2.5}, {"k": 3, "v": 3.5}]"#;

/// `hash` (v0.6.64) sobre una tabla: estable entre llamadas y entre la tabla y una vista con
/// la misma ventana; distinto si cambia una celda.
#[test]
fn hash_of_a_table_is_stable() {
    t(&format!("hash(table({})) == hash(table({}))", ROWS, ROWS));
    t(&format!(
        "hash(table({})) != hash(table([{{\"k\": 1, \"v\": 1.5}}, {{\"k\": 2, \"v\": 2.5}}, {{\"k\": 3, \"v\": 3.5001}}]))",
        ROWS
    ));
    t(&format!("hash(slice(table({}), 0, 3)) == hash(table({}))", ROWS, ROWS));
    // La ley de igualdad: tablas `==` → mismo hash. Y una tabla igualada celda a celda pero
    // construida distinto (con `to_rows` de por medio) también.
    t(&format!(
        "hash(table(to_rows(table({})))) == hash(table({}))",
        ROWS, ROWS
    ));
    // Nulos: `nothing` y `nothing` igualan.
    t("hash(table([{\"k\": 1, \"v\": nothing}])) == hash(table(to_rows(table([{\"k\": 1, \"v\": nothing}]))))");
}

/// `json_encode(t)` es byte a byte el JSON de sus filas (diseño §2).
#[test]
fn json_encode_of_a_table_is_the_rows_one() {
    t(&format!("json_encode(table({})) == json_encode(to_rows(table({})))", ROWS, ROWS));
    // Y de verdad: los bytes (el formato de json_encode: espacios tras `:` y `,`).
    assert_eq!(
        out(&format!(
            "print(json_encode(table({})))",
            r#"[{"k": 1, "v": 1.5}, {"k": 2, "v": 2.5}]"#
        )),
        vec![r#"[{"k": 1, "v": 1.5}, {"k": 2, "v": 2.5}]"#.to_string()]
    );
}

/// La receta "table-v1" del linaje (columns.rs `lineage_sha256`): sensible a los nulos y a la
/// ventana — una vista con offset NO hashea como la tabla entera.
#[test]
fn table_v1_hash_is_sensitive_to_nulls_and_windows() {
    t(r#"hash(table([{"k": 1, "v": nothing}])) != hash(table([{"k": 1, "v": 0.0}]))"#);
    t(r#"hash(slice(table([{"k": 1, "v": 1.5}, {"k": 2, "v": 2.5}, {"k": 3, "v": 3.5}]), 1, 3)) == hash(table([{"k": 2, "v": 2.5}, {"k": 3, "v": 3.5}]))"#);
    t(r#"hash(slice(table([{"k": 1, "v": 1.5}, {"k": 2, "v": 2.5}, {"k": 3, "v": 3.5}]), 1, 3)) != hash(table([{"k": 1, "v": 1.5}, {"k": 2, "v": 2.5}, {"k": 3, "v": 3.5}]))"#);
}

/// Una columna anidada (listas) manda la lectura por el camino de filas (diseño §4: el
/// fallback) y vuelve como tabla con sus listas intactas.
#[test]
fn parquet_nested_columns_fall_back_to_rows_as_a_table() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/parquet_nested_list.parquet");
    let dir = fixture.parent().unwrap().to_string_lossy().replace('\\', "/");
    let src = format!(
        r#"require file.read("{dir}/*")
let t be parquet_read(read_file_bytes("{dir}/parquet_nested_list.parquet"))
print(type_of(t))
print(t[0].tags, t[1].tags, t[2].tags)
print(t[0].id, t[2].id)"#,
        dir = dir
    );
    assert_eq!(
        out(&src),
        vec!["table", r#"["a", "b"] [] ["c"]"#, "1 3"]
    );
}

/// T3 (diseño §4): `parquet_read`/`parquet_scan` devuelven una TABLA, leída por columnas.
/// Los tipos exactos del camino de filas se conservan (diseño: el mismo mapeo que `convert`).
#[test]
fn parquet_read_gives_a_table_with_the_same_types() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/polars_1_44_zstd.parquet");
    let dir = fixture.parent().unwrap().to_string_lossy().replace('\\', "/");
    let src = format!(
        r#"require file.read("{dir}/*")
let t be parquet_read(read_file_bytes("{dir}/polars_1_44_zstd.parquet"))
print(type_of(t))
print(length(columns(t)), columns(t)[0])
print(t[2].id, t[1].name, type_of(t[0].d), type_of(t[0].amt))
print(t[0].id, t[0].x)
print(text(summarize(t, "ok", {{"n": count(), "s": sum_of("x")}}) == summarize(to_rows(t), "ok", {{"n": count(), "s": sum_of("x")}})))"#,
        dir = dir
    );
    assert_eq!(
        out(&src),
        vec![
            "table",
            "7 id",
            "nothing nothing date decimal",
            "1 1.5",
            "true",
        ]
    );
    // La lectura y la escritura cierran redondo: escribir una tabla y leerla da lo mismo
    // (con snappy y con zstd).
    let rt = format!(
        r#"require file.read("{dir}/*")
let t be parquet_read(read_file_bytes("{dir}/polars_1_44_zstd.parquet"))
print(parquet_read(parquet_write(t)) == t, parquet_read(parquet_write(t, {{"compression": "zstd"}})) == t)"#,
        dir = dir
    );
    assert_eq!(out(&rt), vec!["true true".to_string()]);
}

/// Las opciones de lectura (columns, limit) sobre el camino por columnas.
#[test]
fn parquet_options_on_the_columnar_path() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/polars_1_44_zstd.parquet");
    let dir = fixture.parent().unwrap().to_string_lossy().replace('\\', "/");
    let src = format!(
        r#"require file.read("{dir}/*")
print(type_of(parquet_scan("{dir}/polars_1_44_zstd.parquet")))
print(columns(parquet_scan("{dir}/polars_1_44_zstd.parquet", {{"columns": ["id", "x"]}})))
let p be parquet_scan("{dir}/polars_1_44_zstd.parquet", {{"columns": ["id", "x"]}})
print(p[0].id, p[0].x)
print(length(parquet_scan("{dir}/polars_1_44_zstd.parquet", {{"limit": 2}})))"#,
        dir = dir
    );
    assert_eq!(
        out(&src),
        vec![
            "table",
            r#"["id", "x"]"#,
            "1 1.5",
            "2",
        ]
    );
}

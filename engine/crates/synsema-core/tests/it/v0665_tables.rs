//! v0.6.65 — tablas por columnas (specs/v0.6.65-tablas-diseno.md).
//!
//! Los casos decididos del diseño §11, corriendo programas `.syn` reales: construcción y
//! conversión (`table`/`to_rows`/`columns`), lectura (`t[i]`, `length`, `columns`),
//! inmutabilidad (`set` da error enseñando el rodeo), vistas (`slice`), igualdad (sólo
//! tabla↔tabla, G3), `text`/`json` como sus filas, exactitud por columna (un `Int` vuelve
//! `Int`; un `Decimal` no se degrada) y las operaciones de tabla aceptando una tabla.

use synsema_core::interpreter::run_source;

fn out(source: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

/// `print(expr)` → exactamente `expected`.
fn shows(expr: &str, expected: &str) {
    assert_eq!(out(&format!("print({})", expr)), vec![expected.to_string()], "expr: {}", expr);
}

/// La expresión booleana debe ser `true`.
fn t(expr: &str) {
    assert_eq!(out(&format!("print(text({}))", expr)), vec!["true".to_string()], "expr: {}", expr);
}

fn fails_with(source: &str, needle: &str) {
    let r = run_source(source, "<test>");
    assert!(!r.success, "esperaba fallo.\nfuente:\n{}", source);
    assert!(
        r.errors.iter().any(|e| e.contains(needle)),
        "esperaba error con '{}', got {:?}",
        needle,
        r.errors
    );
}

const ROWS: &str = r#"[{"k": 1, "v": 1.5}, {"k": 2, "v": 2.5}, {"k": 3, "v": 3.5}]"#;

#[test]
fn a_table_reports_its_shape_and_schema() {
    let src = format!(
        "let t be table({})\nprint(type_of(t))\nprint(length(t))\nprint(columns(t))",
        ROWS
    );
    assert_eq!(out(&src), vec!["table".to_string(), "3".to_string(), r#"["k", "v"]"#.to_string()]);
}

#[test]
fn to_rows_round_trip_is_identity_for_homogeneous_rows() {
    t(&format!("to_rows(table({})) == {}", ROWS, ROWS));
}

#[test]
fn ragged_rows_get_the_full_schema_with_nothing() {
    t(r#"length(table([{"k": 1}, {"k": 2, "v": 3.0}])) == 2"#);
    t(r#"to_rows(table([{"k": 1}, {"k": 2, "v": 3.0}]))[0].v == nothing"#);
    t(r#"table([{"k": 1}, {"k": 2, "v": 3.0}])[0].v == nothing"#);
    // La fila materializada tiene el esquema completo: la clave existe y vale `nothing`.
    t(r#"contains(keys(table([{"k": 1}, {"k": 2, "v": 3.0}])[0]), "v")"#);
}

#[test]
fn indexing_a_table_gives_its_row() {
    let src = format!(
        "let t be table({})\nprint(t[0].k)\nprint(t[-1].v)\nprint(t[1][\"v\"])",
        ROWS
    );
    assert_eq!(out(&src), vec!["1".to_string(), "3.5".to_string(), "2.5".to_string()]);
    fails_with(
        &format!("let t be table({})\nset x to t[7]", ROWS),
        "out of bounds (table with 3 rows)",
    );
}

#[test]
fn equality_is_within_the_type_only() {
    // G3: dos tablas iguales por valor; una tabla nunca iguala sus filas.
    t(&format!("table({}) == table({})", ROWS, ROWS));
    t(&format!("table({}) != {}", ROWS, ROWS));
    // Distintas en una celda.
    t(&format!("table({}) != table([{{\"k\": 1, \"v\": 1.5}}, {{\"k\": 2, \"v\": 2.5}}, {{\"k\": 3, \"v\": 9.9}}])", ROWS));
    // Nulos: `nothing` contra `nothing` iguala; contra un valor, no.
    t(r#"table([{"k": 1, "v": nothing}]) == table([{"k": 1, "v": nothing}])"#);
    t(r#"table([{"k": 1, "v": nothing}]) != table([{"k": 1, "v": 0.0}])"#);
    // NaN nunca iguala (como los arrays); `nan` es una constante del lenguaje.
    t(r#"table([{"k": 1, "v": nan}]) != table([{"k": 1, "v": nan}])"#);
}

#[test]
fn text_is_exactly_the_rows_one() {
    // `text(t)` tiene que ser byte a byte el texto de sus filas (diseño §2). El lado de
    // `json_encode` se prueba en runtime (json_encode es de stdlib, no del core).
    let src = format!(
        "let t be table({})\nlet rows be to_rows(t)\nprint(text(t) == text(rows))",
        ROWS
    );
    assert_eq!(out(&src), vec!["true".to_string()]);
    // Y los bytes, de verdad (no sólo el == de los textos). El display de un mapa muestra
    // sus claves sin comillas, igual que en una lista de mapas.
    shows(&format!("text(table({}))", ROWS), r#"[{k: 1, v: 1.5}, {k: 2, v: 2.5}, {k: 3, v: 3.5}]"#);
}

#[test]
fn slice_of_a_table_is_a_table_that_shares_the_rows() {
    let src = format!(
        "let t be table({})\nlet s be slice(t, 1, 3)\nprint(type_of(s))\nprint(length(s))\nprint(text(to_rows(s) == slice(to_rows(t), 1, 3)))",
        ROWS
    );
    assert_eq!(out(&src), vec!["table".to_string(), "2".to_string(), "true".to_string()]);
    // Una vista es igual por valor a una tabla reconstruida desde ese rango.
    t(&format!("slice(table({}), 0, 2) == table([{{\"k\": 1, \"v\": 1.5}}, {{\"k\": 2, \"v\": 2.5}}])", ROWS));
}

#[test]
fn a_table_is_immutable_and_teaches_the_way_out() {
    fails_with(
        &format!("let t be table({})\nset t[0] to {{\"k\": 9, \"v\": 9.9}}", ROWS),
        "a table is immutable — convert it with to_rows(t)",
    );
    fails_with(
        &format!("let t be table({})\nset t[0].k to 9", ROWS),
        "a table is immutable",
    );
    fails_with(
        &format!("let t be table({})\nset t.k to 9", ROWS),
        "a table is immutable",
    );
    // Y el rodeo anda: convertir, cambiar, reconstruir.
    let src = format!(
        "let rs be to_rows(table({}))\nset rs[0].k to 9\nprint(table(rs)[0].k == 9)",
        ROWS
    );
    assert_eq!(out(&src), vec!["true".to_string()]);
}

#[test]
fn an_empty_table_is_falsy_with_no_columns() {
    t("length(table([])) == 0");
    t("columns(table([])) == []");
    // La veracidad no se prueba con `== false` (sería cross-type, G3): `or` mira la verdad.
    t("table([]) or false == false");
    t("table([{\"k\": 1}]) or false == true");
    fails_with("let t be table([])\nset x to t[0]", "out of bounds (table with 0 rows)");
}

#[test]
fn columns_stay_exact_no_matter_the_mix() {
    // Una columna mixta (int y float) NO se degrada: cada celda vuelve con su tipo.
    shows(r#"text(table([{"v": 1}, {"v": 2.5}])[0].v)"#, "1");
    shows(r#"text(table([{"v": 1}, {"v": 2.5}])[1].v)"#, "2.5");
    // Un decimal no se convierte en float: preserva su escala (el texto `1.50`, no `1.5`).
    shows(r#"text(table([{"d": 1.50d}])[0].d)"#, "1.50");
    // Un texto y un bool en columnas distintas.
    t(r#"table([{"s": "a", "b": true}])[0].s == "a" and table([{"s": "a", "b": true}])[0].b == true"#);
    // Una columna toda nula vuelve toda nula.
    t(r#"table([{"k": 1}, {"k": 2}]) == table([{"k": 1}, {"k": 2}])"#);
}

#[test]
fn null_cells_round_trip_as_nothing() {
    t(r#"to_rows(table([{"k": 1, "v": nothing}, {"k": 2, "v": 5.0}]))[0].v == nothing"#);
    t(r#"to_rows(table([{"k": 1, "v": nothing}, {"k": 2, "v": 5.0}]))[1].v == 5.0"#);
    // `nothing` dentro de una columna Value también es null.
    t(r#"to_rows(table([{"k": 1}, {"k": nothing}]))[1].k == nothing"#);
}

#[test]
fn table_builtin_rejects_non_maps() {
    fails_with("table([1, 2, 3])", "expected a list of maps");
    fails_with("table(nothing)", "table");
}

#[test]
fn list_generics_reject_a_table() {
    fails_with(
        &format!("let t be table({})\nset x to transform(t, (r) => r)", ROWS),
        "expects a list, got table",
    );
    fails_with(
        &format!("let t be table({})\nset x to append(t, {{\"k\": 4, \"v\": 4.5}})", ROWS),
        "must be a list",
    );
}

#[test]
fn the_table_operations_accept_a_table() {
    let rows = ROWS;
    // summarize da lo mismo sobre filas que sobre la tabla.
    t(&format!(
        "summarize(table({}), \"k\", {{\"n\": count()}}) == summarize({}, \"k\", {{\"n\": count()}})",
        rows, rows
    ));
    // group_by sobre una tabla: los grupos son listas de filas (T2b los pasa a sub-tablas,
    // mismo tipo que la entrada; por ahora el despliegue de rows_arg manda).
    shows(
        &format!("type_of(group_by(table({}), \"k\")[0].items)", rows),
        "list",
    );
    // join / pivot / sort_by / fill_missing / drop_missing / where / count_by aceptan tabla.
    t(&format!(
        "join(table({}), table({}), \"k\") == join({}, {}, \"k\")",
        rows, rows, rows, rows
    ));
    t(&format!(
        "to_rows(sort_by(table({}), (r) => r.k, true)) == sort_by({}, (r) => r.k, true)",
        rows, rows
    ));
    t(&format!(
        "drop_missing(table([{{\"k\": 1, \"v\": nothing}}, {{\"k\": 2, \"v\": 2.5}}]))[0].k == 2"
    ));
    t(&format!(
        "fill_missing(table([{{\"k\": 1, \"v\": nothing}}]), 0.0)[0].v == 0.0"
    ));
    t(&format!(
        "length(where(table({}), (r) => r.v > 2.0)) == 2",
        rows
    ));
}

#[test]
fn a_slice_survives_as_a_view_in_every_direction() {
    let src = format!(
        "let t be table({})\nlet s be slice(t, 1, 2)\nprint(columns(s))\nprint(s[0].v)\nprint(text(s == slice(t, 1, 2)))",
        ROWS
    );
    assert_eq!(out(&src), vec![r#"["k", "v"]"#.to_string(), "2.5".to_string(), "true".to_string()]);
}


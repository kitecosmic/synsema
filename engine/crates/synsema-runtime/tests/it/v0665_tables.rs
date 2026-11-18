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

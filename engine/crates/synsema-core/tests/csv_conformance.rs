//! Conformidad de CSV (Batch 8): `csv_parse`/`csv_encode` corriendo programas `.syn`
//! REALES por el intérprete de core. Cubre RFC 4180 (quoting, escapes, CRLF/LF, BOM),
//! round-trips, opts (headers/delimiter/numbers/eol) y los errores claros con línea (G5).
//! El caso `secret` → `[redacted]` (G8) vive en los unit tests de `csv.rs` y en los e2e
//! del runtime (el builtin `secret()` no se registra en core).

use synsema_core::interpreter::run_source;

fn out(source: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
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

// =========================================================
// Parse: forma default (lista de mapas) + lossless
// =========================================================

#[test]
fn parse_default_headers_lossless() {
    let o = out(
        "let rows be csv_parse(\"a,b\\r\\n1,x\\r\\n00123,y\\r\\n\")\n\
         print(length(rows))\n\
         print(rows[0][\"a\"])\n\
         print(type_of(rows[0][\"a\"]))\n\
         print(rows[1][\"a\"])",
    );
    // Default lossless: TODO texto ("00123" no se convierte en 123).
    assert_eq!(o, vec!["2", "1", "text", "00123"]);
}

#[test]
fn parse_numbers_opt() {
    let o = out(
        "let rows be csv_parse(\"n,s,z\\n42,abc,00123\\n\", {\"numbers\": true})\n\
         print(type_of(rows[0][\"n\"]))\n\
         print(rows[0][\"n\"])\n\
         print(type_of(rows[0][\"s\"]))\n\
         print(rows[0][\"z\"])",
    );
    // \"42\" → Number; \"abc\" queda texto; \"00123\" con numbers:true parsea (123).
    assert_eq!(o, vec!["number", "42", "text", "123"]);
}

#[test]
fn parse_headers_false_lists() {
    let o = out(
        "let rows be csv_parse(\"1,2\\n3,4\\n\", {\"headers\": false})\n\
         print(length(rows))\n\
         print(rows[1][0])",
    );
    assert_eq!(o, vec!["2", "3"]);
}

#[test]
fn parse_empty_text_and_lf() {
    t("csv_parse(\"\") == []");
    // LF pelado (sin CR) también es válido.
    t("length(csv_parse(\"a,b\\n1,2\\n\")) == 1");
}

#[test]
fn parse_bom_tolerated() {
    // El BOM UTF-8 de Excel al inicio no contamina la primera cabecera.
    let o = out(
        "let bom be decode(bytes(\"efbbbf\", \"hex\"))\n\
         let rows be csv_parse(bom + \"a,b\\n1,2\\n\")\n\
         print(rows[0][\"a\"])",
    );
    assert_eq!(o, vec!["1"]);
}

#[test]
fn parse_delimiters_semicolon_and_tab() {
    t("csv_parse(\"a;b\\n1;2\\n\", {\"delimiter\": \";\"})[0][\"b\"] == \"2\"");
    t("csv_parse(\"a\\tb\\n1\\t2\\n\", {\"delimiter\": \"\\t\"})[0][\"b\"] == \"2\"");
}

// =========================================================
// Round-trips (RFC 4180: comas/comillas/saltos embebidos)
// =========================================================

#[test]
fn roundtrip_maps_with_embedded_specials() {
    t(
        "csv_parse(csv_encode([{\"a\": \"x,y\", \"b\": \"with \\\"q\\\"\", \"c\": \"l1\\nl2\"}])) \
         == [{\"a\": \"x,y\", \"b\": \"with \\\"q\\\"\", \"c\": \"l1\\nl2\"}]",
    );
}

#[test]
fn roundtrip_lists_and_minimal_quoting() {
    // Quoting mínimo: campos simples sin comillas, EOL RFC (CRLF) por default.
    t("csv_encode([[\"1\", \"2\"], [\"3\", \"4\"]]) == \"1,2\\r\\n3,4\\r\\n\"");
    t(
        "csv_parse(csv_encode([[\"1\", \"2\"], [\"3\", \"4\"]]), {\"headers\": false}) \
         == [[\"1\", \"2\"], [\"3\", \"4\"]]",
    );
}

#[test]
fn roundtrip_numbers() {
    // Con numbers:true el round-trip reconstruye los números (enteros sin decimales).
    t(
        "csv_parse(csv_encode([{\"n\": 42, \"f\": 2.5}]), {\"numbers\": true}) \
         == [{\"n\": 42, \"f\": 2.5}]",
    );
}

// =========================================================
// Encode: opts y valores especiales
// =========================================================

#[test]
fn encode_headers_subset_and_order() {
    t("csv_encode([{\"a\": \"1\", \"b\": \"2\"}], {\"headers\": [\"b\"]}) == \"b\\r\\n2\\r\\n\"");
    t(
        "csv_encode([{\"a\": \"1\", \"b\": \"2\"}], {\"headers\": [\"b\", \"a\"]}) \
         == \"b,a\\r\\n2,1\\r\\n\"",
    );
}

#[test]
fn encode_eol_lf() {
    t("csv_encode([[\"1\", \"2\"]], {\"eol\": \"\\n\"}) == \"1,2\\n\"");
}

#[test]
fn encode_nothing_empty_and_bool() {
    t("csv_encode([{\"a\": nothing, \"b\": true}]) == \"a,b\\r\\n,true\\r\\n\"");
}

#[test]
fn encode_integers_without_decimals() {
    // Espeja text(42) → "42" (no "42.0"); float estilo Python.
    t("csv_encode([[42, 2.5]]) == \"42,2.5\\r\\n\"");
}

// =========================================================
// Errores claros (G5) — siempre atrapables (G10)
// =========================================================

#[test]
fn error_uneven_fields_reports_line() {
    fails_with("csv_parse(\"a,b\\n1\\n\")", "line 2");
}

#[test]
fn error_unclosed_quote_reports_line() {
    fails_with("csv_parse(\"a,b\\n1,\\\"oops\\n2,3\\n\")", "unclosed quote");
    fails_with("csv_parse(\"a,b\\n1,\\\"oops\\n2,3\\n\")", "line 2");
}

#[test]
fn error_duplicate_headers() {
    fails_with("csv_parse(\"a,a\\n1,2\\n\")", "duplicate header");
}

#[test]
fn error_multichar_delimiter() {
    fails_with("csv_parse(\"a\\n\", {\"delimiter\": \";;\"})", "single ASCII character");
}

#[test]
fn error_encode_mismatched_keys() {
    fails_with(
        "csv_encode([{\"a\": \"1\"}, {\"b\": \"2\", \"c\": \"3\"}])",
        "row 2",
    );
}

#[test]
fn error_encode_nested_suggests_json_encode() {
    fails_with("csv_encode([{\"a\": [1, 2]}])", "json_encode");
}

#[test]
fn error_unknown_option() {
    fails_with("csv_parse(\"a\\n\", {\"headres\": true})", "unknown option");
}

#[test]
fn errors_are_recoverable_g10() {
    // El error de CSV es un error de runtime normal: try/recover lo atrapa y el
    // programa sigue (el agente decide si re-propaga con raise).
    let o = out(
        "let msg be \"\"\ntry\n    csv_parse(\"a,b\\n1\\n\")\nrecover err\n    set msg to err\nprint(contains(msg, \"line 2\"))\nprint(\"sigue vivo\")",
    );
    assert_eq!(o, vec!["true", "sigue vivo"]);
}

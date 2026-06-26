//! Conformidad del tipo `bytes` (Batch 1) — parte PURA (intérprete de core).
//!
//! Construcción/conversión (hex/base64), decode (utf8 estricto vs lossy), operaciones
//! (length/index/slice/contains/concat), igualdad byte-a-byte, truthiness, type_of/is_bytes.
//! Hashing (sha256/sha512), I/O y serve binario viven en los tests del runtime (engine),
//! porque dependen de builtins de stdlib/capabilities. Espeja el §10.2 del spec.

use synsema_core::bytesutil::hex_encode;
use synsema_core::interpreter::run_source;

fn assert_output(source: &str, expected: &[&str]) {
    let r = run_source(source, "<test>");
    assert!(r.success, "El programa falló: {:?}\nfuente:\n{}", r.errors, source);
    let exp: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    assert_eq!(r.output, exp, "fuente:\n{}", source);
}

fn assert_error_contains(source: &str, needle: &str) {
    let r = run_source(source, "<test>");
    assert!(!r.success, "Se esperaba fallo.\nfuente:\n{}", source);
    assert!(
        r.errors.iter().any(|e| e.contains(needle)),
        "Se esperaba un error con '{}', got {:?}",
        needle,
        r.errors
    );
}

// -- Construcción y conversión --

#[test]
fn construct_from_text_utf8_multibyte() {
    // "héllo" → 6 bytes (é = 2 bytes UTF-8); decode round-trip preserva multibyte.
    assert_output("print(text(length(bytes(\"héllo\"))))", &["6"]);
    assert_output("print(decode(bytes(\"héllo\")))", &["héllo"]);
    assert_output("print(decode(bytes(\"héllo\"), \"utf8\"))", &["héllo"]);
}

#[test]
fn construct_from_hex() {
    assert_output("print(decode(bytes(\"48656c6c6f\", \"hex\")))", &["Hello"]);
    // round-trip: decode(.., "hex") es minúsculas.
    assert_output("print(decode(bytes(\"48656C6C6F\", \"hex\"), \"hex\"))", &["48656c6c6f"]);
    assert_output("print(text(length(bytes(\"\", \"hex\"))))", &["0"]);
}

#[test]
fn construct_from_base64() {
    // base64 de "Hello" = "SGVsbG8="
    assert_output("print(decode(bytes(\"Hello\"), \"base64\"))", &["SGVsbG8="]);
    assert_output("print(decode(bytes(\"SGVsbG8=\", \"base64\")))", &["Hello"]);
}

#[test]
fn construct_from_int_list() {
    assert_output("print(decode(bytes([72, 73])))", &["HI"]);
    assert_output("print(text(length(bytes([]))))", &["0"]);
}

#[test]
fn construct_identity_and_display() {
    assert_output("print(decode(bytes(bytes(\"Hi\"))))", &["Hi"]);
    // Display: bytes(<hexlower>)
    assert_output("print(bytes(\"Hi\"))", &["bytes(4869)"]);
    assert_output("print(text(bytes(\"Hi\")))", &["bytes(4869)"]);
}

#[test]
fn construct_display_truncates_over_32_bytes() {
    // 40 bytes (0..39) → primeros 32 en hex + "… (40 bytes)".
    let head: Vec<u8> = (0u8..32).collect();
    let expected = format!("bytes({}… (40 bytes))", hex_encode(&head));
    assert_output("print(bytes(range(40)))", &[&expected]);
}

#[test]
fn construct_errors() {
    assert_error_contains("print(bytes(\"abc\", \"hex\"))", "hex"); // longitud impar
    assert_error_contains("print(bytes(\"zz\", \"hex\"))", "hex"); // no-hex
    assert_error_contains("print(bytes([256]))", "0..=255");
    assert_error_contains("print(bytes([-1]))", "0..=255");
    assert_error_contains("print(bytes([\"x\"]))", "0..=255");
    assert_error_contains("print(bytes(true))", "Cannot convert bool to bytes");
    assert_error_contains("print(bytes(\"x\", \"rot13\"))", "unsupported encoding");
}

// -- decode: utf8 estricto vs lossy (G4) --

#[test]
fn decode_utf8_strict_errors_on_invalid() {
    // 0xFF no es UTF-8 válido → decode estricto ERRORA (no devuelve basura).
    assert_error_contains("print(decode(bytes(\"ff\", \"hex\")))", "UTF-8");
    assert_error_contains("print(decode(bytes(\"ff\", \"hex\"), \"utf8\"))", "UTF-8");
}

#[test]
fn decode_utf8_lossy_is_opt_in() {
    // lossy explícito → U+FFFD.
    assert_output("print(decode(bytes(\"ff\", \"hex\"), \"utf8_lossy\"))", &["\u{FFFD}"]);
}

#[test]
fn decode_errors() {
    assert_error_contains("print(decode(\"not bytes\"))", "decode expects bytes, got text");
    assert_error_contains("print(decode(bytes(\"x\"), \"rot13\"))", "unsupported encoding");
}

#[test]
fn decode_empty() {
    assert_output("print(\"[\" + decode(bytes(\"\")) + \"]\")", &["[]"]);
}

// -- Operaciones --

#[test]
fn index_returns_byte_value() {
    assert_output("print(text(bytes(\"Hi\")[0]))", &["72"]);
    assert_output("print(text(bytes(\"Hi\")[1]))", &["105"]);
    assert_output("print(text(bytes([255])[0]))", &["255"]);
}

#[test]
fn index_out_of_bounds() {
    assert_error_contains("print(text(bytes(\"Hi\")[5]))", "out of bounds");
    assert_error_contains("print(text(bytes(\"Hi\")[-1]))", "out of bounds");
}

#[test]
fn slice_bytes() {
    assert_output("print(decode(slice(bytes(\"Hello\"), 1, 3)))", &["el"]);
    assert_output("print(decode(slice(bytes(\"Hello\"), -2)))", &["lo"]);
    // rango invertido → vacío
    assert_output("print(\"[\" + decode(slice(bytes(\"Hello\"), 3, 1)) + \"]\")", &["[]"]);
}

#[test]
fn contains_bytes_and_byte() {
    assert_output("print(text(contains(bytes(\"Hello\"), bytes(\"ell\"))))", &["true"]);
    assert_output("print(text(contains(bytes(\"Hello\"), bytes(\"xyz\"))))", &["false"]);
    assert_output("print(text(contains(bytes(\"Hello\"), bytes(\"\"))))", &["true"]);
    assert_output("print(text(contains(bytes(\"Hello\"), 72)))", &["true"]); // 'H'
    assert_output("print(text(contains(bytes(\"Hello\"), 99)))", &["false"]);
}

#[test]
fn concat_bytes() {
    assert_output("print(decode(bytes(\"Hel\") + bytes(\"lo\")))", &["Hello"]);
    // bytes + text coerciona vía Display (texto con el repr hex) — consistente, no-lossy.
    assert_output("print(bytes(\"Hi\") + \"!\")", &["bytes(4869)!"]);
    assert_output("print(\"!\" + bytes(\"Hi\"))", &["!bytes(4869)"]);
}

#[test]
fn equality_byte_for_byte_no_cross_type() {
    assert_output("print(text(bytes(\"Hi\") == bytes(\"Hi\")))", &["true"]);
    assert_output("print(text(bytes(\"Hi\") == bytes(\"Ho\")))", &["false"]);
    // bytes nunca igual a text aunque "coincidan" (G3).
    assert_output("print(text(bytes(\"Hi\") == \"Hi\"))", &["false"]);
    assert_output("print(text(bytes(\"Hi\") != \"Hi\"))", &["true"]);
}

#[test]
fn truthiness_empty_is_false() {
    let src = "let b be bytes(\"\")\nwhen b\n    print(\"t\")\notherwise\n    print(\"f\")\n";
    assert_output(src, &["f"]);
    let src2 = "let b be bytes(\"x\")\nwhen b\n    print(\"t\")\notherwise\n    print(\"f\")\n";
    assert_output(src2, &["t"]);
}

#[test]
fn type_of_and_is_bytes() {
    assert_output("print(type_of(bytes(\"x\")))", &["bytes"]);
    assert_output("print(text(is_bytes(bytes(\"x\"))))", &["true"]);
    assert_output("print(text(is_bytes(\"x\")))", &["false"]);
    assert_output("print(text(is_bytes(42)))", &["false"]);
}

#[test]
fn base64_round_trips_all_256_values() {
    // bytes(range(256)) → 256 bytes; decode b64 + re-decode → idéntico (length 256).
    let src = "let all be bytes(range(256))\n\
               let b64 be decode(all, \"base64\")\n\
               let back be bytes(b64, \"base64\")\n\
               print(text(all == back))\n\
               print(text(length(back)))\n";
    assert_output(src, &["true", "256"]);
}

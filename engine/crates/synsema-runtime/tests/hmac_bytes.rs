//! HB1 (v0.6.44): `hmac`, `verify_hmac`, `hmac_sha256` y `constant_time_eq` usan los bytes CRUDOS
//! de un argumento `bytes` (antes, su forma impresa `bytes(6b65…)`: otro MAC, sin aviso). Con texto
//! dan exactamente lo de siempre. Un tipo que no es texto, bytes ni secret es error.
//! HB2: bits sobre enteros de 64 bits y `xor_bytes`, desde un programa.

fn run(src: &str) -> synsema_core::interpreter::RunResult {
    synsema_runtime::engine::run_source(src, "hmac_bytes.syn")
}

fn lines(src: &str) -> Vec<String> {
    let r = run(src);
    assert!(r.success, "{:?}", r.errors);
    r.output.clone()
}

const SPEC: &str = "0x5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0";

#[test]
fn hmac_with_bytes_uses_the_raw_bytes_and_text_is_unchanged() {
    let out = lines(
        r#"print(hex(hmac("data", "key", "sha256")))
print(hex(hmac(bytes("data"), bytes("key"), "sha256")))
print(hex(hmac(bytes("data"), "key", "sha256")))
print(hex(hmac("data", bytes("key"), "sha256")))
print(hex(hmac("data", "key")))
print(hmac_sha256(bytes("data"), bytes("key")))
"#,
    );
    for (k, l) in out[..5].iter().enumerate() {
        assert_eq!(l, SPEC, "línea {}", k + 1);
    }
    assert_eq!(out[5], &SPEC[2..], "hmac_sha256 (hex sin 0x) con bytes");
}

#[test]
fn rfc_4231_vectors_with_binary_keys() {
    // Caso 1: clave 0x0b × 20, "Hi There". Caso 6: clave 0xaa × 131 (más larga que el bloque).
    let out = lines(&format!(
        r#"let k1 be bytes("{}", "hex")
print(hex(hmac("Hi There", k1, "sha256")))
print(hex(hmac(bytes("Hi There"), k1, "sha512")))
let k6 be bytes("{}", "hex")
print(hex(hmac("Test Using Larger Than Block-Size Key - Hash Key First", k6, "sha256")))
"#,
        "0b".repeat(20),
        "aa".repeat(131)
    ));
    assert_eq!(out[0], "0xb0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert_eq!(out[1], "0x87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    assert_eq!(out[2], "0x60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

#[test]
fn verify_hmac_and_constant_time_eq_with_bytes() {
    let out = lines(&format!(
        r#"let mac be hmac(bytes("data"), bytes("key"))
print(verify_hmac(bytes("data"), mac, bytes("key")))
print(verify_hmac("data", "{}", "key"))
print(verify_hmac("data", "sha256={}", bytes("key")))
print(verify_hmac(bytes("data"), mac, bytes("other")))
print(verify_hmac("data", "not a signature", "key"))
print(constant_time_eq(bytes("ab"), "ab"))
print(constant_time_eq(bytes("ab"), bytes("ac")))
"#,
        &SPEC[2..],
        &SPEC[2..]
    ));
    assert_eq!(out, vec!["true", "true", "true", "false", "false", "true", "false"]);
}

#[test]
fn a_type_that_is_not_text_bytes_or_secret_is_an_error() {
    for (src, needle) in [
        ("hmac(123, \"key\")", "hmac: data must be text, bytes or a secret, got number"),
        ("hmac(\"data\", [1, 2])", "hmac: key must be text, bytes or a secret, got list"),
        ("hmac(\"data\", \"key\", 256)", "hmac: algo must be text"),
        ("verify_hmac(\"data\", 5, \"key\")", "verify_hmac: signature must be text (hex or base64) or bytes, got number"),
        ("verify_hmac(\"data\", \"00\", nothing)", "verify_hmac: key must be text, bytes or a secret, got nothing"),
        ("hmac_sha256(true, \"k\")", "hmac_sha256: data must be text, bytes or a secret, got bool"),
        ("constant_time_eq(1, 1)", "constant_time_eq: a must be text, bytes or a secret, got number"),
    ] {
        let r = run(&format!("{}\n", src));
        assert!(!r.success && r.errors.join(" ").contains(needle), "{}: {:?}", src, r.errors);
    }
}

#[test]
fn bits_from_a_program() {
    let out = lines(
        r#"print(bit_xor(0x36, 0x5c))
print(bit_and(-1, 255), bit_or(1, 6), bit_not(0))
print(shl(1, 10), shr(-8, 1))
print(hex(xor_bytes(bytes("3636", "hex"), bytes("5c00", "hex"))))
"#,
    );
    assert_eq!(out, vec!["106", "255 7 -1", "1024 -4", "0x6a36"]);
    for (src, needle) in [
        ("shl(1, 64)", "shl: the shift must be between 0 and 63, got 64"),
        ("shr(1, -1)", "between 0 and 63"),
        ("shl(1, 63)", "does not fit in a 64-bit integer"),
        ("bit_xor(18446744073709551616, 1)", "64-bit integers"),
        ("bit_and(1.5, 1)", "integers, got a float"),
        ("xor_bytes(bytes(\"a\"), bytes(\"bc\"))", "same length, got 1 and 2 bytes"),
        ("xor_bytes(\"a\", bytes(\"b\"))", "bytes(text)"),
    ] {
        let r = run(&format!("{}\n", src));
        assert!(!r.success && r.errors.join(" ").contains(needle), "{}: {:?}", src, r.errors);
    }
}

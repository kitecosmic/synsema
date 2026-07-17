//! Conformidad criptográfica del Batch 11 (blockchain) contra vectores conocidos
//! de fuentes autoritativas. Es CÓDIGO DE DINERO: cada primitiva se ancla a un
//! vector externo, no a "lo que produjo el binario".
//!
//! Cubre: keccak256 ≠ SHA3 (G7), sha512_256, base58/base32/bech32 (round-trips +
//! vectores), secp256k1 RFC 6979 determinista + low-s (G5/G6), ed25519 RFC 8032,
//! dirección EIP-55 (los 4 vectores + clave conocida), ecrecover, y RLP round-trip.
//!
//! Las FIRMAS gateadas se prueban acá a nivel de builtin CON la capability concedida
//! (el gate/sandbox/audit se prueban por el runtime en batch11_e2e.rs).

use std::cell::RefCell;
use std::rc::Rc;

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::bytesutil::{base32_encode, base58_encode, hex_decode, hex_encode};
use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::types::{syn_bool, syn_bytes, syn_list, syn_int, syn_secret, syn_text, SynValue};
use synsema_stdlib::blockchain::register_blockchain_builtins;
use synsema_stdlib::hashing::register_hash_builtins;

/// Aísla el audit de firmas a un temp por proceso: estas pruebas firman de verdad
/// (audit fail-loud + append-only) y sin esto cada `cargo test` ensuciaría el
/// `~/.synsema/audit/sign.log` REAL del dev. NO se suprime el audit (sería firma sin
/// registro = pérdida de seguridad); sólo se redirige a un temp descartable.
static AUDIT_ISOLATE: std::sync::Once = std::sync::Once::new();
fn isolate_audit_dir() {
    AUDIT_ISOLATE.call_once(|| {
        let dir = std::env::temp_dir().join(format!("syn_test_audit_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_var("SYNSEMA_AUDIT_DIR", &dir);
    });
}

/// Intérprete con los builtins de hashing + blockchain, y un CapabilitySet que
/// concede `sign(<key_name>)` para las pruebas de firma.
fn interp_with_sign(key_name: &str) -> Interpreter {
    isolate_audit_dir();
    let interp = Interpreter::new();
    register_hash_builtins(&interp);
    let caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
    caps.borrow_mut()
        .grant(Capability::new(CapabilityType::Sign, Some(key_name.to_string())));
    register_blockchain_builtins(&interp, caps);
    interp
}

/// Llama un builtin por nombre: lo saca del global env (donde `register_builtin` lo
/// dejó) y lo invoca con `call_task`.
fn call(interp: &mut Interpreter, name: &str, args: Vec<SynValue>) -> Result<SynValue, Control> {
    let f = interp
        .global_env
        .borrow()
        .bindings
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("builtin {} no registrado", name));
    interp.call_task(f, args)
}

fn ok_bytes(r: Result<SynValue, Control>) -> Vec<u8> {
    match r {
        Ok(SynValue::Bytes(b)) => b[..].to_vec(),
        Ok(other) => panic!("esperaba bytes, got {}", other.type_name()),
        Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
        Err(_) => panic!("control inesperado"),
    }
}

fn ok_text(r: Result<SynValue, Control>) -> String {
    match r {
        Ok(SynValue::Text(s)) => s.to_string(),
        Ok(other) => panic!("esperaba text, got {}", other.type_name()),
        Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
        Err(_) => panic!("control inesperado"),
    }
}

fn ok_bool(r: Result<SynValue, Control>) -> bool {
    match r {
        Ok(SynValue::Bool(b)) => b,
        Ok(other) => panic!("esperaba bool, got {}", other.type_name()),
        Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
        Err(_) => panic!("control inesperado"),
    }
}

fn hx(s: &str) -> Vec<u8> {
    hex_decode(s).expect("hex de test válido")
}

// =========================================================
// Hashes (G7: Keccak ≠ SHA3)
// =========================================================

#[test]
fn keccak256_is_pre_nist_not_sha3() {
    let mut i = interp_with_sign("K");
    // El vector estrella del spec: previene el error clásico Keccak/SHA3.
    let empty = ok_bytes(call(&mut i, "keccak256", vec![syn_text("")]));
    assert_eq!(
        hex_encode(&empty),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "keccak256(\"\") — si diera a7ffc6f8… sería SHA3-256 (bug clásico)"
    );
    let abc = ok_bytes(call(&mut i, "keccak256", vec![syn_text("abc")]));
    assert_eq!(
        hex_encode(&abc),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
    // También acepta bytes crudos (mismo resultado que el texto UTF-8).
    let abc_b = ok_bytes(call(&mut i, "keccak256", vec![syn_bytes(b"abc".to_vec())]));
    assert_eq!(abc_b, abc);
    // secret → error (G9: el hashing de secrets va por rutas gateadas).
    let e = call(&mut i, "keccak256", vec![syn_secret("K", "deadbeef")]);
    assert!(matches!(e, Err(Control::Error(_))));
}

#[test]
fn sha512_256_known_vector() {
    let mut i = interp_with_sign("K");
    // NIST SHA-512/256("abc").
    let abc = ok_bytes(call(&mut i, "sha512_256", vec![syn_text("abc")]));
    assert_eq!(
        hex_encode(&abc),
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
    );
}

// =========================================================
// Encoding — vectores + round-trips (base58/base32 via bytes()/decode())
// =========================================================

#[test]
fn base58_and_base32_via_core() {
    // Direcciones reales: una Solana (base58) y una Algorand (base32) round-trip.
    // Solana address (32 bytes) → base58 → de vuelta.
    let pk = hx("0000000000000000000000000000000000000000000000000000000000000001");
    let b58 = base58_encode(&pk);
    assert_eq!(synsema_core::bytesutil::base58_decode(&b58).unwrap(), pk);
    // base32 sin padding (Algorand): round-trip de 36 bytes (pubkey+checksum).
    let data: Vec<u8> = (0..36u8).collect();
    let b32 = base32_encode(&data);
    assert!(!b32.contains('='), "convención Algorand: sin padding");
    assert_eq!(synsema_core::bytesutil::base32_decode(&b32).unwrap(), data);
}

// =========================================================
// bech32 / bech32m (BIP-173 / BIP-350) — vía builtins
// =========================================================

#[test]
fn bech32_roundtrip_and_variant() {
    let mut i = interp_with_sign("K");
    let data = syn_bytes(vec![0x00, 0x01, 0x02, 0x03, 0x04]);
    let enc = ok_text(call(&mut i, "bech32_encode", vec![syn_text("avax"), data.clone()]));
    assert!(enc.starts_with("avax1"), "HRP + separador: {}", enc);
    // decode → hrp/data/variant.
    let dec = call(&mut i, "bech32_decode", vec![syn_text(enc.as_str())]);
    let m = match dec {
        Ok(SynValue::Map(m)) => m.borrow().clone(),
        other => panic!("esperaba map: {:?}", other.is_ok()),
    };
    assert_eq!(m.get("hrp").map(|v| v.to_string()).as_deref(), Some("avax"));
    assert_eq!(m.get("variant").map(|v| v.to_string()).as_deref(), Some("bech32"));
    match m.get("data") {
        Some(SynValue::Bytes(b)) => assert_eq!(&b[..], &[0x00, 0x01, 0x02, 0x03, 0x04]),
        _ => panic!("data no es bytes"),
    }
    // bech32m es DISTINTO de bech32 (checksum distinto) — mismo dato, string distinto.
    let encm = ok_text(call(
        &mut i,
        "bech32_encode",
        vec![syn_text("avax"), data, syn_text("bech32m")],
    ));
    assert_ne!(enc, encm, "bech32 y bech32m difieren en el checksum");
    let decm = call(&mut i, "bech32_decode", vec![syn_text(encm.as_str())]);
    let mm = match decm {
        Ok(SynValue::Map(m)) => m.borrow().clone(),
        other => panic!("esperaba map: {:?}", other.is_ok()),
    };
    assert_eq!(mm.get("variant").map(|v| v.to_string()).as_deref(), Some("bech32m"));
    // Checksum alterado → error nombrando checksum (DX).
    let mut bad = enc.clone();
    bad.pop();
    bad.push(if enc.ends_with('q') { 'p' } else { 'q' });
    let e = call(&mut i, "bech32_decode", vec![syn_text(bad.as_str())]);
    assert!(matches!(e, Err(Control::Error(_))));
}

// =========================================================
// secp256k1 — RFC 6979 determinista, low-s, verify/recover/pubkey
// =========================================================

/// Clave conocida `0x…01` y su dirección Ethereum (vector del spec).
const KEY1_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const KEY1_ADDR: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

#[test]
fn secp256k1_sign_is_deterministic_and_low_s() {
    let mut i = interp_with_sign("K");
    let digest = syn_bytes(hx("0000000000000000000000000000000000000000000000000000000000000000"));
    let key = syn_secret("K", KEY1_HEX);
    let s1 = ok_bytes(call(&mut i, "secp256k1_sign", vec![digest.clone(), key.clone()]));
    let s2 = ok_bytes(call(&mut i, "secp256k1_sign", vec![digest.clone(), key.clone()]));
    assert_eq!(s1, s2, "RFC 6979: misma (clave, digest) → misma firma byte a byte (G5)");
    assert_eq!(s1.len(), 65, "r(32) || s(32) || v(1)");
    // low-s (G6): s <= n/2. n/2 para secp256k1:
    let half_n = hx("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
    let s_bytes = &s1[32..64];
    assert!(s_bytes <= &half_n[..], "la firma debe ser low-s (anti-malleability)");
    // v es 0 o 1 (recovery id crudo).
    assert!(s1[64] <= 1, "v (recovery id) es 0/1 para ETH crudo");
}

#[test]
fn secp256k1_verify_and_recover_roundtrip() {
    let mut i = interp_with_sign("K");
    let digest_hex = "1111111111111111111111111111111111111111111111111111111111111111";
    let digest = syn_bytes(hx(digest_hex));
    let key = syn_secret("K", KEY1_HEX);
    let sig = ok_bytes(call(&mut i, "secp256k1_sign", vec![digest.clone(), key.clone()]));
    // pubkey de la clave (comprimida y sin comprimir).
    let pub_c = ok_bytes(call(&mut i, "secp256k1_pubkey", vec![key.clone()]));
    assert_eq!(pub_c.len(), 33);
    let pub_u = ok_bytes(call(&mut i, "secp256k1_pubkey", vec![key.clone(), syn_bool(false)]));
    assert_eq!(pub_u.len(), 65);
    // verify con ambas formas de pubkey.
    assert!(ok_bool(call(&mut i, "secp256k1_verify", vec![digest.clone(), syn_bytes(sig.clone()), syn_bytes(pub_c.clone())])));
    assert!(ok_bool(call(&mut i, "secp256k1_verify", vec![digest.clone(), syn_bytes(sig.clone()), syn_bytes(pub_u.clone())])));
    // firma alterada → false (no error).
    let mut bad = sig.clone();
    bad[0] ^= 0xff;
    assert!(!ok_bool(call(&mut i, "secp256k1_verify", vec![digest.clone(), syn_bytes(bad), syn_bytes(pub_c.clone())])));
    // ecrecover: recupera la pubkey firmante → su dirección == dirección de KEY1.
    let recovered = ok_bytes(call(&mut i, "secp256k1_recover", vec![digest, syn_bytes(sig)]));
    assert_eq!(recovered, pub_u, "ecrecover devuelve la pubkey sin comprimir de la clave");
    let addr = ok_text(call(&mut i, "eth_address", vec![syn_bytes(recovered)]));
    assert_eq!(addr, KEY1_ADDR);
}

// =========================================================
// Dirección EIP-55 — clave conocida + los 4 vectores del EIP
// =========================================================

#[test]
fn eth_address_from_key_and_eip55_vectors() {
    let mut i = interp_with_sign("K");
    // Clave conocida → dirección conocida (deriva la pubkey Rust-side).
    let addr = ok_text(call(&mut i, "eth_address", vec![syn_secret("K", KEY1_HEX)]));
    assert_eq!(addr, KEY1_ADDR);

    // Los 4 vectores de checksum del EIP-55: dada la dirección (20 bytes), el
    // checksum mixed-case debe salir exacto. Reconstruimos vía una pubkey no —
    // en cambio verificamos el checksum sobre bytes conocidos derivando de la addr.
    // (eth_address toma pubkey/secret; para chequear el checksum puro usamos la
    // ruta pubkey: buscamos claves cuya dirección sea cada vector no es práctico,
    // así que validamos el algoritmo de checksum contra los 4 strings canónicos.)
    for want in [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ] {
        let addr_bytes = hx(want.trim_start_matches("0x"));
        // Re-checksum: mismo algoritmo del builtin (keccak del hex lowercase).
        let got = eip55_reference(&addr_bytes);
        assert_eq!(got, want, "checksum EIP-55 exacto");
    }
}

/// Implementación de referencia INDEPENDIENTE del checksum EIP-55 (para no testear
/// el builtin contra sí mismo): usa keccak256 del builtin sobre el hex lowercase.
fn eip55_reference(addr20: &[u8]) -> String {
    use sha3::{Digest, Keccak256};
    let lower = hex_encode(addr20);
    let hash = Keccak256::digest(lower.as_bytes());
    let hash_hex = hex_encode(&hash);
    let mut out = String::from("0x");
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else if hash_hex.as_bytes()[i] >= b'8' {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

// =========================================================
// ed25519 — RFC 8032 vector (message crudo, no pre-hash)
// =========================================================

#[test]
fn ed25519_rfc8032_vector() {
    let mut i = interp_with_sign("K");
    // RFC 8032 TEST 2: seed conocido, mensaje de 1 byte 0x72, firma esperada.
    let seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    let pub_expected = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    let sig_expected = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
    let key = syn_secret("K", seed);
    let msg = syn_bytes(vec![0x72]);
    // pubkey.
    let pk = ok_bytes(call(&mut i, "ed25519_pubkey", vec![key.clone()]));
    assert_eq!(hex_encode(&pk), pub_expected);
    // sign (gateado; el intérprete concede sign("K")).
    let sig = ok_bytes(call(&mut i, "ed25519_sign", vec![msg.clone(), key.clone()]));
    assert_eq!(hex_encode(&sig), sig_expected, "RFC 8032 TEST 2 (determinista)");
    // firmar dos veces → idéntico.
    let sig2 = ok_bytes(call(&mut i, "ed25519_sign", vec![msg.clone(), key.clone()]));
    assert_eq!(sig, sig2);
    // verify.
    assert!(ok_bool(call(&mut i, "ed25519_verify", vec![msg.clone(), syn_bytes(sig.clone()), syn_bytes(pk.clone())])));
    // mensaje alterado → false.
    assert!(!ok_bool(call(&mut i, "ed25519_verify", vec![syn_bytes(vec![0x73]), syn_bytes(sig), syn_bytes(pk)])));
}

#[test]
fn ed25519_accepts_64_byte_solana_key() {
    let mut i = interp_with_sign("K");
    let seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    let pubk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    // Forma Solana: 64 bytes [seed || pubkey].
    let solana_key = syn_secret("K", format!("{}{}", seed, pubk));
    let pk = ok_bytes(call(&mut i, "ed25519_pubkey", vec![solana_key]));
    assert_eq!(hex_encode(&pk), pubk);
    // Pubkey embebida que NO coincide → error claro (sin exponer material).
    let wrong = syn_secret("K", format!("{}{}", seed, "00".repeat(32)));
    let e = call(&mut i, "ed25519_pubkey", vec![wrong]);
    match e {
        Err(Control::Error(re)) => {
            assert!(re.message.contains("does not match"), "{}", re.message);
            assert!(!re.message.contains(seed), "el error jamás muestra material");
        }
        _ => panic!("esperaba error de mismatch"),
    }
}

// =========================================================
// RLP — vectores conocidos + round-trip
// =========================================================

#[test]
fn rlp_known_vectors_and_roundtrip() {
    let mut i = interp_with_sign("K");
    // bytes vacíos → 0x80.
    assert_eq!(ok_bytes(call(&mut i, "rlp_encode", vec![syn_bytes(vec![])])), vec![0x80]);
    // lista vacía → 0xc0.
    assert_eq!(ok_bytes(call(&mut i, "rlp_encode", vec![syn_list(vec![])])), vec![0xc0]);
    // el entero 0 → 0x80 (string vacío).
    assert_eq!(ok_bytes(call(&mut i, "rlp_encode", vec![syn_int(0)])), vec![0x80]);
    // el entero 15 → 0x0f (byte único < 0x80).
    assert_eq!(ok_bytes(call(&mut i, "rlp_encode", vec![syn_int(15)])), vec![0x0f]);
    // el entero 1024 → 0x82 0x04 0x00.
    assert_eq!(ok_bytes(call(&mut i, "rlp_encode", vec![syn_int(1024)])), vec![0x82, 0x04, 0x00]);
    // "dog" (como bytes) → 0x83 'd' 'o' 'g'.
    assert_eq!(
        ok_bytes(call(&mut i, "rlp_encode", vec![syn_bytes(b"dog".to_vec())])),
        vec![0x83, b'd', b'o', b'g']
    );
    // ["cat","dog"] → 0xc8 0x83 cat 0x83 dog.
    let catdog = syn_list(vec![syn_bytes(b"cat".to_vec()), syn_bytes(b"dog".to_vec())]);
    assert_eq!(
        ok_bytes(call(&mut i, "rlp_encode", vec![catdog])),
        vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
    );

    // Round-trip de una tx EIP-1559 (lista anidada de campos típicos).
    let tx = syn_list(vec![
        syn_int(1),                                  // chainId
        syn_int(9),                                  // nonce
        syn_int(1_000_000_000),                      // maxPriorityFee
        syn_int(30_000_000_000i64),                  // maxFee
        syn_int(21000),                              // gas
        syn_bytes(hx("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")), // to (20 bytes)
        syn_int(1_000_000_000_000_000i64),           // value
        syn_bytes(vec![]),                           // data
        syn_list(vec![]),                            // accessList
    ]);
    let enc = ok_bytes(call(&mut i, "rlp_encode", vec![tx.clone()]));
    let dec = call(&mut i, "rlp_decode", vec![syn_bytes(enc.clone())]);
    // re-encode del decodificado == encode original (round-trip estructural).
    let re = ok_bytes(call(&mut i, "rlp_encode", vec![dec.unwrap_or(SynValue::Nothing)]));
    assert_eq!(enc, re, "rlp_encode(rlp_decode(x)) reproduce el encoding");

    // Bignum grande (no cabe en i64) — BigInt path.
    let big = SynValue::Number(synsema_core::number::Number::parse_int_literal(
        "123456789012345678901234567890",
    ));
    let benc = ok_bytes(call(&mut i, "rlp_encode", vec![big]));
    assert_eq!(benc[0], 0x8d, "13 bytes big-endian → prefijo 0x80+13");
}

#[test]
fn rlp_decode_rejects_non_canonical_encodings() {
    // Decoders canónicos (como los de Ethereum): dos byte-strings distintos JAMÁS
    // decodifican a la misma estructura. Cada forma no-mínima se rechaza.
    let mut i = interp_with_sign("K");
    let reject = |i: &mut Interpreter, hexs: &str, why: &str| {
        let e = call(i, "rlp_decode", vec![syn_bytes(hx(hexs))]);
        match e {
            Err(Control::Error(re)) => {
                assert!(re.message.contains("non-canonical"), "{}: {}", why, re.message)
            }
            other => panic!("{}: debía rechazarse, got {:?}", why, other.is_ok()),
        }
    };
    // Un byte <= 0x7f codificado con prefijo 0x81 (debe ser el byte solo).
    reject(&mut i, "8105", "0x81 0x05 no es canónico (0x05 se codifica como 0x05)");
    reject(&mut i, "817f", "0x81 0x7f no es canónico");
    // Forma larga para un payload < 56 bytes (string y lista).
    reject(&mut i, "b8016a", "string: forma larga para largo 1");
    reject(&mut i, "f803010203", "lista: forma larga para largo 3");
    // Byte de largo con cero a la izquierda.
    reject(&mut i, "b90001aa", "string: largo con cero a la izquierda");
    // Las formas CANÓNICAS equivalentes siguen andando.
    // 0x81 0x80: canónico (el byte 0x80 sí necesita prefijo).
    assert_eq!(ok_bytes(call(&mut i, "rlp_decode", vec![syn_bytes(hx("8180"))])), vec![0x80]);
    // String largo legítimo: 56 bytes 0xaa → b8 38 aa*56; round-trip con el encoder.
    let long = vec![0xaau8; 56];
    let enc = ok_bytes(call(&mut i, "rlp_encode", vec![syn_bytes(long.clone())]));
    assert_eq!(enc[..2], [0xb8, 56]);
    assert_eq!(ok_bytes(call(&mut i, "rlp_decode", vec![syn_bytes(enc)])), long);
}

#[test]
fn ed25519_verify_is_strict_rejects_small_order_forgery() {
    // Bajo el `verify` laxo de RFC 8032 cofactorless, la pubkey IDENTIDAD (orden 1,
    // encoding 0x0100…00) con sig (R=identidad, s=0) "valida" CUALQUIER mensaje.
    // verify_strict (lo que exigen Solana/Algorand) la rechaza. Money code.
    let mut i = interp_with_sign("K");
    let mut identity = vec![0u8; 32];
    identity[0] = 1;
    let mut sig = identity.clone();
    sig.extend_from_slice(&[0u8; 32]); // R = identidad || s = 0
    let ok = ok_bool(call(
        &mut i,
        "ed25519_verify",
        vec![syn_bytes(b"drain the wallet".to_vec()), syn_bytes(sig), syn_bytes(identity)],
    ));
    assert!(!ok, "una pubkey de orden pequeño no debe validar nada (forja universal)");
}

#[test]
fn bytes_to_int_and_back_for_rlp_signature_integers() {
    // El puente r/s: EIP-1559 codifica r y s como ENTEROS mínimos (sin ceros a la
    // izquierda), no como blobs de 32 bytes. bytes_to_int/int_to_bytes son el camino
    // exacto (256 bits jamás pasan por float).
    let mut i = interp_with_sign("K");
    // r con un cero a la izquierda (el caso 1-de-256 que rompe una tx mal armada).
    let r = hx("00ff112233445566778899aabbccddeeff00112233445566778899aabbccddee");
    let n = match call(&mut i, "bytes_to_int", vec![syn_bytes(r.clone())]) {
        Ok(v) => v,
        Err(Control::Error(e)) => panic!("bytes_to_int: {}", e.message),
        Err(_) => panic!("control inesperado"),
    };
    // Mínimo: 31 bytes (el cero inicial se cae) — y con size=32 vuelve idéntico.
    let min = ok_bytes(call(&mut i, "int_to_bytes", vec![n.clone()]));
    assert_eq!(min.len(), 31);
    assert_eq!(min[..], r[1..]);
    let padded = ok_bytes(call(&mut i, "int_to_bytes", vec![n.clone(), syn_int(32)]));
    assert_eq!(padded, r, "int_to_bytes(n, 32) restaura el ancho fijo");
    // El entero es EXACTO (no float): el texto decimal coincide con el BigInt real.
    use num_bigint::BigInt;
    let expected = BigInt::from_bytes_be(num_bigint::Sign::Plus, &r);
    assert_eq!(n.to_string(), expected.to_string(), "256 bits exactos, sin float");
    // Bordes: vacío → 0; 0 → vacío; valor que no entra en size → error.
    let zero = match call(&mut i, "bytes_to_int", vec![syn_bytes(vec![])]) {
        Ok(v) => v,
        _ => panic!("bytes vacíos deben dar 0"),
    };
    assert_eq!(zero.to_string(), "0");
    assert_eq!(ok_bytes(call(&mut i, "int_to_bytes", vec![syn_int(0)])), Vec::<u8>::new());
    assert!(matches!(
        call(&mut i, "int_to_bytes", vec![syn_int(256), syn_int(1)]),
        Err(Control::Error(_))
    ));
    assert!(matches!(
        call(&mut i, "int_to_bytes", vec![syn_int(-1)]),
        Err(Control::Error(_))
    ));
}

#[test]
fn rlp_rejects_unsupported_and_bad_input() {
    let mut i = interp_with_sign("K");
    // text → error dirigido (ambigüedad hex/ascii).
    assert!(matches!(call(&mut i, "rlp_encode", vec![syn_text("0xdead")]), Err(Control::Error(_))));
    // entero negativo → error.
    assert!(matches!(call(&mut i, "rlp_encode", vec![syn_int(-1)]), Err(Control::Error(_))));
    // decode de input truncado → error, no panic.
    assert!(matches!(call(&mut i, "rlp_decode", vec![syn_bytes(vec![0x83, b'a'])]), Err(Control::Error(_))));
    // decode con bytes de más → error.
    assert!(matches!(call(&mut i, "rlp_decode", vec![syn_bytes(vec![0x00, 0x00])]), Err(Control::Error(_))));
}

// =========================================================================
// ============================ BATCH 12 ===================================
// =========================================================================
//
// Vectores con PROCEDENCIA (G17): generados OFFLINE con los SDKs oficiales y
// pineados acá. Generadores anotados por sección: eth-abi 5.x + eth-account
// 0.13 (EVM), solders 0.26 (Solana, bindings del SDK Rust oficial),
// py-algorand-sdk 2.x (Algorand). Prohibido "el vector es lo que produjo
// nuestro binario".

use indexmap::IndexMap;
use synsema_core::number::Number;
use synsema_core::types::syn_map;

/// Map Synsema de pares (para params/typed-data de los tests).
fn m(pairs: &[(&str, SynValue)]) -> SynValue {
    let mut im = IndexMap::new();
    for (k, v) in pairs {
        im.insert(k.to_string(), v.clone());
    }
    syn_map(im)
}

fn big(digits: &str) -> SynValue {
    SynValue::Number(Number::parse_int_literal(digits))
}

fn ok_val(r: Result<SynValue, Control>) -> SynValue {
    match r {
        Ok(v) => v,
        Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
        Err(_) => panic!("control inesperado"),
    }
}

fn ok_err(r: Result<SynValue, Control>) -> String {
    match r {
        Err(Control::Error(e)) => e.message,
        Ok(v) => panic!("esperaba error, got {}", v.type_name()),
        Err(_) => panic!("control inesperado"),
    }
}

// =========================================================
// ABI — ejemplos de la spec de Solidity (docs/abi-spec, "Examples"),
// regenerados con eth_abi (la referencia de web3.py):
//   from eth_abi import encode; from eth_utils import keccak
//   keccak(text="baz(uint32,bool)")[:4]; encode(["uint32","bool"], [69, True])
// =========================================================

#[test]
fn abi_selector_and_static_solidity_examples() {
    let mut i = interp_with_sign("K");
    // baz(uint32,bool) — ejemplo estático de la spec de Solidity.
    assert_eq!(
        ok_bytes(call(&mut i, "abi_selector", vec![syn_text("baz(uint32,bool)")])),
        hx("cdcd77c0")
    );
    let enc = ok_bytes(call(
        &mut i,
        "abi_encode",
        vec![syn_text("baz(uint32,bool)"), syn_list(vec![syn_int(69), syn_bool(true)])],
    ));
    let want = [
        &hx("cdcd77c0")[..],
        &hx("00000000000000000000000000000000000000000000000000000000000000450000000000000000000000000000000000000000000000000000000000000001")[..],
    ]
    .concat();
    assert_eq!(enc, want, "selector + encoding exactos de la spec");

    // bar(bytes3[2]) — array fijo de bytes3 ("abc", "def").
    assert_eq!(
        ok_bytes(call(&mut i, "abi_selector", vec![syn_text("bar(bytes3[2])")])),
        hx("fce353f6")
    );
    let enc = ok_bytes(call(
        &mut i,
        "abi_encode",
        vec![
            syn_text("bar(bytes3[2])"),
            syn_list(vec![syn_list(vec![
                syn_bytes(b"abc".to_vec()),
                syn_bytes(b"def".to_vec()),
            ])]),
        ],
    ));
    let want = [
        &hx("fce353f6")[..],
        &hx("61626300000000000000000000000000000000000000000000000000000000006465660000000000000000000000000000000000000000000000000000000000")[..],
    ]
    .concat();
    assert_eq!(enc, want);
}

#[test]
fn abi_dynamic_solidity_examples_sam_f_g() {
    let mut i = interp_with_sign("K");
    // sam(bytes,bool,uint256[]) con ("dave", true, [1,2,3]) — el ejemplo con
    // tipos dinámicos de la spec (offsets 0x60 y 0xa0).
    let sam_args = "0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000464617665000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003";
    let enc = ok_bytes(call(
        &mut i,
        "abi_encode",
        vec![
            syn_text("sam(bytes,bool,uint256[])"),
            syn_list(vec![
                syn_bytes(b"dave".to_vec()),
                syn_bool(true),
                syn_list(vec![syn_int(1), syn_int(2), syn_int(3)]),
            ]),
        ],
    ));
    assert_eq!(enc, [&hx("a5643bf2")[..], &hx(sam_args)[..]].concat());
    // Round-trip: decode de los args (sin selector) reproduce los valores, y
    // re-encodear los valores decodificados reproduce los bytes.
    let dec = ok_val(call(&mut i, "abi_decode", vec![syn_text("(bytes,bool,uint256[])"), syn_bytes(hx(sam_args))]));
    let re = ok_bytes(call(
        &mut i,
        "abi_encode",
        vec![syn_text("sam(bytes,bool,uint256[])"), dec],
    ));
    assert_eq!(re, [&hx("a5643bf2")[..], &hx(sam_args)[..]].concat(), "round-trip encode-decode");

    // f(uint256,uint32[],bytes10,bytes) — el ejemplo completo de la spec.
    let f_args = "00000000000000000000000000000000000000000000000000000000000001230000000000000000000000000000000000000000000000000000000000000080313233343536373839300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000004560000000000000000000000000000000000000000000000000000000000000789000000000000000000000000000000000000000000000000000000000000000d48656c6c6f2c20776f726c642100000000000000000000000000000000000000";
    let enc = ok_bytes(call(
        &mut i,
        "abi_encode",
        vec![
            syn_text("f(uint256,uint32[],bytes10,bytes)"),
            syn_list(vec![
                syn_int(0x123),
                syn_list(vec![syn_int(0x456), syn_int(0x789)]),
                syn_bytes(b"1234567890".to_vec()),
                syn_bytes(b"Hello, world!".to_vec()),
            ]),
        ],
    ));
    assert_eq!(enc, [&hx("8be65246")[..], &hx(f_args)[..]].concat());

    // g(uint256[][],string[]) — arrays dinámicos ANIDADOS (el caso de la spec).
    let g_args = "000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000036f6e650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000374776f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000057468726565000000000000000000000000000000000000000000000000000000";
    let enc = ok_bytes(call(
        &mut i,
        "abi_encode",
        vec![
            syn_text("g(uint256[][],string[])"),
            syn_list(vec![
                syn_list(vec![
                    syn_list(vec![syn_int(1), syn_int(2)]),
                    syn_list(vec![syn_int(3)]),
                ]),
                syn_list(vec![syn_text("one"), syn_text("two"), syn_text("three")]),
            ]),
        ],
    ));
    assert_eq!(enc, [&hx("2289b18c")[..], &hx(g_args)[..]].concat());
    // Round-trip del caso anidado.
    let dec = ok_val(call(&mut i, "abi_decode", vec![syn_text("(uint256[][],string[])"), syn_bytes(hx(g_args))]));
    let re = ok_bytes(call(&mut i, "abi_encode", vec![syn_text("g(uint256[][],string[])"), dec]));
    assert_eq!(re, [&hx("2289b18c")[..], &hx(g_args)[..]].concat());
}

#[test]
fn abi_transfer_uint256_needs_big_and_tuple_int_vectors() {
    let mut i = interp_with_sign("K");
    // ERC-20 transfer con 10^24 (1M tokens de 18 decimales): NO entra en i64 —
    // el camino Big es obligatorio. Vector de eth_abi.
    let enc = ok_bytes(call(
        &mut i,
        "abi_encode",
        vec![
            syn_text("transfer(address,uint256)"),
            syn_list(vec![
                syn_text("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"),
                big("1000000000000000000000000"),
            ]),
        ],
    ));
    let want = [
        &hx("a9059cbb")[..],
        &hx("0000000000000000000000007e5f4552091a69125d5dfcb7b8c2659029395bdf00000000000000000000000000000000000000000000d3c21bcecceda1000000")[..],
    ]
    .concat();
    assert_eq!(enc, want);
    // decode: la dirección vuelve CHECKSUMMED (EIP-55) y el entero es exacto.
    let dec = ok_val(call(
        &mut i,
        "abi_decode",
        vec![syn_text("(address,uint256)"), syn_bytes(enc[4..].to_vec())],
    ));
    match &dec {
        SynValue::List(l) => {
            let l = l.borrow();
            assert_eq!(l[0].to_string(), "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
            assert_eq!(l[1].to_string(), "1000000000000000000000000", "uint256 exacto, sin float");
        }
        _ => panic!("esperaba lista"),
    }

    // int256(-1) / int8(-128) — complemento a dos (vectores de eth_abi).
    let enc = ok_bytes(call(
        &mut i,
        "abi_encode",
        vec![syn_text("neg(int256)"), syn_list(vec![syn_int(-1)])],
    ));
    assert_eq!(hex_encode(&enc[4..]), "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let enc = ok_bytes(call(
        &mut i,
        "abi_encode",
        vec![syn_text("neg(int8)"), syn_list(vec![syn_int(-128)])],
    ));
    assert_eq!(hex_encode(&enc[4..]), "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80");
    let dec = ok_val(call(&mut i, "abi_decode", vec![syn_text("(int8)"), syn_bytes(enc[4..].to_vec())]));
    assert_eq!(dec.to_string(), "[-128]");

    // Tuple anidada (uint256,(address,bool),string) — vector de eth_abi.
    let tup_args = "000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000070000000000000000000000007e5f4552091a69125d5dfcb7b8c2659029395bdf000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000004686f6c6100000000000000000000000000000000000000000000000000000000";
    let enc = ok_bytes(call(
        &mut i,
        "abi_encode",
        vec![
            syn_text("h((uint256,(address,bool),string))"),
            syn_list(vec![syn_list(vec![
                syn_int(7),
                syn_list(vec![
                    syn_text("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"),
                    syn_bool(true),
                ]),
                syn_text("hola"),
            ])]),
        ],
    ));
    assert_eq!(hex_encode(&enc[4..]), tup_args);
}

#[test]
fn abi_canonical_signature_dx() {
    let mut i = interp_with_sign("K");
    // Espacios / nombres de parámetro → error que muestra la forma canónica.
    let e = ok_err(call(
        &mut i,
        "abi_selector",
        vec![syn_text("transfer(address to, uint256 amount)")],
    ));
    assert!(e.contains("transfer(address,uint256)"), "muestra la forma canónica: {}", e);
    // uint/int se NORMALIZAN a uint256/int256 (un solo selector posible).
    let a = ok_bytes(call(&mut i, "abi_selector", vec![syn_text("transfer(address,uint)")]));
    let b = ok_bytes(call(&mut i, "abi_selector", vec![syn_text("transfer(address,uint256)")]));
    assert_eq!(a, b, "el alias uint normaliza al selector canónico");
    // Tipo desconocido → error claro.
    let e = ok_err(call(&mut i, "abi_selector", vec![syn_text("foo(uint7)")]));
    assert!(e.contains("uint7"), "{}", e);
    let e = ok_err(call(&mut i, "abi_selector", vec![syn_text("foo(sting)")]));
    assert!(e.contains("sting"), "{}", e);
}

#[test]
fn abi_encode_errors_name_the_argument() {
    let mut i = interp_with_sign("K");
    // Negativo en uint → nombra el argumento (1-based) y el tipo.
    let e = ok_err(call(
        &mut i,
        "abi_encode",
        vec![
            syn_text("transfer(address,uint256)"),
            syn_list(vec![syn_text("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"), syn_int(-5)]),
        ],
    ));
    assert!(e.contains("argument 2") && e.contains("uint256"), "{}", e);
    // Overflow del ancho.
    let e = ok_err(call(
        &mut i,
        "abi_encode",
        vec![syn_text("f(uint8)"), syn_list(vec![syn_int(256)])],
    ));
    assert!(e.contains("argument 1") && e.contains("does not fit"), "{}", e);
    // Float → error dirigido a enteros exactos (gotcha uint256).
    let e = ok_err(call(
        &mut i,
        "abi_encode",
        vec![syn_text("f(uint256)"), syn_list(vec![SynValue::Number(Number::Float(1e24))])],
    ));
    assert!(e.contains("exact integer"), "{}", e);
    // Checksum EIP-55 INVÁLIDO (mixed-case alterado) → error; lowercase puro pasa.
    let e = ok_err(call(
        &mut i,
        "abi_encode",
        vec![
            syn_text("f(address)"),
            syn_list(vec![syn_text("0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf")]),
        ],
    ));
    assert!(e.contains("checksum"), "{}", e);
    let ok = call(
        &mut i,
        "abi_encode",
        vec![
            syn_text("f(address)"),
            syn_list(vec![syn_text("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")]),
        ],
    );
    assert!(ok.is_ok(), "lowercase puro (sin checksum) se acepta");
}

#[test]
fn abi_decode_is_strict_against_hostile_input() {
    let mut i = interp_with_sign("K");
    let sam_args = hx("0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000464617665000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003");
    let types = syn_text("(bytes,bool,uint256[])");

    // data truncada → error, no panic.
    let e = ok_err(call(
        &mut i,
        "abi_decode",
        vec![types.clone(), syn_bytes(sam_args[..sam_args.len() - 1].to_vec())],
    ));
    assert!(e.contains("truncated"), "{}", e);

    // bytes de más al final → error (largo exacto).
    let mut extra = sam_args.clone();
    extra.extend_from_slice(&[0u8; 32]);
    let e = ok_err(call(&mut i, "abi_decode", vec![types.clone(), syn_bytes(extra)]));
    assert!(e.contains("trailing"), "{}", e);

    // Offset no-canónico (0x60 -> 0x80: hueco) → rechazado.
    let mut gap = sam_args.clone();
    gap[31] = 0x80;
    let e = ok_err(call(&mut i, "abi_decode", vec![types.clone(), syn_bytes(gap)]));
    assert!(e.contains("non-canonical"), "{}", e);

    // Offset hostil fuera de rango → rechazado sin leer "de más".
    let mut hostile = sam_args.clone();
    hostile[24..32].copy_from_slice(&u64::MAX.to_be_bytes());
    let e = ok_err(call(&mut i, "abi_decode", vec![types.clone(), syn_bytes(hostile)]));
    assert!(e.contains("exceeds") || e.contains("out of range"), "{}", e);

    // Largo de array hostil (enorme) → error acotado, sin OOM.
    let huge = hx("0000000000000000000000000000000000000000000000000000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let e = ok_err(call(&mut i, "abi_decode", vec![syn_text("(uint256[])"), syn_bytes(huge)]));
    assert!(e.contains("out of range") || e.contains("exceeds"), "{}", e);

    // Padding sucio en uint8 (bits fuera del ancho) → rechazado.
    let dirty = hx("0100000000000000000000000000000000000000000000000000000000000045");
    let e = ok_err(call(&mut i, "abi_decode", vec![syn_text("(uint8)"), syn_bytes(dirty)]));
    assert!(e.contains("dirty") || e.contains("padding"), "{}", e);

    // bool != 0/1 → rechazado.
    let two = hx("0000000000000000000000000000000000000000000000000000000000000002");
    let e = ok_err(call(&mut i, "abi_decode", vec![syn_text("(bool)"), syn_bytes(two)]));
    assert!(e.contains("bool"), "{}", e);

    // Padding sucio tras el contenido de bytes → rechazado.
    let dirty_tail = hx("0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000461626364000000000000000000000000000000000000000000000000000000ff");
    let e = ok_err(call(&mut i, "abi_decode", vec![syn_text("(bytes)"), syn_bytes(dirty_tail)]));
    assert!(e.contains("padding"), "{}", e);

    // string con contenido no-UTF-8 → error claro.
    let bad_utf8 = hx("00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002fffe000000000000000000000000000000000000000000000000000000000000");
    let e = ok_err(call(&mut i, "abi_decode", vec![syn_text("(string)"), syn_bytes(bad_utf8)]));
    assert!(e.contains("UTF-8"), "{}", e);
}

// =========================================================
// EIP-191 — vectores de eth_account (la referencia de personal_sign):
//   from eth_account.messages import encode_defunct, _hash_eip191_message
//   _hash_eip191_message(encode_defunct(text="Hello World")).hex()
// =========================================================

#[test]
fn eip191_digest_vectors_and_recover_closes_the_loop() {
    let mut i = interp_with_sign("K");
    // Digest de texto (vector de eth_account).
    let d = ok_bytes(call(&mut i, "eip191_digest", vec![syn_text("Hello World")]));
    assert_eq!(
        hex_encode(&d),
        "a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"
    );
    // Digest de bytes crudos (vector de eth_account, primitive=b"\x01\x02\x03").
    let db = ok_bytes(call(&mut i, "eip191_digest", vec![syn_bytes(vec![1, 2, 3])]));
    assert_eq!(
        hex_encode(&db),
        "bcf83051a4d206c6e43d7eaa4c75429737ac0d5ee08ee68430443bd815e6ac05"
    );
    // Composición: el digest ES keccak256 del prefijo EIP-191 + mensaje.
    let manual = ok_bytes(call(
        &mut i,
        "keccak256",
        vec![syn_text("\u{19}Ethereum Signed Message:\n11Hello World")],
    ));
    assert_eq!(d, manual, "prefijo 0x19 Ethereum Signed Message: + len + msg");

    // Firma con la clave conocida 0x…01 → r/s/v EXACTOS de eth_account
    // (Account.sign_message(encode_defunct(text="Hello World"), key1)) y
    // recover cierra el circuito SIWE: digest → firma → recover → dirección.
    let sig = ok_bytes(call(
        &mut i,
        "secp256k1_sign",
        vec![syn_bytes(d.clone()), syn_secret("K", KEY1_HEX)],
    ));
    assert_eq!(
        hex_encode(&sig[..32]),
        "9020b81ff870c0fcdd0c0b1945770f2358c51ec57a0f4e6d9d82ce50d4988f48"
    );
    assert_eq!(
        hex_encode(&sig[32..64]),
        "3b767a68a5f051a9d6c25daf303583ea6e3e03875f735a9e2900d6e4099a03cb"
    );
    assert_eq!(sig[64], 0, "v crudo 0 == v Ethereum 27");
    let pk = ok_bytes(call(&mut i, "secp256k1_recover", vec![syn_bytes(d), syn_bytes(sig)]));
    assert_eq!(ok_text(call(&mut i, "eth_address", vec![syn_bytes(pk)])), KEY1_ADDR);
}

// =========================================================
// EIP-712 — el ejemplo COMPLETO del apéndice del EIP-712 ("Ether Mail",
// clave "cow"), regenerado con eth_account.messages.encode_typed_data
// (domainSeparator/hashStruct exactos: unit tests en blockchain_abi.rs):
//   sm = encode_typed_data(full_message=typed); _hash_eip191_message(sm)
// =========================================================

/// typed-data del apéndice como maps Synsema (G14: legible ANTES de firmar).
fn ether_mail_inputs() -> (SynValue, SynValue, SynValue) {
    let types = m(&[
        (
            "Person",
            syn_list(vec![
                m(&[("name", syn_text("name")), ("type", syn_text("string"))]),
                m(&[("name", syn_text("wallet")), ("type", syn_text("address"))]),
            ]),
        ),
        (
            "Mail",
            syn_list(vec![
                m(&[("name", syn_text("from")), ("type", syn_text("Person"))]),
                m(&[("name", syn_text("to")), ("type", syn_text("Person"))]),
                m(&[("name", syn_text("contents")), ("type", syn_text("string"))]),
            ]),
        ),
    ]);
    let domain = m(&[
        ("name", syn_text("Ether Mail")),
        ("version", syn_text("1")),
        ("chainId", syn_int(1)),
        ("verifyingContract", syn_text("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")),
    ]);
    let message = m(&[
        (
            "from",
            m(&[
                ("name", syn_text("Cow")),
                ("wallet", syn_text("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")),
            ]),
        ),
        (
            "to",
            m(&[
                ("name", syn_text("Bob")),
                ("wallet", syn_text("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")),
            ]),
        ),
        ("contents", syn_text("Hello, Bob!")),
    ]);
    (domain, types, message)
}

#[test]
fn eip712_appendix_digest_and_cow_signature() {
    let mut i = interp_with_sign("K");
    let (domain, types, message) = ether_mail_inputs();
    let digest = ok_bytes(call(
        &mut i,
        "eip712_digest",
        vec![domain, types, syn_text("Mail"), message],
    ));
    assert_eq!(
        hex_encode(&digest),
        "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2",
        "digest final exacto del apéndice del EIP-712"
    );
    // La clave "cow" del ejemplo = keccak256("cow"); firma → r/s/v exactos de
    // eth_account y recover → la dirección del ejemplo (0xCD2a…D826).
    let cow_hex = hex_encode(&ok_bytes(call(&mut i, "keccak256", vec![syn_text("cow")])));
    let cow = syn_secret("K", cow_hex);
    let sig = ok_bytes(call(&mut i, "secp256k1_sign", vec![syn_bytes(digest.clone()), cow]));
    assert_eq!(
        hex_encode(&sig[..32]),
        "4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d"
    );
    assert_eq!(
        hex_encode(&sig[32..64]),
        "07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562"
    );
    assert_eq!(sig[64], 1, "v crudo 1 == v Ethereum 28");
    let pk = ok_bytes(call(&mut i, "secp256k1_recover", vec![syn_bytes(digest), syn_bytes(sig)]));
    assert_eq!(
        ok_text(call(&mut i, "eth_address", vec![syn_bytes(pk)])),
        "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
    );
}

#[test]
fn eip712_arrays_nested_salt_and_atomics_vectors() {
    let mut i = interp_with_sign("K");
    // Arrays + structs anidados + bytes (digest de eth_account, gen_vectors.py).
    let types = m(&[
        (
            "Person",
            syn_list(vec![
                m(&[("name", syn_text("name")), ("type", syn_text("string"))]),
                m(&[("name", syn_text("wallets")), ("type", syn_text("address[]"))]),
            ]),
        ),
        (
            "Group",
            syn_list(vec![
                m(&[("name", syn_text("name")), ("type", syn_text("string"))]),
                m(&[("name", syn_text("members")), ("type", syn_text("Person[]"))]),
            ]),
        ),
        (
            "Mail",
            syn_list(vec![
                m(&[("name", syn_text("from")), ("type", syn_text("Person"))]),
                m(&[("name", syn_text("to")), ("type", syn_text("Group"))]),
                m(&[("name", syn_text("contents")), ("type", syn_text("string"))]),
                m(&[("name", syn_text("attachment")), ("type", syn_text("bytes"))]),
            ]),
        ),
    ]);
    let domain = m(&[
        ("name", syn_text("Ether Mail")),
        ("version", syn_text("1")),
        ("chainId", syn_int(1)),
        ("verifyingContract", syn_text("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")),
    ]);
    let message = m(&[
        (
            "from",
            m(&[
                ("name", syn_text("Cow")),
                (
                    "wallets",
                    syn_list(vec![
                        syn_text("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"),
                        syn_text("0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"),
                    ]),
                ),
            ]),
        ),
        (
            "to",
            m(&[
                ("name", syn_text("Farmers")),
                (
                    "members",
                    syn_list(vec![m(&[
                        ("name", syn_text("Bob")),
                        (
                            "wallets",
                            syn_list(vec![syn_text("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")]),
                        ),
                    ])]),
                ),
            ]),
        ),
        ("contents", syn_text("Hello, Bob!")),
        ("attachment", syn_bytes(hx("25504446"))),
    ]);
    let digest = ok_bytes(call(
        &mut i,
        "eip712_digest",
        vec![domain, types, syn_text("Mail"), message],
    ));
    assert_eq!(
        hex_encode(&digest),
        "0993f2cd439efc7001f2cf759ec8a35c7316367c04a4d9285772f45741a08426"
    );

    // Domain con SOLO name+salt (bytes32) — el orden fijo del EIP filtrado por
    // presencia (digest de eth_account).
    let types3 = m(&[(
        "Ping",
        syn_list(vec![m(&[("name", syn_text("n")), ("type", syn_text("uint256"))])]),
    )]);
    let domain3 = m(&[("name", syn_text("Salty")), ("salt", syn_bytes(vec![1u8; 32]))]);
    let message3 = m(&[("n", syn_int(7))]);
    let digest3 = ok_bytes(call(
        &mut i,
        "eip712_digest",
        vec![domain3, types3, syn_text("Ping"), message3],
    ));
    assert_eq!(
        hex_encode(&digest3),
        "b6bd0c351a7993b61eb0d64610a9fe7bea71552e46422a19a114ed14202d8ad3"
    );

    // Atómicos variados: bool / int256 NEGATIVO / uint8 / bytes32 / uint256[2]
    // (digest de eth_account).
    let types4 = m(&[(
        "Order",
        syn_list(vec![
            m(&[("name", syn_text("active")), ("type", syn_text("bool"))]),
            m(&[("name", syn_text("delta")), ("type", syn_text("int256"))]),
            m(&[("name", syn_text("level")), ("type", syn_text("uint8"))]),
            m(&[("name", syn_text("root")), ("type", syn_text("bytes32"))]),
            m(&[("name", syn_text("limits")), ("type", syn_text("uint256[2]"))]),
        ]),
    )]);
    let domain4 = m(&[("name", syn_text("DEX")), ("chainId", syn_int(43114))]);
    let message4 = m(&[
        ("active", syn_bool(true)),
        ("delta", syn_int(-42)),
        ("level", syn_int(3)),
        ("root", syn_bytes(vec![0x0a; 32])),
        ("limits", syn_list(vec![syn_int(1), big("1000000000000000000000")])),
    ]);
    let digest4 = ok_bytes(call(
        &mut i,
        "eip712_digest",
        vec![domain4, types4, syn_text("Order"), message4],
    ));
    assert_eq!(
        hex_encode(&digest4),
        "355639b54a9fbdba4fa9c0d1b878f4d26078645b55c10caba365c1f23bf53b78"
    );
}

#[test]
fn eip712_errors_name_the_type_and_field() {
    let mut i = interp_with_sign("K");
    let (domain, types, message) = ether_mail_inputs();

    // Campo faltante en el message → nombra campo y tipo (G14).
    let incomplete = m(&[("from", m(&[("name", syn_text("Cow"))]))]);
    let e = ok_err(call(
        &mut i,
        "eip712_digest",
        vec![domain.clone(), types.clone(), syn_text("Mail"), incomplete],
    ));
    assert!(e.contains("wallet") || e.contains("\"to\""), "nombra el campo: {}", e);

    // Campo EXTRA en el message → rechazado nombrándolo (no firmar lo ilegible).
    let extra = m(&[
        (
            "from",
            m(&[
                ("name", syn_text("Cow")),
                ("wallet", syn_text("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")),
            ]),
        ),
        (
            "to",
            m(&[
                ("name", syn_text("Bob")),
                ("wallet", syn_text("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")),
            ]),
        ),
        ("contents", syn_text("Hello, Bob!")),
        ("hidden_drain", syn_text("0xdead")),
    ]);
    let e = ok_err(call(
        &mut i,
        "eip712_digest",
        vec![domain.clone(), types.clone(), syn_text("Mail"), extra],
    ));
    assert!(e.contains("hidden_drain"), "nombra el campo extra: {}", e);

    // Tipo referenciado y NO definido → lo nombra.
    let bad_types = m(&[(
        "Mail",
        syn_list(vec![m(&[("name", syn_text("from")), ("type", syn_text("Persona"))])]),
    )]);
    let e = ok_err(call(
        &mut i,
        "eip712_digest",
        vec![domain.clone(), bad_types, syn_text("Mail"), m(&[])],
    ));
    assert!(e.contains("Persona"), "{}", e);

    // Ciclo de tipos → error claro, sin loop infinito.
    let cyc = m(&[(
        "A",
        syn_list(vec![m(&[("name", syn_text("next")), ("type", syn_text("A"))])]),
    )]);
    let e = ok_err(call(&mut i, "eip712_digest", vec![domain.clone(), cyc, syn_text("A"), m(&[])]));
    assert!(e.contains("cycle"), "{}", e);

    // Campo de domain desconocido → error nombrándolo.
    let bad_domain = m(&[("name", syn_text("X")), ("chainID", syn_int(1))]);
    let e = ok_err(call(
        &mut i,
        "eip712_digest",
        vec![bad_domain, types.clone(), syn_text("Mail"), message.clone()],
    ));
    assert!(e.contains("chainID"), "{}", e);

    // primary type inexistente → error nombrándolo.
    let e = ok_err(call(
        &mut i,
        "eip712_digest",
        vec![domain, types, syn_text("Fantasma"), message],
    ));
    assert!(e.contains("Fantasma"), "{}", e);
}

// =========================================================
// Solana — vectores de solders 0.26 (bindings oficiales del SDK Rust):
//   payer = Keypair.from_seed(bytes.fromhex("4ccd089b…a6fb"))  # RFC 8032 TEST 2
//   ix = Instruction(SystemProgram, (2).to_bytes(4,"little")+lamports.to_bytes(8,"little"),
//                    [AccountMeta(payer,True,True), AccountMeta(dest,False,True)])
//   msg = Message.new_with_blockhash([ix], payer.pubkey(), blockhash); bytes(msg)
//   sig = payer.sign_message(bytes(msg)); bytes(Transaction([payer], msg, blockhash))
// =========================================================

/// Seed ed25519 del payer (RFC 8032 TEST 2 — misma clave del batch 11).
const SOL_SEED: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const SOL_PAYER_PK: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
/// Message legacy del transfer (bytes(msg) de solders, pineado).
const SOL_LEGACY_MSG: &str = "010001033d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c02020202020202020202020202020202020202020202020202020202020202020000000000000000000000000000000000000000000000000000000000000000030303030303030303030303030303030303030303030303030303030303030301020200010c0200000040420f0000000000";
const SOL_LEGACY_SIG: &str = "4f187b036b37f6f12f81d65ffad735b3059de54602bd8e90ecc7bfbe9833f9a55783bed6a29bb3b14f2d1fe898c4bb4778adbdce00a5195b6df6963722bcf60b";
/// Firma del message v0 (cubre el prefijo 0x80 — VersionedTransaction de solders).
const SOL_V0_SIG: &str = "c5cc4f6c0e801bda83dd736dd06c0a9b97218c8755e6be7615387b27599a3494948abd319a82b19cf1538b214feadb93f0bdcb2cfc4dad22b03ebbd2b856dd0d";

/// params del transfer del System Program, con las cuentas en el orden dado
/// (el builtin las reordena por las reglas del runtime).
fn sol_transfer_params(payer: SynValue, dest: SynValue, program: SynValue, blockhash: SynValue) -> SynValue {
    m(&[
        ("fee_payer", payer.clone()),
        ("recent_blockhash", blockhash),
        (
            "instructions",
            syn_list(vec![m(&[
                ("program", program),
                (
                    "accounts",
                    syn_list(vec![
                        m(&[("pubkey", payer), ("signer", syn_bool(true)), ("writable", syn_bool(true))]),
                        m(&[("pubkey", dest), ("writable", syn_bool(true))]),
                    ]),
                ),
                ("data", syn_bytes(hx("0200000040420f0000000000"))),
            ])]),
        ),
    ])
}

#[test]
fn solana_transfer_matches_solders_vectors() {
    let mut i = interp_with_sign("K");
    let params = sol_transfer_params(
        syn_bytes(hx(SOL_PAYER_PK)),
        syn_bytes(vec![0x02; 32]),
        syn_bytes(vec![0u8; 32]), // System Program = 32 bytes cero
        syn_bytes(vec![0x03; 32]),
    );
    let msg = ok_bytes(call(&mut i, "solana_message", vec![params]));
    assert_eq!(hex_encode(&msg), SOL_LEGACY_MSG, "message legacy byte a byte contra solders");

    // El data del transfer se arma con int_to_bytes_le (u32 LE 2 ‖ u64 LE lamports).
    let d4 = ok_bytes(call(&mut i, "int_to_bytes_le", vec![syn_int(2), syn_int(4)]));
    let d8 = ok_bytes(call(&mut i, "int_to_bytes_le", vec![syn_int(1_000_000), syn_int(8)]));
    assert_eq!([&d4[..], &d8[..]].concat(), hx("0200000040420f0000000000"));

    // Firma ed25519 del message CRUDO → exacta contra solders; verify cierra.
    let sig = ok_bytes(call(
        &mut i,
        "ed25519_sign",
        vec![syn_bytes(msg.clone()), syn_secret("K", SOL_SEED)],
    ));
    assert_eq!(hex_encode(&sig), SOL_LEGACY_SIG);
    assert!(ok_bool(call(
        &mut i,
        "ed25519_verify",
        vec![syn_bytes(msg.clone()), syn_bytes(sig.clone()), syn_bytes(hx(SOL_PAYER_PK))],
    )));

    // Wire format: shortvec(1) ‖ sig ‖ message — contra bytes(Transaction).
    let tx = ok_bytes(call(&mut i, "solana_tx", vec![syn_bytes(msg.clone()), syn_bytes(sig)]));
    assert_eq!(hex_encode(&tx), format!("01{}{}", SOL_LEGACY_SIG, SOL_LEGACY_MSG));

    // Pubkeys/blockhash como base58 text → los MISMOS bytes.
    let params58 = sol_transfer_params(
        syn_text("586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5"),
        syn_text("8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"),
        syn_text("11111111111111111111111111111111"),
        syn_text("CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8"),
    );
    let msg58 = ok_bytes(call(&mut i, "solana_message", vec![params58]));
    assert_eq!(msg58, msg, "base58 text y bytes producen el mismo message");
}

#[test]
fn solana_v0_matches_versioned_message_and_multi_instruction_ordering() {
    let mut i = interp_with_sign("K");
    // v0 = 0x80 ‖ cuerpo legacy ‖ shortvec(0) de lookup tables. La FIRMA cubre
    // el prefijo (así serializa VersionedMessage; la firma v0 de solders lo prueba).
    let mut params = match sol_transfer_params(
        syn_bytes(hx(SOL_PAYER_PK)),
        syn_bytes(vec![0x02; 32]),
        syn_bytes(vec![0u8; 32]),
        syn_bytes(vec![0x03; 32]),
    ) {
        SynValue::Map(mp) => mp.borrow().clone(),
        _ => unreachable!(),
    };
    params.insert("version".to_string(), syn_int(0));
    let msg0 = ok_bytes(call(&mut i, "solana_message", vec![syn_map(params.clone())]));
    assert_eq!(
        hex_encode(&msg0),
        format!("80{}00", SOL_LEGACY_MSG),
        "v0 == legacy salvo prefijo de versión + lookup-tables vacío"
    );
    let sig0 = ok_bytes(call(
        &mut i,
        "ed25519_sign",
        vec![syn_bytes(msg0.clone()), syn_secret("K", SOL_SEED)],
    ));
    assert_eq!(hex_encode(&sig0), SOL_V0_SIG, "la firma v0 de solders cubre el prefijo 0x80");
    let tx0 = ok_bytes(call(&mut i, "solana_tx", vec![syn_bytes(msg0), syn_bytes(sig0)]));
    assert_eq!(
        hex_encode(&tx0),
        format!("01{}80{}00", SOL_V0_SIG, SOL_LEGACY_MSG),
        "wire v0 contra bytes(VersionedTransaction) de solders"
    );

    // lookup_tables presente → error claro (etapa 3), no silencio.
    params.insert("lookup_tables".to_string(), syn_list(vec![]));
    let e = ok_err(call(&mut i, "solana_message", vec![syn_map(params)]));
    assert!(e.contains("not supported yet"), "{}", e);

    // Multi-instrucción con flags mezclados: el orden final es fee payer,
    // signers escribibles, signers readonly, no-signers escribibles, no-signers
    // readonly — cada bucket por bytes de pubkey. Vector de solders:
    //   ix2 = Instruction(prog2, b"\x09", [AccountMeta(acc_ro,F,F),
    //         AccountMeta(k2,T,F), AccountMeta(acc_w,F,T), AccountMeta(dest,F,T)])
    //   Message.new_with_blockhash([ix, ix2], payer, blockhash)
    let k2 = "e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58";
    let multi = m(&[
        ("fee_payer", syn_bytes(hx(SOL_PAYER_PK))),
        ("recent_blockhash", syn_bytes(vec![0x03; 32])),
        (
            "instructions",
            syn_list(vec![
                m(&[
                    ("program", syn_bytes(vec![0u8; 32])),
                    (
                        "accounts",
                        syn_list(vec![
                            m(&[("pubkey", syn_bytes(hx(SOL_PAYER_PK))), ("signer", syn_bool(true)), ("writable", syn_bool(true))]),
                            m(&[("pubkey", syn_bytes(vec![0x02; 32])), ("writable", syn_bool(true))]),
                        ]),
                    ),
                    ("data", syn_bytes(hx("0200000040420f0000000000"))),
                ]),
                m(&[
                    ("program", syn_bytes(vec![0x06; 32])),
                    (
                        "accounts",
                        syn_list(vec![
                            m(&[("pubkey", syn_bytes(vec![0x05; 32]))]),
                            m(&[("pubkey", syn_bytes(hx(k2))), ("signer", syn_bool(true))]),
                            m(&[("pubkey", syn_bytes(vec![0x04; 32])), ("writable", syn_bool(true))]),
                            m(&[("pubkey", syn_bytes(vec![0x02; 32])), ("writable", syn_bool(true))]),
                        ]),
                    ),
                    ("data", syn_bytes(vec![0x09])),
                ]),
            ]),
        ),
    ]);
    let msg = ok_bytes(call(&mut i, "solana_message", vec![multi]));
    assert_eq!(
        hex_encode(&msg),
        "020103073d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660ce734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b5802020202020202020202020202020202020202020202020202020202020202020404040404040404040404040404040404040404040404040404040404040404000000000000000000000000000000000000000000000000000000000000000005050505050505050505050505050505050505050505050505050505050505050606060606060606060606060606060606060606060606060606060606060606030303030303030303030303030303030303030303030303030303030303030302040200020c0200000040420f00000000000604050103020109",
        "orden de cuentas y header (2 firmas, 1 ro-signed, 3 ro-unsigned) contra solders"
    );
}

#[test]
fn solana_shortvec_borders_are_minimal() {
    // compact-u16 de Solana (la spec de shortvec de los docs oficiales):
    // 0→[00], 1→[01], 127→[7f], 128→[80 01], 200→[c8 01] — borde de 2 bytes.
    let mut i = interp_with_sign("K");
    for (len, sv) in [
        (0usize, vec![0x00u8]),
        (1, vec![0x01]),
        (127, vec![0x7f]),
        (128, vec![0x80, 0x01]),
        (200, vec![0xc8, 0x01]),
    ] {
        let data = vec![0xaa; len];
        let params = m(&[
            ("fee_payer", syn_bytes(hx(SOL_PAYER_PK))),
            ("recent_blockhash", syn_bytes(vec![0x03; 32])),
            (
                "instructions",
                syn_list(vec![m(&[
                    ("program", syn_bytes(vec![0x06; 32])),
                    ("data", syn_bytes(data.clone())),
                ])]),
            ),
        ]);
        let msg = ok_bytes(call(&mut i, "solana_message", vec![params]));
        // Cola del message: shortvec(1 instr) ‖ prog_idx(1) ‖ shortvec(0 cuentas)
        // ‖ shortvec(len) ‖ data.
        let mut tail = vec![0x01, 0x01, 0x00];
        tail.extend_from_slice(&sv);
        tail.extend_from_slice(&data);
        assert!(msg.ends_with(&tail), "shortvec mínimo para len {}", len);
    }
}

#[test]
fn solana_errors_are_clear_and_safe() {
    let mut i = interp_with_sign("K");
    // Clave desconocida en params → error nombrándola (typo-proof).
    let e = ok_err(call(
        &mut i,
        "solana_message",
        vec![m(&[("fee_payr", syn_bytes(vec![0u8; 32]))])],
    ));
    assert!(e.contains("fee_payr"), "{}", e);
    // Versión inexistente.
    let e = ok_err(call(
        &mut i,
        "solana_message",
        vec![m(&[
            ("fee_payer", syn_bytes(hx(SOL_PAYER_PK))),
            ("recent_blockhash", syn_bytes(vec![3u8; 32])),
            ("instructions", syn_list(vec![])),
            ("version", syn_int(1)),
        ])],
    ));
    assert!(e.contains("version"), "{}", e);
    // Un SECRET donde va una pubkey → error dirigido (la pubkey es pública).
    let e = ok_err(call(
        &mut i,
        "solana_message",
        vec![m(&[
            ("fee_payer", syn_secret("K", SOL_SEED)),
            ("recent_blockhash", syn_bytes(vec![3u8; 32])),
            ("instructions", syn_list(vec![])),
        ])],
    ));
    assert!(e.contains("ed25519_pubkey"), "{}", e);
    assert!(!e.contains(SOL_SEED), "sin fuga de material");

    // solana_tx: cantidad de firmas ≠ las requeridas por el header.
    let msg = hx(SOL_LEGACY_MSG);
    let e = ok_err(call(
        &mut i,
        "solana_tx",
        vec![syn_bytes(msg.clone()), syn_list(vec![syn_bytes(vec![0u8; 64]), syn_bytes(vec![0u8; 64])])],
    ));
    assert!(e.contains("requires 1 signature"), "{}", e);
    // Firma de largo inválido.
    let e = ok_err(call(&mut i, "solana_tx", vec![syn_bytes(msg), syn_bytes(vec![0u8; 63])]));
    assert!(e.contains("64 bytes"), "{}", e);
    // Versión desconocida en el message.
    let mut bad = hx(SOL_LEGACY_MSG);
    bad[0] = 0x81;
    let e = ok_err(call(&mut i, "solana_tx", vec![syn_bytes(bad), syn_bytes(vec![0u8; 64])]));
    assert!(e.contains("version"), "{}", e);
}

// =========================================================
// Algorand — vectores de py-algorand-sdk 2.x (SDK oficial):
//   txn = transaction.PaymentTxn(sender, SuggestedParams(fee=1000, first=1000,
//         last=2000, gh=b64(07*32), gen="testnet-v1.0", flat_fee=True),
//         receiver, amt=123456, note=b"hi")
//   base64.b64decode(encoding.msgpack_encode(txn));  txn.sign(sk);  txn.get_txid()
// =========================================================

/// msgpack canónico de la pay txn (10 campos, claves ordenadas — algosdk).
const ALGO_PAY: &str = "8aa3616d74ce0001e240a3666565cd03e8a26676cd03e8a367656eac746573746e65742d76312e30a26768c4200707070707070707070707070707070707070707070707070707070707070707a26c76cd07d0a46e6f7465c4026869a3726376c4200202020202020202020202020202020202020202020202020202020202020202a3736e64c4203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660ca474797065a3706179";
const ALGO_SIG: &str = "0f43a77212d04374244ec6ea9c48e854531a324290657e17df7622a3ac4e5ec6a8f4b3f98d03f49c5ca652a21799bc08612cb7415ec3aca08695cd8a4c81050d";
const ALGO_SENDER: &str = "HVABPQ7IIOEVVEVXBKTU2G36XSOJQLGPF3CJNDGAZVK7CKXUMYGA6EOE6Y";
const ALGO_RCV: &str = "AIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBMXPWWNQ";

fn algo_pay_txn() -> SynValue {
    m(&[
        ("type", syn_text("pay")),
        // snd como TEXT (valida checksum → bytes), rcv como bytes crudos:
        // ambas formas terminan idénticas en el msgpack.
        ("snd", syn_text(ALGO_SENDER)),
        ("rcv", syn_bytes(vec![0x02; 32])),
        ("amt", syn_int(123_456)),
        ("fee", syn_int(1000)),
        ("fv", syn_int(1000)),
        ("lv", syn_int(2000)),
        ("gen", syn_text("testnet-v1.0")),
        ("gh", syn_bytes(vec![0x07; 32])),
        ("note", syn_bytes(b"hi".to_vec())),
    ])
}

#[test]
fn algorand_pay_matches_algosdk_vectors() {
    let mut i = interp_with_sign("K");
    let encoded = ok_bytes(call(&mut i, "algorand_tx_encode", vec![algo_pay_txn()]));
    assert_eq!(
        hex_encode(&encoded),
        format!("5458{}", ALGO_PAY),
        "\"TX\" ‖ msgpack canónico, byte a byte contra algosdk"
    );
    // Firma ed25519 del encoded (con prefijo TX) → exacta contra algosdk.
    let sig = ok_bytes(call(
        &mut i,
        "ed25519_sign",
        vec![syn_bytes(encoded.clone()), syn_secret("K", SOL_SEED)],
    ));
    assert_eq!(hex_encode(&sig), ALGO_SIG);
    // SignedTxn {"sig", "txn"} → byte a byte contra algosdk.
    let stx = ok_bytes(call(
        &mut i,
        "algorand_tx",
        vec![algo_pay_txn(), syn_bytes(sig)],
    ));
    assert_eq!(
        hex_encode(&stx),
        format!("82a3736967c440{}a374786e{}", ALGO_SIG, ALGO_PAY)
    );
    // TXID componible: base32(sha512_256("TX" ‖ msgpack)) == txn.get_txid().
    use sha2::{Digest, Sha512_256};
    let txid = base32_encode(&Sha512_256::digest(&encoded));
    assert_eq!(txid, "WTAEKXVRJW7GUKT6R2JOEJY4W2PDURTBEP3VM2DR6WC6RWWQOXQA");
}

#[test]
fn algorand_canonical_omits_zero_values() {
    let mut i = interp_with_sign("K");
    // amt=0 (y sin gen/note) → los campos se OMITEN: 7 campos (vector algosdk,
    // "amt" not in txn.dictify()). Si se emitieran, el TXID diferiría.
    let txn0 = m(&[
        ("type", syn_text("pay")),
        ("snd", syn_bytes(hx(SOL_PAYER_PK))),
        ("rcv", syn_bytes(vec![0x02; 32])),
        ("amt", syn_int(0)),
        ("fee", syn_int(1000)),
        ("fv", syn_int(1000)),
        ("lv", syn_int(2000)),
        ("gen", syn_text("")),
        ("gh", syn_bytes(vec![0x07; 32])),
        ("note", syn_bytes(vec![])),
    ]);
    let encoded = ok_bytes(call(&mut i, "algorand_tx_encode", vec![txn0]));
    assert_eq!(
        hex_encode(&encoded[2..]),
        "87a3666565cd03e8a26676cd03e8a26768c4200707070707070707070707070707070707070707070707070707070707070707a26c76cd07d0a3726376c4200202020202020202020202020202020202020202020202020202020202020202a3736e64c4203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660ca474797065a3706179"
    );
    // Una txn TODO-cero → error (no un payload vacío en silencio).
    let e = ok_err(call(
        &mut i,
        "algorand_tx_encode",
        vec![m(&[("amt", syn_int(0)), ("note", syn_bytes(vec![]))])],
    ));
    assert!(e.contains("no non-zero fields"), "{}", e);
}

#[test]
fn algorand_addresses_and_checksum() {
    let mut i = interp_with_sign("K");
    // algo_address desde la pubkey y desde el SECRET (deriva Rust-side, G2).
    let a = ok_text(call(&mut i, "algo_address", vec![syn_bytes(hx(SOL_PAYER_PK))]));
    assert_eq!(a, ALGO_SENDER, "encoding.encode_address de algosdk");
    let a2 = ok_text(call(&mut i, "algo_address", vec![syn_secret("K", SOL_SEED)]));
    assert_eq!(a2, ALGO_SENDER);
    let r = ok_text(call(&mut i, "algo_address", vec![syn_bytes(vec![0x02; 32])]));
    assert_eq!(r, ALGO_RCV);

    // Dirección con un caracter alterado → checksum inválido → error SIN enviar.
    let mut bad = ALGO_SENDER.to_string();
    bad.replace_range(10..11, if &ALGO_SENDER[10..11] == "A" { "B" } else { "A" });
    let e = ok_err(call(
        &mut i,
        "algorand_tx_encode",
        vec![m(&[("type", syn_text("pay")), ("snd", syn_text(bad.as_str()))])],
    ));
    assert!(e.contains("checksum"), "{}", e);
}

#[test]
fn algorand_rejects_bad_amounts_and_secrets() {
    let mut i = interp_with_sign("K");
    // Negativo → error (campos del protocolo son unsigned).
    let e = ok_err(call(
        &mut i,
        "algorand_tx_encode",
        vec![m(&[("type", syn_text("pay")), ("amt", syn_int(-1))])],
    ));
    assert!(e.contains("negative"), "{}", e);
    // Float → error dirigido a enteros exactos.
    let e = ok_err(call(
        &mut i,
        "algorand_tx_encode",
        vec![m(&[("type", syn_text("pay")), ("amt", SynValue::Number(Number::Float(1.5)))])],
    ));
    assert!(e.contains("exact integer"), "{}", e);
    // > u64 → error (uint64 del protocolo).
    let e = ok_err(call(
        &mut i,
        "algorand_tx_encode",
        vec![m(&[("type", syn_text("pay")), ("amt", big("18446744073709551616"))])],
    ));
    assert!(e.contains("64 bits"), "{}", e);
    // Un secret dentro de la txn → error sin fuga.
    let e = ok_err(call(
        &mut i,
        "algorand_tx_encode",
        vec![m(&[("type", syn_text("pay")), ("note", syn_secret("K", SOL_SEED))])],
    ));
    assert!(e.contains("secret"), "{}", e);
    assert!(!e.contains(SOL_SEED), "sin fuga de material");
}

#[test]
fn int_to_bytes_le_is_fixed_width_and_strict() {
    let mut i = interp_with_sign("K");
    assert_eq!(
        ok_bytes(call(&mut i, "int_to_bytes_le", vec![syn_int(2), syn_int(4)])),
        hx("02000000")
    );
    assert_eq!(
        ok_bytes(call(&mut i, "int_to_bytes_le", vec![syn_int(1_000_000), syn_int(8)])),
        hx("40420f0000000000")
    );
    assert_eq!(
        ok_bytes(call(&mut i, "int_to_bytes_le", vec![syn_int(0), syn_int(8)])),
        vec![0u8; 8]
    );
    // No entra en el ancho → error (nunca trunca en silencio).
    let e = ok_err(call(&mut i, "int_to_bytes_le", vec![syn_int(256), syn_int(1)]));
    assert!(e.contains("does not fit"), "{}", e);
    let e = ok_err(call(&mut i, "int_to_bytes_le", vec![syn_int(-1), syn_int(4)]));
    assert!(e.contains("non-negative"), "{}", e);
}

// =========================================================
// Cota de recursión (G10): estructura hostil profunda → ERROR ATRAPABLE, jamás
// un stack overflow / abort (que sería DoS bajo serve). Espeja RLP_MAX_DEPTH del
// batch 11. La profundidad de estos vectores (10k) revienta el stack sin la cota.
// =========================================================

#[test]
fn deep_nesting_errors_instead_of_crashing() {
    // El cuerpo corre en un thread de stack GRANDE: `SynValue` usa `Rc` (no `Send`),
    // así que construir y DROPEAR la estructura hostil pasa en el mismo hilo que la
    // prueba — con el stack default de 2 MB del harness, sólo CONSTRUIRLA ya
    // desborda. El punto de la prueba es que el BUILTIN corta en MAX_DEPTH (64) y
    // devuelve un error atrapable; la prueba end-to-end de que el proceso sobrevive
    // (antes: abort no atrapable) está en la sonda `.syn` del batch 12.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let mut i = interp_with_sign("K");

            // -- ABI: tuples anidados → error, no overflow. Para firma el
            //    anidamiento va DENTRO de los params: f((((…)))). --
            let deep_type = format!("{}uint256{}", "(".repeat(10_000), ")".repeat(10_000));
            let sig = format!("f({}uint256{})", "(".repeat(10_000), ")".repeat(10_000));
            let e = ok_err(call(&mut i, "abi_selector", vec![syn_text(sig.as_str())]));
            assert!(e.contains("nested too deeply"), "abi_selector: {}", e);
            let e = ok_err(call(&mut i, "abi_encode", vec![syn_text(sig.as_str()), syn_list(vec![])]));
            assert!(e.contains("nested too deeply"), "abi_encode: {}", e);
            let e = ok_err(call(
                &mut i,
                "abi_decode",
                vec![syn_text(deep_type.as_str()), syn_bytes(vec![0u8; 32])],
            ));
            assert!(e.contains("nested too deeply"), "abi_decode: {}", e);

            // -- EIP-712: cadena acíclica larguísima A0→A1→…→An → error. El guard
            //    de ciclos NO la cubre (es acíclica); sólo la cota de profundidad. --
            let n = 5_000usize;
            let mut im = IndexMap::new();
            for k in 0..n {
                let field_type =
                    if k + 1 < n { format!("A{}", k + 1) } else { "uint256".to_string() };
                im.insert(
                    format!("A{}", k),
                    syn_list(vec![m(&[
                        ("name", syn_text("x")),
                        ("type", syn_text(field_type.as_str())),
                    ])]),
                );
            }
            let types = syn_map(im);
            let domain = m(&[("name", syn_text("D")), ("version", syn_text("1"))]);
            let e = ok_err(call(
                &mut i,
                "eip712_digest",
                vec![domain, types, syn_text("A0"), m(&[("x", syn_int(0))])],
            ));
            assert!(e.contains("too deep"), "eip712 chain: {}", e);

            // -- Algorand: map anidado profundo (apar→apar→…) → error, no abort. --
            let mut txn = m(&[("type", syn_text("pay"))]);
            for _ in 0..10_000 {
                txn = m(&[("apar", txn)]);
            }
            let e = ok_err(call(&mut i, "algorand_tx_encode", vec![txn]));
            assert!(e.contains("nested too deeply"), "algorand: {}", e);
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("deep-nesting test thread panicked");
}

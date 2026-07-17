//! E2E del Batch 11 (blockchain) por el runtime REAL. Es CÓDIGO DE DINERO: la
//! paranoia de seguridad es el corazón (§8.3/§8.4 del spec).
//!
//! Cubre:
//! - G2: la clave NUNCA se materializa (print/text/json_encode/csv_encode → secret();
//!   no hay builtin que la devuelva).
//! - G3: firma GATEADA por `require sign("NAME")` + audit fail-loud; anti-swap;
//!   denegada dentro de `sandbox` (pero verify/derivación puras funcionan adentro).
//! - G4: errores sin fuga (una clave sembrada NO aparece en el mensaje).
//! - G10: try/recover atrapa; en serve un handler que firma mal → HTTP error, server vivo.
//! - Dogfood: pipeline ETH end-to-end SIN red vía `synsema test` (address/tx/sign/recover).
//! - Composición flagship §6: cron (firma programada) + chart negociado.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::{run_source, run_tests};
use synsema_runtime::serve::run_serve_program;

/// Clave de test conocida (`0x…01`) y su dirección Ethereum (vector del spec). Se
/// SIEMBRA en los tests de no-fuga: su hex NO debe aparecer en ningún error/salida.
const KEY1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const ADDR1: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

/// Serializa los tests que tocan `SYNSEMA_AUDIT_DIR` (env-var del proceso).
static ENV_LOCK: Mutex<()> = Mutex::new(());
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn out(source: &str) -> Vec<String> {
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

// =========================================================
// G2 — la clave NUNCA se materializa en user-space
// =========================================================

#[test]
fn key_never_materializes() {
    let o = out(&format!(
        r#"let k be as_secret("{KEY1}", "HOT_KEY")
print(text(k))
print(json_encode({{"key": k}}))
print(contains(csv_encode([{{"k": k}}]), "{KEY1}"))
-- derivar la pubkey/dirección es PURO y NO expone la clave
print(eth_address(k))"#
    ));
    // text(secret) y json_encode → secret(HOT_KEY)/[redacted], jamás el hex.
    assert!(o[0].contains("secret(HOT_KEY)"), "text(secret): {}", o[0]);
    for line in &o {
        assert!(!line.contains(KEY1), "LEAK de la clave: {}", line);
    }
    assert!(o[2] == "false", "csv_encode redacta, no filtra: {}", o[2]);
    // la dirección pública SÍ sale (deriva sin exponer la privada).
    assert_eq!(o[3], ADDR1);
}

#[test]
fn hashing_a_key_secret_still_errors() {
    // G9: sha256/keccak256 de un secret sigue error (no se debilita).
    for h in ["sha256", "keccak256", "sha512_256"] {
        let o = out(&format!(
            r#"let k be as_secret("{KEY1}", "HOT_KEY")
let msg be ""
try
    let x be {h}(k)
recover err
    set msg to err
print(contains(msg, "{KEY1}"))
print(length(msg) > 0)"#
        ));
        assert_eq!(o[0], "false", "{}: el error no filtra la clave", h);
        assert_eq!(o[1], "true", "{}: hay error", h);
    }
}

// =========================================================
// G3 — firma gateada por `require sign` + audit; anti-swap
// =========================================================

#[test]
fn signing_requires_the_sign_capability() {
    // Sin `require sign` → error de capability (deny-by-default).
    let o = out(&format!(
        r#"let k be as_secret("{KEY1}", "HOT_KEY")
let d be keccak256("hello")
let msg be ""
try
    let sig be secp256k1_sign(d, k)
recover err
    set msg to err
print(contains(msg, "sign not permitted"))
print(contains(msg, "require sign"))
print("vivo")"#
    ));
    assert_eq!(o, vec!["true", "true", "vivo"]);
}

#[test]
fn signing_with_capability_works_and_audits() {
    let _g = env_lock();
    let dir = std::env::temp_dir().join(format!("syn_sign_audit_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::set_var("SYNSEMA_AUDIT_DIR", &dir);

    let r = run_source(
        &format!(
            r#"require sign("HOT_KEY")
let k be as_secret("{KEY1}", "HOT_KEY")
let d be keccak256("hello")
let sig be secp256k1_sign(d, k)
print(length(sig))
-- ed25519 también gateado por el MISMO require sign("HOT_KEY")
let k2 be as_secret("{KEY1}", "HOT_KEY")
let sig2 be ed25519_sign("hello", k2)
print(length(sig2))"#
        ),
        "wallet.syn",
    );
    let log = std::fs::read_to_string(dir.join("sign.log")).ok();
    std::env::remove_var("SYNSEMA_AUDIT_DIR");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(r.success, "firmar con la capability debe funcionar: {:?}", r.errors);
    assert_eq!(r.output, vec!["65", "64"]);
    // El audit registró AMBAS firmas: curva, granted, name, programa — SIN la clave.
    let log = log.expect("sign.log debe existir (fail-loud)");
    assert!(log.contains("sign curve=secp256k1 result=granted name=HOT_KEY"), "audit: {}", log);
    assert!(log.contains("sign curve=ed25519 result=granted name=HOT_KEY"), "audit: {}", log);
    assert!(log.contains("program=wallet"), "audit: {}", log);
    assert!(!log.contains(KEY1), "el audit JAMÁS registra la clave: {}", log);
}

#[test]
fn denied_signing_is_also_audited() {
    let _g = env_lock();
    let dir = std::env::temp_dir().join(format!("syn_sign_deny_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::set_var("SYNSEMA_AUDIT_DIR", &dir);

    // Sin require sign → intento DENEGADO, pero registrado (forense).
    let _ = run_source(
        &format!(
            r#"let k be as_secret("{KEY1}", "HOT_KEY")
try
    let sig be secp256k1_sign(keccak256("x"), k)
recover err
    print("denegado")"#
        ),
        "attacker.syn",
    );
    let log = std::fs::read_to_string(dir.join("sign.log")).ok();
    std::env::remove_var("SYNSEMA_AUDIT_DIR");
    let _ = std::fs::remove_dir_all(&dir);

    let log = log.expect("un intento denegado igual se audita");
    assert!(log.contains("result=denied name=HOT_KEY"), "audit denegado: {}", log);
    assert!(!log.contains(KEY1), "sin fuga: {}", log);
}

#[test]
fn anti_swap_checks_the_actual_secret_name() {
    // require sign("HOT_KEY") pero firmo con un secret de OTRO name → denegado con
    // el name real (como reveal: el scope evalúa el secret que se pasa).
    let o = out(&format!(
        r#"require sign("HOT_KEY")
let otra be as_secret("{KEY1}", "COLD_KEY")
let msg be ""
try
    let sig be secp256k1_sign(keccak256("x"), otra)
recover err
    set msg to err
print(contains(msg, "sign(\"COLD_KEY\")"))
-- la clave correcta SÍ firma
let k be as_secret("{KEY1}", "HOT_KEY")
let sig be secp256k1_sign(keccak256("x"), k)
print(length(sig))"#
    ));
    assert_eq!(o[0], "true", "el gate evalúa el name del secret pasado (anti-swap)");
    assert_eq!(o[1], "65");
}

// =========================================================
// G3 — sandbox: firmar denegado; puros funcionan adentro
// =========================================================

#[test]
fn sandbox_denies_signing_but_allows_pure_ops() {
    let o = out(&format!(
        r#"require sign("HOT_KEY")
let k be as_secret("{KEY1}", "HOT_KEY")
let addr be ""
let signfail be ""
sandbox
    set addr to eth_address(k)
    let pk be secp256k1_pubkey(k)
    try
        let sig be secp256k1_sign(keccak256("hi"), k)
    recover err
        set signfail to err
print(addr)
print(contains(signfail, "sign"))
let sig be secp256k1_sign(keccak256("hi"), k)
print(length(sig))"#
    ));
    assert_eq!(o[0], ADDR1, "eth_address (puro) funciona dentro del sandbox");
    assert_eq!(o[1], "true", "firmar dentro del sandbox está denegado");
    assert_eq!(o[2], "65", "afuera del sandbox, firmar anda de nuevo");
}

// =========================================================
// G4 — errores sin fuga de material
// =========================================================

#[test]
fn errors_never_echo_key_material() {
    // Una clave de largo inválido (no 32 bytes) → error de forma que NO muestra el hex.
    let bad_key = "00112233445566778899aabbccddeeff"; // 16 bytes
    let o = out(&format!(
        r#"require sign("K")
let k be as_secret("{bad_key}", "K")
let msg be ""
try
    let sig be secp256k1_sign(keccak256("x"), k)
recover err
    set msg to err
print(contains(msg, "{bad_key}"))
print(contains(msg, "32 bytes"))
-- digest de largo != 32 → error de forma
let k2 be as_secret("{KEY1}", "K")
let m2 be ""
try
    let sig be secp256k1_sign(bytes("00", "hex"), k2)
recover err
    set m2 to err
print(contains(m2, "32 bytes"))"#
    ));
    assert_eq!(o[0], "false", "el error NO ecoa el material de clave (G4)");
    assert_eq!(o[1], "true", "el error describe la forma esperada (32 bytes)");
    assert_eq!(o[2], "true", "digest ≠ 32 → error de forma");
}

// =========================================================
// Dogfood — pipeline ETH end-to-end SIN red (vía `synsema test`)
// =========================================================

#[test]
fn dogfood_eth_end_to_end_via_synsema_test() {
    let src = format!(
        r#"require sign("HOT_KEY")

test "ETH: address, tx EIP-1559, firma determinista, ecrecover cierra el circuito"
    let k be as_secret("{KEY1}", "HOT_KEY")
    -- 1. dirección desde la clave (deriva la pubkey, no expone la privada)
    assert_eq(eth_address(k), "{ADDR1}")

    -- 2. construir el payload de una tx EIP-1559: 0x02 || rlp([campos])
    let to_bytes be bytes("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "hex")
    let campos be [1, 9, 1000000000, 30000000000, 21000, to_bytes, 1000000000000000, bytes([]), []]
    let tx be rlp_encode(campos)
    let payload be bytes([2]) + tx
    let digest be keccak256(payload)
    assert_eq(length(digest), 32)

    -- 3. firmar (gateado por require sign) — determinista (RFC 6979)
    let sig be secp256k1_sign(digest, k)
    assert_eq(length(sig), 65)
    assert_eq(sig, secp256k1_sign(digest, k))

    -- 4. ecrecover: la pubkey recuperada rinde la MISMA dirección (cierra el circuito)
    let pub be secp256k1_recover(digest, sig)
    assert_eq(eth_address(pub), "{ADDR1}")

    -- 5. verify con la pubkey derivada de la clave
    let pk be secp256k1_pubkey(k)
    assert(secp256k1_verify(digest, sig, pk))

    -- 6. round-trip RLP (leer de vuelta la tx)
    let leido be rlp_decode(tx)
    assert_eq(rlp_encode(leido), tx)

    -- 7. ensamblar la tx FIRMADA lista para broadcast: 0x02 || rlp(campos + [v, r, s]).
    --    r y s van como ENTEROS RLP mínimos (sin ceros a la izquierda), NO como blobs
    --    de 32 bytes — bytes_to_int es el puente exacto (256 bits, sin float).
    let v be sig[64]
    let r be bytes_to_int(slice(sig, 0, 32))
    let s be bytes_to_int(slice(sig, 32, 64))
    let raw be bytes([2]) + rlp_encode(campos + [v, r, s])
    assert_eq(raw[0], 2)
    let firmada be rlp_decode(slice(raw, 1, length(raw)))
    assert_eq(length(firmada), 12)
    -- el ancho fijo se restaura con int_to_bytes(n, 32): cierra el round-trip r/s
    assert_eq(int_to_bytes(r, 32), slice(sig, 0, 32))
    assert_eq(int_to_bytes(bytes_to_int(firmada[10]), 32), slice(sig, 0, 32))

test "ed25519 (Solana/Algorand): firma el mensaje CRUDO, verifica"
    let k be as_secret("{KEY1}", "HOT_KEY")
    let sig be ed25519_sign("transfer 10", k)
    assert_eq(length(sig), 64)
    let pk be ed25519_pubkey(k)
    assert(ed25519_verify("transfer 10", sig, pk))
    -- direcciones: Solana base58, Algorand base32
    assert(length(decode(pk, "base58")) > 0)
    assert(length(decode(pk, "base32")) > 0)
"#
    );
    let r = run_tests(&src, "<dogfood11>.syn");
    assert_eq!(
        r.passed,
        2,
        "dogfood ETH/ed25519 falló: {:?}",
        r.outcomes.iter().map(|o| (&o.name, &o.message)).collect::<Vec<_>>()
    );
}

// =========================================================
// Composición flagship §6 — cron (firma programada) + chart negociado
// =========================================================

#[test]
fn flagship_composition_cron_signs_and_chart() {
    // El diferencial: firma auditada + monitoreo por cron (ejecuta de verdad) +
    // chart legible por humano/agente — todo en un binario, sin red.
    let (path, spath) = {
        let p = std::env::temp_dir().join(format!("syn_wallet_marker_{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let s = p.display().to_string().replace('\\', "/");
        (p, s)
    };
    let o = out(&format!(
        r#"require sign("HOT_KEY")
require time
require file("{spath}")

-- monitoreo programado: la clave se resuelve DENTRO del task (patrón §6; un secret
-- del top-level se redacta al cruzar el snapshot del job — seguro, pero inusable).
task heartbeat()
    let k be as_secret("{KEY1}", "HOT_KEY")
    let sig be secp256k1_sign(keccak256("heartbeat"), k)
    append_file("{spath}", text(length(sig)) + ",")

cron_every(0.2, heartbeat)
sleep(1.0)

-- dashboard: el humano ve el SVG, el agente lee los datos (mismo nodo)
let svg be chart_svg("line", [1, 2, 3], {{"title": "Firmas"}})
print(contains(svg, "<svg"))
each j in cron_list()
    print(j["name"] + " runs>=3:" + text(j["run_count"] >= 3))"#
    ));
    let marker = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    assert_eq!(o[0], "true", "el chart rinde SVG");
    assert!(o[1].starts_with("heartbeat runs>=3:true"), "cron firmó ≥3 veces: {:?}", o);
    // Cada heartbeat firmó (65 bytes) y lo registró.
    assert!(marker.contains("65,"), "las firmas del cron se ejecutaron: {}", marker);
}

// =========================================================
// G10 — serve: handler que firma mal → HTTP error, server vivo
// =========================================================

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn request(port: u16, target: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req = format!("GET {target} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

#[test]
fn serve_signing_handler_error_keeps_server_alive() {
    let port = free_port();
    let prog = format!(
        r#"require serve({port})
require sign("HOT_KEY")

serve on {port}
    route "GET /addr"
        let k be as_secret("{KEY1}", "HOT_KEY")
        give text(eth_address(k))
    route "GET /badsign"
        -- clave de largo inválido → error de runtime (no captura) → 500, server vivo
        let k be as_secret("00", "HOT_KEY")
        give text(length(secp256k1_sign(keccak256("x"), k)))
"#
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "wallet_serve.syn", false);
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Ruta pura de derivación: la dirección sale (firma NO involucrada).
    let addr = request(port, "/addr");
    assert!(addr.contains(" 200 "), "addr status: {}", addr);
    assert!(addr.contains(ADDR1), "dirección: {}", addr);

    // Handler que firma mal → 500, y el material NO aparece en la respuesta.
    let bad = request(port, "/badsign");
    assert!(bad.contains(" 500 "), "badsign status: {}", bad);
    assert!(!bad.contains(KEY1), "la respuesta de error no filtra material");

    // El server sigue vivo tras el error.
    let again = request(port, "/addr");
    assert!(again.contains(" 200 "), "el server debe seguir vivo: {}", again);
}

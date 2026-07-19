//! E2E del Batch 13 (blockchain etapa 3: custodia + transporte) por el runtime
//! REAL, vía `synsema test` / `run` / `serve`, SIN red externa. Es CÓDIGO DE
//! CUSTODIA:
//!
//! - **Onboarding de wallet de cero:** `require wallet` → `mnemonic_generate` →
//!   `mnemonic_to_seed` → `hd_derive` ETH/Solana → direcciones, y todo lo que
//!   sale es `secret` (G19). Vectores contra los SDKs (los mismos de
//!   batch13_hd_conformance).
//! - **Keystore import → firma:** importar un keystore V3 real → derivar la
//!   address → firmar gateado por `sign` (la clave importada nunca se materializa).
//! - **G19 por el runtime:** `text`/`json_encode` de un secret de mnemónico/seed
//!   → `secret(NAME)` / `[redacted]`, jamás el valor.
//! - **G20 en sandbox:** dentro de `sandbox` la creación de custodia se DENIEGA
//!   (caps vaciadas), los builtins PUROS (solana_pda/spl_*) siguen andando.
//! - **G21 WebSocket:** puente WS→SSE bajo `serve`; deny sin `net`; server vivo
//!   tras un handler WS roto.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::{run_source, run_tests};
use synsema_runtime::serve::run_serve_program;

const STD_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ETH_ADDR0: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const SOL_ADDR0: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
const ALGO_ADDR: &str = "AOQQPP7TZYIL4HLQ3UMOOS6ATFT6JVRQTOSQ2XY53SDGIESVGG4MPFYUMQ";
const ALGO_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const KS_ADDR: &str = "0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b";
const KS_PBKDF2: &str = r#"{"address": "008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b", "crypto": {"cipher": "aes-128-ctr", "cipherparams": {"iv": "65feedf1e103d954c4d63b09e56f28cb"}, "ciphertext": "1cf0ab0a1922aab254489b2d137f347b33324d338b89da8e20d618597099beb8", "kdf": "pbkdf2", "kdfparams": {"c": 16384, "dklen": 32, "prf": "hmac-sha256", "salt": "1b045c612f5073812fbdc5268e290f96"}, "mac": "80ca118d91312a2cd26ebfc462f03b092609cc72911ad1c8b70a5197540d3bf6"}, "id": "60cf9c94-f23b-4c85-a36f-5f0abd5968b2", "version": 3}"#;

static AUDIT_ISOLATE: std::sync::Once = std::sync::Once::new();
fn isolate_audit_dir() {
    AUDIT_ISOLATE.call_once(|| {
        let dir = std::env::temp_dir().join(format!("syn_test_audit_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_var("SYNSEMA_AUDIT_DIR", &dir);
    });
}

fn out(source: &str) -> Vec<String> {
    isolate_audit_dir();
    let r = run_source(source, "<test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

// =========================================================
// §3 dogfood — custodia HD completa contra vectores de SDK
// =========================================================

#[test]
fn dogfood_hd_wallet_onboarding() {
    isolate_audit_dir();
    let src = format!(
        r#"require wallet
require reveal("W")

test "generar wallet → respaldo → seed → derivar ETH y Solana"
    -- el agente genera una wallet de cero (frase sellada como secret)
    let frase be mnemonic_generate(12, "W")
    -- la frase es un SECRET: reveal (gateado+auditado) para respaldarla a propósito
    let respaldo be reveal(frase)
    assert_eq(length(split(respaldo, " ")), 12)

test "mnemónico estándar → ETH m/44'/60'/0'/0/0 == vector de ethers"
    let frase be as_secret("{STD}", "W")
    let seed be mnemonic_to_seed(frase)
    let k be hd_derive(seed, "m/44'/60'/0'/0/0")
    assert_eq(eth_address(k), "{ETH}")

test "mismo seed → Solana SLIP-0010 == la address 0 de Phantom"
    let frase be as_secret("{STD}", "W")
    let seed be mnemonic_to_seed(frase)
    let k be hd_derive(seed, "m/44'/501'/0'/0'", "ed25519")
    assert_eq(decode(ed25519_pubkey(k), "base58"), "{SOL}")

test "Algorand 25 palabras (NO BIP-39) round-trip == algosdk"
    let key be as_secret(bytes("{ALGOSEED}", "hex"), "W")
    let frase be algorand_mnemonic(key)
    let back be algorand_mnemonic_to_key(frase)
    assert_eq(algo_address(back), "{ALGO}")
"#,
        STD = STD_MNEMONIC,
        ETH = ETH_ADDR0,
        SOL = SOL_ADDR0,
        ALGOSEED = ALGO_SEED,
        ALGO = ALGO_ADDR,
    );
    let r = run_tests(&src, "<dogfood13-hd>.syn");
    assert_eq!(
        r.passed,
        4,
        "dogfood HD falló: {:?}",
        r.outcomes.iter().map(|o| (&o.name, &o.message)).collect::<Vec<_>>()
    );
}

#[test]
fn dogfood_keystore_import_then_sign() {
    isolate_audit_dir();
    let src = format!(
        r#"require wallet
require sign("HOT")

test "importar keystore V3 → address correcta → firmar con la clave importada"
    let k be keystore_import({KS:?}, as_secret("testpassword", "PW"), "HOT")
    assert_eq(eth_address(k), "{ADDR}")
    -- la clave importada firma sin materializarse (gate `sign`)
    let sig be secp256k1_sign(keccak256("hello"), k)
    assert_eq(length(sig), 65)
    assert_eq(eth_address(secp256k1_recover(keccak256("hello"), sig)), "{ADDR}")
"#,
        KS = KS_PBKDF2,
        ADDR = KS_ADDR,
    );
    let r = run_tests(&src, "<dogfood13-keystore>.syn");
    assert_eq!(
        r.passed,
        1,
        "dogfood keystore falló: {:?}",
        r.outcomes.iter().map(|o| (&o.name, &o.message)).collect::<Vec<_>>()
    );
}

// =========================================================
// G19 — el mnemónico/seed es un secret, no un string
// =========================================================

#[test]
fn g19_secrets_redact_in_text_and_json_by_the_runtime() {
    let o = out(&format!(
        r#"require wallet
let frase be as_secret("{STD}", "SEEDPHRASE")
let seed be mnemonic_to_seed(frase)
let k be hd_derive(seed, "m/44'/60'/0'/0/0")
-- text() de un secret → su redacción, nunca el valor
print(contains(text(frase), "abandon"))
print(text(seed))
-- json_encode de una estructura con secrets → [redacted], no el material
print(contains(json_encode({{"mnemonic": frase, "seed": seed, "key": k}}), "abandon"))
print(contains(json_encode({{"key": k}}), "redacted"))
"#,
        STD = STD_MNEMONIC,
    ));
    assert_eq!(o[0], "false", "text(secret) no ecoa el mnemónico");
    assert!(o[1].starts_with("secret("), "text(seed) es la redacción: {}", o[1]);
    assert_eq!(o[2], "false", "json_encode no filtra material");
    assert_eq!(o[3], "true", "json_encode redacta el secret");
}

// =========================================================
// G20 — sandbox deniega la creación de custodia; puros siguen
// =========================================================

#[test]
fn g20_sandbox_denies_custody_but_pure_builtins_run() {
    let o = out(
        r#"require wallet
let frase be as_secret("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "W")
let pdalen be 0
let datalen be 0
let custodyfail be ""
sandbox
    let pda be solana_pda(["metadata"], "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
    set pdalen to length(pda["address"])
    set datalen to length(spl_transfer_checked_data(1000000, 6))
    try
        let seed be mnemonic_to_seed(frase)
    recover e
        set custodyfail to e
print(pdalen)
print(datalen)
print(contains(custodyfail, "wallet"))
-- afuera del sandbox la custodia anda de nuevo
let seed be mnemonic_to_seed(frase)
let k be hd_derive(seed, "m/44'/60'/0'/0/0")
print(eth_address(k))
"#,
    );
    assert_eq!(o[0], "32", "solana_pda puro: address de 32 bytes en sandbox");
    assert_eq!(o[1], "10", "spl_transfer_checked_data puro en sandbox");
    assert_eq!(o[2], "true", "la creación de custodia se deniega en sandbox");
    assert_eq!(o[3], ETH_ADDR0, "afuera del sandbox la custodia anda");
}

#[test]
fn g20_deny_without_require_wallet() {
    // Sin `require wallet`, generar custodia se deniega (deny-by-default) y es
    // atrapable; el server/programa sigue vivo.
    let o = out(
        r#"try
    let frase be mnemonic_generate(12)
recover e
    print(contains(e, "require wallet"))
print("vivo")
"#,
    );
    assert_eq!(o[0], "true", "deny-by-default sugiere el fix");
    assert_eq!(o[1], "vivo");
}

// =========================================================
// G21 — WebSocket: puente WS→SSE, deny sin net, server vivo
// =========================================================

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

/// Server WS de eco local (sin red externa) para el puente WS→SSE.
fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            thread::spawn(move || {
                let mut ws = match tungstenite::accept(stream) {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                while let Ok(msg) = ws.read() {
                    match msg {
                        m @ (tungstenite::Message::Text(_) | tungstenite::Message::Binary(_)) => {
                            if ws.send(m).is_err() {
                                return;
                            }
                        }
                        tungstenite::Message::Close(_) => return,
                        _ => {}
                    }
                }
            });
        }
    });
    port
}

#[test]
fn ws_bridge_and_gate_through_runtime() {
    let ws_port = echo_server();
    // Puente WS→request: el programa abre un WS saliente (a un RPC/exchange
    // local), hace round-trip y devuelve lo recibido — el patrón que un handler
    // serve usa para reenviar por SSE.
    let o = out(&format!(
        r#"require net("127.0.0.1")
let conn be ws_connect("ws://127.0.0.1:{port}/feed")
ws_send(conn, "ping")
let msg be ws_recv(conn, 5)
print(msg["type"])
print(msg["data"])
ws_close(conn)
"#,
        port = ws_port,
    ));
    assert_eq!(o[0], "text");
    assert_eq!(o[1], "ping", "round-trip WS por el runtime real");

    // Sin `require net` → deny-by-default (G21), atrapable, programa vivo.
    let o2 = out(&format!(
        r#"try
    let conn be ws_connect("ws://127.0.0.1:{port}/feed")
recover e
    print(contains(e, "net"))
print("vivo")
"#,
        port = ws_port,
    ));
    assert_eq!(o2[0], "true", "ws_connect sin net → deny");
    assert_eq!(o2[1], "vivo");
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
fn serve_ws_bridge_handler_keeps_server_alive() {
    let ws_port = echo_server();
    let http_port = free_port();
    let prog = format!(
        r#"require serve({http})
require net("127.0.0.1")

serve on {http}
    route "GET /bridge"
        let conn be ws_connect("ws://127.0.0.1:{ws}/feed")
        ws_send(conn, "from-serve")
        let msg be ws_recv(conn, 5)
        ws_close(conn)
        give msg["data"]
    route "GET /bad"
        -- ws_recv sobre un handle inventado → error de runtime → 500, server vivo
        give ws_recv(999999, 1)
"#,
        http = http_port,
        ws = ws_port,
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "ws_bridge.syn", false);
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", http_port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let ok = request(http_port, "/bridge");
    assert!(ok.contains(" 200 "), "bridge status: {}", ok);
    assert!(ok.contains("from-serve"), "el WS→SSE reenvió el mensaje: {}", ok);

    let bad = request(http_port, "/bad");
    assert!(bad.contains(" 500 "), "handler roto → 500: {}", bad);

    let again = request(http_port, "/bridge");
    assert!(again.contains(" 200 "), "el server sigue vivo: {}", again);
}

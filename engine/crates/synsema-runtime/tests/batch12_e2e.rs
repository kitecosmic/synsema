//! E2E del Batch 12 (blockchain etapa 2) por el runtime REAL — dogfood §6 del
//! spec, SIN red, vía `synsema test`. Es CÓDIGO DE DINERO:
//!
//! - **EVM dApp completo:** permit ERC-2612 como maps LEGIBLES (G14) →
//!   `eip712_digest` → firma GATEADA → `secp256k1_recover` verifica el
//!   firmante; `abi_encode` → tx EIP-1559 (reusa rlp/keccak del batch 11) →
//!   `abi_decode` lee de vuelta el calldata; SIWE con `eip191_digest`.
//! - **Solana / Algorand:** transfer/pay contra vectores PINEADOS de las SDKs
//!   oficiales (G17 — los mismos de blockchain_conformance.rs).
//! - **Gate intacto (G3/G13):** dentro de `sandbox` los builtins nuevos (PUROS)
//!   funcionan y la firma se DENIEGA; sin `require sign` los puros siguen
//!   andando. Ninguna puerta de firma nueva.
//! - **G4/G10:** errores sin fuga de material, atrapables, server vivo.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use synsema_runtime::engine::{run_source, run_tests};
use synsema_runtime::serve::run_serve_program;

/// Clave secp256k1 de test (`0x…01`) y su dirección (vectores del batch 11).
const KEY1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const ADDR1: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";
/// Seed ed25519 (RFC 8032 TEST 2) — la misma de los vectores solders/algosdk.
const SEED: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
/// Vectores pineados (procedencia en blockchain_conformance.rs — G17).
const SOL_MSG: &str = "010001033d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c02020202020202020202020202020202020202020202020202020202020202020000000000000000000000000000000000000000000000000000000000000000030303030303030303030303030303030303030303030303030303030303030301020200010c0200000040420f0000000000";
const SOL_SIG: &str = "4f187b036b37f6f12f81d65ffad735b3059de54602bd8e90ecc7bfbe9833f9a55783bed6a29bb3b14f2d1fe898c4bb4778adbdce00a5195b6df6963722bcf60b";
const ALGO_TX: &str = "54588aa3616d74ce0001e240a3666565cd03e8a26676cd03e8a367656eac746573746e65742d76312e30a26768c4200707070707070707070707070707070707070707070707070707070707070707a26c76cd07d0a46e6f7465c4026869a3726376c4200202020202020202020202020202020202020202020202020202020202020202a3736e64c4203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660ca474797065a3706179";
const ALGO_SENDER: &str = "HVABPQ7IIOEVVEVXBKTU2G36XSOJQLGPF3CJNDGAZVK7CKXUMYGA6EOE6Y";

/// Aísla el audit de firmas a un temp por proceso: los tests firman de verdad y el
/// audit es fail-loud + append-only; sin esto cada `cargo test` ensuciaría el
/// `~/.synsema/audit/sign.log` REAL del dev. NO se suprime (eso sería firma sin
/// registro = pérdida de seguridad), sólo se redirige a un temp descartable.
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
// §6.1 — EVM dApp completo: permit EIP-712 + calldata ABI + SIWE
// =========================================================

#[test]
fn dogfood_evm_dapp_permit_abi_and_siwe() {
    isolate_audit_dir();
    let src = format!(
        r#"require sign("HOT_KEY")

test "permit ERC-2612: typed-data LEGIBLE → digest → firma gateada → recover"
    let k be as_secret("{KEY1}", "HOT_KEY")
    -- el typed-data es un map Synsema: el agente puede MOSTRARLO antes de
    -- firmar (anti blind-signing) — nada de blobs opacos
    let domain be {{"name": "USD Coin", "version": "2", "chainId": 1, "verifyingContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"}}
    let types be {{"Permit": [
        {{"name": "owner", "type": "address"}},
        {{"name": "spender", "type": "address"}},
        {{"name": "value", "type": "uint256"}},
        {{"name": "nonce", "type": "uint256"}},
        {{"name": "deadline", "type": "uint256"}}]}}
    let permit be {{"owner": "{ADDR1}",
        "spender": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "value": 1000000000000000000000000,
        "nonce": 0,
        "deadline": 1893456000}}
    -- "show": el permit es json-serializable tal cual (legible por humanos)
    assert(contains(json_encode(permit), "spender"))
    let digest be eip712_digest(domain, types, "Permit", permit)
    assert_eq(length(digest), 32)
    let sig be secp256k1_sign(digest, k)
    -- el contrato hará ecrecover: el firmante ES el owner del permit
    assert_eq(eth_address(secp256k1_recover(digest, sig)), "{ADDR1}")

test "calldata ABI → tx EIP-1559 → abi_decode lee de vuelta"
    let k be as_secret("{KEY1}", "HOT_KEY")
    -- ERC-20 transfer: 1M tokens (uint256 REAL, no entra en i64 — exacto)
    let data be abi_encode("transfer(address,uint256)", ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", 1000000000000000000000000])
    assert_eq(slice(data, 0, 4), abi_selector("transfer(address,uint256)"))
    -- tx EIP-1559 con el data (rlp + keccak del batch 11, sin cambios)
    let destino be bytes("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "hex")
    let campos be [1, 9, 1000000000, 30000000000, 21000, destino, 0, data, []]
    let payload be bytes([2]) + rlp_encode(campos)
    let sig be secp256k1_sign(keccak256(payload), k)
    assert_eq(length(sig), 65)
    -- leer el calldata de vuelta (auditoría del lado del agente)
    let leido be abi_decode("(address,uint256)", slice(data, 4, length(data)))
    assert_eq(leido[0], "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
    assert_eq(leido[1], 1000000000000000000000000)

test "SIWE: eip191_digest → firma → recover == la address que se autentica"
    let k be as_secret("{KEY1}", "HOT_KEY")
    let msg be "app.example.com wants you to sign in with your Ethereum account: {ADDR1}"
    let digest be eip191_digest(msg)
    let sig be secp256k1_sign(digest, k)
    let quien be eth_address(secp256k1_recover(digest, sig))
    assert_eq(quien, "{ADDR1}")
"#
    );
    let r = run_tests(&src, "<dogfood12-evm>.syn");
    assert_eq!(
        r.passed,
        3,
        "dogfood EVM falló: {:?}",
        r.outcomes.iter().map(|o| (&o.name, &o.message)).collect::<Vec<_>>()
    );
}

// =========================================================
// §6.2/§6.3 — Solana y Algorand contra vectores pineados
// =========================================================

#[test]
fn dogfood_solana_and_algorand_transfers() {
    isolate_audit_dir();
    let src = format!(
        r#"require sign("HOT_KEY")

test "Solana: System transfer → message → firma → wire, contra solders"
    let k be as_secret("{SEED}", "HOT_KEY")
    let payer be ed25519_pubkey(k)
    -- data del transfer: u32 LE 2 (instrucción) ‖ u64 LE lamports
    let data be int_to_bytes_le(2, 4) + int_to_bytes_le(1000000, 8)
    let msg be solana_message({{
        "fee_payer": payer,
        "recent_blockhash": bytes("0303030303030303030303030303030303030303030303030303030303030303", "hex"),
        "instructions": [{{
            "program": "11111111111111111111111111111111",
            "accounts": [
                {{"pubkey": payer, "signer": true, "writable": true}},
                {{"pubkey": bytes("0202020202020202020202020202020202020202020202020202020202020202", "hex"), "writable": true}}],
            "data": data}}]}})
    assert_eq(msg, bytes("{SOL_MSG}", "hex"))
    let sig be ed25519_sign(msg, k)
    assert_eq(sig, bytes("{SOL_SIG}", "hex"))
    assert(ed25519_verify(msg, sig, payer))
    let tx be solana_tx(msg, sig)
    assert_eq(slice(tx, 0, 1), bytes([1]))
    -- listo para JSON-RPC: base64 + sendTransaction vía http_post (userland)
    assert(length(decode(tx, "base64")) > 0)

test "Algorand: pay txn canónica → firma con prefijo TX → SignedTxn, contra algosdk"
    let k be as_secret("{SEED}", "HOT_KEY")
    -- claves CORTAS del protocolo; snd como dirección text (checksum validado)
    let txn be {{"type": "pay", "snd": "{ALGO_SENDER}",
        "rcv": bytes("0202020202020202020202020202020202020202020202020202020202020202", "hex"),
        "amt": 123456, "fee": 1000, "fv": 1000, "lv": 2000,
        "gen": "testnet-v1.0",
        "gh": bytes("0707070707070707070707070707070707070707070707070707070707070707", "hex"),
        "note": bytes("hi")}}
    let listo be algorand_tx_encode(txn)
    assert_eq(listo, bytes("{ALGO_TX}", "hex"))
    let sig be ed25519_sign(listo, k)
    assert(ed25519_verify(listo, sig, ed25519_pubkey(k)))
    let stx be algorand_tx(txn, sig)
    -- listo para POST binario a /v2/transactions (userland http_post)
    assert(length(stx) > length(listo))
    -- la dirección se deriva del secret SIN exponer la clave (espeja eth_address)
    assert_eq(algo_address(k), "{ALGO_SENDER}")
    -- TXID componible: base32(sha512_256("TX" ‖ msgpack))
    let txid be decode(sha512_256(listo), "base32")
    assert_eq(txid, "WTAEKXVRJW7GUKT6R2JOEJY4W2PDURTBEP3VM2DR6WC6RWWQOXQA")
"#
    );
    let r = run_tests(&src, "<dogfood12-sol-algo>.syn");
    assert_eq!(
        r.passed,
        2,
        "dogfood Solana/Algorand falló: {:?}",
        r.outcomes.iter().map(|o| (&o.name, &o.message)).collect::<Vec<_>>()
    );
}

// =========================================================
// §6.4 — Gate intacto: puros SÍ dentro de sandbox, firma NO (G3/G13)
// =========================================================

#[test]
fn sandbox_allows_new_pure_builtins_but_denies_signing() {
    let o = out(&format!(
        r#"require sign("HOT_KEY")
let k be as_secret("{SEED}", "HOT_KEY")
let digestlen be 0
let selector be bytes([])
let sollen be 0
let algolen be 0
let dir be ""
let signfail be ""
-- adentro del sandbox TODO el pipeline puro funciona (los digests/encodings
-- no mueven valor); firmar NO (caps vaciadas — G3, sin puertas nuevas G13)
sandbox
    let d be eip712_digest({{"name": "X"}}, {{"Ping": [{{"name": "n", "type": "uint256"}}]}}, "Ping", {{"n": 1}})
    set digestlen to length(d)
    set selector to abi_selector("transfer(address,uint256)")
    let payer be ed25519_pubkey(k)
    let msg be solana_message({{"fee_payer": payer, "recent_blockhash": payer,
        "instructions": [{{"program": "11111111111111111111111111111111", "data": bytes([0])}}]}})
    set sollen to length(msg)
    set algolen to length(algorand_tx_encode({{"type": "pay", "amt": 5}}))
    set dir to algo_address(k)
    try
        let sig be ed25519_sign(msg, k)
    recover errmsg
        set signfail to errmsg
print(digestlen)
print(decode(selector, "hex"))
print(sollen > 0)
print(algolen > 0)
print(dir)
print(contains(signfail, "sign"))
-- afuera del sandbox la firma anda de nuevo
let sig be ed25519_sign("x", k)
print(length(sig))"#
    ));
    assert_eq!(o[0], "32", "eip712_digest es puro: funciona en sandbox");
    assert_eq!(o[1], "a9059cbb", "abi_selector es puro");
    assert_eq!(o[2], "true", "solana_message es puro");
    assert_eq!(o[3], "true", "algorand_tx_encode es puro");
    assert_eq!(o[4], ALGO_SENDER, "algo_address deriva sin exponer la clave");
    assert_eq!(o[5], "true", "la firma dentro del sandbox se deniega");
    assert_eq!(o[6], "64", "afuera, la firma anda");
}

#[test]
fn new_builtins_work_without_require_sign() {
    // G13: los builtins nuevos son PUROS — sin `require sign` funcionan todos.
    let o = out(
        r#"let d be eip191_digest("hola")
print(length(d))
let sel be abi_selector("balanceOf(address)")
print(decode(sel, "hex"))
let enc be abi_encode("baz(uint32,bool)", [69, true])
print(length(enc))
print(length(algorand_tx_encode({"type": "pay", "amt": 1})))"#,
    );
    assert_eq!(o, vec!["32", "70a08231", "68", "17"]);
}

// =========================================================
// §8 — errores sin fuga de material, atrapables (G4/G10)
// =========================================================

#[test]
fn batch12_errors_never_leak_and_are_catchable() {
    let o = out(&format!(
        r#"let k be as_secret("{SEED}", "HOT_KEY")
let m1 be ""
let m2 be ""
let m3 be ""
try
    let x be abi_encode("f(uint256)", [k])
recover e1
    set m1 to e1
try
    let y be algorand_tx_encode({{"type": "pay", "note": k}})
recover e2
    set m2 to e2
try
    let z be solana_message({{"fee_payer": k, "recent_blockhash": bytes([0]), "instructions": []}})
recover e3
    set m3 to e3
print(contains(m1, "{SEED}"))
print(contains(m2, "{SEED}"))
print(contains(m3, "{SEED}"))
print(length(m1) > 0 and length(m2) > 0 and length(m3) > 0)
print("vivo")"#
    ));
    assert_eq!(&o[..4], &["false", "false", "false", "true"], "sin fuga: {:?}", o);
    assert_eq!(o[4], "vivo", "todos los errores son atrapables");
}

// =========================================================
// G10 — serve: handler con ABI roto → HTTP error, server vivo
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
fn serve_bad_abi_handler_keeps_server_alive() {
    let port = free_port();
    let prog = format!(
        r#"require serve({port})

serve on {port}
    route "GET /calldata"
        give decode(abi_encode("transfer(address,uint256)", ["0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", 1000]), "hex")
    route "GET /bad"
        -- aridad incorrecta → error de runtime → 500, server vivo
        give decode(abi_encode("transfer(address,uint256)", [1]), "hex")
"#
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "dapp_serve.syn", false);
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let ok = request(port, "/calldata");
    assert!(ok.contains(" 200 "), "calldata status: {}", ok);
    assert!(ok.contains("a9059cbb"), "selector en la respuesta: {}", ok);

    let bad = request(port, "/bad");
    assert!(bad.contains(" 500 "), "bad status: {}", bad);

    let again = request(port, "/calldata");
    assert!(again.contains(" 200 "), "el server debe seguir vivo: {}", again);
}

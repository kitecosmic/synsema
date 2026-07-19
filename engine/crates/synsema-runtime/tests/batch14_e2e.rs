//! E2E del Batch 14 (read-side de blockchain) por el runtime REAL, SIN red
//! externa: mocks JSON-RPC (EVM/Solana) y REST (algod) sobre TcpListener local.
//!
//! - **El loop completo contra el vector eth-account:** leer (nonce/chainId/fees)
//!   → construir (`tx_eip1559`) → firmar (`secp256k1_sign`, gate `sign`) →
//!   ensamblar (`tx_eip1559_raw`) → enviar (`eth_send_raw`, el mock EXIGE los
//!   bytes EXACTOS del vector del SDK) → confirmar (`eth_wait_receipt`). RFC 6979
//!   es determinista: misma clave+digest → la MISMA firma que eth-account, así
//!   que el raw coincide byte a byte o el mock rechaza.
//! - **Solana:** blockhash → `solana_message` → `ed25519_sign` → `solana_tx` →
//!   `solana_send` → `solana_confirm`; `solana_balance` + `spl_balance`.
//! - **Algorand:** `algorand_params` (fee POR BYTE + min_fee flat) → txn map →
//!   `algorand_tx_encode` → `ed25519_sign` → `algorand_tx` → `algorand_send`
//!   (body BINARIO x-binary) → `algorand_wait`.
//! - **G22:** sin `require net` → deny atrapable; dentro de `sandbox` → deny;
//!   los builders puros (`tx_eip1559`) siguen andando en sandbox.
//! - **G23:** hex-quantity con ceros a la izquierda, forma equivocada y respuesta
//!   gigante (>16 MiB) → error atrapable, programa vivo.
//! - **Polling acotado:** los tres `wait/confirm` devuelven `nothing` al timeout
//!   contra mocks que jamás confirman — nunca cuelgan.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use synsema_core::bytesutil::{b64_encode, base58_encode};
use synsema_runtime::engine::{run_source, run_tests};

/// Clave del vector (m/44'/60'/0'/0/0 del mnemónico estándar — la misma pineada
/// en batch13_hd_conformance; los vectores raw/hash se generaron con eth-account
/// 0.13.7, el SDK de la Ethereum Foundation).
const VEC_KEY: &str = "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727";
const VEC1_RAW: &str = "02f87301078459682f008506fc23ac00825208946fac4d18c912343bf86fa7049364dd4e424ab9c088016345785d8a000080c080a054afb059cc17c8b3726db836c4d9093aaabfb6d422c9c190ae8e9c561e285fffa03f3c2eb5d5b609d2544817eb1ce8a4e64dfc8d4dbbc9db06f5ce2f2352b13f41";
const VEC1_HASH: &str = "0x6fb18223cd52476122a18a2b59a6c9faca40b36937217962a4f81b0da1c79880";

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

fn tests_pass(source: &str, name: &str, expected: usize) {
    isolate_audit_dir();
    let r = run_tests(source, name);
    assert_eq!(
        r.passed,
        expected,
        "{} falló: {:?}",
        name,
        r.outcomes.iter().map(|o| (&o.name, &o.message)).collect::<Vec<_>>()
    );
}

// =========================================================
// Mock HTTP local (JSON-RPC y REST) — un handler por request
// =========================================================

type Handler = dyn Fn(&str, &str, &str, &[u8]) -> (u16, String) + Send + Sync;

/// Server HTTP mínimo: por conexión lee head + body (Content-Length) y despacha
/// `handler(method, path, content_type, body)` → `(status, body_json)`.
fn mock_http_server(handler: impl Fn(&str, &str, &str, &[u8]) -> (u16, String) + Send + Sync + 'static) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let handler: Arc<Handler> = Arc::new(handler);
    thread::spawn(move || {
        while let Ok((mut sock, _)) = listener.accept() {
            let handler = handler.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let mut acc: Vec<u8> = Vec::new();
                let head_end = loop {
                    match sock.read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => {
                            acc.extend_from_slice(&buf[..n]);
                            if let Some(p) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                                break p;
                            }
                        }
                        Err(_) => return,
                    }
                };
                let head = String::from_utf8_lossy(&acc[..head_end]).to_string();
                let mut lines = head.split("\r\n");
                let request_line = lines.next().unwrap_or("");
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let mut content_length = 0usize;
                let mut content_type = String::new();
                for line in lines {
                    if let Some((k, v)) = line.split_once(':') {
                        let k = k.trim().to_ascii_lowercase();
                        let v = v.trim();
                        if k == "content-length" {
                            content_length = v.parse().unwrap_or(0);
                        } else if k == "content-type" {
                            content_type = v.to_string();
                        }
                    }
                }
                let mut body: Vec<u8> = acc[head_end + 4..].to_vec();
                while body.len() < content_length {
                    match sock.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => body.extend_from_slice(&buf[..n]),
                        Err(_) => return,
                    }
                }
                let (status, resp_body) = handler(&method, &path, &content_type, &body);
                let resp = format!(
                    "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    resp_body.len(),
                    resp_body
                );
                let _ = sock.write_all(resp.as_bytes());
            });
        }
    });
    port
}

/// Envelope JSON-RPC de éxito (id 1, como exige el cliente estricto).
fn rpc_ok(result: serde_json::Value) -> String {
    json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string()
}

fn rpc_err(code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": message}}).to_string()
}

fn rpc_method(body: &[u8]) -> (String, serde_json::Value) {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or(json!({}));
    (
        v.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string(),
        v.get("params").cloned().unwrap_or(json!([])),
    )
}

// =========================================================
// A — el loop EVM completo contra el vector eth-account
// =========================================================

/// Mock EVM: nonce 7, chainId 1, feeHistory con base 15 gwei y p50 1.5 gwei
/// (máx_fee = base*2 = 30 gwei ⇒ los MISMOS números del vector), broadcast que
/// EXIGE el raw exacto del vector, receipt que aparece en el 2º poll.
fn evm_mock() -> u16 {
    let receipt_polls = Arc::new(AtomicUsize::new(0));
    mock_http_server(move |_m, _p, _ct, body| {
        let (method, params) = rpc_method(body);
        let resp = match method.as_str() {
            "eth_chainId" => rpc_ok(json!("0x1")),
            "eth_getTransactionCount" => rpc_ok(json!("0x7")),
            "eth_getBalance" => rpc_ok(json!("0x3635c9adc5dea00000")), // 1000 ETH exactos (> i64 en wei)
            "eth_gasPrice" => rpc_ok(json!("0x3b9aca00")),
            "eth_estimateGas" => rpc_ok(json!("0x5208")),
            // base fee del PRÓXIMO bloque = último elemento = 15 gwei.
            "eth_feeHistory" => rpc_ok(json!({
                "oldestBlock": "0x1",
                "baseFeePerGas": ["0x2540be400", "0x37e11d600"],
                "gasUsedRatio": [0.5],
                "reward": [["0x59682f00"]],
            })),
            // balanceOf → uint256 123456 (32 bytes ABI).
            "eth_call" => rpc_ok(json!(format!("0x{:064x}", 123456))),
            "eth_sendRawTransaction" => {
                let raw = params.get(0).and_then(|p| p.as_str()).unwrap_or("");
                if raw == format!("0x{}", VEC1_RAW) {
                    rpc_ok(json!(VEC1_HASH))
                } else {
                    rpc_err(-32000, "raw tx does not match the eth-account vector")
                }
            }
            "eth_getTransactionReceipt" => {
                if receipt_polls.fetch_add(1, Ordering::SeqCst) == 0 {
                    rpc_ok(json!(null)) // primer poll: aún no minada
                } else {
                    rpc_ok(json!({
                        "blockNumber": "0x64",
                        "status": "0x1",
                        "gasUsed": "0x5208",
                        "transactionHash": VEC1_HASH,
                        "from": "0x9858effd232b4033e47d90003d41ec34ecaeda94",
                        "to": "0x6fac4d18c912343bf86fa7049364dd4e424ab9c0",
                        "logs": [],
                    }))
                }
            }
            other => rpc_err(-32601, &format!("method not found: {}", other)),
        };
        (200, resp)
    })
}

#[test]
fn evm_full_loop_read_build_sign_send_confirm() {
    let port = evm_mock();
    let src = format!(
        r#"require net("127.0.0.1")
require wallet
require sign("HOT")

test "leer → construir → firmar → enviar → confirmar == vector eth-account"
    let url be "http://127.0.0.1:{port}"
    let k be as_secret("{key}", "HOT")
    let from be eth_address(k)
    -- LEER (antes: JSON-RPC a mano con hex-quantities a pulso)
    let nonce be eth_nonce(url, from)
    assert_eq(nonce, 7)
    let chain be eth_chain_id(url)
    assert_eq(chain, 1)
    let fees be eth_fee_history(url)
    assert_eq(fees["base_fee"], 15000000000)
    assert_eq(fees["priority"], 1500000000)
    -- CONSTRUIR (G24: cada campo explícito; el builder ecoa los números)
    let tx be tx_eip1559({{"chain_id": chain, "nonce": nonce,
        "to": "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
        "value": 100000000000000000, "gas": 21000,
        "max_fee": fees["base_fee"] * 2, "max_priority": fees["priority"]}})
    assert_eq(tx["max_fee"], 30000000000)
    assert_eq(tx["to"], "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0")
    -- FIRMAR (la ÚNICA puerta de valor) y ENSAMBLAR (sin hand-roll)
    let sig be secp256k1_sign(tx["digest"], k)
    let raw be tx_eip1559_raw(tx, sig)
    -- ENVIAR: el mock EXIGE los bytes EXACTOS del vector del SDK
    let hash be eth_send_raw(url, raw)
    assert_eq(hash, "{hash}")
    -- CONFIRMAR: polling acotado (el receipt aparece en el 2º poll)
    let receipt be eth_wait_receipt(url, hash, 1, 30)
    assert_eq(receipt["status"], 1)
    assert_eq(receipt["gasUsed"], 21000)
    assert_eq(receipt["from"], "0x9858EfFD232B4033E47d90003D41EC34EcaEda94")

test "lecturas sueltas: balance exacto > i64, eth_call + abi_decode, estimate"
    let url be "http://127.0.0.1:{port}"
    let bal be eth_balance(url, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
    assert_eq(bal, 1000000000000000000000)
    let calldata be abi_encode("balanceOf(address)", ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94"])
    let ret be eth_call(url, {{"to": "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0", "data": calldata}})
    assert_eq(abi_decode("uint256", ret)[0], 123456)
    let gas be eth_estimate_gas(url, {{"to": "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0", "value": 1}})
    assert_eq(gas, 21000)
    assert_eq(eth_gas_price(url), 1000000000)
"#,
        port = port,
        key = VEC_KEY,
        hash = VEC1_HASH,
    );
    tests_pass(&src, "<batch14-evm>.syn", 2);
}

// =========================================================
// B — Solana: blockhash → message → firmar → enviar → confirmar
// =========================================================

fn solana_mock() -> u16 {
    let confirm_polls = Arc::new(AtomicUsize::new(0));
    let blockhash = base58_encode(&[7u8; 32]);
    let signature = base58_encode(&[9u8; 64]);
    mock_http_server(move |_m, _p, _ct, body| {
        let (method, params) = rpc_method(body);
        let resp = match method.as_str() {
            "getLatestBlockhash" => rpc_ok(json!({
                "context": {"slot": 100},
                "value": {"blockhash": blockhash, "lastValidBlockHeight": 250},
            })),
            "getBalance" => rpc_ok(json!({"context": {"slot": 100}, "value": 5_000_000_000u64})),
            "sendTransaction" => {
                // La tx viaja base64; el wire format arranca con el shortvec de
                // firmas (0x01) — si no decodifica, el "nodo" la rechaza.
                let ok = params
                    .get(0)
                    .and_then(|p| p.as_str())
                    .and_then(|s| synsema_core::bytesutil::b64_decode(s).ok())
                    .map(|raw| raw.first() == Some(&1) && raw.len() > 65)
                    .unwrap_or(false);
                if ok {
                    rpc_ok(json!(signature))
                } else {
                    rpc_err(-32002, "transaction did not deserialize")
                }
            }
            "getSignatureStatuses" => {
                // La firma [8;64] simula una tx que ATERRIZÓ pero FALLÓ on-chain.
                let failed_sig = base58_encode(&[8u8; 64]);
                let asked_failed = params
                    .get(0)
                    .and_then(|p| p.as_array())
                    .and_then(|a| a.first())
                    .and_then(|s| s.as_str())
                    == Some(failed_sig.as_str());
                if asked_failed {
                    rpc_ok(json!({
                        "context": {"slot": 102},
                        "value": [{"slot": 100, "confirmations": null,
                                   "err": {"InstructionError": [0, "Custom"]},
                                   "confirmationStatus": "finalized"}],
                    }))
                } else if confirm_polls.fetch_add(1, Ordering::SeqCst) == 0 {
                    rpc_ok(json!({"context": {"slot": 100}, "value": [null]}))
                } else {
                    rpc_ok(json!({
                        "context": {"slot": 101},
                        "value": [{"slot": 100, "confirmations": 3, "err": null,
                                   "confirmationStatus": "confirmed"}],
                    }))
                }
            }
            "getTokenAccountBalance" => rpc_ok(json!({
                "context": {"slot": 100},
                "value": {"amount": "2500000", "decimals": 6, "uiAmountString": "2.5"},
            })),
            other => rpc_err(-32601, &format!("method not found: {}", other)),
        };
        (200, resp)
    })
}

#[test]
fn solana_full_loop_and_balances() {
    let port = solana_mock();
    // Seed ed25519 de test (batch13): la clave es un secret de bytes.
    let src = format!(
        r#"require net("127.0.0.1")
require wallet
require sign("SOL")

test "blockhash → message → firmar → tx → enviar → confirmar"
    let url be "http://127.0.0.1:{port}"
    let k be as_secret(bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"), "SOL")
    let me be ed25519_pubkey(k)
    let bh be solana_latest_blockhash(url)
    assert_eq(length(bh), 32)
    let msg be solana_message({{"fee_payer": me, "recent_blockhash": bh,
        "instructions": [{{"program": "11111111111111111111111111111111",
            "accounts": [{{"pubkey": me, "signer": true, "writable": true}}],
            "data": bytes([2, 0, 0, 0])}}]}})
    let sig be ed25519_sign(msg, k)
    let tx be solana_tx(msg, sig)
    let signature be solana_send(url, tx)
    assert_eq(signature, "{sig58}")
    let status be solana_confirm(url, signature, 30)
    assert_eq(status["confirmation_status"], "confirmed")
    assert_eq(status["err"], nothing)

test "solana_balance + spl_balance (amount con decimals, jamás un 0 inventado)"
    let url be "http://127.0.0.1:{port}"
    let owner be "11111111111111111111111111111111"
    assert_eq(solana_balance(url, owner), 5000000000)
    let bal be spl_balance(url, owner, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
    assert_eq(bal["amount"], 2500000)
    assert_eq(bal["decimals"], 6)

test "una tx que aterrizó pero FALLÓ on-chain: err no es nothing (el caller chequea)"
    let url be "http://127.0.0.1:{port}"
    let status be solana_confirm(url, "{failed58}", 30)
    assert_eq(status["confirmation_status"], "finalized")
    assert(status["err"] != nothing)
"#,
        port = port,
        sig58 = base58_encode(&[9u8; 64]),
        failed58 = base58_encode(&[8u8; 64]),
    );
    tests_pass(&src, "<batch14-solana>.syn", 3);
}

// =========================================================
// C — Algorand: params → txn → firmar → enviar (binario) → confirmar
// =========================================================

fn algorand_mock() -> u16 {
    let wait_polls = Arc::new(AtomicUsize::new(0));
    let gh = b64_encode(&[3u8; 32]);
    mock_http_server(move |method, path, content_type, body| {
        if method == "GET" && path == "/v2/transactions/params" {
            return (
                200,
                json!({
                    "fee": 0, "min-fee": 1000, "last-round": 41,
                    "genesis-hash": gh, "genesis-id": "testnet-v1.0",
                    "consensus-version": "test",
                })
                .to_string(),
            );
        }
        if method == "POST" && path == "/v2/transactions" {
            // El SignedTxn es msgpack BINARIO: {"sig": …, "txn": …} = fixmap(2).
            if content_type != "application/x-binary" {
                return (400, json!({"message": "wrong content type"}).to_string());
            }
            if body.first() != Some(&0x82) {
                return (400, json!({"message": "not a msgpack SignedTxn"}).to_string());
            }
            return (200, json!({"txId": "A".repeat(52)}).to_string());
        }
        if method == "GET" && path.starts_with("/v2/transactions/pending/") {
            // Un txid de puras "B" simula un rechazo del pool (definitivo).
            if path.contains(&"B".repeat(52)) {
                return (
                    200,
                    json!({"confirmed-round": 0,
                           "pool-error": "transaction rejected: overspend"})
                    .to_string(),
                );
            }
            let n = wait_polls.fetch_add(1, Ordering::SeqCst);
            let round = if n == 0 { 0 } else { 45 };
            return (
                200,
                json!({"confirmed-round": round, "pool-error": ""}).to_string(),
            );
        }
        if method == "GET" && path.starts_with("/v2/accounts/") {
            return (200, json!({"amount": 123456789, "min-balance": 100000}).to_string());
        }
        (404, json!({"message": format!("unknown: {} {}", method, path)}).to_string())
    })
}

#[test]
fn algorand_full_loop_binary_broadcast() {
    let port = algorand_mock();
    let src = format!(
        r#"require net("127.0.0.1")
require wallet
require sign("ALGO")

test "params (fee POR BYTE + min_fee flat) → txn → firmar → enviar → confirmar"
    let url be "http://127.0.0.1:{port}"
    let k be as_secret(bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"), "ALGO")
    let me be algo_address(k)
    let p be algorand_params(url)
    assert_eq(p["fee"], 0)
    assert_eq(p["min_fee"], 1000)
    assert_eq(p["fv"], 41)
    assert_eq(p["lv"], 1041)
    assert_eq(length(p["gh"]), 32)
    let txn be {{"type": "pay", "snd": me, "rcv": me, "amt": 1,
        "fee": p["min_fee"], "fv": p["fv"], "lv": p["lv"],
        "gh": p["gh"], "gen": p["gen"]}}
    let sig be ed25519_sign(algorand_tx_encode(txn), k)
    let stx be algorand_tx(txn, sig)
    let txid be algorand_send(url, stx)
    assert_eq(length(txid), 52)
    let info be algorand_wait(url, txid, 30)
    assert_eq(info["confirmed-round"], 45)

test "algorand_account valida el checksum ANTES de tocar la red"
    let url be "http://127.0.0.1:{port}"
    let k be as_secret(bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"), "ALGO")
    let acct be algorand_account(url, algo_address(k))
    assert_eq(acct["amount"], 123456789)
    let bad be ""
    try
        let x be algorand_account(url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    recover e
        set bad to e
    assert(contains(bad, "checksum"))

test "rechazo del pool: error atrapable DEFINITIVO (no esperar en vano)"
    let url be "http://127.0.0.1:{port}"
    let fallo be ""
    try
        let info be algorand_wait(url, "{badtxid}", 30)
    recover e
        set fallo to e
    assert(contains(fallo, "rejected"))
"#,
        port = port,
        badtxid = "B".repeat(52),
    );
    tests_pass(&src, "<batch14-algorand>.syn", 3);
}

// =========================================================
// G22 — deny sin net; sandbox; los builders puros siguen
// =========================================================

#[test]
fn g22_deny_without_net_and_in_sandbox() {
    let port = evm_mock();
    let o = out(&format!(
        r#"let denied be ""
try
    let n be eth_chain_id("http://127.0.0.1:{port}")
recover e
    set denied to e
print(contains(denied, "net"))
print("vivo")
"#,
        port = port,
    ));
    assert_eq!(o[0], "true", "sin require net → deny atrapable");
    assert_eq!(o[1], "vivo");

    // Dentro de sandbox: el read-side (net) se deniega; el builder PURO anda.
    let o2 = out(&format!(
        r#"require net("127.0.0.1")
let denied be ""
let digestlen be 0
sandbox
    try
        let n be eth_chain_id("http://127.0.0.1:{port}")
    recover e
        set denied to e
    let tx be tx_eip1559({{"chain_id": 1, "nonce": 0,
        "to": "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0", "value": 0,
        "gas": 21000, "max_fee": 2, "max_priority": 1}})
    set digestlen to length(tx["digest"])
print(contains(denied, "net"))
print(digestlen)
-- afuera del sandbox la lectura anda de nuevo
print(eth_chain_id("http://127.0.0.1:{port}"))
"#,
        port = port,
    ));
    assert_eq!(o2[0], "true", "en sandbox el RPC se deniega");
    assert_eq!(o2[1], "32", "tx_eip1559 puro sigue andando en sandbox");
    assert_eq!(o2[2], "1", "afuera del sandbox la lectura anda");
}

// =========================================================
// G23 — respuestas hostiles: error atrapable, jamás data en silencio
// =========================================================

fn hostile_mock() -> u16 {
    mock_http_server(move |m, p, _ct, body| {
        // last-round absurdo (u64::MAX): lv = fv + 1000 desbordaría — error
        // atrapable, jamás un wrap silencioso ni un panic de overflow.
        if m == "GET" && p == "/v2/transactions/params" {
            return (
                200,
                json!({
                    "fee": 0, "min-fee": 1000, "last-round": u64::MAX,
                    "genesis-hash": b64_encode(&[3u8; 32]), "genesis-id": "hostile-v1",
                })
                .to_string(),
            );
        }
        let (method, _) = rpc_method(body);
        let resp = match method.as_str() {
            // Hex-quantity NO canónico (ceros a la izquierda): un nodo hostil
            // jamás cuela un número — se rechaza, no se "arregla".
            "eth_getBalance" => rpc_ok(json!("0x01")),
            // Forma equivocada: number donde va un hex string.
            "eth_chainId" => rpc_ok(json!(42)),
            // Respuesta gigante (> 16 MiB): se corta ANTES de parsear.
            "eth_gasPrice" => rpc_ok(json!("a".repeat(17 * 1024 * 1024))),
            // id que no coincide: envelope hostil.
            "eth_getTransactionCount" => {
                json!({"jsonrpc": "2.0", "id": 999, "result": "0x1"}).to_string()
            }
            other => rpc_err(-32601, &format!("method not found: {}", other)),
        };
        (200, resp)
    })
}

#[test]
fn g23_hostile_responses_are_catchable_errors() {
    let port = hostile_mock();
    let src = format!(
        r#"require net("127.0.0.1")

test "hex no canónico, forma equivocada, respuesta gigante, id ajeno, round absurdo"
    let url be "http://127.0.0.1:{port}"
    let e1 be ""
    try
        let x be eth_balance(url, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
    recover e
        set e1 to e
    assert(contains(e1, "non-canonical"))
    let e2 be ""
    try
        let x be eth_chain_id(url)
    recover e
        set e2 to e
    assert(contains(e2, "hex quantity"))
    let e3 be ""
    try
        let x be eth_gas_price(url)
    recover e
        set e3 to e
    assert(contains(e3, "limit"))
    let e4 be ""
    try
        let x be eth_nonce(url, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
    recover e
        set e4 to e
    assert(contains(e4, "id"))
    let e5 be ""
    try
        let p be algorand_params(url)
    recover e
        set e5 to e
    assert(contains(e5, "last-round"))
"#,
        port = port,
    );
    tests_pass(&src, "<batch14-hostile>.syn", 1);
}

// =========================================================
// Polling acotado — jamás cuelga (los tres wait/confirm)
// =========================================================

/// Mock flaky: cada waiter ve 1º un poll sano (aún sin confirmar), 2º un HTTP
/// 500 (blip transitorio) y 3º la confirmación — el waiter debe sobrevivir el
/// blip y confirmar.
fn flaky_mock() -> u16 {
    let evm_polls = Arc::new(AtomicUsize::new(0));
    let sol_polls = Arc::new(AtomicUsize::new(0));
    let algo_polls = Arc::new(AtomicUsize::new(0));
    mock_http_server(move |method, path, _ct, body| {
        if method == "GET" && path.starts_with("/v2/transactions/pending/") {
            return match algo_polls.fetch_add(1, Ordering::SeqCst) {
                0 => (200, json!({"confirmed-round": 0, "pool-error": ""}).to_string()),
                1 => (503, "unavailable".to_string()),
                _ => (200, json!({"confirmed-round": 45, "pool-error": ""}).to_string()),
            };
        }
        let (rpc, _) = rpc_method(body);
        match rpc.as_str() {
            "eth_getTransactionReceipt" => match evm_polls.fetch_add(1, Ordering::SeqCst) {
                0 => (200, rpc_ok(json!(null))),
                1 => (500, "gateway exploded".to_string()),
                _ => (
                    200,
                    rpc_ok(json!({
                        "blockNumber": "0x64", "status": "0x1", "gasUsed": "0x5208",
                        "transactionHash": VEC1_HASH,
                        "from": "0x9858effd232b4033e47d90003d41ec34ecaeda94",
                        "to": "0x6fac4d18c912343bf86fa7049364dd4e424ab9c0",
                        "logs": [],
                    })),
                ),
            },
            "getSignatureStatuses" => match sol_polls.fetch_add(1, Ordering::SeqCst) {
                0 => (200, rpc_ok(json!({"context": {"slot": 1}, "value": [null]}))),
                1 => (502, "bad gateway".to_string()),
                _ => (
                    200,
                    rpc_ok(json!({
                        "context": {"slot": 2},
                        "value": [{"slot": 1, "confirmations": 3, "err": null,
                                   "confirmationStatus": "confirmed"}],
                    })),
                ),
            },
            other => (200, rpc_err(-32601, &format!("method not found: {}", other))),
        }
    })
}

/// Mock que muere DESPUÉS del primer poll sano: todo 500 desde el 2º request.
fn dark_after_first_mock() -> u16 {
    let polls = Arc::new(AtomicUsize::new(0));
    mock_http_server(move |_m, _p, _ct, body| {
        let (rpc, _) = rpc_method(body);
        match rpc.as_str() {
            "eth_getTransactionReceipt" => {
                if polls.fetch_add(1, Ordering::SeqCst) == 0 {
                    (200, rpc_ok(json!(null)))
                } else {
                    (500, "node went dark".to_string())
                }
            }
            other => (200, rpc_err(-32601, &format!("method not found: {}", other))),
        }
    })
}

#[test]
fn transient_failures_mid_wait_retry_dead_node_fails_fast() {
    let flaky = flaky_mock();
    let dark = dark_after_first_mock();
    // Puerto libre y CERRADO (bind + drop): conexión rechazada en el primer poll.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let start = Instant::now();
    let src = format!(
        r#"require net("127.0.0.1")

test "un blip transitorio (5xx) en medio de la espera NO la mata: reintenta y confirma"
    let url be "http://127.0.0.1:{flaky}"
    let h be "0x6fb18223cd52476122a18a2b59a6c9faca40b36937217962a4f81b0da1c79880"
    let receipt be eth_wait_receipt(url, h, 1, 15)
    assert_eq(receipt["status"], 1)
    let status be solana_confirm(url, "{sig58}", 15)
    assert_eq(status["confirmation_status"], "confirmed")
    let info be algorand_wait(url, "{txid}", 15)
    assert_eq(info["confirmed-round"], 45)

test "nodo muerto en el PRIMER poll: error inmediato, no una espera que miente"
    let e be ""
    try
        let r be eth_wait_receipt("http://127.0.0.1:{dead}", "0x6fb18223cd52476122a18a2b59a6c9faca40b36937217962a4f81b0da1c79880", 1, 30)
    recover er
        set e to er
    assert(contains(e, "failed"))

test "el nodo muere DESPUÉS del primer poll: al vencer sube el ERROR, no nothing"
    let e be ""
    try
        let r be eth_wait_receipt("http://127.0.0.1:{dark}", "0x6fb18223cd52476122a18a2b59a6c9faca40b36937217962a4f81b0da1c79880", 1, 3)
    recover er
        set e to er
    assert(contains(e, "HTTP 500"))
    assert(contains(e, "deadline"))
"#,
        flaky = flaky,
        dark = dark,
        dead = dead,
        sig58 = base58_encode(&[9u8; 64]),
        txid = "A".repeat(52),
    );
    tests_pass(&src, "<batch14-transient>.syn", 3);
    // El caso "nodo muerto" debe fallar RÁPIDO (nada de agotar sus 30 s).
    assert!(
        start.elapsed() < Duration::from_secs(30),
        "la suite transitoria no debe estirarse: {:?}",
        start.elapsed()
    );
}

fn never_confirms_mock() -> u16 {
    mock_http_server(move |method, path, _ct, body| {
        if method == "GET" && path.starts_with("/v2/transactions/pending/") {
            return (200, json!({"confirmed-round": 0, "pool-error": ""}).to_string());
        }
        let (rpc, _) = rpc_method(body);
        let resp = match rpc.as_str() {
            "eth_getTransactionReceipt" => rpc_ok(json!(null)),
            "getSignatureStatuses" => rpc_ok(json!({"context": {"slot": 1}, "value": [null]})),
            other => rpc_err(-32601, &format!("method not found: {}", other)),
        };
        (200, resp)
    })
}

#[test]
fn bounded_polling_returns_nothing_never_hangs() {
    let port = never_confirms_mock();
    let start = Instant::now();
    let src = format!(
        r#"require net("127.0.0.1")

test "los tres wait/confirm vencen a nothing"
    let url be "http://127.0.0.1:{port}"
    let h be "0x6fb18223cd52476122a18a2b59a6c9faca40b36937217962a4f81b0da1c79880"
    assert_eq(eth_wait_receipt(url, h, 1, 1), nothing)
    assert_eq(solana_confirm(url, "{sig58}", 1), nothing)
    assert_eq(algorand_wait(url, "{txid}", 1), nothing)
"#,
        port = port,
        sig58 = base58_encode(&[9u8; 64]),
        txid = "A".repeat(52),
    );
    tests_pass(&src, "<batch14-bounded>.syn", 1);
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "el polling acotado no debe estirarse: {:?}",
        start.elapsed()
    );
}

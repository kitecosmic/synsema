//! E2E del Batch 16 (Bitcoin) por el runtime REAL, SIN red externa: mock Esplora
//! REST sobre TcpListener local. Cubre el loop autónomo completo y las guardas.
//!
//! - **El loop P2WPKH:** btc_utxos → btc_tx → secp256k1_sign (gate `sign`) →
//!   btc_tx_raw → btc_send (el mock RECOMPUTA el txid de los bytes posteados y lo
//!   devuelve; btc_send exige que coincida con el local) → btc_wait.
//! - **El loop P2TR key-path:** ídem con schnorr_sign(…, "taproot"). La firma
//!   Schnorr es determinista (aux=0) → el raw es byte-exacto contra el vector
//!   embit, así que el mock puede exigir los bytes EXACTOS.
//! - **PSBT (custodia fría):** el agente arma (btc_tx + psbt_encode), un firmante
//!   externo (fixture embit) devuelve el PSBT firmado, psbt_finalize + btc_send.
//! - **G28/G29 hostiles:** fee faltante, change olvidado, dust, float, cross-red.
//! - **Sandbox/scope:** firmar y wif_import denegados en sandbox; el read-side
//!   deniega sin `net`; el builder PURO sigue andando en sandbox.
//! - **Read-side hostil (G23):** el nodo miente el amount/txid → error atrapable;
//!   btc_wait vence a nothing contra un mock que jamás confirma.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use sha2::{Digest, Sha256};
use synsema_runtime::engine::{run_source, run_tests};

static AUDIT_ISOLATE: std::sync::Once = std::sync::Once::new();
fn isolate_audit_dir() {
    AUDIT_ISOLATE.call_once(|| {
        let dir = std::env::temp_dir().join(format!("syn_test_audit_btc_{}", std::process::id()));
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
// Mock Esplora REST (algunas respuestas son TEXTO plano)
// =========================================================

type Handler = dyn Fn(&str, &str, &[u8]) -> (u16, String) + Send + Sync;

fn mock_http_server(handler: impl Fn(&str, &str, &[u8]) -> (u16, String) + Send + Sync + 'static) -> u16 {
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
                for line in lines {
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_length = v.trim().parse().unwrap_or(0);
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
                let (status, resp_body) = handler(&method, &path, &body);
                let ct = if resp_body.starts_with('{') || resp_body.starts_with('[') {
                    "application/json"
                } else {
                    "text/plain"
                };
                let resp = format!(
                    "HTTP/1.1 {} X\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    ct,
                    resp_body.len(),
                    resp_body
                );
                let _ = sock.write_all(resp.as_bytes());
            });
        }
    });
    port
}

fn dsha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// TXID (display, byte-reversed) del hex posteado a `/tx`: reserializa SIN witness
/// y hace dSHA256. Prueba honestamente que btc_send valida el eco del nodo.
fn txid_from_posted_hex(hex_body: &[u8]) -> String {
    let raw = hex::decode(String::from_utf8_lossy(hex_body).trim()).unwrap_or_default();
    let nowit = strip_witness(&raw);
    let mut h = dsha256(&nowit);
    h.reverse();
    hex::encode(h)
}

/// Reserializa una tx quitando marker/flag/witness (para el txid, BIP-141).
fn strip_witness(raw: &[u8]) -> Vec<u8> {
    let mut p = 0usize;
    let rd = |p: &mut usize, n: usize| -> Vec<u8> {
        let s = raw[*p..*p + n].to_vec();
        *p += n;
        s
    };
    let read_vi = |p: &mut usize| -> u64 {
        let b = raw[*p];
        *p += 1;
        match b {
            0xfd => {
                let v = u16::from_le_bytes(raw[*p..*p + 2].try_into().unwrap()) as u64;
                *p += 2;
                v
            }
            0xfe => {
                let v = u32::from_le_bytes(raw[*p..*p + 4].try_into().unwrap()) as u64;
                *p += 4;
                v
            }
            0xff => {
                let v = u64::from_le_bytes(raw[*p..*p + 8].try_into().unwrap());
                *p += 8;
                v
            }
            n => n as u64,
        }
    };
    let mut out = Vec::new();
    out.extend_from_slice(&rd(&mut p, 4)); // version
    let segwit = raw.get(p) == Some(&0x00);
    if segwit {
        p += 2; // marker + flag
    }
    let n_in = read_vi(&mut p);
    let mut vi = Vec::new();
    write_vi(n_in, &mut vi);
    out.extend_from_slice(&vi);
    for _ in 0..n_in {
        out.extend_from_slice(&rd(&mut p, 36)); // outpoint
        let sl = read_vi(&mut p);
        let mut svi = Vec::new();
        write_vi(sl, &mut svi);
        out.extend_from_slice(&svi);
        out.extend_from_slice(&rd(&mut p, sl as usize));
        out.extend_from_slice(&rd(&mut p, 4)); // sequence
    }
    let n_out = read_vi(&mut p);
    let mut ovi = Vec::new();
    write_vi(n_out, &mut ovi);
    out.extend_from_slice(&ovi);
    for _ in 0..n_out {
        out.extend_from_slice(&rd(&mut p, 8)); // amount
        let sl = read_vi(&mut p);
        let mut svi = Vec::new();
        write_vi(sl, &mut svi);
        out.extend_from_slice(&svi);
        out.extend_from_slice(&rd(&mut p, sl as usize));
    }
    if segwit {
        for _ in 0..n_in {
            let items = read_vi(&mut p);
            for _ in 0..items {
                let il = read_vi(&mut p);
                p += il as usize;
            }
        }
    }
    out.extend_from_slice(&raw[p..p + 4]); // locktime
    out
}

fn write_vi(n: u64, out: &mut Vec<u8>) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x10000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

// mini-hex sin dep externa
mod hex {
    pub fn decode(s: impl AsRef<str>) -> Result<Vec<u8>, ()> {
        let s = s.as_ref();
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
    pub fn encode(b: impl AsRef<[u8]>) -> String {
        b.as_ref().iter().map(|x| format!("{:02x}", x)).collect()
    }
}

// -- UTXOs del vector W (las claves BIP-84 del mnemónico estándar) --
const ADDR_W0: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const KEY_84_0: &str = "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3";
const KEY_84_1: &str = "2fd0affa51529f940a358ec0c50de81267d0bf5158ca61887347676946362c5b";
const PUB_84_0: &str = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c";
const PUB_84_1: &str = "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77";
const ADDR_86_0: &str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
const KEY_86_0: &str = "41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361";
const VEC_T_RAW: &str = "02000000000101a7a00bf2ed15f21c107126686d7662e9eef23c295b8bb746146277e5ced6f4f00000000000fdffffff023075000000000000225120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbbf44c000000000000225120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc0140e077ce8461ab91733cf7249e79e7e47ee198205eb0b53366e2646973b6f9f84cc1c12732d02264d3d06c1e04091e2a3312432914b2f46b73251e80ec59db222c00000000";
const VEC_T_TXID: &str = "d98a84d0e281fd79a1b290a87ba19e8f434f392b5b2c47e60c7ea4556bedc3eb";

/// Mock Esplora: UTXOs de una dirección, tip, balance, fees, broadcast (recomputa
/// el txid) y status (confirmado tras el 2º poll). `demand_exact` (P2TR): el
/// broadcast EXIGE los bytes exactos del vector.
fn esplora_mock(demand_exact: Option<&'static str>) -> u16 {
    let status_polls = Arc::new(AtomicUsize::new(0));
    mock_http_server(move |method, path, body| {
        let status_polls = status_polls.clone();
        if method == "GET" && path == "/blocks/tip/height" {
            return (200, "800100".to_string());
        }
        if method == "GET" && path.starts_with("/address/") && path.ends_with("/utxo") {
            // Los 2 UTXOs del vector W (confirmados).
            return (
                200,
                json!([
                    {"txid": "0be2a795a30050f74e61f5ff5a16c7a5bca650e7a3af6a0ff04544821697b1cd",
                     "vout": 0, "value": 60000, "status": {"confirmed": true, "block_height": 800000}},
                    {"txid": "fd781ed9a57cd59eb91b2322d20b1dcf8675f1d9df6c58e36d1abebd43d05c84",
                     "vout": 1, "value": 40000, "status": {"confirmed": true, "block_height": 800050}}
                ])
                .to_string(),
            );
        }
        if method == "GET" && path.starts_with("/address/") {
            return (
                200,
                json!({
                    "chain_stats": {"funded_txo_sum": 100000, "spent_txo_sum": 0},
                    "mempool_stats": {"funded_txo_sum": 0, "spent_txo_sum": 500}
                })
                .to_string(),
            );
        }
        if method == "GET" && path == "/fee-estimates" {
            return (200, json!({"1": 12.5, "6": 4.2, "144": 1.0}).to_string());
        }
        if method == "POST" && path == "/tx" {
            if let Some(exact) = demand_exact {
                if String::from_utf8_lossy(body).trim() != exact {
                    return (400, "raw tx does not match the vector".to_string());
                }
            }
            // Recompone el txid HONESTAMENTE de los bytes posteados.
            return (200, txid_from_posted_hex(body));
        }
        if method == "GET" && path.starts_with("/tx/") && path.ends_with("/status") {
            // 1er poll: aún sin confirmar (404 = todavía no en mempool); 2º:
            // confirmada en el bloque 800000 (con tip 800100 → 101 confs).
            if status_polls.fetch_add(1, Ordering::SeqCst) == 0 {
                return (404, "Transaction not found".to_string());
            }
            return (
                200,
                json!({"confirmed": true, "block_height": 800000,
                       "block_hash": "0000000000000000000123abc", "block_time": 1700000000})
                .to_string(),
            );
        }
        (404, "not found".to_string())
    })
}

// =========================================================
// A — el loop P2WPKH completo (leer → construir → firmar → enviar → confirmar)
// =========================================================

#[test]
fn btc_p2wpkh_full_loop_read_build_sign_send_confirm() {
    let port = esplora_mock(None);
    let src = format!(
        r#"require net("127.0.0.1")
require sign("HOT")

test "utxos → btc_tx → firmar → btc_tx_raw → btc_send → btc_wait"
    let url be "http://127.0.0.1:{port}"
    let k0 be as_secret("{k0}", "HOT")
    let k1 be as_secret("{k1}", "HOT")
    -- LEER
    let utxos be btc_utxos(url, "{addr}")
    assert_eq(length(utxos), 2)
    assert_eq(utxos[0]["amount"], 60000)
    assert_eq(utxos[0]["confirmations"], 101)
    let bal be btc_balance(url, "{addr}")
    assert_eq(bal["confirmed"], 100000)
    assert_eq(bal["mempool"], 0 - 500)
    let fees be btc_fee_estimates(url)
    assert(fees["1"] > fees["6"])
    -- CONSTRUIR (G28: fee declarado; el eco muestra los números)
    let tx be btc_tx({{
        "inputs": [
            {{"txid": utxos[0]["txid"], "vout": utxos[0]["vout"], "amount": utxos[0]["amount"],
              "address": "{addr}", "pubkey": bytes("{pub0}", "hex")}},
            {{"txid": utxos[1]["txid"], "vout": utxos[1]["vout"], "amount": utxos[1]["amount"],
              "address": "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", "pubkey": bytes("{pub1}", "hex")}}
        ],
        "outputs": [
            {{"address": "1JaUQDVNRdhfNsVncGkXedaPSM5Gc54Hso", "amount": 70000}},
            {{"address": "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", "amount": 29500}}
        ],
        "fee": 500}})
    assert_eq(tx["fee"], 500)
    assert_eq(tx["total_in"], 100000)
    assert_eq(length(tx["digests"]), 2)
    -- FIRMAR (la ÚNICA puerta de valor) y ENSAMBLAR
    let s0 be secp256k1_sign(tx["digests"][0], k0)
    let s1 be secp256k1_sign(tx["digests"][1], k1)
    let raw be btc_tx_raw(tx, [s0, s1])
    let txid be btc_txid(raw)
    -- ENVIAR: el mock recompone el txid de los bytes y btc_send exige que coincida
    let sent be btc_send(url, raw)
    assert_eq(sent, txid)
    -- CONFIRMAR: polling acotado (404 en el 1er poll, confirmada en el 2º)
    let info be btc_wait(url, sent, 1, 30)
    assert_eq(info["confirmed"], true)
    assert_eq(info["block_height"], 800000)
"#,
        port = port,
        k0 = KEY_84_0,
        k1 = KEY_84_1,
        addr = ADDR_W0,
        pub0 = PUB_84_0,
        pub1 = PUB_84_1,
    );
    tests_pass(&src, "<batch16-p2wpkh>.syn", 1);
}

// =========================================================
// B — el loop P2TR key-path (Schnorr determinista: raw byte-exacto)
// =========================================================

#[test]
fn btc_p2tr_full_loop_schnorr_taproot() {
    let port = esplora_mock(Some(VEC_T_RAW));
    let src = format!(
        r#"require net("127.0.0.1")
require sign("COLD")

test "taproot key-path: schnorr_sign con tweak interno → raw byte-exacto → send"
    let url be "http://127.0.0.1:{port}"
    let k be as_secret("{key}", "COLD")
    let tx be btc_tx({{
        "inputs": [{{"txid": "f0f4d6cee577621446b78b5b293cf2eee962766d682671101cf215edf20ba0a7",
            "vout": 0, "amount": 50000, "address": "{addr}"}}],
        "outputs": [
            {{"address": "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh", "amount": 30000}},
            {{"address": "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7", "amount": 19700}}
        ],
        "fee": 300}})
    -- La firma de key-path aplica el tweak BIP-341 INTERNAMENTE ("taproot")
    let sig be schnorr_sign(tx["digests"][0], k, "taproot")
    let raw be btc_tx_raw(tx, [sig])
    assert_eq(btc_txid(raw), "{txid}")
    -- El mock EXIGE los bytes EXACTOS del vector embit (Schnorr es determinista)
    let sent be btc_send(url, raw)
    assert_eq(sent, "{txid}")
"#,
        port = port,
        key = KEY_86_0,
        addr = ADDR_86_0,
        txid = VEC_T_TXID,
    );
    tests_pass(&src, "<batch16-p2tr>.syn", 1);
}

// =========================================================
// E — PSBT: el agente prepara, un firmante externo firma, el agente difunde
// =========================================================

#[test]
fn btc_psbt_cold_custody_flow() {
    // PSBT firmado por embit (fixture) — la clave JAMÁS existió en la máquina del
    // agente. El agente lo audita, lo finaliza y lo difunde.
    let port = esplora_mock(None);
    let psbt_signed = "cHNidP8BAJ0CAAAAAs2xlxaCREXwD2qvo+dQprylxxZa//VhTvdQAKOVp+ILAAAAAAD9////hFzQQ72+Gm3jWGzf2fF1hs8dC9IiIxu5ntV8pdkeeP0BAAAAAP3///8CcBEBAAAAAAAZdqkUwM681sPTyox13F7GLr5VMw75EOKIrDxzAAAAAAAAFgAUPjSYXcpv3cn7NplA5MfY4oc/UpwAAAAAAAEBH2DqAAAAAAAAFgAUwM681sPTyox13F7GLr5VMw75EOIiAgMw1U/Q3UIKbl+NNiT180gsrjUPedXwdTv1vu+cLZGvPEcwRAIgJnkPQ6cWl1hXpVYgyvbKZGOJ3T/tNWPoeCYXNSkYTjACIG+sM2rZLq7EMpmTEyH9SR8+eOyx/8EVWgb9WmOMmOhZAQABAR9AnAAAAAAAABYAFJyQ+TTqUfoPZQQXcEPgkI2mkpmDIgID53X9UfDfuM2GXZ/xzKKhWM9lH+mX/cn+6cHTtemV6ndHMEQCIAb0KldAdaMvbiuCY9BPnxZ2jVsQ89newNBt3h9lT+OtAiA/UTtVaa8m8haBD6lNToF2OmQJ8VswtLECCVngPzvAYgEAAAA=";
    let src = format!(
        r#"require net("127.0.0.1")

test "auditar un PSBT firmado en frío → finalize → send (sin `sign`: PSBT es puro)"
    let url be "http://127.0.0.1:{port}"
    -- AUDITAR el PSBT ajeno ANTES de difundir
    let audit be psbt_decode("{psbt}")
    assert_eq(audit["fee"], 500)
    assert_eq(audit["total_out"], 99500)
    assert_eq(audit["complete"], true)
    -- FINALIZAR + DIFUNDIR (ningún `require sign`: el firmante ya firmó en frío)
    let raw be psbt_finalize("{psbt}")
    let txid be btc_txid(raw)
    let sent be btc_send(url, raw)
    assert_eq(sent, txid)
"#,
        port = port,
        psbt = psbt_signed,
    );
    tests_pass(&src, "<batch16-psbt>.syn", 1);
}

#[test]
fn btc_agent_prepares_unsigned_psbt() {
    // El agente ARMA el PSBT sin firmar (btc_tx + psbt_encode) — puro, sin `sign`.
    let src = r#"test "el agente prepara el PSBT unsigned para la hardware wallet"
    let tx be btc_tx({
        "inputs": [{"txid": "f0f4d6cee577621446b78b5b293cf2eee962766d682671101cf215edf20ba0a7",
            "vout": 0, "amount": 50000,
            "address": "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"}],
        "outputs": [
            {"address": "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh", "amount": 30000},
            {"address": "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7", "amount": 19700}
        ],
        "fee": 300})
    let psbt be psbt_encode(tx)
    -- round-trip: decode del propio encode == mismos amounts/fee
    let back be psbt_decode(psbt)
    assert_eq(back["fee"], 300)
    assert_eq(back["total_out"], 49700)
    assert_eq(back["complete"], false)
"#;
    tests_pass(src, "<batch16-psbt-prepare>.syn", 1);
}

// =========================================================
// G28 / G29 hostiles: cada guarda con su error dirigido
// =========================================================

#[test]
fn g28_g29_hostile_guards_are_catchable() {
    let src = r#"test "G28: fee faltante, change olvidado, dust; G29: float, cross-red"
    let base_in be [{"txid": "0be2a795a30050f74e61f5ff5a16c7a5bca650e7a3af6a0ff04544821697b1cd",
        "vout": 0, "amount": 60000, "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        "pubkey": bytes("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c", "hex")}]

    -- fee faltante → error que nombra G28
    let e1 be ""
    try
        let t be btc_tx({"inputs": base_in,
            "outputs": [{"address": "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", "amount": 59500}]})
    recover e
        set e1 to e
    assert(contains(e1, "G28"))

    -- change olvidado → nombra la diferencia exacta
    let e2 be ""
    try
        let t be btc_tx({"inputs": base_in,
            "outputs": [{"address": "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", "amount": 10000}],
            "fee": 500})
    recover e
        set e2 to e
    assert(contains(e2, "change output"))

    -- dust → nombra el límite
    let e3 be ""
    try
        let t be btc_tx({"inputs": base_in,
            "outputs": [{"address": "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", "amount": 59300},
                        {"address": "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", "amount": 200}],
            "fee": 500})
    recover e
        set e3 to e
    assert(contains(e3, "dust"))

    -- float en amount → conversión sats
    let e4 be ""
    try
        let t be btc_tx({"inputs": base_in,
            "outputs": [{"address": "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", "amount": 0.5}],
            "fee": 500})
    recover e
        set e4 to e
    assert(contains(e4, "sats"))

    -- cross-red: dirección testnet en tx mainnet → nombra las dos redes
    let e5 be ""
    try
        let t be btc_tx({"inputs": base_in,
            "outputs": [{"address": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "amount": 59500}],
            "fee": 500})
    recover e
        set e5 to e
    assert(contains(e5, "testnet"))
    assert(contains(e5, "mainnet"))
"#;
    tests_pass(src, "<batch16-hostile>.syn", 1);
}

// =========================================================
// Sandbox / scope — G30: firmar y wif_import denegados; builder puro sigue
// =========================================================

#[test]
fn sandbox_denies_signing_and_wif_import_pure_builder_survives() {
    // Sin `require sign` → schnorr_sign deniega atrapable.
    let o = out(
        r#"let denied be ""
try
    let k be as_secret("41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361", "K")
    let s be schnorr_sign(bytes("00000000000000000000000000000000000000000000000000000000000000ff", "hex"), k, "taproot")
recover e
    set denied to e
print(contains(denied, "sign"))
print("vivo")
"#,
    );
    assert_eq!(o[0], "true", "sin require sign → schnorr_sign deniega");
    assert_eq!(o[1], "vivo");

    // Sin `require wallet` → wif_import deniega atrapable.
    let o = out(
        r#"let denied be ""
try
    let k be wif_import("KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d")
recover e
    set denied to e
print(contains(denied, "wallet"))
"#,
    );
    assert_eq!(o[0], "true", "sin require wallet → wif_import deniega");

    // Dentro de sandbox: firmar deniega; el builder PURO (btc_tx) sigue andando.
    let o = out(
        r#"require sign("HOT")
require net("127.0.0.1")
let denied be ""
let digests be 0
sandbox
    try
        let k be as_secret("4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3", "HOT")
        let s be schnorr_sign(bytes("00000000000000000000000000000000000000000000000000000000000000ff", "hex"), k, "taproot")
    recover e
        set denied to e
    let tx be btc_tx({"inputs": [{"txid": "0be2a795a30050f74e61f5ff5a16c7a5bca650e7a3af6a0ff04544821697b1cd",
        "vout": 0, "amount": 60000, "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        "pubkey": bytes("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c", "hex")}],
        "outputs": [{"address": "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", "amount": 59500}],
        "fee": 500})
    set digests to length(tx["digests"])
print(contains(denied, "sign"))
print(digests)
"#,
    );
    assert_eq!(o[0], "true", "en sandbox firmar se deniega");
    assert_eq!(o[1], "1", "el builder PURO sigue andando en sandbox");
}

// =========================================================
// WIF import — gateado por `wallet`, firma con la clave importada
// =========================================================

#[test]
fn wif_import_gated_by_wallet_then_signs() {
    let src = r#"require wallet
require sign("imported")

test "wif_import (gate wallet) → deriva su dirección BIP-84 → firma"
    let k be wif_import("KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d", "imported")
    -- La clave importada es la del path 0 del mnemónico estándar (BIP-84)
    assert_eq(btc_address(k), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    -- Y firma (la MISMA puerta `sign`)
    let sig be secp256k1_sign(bytes("00000000000000000000000000000000000000000000000000000000000000ff", "hex"), k)
    assert_eq(length(sig), 65)

test "wif con checksum roto → error atrapable, jamás ecoa el material"
    let e be ""
    try
        let bad be wif_import("KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9X", "x")
    recover er
        set e to er
    assert(contains(e, "WIF"))
"#;
    tests_pass(src, "<batch16-wif>.syn", 2);
}

// =========================================================
// Read-side hostil (G23) + btc_wait acotado
// =========================================================

#[test]
fn read_side_hostile_node_is_catchable() {
    // El nodo miente un amount sobre los 21M de BTC y un txid malformado.
    let port = mock_http_server(|method, path, _body| {
        if method == "GET" && path.ends_with("/utxo") {
            return (
                200,
                json!([{"txid": "00", "vout": 0, "value": 21_000_001 * 100_000_000u64,
                        "status": {"confirmed": false}}])
                .to_string(),
            );
        }
        if method == "POST" && path == "/tx" {
            return (200, "no-es-un-txid".to_string());
        }
        (404, "x".to_string())
    });
    let src = format!(
        r#"require net("127.0.0.1")

test "amount imposible y txid malformado del nodo → error atrapable (G23)"
    let url be "http://127.0.0.1:{port}"
    let e1 be ""
    try
        let u be btc_utxos(url, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    recover e
        set e1 to e
    assert(contains(e1, "21M") or contains(e1, "txid"))
"#,
        port = port,
    );
    tests_pass(&src, "<batch16-g23>.syn", 1);
}

#[test]
fn btc_wait_bounded_returns_nothing_never_hangs() {
    // Un mock que SIEMPRE responde 404 (nunca aparece en mempool): btc_wait vence
    // a nothing sin colgarse.
    let port = mock_http_server(|_m, _p, _b| (404, "not found".to_string()));
    let start = Instant::now();
    let src = format!(
        r#"require net("127.0.0.1")

test "btc_wait vence a nothing contra un nodo que jamás confirma"
    let url be "http://127.0.0.1:{port}"
    assert_eq(btc_wait(url, "cc170717b3abb5c611f431a6f2f1c22235030c6a0cd428175da63db21186dfb2", 1, 1), nothing)
"#,
        port = port,
    );
    tests_pass(&src, "<batch16-bounded>.syn", 1);
    assert!(start.elapsed() < Duration::from_secs(15), "no debe colgar: {:?}", start.elapsed());
}

// =========================================================
// HD BIP-84/86 — hd_derive real → direcciones OFICIALES del mnemónico estándar
// =========================================================

#[test]
fn hd_bip84_bip86_derivation_matches_official_addresses() {
    // El mnemónico estándar de BIP-39; los paths y direcciones son los OFICIALES
    // de bip-0084.mediawiki / bip-0086.mediawiki. Verifica que la derivación del
    // batch 13 (BIP-32 secp256k1) alimenta btc_address sin materializar la clave.
    let src = r#"require wallet

test "BIP-84 m/84'/0'/0'/0/{0,1} → las direcciones P2WPKH oficiales"
    let frase be as_secret("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "W")
    let seed be mnemonic_to_seed(frase)
    let k0 be hd_derive(seed, "m/84'/0'/0'/0/0")
    assert_eq(btc_address(k0), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    let k1 be hd_derive(seed, "m/84'/0'/0'/0/1")
    assert_eq(btc_address(k1), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")

test "BIP-86 m/86'/0'/0'/0/0 → la dirección P2TR oficial (tweak interno)"
    let frase be as_secret("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "W")
    let seed be mnemonic_to_seed(frase)
    let k be hd_derive(seed, "m/86'/0'/0'/0/0")
    assert_eq(btc_address(k, "p2tr"), "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")
"#;
    tests_pass(src, "<batch16-hd>.syn", 2);
}

// =========================================================
// btc_rpc — Bitcoin Core con Basic auth desde un secret
// =========================================================

#[test]
fn btc_rpc_basic_auth_from_secret() {
    // El mock exige el header Authorization Basic correcto (user:pass base64).
    let seen_auth = Arc::new(std::sync::Mutex::new(String::new()));
    let seen = seen_auth.clone();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        while let Ok((mut sock, _)) = listener.accept() {
            let seen = seen.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let mut acc = Vec::new();
                loop {
                    match sock.read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => {
                            acc.extend_from_slice(&buf[..n]);
                            if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let head = String::from_utf8_lossy(&acc);
                for line in head.split("\r\n") {
                    if let Some(v) = line.strip_prefix("Authorization:") {
                        *seen.lock().unwrap() = v.trim().to_string();
                    }
                }
                let body = json!({"jsonrpc": "2.0", "id": 1, "result": 800000}).to_string();
                let resp = format!(
                    "HTTP/1.1 200 X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes());
            });
        }
    });
    let src = format!(
        r#"require net("127.0.0.1")

test "btc_rpc con Basic auth: el pass es un secret que se materializa en el socket"
    let url be "http://127.0.0.1:{port}"
    let pass be as_secret("supersecret", "RPC_PASS")
    let h be btc_rpc(url, "getblockcount", [], {{"user": "bitcoin", "pass": pass}})
    assert_eq(h, 800000)
"#,
        port = port,
    );
    tests_pass(&src, "<batch16-rpc>.syn", 1);
    // "bitcoin:supersecret" en base64 = Yml0Y29pbjpzdXBlcnNlY3JldA==
    let auth = seen_auth.lock().unwrap().clone();
    assert_eq!(auth, "Basic Yml0Y29pbjpzdXBlcnNlY3JldA==", "el Basic auth materializó el secret");
}

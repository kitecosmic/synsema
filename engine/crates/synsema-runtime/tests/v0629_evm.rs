//! v0.6.29 — EVM (specs/lenguaje/evm.md): creación de contratos (CREATE / CREATE2 y el
//! constructor `evm_tx_create` con el firmante verificado), eventos (`abi_event_topic`,
//! `abi_decode_log`), `abi_encode` por tipos, firmas 27/28 (`evm_signature`,
//! `secp256k1_recover`), `evm_address` sobre 20 bytes y los nombres `<familia>_<acción>`
//! con sus alias deprecados. Todo PURO: lo que toca la red se prueba contra la L1 aparte.

use std::sync::Mutex;

use synsema_runtime::engine::run_source;

const KEY1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const KEY2: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const ADDR1: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

static ENV_LOCK: Mutex<()> = Mutex::new(());
static AUDIT_ISOLATE: std::sync::Once = std::sync::Once::new();

/// Firmar escribe un audit fail-loud: se redirige a un temp del proceso (ver batch11_e2e).
#[must_use]
fn isolate_audit_dir() -> std::sync::MutexGuard<'static, ()> {
    AUDIT_ISOLATE.call_once(|| {
        let dir = std::env::temp_dir().join(format!("syn_test_audit_v0629_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_var("SYNSEMA_AUDIT_DIR", &dir);
    });
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn out(src: &str) -> Vec<String> {
    let _g = isolate_audit_dir();
    let r = run_source(src, "<v0629_evm>");
    assert!(r.success, "falló: {:?}\n{}", r.errors, src);
    r.output
}

fn fails(src: &str) -> String {
    let _g = isolate_audit_dir();
    let r = run_source(src, "<v0629_evm>");
    assert!(!r.success, "tenía que fallar:\n{}\nsalida: {:?}", src, r.output);
    r.errors.join("\n")
}

#[test]
fn create_address_vectors() {
    // Vectores clásicos de CREATE (keccak(rlp([sender, nonce]))).
    assert_eq!(
        out(r#"let a be "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
print(lower(evm_create_address(a, 0)))
print(lower(evm_create_address(a, 1)))
print(lower(evm_create_address(a, 2)))
print(lower(evm_create_address(a, 3)))"#),
        vec![
            "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d",
            "0x343c43a37d37dff08ae8c4a11544c718abb4fcf8",
            "0xf778b86fa74e846c4f0a1fbd1335fe81c00a0c91",
            "0xfffd933a0bc612844eaf0c6fe3e5b8e9b6c1d19c",
        ]
    );
}

#[test]
fn create2_address_vectors_from_eip_1014() {
    assert_eq!(
        out(r#"let z be bytes("0000000000000000000000000000000000000000000000000000000000000000", "hex")
print(evm_create2_address("0x0000000000000000000000000000000000000000", z, keccak256(bytes("00", "hex"))))
print(evm_create2_address("0xdeadbeef00000000000000000000000000000000", z, keccak256(bytes("00", "hex"))))
print(evm_create2_address("0xdeadbeef00000000000000000000000000000000", bytes("0x000000000000000000000000feed000000000000000000000000000000000000", "hex"), keccak256(bytes("00", "hex"))))
print(evm_create2_address("0x0000000000000000000000000000000000000000", z, keccak256(bytes("deadbeef", "hex"))))"#),
        vec![
            "0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38",
            "0xB928f69Bb1D91Cd65274e3c79d8986362984fDA3",
            "0xD04116cDd17beBE565EB2422F2497E06cC1C9833",
            "0x70f2b2914A2a4b783FaEFb75f459A580616Fcb5e",
        ]
    );
    assert!(fails(r#"print(evm_create2_address("0x0000000000000000000000000000000000000000", bytes([1]), keccak256("x")))"#)
        .contains("salt"));
}

#[test]
fn event_topic_and_log_decoding() {
    assert_eq!(
        out(r#"print(abi_event_topic("Transfer(address,address,uint256)"))"#),
        vec!["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]
    );
    let src = r#"let transfer be {"type": "event", "name": "Transfer", "anonymous": false, "inputs": [
    {"name": "from", "type": "address", "indexed": true},
    {"name": "to", "type": "address", "indexed": true},
    {"name": "value", "type": "uint256", "indexed": false}]}
let pad be (a) => "0x000000000000000000000000" + slice(lower(a), 2)
let log be {"topics": [abi_event_topic("Transfer(address,address,uint256)"), pad("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"), pad("0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF")], "data": abi_encode("(uint256)", [1000])}
let ev be abi_decode_log(transfer, log)
print(ev.from, ev.to, ev.value)
print(abi_event_topic(transfer) == log.topics[0])
let other be {"topics": [abi_event_topic("Approval(address,address,uint256)")], "data": bytes([])}
print(abi_decode_log(transfer, other, nothing))"#;
    assert_eq!(
        out(src),
        vec![
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF 1000",
            "true",
            "nothing",
        ]
    );
    // Un indexed dinámico sólo viaja como su hash: bytes(32).
    let dyn_src = r#"let ev be {"name": "Named", "inputs": [{"name": "label", "type": "string", "indexed": true}, {"name": "n", "type": "uint8", "indexed": false}]}
let log be {"topics": [abi_event_topic("Named(string,uint8)"), hex(keccak256("hola"))], "data": abi_encode("uint8", [7])}
let d be abi_decode_log(ev, log)
print(d.label == keccak256("hola"), d.n)"#;
    assert_eq!(out(dyn_src), vec!["true 7"]);
    assert!(fails(r#"print(abi_decode_log({"name": "E", "inputs": []}, {"topics": ["0x00"], "data": bytes([])}))"#)
        .contains("abi_decode_log"));
}

#[test]
fn abi_encode_types_without_selector() {
    assert_eq!(
        out(r#"let v be ["0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", 5]
let enc be abi_encode("(address,uint256)", v)
print(length(enc), abi_decode("(address,uint256)", enc) == v)
print(length(abi_encode(["uint256"], [1])), length(abi_encode("transfer(address,uint256)", v)))"#),
        vec!["64 true", "32 68"]
    );
}

#[test]
fn signatures_27_28_and_addresses() {
    let src = format!(
        r#"require sign("K")
let k be as_secret("{KEY1}", "K")
let d be keccak256("mensaje")
let sig be secp256k1_sign(d, k)
let w be evm_signature(sig)
print(w[64] == 27 or w[64] == 28, evm_signature(w) == w)
print(evm_address(secp256k1_recover(d, w)) == evm_address(secp256k1_recover(d, sig)))
print(evm_address(secp256k1_recover(d, w)))
print(evm_address(bytes("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "hex")))
print(evm_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"))"#
    );
    assert_eq!(
        out(&src),
        vec![
            "true true",
            "true",
            ADDR1,
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        ]
    );
    let legacy = format!(
        r#"require sign("K")
let k be as_secret("{KEY1}", "K")
let d be keccak256("m")
let sig be secp256k1_sign(d, k)
print(secp256k1_recover(d, slice(sig, 0, 64) + bytes([37])))"#
    );
    assert!(fails(&legacy).contains("EIP-155"));
}

#[test]
fn contract_creation_with_verified_signer() {
    let build = format!(
        r#"require sign("K")
require sign("OTRA")
let k be as_secret("{KEY1}", "K")
let otra be as_secret("{KEY2}", "OTRA")
let tx be evm_tx_create({{"chain_id": 7960, "nonce": 0, "from": "{ADDR1}", "value": 0, "gas": 500000, "max_fee": 2000000000, "max_priority": 1000000000, "data": bytes("6080604052", "hex")}})
print(tx.to, tx.from, tx.contract_address == evm_create_address("{ADDR1}", 0))
let raw be evm_tx_raw(tx, secp256k1_sign(tx.digest, k))
print(raw[0])
"#
    );
    assert_eq!(out(&build), vec![format!("nothing {} true", ADDR1), "2".to_string()]);
    let wrong = format!(
        r#"require sign("OTRA")
let otra be as_secret("{KEY2}", "OTRA")
let tx be evm_tx_create({{"chain_id": 7960, "nonce": 0, "from": "{ADDR1}", "value": 0, "gas": 500000, "max_fee": 2, "max_priority": 1, "data": bytes([96])}})
print(evm_tx_raw(tx, secp256k1_sign(tx.digest, otra)))"#
    );
    assert!(fails(&wrong).contains("the signature is from"));
    assert!(fails(r#"print(evm_tx_create({"chain_id": 1, "nonce": 0, "from": "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", "to": "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", "value": 0, "gas": 1, "max_fee": 1, "max_priority": 1, "data": bytes([1])}))"#)
        .contains("has no \"to\""));
    assert!(fails(r#"print(evm_tx_create({"chain_id": 1, "nonce": 0, "from": "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", "value": 0, "gas": 1, "max_fee": 1, "max_priority": 1}))"#)
        .contains("init code"));
    assert!(fails(r#"print(evm_tx({"chain_id": 1, "nonce": 0, "value": 0, "gas": 1, "max_fee": 1, "max_priority": 1}))"#)
        .contains("evm_tx_create"));
}

#[test]
fn deprecated_names_still_work() {
    assert_eq!(
        out(r#"let p be {"chain_id": 1, "nonce": 0, "to": "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", "value": 0, "gas": 21000, "max_fee": 2, "max_priority": 1}
print(tx_eip1559(p).digest == evm_tx(p).digest)
print(replace_text("a-b", "-", "+"), replace("a-b", "-", "+"))
print(capture("hello world", "w[a-z]+"), regex_capture("hello world", "w[a-z]+"))"#),
        vec!["true", "a+b a+b", "world [\"world\"]"]
    );
    assert!(fails(r#"print(solana_tx({}, []))"#).contains("solana_tx_raw"));
}

#[test]
fn hmac_is_bytes() {
    assert_eq!(
        out(r#"let m be hmac("data", "key")
print(is_bytes(m), length(m), hex(m) == "0x" + hmac_sha256("data", "key"))"#),
        vec!["true 32 true"]
    );
}

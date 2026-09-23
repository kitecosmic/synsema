//! E2E de T2–T4 del spec de identidad, por programa `.syn` (lo que un usuario escribe):
//!
//! - T3/T4 puros: `canonical_json` (RFC 8785), `did_key_*`, `document_sign`/`document_verify`
//!   (W3C Data Integrity, `eddsa-jcs-2022` / `ecdsa-jcs-2019`) y `receipt`/`receipt_verify`
//!   (Verifiable Credential derivada del audit).
//! - T3 bajo `serve`: la Agent Card en `/.well-known/agent-card.json`, derivada de la tabla de
//!   rutas, firmada como JWS con el `did:key` de `SYNSEMA_IDENTITY_KEY` y verificable
//!   OFFLINE desde Synsema con `jwt_verify(..., {"did": kid})`; y un recibo firmado por una
//!   ruta, verificado desde otro programa con `receipt_verify`.
//! - T2: `webauthn_register` + `webauthn_verify` con un authenticator P-256 emulado (los
//!   mismos bytes que manda un browser: clientDataJSON, attestationObject, authenticatorData).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use synsema_core::bytesutil::{b64url_encode, hex_encode};
use synsema_runtime::engine::run_program;
use synsema_runtime::serve::run_serve_program;
use synsema_stdlib::didkey::{encode as did_encode, KeyAlg};

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn wait_ready(port: u16) {
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            thread::sleep(Duration::from_millis(150));
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("el server no quedó listo en :{}", port);
}

fn request(port: u16, method: &str, target: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    resp
}

fn status(resp: &str) -> u16 {
    resp.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn body_of(resp: &str) -> String {
    resp.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default()
}

fn scratch_dir(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!("synsema-identity-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().replace('\\', "/")
}

fn pem(label: &str, der: &[u8]) -> String {
    format!(
        "-----BEGIN {l}-----\n{}\n-----END {l}-----\n",
        synsema_core::bytesutil::b64_encode(der),
        l = label
    )
}

/// Una clave P-256 fija (escalar 7): SEC1 PEM, SPKI PEM, y su did:key.
struct P256Fixture {
    sec1_pem: String,
    spki_pem: String,
    did: String,
}

fn p256_fixture() -> P256Fixture {
    let mut scalar = [0u8; 32];
    scalar[31] = 7;
    let sk = p256::SecretKey::from_slice(&scalar).unwrap();
    let pt = sk.public_key().to_encoded_point(false);
    let mut sec1 = vec![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
    sec1.extend_from_slice(&scalar);
    let alg: Vec<u8> = vec![
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07,
    ];
    let mut spki = vec![0x30, (alg.len() + 2 + 1 + 65) as u8];
    spki.extend_from_slice(&alg);
    spki.push(0x03);
    spki.push(66);
    spki.push(0x00);
    spki.extend_from_slice(pt.as_bytes());
    let did = did_encode(KeyAlg::P256, sk.public_key().to_encoded_point(true).as_bytes()).unwrap();
    P256Fixture { sec1_pem: pem("EC PRIVATE KEY", &sec1), spki_pem: pem("PUBLIC KEY", &spki), did }
}

/// Un PEM en una línea con `\n` literales, como va en un `.env` o en un literal `.syn`.
fn one_line(pem: &str) -> String {
    pem.replace('\n', "\\n")
}

const ED_PUB_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

#[test]
fn canonical_json_and_did_key_are_exact_and_pure() {
    let p = p256_fixture();
    let prog = format!(
        r#"let c be canonical_json({{"b": 1, "a": [true, nothing, "é", 1.5], "n": 100}})
print("jcs " + c)
let pk be bytes("{ed}", "hex")
let did be did_key_encode(pk)
print("did " + did)
let back be did_key_decode(did)
print("back " + back["alg"] + " " + decode(back["public_key"], "hex") + " " + back["did"])
let doc be did_key_document(did)
print("doc " + doc["id"] + " methods " + text(length(doc["verificationMethod"])))
print("agreement " + json_encode(doc["keyAgreement"]))
print("p256 " + did_key_encode(bytes("{p256_hex}", "hex"), "p256"))
"#,
        ed = ED_PUB_HEX,
        p256_hex = {
            let mut scalar = [0u8; 32];
            scalar[31] = 7;
            hex_encode(p256::SecretKey::from_slice(&scalar).unwrap().public_key().to_encoded_point(true).as_bytes())
        }
    );
    let r = run_program(&prog, "identity_pure.syn");
    assert!(r.success, "errors: {:?}", r.errors);
    let out = r.output.join("\n");
    assert!(out.contains(r#"jcs {"a":[true,null,"é",1.5],"b":1,"n":100}"#), "{}", out);
    assert!(out.contains("did did:key:z6Mk"), "{}", out);
    assert!(out.contains(&format!("back ed25519 {} did:key:z6Mk", ED_PUB_HEX)), "{}", out);
    assert!(out.contains("methods 2"), "ed25519 + la X25519 derivada: {}", out);
    assert!(out.contains("z6LS"), "el keyAgreement X25519 derivado va con multicodec 0xec: {}", out);
    assert!(out.contains(&format!("p256 {}", p.did)), "{}", out);
}

#[test]
fn document_sign_and_verify_are_w3c_data_integrity() {
    let p = p256_fixture();
    let prog = format!(
        r##"require sign("DOC_KEY")

let k be as_secret(bytes("{seed}", "hex"), "DOC_KEY")
let did be did_key_encode(ed25519_pubkey(k))
let mb be did_key_decode(did)["multibase"]
let doc be {{"hello": "world", "n": [1, 2, 3], "nested": {{"z": true, "a": nothing}}}}
let signed be document_sign(doc, k, {{"verification_method": did + "#" + mb, "created": "2026-09-22T00:00:00Z"}})
print("proof " + signed["proof"]["type"] + " " + signed["proof"]["cryptosuite"] + " " + signed["proof"]["proofPurpose"])
print("value starts with z: " + text(starts_with(signed["proof"]["proofValue"], "z")))
let v be document_verify(signed, did)
print("verified " + text(v["verified"]) + " by " + v["verification_method"])
print("jwk " + text(document_verify(signed, {{"kty": "OKP", "crv": "Ed25519", "x": decode(ed25519_pubkey(k), "base64url")}})["verified"]))
print("wrong key " + text(document_verify(signed, "{did_p256}") == nothing))
set signed["hello"] to "tampered"
print("tampered " + text(document_verify(signed, did) == nothing))

-- P-256 por PEM (texto, sin gate) con la suite ECDSA; se verifica por PEM público y por did:key.
let pdoc be document_sign({{"amount": 10, "unit": "credits"}}, "{sec1}", {{"cryptosuite": "ecdsa-jcs-2019", "verification_method": "{did_p256}#{mb_p256}"}})
print("p256 suite " + pdoc["proof"]["cryptosuite"])
print("p256 by pem " + text(document_verify(pdoc, "{spki}")["verified"]))
print("p256 by did " + text(document_verify(pdoc, "{did_p256}")["verified"]))
print("p256 by ed did " + text(document_verify(pdoc, did) == nothing))
"##,
        seed = hex_encode(&[3u8; 32]),
        did_p256 = p.did,
        mb_p256 = &p.did[8..],
        sec1 = one_line(&p.sec1_pem),
        spki = one_line(&p.spki_pem),
    );
    let r = run_program(&prog, "identity_sign.syn");
    assert!(r.success, "errors: {:?}", r.errors);
    let out = r.output.join("\n");
    assert!(out.contains("proof DataIntegrityProof eddsa-jcs-2022 assertionMethod"), "{}", out);
    assert!(out.contains("value starts with z: true"), "{}", out);
    assert!(out.contains("verified true by did:key:z6Mk"), "{}", out);
    assert!(out.contains("jwk true"), "{}", out);
    assert!(out.contains("wrong key true"), "{}", out);
    assert!(out.contains("tampered true"), "{}", out);
    assert!(out.contains("p256 suite ecdsa-jcs-2019"), "{}", out);
    assert!(out.contains("p256 by pem true"), "{}", out);
    assert!(out.contains("p256 by did true"), "{}", out);
    assert!(out.contains("p256 by ed did true"), "{}", out);
}

#[test]
fn a_receipt_is_a_verifiable_credential_derived_from_the_audit() {
    let prog = format!(
        r##"require sign("DOC_KEY")

let k be as_secret(bytes("{seed}", "hex"), "DOC_KEY")
let did be did_key_encode(ed25519_pubkey(k))
let mb be did_key_decode(did)["multibase"]
-- una firma previa: el audit del recibo lista lo que pasó ANTES de la foto (la firma del recibo
-- mismo llega después, y no puede cubrirse a sí misma)
let earlier be document_sign({{"step": 1}}, k, nothing)
let r be receipt({{"sign": k, "verification_method": did + "#" + mb, "result": {{"answer": 42}}}})
print("json " + json_encode(r))
let v be receipt_verify(r, did)
print("receipt verified " + text(v["verified"]) + " issuer " + r["issuer"])
print("plain has proof: " + text(contains(receipt(), "proof")))
print("not a receipt: " + text(receipt_verify({{"type": ["VerifiableCredential"]}}, did) == nothing))
let issuer_opt be "accepted"
try
    receipt({{"sign": k, "issuer": "did:key:zOther"}})
recover e
    set issuer_opt to "error"
print("issuer is an option: " + issuer_opt)
let created_opt be "accepted"
try
    receipt({{"sign": k, "created": "1999-01-01T00:00:00Z"}})
recover e
    set created_opt to "error"
print("created is an option: " + created_opt)
set r["credentialSubject"]["steps"] to 1
print("tampered: " + text(receipt_verify(r, did) == nothing))
"##,
        seed = hex_encode(&[3u8; 32]),
    );
    let r = run_program(&prog, "identity_receipt.syn");
    assert!(r.success, "errors: {:?}", r.errors);
    let out = r.output.join("\n");
    let json_line = out.lines().find(|l| l.starts_with("json ")).expect("json line");
    let v: serde_json::Value = serde_json::from_str(&json_line[5..]).unwrap();
    assert_eq!(v["@context"][0], "https://www.w3.org/ns/credentials/v2");
    assert_eq!(v["type"][1], "SynsemaReceipt");
    assert!(v["issuer"].as_str().unwrap().starts_with("did:key:z6Mk"));
    let vf = v["validFrom"].as_str().expect("validFrom lo pone el reloj del motor");
    assert!(vf.starts_with("20") && vf.ends_with('Z') && vf.contains('T'), "{}", vf);
    assert_eq!(v["proof"]["created"], vf, "la prueba lleva la misma fecha derivada");
    let subj = &v["credentialSubject"];
    assert_eq!(subj["program_sha"].as_str().unwrap().len(), 64, "sha256 del programa en hex");
    assert_eq!(subj["declared_result_sha256"].as_str().unwrap().len(), 64, "declarado por el programa, y el nombre lo dice");
    assert!(subj.get("result_sha256").is_none());
    assert!(subj["engine"].as_str().unwrap().chars().any(|c| c.is_ascii_digit()), "engine version: {}", subj["engine"]);
    let caps = subj["capabilities"].as_array().unwrap();
    assert!(
        caps.iter().any(|e| e["capability"].as_str().unwrap_or("").contains("sign") && e["granted"] == true),
        "el audit del recibo lista el sign concedido antes de la foto: {}",
        subj["capabilities"]
    );
    assert_eq!(v["proof"]["cryptosuite"], "eddsa-jcs-2022");
    assert!(out.contains("receipt verified true issuer did:key:z6Mk"), "{}", out);
    assert!(out.contains("plain has proof: false"), "{}", out);
    assert!(out.contains("not a receipt: true"), "{}", out);
    assert!(out.contains("issuer is an option: error"), "{}", out);
    assert!(out.contains("created is an option: error"), "{}", out);
    assert!(out.contains("tampered: true"), "{}", out);
}

#[test]
fn the_agent_card_is_derived_signed_with_the_server_did_and_verifiable_offline() {
    std::env::set_var("SYNSEMA_IDENTITY_KEY", hex_encode(&[5u8; 32]));
    let port = free_port();
    let dir = scratch_dir("card");
    let p = p256_fixture();
    let prog = format!(
        r#"intent: "Identity e2e: a service with a signed agent card and signed receipts."
require serve({port})
require time

serve on {port}
    route "GET /hello"
        give {{"hi": "there"}}

    route "GET /receipt"
        give receipt({{"sign": "{sec1}", "cryptosuite": "ecdsa-jcs-2019", "verification_method": "{did}#{mb}"}})
"#,
        port = port,
        sec1 = one_line(&p.sec1_pem),
        did = p.did,
        mb = &p.did[8..],
    );
    thread::spawn(move || {
        let _ = run_serve_program(&prog, "identity_card_e2e.syn", false);
    });
    wait_ready(port);

    // La tarjeta: forma A2A, derivada de las rutas, sin transporte A2A declarado, firmada.
    let r = request(port, "GET", "/.well-known/agent-card.json");
    assert_eq!(status(&r), 200, "{}", r);
    let body = body_of(&r);
    let card: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{}: {}", e, body));
    assert_eq!(card["name"], "Identity e2e: a service with a signed agent card and signed receipts.");
    assert_eq!(card["supportedInterfaces"].as_array().unwrap().len(), 0);
    assert!(card.get("url").is_none() && card.get("security").is_none() && card.get("extensions").is_none(), "forma 1.0: sin campos de 0.3");
    let ids: Vec<&str> = card["skills"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec!["get_hello", "get_receipt"]);
    assert!(card.get("securitySchemes").is_none(), "sin `auth with` no se anuncia auth");
    let ext = &card["capabilities"]["extensions"][0];
    assert_eq!(ext["uri"], "https://synsema.org/ext/identity/v1");
    let did = ext["params"]["did"].as_str().unwrap();
    assert!(did.starts_with("did:key:z6Mk"), "{}", did);
    assert!(ext["params"]["openapi"].as_str().unwrap().ends_with("/openapi.json"));
    assert!(ext["params"].get("attestation").is_none());
    let sig = &card["signatures"][0];
    let protected: serde_json::Value =
        serde_json::from_slice(&synsema_core::bytesutil::b64url_decode(sig["protected"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(protected["alg"], "EdDSA");
    assert_eq!(protected["kid"], format!("{}#{}", did, &did[8..]));
    // El alias viejo sirve la misma tarjeta; llms.txt la lista; la ruta está reservada.
    assert_eq!(body_of(&request(port, "GET", "/.well-known/agent.json")), body);
    assert!(body_of(&request(port, "GET", "/llms.txt")).contains("/.well-known/agent-card.json"));

    // Verificarla OFFLINE desde Synsema: JWS sobre el JCS de la tarjeta sin `signatures`,
    // clave resuelta del did:key (sin JWKS ni red).
    std::fs::write(format!("{}/card.json", dir), &body).unwrap();
    let verify = format!(
        r#"require file.read("{d}/*")

let card be json_decode(read_file("{d}/card.json"))
let unsigned be {{}}
each k in keys(card)
    when k != "signatures"
        set unsigned[k] to card[k]
let sig be card["signatures"][0]
let payload be decode(bytes(canonical_json(unsigned)), "base64url")
let tok be sig["protected"] + "." + payload + "." + sig["signature"]
let did be card["capabilities"]["extensions"][0]["params"]["did"]
let claims be jwt_verify(tok, {{"did": did}}, {{"now": 1750000000}})
print("verified name: " + claims["name"])
let other be did_key_encode(bytes("{ed}", "hex"))
print("other key: " + text(jwt_verify(tok, {{"did": other}}, {{"now": 1750000000}}) == nothing))
set unsigned["name"] to "impostor"
let tok2 be sig["protected"] + "." + decode(bytes(canonical_json(unsigned)), "base64url") + "." + sig["signature"]
print("tampered: " + text(jwt_verify(tok2, {{"did": did}}, {{"now": 1750000000}}) == nothing))
"#,
        d = dir,
        ed = ED_PUB_HEX
    );
    let r = run_program(&verify, "verify_card.syn");
    assert!(r.success, "errors: {:?}", r.errors);
    let out = r.output.join("\n");
    assert!(out.contains("verified name: Identity e2e"), "{}", out);
    assert!(out.contains("other key: true"), "{}", out);
    assert!(out.contains("tampered: true"), "{}", out);

    // Un recibo firmado por una ruta (P-256, ecdsa-jcs-2019), verificado desde otro programa
    // con la clave pública del server (did:key), y rechazado con otra clave o alterado.
    let r = request(port, "GET", "/receipt");
    assert_eq!(status(&r), 200, "{}", r);
    let body = body_of(&r);
    let receipt: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{}: {}", e, body));
    assert_eq!(receipt["type"][1], "SynsemaReceipt");
    assert_eq!(receipt["issuer"], p.did);
    assert_eq!(receipt["proof"]["cryptosuite"], "ecdsa-jcs-2019");
    assert_eq!(receipt["credentialSubject"]["program_sha"].as_str().unwrap().len(), 64);
    std::fs::write(format!("{}/receipt.json", dir), &body).unwrap();
    let verify = format!(
        r#"require file.read("{d}/*")

let r be json_decode(read_file("{d}/receipt.json"))
let v be receipt_verify(r, "{did}")
print("receipt ok: " + text(v["verified"]) + " " + v["cryptosuite"])
print("wrong key: " + text(receipt_verify(r, did_key_encode(bytes("{ed}", "hex"))) == nothing))
-- un recibo firmado con ESTA clave pero a nombre de otro did: la firma vale, el emisor no
let impostor be document_sign({{"@context": r["@context"], "type": r["type"], "issuer": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "credentialSubject": r["credentialSubject"]}}, "{sec1}", {{"cryptosuite": "ecdsa-jcs-2019"}})
print("impostor: " + text(receipt_verify(impostor, "{did}") == nothing))
set r["credentialSubject"]["program_sha"] to "0000"
print("tampered: " + text(receipt_verify(r, "{did}") == nothing))
"#,
        d = dir,
        did = p.did,
        ed = ED_PUB_HEX,
        sec1 = one_line(&p.sec1_pem),
    );
    let r = run_program(&verify, "verify_receipt.syn");
    assert!(r.success, "errors: {:?}", r.errors);
    let out = r.output.join("\n");
    assert!(out.contains("receipt ok: true ecdsa-jcs-2019"), "{}", out);
    assert!(out.contains("wrong key: true"), "{}", out);
    assert!(out.contains("impostor: true"), "{}", out);
    assert!(out.contains("tampered: true"), "{}", out);
}

// ---- T2: WebAuthn con un authenticator P-256 emulado (bytes idénticos a los del browser) ----

fn cbor_head(major: u8, n: usize, out: &mut Vec<u8>) {
    if n < 24 {
        out.push((major << 5) | n as u8);
    } else if n < 256 {
        out.push((major << 5) | 24);
        out.push(n as u8);
    } else {
        out.push((major << 5) | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    }
}

fn cbor_int(i: i64, out: &mut Vec<u8>) {
    if i >= 0 {
        cbor_head(0, i as usize, out)
    } else {
        cbor_head(1, (-1 - i) as usize, out)
    }
}

fn cbor_bytes(b: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, b.len(), out);
    out.extend_from_slice(b);
}

fn cbor_text(s: &str, out: &mut Vec<u8>) {
    cbor_head(3, s.len(), out);
    out.extend_from_slice(s.as_bytes());
}

const RP: &str = "app.example";
const ORIGIN: &str = "https://app.example";
const CHAL: &[u8] = b"0123456789abcdef0123456789abcdef";
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

fn client_data(ty: &str, chal: &[u8]) -> Vec<u8> {
    format!(r#"{{"type":"{}","challenge":"{}","origin":"{}","crossOrigin":false}}"#, ty, b64url_encode(chal), ORIGIN).into_bytes()
}

fn cose_p256(sk: &p256::ecdsa::SigningKey) -> Vec<u8> {
    let pt = sk.verifying_key().to_encoded_point(false);
    let mut out = Vec::new();
    cbor_head(5, 5, &mut out);
    cbor_int(1, &mut out);
    cbor_int(2, &mut out);
    cbor_int(3, &mut out);
    cbor_int(-7, &mut out);
    cbor_int(-1, &mut out);
    cbor_int(1, &mut out);
    cbor_int(-2, &mut out);
    cbor_bytes(pt.x().unwrap(), &mut out);
    cbor_int(-3, &mut out);
    cbor_bytes(pt.y().unwrap(), &mut out);
    out
}

fn auth_data(flags: u8, count: u32, cred: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut b = Sha256::digest(RP.as_bytes()).to_vec();
    b.push(flags);
    b.extend_from_slice(&count.to_be_bytes());
    if let Some((id, cose)) = cred {
        b.extend_from_slice(&[0u8; 16]);
        b.extend_from_slice(&(id.len() as u16).to_be_bytes());
        b.extend_from_slice(id);
        b.extend_from_slice(cose);
    }
    b
}

fn attestation_object(auth: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_head(5, 3, &mut out);
    cbor_text("fmt", &mut out);
    cbor_text("none", &mut out);
    cbor_text("attStmt", &mut out);
    cbor_head(5, 0, &mut out);
    cbor_text("authData", &mut out);
    cbor_bytes(auth, &mut out);
    out
}

#[test]
fn webauthn_register_then_verify_from_a_program() {
    use p256::ecdsa::signature::Signer;
    let dir = scratch_dir("webauthn");
    let mut scalar = [0u8; 32];
    scalar[31] = 11;
    let sk = p256::ecdsa::SigningKey::from(p256::SecretKey::from_slice(&scalar).unwrap());
    let cred_id = b"credential-e2e";
    let cose = cose_p256(&sk);
    let reg_auth = auth_data(FLAG_UP | FLAG_UV | FLAG_AT, 0, Some((cred_id, &cose)));
    let registration = serde_json::json!({
        "id": b64url_encode(cred_id),
        "rawId": b64url_encode(cred_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64url_encode(&client_data("webauthn.create", CHAL)),
            "attestationObject": b64url_encode(&attestation_object(&reg_auth)),
        }
    });
    let asr_auth = auth_data(FLAG_UP | FLAG_UV, 7, None);
    let cdj = client_data("webauthn.get", CHAL);
    let mut msg = asr_auth.clone();
    msg.extend_from_slice(&Sha256::digest(&cdj));
    let sig: p256::ecdsa::Signature = sk.sign(&msg);
    let assertion = serde_json::json!({
        "id": b64url_encode(cred_id),
        "rawId": b64url_encode(cred_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64url_encode(&cdj),
            "authenticatorData": b64url_encode(&asr_auth),
            "signature": b64url_encode(sig.to_der().as_bytes()),
            "userHandle": b64url_encode(b"user-42"),
        }
    });
    std::fs::write(format!("{}/reg.json", dir), registration.to_string()).unwrap();
    std::fs::write(format!("{}/asr.json", dir), assertion.to_string()).unwrap();

    let prog = format!(
        r#"require file.read("{d}/*")

let opts be {{"rp_id": "{rp}", "origin": "{origin}", "challenge": "{chal}"}}
let reg be webauthn_register(json_decode(read_file("{d}/reg.json")), opts)
print("registered " + reg["alg"] + " " + reg["public_key"]["kty"] + " fmt " + reg["fmt"] + " uv " + text(reg["user_verified"]))
let asr be json_decode(read_file("{d}/asr.json"))
set reg["user_handle"] to "user-42"
let v be webauthn_verify(asr, reg, {{"rp_id": "{rp}", "origin": "{origin}", "challenge": "{chal}", "sign_count": 3}})
print("count " + text(v["sign_count"]) + " handle " + v["user_handle"] + " alg " + v["alg"] + " id ok " + text(v["id"] == reg["id"]))
print("wrong challenge: " + text(webauthn_verify(asr, reg, {{"rp_id": "{rp}", "origin": "{origin}", "challenge": "{other}"}}) == nothing))
print("wrong origin: " + text(webauthn_verify(asr, reg, {{"rp_id": "{rp}", "origin": "https://evil.example", "challenge": "{chal}"}}) == nothing))
print("replayed counter: " + text(webauthn_verify(asr, reg, {{"rp_id": "{rp}", "origin": "{origin}", "challenge": "{chal}", "sign_count": 7}}) == nothing))
-- la clave sola no alcanza: el id de la credencial ata la clave (error con el arreglo)
let key_alone be "accepted"
try
    webauthn_verify(asr, reg["public_key"], {{"rp_id": "{rp}", "origin": "{origin}", "challenge": "{chal}"}})
recover e
    set key_alone to "error"
print("key alone: " + key_alone)
-- otra credencial (otro id) con esta misma clave: nothing
set reg["id"] to "b3RoZXItY3JlZA"
print("other id: " + text(webauthn_verify(asr, reg, {{"rp_id": "{rp}", "origin": "{origin}", "challenge": "{chal}"}}) == nothing))
"#,
        d = dir,
        rp = RP,
        origin = ORIGIN,
        chal = b64url_encode(CHAL),
        other = b64url_encode(b"ffffffffffffffffffffffffffffffff"),
    );
    let r = run_program(&prog, "webauthn_e2e.syn");
    assert!(r.success, "errors: {:?}", r.errors);
    let out = r.output.join("\n");
    assert!(out.contains("registered ES256 EC fmt none uv true"), "{}", out);
    assert!(out.contains("count 7 handle user-42 alg ES256 id ok true"), "{}", out);
    assert!(out.contains("key alone: error"), "{}", out);
    assert!(out.contains("other id: true"), "{}", out);
    assert!(out.contains("wrong challenge: true"), "{}", out);
    assert!(out.contains("wrong origin: true"), "{}", out);
    assert!(out.contains("replayed counter: true"), "{}", out);
}

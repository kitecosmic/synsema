//! `serve --attested` de punta a punta con el driver `mock` (`SYNSEMA_ATTEST=mock`):
//! el servidor genera su par P-256, obtiene un documento que ata `sha256(spki ‖ program_sha)`,
//! sirve HTTPS con un cert autofirmado emitido con ESA clave y publica
//! `GET /.well-known/attestation`. El cliente hace exactamente lo que haría uno real:
//!
//! 1. Handshake TLS aceptando el cert pero CAPTURÁNDOLO (todavía no confía).
//! 2. Lee el JSON, verifica la firma COSE y la cadena del documento contra la raíz del mock,
//!    recomputa `report_data = sha256(spki ‖ program_sha)` y la compara con `user_data`.
//! 3. Pinea el SPKI del cert que vio en el handshake al `public_key_hex` anunciado: si
//!    coinciden, el canal TLS es el del código atestado. Un pin distinto rompe el handshake.
//!
//! Además: `attestation_document()` desde una ruta devuelve el mismo JSON, `attestation_key()`
//! es un `secret` compatible con `ecdh_shared_secret` (mismo escalar que el SPKI anunciado), y
//! sin plataforma (`SYNSEMA_ATTEST=nitro` fuera de un enclave) el servidor NO arranca.
//!
//! De la auditoría externa: `report_data` ata `config_sha` (el JSON publica `config`),
//! (`reveal(attestation_key())` se rechaza aun con la capability), M9 (`tls_key`), M10 (la
//! barra final no sombrea la ruta reservada; declararla es error de carga), L6 (`mock: true`).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use synsema_runtime::serve::{run_serve_program_with_overrides, ServeOverrides};
use synsema_stdlib::attest::{der, mock, parse_http_response, program_sha, sha256, verify_nitro_document_with_root, AttestConfig};
use synsema_stdlib::cbor::{Cbor, CoseSign1, COSE_ALG_ES384};

/// Serializa los tests que tocan `SYNSEMA_ATTEST` (env del proceso).
static ENV_LOCK: Mutex<()> = Mutex::new(());
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

const PROG: &str = r#"require serve(8080)
require attest

let vault be {"balance": private(500, "app"), "name": "alice"}

serve on 8080
    route "GET /ping"
        give {"ok": true}
    route "GET /identity"
        give attestation_document()
    route "GET /global-raw"
        give {"balance": vault["balance"]}
    route "GET /global-checked"
        let b be vault["balance"]
        give {"priv": declassify(is_private(b), "probe"), "labels": text(declassify(label_of(b), "probe")), "is500": declassify(b == 500, "probe")}
"#;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

/// UN serve atestado por proceso (la identidad se instala una sola vez): los tests lo
/// comparten.
static SERVER: OnceLock<u16> = OnceLock::new();

fn attested_server() -> u16 {
    *SERVER.get_or_init(|| {
        let _g = env_lock();
        std::env::set_var("SYNSEMA_ATTEST", "mock");
        std::env::remove_var("SYNSEMA_ATTEST_MOCK_SEED");
        std::env::remove_var("SYNSEMA_ATTEST_MOCK_PCRS");
        std::env::remove_var("SYNSEMA_ATTEST_MOCK_TIMESTAMP");
        let port = free_port();
        let ov = ServeOverrides { port: Some(port), bind: Some("127.0.0.1".to_string()), attested: true, ..Default::default() };
        thread::spawn(move || {
            let r = run_serve_program_with_overrides(PROG, "attested.syn", false, ov);
            eprintln!("[attested serve exited] {:?}", r.errors);
        });
        for _ in 0..200 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                thread::sleep(Duration::from_millis(200));
                return port;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("el serve atestado no quedó listo en 127.0.0.1:{}", port);
    })
}

/// Verificador que ACEPTA cualquier cert pero lo captura (paso 1 del cliente) o, con un
/// `pin`, exige que el SPKI del cert de entidad final sea exactamente ése (paso 3).
#[derive(Debug)]
struct SpkiVerifier {
    pin: Option<Vec<u8>>,
    seen: Mutex<Option<Vec<u8>>>,
}

impl ServerCertVerifier for SpkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().unwrap() = Some(end_entity.to_vec());
        if let Some(pin) = &self.pin {
            let spki = spki_of_cert(end_entity).map_err(rustls::Error::General)?;
            if &spki != pin {
                return Err(rustls::Error::General("SPKI pin mismatch: this is not the attested key".to_string()));
            }
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// SubjectPublicKeyInfo (DER) de un certificado X.509: el 7.º elemento del TBSCertificate
/// (version [0], serial, signature, issuer, validity, subject, SPKI).
fn spki_of_cert(cert: &[u8]) -> Result<Vec<u8>, String> {
    let (_, cert_body, _) = der::read_tlv(cert)?;
    let (tag, tbs, _) = der::read_tlv(cert_body)?;
    if tag != 0x30 {
        return Err("TBSCertificate is not a SEQUENCE".to_string());
    }
    let mut rest = tbs;
    let mut spki = None;
    for i in 0..7 {
        let (t, body, after) = der::read_tlv(rest)?;
        if i == 6 {
            // Re-armar el TLV completo del SPKI.
            let full_len = rest.len() - after.len();
            spki = Some(rest[..full_len].to_vec());
            let _ = (t, body);
        }
        rest = after;
    }
    spki.ok_or_else(|| "certificate has no SPKI".to_string())
}

/// `GET path` por TLS con el verificador dado → (status, body, cert DER visto).
fn https_get(port: u16, path: &str, pin: Option<Vec<u8>>) -> Result<(u16, String, Vec<u8>), String> {
    let verifier = Arc::new(SpkiVerifier { pin, seen: Mutex::new(None) });
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), ServerName::try_from("localhost").unwrap()).map_err(|e| e.to_string())?;
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    let req = format!("GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path);
    tls.write_all(req.as_bytes()).map_err(|e| format!("write (handshake?): {}", e))?;
    let mut raw = Vec::new();
    // Un servidor que cierra sin close_notify da UnexpectedEof: si ya hay bytes, es la respuesta.
    if let Err(e) = tls.read_to_end(&mut raw) {
        if raw.is_empty() {
            return Err(format!("read: {}", e));
        }
    }
    let (status, body) = parse_http_response(&raw)?;
    let seen = verifier.seen.lock().unwrap().clone().ok_or("no certificate seen")?;
    Ok((status, body, seen))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn well_known_attestation_binds_the_tls_key_to_the_program() {
    let port = attested_server();

    // Paso 1: leer la identidad aceptando el cert sin confiar todavía (se captura).
    let (status, body, cert_seen) = https_get(port, "/.well-known/attestation", None).expect("GET /.well-known/attestation");
    assert_eq!(status, 200, "{}", body);
    let j: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    // Auditoría externa: el driver de desarrollo NO se anuncia como un formato de plataforma.
    assert_eq!(j["format"], "mock");
    assert_eq!(j["driver"], "mock");
    assert!(!j["engine"].as_str().unwrap().is_empty());
    let spki_hex = j["public_key_hex"].as_str().unwrap();
    let spki = unhex(spki_hex);
    assert!(j["public_key"].as_str().unwrap().starts_with("-----BEGIN PUBLIC KEY-----"));
    let psha = j["program_sha"].as_str().unwrap();
    assert_eq!(psha, hex(&program_sha(PROG, "attested.syn").unwrap()), "program_sha = el del fuente servido");

    // M9/L6: el JSON dice con qué clave va el TLS y que el documento es del mock.
    assert_eq!(j["tls_key"], "attested");
    assert_eq!(j["mock"], true);
    // M7: la configuración publicada recomputa a config_sha (JSON canónico, claves ordenadas).
    let cfg = &j["config"];
    assert_eq!(cfg["tls_key"], "attested");
    assert_eq!(cfg["ceiling"], "unbounded");
    assert_eq!(cfg["profile"], "native");
    assert_eq!(cfg["engine"], j["engine"]);
    let expected_cfg = AttestConfig {
        labels: cfg["labels"].as_bool().unwrap(),
        ceiling: None,
        tls_key: "attested",
        profile: "native",
    };
    assert_eq!(j["config_sha"], hex(&expected_cfg.sha()), "config_sha = sha256(json canónico del config publicado)");

    // Paso 2: el documento verifica (COSE ES384 + cadena) contra la raíz del mock, y su
    // user_data es EXACTAMENTE sha256(spki ‖ program_sha ‖ config_sha).
    let doc = synsema_core::bytesutil::b64_decode(j["document"].as_str().unwrap()).unwrap();
    let cose = CoseSign1::parse(&doc).expect("COSE_Sign1");
    assert_eq!(cose.alg().unwrap(), COSE_ALG_ES384);
    let payload = verify_nitro_document_with_root(&doc, &mock::root_der()).expect("documento válido contra la raíz mock");
    let mut bound = spki.clone();
    bound.extend_from_slice(&unhex(psha));
    bound.extend_from_slice(&unhex(j["config_sha"].as_str().unwrap()));
    let want = sha256(&bound);
    assert_eq!(payload.get("user_data").unwrap().as_bytes().unwrap(), &want, "user_data = sha256(spki ‖ program_sha ‖ config_sha)");
    assert!(payload.get("nonce").unwrap().is_null());
    assert_eq!(payload.get("digest").unwrap(), &Cbor::text("SHA384"));

    // Paso 3: el cert del handshake lleva ESE SPKI (el canal TLS es el del código atestado)…
    assert_eq!(spki_of_cert(&cert_seen).unwrap(), spki, "el cert TLS usa la clave atestada");
    // …así que un cliente pinea y habla: /ping y /identity por TLS pineado.
    let (st, body, _) = https_get(port, "/ping", Some(spki.clone())).expect("GET /ping pineado");
    assert_eq!(st, 200);
    assert!(body.contains("\"ok\""), "{}", body);
    let (st, body, _) = https_get(port, "/identity", Some(spki.clone())).expect("GET /identity pineado");
    assert_eq!(st, 200);
    let j2: serde_json::Value = serde_json::from_str(&body).expect("JSON de attestation_document()");
    assert_eq!(j2["document"], j["document"], "attestation_document() devuelve el mismo documento");
    assert_eq!(j2["public_key_hex"], j["public_key_hex"]);
    assert_eq!(j2["program_sha"], j["program_sha"]);
    assert_eq!(j2["config_sha"], j["config_sha"]);
    // M10: la barra final (y las barras repetidas) llegan a la MISMA ruta reservada, nunca a
    // una ruta del programa. Antes del fix `/.well-known/attestation/` caía en el router.
    for variant in ["/.well-known/attestation/", "//.well-known//attestation/"] {
        let (st, body, _) = https_get(port, variant, Some(spki.clone())).expect(variant);
        assert_eq!(st, 200, "{}: {}", variant, body);
        let jv: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(jv["document"], j["document"], "{} es la ruta reservada", variant);
    }
    // Un pin ajeno rompe el handshake: no se habla con una clave que no sea la atestada.
    let mut other = spki.clone();
    let last = other.len() - 1;
    other[last] ^= 0x01;
    let r = https_get(port, "/ping", Some(other));
    assert!(r.is_err(), "pin distinto → handshake rechazado, got {:?}", r.map(|(s, b, _)| (s, b)));
}

#[test]
fn attestation_key_is_the_announced_p256_key_and_a_secret() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let _port = attested_server();
    let id = synsema_stdlib::attest::attested_identity().expect("identidad instalada");
    // El escalar que `attestation_key()` devuelve es el de la clave anunciada: ECDH desde
    // ambos lados coincide (es lo que hace `ecdh_shared_secret(private, peer, "P-256")`).
    let server_sk = p256::SecretKey::from_slice(&id.private_scalar).unwrap();
    let server_pub_from_spki = {
        let (_, spki_body, _) = der::read_tlv(&id.spki_der).unwrap();
        let (_, _alg, rest) = der::read_tlv(spki_body).unwrap();
        let (tag, bits, _) = der::read_tlv(rest).unwrap();
        assert_eq!(tag, 0x03);
        p256::PublicKey::from_sec1_bytes(&bits[1..]).unwrap()
    };
    assert_eq!(server_sk.public_key().to_encoded_point(false), server_pub_from_spki.to_encoded_point(false));
    let client_sk = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
    let a = p256::ecdh::diffie_hellman(server_sk.to_nonzero_scalar(), client_sk.public_key().as_affine());
    let b = p256::ecdh::diffie_hellman(client_sk.to_nonzero_scalar(), server_pub_from_spki.as_affine());
    assert_eq!(a.raw_secret_bytes(), b.raw_secret_bytes());

    // Desde el lenguaje: `attestation_key()` es un secret (se redacta) y entra en
    // ecdh_shared_secret sin conversión; sin `require attest` se niega.
    let ok = synsema_runtime::engine::run_source(
        "require attest\nrequire random\nlet k be attestation_key()\nprint(k)\nlet peer be ecdh_keypair(\"P-256\")\nlet s be ecdh_shared_secret(k, peer.public, \"P-256\")\nprint(s)\n",
        "key.syn",
    );
    assert!(ok.success, "{:?}", ok.errors);
    let out = ok.output.join("\n");
    assert!(out.contains("secret(attestation_key)"), "se redacta: {}", out);
    assert!(out.contains("secret(ecdh_shared_secret)"), "el ECDH acepta el escalar: {}", out);
    let denied = synsema_runtime::engine::run_source("let k be attestation_key()\n", "denied.syn");
    assert!(!denied.success);
    assert!(denied.errors.join(" ").contains("attest"), "{:?}", denied.errors);
    // M8: ni con `require reveal("attestation_key")` se materializa el escalar — el secret
    // está SELLADO (antes del fix devolvía los 32 bytes con audit `granted`).
    let revealed = synsema_runtime::engine::run_source(
        "require attest\nrequire reveal(\"attestation_key\")\nlet k be attestation_key()\nprint(reveal(k))\n",
        "reveal.syn",
    );
    assert!(!revealed.success, "reveal de la clave sellada debe fallar: {:?}", revealed.output);
    let msg = revealed.errors.join(" ");
    assert!(msg.contains("sealed") && msg.contains("attestation_key"), "{}", msg);
    assert!(!revealed.output.iter().any(|l| l.len() > 60), "ningún escalar en la salida: {:?}", revealed.output);
    // Un secret común sigue revelándose con su capability (el sello es sólo de la identidad).
    let normal = synsema_runtime::engine::run_source(
        "require reveal(\"tag\")\nlet s be as_secret(\"hola\", \"tag\")\nprint(reveal(s))\n",
        "reveal_ok.syn",
    );
    assert!(normal.success, "{:?}", normal.errors);
    assert_eq!(normal.output, vec!["hola".to_string()]);
    // El documento también desde `run` (misma identidad del proceso).
    let doc = synsema_runtime::engine::run_source("let d be attestation_document()\nprint(d.driver)\nprint(d.format)\n", "doc.syn");
    assert!(doc.success, "{:?}", doc.errors);
    assert_eq!(doc.output, vec!["mock".to_string(), "mock".to_string()]);
}

/// Auditoría externa: un privado guardado en un GLOBAL cruzaba el snapshot de
/// `serve` (`to_send`) degradado al TEXTO `private(app)`: la etiqueta desaparecía sin aviso
/// (fail-open) y el valor quedaba corrupto (`b == 500` daba false, `type_of` daba "text").
/// Con la variante `SendValue::Private` la etiqueta VIAJA: la respuesta cruda falla cerrado y el
/// valor sigue siendo el número real del otro lado.
#[test]
fn a_private_value_in_a_global_keeps_its_label_across_the_serve_snapshot() {
    let port = attested_server();
    let spki = {
        let (_, body, _) = https_get(port, "/.well-known/attestation", None).unwrap();
        let j: serde_json::Value = serde_json::from_str(&body).unwrap();
        unhex(j["public_key_hex"].as_str().unwrap())
    };
    // Devolver el privado tal cual: sumidero de la respuesta → label_violation, no un placeholder.
    let (st, body, _) = https_get(port, "/global-raw", Some(spki.clone())).expect("GET /global-raw");
    assert_eq!(st, 500, "{}", body);
    assert!(body.contains("label_violation") && body.contains("private to app"), "{}", body);
    // El valor (500) no aparece en el MENSAJE (el `"status": 500` del envelope es otra cosa).
    let err: serde_json::Value = serde_json::from_str(&body).expect("JSON de error");
    assert!(!err["error"].as_str().unwrap().contains("500"), "el valor no sale en el error: {}", body);
    // Y la etiqueta y el VALOR sobrevivieron al snapshot (antes: priv=false, labels=[], is500=false).
    let (st, body, _) = https_get(port, "/global-checked", Some(spki)).expect("GET /global-checked");
    assert_eq!(st, 200, "{}", body);
    let j: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(j["priv"], true, "la etiqueta viaja: {}", body);
    assert_eq!(j["labels"], "[app]", "{}", body);
    assert_eq!(j["is500"], true, "el valor NO se corrompe (antes era el texto `private(app)`)");
}

#[test]
fn attested_serve_rejects_a_program_route_on_a_reserved_path() {
    // M10: declarar `GET /.well-known/attestation` (o cualquier reservado) bajo --attested es
    // error de CARGA. Antes del fix la ruta se registraba y respondía `{"format": "fake"}` con
    // barra final.
    let _ = attested_server();
    let _g = env_lock();
    std::env::set_var("SYNSEMA_ATTEST", "mock");
    for reserved in ["/.well-known/attestation", "/.well-known/attestation/", "/openapi.json"] {
        let prog = format!(
            "require serve(8080)\nserve on 8080\n    route \"GET {}\"\n        give {{\"format\": \"fake\", \"document\": \"FAKE\"}}\n",
            reserved
        );
        let port = free_port();
        let ov = ServeOverrides { port: Some(port), bind: Some("127.0.0.1".to_string()), attested: true, ..Default::default() };
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let r = run_serve_program_with_overrides(&prog, "shadow.syn", false, ov);
            let _ = tx.send((r.success, r.errors.join(" | ")));
        });
        let (success, errors) = rx.recv_timeout(Duration::from_secs(30)).expect("el serve retorna");
        assert!(!success, "{}: debe rechazarse", reserved);
        assert!(errors.contains("reserved path") && errors.contains(reserved.trim_end_matches('/')), "{}: {}", reserved, errors);
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err(), "no bindeó");
    }
}

#[test]
fn attested_serve_refuses_to_start_without_a_platform() {
    // El serve compartido ya arrancó con `mock`; acá se fuerza un driver real fuera de su
    // hardware (`nitro` sin /dev/nsm — en Windows/macOS además es Linux-only) y el servidor
    // debe NO arrancar, con el error de la plataforma, nunca un serve "atestado" sin documento.
    let _ = attested_server();
    let _g = env_lock();
    std::env::set_var("SYNSEMA_ATTEST", "nitro");
    let port = free_port();
    let ov = ServeOverrides { port: Some(port), bind: Some("127.0.0.1".to_string()), attested: true, ..Default::default() };
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let r = run_serve_program_with_overrides(PROG, "no_platform.syn", false, ov);
        let _ = tx.send((r.success, r.errors.join(" | ")));
    });
    let (success, errors) = rx.recv_timeout(Duration::from_secs(30)).expect("el serve retorna en vez de bindear");
    std::env::set_var("SYNSEMA_ATTEST", "mock");
    assert!(!success, "no debe arrancar: {}", errors);
    assert!(errors.contains("serve --attested") && errors.contains("attest"), "{}", errors);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err(), "no bindeó el puerto");
}

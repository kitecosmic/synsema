//! T5 — mTLS del lado CLIENTE: `mtls_identity(cert, key)` declara la identidad de
//! workload de ESTE proceso; a partir de ahí todo `https://` la presenta en el
//! handshake.
//!
//! Qué cubre este e2e: el GATE (`file.read` sobre ambos PEM), el manejo de PEM
//! inválidos (error claro, sin ecoar el contenido de la clave) y la aceptación de
//! un par cert/key legítimo. El apretón de manos mTLS completo contra un servidor
//! que exige cert de cliente vive en `synsema-stdlib/tests/mtls_handshake.rs`,
//! donde se puede construir el trust store del cliente; acá no, porque el cliente
//! HTTP del engine usa los root CAs del SISTEMA a propósito y un test no debe
//! tocarlos.

use synsema_runtime::engine::run_source;

fn make_client_pair() -> (String, String) {
    use rcgen::{CertificateParams, DnType, KeyPair};
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, "agent-7");
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn write_pems(tag: &str, cert_pem: &str, key_pem: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("syn_mtls_{}", tag));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("client.pem");
    let key_path = dir.join("client.key");
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();
    (cert_path, key_path)
}

fn syn_path(p: &std::path::Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

#[test]
fn mtls_identity_accepts_a_valid_pair() {
    let (cert_pem, key_pem) = make_client_pair();
    let (cert, key) = write_pems("ok", &cert_pem, &key_pem);
    let dir = cert.parent().unwrap().to_path_buf();
    let prog = format!(
        "require file.read(\"{d}/*\")\nlet ok be mtls_identity(\"{c}\", \"{k}\")\nprint(ok)\n",
        d = syn_path(&dir),
        c = syn_path(&cert),
        k = syn_path(&key)
    );
    let res = run_source(&prog, "mtls_ok.syn");
    assert!(res.success, "par válido con capability: {:?}", res.errors);
    assert!(
        res.output.join("").contains("true"),
        "devuelve true: {:?}",
        res.output
    );
}


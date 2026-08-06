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
fn mtls_identity_requires_file_read_capability() {
    let (cert_pem, key_pem) = make_client_pair();
    let (cert, key) = write_pems("gate", &cert_pem, &key_pem);
    // Sin `require file.read(...)` de los PEM → denegado, con el fix en el mensaje.
    let prog = format!(
        "let ok be mtls_identity(\"{}\", \"{}\")\nprint(ok)\n",
        syn_path(&cert),
        syn_path(&key)
    );
    let res = run_source(&prog, "mtls_gate.syn");
    assert!(!res.success, "sin file.read debe denegarse");
    let errs = res.errors.join("\n");
    assert!(
        errs.contains("file") && errs.contains("read"),
        "el error nombra la capability: {}",
        errs
    );
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

#[test]
fn mtls_identity_reports_bad_pem_clearly() {
    let dir = std::env::temp_dir().join("syn_mtls_bad");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("no-es-pem.txt");
    std::fs::write(&bad, b"esto no es un PEM secreto").unwrap();
    let prog = format!(
        "require file.read(\"{d}/*\")\nlet ok be mtls_identity(\"{p}\", \"{p}\")\n",
        d = syn_path(&dir),
        p = syn_path(&bad)
    );
    let res = run_source(&prog, "mtls_bad.syn");
    assert!(!res.success, "un PEM inválido debe fallar");
    let errs = res.errors.join("\n");
    assert!(
        errs.contains("certificate") || errs.contains("PEM"),
        "el error describe el problema: {}",
        errs
    );
    // Y el contenido del archivo NUNCA aparece en el mensaje (podría ser la clave).
    assert!(
        !errs.contains("esto no es un PEM secreto"),
        "el error no ecoa el archivo: {}",
        errs
    );
}

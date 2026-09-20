//! `synsema run --attest` con el binario real y el driver `mock`: corre bajo
//! `--deterministic`, imprime la salida del programa y cierra con UNA línea JSON
//! `{output_sha, steps, state_root, program_sha, input_sha, attestation}` cuyo documento ata
//! `sha256(program_sha ‖ input_sha ‖ output_sha)`. Sin plataforma → exit ≠ 0. También los
//! rechazos de flags (`--attest --sandbox`, `serve --attested --watch`).

use std::path::PathBuf;
use std::process::{Command, Stdio};

use synsema_stdlib::attest::{keccak256, mock, program_sha, sha256, verify_nitro_document_with_root, AttestConfig};

fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-attest-cli-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn synsema(dir: &PathBuf, args: &[&str], env: &[(&str, Option<&str>)]) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_synsema"));
    c.args(args).current_dir(dir).env("SYNSEMA_NO_UPDATE_CHECK", "1").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Aislar del entorno de quien corre los tests.
    for k in ["SYNSEMA_ATTEST", "SYNSEMA_ATTEST_MOCK_SEED", "SYNSEMA_ATTEST_MOCK_PCRS", "SYNSEMA_ATTEST_MOCK_TIMESTAMP"] {
        c.env_remove(k);
    }
    for (k, v) in env {
        match v {
            Some(v) => c.env(k, v),
            None => c.env_remove(k),
        };
    }
    let out = c.output().expect("spawn synsema");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

const SRC: &str = "print(1 + 1)\nprint(\"hola \" + args()[0])\n";

#[test]
fn run_attest_prints_output_then_one_json_line_bound_to_program_input_output() {
    let dir = project("ok");
    std::fs::write(dir.join("p.syn"), SRC).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--attest", "p.syn", "--", "mundo"], &[("SYNSEMA_ATTEST", Some("mock"))]);
    assert_eq!(code, 0, "stdout:\n{}\nstderr:\n{}", out, err);
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines.len() >= 3, "{:?}", lines);
    assert_eq!(lines[0], "2");
    assert_eq!(lines[1], "hola mundo");
    let j: serde_json::Value = serde_json::from_str(lines[lines.len() - 1]).expect("la última línea es JSON");
    let joined = "2\nhola mundo";
    assert_eq!(j["output_sha"], hex(&sha256(joined.as_bytes())));
    assert_eq!(j["state_root"], hex(&keccak256(joined.as_bytes())));
    assert_eq!(j["program_sha"], hex(&program_sha(SRC, "p.syn").unwrap()));
    assert_eq!(j["input_sha"], hex(&sha256(b"mundo")));
    assert!(j["steps"].as_u64().unwrap() > 0);
    assert_eq!(j["attestation"]["format"], "mock", "L6: el mock no se anuncia como nitro");
    assert_eq!(j["attestation"]["driver"], "mock");
    assert_eq!(j["attestation"]["mock"], true, "L6");
    assert!(err.contains("FORGEABLE"), "L6: aviso ruidoso en stderr: {}", err);
    // M7: el config publicado es el determinista de `run --attest` y recomputa a config_sha.
    assert_eq!(j["config"]["labels"], false);
    assert_eq!(j["config"]["ceiling"], serde_json::json!(["stdout"]));
    assert_eq!(j["config"]["tls_key"], "none");
    assert_eq!(j["config"]["profile"], "pure");
    let cfg = AttestConfig { labels: false, ceiling: Some(synsema_capabilities::model::build_ceiling_deterministic()), tls_key: "none", profile: "pure" };
    assert_eq!(j["config_sha"], hex(&cfg.sha()));
    // El documento verifica contra la raíz mock (la misma semilla por defecto) y ata
    // sha256(program_sha ‖ input_sha ‖ output_sha ‖ config_sha).
    let doc = synsema_core::bytesutil::b64_decode(j["attestation"]["document"].as_str().unwrap()).unwrap();
    let root = synsema_core::bytesutil::b64_decode(j["attestation"]["root"].as_str().unwrap()).unwrap();
    assert_eq!(root, mock::root_der());
    let payload = verify_nitro_document_with_root(&doc, &root).expect("documento válido");
    let mut bound = Vec::new();
    bound.extend_from_slice(&program_sha(SRC, "p.syn").unwrap());
    bound.extend_from_slice(&sha256(b"mundo"));
    bound.extend_from_slice(&sha256(joined.as_bytes()));
    bound.extend_from_slice(&cfg.sha());
    assert_eq!(payload.get("user_data").unwrap().as_bytes().unwrap(), &sha256(&bound));
    // M7: con --labels la configuración (y por lo tanto el documento) cambia; la salida no.
    let (code, out_l, _) = synsema(&dir, &["run", "--attest", "--labels", "p.syn", "--", "mundo"], &[("SYNSEMA_ATTEST", Some("mock"))]);
    assert_eq!(code, 0);
    let jl: serde_json::Value = serde_json::from_str(out_l.lines().last().unwrap()).unwrap();
    assert_eq!(jl["output_sha"], j["output_sha"]);
    assert_eq!(jl["config"]["labels"], true);
    assert_ne!(jl["config_sha"], j["config_sha"]);
    assert_ne!(jl["attestation"]["document"], j["attestation"]["document"], "el documento ata el modo");

    // Determinista: la misma corrida da el mismo JSON (mock + --deterministic).
    let (_, out2, _) = synsema(&dir, &["run", "--attest", "p.syn", "--", "mundo"], &[("SYNSEMA_ATTEST", Some("mock"))]);
    assert_eq!(out, out2);
    // Otra entrada → otro input_sha y otro documento.
    let (_, out3, _) = synsema(&dir, &["run", "--attest", "p.syn", "--", "otro"], &[("SYNSEMA_ATTEST", Some("mock"))]);
    let j3: serde_json::Value = serde_json::from_str(out3.lines().last().unwrap()).unwrap();
    assert_ne!(j3["input_sha"], j["input_sha"]);
    assert_ne!(j3["attestation"]["document"], j["attestation"]["document"]);
}

#[test]
fn run_attest_format_json_embeds_the_attestation_in_the_report() {
    let dir = project("json");
    std::fs::write(dir.join("p.syn"), "print(40 + 2)\n").unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--attest", "--format", "json", "p.syn"], &[("SYNSEMA_ATTEST", Some("mock"))]);
    assert_eq!(code, 0, "{}\n{}", out, err);
    let j: serde_json::Value = serde_json::from_str(out.trim()).expect("un único JSON en stdout");
    assert_eq!(j["ok"], true);
    assert_eq!(j["output"], serde_json::json!(["42"]));
    assert_eq!(j["output_sha"], hex(&sha256(b"42")));
    assert_eq!(j["attestation"]["format"], "mock");
    assert!(j["steps"].as_u64().unwrap() > 0);
}

#[test]
fn run_attest_forces_deterministic_and_fails_closed_without_a_platform() {
    let dir = project("closed");
    // now() necesita `time`, que el techo determinista no da: --attest lo niega solo.
    std::fs::write(dir.join("t.syn"), "require time\nprint(now())\n").unwrap();
    let (code, _out, err) = synsema(&dir, &["run", "--attest", "t.syn"], &[("SYNSEMA_ATTEST", Some("mock"))]);
    assert_ne!(code, 0, "bajo --attest el reloj está negado");
    assert!(err.contains("time"), "{}", err);
    // Sin plataforma: `nitro` fuera de un enclave (Linux-only y sin /dev/nsm) → exit ≠ 0 con el
    // error de attest, NADA de JSON "atestado" y (L20) el programa NI SE EJECUTA: la salida
    // está vacía (antes del fix imprimía `1` y recién después fallaba).
    std::fs::write(dir.join("p.syn"), "print(1)\n").unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--attest", "p.syn"], &[("SYNSEMA_ATTEST", Some("nitro"))]);
    assert_ne!(code, 0);
    assert!(err.contains("run --attest") && err.contains("attest"), "{}", err);
    assert!(!out.contains("output_sha"), "{}", out);
    assert!(out.trim().is_empty(), "L20: el driver se valida antes de correr; stdout = {:?}", out);
    // Sin `SYNSEMA_ATTEST`, la autodetección decide, y lo que se exige es la PROPIEDAD, no un
    // texto: o sale un documento (un TEE de verdad), o falla cerrado sin publicar nada.
    //
    // El texto no sirve porque depende de la máquina, y eso rompió el primer CI: el runner de
    // GitHub tiene configfs-tsm MONTADO pero no escribible, así que la autodetección elige el
    // driver `tsm` y muere con "Permission denied" en vez del "no attestation platform detected"
    // que esperaba una máquina sin el dispositivo. Los dos son el mismo veredicto.
    //
    // Tampoco se exige stdout vacío acá, y la diferencia con L20 (arriba) es real: con
    // `SYNSEMA_ATTEST` explícito el driver se valida ANTES de correr, así que un nombre que esta
    // máquina no puede servir corta de entrada; con autodetección el driver elegido SÍ existe y
    // recién falla al pedirle el documento, con el programa ya corrido y su salida impresa — que
    // es lo mismo que pasa en el camino feliz (primero la salida, después la línea JSON). Lo que
    // no puede pasar en ninguno de los dos es que salga un artefacto atestado.
    let (code, out, err) = synsema(&dir, &["run", "--attest", "p.syn"], &[("SYNSEMA_ATTEST", None), ("DSTACK_SIMULATOR_ENDPOINT", None)]);
    if code != 0 {
        assert!(err.contains("attest"), "el error nombra la capability: {}", err);
        for marca in ["output_sha", "attestation", "program_sha", "state_root"] {
            assert!(!out.contains(marca), "al fallar no sale NADA del artefacto ({}): {:?}", marca, out);
        }
    } else {
        assert!(out.contains("output_sha"));
    }
    // Flags incompatibles → exit 2.
    let (code, _, err) = synsema(&dir, &["run", "--attest", "--sandbox", "p.syn"], &[("SYNSEMA_ATTEST", Some("mock"))]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("--attest"));
    let (code, _, err) = synsema(&dir, &["run", "--attest", "--explain", "p.syn"], &[("SYNSEMA_ATTEST", Some("mock"))]);
    assert_eq!(code, 2, "{}", err);
    let (code, _, err) = synsema(&dir, &["run", "--attest", "--profile", "native", "p.syn"], &[("SYNSEMA_ATTEST", Some("mock"))]);
    assert_eq!(code, 2, "{}", err);
}

#[test]
fn serve_attested_and_watch_are_mutually_exclusive() {
    let dir = project("watch");
    std::fs::write(dir.join("app.syn"), "require serve(8080)\nserve on 8080\n    route \"GET /\"\n        give {\"ok\": true}\n").unwrap();
    let (code, _, err) = synsema(&dir, &["serve", "--attested", "--watch", "app.syn"], &[("SYNSEMA_ATTEST", Some("mock"))]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("--attested") && err.contains("--watch"), "{}", err);
}

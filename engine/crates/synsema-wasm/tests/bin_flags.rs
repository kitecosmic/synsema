//! v0.6.46 (E3b): el bin `synsema-wasm` (el de wasip1, acá compilado nativo) toma `--trusted`,
//! `--trusted-cap-set` y `--labels` con las mismas formas que `synsema run`.

use std::path::PathBuf;
use std::process::Command;

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("synsema-wasm-bin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("t.syn"), "export task inicial(c)\n    require declassify(\"clientes\")\n    give declassify(c.nombre, \"la inicial\")\n").unwrap();
    let head = "use \"trusted:t\" as t\nlet c be private({\"nombre\": \"Ana\"}, \"clientes\")\n";
    std::fs::write(d.join("a.syn"), format!("{head}print(t.inicial(c))\n")).unwrap();
    std::fs::write(d.join("b.syn"), format!("{head}print(declassify(c.nombre, \"m\"))\n")).unwrap();
    d
}

fn bin(d: &PathBuf, args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_synsema-wasm")).args(args).current_dir(d).output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

/// v0.6.47 (T1): el comienzo del texto fijo de un corte de etiquetas.
const FIXED: &str = "label_violation: the flow checker stopped the run (private to ";

#[test]
fn e3b_wasip1_bin_takes_trusted_modules() {
    let d = dir();
    let (code, out, err) = bin(&d, &["--labels", "--cap-set", "stdout", "--trusted", "t=t.syn", "a.syn"]);
    assert_eq!((code, out.trim()), (0, "Ana"), "{}", err);
    // Directo, el techo no da `declassify`; con un techo de confianza que no lo nombra, la tool tampoco.
    // v0.6.47 (T1): con techo el programa ve el texto fijo; el motivo no sale por stderr.
    let (code, out, err) = bin(&d, &["--labels", "--cap-set", "stdout", "--trusted", "t=t.syn", "b.syn"]);
    let all = out + &err;
    assert!(code != 0 && all.contains(FIXED) && !all.contains("declassify is not granted"), "{}", all);
    let (code, out, err) = bin(&d, &["--labels", "--cap-set", "stdout", "--trusted", "t=t.syn", "--trusted-cap-set", "stdout", "a.syn"]);
    let all = out + &err;
    assert!(code != 0 && all.contains(FIXED) && !all.contains("declassify is not granted"), "{}", all);
    // Sin techo, el dueño ve el motivo.
    std::fs::write(d.join("c.syn"), "let s be private(1, \"app\")\nwhen s == 1\n    print(\"x\")\n").unwrap();
    let (code, _, err) = bin(&d, &["--labels", "c.syn"]);
    assert!(code != 0 && err.contains("print called under private control flow"), "{}", err);
    let (code, _, err) = bin(&d, &["--labels", "--sandbox", "c.syn"]);
    assert!(code != 0 && err.contains(FIXED) && !err.contains("print called"), "{}", err);
    // `--test` igual: el dueño ve el sitio sin techo y el texto fijo con techo.
    std::fs::write(d.join("tc.syn"), "let s be private(1, \"app\")\ntest \"corte\"\n    when s == 1\n        print(\"x\")\n").unwrap();
    let (code, out, _) = bin(&d, &["--test", "--labels", "tc.syn"]);
    assert!(code != 0 && out.contains("print called under private control flow"), "{}", out);
    let (code, out, _) = bin(&d, &["--test", "--labels", "--sandbox", "tc.syn"]);
    assert!(code != 0 && out.contains(FIXED) && !out.contains("print called"), "{}", out);
    let (code, out, err) = bin(&d, &["--labels", "a.syn"]);
    assert!(code != 0 && (out + &err).contains("no trusted module named 't'"), "{}", err);
    let (code, _, err) = bin(&d, &["--trusted", "sin-ruta", "a.syn"]);
    assert!(code == 2 && err.contains("--trusted takes name=path"), "{}", err);
    let (code, _, err) = bin(&d, &["--trusted-cap-set", "stdout", "a.syn"]);
    assert!(code == 2 && err.contains("pass --trusted"), "{}", err);
}

/// v0.6.50 (ronda 1, N6): `--trusted-templates name=dir`, como en `synsema run`: la tool renderiza los
/// templates del host (no los del directorio de trabajo); sin su `--trusted`, o repetido, es error de uso.
#[test]
fn wasip1_bin_takes_trusted_templates() {
    let d = std::env::temp_dir().join(format!("synsema-wasm-tpl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("tpl/parts")).unwrap();
    std::fs::write(d.join("tpl/s.html"), "<p>{upper(n)}</p>{ include \"parts/pie.html\" }").unwrap();
    std::fs::write(d.join("tpl/parts/pie.html"), "<i>pie</i>").unwrap();
    std::fs::write(d.join("s.html"), "<p>DEL-PROGRAMA</p>").unwrap();
    std::fs::write(d.join("h.syn"), "export task saludo(n)\n    give text(render(\"s.html\", {\"n\": n}))\n").unwrap();
    std::fs::write(d.join("p.syn"), "use \"trusted:h\" as h\nprint(h.saludo(\"ana\"))\n").unwrap();
    let (code, out, err) = bin(&d, &["--trusted", "h=h.syn", "--trusted-templates", "h=tpl", "p.syn"]);
    assert!(code == 0 && out.contains("<p>ANA</p><i>pie</i>") && !out.contains("DEL-PROGRAMA"), "{} {}", out, err);
    let (code, _, err) = bin(&d, &["--trusted", "h=h.syn", "p.syn"]);
    assert!(code != 0 && err.contains("the trusted tool 'h' has no templates ('s.html')"), "{}", err);
    let (code, _, err) = bin(&d, &["--trusted", "h=h.syn", "--trusted-templates", "x=tpl", "p.syn"]);
    assert!(code == 2 && err.contains("--trusted-templates x: there is no --trusted x="), "{}", err);
    let (code, _, err) = bin(&d, &["--trusted", "h=h.syn", "--trusted-templates", "h=tpl", "--trusted-templates", "h=tpl", "p.syn"]);
    assert!(code == 2 && err.contains("--trusted-templates h: the name is given twice"), "{}", err);
    let (code, _, err) = bin(&d, &["--trusted", "h=h.syn", "--trusted-templates", "h", "p.syn"]);
    assert!(code == 2 && err.contains("--trusted-templates takes name=dir"), "{}", err);
}

/// v0.6.51 (N5): paridad con el nativo; un `sandbox` pelado deniega `print` también sin techo, y
/// `sandbox under {}` lo deja pasar.
#[test]
fn a_plain_sandbox_denies_print_in_wasm_too() {
    let r = synsema_wasm::run("print(\"antes\")\nsandbox\n    print(\"dentro\")\n", &synsema_wasm::RunOptions::new("s.syn"));
    assert!(!r.ok && r.output == vec!["antes".to_string()], "{:?} {:?}", r.output, r.errors);
    assert!(r.errors[0].contains("a `sandbox` block denies every capability"), "{:?}", r.errors);
    let r = synsema_wasm::run("sandbox under {}\n    print(\"dentro\")\n", &synsema_wasm::RunOptions::new("s.syn"));
    assert!(r.ok && r.output == vec!["dentro".to_string()], "{:?} {:?}", r.output, r.errors);
}

/// v0.6.54 (§D de v0.6.51): el bin de wasip1 toma `--auditor`/`--receipt` como `synsema run`: el
/// recibo sellado sale por stderr antes de la salida (o al archivo de `--receipt`) y el auditor lo
/// abre con su privada.
#[test]
fn v0654_wasip1_bin_seals_a_receipt() {
    let d = std::env::temp_dir().join(format!("synsema-wasm-bin-auditor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("p.syn"), "print(\"hola\")\n").unwrap();
    let (sk, pk) = synsema_stdlib::sealed::generate_keypair();
    let sk = synsema_stdlib::sealed::parse_auditor_key(&sk).unwrap();

    let (code, out, err) = bin(&d, &["--auditor", &pk, "p.syn"]);
    assert_eq!((code, out.trim()), (0, "hola"), "{}", err);
    let receipt: serde_json::Value = serde_json::from_str(err.lines().next().unwrap()).unwrap();
    let opened = synsema_stdlib::sealed::open_receipt(&receipt, &sk).unwrap();
    assert!(opened["header"]["program_sha"].is_string(), "{}", opened);
    assert!(opened["header"]["started"].is_string(), "con reloj, la hora: {}", opened);

    let (code, out, err) = bin(&d, &["--auditor", &pk, "--receipt", "r.json", "p.syn"]);
    assert_eq!((code, out.trim()), (0, "hola"), "{}", err);
    let receipt: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(d.join("r.json")).unwrap()).unwrap();
    assert!(synsema_stdlib::sealed::open_receipt(&receipt, &sk).is_ok());

    for (args, msg) in [
        (vec!["--receipt", "r.json", "p.syn"], "--receipt needs an auditor"),
        (vec!["--auditor", pk.as_str(), "--test", "p.syn"], "does not go with --test"),
        (vec!["--auditor", pk.as_str(), "--receipt", "fd:3", "p.syn"], "fd:N is not available in wasip1"),
        (vec!["--auditor", "nope", "p.syn"], "--auditor:"),
    ] {
        let (code, _, err) = bin(&d, &args);
        assert_eq!(code, 2, "{:?}: {}", args, err);
        assert!(err.contains(msg), "{:?}: {}", args, err);
    }

    // v0.6.54 (B2 de la ronda 1): un `--receipt` que no se puede escribir es un error de uso ANTES
    // de correr: el programa no llega a hacer sus efectos.
    std::fs::write(d.join("e.syn"), "require file_write\nwrite_file(\"efecto.txt\", \"x\")\nprint(\"hecho\")\n").unwrap();
    let (code, out, err) = bin(&d, &["--auditor", &pk, "--receipt", "no/existe/r.json", "e.syn"]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("--receipt: cannot write no/existe/r.json"), "{}", err);
    assert!(out.is_empty(), "{}", out);
    assert!(!d.join("efecto.txt").exists(), "el programa corrió");
    // Con un destino que sí se puede escribir, corre (el control del test de arriba).
    let (code, _, err) = bin(&d, &["--auditor", &pk, "--receipt", "r2.json", "e.syn"]);
    assert_eq!(code, 0, "{}", err);
    assert!(d.join("efecto.txt").exists());
}

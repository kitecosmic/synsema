//! Tests del binario real para v0.6.57.

use super::v0646_tanda_e_cli::{auditor_keys, open_receipt, project, receipt_in, synsema, synsema_env};

/// `run` con `SYNSEMA_THREADS` (o sin él si `threads` es `None`): (código, stdout, stderr).
fn run_threads(dir: &std::path::Path, threads: Option<&str>) -> (i32, String, String) {
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_synsema"));
    c.args(["run", "p.syn"]).current_dir(dir).env("SYNSEMA_NO_UPDATE_CHECK", "1");
    match threads {
        Some(t) => c.env("SYNSEMA_THREADS", t),
        None => c.env_remove("SYNSEMA_THREADS"),
    };
    let o = c.output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// Ítem 5: `SYNSEMA_THREADS` topea los hilos de `matmul` sin cambiar los bits; un valor inválido se
/// avisa una sola vez por stderr y se ignora (el programa sigue).
#[test]
fn synsema_threads_caps_matmul_without_changing_the_bits() {
    let dir = project("v0657-threads");
    std::fs::write(
        dir.join("p.syn"),
        "let a be reshape(arange(0, 90000) * 0.37 - 7000, [300, 300])\n\
         let c be matmul(a, transpose(a))\n\
         let d be matmul(c, a)\n\
         print(sum(d))\n\
         print(json_encode(to_list(d[17])))\n",
    )
    .unwrap();
    let (code1, one, err1) = run_threads(&dir, Some("1"));
    assert_eq!(code1, 0, "{}", err1);
    assert!(!err1.contains("SYNSEMA_THREADS"), "un valor válido no avisa: {}", err1);
    let (code8, eight, _) = run_threads(&dir, Some("8"));
    assert_eq!(code8, 0);
    assert_eq!(one, eight, "1 y 8 hilos tienen que dar los mismos bits");
    let (_, default, _) = run_threads(&dir, None);
    assert_eq!(one, default);

    for bad in ["abc", "0", "-2", "1.5"] {
        let (code, out, err) = run_threads(&dir, Some(bad));
        assert_eq!(code, 0, "un knob inválido no frena el programa: {}", err);
        assert_eq!(out, one);
        assert_eq!(
            err.matches("SYNSEMA_THREADS").count(),
            1,
            "un aviso, una sola vez (aunque haya dos matmul), para {:?}: {}",
            bad,
            err
        );
        assert!(err.contains("is not a whole number >= 1; ignored"), "{}", err);
    }
}

// =========================================================
// Ítem 4: el recibo anota dónde corrió (specs/v0.6.57-recibo-compute.md; cada test nombra sus filas)
// =========================================================

const COMPUTE_KEYS: [&str; 7] = ["arch", "cores", "device", "isa", "matmul_bitwise", "os", "threads"];

/// La forma de `compute`: los siete campos y nada más (fila 15: sin modelo de CPU; N1: sin `bitwise`
/// suelto), con `matmul_bitwise` derivado de `arch` e `isa`.
fn check_compute(c: &serde_json::Value) {
    let o = c.as_object().unwrap_or_else(|| panic!("compute no es un mapa: {}", c));
    let mut keys: Vec<&str> = o.keys().map(|k| k.as_str()).collect();
    keys.sort();
    assert_eq!(keys, COMPUTE_KEYS, "{}", c);
    assert_eq!(c["device"], "cpu");
    assert_eq!(c["os"], std::env::consts::OS);
    assert_eq!(c["arch"], std::env::consts::ARCH);
    let isa = c["isa"].as_str().unwrap();
    assert!(["avx512f+fma", "avx2+fma", "neon+fma", "scalar"].contains(&isa), "{}", c);
    assert_eq!(
        c["matmul_bitwise"].as_bool(),
        Some(std::env::consts::ARCH == "x86_64" && (isa == "avx2+fma" || isa == "avx512f+fma")),
        "{}",
        c
    );
    assert!(c["cores"].as_u64().unwrap() >= 1 && c["threads"].as_u64().unwrap() >= 1, "{}", c);
}

/// Filas 1, 2, 3, 6 y 15: `compute` está aunque no haya `matmul`, no cambia después de un `matmul`
/// grande ni de uno en una rama privada, y `threads` es el tope.
#[test]
fn receipt_says_where_it_ran() {
    let dir = project("v0657-compute");
    std::fs::write(
        dir.join("p.syn"),
        concat!(
            "let before be json_encode(receipt().credentialSubject.compute)\n",
            "let m be reshape(arange(0, 160000) * 0.5, [400, 400])\n",
            "let c be matmul(m, m)\n",
            "let n be private(400, \"app\")\n",
            "when n > 5\n",
            "    let d be matmul(m, m)\n",
            "print(before)\n",
            "print(json_encode(receipt().credentialSubject.compute))\n",
        ),
    )
    .unwrap();
    for threads in [None, Some("4")] {
        let mut env = vec![("SYNSEMA_NO_UPDATE_CHECK", "1")];
        if let Some(t) = threads {
            env.push(("SYNSEMA_THREADS", t));
        }
        let (code, out, err) = synsema_env(&dir, &["run", "--labels", "p.syn"], None, &env);
        assert_eq!(code, 0, "{}", err);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "{}", out);
        assert_eq!(lines[0], lines[1], "compute cambió después de un matmul (fila 2/3)");
        let c: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        check_compute(&c);
        if threads.is_some() {
            assert_eq!(c["threads"], 4, "fila 6: el tope de SYNSEMA_THREADS");
        }
        assert!(!lines[0].contains("model") && !lines[0].contains("brand"), "fila 15: {}", lines[0]);
    }
}

/// Graba `src` con auditor y deja el recibo abierto en `opened.json`: (recibo abierto, stdout).
fn record(dir: &std::path::PathBuf, src: &str) -> (serde_json::Value, String) {
    std::fs::write(dir.join("p.syn"), src).unwrap();
    let (sk, pk) = auditor_keys();
    let (_, out, err) = synsema(dir, &["run", "--labels", "--auditor", &pk, "p.syn"], None);
    let opened = open_receipt(&receipt_in(&err), &sk);
    std::fs::write(dir.join("opened.json"), opened.to_string()).unwrap();
    (opened, out)
}

fn replay(dir: &std::path::PathBuf, src: &str) -> (i32, String, String) {
    std::fs::write(dir.join("q.syn"), src).unwrap();
    synsema(dir, &["run", "--labels", "--replay", "opened.json", "q.syn"], None)
}

/// Filas 9, 10, 12, 12c y 12d: el header sellado lleva `compute` (el mismo que `receipt()` de la misma
/// corrida: se arma en un solo lugar); el replay avisa fuera de la promesa y con otro sistema, al
/// prepararse (también cuando el replay falla), y nunca falla por eso.
#[test]
fn the_sealed_header_says_where_it_ran_and_replay_warns() {
    let dir = project("v0657-sealed");
    // Una corrida que falla: el veredicto es un Err (N2) y el aviso tiene que salir igual.
    let src = "require time
let t be now()
print(json_encode(receipt().credentialSubject.compute))
raise \"boom\"
";
    let (mut opened, out) = record(&dir, src);
    let c = opened["header"]["compute"].clone();
    check_compute(&c);
    let from_receipt: serde_json::Value =
        serde_json::from_str(out.trim()).unwrap_or_else(|e| panic!("stdout no es el compute ({}): {:?}", e, out));
    assert_eq!(from_receipt, c, "receipt() y el header sellado dicen cosas distintas");
    // Fila 10: el mismo lugar, sin línea (si acá aplica la promesa).
    let (code, _, err) = replay(&dir, src);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("replay: the run stopped with an error"), "{}", err);
    if c["matmul_bitwise"] == true {
        assert!(!err.contains("bitwise promise") && !err.contains("libm"), "{}", err);
    }
    // Fila 12 / 12d: un recibo de una máquina fuera de la promesa, y el replay falla.
    let mut out_of_promise = c.clone();
    out_of_promise["arch"] = "aarch64".into();
    out_of_promise["isa"] = "neon+fma".into();
    out_of_promise["matmul_bitwise"] = false.into();
    opened["header"]["compute"] = out_of_promise;
    std::fs::write(dir.join("opened.json"), opened.to_string()).unwrap();
    let (code, _, err) = replay(&dir, src);
    assert_eq!(code, 1, "el aviso no cambia el veredicto: {}", err);
    let warn = err.find("outside the bitwise promise of matmul").unwrap_or_else(|| panic!("sin aviso: {}", err));
    let verdict = err.find("replay: the run stopped with an error").unwrap();
    assert!(warn < verdict, "el aviso sale al preparar, antes de correr: {}", err);
    assert!(err.contains("recorded on ") && err.contains("/aarch64 neon+fma"), "{}", err);
    // Fila 12c: otro sistema operativo.
    let mut other_os = c.clone();
    let os = if std::env::consts::OS == "linux" { "windows" } else { "linux" };
    other_os["os"] = os.into();
    opened["header"]["compute"] = other_os;
    std::fs::write(dir.join("opened.json"), opened.to_string()).unwrap();
    let (_, _, err) = replay(&dir, src);
    assert!(
        err.contains(&format!("the rest of libm come from the system and may differ in the last bit between {} and {}", os, std::env::consts::OS)),
        "{}",
        err
    );
    // Fila 13: un recibo sin `compute` (anterior a 0.6.57): nada.
    opened["header"].as_object_mut().unwrap().remove("compute");
    std::fs::write(dir.join("opened.json"), opened.to_string()).unwrap();
    let (code, _, err) = replay(&dir, src);
    assert_eq!(code, 1);
    assert!(!err.contains("bitwise promise") && !err.contains("libm"), "{}", err);
}

/// Fila 4: dentro de un worker de `parallel_map` el tope del hilo es `tope / min(limit, n)`, y `n` puede
/// ser el largo de una lista privada: el recibo anota el tope del proceso, igual que afuera.
#[test]
fn receipt_in_a_parallel_map_worker_has_the_process_cap() {
    let dir = project("v0657-compute-worker");
    std::fs::write(
        dir.join("p.syn"),
        concat!(
            "task where_(x)\n",
            "    give json_encode(receipt().credentialSubject.compute)\n",
            "let top be json_encode(receipt().credentialSubject.compute)\n",
            "let inner be parallel_map(where_, [1, 2, 3, 4, 5, 6, 7, 8])\n",
            "print(top)\n",
            "print(inner[0])\n",
            "print(inner[7])\n",
        ),
    )
    .unwrap();
    let (code, out, err) =
        synsema_env(&dir, &["run", "p.syn"], None, &[("SYNSEMA_NO_UPDATE_CHECK", "1"), ("SYNSEMA_THREADS", "8")]);
    assert_eq!(code, 0, "{}", err);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{}", out);
    assert_eq!(lines[0], lines[1], "el worker anota otro compute");
    assert_eq!(lines[0], lines[2]);
    let c: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(c["threads"], 8, "{}", c);
}

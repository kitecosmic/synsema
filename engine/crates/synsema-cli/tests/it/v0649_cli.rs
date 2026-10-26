//! Tests del binario real para v0.6.49: las decisiones de la §A (regla y tabla de casos en
//! `specs/v0.6.49-a-modelo.md`; cada test nombra sus filas) y los bugs de la §B que necesitan el CLI.
//! Las sondas de `specs/v0.6.49-a-sondas/` quedan acá, contra el binario de la rama.

use super::v0646_tanda_e_cli::{
    auditor_keys, cut_for_operator, e5, fake_model, open_receipt, project, receipt_in, synsema, synsema_env,
};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

// =========================================================
// A1 — `require declassify("P")` acota bajo un techo, igual que `net`
// =========================================================

const A1_BODY: &str = "let c be private({\"name\": \"Ana\"}, \"customers\")\nprint(declassify(c.name, \"the name is public\"))\n";

fn a1(dir: &PathBuf, require: &str, extra: &[&str]) -> (i32, String, String) {
    std::fs::write(dir.join("p.syn"), format!("{}{}", require, A1_BODY)).unwrap();
    let mut a = vec!["run", "--labels"];
    a.extend_from_slice(extra);
    a.push("p.syn");
    synsema(dir, &a, None)
}

/// Filas 1–5: sin techo publica de ambiente; con techo, sólo lo que el programa declara y el techo
/// permite.
#[test]
fn a1_ceiling_publishes_only_what_the_program_declares() {
    let dir = project("a1");
    let ceiling = ["--cap-set", "stdout,declassify=customers"];
    // 1) Sin techo, sin `require`: de ambiente (D3), como antes.
    let (code, out, err) = a1(&dir, "", &[]);
    assert_eq!((code, out.trim()), (0, "Ana"), "{}", err);
    // 2) La sonda `a1.syn`: el techo nombra `customers` y el programa no lo declara. Antes publicaba.
    let d = cut_for_operator(|x| a1(&dir, "", &[&ceiling[..], x].concat()));
    assert!(d.contains("declassify is not granted") && d.contains("require declassify(\"<principal>\")"), "{}", d);
    // 3) Declarado y permitido.
    let (code, out, err) = a1(&dir, "require declassify(\"customers\")\n", &ceiling);
    assert_eq!((code, out.trim()), (0, "Ana"), "{}", err);
    // 4) Declarado otro principal: no publica, y el audit dice que el techo rechazó el `require`.
    let audit = dir.join("a.jsonl");
    let audit_s = audit.to_string_lossy().into_owned();
    let (code, out, _) = a1(&dir, "require declassify(\"billing\")\n", &[&ceiling[..], &["--audit", &audit_s]].concat());
    assert!(code != 0 && !out.contains("Ana"), "{}", out);
    let text = std::fs::read_to_string(&audit).unwrap();
    assert!(
        text.lines().any(|l| l.contains("billing") && l.contains("\"granted\":false") && l.contains("ceiling")),
        "{}",
        text
    );
    // 5) `require declassify` sin scope: más ancho que el techo, se rechaza entero (y avisa).
    let (code, out, err) = a1(&dir, "require declassify\n", &ceiling);
    assert!(code != 0 && !out.contains("Ana"), "{}", out);
    assert!(err.contains("bare `require declassify`"), "{}", err);
}

/// Filas 8–10: una tool de confianza es un programa con su propio techo (`--trusted-cap-set`).
#[test]
fn a1_trusted_tool_declassifies_only_what_its_task_declares() {
    let dir = project("a1-trusted");
    std::fs::write(dir.join("app.syn"), "use \"trusted:t\" as t\nlet c be private({\"name\": \"Ana\"}, \"customers\")\nprint(t.nombre(c))\n").unwrap();
    let tool = |require: &str| format!("export task nombre(c)\n{}    give declassify(c.name, \"the name is public\")\n", require);
    let run = |extra: &[&str]| {
        let mut a = vec!["run", "--labels", "--cap-set", "stdout", "--trusted", "t=t.syn"];
        a.extend_from_slice(extra);
        a.push("app.syn");
        synsema(&dir, &a, None)
    };
    let trusted_ceiling = ["--trusted-cap-set", "stdout,declassify=customers"];
    // 8) Techo de confianza que lo nombra, la task sin `require`: no publica.
    std::fs::write(dir.join("t.syn"), tool("")).unwrap();
    let d = cut_for_operator(|x| run(&[&trusted_ceiling[..], x].concat()));
    assert!(d.contains("declassify is not granted"), "{}", d);
    // 9) Con su `require`: publica.
    std::fs::write(dir.join("t.syn"), tool("    require declassify(\"customers\")\n")).unwrap();
    let (code, out, err) = run(&trusted_ceiling);
    assert_eq!((code, out.trim()), (0, "Ana"), "{}", err);
    // 10) Sin techo de confianza, la task sin `require` declasifica de ambiente (como un programa
    // sin techo; el CHANGELOG lo dice).
    std::fs::write(dir.join("t.syn"), tool("")).unwrap();
    let (code, out, err) = run(&[]);
    assert_eq!((code, out.trim()), (0, "Ana"), "{}", err);
}

// =========================================================
// A2 — el reloj se cerca en todo el programa
// =========================================================

/// Filas 1, 2 y 4: con etiquetas y auditor, dos `now()` dan lo mismo aunque no haya nada privado, con
/// un `print` en el medio, y después de un bucle privado (a35).
#[test]
fn a2_the_clock_is_fenced_in_the_whole_program() {
    let dir = project("a2");
    let (_, pk) = auditor_keys();
    for (name, src) in [
        ("seguidos", "require time\nlet a be now()\nlet b be now()\nprint(text(a == b))\n"),
        ("print", "require time\nlet a be now()\nprint(\"x\")\nlet b be now()\nprint(text(a == b))\n"),
        (
            "bucle",
            "require time\nlet n be private(3000, \"app\")\nlet a be now()\nlet i be private(0, \"app\")\nwhile i < n\n    set i to i + 1\nlet b be now()\nprint(text(a == b))\n",
        ),
    ] {
        std::fs::write(dir.join("p.syn"), src).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "--labels", "--auditor", &pk, "--receipt", "r.json", "p.syn"], None);
        assert_eq!(code, 0, "{}: {}", name, err);
        assert_eq!(out.lines().last(), Some("true"), "{}: {}", name, out);
    }
}

// =========================================================
// A3 — un secreto no nace en una rama privada: el mensaje dice la regla
// =========================================================

const A3_CREATED: &str = "a secret cannot be created or chosen under private control flow";

/// Filas 1, 7 y 8: `mnemonic_generate` en una rama privada (la sonda `a3.syn`).
#[test]
fn a3_secret_created_in_a_private_branch_says_the_rule() {
    let dir = project("a3");
    let (_, pk) = auditor_keys();
    let mut texts = Vec::new();
    for v in ["1", "2"] {
        std::fs::write(
            dir.join("p.syn"),
            format!("require wallet(\"W\")\nlet k be private({v}, \"app\")\nwhen k > 0\n    let m be mnemonic_generate(12, \"W\")\nprint(\"done\")\n"),
        )
        .unwrap();
        let (code, out, err) = synsema(&dir, &["run", "--labels", "--auditor", &pk, "--receipt", "r.json", "p.syn"], None);
        assert!(code != 0 && !out.contains("done"), "{}", out);
        assert!(err.contains(A3_CREATED) && err.contains("before the `when`"), "{}", err);
        assert!(!err.contains("already opaque"), "{}", err);
        texts.push(err.lines().find(|l| l.contains(A3_CREATED)).unwrap().to_string());
    }
    assert_eq!(texts[0], texts[1], "el texto depende del dato");
    // 7) Con techo: el programa ve el texto fijo de T1 y el operador, la regla.
    let d = cut_for_operator(|x| synsema(&dir, &[&["run", "--labels", "--cap-set", "stdout,wallet=W"][..], x, &["p.syn"]].concat(), None));
    assert!(d.contains(A3_CREATED), "{}", d);
}

/// Fila 5: `sign` con `SYNSEMA_SIGN_CEILING` en una rama privada, con auditor: antes
/// `Runtime error: private(app)`, sin texto.
#[test]
fn a3_sign_with_a_ceiling_in_a_private_branch_says_why() {
    let dir = project("a3-sign");
    let audit = dir.join("audit");
    let audit_s = audit.to_string_lossy().into_owned();
    std::fs::write(
        dir.join("p.syn"),
        "require secret(\"K\")\nrequire sign(\"K\")\nlet k be secret(\"K\")\nlet p be private(1, [\"cliente\"])\nwhen p == 1\n    let s be ed25519_sign(\"hola\", k)\nprint(\"listo\")\n",
    )
    .unwrap();
    let (_, pk) = auditor_keys();
    let env = [
        ("K", "1111111111111111111111111111111111111111111111111111111111111111"),
        ("SYNSEMA_SIGN_CEILING", "K:5"),
        ("SYNSEMA_AUDIT_DIR", audit_s.as_str()),
    ];
    let (code, out, err) = synsema_env(&dir, &["run", "--labels", "--auditor", &pk, "--receipt", "r.json", "p.syn"], None, &env);
    assert!(code != 0 && !out.contains("listo"), "{}", out);
    assert!(err.contains("a signature that counts against SYNSEMA_SIGN_CEILING cannot run in a branch decided by a private value"), "{}", err);
    assert!(!err.contains("private(cliente)\n") && !err.contains("sign(\"K\")"), "{}", err);
}

// =========================================================
// A5 — un CIDR no cubre nombres
// =========================================================

/// Filas 1 y 2 (las sondas `a5.syn`/`a5b.syn`, con loopback para no salir de la máquina).
#[test]
fn a5_a_cidr_grant_reaches_addresses_not_names() {
    let dir = project("a5");
    std::fs::write(
        dir.join("p.syn"),
        "require net(\"127.0.0.0/8\")\ntry\n    http_get(\"http://localhost:1/\", timeout = 2)\nrecover e\n    print(\"name: \" + e)\nlet r be http_get(\"http://127.0.0.1:1/\", timeout = 2)\nprint(\"ip: \" + text(r.status))\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "p.syn"], None);
    assert_eq!(code, 0, "{}", err);
    let name = out.lines().find(|l| l.starts_with("name: ")).unwrap_or_else(|| panic!("{}", out));
    assert!(name.contains("Capability not granted: net(\"localhost:1\")"), "{}", name);
    assert!(name.contains("net(\"127.0.0.0/8\") covers the addresses inside it") && name.contains("does not depend on DNS"), "{}", name);
    assert!(name.contains("`require net(\"localhost:1\")`"), "{}", name);
    // La dirección literal sí está concedida: el pedido sale (y falla la conexión, no el permiso).
    assert!(out.lines().any(|l| l == "ip: 0"), "{}", out);
}

// =========================================================
// A6 — `discovery off` apaga todo, robots incluido
// =========================================================

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn http_status(port: u16, path: &str) -> Option<String> {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    s.write_all(format!("GET {} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", path).as_bytes()).ok()?;
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    Some(buf)
}

fn serve_and_get(dir: &PathBuf, block: &str, path: &str) -> String {
    let port = free_port();
    std::fs::write(dir.join("app.syn"), format!("require serve({p})\nserve on {p}\n{block}    route \"GET /x\"\n        give \"x\"\n", p = port)).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["serve", "app.syn"])
        .current_dir(dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn synsema serve");
    let t0 = Instant::now();
    let mut ready = false;
    while t0.elapsed() < Duration::from_secs(30) {
        if http_status(port, "/x").is_some_and(|r| r.starts_with("HTTP/1.1 200")) {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let got = if ready { http_status(port, path).unwrap_or_default() } else { String::new() };
    let _ = child.kill();
    let _ = child.wait();
    assert!(ready, "el server no levantó");
    got
}

/// Filas 1–3 (la sonda `a6.syn`).
#[test]
fn a6_discovery_off_turns_robots_off_even_with_private() {
    let dir = project("a6");
    let r = serve_and_get(&dir, "    discovery off\n    private\n", "/robots.txt");
    assert!(r.starts_with("HTTP/1.1 404"), "{}", r);
    let r = serve_and_get(&dir, "    private\n", "/robots.txt");
    assert!(r.starts_with("HTTP/1.1 200") && r.contains("Disallow: /"), "{}", r);
    let r = serve_and_get(&dir, "    discovery off\n    private\n    route \"GET /*path\"\n        give \"del programa\"\n", "/robots.txt");
    assert!(r.starts_with("HTTP/1.1 200") && r.contains("del programa"), "{}", r);
}

// =========================================================
// A7 — `--replay` exige el mismo programa
// =========================================================

/// Graba `src` con auditor y deja el recibo abierto en `opened.json`.
fn record(dir: &PathBuf, src: &str, env: &[(&str, &str)]) -> serde_json::Value {
    std::fs::write(dir.join("p.syn"), src).unwrap();
    let (sk, pk) = auditor_keys();
    let (_, _, err) = synsema_env(dir, &["run", "--labels", "--auditor", &pk, "p.syn"], None, env);
    let opened = open_receipt(&receipt_in(&err), &sk);
    std::fs::write(dir.join("opened.json"), opened.to_string()).unwrap();
    opened
}

fn replay(dir: &PathBuf, src: &str, extra: &[&str]) -> (i32, String, String) {
    std::fs::write(dir.join("q.syn"), src).unwrap();
    let mut a = vec!["run", "--labels", "--replay", "opened.json"];
    a.extend_from_slice(extra);
    a.push("q.syn");
    synsema(dir, &a, None)
}

const A7: &str = "require time\nlet t be now()\nprint(\"one\")\n";

/// Filas 1–4 (las sondas `a7.syn`/`a7b.syn`).
#[test]
fn a7_replay_needs_the_same_program() {
    let dir = project("a7");
    record(&dir, A7, &[]);
    // 1) El mismo programa (con otro nombre de archivo: el sha es del fuente).
    let (code, out, err) = replay(&dir, A7, &[]);
    assert_eq!((code, out.trim()), (0, "one"), "{}", err);
    assert!(err.contains("replay: the 0 inputs match the recorded run (same seed, the same 1 clock reading)"), "{}", err);
    // 2) Otro programa: no corre.
    let other = "require time\nlet t be now()\nprint(\"two, a different program\")\n";
    let (code, out, err) = replay(&dir, other, &[]);
    assert_eq!(code, 2, "{}", err);
    assert!(out.is_empty(), "{}", out);
    assert!(err.contains("the receipt is of another program") && err.contains("--replay-any-program"), "{}", err);
    // 3) Con el flag corre, y dice que no es una verificación.
    let (code, out, err) = replay(&dir, other, &["--replay-any-program"]);
    assert_eq!((code, out.trim()), (0, "two, a different program"), "{}", err);
    assert!(err.contains("(another program: not a verification)"), "{}", err);
    // 4) Más lecturas del reloj que las grabadas, sin truncado: es una diferencia.
    let more = "require time\nlet t be now()\nlet u be now()\nprint(\"one\")\n";
    let (code, _, err) = replay(&dir, more, &["--replay-any-program"]);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("replay: the run read the clock 2 times, the recorded run 1"), "{}", err);
    assert!(!err.contains("same clock readings"), "{}", err);
    // El flag sin `--replay` es un error de uso.
    let (code, _, err) = synsema(&dir, &["run", "--replay-any-program", "q.syn"], None);
    assert_eq!(code, 2, "{}", err);
}

/// Fila 5: sólo se cortó el reloj; el aviso lo nombra (antes, "truncated 0 sealed entries") y las
/// lecturas de más no son una diferencia.
#[test]
fn a7_replay_names_a_truncated_clock() {
    let dir = project("a7-clock");
    let src = "require time\nlet i be 0\nlet t be 0\nwhile i < 400\n    set t to now()\n    set i to i + 1\nprint(\"listo\")\n";
    let opened = record(&dir, src, &[("SYNSEMA_RECEIPT_SEALED_BYTES", "4096")]);
    assert!(opened["clock_truncated"].as_u64().unwrap_or(0) > 0, "{}", opened);
    assert_eq!(opened["truncated"].as_u64().unwrap_or(0), 0, "{}", opened);
    let (code, out, err) = replay(&dir, src, &[]);
    assert_eq!((code, out.trim()), (0, "listo"), "{}", err);
    assert!(!err.contains("truncated 0 sealed entries"), "{}", err);
    assert!(err.contains("clock readings and truncated") && err.contains("past the receipt's truncation"), "{}", err);
}

/// Filas 6 y 7: una corrida que falla no "coincide"; un recibo sin `program_sha` no se compara.
#[test]
fn a7_replay_of_a_failed_run_and_of_a_receipt_without_sha() {
    let dir = project("a7-fail");
    let src = "require time\nlet t be now()\nraise \"boom\"\n";
    let mut opened = record(&dir, src, &[]);
    let (code, _, err) = replay(&dir, src, &[]);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("replay: the run stopped with an error"), "{}", err);
    assert!(!err.contains("inputs match the recorded run ("), "{}", err);
    opened["header"].as_object_mut().unwrap().remove("program_sha");
    std::fs::write(dir.join("opened.json"), opened.to_string()).unwrap();
    let (code, out, err) = replay(&dir, src, &[]);
    assert_eq!(code, 2, "{}", err);
    assert!(out.is_empty() && err.contains("the receipt has no program_sha"), "{}{}", out, err);
}

// =========================================================
// A9 — `llm-data` nombra el permiso; aviso de `generate "x" + c`
// =========================================================

fn llm_data_reasons(audit: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(audit)
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["source"] == "llm-data")
        .map(|v| format!("{} | {} | {}", v["capability"], v["granted"], v["reason"]))
        .collect()
}

/// Filas 1, 2, 3 y 5.
#[test]
fn a9_llm_data_names_the_permission_once_per_call() {
    let (port, _seen) = fake_model();
    let dir = project("a9");
    let audit = dir.join("a.jsonl");
    let audit_s = audit.to_string_lossy().into_owned();
    let ceiling = "stdout,llm=p@127.0.0.1,llm=q@127.0.0.1";
    // 1) y 2): una pública y una con datos de `p`.
    let src = "require llm(\"p\")\nrequire llm(\"q\")\nprint(reason \"hola\")\nlet x be private(\"dato\", \"p\")\nlet y be private(\"otro\", \"q\")\nlet r be reason x\nlet s be reason x + y\n";
    let mut runs = Vec::new();
    for _ in 0..3 {
        let _ = std::fs::remove_file(&audit);
        let (code, out, err) = e5(&dir, port, src, &["--cap-set", ceiling, "--audit", &audit_s], &[]);
        assert_eq!((code, out.trim()), (0, "respuesta"), "{}", err);
        runs.push(llm_data_reasons(&audit));
    }
    // Una sola entrada por llamada con datos privados (la pública no tiene), con el conjunto
    // DECLARADO: `p` sólo o `p` y `q`, el mismo texto.
    let want = r#""llm(\"p,q@127.0.0.1\")" | true | "Granted by llm(\"p,q@127.0.0.1\")""#;
    assert_eq!(runs[0], [want, want], "{:?}", runs[0]);
    // 5) La misma corrida da el mismo audit.
    assert!(runs.iter().all(|r| r == &runs[0]), "{:?}", runs);
}

/// Fila 6: el aviso al cargar, una vez, con la línea; y el modelo no ve `c`.
#[test]
fn a9_generate_joined_with_plus_warns_at_load() {
    let (port, seen) = fake_model();
    let dir = project("a9-gen");
    let src = "require llm\nlet c be \"DATO-QUE-NO-VE\"\nlet r be generate \"un saludo\" + c\nprint(r)\n";
    let (code, out, err) = e5(&dir, port, src, &[], &[]);
    assert_eq!((code, out.trim()), (0, "respuestaDATO-QUE-NO-VE"), "{}", err);
    assert_eq!(err.matches("`generate \"…\" + …` joins the model's answer").count(), 1, "{}", err);
    assert!(err.contains("p.syn:3:"), "{}", err);
    assert!(!seen.lock().unwrap().iter().any(|b| b.contains("DATO-QUE-NO-VE")));
    // `synsema check` también lo dice.
    let (_, out, err) = synsema(&dir, &["check", "p.syn"], None);
    assert!(format!("{}{}", out, err).contains("joins the model's answer"), "{}{}", out, err);
}

// =========================================================
// §B — bugs que necesitan el binario
// =========================================================

/// B5: `synsema --help` era "subcomando desconocido"; el uso lista los flags de confianza y de replay.
#[test]
fn b5_help_lists_trusted_and_replay_flags() {
    let dir = project("b5");
    for h in ["--help", "-h", "help"] {
        let (code, out, err) = synsema(&dir, &[h], None);
        assert_eq!(code, 0, "{}: {}", h, err);
        for flag in ["--trusted <nombre=ruta>", "--trusted-cap-set <list>", "--replay-any-program"] {
            assert!(out.contains(flag), "{}: falta {}: {}", h, flag, out);
        }
    }
    // El uso de `run` y el de `test` también.
    let (_, _, err) = synsema(&dir, &["run", "--nada", "p.syn"], None);
    assert!(err.contains("--trusted-cap-set"), "{}", err);
    let (_, _, err) = synsema(&dir, &["test"], None);
    assert!(err.contains("--trusted <nombre=ruta>"), "{}", err);
}

/// B6: en `code check`, los avisos de deprecación traen su línea y la ruta relativa (salían en la
/// línea 0 con la ruta absoluta en el mensaje), y el de una capability faltante apunta a la llamada.
#[test]
fn b6_code_check_puts_each_warning_on_its_line() {
    let dir = project("b6");
    std::fs::write(
        dir.join("p.syn"),
        "task go()\n    print(\"a\")\n    let r be fetch(\"https://api.x.com/\")\n    give r\nlet e be eye(2)\nprint(percentile([1, 2], 0.5))\nprint(go())\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["code", "check", "--json"], None);
    assert_eq!(code, 0, "{}{}", out, err);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let ws = v["warnings"].as_array().unwrap();
    let at = |line: u64, needle: &str| ws.iter().any(|w| w["file"] == "p.syn" && w["line"] == line && w["message"].as_str().unwrap().contains(needle));
    assert!(at(5, "`eye` is deprecated"), "{}", out);
    assert!(at(6, "percentile takes p from 0 to 100"), "{}", out);
    assert!(at(3, "needs capability `net`"), "la llamada, no la línea 1 del task: {}", out);
    let dir_s = dir.to_string_lossy().replace('\\', "/");
    assert!(!ws.iter().any(|w| w["line"] == 0 || w["message"].as_str().unwrap().replace('\\', "/").contains(&dir_s)), "{}", out);
}

/// B7: `synsema check` rechaza un builtin protegido leído como valor (como `run` y `code check`), y
/// `code check` no sugiere un `require declassify` desnudo.
#[test]
fn b7_check_sees_protected_names_and_code_check_names_a_principal() {
    let dir = project("b7");
    for src in ["let d be declassify\nprint(d)\n", "let p be private\nprint(p)\n"] {
        std::fs::write(dir.join("p.syn"), src).unwrap();
        let (code, out, err) = synsema(&dir, &["check", "p.syn"], None);
        assert_eq!(code, 1, "{}: {}{}", src, out, err);
        assert!(!out.contains("OK") && err.contains("p.syn:1:"), "{}: {}{}", src, out, err);
        let (code, _, _) = synsema(&dir, &["run", "p.syn"], None);
        assert_ne!(code, 0, "{}", src);
    }
    std::fs::write(dir.join("p.syn"), "let c be private(\"Ana\", \"customers\")\nprint(declassify(c, \"public\"))\n").unwrap();
    let (code, out, err) = synsema(&dir, &["code", "check", "--json"], None);
    assert_eq!(code, 0, "{}{}", out, err);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let w = v["warnings"].as_array().unwrap().iter().find(|w| w["message"].as_str().unwrap().contains("`declassify`")).unwrap_or_else(|| panic!("{}", out));
    let m = w["message"].as_str().unwrap();
    assert!(m.contains("require declassify(\"<principal>\")") && !m.contains("add `require declassify` ("), "{}", m);
}

/// B8: sobre un módulo de confianza, `set t.NEW` y `set t.task` son errores, como sobre uno de
/// archivo; un dato exportado cambia sólo la copia del programa.
#[test]
fn b8_set_on_a_trusted_module_follows_the_module_rules() {
    let dir = project("b8");
    std::fs::write(dir.join("t.syn"), "export let LIMIT be 3\nexport task g()\n    give LIMIT\n").unwrap();
    let run = |stmt: &str| {
        std::fs::write(dir.join("p.syn"), format!("use \"trusted:t\" as t\n{}\nprint(t.g())\nprint(t.LIMIT)\n", stmt)).unwrap();
        synsema(&dir, &["run", "--trusted", "t=t.syn", "p.syn"], None)
    };
    let (code, _, err) = run("set t.NEW to 1");
    assert!(code != 0 && err.contains("trusted module has no export 'NEW'"), "{}", err);
    let (code, _, err) = run("set t.g to 2");
    assert!(code != 0 && err.contains("cannot replace the trusted task 'g'"), "{}", err);
    let (code, _, err) = run("set t[\"g\"] to 2");
    assert!(code != 0 && err.contains("cannot replace the trusted task 'g'"), "{}", err);
    // El dato cambia en la copia del programa; la tool sigue leyendo el suyo.
    let (code, out, err) = run("set t.LIMIT to 9");
    assert_eq!((code, out.lines().collect::<Vec<_>>()), (0, vec!["3", "9"]), "{}", err);
}

/// B9: una task de confianza se describe con `tool_spec` y se despacha con `call_tool` (argumentos
/// nombrados), en el scope de su módulo; antes sólo se podía llamar posicional.
#[test]
fn b9_trusted_tasks_dispatch_with_call_tool_and_tool_spec() {
    let dir = project("b9");
    std::fs::write(
        dir.join("t.syn"),
        "export task saludo(nombre, cliente: map, signo = \"!\")\n    require declassify(\"clientes\")\n    give \"hola \" + nombre + \" de \" + declassify(cliente.ciudad, \"la ciudad es pública\") + signo\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("p.syn"),
        "use \"trusted:t\" as t\nlet c be private({\"ciudad\": \"Salta\"}, \"clientes\")\nlet spec be tool_spec(t.saludo, \"saluda\")\nprint(spec.name + \" \" + text(spec.params) + \" \" + text(spec.optional))\nprint(call_tool(t.saludo, {\"cliente\": c, \"nombre\": \"Ana\"}))\nprint(t.saludo(\"Eva\", c, signo = \"?\"))\ntry\n    call_tool(t.saludo, {\"cliente\": 1, \"nombre\": \"Ana\"})\nrecover e\n    print(\"tipo: \" + e)\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "--cap-set", "stdout", "--trusted", "t=t.syn", "--trusted-cap-set", "stdout,declassify=clientes", "p.syn"], None);
    assert_eq!(code, 0, "{}{}", out, err);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], r#"saludo ["nombre", "cliente: map", "signo"] ["signo"]"#, "{}", out);
    assert_eq!(lines[1], "hola Ana de Salta!", "{}", out);
    assert_eq!(lines[2], "hola Eva de Salta?", "{}", out);
    assert!(lines[3].starts_with("tipo: ") && lines[3].contains("cliente"), "{}", out);
    // Los argumentos siguen siendo datos: una task adentro es error también por nombre.
    std::fs::write(dir.join("p.syn"), "use \"trusted:t\" as t\ntask f()\n    give 1\nprint(call_tool(t.saludo, {\"nombre\": f, \"cliente\": {}}))\n").unwrap();
    let (code, _, err) = synsema(&dir, &["run", "--trusted", "t=t.syn", "p.syn"], None);
    assert!(code != 0 && err.contains("a trusted tool takes data, not code"), "{}", err);
}

/// B10: un prompt privado fuera de una rama dice que el prompt es privado; dentro de una rama
/// privada sigue diciendo la rama.
#[test]
fn b10_read_line_names_a_private_prompt() {
    let dir = project("b10");
    std::fs::write(dir.join("p.syn"), "let p be private(\"clave: \", \"app\")\nlet x be read_line(p)\nprint(\"ok\")\n").unwrap();
    let (code, _, err) = synsema(&dir, &["run", "--labels", "p.syn"], Some("hola\n"));
    assert!(code != 0 && err.contains("the read_line prompt is private (to app)"), "{}", err);
    assert!(!err.contains("under private control flow"), "{}", err);
    std::fs::write(dir.join("p.syn"), "let k be private(1, \"app\")\nwhen k > 0\n    let x be read_line(\"clave: \")\nprint(\"ok\")\n").unwrap();
    let (code, _, err) = synsema(&dir, &["run", "--labels", "p.syn"], Some("hola\n"));
    assert!(code != 0 && err.contains("read_line prompt under private control flow"), "{}", err);
}

/// B11: lo que lee `edit_file` entra en `inputs` (con `--replay` comparado), `synsema test` acepta
/// `--auditor` (un archivo) y `serve` no pierde recibos si se borra el archivo de `--receipt`.
#[test]
fn b11_edit_file_reads_are_inputs() {
    let dir = project("b11-edit");
    std::fs::write(dir.join("a.txt"), "hola mundo").unwrap();
    std::fs::write(
        dir.join("p.syn"),
        "require file(\"a.txt\")\nedit_file(\"a.txt\", \"hola\", \"chau\")\nlet ins be receipt().credentialSubject.inputs\nprint(text(length(ins)) + \" \" + ins[0].source + \" \" + ins[0].what)\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "p.syn"], None);
    assert_eq!((code, out.trim()), (0, "1 edit_file a.txt"), "{}", err);
    // Con el recibo: `--replay` ve un archivo distinto como otra entrada.
    std::fs::write(dir.join("a.txt"), "hola mundo").unwrap();
    std::fs::write(dir.join("p.syn"), "require file(\"a.txt\")\nedit_file(\"a.txt\", \"hola\", \"chau\")\nprint(\"listo\")\n").unwrap();
    let (sk, pk) = auditor_keys();
    let (code, _, err) = synsema(&dir, &["run", "--labels", "--auditor", &pk, "p.syn"], None);
    assert_eq!(code, 0, "{}", err);
    std::fs::write(dir.join("opened.json"), open_receipt(&receipt_in(&err), &sk).to_string()).unwrap();
    std::fs::write(dir.join("a.txt"), "hola mundo").unwrap();
    let (code, _, err) = synsema(&dir, &["run", "--labels", "--replay", "opened.json", "p.syn"], None);
    assert_eq!(code, 0, "{}", err);
    std::fs::write(dir.join("a.txt"), "hola otro mundo").unwrap();
    let (code, _, err) = synsema(&dir, &["run", "--labels", "--replay", "opened.json", "p.syn"], None);
    assert_eq!(code, 1, "--replay no vio que edit_file leyó otro archivo: {}", err);
}

#[test]
fn b11_test_takes_an_auditor_for_one_file() {
    let dir = project("b11-test");
    std::fs::write(dir.join("t.syn"), "test \"suma\"\n    assert_eq(1 + 1, 2)\n").unwrap();
    std::fs::write(dir.join("u.syn"), "test \"resta\"\n    assert_eq(2 - 1, 1)\n").unwrap();
    let (sk, pk) = auditor_keys();
    let (code, out, err) = synsema(&dir, &["test", "--labels", "--auditor", &pk, "t.syn"], None);
    assert_eq!(code, 0, "{}{}", out, err);
    assert!(out.contains("1 passed"), "{}", out);
    let opened = open_receipt(&receipt_in(&err), &sk);
    assert!(opened["header"]["program_sha"].is_string(), "{}", opened);
    let (code, _, err) = synsema(&dir, &["test", "--auditor", &pk, "t.syn", "u.syn"], None);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("--auditor seals one run"), "{}", err);
    // Una clave mala por el knob se nombra como el knob (§C).
    let (code, _, err) = synsema_env(&dir, &["test", "t.syn"], None, &[("SYNSEMA_AUDITOR_KEY", "no-es-una-clave")]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("SYNSEMA_AUDITOR_KEY: ") && !err.contains("--auditor: "), "{}", err);
    // Y en `serve`, que lee la clave por su lado (falla antes de escuchar).
    let (code, _, err) = synsema_env(&dir, &["serve", "t.syn"], None, &[("SYNSEMA_AUDITOR_KEY", "no-es-una-clave")]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("synsema serve: SYNSEMA_AUDITOR_KEY: "), "{}", err);
}

#[test]
fn b11_serve_keeps_receipts_after_the_file_is_deleted() {
    let dir = project("b11-serve");
    let port = free_port();
    std::fs::write(dir.join("app.syn"), format!("require serve({p})\nserve on {p}\n    route \"GET /x\"\n        give \"x\"\n", p = port)).unwrap();
    let (_, pk) = auditor_keys();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["serve", "--auditor", &pk, "--receipt", "r.jsonl", "app.syn"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn synsema serve");
    let t0 = Instant::now();
    let mut ready = false;
    while t0.elapsed() < Duration::from_secs(30) {
        if http_status(port, "/x").is_some_and(|r| r.starts_with("HTTP/1.1 200")) {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let lines = |d: &PathBuf| std::fs::read_to_string(d.join("r.jsonl")).map(|s| s.lines().count()).unwrap_or(0);
    let before = lines(&dir);
    let removed = std::fs::remove_file(dir.join("r.jsonl"));
    let again = http_status(port, "/x").unwrap_or_default();
    let after = lines(&dir);
    let _ = child.kill();
    let _ = child.wait();
    assert!(ready, "el server no levantó");
    assert!(before >= 1, "sin recibos antes de borrar");
    removed.expect("borrar el archivo de recibos");
    assert!(again.starts_with("HTTP/1.1 200"), "{}", again);
    assert_eq!(after, 1, "el recibo del request después de borrar el archivo se perdió");
}

// =========================================================
// §C — mensajes de la tanda de docs v0.6.46
// =========================================================

fn run_src(dir: &PathBuf, src: &str, args: &[&str]) -> (i32, String, String) {
    std::fs::write(dir.join("c.syn"), src).unwrap();
    let mut a = vec!["run"];
    a.extend_from_slice(args);
    a.push("c.syn");
    synsema(dir, &a, None)
}

#[test]
fn c_in_units_names_the_unit_and_the_duration() {
    let dir = project("c-in-units");
    let (code, _, err) = run_src(&dir, "print(in_units(90, \"hours\"))\n", &[]);
    assert!(code != 0 && err.contains("in_units(duration(seconds = 90), \"hours\")"), "{}", err);
    let (code, _, err) = run_src(&dir, "print(in_units(\"10m\", \"seconds\"))\n", &[]);
    assert!(code != 0 && err.contains("in_units() takes a duration, got text") && err.contains("t2 - t1"), "{}", err);
    let (code, _, err) = run_src(&dir, "print(in_units(duration(seconds = 60), \"fortnights\"))\n", &[]);
    assert!(code != 0 && err.contains("unknown unit \"fortnights\"") && err.contains("\"milliseconds\""), "{}", err);
}

#[test]
fn c_declassify_log_says_when_the_principal_is_not_declared() {
    let dir = project("c-inf");
    // Un programa sin `private("P")` no declara principales: antes decía `from […]`.
    let (code, out, err) = run_src(&dir, "print(declassify(1, \"r\"))\n", &["--labels"]);
    assert_eq!((code, out.trim()), (0, "1"), "{}", err);
    assert!(err.contains("(from principals the program does not declare to"), "{}", err);
    let (_, _, err) = run_src(&dir, "let x be private(1, \"ab\")\nprint(declassify(x, \"r\"))\n", &["--labels"]);
    assert!(err.contains("(from [ab] to"), "{}", err);
}

#[test]
fn c_a_require_missing_in_a_trusted_task_points_at_the_task() {
    let dir = project("c-trusted-require");
    std::fs::write(dir.join("t.syn"), "export task anota(x)\n    write_file(\"nota.txt\", x)\n    give \"ok\"\n").unwrap();
    std::fs::write(dir.join("p.syn"), "use \"trusted:t\" as t\nprint(t.anota(\"hola\"))\n").unwrap();
    let (code, _, err) = synsema(&dir, &["run", "--cap-set", "stdout", "--trusted", "t=t.syn", "--trusted-cap-set", "stdout,file.write", "p.syn"], None);
    assert!(code != 0, "{}", err);
    assert!(err.contains("to the task of the trusted module `t`") && !err.contains("program's preamble"), "{}", err);
    assert!(!dir.join("nota.txt").exists());
}

#[test]
fn c_a_cut_receipt_alone_in_its_file_is_named() {
    let dir = project("c-cut");
    std::fs::write(dir.join("p.syn"), "print(\"hola\")\n").unwrap();
    let (_, pk) = auditor_keys();
    let (code, _, err) = synsema(&dir, &["run", "--auditor", &pk, "p.syn"], None);
    assert_eq!(code, 0, "{}", err);
    let r = receipt_in(&err).to_string();
    std::fs::write(dir.join("cut.jsonl"), format!("{}\n", &r[..r.len() / 2])).unwrap();
    let (code, _, err) = synsema(&dir, &["receipt", "verify", "cut.jsonl"], None);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("line 1 of cut.jsonl names a sealed receipt but is not one"), "{}", err);
    std::fs::write(dir.join("vacio.jsonl"), "hola\n").unwrap();
    let (_, _, err) = synsema(&dir, &["receipt", "verify", "vacio.jsonl"], None);
    assert!(err.contains("has no sealed receipt"), "{}", err);
}

#[cfg(windows)]
#[test]
fn c_a_windows_name_ending_in_a_dot_says_why() {
    let dir = project("c-dot");
    std::fs::write(dir.join("a.txt"), "x").unwrap();
    for name in ["a.txt.", "a.txt "] {
        let (code, _, err) = run_src(&dir, &format!("require file.read({:?})\nprint(read_file({:?}))\n", name, name), &[]);
        assert!(code != 0 && err.contains("cannot end in a dot or a space") && !err.contains("broken link"), "{}", err);
    }
}

#[test]
fn c_a_secret_made_by_the_program_in_a_url_is_not_told_to_bind() {
    let dir = project("c-derived-url");
    let src = "require net(\"127.0.0.1\")\nlet s be as_secret(\"abc\", \"S\")\nprint(http_get(\"http://127.0.0.1:9/x?k=\" + s))\n";
    let (code, _, err) = run_src(&dir, src, &[]);
    assert!(code != 0 && err.contains("made by the program") && !err.contains("for net(\"127.0.0.1"), "{}", err);
    // Uno leído de la config sí se puede atar, y el error lo sigue diciendo.
    std::fs::write(dir.join("c.syn"), "require net(\"127.0.0.1\")\nrequire secret(\"S\")\nlet s be secret(\"S\")\nprint(http_get(\"http://127.0.0.1:9/x?k=\" + s))\n").unwrap();
    let (code, _, err) = synsema_env(&dir, &["run", "c.syn"], None, &[("S", "abc")]);
    assert!(code != 0 && err.contains("require secret(\"S\") for net(\"127.0.0.1:9\")"), "{}", err);
    // Uno armado sólo con secrets de la config (`bearer`) sigue siendo de la config.
    std::fs::write(dir.join("c.syn"), "require net(\"127.0.0.1\")\nrequire secret(\"S\")\nprint(http_get(\"http://127.0.0.1:9/x?k=\" + bearer(secret(\"S\"))))\n").unwrap();
    let (code, _, err) = synsema_env(&dir, &["run", "c.syn"], None, &[("S", "abc")]);
    assert!(code != 0 && err.contains("for net(\"127.0.0.1:9\")") && !err.contains("made by the program"), "{}", err);
}

// =========================================================
// Auditoría v0.6.49, ronda 1 (`specs/auditoria-v0.6.49-ronda1.md`)
// =========================================================

/// A1 fila 13: sin `--labels` no hay etiquetas (`private` es un error) y `declassify` es la identidad,
/// sin chequeo, ni bajo techo.
#[test]
fn a1_without_labels_declassify_is_not_checked() {
    let dir = project("a1-nolabels");
    std::fs::write(dir.join("p.syn"), "print(declassify(\"Ana\", \"the name is public\"))\n").unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--cap-set", "stdout,declassify=customers", "p.syn"], None);
    assert_eq!((code, out.trim()), (0, "Ana"), "{}", err);
}

/// M2 (A1 filas 14 y 15): un agente declara sus capabilities; el `require declassify` del preámbulo no
/// le llega, y el corte nombra el agente y dice dónde va la línea.
#[test]
fn r1_m2_an_agent_declares_its_own_declassify() {
    let dir = project("r1-m2");
    let body = "    let c be private({\"name\": \"Ana\"}, \"customers\")\n    print(declassify(c.name, \"public name\"))\nspawn Pub\n";
    let run = |src: String, extra: &[&str]| {
        std::fs::write(dir.join("p.syn"), src).unwrap();
        synsema(&dir, &[&["run", "--labels", "--cap-set", "stdout,declassify=customers"][..], extra, &["p.syn"]].concat(), None)
    };
    // 14) En el preámbulo: no alcanza al agente.
    let d = cut_for_operator(|x| run(format!("require declassify(\"customers\")\nagent Pub\n{}", body), x));
    assert!(d.contains("agent Pub") && d.contains("the program's `require` does not reach it"), "{}", d);
    // 15) En el cuerpo del agente: publica.
    let (code, out, err) = run(format!("agent Pub\n    require declassify(\"customers\")\n{}", body), &[]);
    assert_eq!((code, out.lines().last()), (0, Some("[Pub_0] Ana")), "{}", err);
}

/// M1: `decide` servido por el juez, con datos privados y sin `llm`: el error dice por qué, también
/// con lo privado (antes salía `private(customers)`).
#[test]
fn r1_m1_judge_decide_on_private_data_says_why_it_needs_llm() {
    let dir = project("r1-m1");
    std::fs::write(
        dir.join("p.syn"),
        "require judge(\"customers\")\nlet c be private(\"ana\", \"customers\")\nlet d be decide between [\"alpha\", \"beta\"] given c\nprint(label_of(d))\n",
    )
    .unwrap();
    let env = [("SYNSEMA_JUDGE_PROVIDER", "mock"), ("SYNSEMA_JUDGE_DECIDE", "1"), ("SYNSEMA_ENV_FILE", "")];
    let (code, out, err) = synsema_env(&dir, &["run", "--labels", "--cap-set", "stdout,judge=customers@local,judge", "p.syn"], None, &env);
    assert!(code != 0 && out.is_empty(), "{}", out);
    assert!(err.contains("p.syn:3:") && err.contains("falls back to the model") && err.contains("needs `llm`"), "{}", err);
    assert!(!err.contains("private(customers)"), "{}", err);
}

/// M3 (A7 fila 9): el recibo graba el sha de cada módulo `--trusted`, y `--replay` lo compara.
#[test]
fn r1_m3_replay_compares_the_trusted_modules() {
    let dir = project("r1-m3");
    std::fs::write(dir.join("p.syn"), "use \"trusted:t\" as t\nprint(t.v())\n").unwrap();
    std::fs::write(dir.join("t.syn"), "export task v()\n    give 1\n").unwrap();
    let (sk, pk) = auditor_keys();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "--auditor", &pk, "--trusted", "t=t.syn", "p.syn"], None);
    assert_eq!((code, out.trim()), (0, "1"), "{}", err);
    let opened = open_receipt(&receipt_in(&err), &sk);
    assert!(opened["header"]["trusted"]["t"].as_str().is_some_and(|s| s.len() == 64), "{}", opened["header"]);
    std::fs::write(dir.join("opened.json"), opened.to_string()).unwrap();
    let replay = |extra: &[&str]| synsema(&dir, &[&["run", "--labels", "--replay", "opened.json"][..], extra, &["p.syn"]].concat(), None);
    // La misma tool: coincide.
    let (code, _, err) = replay(&["--trusted", "t=t.syn"]);
    assert_eq!(code, 0, "{}", err);
    assert!(err.contains("inputs match the recorded run") && !err.contains("not a verification"), "{}", err);
    // La tool cambiada: no corre.
    std::fs::write(dir.join("t.syn"), "export task v()\n    give 2\n").unwrap();
    let (code, out, err) = replay(&["--trusted", "t=t.syn"]);
    assert_eq!(code, 2, "{}", err);
    assert!(out.is_empty() && err.contains("trusted modules") && err.contains("--replay-any-program"), "{}{}", out, err);
    // Con el flag corre, y no es una verificación.
    let (code, out, err) = replay(&["--trusted", "t=t.syn", "--replay-any-program"]);
    assert_eq!((code, out.trim()), (0, "2"), "{}", err);
    assert!(err.contains("(another program: not a verification)"), "{}", err);
    // Otro nombre de módulo tampoco es la corrida grabada.
    let (code, _, err) = replay(&["--trusted", "u=t.syn"]);
    assert_eq!(code, 2, "{}", err);
}

/// B3 (A7 fila 8): una corrida que termina con `exit(n)` se compara hasta el final.
#[test]
fn r1_b3_replay_of_an_exit_compares_to_the_end() {
    let dir = project("r1-b3");
    let src = "require time\nlet t be now()\nexit(3)\n";
    record(&dir, src, &[]);
    let (code, _, err) = replay(&dir, src, &[]);
    assert_eq!(code, 3, "{}", err);
    assert!(err.contains("replay: the 0 inputs match the recorded run (same seed, the same 1 clock reading), ended with exit(3)"), "{}", err);
    assert!(!err.contains("stopped with an error"), "{}", err);
}

/// B2 — A3 filas 2, 4, 6 y 6b.
#[test]
fn r1_b2_a3_rows_that_had_no_test() {
    let dir = project("r1-b2-a3");
    let (_, pk) = auditor_keys();
    let seed = ("S", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    // 2) `hd_derive` en una rama privada, con auditor.
    std::fs::write(
        dir.join("p.syn"),
        "require secret(\"S\")\nrequire wallet(\"S\")\nlet s be secret(\"S\")\nlet k be private(1, \"app\")\nwhen k > 0\n    let d be hd_derive(s, \"m/44'/60'/0'/0/0\")\nprint(\"done\")\n",
    )
    .unwrap();
    let (code, out, err) = synsema_env(&dir, &["run", "--labels", "--auditor", &pk, "--receipt", "r.json", "p.syn"], None, &[seed]);
    assert!(code != 0 && !out.contains("done"), "{}", out);
    assert!(err.contains(A3_CREATED), "{}", err);
    // 4) `ks[i]` con `i` privado.
    std::fs::write(
        dir.join("p.syn"),
        "let ks be [as_secret(\"a\", \"A\"), as_secret(\"b\", \"B\")]\nlet i be private(0, \"app\")\nlet k be ks[i]\nprint(\"done\")\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "p.syn"], None);
    assert!(code != 0 && !out.contains("done"), "{}", out);
    assert!(err.contains("a secret cannot be made from, combined with or chosen by a private value"), "{}", err);
    // 6) `reveal` sin auditor: lo corta el sumidero, con su texto.
    std::fs::write(
        dir.join("p.syn"),
        "require secret(\"S\")\nlet s be secret(\"S\")\nlet k be private(1, \"app\")\nwhen k > 0\n    print(reveal(s))\nprint(\"done\")\n",
    )
    .unwrap();
    let (code, out, err) = synsema_env(&dir, &["run", "--labels", "p.syn"], None, &[seed]);
    assert!(code != 0 && !out.contains("done"), "{}", out);
    assert!(err.contains("reveal called under private control flow"), "{}", err);
    // 6b) Una operación de wallet sin auditor: `audited_in_private_branch`, no `private(app)`.
    std::fs::write(
        dir.join("p.syn"),
        "require wallet(\"W\")\nlet k be private(1, \"app\")\nwhen k > 0\n    let m be mnemonic_generate(12, \"W\")\nprint(\"done\")\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "p.syn"], None);
    assert!(code != 0 && !out.contains("done"), "{}", out);
    assert!(err.contains("label_violation: wallet writes the audit log"), "{}", err);
    assert!(!err.contains("private(app)"), "{}", err);
}

/// B2 — A9 fila 4: el techo no nombra al principal; la llamada se rechaza y `llm-data` queda negada.
#[test]
fn r1_b2_a9_a_ceiling_without_the_principal_denies_llm_data() {
    let (port, seen) = fake_model();
    let dir = project("r1-b2-a9");
    let audit = dir.join("a.jsonl");
    let audit_s = audit.to_string_lossy().into_owned();
    let src = "require llm(\"p\")\nlet x be private(\"dato\", \"p\")\nlet r be reason x\nprint(\"done\")\n";
    let (code, out, err) = e5(&dir, port, src, &["--cap-set", "stdout,llm=q@127.0.0.1", "--audit", &audit_s], &[]);
    assert!(code != 0 && !out.contains("done"), "{}", out);
    let reasons = llm_data_reasons(&audit);
    assert!(!reasons.is_empty() && reasons.iter().all(|r| r.contains("| false |")), "{:?} {}", reasons, err);
    assert!(seen.lock().unwrap().is_empty(), "el dato llegó al modelo");
}

// =========================================================
// Auditoría v0.6.49, ronda 2
// =========================================================

/// M1 y B2 (C filas 2 y 5): el chequeo de `llm` corre antes de evaluar `given`, así que un `given`
/// que opera sobre lo privado no lo redacta; el remedio nombra la forma con principal.
#[test]
fn r2_m1_judge_decide_checks_llm_before_the_given() {
    let dir = project("r2-m1");
    let env = [("SYNSEMA_JUDGE_PROVIDER", "mock"), ("SYNSEMA_JUDGE_DECIDE", "1"), ("SYNSEMA_ENV_FILE", "")];
    for (c, given) in [("private({\"name\": \"ana\"}, \"customers\")", "c.name"), ("private(\"ana\", \"customers\")", "\"cliente: \" + c")] {
        std::fs::write(
            dir.join("p.syn"),
            format!("require judge(\"customers\")\nlet c be {}\nlet d be decide between [\"alpha\", \"beta\"] given {}\nprint(label_of(d))\n", c, given),
        )
        .unwrap();
        let (code, out, err) = synsema_env(&dir, &["run", "--labels", "--cap-set", "stdout,judge=customers@local,judge", "p.syn"], None, &env);
        assert!(code != 0 && out.is_empty(), "{}: {}", given, out);
        assert!(err.contains("p.syn:3:") && err.contains("falls back to the model"), "{}: {}", given, err);
        assert!(!err.contains("private(customers)"), "{}: {}", given, err);
        assert!(err.contains("require llm(\"<principal>\")") && err.contains("llm=<principal>@<provider host>"), "{}: {}", given, err);
    }
}

/// B1 (C fila 3): bajo una rama privada el primer error es el del sumidero, el de fondo.
#[test]
fn r2_b1_judge_decide_under_a_private_branch_says_the_branch() {
    let dir = project("r2-b1");
    std::fs::write(
        dir.join("p.syn"),
        "require judge(\"customers\")\nlet c be private(\"ana\", \"customers\")\nwhen c == \"ana\"\n    let d be decide between [\"alpha\", \"beta\"] given \"x\"\nprint(\"fin\")\n",
    )
    .unwrap();
    let env = [("SYNSEMA_JUDGE_PROVIDER", "mock"), ("SYNSEMA_JUDGE_DECIDE", "1"), ("SYNSEMA_ENV_FILE", "")];
    let d = cut_for_operator(|x| {
        synsema_env(&dir, &[&["run", "--labels", "--cap-set", "stdout,judge=customers@local,judge"][..], x, &["p.syn"]].concat(), None, &env)
    });
    assert!(d.contains("called under private control flow"), "{}", d);
}

/// B3 (A1 filas 16–19): el texto de la denegación nombra el lugar donde va la línea con un
/// `parallel_map` dentro de un agente y con una task de confianza que llama un agente.
#[test]
fn r2_b3_the_refusal_names_where_the_line_goes() {
    let dir = project("r2-b3");
    let ceiling = ["--cap-set", "stdout,declassify=customers"];
    let run = |src: &str, extra: &[&str]| {
        std::fs::write(dir.join("p.syn"), src).unwrap();
        synsema(&dir, &[&["run", "--labels"][..], &ceiling, extra, &["p.syn"]].concat(), None)
    };
    let task = "task pub(i)\n    let c be private({\"name\": \"Ana\" + text(i)}, \"customers\")\n    give declassify(c.name, \"public name\")\n";
    // 16) `parallel_map` dentro de un agente, sin `require` o con el del preámbulo.
    for pre in ["", "require declassify(\"customers\")\n"] {
        let src = format!("{}{}agent Pub\n    print(parallel_map(pub, [1, 2]))\nspawn Pub\n", pre, task);
        let d = cut_for_operator(|x| run(&src, x));
        assert!(d.contains("in the program's preamble, or in the body of the agent that runs this code"), "{}", d);
        // Ronda 3 (B1): `spawn` lanza un agente, que declara los suyos: no hereda.
        assert!(!d.contains("spawn"), "{}", d);
    }
    // 17) Con el `require` en el agente: publica.
    let src = format!("{}agent Pub\n    require declassify(\"customers\")\n    print(parallel_map(pub, [1, 2]))\nspawn Pub\n", task);
    let (code, out, err) = run(&src, &[]);
    assert_eq!((code, out.lines().last()), (0, Some("[Pub_0] [\"Ana1\", \"Ana2\"]")), "{}", err);
    // 18) Una task de confianza llamada desde un agente que ya tiene su `require`: lo que falta es
    // el de la task.
    let agent = "agent Pub\n    require declassify(\"customers\")\n    use \"trusted:t\" as t\n    let c be private({\"name\": \"Ana\"}, \"customers\")\n    print(t.pub(c))\nspawn Pub\n";
    let trusted = ["--trusted", "t=t.syn", "--trusted-cap-set", "stdout,declassify=customers"];
    std::fs::write(dir.join("t.syn"), "export task pub(c)\n    give declassify(c.name, \"public name\")\n").unwrap();
    let d = cut_for_operator(|x| run(agent, &[&trusted[..], x].concat()));
    assert!(d.contains("to the exported task that runs it") && d.contains("--trusted-cap-set declassify=<principal>"), "{}", d);
    assert!(!d.contains("agent Pub"), "{}", d);
    // 19) Con el `require` en la task: publica.
    std::fs::write(dir.join("t.syn"), "export task pub(c)\n    require declassify(\"customers\")\n    give declassify(c.name, \"public name\")\n").unwrap();
    let (code, out, err) = run(agent, &trusted);
    assert_eq!((code, out.lines().last()), (0, Some("[Pub_0] Ana")), "{}", err);
}

/// B4 (A7 fila 10): una diferencia sale con 1 aunque la corrida termine con `exit(n)`.
#[test]
fn r2_b4_a_difference_exits_with_1_even_after_exit() {
    let dir = project("r2-b4");
    let src = "require time\nrequire file.read\nwhen file_exists(\"flag.txt\")\n    let a be now()\n    let b be read_file(\"flag.txt\")\nexit(3)\n";
    std::fs::write(dir.join("flag.txt"), "hola\n").unwrap();
    record(&dir, src, &[]);
    std::fs::remove_file(dir.join("flag.txt")).unwrap();
    let (code, _, err) = replay(&dir, src, &[]);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("replay: the run read 0 of the 1 inputs of the recorded run, ended with exit(3)"), "{}", err);
}

/// B5 (A2 fila 3): un bucle público no mueve el reloj cercado y una lectura de afuera con el PC
/// público sí. `read_file` es también un sumidero (lo mueven los dos momentos); `read_line` no lo
/// es, y lo mueve sólo la entrada de linaje; `write_file` es sumidero y no entrada.
#[test]
fn r2_b5_a_public_read_is_a_public_moment() {
    let dir = project("r2-b5");
    std::fs::write(dir.join("dato.txt"), "hola\n").unwrap();
    let (_, pk) = auditor_keys();
    for (read, stdin) in [("read_file(\"dato.txt\")", None), ("read_line()", Some("hola\n")), ("write_file(\"out.txt\", \"x\")", None)] {
        std::fs::write(
            dir.join("p.syn"),
            format!("require time\nrequire file.read\nrequire file.write\nlet a be now()\nlet i be 0\nwhile i < 20000\n    set i to i + 1\nlet a2 be now()\nlet x be {}\nlet b be now()\nprint(text(a == a2) + \" \" + text(a2 == b))\n", read),
        )
        .unwrap();
        let (code, out, err) = synsema(&dir, &["run", "--labels", "--auditor", &pk, "p.syn"], stdin);
        assert_eq!((code, out.lines().last()), (0, Some("true false")), "{}: {}", read, err);
    }
}

/// N2 (A7 filas 9 y 9b): un recibo con `trusted` contra una corrida sin `--trusted`, y uno sin el
/// campo contra una corrida con `--trusted`.
#[test]
fn r2_n2_replay_with_trusted_on_one_side_only() {
    let dir = project("r2-n2");
    std::fs::write(dir.join("p.syn"), "use \"trusted:t\" as t\nprint(t.v())\n").unwrap();
    std::fs::write(dir.join("t.syn"), "export task v()\n    give 1\n").unwrap();
    let (sk, pk) = auditor_keys();
    let (code, _, err) = synsema(&dir, &["run", "--labels", "--auditor", &pk, "--trusted", "t=t.syn", "p.syn"], None);
    assert_eq!(code, 0, "{}", err);
    let mut opened = open_receipt(&receipt_in(&err), &sk);
    std::fs::write(dir.join("opened.json"), opened.to_string()).unwrap();
    // 9) El recibo lo tiene y la corrida no.
    let (code, out, err) = synsema(&dir, &["run", "--labels", "--replay", "opened.json", "p.syn"], None);
    assert_eq!(code, 2, "{}", err);
    assert!(out.is_empty() && err.contains("trusted modules") && err.contains("(none)"), "{}{}", out, err);
    // 9b) Un recibo viejo, sin el campo, y la corrida con `--trusted`.
    opened["header"].as_object_mut().unwrap().remove("trusted");
    std::fs::write(dir.join("opened.json"), opened.to_string()).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "--replay", "opened.json", "--trusted", "t=t.syn", "p.syn"], None);
    assert_eq!(code, 2, "{}", err);
    assert!(out.is_empty() && err.contains("trusted modules") && err.contains("(none)"), "{}{}", out, err);
}

// =========================================================
// Auditoría v0.6.49, ronda 3
// =========================================================

/// B1 (A1 fila 20): un agente lanzado por otro declara los suyos; el `require` del de afuera no le
/// llega y la denegación lo nombra a él.
#[test]
fn r3_b1_an_agent_spawned_by_another_declares_its_own() {
    let dir = project("r3-b1");
    // El `sleep(2)` espera a `Sub`: si `Pub` termina antes, la salida de `Sub` se pierde (fuera de
    // alcance de v0.6.49; queda en la lista de la versión siguiente).
    let run = |sub_require: &str, extra: &[&str]| {
        std::fs::write(
            dir.join("p.syn"),
            format!(
                "agent Pub\n    require declassify(\"customers\")\n    require time\n    agent Sub\n{}        let c be private({{\"name\": \"Ana\"}}, \"customers\")\n        print(declassify(c.name, \"public name\"))\n    spawn Sub\n    sleep(2)\nspawn Pub\n",
                sub_require
            ),
        )
        .unwrap();
        synsema(&dir, &[&["run", "--labels", "--cap-set", "stdout,declassify=customers,time"][..], extra, &["p.syn"]].concat(), None)
    };
    let d = cut_for_operator(|x| run("", x));
    assert!(d.contains("to the body of agent Sub"), "{}", d);
    let (code, out, err) = run("        require declassify(\"customers\")\n", &[]);
    assert!(code == 0 && out.contains("] Ana"), "{}{}", out, err);
}

/// B2 (A1 fila 21): un `declassify` en el nivel superior de un módulo de confianza: el texto dice que
/// se lo mueva a una task exportada (ahí no se puede declarar nada).
#[test]
fn r3_b2_a_declassify_at_the_top_of_a_trusted_module() {
    let dir = project("r3-b2");
    std::fs::write(dir.join("p.syn"), "use \"trusted:t\" as t\nprint(t.v())\n").unwrap();
    std::fs::write(
        dir.join("t.syn"),
        "let c be private({\"name\": \"Ana\"}, \"customers\")\nexport let NAME be declassify(c.name, \"public name\")\nexport task v()\n    give NAME\n",
    )
    .unwrap();
    let d = cut_for_operator(|x| {
        synsema(
            &dir,
            &[&["run", "--labels", "--cap-set", "stdout,declassify=customers", "--trusted", "t=t.syn", "--trusted-cap-set", "stdout,declassify=customers"][..], x, &["p.syn"]].concat(),
            None,
        )
    });
    assert!(d.starts_with("trusted:t:2:") && d.contains("while the module loads nothing is declared, not even by a task its top level calls: move the declassify into an exported task and call it from the program"), "{}", d);
}

// ── Auditoría v0.6.49, ronda 4 ──────────────────────────────────────────────────────────────────

/// B1 (A1 fila 22): el nivel superior de un módulo de confianza llama, al cargarlo, a una task
/// exportada que ya tiene su `require`. La carga no concede nada: el texto dice que la llame el
/// programa. Llamada desde el programa, publica.
#[test]
fn r4_b1_a_task_called_while_the_trusted_module_loads() {
    let dir = project("r4-b1");
    let run = |top: &str, prog: &str, extra: &[&str]| {
        std::fs::write(dir.join("p.syn"), prog).unwrap();
        std::fs::write(
            dir.join("t.syn"),
            format!("export task pub(c)
    require declassify(\"customers\")
    give declassify(c.name, \"public name\")
{}", top),
        )
        .unwrap();
        synsema(
            &dir,
            &[&["run", "--labels", "--cap-set", "stdout,declassify=customers", "--trusted", "t=t.syn", "--trusted-cap-set", "stdout,declassify=customers"][..], extra, &["p.syn"]].concat(),
            None,
        )
    };
    let d = cut_for_operator(|x| {
        run(
            "let k be private({\"name\": \"Ana\"}, \"customers\")
export let N be pub(k)
",
            "use \"trusted:t\" as t
print(t.N)
",
            x,
        )
    });
    assert!(d.starts_with("trusted:t:3:") && d.contains("not even by a task its top level calls") && d.contains("call it from the program"), "{}", d);
    let (code, out, err) = run("", "use \"trusted:t\" as t
let c be private({\"name\": \"Ana\"}, \"customers\")
print(t.pub(c))
", &[]);
    assert!(code == 0 && out.contains("Ana"), "{}{}", out, err);
}

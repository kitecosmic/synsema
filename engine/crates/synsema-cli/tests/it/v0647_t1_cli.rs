//! v0.6.47 (T1) — el texto de un corte de etiquetas no dice qué sitio falló cuando el código no es del
//! que corre el binario. El dato privado elige cuál de N sitios corta la corrida; con un techo
//! (`--cap-set`, `--sandbox`, `--deterministic`, `--trusted`) el stderr de `synsema run` es lo que un
//! agente le devuelve al modelo, así que sale el mismo texto para cualquier sitio, y el detalle va al
//! recibo sellado. Sin techo, quien corre el binario escribió el programa: el texto de siempre.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-v0647-t1-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn synsema(dir: &PathBuf, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(args)
        .current_dir(dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdin(Stdio::null())
        .output()
        .expect("spawn synsema");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Seis sitios de tipos distintos, uno por valor del dato: asignar a una variable pública, imprimir,
/// escribir un archivo (un sumidero con efecto), `exit`, un `raise` bajo la rama privada y la red.
const SITES: [&str; 6] = [
    "set a to 1",
    "print(\"x\")",
    "write_file(\"o.txt\", \"x\")",
    "exit(3)",
    "raise \"boom\"",
    "http_get(\"http://127.0.0.1:9/x\")",
];

fn sitio(k: usize) -> String {
    let mut src = format!("let s be private({}, \"app\")\nlet a be 0\n", k);
    for (i, site) in SITES.iter().enumerate() {
        src.push_str(&format!("when s == {}\n    {}\n", i, site));
    }
    src
}

const FIXED: &str = "Runtime error: label_violation: the flow checker stopped the run (private to app); what failed, where and how to fix it go to the operator, not to the program";

#[test]
fn with_a_ceiling_every_site_gives_the_same_text_and_exit_code() {
    let dir = project("ceiling");
    let mut seen = Vec::new();
    for k in 0..SITES.len() {
        std::fs::write(dir.join("sitio.syn"), sitio(k)).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "--labels", "--cap-set", "stdout,file.write,net=127.0.0.1", "sitio.syn"]);
        assert_ne!(code, 0, "sitio {}: tenía que cortar\n{}{}", k, out, err);
        assert!(!dir.join("o.txt").exists(), "sitio {}: el archivo no se escribe", k);
        assert_eq!(err.trim(), FIXED, "sitio {}: el texto fijo y nada más", k);
        seen.push((code, out, err));
    }
    for (k, s) in seen.iter().enumerate() {
        assert_eq!(s, &seen[0], "el sitio {} se distingue del 0 (código, stdout o stderr)", k);
    }
    // Los demás techos, lo mismo.
    std::fs::write(dir.join("sitio.syn"), sitio(0)).unwrap();
    for args in [vec!["--sandbox"], vec!["--deterministic"]] {
        let mut a = vec!["run", "--labels"];
        a.extend(args.iter().copied());
        a.push("sitio.syn");
        let (code, _, err) = synsema(&dir, &a);
        assert_ne!(code, 0);
        assert_eq!(err.trim(), FIXED, "{:?}", args);
    }
}

#[test]
fn without_a_ceiling_the_owner_gets_the_site_and_the_fix() {
    let dir = project("owner");
    std::fs::write(dir.join("sitio.syn"), sitio(0)).unwrap();
    let (code, _, err) = synsema(&dir, &["run", "--labels", "sitio.syn"]);
    assert_ne!(code, 0);
    assert!(err.contains("sitio.syn:4:5:") && err.contains("cannot assign to 'a'"), "{}", err);
    std::fs::write(dir.join("sitio.syn"), sitio(1)).unwrap();
    let (_, _, err) = synsema(&dir, &["run", "--labels", "sitio.syn"]);
    assert!(err.contains("sitio.syn:6:") && err.contains("print called under private control flow"), "{}", err);
}

/// Con techo y auditor, el detalle va al sobre del recibo: lo abre el auditor, no el programa.
#[test]
fn with_a_ceiling_the_detail_goes_to_the_sealed_receipt() {
    let dir = project("receipt");
    let (sk, pk) = synsema_stdlib::sealed::generate_keypair();
    std::fs::write(dir.join("sitio.syn"), sitio(0)).unwrap();
    let (code, _, err) = synsema(&dir, &["run", "--labels", "--cap-set", "stdout", "--auditor", &pk, "sitio.syn"]);
    assert_ne!(code, 0);
    assert!(err.contains(FIXED) && !err.contains("cannot assign"), "{}", err);
    let receipt = err
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v.get("synsema_receipt").is_some())
        .last()
        .unwrap_or_else(|| panic!("no hay recibo en stderr:\n{}", err));
    assert!(!receipt.to_string().contains("cannot assign"), "el detalle no va en claro en el recibo");
    let sk = synsema_core::bytesutil::b64url_decode(&sk).unwrap();
    let opened = synsema_stdlib::sealed::open_receipt(&receipt, &sk).expect("el auditor abre el recibo");
    let entries = opened["entries"].as_array().unwrap();
    assert!(
        entries.iter().any(|e| e["sealed"] == true
            && e["entry"]["kind"] == "label_violation"
            && e["entry"]["detail"].as_str().is_some_and(|d| d.contains("sitio.syn:4:5:") && d.contains("cannot assign to 'a'"))),
        "{:?}",
        entries
    );
}

/// `synsema test` sigue la misma regla: con techo el texto fijo, sin techo el sitio.
#[test]
fn synsema_test_gives_the_fixed_text_with_a_ceiling_and_the_site_without() {
    let dir = project("test-cmd");
    std::fs::write(dir.join("t.syn"), "let s be private(1, \"app\")\ntest \"corte\"\n    when s == 1\n        print(\"x\")\n").unwrap();
    let (code, out, err) = synsema(&dir, &["test", "--labels", "--cap-set", "stdout", "t.syn"]);
    let all = out + &err;
    assert!(code != 0 && all.contains(FIXED.trim_start_matches("Runtime error: ")) && !all.contains("print called"), "{}", all);
    let (code, out, err) = synsema(&dir, &["test", "--labels", "t.syn"]);
    let all = out + &err;
    assert!(code != 0 && all.contains("print called under private control flow"), "{}", all);
}

/// Diez agentes por dígito: el que se corta es el dígito. `agents()` lo delataba y el principal
/// imprimía la tarjeta en una corrida (A1 de la auditoría de T1).
fn agentes(secret: &str, digits: usize) -> String {
    let mut s = format!("let t be private(\"{}\", \"app\")\n", secret);
    for i in 0..digits {
        for d in 0..10 {
            // Después de la rama, un `print` público: el eco en vivo delataba quién sobrevivió.
            s.push_str(&format!("agent P{i}_{d}\n    when t[{i}] == \"{d}\"\n        print(\"x\")\n    print(\"vivo\")\n"));
        }
    }
    for i in 0..digits {
        for d in 0..10 {
            s.push_str(&format!("spawn P{i}_{d}\n"));
        }
    }
    s.push_str(&format!(
        "let n be 0\nlet listos be 0\nwhile listos < {total} and n < 2000000\n    set n to n + 1\n    set listos to 0\n    each a in agents()\n        when a.state == \"error\" or a.state == \"done\"\n            set listos to listos + 1\nlet dig be []\neach i in range({digits})\n    each a in agents()\n        when a.state == \"error\" and starts_with(a.name, \"P\" + text(i) + \"_\")\n            set dig to dig + [replace(a.name, \"P\" + text(i) + \"_\", \"\")]\nprint(\"recuperado: \" + join(dig, \"\"))\n",
        total = digits * 10
    ));
    s
}

#[test]
fn an_agent_cut_by_labels_stops_the_whole_run() {
    let dir = project("agentes");
    let mut seen = Vec::new();
    for secret in ["4539148803436467", "1234567890123456"] {
        std::fs::write(dir.join("a.syn"), agentes(secret, 2)).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "--labels", "--cap-set", "stdout", "a.syn"]);
        assert_ne!(code, 0, "{}{}", out, err);
        assert!(!out.contains("recuperado") && !out.contains("vivo") && !out.contains("[P"), "{}", out);
        assert_eq!(err.trim(), FIXED, "ni qué agente falló ni su sitio: {}", err);
        seen.push((code, out, err));
    }
    assert_eq!(seen[0], seen[1], "dos tarjetas distintas se distinguen");
    // Sin techo, el dueño ve qué agente y qué sitio.
    std::fs::write(dir.join("a.syn"), agentes("4539148803436467", 1)).unwrap();
    let (code, _, err) = synsema(&dir, &["run", "--labels", "a.syn"]);
    assert!(code != 0 && err.contains("agent P0_4") && err.contains("print called under private control flow"), "{}", err);
}

/// Sin corte, el eco retenido de los agentes sale al final, como siempre.
#[test]
fn without_a_cut_the_held_echo_of_the_agents_comes_out() {
    let dir = project("eco");
    std::fs::write(
        dir.join("e.syn"),
        "let t be private(\"4\", \"app\")\nagent A\n    when t == \"9\"\n        print(\"x\")\n    print(\"vivo\")\nspawn A\nprint(\"fin\")\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "--cap-set", "stdout", "e.syn"]);
    assert_eq!(code, 0, "{}{}", out, err);
    assert!(out.contains("[A_0] vivo") && out.contains("fin"), "{}", out);
}

/// Un agente cortado dentro de un bloque `test` corta la suite entera con un solo outcome.
#[test]
fn an_agent_cut_in_a_test_block_stops_the_suite() {
    let dir = project("test-agentes");
    let mut seen = Vec::new();
    for k in [3, 7] {
        std::fs::write(
            dir.join("t.syn"),
            format!(
                "let s be private({k}, \"app\")\nagent Siete\n    when s == 7\n        print(\"x\")\ntest \"uno\"\n    spawn Siete\ntest \"dos\"\n    let z be 1\n"
            ),
        )
        .unwrap();
        let (code, out, err) = synsema(&dir, &["test", "--labels", "--cap-set", "stdout", "t.syn"]);
        seen.push((k, code, out, err));
    }
    let (_, c3, o3, e3) = &seen[0];
    let (_, c7, o7, e7) = &seen[1];
    assert_eq!(*c3, 0, "con s=3 nadie corta: {}{}", o3, e3);
    assert!(*c7 != 0 && (o7.clone() + e7).contains("labels: the run was stopped") && !(o7.clone() + e7).contains("Siete"), "{}{}", o7, e7);
}

/// Después del corte de un agente, ningún efecto de la corrida sale (todo sumidero da el corte),
/// aunque el principal no mire `agents()`.
#[test]
fn after_an_agent_cut_no_effect_of_the_run_goes_out() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let dir = project("efecto");
    std::fs::write(
        dir.join("e.syn"),
        format!(
            "require net(\"127.0.0.1\")\nrequire time\nlet t be private(\"7\", \"app\")\nagent A\n    when t == \"7\"\n        print(\"x\")\nspawn A\nsleep(1)\nlet r be http_post(\"http://127.0.0.1:{port}/x\", {{\"hola\": 1}})\n"
        ),
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "--cap-set", "stdout,time,net=127.0.0.1", "e.syn"]);
    assert_ne!(code, 0, "{}{}", out, err);
    assert_eq!(err.trim(), FIXED, "{}", err);
    assert!(listener.accept().is_err(), "salió un request después del corte del agente");
}

/// Un corte antes de toda salida y uno después dan la misma salida (la línea fija): si no, «hubo
/// líneas antes del corte» sería un bit que elige el privado.
#[test]
fn a_cut_before_any_output_looks_like_a_cut_after_it() {
    let dir = project("prefijo");
    let mut seen = Vec::new();
    for k in 1..=2 {
        std::fs::write(
            dir.join(format!("p{k}.syn")),
            format!("let s be private({k}, \"app\")\nwhen s == 1\n    print(\"x\")\nprint(\"antes\")\nwhen s == 2\n    print(\"y\")\n"),
        )
        .unwrap();
        let f = format!("p{k}.syn");
        seen.push(synsema(&dir, &["run", "--labels", "--cap-set", "stdout", &f]));
    }
    assert_eq!(seen[0], seen[1]);
    assert!(seen[0].1.contains("its output is withheld"), "{:?}", seen[0]);
}

/// Ronda 2: `conform --swarm` pasa por el mismo cierre. Con un corte de un agente, el JSON no trae los
/// estados ni el blackboard, y es el mismo para cualquier agente que corte.
#[test]
fn conform_swarm_closes_like_run() {
    let dir = project("conform");
    let src = |d: u8| {
        let mut s = format!("let t be private(\"{d}\", \"app\")\n");
        for k in 0..3 {
            s.push_str(&format!("agent P{k}\n    when t == \"{k}\"\n        print(\"x\")\n"));
        }
        s + "spawn P0\nspawn P1\nspawn P2\n"
    };
    let mut seen = Vec::new();
    for d in [0u8, 2] {
        std::fs::write(dir.join(format!("c{d}.syn")), src(d)).unwrap();
        seen.push(synsema(&dir, &["conform", "--swarm", "--labels", "--cap-set", "stdout", &format!("c{d}.syn")]));
    }
    assert_eq!(seen[0], seen[1]);
    let out = &seen[0].1;
    assert!(out.contains("\"ok\": false") && out.contains("\"agents\": {}") && out.contains("\"blackboard\": {}"), "{}", out);
    // Sin corte, el volcado de siempre.
    std::fs::write(dir.join("c9.syn"), src(9)).unwrap();
    let (_, out, _) = synsema(&dir, &["conform", "--swarm", "--labels", "--cap-set", "stdout", "c9.syn"]);
    assert!(out.contains("\"ok\": true") && out.contains("\"P0_0\":\"DONE\""), "{}", out);
}

/// Ronda 2: el stderr del principal y de los agentes sale al cierre de la corrida, no cuando termina
/// cada uno; con un corte (de un agente o del principal) no sale nada, ni el eco de los agentes.
#[test]
fn stderr_and_echo_are_held_until_the_run_closes() {
    let dir = project("stderr");
    let src = |who: &str, k: u8| {
        format!(
            "let t be private({k}, \"app\")\nagent W\n    eprint(\"testigo\")\n    print(\"eco\")\nagent C\n    let n be 0\n    while n < 20000\n        set n to n + 1\n    {cut_agent}\nspawn W\nspawn C\neprint(\"principal\")\nlet m be 0\nwhile m < 40000\n    set m to m + 1\n{cut_main}\n",
            cut_agent = if who == "agente" { "when t == 1\n        print(\"x\")" } else { "print(\"c\")" },
            cut_main = if who == "principal" { "when t == 1\n    print(\"x\")" } else { "print(\"fin\")" },
        )
    };
    for who in ["agente", "principal"] {
        std::fs::write(dir.join("s.syn"), src(who, 1)).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "--labels", "--cap-set", "stdout", "s.syn"]);
        assert_ne!(code, 0, "{}", who);
        assert_eq!(err.trim(), FIXED, "{}: {}", who, err);
        assert!(out.contains("its output is withheld") && !out.contains("eco"), "{}: {}", who, out);
        std::fs::write(dir.join("s.syn"), src(who, 0)).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "--labels", "--cap-set", "stdout", "s.syn"]);
        assert_eq!(code, 0, "{}: {}{}", who, out, err);
        assert!(err.contains("testigo") && err.contains("principal") && out.contains("[W_0] eco"), "{}: {} / {}", who, out, err);
    }
}

/// Ronda 2: el prompt de `read_line` se junta como `print` bajo etiquetas: con un corte no sale.
#[test]
fn the_read_line_prompt_is_held_like_print() {
    let dir = project("readline");
    let src = |k: u8| format!("let t be private({k}, \"app\")\neach i in range(3)\n    let l be read_line(\"prompt\")\n    when t == i\n        print(\"x\")\n");
    std::fs::write(dir.join("r.syn"), src(1)).unwrap();
    let (code, out, _) = synsema(&dir, &["run", "--labels", "--cap-set", "stdout", "r.syn"]);
    assert!(code != 0 && !out.contains("prompt"), "{}", out);
    std::fs::write(dir.join("r.syn"), src(9)).unwrap();
    let (code, out, _) = synsema(&dir, &["run", "--labels", "--cap-set", "stdout", "r.syn"]);
    assert_eq!((code, out.matches("prompt").count()), (0, 3), "{}", out);
}

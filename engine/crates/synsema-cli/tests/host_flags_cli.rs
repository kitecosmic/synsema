//! E2E del binario real (spec `specs/tanda-motor-lamps.md`): los flags del host comunes
//! (`--sandbox`/`--cap-set`/`--profile`/`--audit`), `conform` honrando el techo (hasta
//! v0.6.13 lo ignoraba), flags desconocidos → exit 2, `run -` (stdin), `run --format json`
//! (el informe con la forma de `syn.run()`), `--` para `args()`, y el JSONL de `--audit`.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-host-flags-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn shell_echo() -> (&'static str, Vec<&'static str>) {
    if cfg!(windows) {
        ("cmd", vec!["/C", "echo pwned"])
    } else {
        ("sh", vec!["-c", "echo pwned"])
    }
}

fn hostile_program() -> String {
    let (sh, args) = shell_echo();
    let args_lit = args.iter().map(|a| format!("\"{}\"", a)).collect::<Vec<_>>().join(", ");
    format!(
        "require exec(\"{sh}\")\nlet r be run(\"{sh}\", [{args}])\nprint(r[\"stdout\"])\n",
        sh = sh,
        args = args_lit
    )
}

fn synsema(dir: &PathBuf, args: &[&str], stdin: Option<&str>) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_synsema"));
    c.args(args)
        .current_dir(dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().expect("spawn synsema");
    if let Some(src) = stdin {
        let mut si = child.stdin.take().unwrap();
        si.write_all(src.as_bytes()).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn unknown_flag_exits_2_in_run_test_conform() {
    let dir = project("unknown");
    std::fs::write(dir.join("p.syn"), "print(1)\n").unwrap();
    for cmd in ["run", "test", "conform"] {
        let (code, _out, err) = synsema(&dir, &[cmd, "--bogus", "p.syn"], None);
        assert_eq!(code, 2, "{}: {}", cmd, err);
        assert!(err.contains("unknown flag '--bogus'"), "{}: {}", cmd, err);
    }
    // `run --audit json p.syn` ya no corre "sin audit con `json` como path".
    let (code, out, _err) = synsema(&dir, &["run", "--audit", "json", "p.syn"], None);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), "1");
}

#[test]
fn cap_set_value_cannot_start_with_dashes() {
    let dir = project("capset");
    std::fs::write(dir.join("p.syn"), "print(1)\n").unwrap();
    let (code, _, err) = synsema(&dir, &["run", "--cap-set", "--sandbox", "p.syn"], None);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("--cap-set requires a value"), "{}", err);
    let (code, _, err) = synsema(&dir, &["run", "--sandbox", "--cap-set", "stdout", "p.syn"], None);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("mutually exclusive"), "{}", err);
}

#[test]
fn conform_sandbox_denies_exec_and_pwned_never_appears() {
    let dir = project("conform");
    std::fs::write(dir.join("hostile.syn"), hostile_program()).unwrap();
    // Sin techo: el programa ejecuta el comando (es lo que pide con `require exec`).
    let (code, out, _) = synsema(&dir, &["conform", "hostile.syn"], None);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("JSON");
    assert_eq!(v["ok"], true, "{}", out);
    assert!(out.contains("pwned"));
    // Con --sandbox: denegado, `pwned` no aparece, el contrato JSON se mantiene, exit 0.
    let (code, out, _) = synsema(&dir, &["conform", "--sandbox", "hostile.syn"], None);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("JSON con --sandbox");
    assert_eq!(v["ok"], false, "{}", out);
    assert!(!out.contains("pwned"), "{}", out);
    let err = v["err"].as_array().unwrap().iter().map(|e| e.as_str().unwrap()).collect::<Vec<_>>().join("\n");
    assert!(err.contains("Capability not granted: exec") && err.contains("above the host ceiling"), "{}", err);
    // --cap-set con exec: vuelve a ejecutar.
    let (sh, _) = shell_echo();
    let (code, out, _) = synsema(&dir, &["conform", "--cap-set", &format!("stdout,exec={}", sh), "hostile.syn"], None);
    assert_eq!(code, 0);
    assert!(out.contains("pwned"), "{}", out);
}

#[test]
fn conform_swarm_honors_ceiling() {
    let dir = project("swarm");
    let (sh, args) = shell_echo();
    let args_lit = args.iter().map(|a| format!("\"{}\"", a)).collect::<Vec<_>>().join(", ");
    let prog = format!(
        "agent Runner\n    require exec(\"{sh}\")\n    let r be run(\"{sh}\", [{args}])\n    share r[\"stdout\"] as \"out\"\n\nspawn Runner\nprint(\"main\")\n",
        sh = sh,
        args = args_lit
    );
    std::fs::write(dir.join("sw.syn"), prog).unwrap();
    let (code, out, _) = synsema(&dir, &["conform", "--swarm", "--sandbox", "sw.syn"], None);
    assert_eq!(code, 0, "{}", out);
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("JSON");
    assert!(!out.contains("pwned"), "{}", out);
    let agents = v["agents"].to_string();
    assert!(agents.to_lowercase().contains("error"), "el agente debía terminar en ERROR: {}", out);
}

#[test]
fn run_dash_reads_stdin_and_double_dash_feeds_args() {
    let dir = project("stdin");
    let src = "print(args())\nprint(length(args()))\n";
    let (code, out, err) = synsema(&dir, &["run", "-", "--", "--hello", "world"], Some(src));
    assert_eq!(code, 0, "{}", err);
    let lines: Vec<&str> = out.lines().map(|l| l.trim()).collect();
    assert_eq!(lines, vec!["[--hello, world]", "2"], "{}", out);
    // Sin `--`, un positional tras el path también es del programa.
    std::fs::write(dir.join("a.syn"), "print(args())\n").unwrap();
    let (code, out, _) = synsema(&dir, &["run", "a.syn", "x", "y"], None);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), "[x, y]");
    // self_path() es el ejecutable en curso.
    std::fs::write(dir.join("s.syn"), "print(self_path())\n").unwrap();
    let (code, out, _) = synsema(&dir, &["run", "s.syn"], None);
    assert_eq!(code, 0);
    assert!(out.trim().to_lowercase().ends_with(if cfg!(windows) { "synsema.exe" } else { "synsema" }), "{}", out);
}

#[test]
fn run_format_json_matches_wasm_shape() {
    let dir = project("report");
    let src = "require net(\"api.example.com\")\nprint(\"hola\")\nlet r be run(\"nope\", [])\n";
    let (code, out, _) = synsema(&dir, &["run", "-", "--format", "json", "--cap-set", "stdout,time"], Some(src));
    assert_eq!(code, 1);
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("stdout es SOLO el informe");
    assert_eq!(v["ok"], false);
    assert_eq!(v["output"], serde_json::json!(["hola"]));
    assert_eq!(v["exit"], 1);
    assert!(v["llm_tokens"].is_number());
    let errors = v["errors"].as_array().unwrap();
    assert!(errors[0].as_str().unwrap().contains("Capability not granted: exec"), "{}", out);
    let audit = v["audit"].as_array().unwrap();
    // Grants ambientales (stdout/time entran), el `require net` rechazado por el techo, y el
    // `run` denegado — todos con la forma {capability, granted, source, reason, origin}.
    let has = |f: &dyn Fn(&serde_json::Value) -> bool| audit.iter().any(f);
    assert!(has(&|e| e["capability"] == "stdout" && e["granted"] == true && e["origin"] == "runtime"), "{}", out);
    assert!(has(&|e| e["capability"] == "net(\"api.example.com\")" && e["granted"] == false && e["source"] == "ceiling"), "{}", out);
    assert!(has(&|e| e["capability"] == "exec(\"nope\")" && e["granted"] == false && e["source"] == "run()"), "{}", out);
    for e in audit {
        for k in ["capability", "granted", "source", "reason", "origin", "context", "ts"] {
            assert!(e.get(k).is_some(), "falta {} en {}", k, e);
        }
    }
    // `line` del `run` que disparó el chequeo (fuente por stdin → línea 3).
    assert!(has(&|e| e["capability"] == "exec(\"nope\")" && e["line"] == 3), "{}", out);
}

#[test]
fn audit_json_to_file_and_summary_line() {
    let dir = project("auditfile");
    std::fs::write(dir.join("p.syn"), "require time\nlet t be now()\nprint(\"ok\")\n").unwrap();
    let audit = dir.join("audit.jsonl");
    let (code, out, _) = synsema(&dir, &["run", "--audit", audit.to_str().unwrap(), "--cap-set", "stdout,time", "p.syn"], None);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), "ok");
    let text = std::fs::read_to_string(&audit).unwrap();
    let lines: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).expect("una línea JSON")).collect();
    let last = lines.last().unwrap();
    assert!(last.get("summary").is_some(), "{}", text);
    assert_eq!(last["summary"]["exit"], 0);
    assert!(last["summary"]["granted"].as_u64().unwrap() >= 2, "{}", text);
    assert!(lines.iter().any(|e| e["capability"] == "time" && e["source"] == "now()" && e["line"] == 2), "{}", text);
    // stderr con `--audit json`.
    let (code, _, err) = synsema(&dir, &["run", "--audit", "json", "--sandbox", "p.syn"], None);
    assert_eq!(code, 0);
    assert!(err.lines().any(|l| l.contains("\"summary\"")), "{}", err);
}

#[test]
fn audit_never_contains_a_secret_value() {
    // Un `--audit json` NUNCA debe dejar el valor de un secret en el stream: las
    // capabilities auditadas son NOMBRES (`secret("K")`, `reveal("K")`), no valores.
    let dir = project("auditsecret");
    let audit = dir.join("a.jsonl");
    let prog = "require secret(\"K\")\nrequire reveal(\"K\")\nlet k be secret(\"K\")\nlet plain be reveal(k)\nprint(length(plain) > 0)\n";
    std::fs::write(dir.join("p.syn"), prog).unwrap();
    let sentinel = "S3NT1NEL-SECRET-VALUE-abc123";
    let mut c = Command::new(env!("CARGO_BIN_EXE_synsema"));
    c.args(["run", "--audit", audit.to_str().unwrap(), "--cap-set", "stdout,secret=K,reveal=K", "p.syn"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .env("SYNSEMA_AUDIT_DIR", dir.join("auditlog").to_str().unwrap())
        .env("K", sentinel);
    let out = c.output().unwrap();
    assert_eq!(out.status.code().unwrap_or(-1), 0, "{}", String::from_utf8_lossy(&out.stderr));
    let stream = std::fs::read_to_string(&audit).unwrap();
    assert!(!stream.contains(sentinel), "el valor del secret se filtró en el audit stream: {}", stream);
    // Ni en la salida, ni en el reveal.log fail-loud.
    assert!(!String::from_utf8_lossy(&out.stdout).contains(sentinel));
    let logdir = dir.join("auditlog");
    if let Ok(rd) = std::fs::read_dir(&logdir) {
        for e in rd.flatten() {
            let content = std::fs::read_to_string(e.path()).unwrap_or_default();
            assert!(!content.contains(sentinel), "el valor del secret se filtró en {:?}", e.path());
        }
    }
    // Y sí registró el USO de la capability por su nombre.
    assert!(stream.contains("reveal(\\\"K\\\")") || stream.contains("secret(\\\"K\\\")"), "{}", stream);
}

#[cfg(windows)]
#[test]
fn audit_fd_on_windows_exits_2() {
    let dir = project("fd");
    std::fs::write(dir.join("p.syn"), "print(1)\n").unwrap();
    let (code, _, err) = synsema(&dir, &["run", "--audit", "fd:3", "p.syn"], None);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("only available on Unix"), "{}", err);
}

#[test]
fn stdout_denied_by_ceiling_fails_on_first_print() {
    let dir = project("stdout");
    std::fs::write(dir.join("p.syn"), "require time\nlet t be now()\nprint(\"visible\")\n").unwrap();
    // Techo sin stdout: el primer print falla (antes imprimía igual).
    let (code, out, err) = synsema(&dir, &["run", "--cap-set", "time", "p.syn"], None);
    assert_eq!(code, 1, "{}", err);
    assert!(!out.contains("visible"), "{}", out);
    assert!(err.contains("Capability not granted: stdout"), "{}", err);
    // Sin techo, print sigue libre.
    let (code, out, _) = synsema(&dir, &["run", "p.syn"], None);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), "visible");
}

#[test]
fn run_strips_synsema_secrets_from_the_child_environment() {
    // Auditoría 2026-08-30 (F3): un programa con `exec` pero SIN `env`/`secret` no debe
    // exfiltrar las claves de proveedor / secretos del `.env` del padre por `run(cmd)`.
    // El entorno base (PATH…) sí se hereda para que el comando funcione.
    let dir = project("runenv");
    let (cmd, args) = if cfg!(windows) { ("cmd", "\"/C\", \"set\"") } else { ("sh", "\"-c\", \"env\"") };
    let prog = format!("require exec(\"{c}\")\nlet r be run(\"{c}\", [{a}])\nprint(r[\"stdout\"])\n", c = cmd, a = args);
    std::fs::write(dir.join("p.syn"), &prog).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_synsema"));
    c.args(["run", "--cap-set", &format!("stdout,exec={}", cmd), "p.syn"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .env("ANTHROPIC_API_KEY", "sk-PARENT-KEY-SENTINEL");
    let out = c.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code().unwrap_or(-1), 0, "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!stdout.contains("sk-PARENT-KEY-SENTINEL"), "la clave del proceso se filtró al hijo: {}", stdout);
    assert!(!stdout.contains("ANTHROPIC_API_KEY"), "{}", stdout);
    // El comando corrió con su entorno base (PATH presente).
    assert!(stdout.to_uppercase().contains("PATH="), "el hijo perdió PATH (comando roto): {}", stdout);
}

#[test]
fn render_disk_read_requires_file_capability() {
    // Auditoría 2026-08-30 (F1): `render(path)` de DISCO leía cualquier archivo del cwd sin
    // capability — un LFI que bypasaba `file.read` + techo + secret. Ahora la llamada de
    // nivel superior gatea `file.read` (los assets del bundle y los include anidados no).
    let dir = project("render");
    std::fs::write(dir.join(".env"), "STRIPE=sk_live_LEAK_SENTINEL\n").unwrap();
    std::fs::write(dir.join("card.html"), "hi { name }\n").unwrap();
    // Sin `require file`: el LFI está cerrado.
    let (code, out, err) = synsema(&dir, &["run", "-"], Some("show body of render(\".env\")\n"));
    assert_eq!(code, 1, "{}", out);
    assert!(err.contains("Capability not granted: file_read"), "{}", err);
    assert!(!out.contains("sk_live_LEAK_SENTINEL"), "el LFI sigue abierto: {}", out);
    // Con `require file.read` sí renderiza.
    let (code, out, err) = synsema(&dir, &["run", "-"], Some("require file.read(\"card.html\")\nshow body of render(\"card.html\", {\"name\": \"x\"})\n"));
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("hi x"), "{}", out);
    // Bajo --sandbox el techo gana aunque el programa lo declare.
    let (code, _out, err) = synsema(&dir, &["run", "--sandbox", "-"], Some("require file.read(\"card.html\")\nshow body of render(\"card.html\", {\"name\": \"x\"})\n"));
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("above the host ceiling"), "{}", err);
}

#[test]
fn read_line_prompt_respects_the_stdout_ceiling() {
    // Auditoría 2026-08-30 (F4): el prompt de `read_line` era la única salida que no
    // pasaba por el gate de `stdout` — bajo un techo sin stdout, escribía igual.
    let dir = project("readline");
    let (code, out, err) = synsema(&dir, &["run", "--cap-set", "time", "-"], Some("try\n    let x be read_line(\"PROMPT_SHOULD_NOT_LEAK\")\nrecover e\n    print(\"caught\")\n"));
    let _ = code;
    assert!(!out.contains("PROMPT_SHOULD_NOT_LEAK"), "el prompt escapó el techo de stdout: {}", out);
    assert!(err.contains("Capability not granted: stdout") || out.is_empty(), "{}{}", out, err);
}

#[test]
fn pure_profile_memory_does_not_touch_disk() {
    // Auditoría 2026-08-30 (F2): `remember`/progress escribían el `.db` a disco bajo
    // `--profile pure` ("sin filesystem"). Ahora la memoria declarada queda in-memory.
    // Un archivo .syn (no stdin) tiene dir de programa → sin el fix, persistiría.
    let dir = project("puremem");
    std::fs::write(dir.join("x.syn"), "require memory(\"x\")\nremember(\"learning\", \"v\")\nprint(\"ok\")\n").unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--profile", "pure", "x.syn"], None);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("ok"), "{}", out);
    assert!(!dir.join(".synsema").exists(), "el perfil puro escribió estado a disco: {:?}", std::fs::read_dir(dir.join(".synsema")).ok());
    // Control: el MISMO programa sin --profile pure SÍ persiste el .db.
    std::fs::write(dir.join("y.syn"), "require memory(\"y\")\nremember(\"learning\", \"v\")\nprint(\"ok\")\n").unwrap();
    let (code, _out, err) = synsema(&dir, &["run", "y.syn"], None);
    assert_eq!(code, 0, "{}", err);
    assert!(dir.join(".synsema").join("state").join("y.db").exists(), "sin pure debería persistir");
}

#[test]
fn profile_pure_stubs_os_builtins_but_keeps_pure_ones() {
    let dir = project("pure");
    std::fs::write(dir.join("f.txt"), "data").unwrap();
    let prog = "require file(\"./f.txt\")\nprint(sha256(\"a\") != nothing)\ntry\n    read_file(\"./f.txt\")\nrecover e\n    print(e)\ntry\n    sql(\"x\", \"select 1\")\nrecover e\n    print(e)\nprint(term_open() == nothing)\n";
    std::fs::write(dir.join("p.syn"), prog).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--profile", "pure", "p.syn"], None);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("read_file: not available in the pure profile — this run has no filesystem (drop --profile pure to run it natively)"), "{}", out);
    assert!(out.contains("sql: not available in the pure profile — this run has no database drivers"), "{}", out);
    assert!(out.lines().next().unwrap().trim() == "true");
    assert!(out.trim().ends_with("true"), "{}", out);
    // Sin el flag, read_file funciona (programa mínimo: sólo lectura de archivo).
    std::fs::write(dir.join("q.syn"), "require file.read(\"./f.txt\")\nprint(read_file(\"./f.txt\"))\n").unwrap();
    let (code, out, err) = synsema(&dir, &["run", "q.syn"], None);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(out.trim(), "data");
    assert!(!out.contains("not available"), "{}", out);
    // serve no corre bajo pure; el nombre inválido es error de uso.
    let (code, _, err) = synsema(&dir, &["serve", "--profile", "pure", "p.syn"], None);
    assert_eq!(code, 2, "{}", err);
    let (code, _, err) = synsema(&dir, &["run", "--profile", "bogus", "p.syn"], None);
    assert_eq!(code, 2, "{}", err);
}

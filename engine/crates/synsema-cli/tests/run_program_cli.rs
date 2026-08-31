//! E2E de `run_program(source, opts)` sobre el binario real (spec `tanda-motor-lamps.md`
//! §2.6): el hijo es un PROCESO del mismo binario, así que estos tests tienen que correr
//! con `synsema` de verdad (en un test del runtime `current_exe()` sería el test-bin).
//! Son los ocho casos de `prototipo-node/verify.mjs` de Lamps, reescritos.

use std::path::PathBuf;
use std::process::Command;

fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-run-program-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn synsema(dir: &PathBuf, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_synsema"));
    c.args(args).current_dir(dir).env("SYNSEMA_NO_UPDATE_CHECK", "1");
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().expect("spawn synsema");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn shell() -> (&'static str, &'static str) {
    if cfg!(windows) {
        ("cmd", "\"/C\", \"echo pwned\"")
    } else {
        ("sh", "\"-c\", \"echo pwned\"")
    }
}

/// Un padre que corre `child` con `opts` y vuelca el resultado como JSON en una línea.
fn parent(requires: &str, child: &str, opts: &str) -> String {
    format!(
        "{requires}\nlet child be {child:?}\nlet r be run_program(child, {opts})\nprint(json_encode(r))\n",
        requires = requires,
        child = child,
        opts = opts
    )
}

fn run_parent(dir: &PathBuf, prog: &str, args: &[&str], env: &[(&str, &str)]) -> (i32, serde_json::Value, String) {
    std::fs::write(dir.join("parent.syn"), prog).unwrap();
    let mut a = vec!["run"];
    a.extend_from_slice(args);
    a.push("parent.syn");
    let (code, out, err) = synsema(dir, &a, env);
    let last = out.lines().last().unwrap_or("").trim().to_string();
    let v: serde_json::Value = serde_json::from_str(&last).unwrap_or_else(|_| panic!("el padre no imprimió JSON:\nstdout={}\nstderr={}", out, err));
    (code, v, err)
}

#[test]
fn hostile_child_is_refused_with_structured_audit() {
    let dir = project("hostile");
    let (sh, args) = shell();
    let child = format!("require exec(\"{sh}\")\nlet r be run(\"{sh}\", [{args}])\nprint(r[\"stdout\"])\n", sh = sh, args = args);
    // profile native: el `run` del hijo llega al chequeo de `exec` (bajo pure sería un
    // stub antes del gate); el techo "sandbox" [stdout,time] lo deniega igual.
    let prog = parent("require sandbox_run", &child, "{\"ceiling\": \"sandbox\", \"profile\": \"native\", \"timeout\": 20}");
    let (code, r, err) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(r["ok"], false, "{}", r);
    assert_eq!(r["exit"], 1);
    assert_eq!(r["timed_out"], false);
    let out = r["output"].to_string();
    assert!(!out.contains("pwned"), "{}", r);
    let audit = r["audit"].as_array().expect("audit es lista");
    assert!(
        audit.iter().any(|e| e["capability"].as_str().unwrap_or("").starts_with("exec(") && e["granted"] == false && e["reason"].as_str().unwrap_or("").contains("above host ceiling")),
        "{}",
        r
    );
    assert!(r["errors"][0].as_str().unwrap().contains("Capability not granted: exec"), "{}", r);
}

#[test]
fn session_ceiling_intersects_parent_and_wildcard_drops_entirely() {
    let dir = project("intersect");
    // El padre corre bajo --cap-set stdout,net=uno,sandbox_run y presta stdout+net=uno.
    // El hijo pide stdout, net=uno, net=dos y net=* → net=dos y net=* se recortan.
    let child = "print(\"child\")\n";
    let prog = parent(
        "require sandbox_run\nrequire net(\"uno\")",
        child,
        "{\"ceiling\": \"stdout,net=uno,net=dos,net=*\", \"timeout\": 20}",
    );
    std::fs::write(dir.join("parent.syn"), &prog).unwrap();
    let audit = dir.join("parent.jsonl");
    let (code, out, err) = synsema(
        &dir,
        &["run", "--cap-set", "stdout,net=uno,sandbox_run", "--audit", audit.to_str().unwrap(), "parent.syn"],
        &[],
    );
    assert_eq!(code, 0, "{}", err);
    let last = out.lines().last().unwrap().trim();
    let r: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(r["ok"], true, "{}", r);
    assert_eq!(r["output"], serde_json::json!(["child"]));
    // El audit del PADRE registra los recortes con la razón.
    let text = std::fs::read_to_string(&audit).unwrap();
    let lines: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let trimmed: Vec<String> = lines
        .iter()
        .filter(|e| e["reason"] == "above parent ceiling")
        .map(|e| e["capability"].as_str().unwrap().to_string())
        .collect();
    assert!(trimmed.contains(&"net(\"dos\")".to_string()), "{}", text);
    assert!(trimmed.contains(&"net(\"*\")".to_string()), "{}", text);
    assert!(!trimmed.contains(&"net(\"uno\")".to_string()), "{}", text);
    assert!(lines.iter().any(|e| e["capability"] == "sandbox_run" && e["granted"] == true && e["source"] == "run_program()"), "{}", text);
}

#[test]
fn run_program_requires_sandbox_run_and_parent_must_declare_what_it_lends() {
    let dir = project("gate");
    // Sin `require sandbox_run`: denegado en el padre.
    let prog = parent("", "print(1)\n", "{\"ceiling\": \"sandbox\"}");
    std::fs::write(dir.join("parent.syn"), &prog).unwrap();
    let (code, _, err) = synsema(&dir, &["run", "parent.syn"], &[]);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("Capability not granted: sandbox_run"), "{}", err);
    // Con sandbox_run pero sin `require net`: el hijo no recibe net aunque lo pida.
    let child = "require net(\"api.example.com\")\nlet r be fetch(\"https://api.example.com/x\")\n";
    let prog = parent("require sandbox_run", child, "{\"ceiling\": \"stdout,net=api.example.com\", \"timeout\": 20}");
    let (code, r, err) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(r["ok"], false, "{}", r);
    assert!(r["errors"][0].as_str().unwrap().contains("Capability not granted: net"), "{}", r);
}

#[test]
fn secret_never_appears_and_env_is_replaced_not_inherited() {
    let dir = project("secret");
    // .env del cwd con un centinela: el hijo NO lo lee (SYNSEMA_ENV_FILE="" en el hijo).
    std::fs::write(dir.join(".env"), "PARENT_ONLY=sentinel-from-dotenv\n").unwrap();
    let child = "require env(\"K\")\nrequire env(\"PARENT_ONLY\")\nrequire env(\"CHILD_ONLY\")\nprint(env(\"CHILD_ONLY\", \"missing\"))\nprint(env(\"PARENT_ONLY\", \"missing\"))\nprint(env(\"K\", \"missing\"))\n";
    // El padre presta `env` amplio (`require env("*")`); el hijo hereda ese techo.
    let prog = parent(
        "require sandbox_run\nrequire secret(\"K\")\nrequire env(\"*\")",
        child,
        "{\"ceiling\": \"stdout,env=*\", \"env\": {\"CHILD_ONLY\": \"yes\"}, \"timeout\": 20}",
    );
    let (code, r, err) = run_parent(&dir, &prog, &[], &[("K", "sentinel-from-process"), ("PARENT_ONLY", "sentinel-from-process-2")]);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(r["ok"], true, "{}", r);
    assert_eq!(r["output"], serde_json::json!(["yes", "missing", "missing"]), "{}", r);
    let dump = r.to_string();
    assert!(!dump.contains("sentinel"), "{}", dump);
    // Pasar un `secret` en `env` es error del padre (hay que reveal() a propósito).
    let prog = "require sandbox_run\nrequire secret(\"K\")\nlet s be secret(\"K\")\nlet r be run_program(\"print(1)\", {\"env\": {\"X\": s}})\nprint(json_encode(r))\n";
    std::fs::write(dir.join("parent.syn"), prog).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "parent.syn"], &[("K", "sentinel-from-process")]);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("is a secret") && err.contains("reveal()"), "{}", err);
    assert!(!err.contains("sentinel") && !out.contains("sentinel"), "{}{}", out, err);
}

#[test]
fn timeout_kills_child_and_reports_it() {
    let dir = project("timeout");
    let child = "require time\nprint(\"start\")\nwhile true\n    sleep(0.05)\n";
    let prog = parent("require sandbox_run\nrequire time", child, "{\"ceiling\": \"stdout,time\", \"timeout\": 1}");
    let start = std::time::Instant::now();
    let (code, r, err) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!(code, 0, "{}", err);
    assert!(start.elapsed() < std::time::Duration::from_secs(15), "el timeout no cortó");
    assert_eq!(r["ok"], false, "{}", r);
    assert_eq!(r["timed_out"], true, "{}", r);
    assert!(r["exit"].is_null(), "{}", r);
    assert!(r["errors"][0].as_str().unwrap().contains("timed out after"), "{}", r);
}

#[test]
fn depth_limit_enforced() {
    let dir = project("depth");
    // Un programa que se corre a sí mismo: el nivel N corre el N+1 hasta que el knob corta.
    let self_src = "require sandbox_run\nlet me be read_file(\"self.syn\")\nlet r be run_program(me, {\"ceiling\": \"stdout,sandbox_run,file.read=self.syn\", \"profile\": \"native\", \"timeout\": 20})\nprint(json_encode(r))\n";
    let self_prog = format!("require file.read(\"self.syn\")\n{}", self_src);
    std::fs::write(dir.join("self.syn"), &self_prog).unwrap();
    let (code, out, err) = synsema(&dir, &["run", "self.syn"], &[("SYNSEMA_RUN_PROGRAM_MAX_DEPTH", "2")]);
    assert_eq!(code, 0, "{}", err);
    let last = out.lines().last().unwrap().trim();
    let r: serde_json::Value = serde_json::from_str(last).unwrap();
    // nivel 0 → hijo nivel 1 (ok) → nieto nivel 2 falla con max depth 2 → el hijo reporta ok:true
    // con el JSON del nieto en su output; buscamos el texto "max depth" en la cadena.
    let dump = r.to_string();
    assert!(dump.contains("max depth 2 exceeded"), "{}", dump);
}

#[test]
fn pure_parent_cannot_spawn_native_child() {
    let dir = project("pure");
    std::fs::write(dir.join("f.txt"), "x").unwrap();
    let child = "require file.read(\"f.txt\")\nprint(read_file(\"f.txt\"))\n";
    let prog = parent(
        "require sandbox_run\nrequire file.read(\"f.txt\")",
        child,
        "{\"ceiling\": \"stdout,file.read=f.txt\", \"profile\": \"native\", \"timeout\": 20}",
    );
    std::fs::write(dir.join("parent.syn"), &prog).unwrap();
    let audit = dir.join("p.jsonl");
    let (code, out, err) = synsema(&dir, &["run", "--profile", "pure", "--audit", audit.to_str().unwrap(), "parent.syn"], &[]);
    assert_eq!(code, 0, "{}", err);
    let r: serde_json::Value = serde_json::from_str(out.lines().last().unwrap().trim()).unwrap();
    assert_eq!(r["ok"], false, "{}", r);
    assert!(r["errors"][0].as_str().unwrap().contains("read_file: not available in the pure profile"), "{}", r);
    let text = std::fs::read_to_string(&audit).unwrap();
    assert!(text.contains("\"reason\":\"above parent profile\""), "{}", text);
    // Un padre nativo sí puede prestar native.
    let (code, r, err) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(r["ok"], true, "{}", r);
    assert_eq!(r["output"], serde_json::json!(["x"]));
}

#[test]
fn empty_intersection_runs_with_none_and_sandbox_block_lends_nothing() {
    let dir = project("none");
    // El padre no tiene net: la intersección de un techo "net=x" queda vacía → `none`
    // → el hijo ni siquiera puede imprimir.
    let prog = parent("require sandbox_run", "print(\"hi\")\n", "{\"ceiling\": \"net=x\", \"timeout\": 20}");
    let (code, r, err) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(r["ok"], false, "{}", r);
    assert!(r["errors"][0].as_str().unwrap().contains("Capability not granted: stdout"), "{}", r);
    // Dentro de un `sandbox` el padre no puede prestar nada (ni llamar run_program).
    let prog = "require sandbox_run\nsandbox\n    let r be run_program(\"print(1)\", {\"ceiling\": \"sandbox\"})\n    print(json_encode(r))\n";
    std::fs::write(dir.join("parent.syn"), prog).unwrap();
    let (code, _, err) = synsema(&dir, &["run", "parent.syn"], &[]);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("Capability not granted: sandbox_run"), "{}", err);
}

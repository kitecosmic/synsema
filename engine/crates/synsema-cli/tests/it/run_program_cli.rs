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

/// v0.6.54 (1): una opción que `run_program` no conoce es error y el hijo no corre (antes,
/// `"ceilng"` corría al hijo sin el techo pedido). Unas opciones que no son un mapa, también.
#[test]
fn an_unknown_option_is_an_error_and_nothing_runs() {
    let dir = project("unknown-opt");
    let marker = dir.join("ran.txt");
    let child = format!(
        "require file.write\nwrite_file({:?}, \"x\")\n",
        marker.to_string_lossy().replace('\\', "/")
    );
    for opts in ["{\"ceilng\": \"net=*\", \"profile\": \"native\"}", "\"sandbox\""] {
        let prog = format!("require sandbox_run\nrequire file.write\nlet r be run_program({:?}, {})\nprint(r.ok)\n", child, opts);
        std::fs::write(dir.join("parent.syn"), &prog).unwrap();
        let (code, out, err) = synsema(&dir, &["run", "parent.syn"], &[]);
        assert_ne!(code, 0, "{} {}", out, err);
        assert!(!marker.exists(), "el hijo corrió con {}", opts);
        if opts.starts_with('{') {
            assert!(
                err.contains("run_program: unknown option \"ceilng\" (valid options: ceiling, profile, env, timeout, cwd, filename, explain) — nothing ran"),
                "{}",
                err
            );
        } else {
            assert!(err.contains("run_program: options must be a map, got text — nothing ran"), "{}", err);
        }
    }
    // `explain` que no es un booleano tampoco se acepta.
    let prog = "require sandbox_run\nlet r be run_program(\"print(1)\", {\"explain\": \"yes\"})\n";
    std::fs::write(dir.join("parent.syn"), prog).unwrap();
    let (code, _, err) = synsema(&dir, &["run", "parent.syn"], &[]);
    assert_ne!(code, 0);
    assert!(err.contains("run_program: explain must be true or false"), "{}", err);
}

/// v0.6.54 (2): el stderr del hijo (su `eprint`) vuelve en `stderr`, aparte de `output` y `errors`.
#[test]
fn the_child_stderr_comes_back() {
    let dir = project("stderr");
    let child = "print(1)\neprint(\"warn one\")\neprint(\"warn two\")\nlet xs be [1]\nprint(xs[3])\n";
    let prog = parent("require sandbox_run", child, "{}");
    let (code, r, err) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(r["ok"], false, "{}", r);
    assert_eq!(r["output"], serde_json::json!(["1"]), "{}", r);
    assert_eq!(r["stderr"], serde_json::json!(["warn one", "warn two"]), "{}", r);
    assert_eq!(r["stderr_truncated"], false, "{}", r);
    assert!(r["errors"][0].as_str().unwrap().contains("Index 3 out of bounds"), "{}", r);
    // Sin `explain`, el campo existe y es nothing.
    assert!(r["diagnostic"].is_null(), "{}", r);
    // El hijo sin stderr: lista vacía.
    let prog = parent("require sandbox_run", "print(1)\n", "{}");
    let (_, r, _) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!(r["stderr"], serde_json::json!([]), "{}", r);
}

/// v0.6.54 (M2 y N4 de la ronda 1): el padre no arma más de 100 000 líneas del `stderr` ni del
/// `output` del hijo (cada línea es un valor: 10 MB de saltos de línea eran 476 MB en el padre), y
/// un informe de más de 32 MB no se lee.
#[test]
fn the_child_lines_are_capped() {
    let dir = project("caps");
    let summary = r#"print(json_encode({"ok": r.ok, "out": length(r.output), "ot": r.output_truncated, "err": length(r.stderr), "et": r.stderr_truncated, "at": r.audit_truncated, "errors": r.errors}))
"#;
    // 131 073 líneas de stderr (un `eprint` de 2^17 saltos de línea) y 100 005 de `output`.
    let child = r#"let s be "\n"
let j be 0
while j < 17
    set s to s + s
    set j to j + 1
eprint(s)
let i be 0
while i < 100005
    print("")
    set i to i + 1
"#;
    let prog = format!("require sandbox_run\nlet r be run_program({:?}, {{\"timeout\": 120}})\n{}", child, summary);
    let (code, r, err) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(r["err"], 100_000, "{}", r);
    assert_eq!(r["et"], true, "{}", r);
    assert_eq!(r["out"], 100_000, "{}", r);
    assert_eq!(r["ot"], true, "{}", r);
    assert_eq!(r["ok"], true, "recortar la salida no es un error: {}", r);
    // Justo debajo de los topes: entero y sin recorte.
    let child = "eprint(\"a\")\nprint(\"b\")\n";
    let prog = format!("require sandbox_run\nlet r be run_program({:?}, {{}})\n{}", child, summary);
    let (_, r, _) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!((r["err"].clone(), r["et"].clone(), r["out"].clone(), r["ot"].clone()), (serde_json::json!(1), serde_json::json!(false), serde_json::json!(1), serde_json::json!(false)), "{}", r);
    // Un informe de más de 32 MB (33 líneas de 1 MiB) no se lee: es un error que lo dice.
    let child = r#"let s be "x"
let j be 0
while j < 20
    set s to s + s
    set j to j + 1
let i be 0
while i < 33
    print(s)
    set i to i + 1
"#;
    let prog = format!("require sandbox_run\nlet r be run_program({:?}, {{\"timeout\": 120}})\n{}", child, summary);
    let (code, r, err) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(r["ok"], false, "{}", r);
    assert_eq!(r["out"], 0, "{}", r);
    assert!(r["errors"][0].as_str().unwrap().contains("the child's report is larger than 32 MB"), "{}", r);
}

/// v0.6.54 (R2-3 de la ronda 2): cada chequeo de permiso del hijo es una entrada del audit, algo que
/// el programa no elige. Un hijo sano con 50 001 lecturas permitidas llega con `ok`, su salida, las
/// primeras 50 000 entradas y `audit_truncated`.
#[test]
fn a_long_audit_keeps_ok_and_the_output() {
    let dir = project("audit");
    std::fs::write(dir.join("dato.txt"), "x").unwrap();
    let child = r#"require file.read("dato.txt")
let i be 0
while i < 50001
    let t be read_file("dato.txt")
    set i to i + 1
print("listo")
"#;
    let prog = format!(
        "require sandbox_run\nrequire file.read(\"dato.txt\")\nlet r be run_program({:?}, {{\"ceiling\": {{\"file.read\": \"dato.txt\"}}, \"timeout\": 300, \"profile\": \"native\"}})\nprint(json_encode({{\"ok\": r.ok, \"output\": r.output, \"n\": length(r.audit), \"at\": r.audit_truncated, \"errors\": r.errors}}))\n",
        child
    );
    let (code, r, err) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(r["ok"], true, "{}", r);
    assert_eq!(r["output"], serde_json::json!(["listo"]), "{}", r);
    assert_eq!(r["n"], 50_000, "{}", r);
    assert_eq!(r["at"], true, "{}", r);
    // Un hijo con pocas entradas: entero y sin recorte.
    let prog = format!(
        "require sandbox_run\nrequire file.read(\"dato.txt\")\nlet r be run_program({:?}, {{\"ceiling\": {{\"file.read\": \"dato.txt\"}}, \"profile\": \"native\"}})\nprint(json_encode({{\"ok\": r.ok, \"at\": r.audit_truncated}}))\n",
        "require file.read(\"dato.txt\")\nprint(read_file(\"dato.txt\"))\n"
    );
    let (_, r, _) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!((r["ok"].clone(), r["at"].clone()), (serde_json::json!(true), serde_json::json!(false)), "{}", r);
}

/// v0.6.54 (R3-2 de la ronda 3): el audit del hijo también tiene tope de bytes. Con una ruta de
/// ~410 caracteres cada entrada pesa ~1 KB: 20 001 lecturas son ~21 MB de audit, más que los 16 MB
/// del presupuesto. Llega recortado, con `ok` y la salida.
#[test]
fn a_long_path_audit_keeps_ok_and_the_output() {
    let dir = project("audit-bytes");
    let rel = format!("{}/{}/dato.txt", "a".repeat(200), "b".repeat(200));
    std::fs::create_dir_all(dir.join(format!("{}/{}", "a".repeat(200), "b".repeat(200)))).unwrap();
    std::fs::write(dir.join(&rel), "x").unwrap();
    let child = format!(
        "require file.read({rel:?})\nlet i be 0\nwhile i < 20001\n    let t be read_file({rel:?})\n    set i to i + 1\nprint(\"listo\")\n"
    );
    let prog = format!(
        "require sandbox_run\nrequire file.read({rel:?})\nlet r be run_program({child:?}, {{\"ceiling\": {{\"file.read\": {rel:?}}}, \"timeout\": 300, \"profile\": \"native\"}})\nprint(json_encode({{\"ok\": r.ok, \"output\": r.output, \"n\": length(r.audit), \"at\": r.audit_truncated, \"errors\": r.errors}}))\n"
    );
    let (code, r, err) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(r["ok"], true, "{}", r);
    assert_eq!(r["output"], serde_json::json!(["listo"]), "{}", r);
    assert_eq!(r["at"], true, "{}", r);
    let n = r["n"].as_u64().unwrap();
    assert!(n >= 1 && n <= 20_000, "{}", r);
}

/// v0.6.54 (3): `explain: true` trae el diagnóstico de `--explain` como mapa: el error de runtime
/// con su línea, el código alrededor y las variables; el de parse con su ubicación.
#[test]
fn explain_gives_the_structured_diagnostic() {
    let dir = project("explain");
    let child = "let total be 10\nlet xs be [1]\nprint(xs[3])\n";
    let prog = parent("require sandbox_run", child, "{\"explain\": true}");
    let (code, r, err) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!(code, 0, "{}", err);
    let d = &r["diagnostic"];
    assert_eq!(d["error_type"], "RuntimeError", "{}", r);
    assert_eq!(d["file"], "<run_program>", "{}", r);
    assert_eq!(d["line"], 3, "{}", r);
    assert_eq!(d["column"], 9, "{}", r);
    assert_eq!(d["message"], "Index 3 out of bounds (list length 1)", "{}", r);
    assert_eq!(d["error_category"], "data", "{}", r);
    assert_eq!(d["variables"]["total"], "10", "{}", r);
    assert!(d["source_context"].as_array().unwrap().iter().any(|l| l == "print(xs[3])"), "{}", r);
    assert!(!d["suggestions"].as_array().unwrap().is_empty(), "{}", r);
    // Error de parse: con línea y columna (antes, `--explain` daba 0 y la ubicación en el mensaje).
    let prog = parent("require sandbox_run", "print(1)\nprint(2\n", "{\"explain\": true}");
    let (_, r, _) = run_parent(&dir, &prog, &[], &[]);
    let d = &r["diagnostic"];
    assert_eq!(d["error_type"], "ParseError", "{}", r);
    assert!(d["line"].as_u64().unwrap() >= 2, "{}", r);
    assert!(!d["message"].as_str().unwrap().contains("<run_program>:"), "{}", r);
    // Una corrida que anda: nothing.
    let prog = parent("require sandbox_run", "print(1)\n", "{\"explain\": true}");
    let (_, r, _) = run_parent(&dir, &prog, &[], &[]);
    assert_eq!(r["ok"], true, "{}", r);
    assert!(r["diagnostic"].is_null(), "{}", r);
}

/// v0.6.54 (3): `run --format json --diagnostic`. Con datos privados de por medio las variables no
/// salen (como `steps`); una variable enorme sale cortada; sin `--format json` es un error de uso.
#[test]
fn the_report_diagnostic_hides_variables_after_private_data() {
    let dir = project("diag-cli");
    std::fs::write(dir.join("p.syn"), "let k be private(upper(\"topsecret\"), \"ab\")\nlet n be 5\nlet xs be [1]\nprint(xs[3])\n").unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "--format", "json", "--diagnostic", "p.syn"], &[]);
    assert_eq!(code, 1, "{}", err);
    let r: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(r["diagnostic"]["line"], 4, "{}", r);
    assert!(r["diagnostic"]["variables"].is_null(), "{}", r);
    // El valor (no está literal en el código, que `source_context` sí muestra) no sale.
    assert!(!out.contains("TOPSECRET"), "{}", out);
    // Una corrida cortada por el chequeo de flujo: sin diagnóstico (la línea del corte es todo).
    std::fs::write(dir.join("q.syn"), "let k be private(upper(\"topsecret\"), \"ab\")\nwhen length(k) > 0\n    eprint(\"y\")\nlet xs be [1]\nprint(xs[3])\n").unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "--format", "json", "--diagnostic", "q.syn"], &[]);
    assert_eq!(code, 1, "{}", err);
    let r: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert!(r["errors"][0].as_str().unwrap().contains("label_violation"), "{}", r);
    assert!(r["diagnostic"].is_null(), "{}", r);
    // El corte de un AGENTE con el principal fallando por su cuenta: la corrida entera termina
    // con el corte, y el diagnóstico del principal tampoco sale.
    std::fs::write(
        dir.join("a.syn"),
        "agent W\n    let k be private(upper(\"topsecret\"), \"ab\")\n    when length(k) > 0\n        eprint(\"y\")\nspawn W\nlet xs be [1]\nprint(xs[3])\n",
    )
    .unwrap();
    let (code, out, err) = synsema(&dir, &["run", "--labels", "--format", "json", "--diagnostic", "a.syn"], &[]);
    assert_eq!(code, 1, "{}", err);
    let r: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert!(r["errors"][0].as_str().unwrap().contains("label_violation"), "{}", r);
    assert!(r["diagnostic"].is_null(), "{}", r);
    // Sin datos privados, las variables salen; una enorme, cortada.
    std::fs::write(dir.join("b.syn"), "let n be 5\nlet big be range(0, 100000)\nprint(big[200000])\n").unwrap();
    let (_, out, _) = synsema(&dir, &["run", "--format", "json", "--diagnostic", "b.syn"], &[]);
    let r: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(r["diagnostic"]["variables"]["n"], "5", "{}", r);
    let big = r["diagnostic"]["variables"]["big"].as_str().unwrap();
    assert!(big.chars().count() < 1100 && big.ends_with("chars)"), "{}", big);
    // Sin `--diagnostic`, el informe no cambia de forma.
    let (_, out, _) = synsema(&dir, &["run", "--format", "json", "b.syn"], &[]);
    let r: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert!(r.get("diagnostic").is_none(), "{}", r);
    let (code, _, err) = synsema(&dir, &["run", "--diagnostic", "b.syn"], &[]);
    assert_eq!(code, 2);
    assert!(err.contains("--diagnostic goes with --format json"), "{}", err);
}

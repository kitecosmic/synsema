//! v0.6.58, §13: el recibo, `--replay` y la atestación con paquetes (las filas R de §15). Usa el
//! registro local y los paquetes de `v0658_get_cli`.

use serde_json::{json, Value};

use super::v0646_tanda_e_cli::{auditor_keys, open_receipt, receipt_in, synsema_env};
use super::v0658_get_cli::{modules, says, url, uses_bpe, Pkg, Proj, Reg};

/// Un proyecto con `tok` (que usa `bpe`) y `otro` declarado, después de `get`.
struct Two {
    reg: Reg,
    p: Proj,
    tok: Pkg,
    bpe: Pkg,
}

fn two(tag: &str) -> Two {
    let reg = Reg::start();
    let b = reg.base();
    let bpe = says(&format!("{}/bpe-core", b), "0.3.1", "bpe");
    let ub = reg.publish("/bpe-core/0.3.1", &bpe);
    let tok = uses_bpe(&format!("{}/tokenizador", b), "0.1.0", &ub, &bpe);
    let ut = reg.publish("/tokenizador/0.1.0", &tok);
    let otro = says(&format!("{}/otro", b), "0.1.0", "otro");
    let uo = reg.publish("/otro/0.1.0", &otro);
    let p = Proj::new(tag, modules(&[("tok", url(&ut)), ("otro", url(&uo))]));
    p.ok(&[]);
    Two { reg, p, tok, bpe }
}

fn modules_json(t: &Two) -> Value {
    json!({
        "direct": {"tok": t.tok.id},
        "packages": {
            t.bpe.id.clone(): {"hash": t.bpe.hash(), "version": "0.3.1"},
            t.tok.id.clone(): {"hash": t.tok.hash(), "version": "0.1.0"},
        }
    })
}

fn run_args(p: &Proj, args: &[&str], src: &str) -> (i32, String, String) {
    std::fs::write(p.dir.join("p.syn"), src).unwrap();
    let cache = p.cache.to_string_lossy().into_owned();
    synsema_env(&p.dir, args, None, &[("SYNSEMA_MODULE_CACHE", &cache)])
}

/// R1, R2: `credentialSubject.modules` con lo que se alcanzó (`otro`, declarado y nunca usado, no
/// está); sin paquetes, no va.
#[test]
fn r1_r2_the_receipt_names_the_packages_that_ran() {
    let t = two("r1");
    let out = t.p.run("use \"tok\" as tok\nlet m be receipt().credentialSubject.modules\nprint(json_encode(m))\n");
    let got: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(got, modules_json(&t));
    let out = t.p.run("print(json_encode(receipt().credentialSubject))\n");
    assert!(!out.contains("\"modules\""), "{}", out);
}

/// R3: un `use "tok"` que sólo corre en una rama privada aparece igual, y nada depende de la rama.
#[test]
fn r3_a_use_in_a_private_branch_is_in_the_receipt_either_way() {
    let t = two("r3");
    let mut outs = Vec::new();
    for n in ["1", "9"] {
        let src = format!(
            "task con_tok()\n    use \"tok\" as tok\n    give tok.cual()\nlet n be private({n}, \"app\")\nwhen n > 5\n    let x be con_tok()\nprint(json_encode(receipt().credentialSubject.modules))\n"
        );
        let (code, out, err) = run_args(&t.p, &["run", "--labels", "p.syn"], &src);
        assert_eq!(code, 0, "{}", err);
        outs.push(out);
    }
    assert_eq!(outs[0], outs[1]);
    assert_eq!(serde_json::from_str::<Value>(outs[0].trim()).unwrap(), modules_json(&t));
}

/// R4, R5, R6, R8, R12: `header.modules` firmado, y `--replay` lo compara antes que `program_sha`.
#[test]
fn r4_r5_r6_r8_r12_the_sealed_header_and_the_replay() {
    let t = two("r4");
    let (sk, pk) = auditor_keys();
    let src = "use \"tok\" as tok\nprint(tok.cual())\n";
    let (code, out, err) = run_args(&t.p, &["run", "--auditor", &pk, "p.syn"], src);
    assert_eq!((code, out.trim()), (0, "bpe"), "{}", err);
    let opened = open_receipt(&receipt_in(&err), &sk);
    assert_eq!(opened["header"]["modules"], modules_json(&t));
    std::fs::write(t.p.dir.join("opened.json"), opened.to_string()).unwrap();
    let replay = |extra: &[&str]| run_args(&t.p, &[&["run", "--replay", "opened.json"][..], extra, &["p.syn"]].concat(), src);

    // R5: los mismos paquetes.
    let (code, _, err) = replay(&[]);
    assert_eq!(code, 0, "{}", err);
    assert!(err.contains("inputs match the recorded run") && !err.contains("not a verification"), "{}", err);

    // R6, R12: `tok` apunta a otro `id` con los mismos `.syn`.
    let b = t.reg.base();
    let tok2 = uses_bpe(&format!("{}/tok-fork", b), "0.1.0", &format!("{}/bpe-core/0.3.1/synsema.json", b), &t.bpe);
    let u2 = t.reg.publish("/tok-fork/0.1.0", &tok2);
    let saved = t.p.json();
    let mut j = saved.clone();
    j["modules"]["tok"] = url(&u2);
    t.p.write(j);
    t.p.ok(&[]);
    let (code, out, err) = replay(&[]);
    assert_eq!(code, 2, "{}{}", out, err);
    let here = json!({
        "direct": {"tok": tok2.id},
        "packages": {
            t.bpe.id.clone(): {"hash": t.bpe.hash(), "version": "0.3.1"},
            tok2.id.clone(): {"hash": tok2.hash(), "version": "0.1.0"},
        }
    });
    assert!(
        err.contains(&format!(
            "--replay: the receipt's modules ({}) are not the ones here ({}); to run against it anyway, add --replay-any-program (the result is not a verification)",
            modules_json(&t),
            here
        )),
        "{}",
        err
    );
    // Con el flag corre, y no es una verificación.
    let (code, _, err) = replay(&["--replay-any-program"]);
    assert_eq!(code, 0, "{}", err);
    assert!(err.contains("(another program: not a verification)"), "{}", err);
    t.p.write(saved);

    // R8: un recibo viejo (sin `modules`) con paquetes acá: el mismo error con `none`.
    let mut old = opened.clone();
    old["header"].as_object_mut().unwrap().remove("modules");
    std::fs::write(t.p.dir.join("opened.json"), old.to_string()).unwrap();
    let (code, _, err) = replay(&[]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains(&format!("--replay: the receipt's modules (none) are not the ones here ({})", modules_json(&t))), "{}", err);
}

/// R9: `code sha` muestra cada paquete por su clave, nunca por la carpeta del caché.
#[test]
fn r9_code_sha_shows_the_package_key_not_the_cache() {
    let t = two("r9");
    std::fs::write(t.p.dir.join("p.syn"), "use \"tok\" as tok\nprint(tok.cual())\n").unwrap();
    let cache = t.p.cache.to_string_lossy().into_owned();
    let (code, out, err) = synsema_env(&t.p.dir, &["code", "sha", "p.syn", "--json"], None, &[("SYNSEMA_MODULE_CACHE", &cache)]);
    assert_eq!(code, 0, "{}", err);
    let j: Value = serde_json::from_str(&out).unwrap();
    let mains: Vec<&str> = j["packages"].as_array().unwrap().iter().map(|p| p["main"].as_str().unwrap()).collect();
    let want = format!("pkg:{}/m.syn", t.tok.hash().replacen(':', "-", 1));
    assert!(mains.contains(&want.as_str()), "{}", out);
    assert!(!out.contains("cache"), "{}", out);
}

/// R11 (con `run --attest`; `serve --attested` arma el config con el mismo `modules_of`): dos
/// corridas que sólo difieren en el hash de `tok` (los mismos `.syn`, otra plantilla) dan otro
/// `config_sha` y otro `report_data`.
#[test]
fn r11_the_attestation_binds_the_packages() {
    let reg = Reg::start();
    let id = format!("{}/tok", reg.base());
    let main = "export task cual()\n    give \"x\"\nexport task vista()\n    give render(\"v.html\")\n";
    let a = Pkg::new(&id, "0.1.0", main).file("v.html", "uno");
    let b = Pkg::new(&id, "0.1.0", main).file("v.html", "dos");
    let ua = reg.publish("/tok/a", &a);
    let ub = reg.publish("/tok/b", &b);
    let mut docs = Vec::new();
    for (tag, u) in [("r11a", &ua), ("r11b", &ub)] {
        let p = Proj::new(tag, modules(&[("tok", url(u))]));
        p.ok(&[]);
        std::fs::write(p.dir.join("p.syn"), "use \"tok\" as tok\nprint(tok.cual())\n").unwrap();
        let cache = p.cache.to_string_lossy().into_owned();
        let (code, out, err) =
            synsema_env(&p.dir, &["run", "--attest", "p.syn"], None, &[("SYNSEMA_MODULE_CACHE", &cache), ("SYNSEMA_ATTEST", "mock")]);
        assert_eq!(code, 0, "{}", err);
        let j: Value = serde_json::from_str(out.lines().last().unwrap()).unwrap();
        docs.push(j);
    }
    assert_eq!(docs[0]["program_sha"], docs[1]["program_sha"], "los .syn del programa son los mismos");
    assert_eq!(docs[0]["config"]["modules"]["packages"][&id]["hash"], json!(a.hash()));
    assert_eq!(docs[1]["config"]["modules"]["packages"][&id]["hash"], json!(b.hash()));
    assert_ne!(docs[0]["config_sha"], docs[1]["config_sha"]);
    assert_ne!(docs[0]["attestation"], docs[1]["attestation"]);
}

/// R10 (s1): el programa reescribe `m.syn` entre dos `parallel_map` cuyas tasks hacen `use "./m.syn"`:
/// las dos rondas ven lo de la tabla (V = 1), y el `program_sha` del recibo es el de lo que corrió.
#[test]
fn r10_a_module_rewritten_while_running_is_not_what_the_workers_see() {
    let p = Proj::new("r10", json!({}));
    std::fs::write(p.dir.join("m.syn"), "export let V be 1\n").unwrap();
    let src = "require file.write(\"**\")\ntask v(x)\n    use \"./m.syn\" as m\n    give m.V\nprint(parallel_map(v, [1, 2]))\nwrite_file(\"m.syn\", \"export let V be 2\\n\")\nprint(parallel_map(v, [1, 2]))\nprint(receipt().credentialSubject.program_sha)\n";
    std::fs::write(p.dir.join("p.syn"), src).unwrap();
    let (code, sha_before, err) = synsema_env(&p.dir, &["code", "sha", "p.syn"], None, &[]);
    assert_eq!(code, 0, "{}", err);
    let (code, out, err) = synsema_env(&p.dir, &["run", "p.syn"], None, &[]);
    assert_eq!(code, 0, "{}", err);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(&lines[..2], &["[1, 1]", "[1, 1]"], "{}", out);
    assert_eq!(lines[2], sha_before.trim());
}

/// A2 (ronda 1): el header sellado nombra los paquetes de la tabla que armó la corrida, aunque el
/// programa reescriba su `synsema.json` mientras corre (a otro paquete que también está en el caché);
/// `--replay` con ese `synsema.json` cambiado da R6. Lo mismo en cada request de `serve --auditor`.
#[test]
fn a2_the_sealed_header_names_what_ran_not_what_is_on_disk_at_the_end() {
    use super::build_cli::{free_port, http, wait_ready, KillOnDrop};
    let t = two("a2");
    let b = t.reg.base();
    let tok2 = uses_bpe(&format!("{}/tok-fork", b), "0.1.0", &format!("{}/bpe-core/0.3.1/synsema.json", b), &t.bpe);
    let u2 = t.reg.publish("/tok-fork/0.1.0", &tok2);
    // El otro paquete, bajado al caché; después se vuelve al `synsema.json` de antes y el otro queda
    // en `evil.json`, que el programa copia encima mientras corre.
    let saved = t.p.json();
    let mut evil = saved.clone();
    evil["modules"]["tok"] = url(&u2);
    t.p.write(evil.clone());
    t.p.ok(&[]);
    let evil_text = std::fs::read_to_string(t.p.dir.join("synsema.json")).unwrap();
    std::fs::write(t.p.dir.join("evil.json"), &evil_text).unwrap();
    t.p.write(saved.clone());
    let (sk, pk) = auditor_keys();
    let src = "require file.write(\"synsema.json\")\nrequire file.read(\"evil.json\")\nuse \"tok\" as tok\nprint(tok.cual())\nwrite_file(\"synsema.json\", read_file(\"evil.json\"))\n";
    let (code, out, err) = run_args(&t.p, &["run", "--auditor", &pk, "p.syn"], src);
    assert_eq!((code, out.trim()), (0, "bpe"), "{}", err);
    let opened = open_receipt(&receipt_in(&err), &sk);
    assert_eq!(opened["header"]["modules"], modules_json(&t), "el header nombra otro paquete que el que corrió");
    std::fs::write(t.p.dir.join("opened.json"), opened.to_string()).unwrap();
    // El `synsema.json` quedó como lo dejó el programa (el otro): `--replay` no lo da por bueno.
    let (code, out, err) = run_args(&t.p, &["run", "--replay", "opened.json", "p.syn"], src);
    assert_eq!(code, 2, "{}{}", out, err);
    assert!(err.contains("--replay: the receipt's modules ("), "{}", err);

    // `serve --auditor`: cada request sella con la tabla de la corrida.
    t.p.write(saved);
    let port = free_port();
    let srv = format!(
        "require serve({port})\nrequire file.write(\"synsema.json\")\nrequire file.read(\"evil.json\")\nuse \"tok\" as tok\nwrite_file(\"synsema.json\", read_file(\"evil.json\"))\nserve on {port}\n    route \"GET /api/ping\"\n        give \"pong\"\n    route \"GET /\"\n        give tok.cual()\n"
    );
    std::fs::write(t.p.dir.join("srv.syn"), srv).unwrap();
    let cache = t.p.cache.to_string_lossy().into_owned();
    {
        let _child = KillOnDrop(
            std::process::Command::new(env!("CARGO_BIN_EXE_synsema"))
                .args(["serve", "--auditor", &pk, "--receipt", "r.jsonl", "srv.syn"])
                .current_dir(&t.p.dir)
                .env("SYNSEMA_NO_UPDATE_CHECK", "1")
                .env("SYNSEMA_MODULE_CACHE", &cache)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn synsema serve"),
        );
        wait_ready(port);
        let (st, head, body) = http(port, "/");
        assert_eq!((st, body.as_str()), (200, "\"bpe\""), "{}", head);
    }
    let lines = std::fs::read_to_string(t.p.dir.join("r.jsonl")).unwrap();
    let last = lines.lines().filter(|l| !l.trim().is_empty()).last().expect("un recibo por request");
    let opened = open_receipt(&serde_json::from_str::<Value>(last).unwrap(), &sk);
    assert_eq!(opened["header"]["modules"], modules_json(&t), "el header del request nombra otro paquete");
}

/// Ronda 2 (M-r2-1): con `run --auditor`, una corrida que falla antes de su primera sentencia (no
/// parsea, o su tabla da error) imprime su error y deja el recibo, sin `modules` (no corrió ningún
/// paquete), como en v0.6.57. Una que armó la tabla y falla al correr nombra lo que corrió.
#[test]
fn m_r2_1_a_run_that_fails_before_starting_still_leaves_its_receipt() {
    let t = two("mr21");
    let (sk, pk) = auditor_keys();
    let cases: [(&str, &str); 2] = [("let x be 1 +\n", "p.syn:"), ("use \"nope\" as f\nprint(1)\n", "nope")];
    for (src, says_err) in cases {
        let (code, _out, err) = run_args(&t.p, &["run", "--auditor", &pk, "p.syn"], src);
        assert_eq!(code, 1, "{}", err);
        assert!(!err.contains("could not be delivered"), "{}", err);
        assert!(err.contains(says_err), "el error del programa no se imprime: {}", err);
        let opened = open_receipt(&receipt_in(&err), &sk);
        assert!(opened["header"].get("modules").map_or(true, |m| m.is_null()), "{}", opened);
    }
    let (code, _out, err) = run_args(&t.p, &["run", "--auditor", &pk, "p.syn"], "use \"tok\" as tok\nprint(tok.cual())\nprint(no_existe)\n");
    assert_eq!(code, 1, "{}", err);
    let opened = open_receipt(&receipt_in(&err), &sk);
    assert_eq!(opened["header"]["modules"], modules_json(&t), "{}", err);
}

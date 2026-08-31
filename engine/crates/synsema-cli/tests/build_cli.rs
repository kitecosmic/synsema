//! E2E de `synsema build` sobre el binario real (spec `specs/tanda-motor-lamps.md`): el
//! binario único corre el programa con `args()`, `--engine` devuelve el CLI, el sha del
//! bundle se verifica, los `use`/templates/assets viven dentro (sin disco), el techo y el
//! perfil horneados mandan, y `update` se niega a pisar un programa construido.

use std::path::PathBuf;
use std::process::Command;

fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-build-cli-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("lib")).unwrap();
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(
        dir.join("lamp.syn"),
        "use \"./lib/m.syn\" as m\nprint(m.twice(21))\nprint(args())\nprint(read_file(\"assets/a.json\"))\nprint(file_exists(\"assets/a.json\"))\nprint(render(\"card.html\", {\"name\": \"lamp\"}))\n",
    )
    .unwrap();
    std::fs::write(dir.join("lib").join("m.syn"), "export task twice(x)\n    give x * 2\n").unwrap();
    std::fs::write(dir.join("assets").join("a.json"), "{\"k\": 1}").unwrap();
    std::fs::write(dir.join("card.html"), "<b>{ name }</b>\n").unwrap();
    dir
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{}.exe", base)
    } else {
        base.to_string()
    }
}

fn run(cmd: &PathBuf, dir: &PathBuf, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .expect("spawn");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn synsema(dir: &PathBuf, args: &[&str]) -> (i32, String, String) {
    run(&PathBuf::from(env!("CARGO_BIN_EXE_synsema")), dir, args)
}

fn build(dir: &PathBuf, extra: &[&str]) -> PathBuf {
    let out = dir.join(exe_name("lamp"));
    let mut args = vec!["build", "lamp.syn", "-o", out.to_str().unwrap(), "--include", "assets/"];
    args.extend_from_slice(extra);
    let (code, stdout, err) = synsema(dir, &args);
    assert_eq!(code, 0, "{}\n{}", stdout, err);
    assert!(stdout.starts_with("built "), "{}", stdout);
    out
}

#[test]
fn build_hello_and_run_it_without_the_sources_on_disk() {
    let dir = project("hello");
    let lamp = build(&dir, &[]);
    // Sin los fuentes ni los assets en disco: todo vive en el bundle.
    std::fs::remove_dir_all(dir.join("lib")).unwrap();
    std::fs::remove_dir_all(dir.join("assets")).unwrap();
    std::fs::remove_file(dir.join("card.html")).unwrap();
    std::fs::remove_file(dir.join("lamp.syn")).unwrap();
    let (code, out, err) = run(&lamp, &dir, &["--hello", "world"]);
    assert_eq!(code, 0, "{}", err);
    let lines: Vec<&str> = out.lines().map(|l| l.trim()).collect();
    assert_eq!(lines[0], "42");
    assert_eq!(lines[1], "[--hello, world]");
    assert_eq!(lines[2], "{\"k\": 1}");
    assert_eq!(lines[3], "true");
    assert!(lines[4].contains("<b>lamp</b>"), "{}", out);
    // `--engine` es el CLI del motor.
    let (code, out, _) = run(&lamp, &dir, &["--engine", "version"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("Synsema "), "{}", out);
    // `update` se niega sobre un programa construido.
    let (code, _, err) = run(&lamp, &dir, &["--engine", "update"]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("built program"), "{}", err);
    // El binario `synsema` de siempre acepta `--engine` como prefijo no-op.
    let (code, out, _) = synsema(&dir, &["--engine", "version"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("Synsema "));
}

#[test]
fn corrupt_sha_refuses_to_run() {
    let dir = project("corrupt");
    let lamp = build(&dir, &[]);
    let mut bytes = std::fs::read(&lamp).unwrap();
    // Un byte del payload (justo antes del trailer de 64 bytes) alterado.
    let idx = bytes.len() - 64 - 3;
    bytes[idx] ^= 0xff;
    let broken = dir.join(exe_name("broken"));
    std::fs::write(&broken, &bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let (code, out, err) = run(&broken, &dir, &[]);
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("bundle corrupt"), "{}", err);
    assert!(out.trim().is_empty());
}

#[test]
fn bundled_reads_are_audited_and_writes_are_rejected() {
    let dir = project("audit");
    std::fs::write(
        dir.join("lamp.syn"),
        "print(read_file(\"assets/a.json\"))\ntry\n    write_file(\"assets/a.json\", \"x\")\nrecover e\n    print(e)\n",
    )
    .unwrap();
    // Techo SIN file: la lectura del bundle no lo necesita (es parte del programa).
    let lamp = build(&dir, &["--cap-set", "stdout"]);
    let (code, out, err) = run(&lamp, &dir, &["--engine", "run", "--audit", "json", "lamp.syn"]);
    // `--engine run lamp.syn` corre desde DISCO sin overlay → pide file.read y falla.
    assert_eq!(code, 1, "{}", err);
    assert!(err.contains("Capability not granted: file_read"), "{}", err);
    let _ = (code, out);
    // En modo programa: lee del bundle, audita `bundled asset`, y la escritura se rechaza.
    let audit = dir.join("a.jsonl");
    std::fs::write(dir.join("lamp.syn"), "require file.write(\"assets/a.json\")\nprint(read_file(\"assets/a.json\"))\ntry\n    write_file(\"assets/a.json\", \"x\")\nrecover e\n    print(e)\n").unwrap();
    let lamp = build(&dir, &["--cap-set", "stdout,file.write=assets/a.json"]);
    let _ = audit;
    let (code, out, err) = run(&lamp, &dir, &[]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("{\"k\": 1}"), "{}", out);
    assert!(out.contains("is part of the bundle (read-only)"), "{}", out);
}

#[test]
fn baked_cap_set_and_profile_pure_are_enforced() {
    let dir = project("baked");
    let (sh, args) = if cfg!(windows) { ("cmd", "\"/C\", \"echo pwned\"") } else { ("sh", "\"-c\", \"echo pwned\"") };
    std::fs::write(
        dir.join("lamp.syn"),
        format!("require exec(\"{sh}\")\ntry\n    let r be run(\"{sh}\", [{args}])\n    print(r[\"stdout\"])\nrecover e\n    print(e)\n", sh = sh, args = args),
    )
    .unwrap();
    // Techo horneado sin exec.
    let lamp = build(&dir, &["--sandbox"]);
    let (code, out, _) = run(&lamp, &dir, &[]);
    assert_eq!(code, 0);
    assert!(!out.contains("pwned"), "{}", out);
    assert!(out.contains("above the host ceiling"), "{}", out);
    // Los argumentos del programa NO son flags del motor: `--sandbox` acá es un arg.
    std::fs::write(dir.join("lamp.syn"), "print(args())\n").unwrap();
    let lamp = build(&dir, &[]);
    let (code, out, _) = run(&lamp, &dir, &["--sandbox", "--cap-set", "x"]);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), "[--sandbox, --cap-set, x]");
    // Perfil puro horneado: `run` es un stub aunque el techo lo permita.
    std::fs::write(
        dir.join("lamp.syn"),
        format!("require exec(\"{sh}\")\ntry\n    run(\"{sh}\", [])\nrecover e\n    print(e)\nprint(read_file(\"assets/a.json\"))\n", sh = sh),
    )
    .unwrap();
    let lamp = build(&dir, &["--profile", "pure"]);
    let (code, out, err) = run(&lamp, &dir, &[]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("run: not available in the pure profile"), "{}", out);
    // Las lecturas del bundle no son filesystem: siguen funcionando bajo pure.
    assert!(out.contains("{\"k\": 1}"), "{}", out);
}

#[test]
fn baked_sandbox_serves_bundle_but_denies_disk_and_traversal() {
    // Un binario horneado con techo `--sandbox` (sin `file`): lee su bundle (parte del
    // programa) pero NO puede leer disco arbitrario ni escapar por `..`.
    let dir = project("traversal");
    std::fs::write(dir.join("secret_on_disk.txt"), "SECRET_ON_DISK").unwrap();
    let parent = dir.parent().unwrap().to_path_buf();
    std::fs::write(parent.join("outside_secret_marker.txt"), "SECRET_OUTSIDE").unwrap();
    std::fs::write(
        dir.join("lamp.syn"),
        "print(\"bundle: \" + read_file(\"assets/a.json\"))\ntry\n    print(\"disk: \" + read_file(\"secret_on_disk.txt\"))\nrecover e\n    print(\"disk denied\")\ntry\n    print(\"trav: \" + read_file(\"../outside_secret_marker.txt\"))\nrecover e\n    print(\"trav denied\")\n",
    )
    .unwrap();
    let lamp = build(&dir, &["--sandbox"]);
    let (code, out, err) = run(&lamp, &dir, &[]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("bundle: {\"k\": 1}"), "{}", out);
    assert!(out.contains("disk denied"), "leyó disco fuera del bundle: {}", out);
    assert!(out.contains("trav denied"), "escapó por traversal: {}", out);
    assert!(!out.contains("SECRET_ON_DISK") && !out.contains("SECRET_OUTSIDE"), "{}", out);
    let _ = std::fs::remove_file(parent.join("outside_secret_marker.txt"));
}

#[test]
fn build_usage_errors_exit_2() {
    let dir = project("usage");
    let out = dir.join(exe_name("x"));
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn"]);
    assert_eq!(code, 2, "{}", err);
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", out.to_str().unwrap(), "--include", "../nope"]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("matched nothing") || err.contains("not found"), "{}", err);
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", out.to_str().unwrap(), "--include", "../lamp.syn"]);
    assert_eq!(code, 2, "{}", err);
    let (code, _, err) = synsema(&dir, &["build", "lamp.syn", "-o", out.to_str().unwrap(), "--profile", "bogus"]);
    assert_eq!(code, 2, "{}", err);
    // Construir desde un binario ya construido se rechaza.
    let lamp = build(&dir, &[]);
    let (code, _, err) = run(&lamp, &dir, &["--engine", "build", "lamp.syn", "-o", out.to_str().unwrap()]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("already a built program"), "{}", err);
}

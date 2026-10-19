//! v0.6.45 — un link (symlink, junction) no saca una ruta de su límite. `use` y los scopes de
//! `file.*` comparaban por NOMBRE: con `tools/ext` como junction a otra carpeta, `use "./ext/o.syn"`
//! cargaba código de afuera y `read_file("data/ext/x")` leía fuera de `file.read("./data/*")`. Ahora
//! también se decide en disco. Y `read_file` dice la causa real cuando no puede leer.
//! En Windows los links son junctions (`mklink /J`, sin privilegios); en Unix, symlinks.

use std::path::Path;
use std::process::Command;

fn link_dir(target: &Path, link: &Path) {
    #[cfg(windows)]
    {
        // `mklink` no acepta `/` como separador (lo lee como una opción).
        let win = |p: &Path| p.to_string_lossy().replace('/', "\\");
        let ok = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(win(link))
            .arg(win(target))
            .output()
            .expect("mklink")
            .status
            .success();
        assert!(ok, "mklink /J {} {}", link.display(), target.display());
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
}

struct Tree(std::path::PathBuf);

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `<tmp>/<name>/{proj,outside}`: `outside/o.syn` y `outside/secret.txt` fuera del proyecto.
fn tree(name: &str) -> Tree {
    let root = std::env::temp_dir().join(format!("synsema-v0645-links-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("proj/tools/real")).unwrap();
    std::fs::create_dir_all(root.join("proj/data/in")).unwrap();
    std::fs::create_dir_all(root.join("outside")).unwrap();
    std::fs::write(root.join("outside/o.syn"), "export task hi()\n    give \"de afuera\"\n").unwrap();
    std::fs::write(root.join("outside/secret.txt"), "SECRETO de afuera\n").unwrap();
    std::fs::write(root.join("proj/tools/real/r.syn"), "export task hi()\n    give \"de adentro\"\n").unwrap();
    std::fs::write(root.join("proj/data/in/a.txt"), "hola adentro\n").unwrap();
    link_dir(&root.join("outside"), &root.join("proj/tools/ext"));
    link_dir(&root.join("outside"), &root.join("proj/data/ext"));
    link_dir(&root.join("proj/tools/real"), &root.join("proj/tools/alias"));
    Tree(root)
}

fn synsema(cwd: &Path, args: &[&str], src: &str) -> (i32, String, String) {
    std::fs::write(cwd.join("app.syn"), src).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .arg("run")
        .args(args)
        .arg("app.syn")
        .current_dir(cwd)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .expect("spawn synsema");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn use_does_not_follow_a_link_out_of_the_project() {
    let t = tree("use");
    let proj = t.0.join("proj");
    // tools/main.syn importa por la junction que sale: antes cargaba outside/o.syn.
    std::fs::write(proj.join("tools/main.syn"), "use \"./ext/o.syn\" as o\nexport task go()\n    give o.hi()\n").unwrap();
    let (code, out, err) = synsema(&proj, &[], "use \"./tools/main.syn\" as m\nprint(m.go())\n");
    assert_ne!(code, 0, "{}{}", out, err);
    assert!(!out.contains("de afuera"), "{}", out);
    assert!(err.contains("through a link") && err.contains("./ext/o.syn"), "{}", err);
    // Un link que queda DENTRO del proyecto sigue valiendo.
    let (code, out, err) = synsema(&proj, &[], "use \"./tools/alias/r.syn\" as r\nprint(r.hi())\n");
    assert_eq!(code, 0, "{}", err);
    assert_eq!(out.trim(), "de adentro");
}

#[test]
fn use_works_when_the_project_itself_is_reached_through_a_link() {
    let t = tree("root");
    // El proyecto entero visto por un link: los links que SON parte de la raíz valen.
    link_dir(&t.0.join("proj"), &t.0.join("proj-link"));
    let cwd = t.0.join("proj-link");
    let (code, out, err) = synsema(&cwd, &[], "use \"./tools/real/r.syn\" as r\nprint(r.hi())\n");
    assert_eq!(code, 0, "{}", err);
    assert_eq!(out.trim(), "de adentro");
}

#[test]
fn file_scopes_are_checked_where_the_path_really_leads() {
    let t = tree("file");
    let proj = t.0.join("proj");
    let src = r#"require file.read("./data/*")
require file.read("./data")
print(read_file("data/in/a.txt"))
try
    print(read_file("data/ext/secret.txt"))
recover e
    print("ERR " + e)
print(length(grep("data", "SECRETO")["matches"]))
print(length(grep("data", "hola")["matches"]))
"#;
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("hola adentro"), "{}", out);
    assert!(!out.contains("SECRETO de afuera"), "{}", out);
    assert!(out.contains("ERR ") && out.contains("a link (symlink or junction) on the way leads outside"), "{}", out);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(&lines[lines.len() - 2..], &["0", "1"], "grep no entra por el link: {}", out);
}

#[test]
fn the_host_ceiling_holds_against_a_link_too() {
    let t = tree("ceiling");
    let proj = t.0.join("proj");
    // El programa pide `./data/ext/*`: por nombre cae dentro del techo del host (./data/*), en
    // disco no — el techo lo rechaza al conceder y el uso dice que está por encima del techo.
    let src = "require file.read(\"./data/ext/*\")\nrequire file.read(\"./data/in/*\")\ntry\n    print(read_file(\"data/ext/secret.txt\"))\nrecover e\n    print(\"ERR \" + e)\nprint(read_file(\"data/in/a.txt\"))\n";
    let (code, out, err) = synsema(&proj, &["--cap-set", "stdout,file.read=./data/*"], src);
    assert_eq!(code, 0, "{}", err);
    assert!(!out.contains("SECRETO"), "{}", out);
    assert!(out.contains("ERR ") && out.contains("ceiling"), "{}", out);
    assert!(out.contains("hola adentro"), "{}", out);
}

#[test]
fn list_dir_and_file_info_report_links_the_same_way() {
    let t = tree("info");
    let proj = t.0.join("proj");
    let src = r#"require file.read("./tools")
require file.read("./tools/*")
each e in list_dir("tools")
    print(e["name"] + " dir=" + text(e["is_dir"]) + " link=" + text(e["is_link"]))
let i be file_info("tools/alias")
print("info alias dir=" + text(i["is_dir"]) + " link=" + text(i["is_link"]))
let r be file_info("tools/real")
print("info real link=" + text(r["is_link"]))
"#;
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("alias dir=true link=true"), "{}", out);
    assert!(out.contains("ext dir=true link=true"), "{}", out);
    assert!(out.contains("real dir=true link=false"), "{}", out);
    assert!(out.contains("info alias dir=true link=true"), "{}", out);
    assert!(out.contains("info real link=false"), "{}", out);
}

#[test]
fn read_file_names_the_real_cause() {
    let t = tree("errors");
    let proj = t.0.join("proj");
    std::fs::write(proj.join("data/bin.dat"), [0xffu8, 0xfe, 0x00, 0x80]).unwrap();
    let src = r#"require file.read("./data/*")
each p in ["data/in", "data/bin.dat", "data/nope.txt"]
    try
        read_file(p)
    recover e
        print(e)
"#;
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("Cannot read file data/in: it is a directory"), "{}", out);
    assert!(out.contains("Cannot read file data/bin.dat: it is not valid UTF-8 text (use read_file_bytes)"), "{}", out);
    assert!(out.contains("File not found: data/nope.txt"), "{}", out);
}

/// Un archivo abierto sin compartir por otro proceso (lo que hace un editor o un antivirus en
/// Windows): antes `File not found`; ahora dice que está en uso, y que reintentar sirve.
#[cfg(windows)]
#[test]
fn read_file_says_when_another_process_holds_the_file() {
    use std::os::windows::fs::OpenOptionsExt;
    let t = tree("locked");
    let proj = t.0.join("proj");
    std::fs::write(proj.join("data/locked.syn"), "print(1)\n").unwrap();
    let _held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(proj.join("data/locked.syn"))
        .unwrap();
    let src = "require file.read(\"./data/*\")\ntry\n    read_file(\"data/locked.syn\")\nrecover e\n    print(e)\nprint(file_info(\"data/locked.syn\")[\"exists\"])\n";
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("Cannot read file data/locked.syn: in use by another process"), "{}", out);
    assert!(out.contains("true"), "{}", out);
}

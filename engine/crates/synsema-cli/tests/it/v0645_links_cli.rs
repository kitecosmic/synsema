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
    let src = r#"require file.read("./data/**")
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
    let (code, out, err) = synsema(&proj, &["--cap-set", "stdout,file.read=./data/**"], src);
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
    // v0.6.51 (L1): `ext` lleva afuera del permiso; el motor no mira lo que hay detrás.
    assert!(out.contains("ext dir=false link=true"), "{}", out);
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

// ---------------------------------------------------------------------------------------------
// Segunda ronda (auditoría de v0.6.45): globs por segmentos, links rotos, temporales, la raíz de
// una unidad, carpetas que distinguen mayúsculas, y los caminos de archivos que no pasaban por el
// gate (static, SQLite ATTACH/VACUUM INTO, run_program con cwd, include/layout).
// ---------------------------------------------------------------------------------------------

/// `./*` es "los archivos de esta carpeta": antes el `*` cruzaba `/` y `..` y daba el disco entero.
#[test]
fn a_star_scope_is_this_folder_not_the_disk() {
    let t = tree("star");
    let proj = t.0.join("proj");
    std::fs::write(proj.join("top.txt"), "arriba\n").unwrap();
    let src = r#"require file.read("./*")
print(read_file("top.txt"))
each p in ["../outside/secret.txt", "data/in/a.txt"]
    try
        print(read_file(p))
    recover e
        print("ERR " + p)
"#;
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("arriba"), "{}", out);
    assert!(!out.contains("SECRETO") && !out.contains("hola adentro"), "{}", out);
    assert!(out.contains("ERR ../outside/secret.txt") && out.contains("ERR data/in/a.txt"), "{}", out);
    // `./**` sí cruza carpetas, pero no sale del proyecto por nombre ni por un link.
    let src = r#"require file.read("./**")
print(read_file("data/in/a.txt"))
try
    print(read_file("data/ext/secret.txt"))
recover e
    print("ERR link")
try
    print(read_file("../outside/secret.txt"))
recover e
    print("ERR up")
"#;
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("hola adentro") && out.contains("ERR link") && out.contains("ERR up"), "{}", out);
    assert!(!out.contains("SECRETO"), "{}", out);
}

/// Un link roto existe como nombre: escribir por él crea el archivo en su destino. Se juzga el
/// destino (antes se lo tomaba como un nombre cualquiera y quedaba "adentro").
#[test]
fn writing_through_a_broken_link_is_judged_at_its_target() {
    let t = tree("broken");
    let proj = t.0.join("proj");
    // data/drop -> outside/nueva (no existe todavía).
    link_dir(&t.0.join("outside").join("nueva"), &proj.join("data").join("drop"));
    let src = r#"require file.write("./data/**")
try
    append_file("data/drop/x.txt", "clave")
    print("ESCRIBIO")
recover e
    print("ERR " + e)
"#;
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(!out.contains("ESCRIBIO"), "{}", out);
    assert!(out.contains("leads outside"), "{}", out);
    assert!(!t.0.join("outside/nueva/x.txt").exists());
}

/// Unix: un symlink roto a un ARCHIVO, el temporal predecible de `write_file` con un link plantado,
/// y un scope sin parte literal (`*.csv`) con un link afuera.
#[cfg(unix)]
#[test]
fn file_links_cannot_write_or_read_outside() {
    let t = tree("filelinks");
    let proj = t.0.join("proj");
    std::os::unix::fs::symlink(t.0.join("outside/authorized_keys"), proj.join("data/log.txt")).unwrap();
    std::os::unix::fs::symlink(t.0.join("outside/bashrc"), proj.join("data/out.txt.synsema.tmp")).unwrap();
    std::os::unix::fs::symlink(t.0.join("outside/secret.txt"), proj.join("ventas.csv")).unwrap();
    let src = r#"require file.write("./data/**")
require file.read("*.csv")
try
    append_file("data/log.txt", "clave")
recover e
    print("ERR append")
write_file("data/out.txt", "hola")
try
    print(read_file("ventas.csv"))
recover e
    print("ERR csv")
"#;
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("ERR append") && out.contains("ERR csv"), "{}", out);
    assert!(!out.contains("SECRETO"), "{}", out);
    assert!(!t.0.join("outside/authorized_keys").exists());
    assert!(!t.0.join("outside/bashrc").exists(), "el temporal no sigue un link plantado");
    assert_eq!(std::fs::read_to_string(proj.join("data/out.txt")).unwrap(), "hola");
}

/// Windows: un scope en la raíz de una unidad (`C:/**`) cubre la unidad (la base `C:` se tomaba
/// como un nombre relativo y no cubría nada).
#[cfg(windows)]
#[test]
fn a_drive_root_scope_covers_the_drive() {
    let t = tree("drive");
    let proj = t.0.join("proj");
    let drive = proj.to_string_lossy()[..2].to_string();
    // Ruta absoluta: por nombre, un scope absoluto se compara con rutas absolutas.
    let file = proj.join("data/in/a.txt").to_string_lossy().replace('\\', "/");
    let src = format!("require file.read(\"{}/**\")\nprint(read_file(\"{}\"))\n", drive, file);
    let (code, out, err) = synsema(&proj, &[], &src);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("hola adentro"), "{}", out);
}

/// Windows: en una carpeta que distingue mayúsculas (las que crea WSL), `DATA` y `data` son dos
/// cosas: `DATA` como junction afuera no pasa por ser `data` en minúsculas.
#[cfg(windows)]
#[test]
fn a_case_sensitive_folder_is_not_fooled_by_case() {
    let t = tree("case");
    let proj = t.0.join("proj");
    let sub = proj.join("cs");
    std::fs::create_dir_all(&sub).unwrap();
    let ok = Command::new("fsutil")
        .args(["file", "setCaseSensitiveInfo"])
        .arg(&sub)
        .arg("enable")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("(fsutil setCaseSensitiveInfo no disponible: se saltea)");
        return;
    }
    // Primero la junction y después la carpeta real: `mklink` (cmd) no distingue mayúsculas.
    link_dir(&t.0.join("outside"), &sub.join("DATA"));
    std::fs::create_dir(sub.join("data")).unwrap();
    let src = "require file.read(\"./data/**\")\ntry\n    print(read_file(\"DATA/secret.txt\"))\nrecover e\n    print(\"ERR\")\n";
    let (code, out, err) = synsema(&sub, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(!out.contains("SECRETO"), "{}", out);
    assert!(out.contains("ERR"), "{}", out);
}

/// `static` sirve una carpeta: pide `file.read("<dir>/**")`.
#[test]
fn static_needs_file_read_on_its_folder() {
    let t = tree("static");
    let proj = t.0.join("proj");
    std::fs::create_dir_all(proj.join("public")).unwrap();
    std::fs::write(proj.join("app.syn"), "require serve(18431)\nserve on 18431\n    static \"/\" from \"./public\"\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["serve", "app.syn"])
        .current_dir(&proj)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .expect("spawn synsema");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{}", err);
    assert!(err.contains("require file.read(\"public/**\")"), "{}", err);
}

/// SQLite: `ATTACH` y `VACUUM INTO` a un archivo no salen del `require db(...)`; un VACUUM normal
/// sí anda.
#[test]
fn sqlite_cannot_attach_or_vacuum_into_another_file() {
    let t = tree("sqlite");
    let proj = t.0.join("proj");
    let src = r#"require db("./app.db")
db_open("./app.db")
sql_exec("CREATE TABLE t (x INTEGER)")
each q in ["ATTACH DATABASE '../outside/robada.db' AS o", "VACUUM INTO '../outside/copia.db'"]
    try
        sql_exec(q)
        print("PASO " + q)
    recover e
        print("ERR " + e)
sql_exec("VACUUM")
print("vacuum ok")
"#;
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(!out.contains("PASO"), "{}", out);
    assert!(out.contains("vacuum ok"), "{}", out);
    assert!(!t.0.join("outside/robada.db").exists() && !t.0.join("outside/copia.db").exists());
}

/// `run_program` con `cwd`: el techo del hijo viaja con rutas absolutas, ancladas donde el padre
/// las decidió (antes `./data` se resolvía contra el `cwd` del hijo).
#[test]
fn run_program_ceiling_stays_anchored_in_the_parent() {
    let t = tree("runprog");
    let proj = t.0.join("proj");
    std::fs::create_dir_all(t.0.join("otro/data/in")).unwrap();
    std::fs::write(t.0.join("otro/data/in/a.txt"), "OTRO lado\n").unwrap();
    let cwd = t.0.join("otro").to_string_lossy().replace('\\', "/");
    let child = "require file.read(\"./data/**\")\ntry\n    print(read_file(\"data/in/a.txt\"))\nrecover e\n    print(\"ERR hijo\")\n";
    let src = format!(
        "require sandbox_run\nrequire file.read(\"./data/**\")\nlet r be run_program({child:?}, {{\"ceiling\": \"stdout,file.read=./data/**\", \"profile\": \"native\", \"cwd\": {cwd:?}, \"timeout\": 20}})\nprint(r[\"output\"])\nprint(r[\"errors\"])\n",
        child = child,
        cwd = cwd
    );
    let (code, out, err) = synsema(&proj, &[], &src);
    assert_eq!(code, 0, "{}", err);
    assert!(!out.contains("OTRO lado"), "{}", out);
}

/// `{ include }` / `{ layout }` leídos del disco pasan por `file.read` como `render()`.
#[test]
fn a_template_include_needs_file_read() {
    let t = tree("include");
    let proj = t.0.join("proj");
    std::fs::create_dir_all(proj.join("pages")).unwrap();
    std::fs::write(proj.join(".env"), "CLAVE=secreta\n").unwrap();
    std::fs::write(proj.join("pages/p.html"), "<p>{ include \".env\" }</p>\n").unwrap();
    let src = "require file.read(\"./pages/*\")\ntry\n    print(body of render(\"pages/p.html\", {}))\nrecover e\n    print(\"ERR \" + e)\n";
    let (code, out, err) = synsema(&proj, &["--no-env-file"], src);
    assert_eq!(code, 0, "{}", err);
    assert!(!out.contains("secreta"), "{}", out);
    assert!(out.contains("ERR ") && out.contains("Capability not granted"), "{}", out);
}

// ---------------------------------------------------------------------------------------------
// Tercera ronda (auditoría de v0.6.45, ronda 2).
// ---------------------------------------------------------------------------------------------

/// Unix: un link roto con destino ABSOLUTO que lleva `..` después de un nombre (`j/..`, con `j` un
/// link a otra carpeta) no se colapsa como texto: el sistema subiría desde el destino de `j`.
#[cfg(unix)]
#[test]
fn a_broken_link_with_an_absolute_dotdot_target_is_not_guessed() {
    let t = tree("absdotdot");
    let proj = t.0.join("proj");
    std::fs::create_dir_all(t.0.join("outside/sub")).unwrap();
    std::os::unix::fs::symlink(t.0.join("outside/sub"), proj.join("data/j")).unwrap();
    let target = format!("{}/data/j/../authorized_keys", proj.display());
    std::os::unix::fs::symlink(&target, proj.join("data/out")).unwrap();
    let src = "require file.write(\"./data/**\")\ntry\n    append_file(\"data/out\", \"clave\")\n    print(\"ESCRIBIO\")\nrecover e\n    print(\"ERR\")\n";
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("ERR") && !out.contains("ESCRIBIO"), "{}", out);
    assert!(!t.0.join("outside/authorized_keys").exists());
}

/// SQLite: un `ATTACH` con el nombre como expresión (el authorizer recibe NULL) y una URI `file:`
/// no salen del `require db(...)`; un pragma que cambia directorios tampoco pasa.
#[test]
fn sqlite_expressions_uris_and_directory_pragmas_are_refused() {
    let t = tree("sqlite2");
    let proj = t.0.join("proj");
    let src = r#"require db("./app.db")
require db("*.db")
db_open("./app.db")
each q in ["ATTACH '../outside/' || 'x.db' AS o", "ATTACH printf('%s', '../outside/y.db') AS o", "PRAGMA temp_store_directory = '../outside'"]
    try
        sql_exec(q)
        print("PASO " + q)
    recover e
        print("ERR")
try
    db_open("file:../outside/z.db?mode=rwc")
    print("PASO uri")
recover e
    print("ERR uri " + e)
"#;
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(!out.contains("PASO"), "{}", out);
    assert!(out.contains("ERR uri") && out.contains("`file:` URI"), "{}", out);
    for f in ["x.db", "y.db", "z.db"] {
        assert!(!t.0.join("outside").join(f).exists(), "{}", f);
    }
}

/// `run_program`: un scope con coma no viaja al hijo (se partía en items y le daba `exec`), y el
/// programa no le puede fijar variables `SYNSEMA_*` al motor del hijo.
#[test]
fn run_program_refuses_a_comma_scope_and_engine_variables() {
    let t = tree("rpguard");
    let proj = t.0.join("proj");
    let src = r#"require sandbox_run
require file.read("./data/*")
try
    print(run_program("print(1)", {"ceiling": {"file.read": "data/x,exec,file.read=y"}, "profile": "native"}))
recover e
    print("ERR coma " + e)
try
    print(run_program("print(1)", {"env": {"SYNSEMA_AUDIT": "../outside/pisado.txt"}, "profile": "native"}))
recover e
    print("ERR env " + e)
"#;
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("ERR coma") && out.contains("has a comma"), "{}", out);
    assert!(out.contains("ERR env") && out.contains("SYNSEMA_AUDIT"), "{}", out);
    assert!(!t.0.join("outside/pisado.txt").exists());
}

/// `grep` sobre una carpeta lee su árbol: pide `file.read("<carpeta>/**")`, no sólo la carpeta.
#[test]
fn grep_on_a_folder_needs_its_tree() {
    let t = tree("grep2");
    let proj = t.0.join("proj");
    let src = "require file.read(\"./data/in\")\ntry\n    print(length(grep(\"data/in\", \"hola\")[\"matches\"]))\nrecover e\n    print(\"ERR \" + e)\n";
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("ERR ") && out.contains("data/in/**"), "{}", out);
    let src = "require file.read(\"./data/in/**\")\nprint(length(grep(\"data/in\", \"hola\")[\"matches\"]))\n";
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(out.trim(), "1");
}

/// v0.6.45 (auditoría, ronda 2, M2): una operación que audita (acá `ed25519_sign`) dentro de una
/// rama decidida por un valor privado no corre: que la entrada del audit exista o no revelaba la
/// rama. Fuera de la rama firma y audita como siempre.
#[test]
fn signing_in_a_private_branch_is_refused_and_leaves_no_audit_line() {
    let t = tree("m2");
    let proj = t.0.join("proj");
    let audit = t.0.join("audit");
    let run = |src: &str| {
        std::fs::write(proj.join("app.syn"), src).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
            .args(["run", "--labels", "app.syn"])
            .current_dir(&proj)
            .env("SYNSEMA_NO_UPDATE_CHECK", "1")
            .env("SYNSEMA_AUDIT_DIR", &audit)
            .env("K", "1111111111111111111111111111111111111111111111111111111111111111")
            .output()
            .expect("spawn synsema");
        (String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
    };
    // `secret()` ya es un sumidero: se lee fuera de la rama, para que lo que se pruebe sea la firma.
    let pre = "require secret(\"K\")\nrequire sign(\"K\")\nlet k be secret(\"K\")\nlet p be private(1, [\"cliente\"])\n";
    let (out, err) = run(&format!("{}when p == 1\n    let s be ed25519_sign(\"hola\", k)\n", pre));
    // El error nace dentro de la rama privada y sale redactado (su texto dependería del dato): lo
    // que se verifica es que la corrida falla y que no queda línea de audit.
    let all = format!("{}{}", out, err);
    assert!(all.contains("Runtime error"), "{}", all);
    assert!(!audit.join("sign.log").exists(), "no queda línea de audit: {}", all);
    let (out, err) = run(&format!("{}print(length(ed25519_sign(\"hola\", k)))\n", pre));
    assert_eq!(out.trim(), "64", "{}", err);
    assert!(std::fs::read_to_string(audit.join("sign.log")).unwrap().contains("result=granted"));
}

// ---------------------------------------------------------------------------------------------
// Cuarta ronda (auditoría de v0.6.45, ronda 3).
// ---------------------------------------------------------------------------------------------

/// `db_open`: `./file:…` (normaliza a una URI de SQLite) y una ruta con `://` que no es un servidor
/// conocido no abren nada fuera del scope.
#[test]
fn db_open_refuses_uri_and_url_lookalikes() {
    let t = tree("dburi");
    let proj = t.0.join("proj");
    let out_abs = t.0.join("outside").join("robada.db").to_string_lossy().replace('\\', "/");
    let enc = out_abs.replace('/', "%2F").replace(':', "%3A");
    let src = format!(
        "require db(\"*.db\")\nrequire db(\"./data/*\")\neach t in [\"./file:{enc}\", \"x/../file:{enc}\", \"data/a://../../../outside/otra.db\"]\n    try\n        db_open(t)\n        print(\"PASO \" + t)\n    recover e\n        print(\"ERR\")\n",
        enc = enc
    );
    let (code, out, err) = synsema(&proj, &[], &src);
    assert_eq!(code, 0, "{}", err);
    assert!(!out.contains("PASO"), "{}", out);
    assert!(!t.0.join("outside/robada.db").exists() && !t.0.join("outside/otra.db").exists());
}

/// `run_program`: el `env` no puede fijar `HOME` (dónde audita `reveal` el hijo) y `filename` es una
/// etiqueta, no una ruta.
#[test]
fn run_program_refuses_path_variables_and_a_folder_filename() {
    let t = tree("rpenv");
    let proj = t.0.join("proj");
    let src = r#"require sandbox_run
try
    print(run_program("print(1)", {"env": {"HOME": "../outside"}, "profile": "native"}))
recover e
    print("ERR home " + e)
try
    print(run_program("print(1)", {"filename": "../outside/p.syn", "profile": "native"}))
recover e
    print("ERR filename " + e)
"#;
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("ERR home") && out.contains("HOME"), "{}", out);
    assert!(out.contains("ERR filename") && out.contains("label, not a path"), "{}", out);
}

/// Windows: el techo que `run_program` manda con `/data/**` viaja como `C:/data/**`; el hijo que
/// declara `/data/**` cae dentro (antes "above the host ceiling").
#[cfg(windows)]
#[test]
fn run_program_child_with_a_slash_scope_fits_the_parent_ceiling() {
    let t = tree("rpslash");
    let proj = t.0.join("proj");
    let child = "require file.read(\"/synsema-v0645-no-existe/**\")\nprint(\"hijo ok\")\n";
    let src = format!(
        "require sandbox_run\nrequire file.read(\"/synsema-v0645-no-existe/**\")\nlet r be run_program({child:?}, {{\"ceiling\": \"stdout,file.read=/synsema-v0645-no-existe/**\", \"profile\": \"native\", \"timeout\": 20}})\nprint(r[\"output\"])\nprint(r[\"errors\"])\n",
        child = child
    );
    let (code, out, err) = synsema(&proj, &[], &src);
    assert_eq!(code, 0, "{}", err);
    assert!(out.contains("hijo ok"), "{}", out);
    assert!(!out.contains("above the host ceiling"), "{}", out);
}

/// Una firma en rama privada no deja ni la entrada concedida del audit de capabilities.
#[test]
fn signing_in_a_private_branch_leaves_no_capability_audit_either() {
    let t = tree("m2b");
    let proj = t.0.join("proj");
    std::fs::write(
        proj.join("app.syn"),
        "require secret(\"K\")\nrequire sign(\"K\")\nlet k be secret(\"K\")\nlet p be private(1, [\"cliente\"])\nwhen p == 1\n    let s be ed25519_sign(\"hola\", k)\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["run", "--labels", "--audit", "json", "app.syn"])
        .current_dir(&proj)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .env("SYNSEMA_AUDIT_DIR", t.0.join("audit"))
        .env("K", "1111111111111111111111111111111111111111111111111111111111111111")
        .output()
        .expect("spawn synsema");
    let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(
        !all.lines().any(|l| l.contains("sign(") && l.contains("\"granted\":true")),
        "ninguna entrada de audit concedida para sign: {}",
        all
    );
    assert!(!t.0.join("audit/sign.log").exists(), "{}", all);
}

// ---------------------------------------------------------------------------------------------
// Quinta ronda (auditoría de v0.6.45, ronda 4).
// ---------------------------------------------------------------------------------------------

/// SQLite en modo defensivo sigue consultando una vista con FTS5 (`MATCH`, `bm25()`): el esquema no
/// se marca como no confiable.
#[test]
fn sqlite_fts5_views_still_work() {
    let t = tree("fts5");
    let proj = t.0.join("proj");
    let src = r#"require db("./app.db")
db_open("./app.db")
sql_exec("CREATE VIRTUAL TABLE docs USING fts5(body)")
sql_exec("INSERT INTO docs(body) VALUES ('hola mundo'), ('chau')")
sql_exec("CREATE VIEW hits AS SELECT body, bm25(docs) AS rank FROM docs WHERE docs MATCH 'hola'")
print(length(sql("SELECT body FROM hits")))
"#;
    let (code, out, err) = synsema(&proj, &[], src);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(out.trim(), "1", "{}", err);
}

/// `run_program` con `cwd` afuera: el estado del hijo (`memory`) no se crea en ese `cwd`.
#[test]
fn run_program_child_state_does_not_follow_cwd() {
    let t = tree("rpstate");
    let proj = t.0.join("proj");
    let cwd = t.0.join("outside").to_string_lossy().replace('\\', "/");
    let child = "require memory(\"m\")\nremember(\"k\", 1)\nprint(\"hijo\")\n";
    let src = format!(
        "require sandbox_run\nrequire memory(\"m\")\nlet r be run_program({child:?}, {{\"ceiling\": \"stdout,memory=m\", \"profile\": \"native\", \"cwd\": {cwd:?}, \"timeout\": 20}})\nprint(r[\"output\"])\nprint(r[\"errors\"])\n",
        child = child,
        cwd = cwd
    );
    let (code, out, err) = synsema(&proj, &[], &src);
    assert_eq!(code, 0, "{}", err);
    assert!(!t.0.join("outside/.synsema").exists(), "nada en el cwd del hijo: {}", out);
}

/// Con etiquetas, la cantidad de entradas del audit no depende de qué rama privada se tomó.
#[test]
fn the_audit_does_not_count_a_private_branch() {
    let t = tree("auditcount");
    let proj = t.0.join("proj");
    let count = |v: i64| {
        std::fs::write(
            proj.join("app.syn"),
            format!("require time\nlet p be private({}, [\"c\"])\nwhen p == 1\n    let t be now()\nprint(\"fin\")\n", v),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
            .args(["run", "--labels", "--audit", "json", "app.syn"])
            .current_dir(&proj)
            .env("SYNSEMA_NO_UPDATE_CHECK", "1")
            .output()
            .expect("spawn synsema");
        let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        all.matches("\"capability\"").count()
    };
    assert_eq!(count(1), count(2), "la rama tomada no cambia el audit");
}

/// Con etiquetas, un `require` dentro de una rama privada no concede nada: la corrida falla.
#[test]
fn a_require_in_a_private_branch_is_refused() {
    let t = tree("reqpriv");
    let proj = t.0.join("proj");
    std::fs::write(proj.join("app.syn"), "let p be private(1, [\"c\"])\nwhen p == 1\n    require random\nprint(\"fin\")\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["run", "--labels", "app.syn"])
        .current_dir(&proj)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .expect("spawn synsema");
    let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(!out.status.success(), "{}", all);
    assert!(!String::from_utf8_lossy(&out.stdout).contains("fin"), "{}", all);
}

/// Ronda 5 (M1): con varios programas en un mismo `synsema test`, el estado del hijo de
/// `run_program` queda junto al programa que lo lanzó, no junto al primero que corrió.
#[test]
fn run_program_child_state_follows_its_own_program_in_a_test_run() {
    let t = tree("rpstate-test");
    let (a, b) = (t.0.join("a"), t.0.join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("a_test.syn"), "test \"a\"\n    assert_eq(1, 1)\n").unwrap();
    let child = "require memory(\"m\")\nremember(\"learning\", \"del hijo\")\n";
    std::fs::write(
        b.join("b_test.syn"),
        format!(
            "require sandbox_run\nrequire memory(\"m\")\ntest \"b\"\n    let r be run_program({child:?}, {{\"ceiling\": \"memory=m\", \"profile\": \"native\", \"timeout\": 20}})\n    assert_eq(r[\"errors\"], [])\n    assert_eq(length(recall(\"learning\")), 1)\n",
            child = child
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["test", "a/a_test.syn", "b/b_test.syn"])
        .current_dir(&t.0)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .env_remove("SYNSEMA_STATE_DIR")
        .output()
        .expect("spawn synsema");
    let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "{}", all);
    assert!(!a.join(".synsema").exists(), "nada junto al otro programa: {}", all);
}

/// Ronda 5 (B1): padre e hijo comparten `memory=m`; lo que el hijo guardó vuelve al padre y un
/// `remember` posterior del padre no lo pisa (reusaba el id de la entrada del hijo).
#[test]
fn run_program_child_memory_is_not_overwritten_by_the_parent() {
    let t = tree("rpshared");
    let proj = t.0.join("proj");
    let child = "require memory(\"m\")\nremember(\"learning\", \"del hijo\")\n";
    let src = format!(
        "require sandbox_run\nrequire memory(\"m\")\nremember(\"learning\", \"padre 1\")\nlet r be run_program({child:?}, {{\"ceiling\": \"memory=m\", \"profile\": \"native\", \"timeout\": 20}})\nprint(r[\"errors\"])\nremember(\"learning\", \"padre 2\")\nprint(length(recall(\"learning\")))\n",
        child = child
    );
    let (code, out, err) = synsema(&proj, &[], &src);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(out.lines().last().map(str::trim), Some("3"), "{}{}", out, err);
    // Y en disco quedaron las tres.
    let (code, out, err) = synsema(&proj, &[], "require memory(\"m\")\nprint(length(recall(\"learning\")))\n");
    assert_eq!(code, 0, "{}", err);
    assert_eq!(out.trim(), "3", "{}", err);
}

/// Ronda 5 (B2): con etiquetas, el `require` de una task con un scope privado es `label_violation`
/// (es el techo de la tool en `call_tool`: lo concedido dependería del dato).
#[test]
fn a_task_require_with_a_private_scope_is_refused() {
    let t = tree("taskpriv");
    let proj = t.0.join("proj");
    std::fs::write(
        proj.join("app.syn"),
        "let p be private(\"./data/in/a.txt\", [\"c\"])\ntask t()\n    require file.read(p)\n    give 1\nprint(\"fin\")\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["run", "--labels", "app.syn"])
        .current_dir(&proj)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .expect("spawn synsema");
    let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(!out.status.success(), "{}", all);
    assert!(all.contains("label_violation"), "{}", all);
    assert!(!String::from_utf8_lossy(&out.stdout).contains("fin"), "{}", all);
}

/// Ronda 5 (revisión): un `run_program` desde un tick de cron en `run` comparte la memoria igual que
/// desde el programa (el tick arma su intérprete en otro hilo y no recibía la carpeta).
#[test]
fn run_program_from_a_cron_tick_shares_the_memory() {
    let t = tree("rpcron");
    let proj = t.0.join("proj");
    let child = "require memory(\"m\")\nremember(\"learning\", \"del hijo\")\n";
    let src = format!(
        "require sandbox_run\nrequire time\nrequire memory(\"m\")\ntask tick()\n    let r be run_program({child:?}, {{\"ceiling\": \"memory=m\", \"profile\": \"native\", \"timeout\": 20}})\n    print(r[\"errors\"])\ncron_after(0, tick)\nsleep(4)\nprint(length(recall(\"learning\")))\n",
        child = child
    );
    let (code, out, err) = synsema(&proj, &[], &src);
    assert_eq!(code, 0, "{}", err);
    assert_eq!(out.lines().last().map(str::trim), Some("1"), "{}{}", out, err);
}

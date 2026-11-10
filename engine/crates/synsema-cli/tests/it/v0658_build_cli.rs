//! v0.6.58, §9: `build` con un proyecto y paquetes (las filas B de §15, y K33). Usa el registro
//! local y los paquetes de `v0658_get_cli`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

use super::v0646_tanda_e_cli::synsema_env;
use super::v0658_get_cli::{modules, says, url, Pkg, Proj, Reg};

/// Un binario construido: pesa ~180 MB, así que se borra al salir, también en un pánico.
struct Built(PathBuf);

impl Drop for Built {
    fn drop(&mut self) {
        for _ in 0..50 {
            if std::fs::remove_file(&self.0).is_ok() || !self.0.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

fn exe(dir: &Path, base: &str) -> PathBuf {
    dir.join(if cfg!(windows) { format!("{}.exe", base) } else { base.to_string() })
}

fn run_exe(exe: &Path, cwd: &Path, env: &[(&str, &str)]) -> (i32, String, String) {
    let mut c = Command::new(exe);
    c.current_dir(cwd).env("SYNSEMA_NO_UPDATE_CHECK", "1");
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().expect("spawn");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

const PROGRAM: &str = "require file.read(\"**\")\nuse \"tok\" as tok\ntask cb(x)\n    give body of render(\"vista.html\", {\"x\": x})\nprint(tok.aplicar([1, 2], cb))\nprint(tok.suya())\nlet m be receipt().credentialSubject.modules\nprint(json_encode(m))\nlet k be \"pkg:PKG/\" + \"vista.html\"\ntry\n    print(render(k))\nrecover e\n    print(\"no: \" + text(e))\nprint(file_exists(\"pkg:PKG/m.syn\"))\n";

/// B1, B2, B5, K33: el bundle lleva `synsema.json` y los paquetes; el binario corre sin caché y sin
/// red, con los mismos `modules`, aunque la carpeta de arriba tenga un `synsema.json` roto; el
/// callback del programa que el paquete llama renderiza la plantilla del programa. B4 (en `run`):
/// una clave `pkg:` no es una ruta del bundle.
#[test]
fn b1_b2_b4_b5_k33_a_built_binary_carries_its_packages() {
    let reg = Reg::start();
    let tok = Pkg::new(
        &format!("{}/tok", reg.base()),
        "0.1.0",
        "export task aplicar(xs, cb)\n    require file.read(\"**\")\n    give apply(xs, cb)\nexport task suya()\n    give body of render(\"vista.html\", {\"x\": 0})\n",
    )
    .file("vista.html", "<p>del paquete { x }</p>");
    let u = reg.publish("/tok/0.1.0", &tok);
    let p = Proj::new("b1", modules(&[("tok", url(&u))]));
    p.ok(&[]);
    drop(reg);
    std::fs::write(p.dir.join("vista.html"), "<i>del programa { x }</i>").unwrap();
    let src = PROGRAM.replace("PKG", &tok.hash().replacen(':', "-", 1));
    let ran = p.run(&src);
    let lines: Vec<&str> = ran.lines().collect();
    assert_eq!(lines[0], "[\"<i>del programa 1</i>\", \"<i>del programa 2</i>\"]", "{}", ran);
    assert_eq!(lines[1], "<p>del paquete 0</p>", "{}", ran);
    assert!(lines[3].starts_with("no: ") && lines[3].contains("template not found"), "{}", ran);
    assert_eq!(lines[4], "false", "{}", ran);

    let out_dir = p.dir.join("out");
    let sub = out_dir.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let bin = Built(exe(&sub, "app"));
    let cache = p.cache.to_string_lossy().into_owned();
    let (code, out, err) = synsema_env(&p.dir, &["build", "p.syn", "-o", bin.0.to_str().unwrap()], None, &[("SYNSEMA_MODULE_CACHE", &cache)]);
    assert_eq!(code, 0, "{}{}", out, err);

    // B5: arriba, un `synsema.json` roto; y sin caché (B2).
    std::fs::write(out_dir.join("synsema.json"), "{roto").unwrap();
    let nowhere = p.dir.join("no-hay-cache").to_string_lossy().into_owned();
    let (code, out, err) = run_exe(&bin.0, &sub, &[("SYNSEMA_MODULE_CACHE", &nowhere)]);
    assert_eq!(code, 0, "{}{}", out, err);
    assert_eq!(out, ran, "{}", err);
    std::fs::write(out_dir.join("synsema.json"), "{\"synsema\": \"9.9.9\"}").unwrap();
    let (code, out2, err) = run_exe(&bin.0, &sub, &[("SYNSEMA_MODULE_CACHE", &nowhere)]);
    assert_eq!((code, out2.as_str()), (0, ran.as_str()), "{}", err);
    let m: Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(m["packages"][&tok.id]["hash"], json!(tok.hash()));
}

/// B3: `tok` fuera del caché es N5 en el build.
#[test]
fn b3_a_package_out_of_the_cache_fails_the_build() {
    let reg = Reg::start();
    let tok = says(&format!("{}/tok", reg.base()), "0.1.0", "x");
    let u = reg.publish("/tok/0.1.0", &tok);
    let p = Proj::new("b3", modules(&[("tok", url(&u))]));
    p.ok(&[]);
    std::fs::write(p.dir.join("p.syn"), "use \"tok\" as tok\nprint(tok.cual())\n").unwrap();
    let empty = p.dir.join("vacio").to_string_lossy().into_owned();
    let bin = Built(exe(&p.dir, "app"));
    let (code, out, err) = synsema_env(&p.dir, &["build", "p.syn", "-o", bin.0.to_str().unwrap()], None, &[("SYNSEMA_MODULE_CACHE", &empty)]);
    assert_eq!(code, 2, "{}{}", out, err);
    assert!(err.contains("use \"tok\": module tok 0.1.0 is not downloaded: run synsema get (it needs the network)"), "{}", err);
    assert!(!bin.0.exists());
}

/// B6: `cd scripts && synsema build x.syn -o app`, con `use "../lib/y.syn"` y el `synsema.json` en
/// el padre: construye, y el binario imprime lo mismo que `run`.
#[test]
fn b6_the_bundle_root_is_the_project_root() {
    let p = Proj::new("b6", json!({}));
    let scripts = p.dir.join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::create_dir_all(p.dir.join("lib")).unwrap();
    std::fs::write(p.dir.join("lib").join("y.syn"), "export let Y be 41\n").unwrap();
    std::fs::write(scripts.join("x.syn"), "use \"../lib/y.syn\" as y\nprint(y.Y + 1)\n").unwrap();
    let (code, ran, err) = synsema_env(&scripts, &["run", "x.syn"], None, &[]);
    assert_eq!((code, ran.trim()), (0, "42"), "{}", err);
    let bin = Built(exe(&scripts, "app"));
    let (code, out, err) = synsema_env(&scripts, &["build", "x.syn", "-o", bin.0.to_str().unwrap()], None, &[]);
    assert_eq!(code, 0, "{}{}", out, err);
    let elsewhere = p.dir.join("otro");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let (code, out, err) = run_exe(&bin.0, &elsewhere, &[]);
    assert_eq!((code, out.as_str()), (0, ran.as_str()), "{}", err);
}

/// M5 (ronda 1): `build` lee las plantillas (y `static`, `--include`) desde el directorio actual,
/// como `run` (D-28). Desde `scripts/`, el binario imprime la plantilla de `scripts/`; desde la
/// raíz, la de la raíz: lo mismo que `run` en cada lugar. Una plantilla y un módulo con la misma
/// clave y distinto contenido son un error del build.
#[test]
fn m5_build_reads_templates_from_the_current_directory_like_run() {
    let p = Proj::new("m5", json!({}));
    let scripts = p.dir.join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::create_dir_all(p.dir.join("lib")).unwrap();
    std::fs::write(p.dir.join("lib").join("y.syn"), "export let Y be 41\n").unwrap();
    let src = "require file.read(\"**\")\nuse \"../lib/y.syn\" as y\nprint(y.Y + 1)\nprint(body of render(\"t.html\"))\n";
    std::fs::write(scripts.join("x.syn"), src).unwrap();
    std::fs::write(scripts.join("t.html"), "<i>de scripts</i>").unwrap();
    std::fs::write(p.dir.join("t.html"), "<i>de la raiz</i>").unwrap();
    let elsewhere = p.dir.join("otro");
    std::fs::create_dir_all(&elsewhere).unwrap();
    for (cwd, main, want) in [(&scripts, "x.syn", "de scripts"), (&p.dir, "scripts/x.syn", "de la raiz")] {
        let (code, ran, err) = synsema_env(cwd, &["run", main], None, &[]);
        assert_eq!(code, 0, "{}", err);
        assert!(ran.contains(want) && ran.starts_with("42"), "{}", ran);
        let bin = Built(exe(cwd, "app"));
        let (code, out, err) = synsema_env(cwd, &["build", main, "-o", bin.0.to_str().unwrap()], None, &[]);
        assert_eq!(code, 0, "{}{}", out, err);
        let (code, out, err) = run_exe(&bin.0, &elsewhere, &[]);
        assert_eq!((code, out.as_str()), (0, ran.as_str()), "{}", err);
    }
    // La misma clave para una plantilla del directorio actual y un módulo de la raíz.
    std::fs::write(scripts.join("z.syn"), "require file.read(\"**\")\nuse \"../lib/y.syn\" as y\nprint(body of render(\"lib/y.syn\"))\n").unwrap();
    std::fs::create_dir_all(scripts.join("lib")).unwrap();
    std::fs::write(scripts.join("lib").join("y.syn"), "otra cosa").unwrap();
    let bin = Built(exe(&scripts, "z"));
    let (code, _, err) = synsema_env(&scripts, &["build", "z.syn", "-o", bin.0.to_str().unwrap()], None, &[]);
    assert_eq!(code, 2, "{}", err);
    assert!(err.contains("'lib/y.syn' names two different files in the bundle"), "{}", err);
}

/// B4 (en el binario, con `serve`): `static "/" from "."` sirve los archivos del programa, nunca los
/// de un paquete por su clave (`/pkg:tree-sha256-…/m.syn` da 404), y la plantilla del paquete sigue
/// siendo del paquete. El binario corre con un caché vacío y el registro apagado.
#[test]
fn b4_a_built_server_does_not_serve_the_files_of_a_package() {
    use super::build_cli::{free_port, http, wait_ready, KillOnDrop};
    let reg = Reg::start();
    let tok = Pkg::new(&format!("{}/tok", reg.base()), "0.1.0", "export task suya()\n    give body of render(\"vista.html\", {\"x\": 7})\n")
        .file("vista.html", "<p>del paquete { x }</p>");
    let u = reg.publish("/tok/0.1.0", &tok);
    let p = Proj::new("b4serve", modules(&[("tok", url(&u))]));
    p.ok(&[]);
    drop(reg);
    let port = free_port();
    std::fs::write(p.dir.join("publico.txt"), "del programa").unwrap();
    std::fs::write(
        p.dir.join("p.syn"),
        format!(
            "require serve({port})\nrequire file.read(\"**\")\nuse \"tok\" as tok\n\nserve on {port}\n    static \"/\" from \".\"\n    route \"GET /api/ping\"\n        give \"pong\"\n    route \"GET /hola\"\n        give tok.suya()\n"
        ),
    )
    .unwrap();
    let out_dir = std::env::temp_dir().join(format!("synsema-v0658-b4-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out_dir);
    std::fs::create_dir_all(&out_dir).unwrap();
    let bin = Built(exe(&out_dir, "srv"));
    let cache = p.cache.to_string_lossy().into_owned();
    let (code, out, err) =
        synsema_env(&p.dir, &["build", "p.syn", "-o", bin.0.to_str().unwrap(), "--serve", "--bind", "127.0.0.1"], None, &[("SYNSEMA_MODULE_CACHE", &cache)]);
    assert_eq!(code, 0, "{}{}", out, err);

    let empty = out_dir.join("cache-vacio");
    std::fs::create_dir_all(&empty).unwrap();
    {
        let _child = KillOnDrop(
            Command::new(&bin.0)
                .current_dir(&out_dir)
                .env("SYNSEMA_NO_UPDATE_CHECK", "1")
                .env("SYNSEMA_MODULE_CACHE", &empty)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn"),
        );
        wait_ready(port);
        let (st, head, body) = http(port, "/publico.txt");
        assert_eq!((st, body.as_str()), (200, "del programa"), "{}", head);
        let (st, head, body) = http(port, "/hola");
        assert_eq!(st, 200, "{}", head);
        assert!(body.contains("<p>del paquete 7</p>"), "{}", body);
        let key = tok.hash().replacen(':', "-", 1);
        for path in [format!("/pkg:{}/m.syn", key), format!("/pkg:{}/vista.html", key), format!("/{}/m.syn", key)] {
            let (st, head, _) = http(port, &path);
            assert_eq!(st, 404, "{}: {}", path, head);
        }
    }
    let _ = std::fs::remove_dir_all(&out_dir);
}

/// M7 (ronda 1): `static "/" from "."` no publica lo oculto (`.env`, `.git/`), salvo `.well-known`;
/// lo oculto y el binario anterior no viajan en el bundle. Igual desde el disco (`synsema serve`).
/// (El `deny` del host sobre lo del bundle: `server::tests::a_static_mount_does_not_publish_hidden_files`.)
#[test]
fn m7_a_static_mount_does_not_publish_hidden_files() {
    use super::build_cli::{free_port, http, wait_ready, KillOnDrop};
    let p = Proj::new("m7", json!({}));
    std::fs::write(p.dir.join(".env"), "API_KEY=marca-m7-oculta").unwrap();
    std::fs::create_dir_all(p.dir.join(".git")).unwrap();
    std::fs::write(p.dir.join(".git").join("HEAD"), "ref: refs/heads/main").unwrap();
    std::fs::create_dir_all(p.dir.join(".well-known")).unwrap();
    std::fs::write(p.dir.join(".well-known").join("security.txt"), "Contact: x").unwrap();
    std::fs::write(p.dir.join("publico.txt"), "del programa").unwrap();
    let port = free_port();
    std::fs::write(
        p.dir.join("p.syn"),
        format!("require serve({port})\nrequire file.read(\"**\")\n\nserve on {port}\n    static \"/\" from \".\"\n    route \"GET /api/ping\"\n        give \"pong\"\n"),
    )
    .unwrap();
    let check = |port: u16| {
        wait_ready(port);
        for (path, want) in [("/publico.txt", 200), ("/.well-known/security.txt", 200), ("/.env", 404), ("/.git/HEAD", 404), ("/%2eenv", 404)] {
            let (st, head, _) = http(port, path);
            assert_eq!(st, want, "{}: {}", path, head);
        }
    };
    // El binario (con un build anterior en la carpeta: no viaja adentro).
    let bin = Built(exe(&p.dir, "srv"));
    for _ in 0..2 {
        let (code, out, err) = synsema_env(&p.dir, &["build", "p.syn", "-o", bin.0.to_str().unwrap(), "--serve", "--bind", "127.0.0.1"], None, &[]);
        assert_eq!(code, 0, "{}{}", out, err);
    }
    let bytes = std::fs::read(&bin.0).unwrap();
    assert!(!bytes.windows(b"marca-m7-oculta".len()).any(|w| w == b"marca-m7-oculta"), "el .env viajó en el binario");
    let size = bytes.len();
    drop(bytes);
    let (code, out, err) = synsema_env(&p.dir, &["build", "p.syn", "-o", bin.0.to_str().unwrap(), "--serve", "--bind", "127.0.0.1"], None, &[]);
    assert_eq!(code, 0, "{}{}", out, err);
    assert!(std::fs::metadata(&bin.0).unwrap().len() < (size as u64) + 4096, "el binario anterior viajó en el bundle");
    let elsewhere = p.dir.join("otro");
    std::fs::create_dir_all(&elsewhere).unwrap();
    {
        let _child = KillOnDrop(
            Command::new(&bin.0).current_dir(&elsewhere).env("SYNSEMA_NO_UPDATE_CHECK", "1").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().expect("spawn"),
        );
        check(port);
    }
    // Desde el disco.
    {
        let _child = KillOnDrop(
            Command::new(env!("CARGO_BIN_EXE_synsema"))
                .args(["serve", "p.syn"])
                .current_dir(&p.dir)
                .env("SYNSEMA_NO_UPDATE_CHECK", "1")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn"),
        );
        check(port);
    }
}

/// B13 (ronda 1): toda tool de `synsema code` revisa el mínimo del proyecto (§8), con una ruta o sin.
#[test]
fn b13_every_code_tool_checks_the_minimum() {
    let p = Proj::new("b13", json!({"synsema": "99.0.0"}));
    std::fs::write(p.dir.join("p.syn"), "task f()\n    give 1\nprint(f())\n").unwrap();
    let calls: [&[&str]; 11] = [
        &["outline"],
        &["outline", "p.syn"],
        &["symbol", "f", "p.syn"],
        &["refs", "f"],
        &["routes"],
        &["caps", "p.syn"],
        &["check"],
        &["deps"],
        &["search", "give"],
        &["sha", "p.syn"],
        &["outline", "."],
    ];
    for c in calls {
        let mut args = vec!["code"];
        args.extend_from_slice(c);
        let (code, out, err) = synsema_env(&p.dir, &args, None, &[]);
        assert_ne!(code, 0, "{:?}: {}", c, out);
        assert!(err.contains("this project needs synsema >= 99.0.0"), "{:?}: {}{}", c, out, err);
    }
}

/// B15 (ronda 1): un `use` de un archivo que no existía cuando arrancó el programa falla igual
/// después de que el archivo aparece: lo que corre es lo que se leyó antes (R10), y un worker de
/// `serve` no lo lee del disco.
#[test]
fn b15_a_module_that_appears_later_is_not_read_from_disk() {
    let p = Proj::new("b15", json!({}));
    let src = "require file\ntask h()\n    use \"./late.syn\" as m\n    give m.v()\nwrite_file(\"late.syn\", \"export task v()\\n    give 2\\n\")\nprint(h())\n";
    std::fs::write(p.dir.join("p.syn"), src).unwrap();
    let (code, out, err) = synsema_env(&p.dir, &["run", "p.syn"], None, &[]);
    assert_ne!(code, 0, "{}", out);
    assert!(err.contains("module not found: ./late.syn (it did not exist when the program started)"), "{}{}", out, err);
    // Con el archivo ya ahí al arrancar, corre.
    let (code, out, err) = synsema_env(&p.dir, &["run", "p.syn"], None, &[]);
    assert_eq!(code, 0, "{}{}", out, err);
    assert_eq!(out.trim(), "2");
    // N-r2-6 (ronda 2): uno que estaba pero no se pudo leer como texto no dice «no existía».
    std::fs::write(p.dir.join("malo.syn"), b"export let x be \"\xff\xfe\"\n").unwrap();
    std::fs::write(p.dir.join("q.syn"), "use \"./malo.syn\" as m\nprint(m.x)\n").unwrap();
    let (code, out, err) = synsema_env(&p.dir, &["run", "q.syn"], None, &[]);
    assert_ne!(code, 0, "{}", out);
    assert!(err.contains("module cannot be read: ./malo.syn (it could not be read when the program started: "), "{}{}", out, err);
}

/// B17 (ronda 1): un binario construido no revisa el mínimo de su `synsema.json` (§8/§9: se revisó al
/// construir; el motor es el que lleva). El bundle se re-sella con `{"synsema": "99.0.0"}` y corre igual.
#[test]
fn b17_a_built_binary_does_not_check_the_minimum() {
    use synsema_core::bundle::Bundle;
    let p = Proj::new("b17", json!({"synsema": "0.0.1"}));
    std::fs::write(p.dir.join("p.syn"), "print(\"corre\")\n").unwrap();
    let bin = Built(exe(&p.dir, "app"));
    let (code, out, err) = synsema_env(&p.dir, &["build", "p.syn", "-o", bin.0.to_str().unwrap()], None, &[]);
    assert_eq!(code, 0, "{}{}", out, err);
    let bytes = std::fs::read(&bin.0).unwrap();
    let n = bytes.len();
    let base_len = u64::from_le_bytes(bytes[n - 64..n - 56].try_into().unwrap()) as usize;
    let payload_len = u64::from_le_bytes(bytes[n - 56..n - 48].try_into().unwrap()) as usize;
    let b = Bundle::parse(&bytes[base_len..base_len + payload_len]).unwrap();
    assert!(b.get("synsema.json").is_some(), "{:?}", b.names());
    let entries: Vec<(String, Vec<u8>)> = b
        .names()
        .iter()
        .map(|k| (k.clone(), if k == "synsema.json" { br#"{"synsema": "99.0.0"}"#.to_vec() } else { b.get(k).unwrap().to_vec() }))
        .collect();
    let again = Bundle::new(b.manifest.clone(), entries).unwrap();
    let mut out_bytes = bytes[..base_len].to_vec();
    out_bytes.extend_from_slice(&again.serialize(base_len as u64));
    std::fs::write(&bin.0, out_bytes).unwrap();
    let (code, out, err) = run_exe(&bin.0, &p.dir, &[]);
    assert_eq!((code, out.trim()), (0, "corre"), "{}", err);
}

/// Un link a una carpeta (junction en Windows, symlink en Unix).
fn dir_link(link: &Path, target: &Path) {
    #[cfg(windows)]
    {
        let st = Command::new("cmd").args(["/C", "mklink", "/J"]).arg(link).arg(target).output().expect("mklink");
        assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
}

/// Ronda 2 (M-r2-2): un link adentro de un mount estático que sale de la carpeta, o que lleva a
/// `.git`, no viaja en el binario: el binario da 404 como `synsema serve` (la regla del disco).
#[test]
fn m_r2_2_a_link_in_a_static_mount_does_not_carry_what_the_disk_denies() {
    use super::build_cli::{free_port, http, wait_ready, KillOnDrop};
    let p = Proj::new("mr22", json!({}));
    let fuera = p.dir.with_file_name(format!("{}-fuera", p.dir.file_name().unwrap().to_string_lossy()));
    std::fs::create_dir_all(&fuera).unwrap();
    struct Gone(PathBuf);
    impl Drop for Gone {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _gone = Gone(fuera.clone());
    std::fs::write(fuera.join("plain.txt"), "marca-mr22-fuera").unwrap();
    std::fs::create_dir_all(p.dir.join(".git")).unwrap();
    std::fs::write(p.dir.join(".git").join("HEAD"), "marca-mr22-git").unwrap();
    std::fs::create_dir_all(p.dir.join("adentro")).unwrap();
    std::fs::write(p.dir.join("adentro").join("x.txt"), "del programa").unwrap();
    std::fs::write(p.dir.join("publico.txt"), "del programa").unwrap();
    dir_link(&p.dir.join("lnk"), &fuera);
    dir_link(&p.dir.join("gitj"), &p.dir.join(".git"));
    dir_link(&p.dir.join("bien"), &p.dir.join("adentro"));
    let port = free_port();
    std::fs::write(
        p.dir.join("p.syn"),
        format!("require serve({port})\nrequire file.read(\"**\")\n\nserve on {port}\n    static \"/\" from \".\"\n    route \"GET /api/ping\"\n        give \"pong\"\n"),
    )
    .unwrap();
    let check = |port: u16| {
        wait_ready(port);
        for (path, want) in [("/publico.txt", 200), ("/bien/x.txt", 200), ("/lnk/plain.txt", 404), ("/gitj/HEAD", 404)] {
            let (st, head, _) = http(port, path);
            assert_eq!(st, want, "{}: {}", path, head);
        }
    };
    let bin = Built(exe(&p.dir, "srv"));
    let (code, out, err) = synsema_env(&p.dir, &["build", "p.syn", "-o", bin.0.to_str().unwrap(), "--serve", "--bind", "127.0.0.1"], None, &[]);
    assert_eq!(code, 0, "{}{}", out, err);
    let bytes = std::fs::read(&bin.0).unwrap();
    for mark in [&b"marca-mr22-fuera"[..], b"marca-mr22-git"] {
        assert!(!bytes.windows(mark.len()).any(|w| w == mark), "{} viajó en el binario", String::from_utf8_lossy(mark));
    }
    drop(bytes);
    let elsewhere = p.dir.join("otro");
    std::fs::create_dir_all(&elsewhere).unwrap();
    {
        let _child = KillOnDrop(
            Command::new(&bin.0).current_dir(&elsewhere).env("SYNSEMA_NO_UPDATE_CHECK", "1").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().expect("spawn"),
        );
        check(port);
    }
    {
        let _child = KillOnDrop(
            Command::new(env!("CARGO_BIN_EXE_synsema"))
                .args(["serve", "p.syn"])
                .current_dir(&p.dir)
                .env("SYNSEMA_NO_UPDATE_CHECK", "1")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn"),
        );
        check(port);
    }
}

/// Ronda 2 (M-r2-6, previo a v0.6.58): un cuerpo que pide más registros que los que tiene un chunk de
/// la VM (una lista literal de 70 001 elementos, 70 000 `|>`) corre en el tree-walker y da lo
/// correcto, en el programa, en una task, en una lambda y con una vuelta de `each`, con jit y sin.
/// v0.6.57 daba `length` = 4465 sin error; la rama, un pánico en debug.
#[test]
fn m_r2_6_a_body_with_more_values_than_registers_runs_right() {
    let dir = std::env::temp_dir().join(format!("synsema-mr26-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let list = |n: usize, item: &str| format!("[{}]", vec![item; n].join(", "));
    let cases = [
        (format!("let l be {}\nprint(length(l))\n", list(70_001, "0")), "70001"),
        (format!("let x be -1{}\nprint(x)\n", " |> abs".repeat(70_000)), "1"),
        (format!("task f(a)\n    let l be {}\n    give length(l) + a\nprint(f(1))\nprint(f(2))\nprint(f(3))\n", list(40_000, "a")), "40001\n40002\n40003"),
        (format!("let g be (a) => length({})\nprint(g(1))\nprint(g(2))\nprint(g(3))\n", list(40_000, "a")), "40000\n40000\n40000"),
        (format!("let s be 0\neach i in [1, 2, 3]\n    let l be {}\n    set s to s + length(l)\nprint(s)\n", list(40_000, "i")), "120000"),
    ];
    for (i, (src, want)) in cases.iter().enumerate() {
        std::fs::write(dir.join("grande.syn"), src).unwrap();
        for flags in [&["run"][..], &["run", "--jitless"]] {
            let args: Vec<&str> = flags.iter().copied().chain(["grande.syn"]).collect();
            let (code, out, err) = synsema_env(&dir, &args, None, &[]);
            assert_eq!((code, out.trim().replace("\r\n", "\n").as_str()), (0, *want), "caso {} {:?}: {}", i, flags, err);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Ronda 3 (M-r3-2): con la raíz del proyecto arriba de la carpeta actual, un mount `static "/" from
/// "."` del binario serviría el programa, sus módulos y el `synsema.json` (entran por su ruta desde
/// la raíz) que el disco no sirve ahí: `build` falla y dice qué hacer. Desde la raíz, o con un mount
/// que no los cubre, construye.
#[test]
fn m_r3_2_a_root_mount_does_not_serve_what_came_from_the_project_root() {
    let p = Proj::new("mr32", json!({}));
    std::fs::create_dir_all(p.dir.join("lib")).unwrap();
    std::fs::write(p.dir.join("lib").join("secret.syn"), "export let KEY be \"CODIGO-DEL-SERVIDOR\"\n").unwrap();
    let app = p.dir.join("app");
    std::fs::create_dir_all(app.join("pub")).unwrap();
    std::fs::write(app.join("pub").join("index.html"), "<p>hola</p>\n").unwrap();
    let main = |from: &str| {
        format!("use \"../lib/secret.syn\" as s\nrequire serve(18999)\nrequire file.read(\"**\")\n\nserve on 18999\n    static \"/\" from \"{from}\"\n    route \"GET /api/k\"\n        give text(length(s.KEY))\n")
    };
    let bin = Built(exe(&p.dir, "mr32"));
    std::fs::write(app.join("main.syn"), main(".")).unwrap();
    let (code, out, err) = synsema_env(&app, &["build", "main.syn", "-o", bin.0.to_str().unwrap(), "--serve", "--bind", "127.0.0.1"], None, &[]);
    assert_ne!(code, 0, "{}{}", out, err);
    assert!(err.contains("would be served by static \".\" in the built binary, and the disk does not serve it there"), "{}", err);
    assert!(err.contains("run synsema build from the project root"), "{}", err);
    // N-r4-2: el consejo dice qué sirve "." desde la raíz (todo, el código también).
    assert!(err.contains("where static \".\" is the project root and serves all of it, the code included"), "{}", err);
    assert!(!bin.0.exists() || !std::fs::read(&bin.0).unwrap().windows(19).any(|w| w == b"CODIGO-DEL-SERVIDOR"));
    // Un mount que no cubre lo de la raíz: construye.
    std::fs::write(app.join("main.syn"), main("pub")).unwrap();
    let (code, out, err) = synsema_env(&app, &["build", "main.syn", "-o", bin.0.to_str().unwrap(), "--serve", "--bind", "127.0.0.1"], None, &[]);
    assert_eq!(code, 0, "{}{}", out, err);
    // Desde la raíz, el mount "." es la raíz: el disco sirve lo mismo que el binario.
    std::fs::write(app.join("main.syn"), main(".")).unwrap();
    let (code, out, err) = synsema_env(&p.dir, &["build", "app/main.syn", "-o", bin.0.to_str().unwrap(), "--serve", "--bind", "127.0.0.1"], None, &[]);
    assert_eq!(code, 0, "{}{}", out, err);
}

/// Ronda 3 (M-r3-4 y B-r3-1, previos): cada programa corre con jit y sin, y da lo de la referencia.
/// Antes, un resultado equivocado (M-r3-4) o `internal error in the engine` (B-r3-1).
fn runs_like_the_reference(tag: &str, src: &str, want: &str) {
    let dir = std::env::temp_dir().join(format!("synsema-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("grande.syn"), src).unwrap();
    for flags in [&["run"][..], &["run", "--jitless"]] {
        let args: Vec<&str> = flags.iter().copied().chain(["grande.syn"]).collect();
        let (code, out, err) = synsema_env(&dir, &args, None, &[]);
        assert_eq!((code, out.trim().replace("\r\n", "\n").as_str()), (0, want), "{:?}: {}", flags, err);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn lets70k(indent: &str) -> String {
    (0..70_000).map(|i| format!("{indent}let v{i} be {i}\n")).collect()
}

const THREE: &str = "text(v0) + \",\" + text(v65536) + \",\" + text(v69999)";

/// M-r3-4: más de 65 535 nombres en un frame que una lambda ve (en una task y en una vuelta de
/// `each`): dos variables compartían slot y daba `65536,65536,69999`.
#[test]
fn m_r3_4_a_frame_with_more_names_than_slots_reads_each_one() {
    let task = format!("task f()\n    let cap be () => 1\n{}    give {THREE}\nprint(f())\nprint(f())\nprint(f())\n", lets70k("    "));
    runs_like_the_reference("mr34a", &task, "0,65536,69999\n0,65536,69999\n0,65536,69999");
    let each = format!("each k in range(1)\n    let cap be () => k\n{}    print({THREE})\n", lets70k("    "));
    runs_like_the_reference("mr34b", &each, "0,65536,69999");
    // Sin lambda: el mismo frame, que antes iba en registros (la ventana de locales).
    let plain = format!("task f()\n{}    give {THREE}\nprint(f())\nprint(f())\nprint(f())\n", lets70k("    "));
    runs_like_the_reference("mr34c", &plain, "0,65536,69999\n0,65536,69999\n0,65536,69999");
}

/// B-r3-1: tres vueltas de `each` de 25 000 `let` en una task (cada una cabe sola; juntas pasan los
/// 65 535 lugares de la ventana de locales) y una task de 65 535 parámetros.
#[test]
fn b_r3_1_a_task_with_more_locals_or_params_than_slots() {
    let loop_of = |v: &str| {
        let lets: String = (0..25_000).map(|i| format!("        let {v}{i} be {i}\n")).collect();
        format!("    each k in range(1)\n{lets}        set t to t + {v}24999\n")
    };
    let task = format!("task f()\n    let t be 0\n{}{}{}    give t\nprint(f())\nprint(f())\n", loop_of("a"), loop_of("b"), loop_of("c"));
    runs_like_the_reference("br31a", &task, "74997\n74997");
    let params = (0..65_535).map(|i| format!("p{i}")).collect::<Vec<_>>().join(", ");
    let args = (0..65_535).map(|i| i.to_string()).collect::<Vec<_>>().join(", ");
    let g = format!("task g({params})\n    give text(p0) + \",\" + text(p65534)\nprint(g({args}))\nprint(g({args}))\n");
    runs_like_the_reference("br31b", &g, "0,65534\n0,65534");
}

/// B-r3-1: 70 000 `set s to s + …` (las cadenas de texto se numeran con `u16`).
#[test]
fn b_r3_1_more_text_chains_than_numbers() {
    let src = format!("let s be \"\"\n{}print(length(s))\n", "set s to s + \"a\"\n".repeat(70_000));
    runs_like_the_reference("br31c", &src, "70000");
}

/// B-r3-1: 70 000 `while` que corren (los bucles del nivel nativo se numeran con `u16`).
#[test]
fn b_r3_1_more_loops_than_numbers() {
    let src = format!("let c be 0\nlet t be 0\n{}print(t)\n", "set c to 0\nwhile c < 1\n    set c to c + 1\n    set t to t + 1\n".repeat(70_000));
    runs_like_the_reference("br31d", &src, "70000");
}

/// Ronda 4: un programa con sus archivos, corrido con jit y sin; el código, la salida y el error.
fn run_files(tag: &str, files: &[(&str, String)], main: &str) -> Vec<(i32, String, String)> {
    let dir = std::env::temp_dir().join(format!("synsema-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, text) in files {
        std::fs::write(dir.join(name), text).unwrap();
    }
    let out = [&["run"][..], &["run", "--jitless"]]
        .iter()
        .map(|flags| {
            let args: Vec<&str> = flags.iter().copied().chain([main]).collect();
            let (code, out, err) = synsema_env(&dir, &args, None, &[]);
            (code, out.trim().replace("\r\n", "\n"), err)
        })
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    out
}

/// Ronda 4 (M-r4-1): `h(n)` recursiva con `k` `when` anidados alrededor de la llamada; con `cold`, un
/// literal de 40 000 elementos manda el cuerpo entero a la referencia (M-r2-6).
fn recursive_task(cold: bool, k: usize, n: usize) -> String {
    let big = if cold { format!("[{}]", vec!["0"; 40_000].join(", ")) } else { "[0]".to_string() };
    let mut s = format!("task h(n)\n    let big be {big}\n    when n == 0\n        give 0\n");
    let mut ind = "    ".to_string();
    for _ in 0..k {
        s += &format!("{ind}when true\n");
        ind += "    ";
    }
    s += &format!("{ind}give h(n - 1) + 1\n");
    if k > 0 {
        s += "    give -1\n";
    }
    s + &format!("print(h({n}))\n")
}

/// Ronda 4 (M-r4-1): una task recursiva cuyo cuerpo corre en frío (la referencia baja una función de
/// Rust por bloque) da el resultado o el error de recursión, nunca el desborde de la pila del host
/// (antes: rc 127 con 100 o 300 `when` × 2999 llamadas). El guardián cobra lo que pesa el árbol.
#[test]
fn m_r4_1_a_recursion_through_a_cold_body_hits_the_limit_not_the_stack() {
    for k in [100, 300] {
        for (code, out, err) in run_files("mr41a", &[("h.syn", recursive_task(true, k, 2999))], "h.syn") {
            assert_eq!(code, 1, "k = {k}: {out}{err}");
            assert!(err.contains("maximum recursion depth exceeded"), "k = {k}: {err}");
        }
    }
    // Debajo del límite, el resultado: un cuerpo frío plano no pesa y llega a 2999, como en la
    // referencia (nativo: los primeros 8 niveles caben en la llamada); con 30 `when`, a 200.
    for (k, n) in [(0, 2999), (30, 200)] {
        for (code, out, err) in run_files("mr41b", &[("h.syn", recursive_task(true, k, n))], "h.syn") {
            assert_eq!((code, out.as_str()), (0, n.to_string().as_str()), "k = {k}: {err}");
        }
    }
    // La misma task por la VM no cambia: 100 `when` × 2999.
    for (code, out, err) in run_files("mr41c", &[("h.syn", recursive_task(false, 100, 2999))], "h.syn") {
        assert_eq!((code, out.as_str()), (0, "2999"), "{err}");
    }
}

/// Ronda 4 (M-r4-1, el mismo mecanismo, previo): con las etiquetas todo corre en la referencia, así
/// que una task recursiva con 8 `when` anidados × 2999 llamadas desbordaba la pila (rc 127). Cada
/// llamada cobra lo que anida su cuerpo: el error de recursión; con 6, el resultado como antes.
#[test]
fn m_r4_1_a_recursion_in_the_reference_with_labels_hits_the_limit_not_the_stack() {
    let dir = std::env::temp_dir().join(format!("synsema-mr41l-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (k, want) in [(8, None), (30, None), (100, None), (6, Some("2999")), (0, Some("2999"))] {
        std::fs::write(dir.join("h.syn"), recursive_task(false, k, 2999)).unwrap();
        let (code, out, err) = synsema_env(&dir, &["run", "--labels", "h.syn"], None, &[]);
        // Con 6 y 0, el número. Sólo en aarch64 debug (frames más grandes que la calibración de
        // x86_64) vale también el error de recursión: el hilo avisa su pila. Nunca el proceso
        // abortado. Ronda 8 (B-r8-2): en los demás hosts sigue estricto, así que un aviso de pila
        // que rechace una recursión válida se ve en Windows y en Linux.
        let refused = code == 1 && err.contains("maximum recursion depth exceeded");
        let host_may_refuse = cfg!(all(target_arch = "aarch64", debug_assertions));
        eprintln!("k = {k}: rc {code}, {}", if refused { "el error de recursión" } else { out.trim() });
        match want {
            Some(w) => assert!(
                (code == 0 && out.trim() == w) || (host_may_refuse && refused),
                "k = {k}: rc {code} {out}{err}"
            ),
            None => assert!(refused, "k = {k}: rc {code} {out}{err}"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Ronda 8 (B-r8-1): el REPL corría en el hilo principal (1 MB en Windows) sin avisar su pila: una
/// task de cuerpo frío con 6 `when` lo tumbaba a las 20 llamadas (rc 127). Ahora corre en el hilo
/// del motor, como `run`: 2999, y pasado el tope, el error.
#[test]
fn b_r8_1_a_recursion_in_the_repl_does_not_take_it_down() {
    let dir = std::env::temp_dir().join(format!("synsema-br81-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let task = recursive_task(true, 6, 0);
    let lib = task.replacen("task h(n)", "export task h(n)", 1).replace("print(h(0))\n", "");
    std::fs::write(dir.join("libc6.syn"), lib).unwrap();
    // Ronda 9 (B-r9-1): en aarch64 debug (frames más grandes que la calibración de x86_64) 2999
    // puede dar el error, como en m_r4_1; 20 no (el guardián no mira la pila antes de 64 llamadas).
    let host_may_refuse = cfg!(all(target_arch = "aarch64", debug_assertions));
    for (n, want) in [(20, "20"), (2999, "2999"), (3500, "maximum recursion depth exceeded")] {
        let stdin = format!("use \"./libc6.syn\" as L\nprint(L.h({n}))\n");
        let (code, out, err) = synsema_env(&dir, &["repl"], Some(&stdin), &[]);
        let all = format!("{out}{err}");
        let refused = all.contains("maximum recursion depth exceeded");
        eprintln!("n = {n}: rc {code}, {}", if refused { "el error de recursión" } else { want });
        assert_eq!(code, 0, "n = {n}: {all}");
        assert!(all.contains(want) || (n == 2999 && host_may_refuse && refused), "n = {n}: {all}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Ronda 4 (B-r4-3, previo): una plantilla con `k` bloques que se renderiza a sí misma por una task
/// cobra sus bloques en el guardián: 500 × 2999 da el error (antes, rc 127 en release); 30 × 1000
/// sigue dando el resultado.
#[test]
fn b_r4_3_a_template_rendered_inside_a_recursion_counts_its_blocks() {
    let tpl = |k: usize| format!("{}{{ raw g(n) }}{}", "{ when true }".repeat(k), "{ end }".repeat(k));
    let prog = |n: usize| {
        format!("require file.read(\"**\")\ntask g(n)\n    when n == 0\n        give \"x\"\n    give render(\"t.html\", {{\"n\": n - 1}})[\"body\"]\nprint(length(g({n})))\n")
    };
    for (code, out, err) in run_files("br43a", &[("t.html", tpl(500)), ("t.syn", prog(2999))], "t.syn") {
        assert_eq!(code, 1, "{out}{err}");
        assert!(err.contains("maximum recursion depth exceeded"), "{err}");
    }
    for (code, out, err) in run_files("br43b", &[("t.html", tpl(30)), ("t.syn", prog(1000))], "t.syn") {
        assert_eq!((code, out.as_str()), (0, "1"), "{err}");
    }
}

/// Ronda 4 (B-r4-2, previo): un lugar de la ventana de locales ≥ 0x8000 chocaba con el bit `PARAM`
/// de `TryInPlace`: `set x to x + k` daba `internal error in the engine`. La ventana llega hasta
/// 0x7FFF; lo que no cabe corre en frío y da lo de la referencia.
#[test]
fn b_r4_2_a_local_past_the_param_bit_updates_in_place_right() {
    let lets = |p: &str, n: usize, ind: &str| (0..n).map(|i| format!("{ind}let {p}{i} be {i}\n")).collect::<String>();
    let mut m = format!("task f()\n{}    let t be 0\n    each k in range(3)\n{}", lets("v", 32_760, "    "), lets("w", 20, "        "));
    m += "        let x be 1\n        set x to x + k\n        set t to t + x\n    give t\nprint(f())\n";
    runs_like_the_reference("br42a", &m, "6");
    let two = |body: &str| {
        format!(
            "task f()\n    let t be 0\n    each k in range(1)\n{}        set t to t + a19999\n    each k in range(1)\n{}{body}    give t\nprint(f())\nprint(f())\n",
            lets("a", 20_000, "        "),
            lets("b", 20_000, "        ")
        )
    };
    let list = "        let xs be [7]\n        set xs to xs + [1]\n        set xs to append(xs, 2)\n        set t to t + length(xs) * 1000000\n";
    let map = "        let m be {\"a\": 1}\n        set m to merge(m, {\"b\": 2})\n        set t to t + length(keys(m)) * 1000000\n";
    runs_like_the_reference("br42b", &two(list), "3019999\n3019999");
    runs_like_the_reference("br42c", &two(map), "2019999\n2019999");
}

/// El cuerpo de una task `name(n)` recursiva con `k` `when` anidados y, si `tries`, `tries` `try`
/// alrededor de la llamada (un `try` lo corre la referencia).
fn route_task(name: &str, k: usize, tries: usize) -> String {
    let mut s = format!("task {name}(n)\n    when n == 0\n        give 0\n    let r be 0\n");
    let mut ind = "    ".to_string();
    for _ in 0..tries {
        s += &format!("{ind}try\n");
        ind += "    ";
    }
    for _ in 0..k {
        s += &format!("{ind}when true\n");
        ind += "    ";
    }
    s += &format!("{ind}set r to {name}(n - 1) + 1\n");
    for t in (0..tries).rev() {
        let i = "    ".repeat(t + 1);
        s += &format!("{i}recover e\n{i}    set r to -1\n");
    }
    s + "    give r\n"
}

/// Ronda 5 (M-r5-1): en `serve` una ruta corre en un hilo de 64 MB de pila y el guardián estaba
/// calibrado para 512 MB: una recursión por la referencia (con `--labels`, o a través de un `try`)
/// tumbaba el servidor entero con 0xC00000FD (en debug, un `try` a las 1000 llamadas; con
/// `--labels`, una recursión plana a las 1500). Ahora la ruta responde (200 con el número o 500 con
/// el error de recursión) y el servidor sigue vivo.
#[test]
fn m_r5_1_a_recursion_in_a_serve_route_does_not_take_the_server_down() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    fn get(port: u16, path: &str) -> String {
        let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else { return String::new() };
        let _ = s.set_read_timeout(Some(Duration::from_secs(300)));
        let _ = s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes());
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }
    let cases: [(&[&str], &[(&str, usize, usize)]); 2] = [
        (&["--labels"], &[("flat", 0, 0), ("w6", 6, 0)]),
        (&[], &[("t1", 0, 1), ("u4", 4, 1)]),
    ];
    for (flags, tasks) in cases {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let dir = std::env::temp_dir().join(format!("synsema-m-r5-1-{port}"));
        std::fs::create_dir_all(&dir).unwrap();
        let mut prog = format!("require serve({port})\n");
        for (name, k, tries) in tasks {
            prog += &route_task(name, *k, *tries);
        }
        prog += &format!("serve on {port}\n    route \"GET /ping\"\n        give {{\"pong\": true}}\n");
        for (name, ..) in tasks {
            prog += &format!("    route \"GET /{name}\"\n        give {{\"r\": {name}(2999)}}\n");
        }
        std::fs::write(dir.join("s.syn"), &prog).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_synsema"))
            .current_dir(&dir)
            .arg("serve")
            .args(flags)
            .arg("s.syn")
            .env("SYNSEMA_NO_UPDATE_CHECK", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("synsema serve");
        let t0 = Instant::now();
        while !get(port, "/ping").starts_with("HTTP/1.1 200") {
            assert!(t0.elapsed() < Duration::from_secs(60), "{flags:?}: el server no levantó");
            std::thread::sleep(Duration::from_millis(100));
        }
        for (name, ..) in tasks {
            let r = get(port, &format!("/{name}"));
            // 200 con un número: el resultado o, con un `try`, lo que suma arriba del que atrapó el error.
            let ok = (r.starts_with("HTTP/1.1 200") && r.contains("{\"r\": "))
                || (r.starts_with("HTTP/1.1 500") && r.contains("maximum recursion depth exceeded"));
            let alive = child.try_wait().unwrap().is_none();
            if !ok || !alive {
                let _ = child.kill();
                let out = child.wait_with_output().unwrap();
                panic!(
                    "{flags:?} /{name}: vivo={alive} status={:?} respuesta={}\nstderr: {}",
                    out.status.code(),
                    r.chars().take(300).collect::<String>(),
                    String::from_utf8_lossy(&out.stderr).chars().take(2000).collect::<String>()
                );
            }
            assert!(get(port, "/ping").starts_with("HTTP/1.1 200"), "{flags:?} /{name}: /ping no respondió después");
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Ronda 6 (M-r6-1): el job de `cron_every` corría en un hilo de 2 MB que no avisaba su pila: una
/// recursión en el tick tumbaba el proceso entero (con un `try` alrededor de la llamada, a las 23
/// llamadas en debug), en `serve` y en `run`. Ahora el tick da el resultado o el error de recursión
/// (`[cron] job 'tick' failed: …`) y el proceso sigue.
#[test]
fn m_r6_1_a_recursion_in_a_cron_tick_does_not_take_the_process_down() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::{Duration, Instant};
    /// El servidor se cierra también si el test falla (por su PID: es el hijo de este test).
    struct Kill(std::process::Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn get(port: u16, path: &str) -> String {
        let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else { return String::new() };
        let _ = s.set_read_timeout(Some(Duration::from_secs(60)));
        let _ = s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes());
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }
    let flat = "task f(n)\n    when n == 0\n        give 0\n    give f(n - 1) + 1\n";
    let with_try = "task f(n)\n    when n == 0\n        give 0\n    let r be 0\n    try\n        set r to f(n - 1) + 1\n    recover e\n        set r to -1\n    give r\n";
    let tick = "task tick()\n    print(\"tick \" + text(f(2999)))\ncron_every(1, tick)\n";
    // `serve`: con etiquetas la recursión plana, sin etiquetas la del `try`.
    for (flags, body) in [(&["--labels"][..], flat), (&[][..], with_try)] {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let dir = std::env::temp_dir().join(format!("synsema-m-r6-1-{port}"));
        std::fs::create_dir_all(&dir).unwrap();
        let prog = format!("require serve({port})\nrequire time\n{body}{tick}serve on {port}\n    route \"GET /ping\"\n        give {{\"pong\": true}}\n");
        std::fs::write(dir.join("c.syn"), &prog).unwrap();
        let out = std::fs::File::create(dir.join("out.txt")).unwrap();
        let err = std::fs::File::create(dir.join("err.txt")).unwrap();
        let mut child = Kill(Command::new(env!("CARGO_BIN_EXE_synsema"))
            .current_dir(&dir)
            .arg("serve")
            .args(flags)
            .arg("c.syn")
            .env("SYNSEMA_NO_UPDATE_CHECK", "1")
            .stdout(out)
            .stderr(err)
            .spawn()
            .expect("synsema serve"));
        let t0 = Instant::now();
        let mut ticks = 0;
        while ticks < 2 && t0.elapsed() < Duration::from_secs(120) {
            std::thread::sleep(Duration::from_millis(250));
            let text = std::fs::read_to_string(dir.join("out.txt")).unwrap_or_default()
                + &std::fs::read_to_string(dir.join("err.txt")).unwrap_or_default();
            // Un tick: el número (con el `try`, lo que suma arriba del que atrapó el error) o el error.
            // (`serve` antepone `[serve] ` a lo que imprime el programa.)
            ticks = text.lines().filter(|l| l.trim_start_matches("[serve] ").strip_prefix("tick ").is_some_and(|x| x.trim().parse::<i64>().is_ok())).count()
                + text.matches("[cron] job 'tick' failed: maximum recursion depth exceeded").count();
            if let Some(st) = child.0.try_wait().unwrap() {
                panic!("{flags:?}: el proceso murió ({:?}) en el tick\n{text}", st.code());
            }
        }
        assert!(ticks >= 1, "{flags:?}: el tick no dio ni el número ni el error en 120 s");
        assert!(get(port, "/ping").starts_with("HTTP/1.1 200"), "{flags:?}: /ping no respondió después del tick");
        assert!(child.0.try_wait().unwrap().is_none(), "{flags:?}: el proceso murió");
        drop(child);
        let _ = std::fs::remove_dir_all(&dir);
    }
    // `run`: el mismo tick con el `try`, y el programa sigue hasta el final.
    let dir = std::env::temp_dir().join(format!("synsema-m-r6-1-run-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("r.syn"), format!("require time\n{with_try}{tick}sleep(3)\nprint(\"fin\")\n")).unwrap();
    let (code, out, err) = synsema_env(&dir, &["run", "r.syn"], None, &[]);
    assert_eq!(code, 0, "run: {out}\n{err}");
    assert!(out.contains("fin"), "run: {out}\n{err}");
    assert!(out.contains("tick ") || err.contains("maximum recursion depth exceeded"), "run: el tick no corrió: {out}\n{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

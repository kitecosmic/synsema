//! v0.6.58, §10 y §11: `synsema get` contra un registro local (HTTP en loopback, que §7 permite) que
//! cuenta las conexiones. Las filas G de §15 del diseño.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use synsema_core::modtable::{sha256_hex, short_hash, tree_hash};

use super::v0646_tanda_e_cli::{project, synsema_env};

// ---------------------------------------------------------------------------------------------
// El registro

#[derive(Clone)]
pub(crate) enum Resp {
    Body(Vec<u8>),
    Status(u16),
    Redirect(String),
    /// Sin `Content-Length` ni chunked: el cuerpo termina al cerrar (G4).
    UntilClose(Vec<u8>),
    /// B4 (ronda 1): anuncia `n` bytes y cierra antes.
    Truncated(Vec<u8>, usize),
}

pub(crate) struct Reg {
    port: u16,
    routes: Arc<Mutex<HashMap<String, Resp>>>,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Reg {
    pub(crate) fn start() -> Reg {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let routes: Arc<Mutex<HashMap<String, Resp>>> = Arc::default();
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (r, h, s) = (routes.clone(), hits.clone(), stop.clone());
        std::thread::spawn(move || {
            for c in l.incoming() {
                if s.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(c) = c else { continue };
                h.fetch_add(1, Ordering::SeqCst);
                let r = r.clone();
                std::thread::spawn(move || answer(c, &r));
            }
        });
        Reg { port, routes, hits, stop }
    }

    pub(crate) fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub(crate) fn put(&self, path: &str, r: Resp) {
        self.routes.lock().unwrap().insert(path.to_string(), r);
    }

    /// Publica `p` en `<dir>/synsema.json` y `<dir>/<archivo>`; devuelve la URL del índice.
    pub(crate) fn publish(&self, dir: &str, p: &Pkg) -> String {
        self.put(&format!("{}/synsema.json", dir), Resp::Body(p.index()));
        for (f, b) in &p.files {
            self.put(&format!("{}/{}", dir, f), Resp::Body(b.clone()));
        }
        format!("{}{}/synsema.json", self.base(), dir)
    }

    pub(crate) fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for Reg {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn answer(mut c: TcpStream, routes: &Mutex<HashMap<String, Resp>>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16384 {
        match c.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
    let r = routes.lock().unwrap().get(&path).cloned().unwrap_or(Resp::Status(404));
    let _ = match r {
        Resp::Body(b) => {
            let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len());
            c.write_all(&b)
        }
        Resp::Status(s) => write!(c, "HTTP/1.1 {} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", s),
        Resp::Redirect(loc) => write!(c, "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", loc),
        Resp::UntilClose(b) => {
            let _ = write!(c, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
            c.write_all(&b)
        }
        Resp::Truncated(b, n) => {
            let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", n);
            c.write_all(&b)
        }
    };
    let _ = c.flush();
}

// ---------------------------------------------------------------------------------------------
// Los paquetes

#[derive(Clone)]
pub(crate) struct Pkg {
    pub(crate) id: String,
    version: String,
    main: String,
    files: Vec<(String, Vec<u8>)>,
    deps: Vec<(String, Value)>,
}

impl Pkg {
    pub(crate) fn new(id: &str, version: &str, main_src: &str) -> Pkg {
        Pkg { id: id.to_string(), version: version.to_string(), main: "m.syn".to_string(), files: vec![("m.syn".to_string(), main_src.as_bytes().to_vec())], deps: Vec::new() }
    }

    pub(crate) fn file(mut self, path: &str, src: &str) -> Pkg {
        self.files.push((path.to_string(), src.as_bytes().to_vec()));
        self
    }

    /// Una dependencia fijada (`url`, `id`, `version` y `hash` del paquete `p`).
    pub(crate) fn dep(mut self, name: &str, url: &str, p: &Pkg) -> Pkg {
        self.deps.push((name.to_string(), json!({"url": url, "id": p.id, "version": p.version, "hash": p.hash()})));
        self
    }

    pub(crate) fn dep_raw(mut self, name: &str, v: Value) -> Pkg {
        self.deps.push((name.to_string(), v));
        self
    }

    pub(crate) fn index(&self) -> Vec<u8> {
        let files: Vec<Value> = self.files.iter().map(|(p, b)| json!({"path": p, "sha256": sha256_hex(b)})).collect();
        let mut o = json!({"id": self.id, "version": self.version, "main": self.main, "files": files});
        if !self.deps.is_empty() {
            let mut m = serde_json::Map::new();
            for (n, v) in &self.deps {
                m.insert(n.clone(), v.clone());
            }
            o["modules"] = Value::Object(m);
        }
        serde_json::to_vec_pretty(&o).unwrap()
    }

    pub(crate) fn hash(&self) -> String {
        let idx = self.index();
        let shas: Vec<(String, String)> = self.files.iter().map(|(p, b)| (p.clone(), sha256_hex(b))).collect();
        let index_sha = sha256_hex(&idx);
        tree_hash(shas.iter().map(|(p, s)| (p.as_str(), s.as_str())).chain(std::iter::once(("synsema.json", index_sha.as_str()))))
    }
}

// ---------------------------------------------------------------------------------------------
// El proyecto

pub(crate) struct Proj {
    pub(crate) dir: PathBuf,
    pub(crate) cache: PathBuf,
}

impl Proj {
    pub(crate) fn new(tag: &str, manifest: Value) -> Proj {
        let dir = project(&format!("get-{}", tag));
        let cache = dir.join("cache");
        let p = Proj { dir, cache };
        p.write(manifest);
        p
    }

    /// Otro proyecto que comparte el caché de `self` (G16, G22).
    pub(crate) fn sibling(&self, tag: &str, manifest: Value) -> Proj {
        let dir = project(&format!("get-{}", tag));
        let p = Proj { dir, cache: self.cache.clone() };
        p.write(manifest);
        p
    }

    pub(crate) fn write(&self, manifest: Value) {
        std::fs::write(self.dir.join("synsema.json"), serde_json::to_string_pretty(&manifest).unwrap() + "\n").unwrap();
    }

    pub(crate) fn get(&self, args: &[&str]) -> (i32, String, String) {
        let mut a = vec!["get"];
        a.extend_from_slice(args);
        let cache = self.cache.to_string_lossy().into_owned();
        synsema_env(&self.dir, &a, None, &[("SYNSEMA_MODULE_CACHE", &cache)])
    }

    pub(crate) fn ok(&self, args: &[&str]) -> String {
        let (code, out, err) = self.get(args);
        assert_eq!(code, 0, "get {:?}\nstdout:\n{}\nstderr:\n{}", args, out, err);
        out
    }

    pub(crate) fn fails(&self, args: &[&str]) -> String {
        let (code, out, err) = self.get(args);
        assert_eq!(code, 1, "get {:?} should fail\nstdout:\n{}\nstderr:\n{}", args, out, err);
        err.trim_end().to_string()
    }

    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.dir.join("synsema.json")).unwrap()).unwrap()
    }

    pub(crate) fn text(&self) -> String {
        std::fs::read_to_string(self.dir.join("synsema.json")).unwrap()
    }

    pub(crate) fn run(&self, src: &str) -> String {
        std::fs::write(self.dir.join("p.syn"), src).unwrap();
        let cache = self.cache.to_string_lossy().into_owned();
        let (code, out, err) = synsema_env(&self.dir, &["run", "p.syn"], None, &[("SYNSEMA_MODULE_CACHE", &cache)]);
        assert_eq!(code, 0, "run\nstdout:\n{}\nstderr:\n{}", out, err);
        out
    }

    /// Las carpetas de paquetes del caché.
    pub(crate) fn installed(&self) -> usize {
        std::fs::read_dir(&self.cache).map(|rd| rd.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("tree-sha256-")).count()).unwrap_or(0)
    }
}

pub(crate) fn modules(xs: &[(&str, Value)]) -> Value {
    let mut m = serde_json::Map::new();
    for (n, v) in xs {
        m.insert(n.to_string(), v.clone());
    }
    json!({ "modules": m })
}

pub(crate) fn url(u: &str) -> Value {
    json!({ "url": u })
}

/// Un paquete que da su nombre y versión.
pub(crate) fn says(id: &str, version: &str, tag: &str) -> Pkg {
    Pkg::new(id, version, &format!("export task cual()\n    give \"{}\"\n", tag))
}

/// Un paquete que usa `bpe` y da lo que da ese.
pub(crate) fn uses_bpe(id: &str, version: &str, bpe_url: &str, bpe: &Pkg) -> Pkg {
    Pkg::new(id, version, "use \"bpe\" as bpe\nexport task cual()\n    give bpe.cual()\n").dep("bpe", bpe_url, bpe)
}

// ---------------------------------------------------------------------------------------------
// G1, G2, G8, G24: la primera vez, otra vez sin red, `--check` sin red, y `run` con lo escrito

#[test]
fn g1_g2_g8_first_get_writes_everything_then_nothing_needs_the_network() {
    let reg = Reg::start();
    let b = reg.base();
    let bpe = says(&format!("{}/bpe-core", b), "0.3.0", "bpe-0.3.0");
    let bpe_url = reg.publish("/bpe-core/0.3.0", &bpe);
    let tok = Pkg::new(
        &format!("{}/tokenizador", b),
        "0.1.0",
        "use \"bpe\" as bpe\nexport task cual()\n    give bpe.cual()\nexport task pedir()\n    require net(\"api.x.com\")\n    give 1\n",
    )
    .dep("bpe", &bpe_url, &bpe);
    let tok_url = reg.publish("/tokenizador/0.1.0", &tok);
    let p = Proj::new("g1", json!({"synsema": "0.6.58", "modules": {"tok": {"url": tok_url}}}));
    let out = p.ok(&[]);
    assert!(out.contains(&format!("tok 0.1.0 ({}), new", short_hash(&tok.hash()))), "{}", out);
    assert!(out.contains("  task pedir: net(\"api.x.com\")"), "{}", out);
    assert!(out.contains(&format!("{}/bpe-core 0.3.0 ({}), new\n  requires nothing", b, short_hash(&bpe.hash()))), "{}", out);
    let j = p.json();
    // El orden de las claves se conserva: `synsema` primero, y lo que agrega va detrás de `url`.
    let text = p.text();
    assert!(text.starts_with("{\n  \"synsema\": \"0.6.58\",\n  \"modules\": {\n    \"tok\": {\n      \"url\""), "{}", text);
    assert!(text.ends_with("}\n"), "{}", text);
    assert_eq!(j["modules"]["tok"]["id"], json!(tok.id));
    assert_eq!(j["modules"]["tok"]["version"], json!("0.1.0"));
    assert_eq!(j["modules"]["tok"]["hash"], json!(tok.hash()));
    assert_eq!(j["modules"]["tok"]["requires"], json!(["net(\"api.x.com\")"]));
    assert_eq!(j["indirect"][&bpe.id], json!({"url": bpe_url, "version": "0.3.0", "hash": bpe.hash(), "requires": []}));
    assert_eq!(p.installed(), 2);
    assert_eq!(p.run("use \"tok\" as tok\nprint(tok.cual())\n").trim(), "bpe-0.3.0");

    // G2: otra vez, todo en el caché: ninguna conexión.
    let before = reg.hits();
    p.ok(&[]);
    assert_eq!(reg.hits(), before);
    assert_eq!(p.json(), j);

    // G8: `--check` sin red (el registro apagado).
    drop(reg);
    let out = p.ok(&["--check"]);
    assert!(out.contains("synsema.json matches the module cache (2 packages)"), "{}", out);

    // G24: un caché relativo es relativo a la raíz, desde la raíz y desde una subcarpeta.
    std::fs::rename(&p.cache, p.dir.join("vendor")).unwrap();
    std::fs::create_dir_all(p.dir.join("scripts")).unwrap();
    std::fs::write(p.dir.join("scripts").join("x.syn"), "use \"tok\" as tok\nprint(tok.cual())\n").unwrap();
    for (cwd, arg) in [(p.dir.clone(), "scripts/x.syn"), (p.dir.join("scripts"), "x.syn")] {
        let (code, out, err) = synsema_env(&cwd, &["run", arg], None, &[("SYNSEMA_MODULE_CACHE", "./vendor")]);
        assert_eq!((code, out.trim()), (0, "bpe-0.3.0"), "{}", err);
    }
}

// ---------------------------------------------------------------------------------------------
// §10.2: los errores del hash, en orden

#[test]
fn g3_g5_g26_g18_the_hash_errors_and_a_mirror() {
    let reg = Reg::start();
    let id = format!("{}/tok", reg.base());
    let v1 = says(&id, "0.1.0", "uno");
    let u = reg.publish("/tok/0.1.0", &v1);
    let p = Proj::new("g3", modules(&[("tok", url(&u))]));
    p.ok(&[]);
    let pinned = p.text();
    std::fs::remove_dir_all(&p.cache).unwrap();

    // G3: la misma versión con otro contenido.
    let re = says(&id, "0.1.0", "otro contenido");
    reg.publish("/tok/0.1.0", &re);
    let e = p.fails(&[]);
    assert_eq!(
        e,
        format!(
            "get: the registry changed the content of tok 0.1.0 without changing its version (expected {}, got {}): it may be tampering or a republication; nothing was installed. If you trust the change, remove the hash of tok in synsema.json and run synsema get again",
            short_hash(&v1.hash()),
            short_hash(&re.hash())
        )
    );
    assert_eq!(p.text(), pinned);

    // G5: la URL sirve otra versión.
    let v2 = says(&id, "0.2.0", "dos");
    reg.publish("/tok/0.1.0", &v2);
    assert_eq!(
        p.fails(&[]),
        format!(
            "get: {} now serves tok 0.2.0, but synsema.json pins tok 0.1.0 ({}); nothing was installed. To move to 0.2.0: synsema get --update tok",
            u,
            short_hash(&v1.hash())
        )
    );

    // G26: hash a mano sin `version`.
    p.write(modules(&[("tok", json!({"url": u, "hash": v1.hash()}))]));
    assert_eq!(
        p.fails(&[]),
        format!("get: tok: {} serves {}, but synsema.json pins {}; nothing was installed", u, short_hash(&v2.hash()), short_hash(&v1.hash()))
    );
    assert_eq!(p.installed(), 0);

    // G18: el hash escrito y la URL cambiada a un espejo (fuera del `id`) que sirve lo mismo.
    let mirror = reg.publish("/espejo/tok-0.1.0", &v1);
    let mut j: Value = serde_json::from_str(&pinned).unwrap();
    j["modules"]["tok"]["url"] = json!(mirror);
    p.write(j);
    p.ok(&[]);
    assert_eq!(p.run("use \"tok\" as tok\nprint(tok.cual())\n").trim(), "uno");
}

#[test]
fn g4_g21_a_broken_download_installs_nothing() {
    let reg = Reg::start();
    let id = format!("{}/tok", reg.base());
    let tok = says(&id, "0.1.0", "x").file("capas.syn", "export task f()\n    give 1\n");
    let u = reg.publish("/tok/0.1.0", &tok);
    let p = Proj::new("g4", modules(&[("tok", url(&u))]));
    let broken = |cause: &str| format!("get: could not download tok from {}: {}; nothing was installed", u, cause);

    // Un 404 del índice, un archivo que falta, y uno truncado sin `Content-Length`.
    reg.put("/tok/0.1.0/synsema.json", Resp::Status(404));
    assert_eq!(p.fails(&[]), broken("HTTP 404"));
    reg.publish("/tok/0.1.0", &tok);
    reg.put("/tok/0.1.0/capas.syn", Resp::Status(404));
    assert_eq!(p.fails(&[]), broken("capas.syn: HTTP 404"));
    reg.put("/tok/0.1.0/capas.syn", Resp::UntilClose(b"export task f()\n".to_vec()));
    assert_eq!(p.fails(&[]), broken("capas.syn does not match its sha256 in the index"));

    // G21: el índice nuevo con un archivo viejo.
    reg.put("/tok/0.1.0/capas.syn", Resp::Body(b"export task f()\n    give 2\n".to_vec()));
    assert_eq!(p.fails(&[]), broken("capas.syn does not match its sha256 in the index"));
    assert_eq!(p.installed(), 0);
    assert!(!p.text().contains("hash"));
}

// ---------------------------------------------------------------------------------------------
// G6, G7: `--update` y la regla de `--accept`, caso 1

#[test]
fn g6_g7_an_update_whose_requires_grow_needs_accept() {
    let reg = Reg::start();
    let id = format!("{}/tok", reg.base());
    let v1 = says(&id, "0.1.0", "uno");
    let u = reg.publish("/tok/latest", &v1);
    let p = Proj::new("g6", modules(&[("tok", url(&u))]));
    p.ok(&[]);
    let before = p.text();
    let v2 = Pkg::new(&id, "0.2.0", "export task cual()\n    require net(\"api.x.com\")\n    give \"dos\"\n");
    reg.publish("/tok/latest", &v2);
    let e = p.fails(&["--update", "tok"]);
    let accept = format!("tok@{}", v2.hash());
    assert_eq!(
        e,
        format!(
            "get: tok 0.2.0 now requires net(\"api.x.com\") (0.1.0 required nothing); nothing was changed. To accept: synsema get --update tok --accept {}",
            accept
        )
    );
    assert_eq!(p.text(), before);

    // G52: `--accept` sin hash.
    assert_eq!(p.fails(&["--update", "tok", "--accept", "tok"]), "get: --accept needs the hash shown by get (--accept tok@tree-sha256:…)");

    // G7: con el `--accept` impreso, escribe e imprime la diferencia.
    let out = p.ok(&["--update", "tok", "--accept", &accept]);
    assert!(out.contains(&format!("tok 0.1.0 → 0.2.0 ({})", short_hash(&v2.hash()))), "{}", out);
    assert!(out.contains("  requires: nothing → net(\"api.x.com\")"), "{}", out);
    assert_eq!(p.json()["modules"]["tok"]["version"], json!("0.2.0"));
    assert_eq!(p.json()["modules"]["tok"]["requires"], json!(["net(\"api.x.com\")"]));
}

// ---------------------------------------------------------------------------------------------
// G9 a G11, G37: las URLs

#[test]
fn g9_g10_g11_g37_urls_are_checked_before_anything_is_fetched() {
    let reg = Reg::start();
    let cases = [
        ("http://reg.example/tok/synsema.json", "get: tok: http:// is only allowed to this machine (127.0.0.1, ::1, localhost); use https://".to_string()),
        ("https://u:p@reg.example/tok/synsema.json", "get: tok: a URL with credentials is not supported".to_string()),
        (
            "https://reg.example/tokenizador/../otro/0.1.0/synsema.json",
            "get: tok: the url has a dot segment or an encoded separator: https://reg.example/tokenizador/../otro/0.1.0/synsema.json".to_string(),
        ),
        (
            "https://reg.example/tokenizador/%2E%2e/otro/synsema.json",
            "get: tok: the url has a dot segment or an encoded separator: https://reg.example/tokenizador/%2E%2e/otro/synsema.json".to_string(),
        ),
        // M3 (ronda 1): el `\` literal; B10: un 127 que no es una dirección.
        (
            r"http://127.0.0.1:9/tok/x\..\..\evil/0.1.0/synsema.json",
            r"get: tok: the url has a backslash, which some servers take as a path separator: http://127.0.0.1:9/tok/x\..\..\evil/0.1.0/synsema.json".to_string(),
        ),
        ("http://127.0.0.999/tok/synsema.json", "get: tok: http:// is only allowed to this machine (127.0.0.1, ::1, localhost); use https://".to_string()),
    ];
    for (u, want) in cases {
        let p = Proj::new("g9", modules(&[("tok", url(u))]));
        assert_eq!(p.fails(&[]), want);
    }
    assert_eq!(reg.hits(), 0);

    // G11: una redirección a `http://` de otra máquina.
    reg.put("/tok/synsema.json", Resp::Redirect("http://reg.example/tok/synsema.json".to_string()));
    let u = format!("{}/tok/synsema.json", reg.base());
    let p = Proj::new("g11", modules(&[("tok", url(&u))]));
    assert_eq!(p.fails(&[]), format!("get: tok: {} redirects to http://reg.example/tok/synsema.json; only https redirects are followed", u));

    // B8 (ronda 1): un `Location` relativo con `..` se resuelve por RFC 3986 antes de G37.
    let tok = says(&format!("{}/tok", reg.base()), "0.1.0", "x");
    reg.publish("/tok/0.1.0", &tok);
    reg.put("/tok/latest/synsema.json", Resp::Redirect("../0.1.0/synsema.json".to_string()));
    let p = Proj::new("b8", modules(&[("tok", url(&format!("{}/tok/latest/synsema.json", reg.base())))]));
    p.ok(&[]);
    assert_eq!(p.json()["modules"]["tok"]["hash"].as_str(), Some(tok.hash().as_str()));
}

// ---------------------------------------------------------------------------------------------
// §10.3: la validación


/// Un `id` que sirve en cualquier puerto del registro: el de `Reg` cambia por test, así que los
/// paquetes de validación se arman con un `id` a mano y el `id` se revisa último (§10.3, paso 6).
fn local(pkg: impl Fn(&str) -> Pkg, tag: &str) -> String {
    let reg = Reg::start();
    let p0 = pkg(&format!("{}/tok", reg.base()));
    let u = reg.publish("/tok/0.1.0", &p0);
    let p = Proj::new(tag, modules(&[("tok", url(&u))]));
    let e = p.fails(&[]);
    assert_eq!(p.installed(), 0, "{}", e);
    e
}

#[test]
fn g12_g36_g49_g20_g44_requires_and_trusted_inside_a_package() {
    let e = local(|id| Pkg::new(id, "0.1.0", "when true\n    require net(\"x\")\nexport task f()\n    give 1\n"), "g36");
    assert_eq!(e, "get: tok: require net(\"x\") in m.syn:2 is outside a task; a package declares its capabilities inside its tasks");
    let e = local(|id| Pkg::new(id, "0.1.0", "export task f()\n    give 1\nserve on 8080\n    route \"GET /\"\n        give 1\n"), "g12");
    assert!(e.starts_with("get: tok: m.syn:3 has a 'serve' block; a package does not serve, the program that uses it does"), "{}", e);
    let e = local(
        |id| says(id, "0.1.0", "x").file("pruebas.syn", "test \"lee\"\n    require file.read(\"./**\")\n    assert_eq(1, 1)\n"),
        "g49",
    );
    assert_eq!(e, "get: tok: require file.read(\"./**\") in pruebas.syn:2 is inside a test block; a package's tests do not declare capabilities");
    let e = local(|id| Pkg::new(id, "0.1.0", "export task pedir(h)\n    let H be h\n    require net(H)\n    give 1\n"), "g20");
    assert_eq!(e, "get: tok: require net(H) in task pedir is not a literal; a package declares its capabilities with literals so they can be reviewed");
    let e = local(|id| says(id, "0.1.0", "x").file("capas.syn", "use \"trusted:t\" as t\nexport task f()\n    give 1\n"), "g44");
    assert_eq!(e, "get: tok: use \"trusted:t\" in capas.syn: a package cannot use the host's trusted tools; the program passes it a callback instead");
}

#[test]
fn g13_g15_invalid_paths_and_limits() {
    fn with(paths: &[&str], main: &str) -> impl Fn(&str) -> Pkg {
        let paths: Vec<String> = paths.iter().map(|s| s.to_string()).collect();
        let main = main.to_string();
        move |id: &str| {
            let mut p = Pkg::new(id, "0.1.0", "export task f()\n    give 1\n");
            p.files.clear();
            for f in &paths {
                p.files.push((f.to_string(), b"export task f()\n    give 1\n".to_vec()));
            }
            p.main = main.clone();
            p
        }
    }
    for (paths, main, bad) in [
        (&["../x.syn", "m.syn"][..], "m.syn", "../x.syn"),
        (&["a\\b.syn", "m.syn"][..], "m.syn", "a\\b.syn"),
        (&["C:x.syn", "m.syn"][..], "m.syn", "C:x.syn"),
        (&["A.syn", "a.syn"][..], "a.syn", "a.syn"),
        (&["a", "a/b.syn"][..], "a/b.syn", "a"),
        (&["A", "a/b.syn"][..], "a/b.syn", "A"),
        (&["SYNSEMA.JSON", "m.syn"][..], "m.syn", "SYNSEMA.JSON"),
        (&["COM0.syn", "m.syn"][..], "m.syn", "COM0.syn"),
        (&["m.syn"][..], "otro.syn", "otro.syn"),
    ] {
        let e = local(with(paths, main), "g13");
        let want = format!("get: tok: invalid path in files: \"{}\" (", bad);
        assert!(e.starts_with(&want), "{:?}: {}", paths, e);
    }
    let long = format!("{}.syn", "a".repeat(125));
    let e = local(with(&[&long, "m.syn"], "m.syn"), "g15");
    assert_eq!(e, format!("get: tok: the path \"{}\" is larger than 128 bytes", long));
    let many: Vec<String> = (0..257).map(|i| format!("f{}.syn", i)).collect();
    let many_ref: Vec<&str> = many.iter().map(String::as_str).collect();
    let e = local(with(&many_ref, "f0.syn"), "g15b");
    assert_eq!(e, "get: tok: the file list (257 files) is larger than 256 files");
}

/// G15, los topes que no son de rutas: un archivo de más de 4 MiB, un paquete de más de 32 MiB, un
/// grafo de más de 1024 paquetes y más de 64 niveles de dependencias. Nada queda instalado.
#[test]
fn g15_size_graph_and_depth_limits() {
    let mib = 1024 * 1024;
    let e = local(|id| says(id, "0.1.0", "x").file("big.syn", &"a".repeat(4 * mib + 1)), "g15c");
    assert_eq!(e, "get: tok: big.syn is larger than 4 MiB");
    // Cada archivo entra (4 MiB − 1), los nueve juntos no.
    let e = local(
        |id| (0..9).fold(says(id, "0.1.0", "x"), |p, i| p.file(&format!("b{}.syn", i), &"a".repeat(4 * mib - 1))),
        "g15d",
    );
    assert_eq!(e, "get: tok: the package is larger than 32 MiB");

    let reg = Reg::start();
    let b = reg.base();
    // Un paquete con 1024 dependencias: con él son 1025.
    let mut hub = says(&format!("{}/hub", b), "0.1.0", "hub");
    for i in 0..1024 {
        let d = says(&format!("{}/d{}", b, i), "0.1.0", "d");
        let u = reg.publish(&format!("/d{}/0.1.0", i), &d);
        hub = hub.dep(&format!("d{}", i), &u, &d);
    }
    let uh = reg.publish("/hub/0.1.0", &hub);
    let p = Proj::new("g15e", modules(&[("hub", url(&uh))]));
    assert_eq!(p.fails(&[]), "get: the dependency graph is larger than 1024 packages");
    assert_eq!(p.installed(), 0);

    // Una cadena de 70 paquetes, cada uno depende del siguiente.
    let mut next = says(&format!("{}/c69", b), "0.1.0", "fondo");
    let mut un = reg.publish("/c69/0.1.0", &next);
    for i in (0..69).rev() {
        let c = says(&format!("{}/c{}", b, i), "0.1.0", "c").dep(&format!("c{}", i + 1), &un, &next);
        un = reg.publish(&format!("/c{}/0.1.0", i), &c);
        next = c;
    }
    let p = Proj::new("g15f", modules(&[("c0", url(&un))]));
    assert_eq!(p.fails(&[]), "get: the dependency depth is larger than 64 levels");
    assert_eq!(p.installed(), 0);
}

#[test]
fn g19_g27_templates_and_data_files() {
    let e = local(|id| says(id, "0.1.0", "x").file("capas.syn", "export task f()\n    give render(\"otra.html\")\n"), "g19");
    assert_eq!(e, "get: tok: render(\"otra.html\") in capas.syn is not in files");
    let e = local(|id| says(id, "0.1.0", "x").file("datos.bin", "x"), "g27");
    assert_eq!(e, "get: tok: datos.bin is neither a .syn file nor a template the package renders; data goes in a .syn literal");
    // Una plantilla alcanzada, y la que ella incluye, sí entran.
    let reg = Reg::start();
    let tok = says(&format!("{}/tok", reg.base()), "0.1.0", "x")
        .file("capas.syn", "export task f()\n    give render(\"v.html\")\n")
        .file("v.html", "{ include \"parte.html\" }")
        .file("parte.html", "hola");
    let u = reg.publish("/tok/0.1.0", &tok);
    Proj::new("g19ok", modules(&[("tok", url(&u))])).ok(&[]);
}

#[test]
fn g23_deep_nesting_is_an_error_not_a_stack_overflow() {
    let deep = format!("let x be {}1{}\n", "(".repeat(5000), ")".repeat(5000));
    let e = local(|id| says(id, "0.1.0", "x").file("h5000.syn", &deep), "g23");
    assert_eq!(e, "get: tok: h5000.syn nests deeper than 1024");
}

/// M1 (ronda 1): una cadena de operadores arma un árbol tan hondo como operadores tiene; el
/// tope cuenta esa profundidad también (400 000 términos daban STATUS_STACK_OVERFLOW al
/// recorrer el árbol, después del parseo).
#[test]
fn g23_a_long_operator_chain_counts_toward_the_limit() {
    let chain = format!("let x be 1{}\n", " + 1".repeat(400_000));
    let e = local(|id| says(id, "0.1.0", "x").file("cadena.syn", &chain), "g23c");
    assert_eq!(e, "get: tok: cadena.syn nests deeper than 1024");
}

/// M2 (ronda 1): el `id` de un directo es el de lo que sirvió su `url` (o su hash), no el escrito.
/// Mudar la `url` sacando el `hash`, o editar el `id` a mano, no hace pánico ni escribe en el
/// nombre el paquete de otro.
#[test]
fn m2_the_direct_id_is_the_resolved_one_not_the_written_one() {
    let reg = Reg::start();
    let tok = says(&format!("{}/tok", reg.base()), "0.1.0", "tok");
    let ut = reg.publish("/tok/0.1.0", &tok);
    let deep = says(&format!("{}/deep", reg.base()), "0.1.0", "deep");
    let ud = reg.publish("/deep/0.1.0", &deep);
    // Un paquete que depende del `id` viejo: el `id` escrito sí está en lo elegido.
    let over = Pkg::new(&format!("{}/over", reg.base()), "0.2.0", "use \"tok\" as tok\nexport task cual()\n    give tok.cual()\n").dep("tok", &ut, &tok);
    let uo = reg.publish("/over/0.2.0", &over);
    let p = Proj::new("m2", modules(&[("tok", url(&ut))]));
    p.ok(&[]);
    // Mudar la `url` y sacar el `hash`.
    let mut j = p.json();
    j["modules"]["tok"]["url"] = json!(ud);
    j["modules"]["tok"].as_object_mut().unwrap().remove("hash");
    p.write(j);
    let out = p.ok(&[]);
    let j = p.json();
    assert_eq!((j["modules"]["tok"]["id"].as_str(), j["modules"]["tok"]["hash"].as_str()), (Some(deep.id.as_str()), Some(deep.hash().as_str())), "{}", out);
    p.ok(&["--check"]);
    // El `id` editado a mano con el hash escrito: se corrige con lo del hash.
    let mut j = p.json();
    j["modules"]["tok"]["id"] = json!(format!("{}/otro", reg.base()));
    p.write(j);
    let out = p.ok(&[]);
    assert_eq!(p.json()["modules"]["tok"]["id"].as_str(), Some(deep.id.as_str()));
    // N-r2-4 (ronda 2): el reporte no nombra el `id` escrito a mano, que nunca fue un paquete.
    assert!(!out.contains("/otro"), "{}", out);
    assert!(out.contains(&format!("tok 0.1.0 ({})", short_hash(&deep.hash()))), "{}", out);
    // La `url` nueva depende del `id` viejo: el nombre apunta a `over`, el viejo queda indirecto.
    let mut j = p.json();
    j["modules"]["tok"] = json!({"url": uo, "id": tok.id, "version": "0.1.0"});
    p.write(j);
    p.ok(&[]);
    let j = p.json();
    assert_eq!((j["modules"]["tok"]["id"].as_str(), j["modules"]["tok"]["hash"].as_str()), (Some(over.id.as_str()), Some(over.hash().as_str())));
    assert_eq!(j["indirect"][&tok.id]["hash"].as_str(), Some(tok.hash().as_str()), "{}", j);
    p.ok(&["--check"]);
    assert_eq!(p.run("use \"tok\" as t\nprint(t.cual())\n").trim(), "tok");
}

#[test]
fn g28_g32_g38_dependency_without_hash_and_the_id() {
    let e = local(|id| says(id, "0.1.0", "x").dep_raw("bpe", json!({"url": "https://reg.example/bpe/synsema.json"})), "g28");
    assert_eq!(e, "get: tok: its dependency bpe has no hash; a package pins its dependencies");

    // G32: el `id` no es prefijo de la `url`.
    let reg = Reg::start();
    let tok = says(&format!("{}/otro", reg.base()), "0.1.0", "x");
    let u = reg.publish("/tok/0.1.0", &tok);
    let p = Proj::new("g32", modules(&[("tok", url(&u))]));
    assert_eq!(
        p.fails(&[]),
        format!("get: tok: the package says it is {}, but it was fetched from {}; a package is fetched from under its id", tok.id, u)
    );

    // G38: una `url` debajo del `id` que redirige fuera de él, con la URL final.
    let tok = says(&format!("{}/tok", reg.base()), "0.1.0", "x");
    let fuera = reg.publish("/fuera/tok", &tok);
    reg.put("/tok/0.1.0/synsema.json", Resp::Redirect("/fuera/tok/synsema.json".to_string()));
    let p = Proj::new("g38", modules(&[("tok", url(&u))]));
    assert_eq!(
        p.fails(&[]),
        format!("get: tok: the package says it is {}, but it was fetched from {}; a package is fetched from under its id", tok.id, fuera)
    );
}

#[test]
fn g25_a_redirect_is_followed_and_files_are_relative_to_it() {
    let reg = Reg::start();
    let tok = says(&format!("{}/tok", reg.base()), "0.1.0", "real").file("capas.syn", "export task f()\n    give 1\n");
    reg.publish("/tok/real", &tok);
    reg.put("/tok/viejo/synsema.json", Resp::Redirect("/tok/real/synsema.json".to_string()));
    let p = Proj::new("g25", modules(&[("tok", url(&format!("{}/tok/viejo/synsema.json", reg.base())))]));
    p.ok(&[]);
    assert_eq!(p.run("use \"tok\" as tok\nprint(tok.cual())\n").trim(), "real");
}

#[test]
fn g16_two_gets_at_once_share_one_folder() {
    let reg = Reg::start();
    let tok = says(&format!("{}/tok", reg.base()), "0.1.0", "x");
    let u = reg.publish("/tok/0.1.0", &tok);
    let a = Proj::new("g16a", modules(&[("tok", url(&u))]));
    let b = a.sibling("g16b", modules(&[("tok", url(&u))]));
    let (ra, rb) = std::thread::scope(|s| {
        let ha = s.spawn(|| a.get(&[]));
        let hb = s.spawn(|| b.get(&[]));
        (ha.join().unwrap(), hb.join().unwrap())
    });
    assert_eq!(ra.0, 0, "{}", ra.2);
    assert_eq!(rb.0, 0, "{}", rb.2);
    assert_eq!(a.installed(), 1);
}

#[test]
fn g17_no_home_and_no_knob() {
    let reg = Reg::start();
    let tok = says(&format!("{}/tok", reg.base()), "0.1.0", "x");
    let u = reg.publish("/tok/0.1.0", &tok);
    let p = Proj::new("g17", modules(&[("tok", url(&u))]));
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_synsema"));
    c.arg("get").current_dir(&p.dir).env("SYNSEMA_NO_UPDATE_CHECK", "1");
    for k in ["SYNSEMA_MODULE_CACHE", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"] {
        c.env_remove(k);
    }
    let out = c.output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&out.stderr).trim_end(), "get: no home directory to keep modules in; set SYNSEMA_MODULE_CACHE");
}

// ---------------------------------------------------------------------------------------------
// §11: el grafo y la selección

#[test]
fn g29_g30_g31_g43_graph_errors() {
    let reg = Reg::start();
    let b = reg.base();
    let bid = format!("{}/bpe-core", b);
    // G29: la misma versión con dos hashes.
    let b1 = says(&bid, "0.3.0", "uno");
    let b2 = says(&bid, "0.3.0", "dos");
    let u1 = reg.publish("/bpe-core/0.3.0-a", &b1);
    let u2 = reg.publish("/bpe-core/0.3.0-b", &b2);
    let tok = uses_bpe(&format!("{}/tok", b), "0.1.0", &u1, &b1);
    let otro = uses_bpe(&format!("{}/otro", b), "0.1.0", &u2, &b2);
    let ut = reg.publish("/tok/0.1.0", &tok);
    let uo = reg.publish("/otro/0.1.0", &otro);
    let p = Proj::new("g29", modules(&[("tok", url(&ut)), ("otro", url(&uo))]));
    assert_eq!(
        p.fails(&[]),
        format!(
            "get: {} 0.3.0 has two different hashes: {} (from tok) and {} (from otro); nothing was installed",
            bid,
            short_hash(&b1.hash()),
            short_hash(&b2.hash())
        )
    );
    assert_eq!(p.installed(), 0);

    // G30: un ciclo de `id` (a 0.1 → c → a 0.2).
    let aid = format!("{}/a", b);
    let cid = format!("{}/c", b);
    let a2 = says(&aid, "0.2.0", "a2");
    let ua2 = reg.publish("/a/0.2.0", &a2);
    let c = says(&cid, "0.1.0", "c").dep("a", &ua2, &a2);
    let uc = reg.publish("/c/0.1.0", &c);
    let a1 = says(&aid, "0.1.0", "a1").dep("c", &uc, &c);
    let ua1 = reg.publish("/a/0.1.0", &a1);
    let p = Proj::new("g30", modules(&[("a", url(&ua1))]));
    assert_eq!(p.fails(&[]), format!("get: dependency cycle: {} → {} → {}", aid, cid, aid));

    // M4 (ronda 1): el ciclo se cierra sólo entre las versiones elegidas (x → ca 0.2.0 → cb 0.1.0;
    // y → cb 0.2.0 → ca 0.1.0; quedan ca 0.2.0 y cb 0.2.0, que se piden entre sí).
    let (caid, cbid) = (format!("{}/ca", b), format!("{}/cb", b));
    let ca1 = says(&caid, "0.1.0", "ca1");
    let uca1 = reg.publish("/ca/0.1.0", &ca1);
    let cb1 = says(&cbid, "0.1.0", "cb1");
    let ucb1 = reg.publish("/cb/0.1.0", &cb1);
    let ca2 = says(&caid, "0.2.0", "ca2").dep("cb", &ucb1, &cb1);
    let uca2 = reg.publish("/ca/0.2.0", &ca2);
    let cb2 = says(&cbid, "0.2.0", "cb2").dep("ca", &uca1, &ca1);
    let ucb2 = reg.publish("/cb/0.2.0", &cb2);
    let x = says(&format!("{}/x", b), "0.1.0", "x").dep("ca", &uca2, &ca2);
    let ux = reg.publish("/x/0.1.0", &x);
    let y = says(&format!("{}/y", b), "0.1.0", "y").dep("cb", &ucb2, &cb2);
    let uy = reg.publish("/y/0.1.0", &y);
    let p = Proj::new("m4", modules(&[("x", url(&ux)), ("y", url(&uy))]));
    assert_eq!(p.fails(&[]), format!("get: dependency cycle: {} → {} → {}", caid, cbid, caid));
    assert_eq!(p.installed(), 0);

    // G31: dos nombres directos con el mismo `id`.
    let p = Proj::new("g31", modules(&[("tok", url(&ut)), ("tok2", url(&ut))]));
    assert_eq!(p.fails(&[]), format!("get: tok and tok2 are the same package ({}/tok); keep one", b));

    // G43: la arista dice 9.9.9 y el índice 0.3.0.
    let mut wrong = json!({"url": u1, "id": bid, "version": "9.9.9", "hash": b1.hash()});
    let otro = says(&format!("{}/otro", b), "0.1.0", "o").dep_raw("bpe", wrong.take());
    let uo = reg.publish("/otro/mal", &otro);
    let p = Proj::new("g43", modules(&[("otro", url(&uo))]));
    assert_eq!(p.fails(&[]), format!("get: otro says {} 9.9.9, but {} serves 0.3.0; nothing was installed", bid, u1));
}

/// G33 (caso 4), G35 (`--check` con `indirect` editado), G42 (la `url` menor) y G51 (lo aceptado
/// cambió entre corridas).
#[test]
fn g33_g35_g51_a_higher_version_chosen_by_another_package_needs_accept() {
    let reg = Reg::start();
    let b = reg.base();
    let bid = format!("{}/bpe-core", b);
    let b30 = says(&bid, "0.3.0", "bpe-0.3.0");
    let b31 = says(&bid, "0.3.1", "bpe-0.3.1");
    let u30 = reg.publish("/bpe-core/0.3.0", &b30);
    let u31 = reg.publish("/bpe-core/0.3.1", &b31);
    let tok = uses_bpe(&format!("{}/tok", b), "0.1.0", &u30, &b30);
    let otro = uses_bpe(&format!("{}/otro", b), "0.1.0", &u31, &b31);
    let ut = reg.publish("/tok/0.1.0", &tok);
    let uo = reg.publish("/otro/latest", &otro);
    let p = Proj::new("g33", modules(&[("tok", url(&ut)), ("otro", url(&uo))]));
    let accept = format!("otro@{}", otro.hash());
    assert_eq!(
        p.fails(&[]),
        format!(
            "get: {} 0.3.1 is chosen because otro requires it (from {}); tok asked for 0.3.0; nothing was installed. To accept: synsema get --accept {}",
            bid, uo, accept
        )
    );
    assert_eq!(p.installed(), 0);

    // G51: entre las dos corridas, `otro` sirve otra cosa (que además pide red).
    let otro2 = Pkg::new(&format!("{}/otro", b), "0.1.1", "use \"bpe\" as bpe\nexport task cual()\n    require net(\"evil.example\")\n    give bpe.cual()\n")
        .dep("bpe", &u31, &b31);
    reg.publish("/otro/latest", &otro2);
    let e = p.fails(&["--accept", &accept]);
    assert!(
        e.starts_with(&format!(
            "get: otro is now {}, not the one shown ({}); nothing was changed\n",
            short_hash(&otro2.hash()),
            short_hash(&otro.hash())
        )),
        "{}",
        e
    );
    assert!(e.contains(&format!("To accept: synsema get --accept otro@{}", otro2.hash())), "{}", e);
    reg.publish("/otro/latest", &otro);

    // Con el `--accept`: 0.3.1 en `indirect`, y las dos corren con 0.3.1.
    p.ok(&["--accept", &accept]);
    let j = p.json();
    assert_eq!(j["indirect"][&bid]["version"], json!("0.3.1"));
    assert_eq!(j["indirect"][&bid]["url"], json!(u31));
    assert_eq!(p.run("use \"tok\" as tok\nuse \"otro\" as otro\nprint(tok.cual())\nprint(otro.cual())\n"), "bpe-0.3.1\nbpe-0.3.1\n");
    // La versión que perdió no se instala; su índice queda para `--check`.
    assert_eq!(p.installed(), 3);

    // G35: `--check` sin red con `indirect` editado a mano.
    drop(reg);
    p.ok(&["--check"]);
    let mut j = p.json();
    j["indirect"][&bid]["version"] = json!("0.3.0");
    p.write(j);
    assert_eq!(p.fails(&["--check"]), format!("get --check: indirect {} says 0.3.0, but the selection gives 0.3.1", bid));
}

#[test]
fn g42_the_smallest_url_is_written_in_both_orders() {
    let reg = Reg::start();
    let b = reg.base();
    let bid = format!("{}/bpe-core", b);
    let bpe = says(&bid, "0.3.0", "x");
    let ua = reg.publish("/bpe-core/a", &bpe);
    let ub = reg.publish("/bpe-core/b", &bpe);
    let tok = uses_bpe(&format!("{}/tok", b), "0.1.0", &ub, &bpe);
    let otro = uses_bpe(&format!("{}/otro", b), "0.1.0", &ua, &bpe);
    let ut = reg.publish("/tok/0.1.0", &tok);
    let uo = reg.publish("/otro/0.1.0", &otro);
    for order in [[("tok", &ut), ("otro", &uo)], [("otro", &uo), ("tok", &ut)]] {
        let p = Proj::new("g42", modules(&order.map(|(n, u)| (n, url(u)))));
        p.ok(&[]);
        assert_eq!(p.json()["indirect"][&bid]["url"], json!(ua));
    }
}

#[test]
fn g41_the_selection_is_the_maximum_over_a_fixed_graph() {
    let reg = Reg::start();
    let b = reg.base();
    let (xid, yid) = (format!("{}/x", b), format!("{}/y", b));
    let y1 = says(&yid, "0.1.0", "y1");
    let y2 = says(&yid, "0.2.0", "y2");
    let uy1 = reg.publish("/y/0.1.0", &y1);
    let uy2 = reg.publish("/y/0.2.0", &y2);
    let zid = format!("{}/z", b);
    let z = says(&zid, "0.1.0", "z");
    let uz = reg.publish("/z/0.1.0", &z);
    let x3 = says(&xid, "0.3.0", "x3").dep("y", &uy2, &y2).dep("z", &uz, &z);
    let x4 = says(&xid, "0.4.0", "x4");
    let ux3 = reg.publish("/x/0.3.0", &x3);
    let ux4 = reg.publish("/x/0.4.0", &x4);
    let a = says(&format!("{}/a", b), "0.1.0", "a").dep("x", &ux3, &x3).dep("y", &uy1, &y1);
    let bb = says(&format!("{}/b", b), "0.1.0", "b").dep("x", &ux4, &x4);
    let ua = reg.publish("/a/0.1.0", &a);
    let ub = reg.publish("/b/0.1.0", &bb);
    for order in [[("a", &ua), ("b", &ub)], [("b", &ub), ("a", &ua)]] {
        let p = Proj::new("g41", modules(&order.map(|(n, u)| (n, url(u)))));
        // `a` pide x 0.3.0 y queda x 0.4.0, elegida por `b` (caso 4).
        let e = p.fails(&[]);
        assert!(e.starts_with(&format!("get: {} 0.4.0 is chosen because b requires it (from {}); a asked for 0.3.0", xid, ub)), "{}", e);
        p.ok(&["--accept", &format!("b@{}", bb.hash())]);
        let j = p.json();
        assert_eq!(j["indirect"][&xid]["version"], json!("0.4.0"));
        assert_eq!(j["indirect"][&yid]["version"], json!("0.2.0"));
        // `z` sólo lo pedía x 0.3.0, que perdió: no se escribe ni se instala (§11.3, paso 3).
        assert!(j["indirect"].get(&zid).is_none(), "{}", p.text());
        assert_eq!(p.installed(), 4);
    }
}

/// G34 (caso 2 con un directo), G40 (casos 1 y 2 en un texto) y G46 (una bajada).
#[test]
fn g34_g40_g46_a_version_already_written_changes_only_with_accept() {
    let reg = Reg::start();
    let b = reg.base();
    let bid = format!("{}/bpe-core", b);
    let b20 = says(&bid, "0.2.0", "bpe-0.2.0");
    let b30 = Pkg::new(&bid, "0.3.0", "export task cual()\n    require net(\"api.x.com\")\n    give \"bpe-0.3.0\"\n");
    let u20 = reg.publish("/bpe-core/0.2.0", &b20);
    let u30 = reg.publish("/bpe-core/0.3.0", &b30);
    let p = Proj::new("g34", modules(&[("bpe", url(&u20))]));
    p.ok(&[]);
    let before = p.text();
    let otro = uses_bpe(&format!("{}/otro", b), "0.1.0", &u30, &b30);
    let uo = reg.publish("/otro/0.1.0", &otro);
    let mut j = p.json();
    j["modules"]["otro"] = url(&uo);
    p.write(j);
    let with_otro = p.text();
    let accept = format!("bpe@{}", b30.hash());
    // G40: sube y además pide más: un texto, un `--accept`.
    assert_eq!(
        p.fails(&[]),
        format!(
            "get: bpe 0.2.0 → 0.3.0 (required by otro) now requires net(\"api.x.com\"); nothing was changed. To accept: synsema get --accept {}",
            accept
        )
    );
    assert_eq!(p.text(), with_otro);
    let _ = before;
    p.ok(&["--accept", &accept]);
    let j = p.json();
    assert_eq!(j["modules"]["bpe"]["version"], json!("0.3.0"));
    assert_eq!(j["modules"]["bpe"]["url"], json!(u30));

    // G46: se saca `otro`; `bpe` baja... pero es directo, y su `url` ahora es la de 0.3.0: la
    // bajada de un `indirect` se prueba con `tok` (que pide 0.3.0) y `otro2` (que pide 0.3.1).
    let b31 = says(&bid, "0.3.1", "bpe-0.3.1");
    let b30b = says(&bid, "0.3.0", "bpe-0.3.0b");
    let u31 = reg.publish("/bpe-core/0.3.1", &b31);
    let u30b = reg.publish("/bpe-core/0.3.0b", &b30b);
    let tok = uses_bpe(&format!("{}/tok", b), "0.1.0", &u30b, &b30b);
    let otro2 = uses_bpe(&format!("{}/otro2", b), "0.1.0", &u31, &b31);
    let ut = reg.publish("/tok/0.1.0", &tok);
    let uo2 = reg.publish("/otro2/0.1.0", &otro2);
    let q = Proj::new("g46", modules(&[("tok", url(&ut)), ("otro2", url(&uo2))]));
    q.ok(&["--accept", &format!("otro2@{}", otro2.hash())]);
    let mut j = q.json();
    j["modules"].as_object_mut().unwrap().remove("otro2");
    q.write(j);
    let accept = format!("{}@{}", bid, b30b.hash());
    assert_eq!(
        q.fails(&[]),
        format!(
            "get: {} 0.3.1 → 0.3.0 (no package requires 0.3.1 anymore); nothing was changed. To accept: synsema get --accept {}",
            bid, accept
        )
    );
    let out = q.ok(&["--accept", &accept]);
    assert!(out.contains(&format!("{} 0.3.1 → 0.3.0", bid)), "{}", out);
    assert_eq!(q.json()["indirect"][&bid]["version"], json!("0.3.0"));
    assert_eq!(q.run("use \"tok\" as tok\nprint(tok.cual())\n").trim(), "bpe-0.3.0b");
}

/// G39 (un fork bajo un `id` que ya estaba), G53 (el fork cambia de commit entre corridas), G50 (un
/// directo nuevo que pide menos que lo elegido) y G45.
#[test]
fn g39_g45_g50_g53_a_fork_does_not_enter_an_id_without_accept() {
    let reg = Reg::start();
    let b = reg.base();
    let rid = format!("{}/org/repo", b);
    let r01 = says(&rid, "0.1.0", "original");
    let r99 = says(&rid, "9.9.9", "fork");
    let r99b = says(&rid, "9.9.9", "fork, otro commit");
    let u01 = reg.publish("/org/repo/v0.1.0", &r01);
    let u99 = reg.publish("/org/repo/fork", &r99);
    let tok = Pkg::new(&format!("{}/tok", b), "0.1.0", "use \"r\" as r\nexport task cual()\n    give r.cual()\n").dep("r", &u01, &r01);
    let ut = reg.publish("/tok/0.1.0", &tok);
    let p = Proj::new("g39", modules(&[("tok", url(&ut))]));
    p.ok(&[]);
    let otro = Pkg::new(&format!("{}/otro", b), "0.1.0", "use \"r\" as r\nexport task cual()\n    give r.cual()\n").dep("r", &u99, &r99);
    let uo = reg.publish("/otro/latest", &otro);
    let mut j = p.json();
    j["modules"]["otro"] = url(&uo);
    p.write(j);
    let accept = format!("{}@{}", rid, r99.hash());
    assert_eq!(
        p.fails(&[]),
        format!("get: {} 0.1.0 → 9.9.9 because otro requires it (from {}); nothing was changed. To accept: synsema get --accept {}", rid, uo, accept)
    );

    // G53: entre las dos corridas, `otro` pide 9.9.9 de otro commit.
    let u99b = reg.publish("/org/repo/fork2", &r99b);
    let otro_b = Pkg::new(&format!("{}/otro", b), "0.1.0", "use \"r\" as r\nexport task cual()\n    give r.cual()\n").dep("r", &u99b, &r99b);
    reg.publish("/otro/latest", &otro_b);
    let e = p.fails(&["--accept", &accept]);
    assert!(
        e.starts_with(&format!(
            "get: {} 9.9.9 is now {}, not the one shown ({}); nothing was changed\n",
            rid,
            short_hash(&r99b.hash()),
            short_hash(&r99.hash())
        )),
        "{}",
        e
    );
    assert!(e.contains(&format!("To accept: synsema get --accept {}@{}", rid, r99b.hash())), "{}", e);

    // G50: `get` con sólo `otro` (el fork entra, lo nombra el comando); después se agrega `repo`
    // directo, que sirve 0.1.0.
    reg.publish("/otro/latest", &otro);
    let q = Proj::new("g50", modules(&[("otro", url(&uo))]));
    q.ok(&[]);
    let mut j = q.json();
    j["modules"]["repo"] = url(&u01);
    q.write(j);
    assert_eq!(
        q.fails(&[]),
        format!(
            "get: {} 9.9.9 is chosen because otro requires it (from {}); repo (direct) asked for 0.1.0; nothing was changed. To accept: synsema get --accept otro@{}",
            rid,
            uo,
            otro.hash()
        )
    );
    // Lo mismo con `tok`, que pide 0.1.0.
    let mut j = q.json();
    j["modules"].as_object_mut().unwrap().remove("repo");
    j["modules"]["tok"] = url(&ut);
    q.write(j);
    assert_eq!(
        q.fails(&[]),
        format!(
            "get: {} 9.9.9 is chosen because otro requires it (from {}); tok asked for 0.1.0; nothing was changed. To accept: synsema get --accept otro@{}",
            rid,
            uo,
            otro.hash()
        )
    );

    // G45: primer `get` con `repo` y `otro`: nada instalado hasta el `--accept`.
    let r = Proj::new("g45", modules(&[("repo", url(&u01)), ("otro", url(&uo))]));
    let e = r.fails(&[]);
    assert_eq!(
        e,
        format!(
            "get: {} 9.9.9 is chosen because otro requires it (from {}); repo (direct) asked for 0.1.0; nothing was installed. To accept: synsema get --accept otro@{}",
            rid,
            uo,
            otro.hash()
        )
    );
    assert_eq!(r.installed(), 0);
    r.ok(&["--accept", &format!("otro@{}", otro.hash())]);
    assert_eq!(r.json()["modules"]["repo"]["version"], json!("9.9.9"));
}

/// G47 (caso 3) y G48 (un `--accept` del directo acepta las transitivas).
#[test]
fn g47_g48_an_update_that_brings_new_or_higher_dependencies() {
    let reg = Reg::start();
    let b = reg.base();
    let deps: Vec<(String, Pkg, Pkg)> = ["d1", "d2", "d3"]
        .iter()
        .map(|n| (n.to_string(), says(&format!("{}/{}", b, n), "0.1.0", n), says(&format!("{}/{}", b, n), "0.2.0", n)))
        .collect();
    let mut tok1 = says(&format!("{}/tok", b), "0.1.0", "t1");
    let mut tok2 = says(&format!("{}/tok", b), "0.2.0", "t2");
    for (n, v1, v2) in &deps {
        let u1 = reg.publish(&format!("/{}/0.1.0", n), v1);
        let u2 = reg.publish(&format!("/{}/0.2.0", n), v2);
        tok1 = tok1.dep(n, &u1, v1);
        tok2 = tok2.dep(n, &u2, v2);
    }
    reg.publish("/tok/latest", &tok1);
    let p = Proj::new("g48", modules(&[("tok", url(&format!("{}/tok/latest/synsema.json", b)))]));
    p.ok(&[]);
    reg.publish("/tok/latest", &tok2);
    let e = p.fails(&["--update", "tok"]);
    for (n, _, _) in &deps {
        assert!(e.contains(&format!("get: {}/{} 0.1.0 → 0.2.0 because tok requires it", b, n)), "{}", e);
    }
    let out = p.ok(&["--update", "tok", "--accept", &format!("tok@{}", tok2.hash())]);
    assert!(out.contains("tok 0.1.0 → 0.2.0"), "{}", out);

    // G47: `tok` 0.3.0 trae un `id` nuevo que pide red.
    let exfil = Pkg::new(&format!("{}/exfil", b), "0.1.0", "export task f()\n    require net(\"evil.example\")\n    give 1\n");
    let ue = reg.publish("/exfil/0.1.0", &exfil);
    let mut tok3 = says(&format!("{}/tok", b), "0.3.0", "t3").dep("exfil", &ue, &exfil);
    for (n, _, v2) in &deps {
        tok3 = tok3.dep(n, &format!("{}/{}/0.2.0/synsema.json", b, n), v2);
    }
    reg.publish("/tok/latest", &tok3);
    assert_eq!(
        p.fails(&["--update", "tok"]),
        format!(
            "get: tok 0.3.0 brings a new dependency {}/exfil (requires net(\"evil.example\")); nothing was changed. To accept: synsema get --update tok --accept tok@{}",
            b,
            tok3.hash()
        )
    );
}

/// G22: un PR cambia sólo el `hash` de `tok` a un paquete del caché que pide red.
#[test]
fn g22_check_reads_requires_from_the_cached_tree() {
    let reg = Reg::start();
    let id = format!("{}/tok", reg.base());
    let good = says(&id, "0.1.0", "bien");
    let evil = Pkg::new(&id, "0.1.0", "export task cual()\n    require net(\"evil.example\")\n    give 1\n");
    let ug = reg.publish("/tok/0.1.0", &good);
    let ue = reg.publish("/tok/mal", &evil);
    let p = Proj::new("g22", modules(&[("tok", url(&ug))]));
    p.ok(&[]);
    // El árbol malo llega al caché por otro proyecto.
    p.sibling("g22b", modules(&[("tok", url(&ue))])).ok(&[]);
    drop(reg);
    let mut j = p.json();
    j["modules"]["tok"]["hash"] = json!(evil.hash());
    p.write(j);
    assert_eq!(
        p.fails(&["--check"]),
        format!(
            "get --check: tok: synsema.json says requires [] but {} requires net(\"evil.example\"); run synsema get --update tok",
            short_hash(&evil.hash())
        )
    );
}

/// D-22 fuera de un paquete: el tope vale para cualquier carga, con la ubicación y sin desbordar.
/// 1000 niveles siguen parseando (`v0652_cli`).
#[test]
fn g23_the_nesting_limit_also_holds_for_a_program() {
    let p = Proj::new("g23run", json!({}));
    std::fs::write(p.dir.join("hondo.syn"), format!("let x be {}1{}\nprint(x)\n", "(".repeat(1100), ")".repeat(1100))).unwrap();
    for cmd in ["check", "run"] {
        let (code, out, err) = synsema_env(&p.dir, &[cmd, "hondo.syn"], None, &[]);
        assert_eq!(code, 1, "{}: {}\n{}", cmd, out, err);
        assert!(err.contains("hondo.syn:1:") && err.contains("the code nests deeper than 1024 levels"), "{}: {}", cmd, err);
        assert!(!err.contains("overflowed its stack"), "{}: {}", cmd, err);
    }
}

/// M1 (ronda 1): las cadenas (`+`, `and`, `**`, `.x`, `[i]`, `()`, `of`) cuentan en el mismo
/// tope que los paréntesis; 1000 términos siguen corriendo.
#[test]
fn g23_operator_chains_count_toward_the_limit_in_a_program() {
    let p = Proj::new("g23chain", json!({}));
    let forms = [
        format!("let x be 1{}\nprint(x)\n", " + 1".repeat(400_000)),
        format!("let x be true{}\nprint(x)\n", " and true".repeat(2000)),
        format!("let x be 1{}\nprint(x)\n", " ** 1".repeat(2000)),
        format!("let m be {{}}\nlet x be m{}\nprint(x)\n", ".a".repeat(2000)),
        format!("let m be [1]\nlet x be m{}\nprint(x)\n", "[0]".repeat(2000)),
        format!("task f()\n    give f\nlet x be f{}\nprint(x)\n", "()".repeat(2000)),
        format!("let m be {{}}\nlet x be {}m\nprint(x)\n", "a of ".repeat(2000)),
    ];
    for (i, src) in forms.iter().enumerate() {
        std::fs::write(p.dir.join("cadena.syn"), src).unwrap();
        for cmd in ["check", "run"] {
            let (code, out, err) = synsema_env(&p.dir, &[cmd, "cadena.syn"], None, &[]);
            assert_eq!(code, 1, "forma {} {}: {}\n{}", i, cmd, out, err);
            assert!(err.contains("the code nests deeper than 1024 levels"), "forma {} {}: {}", i, cmd, err);
        }
    }
    std::fs::write(p.dir.join("cadena.syn"), format!("let x be 1{}\nprint(x)\n", " + 1".repeat(1000))).unwrap();
    let (code, out, err) = synsema_env(&p.dir, &["run", "cadena.syn"], None, &[]);
    assert_eq!((code, out.trim()), (0, "1001"), "{}", err);
}

// ---------------------------------------------------------------------------------------------
// Ronda 1: B4, B5, B6, B7, B9

/// B4: un índice que no es JSON, o que se corta antes de su `Content-Length`, es una descarga rota
/// (§10.2, fila 1), no un índice inválido.
#[test]
fn b4_a_broken_index_is_a_broken_download() {
    let reg = Reg::start();
    reg.put("/tok/synsema.json", Resp::Body(b"{\"id\": \"http://x".to_vec()));
    let u = format!("{}/tok/synsema.json", reg.base());
    let p = Proj::new("b4a", modules(&[("tok", url(&u))]));
    let e = p.fails(&[]);
    assert!(e.starts_with(&format!("get: could not download tok from {}: synsema.json is not JSON", u)) && e.ends_with("; nothing was installed"), "{}", e);
    let tok = says(&format!("{}/tok", reg.base()), "0.1.0", "x");
    let full = tok.index();
    reg.put("/tok/synsema.json", Resp::Truncated(full[..full.len() / 2].to_vec(), full.len()));
    let e = p.fails(&[]);
    assert_eq!(e, format!("get: could not download tok from {}: the response ended after {} of its {} bytes; nothing was installed", u, full.len() / 2, full.len()));
    assert_eq!(p.installed(), 0);
}

/// B5: con el hash escrito, un índice republicado (y además inválido) se ve como republicación
/// (§10.2, filas 2 y 3): el hash se compara antes de validar.
#[test]
fn b5_a_republished_invalid_index_is_a_republication() {
    let reg = Reg::start();
    let tok = says(&format!("{}/tok", reg.base()), "0.1.0", "x");
    let u = reg.publish("/tok/0.1.0", &tok);
    let p = Proj::new("b5", modules(&[("tok", url(&u))]));
    p.ok(&[]);
    std::fs::remove_dir_all(&p.cache).unwrap();
    let bad = says(&tok.id, "0.1.0", "x").file("COM0.syn", "export let x be 1\n");
    reg.publish("/tok/0.1.0", &bad);
    let e = p.fails(&[]);
    assert!(e.starts_with("get: the registry changed the content of tok 0.1.0 without changing its version"), "{}", e);
    assert!(e.contains(&short_hash(&bad.hash())), "{}", e);
    // N-r2-5 (ronda 2): republicado sin `files`, o con un `sha256` que no es texto: también es una
    // republicación (antes, el error de validación).
    assert_eq!(u, format!("{}/tok/0.1.0/synsema.json", reg.base()));
    for idx in [
        json!({"id": tok.id, "version": "0.1.0", "main": "m.syn"}),
        json!({"id": tok.id, "version": "0.1.0", "main": "m.syn", "files": [{"path": "m.syn", "sha256": 5}]}),
    ] {
        reg.put("/tok/0.1.0/synsema.json", Resp::Body(serde_json::to_vec_pretty(&idx).unwrap()));
        let e = p.fails(&[]);
        assert!(e.starts_with("get: the registry changed the content of tok 0.1.0 without changing its version"), "{}", e);
    }
}

/// B6: §10.3 en orden: el paso 3 de todos los `.syn` antes que el 4 (un `render` que falta), y en un
/// directo, los pasos 3 a 5 antes que el 6 (el `id` contra la `url`).
#[test]
fn b6_the_validation_runs_in_the_order_of_the_design() {
    let reg = Reg::start();
    let tok = Pkg::new(&format!("{}/tok", reg.base()), "0.1.0", "export task f()\n    give render(\"falta.html\")\n").file("b.syn", "require net\nexport let x be 1\n");
    let u = reg.publish("/tok/0.1.0", &tok);
    let e = Proj::new("b6a", modules(&[("tok", url(&u))])).fails(&[]);
    assert!(e.contains("b.syn") && !e.contains("falta.html"), "{}", e);
    // El `id` no está debajo de la `url` y además falta una plantilla: sale la plantilla.
    let otro = Pkg::new("https://otro.example/tok", "0.1.0", "export task f()\n    give render(\"falta.html\")\n");
    let u = reg.publish("/otro/0.1.0", &otro);
    let e = Proj::new("b6b", modules(&[("tok", url(&u))])).fails(&[]);
    assert_eq!(e, "get: tok: render(\"falta.html\") in m.syn is not in files");
}

/// B7: con dos casos independientes, cada línea imprime el comando entero (los dos `--accept`), y
/// seguir una basta.
#[test]
fn b7_the_printed_command_accepts_every_pending_case() {
    let reg = Reg::start();
    let b = reg.base();
    let mut pairs = Vec::new();
    for (k, lib) in [("1", "bpe"), ("2", "bpe2")] {
        let lid = format!("{}/{}", b, lib);
        let l0 = says(&lid, "0.3.0", lib);
        let l1 = says(&lid, "0.3.1", lib);
        let u0 = reg.publish(&format!("/{}/0.3.0", lib), &l0);
        let u1 = reg.publish(&format!("/{}/0.3.1", lib), &l1);
        let tok = uses_bpe(&format!("{}/tok{}", b, k), "0.1.0", &u0, &l0);
        let otro = uses_bpe(&format!("{}/otro{}", b, k), "0.1.0", &u1, &l1);
        let ut = reg.publish(&format!("/tok{}/0.1.0", k), &tok);
        let uo = reg.publish(&format!("/otro{}/0.1.0", k), &otro);
        pairs.push((format!("tok{}", k), ut, format!("otro{}", k), uo, otro));
    }
    let mods: Vec<(&str, Value)> = pairs.iter().flat_map(|(t, ut, o, uo, _)| [(t.as_str(), url(ut)), (o.as_str(), url(uo))]).collect();
    let p = Proj::new("b7", modules(&mods));
    let e = p.fails(&[]);
    let lines: Vec<&str> = e.lines().collect();
    assert_eq!(lines.len(), 2, "{}", e);
    let both = format!("To accept: synsema get --accept otro1@{} --accept otro2@{}", pairs[0].4.hash(), pairs[1].4.hash());
    assert!(lines.iter().all(|l| l.ends_with(&both)), "{}", e);
    // Con sólo el primero, la línea que queda lleva los dos (el que ya vale y el que falta).
    let first = format!("otro1@{}", pairs[0].4.hash());
    let e = p.fails(&["--accept", &first]);
    assert!(e.lines().count() == 1 && e.ends_with(&both), "{}", e);
    p.ok(&["--accept", &first, "--accept", &format!("otro2@{}", pairs[1].4.hash())]);
}

/// B9: un índice dañado en `<cache>/index/` (el de una versión que pierde): `--check` lo dice y cómo se
/// arregla; `get` avisa, lo baja y lo reescribe; después `--check` anda.
#[test]
fn b9_a_damaged_cached_index_is_named_and_repaired() {
    let reg = Reg::start();
    let b = reg.base();
    let bid = format!("{}/bpe", b);
    let b1 = says(&bid, "0.1.0", "b1");
    let b2 = says(&bid, "0.2.0", "b2");
    let u1 = reg.publish("/bpe/0.1.0", &b1);
    let u2 = reg.publish("/bpe/0.2.0", &b2);
    let a = uses_bpe(&format!("{}/a", b), "0.1.0", &u1, &b1);
    let c = uses_bpe(&format!("{}/c", b), "0.1.0", &u2, &b2);
    let ua = reg.publish("/a/0.1.0", &a);
    let uc = reg.publish("/c/0.1.0", &c);
    let p = Proj::new("b9", modules(&[("a", url(&ua)), ("c", url(&uc))]));
    let e = p.fails(&[]);
    let accept = e.rsplit("--accept ").next().unwrap().to_string();
    p.ok(&["--accept", &accept]);
    p.ok(&["--check"]);
    let idx = p.cache.join("index").join(format!("{}.json", b1.hash().replacen(':', "-", 1)));
    assert!(idx.is_file(), "{}", idx.display());
    std::fs::write(&idx, "{roto").unwrap();
    let e = p.fails(&["--check"]);
    assert!(e.starts_with(&format!("get --check: the cached index of {} 0.1.0 ({}) is damaged: ", bid, short_hash(&b1.hash()))) && e.ends_with("; run synsema get to fetch it again"), "{}", e);
    let (code, _, err) = p.get(&[]);
    assert_eq!(code, 0, "{}", err);
    assert!(err.contains("is damaged; fetching it again"), "{}", err);
    assert_eq!(std::fs::read(&idx).unwrap(), b1.index());
    p.ok(&["--check"]);
    // Ronda 2 (B-r2-5): dañado y sin poder reemplazarlo (sólo lectura en Windows; la carpeta sin
    // escritura en Unix): un error que nombra el archivo, no «fetching it again» con rc 0.
    std::fs::write(&idx, "{roto").unwrap();
    let locked = if cfg!(windows) { idx.clone() } else { idx.parent().unwrap().to_path_buf() };
    let set_ro = |ro: bool| {
        let mut perm = std::fs::metadata(&locked).unwrap().permissions();
        perm.set_readonly(ro);
        std::fs::set_permissions(&locked, perm).unwrap();
    };
    set_ro(true);
    let (code, _, err) = p.get(&[]);
    set_ro(false);
    assert_ne!(code, 0, "{}", err);
    assert!(err.contains(&format!("get: the cached index {} does not match its hash and cannot be replaced (", idx.display())), "{}", err);
    assert!(err.contains("delete it and run synsema get again"), "{}", err);
    p.ok(&[]);
    assert_eq!(std::fs::read(&idx).unwrap(), b1.index());
}

/// Ronda 8 (N-r8-2): con la carpeta del proyecto sin escritura (Unix), `get` falla ya al crear el
/// temporal de `synsema.json`; el error nombra `synsema.json`, no `.synsema.json.tmp-<pid>`.
#[cfg(unix)]
#[test]
fn n_r8_2_an_unwritable_project_folder_names_synsema_json() {
    use std::os::unix::fs::PermissionsExt;
    let reg = Reg::start();
    let b = reg.base();
    let bpe = says(&format!("{}/bpe", b), "0.1.0", "b1");
    let u = reg.publish("/bpe/0.1.0", &bpe);
    let manifest = modules(&[("bpe", url(&u))]);
    let p = Proj::new("nr82", manifest.clone());
    p.ok(&[]);
    // Otra vez sin el hash: `get` tiene que reescribir `synsema.json`.
    p.write(manifest);
    let mode = |m: u32| std::fs::set_permissions(&p.dir, std::fs::Permissions::from_mode(m)).unwrap();
    mode(0o555);
    let (code, _, err) = p.get(&[]);
    mode(0o755);
    assert_ne!(code, 0, "{}", err);
    let want = format!("get: could not write {}: ", p.dir.join("synsema.json").display());
    assert!(err.contains(&want) && !err.contains(".synsema.json.tmp-"), "{}", err);
}

/// N10 (ronda 1): `synsema get --help` sale por stdout con rc 0.
#[test]
fn n10_get_help_exits_zero() {
    let dir = std::env::temp_dir();
    let (code, out, err) = super::v0646_tanda_e_cli::synsema_env(&dir, &["get", "--help"], None, &[]);
    assert_eq!(code, 0, "{}", err);
    assert!(out.starts_with("usage: synsema get "), "{}", out);
}

/// Ronda 2 (M-r2-4): `otherwise when` (en línea y en bloque) y los huecos de una plantilla también
/// cuentan para el tope; antes `get` desbordaba la pila con ellos.
#[test]
fn m_r2_4_when_chains_and_template_holes_count_toward_the_limit_in_get() {
    let forms = [
        ("huecos.syn", format!("export let x be `{}`\n", "{1}".repeat(400_000))),
        ("enlinea.syn", format!("export let x be {}1\n", "when 1 == 2 then 0 otherwise ".repeat(70_000))),
        ("bloque.syn", format!("when 1 == 2\n    print(0)\n{}otherwise\n    print(1)\n", "otherwise when 1 == 2\n    print(0)\n".repeat(70_000))),
    ];
    for (i, (name, src)) in forms.iter().enumerate() {
        let e = local(|id| says(id, "0.1.0", "x").file(name, src), &format!("mr24g{}", i));
        assert_eq!(e, format!("get: tok: {} nests deeper than 1024", name));
    }
}

/// Ronda 2 (M-r2-4): lo mismo en un programa (`check`, `run`), con plantillas anidadas también;
/// 1000 niveles de cada forma siguen corriendo.
#[test]
fn m_r2_4_when_chains_and_template_holes_count_toward_the_limit_in_a_program() {
    let p = Proj::new("mr24", json!({}));
    let inline = |n: usize| format!("let x be {}1\nprint(x)\n", "when 1 == 2 then 0 otherwise ".repeat(n));
    let block = |n: usize| format!("when 1 == 2\n    print(0)\n{}otherwise\n    print(1)\n", "otherwise when 1 == 2\n    print(0)\n".repeat(n));
    let holes = |n: usize| format!("let x be `{}`\nprint(length(x))\n", "{1}".repeat(n));
    let nested = |n: usize| format!("let x be {}1{}\nprint(x)\n", "`{".repeat(n), "}`".repeat(n));
    for (i, src) in [inline(1100), block(1100), holes(1100), nested(1100), inline(70_000)].iter().enumerate() {
        std::fs::write(p.dir.join("hondo.syn"), src).unwrap();
        for cmd in ["check", "run"] {
            let (code, out, err) = synsema_env(&p.dir, &[cmd, "hondo.syn"], None, &[]);
            assert_eq!(code, 1, "forma {} {}: {}\n{}", i, cmd, out, err);
            assert!(err.contains("the code nests deeper than 1024 levels"), "forma {} {}: {}", i, cmd, err);
        }
    }
    for (src, want) in [(inline(1000), "1"), (block(1000), "1"), (holes(1000), "1000"), (nested(500), "1")] {
        std::fs::write(p.dir.join("hondo.syn"), &src).unwrap();
        let (code, out, err) = synsema_env(&p.dir, &["run", "hondo.syn"], None, &[]);
        assert_eq!((code, out.trim()), (0, want), "{}", err);
    }
}

/// Ronda 3 (M-r3-3): una plantilla HTML de un paquete con 70 000 bloques anidados (`when`, `each`,
/// `fill`, cadenas de `otherwise when`) es el error del tope en `get`, sin desbordar la pila y sin
/// instalar nada.
#[test]
fn m_r3_3_nested_template_blocks_count_toward_the_limit_in_get() {
    let n = 70_000;
    let forms = [
        format!("{}x{}", "{ when true }".repeat(n), "{ end }".repeat(n)),
        format!("{}x{}", "{ each a in [1] }".repeat(n), "{ end }".repeat(n)),
        format!("{}x{}", "{ fill \"a\" }".repeat(n), "{ end }".repeat(n)),
        format!("{{ when false }}a{}x{{ end }}", "{ otherwise when false }a".repeat(n)),
    ];
    for (i, t) in forms.iter().enumerate() {
        let e = local(|id| Pkg::new(id, "0.1.0", "export task f()\n    give render(\"t.html\", {})\n").file("t.html", t), &format!("mr33g{}", i));
        assert_eq!(e, "get: tok: t.html nests deeper than 1024", "forma {}", i);
    }
}

/// Ronda 3 (M-r3-3): lo mismo al correr una plantilla local; 1000 niveles siguen corriendo.
#[test]
fn m_r3_3_nested_template_blocks_count_toward_the_limit_in_a_program() {
    let p = Proj::new("mr33", json!({}));
    std::fs::write(p.dir.join("r.syn"), "require file.read(\"**\")\nprint(length(render(\"t.html\", {})[\"body\"]))\n").unwrap();
    let when = |n: usize| format!("{}x{}", "{ when true }".repeat(n), "{ end }".repeat(n));
    let chain = |n: usize| format!("{{ when false }}a{}x{{ end }}", "{ otherwise when false }a".repeat(n));
    for (i, t) in [when(1100), when(150_000), chain(1100)].iter().enumerate() {
        std::fs::write(p.dir.join("t.html"), t).unwrap();
        let (code, out, err) = synsema_env(&p.dir, &["run", "r.syn"], None, &[]);
        assert_eq!(code, 1, "forma {}: {}\n{}", i, out, err);
        assert!(err.contains("the code nests deeper than 1024 levels"), "forma {}: {}", i, err);
    }
    for (t, want) in [(when(1000), "1"), (chain(1000), "0")] {
        std::fs::write(p.dir.join("t.html"), &t).unwrap();
        let (code, out, err) = synsema_env(&p.dir, &["run", "r.syn"], None, &[]);
        assert_eq!((code, out.trim()), (0, want), "{}", err);
    }
}

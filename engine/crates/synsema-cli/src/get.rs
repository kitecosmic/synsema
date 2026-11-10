//! v0.6.58 (§10 y §11 de `specs/v0.6.58-diseno.md`): `synsema get`.
//!
//! Baja los paquetes que nombra el `synsema.json` del proyecto, los verifica archivo por archivo
//! contra su índice, los valida (§10.3), resuelve las dependencias con la selección de versión
//! mínima (§11.3), los instala en el caché y escribe lo resuelto. Nada cambia lo que corre sin que el
//! comando lo nombre o alguien lo acepte (`--accept`, §10.1). `get --check` repite la selección sin
//! red y compara con lo escrito.
//!
//! Es lo único que resuelve: `run` lee lo escrito (§11.3).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use synsema_core::modtable::{
    self, is_tree_hash, normalize_id, package_dir, sha256_hex, short_hash, tree_hash, MAX_DEP_DEPTH, MAX_FILES, MAX_FILE_BYTES,
    MAX_PACKAGES, MAX_PACKAGE_BYTES, MAX_PATH_BYTES,
};
use synsema_core::project::{self, Manifest, ModEntry};

const TIMEOUT_SECS: u64 = 120;
const MAX_REDIRECTS: usize = 5;

// ---------------------------------------------------------------------------------------------
// Los argumentos

struct Opts {
    check: bool,
    update: Option<String>,
    /// `--accept <clave>@tree-sha256:<hex>`: la clave es un nombre directo o un `id`.
    accept: Vec<(String, String)>,
}

fn parse_args(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts { check: false, update: None, accept: Vec::new() };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--check" => o.check = true,
            "--update" => {
                i += 1;
                let Some(n) = args.get(i) else { return Err("get: --update needs the name of a module".to_string()) };
                o.update = Some(n.clone());
            }
            "--accept" => {
                i += 1;
                let Some(a) = args.get(i) else {
                    return Err("get: --accept needs the hash shown by get (--accept otro@tree-sha256:…)".to_string());
                };
                // Se parte en el último `@`: un `id` es una URL y puede tener uno.
                match a.rsplit_once('@') {
                    Some((k, h)) if !k.is_empty() && is_tree_hash(h) => o.accept.push((k.to_string(), h.to_string())),
                    _ => return Err(format!("get: --accept needs the hash shown by get (--accept {}@tree-sha256:…)", a)),
                }
            }
            other => return Err(format!("get: unknown argument '{}' (synsema get [--update <name>] [--accept <name>@<hash>]... | --check)", other)),
        }
        i += 1;
    }
    if o.check && (o.update.is_some() || !o.accept.is_empty()) {
        return Err("get: --check does not change anything; run it alone".to_string());
    }
    Ok(o)
}

const USAGE: &str = "usage: synsema get [--update <name>] [--accept <name>@<hash>]... | --check

Fetches the modules that synsema.json names, checks each one, writes its hash and puts it in the cache.
  (no flags)                fetch what is missing and write its hash
  --update <name>           fetch <name> again from its url and show what changed
  --accept <name>@<hash>    accept a change get showed (with the hash it printed)
  --check                   change nothing: fail if synsema.json and the cache do not match";

pub fn cmd_get(args: &[String]) -> ExitCode {
    // N10 (ronda 1): la ayuda sale por stdout con rc 0, como la de los otros comandos.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", USAGE);
        return ExitCode::SUCCESS;
    }
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{}", msg);
            ExitCode::from(1)
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let opts = parse_args(args)?;
    synsema_stdlib::project_owner::install();
    let cwd = std::env::current_dir().map_err(|e| format!("get: {}", e))?;
    // El proyecto, con las reglas de §3: desde el directorio actual hacia arriba.
    let probe = cwd.join("synsema-get");
    let project = project::resolve(&probe.to_string_lossy()).map_err(|e| format!("get: {}", e))?;
    let (Some(root), Some(manifest)) = (project.root.clone(), project.manifest.clone()) else {
        return Err(format!(
            "get: there is no synsema.json in {} or above; write {{\"modules\": {{\"tok\": {{\"url\": \"https://…\"}}}}}} (synsema init writes one)",
            cwd.display()
        ));
    };
    let cache = modtable::cache_dir(Some(&root)).map_err(|e| {
        if e.contains("no home folder") {
            "get: no home directory to keep modules in; set SYNSEMA_MODULE_CACHE".to_string()
        } else {
            format!("get: {}", e)
        }
    })?;
    let json_path = root.join("synsema.json");
    if opts.check {
        return check(&manifest, &cache);
    }
    let raw = std::fs::read(&json_path).map_err(|e| format!("get: {}: {}", json_path.display(), e))?;
    get(&opts, &manifest, &raw, &json_path, &cache)
}

// ---------------------------------------------------------------------------------------------
// Las URLs (§7)

/// `(esquema, autoridad, ruta con la consulta)`.
fn split_url(url: &str) -> Option<(String, &str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let cut = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some((scheme.to_ascii_lowercase(), &rest[..cut], &rest[cut..]))
}

fn host_of(authority: &str) -> &str {
    let a = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if let Some(rest) = a.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("");
    }
    a.rsplit_once(':').map_or(a, |(h, p)| if p.bytes().all(|b| b.is_ascii_digit()) { h } else { a })
}

/// Loopback por texto, en la forma canónica (B10, ronda 1): `localhost`, `::1` o `127.a.b.c` con cada
/// parte un decimal de 0 a 255 sin ceros a la izquierda. `127.0.0.999` o `127.000.000.001` no son
/// direcciones, irían al resolvedor: no son de esta máquina.
fn is_loopback(authority: &str) -> bool {
    let h = host_of(authority).to_ascii_lowercase();
    if h == "localhost" || h == "::1" {
        return true;
    }
    let parts: Vec<&str> = h.split('.').collect();
    parts.len() == 4
        && parts[0] == "127"
        && parts.iter().all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()) && (*p == "0" || !p.starts_with('0')) && p.parse::<u8>().is_ok())
}

/// Lo que una URL tiene que cumplir antes de pedir nada (G9, G10, G37).
fn check_url(name: &str, url: &str) -> Result<(), String> {
    let Some((scheme, authority, path)) = split_url(url) else {
        return Err(format!("get: {}: '{}' is not a URL (https://…)", name, url));
    };
    if authority.contains('@') {
        return Err(format!("get: {}: a URL with credentials is not supported", name));
    }
    match scheme.as_str() {
        "https" => {}
        "http" if is_loopback(authority) => {}
        "http" => return Err(format!("get: {}: http:// is only allowed to this machine (127.0.0.1, ::1, localhost); use https://", name)),
        _ => return Err(format!("get: {}: only https:// URLs are supported, not '{}'", name, url)),
    }
    // M3 (ronda 1): el cliente manda `\` tal cual y hay servidores que lo toman por `/` (IIS, los que
    // arman rutas de Windows): `x\..\..\evil` saldría de la carpeta del `id` (§11.2).
    if url.contains('\\') {
        return Err(format!("get: {}: the url has a backslash, which some servers take as a path separator: {}", name, url));
    }
    let p = path.split(['?', '#']).next().unwrap_or("");
    let lower = p.to_ascii_lowercase();
    if p.split('/').any(|s| s == "." || s == "..") || lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
        return Err(format!("get: {}: the url has a dot segment or an encoded separator: {}", name, url));
    }
    // Ronda 2 (M-r2-5): la ruta, sólo con caracteres que ningún servidor reinterpreta. Una lista de
    // formas prohibidas no cierra la clase (`..;` de Tomcat/Jetty, `%252e` decodificado dos veces,
    // `..%20`, los puntos de ancho completo): sin `%` ni `;` ni nada fuera de ASCII, lo que llega al
    // registro es lo que se comparó con el `id` (§11.2).
    if let Some(c) = p.chars().find(|c| !path_char_ok(*c)) {
        return Err(format!(
            "get: {}: the url path has '{}'; a package url uses only letters, digits, / and - . _ ~ ! $ & ' ( ) * + , = : @ (no %-escapes, no ;): {}",
            name, c, url
        ));
    }
    Ok(())
}

/// Ronda 2 (M-r2-5): los caracteres de una ruta de RFC 3986 (`pchar` y `/`) sin `%` (los escapes)
/// ni `;` (los parámetros de ruta que algunos servidores sacan antes de resolver `..`).
fn path_char_ok(c: char) -> bool {
    c.is_ascii_alphanumeric() || "/-._~!$&'()*+,=:@".contains(c)
}

/// RFC 3986 §5.2.4 sobre una ruta absoluta (`/…`): `.` se va y `..` saca el segmento anterior (B8).
fn remove_dot_segments(path: &str) -> String {
    let segs: Vec<&str> = path.split('/').collect();
    let last = segs.len().saturating_sub(1);
    let mut out: Vec<&str> = Vec::new();
    for (i, s) in segs.iter().enumerate().skip(1) {
        match *s {
            "." | ".." => {
                if *s == ".." {
                    out.pop();
                }
                if i == last {
                    out.push("");
                }
            }
            s => out.push(s),
        }
    }
    format!("/{}", out.join("/"))
}

/// Un `Location` contra la URL que lo devolvió (RFC 3986 §5.2: referencia de red, absoluta o
/// relativa, con los segmentos de punto resueltos).
fn resolve_ref(base: &str, loc: &str) -> String {
    // Ronda 2 (B-r2-4): hay esquema sólo si el `:` llega antes del primer `/`, `?` o `#` (RFC 3986
    // §3.1); `/x?next=https://…` es una ruta. Una referencia absoluta también resuelve sus `..`.
    let head = &loc[..loc.find(['/', '?', '#']).unwrap_or(loc.len())];
    let has_scheme = head.split_once(':').is_some_and(|(s, _)| {
        s.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && s.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    });
    if has_scheme {
        return match split_url(loc) {
            Some((s, a, p)) => {
                let cut = p.find(['?', '#']).unwrap_or(p.len());
                let (lpath, tail) = p.split_at(cut);
                let lpath = if lpath.is_empty() { "/" } else { lpath };
                format!("{}://{}{}{}", s, a, remove_dot_segments(lpath), tail)
            }
            None => loc.to_string(),
        };
    }
    let (scheme, authority, path) = split_url(base).unwrap_or_default();
    if loc.starts_with("//") {
        return resolve_ref(base, &format!("{}:{}", scheme, loc));
    }
    let cut = loc.find(['?', '#']).unwrap_or(loc.len());
    let (lpath, tail) = loc.split_at(cut);
    let merged = if lpath.starts_with('/') {
        lpath.to_string()
    } else if lpath.is_empty() {
        // Sólo consulta o fragmento: la misma ruta.
        path.split(['?', '#']).next().unwrap_or("").to_string()
    } else {
        let dir = path.split(['?', '#']).next().unwrap_or("");
        let dir = &dir[..dir.rfind('/').map_or(0, |i| i + 1)];
        let dir = if dir.is_empty() { "/" } else { dir };
        format!("{}{}", dir, lpath)
    };
    format!("{}://{}{}{}", scheme, authority, remove_dot_segments(&merged), tail)
}

/// La carpeta de una URL (para pedir los archivos relativos al índice, G25).
fn url_dir(url: &str) -> String {
    let base = url.split(['?', '#']).next().unwrap_or(url);
    match base.rfind('/') {
        Some(i) if i > base.find("://").map_or(0, |j| j + 2) => base[..=i].to_string(),
        _ => format!("{}/", base),
    }
}

/// Un pedido que falló: o es una regla de forma (no una descarga rota), o la descarga se rompió.
enum Fail {
    Shape(String),
    Down(String),
}

/// GET con las redirecciones de §7 y un tope de bytes. Devuelve la URL final y el cuerpo.
fn download(name: &str, url: &str, cap: u64, what: &str) -> Result<(String, Vec<u8>), Fail> {
    let mut cur = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let mut buf: Vec<u8> = Vec::new();
        let mut over = false;
        let r = synsema_stdlib::http::host::http_request_stream("GET", &cur, None, None, TIMEOUT_SECS, &mut |b: &[u8]| {
            if buf.len() as u64 + b.len() as u64 > cap {
                over = true;
                return false;
            }
            buf.extend_from_slice(b);
            true
        });
        let (status, headers) = r.map_err(Fail::Down)?;
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let Some(loc) = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("location")).map(|(_, v)| v.trim().to_string()) else {
                return Err(Fail::Down(format!("HTTP {} without a Location", status)));
            };
            let next = resolve_ref(&cur, &loc);
            let from_loop = split_url(&cur).is_some_and(|(_, a, _)| is_loopback(a));
            let (ns, na, _) = split_url(&next).unwrap_or_default();
            let ok = ns == "https" || (ns == "http" && from_loop && is_loopback(na));
            if !ok {
                return Err(Fail::Shape(format!("get: {}: {} redirects to {}; only https redirects are followed", name, cur, next)));
            }
            check_url(name, &next).map_err(Fail::Shape)?;
            cur = next;
            continue;
        }
        if over {
            return Err(Fail::Shape(format!("get: {}: {} is larger than {}", name, what, show_bytes(cap))));
        }
        if !(200..300).contains(&status) {
            return Err(Fail::Down(format!("HTTP {}", status)));
        }
        // B4 (ronda 1): el cliente devuelve `Ok` si la conexión se corta antes del `Content-Length`:
        // un cuerpo más corto que lo anunciado es una descarga rota, no un archivo.
        if let Some(n) = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse::<u64>().ok()) {
            if buf.len() as u64 != n {
                return Err(Fail::Down(format!("the response ended after {} of its {} bytes", buf.len(), n)));
            }
        }
        return Ok((cur, buf));
    }
    Err(Fail::Down(format!("more than {} redirects", MAX_REDIRECTS)))
}

fn show_bytes(n: u64) -> String {
    if n % (1024 * 1024) == 0 {
        format!("{} MiB", n / (1024 * 1024))
    } else {
        format!("{} bytes", n)
    }
}

fn broken(name: &str, url: &str, cause: &str) -> String {
    format!("get: could not download {} from {}: {}; nothing was installed", name, url, cause)
}

// ---------------------------------------------------------------------------------------------
// El índice y el árbol (§4.2, §4.3, §10.3)

/// Un árbol bajado y verificado contra su índice.
struct Tree {
    /// La URL final del índice (después de las redirecciones).
    url: String,
    index_bytes: Vec<u8>,
    index: Manifest,
    files: Vec<(String, Vec<u8>)>,
    hash: String,
}

fn strict_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit()))
}

fn version_key(v: &str) -> (u32, u32, u32) {
    project::parse_three(v).unwrap_or((0, 0, 0))
}

fn valid_id(id: &str) -> bool {
    let Some((scheme, authority, path)) = split_url(id) else { return false };
    (scheme == "https" || (scheme == "http" && is_loopback(authority)))
        && !authority.is_empty()
        && !authority.contains('@')
        && !path.contains(['?', '#'])
        && !id.ends_with('/')
}

/// El índice de un paquete: lo que §4.2 pide de su forma, antes de pedir ningún archivo.
fn parse_index(name: &str, bytes: &[u8]) -> Result<Manifest, String> {
    let version = serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| v.get("version").and_then(|x| x.as_str()).map(str::to_string))
        .unwrap_or_default();
    let idx = project::parse_manifest_of(bytes, "synsema.json", Some((name, &version))).map_err(|e| format!("get: {}: {}", name, e))?;
    let Some(id) = idx.id.as_deref() else {
        return Err(format!("get: {}: the package's synsema.json has no \"id\" (the URL prefix it is published under)", name));
    };
    if !valid_id(id) {
        return Err(format!("get: {}: \"id\" is a URL prefix like https://reg.example/name (https, no ?, # or / at the end), not '{}'", name, id));
    }
    match idx.version.as_deref() {
        Some(v) if strict_version(v) => {}
        Some(v) => return Err(format!("get: {}: \"version\" is three numbers like \"0.1.0\", not \"{}\"", name, v)),
        None => return Err(format!("get: {}: the package's synsema.json has no \"version\"", name)),
    }
    let Some(main) = idx.main.as_deref() else {
        return Err(format!("get: {}: the package's synsema.json has no \"main\"", name));
    };
    let Some(files) = idx.files.as_ref() else {
        return Err(format!("get: {}: the package's synsema.json has no \"files\"", name));
    };
    if files.len() > MAX_FILES {
        return Err(format!("get: {}: the file list ({} files) is larger than {} files", name, files.len(), MAX_FILES));
    }
    let invalid = |p: &str, rule: &str| format!("get: {}: invalid path in files: \"{}\" ({})", name, p, rule);
    for f in files {
        if f.path.len() > MAX_PATH_BYTES {
            return Err(format!("get: {}: the path \"{}\" is larger than {} bytes", name, f.path, MAX_PATH_BYTES));
        }
        if let Err(e) = modtable::check_pkg_path(&f.path) {
            let rule = if e.contains("Windows") {
                "a name Windows reserves"
            } else {
                "relative, '/' between segments of letters, digits, '.', '_' and '-'"
            };
            return Err(invalid(&f.path, rule));
        }
        if f.path.eq_ignore_ascii_case("synsema.json") {
            return Err(invalid(&f.path, "the index is not one of the files"));
        }
        if f.sha256.len() != 64 || !f.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(format!("get: {}: the sha256 of \"{}\" is not 64 lowercase hex digits", name, f.path));
        }
    }
    for (i, a) in files.iter().enumerate() {
        let la = a.path.to_ascii_lowercase();
        for b in &files[i + 1..] {
            let lb = b.path.to_ascii_lowercase();
            if la == lb {
                return Err(invalid(&b.path, &format!("it differs from \"{}\" only in case", a.path)));
            }
        }
        for b in files {
            let lb = b.path.to_ascii_lowercase();
            if lb.len() > la.len() && lb.starts_with(&la) && lb.as_bytes()[la.len()] == b'/' {
                return Err(invalid(&a.path, &format!("it is also a folder of \"{}\"", b.path)));
            }
        }
    }
    if !files.iter().any(|f| f.path == main) {
        return Err(invalid(main, "main is not in files"));
    }
    if !main.ends_with(".syn") {
        return Err(invalid(main, "main is not a .syn file"));
    }
    for (dep, e) in &idx.modules {
        if !e.hash.as_deref().is_some_and(is_tree_hash) {
            return Err(format!("get: {}: its dependency {} has no hash; a package pins its dependencies", name, dep));
        }
        if !e.id.as_deref().is_some_and(valid_id) || !e.version.as_deref().is_some_and(strict_version) {
            return Err(format!("get: {}: its dependency {} needs \"id\" and \"version\" (a package pins its dependencies)", name, dep));
        }
    }
    if !idx.indirect.is_empty() {
        return Err(format!("get: {}: a package's synsema.json has no \"indirect\" (only a project's does)", name));
    }
    Ok(idx)
}

fn index_tree_hash(idx: &Manifest, index_bytes: &[u8]) -> String {
    let index_sha = sha256_hex(index_bytes);
    let files = idx.files.as_deref().unwrap_or(&[]);
    tree_hash(files.iter().map(|f| (f.path.as_str(), f.sha256.as_str())).chain(std::iter::once(("synsema.json", index_sha.as_str()))))
}

/// Baja el índice de `url` (y, con `full`, cada archivo, verificado contra su sha256).
fn fetch(name: &str, url: &str, full: bool) -> Result<Tree, String> {
    let (final_url, index_bytes, _) = fetch_index(name, url)?;
    fetch_rest(name, url, final_url, index_bytes, full)
}

/// El índice de `url`, bajado. B4 (ronda 1): uno que no es JSON (truncado, o una página de error con
/// 200) es una descarga rota (§10.2, fila 1), no un índice inválido.
fn fetch_index(name: &str, url: &str) -> Result<(String, Vec<u8>, serde_json::Value), String> {
    check_url(name, url)?;
    let (final_url, index_bytes) = download(name, url, MAX_FILE_BYTES, "synsema.json").map_err(|f| match f {
        Fail::Shape(s) => s,
        Fail::Down(c) => broken(name, url, &c),
    })?;
    let raw: serde_json::Value = serde_json::from_slice(&index_bytes).map_err(|e| broken(name, url, &format!("synsema.json is not JSON ({})", e)))?;
    Ok((final_url, index_bytes, raw))
}

/// B5 (ronda 1): el hash del árbol que el índice declara (sus `files` y sus bytes), sin validarlo:
/// con un hash escrito se compara antes que las reglas de §10.3, así una republicación se ve como
/// republicación (§10.2, filas 2 y 3) aunque el índice nuevo además sea inválido. `None` si el
/// índice ni siquiera tiene esa forma (entonces no puede coincidir y lo dice la validación).
/// Ronda 2 (N-r2-5): siempre hay uno. Sin `files` es el árbol del índice solo (como
/// `index_tree_hash`); una entrada sin `path` o `sha256` de texto se saltea: el hash entra los bytes del
/// índice, que ya no son los de uno válido, así que no coincide con el fijado, y un índice republicado
/// sin `files` (o con `"sha256": 5`) da el error de republicación, no el de validación.
fn declared_hash(raw: &serde_json::Value, index_bytes: &[u8]) -> Option<String> {
    let files = raw.get("files").and_then(|f| f.as_array()).map(Vec::as_slice).unwrap_or(&[]);
    let pairs: Vec<(&str, &str)> = files.iter().filter_map(|f| Some((f.get("path")?.as_str()?, f.get("sha256")?.as_str()?))).collect();
    let index_sha = sha256_hex(index_bytes);
    Some(tree_hash(pairs.into_iter().chain(std::iter::once(("synsema.json", index_sha.as_str())))))
}

/// El resto de `fetch`: la validación del índice (§10.3) y, con `full`, los archivos.
fn fetch_rest(name: &str, url: &str, final_url: String, index_bytes: Vec<u8>, full: bool) -> Result<Tree, String> {
    let index = parse_index(name, &index_bytes)?;
    let hash = index_tree_hash(&index, &index_bytes);
    let mut files = Vec::new();
    if full {
        let dir = url_dir(&final_url);
        let mut total = index_bytes.len() as u64;
        for f in index.files.as_deref().unwrap_or(&[]) {
            let furl = format!("{}{}", dir, f.path);
            let (_, bytes) = download(name, &furl, MAX_FILE_BYTES, &f.path).map_err(|e| match e {
                Fail::Shape(s) => s,
                Fail::Down(c) => broken(name, url, &format!("{}: {}", f.path, c)),
            })?;
            total += bytes.len() as u64;
            if total > MAX_PACKAGE_BYTES {
                return Err(format!("get: {}: the package is larger than {}", name, show_bytes(MAX_PACKAGE_BYTES)));
            }
            if sha256_hex(&bytes) != f.sha256 {
                return Err(broken(name, url, &format!("{} does not match its sha256 in the index", f.path)));
            }
            files.push((f.path.clone(), bytes));
        }
    }
    Ok(Tree { url: final_url, index_bytes, index, files, hash })
}

/// Lo que se lee de los `.syn` de un paquete: lo que pide (§6.2) y lo que pide cada task.
#[derive(Clone, Debug, Default)]
struct Reqs {
    all: Vec<String>,
    tasks: Vec<(String, Vec<String>)>,
}

fn show_require((cap, scope): &(String, Option<String>)) -> String {
    match scope {
        None => cap.clone(),
        Some(s) => format!("{}({})", cap, serde_json::Value::String(s.clone())),
    }
}

/// Valida los archivos de un paquete (§10.3, pasos 3 a 5) y lee lo que pide. `files` son los bytes
/// verificados (de una descarga o del caché).
fn validate(name: &str, main: &str, files: &[(String, Arc<[u8]>)]) -> Result<Reqs, String> {
    use synsema_core::ast::NodeKind as K;
    let have: HashMap<&str, &[u8]> = files.iter().map(|(p, b)| (p.as_str(), &b[..])).collect();
    let norm = |p: &str| p.trim_start_matches("./").to_string();
    let mut programs: HashMap<String, synsema_core::ast::Program> = HashMap::new();
    let mut reached: Vec<String> = Vec::new();
    for (path, bytes) in files {
        if !path.ends_with(".syn") {
            continue;
        }
        let Ok(src) = std::str::from_utf8(bytes) else {
            return Err(format!("get: {}: {} is not UTF-8", name, path));
        };
        let program = synsema_core::parser::parse_source(src, path).map_err(|e| {
            let msg = e.to_string();
            if msg.contains(synsema_core::parser::NEST_ERROR) {
                format!("get: {}: {} nests deeper than {}", name, path, synsema_core::parser::MAX_NEST)
            } else {
                format!("get: {}: {}: {}", name, path, msg)
            }
        })?;
        modtable::check_package_syn_get(&program, src, name, path)?;
        programs.insert(path.clone(), program);
    }
    // Paso 4, después del 3 en TODOS los `.syn` (B6, ronda 1): cada `render` literal está en `files`.
    // En el orden de `files`, así el error es el mismo en cada corrida.
    for (path, _) in files {
        let Some(program) = programs.get(path) else { continue };
        for (lit, _line) in synsema_core::templates::render_literals(program) {
            let t = norm(&lit);
            if !have.contains_key(t.as_str()) {
                return Err(format!("get: {}: render(\"{}\") in {} is not in files", name, lit, path));
            }
            if !reached.contains(&t) {
                reached.push(t);
            }
        }
    }
    // Las plantillas alcanzadas, y lo que ellas incluyen (paso 4).
    let mut i = 0;
    while i < reached.len() {
        let t = reached[i].clone();
        i += 1;
        let Ok(src) = std::str::from_utf8(have[t.as_str()]) else {
            return Err(format!("get: {}: {} is not UTF-8", name, t));
        };
        let refs = synsema_core::templates::template_refs(src, &t).map_err(|e| {
            if e.contains(synsema_core::parser::NEST_ERROR) {
                format!("get: {}: {} nests deeper than {}", name, t, synsema_core::parser::MAX_NEST)
            } else {
                format!("get: {}: {}: {}", name, t, e)
            }
        })?;
        for r in refs {
            let n = norm(&r);
            if !have.contains_key(n.as_str()) {
                return Err(format!("get: {}: the template \"{}\" (from {}) is not in files", name, r, t));
            }
            if !reached.contains(&n) {
                reached.push(n);
            }
        }
    }
    // Paso 5: cada archivo es un `.syn` o una plantilla alcanzada.
    for (path, _) in files {
        if !path.ends_with(".syn") && !reached.contains(path) {
            return Err(format!(
                "get: {}: {} is neither a .syn file nor a template the package renders; data goes in a .syn literal",
                name, path
            ));
        }
    }
    // Lo que pide (§6.2): los `require` de los `.syn` que `main` alcanza, como el dominio al correr.
    let mut seen: Vec<String> = Vec::new();
    let mut todo = vec![main.to_string()];
    let mut pairs: Vec<(String, Option<String>)> = Vec::new();
    let mut tasks: Vec<(String, Vec<String>)> = Vec::new();
    while let Some(p) = todo.pop() {
        if seen.contains(&p) {
            continue;
        }
        seen.push(p.clone());
        let Some(program) = programs.get(&p) else { continue };
        for pair in modtable::require_pairs(program) {
            if !pairs.contains(&pair) {
                pairs.push(pair);
            }
        }
        for stmt in &program.statements {
            synsema_core::ast_api::walk(stmt, &mut |n| {
                if let K::TaskDefinition { name: tn, .. } = &n.kind {
                    let sub = std::slice::from_ref(n);
                    let mut rs: Vec<String> = modtable::require_pairs_in(sub).iter().map(show_require).collect();
                    rs.sort();
                    rs.dedup();
                    if !rs.is_empty() {
                        tasks.push((tn.to_string(), rs));
                    }
                }
            });
        }
        for raw in synsema_core::loaded_modules::use_paths(program) {
            if matches!(modtable::classify(&raw), Ok(modtable::UseKind::File)) {
                if let Ok(t) = modtable::pkg_relative(&p, &raw) {
                    todo.push(t);
                }
            }
        }
    }
    let mut all: Vec<String> = pairs.iter().map(show_require).collect();
    all.sort();
    all.dedup();
    Ok(Reqs { all, tasks })
}

// ---------------------------------------------------------------------------------------------
// El caché (§5.1)

fn index_cache_path(cache: &Path, hash: &str) -> PathBuf {
    cache.join("index").join(format!("{}.json", hash.replacen(':', "-", 1)))
}

fn temp_name(dir: &Path, tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    dir.join(format!(".tmp-{}-{}-{}", tag, std::process::id(), nanos))
}

/// `rename` con los reintentos de Windows (D-29): un antivirus o el indexador tienen el archivo
/// abierto un momento.
fn rename_retry(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut wait = 5u64;
    let mut last = None;
    for attempt in 0..8 {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) => {
                let retry = cfg!(windows) && matches!(e.raw_os_error(), Some(5) | Some(32));
                if !retry || attempt == 7 {
                    return Err(e);
                }
                last = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(wait));
                wait = (wait * 2).min(500);
            }
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("rename")))
}

fn make_writable_and_remove(dir: &Path) {
    fn walk(p: &Path) {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let path = e.path();
                if path.is_dir() {
                    walk(&path);
                } else if let Ok(md) = std::fs::metadata(&path) {
                    let mut perm = md.permissions();
                    #[allow(clippy::permissions_set_readonly_false)]
                    perm.set_readonly(false);
                    let _ = std::fs::set_permissions(&path, perm);
                }
            }
        }
    }
    walk(dir);
    let _ = std::fs::remove_dir_all(dir);
}

/// Guarda el índice de una versión alcanzada (§11.3, paso 1), también de una que pierde.
fn save_index(cache: &Path, hash: &str, bytes: &[u8]) -> Result<(), String> {
    let path = index_cache_path(cache, hash);
    // B9 (ronda 1): uno dañado (otros bytes que los que fijan el hash) se reescribe; antes quedaba
    // y cada `get` volvía a la red sin decirlo.
    if path.is_file() && std::fs::read(&path).is_ok_and(|b| b == bytes) {
        return Ok(());
    }
    let dir = path.parent().expect("index/");
    std::fs::create_dir_all(dir).map_err(|e| format!("get: {}: {}", dir.display(), e))?;
    let tmp = temp_name(dir, "index");
    let written = std::fs::write(&tmp, bytes).and_then(|()| rename_retry(&tmp, &path));
    let Err(e) = written else { return Ok(()) };
    let _ = std::fs::remove_file(&tmp);
    // Ronda 2 (B-r2-5): si no se pudo reemplazar (sólo lectura, sin permiso; en Unix la carpeta sin
    // escritura falla ya al crear el temporal) y lo que quedó no es lo bueno, es un error que nombra
    // el archivo; antes se avisaba «fetching it again», rc 0, y el índice seguía dañado. Otro `get`
    // que ya escribió los mismos bytes no es error.
    if std::fs::read(&path).is_ok_and(|b| b == bytes) {
        return Ok(());
    }
    if path.is_file() {
        return Err(format!(
            "get: the cached index {} does not match its hash and cannot be replaced ({}); delete it and run synsema get again",
            path.display(),
            e
        ));
    }
    Err(format!("get: {}: {}", path.display(), e))
}

/// Instala un árbol: a una carpeta temporal, verificado, archivos de sólo lectura y renombrado. Si
/// otro `get` ganó la carrera, se verifica la que ya está (G16).
fn install(cache: &Path, name: &str, tree: &Tree) -> Result<(), String> {
    let dest = package_dir(cache, &tree.hash);
    let version = tree.index.version.clone().unwrap_or_default();
    if dest.join("synsema.json").is_file() {
        return modtable::load_package(&dest, &tree.hash, name, &version, name, 1).map(|_| ()).map_err(|e| format!("get: {}", e));
    }
    std::fs::create_dir_all(cache).map_err(|e| format!("get: {}: {}", cache.display(), e))?;
    let tmp = temp_name(cache, "pkg");
    let write = || -> std::io::Result<()> {
        std::fs::create_dir_all(&tmp)?;
        std::fs::write(tmp.join("synsema.json"), &tree.index_bytes)?;
        for (p, b) in &tree.files {
            let target = tmp.join(p);
            if let Some(d) = target.parent() {
                std::fs::create_dir_all(d)?;
            }
            std::fs::write(&target, b)?;
        }
        Ok(())
    };
    if let Err(e) = write() {
        make_writable_and_remove(&tmp);
        return Err(format!("get: could not write the module cache in {}: {}", cache.display(), e));
    }
    if let Err(e) = modtable::load_package(&tmp, &tree.hash, name, &version, name, 1) {
        make_writable_and_remove(&tmp);
        return Err(format!("get: {}", e));
    }
    // Los archivos de sólo lectura, las carpetas no (D-26): así se borra con `rm -rf`.
    for (p, _) in &tree.files {
        set_readonly(&tmp.join(p));
    }
    set_readonly(&tmp.join("synsema.json"));
    match rename_retry(&tmp, &dest) {
        Ok(()) => Ok(()),
        Err(_) if dest.join("synsema.json").is_file() => {
            make_writable_and_remove(&tmp);
            modtable::load_package(&dest, &tree.hash, name, &version, name, 1).map(|_| ()).map_err(|e| format!("get: {}", e))
        }
        Err(e) => {
            make_writable_and_remove(&tmp);
            Err(format!("get: could not move {} into the module cache: {}", name, e))
        }
    }
}

fn set_readonly(p: &Path) {
    if let Ok(md) = std::fs::metadata(p) {
        let mut perm = md.permissions();
        perm.set_readonly(true);
        let _ = std::fs::set_permissions(p, perm);
    }
}

// ---------------------------------------------------------------------------------------------
// El grafo y la selección (§11.3)

/// Una versión alcanzada, por su hash.
struct Node {
    id: String,
    version: String,
    /// La URL por la que se llegó (la primera).
    url: String,
    deps: Vec<(String, ModEntry)>,
    /// El árbol, si se bajó entero o está en el caché; `None` si sólo se tiene el índice.
    files: Option<Vec<(String, Arc<[u8]>)>>,
    /// El árbol bajado que falta instalar.
    fresh: Option<Tree>,
    main: String,
    reqs: Option<Reqs>,
}

/// Una arista: quién pide (`None` es el proyecto) qué versión de qué `id`.
#[derive(Clone)]
struct Edge {
    from: Option<String>,
    id: String,
    version: String,
    url: String,
    hash: String,
}

struct Graph<'a> {
    cache: &'a Path,
    offline: bool,
    nodes: HashMap<String, Node>,
    edges: Vec<Edge>,
    /// El nombre directo por el que se llegó primero a cada hash (para «pedido por»).
    root: HashMap<String, String>,
}

impl Graph<'_> {
    /// Una versión por su hash, del caché (el árbol o el índice guardado) o de la red. Verifica que
    /// el índice sea el de la arista (G43) y su hash.
    fn obtain(&mut self, shown: &str, from: &str, e: &Edge, need_files: bool) -> Result<(), String> {
        if let Some(n) = self.nodes.get(&e.hash) {
            if !need_files || n.files.is_some() {
                return Ok(());
            }
        }
        let dir = package_dir(self.cache, &e.hash);
        if dir.join("synsema.json").is_file() {
            let pkg = modtable::load_package(&dir, &e.hash, shown, &e.version, shown, 1).map_err(|x| self.prefix(x))?;
            let files: Vec<(String, Arc<[u8]>)> = pkg.files.iter().map(|(p, b)| (p.clone(), b.clone())).collect();
            self.check_edge(from, e, &pkg.id, &pkg.version, &pkg.index.modules)?;
            let main = pkg.index.main.clone().unwrap_or_default();
            self.put(e, pkg.id.clone(), pkg.version.clone(), pkg.index.modules.clone(), Some(files), None, main, pkg.index_bytes.to_vec());
            return Ok(());
        }
        if !need_files {
            let ip = index_cache_path(self.cache, &e.hash);
            if let Ok(bytes) = std::fs::read(&ip) {
                if let Ok(idx) = parse_index(shown, &bytes) {
                    if index_tree_hash(&idx, &bytes) == e.hash {
                        let (id, ver) = (idx.id.clone().unwrap_or_default(), idx.version.clone().unwrap_or_default());
                        self.check_edge(from, e, &id, &ver, &idx.modules)?;
                        let main = idx.main.clone().unwrap_or_default();
                        self.put(e, id, ver, idx.modules.clone(), None, None, main, bytes);
                        return Ok(());
                    }
                }
                // B9 (ronda 1): está, pero no es el del hash. `--check` lo dice (y cómo se arregla);
                // `get` avisa que va a la red y lo reescribe (`save_index`).
                if self.offline {
                    return Err(format!(
                        "get --check: the cached index of {} {} ({}) is damaged: {}; run synsema get to fetch it again",
                        shown,
                        e.version,
                        short_hash(&e.hash),
                        ip.display()
                    ));
                }
                eprintln!("get: the cached index of {} {} ({}) is damaged; fetching it again", shown, e.version, short_hash(&e.hash));
            }
        }
        if self.offline {
            return Err(if need_files {
                format!("get --check: {} {} is not in the cache: run synsema get", shown, e.version)
            } else {
                format!("get --check: the index of {} {} ({}) is not in the cache: run synsema get", shown, e.version, short_hash(&e.hash))
            });
        }
        // B5 (ronda 1): lo que el índice dice ser (G43) y su hash, antes de validarlo.
        let (final_url, index_bytes, raw) = fetch_index(shown, &e.url)?;
        let raw_str = |k: &str| raw.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
        self.check_edge(from, e, &raw_str("id"), &raw_str("version"), &[])?;
        let declared = declared_hash(&raw, &index_bytes);
        let tree = match declared.as_deref() {
            Some(h) if h != e.hash => None,
            _ => Some(fetch_rest(shown, &e.url, final_url, index_bytes, need_files)?),
        };
        let got_hash = tree.as_ref().map(|t| t.hash.clone()).or(declared).unwrap_or_default();
        if got_hash != e.hash {
            return Err(format!(
                "get: {} pins {} {} as {}, but {} serves {}; nothing was installed",
                from,
                e.id,
                e.version,
                short_hash(&e.hash),
                e.url,
                short_hash(&got_hash)
            ));
        }
        let tree = tree.expect("con el hash que coincide, el árbol se bajó");
        let (id, ver) = (tree.index.id.clone().unwrap_or_default(), tree.index.version.clone().unwrap_or_default());
        save_index(self.cache, &tree.hash, &tree.index_bytes)?;
        let main = tree.index.main.clone().unwrap_or_default();
        let mods = tree.index.modules.clone();
        let ib = tree.index_bytes.clone();
        if need_files {
            let files: Vec<(String, Arc<[u8]>)> = tree.files.iter().map(|(p, b)| (p.clone(), Arc::from(b.clone().into_boxed_slice()))).collect();
            self.put(e, id, ver, mods, Some(files), Some(tree), main, ib);
        } else {
            self.put(e, id, ver, mods, None, None, main, ib);
        }
        Ok(())
    }

    fn prefix(&self, e: String) -> String {
        if self.offline {
            format!("get --check: {}", e)
        } else {
            format!("get: {}", e)
        }
    }

    /// G43: el índice que llegó tiene que ser el que nombra la arista.
    fn check_edge(&self, from: &str, e: &Edge, id: &str, ver: &str, _mods: &[(String, ModEntry)]) -> Result<(), String> {
        if e.from.is_some() && (normalize_id(id) != e.id || ver != e.version) {
            return Err(format!("get: {} says {} {}, but {} serves {}; nothing was installed", from, e.id, e.version, e.url, ver));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn put(
        &mut self,
        e: &Edge,
        id: String,
        version: String,
        deps: Vec<(String, ModEntry)>,
        files: Option<Vec<(String, Arc<[u8]>)>>,
        fresh: Option<Tree>,
        main: String,
        _index_bytes: Vec<u8>,
    ) {
        let reqs = self.nodes.get(&e.hash).and_then(|n| n.reqs.clone());
        let url = self.nodes.get(&e.hash).map(|n| n.url.clone()).unwrap_or_else(|| e.url.clone());
        self.nodes.insert(e.hash.clone(), Node { id: normalize_id(&id), version, url, deps, files, fresh, main, reqs });
    }

    /// Recorre las dependencias de `hash` (DFS con la pila de `id` para los ciclos, G30).
    fn walk(&mut self, hash: &str, path: &mut Vec<String>, depth: usize) -> Result<(), String> {
        if depth > MAX_DEP_DEPTH {
            return Err(format!("get: the dependency depth is larger than {} levels", MAX_DEP_DEPTH));
        }
        let (deps, from_name) = {
            let n = &self.nodes[hash];
            (n.deps.clone(), self.display_of(hash))
        };
        for (_, d) in deps {
            let id = normalize_id(d.id.as_deref().unwrap_or_default());
            if let Some(i) = path.iter().position(|p| *p == id) {
                let mut cyc: Vec<String> = path[i..].to_vec();
                cyc.push(id);
                return Err(format!("get: dependency cycle: {}", cyc.join(" → ")));
            }
            let e = Edge {
                from: Some(hash.to_string()),
                id: id.clone(),
                version: d.version.clone().unwrap_or_default(),
                url: d.url.clone(),
                hash: d.hash.clone().unwrap_or_default(),
            };
            self.edges.push(e.clone());
            let known = self.nodes.contains_key(&e.hash);
            if !known {
                if self.nodes.len() >= MAX_PACKAGES {
                    return Err(format!("get: the dependency graph is larger than {} packages", MAX_PACKAGES));
                }
                check_url(&id, &e.url)?;
                self.obtain(&id, &from_name, &e, false)?;
                let r = self.root.get(hash).cloned().unwrap_or_default();
                self.root.entry(e.hash.clone()).or_insert(r);
            }
            path.push(id);
            if !known {
                self.walk(&e.hash, path, depth + 1)?;
            }
            path.pop();
        }
        Ok(())
    }

    fn display_of(&self, hash: &str) -> String {
        self.root.get(hash).cloned().unwrap_or_else(|| self.nodes.get(hash).map(|n| n.id.clone()).unwrap_or_default())
    }
}

/// Lo elegido para cada `id`.
#[derive(Clone)]
struct Chosen {
    version: String,
    hash: String,
    url: String,
}

/// §11.3, paso 2: por cada `id`, la versión más alta pedida; G29 y G42.
fn select(g: &Graph) -> Result<HashMap<String, Chosen>, String> {
    let mut by_id: HashMap<&str, Vec<&Edge>> = HashMap::new();
    for e in &g.edges {
        by_id.entry(e.id.as_str()).or_default().push(e);
    }
    let mut out = HashMap::new();
    for (id, es) in by_id {
        let max = es.iter().map(|e| version_key(&e.version)).max().expect("una arista");
        let top: Vec<&&Edge> = es.iter().filter(|e| version_key(&e.version) == max).collect();
        let first = top[0];
        if let Some(other) = top.iter().find(|e| e.hash != first.hash) {
            let who = |e: &Edge| e.from.as_deref().map(|h| g.display_of(h)).unwrap_or_else(|| "synsema.json".to_string());
            return Err(format!(
                "get: {} {} has two different hashes: {} (from {}) and {} (from {}); nothing was installed",
                id,
                first.version,
                short_hash(&first.hash),
                who(first),
                short_hash(&other.hash),
                who(other)
            ));
        }
        let url = top.iter().map(|e| e.url.as_str()).min_by(|a, b| a.as_bytes().cmp(b.as_bytes())).unwrap_or(&first.url).to_string();
        out.insert(id.to_string(), Chosen { version: first.version.clone(), hash: first.hash.clone(), url });
    }
    Ok(out)
}

/// G30 sobre lo elegido (M4, ronda 1): `walk` ve los ciclos de cada versión pedida, pero con dos
/// versiones por `id` el ciclo puede cerrarse sólo entre las que `select` eligió (`ca 0.2.0` pide
/// `cb`, `cb 0.2.0` pide `ca`). Se recorre el grafo de `id` por las versiones elegidas desde los
/// directos, con la pila del camino; cada `id` se termina una vez.
fn chosen_cycle(g: &Graph, chosen: &HashMap<String, Chosen>, directs: &[String]) -> Result<(), String> {
    fn deps_of(g: &Graph, chosen: &HashMap<String, Chosen>, id: &str) -> Vec<String> {
        chosen.get(id).and_then(|c| g.nodes.get(&c.hash)).map(|n| n.deps.iter().map(|(_, d)| normalize_id(d.id.as_deref().unwrap_or_default())).collect()).unwrap_or_default()
    }
    let mut done: HashSet<String> = HashSet::new();
    for root in directs {
        if done.contains(root) {
            continue;
        }
        // Pila explícita: (id, sus dependencias, la próxima a mirar).
        let mut path: Vec<String> = vec![root.clone()];
        let mut stack: Vec<(Vec<String>, usize)> = vec![(deps_of(g, chosen, root), 0)];
        while let Some((deps, i)) = stack.last_mut() {
            if *i == deps.len() {
                stack.pop();
                done.insert(path.pop().expect("el camino va con la pila"));
                continue;
            }
            let d = deps[*i].clone();
            *i += 1;
            if let Some(k) = path.iter().position(|p| *p == d) {
                let mut cyc: Vec<String> = path[k..].to_vec();
                cyc.push(d);
                return Err(format!("get: dependency cycle: {}", cyc.join(" → ")));
            }
            if done.contains(&d) {
                continue;
            }
            let next = deps_of(g, chosen, &d);
            path.push(d);
            stack.push((next, 0));
        }
    }
    Ok(())
}

/// §11.3, paso 3: los `id` que se alcanzan desde el proyecto por las versiones elegidas.
fn reachable(g: &Graph, chosen: &HashMap<String, Chosen>, directs: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut todo: Vec<String> = directs.to_vec();
    while let Some(id) = todo.pop() {
        if out.contains(&id) {
            continue;
        }
        out.push(id.clone());
        let Some(c) = chosen.get(&id) else { continue };
        if let Some(n) = g.nodes.get(&c.hash) {
            for (_, d) in &n.deps {
                todo.push(normalize_id(d.id.as_deref().unwrap_or_default()));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// `get`

/// Lo que ya estaba escrito para un `id`.
#[derive(Clone)]
struct Old {
    version: String,
    hash: String,
    requires: Vec<String>,
}

/// Un caso de la regla de `--accept` (§10.1).
struct Case {
    text: String,
    /// La clave y el hash que se imprimen.
    shown: (String, String),
    /// Lo que lo acepta: `(clave, hash)`.
    accepts: Vec<(String, String)>,
}

fn show_list(xs: &[String]) -> String {
    if xs.is_empty() {
        "nothing".to_string()
    } else {
        xs.join(", ")
    }
}

fn get(opts: &Opts, manifest: &Manifest, raw: &[u8], json_path: &Path, cache: &Path) -> Result<(), String> {
    if let Some(u) = &opts.update {
        if manifest.module(u).is_none() {
            return Err(format!("get: --update {}: synsema.json has no module \"{}\"", u, u));
        }
    }
    let first_time = manifest.modules.iter().all(|(_, e)| e.hash.is_none());
    let mut g = Graph { cache, offline: false, nodes: HashMap::new(), edges: Vec::new(), root: HashMap::new() };
    // Los directos: lo que el comando nombra (sin hash, o `--update`) se baja de su `url`; lo demás
    // sale del caché o se baja y se compara con lo escrito (§10.2).
    let mut named: Vec<String> = Vec::new();
    let mut direct_hash: Vec<(String, String)> = Vec::new();
    let mut direct_ids: Vec<String> = Vec::new();
    for (name, entry) in &manifest.modules {
        let is_update = opts.update.as_deref() == Some(name.as_str());
        let pinned = entry.hash.clone().filter(|h| !h.is_empty());
        let tree_hash_now = if pinned.is_none() || is_update {
            named.push(name.clone());
            let tree = fetch(name, &entry.url, true)?;
            let e = Edge { from: None, id: String::new(), version: String::new(), url: entry.url.clone(), hash: tree.hash.clone() };
            let id = tree.index.id.clone().unwrap_or_default();
            let ver = tree.index.version.clone().unwrap_or_default();
            let mods = tree.index.modules.clone();
            let main = tree.index.main.clone().unwrap_or_default();
            let ib = tree.index_bytes.clone();
            let files: Vec<(String, Arc<[u8]>)> = tree.files.iter().map(|(p, b)| (p.clone(), Arc::from(b.clone().into_boxed_slice()))).collect();
            // §10.3 en orden (B6, ronda 1): los pasos 3 a 5 antes que el 6 (el `id` contra la `url`).
            let reqs = validate(name, &main, &files)?;
            id_under_url(name, &tree)?;
            save_index(cache, &tree.hash, &tree.index_bytes)?;
            let h = tree.hash.clone();
            g.put(&e, id, ver, mods, Some(files), Some(tree), main, ib);
            g.nodes.get_mut(&h).expect("recién puesto").reqs = Some(reqs);
            h
        } else {
            let hash = pinned.expect("con hash");
            if !is_tree_hash(&hash) {
                return Err(format!("get: {}: the hash in synsema.json is not tree-sha256:<64 hex>; remove it and run synsema get", name));
            }
            obtain_pinned(&mut g, name, entry, &hash)?;
            hash
        };
        let id = g.nodes[&tree_hash_now].id.clone();
        if let Some(i) = direct_ids.iter().position(|x| *x == id) {
            return Err(format!("get: {} and {} are the same package ({}); keep one", manifest.modules[i].0, name, id));
        }
        direct_ids.push(id.clone());
        direct_hash.push((name.clone(), tree_hash_now.clone()));
        g.root.insert(tree_hash_now.clone(), name.clone());
        let n = &g.nodes[&tree_hash_now];
        g.edges.push(Edge { from: None, id, version: n.version.clone(), url: entry.url.clone(), hash: tree_hash_now.clone() });
    }
    for (_, h) in direct_hash.clone() {
        let id = g.nodes[&h].id.clone();
        g.walk(&h, &mut vec![id], 1)?;
    }
    let chosen = select(&g)?;
    chosen_cycle(&g, &chosen, &direct_ids)?;
    let reach = reachable(&g, &chosen, &direct_ids);
    // Lo elegido y alcanzado se baja entero si sólo se tenía el índice, y se valida.
    for id in &reach {
        let c = chosen[id].clone();
        let shown = direct_name(manifest, &g, id).unwrap_or_else(|| id.clone());
        let e = Edge { from: Some(String::new()), id: id.clone(), version: c.version.clone(), url: c.url.clone(), hash: c.hash.clone() };
        if g.nodes[&c.hash].files.is_none() {
            let from = g.display_of(&c.hash);
            g.obtain(&shown, &from, &e, true)?;
        }
        let n = g.nodes.get(&c.hash).expect("elegido");
        if n.reqs.is_none() {
            let reqs = validate(&shown, &n.main, n.files.as_deref().unwrap_or(&[]))?;
            g.nodes.get_mut(&c.hash).expect("elegido").reqs = Some(reqs);
        }
    }
    // Paso 6 de §10.3 para los transitivos bajados: el `id` contra la URL final.
    // Un directo ya se revisó al bajarlo, o tenía hash escrito: un espejo sirve (G18).
    for id in &reach {
        let c = &chosen[id];
        if direct_hash.iter().any(|(_, h)| *h == c.hash) {
            continue;
        }
        if let Some(t) = g.nodes[&c.hash].fresh.as_ref() {
            let shown = direct_name(manifest, &g, id).unwrap_or_else(|| id.clone());
            id_under_url(&shown, t)?;
        }
    }
    // La regla de `--accept` (§10.1).
    let old = old_state(manifest);
    let cases = accept_cases(manifest, &g, &chosen, &reach, &old, &named, opts.update.as_deref());
    let known = known_keys(manifest, &g, &chosen, &reach);
    let mut stale: Vec<String> = Vec::new();
    for (k, h) in &opts.accept {
        match known.iter().find(|(kk, _, _)| kk == k || normalize_id(kk) == normalize_id(k)) {
            None => return Err(format!("get: --accept {}: there is no {} in what get resolved", k, k)),
            Some((_, cur, label)) if cur != h => {
                stale.push(format!("get: {} is now {}, not the one shown ({}); nothing was changed", label, short_hash(cur), short_hash(h)))
            }
            Some(_) => {}
        }
    }
    let pending: Vec<&Case> = cases
        .iter()
        .filter(|c| !c.accepts.iter().any(|(k, h)| opts.accept.iter().any(|(ak, ah)| ah == h && (ak == k || normalize_id(ak) == normalize_id(k)))))
        .collect();
    if !stale.is_empty() || !pending.is_empty() {
        let nothing = if first_time { "nothing was installed" } else { "nothing was changed" };
        let mut lines = stale;
        let cmd_prefix = match &opts.update {
            Some(u) => format!("synsema get --update {}", u),
            None => "synsema get".to_string(),
        };
        // B7 (ronda 1): cada línea imprime el comando entero: los `--accept` de esta corrida que
        // siguen valiendo y los de TODOS los casos pendientes. Seguir cualquiera de las líneas
        // avanza; antes cada una llevaba sólo el suyo y, con dos casos, se iba y se volvía.
        let mut accepts: Vec<String> = opts
            .accept
            .iter()
            .filter(|(k, h)| known.iter().any(|(kk, cur, _)| cur == h && (kk == k || normalize_id(kk) == normalize_id(k))))
            .map(|(k, h)| format!("--accept {}@{}", k, h))
            .collect();
        for c in &pending {
            let a = format!("--accept {}@{}", c.shown.0, c.shown.1);
            if !accepts.contains(&a) {
                accepts.push(a);
            }
        }
        let command = format!("{} {}", cmd_prefix, accepts.join(" "));
        for c in &pending {
            lines.push(format!("get: {}; {}. To accept: {}", c.text, nothing, command));
        }
        return Err(lines.join("\n"));
    }
    // Instalar lo alcanzado y escribir.
    for id in &reach {
        let c = &chosen[id];
        let shown = direct_name(manifest, &g, id).unwrap_or_else(|| id.clone());
        let n = g.nodes.get_mut(&c.hash).expect("elegido");
        if let Some(t) = n.fresh.take() {
            install(cache, &shown, &t)?;
        }
    }
    let new_text = write_manifest(raw, manifest, &g, &chosen, &reach)?;
    let tmp = json_path.with_file_name(format!(".synsema.json.tmp-{}", std::process::id()));
    std::fs::write(&tmp, new_text.as_bytes()).map_err(|e| format!("get: {}: {}", tmp.display(), e))?;
    rename_retry(&tmp, json_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("get: could not write {}: {}", json_path.display(), e)
    })?;
    report(manifest, &g, &chosen, &reach, &old_for_report(manifest, &g, &old), opts.update.as_deref());
    Ok(())
}

/// Un directo con hash: del caché, o bajado de su `url` y comparado con lo escrito (§10.2).
fn obtain_pinned(g: &mut Graph, name: &str, entry: &ModEntry, hash: &str) -> Result<(), String> {
    let dir = package_dir(g.cache, hash);
    let ver = entry.version.clone().unwrap_or_default();
    let e = Edge { from: None, id: String::new(), version: ver.clone(), url: entry.url.clone(), hash: hash.to_string() };
    if dir.join("synsema.json").is_file() {
        return g.obtain(name, "synsema.json", &e, true);
    }
    // B5 (ronda 1): primero el hash que declara el índice, después la validación.
    let (final_url, index_bytes, raw) = fetch_index(name, &entry.url)?;
    let got_ver = raw.get("version").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let declared = declared_hash(&raw, &index_bytes);
    let tree = match declared.as_deref() {
        Some(h) if h != hash => None,
        _ => Some(fetch_rest(name, &entry.url, final_url, index_bytes, true)?),
    };
    let got_hash = tree.as_ref().map(|t| t.hash.clone()).or(declared).unwrap_or_default();
    if got_hash != hash {
        let tree_hash_shown = got_hash.clone();
        return Err(match entry.version.as_deref() {
            Some(v) if v == got_ver => format!(
                "get: the registry changed the content of {} {} without changing its version (expected {}, got {}): it may be tampering or a republication; nothing was installed. If you trust the change, remove the hash of {} in synsema.json and run synsema get again",
                name,
                v,
                short_hash(hash),
                short_hash(&tree_hash_shown),
                name
            ),
            Some(v) => format!(
                "get: {} now serves {} {}, but synsema.json pins {} {} ({}); nothing was installed. To move to {}: synsema get --update {}",
                entry.url,
                name,
                got_ver,
                name,
                v,
                short_hash(hash),
                got_ver,
                name
            ),
            None => format!(
                "get: {}: {} serves {}, but synsema.json pins {}; nothing was installed",
                name,
                entry.url,
                short_hash(&tree_hash_shown),
                short_hash(hash)
            ),
        });
    }
    let tree = tree.expect("con el hash que coincide, el árbol se bajó");
    // El hash coincide: el contenido es el que se escribió (un espejo sirve, G18).
    save_index(g.cache, &tree.hash, &tree.index_bytes)?;
    let id = tree.index.id.clone().unwrap_or_default();
    let mods = tree.index.modules.clone();
    let main = tree.index.main.clone().unwrap_or_default();
    let ib = tree.index_bytes.clone();
    let files: Vec<(String, Arc<[u8]>)> = tree.files.iter().map(|(p, b)| (p.clone(), Arc::from(b.clone().into_boxed_slice()))).collect();
    g.put(&e, id, got_ver, mods, Some(files), Some(tree), main, ib);
    Ok(())
}

/// G32/G38: la URL final del índice está debajo del `id` del paquete.
fn id_under_url(name: &str, tree: &Tree) -> Result<(), String> {
    let id = tree.index.id.clone().unwrap_or_default();
    let want = format!("{}/", normalize_id(&id));
    if !normalize_id(&tree.url).starts_with(&want) {
        return Err(format!(
            "get: {}: the package says it is {}, but it was fetched from {}; a package is fetched from under its id",
            name, id, tree.url
        ));
    }
    Ok(())
}

/// El nombre directo de un `id`: el de la arista del proyecto cuyo paquete es ese `id` (lo que
/// sirvió la `url`, o el hash escrito). El `id` escrito en `synsema.json` es sólo «lo que estaba»
/// (M2, ronda 1): con la `url` mudada o el `id` editado a mano, manda lo resuelto. `root` sola no
/// sirve: también nombra a los transitivos por el directo de arriba.
fn direct_name(manifest: &Manifest, g: &Graph, id: &str) -> Option<String> {
    g.edges
        .iter()
        .filter(|e| e.from.is_none() && g.nodes.get(&e.hash).is_some_and(|x| x.id == id))
        .filter_map(|e| g.root.get(&e.hash))
        .find(|n| manifest.module(n).is_some())
        .cloned()
}

fn old_state(manifest: &Manifest) -> HashMap<String, Old> {
    let mut out = HashMap::new();
    for (_, e) in manifest.modules.iter().chain(manifest.indirect.iter()) {
        if let (Some(id), Some(v), Some(h)) = (e.id.as_deref(), e.version.as_deref(), e.hash.as_deref()) {
            out.insert(normalize_id(id), Old { version: v.to_string(), hash: h.to_string(), requires: e.requires.clone() });
        }
    }
    out
}

/// Ronda 2 (N-r2-4): lo escrito, para el reporte. Una entrada directa cuyo `id` escrito no es el del
/// paquete que resolvió su `url` (editado a mano, o la `url` mudada) se reporta bajo el resuelto: el
/// reporte no habla de un `id` que nunca fue un paquete («… removed»). La regla de `--accept` sigue con
/// lo escrito ([`old_state`]).
fn old_for_report(manifest: &Manifest, g: &Graph, old: &HashMap<String, Old>) -> HashMap<String, Old> {
    let mut out = old.clone();
    for (name, e) in &manifest.modules {
        let (Some(written), Some(resolved)) = (e.id.as_deref().map(normalize_id), direct_id(manifest, g, name).map(|r| normalize_id(&r))) else { continue };
        if written != resolved && !manifest.indirect.iter().any(|(id, _)| normalize_id(id) == written) {
            if let Some(o) = out.remove(&written) {
                out.entry(resolved).or_insert(o);
            }
        }
    }
    out
}

/// La clave con la que se muestra un `id`: su nombre directo o el `id`.
fn key_of(manifest: &Manifest, g: &Graph, id: &str) -> String {
    direct_name(manifest, g, id).unwrap_or_else(|| id.to_string())
}

/// Lo que un `--accept` puede nombrar: cada nombre directo y cada `id` alcanzado, con su hash y cómo
/// se lo nombra en un error (un `id` con su versión, G53; un nombre solo, G51).
fn known_keys(manifest: &Manifest, g: &Graph, chosen: &HashMap<String, Chosen>, reach: &[String]) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for id in reach {
        let c = &chosen[id];
        if let Some(n) = direct_name(manifest, g, id) {
            out.push((n.clone(), c.hash.clone(), n));
        }
        out.push((id.clone(), c.hash.clone(), format!("{} {}", id, c.version)));
    }
    out
}

/// Quiénes piden la versión elegida de `id` (sin el proyecto), como `(nombre directo raíz, hash del
/// que pide, url del que pide)`.
fn requesters(g: &Graph, id: &str, c: &Chosen) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    for e in &g.edges {
        if e.id == id && e.hash == c.hash {
            if let Some(f) = &e.from {
                let root = g.display_of(f);
                let url = g.nodes.get(f).map(|n| n.url.clone()).unwrap_or_default();
                if !out.iter().any(|(r, h, _)| *r == root && h == f) {
                    out.push((root, f.clone(), url));
                }
            }
        }
    }
    out
}

/// El hash de la arista del proyecto de un directo (lo que sirvió su `url` o su hash escrito).
fn root_hash(g: &Graph, _manifest: &Manifest, root: &str) -> Option<String> {
    g.edges.iter().find(|e| e.from.is_none() && g.root.get(&e.hash).is_some_and(|n| n == root)).map(|e| e.hash.clone())
}

fn accept_cases(
    manifest: &Manifest,
    g: &Graph,
    chosen: &HashMap<String, Chosen>,
    reach: &[String],
    old: &HashMap<String, Old>,
    named: &[String],
    update: Option<&str>,
) -> Vec<Case> {
    let mut cases = Vec::new();
    let mut ids: Vec<&String> = reach.iter().collect();
    ids.sort();
    let chosen_hash_of_root = |root: &str| -> String {
        let rid = direct_id(manifest, g, root);
        rid.and_then(|i| chosen.get(&i).map(|c| c.hash.clone())).unwrap_or_default()
    };
    for id in ids {
        let c = &chosen[id];
        let key = key_of(manifest, g, id);
        let is_named = direct_name(manifest, g, id).is_some_and(|n| named.contains(&n));
        let reqs = g.nodes[&c.hash].reqs.clone().unwrap_or_default().all;
        let who = requesters(g, id, c);
        let mut accepts: Vec<(String, String)> = vec![(key.clone(), c.hash.clone())];
        for (root, _, _) in &who {
            accepts.push((root.clone(), chosen_hash_of_root(root)));
        }
        match old.get(id) {
            Some(o) => {
                let ver_changed = o.version != c.version;
                let added: Vec<String> = reqs.iter().filter(|r| !o.requires.contains(r)).cloned().collect();
                let case2 = ver_changed && !is_named;
                let case1 = !added.is_empty();
                if !case1 && !case2 {
                    continue;
                }
                let why = if version_key(&c.version) > version_key(&o.version) {
                    match who.first() {
                        Some((root, _, url)) if !case1 => format!("because {} requires it (from {})", root, url),
                        Some((root, _, _)) => format!("(required by {})", root),
                        None => "(synsema.json)".to_string(),
                    }
                } else {
                    format!("(no package requires {} anymore)", o.version)
                };
                let text = match (case1, case2) {
                    (true, true) => format!("{} {} → {} {} now requires {}", key, o.version, c.version, why, added.join(", ")),
                    (false, true) => format!("{} {} → {} {}", key, o.version, c.version, why),
                    _ => format!("{} {} now requires {} ({} required {})", key, c.version, added.join(", "), o.version, show_list(&o.requires)),
                };
                cases.push(Case { text, shown: (key.clone(), c.hash.clone()), accepts });
            }
            None => {
                if is_named || direct_name(manifest, g, id).is_some() {
                    continue;
                }
                // Caso 3: entra por un paquete que ya estaba (no por un directo nuevo).
                let roots: Vec<&String> = who.iter().map(|(r, _, _)| r).collect();
                let by_new = roots.iter().any(|r| named.contains(r) && update != Some(r.as_str()));
                if by_new || roots.is_empty() {
                    continue;
                }
                let root = roots[0].clone();
                let root_ver = direct_id(manifest, g, &root).and_then(|i| chosen.get(&i).map(|c| c.version.clone())).unwrap_or_default();
                let rh = chosen_hash_of_root(&root);
                cases.push(Case {
                    text: format!("{} {} brings a new dependency {} (requires {})", root, root_ver, id, show_list(&reqs)),
                    shown: (root.clone(), rh),
                    accepts,
                });
            }
        }
    }
    // Caso 4: una arista de lo que el comando nombra queda en una versión más alta que la que pide,
    // elegida por un paquete que no es ese `id`.
    for name in named {
        let Some(nid) = direct_id(manifest, g, name) else { continue };
        // Lo que sirvió su `url` (puede no ser lo elegido, G50).
        let Some(nh) = g.edges.iter().find(|e| e.from.is_none() && g.root.get(&e.hash) == Some(name)).map(|e| e.hash.clone()) else {
            continue;
        };
        let mut asks: Vec<(String, &Edge)> = Vec::new();
        for e in &g.edges {
            if e.from.as_deref() == Some(nh.as_str()) {
                asks.push((name.clone(), e));
            } else if e.from.is_none() && e.id == nid && manifest.module(name).is_some_and(|m| m.hash.is_none()) {
                asks.push((format!("{} (direct)", name), e));
            }
        }
        for (asker, e) in asks {
            let Some(c) = chosen.get(&e.id) else { continue };
            if version_key(&c.version) <= version_key(&e.version) {
                continue;
            }
            let who = requesters(g, &e.id, c);
            let Some((chooser, _, url)) = who.iter().find(|(_, h, _)| g.nodes.get(h).is_some_and(|n| n.id != e.id)).cloned() else {
                continue;
            };
            if chooser == *name && !asker.ends_with("(direct)") {
                continue;
            }
            let ch = chosen_hash_of_root(&chooser);
            cases.push(Case {
                text: format!("{} {} is chosen because {} requires it (from {}); {} asked for {}", e.id, c.version, chooser, url, asker, e.version),
                shown: (chooser.clone(), ch.clone()),
                accepts: vec![(chooser, ch), (e.id.clone(), c.hash.clone())],
            });
        }
    }
    cases
}

/// El `id` de un directo: el del paquete de su arista del proyecto, nunca el escrito (M2).
fn direct_id(manifest: &Manifest, g: &Graph, name: &str) -> Option<String> {
    root_hash(g, manifest, name).and_then(|h| g.nodes.get(&h).map(|n| n.id.clone()))
}

fn requires_value(xs: &[String]) -> serde_json::Value {
    serde_json::Value::Array(xs.iter().map(|x| serde_json::Value::String(x.clone())).collect())
}

/// Escribe lo resuelto: 2 espacios, el orden de las claves conservado y un `\n` final (§10.1).
fn write_manifest(raw: &[u8], manifest: &Manifest, g: &Graph, chosen: &HashMap<String, Chosen>, reach: &[String]) -> Result<String, String> {
    use serde_json::{Map, Value};
    let mut doc: Value = serde_json::from_slice(raw).map_err(|e| format!("get: synsema.json: {}", e))?;
    let obj = doc.as_object_mut().ok_or("get: synsema.json is not an object")?;
    let mut direct_ids: Vec<String> = Vec::new();
    if let Some(Value::Object(mods)) = obj.get_mut("modules") {
        for (name, _) in &manifest.modules {
            let Some(id) = direct_id(manifest, g, name) else { continue };
            let c = &chosen[&id];
            let n = &g.nodes[&c.hash];
            let Some(Value::Object(m)) = mods.get_mut(name) else { continue };
            if c.hash != root_hash(g, manifest, name).unwrap_or_default() {
                m.insert("url".to_string(), Value::String(c.url.clone()));
            }
            m.insert("id".to_string(), Value::String(n.id.clone()));
            m.insert("version".to_string(), Value::String(c.version.clone()));
            m.insert("hash".to_string(), Value::String(c.hash.clone()));
            m.insert("requires".to_string(), requires_value(&n.reqs.clone().unwrap_or_default().all));
            direct_ids.push(id);
        }
    }
    let mut ind: Map<String, Value> = Map::new();
    let mut rest: Vec<&String> = reach.iter().filter(|id| !direct_ids.contains(id)).collect();
    // Los que ya estaban, en su orden; los nuevos, ordenados.
    let mut ordered: Vec<String> = manifest.indirect.iter().map(|(k, _)| normalize_id(k)).filter(|k| rest.contains(&k)).collect();
    rest.sort();
    for id in rest {
        if !ordered.contains(id) {
            ordered.push(id.clone());
        }
    }
    for id in ordered {
        let c = &chosen[&id];
        let n = &g.nodes[&c.hash];
        let mut m = Map::new();
        m.insert("url".to_string(), Value::String(c.url.clone()));
        m.insert("version".to_string(), Value::String(c.version.clone()));
        m.insert("hash".to_string(), Value::String(c.hash.clone()));
        m.insert("requires".to_string(), requires_value(&n.reqs.clone().unwrap_or_default().all));
        ind.insert(id, Value::Object(m));
    }
    if ind.is_empty() {
        obj.remove("indirect");
    } else {
        obj.insert("indirect".to_string(), Value::Object(ind));
    }
    let mut s = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    s.push('\n');
    Ok(s)
}

/// Lo que se imprime al terminar: lo que pide cada task (G1) y, con `--update`, la diferencia (G7).
fn report(manifest: &Manifest, g: &Graph, chosen: &HashMap<String, Chosen>, reach: &[String], old: &HashMap<String, Old>, update: Option<&str>) {
    let mut ids: Vec<&String> = reach.iter().collect();
    ids.sort_by_key(|id| (direct_name(manifest, g, id).is_none(), (*id).clone()));
    for id in ids {
        let c = &chosen[id];
        let key = key_of(manifest, g, id);
        let reqs = g.nodes[&c.hash].reqs.clone().unwrap_or_default();
        match old.get(id.as_str()) {
            Some(o) if o.hash != c.hash => println!("{} {} → {} ({})", key, o.version, c.version, short_hash(&c.hash)),
            Some(_) if update.is_some() => println!("{} {} ({}), unchanged", key, c.version, short_hash(&c.hash)),
            Some(_) => println!("{} {} ({})", key, c.version, short_hash(&c.hash)),
            None => println!("{} {} ({}), new", key, c.version, short_hash(&c.hash)),
        }
        if let Some(o) = old.get(id.as_str()) {
            if o.requires != reqs.all {
                println!("  requires: {} → {}", show_list(&o.requires), show_list(&reqs.all));
            }
        }
        if reqs.tasks.is_empty() {
            println!("  requires nothing");
        }
        for (t, rs) in &reqs.tasks {
            println!("  task {}: {}", t, rs.join(", "));
        }
    }
    // En orden de `id` (N10): el reporte no depende del orden del `HashMap`.
    let mut gone: Vec<(&String, &Old)> = old.iter().filter(|(id, _)| !reach.contains(id) && direct_name(manifest, g, id).is_none()).collect();
    gone.sort_by(|a, b| a.0.cmp(b.0));
    for (id, o) in gone {
        println!("{} {} removed (no package requires it anymore)", id, o.version);
    }
}

// ---------------------------------------------------------------------------------------------
// `get --check` (§10.1, §11.3 paso 6): sin red

fn check(manifest: &Manifest, cache: &Path) -> Result<(), String> {
    let mut g = Graph { cache, offline: true, nodes: HashMap::new(), edges: Vec::new(), root: HashMap::new() };
    let mut direct_ids: Vec<String> = Vec::new();
    for (name, entry) in &manifest.modules {
        let Some(hash) = entry.hash.clone().filter(|h| is_tree_hash(h)) else {
            return Err(format!("get --check: {} has no hash: run synsema get", name));
        };
        let e = Edge { from: None, id: String::new(), version: entry.version.clone().unwrap_or_default(), url: entry.url.clone(), hash: hash.clone() };
        g.obtain(name, "synsema.json", &e, true)?;
        let n = &g.nodes[&hash];
        let id = n.id.clone();
        if entry.id.as_deref().map(normalize_id).as_deref() != Some(id.as_str()) || entry.version.as_deref() != Some(n.version.as_str()) {
            return Err(format!(
                "get --check: {}: synsema.json says {} {}, but {} is {} {}; run synsema get --update {}",
                name,
                entry.id.as_deref().unwrap_or("(no id)"),
                entry.version.as_deref().unwrap_or("(no version)"),
                short_hash(&hash),
                id,
                n.version,
                name
            ));
        }
        g.root.insert(hash.clone(), name.clone());
        g.edges.push(Edge { from: None, id: id.clone(), version: n.version.clone(), url: entry.url.clone(), hash: hash.clone() });
        direct_ids.push(id);
    }
    for (name, entry) in &manifest.modules {
        let h = entry.hash.clone().unwrap_or_default();
        let id = g.nodes[&h].id.clone();
        let _ = name;
        g.walk(&h, &mut vec![id], 1)?;
    }
    let chosen = select(&g)?;
    chosen_cycle(&g, &chosen, &direct_ids).map_err(|x| x.replacen("get: ", "get --check: ", 1))?;
    let reach = reachable(&g, &chosen, &direct_ids);
    // Lo escrito contra la selección (G35) y contra el paquete del caché (G22).
    for (name, entry) in &manifest.modules {
        let id = normalize_id(entry.id.as_deref().unwrap_or_default());
        let c = &chosen[&id];
        if entry.version.as_deref() != Some(c.version.as_str()) || entry.hash.as_deref() != Some(c.hash.as_str()) {
            return Err(format!("get --check: {} says {}, but the selection gives {}", name, entry.version.as_deref().unwrap_or("?"), c.version));
        }
    }
    for id in &reach {
        if direct_ids.contains(id) {
            continue;
        }
        let c = &chosen[id];
        match manifest.indirect.iter().find(|(k, _)| normalize_id(k) == *id) {
            None => return Err(format!("get --check: indirect has no {} (the selection gives {}); run synsema get", id, c.version)),
            Some((k, e)) => {
                if e.version.as_deref() != Some(c.version.as_str()) {
                    return Err(format!("get --check: indirect {} says {}, but the selection gives {}", k, e.version.as_deref().unwrap_or("?"), c.version));
                }
                if e.hash.as_deref() != Some(c.hash.as_str()) {
                    return Err(format!("get --check: indirect {} says {}, but the selection gives {}", k, short_hash(e.hash.as_deref().unwrap_or("?")), short_hash(&c.hash)));
                }
            }
        }
    }
    for (k, _) in &manifest.indirect {
        if !reach.contains(&normalize_id(k)) {
            return Err(format!("get --check: indirect {} is not reached by the selection; run synsema get", k));
        }
    }
    // Lo que pide cada paquete, leído de su árbol (G22).
    let mut all: Vec<(String, &ModEntry)> = manifest.modules.iter().map(|(n, e)| (n.clone(), e)).collect();
    all.extend(manifest.indirect.iter().map(|(k, e)| (k.clone(), e)));
    for (key, e) in all {
        let h = e.hash.clone().unwrap_or_default();
        let id = normalize_id(e.id.as_deref().unwrap_or(&key));
        let shown = key.clone();
        let edge = Edge { from: None, id, version: e.version.clone().unwrap_or_default(), url: e.url.clone(), hash: h.clone() };
        g.obtain(&shown, "synsema.json", &edge, true)?;
        let n = &g.nodes[&h];
        let reqs = validate(&shown, &n.main, n.files.as_deref().unwrap_or(&[])).map_err(|x| x.replacen("get: ", "get --check: ", 1))?;
        let mut written = e.requires.clone();
        written.sort();
        if written != reqs.all {
            let upd = if manifest.module(&key).is_some() { format!("synsema get --update {}", key) } else { "synsema get".to_string() };
            return Err(format!(
                "get --check: {}: synsema.json says requires {} but {} requires {}; run {}",
                key,
                if written.is_empty() { "[]".to_string() } else { written.join(", ") },
                short_hash(&h),
                show_list(&reqs.all),
                upd
            ));
        }
    }
    let _ = BTreeSet::<String>::new();
    println!("get --check: synsema.json matches the module cache ({} packages)", reach.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert!(check_url("t", "https://reg.example/t/0.1.0/synsema.json").is_ok());
        assert!(check_url("t", "http://127.0.0.1:8080/t/synsema.json").is_ok());
        assert!(check_url("t", "http://localhost/t/synsema.json").is_ok());
        assert!(check_url("t", "http://[::1]:9/t/synsema.json").is_ok());
        assert_eq!(
            check_url("tok", "http://reg.example/t.json").unwrap_err(),
            "get: tok: http:// is only allowed to this machine (127.0.0.1, ::1, localhost); use https://"
        );
        assert_eq!(check_url("tok", "https://u:p@reg.example/t.json").unwrap_err(), "get: tok: a URL with credentials is not supported");
        for bad in [
            "https://reg.example/tokenizador/../otro/0.1.0/synsema.json",
            "https://reg.example/tokenizador/%2e%2e/otro/synsema.json",
            "https://reg.example/a%2Fb/synsema.json",
            "https://reg.example/a%5cb/synsema.json",
        ] {
            assert_eq!(check_url("tok", bad).unwrap_err(), format!("get: tok: the url has a dot segment or an encoded separator: {}", bad));
        }
        // M3: un `\` literal, en cualquier lugar.
        let bs = r"http://127.0.0.1:47811/tok/x\..\..\evil/0.1.0/synsema.json";
        assert_eq!(check_url("tok", bs).unwrap_err(), format!("get: tok: the url has a backslash, which some servers take as a path separator: {}", bs));
        assert!(check_url("tok", r"https://reg.example/a\b/synsema.json").is_err());
        // M-r2-5 (ronda 2): lo que un servidor reinterpreta no pasa, con un solo texto.
        for (bad, c) in [
            ("http://127.0.0.1:47931/tok/x/..;/..;/evil/0.1.0/synsema.json", ';'),
            ("https://reg.example/tok/%252e%252e/evil/synsema.json", '%'),
            ("https://reg.example/tok/..%20/evil/synsema.json", '%'),
            ("https://reg.example/tok/%EF%BC%8E%EF%BC%8E/evil/synsema.json", '%'),
            ("https://reg.example/tok/\u{ff0e}\u{ff0e}/evil/synsema.json", '\u{ff0e}'),
            ("https://reg.example/tok/a b/synsema.json", ' '),
        ] {
            let e = check_url("tok", bad).unwrap_err();
            assert!(e.starts_with(&format!("get: tok: the url path has '{}'; a package url uses only", c)) && e.ends_with(bad), "{}", e);
        }
        // Lo de siempre sigue pasando, y la consulta no es ruta.
        for ok in ["https://reg.example/@scope/tok-1_x.y~z/0.1.0/synsema.json", "https://reg.example/t/synsema.json?ref=a%20b;c"] {
            assert!(check_url("t", ok).is_ok(), "{}", ok);
        }
        // B10: loopback sólo en la forma canónica.
        for ok in ["127.0.0.1", "127.0.0.2", "127.255.0.10", "localhost", "[::1]"] {
            assert!(check_url("t", &format!("http://{}:9/t/synsema.json", ok)).is_ok(), "{}", ok);
        }
        for bad in ["127.0.0.999", "127.000.000.001", "127.0.0.01", "127.1", "0177.0.0.1", "localhost.", "127.0.0.", "127.0.0.1.2"] {
            assert!(check_url("t", &format!("http://{}:9/t/synsema.json", bad)).is_err(), "{}", bad);
        }
    }

    #[test]
    fn locations() {
        assert_eq!(resolve_ref("https://a.example/x/y/synsema.json", "/real/synsema.json"), "https://a.example/real/synsema.json");
        assert_eq!(resolve_ref("https://a.example/x/y/synsema.json", "z/synsema.json"), "https://a.example/x/y/z/synsema.json");
        assert_eq!(resolve_ref("https://a.example/x", "//b.example/q"), "https://b.example/q");
        // B-r2-4 (ronda 2): una absoluta también resuelve sus `..`; el esquema es lo de antes del
        // primer `/`, `?` o `#`.
        assert_eq!(resolve_ref("https://a.example/x", "https://b.example/tok/latest/../0.1.0/synsema.json"), "https://b.example/tok/0.1.0/synsema.json");
        assert_eq!(resolve_ref("https://a.example/x", "//b.example/a/./b/../c"), "https://b.example/a/c");
        assert_eq!(resolve_ref("https://a.example/tok/x", "/tok/y?next=https://evil.example/"), "https://a.example/tok/y?next=https://evil.example/");
        assert_eq!(resolve_ref("https://a.example/tok/x", "y?next=https://evil.example/"), "https://a.example/tok/y?next=https://evil.example/");
        assert_eq!(url_dir("https://a.example/x/y/synsema.json"), "https://a.example/x/y/");
        // B8: RFC 3986 §5.2.4.
        assert_eq!(resolve_ref("https://a.example/tok/latest/synsema.json", "../0.1.0/synsema.json"), "https://a.example/tok/0.1.0/synsema.json");
        assert_eq!(resolve_ref("https://a.example/a/b/c", "./d/../e?x=1"), "https://a.example/a/b/e?x=1");
        assert_eq!(resolve_ref("https://a.example/a/b/c", "/x/./y/../z"), "https://a.example/x/z");
        assert_eq!(resolve_ref("https://a.example/a/b/c", ".."), "https://a.example/a/");
        assert_eq!(resolve_ref("https://a.example/a", "../../../q"), "https://a.example/q");
        assert_eq!(resolve_ref("https://a.example/a/b?k", "?z"), "https://a.example/a/b?z");
    }
}

//! Los scopes de capability que son rutas: la normalización léxica y el glob con que el
//! runtime (`synsema-capabilities`, `Capability::covers`) decide si un grant cubre una ruta.
//! Viven acá para que `synsema check` (`codeintel`) use exactamente el mismo matcher.

/// `fnmatch` estilo Unix (case-sensitive, como el oráculo en Linux). Soporta `*`
/// (cero o más) y `?` (uno). Los corchetes `[...]` se tratan literales (no aparecen
/// en scopes de capability; el contrato sólo exige `*`). `pub` para reusar en el filtro
/// `glob` de `grep` (secure.rs).
pub fn fnmatch(name: &str, pattern: &str) -> bool {
    let n: Vec<char> = name.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    glob(&n, &p)
}

fn glob(name: &[char], pat: &[char]) -> bool {
    match pat.split_first() {
        None => name.is_empty(),
        Some((&'*', rest)) => (0..=name.len()).any(|k| glob(&name[k..], rest)),
        Some((&'?', rest)) => !name.is_empty() && glob(&name[1..], rest),
        Some((&c, rest)) => !name.is_empty() && name[0] == c && glob(&name[1..], rest),
    }
}

/// v0.6.20 — `~`, `~/…` y `~\…` = el home del usuario (`HOME`, si no `USERPROFILE`).
/// Vale igual para un scope (`require file("~/.synsema/*")`) y para el argumento de un
/// builtin, porque los dos pasan por `normalize_path`: UNA expansión, `covers()` no cambia.
/// Sin home resoluble se deja literal: un scope literal `~/…` no cubre ninguna ruta real →
/// deniega (falla cerrado, nunca abierto). `~usuario/…` no se soporta a propósito.
fn expand_home(p: &str) -> String {
    let is_tilde = p == "~" || p.starts_with("~/") || p.starts_with("~\\");
    if !is_tilde {
        return p.to_string();
    }
    let home = std::env::var("HOME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| std::env::var("USERPROFILE").ok().filter(|h| !h.trim().is_empty()));
    match home {
        Some(h) => format!("{}{}", h.trim_end_matches(['/', '\\']), &p[1..]),
        None => p.to_string(),
    }
}

/// Normaliza una ruta de forma LÉXICA (sin tocar el filesystem): unifica separadores
/// a `/`, colapsa `.` y `..`, quita un `./` inicial. NO resuelve symlinks ni vuelve la
/// ruta absoluta (preserva relativa/absoluta y el prefijo de unidad Windows). Así el
/// scope-glob de `file.read("./data/*")` se chequea contra la ruta REAL a la que apunta
/// el argumento, cerrando el bypass `./data/../../etc` sin cambiar la semántica del scope.
pub fn normalize_path(p: &str) -> String {
    let p = expand_home(p).replace('\\', "/");
    let (prefix, rest): (String, &str) = match p.as_bytes() {
        // Unidad Windows: "C:/..."
        [c, b':', b'/', ..] if c.is_ascii_alphabetic() => (p[..3].to_string(), &p[3..]),
        // Absoluta unix: "/..."
        _ if p.starts_with('/') => ("/".to_string(), &p[1..]),
        _ => (String::new(), p.as_str()),
    };
    let rooted = !prefix.is_empty();
    let mut out: Vec<&str> = Vec::new();
    for seg in rest.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                match out.last() {
                    Some(&s) if s != ".." => {
                        out.pop();
                    }
                    // ".." sin segmento normal arriba: en ruta rooteada se descarta
                    // (no se sube de la raíz); en relativa se conserva (escapa del prefijo).
                    _ if !rooted => out.push(".."),
                    _ => {}
                }
            }
            s => out.push(s),
        }
    }
    let joined = out.join("/");
    if rooted {
        format!("{}{}", prefix, joined)
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// ¿Un grant de ruta cubre la ruta pedida? Lo mismo que `Capability::covers` para
/// `file`/`file.read`/`file.write`: las dos se normalizan (`./x.csv` y `x.csv` son la misma),
/// se comparan sin mayúsculas donde el filesystem no las distingue, y el grant puede ser glob.
pub fn path_covers(grant: &str, req: &str) -> bool {
    #[cfg(any(windows, target_os = "macos"))]
    let fold = |s: String| -> String { s.to_lowercase() };
    #[cfg(not(any(windows, target_os = "macos")))]
    let fold = |s: String| -> String { s };
    let (g, r) = (fold(normalize_path(grant)), fold(normalize_path(req)));
    g == r || fnmatch(&r, &g)
}

/// v0.6.45 — a dónde LLEVA una ruta en disco: la ruta absoluta con los links (symlinks,
/// junctions) resueltos, con `/` y sin el prefijo `\\?\` de Windows. Lo que no existe todavía
/// (un archivo por escribir) se resuelve hasta el ancestro más profundo que existe y se le
/// agrega el resto tal cual: un nombre que no existe no puede ser un link. Parte de la forma
/// LÉXICA (`normalize_path`), que es la que abren los builtins. `None` sin filesystem (wasm) o
/// si no hay directorio de trabajo.
#[cfg(not(target_arch = "wasm32"))]
pub fn physical_path(p: &str) -> Option<String> {
    let abs = absolute_lexical(p)?;
    let mut cur = std::path::PathBuf::from(&abs);
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    let real = loop {
        match std::fs::canonicalize(&cur) {
            Ok(c) => break c,
            Err(_) => {
                rest.push(cur.file_name()?.to_os_string());
                cur = cur.parent()?.to_path_buf();
            }
        }
    };
    let mut out = real.to_string_lossy().into_owned();
    if let Some(unc) = out.strip_prefix(r"\\?\UNC\") {
        out = format!(r"\\{}", unc);
    } else if let Some(local) = out.strip_prefix(r"\\?\") {
        out = local.to_string();
    }
    let mut out = out.replace('\\', "/");
    for seg in rest.iter().rev() {
        if !out.ends_with('/') {
            out.push('/');
        }
        out.push_str(&seg.to_string_lossy());
    }
    Some(out)
}

#[cfg(target_arch = "wasm32")]
pub fn physical_path(_p: &str) -> Option<String> {
    None
}

/// La ruta absoluta LÉXICA (cwd + ruta normalizada, sin tocar links), con `/`.
#[cfg(not(target_arch = "wasm32"))]
fn absolute_lexical(p: &str) -> Option<String> {
    let norm = normalize_path(p);
    let rooted = norm.starts_with('/') || matches!(norm.as_bytes(), [c, b':', b'/', ..] if c.is_ascii_alphabetic());
    if rooted {
        return Some(norm);
    }
    let cwd = std::env::current_dir().ok()?;
    Some(normalize_path(&format!("{}/{}", cwd.to_string_lossy(), norm)))
}

/// La parte literal de un scope (hasta el primer segmento con `*` o `?`) y el resto del patrón.
/// `None` si un scope relativo no tiene parte literal (`*`, `*.csv`): no ancla ningún directorio.
fn split_scope(scope: &str) -> Option<(String, Option<String>)> {
    let norm = normalize_path(scope);
    let segs: Vec<&str> = norm.split('/').collect();
    let Some(i) = segs.iter().position(|s| s.contains(['*', '?'])) else {
        return Some((norm.clone(), None));
    };
    let literal = segs[..i].join("/");
    if literal.is_empty() && !norm.starts_with('/') {
        return None;
    }
    Some((if literal.is_empty() { "/".to_string() } else { literal }, Some(segs[i..].join("/"))))
}

/// v0.6.45 — la forma física de un SCOPE: su parte literal (hasta el primer segmento con `*` o
/// `?`) resuelta en disco, con el resto del patrón detrás. Un link que es parte del scope
/// declarado vale (el grant nombra ese lugar, sea cual sea); lo que está DEBAJO y sale, no. Un
/// scope relativo sin parte literal (`*`, `*.csv`) no ancla ningún directorio: `None`, y queda la
/// comparación por nombre de siempre.
pub fn physical_scope(scope: &str) -> Option<String> {
    let (literal, pattern) = split_scope(scope)?;
    let base = physical_path(&literal)?;
    Some(match pattern {
        None => base,
        Some(p) => format!("{}/{}", base.trim_end_matches('/'), p),
    })
}

/// `physical_scope` con memoria: un scope es un grant, un techo o un deny — pocos y fijos — y
/// resolverlo cuesta un `canonicalize` (decenas de µs en Windows). La clave lleva el cwd. Si la
/// base cambiara de lugar después, la comparación con la forma vieja DENIEGA de más (la ruta
/// pedida se resuelve siempre en el momento), nunca concede de más.
fn physical_scope_cached(scope: &str) -> Option<String> {
    use std::cell::RefCell;
    use std::collections::HashMap;
    thread_local! {
        static CACHE: RefCell<HashMap<(String, String), Option<String>>> = RefCell::new(HashMap::new());
    }
    let cwd = std::env::current_dir().ok()?.to_string_lossy().into_owned();
    let key = (cwd, scope.to_string());
    if let Some(hit) = CACHE.with(|c| c.borrow().get(&key).cloned()) {
        return hit;
    }
    let v = physical_scope(scope);
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c.len() >= 256 {
            c.clear();
        }
        c.insert(key, v.clone());
    });
    v
}

/// ¿Hay un link entre la base literal del scope y la ruta pedida? El camino rápido de
/// `path_within_physically`: si la ruta está por nombre bajo la base y ninguno de los componentes
/// de DEBAJO es un link, en disco también está adentro (los links de la base misma valen: el grant
/// nombra ese lugar). Un `symlink_metadata` por componente que existe, hasta el primero que no:
/// normalmente uno. `None` si la ruta no está por nombre bajo la base (decide el camino lento).
#[cfg(not(target_arch = "wasm32"))]
fn link_below_base(base: &str, req: &str) -> Option<bool> {
    let base = absolute_lexical(base)?;
    let req = absolute_lexical(req)?;
    let b = base.trim_end_matches('/');
    #[cfg(any(windows, target_os = "macos"))]
    let rest = {
        let (bl, rl) = (b.to_lowercase(), req.to_lowercase());
        if rl != bl && !rl.strip_prefix(&bl).is_some_and(|r| r.starts_with('/')) {
            return None;
        }
        // Mismo largo en bytes salvo mayúsculas fuera de ASCII; si no, que decida el camino lento.
        if bl.len() != b.len() || rl.len() != req.len() {
            return None;
        }
        req[b.len()..].to_string()
    };
    #[cfg(not(any(windows, target_os = "macos")))]
    let rest = {
        if req != b && !req.strip_prefix(b).is_some_and(|r| r.starts_with('/')) {
            return None;
        }
        req[b.len()..].to_string()
    };
    // Cada componente es una consulta al disco (~25 µs en Windows con el antivirus en el medio); con
    // más de dos, un solo `canonicalize` del camino lento sale más barato.
    if rest.split('/').filter(|s| !s.is_empty()).count() > 2 {
        return None;
    }
    let mut cur = std::path::PathBuf::from(if b.is_empty() { "/" } else { b });
    for seg in rest.split('/').filter(|s| !s.is_empty()) {
        cur.push(seg);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => return Some(true),
            Ok(_) => {}
            Err(_) => return Some(false),
        }
    }
    Some(false)
}

#[cfg(target_arch = "wasm32")]
fn link_below_base(_base: &str, _req: &str) -> Option<bool> {
    Some(false)
}

/// v0.6.45 — ¿la ruta pedida queda, en disco, dentro del scope? La otra mitad de `path_covers`
/// (que compara nombres): con un link debajo del scope que lleva afuera, por nombre está dentro y
/// en disco no. Sin forma física (wasm, un scope sin ancla) decide sólo el nombre.
pub fn path_within_physically(scope: &str, req: &str) -> bool {
    let Some((literal, _)) = split_scope(scope) else {
        return true;
    };
    if link_below_base(&literal, req) == Some(false) {
        return true;
    }
    let (Some(g), Some(r)) = (physical_scope_cached(scope), physical_path(req)) else {
        return true;
    };
    physical_match(&g, &r)
}

/// v0.6.45 — para un `deny`: ¿la ruta pedida llega, en disco, a lo que el scope nombra? Un link
/// que lleva a un lugar denegado tiene que dar con la denegación aunque su nombre no.
pub fn path_reaches_physically(scope: &str, req: &str) -> bool {
    match (physical_scope_cached(scope), physical_path(req)) {
        (Some(g), Some(r)) => physical_match(&g, &r),
        _ => false,
    }
}

/// v0.6.45 — ¿`path`, en disco, es `dir` o queda debajo de `dir`? Para la raíz de `use`: un
/// prefijo de directorio (con límite en `/`), no un glob. Sin forma física (wasm) → `true`: decide
/// la comparación por nombre que ya se hizo.
pub fn physically_beneath(dir: &str, path: &str) -> bool {
    let (Some(d), Some(p)) = (physical_path(dir), physical_path(path)) else {
        return true;
    };
    #[cfg(any(windows, target_os = "macos"))]
    let (d, p) = (d.to_lowercase(), p.to_lowercase());
    let d = d.trim_end_matches('/');
    p == d || p.strip_prefix(d).is_some_and(|rest| rest.starts_with('/'))
}

fn physical_match(g: &str, r: &str) -> bool {
    #[cfg(any(windows, target_os = "macos"))]
    let (g, r) = (g.to_lowercase(), r.to_lowercase());
    g == r || fnmatch(&r, &g)
}

#[cfg(test)]
mod physical_tests {
    /// v0.6.45 — lo que agrega el chequeo en disco a una lectura: correr con
    /// `cargo test --release -p synsema-core --lib physical_cost -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn physical_cost() {
        let d = std::env::temp_dir().join(format!("synsema-physcost-{}", std::process::id()));
        std::fs::create_dir_all(d.join("data/sub")).unwrap();
        std::fs::write(d.join("data/a.txt"), "hola\n").unwrap();
        std::fs::write(d.join("data/sub/b.txt"), "hola\n").unwrap();
        let r = d.to_string_lossy().replace('\\', "/");
        let (grant, f1, f2) = (format!("{}/data/*", r), format!("{}/data/a.txt", r), format!("{}/data/sub/b.txt", r));
        let n = 4000;
        let time = |f: &dyn Fn()| {
            let t = std::time::Instant::now();
            for _ in 0..n {
                f();
            }
            t.elapsed().as_secs_f64() / n as f64 * 1e6
        };
        let read = time(&|| {
            std::hint::black_box(std::fs::read_to_string(&f1).unwrap());
        });
        let check1 = time(&|| assert!(super::path_within_physically(&grant, &f1)));
        let check2 = time(&|| assert!(super::path_within_physically(&grant, &f2)));
        println!("read_to_string {:.1} us | check depth 1 {:.1} us | check depth 2 {:.1} us", read, check1, check2);
        let _ = std::fs::remove_dir_all(&d);
    }
}

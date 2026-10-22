//! Los scopes de capability que son rutas: la normalización léxica y el glob con que el
//! runtime (`synsema-capabilities`, `Capability::covers`) decide si un grant cubre una ruta.
//! Viven acá para que `synsema check` (`codeintel`) use exactamente el mismo matcher.

/// v0.6.46 (D4): los nombres que entiende un `require` (y `--cap-set`). Es la única lista: la de
/// `synsema-capabilities` (`KNOWN_CAPABILITY_NAMES`) es esta misma, y su test exige que cada nombre
/// tenga su `CapabilityType` y cada tipo su nombre acá.
pub const KNOWN_CAPABILITY_NAMES: &str = "net, file, file.read, file.write, exec, env, time, random, stdout, stdin, llm, judge, db, serve, secret, reveal, sign, wallet, spend, memory, sandbox_run, attest, declassify";

/// v0.6.46 (D4): ¿lo entiende un `require`? También `file_read`/`file_write`, la forma en que el
/// audit los imprime.
pub fn is_capability_name(name: &str) -> bool {
    name == "file_read" || name == "file_write" || KNOWN_CAPABILITY_NAMES.split(", ").any(|k| k == name)
}

/// v0.6.46 (D4): el error de un `require` con un nombre que no existe, con el más cercano por
/// distancia de edición si lo hay. Antes se ignoraba: `require nett("x")` no concedía nada y el
/// programa fallaba lejos, con un error que no nombraba el typo.
pub fn unknown_capability_error(name: &str) -> Option<String> {
    if is_capability_name(name) {
        return None;
    }
    let close = KNOWN_CAPABILITY_NAMES
        .split(", ")
        .map(|k| (edit_distance(name, k), k))
        .min()
        .filter(|(d, k)| *d <= 2.max(k.len() / 3));
    let hint = close.map(|(_, k)| format!(" — did you mean `require {}`?", k)).unwrap_or_default();
    Some(format!(
        "unknown capability `{}` in `require`{}; a name that does not exist grants nothing. Known: {}",
        name, hint, KNOWN_CAPABILITY_NAMES
    ))
}

/// Distancia de Levenshtein por caracteres (para sugerir un nombre cercano).
pub(crate) fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            cur[j + 1] = (prev[j] + usize::from(ca != *cb)).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

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
    let (g, r) = same_form(grant, req);
    let (g, r) = (fold(g), fold(r));
    g == r || path_glob(&r, &g)
}

/// v0.6.45 — las dos rutas normalizadas y en la MISMA forma: si una es absoluta y la otra relativa,
/// la relativa se vuelve absoluta con el cwd. Antes nunca coincidían (`file.read("C:/proj/**")` no
/// cubría `data/x`, y un techo con rutas absolutas —el que `run_program` le manda al hijo— no cubría
/// el `require file.read("x")` relativo del hijo). Sólo en el caso mixto se consulta el cwd.
pub fn same_form(a: &str, b: &str) -> (String, String) {
    let (na, nb) = (normalize_path(a), normalize_path(b));
    // Ronda 3 (M1): en Windows `/x` es "la unidad del cwd": contra una ruta CON unidad se compara
    // como `<unidad>:/x` (lo que `absolute_scope` le manda al hijo de `run_program`), si no un techo
    // `C:/data/**` no cubría el `require file.read("/data/**")` del hijo.
    #[cfg(windows)]
    {
        let slash = |s: &str| s.starts_with('/') && !s.starts_with("//");
        let drive = |s: &str| matches!(s.as_bytes(), [c, b':', ..] if c.is_ascii_alphabetic());
        // Ronda 4 (B4): también contra una ruta RELATIVA (que pasa a tener la unidad del cwd).
        if slash(&na) && !slash(&nb) {
            let nb = if drive(&nb) { nb } else { absolute_scope(&nb) };
            return (absolute_scope(&na), nb);
        }
        if slash(&nb) && !slash(&na) {
            let na = if drive(&na) { na } else { absolute_scope(&na) };
            return (na, absolute_scope(&nb));
        }
    }
    match (is_rooted(&na), is_rooted(&nb)) {
        (true, false) => (na, absolute_scope(&nb)),
        (false, true) => (absolute_scope(&na), nb),
        _ => (na, nb),
    }
}

/// v0.6.45 (ronda 3, A2) — ¿un scope de `db` es la URL de un servidor? El MISMO criterio que usa
/// `db_open` para elegir backend (esquemas conocidos), no "contiene `://`". Vive acá para que el
/// runtime (`Capability::covers`) y `synsema check` decidan igual.
pub fn is_db_url(s: &str) -> bool {
    let l = s.trim_start().to_ascii_lowercase();
    ["postgres://", "postgresql://", "mysql://", "mongodb://", "mongodb+srv://", "redis://", "rediss://"]
        .iter()
        .any(|p| l.starts_with(p))
}

/// v0.6.45 — el glob de un scope de RUTA, por segmentos (como gitignore y los globs de shell):
/// `*` y `?` coinciden dentro de UN segmento, `**` cruza carpetas (cero o más segmentos, así que
/// `./data/**` también cubre `./data`), y ningún comodín coincide con `..` ni pasa de una ruta
/// relativa a una absoluta. Antes era `fnmatch` sobre la ruta entera: el `*` cruzaba `/` y `..`, y
/// `file.read("./*")` cubría `/etc/passwd`. Las dos rutas llegan normalizadas (y, donde el disco no
/// distingue mayúsculas, ya en minúsculas). Comparar un scope contra otro (el techo al conceder)
/// también funciona: un `**` pedido sólo lo cubre un `**`.
pub fn path_glob(path: &str, pattern: &str) -> bool {
    fn split(p: &str) -> (&str, Vec<&str>) {
        let root_len = match p.as_bytes() {
            [c, b':', b'/', ..] if c.is_ascii_alphabetic() => 3,
            [b'/', ..] => 1,
            _ => 0,
        };
        let segs = p[root_len..].split('/').filter(|s| !s.is_empty() && *s != ".").collect();
        (&p[..root_len], segs)
    }
    fn wild(s: &str) -> bool {
        s.contains(['*', '?'])
    }
    fn segs_match(p: &[&str], r: &[&str]) -> bool {
        match p.split_first() {
            None => r.is_empty(),
            Some((&"**", rest)) => {
                segs_match(rest, r) || matches!(r.first(), Some(s) if *s != "..") && segs_match(p, &r[1..])
            }
            Some((&ps, rest)) => match r.split_first() {
                Some((&rs, rrest)) => {
                    let one = if rs == "**" || (rs == ".." && ps != "..") {
                        false
                    } else if wild(rs) {
                        // Un segmento pedido con comodines (un scope comparado con otro, el techo al
                        // conceder) sólo lo cubre uno idéntico o `*`: `a?` no cubre `a*`.
                        ps == rs || ps == "*"
                    } else if wild(ps) {
                        fnmatch(rs, ps)
                    } else {
                        rs == ps
                    };
                    one && segs_match(rest, rrest)
                }
                None => false,
            },
        }
    }
    let ((pr, ps), (rr, rs)) = (split(pattern), split(path));
    pr == rr && segs_match(&ps, &rs)
}

/// v0.6.45 — a dónde LLEVA una ruta en disco, con los links (symlinks, junctions) resueltos.
/// `Path` es la ruta absoluta con `/` y sin el prefijo `\\?\` de Windows. `NoFs`: no hay disco
/// (wasm), decide la comparación por nombre. `Unresolved`: no se pudo resolver (un link que no se
/// puede leer, un ciclo, un error del sistema): quien pregunta **deniega**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Physical {
    Path(String),
    NoFs,
    Unresolved,
}

/// Cuántos links seguidos se resuelven antes de rendirse (Linux usa 40).
#[cfg(not(target_arch = "wasm32"))]
const MAX_LINK_HOPS: usize = 40;

/// La ruta física de `p`. Parte de la forma LÉXICA (`normalize_path`, la que abren los builtins).
/// Lo que no existe todavía (un archivo por escribir) se resuelve hasta el ancestro más profundo
/// que existe y se le agrega el resto; pero un nombre que **existe como link roto** se sigue: abrir
/// con `create` crea el archivo en su destino, así que lo que se juzga es el destino (antes se lo
/// tomaba como un nombre más y `append_file` creaba el archivo fuera del scope).
#[cfg(not(target_arch = "wasm32"))]
pub fn physical_path(p: &str) -> Physical {
    match absolute_lexical(p) {
        Some(abs) => match overridden(&abs) {
            Some(real) => Physical::Path(real),
            None => resolve_physical(abs),
        },
        None => Physical::Unresolved,
    }
}

#[cfg(not(target_arch = "wasm32"))]
thread_local! {
    /// v0.6.46 (E8): (ruta léxica absoluta, dónde está de verdad) de un archivo YA ABIERTO. Mientras
    /// dura `with_physical`, el chequeo de siempre juzga esa ruta por la ubicación real del handle,
    /// no por una segunda resolución del nombre: lo que se juzga es lo que se va a leer o escribir.
    static PHYSICAL_OVERRIDE: std::cell::RefCell<Option<(String, String)>> = const { std::cell::RefCell::new(None) };
}

#[cfg(not(target_arch = "wasm32"))]
fn overridden(abs: &str) -> Option<String> {
    PHYSICAL_OVERRIDE.with(|o| o.borrow().as_ref().filter(|(k, _)| k == abs).map(|(_, v)| v.clone()))
}

/// v0.6.46 (E8): corre `f` (el chequeo de capabilities) juzgando la ruta `req` por `real`, la
/// ubicación en disco de un handle ya abierto (sin links: la da el sistema). Restaura lo anterior.
#[cfg(not(target_arch = "wasm32"))]
pub fn with_physical<T>(req: &str, real: &str, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<(String, String)>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let prev = self.0.take();
            PHYSICAL_OVERRIDE.with(|o| *o.borrow_mut() = prev);
        }
    }
    let key = absolute_lexical(req).unwrap_or_else(|| req.to_string());
    let prev = PHYSICAL_OVERRIDE.with(|o| o.replace(Some((key, clean_verbatim(real)))));
    let _r = Restore(prev);
    f()
}

/// En wasm no hay disco que juzgar (`absolute_path` es `None` y nunca se llega acá con un handle).
#[cfg(target_arch = "wasm32")]
pub fn with_physical<T>(_req: &str, _real: &str, f: impl FnOnce() -> T) -> T {
    f()
}

/// v0.6.46 (E8): la ruta absoluta léxica (cwd + ruta normalizada, sin tocar links), con `/`: la
/// misma forma que juzga el chequeo, para abrirla sin seguir links.
#[cfg(not(target_arch = "wasm32"))]
pub fn absolute_path(p: &str) -> Option<String> {
    absolute_lexical(p)
}

#[cfg(target_arch = "wasm32")]
pub fn absolute_path(_p: &str) -> Option<String> {
    None
}

#[cfg(target_arch = "wasm32")]
pub fn physical_path(_p: &str) -> Physical {
    Physical::NoFs
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_physical(abs: String) -> Physical {
    use std::path::PathBuf;
    let mut abs = abs;
    for _ in 0..MAX_LINK_HOPS {
        let mut cur = PathBuf::from(&abs);
        let mut rest: Vec<String> = Vec::new();
        // Ok(real): el ancestro existente más profundo, ya canónico. Err(link): un link que existe
        // pero no se resuelve (roto, o un ciclo) y hay que seguir a mano.
        let step: Result<PathBuf, PathBuf> = loop {
            match std::fs::canonicalize(&cur) {
                Ok(real) => break Ok(real),
                Err(_) => match std::fs::symlink_metadata(&cur) {
                    Ok(m) if m.file_type().is_symlink() => break Err(cur.clone()),
                    // Existe y no se pudo canonizar (permiso, un dispositivo raro): no se adivina.
                    Ok(_) => return Physical::Unresolved,
                    Err(_) => {
                        let Some(name) = cur.file_name() else { return Physical::Unresolved };
                        rest.push(name.to_string_lossy().into_owned());
                        let Some(parent) = cur.parent() else { return Physical::Unresolved };
                        cur = parent.to_path_buf();
                    }
                },
            }
        };
        match step {
            Ok(real) => {
                let mut out = clean_verbatim(&real.to_string_lossy());
                for seg in rest.iter().rev() {
                    if !out.ends_with('/') {
                        out.push('/');
                    }
                    out.push_str(seg);
                }
                return Physical::Path(out);
            }
            Err(link) => {
                let Ok(raw_target) = std::fs::read_link(&link) else { return Physical::Unresolved };
                let raw_target = raw_target.to_string_lossy().into_owned();
                // Ronda 2 (M7): un destino que no es una ruta de unidad ni relativa (`\\?\Volume{…}\`,
                // un recurso de red `\\server\share`, `\\?\UNC\…`, `\\.\…`) no se interpreta: limpio
                // quedaba como un nombre relativo (`Volume{…}/`) o como `/server/share` (que en
                // Windows es `C:\server\share`) y caía "adentro" mientras el sistema abría otro lado.
                if is_foreign_target(&raw_target) {
                    return Physical::Unresolved;
                }
                let target = clean_verbatim(&raw_target);
                // Un `..` después de un nombre del destino depende de si ese nombre es a su vez un
                // link (el sistema resuelve el nombre y sube desde su destino; acá se colapsaría el
                // texto): no se adivina, ni en un destino relativo ni en uno absoluto (ronda 2, A1).
                let segs: Vec<&str> = target.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
                let first_normal = segs.iter().position(|s| *s != "..").unwrap_or(segs.len());
                if segs[first_normal..].contains(&"..") {
                    return Physical::Unresolved;
                }
                // Un destino relativo cuelga del directorio REAL del link (el padre existe: el link
                // está ahí); sus `..` del principio son léxicos de verdad sobre esa ruta canónica.
                let joined = if is_rooted(&target) {
                    target
                } else {
                    let Some(parent) = link.parent() else { return Physical::Unresolved };
                    let Ok(real_parent) = std::fs::canonicalize(parent) else { return Physical::Unresolved };
                    format!("{}/{}", clean_verbatim(&real_parent.to_string_lossy()), segs.join("/"))
                };
                let mut next = drive_root(normalize_path(&joined));
                for seg in rest.iter().rev() {
                    if !next.ends_with('/') {
                        next.push('/');
                    }
                    next.push_str(seg);
                }
                abs = next;
            }
        }
    }
    Physical::Unresolved
}

/// Ronda 2 (M7): ¿el destino de un link es algo que no se puede comparar con una ruta de unidad?
/// Un volumen sin letra (`\\?\Volume{…}\`), un dispositivo (`\\.\…`) o un recurso de red
/// (`\\server\share`, `\\?\UNC\…`). En Unix nada de esto existe y siempre da `false`.
#[cfg(not(target_arch = "wasm32"))]
fn is_foreign_target(raw: &str) -> bool {
    if !cfg!(windows) {
        return false;
    }
    let r = raw.replace('/', "\\");
    if let Some(v) = r.strip_prefix(r"\\?\") {
        // `\\?\C:\…` es una unidad; todo lo demás (`UNC\`, `Volume{`, `GLOBALROOT`…) no.
        let b = v.as_bytes();
        return !(b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':');
    }
    r.starts_with(r"\\")
}

/// Sin el prefijo verbatim de Windows (`\\?\C:\…`, `\\?\UNC\…`) y con `/`.
fn clean_verbatim(s: &str) -> String {
    let s = if let Some(unc) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{}", unc)
    } else if let Some(local) = s.strip_prefix(r"\\?\") {
        local.to_string()
    } else {
        s.to_string()
    };
    s.replace('\\', "/")
}

fn is_rooted(norm: &str) -> bool {
    norm.starts_with('/') || matches!(norm.as_bytes(), [c, b':', ..] if c.is_ascii_alphabetic())
}

/// La ruta absoluta LÉXICA (cwd + ruta normalizada, sin tocar links), con `/`. Una ruta verbatim
/// (`\\?\C:\…`) se limpia antes: si no, se normalizaba como `/?/C:/…` y no resolvía nada.
#[cfg(not(target_arch = "wasm32"))]
fn absolute_lexical(p: &str) -> Option<String> {
    let norm = normalize_path(&clean_verbatim(p));
    if is_rooted(&norm) {
        return Some(drive_root(norm));
    }
    let cwd = std::env::current_dir().ok()?;
    Some(normalize_path(&format!("{}/{}", clean_verbatim(&cwd.to_string_lossy()), norm)))
}

/// v0.6.45 — un scope de ruta en forma absoluta (cwd + scope normalizado, el patrón intacto), para
/// mandarlo a otro proceso que puede tener otro cwd (`run_program`). Sin cwd (wasm), tal cual.
pub fn absolute_scope(scope: &str) -> String {
    let norm = normalize_path(&clean_verbatim(scope));
    // Ronda 2 (B5): en Windows `/data` es "la unidad del cwd": se le pone la del padre, si no el
    // hijo con otro `cwd` (`D:/`) lo leía como `D:\data`.
    #[cfg(windows)]
    if norm.starts_with('/') && !norm.starts_with("//") {
        if let Ok(cwd) = std::env::current_dir() {
            let c = clean_verbatim(&cwd.to_string_lossy());
            if let [d, b':', ..] = c.as_bytes() {
                return format!("{}:{}", *d as char, norm);
            }
        }
    }
    if is_rooted(&norm) {
        return drive_root(norm);
    }
    match std::env::current_dir() {
        Ok(cwd) => {
            let base = clean_verbatim(&cwd.to_string_lossy());
            if norm == "." {
                normalize_path(&base)
            } else {
                normalize_path(&format!("{}/{}", base, norm))
            }
        }
        Err(_) => norm,
    }
}

/// `C:` sola es la raíz de la unidad, `C:/` (en Windows `C:` sin barra sería "el cwd de C:").
fn drive_root(s: String) -> String {
    if matches!(s.as_bytes(), [c, b':'] if c.is_ascii_alphabetic()) {
        format!("{}/", s)
    } else {
        s
    }
}

/// La parte literal de un scope (hasta el primer segmento con `*` o `?`) y el resto del patrón.
/// Un scope relativo sin parte literal (`*`, `*.csv`) se ancla en el cwd (`.`): con el glob por
/// segmentos es exactamente lo que nombra. `X:` sola es `X:/`.
fn split_scope(scope: &str) -> (String, Option<String>) {
    let norm = normalize_path(scope);
    let segs: Vec<&str> = norm.split('/').collect();
    let Some(i) = segs.iter().position(|s| s.contains(['*', '?'])) else {
        return (drive_root(norm.clone()), None);
    };
    let literal = segs[..i].join("/");
    let literal = if literal.is_empty() {
        if norm.starts_with('/') { "/".to_string() } else { ".".to_string() }
    } else {
        drive_root(literal)
    };
    (literal, Some(segs[i..].join("/")))
}

/// v0.6.45 — la forma física de un SCOPE: su parte literal resuelta en disco, con el resto del
/// patrón detrás. Un link que es parte del scope declarado vale (el grant nombra ese lugar, sea
/// cual sea); lo que está DEBAJO y sale, no. Se resuelve en cada consulta del camino lento: una
/// caché podía conceder de más si la base cambiaba de lugar.
pub fn physical_scope(scope: &str) -> Physical {
    match physical_scope_parts(scope) {
        Ok((base, None)) => Physical::Path(base),
        Ok((base, Some(p))) => Physical::Path(format!("{}/{}", base.trim_end_matches('/'), p)),
        Err(other) => other,
    }
}

/// La base física (LITERAL) del scope y el resto del patrón, por separado. Ronda 3 (N3): pegados en
/// un solo texto, un `*` o `?` en el nombre real de la base (Linux los permite) actuaba como comodín.
fn physical_scope_parts(scope: &str) -> Result<(String, Option<String>), Physical> {
    let (literal, pattern) = split_scope(scope);
    match physical_path(&literal) {
        Physical::Path(base) => Ok((base, pattern)),
        other => Err(other),
    }
}

/// Cuántos componentes debajo de la base revisa el camino rápido: cada uno es una consulta al disco
/// (~25 µs en Windows con el antivirus en el medio); el camino lento son dos `canonicalize`.
#[cfg(not(target_arch = "wasm32"))]
const FAST_PATH_DEPTH: usize = 4;

/// ¿Hay un link entre la base literal del scope y la ruta pedida? El camino rápido de
/// `path_within_physically`: si la ruta está por nombre bajo la base —byte a byte: en una carpeta
/// que distingue mayúsculas (las que crea WSL) `DATA` y `data` son dos cosas— y ninguno de los
/// componentes de DEBAJO es un link, en disco también está adentro (los links de la base misma
/// valen). Un `symlink_metadata` por componente que existe, hasta el primero que no. `None`:
/// decide el camino lento.
#[cfg(not(target_arch = "wasm32"))]
fn link_below_base(base: &str, req: &str) -> Option<bool> {
    let base = absolute_lexical(base)?;
    let req = absolute_lexical(req)?;
    let b = base.trim_end_matches('/');
    if req != b && !req.strip_prefix(b).is_some_and(|r| r.starts_with('/')) {
        return None;
    }
    let rest: Vec<&str> = req[b.len()..].split('/').filter(|s| !s.is_empty()).collect();
    if rest.len() > FAST_PATH_DEPTH {
        return None;
    }
    // La base con su barra (`C:/`, `/`) para que `push` no arme `C:x`.
    let mut cur = std::path::PathBuf::from(format!("{}/", b));
    for seg in rest {
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

#[cfg(not(target_arch = "wasm32"))]
fn has_override() -> bool {
    PHYSICAL_OVERRIDE.with(|o| o.borrow().is_some())
}

#[cfg(target_arch = "wasm32")]
fn has_override() -> bool {
    false
}

/// v0.6.45 — ¿la ruta pedida queda, en disco, dentro del scope? La otra mitad de `path_covers`
/// (que compara nombres): con un link debajo del scope que lleva afuera, por nombre está dentro y
/// en disco no. Sin disco (wasm) decide el nombre; si algo no se puede resolver, no.
pub fn path_within_physically(scope: &str, req: &str) -> bool {
    let (literal, _) = split_scope(scope);
    // v0.6.46 (E8): con la ubicación real de un handle (`with_physical`), sin el atajo por nombre.
    if !has_override() && link_below_base(&literal, req) == Some(false) {
        return true;
    }
    match (physical_scope_parts(scope), physical_path(req)) {
        (Err(Physical::NoFs), _) | (_, Physical::NoFs) => true,
        (Ok((base, pattern)), Physical::Path(r)) => physical_match(&base, pattern.as_deref(), &r),
        _ => false,
    }
}

/// v0.6.45 — para un `deny`: ¿la ruta pedida llega, en disco, a lo que el scope nombra? Un link
/// que lleva a un lugar denegado da con la denegación aunque su nombre no. Lo que no se puede
/// resolver cuenta como que llega (falla cerrado). Sin atajo: en el árbol nadie arma `deny` de
/// rutas (sólo se propagan; los usan embebedores), así que el costo no lo paga ningún programa.
pub fn path_reaches_physically(scope: &str, req: &str) -> bool {
    match (physical_scope_parts(scope), physical_path(req)) {
        (Err(Physical::NoFs), _) | (_, Physical::NoFs) => false,
        (Ok((base, pattern)), Physical::Path(r)) => physical_match(&base, pattern.as_deref(), &r),
        // Ronda 2 (N2): un `deny` cuyo lugar no se puede resolver (una unidad sin montar) no alcanza
        // por el disco a nada; por nombre sigue valiendo (`covers_by_name`). Antes negaba TODO archivo.
        (Err(_), _) => false,
        // La ruta pedida no se puede resolver: falla cerrado.
        (_, Physical::Unresolved) => true,
    }
}

/// v0.6.45 — ¿`path`, en disco, es `dir` o queda debajo de `dir`? Para la raíz de `use`: un
/// prefijo de directorio (con límite en `/`), no un glob. Sin disco (wasm) → `true`: decide la
/// comparación por nombre que ya se hizo; si no se puede resolver, `false`.
pub fn physically_beneath(dir: &str, path: &str) -> bool {
    let (d, p) = match (physical_path(dir), physical_path(path)) {
        (Physical::NoFs, _) | (_, Physical::NoFs) => return true,
        (Physical::Path(d), Physical::Path(p)) => (d, p),
        _ => return false,
    };
    #[cfg(any(windows, target_os = "macos"))]
    let (d, p) = (d.to_lowercase(), p.to_lowercase());
    let d = d.trim_end_matches('/');
    p == d || p.strip_prefix(d).is_some_and(|rest| rest.starts_with('/'))
}

/// ¿La ruta física `r` queda bajo la base literal `base` y su resto coincide con `pattern`? La base
/// se compara como prefijo LITERAL (con límite en `/`); el glob sólo se aplica al resto.
fn physical_match(base: &str, pattern: Option<&str>, r: &str) -> bool {
    #[cfg(any(windows, target_os = "macos"))]
    let (base, r, pattern) = (base.to_lowercase(), r.to_lowercase(), pattern.map(str::to_lowercase));
    #[cfg(not(any(windows, target_os = "macos")))]
    let pattern = pattern.map(str::to_string);
    let b = base.trim_end_matches('/');
    let rest = if r == b {
        ""
    } else {
        match r.strip_prefix(b) {
            Some(rest) if rest.starts_with('/') || b.is_empty() => rest.trim_start_matches('/'),
            _ => return false,
        }
    };
    match pattern {
        None => rest.is_empty(),
        Some(p) => path_glob(rest, &p),
    }
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
        std::fs::create_dir_all(d.join("data/a/b/c/e")).unwrap();
        let deep = |p: &str| {
            let f = format!("{}/data/{}", r, p);
            std::fs::write(&f, "hola
").unwrap();
            f
        };
        let (f3, f4, f5) = (deep("a/b/x.txt"), deep("a/b/c/x.txt"), deep("a/b/c/e/x.txt"));
        let grant2 = format!("{}/data/**", r);
        let c3 = time(&|| assert!(super::path_within_physically(&grant2, &f3)));
        let c4 = time(&|| assert!(super::path_within_physically(&grant2, &f4)));
        let c5 = time(&|| assert!(super::path_within_physically(&grant2, &f5)));
        println!("read_to_string {:.1} us | check depth 1 {:.1} us | check depth 2 {:.1} us", read, check1, check2);
        println!("depth 3 {:.1} us | depth 4 {:.1} us | depth 5 (camino lento) {:.1} us", c3, c4, c5);
        let _ = std::fs::remove_dir_all(&d);
    }
}

// ---------------------------------------------------------------------------------------------
// v0.6.46 (E1): los hosts de un secret atado (`require secret("K") for net("h")`). Viven acá, con
// el resto de los scopes, porque los usan core (`+` de dos secrets atados), el modelo de
// capabilities (el techo `secret=K@h`) y stdlib (cada request).

/// `host` o `host:puerto` → `(host, puerto)`; `[::1]:8545` lleva puerto y `::1` no. La misma
/// partición que `split_net_scope` del modelo.
pub fn split_host_port(scope: &str) -> (&str, Option<&str>) {
    if let Some(inner) = scope.strip_prefix('[') {
        if let Some((h, after)) = inner.split_once(']') {
            return (h, after.strip_prefix(':').filter(|p| !p.is_empty()));
        }
    }
    match scope.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (h, Some(p)),
        _ => (scope, None),
    }
}

/// El scope de `net` que nombra un texto, como lo guarda `Capability::new`: de una URL, su host (y
/// el puerto si lo escribe), sin credenciales, ruta ni query; un host suelto, en minúsculas.
pub fn net_host_scope(s: &str) -> String {
    if let Some((_, rest)) = s.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let hostport = authority.rsplit('@').next().unwrap_or("");
        let (h, p) = split_host_port(hostport);
        let h = h.to_lowercase();
        if h.is_empty() {
            return "<no host>".to_string();
        }
        return match p {
            Some(p) if h.contains(':') => format!("[{}]:{}", h, p),
            Some(p) => format!("{}:{}", h, p),
            None => h,
        };
    }
    if s.starts_with('[') && s.ends_with(']') {
        return s[1..s.len() - 1].to_lowercase();
    }
    s.to_lowercase()
}

/// ¿El host de una atadura (`api.x.com`, `*.x.com`, con puerto opcional) cubre el destino
/// `host[:puerto]`? El destino también puede ser un patrón (al intersectar dos ataduras o
/// comparar con el techo): `*.x.com` cubre `*.y.x.com`. Sin puerto en la atadura, cualquier
/// puerto; con puerto, sólo ese.
pub fn bound_host_covers(pattern: &str, dest: &str) -> bool {
    let (ph, pp) = split_host_port(pattern);
    let (dh, dp) = split_host_port(dest);
    let host_ok = ph == dh || (ph.starts_with("*.") && dh.len() > ph.len() - 1 && dh.ends_with(&ph[1..]));
    host_ok && (pp.is_none() || pp == dp)
}

/// La gramática de un host de atadura, más estricta que la de `net`: un host exacto o
/// `*.dominio` (el `*` sólo como primera etiqueta entera), con puerto opcional. `None` si vale.
pub fn bound_host_error(h: &str) -> Option<String> {
    let (host, _) = split_host_port(h);
    if host.is_empty() || host == "<no host>" {
        return Some(format!("{:?} has no host", h));
    }
    if host == "*" || host == "*." {
        return Some("binding a secret to every host is not binding it: name the host it goes to".to_string());
    }
    let rest = host.strip_prefix("*.").unwrap_or(host);
    if rest.contains('*') || rest.contains('?') || rest.contains('[') {
        return Some(format!(
            "{:?}: a `*` may only be the whole first label (`*.example.com`), and nowhere else",
            h
        ));
    }
    if host.starts_with("*.") && !rest.contains('.') {
        return Some(format!("{:?}: `*.{}` would cover a whole top-level domain; name the domain", h, rest));
    }
    None
}

/// Los destinos que cubren las dos ataduras a la vez (para `+` de dos secrets atados): un host de
/// una que la otra cubre. Vacío = ninguna request puede llevar a los dos.
pub fn intersect_bound(a: &[String], b: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for h in a.iter().filter(|h| b.iter().any(|p| bound_host_covers(p, h))) {
        if !out.contains(h) {
            out.push(h.clone());
        }
    }
    for h in b.iter().filter(|h| a.iter().any(|p| bound_host_covers(p, h))) {
        if !out.contains(h) {
            out.push(h.clone());
        }
    }
    out
}

#[cfg(test)]
mod bound_tests {
    use super::*;

    #[test]
    fn bound_hosts_cover_and_intersect() {
        assert!(bound_host_covers("api.x.com", "api.x.com"));
        assert!(!bound_host_covers("api.x.com", "evil.com"));
        assert!(!bound_host_covers("api.x.com", "api.x.com.evil.com"));
        assert!(bound_host_covers("*.x.com", "a.b.x.com"));
        assert!(!bound_host_covers("*.x.com", "x.com"));
        assert!(!bound_host_covers("*.x.com", "evilx.com"));
        assert!(bound_host_covers("localhost:8545", "localhost:8545"));
        assert!(!bound_host_covers("localhost:8545", "localhost:9000"));
        assert!(bound_host_covers("localhost", "localhost:9000"));
        assert!(bound_host_covers("*.x.com", "*.y.x.com"));
        assert!(!bound_host_covers("a.x.com", "*.x.com"));
        let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(intersect_bound(&v(&["a.x.com", "b.com"]), &v(&["*.x.com"])), v(&["a.x.com"]));
        assert!(intersect_bound(&v(&["a.com"]), &v(&["b.com"])).is_empty());
        assert!(bound_host_error("*").is_some());
        assert!(bound_host_error("a*.x.com").is_some());
        assert!(bound_host_error("*.com").is_some());
        assert!(bound_host_error("*.x.com").is_none());
        assert!(bound_host_error("api.x.com:443").is_none());
    }
}

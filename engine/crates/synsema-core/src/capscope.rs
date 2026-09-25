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

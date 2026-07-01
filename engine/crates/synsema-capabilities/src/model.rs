//! Modelo de capabilities de Synsema.
//!
//! Port fiel de `synsema/capabilities/model.py`. Las capabilities son la base de
//! seguridad: cero acceso por defecto, grants explícitos y con scope, auditados.

use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt;
use std::rc::Rc;

/// Categorías de capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CapabilityType {
    Net,
    FileRead,
    FileWrite,
    File,
    Exec,
    Env,
    Time,
    Random,
    Stdout,
    Stdin,
    Llm,
    Db,
    Serve,
    /// Leer una variable como `secret` (valor opaco tainted). Scope = nombre/prefijo.
    Secret,
    /// Habilita `reveal()` (extraer plaintext de un secret). Coarse, sin scope.
    Reveal,
}

impl CapabilityType {
    /// Nombre lowercase, como `CapabilityType.NAME.lower()` de Python (para Display).
    /// Nota: `FILE_READ` → "file_read" (guión bajo), aunque se parsea como "file.read".
    pub fn name_lower(&self) -> &'static str {
        use CapabilityType::*;
        match self {
            Net => "net",
            FileRead => "file_read",
            FileWrite => "file_write",
            File => "file",
            Exec => "exec",
            Env => "env",
            Time => "time",
            Random => "random",
            Stdout => "stdout",
            Stdin => "stdin",
            Llm => "llm",
            Db => "db",
            Serve => "serve",
            Secret => "secret",
            Reveal => "reveal",
        }
    }
}

/// Mapa nombre→tipo (CAPABILITY_NAMES del oráculo).
pub fn capability_type_from_name(name: &str) -> Option<CapabilityType> {
    use CapabilityType::*;
    Some(match name {
        "net" => Net,
        "file" => File,
        "file.read" => FileRead,
        "file.write" => FileWrite,
        "exec" => Exec,
        "env" => Env,
        "time" => Time,
        "random" => Random,
        "stdout" => Stdout,
        "stdin" => Stdin,
        "llm" => Llm,
        "db" => Db,
        "serve" => Serve,
        "secret" => Secret,
        "reveal" => Reveal,
        _ => return None,
    })
}

/// Una capability concreta: tipo + scope opcional.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Capability {
    pub ty: CapabilityType,
    pub scope: Option<String>,
}

impl Capability {
    pub fn new(ty: CapabilityType, scope: Option<String>) -> Self {
        Self { ty, scope }
    }

    /// ¿Este grant cubre la capability pedida?
    /// - Mismo tipo (salvo FILE que cubre FILE_READ/FILE_WRITE).
    /// - scope None = wildcard total.
    /// - self con scope y other con scope None → no cubre.
    /// - match exacto o glob (`*.example.com` cubre `api.example.com`).
    pub fn covers(&self, other: &Capability) -> bool {
        if self.ty != other.ty {
            let file_covers = self.ty == CapabilityType::File
                && matches!(other.ty, CapabilityType::FileRead | CapabilityType::FileWrite);
            if !file_covers {
                return false;
            }
        }
        // Para capacidades cuyo scope es una RUTA o URL (file/file.read/file.write y db),
        // canonizar AMBOS scopes antes de comparar. file: ruta léxica (cierra el bypass
        // `..`). db: si el scope es una URL (`postgres://…`) → `canon_url` (scheme/host/db,
        // sin credenciales/puerto); si es ruta (SQLite) → `normalize_path`. Así
        // `db("postgres://localhost/appdb")` cubre el connstring completo, y una grant de
        // ruta nunca cubre una URL (canónicos distintos). Centralizado acá (un solo punto).
        let is_path = matches!(
            self.ty,
            CapabilityType::File
                | CapabilityType::FileRead
                | CapabilityType::FileWrite
                | CapabilityType::Db
        );
        let is_db = self.ty == CapabilityType::Db;
        let canon = |s: &str| -> String {
            if is_db && s.contains("://") {
                canon_url(s)
            } else {
                normalize_path(s)
            }
        };
        match &self.scope {
            // Sin scope = grant wildcard (poder máximo: cubre cualquier ruta/URL). Intacto.
            None => true,
            Some(self_scope) => match &other.scope {
                // self tiene scope, other None → no cubre (paridad con Python).
                None => false,
                Some(other_scope) => {
                    if is_path {
                        let grant = canon(self_scope);
                        let req = canon(other_scope);
                        grant == req || fnmatch(&req, &grant)
                    } else {
                        self_scope == other_scope || fnmatch(other_scope, self_scope)
                    }
                }
            },
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Python usa `if self.scope:` (truthy) → scope vacío se trata como sin scope.
        match &self.scope {
            Some(s) if !s.is_empty() => write!(f, "{}(\"{}\")", self.ty.name_lower(), s),
            _ => write!(f, "{}", self.ty.name_lower()),
        }
    }
}

/// Canoniza una URL de conexión (Postgres/MySQL/…) a `scheme://host/dbname`:
/// minúsculas, **sin credenciales** (userinfo), **sin puerto**, **sin query/fragment**.
/// Es el scope canónico de la capability `db` para motores remotos (el `://` lo distingue
/// de una ruta de archivo SQLite). Preserva un `*` como nombre/host para los globs
/// (`db("postgres://localhost/*")`). Idempotente.
pub fn canon_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r),
        None => return url.to_lowercase(),
    };
    // sin query/fragment
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    // authority / path
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, p),
        None => (rest, ""),
    };
    // sin userinfo (user:pw@)
    let host_port = match authority.rsplit_once('@') {
        Some((_, hp)) => hp,
        None => authority,
    };
    // sin puerto (último `:`; no se contemplan IPv6 con corchetes — caso raro)
    let host = match host_port.rsplit_once(':') {
        Some((h, _)) => h,
        None => host_port,
    }
    .to_lowercase();
    // dbname = primer segmento del path
    let db = path.split('/').next().unwrap_or("").to_lowercase();
    if db.is_empty() {
        format!("{}://{}", scheme, host)
    } else {
        format!("{}://{}/{}", scheme, host, db)
    }
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

/// Normaliza una ruta de forma LÉXICA (sin tocar el filesystem): unifica separadores
/// a `/`, colapsa `.` y `..`, quita un `./` inicial. NO resuelve symlinks ni vuelve la
/// ruta absoluta (preserva relativa/absoluta y el prefijo de unidad Windows). Así el
/// scope-glob de `file.read("./data/*")` se chequea contra la ruta REAL a la que apunta
/// el argumento, cerrando el bypass `./data/../../etc` sin cambiar la semántica del scope.
pub fn normalize_path(p: &str) -> String {
    let p = p.replace('\\', "/");
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

/// Registro de un chequeo de capability (audit trail).
#[derive(Clone, Debug)]
pub struct CapabilityAuditEntry {
    pub capability: Capability,
    pub granted: bool,
    pub source: String,
    pub reason: String,
}

/// Conjunto de capabilities otorgadas, con audit trail. Cada contexto de ejecución
/// (global, sandbox, agente) tiene el suyo.
pub struct CapabilitySet {
    pub name: String,
    pub granted: HashSet<Capability>,
    pub denied: HashSet<Capability>,
    pub audit_log: Vec<CapabilityAuditEntry>,
    pub parent: Option<Rc<RefCell<CapabilitySet>>>,
    /// Techo de capabilities impuesto por el HOST (`--sandbox`/`--cap-set`): un grant sólo
    /// se concede si ALGUNA de estas capabilities lo cubre (fail-closed). `None` = sin techo
    /// (comportamiento por defecto, byte-idéntico a antes). El techo sólo RESTA, nunca
    /// amplía: `caps_efectivas ⊆ require ∩ techo`. Se propaga (`Rc::clone`, barato) a todo
    /// set derivado (hijo/sandbox/worker/agente) para que su `grant()`/`check()` lo honren.
    pub ceiling: Option<Rc<Vec<Capability>>>,
}

impl CapabilitySet {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            granted: HashSet::new(),
            denied: HashSet::new(),
            audit_log: Vec::new(),
            parent: None,
            ceiling: None,
        }
    }

    /// ¿La capability cae DENTRO del techo del host? Reusa el mismo `covers()` que gate los
    /// `require` (misma canonización de rutas/URLs, mismo cierre de bypass `..`/glob), así no
    /// hay una segunda lógica de scopes que pueda divergir. Sin techo (`None`) → siempre true.
    fn within_ceiling(&self, cap: &Capability) -> bool {
        match &self.ceiling {
            None => true,
            Some(c) => c.iter().any(|allowed| allowed.covers(cap)),
        }
    }

    pub fn grant(&mut self, capability: Capability) {
        // Fail-closed: si el host puso un techo y no cubre esta capability, NO se inserta
        // (el techo nunca amplía). Se audita el rechazo. Sin techo → inserta como siempre.
        if !self.within_ceiling(&capability) {
            self.audit_log.push(CapabilityAuditEntry {
                capability,
                granted: false,
                source: "ceiling".to_string(),
                reason: "above host ceiling (--sandbox/--cap-set)".to_string(),
            });
            return;
        }
        self.granted.insert(capability);
    }

    /// Deniega explícitamente (sobrescribe grants).
    pub fn deny(&mut self, capability: Capability) {
        self.denied.insert(capability);
    }

    /// ¿Está permitida? True si otorgada y no denegada. Cada chequeo se audita.
    pub fn check(&mut self, requested: &Capability, source: &str) -> bool {
        // 1) Denegaciones explícitas primero.
        let denied_by: Option<Capability> =
            self.denied.iter().find(|d| d.covers(requested)).cloned();
        if let Some(d) = denied_by {
            self.audit_log.push(CapabilityAuditEntry {
                capability: requested.clone(),
                granted: false,
                source: source.to_string(),
                reason: format!("Explicitly denied by {}", d),
            });
            return false;
        }

        // 1.5) Techo del host (defense-in-depth, autoritativo): un USO por encima del techo
        // se deniega SIEMPRE, aunque un grant (propio o heredado del padre) lo cubriera.
        // `grant()` ya evita insertar por encima del techo; esto cierra cualquier fuga de un
        // set derivado que hubiera colado un grant. Sólo corre si hay techo (`is_some`) → el
        // hot-path por defecto (`ceiling = None`) no paga nada.
        if self.ceiling.is_some() && !self.within_ceiling(requested) {
            self.audit_log.push(CapabilityAuditEntry {
                capability: requested.clone(),
                granted: false,
                source: source.to_string(),
                reason: "Above host ceiling (--sandbox/--cap-set)".to_string(),
            });
            return false;
        }

        // 2) Grants.
        let granted_by: Option<Capability> =
            self.granted.iter().find(|c| c.covers(requested)).cloned();
        if let Some(c) = granted_by {
            self.audit_log.push(CapabilityAuditEntry {
                capability: requested.clone(),
                granted: true,
                source: source.to_string(),
                reason: format!("Granted by {}", c),
            });
            return true;
        }

        // 3) Padre (su check audita en el padre).
        if let Some(parent) = self.parent.clone() {
            if parent.borrow_mut().check(requested, source) {
                return true;
            }
        }

        // 4) Sin grant.
        self.audit_log.push(CapabilityAuditEntry {
            capability: requested.clone(),
            granted: false,
            source: source.to_string(),
            reason: "No matching grant found".to_string(),
        });
        false
    }

    /// Chequea y devuelve error si no está otorgada.
    pub fn require(&mut self, requested: &Capability, source: &str) -> Result<(), CapabilityViolation> {
        if !self.check(requested, source) {
            return Err(CapabilityViolation {
                message: format!("Capability not granted: {}", requested),
                requested: Some(requested.clone()),
                source: source.to_string(),
            });
        }
        Ok(())
    }

    /// Crea un hijo que SÍ hereda del padre (cadena de scopes). El techo del host se
    /// PROPAGA al hijo (`Rc::clone`): un contexto derivado jamás excede el techo.
    pub fn create_child(parent: &Rc<RefCell<CapabilitySet>>, name: &str) -> CapabilitySet {
        CapabilitySet {
            name: name.to_string(),
            granted: HashSet::new(),
            denied: HashSet::new(),
            audit_log: Vec::new(),
            parent: Some(parent.clone()),
            ceiling: parent.borrow().ceiling.clone(),
        }
    }

    /// Crea un sandbox restringido que NO hereda: sólo los grants explícitos.
    /// (Ignora `self`, igual que el oráculo.) El techo del host SÍ se propaga (`Rc::clone`):
    /// el sandbox nunca puede conceder por encima del techo, aunque el grant sea explícito.
    pub fn create_sandbox(&self, name: &str, allowed: &[Capability]) -> CapabilitySet {
        let mut sandbox = CapabilitySet::new(&format!("sandbox:{}", name));
        sandbox.ceiling = self.ceiling.clone();
        for cap in allowed {
            sandbox.grant(cap.clone());
        }
        sandbox
    }

    pub fn get_audit_report(&self) -> String {
        let mut lines = vec![
            format!("Capability Audit Report: {}", self.name),
            format!("  Grants: {}", self.granted.len()),
            format!("  Denials: {}", self.denied.len()),
            format!("  Checks: {}", self.audit_log.len()),
            String::new(),
        ];
        for entry in &self.audit_log {
            let status = if entry.granted { "GRANTED" } else { "DENIED" };
            lines.push(format!("  [{}] {} at {}", status, entry.capability, entry.source));
            lines.push(format!("    Reason: {}", entry.reason));
        }
        lines.join("\n")
    }
}

/// Error al usar una capability no otorgada.
#[derive(Debug, Clone)]
pub struct CapabilityViolation {
    pub message: String,
    pub requested: Option<Capability>,
    pub source: String,
}

impl fmt::Display for CapabilityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CapabilityViolation {}

/// Parsea una capability desde nombre + scope opcional.
pub fn parse_capability(name: &str, scope: Option<&str>) -> Result<Capability, String> {
    match capability_type_from_name(name) {
        Some(ty) => Ok(Capability::new(ty, scope.map(|s| s.to_string()))),
        None => Err(format!(
            "Unknown capability type: '{}'. Known: [net, file, file.read, file.write, exec, env, time, random, stdout, stdin, llm, db, serve, secret, reveal]",
            name
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(ty: CapabilityType, scope: Option<&str>) -> Capability {
        Capability::new(ty, scope.map(|s| s.to_string()))
    }

    #[test]
    fn capability_creation() {
        let c = parse_capability("net", Some("api.example.com")).unwrap();
        assert_eq!(c.ty, CapabilityType::Net);
        assert_eq!(c.scope.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn capability_covers_exact() {
        let c = cap(CapabilityType::Net, Some("api.example.com"));
        let r = cap(CapabilityType::Net, Some("api.example.com"));
        assert!(c.covers(&r));
    }

    #[test]
    fn capability_covers_wildcard() {
        let c = cap(CapabilityType::Net, Some("*.example.com"));
        let r = cap(CapabilityType::Net, Some("api.example.com"));
        assert!(c.covers(&r));
    }

    #[test]
    fn capability_covers_none_scope() {
        let c = cap(CapabilityType::Net, None);
        let r = cap(CapabilityType::Net, Some("anything.com"));
        assert!(c.covers(&r));
    }

    #[test]
    fn capability_file_covers_read_write() {
        let c = cap(CapabilityType::File, Some("/data/*"));
        let read = cap(CapabilityType::FileRead, Some("/data/report.csv"));
        let write = cap(CapabilityType::FileWrite, Some("/data/output.csv"));
        assert!(c.covers(&read));
        assert!(c.covers(&write));
    }

    #[test]
    fn normalize_path_is_identity_on_normal_paths() {
        // Idempotencia / back-compat: rutas ya normales quedan igual.
        assert_eq!(normalize_path("/tmp/x.txt"), "/tmp/x.txt");
        assert_eq!(normalize_path("/data/*"), "/data/*");
        assert_eq!(normalize_path("data/report.csv"), "data/report.csv");
        assert_eq!(normalize_path("C:/data/x.txt"), "C:/data/x.txt");
    }

    #[test]
    fn normalize_path_collapses_dots_and_separators() {
        assert_eq!(normalize_path("./data/x"), "data/x");
        assert_eq!(normalize_path("data/./x"), "data/x");
        assert_eq!(normalize_path("data\\sub\\x"), "data/sub/x"); // separadores Windows
        assert_eq!(normalize_path("./data/../../etc/passwd"), "../etc/passwd");
        // ".." no sube de una raíz absoluta.
        assert_eq!(normalize_path("/data/../../etc"), "/etc");
        assert_eq!(normalize_path("C:/data/../x"), "C:/x");
        // ruta relativa vacía → "."
        assert_eq!(normalize_path("./"), ".");
    }

    #[test]
    fn covers_closes_traversal_bypass() {
        // El caso estrella del fix #5: scope acotado ya NO se escapa con `..`.
        let grant = cap(CapabilityType::FileRead, Some("./data/*"));
        let ok = cap(CapabilityType::FileRead, Some("./data/report.csv"));
        let escape = cap(CapabilityType::FileRead, Some("./data/../../etc/passwd"));
        assert!(grant.covers(&ok), "ruta dentro del scope debe cubrirse");
        assert!(!grant.covers(&escape), "el bypass `..` debe quedar fuera del scope");

        // Poder total preservado: wildcard cubre cualquier ruta, con o sin `..`.
        let star = cap(CapabilityType::FileRead, Some("*"));
        assert!(star.covers(&escape));
        let total = cap(CapabilityType::File, None);
        assert!(total.covers(&escape));
    }

    #[test]
    fn canon_url_strips_credentials_port_query_case() {
        assert_eq!(
            canon_url("postgres://user:pw@Localhost:5432/AppDB?sslmode=require"),
            "postgres://localhost/appdb"
        );
        assert_eq!(canon_url("postgresql://h/db"), "postgresql://h/db");
        assert_eq!(canon_url("postgres://localhost/*"), "postgres://localhost/*");
        assert_eq!(canon_url("postgres://*"), "postgres://*");
        // idempotente
        assert_eq!(canon_url("postgres://localhost/appdb"), "postgres://localhost/appdb");
    }

    #[test]
    fn covers_db_url_branch() {
        // grant URL (sin credenciales) cubre el connstring completo del db_open.
        let grant = cap(CapabilityType::Db, Some("postgres://localhost/appdb"));
        let req = cap(CapabilityType::Db, Some("postgres://user:pw@localhost:5432/appdb"));
        assert!(grant.covers(&req), "grant URL debe cubrir el connstring completo");

        // no cubre otra base.
        let other = cap(CapabilityType::Db, Some("postgres://localhost/otra"));
        assert!(!grant.covers(&other));

        // globs de host/base.
        let any_db = cap(CapabilityType::Db, Some("postgres://localhost/*"));
        assert!(any_db.covers(&req));
        let any_pg = cap(CapabilityType::Db, Some("postgres://*"));
        assert!(any_pg.covers(&req));

        // db("*") y `require db` (None) cubren URL y ruta.
        let star = cap(CapabilityType::Db, Some("*"));
        assert!(star.covers(&req));
        assert!(star.covers(&cap(CapabilityType::Db, Some("./store.db"))));
        let total = cap(CapabilityType::Db, None);
        assert!(total.covers(&req));

        // una grant de RUTA no cubre una URL y viceversa.
        let path_grant = cap(CapabilityType::Db, Some("./data/*"));
        assert!(!path_grant.covers(&req));
        let url_grant = cap(CapabilityType::Db, Some("postgres://localhost/*"));
        assert!(!url_grant.covers(&cap(CapabilityType::Db, Some("./data/x.db"))));
    }

    #[test]
    fn capability_does_not_cover_different_type() {
        let c = cap(CapabilityType::Net, Some("example.com"));
        let r = cap(CapabilityType::File, Some("example.com"));
        assert!(!c.covers(&r));
    }

    #[test]
    fn capability_set_grant_check() {
        let mut cs = CapabilitySet::new("test");
        cs.grant(cap(CapabilityType::Net, Some("api.example.com")));
        assert!(cs.check(&cap(CapabilityType::Net, Some("api.example.com")), ""));
        assert!(!cs.check(&cap(CapabilityType::Net, Some("evil.com")), ""));
    }

    #[test]
    fn capability_set_deny_overrides_grant() {
        let mut cs = CapabilitySet::new("test");
        cs.grant(cap(CapabilityType::Net, Some("*.example.com")));
        cs.deny(cap(CapabilityType::Net, Some("secret.example.com")));
        assert!(cs.check(&cap(CapabilityType::Net, Some("api.example.com")), ""));
        assert!(!cs.check(&cap(CapabilityType::Net, Some("secret.example.com")), ""));
    }

    #[test]
    fn capability_set_parent_inheritance() {
        let parent = Rc::new(RefCell::new(CapabilitySet::new("parent")));
        parent.borrow_mut().grant(cap(CapabilityType::Time, None));
        let mut child = CapabilitySet::create_child(&parent, "child");
        assert!(child.check(&cap(CapabilityType::Time, None), ""));
    }

    #[test]
    fn capability_sandbox_no_inheritance() {
        let mut parent = CapabilitySet::new("parent");
        parent.grant(cap(CapabilityType::Net, None));
        let mut sandbox = parent.create_sandbox("restricted", &[]);
        // El sandbox NO hereda las capabilities del padre.
        assert!(!sandbox.check(&cap(CapabilityType::Net, Some("example.com")), ""));
    }

    #[test]
    fn capability_sandbox_explicit_grants() {
        let parent = CapabilitySet::new("parent");
        let mut sandbox = parent.create_sandbox("restricted", &[cap(CapabilityType::Stdout, None)]);
        assert!(sandbox.check(&cap(CapabilityType::Stdout, None), ""));
        assert!(!sandbox.check(&cap(CapabilityType::Net, Some("anything")), ""));
    }

    #[test]
    fn capability_audit_trail() {
        let mut cs = CapabilitySet::new("test");
        cs.grant(cap(CapabilityType::Net, Some("example.com")));
        cs.check(&cap(CapabilityType::Net, Some("example.com")), "test:1");
        cs.check(&cap(CapabilityType::Net, Some("evil.com")), "test:2");
        assert_eq!(cs.audit_log.len(), 2);
        assert!(cs.audit_log[0].granted);
        assert!(!cs.audit_log[1].granted);
    }

    // ---- Techo del host (--sandbox / --cap-set) ----

    fn ceil(caps: Vec<Capability>) -> Option<Rc<Vec<Capability>>> {
        Some(Rc::new(caps))
    }

    #[test]
    fn ceiling_none_is_identity() {
        // Regresión cero: sin techo, grant/check son idénticos a antes.
        let mut cs = CapabilitySet::new("test");
        assert!(cs.ceiling.is_none());
        cs.grant(cap(CapabilityType::Exec, None));
        assert!(cs.check(&cap(CapabilityType::Exec, Some("ls")), ""));
    }

    #[test]
    fn ceiling_blocks_grant_above_it() {
        // --sandbox ≡ techo [stdout, time]: un grant de exec NO se concede (ni se inserta).
        let mut cs = CapabilitySet::new("program");
        cs.ceiling = ceil(vec![
            cap(CapabilityType::Stdout, None),
            cap(CapabilityType::Time, None),
        ]);
        cs.grant(cap(CapabilityType::Exec, None)); // require exec("...")
        assert!(!cs.check(&cap(CapabilityType::Exec, Some("ls")), ""), "exec fuera del techo");
        assert!(cs.granted.is_empty(), "no se inserta por encima del techo");
        // stdout/time SÍ (están en el techo).
        cs.grant(cap(CapabilityType::Stdout, None));
        cs.grant(cap(CapabilityType::Time, None));
        assert!(cs.check(&cap(CapabilityType::Stdout, None), ""));
        assert!(cs.check(&cap(CapabilityType::Time, None), ""));
    }

    #[test]
    fn ceiling_check_is_authoritative_even_if_granted_leaks() {
        // Red de seguridad: aunque un set derivado cuele un grant DIRECTO por encima del
        // techo (evitando grant()), el USO se deniega en check().
        let mut cs = CapabilitySet::new("leaky");
        cs.ceiling = ceil(vec![cap(CapabilityType::Stdout, None)]);
        cs.granted.insert(cap(CapabilityType::Exec, None)); // fuga: insert directo
        assert!(!cs.check(&cap(CapabilityType::Exec, Some("rm")), ""), "check autoritativo");
    }

    #[test]
    fn ceiling_blocks_scope_escalation() {
        // --cap-set "net=api.mock.test" + require net("*") → net("*") NO se concede (el
        // techo no lo cubre); ningún fetch supera el techo.
        let mut cs = CapabilitySet::new("program");
        cs.ceiling = ceil(vec![cap(CapabilityType::Net, Some("api.mock.test"))]);
        cs.grant(cap(CapabilityType::Net, Some("*"))); // wildcard: no lo cubre el techo
        assert!(!cs.check(&cap(CapabilityType::Net, Some("evil.com")), ""));
        assert!(!cs.check(&cap(CapabilityType::Net, Some("api.mock.test")), ""), "ni el propio host, no se concedió nada");
        // En cambio, un require ACOTADO al techo sí funciona.
        cs.grant(cap(CapabilityType::Net, Some("api.mock.test")));
        assert!(cs.check(&cap(CapabilityType::Net, Some("api.mock.test")), ""));
    }

    #[test]
    fn ceiling_db_scoped_blocks_other_paths() {
        // --cap-set "db=:memory:": db(:memory:) OK; cualquier otra ruta/URL denegada.
        let mut cs = CapabilitySet::new("program");
        cs.ceiling = ceil(vec![cap(CapabilityType::Db, Some(":memory:"))]);
        cs.grant(cap(CapabilityType::Db, Some(":memory:")));
        assert!(cs.check(&cap(CapabilityType::Db, Some(":memory:")), ""));
        // require db("./real.db") por encima del techo → no se concede.
        cs.grant(cap(CapabilityType::Db, Some("./real.db")));
        assert!(!cs.check(&cap(CapabilityType::Db, Some("./real.db")), ""));
        // require db (wildcard, sin scope) tampoco escala.
        cs.grant(cap(CapabilityType::Db, None));
        assert!(!cs.check(&cap(CapabilityType::Db, Some("./real.db")), ""));
    }

    #[test]
    fn ceiling_propagates_to_child() {
        let parent = Rc::new(RefCell::new(CapabilitySet::new("parent")));
        parent.borrow_mut().ceiling = ceil(vec![cap(CapabilityType::Stdout, None)]);
        let mut child = CapabilitySet::create_child(&parent, "child");
        assert!(child.ceiling.is_some());
        child.grant(cap(CapabilityType::Exec, None));
        assert!(!child.check(&cap(CapabilityType::Exec, Some("ls")), ""), "el hijo hereda el techo");
    }

    #[test]
    fn ceiling_propagates_to_sandbox() {
        let mut parent = CapabilitySet::new("parent");
        parent.ceiling = ceil(vec![cap(CapabilityType::Stdout, None)]);
        // Grant explícito de exec al sandbox: aun así el techo lo bloquea.
        let mut sandbox = parent.create_sandbox("restricted", &[cap(CapabilityType::Exec, None)]);
        assert!(sandbox.ceiling.is_some());
        assert!(!sandbox.check(&cap(CapabilityType::Exec, Some("ls")), ""), "el sandbox nunca excede el techo");
    }
}

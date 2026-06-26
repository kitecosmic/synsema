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
        match &self.scope {
            // Sin scope = grant wildcard.
            None => true,
            Some(self_scope) => match &other.scope {
                // self tiene scope, other None → no cubre (paridad con Python).
                None => false,
                Some(other_scope) => {
                    self_scope == other_scope || fnmatch(other_scope, self_scope)
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

/// `fnmatch` estilo Unix (case-sensitive, como el oráculo en Linux). Soporta `*`
/// (cero o más) y `?` (uno). Los corchetes `[...]` se tratan literales (no aparecen
/// en scopes de capability; el contrato sólo exige `*`).
fn fnmatch(name: &str, pattern: &str) -> bool {
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
}

impl CapabilitySet {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            granted: HashSet::new(),
            denied: HashSet::new(),
            audit_log: Vec::new(),
            parent: None,
        }
    }

    pub fn grant(&mut self, capability: Capability) {
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

    /// Crea un hijo que SÍ hereda del padre (cadena de scopes).
    pub fn create_child(parent: &Rc<RefCell<CapabilitySet>>, name: &str) -> CapabilitySet {
        CapabilitySet {
            name: name.to_string(),
            granted: HashSet::new(),
            denied: HashSet::new(),
            audit_log: Vec::new(),
            parent: Some(parent.clone()),
        }
    }

    /// Crea un sandbox restringido que NO hereda: sólo los grants explícitos.
    /// (Ignora `self`, igual que el oráculo.)
    pub fn create_sandbox(&self, name: &str, allowed: &[Capability]) -> CapabilitySet {
        let mut sandbox = CapabilitySet::new(&format!("sandbox:{}", name));
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
}

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
    /// Habilita FIRMAR con una clave privada (secp256k1/ed25519). La operación más
    /// peligrosa del lenguaje (autoriza movimiento de valor): deny-by-default, con
    /// scope al NAME del secret de la clave (como `Reveal` scoped) y audit fail-loud.
    /// Nunca es ambiente. Batch 11 (blockchain).
    Sign,
    /// Habilita CREAR CUSTODIA: generar/derivar/importar material de clave (mnemónicos
    /// BIP-39, seeds, claves HD, keystores). No mueve valor (eso sigue siendo `Sign`),
    /// pero crea claves que lo moverán: deny-by-default, con scope al NAME del secret
    /// de origen (o al label del secret nuevo al generar) y audit fail-loud en
    /// `wallet.log`. Nunca es ambiente. Batch 13 (G20).
    Wallet,
    /// Registrar un GASTO externo (`spend(monto, unidad, motivo)`, FRAMEWORK F1). No
    /// mueve valor por sí misma (eso lo hace el PSP/exchange del programa), pero es la
    /// declaración auditada de que se va a mover: deny-by-default SIEMPRE (jamás
    /// auto-granted), scope = unidad (`spend("USD")`), matching literal + prefijo
    /// trailing-`*` (mismas reglas que `secret`), audit fail-loud en `spend.log`.
    /// Espejo exacto de `sign`/`wallet`.
    Spend,
    /// Memoria persistente declarada del agente (`require memory("nombre")`). La
    /// declaración ES la identidad: scope = nombre literal del `.db` (DB-M1). Gatea
    /// toda la familia de estado persistente (memory + rules + progress + decisions).
    /// Deny-by-default incluso en `run` (no es ambiente como stdout/time/llm). El
    /// scope NO es una ruta: se compara literal + fnmatch, lo que da prefijos
    /// `memory=shop-*` en `--cap-set` gratis. Nunca sin scope en un `require`.
    Memory,
    /// Habilita `run_program(source, opts)`: correr OTRO programa Synsema en un proceso
    /// hijo del mismo binario, bajo un techo que es la intersección de lo pedido con lo
    /// que el padre tiene efectivamente. Deny-by-default, sin scope. Lo que el padre
    /// puede PRESTAR al hijo tiene que estar en sus propios `require`.
    SandboxRun,
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
            Sign => "sign",
            Wallet => "wallet",
            Spend => "spend",
            Memory => "memory",
            SandboxRun => "sandbox_run",
        }
    }

    /// Nombre tal como lo entiende `--cap-set`/`require` (el inverso exacto de
    /// `capability_type_from_name`): `file.read`, no `file_read`.
    pub fn wire_name(&self) -> &'static str {
        match self {
            CapabilityType::FileRead => "file.read",
            CapabilityType::FileWrite => "file.write",
            other => other.name_lower(),
        }
    }
}

/// Nombres aceptados por `--cap-set` (para el mensaje de error y los docs).
pub const KNOWN_CAPABILITY_NAMES: &str = "net, file, file.read, file.write, exec, env, time, random, stdout, stdin, llm, db, serve, secret, reveal, sign, wallet, spend, memory, sandbox_run";

/// Mapa nombre→tipo (CAPABILITY_NAMES del oráculo).
pub fn capability_type_from_name(name: &str) -> Option<CapabilityType> {
    use CapabilityType::*;
    Some(match name {
        "net" => Net,
        "file" => File,
        // `file_read`/`file_write` es como `Display` los imprime (un audit se puede
        // volver a pegar en un `--cap-set`).
        "file.read" | "file_read" => FileRead,
        "file.write" | "file_write" => FileWrite,
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
        "sign" => Sign,
        "wallet" => Wallet,
        "spend" => Spend,
        "memory" => Memory,
        "sandbox_run" => SandboxRun,
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

    /// Serialización como item de `--cap-set` (`net=api.x`, `file.read=./data`,
    /// `stdout`): el inverso exacto de `build_ceiling`, para que un techo calculado en
    /// Rust (p. ej. la intersección de `run_program`) viaje a otro proceso por flag.
    pub fn cap_set_item(&self) -> String {
        match &self.scope {
            Some(s) if !s.is_empty() => format!("{}={}", self.ty.wire_name(), s),
            _ => self.ty.wire_name().to_string(),
        }
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
        // F5 (defensa en profundidad): en filesystems case-insensitive (Windows, macOS)
        // `./Secret` y `./secret` son el MISMO archivo. Se compara con case-fold para que
        // un grant cubra ambos (correcto) y un `deny` no falle abierto. NO cambia la
        // salida de `normalize_path` (paridad byte-a-byte con el oráculo preservada).
        #[cfg(any(windows, target_os = "macos"))]
        let case_fold = |s: String| -> String { s.to_lowercase() };
        #[cfg(not(any(windows, target_os = "macos")))]
        let case_fold = |s: String| -> String { s };
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
                        let grant = case_fold(canon(self_scope));
                        let req = case_fold(canon(other_scope));
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

/// Por qué se denegó una capability. La distinción importa para QUIÉN puede
/// arreglarlo: `NoGrant` lo arregla el programa (un `require`); `AboveCeiling` sólo
/// el host (ampliar `--sandbox`/`--cap-set`/el ceiling del embebedor) — un agente que
/// se auto-repara agregando un `require` que ya tiene entra en loop si no se lo decimos.
#[derive(Clone, Debug, PartialEq)]
pub enum DenyCause {
    ExplicitlyDenied(Capability),
    AboveCeiling,
    NoGrant,
}

/// El texto del techo, idéntico en todas las ramas (los clasificadores del audit
/// comparan por string).
pub const ABOVE_CEILING: &str = "above host ceiling (--sandbox/--cap-set)";
/// `reason` de un grant ambiental que entró (stdout/time/llm bajo `run` no-secure,
/// `serve(port)` por `--port`).
pub const AMBIENT_GRANT: &str = "auto-granted by the runtime";
/// `reason` de una lectura servida desde el bundle de `synsema build` (sin `file.read`:
/// el asset es parte del programa, como un `use`).
pub const BUNDLED_ASSET: &str = "bundled asset (part of the program)";

/// Registro de un chequeo de capability (audit trail).
#[derive(Clone, Debug)]
pub struct CapabilityAuditEntry {
    pub capability: Capability,
    pub granted: bool,
    pub source: String,
    pub reason: String,
    /// Quién originó la entrada: `"program"` (un `require` del programa o una llamada
    /// que hizo) o `"runtime"` (un grant ambiente del host: stdout/time/llm bajo `run`,
    /// `serve` concedido por `--port`…). Deja separar "este tenant quiso leer STRIPE_KEY"
    /// del ruido de los grants ambientales rechazados por el techo.
    pub origin: &'static str,
}

/// Una entrada del audit en forma de strings (la frontera con el embebedor wasm, el
/// informe `--format json` y el JSONL de `--audit`): `{capability, granted, source,
/// reason, origin}`. Misma forma en todos los hosts.
#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub capability: String,
    pub granted: bool,
    pub source: String,
    pub reason: String,
    pub origin: String,
}

impl From<&CapabilityAuditEntry> for AuditEntry {
    fn from(e: &CapabilityAuditEntry) -> Self {
        AuditEntry {
            capability: e.capability.to_string(),
            granted: e.granted,
            source: e.source.clone(),
            reason: e.reason.clone(),
            origin: e.origin.to_string(),
        }
    }
}

/// El `audit_log` de un set como lista de `AuditEntry`.
pub fn export_audit(caps: &Rc<RefCell<CapabilitySet>>) -> Vec<AuditEntry> {
    caps.borrow().audit_log.iter().map(AuditEntry::from).collect()
}

/// Sink de audit del PROCESO (`--audit json|<ruta>|fd:N`, `run --format json`): cada
/// chequeo/grant de CUALQUIER `CapabilitySet` (main, agentes, workers, requests) se
/// entrega al sink además de quedar en el `audit_log` del set. Un `OnceLock`: el sink es
/// política de quien invocó el binario. Sin sink instalado no cuesta nada (un `get()`).
pub mod audit_sink {
    use super::CapabilityAuditEntry;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::OnceLock;

    /// Un evento de audit tal como lo ve el sink: la entrada + de qué contexto vino +
    /// dónde estaba el programa (si el intérprete lo sabía).
    pub struct AuditEvent<'a> {
        pub ts: String,
        pub context: &'a str,
        pub entry: &'a CapabilityAuditEntry,
        pub file: Option<String>,
        pub line: Option<usize>,
    }

    type Sink = Box<dyn Fn(&AuditEvent<'_>) + Send + Sync>;
    static SINK: OnceLock<Sink> = OnceLock::new();
    static INSTALLED: AtomicBool = AtomicBool::new(false);

    /// Instala el sink (una vez por proceso). `false` si ya había uno.
    pub fn install(sink: Sink) -> bool {
        let ok = SINK.set(sink).is_ok();
        if ok {
            INSTALLED.store(true, Ordering::Release);
            synsema_core::audit_loc::enable();
        }
        ok
    }

    pub fn installed() -> bool {
        INSTALLED.load(Ordering::Acquire)
    }

    /// `2026-08-30T14:02:11.482Z` desde segundos Unix (reloj del core: funciona en
    /// cualquier host, sin la feature `clock` de chrono que wasm no tiene).
    fn iso8601_millis(secs: f64) -> String {
        let total_ms = (secs * 1000.0).floor() as i64;
        let s = total_ms.div_euclid(1000);
        let ms = total_ms.rem_euclid(1000);
        let days = s.div_euclid(86_400);
        let rem = s.rem_euclid(86_400);
        // Conversión civil (Howard Hinnant).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60, ms
        )
    }

    pub(super) fn emit(context: &str, entry: &CapabilityAuditEntry) {
        if !INSTALLED.load(Ordering::Acquire) {
            return;
        }
        if let Some(sink) = SINK.get() {
            let (file, line) = match synsema_core::audit_loc::current() {
                Some(loc) => (Some(loc.file), Some(loc.line)),
                None => (None, None),
            };
            let ts = iso8601_millis(synsema_core::clock::now_secs_f64());
            sink(&AuditEvent { ts, context, entry, file, line });
        }
    }
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
    /// Grants del PROGRAMA que el techo rechazó: la capability está DECLARADA aunque no
    /// concedida — es lo que distingue "declared but above the ceiling" de "no grant".
    pub rejected_by_ceiling: Vec<Capability>,
}

impl CapabilitySet {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            granted: HashSet::new(),
            denied: HashSet::new(),
            audit_log: Vec::new(),
            rejected_by_ceiling: Vec::new(),
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

    /// Un grant del PROGRAMA (`require …`).
    pub fn grant(&mut self, capability: Capability) {
        self.grant_from(capability, "program");
    }

    /// Un grant AMBIENTE del host/runtime (stdout/time/llm bajo `run`, `serve` por `--port`):
    /// si el techo lo rechaza, la entrada del audit dice `origin: "runtime"` — el programa
    /// nunca lo pidió.
    pub fn grant_ambient(&mut self, capability: Capability) {
        self.grant_from(capability, "runtime");
    }

    /// Pushea una entrada al `audit_log` del set y la entrega al sink del proceso (si
    /// hay). ÚNICO camino de escritura del audit: todo chequeo/grant pasa por acá.
    pub fn push_audit(&mut self, entry: CapabilityAuditEntry) {
        audit_sink::emit(&self.name, &entry);
        self.audit_log.push(entry);
    }

    fn grant_from(&mut self, capability: Capability, origin: &'static str) {
        // Fail-closed: si el host puso un techo y no cubre esta capability, NO se inserta
        // (el techo nunca amplía). Se audita el rechazo. Sin techo → inserta como siempre.
        if !self.within_ceiling(&capability) {
            if origin == "program" {
                self.rejected_by_ceiling.push(capability.clone());
            }
            self.push_audit(CapabilityAuditEntry {
                capability,
                granted: false,
                source: "ceiling".to_string(),
                reason: ABOVE_CEILING.to_string(),
                origin,
            });
            return;
        }
        // Un grant AMBIENTE que entra deja rastro: sin esta entrada el audit no puede
        // distinguir "stdout auto-concedido por el runtime" de "nunca se habló de stdout".
        if origin == "runtime" {
            self.push_audit(CapabilityAuditEntry {
                capability: capability.clone(),
                granted: true,
                source: "ambient".to_string(),
                reason: AMBIENT_GRANT.to_string(),
                origin,
            });
        }
        self.granted.insert(capability);
    }

    /// Vacía el set (grants, denials, audit, padre) CONSERVANDO el techo del host. Es lo
    /// que un contexto reutilizado (un worker de `serve` entre requests) tiene que hacer:
    /// `*set = CapabilitySet::new(..)` perdería el techo — y con él, el `--sandbox`.
    pub fn reset_keeping_ceiling(&mut self, name: &str) {
        let ceiling = self.ceiling.clone();
        *self = CapabilitySet::new(name);
        self.ceiling = ceiling;
    }

    /// Deniega explícitamente (sobrescribe grants).
    pub fn deny(&mut self, capability: Capability) {
        self.denied.insert(capability);
    }

    /// ¿Está permitida? True si otorgada y no denegada. Cada chequeo se audita.
    pub fn check(&mut self, requested: &Capability, source: &str) -> bool {
        self.check_cause(requested, source).is_ok()
    }

    /// Como `check`, pero dice POR QUÉ se denegó — para que el mensaje de error apunte
    /// al actor correcto (programa vs host).
    pub fn check_cause(&mut self, requested: &Capability, source: &str) -> Result<(), DenyCause> {
        self.check_inner(requested, source, true)
    }

    /// La MISMA decisión que `check_cause` (denials, techo, grants, cadena de padres)
    /// pero SIN dejar rastro en el audit. Para calcular una intersección ("¿el padre
    /// cubriría esto?") sin que cada item recortado deje dos entradas.
    pub fn check_silent(&mut self, requested: &Capability) -> bool {
        self.check_inner(requested, "silent", false).is_ok()
    }

    fn check_inner(&mut self, requested: &Capability, source: &str, audit: bool) -> Result<(), DenyCause> {
        // 1) Denegaciones explícitas primero.
        let denied_by: Option<Capability> =
            self.denied.iter().find(|d| d.covers(requested)).cloned();
        if let Some(d) = denied_by {
            if audit {
                self.push_audit(CapabilityAuditEntry {
                    capability: requested.clone(),
                    granted: false,
                    source: source.to_string(),
                    reason: format!("Explicitly denied by {}", d),
                    origin: "program",
                });
            }
            return Err(DenyCause::ExplicitlyDenied(d));
        }

        // 1.5) Techo del host (defense-in-depth, autoritativo): un USO por encima del techo
        // se deniega SIEMPRE, aunque un grant (propio o heredado del padre) lo cubriera.
        // `grant()` ya evita insertar por encima del techo; esto cierra cualquier fuga de un
        // set derivado que hubiera colado un grant. Sólo corre si hay techo (`is_some`) → el
        // hot-path por defecto (`ceiling = None`) no paga nada.
        // Sólo es "declared but above the ceiling" si el programa la DECLARÓ (un grant
        // vigente o uno que el techo rechazó, acá o en el padre); si no, es "no grant" —
        // el programa tiene que agregar el `require` primero.
        if self.ceiling.is_some() && !self.within_ceiling(requested) && self.is_declared(requested) {
            if audit {
                self.push_audit(CapabilityAuditEntry {
                    capability: requested.clone(),
                    granted: false,
                    source: source.to_string(),
                    reason: ABOVE_CEILING.to_string(),
                    origin: "program",
                });
            }
            return Err(DenyCause::AboveCeiling);
        }

        // 2) Grants.
        let granted_by: Option<Capability> =
            self.granted.iter().find(|c| c.covers(requested)).cloned();
        if let Some(c) = granted_by {
            if audit {
                self.push_audit(CapabilityAuditEntry {
                    capability: requested.clone(),
                    granted: true,
                    source: source.to_string(),
                    reason: format!("Granted by {}", c),
                    origin: "program",
                });
            }
            return Ok(());
        }

        // 3) Padre (su check audita en el padre).
        if let Some(parent) = self.parent.clone() {
            match parent.borrow_mut().check_inner(requested, source, audit) {
                Ok(()) => return Ok(()),
                Err(DenyCause::AboveCeiling) => return Err(DenyCause::AboveCeiling),
                Err(_) => {}
            }
        }

        // 4) Sin grant.
        if audit {
            self.push_audit(CapabilityAuditEntry {
                capability: requested.clone(),
                granted: false,
                source: source.to_string(),
                reason: "No matching grant found".to_string(),
                origin: "program",
            });
        }
        Err(DenyCause::NoGrant)
    }

    fn is_declared(&self, requested: &Capability) -> bool {
        self.granted.iter().any(|c| c.covers(requested))
            || self.rejected_by_ceiling.iter().any(|c| c.covers(requested))
            || self.parent.as_ref().map(|p| p.borrow().is_declared(requested)).unwrap_or(false)
    }

    /// El mensaje de una denegación, apuntando a quien puede resolverla.
    pub fn denial_message(requested: &Capability, cause: &DenyCause) -> String {
        match cause {
            DenyCause::AboveCeiling => format!(
                "Capability not granted: {} — declared but above the host ceiling (--sandbox/--cap-set). The program cannot fix this; the host must widen the ceiling",
                requested
            ),
            DenyCause::ExplicitlyDenied(d) => {
                format!("Capability not granted: {} — explicitly denied by {}", requested, d)
            }
            DenyCause::NoGrant => format!("Capability not granted: {}", requested),
        }
    }

    /// Chequea y devuelve error si no está otorgada.
    pub fn require(&mut self, requested: &Capability, source: &str) -> Result<(), CapabilityViolation> {
        if let Err(cause) = self.check_cause(requested, source) {
            return Err(CapabilityViolation {
                message: Self::denial_message(requested, &cause),
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
            rejected_by_ceiling: Vec::new(),
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
            "Unknown capability type: '{}'. Known: [net, file, file.read, file.write, exec, env, time, random, stdout, stdin, llm, db, serve, secret, reveal, sign, wallet, spend, memory]",
            name
        )),
    }
}

/// G-6 (DB-M1): valida un nombre de memoria declarado (`require memory("nombre")`).
/// Sólo `[a-zA-Z0-9_-]+`: sin `/`, `\`, `..`, ni vacío — el nombre se convierte en el
/// filename `<nombre>.db`, así que un nombre inválido falla EN LA DECLARACIÓN, no al
/// persistir. Mensaje en inglés, autocontenido y LLM-safe (Decisión #8).
pub fn validate_memory_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(
            "Invalid memory name: empty. Memory names must match [a-zA-Z0-9_-]+ (letters, digits, '_' and '-' only), e.g. require memory(\"my-agent\")".to_string(),
        );
    }
    if let Some(bad) = name.chars().find(|c| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-')) {
        return Err(format!(
            "Invalid memory name: \"{}\" contains '{}'. Memory names must match [a-zA-Z0-9_-]+ (letters, digits, '_' and '-' only) — no paths, no '/', no '\\', no '..'",
            name, bad
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // Discovery-era audit fixes: la causa llega al mensaje (programa vs host) y el audit
    // distingue el origen (program vs runtime) — sin re-parsear el fuente.
    #[test]
    fn deny_cause_and_origin() {
        let mut caps = CapabilitySet::new("t");
        caps.ceiling = Some(Rc::new(vec![Capability::new(CapabilityType::Stdout, None)]));
        caps.grant_ambient(Capability::new(CapabilityType::Time, None)); // runtime, rechazado
        caps.grant(Capability::new(CapabilityType::Secret, Some("STRIPE_KEY".into()))); // program, rechazado
        let secret = Capability::new(CapabilityType::Secret, Some("STRIPE_KEY".into()));
        assert_eq!(caps.check_cause(&secret, "t"), Err(DenyCause::AboveCeiling));
        let net = Capability::new(CapabilityType::Net, Some("x".into()));
        assert_eq!(caps.check_cause(&net, "t"), Err(DenyCause::NoGrant), "no declarada: aunque el techo no la cubra, el programa va primero");
        let mut open = CapabilitySet::new("open");
        assert_eq!(open.check_cause(&net, "t"), Err(DenyCause::NoGrant));
        let msg = CapabilitySet::denial_message(&secret, &DenyCause::AboveCeiling);
        assert!(msg.contains("host must widen the ceiling") && !msg.contains("add `require"), "{}", msg);
        let log = &caps.audit_log;
        let time = log.iter().find(|e| e.capability.ty == CapabilityType::Time).unwrap();
        assert_eq!((time.origin, time.source.as_str(), time.reason.as_str()), ("runtime", "ceiling", ABOVE_CEILING));
        let sk = log.iter().find(|e| e.capability.ty == CapabilityType::Secret && e.source == "ceiling").unwrap();
        assert_eq!(sk.origin, "program");
        let call = log.iter().find(|e| e.capability.ty == CapabilityType::Secret && e.source == "t").unwrap();
        assert_eq!((call.origin, call.reason.as_str()), ("program", ABOVE_CEILING));
    }

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

    // ---- memory (DB-M1) ----

    #[test]
    fn memory_capability_parses_and_displays() {
        let c = parse_capability("memory", Some("shop")).unwrap();
        assert_eq!(c.ty, CapabilityType::Memory);
        assert_eq!(c.to_string(), "memory(\"shop\")");
    }

    #[test]
    fn memory_scope_is_literal_not_path() {
        // El scope de memory NO se canoniza como ruta: literal + fnmatch.
        let exact = cap(CapabilityType::Memory, Some("shop"));
        assert!(exact.covers(&cap(CapabilityType::Memory, Some("shop"))));
        assert!(!exact.covers(&cap(CapabilityType::Memory, Some("other"))));
        // Prefijo para el ceiling --cap-set "memory=shop-*".
        let prefix = cap(CapabilityType::Memory, Some("shop-*"));
        assert!(prefix.covers(&cap(CapabilityType::Memory, Some("shop-eu"))));
        assert!(!prefix.covers(&cap(CapabilityType::Memory, Some("billing"))));
        // Sin scope (sólo posible como ceiling) cubre cualquier nombre.
        let bare = cap(CapabilityType::Memory, None);
        assert!(bare.covers(&cap(CapabilityType::Memory, Some("anything"))));
    }

    #[test]
    fn memory_name_validation_g6() {
        assert!(validate_memory_name("shop").is_ok());
        assert!(validate_memory_name("shop-agent_2").is_ok());
        assert!(validate_memory_name("").is_err());
        assert!(validate_memory_name("../x").is_err());
        assert!(validate_memory_name("a/b").is_err());
        assert!(validate_memory_name("a\\b").is_err());
        assert!(validate_memory_name("a b").is_err());
        assert!(validate_memory_name("a.db").is_err());
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

/// Construye el techo de capabilities del host desde `--sandbox`/`--cap-set` (defense-in-depth:
/// el operador impone un límite que el código ejecutado no puede exceder, sin importar qué
/// `require`). `--sandbox` ≡ techo `[stdout, time]` (sólo cómputo + `print`). `--cap-set` parsea
/// items separados por coma: `name` (wildcard, sin scope) o `name=scope`. Son mutuamente
/// excluyentes. Devuelve `Ok(None)` cuando no hay ninguno (comportamiento por defecto, sin techo).
///
/// Vive acá (y no en la CLI) para que TODOS los front-ends del intérprete —el binario
/// `synsema` y el artefacto `synsema-wasm`— parseen las mismas flags con la misma
/// semántica: un techo que se acepta en uno y se ignora en otro es un agujero, no un knob.
pub fn build_ceiling(sandbox: bool, cap_set: Option<&str>) -> Result<Option<Vec<Capability>>, String> {
    match (sandbox, cap_set) {
        (true, Some(_)) => {
            Err("--sandbox and --cap-set are mutually exclusive; choose one".to_string())
        }
        // Techo mínimo: cómputo + stdout (print) + time (now/sleep). Nada de net/exec/file/llm/…
        (true, None) => Ok(Some(vec![
            Capability::new(CapabilityType::Stdout, None),
            Capability::new(CapabilityType::Time, None),
        ])),
        // `none`: un techo que no cubre NADA (ni stdout). Es lo que recibe el hijo de
        // `run_program` cuando la intersección con el padre queda vacía.
        (false, Some(list)) if list.trim() == "none" => Ok(Some(Vec::new())),
        (false, Some(list)) => {
            let mut caps = Vec::new();
            for item in list.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                // `name=scope` (net=api.mock.test, db=:memory:, file.read=./data/*) o `name`.
                let (name, scope) = match item.split_once('=') {
                    Some((n, s)) => (n.trim(), Some(s.trim().to_string())),
                    None => (item, None),
                };
                match capability_type_from_name(name) {
                    Some(ty) => caps.push(Capability::new(ty, scope)),
                    None => {
                        return Err(format!(
                            "--cap-set: unknown capability '{}'. Known: {} (or `none` for an empty ceiling)",
                            name, KNOWN_CAPABILITY_NAMES
                        ))
                    }
                }
            }
            if caps.is_empty() {
                return Err("--cap-set requires at least one capability".to_string());
            }
            Ok(Some(caps))
        }
        (false, None) => Ok(None),
    }
}

#[cfg(test)]
mod tanda_motor_tests {
    use super::*;

    #[test]
    fn reset_keeping_ceiling_preserves_ceiling() {
        let mut cs = CapabilitySet::new("request");
        cs.ceiling = Some(Rc::new(vec![Capability::new(CapabilityType::Stdout, None)]));
        cs.grant(Capability::new(CapabilityType::Exec, Some("cmd".into())));
        assert!(cs.granted.is_empty(), "el techo rechaza exec");
        cs.reset_keeping_ceiling("request");
        assert!(cs.ceiling.is_some());
        assert!(cs.audit_log.is_empty());
        cs.grant(Capability::new(CapabilityType::Exec, Some("cmd".into())));
        assert!(!cs.check(&Capability::new(CapabilityType::Exec, Some("cmd".into())), "run()"));
    }

    #[test]
    fn cap_set_item_round_trips_every_type() {
        use CapabilityType::*;
        for ty in [Net, FileRead, FileWrite, File, Exec, Env, Time, Random, Stdout, Stdin, Llm, Db, Serve, Secret, Reveal, Sign, Wallet, Spend, Memory, SandboxRun] {
            for scope in [None, Some("x-*".to_string())] {
                let cap = Capability::new(ty, scope.clone());
                let back = build_ceiling(false, Some(&cap.cap_set_item())).unwrap().unwrap();
                assert_eq!(back, vec![cap]);
            }
        }
    }

    #[test]
    fn build_ceiling_none_is_empty_set_and_accepts_display_names() {
        assert_eq!(build_ceiling(false, Some("none")).unwrap(), Some(vec![]));
        let c = build_ceiling(false, Some("file_read=./a,file_write=./b")).unwrap().unwrap();
        assert_eq!(c[0].ty, CapabilityType::FileRead);
        assert_eq!(c[1].ty, CapabilityType::FileWrite);
        let err = build_ceiling(false, Some("bogus")).unwrap_err();
        assert!(err.contains("sandbox_run") && err.contains("spend"), "{}", err);
    }

    #[test]
    fn ambient_grant_leaves_audit_entry() {
        let mut cs = CapabilitySet::new("program");
        cs.grant_ambient(Capability::new(CapabilityType::Stdout, None));
        assert_eq!(cs.audit_log.len(), 1);
        let e = &cs.audit_log[0];
        assert!(e.granted);
        assert_eq!(e.origin, "runtime");
        assert_eq!(e.source, "ambient");
        assert_eq!(e.reason, AMBIENT_GRANT);
        // Un grant del programa que entra NO deja entrada (sólo los chequeos).
        cs.grant(Capability::new(CapabilityType::Net, Some("a".into())));
        assert_eq!(cs.audit_log.len(), 1);
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn path_scope_matching_is_case_insensitive_on_case_insensitive_fs() {
        // F5 (auditoría): en NTFS/APFS `./data` y `./DATA` son el mismo archivo. Un grant
        // cubre ambas variantes (correcto), y un `deny` no falla abierto. En Linux
        // (case-sensitive) NO se foldea (este test no corre ahí).
        let grant = Capability::new(CapabilityType::FileRead, Some("data/x.txt".into()));
        assert!(grant.covers(&Capability::new(CapabilityType::FileRead, Some("DATA/x.txt".into()))));
        assert!(grant.covers(&Capability::new(CapabilityType::FileRead, Some("data/x.txt".into()))));
        let glob = Capability::new(CapabilityType::FileRead, Some("data/*".into()));
        assert!(glob.covers(&Capability::new(CapabilityType::FileRead, Some("DATA/secret.txt".into()))));
        // net (no-path) sigue case-sensitive (los hostnames ya se bajan a minúscula aparte).
        let net = Capability::new(CapabilityType::Net, Some("api.x".into()));
        assert!(!net.covers(&Capability::new(CapabilityType::Net, Some("API.X".into()))));
    }

    #[test]
    fn check_silent_matches_check_cause_without_audit() {
        let mut cs = CapabilitySet::new("program");
        cs.ceiling = Some(Rc::new(vec![Capability::new(CapabilityType::Net, Some("uno".into()))]));
        cs.grant(Capability::new(CapabilityType::Net, Some("uno".into())));
        let before = cs.audit_log.len();
        assert!(cs.check_silent(&Capability::new(CapabilityType::Net, Some("uno".into()))));
        // `net=*` pedido bajo `net("uno")` cae ENTERO (el patrón es el grant).
        assert!(!cs.check_silent(&Capability::new(CapabilityType::Net, Some("*".into()))));
        assert!(!cs.check_silent(&Capability::new(CapabilityType::Net, None)));
        assert!(!cs.check_silent(&Capability::new(CapabilityType::Exec, Some("cmd".into()))));
        assert_eq!(cs.audit_log.len(), before, "check_silent no audita");
        assert!(cs.check(&Capability::new(CapabilityType::Net, Some("uno".into())), "x"));
        assert_eq!(cs.audit_log.len(), before + 1);
    }
}

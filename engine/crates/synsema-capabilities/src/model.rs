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
    /// El primitivo `judge` (System One): juicios calibrados contra un `state`. Capability
    /// PROPIA, no la concede `llm`: un programa puede tener derecho a clasificar sin tener
    /// derecho a generar. Coarse, sin scope (el host lo fija el runtime, no el programa).
    Judge,
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
    /// Pedir a la PLATAFORMA un documento de attestation (`attest(opts)`):
    /// I/O no determinista contra un dispositivo o socket del host (NSM de Nitro,
    /// Configfs-tsm de TDX/SEV-SNP, el socket de dstack, o el driver `mock` de CI).
    /// Deny-by-default, sin scope, JAMÁS ambiente: no está en el techo `--sandbox` ni en
    /// El determinista (`--deterministic` la niega solo). Nombre genérico a propósito:
    /// Es una capability del motor, como `time` o `random`, no un adaptador.
    Attest,
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
            Judge => "judge",
            Db => "db",
            Serve => "serve",
            Secret => "secret",
            Reveal => "reveal",
            Sign => "sign",
            Wallet => "wallet",
            Spend => "spend",
            Memory => "memory",
            SandboxRun => "sandbox_run",
            Attest => "attest",
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
pub const KNOWN_CAPABILITY_NAMES: &str = "net, file, file.read, file.write, exec, env, time, random, stdout, stdin, llm, judge, db, serve, secret, reveal, sign, wallet, spend, memory, sandbox_run, attest";

/// Capabilities LOCALES AL PROCESO: el stdout, el stdin, el reloj y la entropía del proceso
/// que corre. Un techo DELEGADO (un captoken, un `sandbox under`) NO las gobierna: quien
/// delega autoridad no posee el stdout ni el reloj del proceso del delegatario, así que no
/// puede ni darlos ni quitarlos por `caps` (§12.1 del spec de identidad). Las gobiernan el
/// HOST (`--cap-set`, `--deterministic`) y el programa (`require random`). Lo único que un
/// emisor puede pedir sobre ellas es el caveat `deterministic` (sin reloj ni entropía), que
/// es una restricción de ejecución, no autoridad — y va en `Delegation::deterministic`.
pub const PROCESS_LOCAL: &[CapabilityType] =
    &[CapabilityType::Stdout, CapabilityType::Stdin, CapabilityType::Time, CapabilityType::Random];

/// ¿Es una capability local al proceso (no delegable por token ni por bloque)?
pub fn is_process_local(ty: CapabilityType) -> bool {
    PROCESS_LOCAL.contains(&ty)
}

/// De dónde viene un techo delegado: un captoken verificado (con su `id`, que es lo que se
/// revoca — los captokens son simétricos y no tienen `keyid`) o un bloque `sandbox under`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DelegationSource {
    Token(String),
    Block,
}

impl DelegationSource {
    /// El `source` de la entrada de audit cuando un grant se rechaza por este techo.
    pub fn audit_source(&self) -> &'static str {
        match self {
            DelegationSource::Token(_) => "token",
            DelegationSource::Block => "sandbox",
        }
    }
}

/// Un techo DELEGADO: lo que un captoken verificado (o un `sandbox under`) deja hacer a la
/// unidad de trabajo que corre bajo él. Se apila sobre el techo del host y sólo RESTA:
/// `caps_efectivas ⊆ require ∩ techo_host ∩ techo_delegado`. Gobierna la autoridad
/// TRANSFERIBLE (net/file/exec/env/db/llm/judge/serve/secret/reveal/sign/wallet/spend/
/// memory/sandbox_run/attest) y deja pasar lo local al proceso (`PROCESS_LOCAL`), salvo que
/// el emisor haya pedido `deterministic`: entonces `time` y `random` se niegan, exactamente
/// como el techo `--deterministic` del host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegation {
    pub caps: Vec<Capability>,
    pub source: DelegationSource,
    pub deterministic: bool,
}

impl Delegation {
    pub fn token(id: impl Into<String>, caps: Vec<Capability>, deterministic: bool) -> Self {
        Delegation { caps, source: DelegationSource::Token(id.into()), deterministic }
    }

    pub fn block(caps: Vec<Capability>) -> Self {
        Delegation { caps, source: DelegationSource::Block, deterministic: false }
    }

    /// ¿Este techo delegado cubre la capability? Mismo `covers()` que gatea los `require`
    /// (misma canonización, mismo glob): no hay una segunda lógica de scopes.
    pub fn covers(&self, cap: &Capability) -> bool {
        if is_process_local(cap.ty) {
            return !(self.deterministic && matches!(cap.ty, CapabilityType::Time | CapabilityType::Random));
        }
        self.caps.iter().any(|allowed| allowed.covers(cap))
    }

    /// El `reason` de la entrada de audit (y el sufijo del mensaje) de un rechazo.
    pub fn reason_for(&self, cap: &Capability) -> String {
        let deterministic = self.deterministic && is_process_local(cap.ty);
        match (&self.source, deterministic) {
            (DelegationSource::Token(id), false) => format!("above delegated ceiling (token {})", id),
            (DelegationSource::Token(id), true) => {
                format!("denied by the deterministic caveat of token {}", id)
            }
            (DelegationSource::Block, _) => "above sandbox ceiling (sandbox under)".to_string(),
        }
    }
}

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
        "judge" => Judge,
        "db" => Db,
        "serve" => Serve,
        "secret" => Secret,
        "reveal" => Reveal,
        "sign" => Sign,
        "wallet" => Wallet,
        "spend" => Spend,
        "memory" => Memory,
        "sandbox_run" => SandboxRun,
        "attest" => Attest,
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
        // `net` es un permiso por HOST, o por `host:puerto` si el puerto se escribió:
        // `require net("https://user:pw@api.x.com/v1?key=…")` se guarda como `api.x.com` y
        // `net("http://localhost:8545")` como `localhost:8545` (sólo ese puerto: un permiso nunca
        // es más amplio que lo declarado). Nunca queda en el scope (ni en el audit, ni en un
        // mensaje) lo que un URL trae además: credenciales, ruta, query.
        let scope = match (ty, scope) {
            (CapabilityType::Net, Some(s)) if s.contains("://") => Some(net_host_of(&s)),
            (CapabilityType::Net, Some(s)) if s.starts_with('[') && s.ends_with(']') => Some(s[1..s.len() - 1].to_lowercase()),
            (CapabilityType::Net, Some(s)) if s.starts_with('[') => Some(s.to_lowercase()),
            (_, s) => s,
        };
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
                    } else if self.ty == CapabilityType::Net {
                        // Host y puerto por separado: un grant sin puerto cubre cualquier puerto
                        // del host; con puerto, sólo ese.
                        let (gh, gp) = split_net_scope(self_scope);
                        let (rh, rp) = split_net_scope(other_scope);
                        let host_ok = gh == rh || fnmatch(rh, gh) || self_scope == other_scope;
                        host_ok && (gp.is_none() || gp == rp)
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

/// El host y el puerto EXPLÍCITO de un URL (minúsculas, sin credenciales): `(host, puerto)`.
/// IPv6 va sin corchetes. `None` de puerto si el URL no lo escribe.
fn url_host_port(url: &str) -> (String, Option<String>) {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or("");
    let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
        let (h, after) = inner.split_once(']').unwrap_or((inner, ""));
        (h, after.strip_prefix(':'))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };
    let port = port.filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())).map(str::to_string);
    (host.to_lowercase(), port)
}

/// `host` o `host:puerto` (IPv6 con puerto: `[::1]:8545`).
fn join_net_scope(host: &str, port: Option<&str>) -> String {
    match port {
        Some(p) if host.contains(':') => format!("[{}]:{}", host, p),
        Some(p) => format!("{}:{}", host, p),
        None => host.to_string(),
    }
}

/// Un scope de `net` → `(host, puerto)`. `[::1]:8545` y `host:8545` llevan puerto; `::1` (IPv6
/// sin corchetes) y `host` no.
pub fn split_net_scope(scope: &str) -> (&str, Option<&str>) {
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

/// El scope de `net` que declara un URL: su host, más el puerto si el URL lo escribe. Un URL
/// sin host queda como `<no host>` (no cubre nada, y no ecoa el URL).
fn net_host_of(url: &str) -> String {
    let (host, port) = url_host_port(url);
    if host.is_empty() {
        "<no host>".to_string()
    } else {
        join_net_scope(&host, port.as_deref())
    }
}

/// El scope de `net` que PIDE una conexión a `url`: el host, más el puerto si el URL lo escribe
/// (`127.0.0.1:8545`). Sin puerto escrito se pide el host solo, como siempre (y los mensajes no
/// cambian): lo cubre un grant sin puerto, y uno con puerto no, porque no dice ese puerto.
/// `None` si no hay host.
pub fn net_request_scope(url: &str) -> Option<String> {
    let (host, port) = url_host_port(url);
    if host.is_empty() {
        return None;
    }
    Some(join_net_scope(&host, port.as_deref()))
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

/// Por qué se denegó una capability. La distinción importa para QUIÉN puede
/// arreglarlo: `NoGrant` lo arregla el programa (un `require`); `AboveCeiling` sólo
/// el host (ampliar `--sandbox`/`--cap-set`/el ceiling del embebedor) — un agente que
/// se auto-repara agregando un `require` que ya tiene entra en loop si no se lo decimos.
#[derive(Clone, Debug, PartialEq)]
pub enum DenyCause {
    ExplicitlyDenied(Capability),
    AboveCeiling,
    /// Declarada por el programa, pero por encima del techo DELEGADO (el token del caller
    /// no la concede, o un `sandbox under` la dejó afuera). Si es un token, es culpa del
    /// CALLER (bajo `serve` → 403 genérico), no del programa ni del host.
    Delegated(Delegation),
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
    /// Techos DELEGADOS (T1 del spec de identidad), apilados: el captoken que autenticó la
    /// request (lo pone el runtime de serve por request), y encima cada `sandbox under`
    /// anidado. Una capability pasa sólo si TODOS la cubren, además del techo del host.
    /// Es el segundo dueño de la capa: el caller delega, el host gobierna, el programa
    /// declara; ninguno amplía al otro. Se propaga a todo set derivado (hijo/sandbox/
    /// worker/agente) igual que `ceiling`, y `reset_keeping_ceiling` lo VACÍA a propósito
    /// (un techo delegado es de una unidad de trabajo, jamás del worker que la corrió).
    pub delegated: Vec<Rc<Delegation>>,
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
            delegated: Vec::new(),
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

    /// El primer techo DELEGADO que NO cubre la capability (si hay alguno). Sin techos
    /// delegados → `None` (el hot-path por defecto no paga nada).
    fn rejected_by_delegation(&self, cap: &Capability) -> Option<Rc<Delegation>> {
        self.delegated.iter().find(|d| !d.covers(cap)).cloned()
    }

    /// Apila un techo delegado (el token de la request, un `sandbox under`).
    pub fn push_delegation(&mut self, delegation: Delegation) {
        self.delegated.push(Rc::new(delegation));
    }

    /// Quita el último techo delegado apilado (al salir de un `sandbox under`).
    pub fn pop_delegation(&mut self) -> Option<Rc<Delegation>> {
        self.delegated.pop()
    }

    /// Los techos delegados vigentes, en forma OWNED (para cruzar a un hilo: un agente
    /// spawneado, un worker de `parallel_map`).
    pub fn delegations(&self) -> Vec<Delegation> {
        self.delegated.iter().map(|d| (**d).clone()).collect()
    }

    /// Instala techos delegados heredados de la unidad de trabajo que creó ésta.
    pub fn set_delegations(&mut self, delegations: Vec<Delegation>) {
        self.delegated = delegations.into_iter().map(Rc::new).collect();
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
        // Techo DELEGADO (token / `sandbox under`): mismo tratamiento que el del host — no se
        // inserta, queda como DECLARADA (el programa la pidió; es el caller quien no la
        // concede) y el audit dice de qué token vino.
        if let Some(d) = self.rejected_by_delegation(&capability) {
            if origin == "program" {
                self.rejected_by_ceiling.push(capability.clone());
            }
            let reason = d.reason_for(&capability);
            self.push_audit(CapabilityAuditEntry {
                capability,
                granted: false,
                source: d.source.audit_source().to_string(),
                reason,
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
    /// Los techos DELEGADOS se vacían A PROPÓSITO: el token es de la request que se fue,
    /// y el request siguiente del mismo worker tiene que ver el techo del host completo
    /// (T1 del spec de identidad: "nunca un slot aparte").
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

        // 1.6) Techos DELEGADOS (el token de la request, los `sandbox under` apilados): un
        // USO por encima se deniega aunque el grant exista — el programa la declaró, el
        // caller no la delegó. Mismo criterio que el host: sólo si está DECLARADA; si no,
        // es "no grant" y la culpa es del programa, no del token.
        if !self.delegated.is_empty() {
            if let Some(d) = self.rejected_by_delegation(requested) {
                if self.is_declared(requested) {
                    if audit {
                        self.push_audit(CapabilityAuditEntry {
                            capability: requested.clone(),
                            granted: false,
                            source: source.to_string(),
                            reason: d.reason_for(requested),
                            origin: "program",
                        });
                    }
                    return Err(DenyCause::Delegated((*d).clone()));
                }
            }
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
                Err(DenyCause::Delegated(d)) => return Err(DenyCause::Delegated(d)),
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

    /// El `require` exacto que concedería la capability pedida (la forma que el programa
    /// escribe: `require net("api.x")`, `require file.read("./data")`, `require llm`).
    pub fn require_line(requested: &Capability) -> String {
        match &requested.scope {
            Some(s) if !s.is_empty() => format!("require {}(\"{}\")", requested.ty.wire_name(), s),
            _ => format!("require {}", requested.ty.wire_name()),
        }
    }

    /// El mensaje de una denegación, apuntando a quien puede resolverla — y diciendo en
    /// voz alta que es un PERMISO, no un bug: un agente que codea y lee "not granted" sin
    /// más se pone a inventar soluciones a algo que sólo un `require` arregla.
    pub fn denial_message(requested: &Capability, cause: &DenyCause) -> String {
        match cause {
            DenyCause::AboveCeiling => format!(
                "Capability not granted: {} — declared but above the host ceiling (--sandbox/--cap-set). The program cannot fix this; the host must widen the ceiling",
                requested
            ),
            DenyCause::ExplicitlyDenied(d) => {
                format!("Capability not granted: {} — explicitly denied by {}", requested, d)
            }
            DenyCause::Delegated(d) => match &d.source {
                DelegationSource::Token(id) if d.deterministic && is_process_local(requested.ty) => format!(
                    "Capability not granted: {} — denied by the deterministic caveat of token {}: the caller asked for a run without clock or entropy. The program cannot fix this; the caller must mint a token without that caveat",
                    requested, id
                ),
                DelegationSource::Token(id) => format!(
                    "Capability not granted: {} — denied by the delegated ceiling of token {}: the program declares it, but the caller's token does not grant it. The program cannot fix this; the caller must present a token that carries it",
                    requested, id
                ),
                DelegationSource::Block => format!(
                    "Capability not granted: {} — outside the ceiling of the enclosing `sandbox under` block; add it to that block's caps or run this outside the block",
                    requested
                ),
            },
            DenyCause::NoGrant => format!(
                "Capability not granted: {} — this is a permission, not a bug: add `{}` to the program's preamble (or to the importing file, when this code runs in a module)",
                requested,
                Self::require_line(requested)
            ),
        }
    }

    /// Chequea y devuelve error si no está otorgada.
    pub fn require(&mut self, requested: &Capability, source: &str) -> Result<(), CapabilityViolation> {
        if let Err(cause) = self.check_cause(requested, source) {
            return Err(CapabilityViolation {
                message: Self::denial_message(requested, &cause),
                requested: Some(requested.clone()),
                source: source.to_string(),
                cause,
            });
        }
        Ok(())
    }

    /// La violación de una denegación YA decidida por `check_cause`: para los gates que
    /// escriben su propio texto en el caso común (sign/spend/wallet/secret/reveal) pero deben
    /// conservar la CAUSA cuando la culpa es del caller — un techo delegado → `denied_by_token`
    /// → 403 bajo `serve`, jamás un 500 con "add `require …`" que manda a arreglar un programa
    /// que ya lo declara y enumera la superficie hacia afuera (auditoría T1–T4, ronda 1).
    pub fn violation(requested: &Capability, cause: DenyCause, source: &str) -> CapabilityViolation {
        CapabilityViolation {
            message: Self::denial_message(requested, &cause),
            requested: Some(requested.clone()),
            source: source.to_string(),
            cause,
        }
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
            delegated: parent.borrow().delegated.clone(),
        }
    }

    /// Crea un sandbox restringido que NO hereda: sólo los grants explícitos.
    /// (Ignora `self`, igual que el oráculo.) El techo del host SÍ se propaga (`Rc::clone`):
    /// el sandbox nunca puede conceder por encima del techo, aunque el grant sea explícito.
    /// Los techos delegados también: un sandbox dentro de una request sigue bajo su token.
    pub fn create_sandbox(&self, name: &str, allowed: &[Capability]) -> CapabilitySet {
        let mut sandbox = CapabilitySet::new(&format!("sandbox:{}", name));
        sandbox.ceiling = self.ceiling.clone();
        sandbox.delegated = self.delegated.clone();
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
    /// Por qué: decide QUIÉN tiene la culpa (programa / host / el token del caller).
    pub cause: DenyCause,
}

impl CapabilityViolation {
    /// ¿La denegó el token del CALLER (techo delegado de un captoken)? Bajo `serve` eso es
    /// un 403 genérico hacia afuera, no un 500: la culpa no es del server.
    pub fn denied_by_token(&self) -> bool {
        matches!(&self.cause, DenyCause::Delegated(d) if matches!(d.source, DelegationSource::Token(_)))
    }

    /// El error de runtime equivalente, con el flag `denied_by_token` puesto — la ÚNICA
    /// forma de convertir una violación en error: el texto nunca decide el status HTTP.
    pub fn into_error(self) -> synsema_core::interpreter::RuntimeError {
        let denied_by_token = self.denied_by_token();
        let mut e = synsema_core::interpreter::RuntimeError::new(self.message);
        e.denied_by_token = denied_by_token;
        e
    }
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

/// v0.6.20 — techo DETERMINISTA: el de `--sandbox` sin `time` (y sin `random`, que el
/// sandbox tampoco tiene): sólo `stdout`. Es lo que el CLI empaqueta como `--deterministic`
/// junto con `--profile pure`: un programa bajo este techo no puede leer el reloj ni
/// entropía, así el determinismo es por construcción (VMs, TEEs, tests reproducibles), no
/// por disciplina. Nombre genérico a propósito: le sirve a cualquier host, no a uno.
pub fn build_ceiling_deterministic() -> Vec<Capability> {
    vec![Capability::new(CapabilityType::Stdout, None)]
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
        for ty in [Net, FileRead, FileWrite, File, Exec, Env, Time, Random, Stdout, Stdin, Llm, Judge, Db, Serve, Secret, Reveal, Sign, Wallet, Spend, Memory, SandboxRun, Attest] {
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

#[cfg(test)]
mod v0620_tests {
    use super::*;

    /// §4.3 — `~` se expande al home en scopes y rutas por igual; `~usuario` y un `~` en
    /// medio no se tocan.
    #[test]
    fn tilde_expands_to_home_in_scopes_and_paths() {
        let home = std::env::var("HOME")
            .ok()
            .filter(|h| !h.trim().is_empty())
            .or_else(|| std::env::var("USERPROFILE").ok().filter(|h| !h.trim().is_empty()));
        if let Some(h) = home {
            let want = normalize_path(&format!("{}/.synsema/x", h));
            assert_eq!(normalize_path("~/.synsema/x"), want);
            assert_eq!(normalize_path("~\\.synsema\\x"), want);
            assert_eq!(normalize_path("~"), normalize_path(&h));
            let scope = Capability::new(CapabilityType::FileWrite, Some("~/.synsema/*".to_string()));
            let inside = Capability::new(CapabilityType::FileWrite, Some(format!("{}/.synsema/token.json", h)));
            let outside = Capability::new(CapabilityType::FileWrite, Some(format!("{}/other/token.json", h)));
            assert!(scope.covers(&inside));
            assert!(!scope.covers(&outside));
        }
        assert_eq!(normalize_path("~user/x"), "~user/x");
        assert_eq!(normalize_path("data/~/x"), "data/~/x");
    }

    /// §4.5 — el techo determinista es sólo stdout: ni time ni random.
    #[test]
    fn deterministic_ceiling_has_only_stdout() {
        let c = build_ceiling_deterministic();
        assert_eq!(c.len(), 1);
        assert!(c[0].covers(&Capability::new(CapabilityType::Stdout, None)));
        assert!(!c.iter().any(|x| x.covers(&Capability::new(CapabilityType::Time, None))));
        assert!(!c.iter().any(|x| x.covers(&Capability::new(CapabilityType::Random, None))));
    }
}

#[cfg(test)]
mod tee_tests {
    use super::*;

    /// `attest` es una capability más del motor (round-trip por `--cap-set` y
    /// `require`), pero NO viene en ningún techo empaquetado: ni `--sandbox` ni el
    /// determinista la listan, así que bajo `--deterministic` un `require attest` queda
    /// negado solo (es I/O de plataforma, no determinista por definición).
    #[test]
    fn attest_is_known_but_absent_from_every_packaged_ceiling() {
        assert_eq!(capability_type_from_name("attest"), Some(CapabilityType::Attest));
        assert_eq!(CapabilityType::Attest.wire_name(), "attest");
        assert!(KNOWN_CAPABILITY_NAMES.contains("attest"));
        let want = Capability::new(CapabilityType::Attest, None);
        let det = build_ceiling_deterministic();
        assert!(!det.iter().any(|c| c.covers(&want)), "el techo determinista no cubre attest");
        let sandbox = build_ceiling(true, None).unwrap().unwrap();
        assert!(!sandbox.iter().any(|c| c.covers(&want)), "--sandbox no cubre attest");
        // Bajo el techo determinista, un `require attest` del programa NO concede nada.
        let mut cs = CapabilitySet::new("program");
        cs.ceiling = Some(Rc::new(det));
        cs.grant(want.clone());
        assert!(!cs.check(&want, "attest()"), "attest negada bajo --deterministic");
        // Sin techo y con `require attest` explícito sí pasa; sin el require, no (deny-by-default).
        let mut open = CapabilitySet::new("program");
        assert!(!open.check(&want, "attest()"));
        open.grant(want.clone());
        assert!(open.check(&want, "attest()"));
    }
}

#[cfg(test)]
mod delegated_ceiling_tests {
    use super::*;

    fn cap(name: &str, scope: Option<&str>) -> Capability {
        Capability::new(capability_type_from_name(name).unwrap(), scope.map(|s| s.to_string()))
    }

    /// El token gobierna la autoridad transferible y deja pasar lo local al proceso.
    #[test]
    fn delegated_ceiling_cuts_transferable_and_passes_process_local() {
        let mut cs = CapabilitySet::new("request");
        cs.grant_ambient(cap("stdout", None));
        cs.grant_ambient(cap("time", None));
        cs.grant(cap("net", Some("api.example.com")));
        cs.grant(cap("db", Some("orders")));
        cs.push_delegation(Delegation::token("tok-1", vec![cap("db", Some("orders"))], false));

        assert!(cs.check(&cap("db", Some("orders")), "sql()"), "lo que el token lista pasa");
        assert!(cs.check(&cap("stdout", None), "print()"), "stdout es local al proceso");
        assert!(cs.check(&cap("time", None), "now()"), "time es local al proceso");
        let cause = cs.check_cause(&cap("net", Some("api.example.com")), "fetch()").unwrap_err();
        match cause {
            DenyCause::Delegated(d) => assert_eq!(d.source, DelegationSource::Token("tok-1".into())),
            other => panic!("esperaba Delegated, got {:?}", other),
        }
        let msg = CapabilitySet::denial_message(&cap("net", Some("api.example.com")), &cause_of(&mut cs));
        assert!(msg.contains("delegated ceiling of token tok-1"), "{}", msg);
        // El audit dice de qué token vino.
        let last = cs.audit_log.last().unwrap();
        assert!(!last.granted);
        assert!(last.reason.contains("token tok-1"), "{}", last.reason);
    }

    fn cause_of(cs: &mut CapabilitySet) -> DenyCause {
        cs.check_cause(&cap("net", Some("api.example.com")), "fetch()").unwrap_err()
    }

    /// Una capability que el programa NUNCA declaró es "no grant" (culpa del programa), no
    /// "denegada por el token": el 403 es sólo para lo que el programa pidió y el token no dio.
    #[test]
    fn undeclared_is_no_grant_even_under_a_token() {
        let mut cs = CapabilitySet::new("request");
        cs.push_delegation(Delegation::token("tok-1", vec![cap("db", Some("orders"))], false));
        let cause = cs.check_cause(&cap("exec", None), "run()").unwrap_err();
        assert_eq!(cause, DenyCause::NoGrant);
        let msg = CapabilitySet::denial_message(&cap("exec", None), &cause);
        assert!(msg.contains("this is a permission, not a bug") && msg.contains("add `require exec`"), "{}", msg);
    }

    /// `deterministic` niega el reloj y la entropía (y sólo eso) aunque sean locales.
    #[test]
    fn deterministic_caveat_denies_clock_and_entropy() {
        let mut cs = CapabilitySet::new("request");
        cs.grant_ambient(cap("stdout", None));
        cs.grant_ambient(cap("time", None));
        cs.grant(cap("random", None));
        cs.push_delegation(Delegation::token("tok-det", vec![cap("net", None)], true));
        assert!(cs.check(&cap("stdout", None), "print()"));
        let t = cs.check_cause(&cap("time", None), "now()").unwrap_err();
        assert!(matches!(t, DenyCause::Delegated(_)));
        let msg = CapabilitySet::denial_message(&cap("time", None), &t);
        assert!(msg.contains("deterministic caveat of token tok-det"), "{}", msg);
        assert!(matches!(cs.check_cause(&cap("random", None), "token()").unwrap_err(), DenyCause::Delegated(_)));
    }

    /// Un `require` bajo un techo delegado que no lo cubre no se inserta, queda DECLARADO y
    /// auditado con `source: token`; y el reset por request lo vacía todo.
    #[test]
    fn grant_above_delegation_is_rejected_and_reset_clears_delegations() {
        let mut cs = CapabilitySet::new("request");
        cs.push_delegation(Delegation::token("tok-1", vec![cap("db", Some("orders"))], false));
        cs.grant(cap("net", Some("api.example.com")));
        assert!(cs.granted.is_empty());
        let e = cs.audit_log.last().unwrap();
        assert_eq!(e.source, "token");
        assert!(e.reason.contains("above delegated ceiling (token tok-1)"), "{}", e.reason);
        assert!(matches!(cs.check_cause(&cap("net", Some("api.example.com")), "fetch()").unwrap_err(), DenyCause::Delegated(_)));

        cs.reset_keeping_ceiling("request");
        assert!(cs.delegated.is_empty(), "el techo delegado es de la request, no del worker");
        cs.grant(cap("net", Some("api.example.com")));
        assert!(cs.check(&cap("net", Some("api.example.com")), "fetch()"));
    }

    /// Los techos delegados se apilan (token de la request + `sandbox under`) y todos
    /// tienen que cubrir; el host sigue mandando sobre todo, locales incluidas.
    #[test]
    fn delegations_stack_and_host_ceiling_still_wins() {
        let mut cs = CapabilitySet::new("request");
        cs.ceiling = Some(Rc::new(vec![cap("db", None), cap("net", None)]));
        cs.grant(cap("db", Some("orders")));
        cs.grant(cap("db", Some("audit")));
        // `require time` del PROGRAMA (declarada): el host la rechaza al conceder y el uso
        // dice "above host ceiling". (Un grant AMBIENTE rechazado no cuenta como declarado.)
        cs.grant(cap("time", None));
        cs.push_delegation(Delegation::token("tok-1", vec![cap("db", None)], false));
        cs.push_delegation(Delegation::block(vec![cap("db", Some("orders"))]));
        assert!(cs.check(&cap("db", Some("orders")), "sql()"));
        let c = cs.check_cause(&cap("db", Some("audit")), "sql()").unwrap_err();
        match c {
            DenyCause::Delegated(d) => assert_eq!(d.source, DelegationSource::Block),
            other => panic!("{:?}", other),
        }
        cs.pop_delegation();
        assert!(cs.check(&cap("db", Some("audit")), "sql()"));
        // El host no cubre `time` → denegada por el host aunque el token la deje pasar.
        assert_eq!(cs.check_cause(&cap("time", None), "now()").unwrap_err(), DenyCause::AboveCeiling);
        // Un hijo hereda los techos delegados.
        let rc = Rc::new(RefCell::new(cs));
        let child = CapabilitySet::create_child(&rc, "child");
        assert_eq!(child.delegated.len(), 1);
    }

    #[test]
    fn violation_carries_the_token_flag_into_the_runtime_error() {
        let mut cs = CapabilitySet::new("request");
        cs.grant(cap("net", None));
        cs.push_delegation(Delegation::token("tok-1", vec![cap("db", None)], false));
        let v = cs.require(&cap("net", None), "fetch()").unwrap_err();
        assert!(v.denied_by_token());
        let e = v.into_error();
        assert!(e.denied_by_token);
        // Un bloque `sandbox under` es decisión del programa: no es "del token".
        let mut cs2 = CapabilitySet::new("request");
        cs2.grant(cap("net", None));
        cs2.push_delegation(Delegation::block(vec![cap("db", None)]));
        let v2 = cs2.require(&cap("net", None), "fetch()").unwrap_err();
        assert!(!v2.denied_by_token());
        assert!(!v2.into_error().denied_by_token);
    }
}

//! Modelo de capabilities de Synsema.
//!
//! Port fiel de `synsema/capabilities/model.py`. Las capabilities son la base de
//! seguridad: cero acceso por defecto, grants explícitos y con scope, auditados.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::rc::Rc;

/// Categorías de capability. El orden de declaración es el desempate fijo de `Capability::cmp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    /// v0.6.46 (E3): publicar un dato privado (`declassify(v, motivo, to?)`) con las etiquetas
    /// encendidas. Scope = principal que la llamada quita (o glob: `clientes*`). Es el `unsafe` de
    /// Rust: sin techo del host la concede el runtime (sin rastro en el audit: es el modo de
    /// siempre); con techo, sólo lo que el techo nombra (`--cap-set declassify=clientes`); dentro
    /// de `sandbox`, nada salvo que `sandbox under` la delegue. Sin etiquetas no se chequea.
    Declassify,
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
            Declassify => "declassify",
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

/// Nombres aceptados por `--cap-set` (para el mensaje de error y los docs). v0.6.46 (D4): es la
/// lista de core, la misma con la que el parser rechaza un `require` desconocido.
pub const KNOWN_CAPABILITY_NAMES: &str = synsema_core::capscope::KNOWN_CAPABILITY_NAMES;

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

/// v0.6.46 (E5) — `covers` de `llm`/`judge`. El scope nombra a QUIÉN pertenece lo privado que se
/// le puede mandar al modelo, y opcionalmente a qué provider: `P` o `P@host` (`@local` = un modelo
/// en el proceso, `@embedder` = el hook de wasm). El pedido de una llamada con datos públicos no
/// lleva scope; el de una con datos de P lleva `P@<host del provider>`.
/// - Sin scope (`require llm`, `--cap-set llm`): sólo datos públicos. No cubre ningún principal.
/// - Con scope: cubre los datos públicos (antes `require llm("P")` rompía las operaciones) y los
///   de los principales que nombra (exacto o glob). Si el pedido nombra el provider y éste
///   también, tienen que coincidir (exacto o glob, sin mayúsculas); si alguno no lo nombra,
///   vale cualquiera. Así un techo `llm=P@api.x` acepta el `require llm("P")` del programa, y en
///   la llamada sólo cubre `P@api.x`.
fn llm_scope_covers(grant: Option<&str>, req: Option<&str>) -> bool {
    match (grant, req) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(g), Some(r)) => {
            let split = |s: &str| match s.rsplit_once('@') {
                Some((p, h)) => (p.to_string(), Some(h.to_ascii_lowercase())),
                None => (s.to_string(), None),
            };
            let (gp, gh) = split(g);
            let (rp, rh) = split(r);
            let principal_ok = gp == rp || fnmatch(&rp, &gp);
            principal_ok
                && match (gh, rh) {
                    (Some(g), Some(r)) => g == r || fnmatch(&r, &g),
                    _ => true,
                }
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
        "declassify" => Declassify,
        _ => return None,
    })
}

/// Una capability concreta: tipo + scope opcional.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Capability {
    pub ty: CapabilityType,
    pub scope: Option<String>,
}

/// v0.6.47 (T2): los grants y denies de un set, en su orden canónico (`Capability::cmp`). Con un
/// `HashSet`, cuando dos grants cubrían lo mismo el audit nombraba uno al azar (la semilla del hash
/// cambia por corrida): esa diferencia la elegía la corrida, no el programa.
pub type CapSet = BTreeSet<Capability>;

impl Capability {
    /// La familia del tipo: los tipos que pueden cubrirse entre sí (sólo `file` cubre a `file.read`
    /// y `file.write`; ver `covers_by_name`).
    fn family(ty: CapabilityType) -> CapabilityType {
        match ty {
            CapabilityType::FileRead | CapabilityType::FileWrite => CapabilityType::File,
            t => t,
        }
    }

    /// Los tipos donde un grant con scope cubre un pedido sin scope: en `llm`/`judge` el scope nombra
    /// los datos privados que se pueden mandar, y el pedido sin scope (datos públicos) lo cubre
    /// cualquiera (`llm_scope_covers`). En el resto, sin scope sólo lo cubre un grant sin scope.
    fn scoped_covers_unscoped(ty: CapabilityType) -> bool {
        matches!(ty, CapabilityType::Llm | CapabilityType::Judge)
    }

    /// El grant de `set` que cubre `requested`, el primero en el orden canónico (el más específico).
    /// Sólo prueba `covers` con la familia del pedido. Uno sin scope (fuera de `llm`/`judge`) sólo lo
    /// cubre un grant sin scope, y esos son los menos específicos (rango 0): van al final del set,
    /// ordenados por tipo; se los recorre desde atrás (sin comparar; buscar con `range` compara contra
    /// cada clave del nodo y cada comparación recorre los scopes) y el primero en el orden canónico es
    /// el último encontrado. En `llm`/`judge` el sin scope es el más angosto y va primero.
    fn first_covering<'a>(set: &'a CapSet, requested: &Capability) -> Option<&'a Capability> {
        let fam = Self::family(requested.ty);
        if requested.scope.is_none() && !Self::scoped_covers_unscoped(fam) {
            return set
                .iter()
                .rev()
                .take_while(|c| c.scope.is_none())
                .filter(|c| Self::family(c.ty) == fam && c.covers(requested))
                .last();
        }
        set.iter().filter(|c| Self::family(c.ty) == fam).find(|c| c.covers(requested))
    }

    /// Cuán poco cubre el grant, de mayor a menor: `(rango, sin comodín, literales)`, con la
    /// misma lectura que `covers` en cada tipo (el modelo y sus casos: `specs/t2-especificidad-modelo.md`).
    /// - rango: 2 = `llm`/`judge` sin scope (sólo lo público, lo más angosto); 1 = con scope; 0 = sin
    ///   scope en el resto (el comodín).
    /// - comodín: `*` o `?` (`[` es literal en `fnmatch` y `path_glob`). En `net` un CIDR es un rango
    ///   y cuenta los bits del prefijo (más el puerto, como en un host); en `secret`/`llm`/`judge`
    ///   el comodín se mira en el nombre: un `*` en la atadura (`@*.x.com`) no la vuelve más amplia
    ///   que no atar, y la atadura suma literales.
    ///
    /// Sólo depende del tipo y del texto del scope (no del cwd ni del entorno): el orden del `BTreeSet`
    /// no puede cambiar con el elemento adentro. Por eso una ruta relativa contra una absoluta se
    /// compara por el largo del texto (declarado).
    fn specificity(&self) -> (u8, bool, usize) {
        let wild = |c: char| matches!(c, '*' | '?');
        let literals = |s: &str| s.chars().filter(|c| !wild(*c)).count();
        let Some(s) = &self.scope else {
            return (if Self::scoped_covers_unscoped(self.ty) { 2 } else { 0 }, true, 0);
        };
        match self.ty {
            CapabilityType::Net => {
                let (host, port) = split_net_scope(s);
                let cidr = host.split_once('/').and_then(|(ip, bits)| {
                    ip.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().ok()?;
                    bits.parse::<usize>().ok()
                });
                match cidr {
                    // El puerto suma como en un host (`:9`): un CIDR con puerto es más angosto.
                    Some(bits) => (1, false, bits + port.map_or(0, |p| p.len() + 1)),
                    None => (1, !host.contains(wild), literals(s)),
                }
            }
            CapabilityType::Secret | CapabilityType::Llm | CapabilityType::Judge => {
                let (name, _) = split_secret_scope(s);
                (1, !name.contains(wild), literals(s))
            }
            _ => (1, !s.contains(wild), literals(s)),
        }
    }
}

/// v0.6.47 (T2): el orden canónico. Primero el más específico, el que cubre menos (también entre
/// tipos: `file` cubre a `file.read`; ver `specificity`); después el tipo y el scope como desempate
/// fijo. Quedarse con el primero que cubre da el grant más específico sin probar `covers` de más
/// (puede ir a disco).
impl Ord for Capability {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .specificity()
            .cmp(&self.specificity())
            .then_with(|| self.ty.cmp(&other.ty))
            .then_with(|| self.scope.cmp(&other.scope))
    }
}

impl PartialOrd for Capability {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
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
            // Un nombre de host no distingue mayúsculas (como en el URL): `net("API.x.com")`
            // cubre `api.x.com` y al revés.
            (CapabilityType::Net, Some(s)) => Some(s.to_lowercase()),
            // v0.6.46 (E1): un secret atado, `K@h1|h2` (el `require secret("K") for net(…)` y el
            // techo `secret=K@h`): el nombre a la izquierda del ÚLTIMO `@`, y cada host como un
            // scope de `net`.
            (CapabilityType::Secret, Some(s)) if s.contains('@') => {
                let (name, hosts) = s.rsplit_once('@').unwrap_or((&s, ""));
                let hosts: Vec<String> = hosts
                    .split('|')
                    .filter(|h| !h.is_empty())
                    .map(synsema_core::capscope::net_host_scope)
                    .collect();
                Some(format!("{}@{}", name, hosts.join("|")))
            }
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
    /// - v0.6.45: una RUTA además tiene que quedar dentro del scope EN DISCO — un link (symlink,
    ///   junction) debajo del scope que lleva afuera la deja afuera, aunque por nombre esté
    ///   adentro. Es la misma decisión para el grant, el techo del host y los techos delegados.
    pub fn covers(&self, other: &Capability) -> bool {
        if !self.covers_by_name(other) {
            return false;
        }
        match (self.physical_scope_pair(other), &self.scope, &other.scope) {
            (true, Some(g), Some(r)) => synsema_core::capscope::path_within_physically(g, r),
            _ => true,
        }
    }

    /// v0.6.45 — para un `deny`: ¿la ruta pedida llega EN DISCO a lo que este scope nombra? Un
    /// link a un lugar denegado da con la denegación aunque su nombre no coincida.
    pub fn reaches_physically(&self, other: &Capability) -> bool {
        if self.ty != other.ty
            && !(self.ty == CapabilityType::File
                && matches!(other.ty, CapabilityType::FileRead | CapabilityType::FileWrite))
        {
            return false;
        }
        match (self.physical_scope_pair(other), &self.scope, &other.scope) {
            (true, Some(g), Some(r)) => synsema_core::capscope::path_reaches_physically(g, r),
            _ => false,
        }
    }

    /// ¿Los dos scopes son rutas de disco (file/file.read/file.write, o una base SQLite)?
    fn physical_scope_pair(&self, other: &Capability) -> bool {
        let path_ty = |t: CapabilityType| {
            matches!(t, CapabilityType::File | CapabilityType::FileRead | CapabilityType::FileWrite | CapabilityType::Db)
        };
        let url = |c: &Capability| c.ty == CapabilityType::Db && c.scope.as_deref().is_some_and(is_db_url);
        path_ty(self.ty) && path_ty(other.ty) && !url(self) && !url(other)
    }

    /// La comparación por NOMBRE de `covers` (sin mirar el disco): la de siempre. La usa el
    /// mensaje de un rechazo para decir que fue un link y no un scope de menos.
    pub fn covers_by_name(&self, other: &Capability) -> bool {
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
            if is_db && is_db_url(s) {
                canon_url(s)
            } else {
                normalize_path(s)
            }
        };
        if Self::scoped_covers_unscoped(self.ty) {
            return llm_scope_covers(self.scope.as_deref(), other.scope.as_deref());
        }
        match &self.scope {
            // Sin scope = grant wildcard (poder máximo: cubre cualquier ruta/URL). Intacto.
            None => true,
            Some(self_scope) => match &other.scope {
                // self tiene scope, other None → no cubre (paridad con Python).
                None => false,
                Some(other_scope) => {
                    if is_path {
                        // v0.6.45: una ruta relativa contra una absoluta se compara en la misma forma
                        // (la relativa, con el cwd). Las URLs de base de datos, tal cual.
                        let url = is_db && (is_db_url(self_scope) || is_db_url(other_scope));
                        let (g0, r0) = if url {
                            (canon(self_scope), canon(other_scope))
                        } else {
                            synsema_core::capscope::same_form(self_scope, other_scope)
                        };
                        let grant = case_fold(g0);
                        let req = case_fold(r0);
                        // Una URL de base de datos sigue con el glob de siempre; una ruta, con el
                        // glob por segmentos (v0.6.45: `*` ya no cruza `/` ni `..`).
                        // `db("*")` sigue cubriendo una URL pedida (el glob de siempre).
                        grant == req
                            || if url { fnmatch(&req, &grant) } else { synsema_core::capscope::path_glob(&req, &grant) }
                    } else if self.ty == CapabilityType::Secret {
                        // v0.6.46 (E1): el nombre como siempre (exacto o glob); si este lado ata
                        // el secret a hosts, el otro tiene que estar atado a hosts que éstos
                        // cubran. Sin atadura de este lado, cubre con o sin atadura del otro.
                        let (gn, gh) = split_secret_scope(self_scope);
                        let (rn, rh) = split_secret_scope(other_scope);
                        let name_ok = gn == rn || fnmatch(rn, gn);
                        name_ok
                            && match (gh, rh) {
                                (None, _) => true,
                                (Some(_), None) => false,
                                (Some(g), Some(r)) => r.split('|').all(|h| {
                                    g.split('|').any(|p| synsema_core::capscope::bound_host_covers(p, h))
                                }),
                            }
                    } else if self.ty == CapabilityType::Net {
                        // Host y puerto por separado: un grant sin puerto cubre cualquier puerto
                        // del host; con puerto, sólo ese.
                        let (gh, gp) = split_net_scope(self_scope);
                        let (rh, rp) = split_net_scope(other_scope);
                        // v0.6.46 (E7): un CIDR (`net("10.0.0.0/8")`) cubre una IP literal de adentro.
                        let host_ok = gh == rh
                            || fnmatch(rh, gh)
                            || self_scope == other_scope
                            || rh.parse::<std::net::IpAddr>().is_ok_and(|ip| cidr_contains(gh, ip) == Some(true));
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

/// v0.6.46 (E1): un scope de `secret` → `(nombre, hosts de la atadura)`: `K@h1|h2` →
/// `("K", Some("h1|h2"))`, `K` → `("K", None)`. Se parte en el ÚLTIMO `@`.
pub fn split_secret_scope(scope: &str) -> (&str, Option<&str>) {
    match scope.rsplit_once('@') {
        Some((n, h)) => (n, Some(h)),
        None => (scope, None),
    }
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

// =========================================================
// v0.6.46 (E7): `net` mira la IP a la que conecta (SSRF)
// =========================================================
// Un grant con comodín (`require net` sin scope, `"*"`, `"*.x.com"`; un techo o un `sandbox under`
// igual) sólo llega a IPs PÚBLICAS. Una IP privada (loopback, RFC 1918, CGNAT, link-local con los
// metadatos de la nube, ULA, multicast, documentación) exige que CADA capa nombre el destino: el
// host exacto, la IP o un CIDR que la contenga. El cliente resuelve una vez, chequea la IP y conecta
// a ésa: no queda ventana para un DNS que cambie entre las dos.

/// ¿`ip` es una dirección pública de internet? Una IPv4 mapeada o traducida en IPv6 (`::ffff:a.b.c.d`,
/// NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) vale lo que valga la IPv4 de adentro.
pub fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip.to_canonical() {
        std::net::IpAddr::V4(a) => public_v4(a),
        std::net::IpAddr::V6(a) => public_v6(a),
    }
}

fn public_v4(a: std::net::Ipv4Addr) -> bool {
    let [b0, b1, b2, _] = a.octets();
    !(b0 == 0                                             // "esta red"
        || b0 == 10                                       // RFC 1918
        || b0 == 127                                      // loopback
        || b0 >= 224                                      // multicast, reservada, broadcast
        || (b0 == 100 && (64..128).contains(&b1))         // CGNAT 100.64/10
        || (b0 == 169 && b1 == 254)                       // link-local (metadatos de la nube)
        || (b0 == 172 && (16..32).contains(&b1))          // RFC 1918
        || (b0 == 192 && b1 == 0 && (b2 == 0 || b2 == 2)) // IETF 192.0.0/24, TEST-NET-1
        || (b0 == 192 && b1 == 88 && b2 == 99)            // relay 6to4
        || (b0 == 192 && b1 == 168)                       // RFC 1918
        || (b0 == 198 && (b1 == 18 || b1 == 19))          // benchmarking
        || (b0 == 198 && b1 == 51 && b2 == 100)           // TEST-NET-2
        || (b0 == 203 && b1 == 0 && b2 == 113))           // TEST-NET-3
}

fn public_v6(a: std::net::Ipv6Addr) -> bool {
    let s = a.segments();
    // NAT64 (64:ff9b::/96) y 6to4 (2002::/16) llevan una IPv4 adentro.
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return public_v4(std::net::Ipv4Addr::from(((s[6] as u32) << 16) | s[7] as u32));
    }
    if s[0] == 0x2002 {
        return public_v4(std::net::Ipv4Addr::from(((s[1] as u32) << 16) | s[2] as u32));
    }
    // Sólo 2000::/3 es unicast global (deja afuera ::1, ::, ULA fc00::/7, fe80::/10, ff00::/8,
    // 64:ff9b:1::/48, 100::/64). Adentro, lo de la IETF (2001::/23, con Teredo) y documentación.
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && s[1] < 0x200)
        && !(s[0] == 0x2001 && s[1] == 0xdb8)
        && !(s[0] == 0x3fff && s[1] < 0x1000)
}

/// `Some(¿adentro?)` si `scope` es un CIDR (`10.0.0.0/8`, `fd00::/8`); `None` si no lo es.
fn cidr_contains(scope: &str, ip: std::net::IpAddr) -> Option<bool> {
    use std::net::IpAddr;
    let (net, bits) = scope.split_once('/')?;
    let net: IpAddr = net.trim_start_matches('[').trim_end_matches(']').parse().ok()?;
    let bits: u32 = bits.parse().ok()?;
    Some(match (net.to_canonical(), ip.to_canonical()) {
        (IpAddr::V4(n), IpAddr::V4(i)) if bits <= 32 => {
            let m = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(n) & m == u32::from(i) & m
        }
        (IpAddr::V6(n), IpAddr::V6(i)) if bits <= 128 => {
            let m = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(n) & m == u128::from(i) & m
        }
        _ => false,
    })
}

/// ¿El scope de `net` NOMBRA el destino `dest` (`host` o `host:puerto`) que resolvió a `ip`? Lo
/// nombra el host exacto, la IP exacta o un CIDR que la contenga, con la regla de puerto de
/// siempre. Un comodín (sin scope, `*`, `*.x.com`) nunca lo nombra.
pub fn net_scope_names(scope: &str, dest: &str, ip: std::net::IpAddr) -> bool {
    let (gh, gp) = split_net_scope(scope);
    let (rh, rp) = split_net_scope(dest);
    if gp.is_some() && gp != rp {
        return false;
    }
    if let Some(inside) = cidr_contains(gh, ip) {
        return inside;
    }
    if gh.contains(['*', '?', '[']) {
        return false;
    }
    gh == rh || gh.parse::<std::net::IpAddr>().is_ok_and(|g| g.to_canonical() == ip.to_canonical())
}

/// Las capas de `net` de un `CapabilitySet` (denegaciones, grants propios y de los padres, techo
/// del host, techos delegados), en forma OWNED: se manda a otro hilo (el lado async de `proxy to`).
#[derive(Clone, Debug, Default)]
pub struct NetLayers {
    denied: Vec<Capability>,
    granted: Vec<Capability>,
    ceiling: Option<Vec<Capability>>,
    delegated: Vec<Delegation>,
}

impl NetLayers {
    /// ¿Se puede conectar a `dest` (`host[:puerto]`), que resolvió a `ip`? A una IP pública, sí (el
    /// gate por nombre ya pasó); a una privada, sólo si cada capa la nombra.
    pub fn admits(&self, dest: &str, ip: std::net::IpAddr) -> Result<(), DenyCause> {
        let names = |c: &Capability| c.scope.as_deref().is_some_and(|g| net_scope_names(g, dest, ip));
        // Un `deny net("10.0.0.0/8")` alcanza también a un nombre que resuelve adentro.
        if let Some(d) = self.denied.iter().find(|d| names(d)) {
            return Err(DenyCause::ExplicitlyDenied(d.clone()));
        }
        if is_public_ip(ip) {
            return Ok(());
        }
        if self.ceiling.as_ref().is_some_and(|c| !c.iter().any(names)) {
            return Err(DenyCause::AboveCeiling);
        }
        if let Some(d) = self.delegated.iter().find(|d| !d.caps.iter().any(names)) {
            return Err(DenyCause::Delegated(d.clone()));
        }
        if self.granted.iter().any(names) {
            Ok(())
        } else {
            Err(DenyCause::NoGrant)
        }
    }
}

/// El mensaje de una conexión a una IP privada que alguna capa no nombra.
pub fn private_dest_message(who: &str, dest: &str, ip: std::net::IpAddr, cause: &DenyCause) -> String {
    let host = split_net_scope(dest).0;
    let what = format!("{}: `{}` resolved to {}, a private address", who, host, ip.to_canonical());
    match cause {
        DenyCause::ExplicitlyDenied(d) => format!("{}, explicitly denied by {}", what, d),
        DenyCause::AboveCeiling => format!(
            "{}; the host ceiling (--sandbox/--cap-set) reaches only public addresses for it. The program cannot fix this; the host must name it: `--cap-set net={}`",
            what, dest
        ),
        DenyCause::Delegated(d) => format!(
            "{}; the {} reaches only public addresses for it: name it there (`net(\"{}\")`)",
            what,
            match &d.source {
                DelegationSource::Token(id) => format!("delegated ceiling of token {}", id),
                DelegationSource::Block => "enclosing `sandbox under` block".to_string(),
            },
            dest
        ),
        DenyCause::NoGrant => format!(
            "{}; a `net` grant with a wildcard reaches only public addresses. Name it: `require net(\"{}\")`, its address or its CIDR (the scope can come from the configuration: `require net(env(\"…_URL\"))`)",
            what, dest
        ),
    }
}

/// Canoniza una URL de conexión (Postgres/MySQL/…) a `scheme://host/dbname`:
/// minúsculas, **sin credenciales** (userinfo), **sin puerto**, **sin query/fragment**.
/// Es el scope canónico de la capability `db` para motores remotos (el `://` lo distingue
/// de una ruta de archivo SQLite). Preserva un `*` como nombre/host para los globs
/// (`db("postgres://localhost/*")`). Idempotente.
pub fn canon_url(url: &str) -> String {
    // Ronda 4 (revisión, B6): sin espacios adelante, como `is_db_url` y `db_open`.
    let url = url.trim_start();
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

// `fnmatch` y `normalize_path` viven en `synsema_core::capscope` (los usa también
// `synsema check`, que no puede depender de este crate): un solo matcher de scopes.
pub use synsema_core::capscope::{fnmatch, normalize_path};

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
/// v0.6.45 (ronda 3, A2) — ¿un scope de `db` es la URL de un servidor? El MISMO criterio que usa
/// `db_open` para elegir backend (esquemas conocidos), no "contiene `://`": `data/a://../../x.db` se
/// juzgaba como URL (sin chequeo de ruta, con el glob que cruza `/`) y se abría como un archivo de
/// SQLite fuera del scope.
pub fn is_db_url(s: &str) -> bool {
    synsema_core::capscope::is_db_url(s)
}

/// v0.6.45 — el `reason` del audit cuando un grant cubre la ruta por nombre y un link la saca.
pub const LINK_ESCAPE: &str = "resolves outside the grant through a link";
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
    /// v0.6.49 (B2): el módulo de confianza en cuyo scope se hizo (`trusted:<módulo>`), o `None`.
    /// Lo pone `push_audit`; el JSONL del nativo ya lo decía en `context`, y wasm no lo veía.
    pub context: Option<String>,
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
    /// `trusted:<módulo>` si la entrada nació dentro de una tool de confianza.
    pub context: Option<String>,
}

impl From<&CapabilityAuditEntry> for AuditEntry {
    fn from(e: &CapabilityAuditEntry) -> Self {
        AuditEntry {
            capability: e.capability.to_string(),
            granted: e.granted,
            source: e.source.clone(),
            reason: e.reason.clone(),
            origin: e.origin.to_string(),
            context: e.context.clone(),
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

    /// v0.6.46 (E6): la entrada en el registro de la corrida del recibo sellado. La pública va sin
    /// hora (afuera del sobre el recibo sólo dice cuándo empezó la corrida); la sellada, con la hora
    /// del reloj de la corrida.
    #[cold]
    #[inline(never)]
    pub(super) fn record_run(context: &str, entry: &CapabilityAuditEntry, sealed: bool) {
        let (file, line) = match synsema_core::audit_loc::current() {
            Some(loc) => (Some(loc.file.to_string()), Some(loc.line)),
            None => (None, None),
        };
        let mut v = serde_json::json!({
            "kind": "capability",
            "context": context,
            "capability": entry.capability.to_string(),
            "granted": entry.granted,
            "source": entry.source,
            "reason": entry.reason,
            "origin": entry.origin,
            "file": file,
            "line": line,
        });
        if sealed {
            v["ts"] = serde_json::json!(iso8601_millis(synsema_core::clock::now_secs_f64()));
            synsema_core::sealed::push_sealed(v.to_string());
        } else {
            synsema_core::sealed::push_public(v.to_string());
        }
    }

    pub(super) fn emit(context: &str, entry: &CapabilityAuditEntry) {
        if !INSTALLED.load(Ordering::Acquire) {
            return;
        }
        if let Some(sink) = SINK.get() {
            let (file, line) = match synsema_core::audit_loc::current() {
                Some(loc) => (Some(loc.file.to_string()), Some(loc.line)),
                None => (None, None),
            };
            let ts = iso8601_millis(synsema_core::clock::now_secs_f64());
            sink(&AuditEvent { ts, context, entry, file, line });
        }
    }
}

/// v0.6.46 (E3b): lo que el scope de un módulo de confianza deja de lado y devuelve al salir.
pub struct TrustedSaved {
    name: String,
    granted: CapSet,
    denied: CapSet,
    parent: Option<Rc<RefCell<CapabilitySet>>>,
    ceiling: Option<Rc<Vec<Capability>>>,
    delegated: Vec<Rc<Delegation>>,
    rejected_by_ceiling: Vec<Capability>,
}

/// Conjunto de capabilities otorgadas, con audit trail. Cada contexto de ejecución
/// (global, sandbox, agente) tiene el suyo.
pub struct CapabilitySet {
    pub name: String,
    pub granted: CapSet,
    pub denied: CapSet,
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
    /// v0.6.50 (E-b): el agente que corre con este set: un `require` que falta va en su cuerpo,
    /// no en el preámbulo del programa (que no le llega). Lo heredan sus hijos.
    pub agent: Option<String>,
    /// v0.6.50 (ronda 1, B4): cuántos bloques `sandbox` hay abiertos sobre este set (el hook los
    /// vacía y restaura): adentro, lo que falta no se arregla con un `require`.
    pub sandbox_depth: u32,
}

impl CapabilitySet {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            granted: CapSet::new(),
            denied: CapSet::new(),
            audit_log: Vec::new(),
            rejected_by_ceiling: Vec::new(),
            parent: None,
            ceiling: None,
            delegated: Vec::new(),
            agent: None,
            sandbox_depth: 0,
        }
    }

    /// El motivo de un rechazo del techo. v0.6.49 (B3): `llm("P")`/`judge("P")` contra un techo que
    /// tiene `llm`/`judge` SIN principal decía sólo "above host ceiling", y el programa veía andar sus
    /// llamadas públicas (ésas las cubre el `llm` de ambiente): el motivo dice qué ítem falta.
    fn ceiling_reason(&self, cap: &Capability) -> String {
        if let (CapabilityType::Llm | CapabilityType::Judge, Some(scope), Some(c)) = (&cap.ty, &cap.scope, &self.ceiling) {
            if c.iter().any(|a| a.ty == cap.ty && a.scope.is_none()) {
                let principal = scope.rsplit_once('@').map_or(scope.as_str(), |(p, _)| p);
                return format!(
                    "{}: the ceiling's `{ty}` allows public data only; data private to {p} goes to the model with `{ty}={p}@<provider host>`",
                    ABOVE_CEILING,
                    ty = cap.ty.name_lower(),
                    p = principal
                );
            }
        }
        ABOVE_CEILING.to_string()
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

    /// v0.6.46 (E3): `declassify` de ambiente (D3: el `unsafe` de Rust), sólo SIN techo y sin scope.
    /// Va directo a `granted`, sin entrada de audit: la tenía todo programa, declasificara o no, y
    /// el audit de cada corrida habría cambiado. Así `sandbox` la vacía como a todo grant, y
    /// serve la recupera en cada request desde el snapshot del preámbulo.
    ///
    /// v0.6.49 (A1): con techo no hay nada de ambiente. La concede el `require declassify("P")` del
    /// programa (o de la task de confianza), que pasa por el techo como cualquier `require`, igual
    /// que `net`: se publica lo que el programa declara Y el techo permite. Antes se concedía cada
    /// ítem `declassify=…` del techo, declarara el programa o no.
    pub fn grant_ambient_declassify(&mut self) {
        if self.ceiling.is_none() {
            self.granted.insert(Capability::new(CapabilityType::Declassify, None));
        }
    }

    /// v0.6.46 (E3b): entra al scope de un módulo de confianza. Deja de lado TODO lo del llamador
    /// (grants, denials, padre, techo, techos delegados) y concede lo de ambiente (`stdout`, `time`;
    /// `declassify` sólo sin techo de confianza, v0.6.49 A1) más lo que la task declaró, filtrado por ese techo
    /// (sin techo de confianza, lo declarado entero). El audit de adentro sale con el nombre
    /// `trusted:<módulo>`. `leave_trusted_scope` lo devuelve todo.
    pub fn enter_trusted_scope(
        &mut self,
        module: &str,
        ceiling: Option<Rc<Vec<Capability>>>,
        declared: &[Capability],
    ) -> TrustedSaved {
        let saved = TrustedSaved {
            name: std::mem::replace(&mut self.name, format!("trusted:{}", module)),
            granted: std::mem::take(&mut self.granted),
            denied: std::mem::take(&mut self.denied),
            parent: self.parent.take(),
            ceiling: std::mem::replace(&mut self.ceiling, ceiling),
            delegated: std::mem::take(&mut self.delegated),
            rejected_by_ceiling: std::mem::take(&mut self.rejected_by_ceiling),
        };
        for ty in [CapabilityType::Stdout, CapabilityType::Time] {
            let c = Capability::new(ty, None);
            if self.within_ceiling(&c) {
                self.granted.insert(c);
            }
        }
        self.grant_ambient_declassify();
        for c in declared {
            self.grant(c.clone());
        }
        saved
    }

    /// v0.6.46 (E3b): sale del scope de confianza (ver `enter_trusted_scope`).
    pub fn leave_trusted_scope(&mut self, s: TrustedSaved) {
        self.name = s.name;
        self.granted = s.granted;
        self.denied = s.denied;
        self.parent = s.parent;
        self.ceiling = s.ceiling;
        self.delegated = s.delegated;
        self.rejected_by_ceiling = s.rejected_by_ceiling;
    }

    /// v0.6.46 (E5): ¿el techo del host tiene un ítem que nombra el provider (`P@host`, `P@*` para
    /// cualquiera) y cubre esta capability? Para lo que sólo el host puede permitir (mandarle a un
    /// modelo datos privados): sin techo, no; con `llm=P` o `llm=*` sin `@`, tampoco (ronda 1, M2:
    /// valía "a cualquier provider", y `llm=*` era "todo lo privado a cualquier modelo").
    pub fn ceiling_names(&self, cap: &Capability) -> bool {
        self.ceiling.as_ref().is_some_and(|c| {
            c.iter().any(|a| a.scope.as_deref().is_some_and(|s| s.contains('@')) && a.covers(cap))
        })
    }

    /// Pushea una entrada al `audit_log` del set y la entrega al sink del proceso (si
    /// hay). ÚNICO camino de escritura del audit: todo chequeo/grant pasa por acá.
    pub fn push_audit(&mut self, mut entry: CapabilityAuditEntry) {
        if self.name.starts_with("trusted:") {
            entry.context = Some(self.name.clone());
        }
        // v0.6.45 (ronda 4, M5): con etiquetas, una entrada generada en una rama decidida por un valor
        // privado no se registra: cuántas hubo decía qué rama se tomó y cuántas vueltas dio un bucle
        // privado (5 entradas con n=1, 54 con n=50). Lo que audita en serio (`sign`/`spend`/
        // `reveal`/wallet) ya no corre en una rama privada; el recibo sellado de v0.6.46 va a
        // registrar estas entradas sin revelar la rama.
        //
        // v0.6.46 (E6): con el recibo sellado, va al sobre (ni al sink del proceso ni al `audit_log`);
        // la pública queda además en el registro de la corrida, en orden con las selladas.
        if synsema_core::labels::pc_private_now() {
            if synsema_core::sealed::active() {
                audit_sink::record_run(&self.name, &entry, true);
            }
            return;
        }
        audit_sink::emit(&self.name, &entry);
        if synsema_core::sealed::active() {
            audit_sink::record_run(&self.name, &entry, false);
        }
        self.audit_log.push(entry);
    }

    fn grant_from(&mut self, capability: Capability, origin: &'static str) {
        // Fail-closed: si el host puso un techo y no cubre esta capability, NO se inserta
        // (el techo nunca amplía). Se audita el rechazo. Sin techo → inserta como siempre.
        if !self.within_ceiling(&capability) {
            if origin == "program" {
                self.rejected_by_ceiling.push(capability.clone());
            }
            let reason = self.ceiling_reason(&capability);
            self.push_audit(CapabilityAuditEntry {
                capability,
                granted: false,
                source: "ceiling".to_string(),
                reason,
                origin,
                context: None,
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
                context: None,
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
                context: None,
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
        let denied_by: Option<Capability> = self
            .denied
            .iter()
            .find(|d| d.covers_by_name(requested) || d.reaches_physically(requested))
            .cloned();
        if let Some(d) = denied_by {
            if audit {
                self.push_audit(CapabilityAuditEntry {
                    capability: requested.clone(),
                    granted: false,
                    source: source.to_string(),
                    reason: format!("Explicitly denied by {}", d),
                    origin: "program",
                    context: None,
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
                    reason: self.ceiling_reason(requested),
                    origin: "program",
                    context: None,
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
                            context: None,
                        });
                    }
                    return Err(DenyCause::Delegated((*d).clone()));
                }
            }
        }

        // 2) Grants.
        let granted_by: Option<Capability> = Capability::first_covering(&self.granted, requested).cloned();
        if let Some(c) = granted_by {
            if audit {
                self.push_audit(CapabilityAuditEntry {
                    capability: requested.clone(),
                    granted: true,
                    source: source.to_string(),
                    reason: format!("Granted by {}", c),
                    origin: "program",
                    context: None,
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
            let reason = if self.escapes_through_link(requested) {
                LINK_ESCAPE
            } else {
                "No matching grant found"
            };
            self.push_audit(CapabilityAuditEntry {
                capability: requested.clone(),
                granted: false,
                source: source.to_string(),
                reason: reason.to_string(),
                origin: "program",
                context: None,
            });
        }
        Err(DenyCause::NoGrant)
    }

    /// v0.6.46 (E7): las capas de `net` de este set y de sus padres (ver `NetLayers`).
    pub fn net_layers(&self) -> NetLayers {
        let net = |c: &&Capability| c.ty == CapabilityType::Net;
        let mut layers = NetLayers {
            denied: Vec::new(),
            granted: Vec::new(),
            ceiling: self.ceiling.as_ref().map(|c| c.iter().filter(net).cloned().collect()),
            delegated: self
                .delegated
                .iter()
                .map(|d| Delegation { caps: d.caps.iter().filter(net).cloned().collect(), ..(**d).clone() })
                .collect(),
        };
        let mut collect = |set: &CapabilitySet| {
            layers.denied.extend(set.denied.iter().filter(net).cloned());
            layers.granted.extend(set.granted.iter().filter(net).cloned());
        };
        collect(self);
        let mut next = self.parent.clone();
        while let Some(p) = next {
            collect(&p.borrow());
            next = p.borrow().parent.clone();
        }
        layers
    }

    /// v0.6.49 (A5): el primer grant de `net` con un CIDR (`net("10.0.0.0/8")`), propio o de un padre,
    /// cuando lo pedido es un NOMBRE. Un CIDR cubre las direcciones escritas como tales y nunca un
    /// nombre, resuelva a donde resuelva (el permiso no depende del DNS, como en E7): el mensaje lo
    /// dice y nombra el `require` del nombre, que es lo que lo arregla.
    fn cidr_grant_for_name(&self, requested: &Capability) -> Option<Capability> {
        if requested.ty != CapabilityType::Net {
            return None;
        }
        let (host, _) = split_net_scope(requested.scope.as_deref()?);
        if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        let is_cidr = |c: &&Capability| {
            c.ty == CapabilityType::Net
                && c.scope.as_deref().is_some_and(|g| {
                    let (gh, _) = split_net_scope(g);
                    cidr_contains(gh, std::net::IpAddr::from([0u8, 0, 0, 0])).is_some()
                        || cidr_contains(gh, std::net::IpAddr::from([0u16; 8])).is_some()
                })
        };
        self.granted
            .iter()
            .find(is_cidr)
            .cloned()
            .or_else(|| self.parent.as_ref().and_then(|p| p.borrow().cidr_grant_for_name(requested)))
    }

    /// v0.6.45 — ¿un grant la cubre por NOMBRE pero no en disco? Es un link debajo del scope que
    /// lleva afuera, no un `require` que falta: el mensaje y el audit lo dicen.
    fn escapes_through_link(&self, requested: &Capability) -> bool {
        self.granted.iter().any(|c| c.covers_by_name(requested))
            || self.parent.as_ref().map(|p| p.borrow().escapes_through_link(requested)).unwrap_or(false)
    }

    /// v0.6.46: los `deny` de este set y de sus padres, copiados: para lo que recorre un árbol en
    /// otro hilo (`watch`), donde el set no viaja. Vacío sin ningún `deny`.
    pub fn denied_snapshot(&self) -> Vec<Capability> {
        let mut out: Vec<Capability> = self.denied.iter().cloned().collect();
        if let Some(p) = &self.parent {
            out.extend(p.borrow().denied_snapshot());
        }
        out
    }

    /// v0.6.45 — ¿un `deny` (propio o de un padre) alcanza esta capability, por nombre o en disco?
    /// Para lo que recorre un árbol bajo un solo `require` (`grep`): cada archivo de adentro tiene
    /// que respetar un `deny` del medio. Sin `deny` no hace nada (no paga ninguna consulta).
    pub fn denies(&self, requested: &Capability) -> bool {
        self.denied.iter().any(|d| d.covers_by_name(requested) || d.reaches_physically(requested))
            || self.parent.as_ref().map(|p| p.borrow().denies(requested)).unwrap_or(false)
    }

    /// v0.6.46 (E1): los hosts a los que el programa ató el secret `name` (`require secret("K") for
    /// net(…)`, en este set o en un padre): `Some("h1|h2")`, o `None` si ningún grant lo ata. Con
    /// varios grants que lo atan, todos sus hosts. Es lo que `secret("K")` pide y guarda en el valor.
    pub fn secret_binding(&self, name: &str) -> Option<String> {
        let mut hosts: Vec<String> = Vec::new();
        let mut collect = |set: &CapabilitySet| {
            // Lo rechazado por el techo también: es lo que el programa declaró, y el mensaje que
            // sigue (por encima del techo, con la línea a escribir) depende de pedirlo atado.
            for c in set.granted.iter().chain(set.rejected_by_ceiling.iter()).filter(|c| c.ty == CapabilityType::Secret) {
                if let Some((gn, Some(gh))) = c.scope.as_deref().map(split_secret_scope) {
                    if gn == name || fnmatch(name, gn) {
                        for h in gh.split('|') {
                            if !hosts.iter().any(|x| x == h) {
                                hosts.push(h.to_string());
                            }
                        }
                    }
                }
            }
        };
        collect(self);
        let mut next = self.parent.clone();
        while let Some(p) = next {
            collect(&p.borrow());
            next = p.borrow().parent.clone();
        }
        if hosts.is_empty() {
            None
        } else {
            Some(hosts.join("|"))
        }
    }

    /// v0.6.46 (E1): los hosts a los que el TECHO del host ata el secret `name` (`--cap-set
    /// secret=K@h`), para el mensaje que dice qué escribir.
    pub fn ceiling_binding(&self, name: &str) -> Option<String> {
        let c = self.ceiling.as_ref()?;
        c.iter().filter(|c| c.ty == CapabilityType::Secret).find_map(|c| match c.scope.as_deref().map(split_secret_scope) {
            Some((gn, Some(gh))) if gn == name || fnmatch(name, gn) => Some(gh.to_string()),
            _ => None,
        })
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

    /// v0.6.49 (§C): dentro de una tool de confianza el `require` que falta va en la task del
    /// módulo, no en el preámbulo del programa (que no le da nada a la tool).
    fn where_to_require(&self, message: String) -> String {
        let there = if let Some(module) = self.name.strip_prefix("trusted:") {
            format!(
                "to the task of the trusted module `{}` that needs it (a trusted task has only what it declares, within the host's --trusted-cap-set)",
                module
            )
        } else if let Some(agent) = &self.agent {
            // v0.6.50 (E-b): un agente declara las suyas; el `require` del programa no le llega.
            format!("to the body of agent {} (an agent declares its own capabilities: the program's `require` does not reach it)", agent)
        } else if self.name == "parallel" {
            // Un worker de `parallel_map` hereda de quien lo lanzó y no sabe si fue un agente.
            "to the program's preamble, or to the body of the agent that runs this code (an agent declares its own, also for its `parallel_map`)".to_string()
        } else {
            return message;
        };
        // Una sola vez: `there` puede nombrar el preámbulo (el de `parallel`).
        const LONG: &str = "to the program's preamble (or to the importing file, when this code runs in a module)";
        if message.contains(LONG) {
            message.replacen(LONG, &there, 1)
        } else {
            message.replacen("to the program's preamble", &there, 1)
        }
    }

    /// Chequea y devuelve error si no está otorgada.
    pub fn require(&mut self, requested: &Capability, source: &str) -> Result<(), CapabilityViolation> {
        if let Err(cause) = self.check_cause(requested, source) {
            let cidr = if cause == DenyCause::NoGrant { self.cidr_grant_for_name(requested) } else { None };
            let message = if cause == DenyCause::NoGrant && self.escapes_through_link(requested) {
                format!(
                    "Capability not granted: {} — by name the path is inside the granted scope, but a link (symlink or junction) on the way leads outside it. Synsema checks where a path really leads: grant the place the link points to, or remove the link",
                    requested
                )
            } else if let Some(c) = cidr {
                format!(
                    "Capability not granted: {} — {} covers the addresses inside it when the URL writes the address, never a name, whatever the name resolves to: the permission does not depend on DNS. Name the host: add `{}` to the program's preamble",
                    requested,
                    c,
                    Self::require_line(requested)
                )
            } else if cause == DenyCause::NoGrant && self.sandbox_depth > 0 {
                // v0.6.50 (ronda 1, B4): un `sandbox` deniega todo; un `require` (que puede estar
                // ya) no lo arregla. Ronda 2: también dentro de una task de confianza (N2), y una
                // capability del proceso no se propone en `sandbox under`, que no la lleva (B2).
                let who = if self.name.starts_with("trusted:") { "the trusted task" } else { "the program" };
                if is_process_local(requested.ty) {
                    format!(
                        "Capability not granted: {} — a `sandbox` block denies every capability, whatever {} declares, and `sandbox under` cannot carry {} (stdout, stdin, time and random are the process's; the host ceiling governs them): run this outside the block",
                        requested,
                        who,
                        requested.ty.wire_name()
                    )
                } else {
                    format!(
                        "Capability not granted: {} — a `sandbox` block denies every capability, whatever {} declares: to allow it inside the block use `sandbox under {{\"{}\": …}}` (what {} already has, within those caps), or run this outside the block",
                        requested,
                        who,
                        requested.ty.wire_name(),
                        who
                    )
                }
            } else {
                Self::denial_message(requested, &cause)
            };
            let message = self.where_to_require(message);
            return Err(CapabilityViolation {
                message,
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
            granted: CapSet::new(),
            denied: CapSet::new(),
            audit_log: Vec::new(),
            rejected_by_ceiling: Vec::new(),
            parent: Some(parent.clone()),
            ceiling: parent.borrow().ceiling.clone(),
            delegated: parent.borrow().delegated.clone(),
            agent: parent.borrow().agent.clone(),
            sandbox_depth: 0,
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
        // v0.6.46 (E3): la lista sale de `KNOWN_CAPABILITY_NAMES` (la escrita a mano no tenía
        // judge, sandbox_run ni attest).
        None => Err(format!("Unknown capability type: '{}'. Known: [{}]", name, KNOWN_CAPABILITY_NAMES)),
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
    /// v0.6.49 (A1): bajo un techo, `declassify` no se concede de ambiente: la concede el `require`
    /// del programa, filtrado por el techo como cualquier otro (filas 2–7 del modelo).
    #[test]
    fn a1_declassify_under_a_ceiling_needs_the_programs_require() {
        let d = |p: Option<&str>| Capability::new(CapabilityType::Declassify, p.map(|s| s.to_string()));
        let with_ceiling = |items: Vec<Capability>| {
            let mut cs = CapabilitySet::new("t");
            cs.ceiling = Some(Rc::new(items));
            cs.grant_ambient_declassify();
            cs
        };
        // Sin techo: de ambiente, sin scope (fila 1).
        let mut open = CapabilitySet::new("t");
        open.grant_ambient_declassify();
        assert!(open.check_silent(&d(Some("customers"))));
        // Techo `declassify=customers` sin `require`: nada (fila 2; antes se concedía).
        let mut cs = with_ceiling(vec![d(Some("customers"))]);
        assert!(!cs.check_silent(&d(Some("customers"))));
        // Con el `require` que el techo permite, sí (fila 3); con otro principal, no (fila 4).
        cs.grant(d(Some("customers")));
        assert!(cs.check_silent(&d(Some("customers"))));
        let mut cs = with_ceiling(vec![d(Some("customers"))]);
        cs.grant(d(Some("billing")));
        assert!(!cs.check_silent(&d(Some("billing"))) && !cs.check_silent(&d(Some("customers"))));
        assert!(cs.audit_log.iter().any(|e| !e.granted && e.capability == d(Some("billing")) && e.source == "ceiling"));
        // Un `require declassify` sin scope es más ancho que el techo y se rechaza entero (fila 5).
        let mut cs = with_ceiling(vec![d(Some("customers"))]);
        cs.grant(d(None));
        assert!(!cs.check_silent(&d(Some("customers"))));
        // Techo sin scope + `require` con scope (fila 6); techo sin `declassify` (fila 7).
        let mut cs = with_ceiling(vec![d(None)]);
        cs.grant(d(Some("customers")));
        assert!(cs.check_silent(&d(Some("customers"))) && !cs.check_silent(&d(Some("billing"))));
        let mut cs = with_ceiling(vec![Capability::new(CapabilityType::Stdout, None)]);
        cs.grant(d(Some("customers")));
        assert!(!cs.check_silent(&d(Some("customers"))));
    }

    /// v0.6.49 (A5): un CIDR no cubre un nombre, y el error lo explica sólo cuando aplica.
    #[test]
    fn a5_cidr_does_not_cover_a_name_and_the_error_says_so() {
        let net = |s: &str| Capability::new(CapabilityType::Net, Some(s.to_string()));
        let mut cs = CapabilitySet::new("t");
        cs.grant(net("10.0.0.0/8"));
        assert!(cs.require(&net("10.1.2.3:1"), "t").is_ok());
        let e = cs.require(&net("10.1.2.3.nip.io:1"), "t").unwrap_err().to_string();
        assert!(e.contains("net(\"10.0.0.0/8\") covers the addresses inside it") && e.contains("does not depend on DNS"), "{}", e);
        assert!(e.contains("`require net(\"10.1.2.3.nip.io:1\")`"), "{}", e);
        // Una dirección fuera del rango no es un nombre: el mensaje de siempre (fila 4).
        let e = cs.require(&net("[::1]:1"), "t").unwrap_err().to_string();
        assert!(!e.contains("DNS") && e.contains("this is a permission, not a bug"), "{}", e);
        // Sin CIDR, el mensaje de siempre (fila 3).
        let mut cs = CapabilitySet::new("t");
        cs.grant(net("api.x.com"));
        let e = cs.require(&net("db.internal"), "t").unwrap_err().to_string();
        assert!(!e.contains("DNS") && e.contains("this is a permission, not a bug"), "{}", e);
        // También un CIDR IPv6 y uno heredado del padre.
        let parent = Rc::new(RefCell::new(CapabilitySet::new("p")));
        parent.borrow_mut().grant(net("fd00::/8"));
        let mut child = CapabilitySet::create_child(&parent, "c");
        let e = child.require(&net("db.internal"), "t").unwrap_err().to_string();
        assert!(e.contains("net(\"fd00::/8\")") && e.contains("does not depend on DNS"), "{}", e);
    }

    /// v0.6.49 (B2): lo que se audita dentro de una tool de confianza lleva `trusted:<módulo>`;
    /// antes y después, nada.
    #[test]
    fn b2_audit_inside_a_trusted_scope_names_the_module() {
        let stdout = Capability::new(CapabilityType::Stdout, None);
        let mut cs = CapabilitySet::new("program");
        cs.grant(stdout.clone());
        let saved = cs.enter_trusted_scope("tools", None, &[Capability::new(CapabilityType::Time, None)]);
        let _ = cs.require(&stdout, "print()");
        cs.leave_trusted_scope(saved);
        let _ = cs.require(&stdout, "print()");
        let ctx: Vec<Option<&str>> = cs.audit_log.iter().map(|e| e.context.as_deref()).collect();
        assert_eq!(ctx, [Some("trusted:tools"), None]);
        let exported = export_audit(&Rc::new(RefCell::new(cs)));
        assert_eq!(exported.iter().map(|a| a.context.as_deref()).collect::<Vec<_>>(), [Some("trusted:tools"), None]);
    }

    /// v0.6.49 (B3): `llm("P")` contra un techo con `llm` sin principal: el motivo dice qué ítem falta.
    #[test]
    fn b3_scoped_llm_above_an_unscoped_ceiling_says_which_item() {
        let llm = |s: Option<&str>| Capability::new(CapabilityType::Llm, s.map(str::to_string));
        let mut cs = CapabilitySet::new("t");
        cs.ceiling = Some(Rc::new(vec![Capability::new(CapabilityType::Stdout, None), llm(None)]));
        cs.grant(llm(Some("a")));
        let r = &cs.audit_log.last().unwrap().reason;
        assert!(r.starts_with(ABOVE_CEILING) && r.contains("`llm=a@<provider host>`"), "{}", r);
        // Sin `llm` en el techo, el motivo de siempre.
        let mut cs = CapabilitySet::new("t");
        cs.ceiling = Some(Rc::new(vec![Capability::new(CapabilityType::Stdout, None)]));
        cs.grant(llm(Some("a")));
        assert_eq!(cs.audit_log.last().unwrap().reason, ABOVE_CEILING);
    }

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
    fn a_net_grant_without_a_scheme_ignores_case() {
        let g = Capability::new(CapabilityType::Net, Some("API.Example.com:8080".into()));
        assert!(g.covers(&Capability::new(CapabilityType::Net, Some("api.example.com:8080".into()))));
        let g = Capability::new(CapabilityType::Net, Some("*.Example.COM".into()));
        assert!(g.covers(&Capability::new(CapabilityType::Net, Some("https://Api.example.com".into()))));
        assert!(!g.covers(&Capability::new(CapabilityType::Net, Some("api.other.com".into()))));
    }

    #[test]
    fn covers_closes_traversal_bypass() {
        // El caso estrella del fix #5: scope acotado ya NO se escapa con `..`.
        let grant = cap(CapabilityType::FileRead, Some("./data/*"));
        let ok = cap(CapabilityType::FileRead, Some("./data/report.csv"));
        let escape = cap(CapabilityType::FileRead, Some("./data/../../etc/passwd"));
        assert!(grant.covers(&ok), "ruta dentro del scope debe cubrirse");
        assert!(!grant.covers(&escape), "el bypass `..` debe quedar fuera del scope");

        // v0.6.45: el glob de ruta es por segmentos — `*` es "esta carpeta" y ya no cruza `/` ni
        // `..` (antes `*` era poder total por nombre). El poder total es `require file.read` sin scope.
        let star = cap(CapabilityType::FileRead, Some("*"));
        assert!(!star.covers(&escape));
        assert!(star.covers(&cap(CapabilityType::FileRead, Some("./x.csv"))));
        assert!(!star.covers(&cap(CapabilityType::FileRead, Some("./data/x.csv"))));
        let total = cap(CapabilityType::File, None);
        assert!(total.covers(&escape));
    }

    /// v0.6.45 — el glob de un scope de ruta, por segmentos.
    #[test]
    fn path_globs_match_by_segment() {
        let g = |p: &str, pat: &str| synsema_core::capscope::path_glob(&normalize_path(p), &normalize_path(pat));
        // `*` dentro de un segmento; `**` cruza (y cubre la carpeta misma).
        assert!(g("data/a.csv", "./data/*"));
        assert!(!g("data/sub/a.csv", "./data/*"));
        assert!(g("data/sub/a.csv", "./data/**"));
        assert!(g("data", "./data/**"));
        assert!(g("data/sub/a.csv", "./data/**/*.csv"));
        assert!(!g("data/sub/a.txt", "./data/**/*.csv"));
        assert!(g("x.csv", "*.csv"));
        assert!(!g("data/x.csv", "*.csv"));
        assert!(!g("/etc/x.csv", "*.csv"));
        // Ningún comodín coincide con `..` ni salta de relativa a absoluta.
        assert!(!g("../x.csv", "*.csv"));
        assert!(!g("../x", "**"));
        assert!(!g("/etc/passwd", "./**"));
        assert!(g("/etc/passwd", "/etc/*"));
        assert!(g("C:/Users/x/a.txt", "C:/Users/*/a.txt"));
        assert!(!g("D:/Users/x/a.txt", "C:/**"));
        // Scope contra scope (el techo al conceder): un `**` pedido sólo lo cubre un `**`.
        assert!(!g("data/**", "./data/*"));
        assert!(g("data/*", "./data/**"));
        // Ronda 2 (N1): un segmento pedido con comodines sólo lo cubre uno idéntico o `*`.
        assert!(!g("data/a*", "./data/a?"));
        assert!(!g("*", "./?"));
        assert!(g("data/a*", "./data/*"));
        assert!(g("data/a*", "./data/a*"));
    }

    /// Ronda 2 (N2): un `deny` sobre una unidad que no existe no deniega TODO archivo (su lugar no se
    /// puede resolver: no alcanza a nada por el disco; por nombre sigue valiendo).
    #[cfg(windows)]
    #[test]
    fn a_deny_on_a_missing_drive_does_not_deny_everything() {
        let Some(missing) = ('D'..='Z').rev().find(|d| !std::path::Path::new(&format!("{}:\\", d)).exists()) else { return };
        let mut set = CapabilitySet::new("t");
        set.grant(cap(CapabilityType::FileRead, None));
        set.deny(cap(CapabilityType::FileRead, Some(&format!("{}:/x/*", missing))));
        let here = std::env::temp_dir().join("synsema-n2.txt").to_string_lossy().replace('\\', "/");
        assert!(set.check_cause(&cap(CapabilityType::FileRead, Some(&here)), "t").is_ok());
        assert!(set.check_cause(&cap(CapabilityType::FileRead, Some(&format!("{}:/x/a", missing))), "t").is_err());
    }

    /// v0.6.45 — un link debajo del scope que lleva afuera: el grant no lo cubre (aunque por nombre
    /// sí) y un `deny` del destino lo alcanza (aunque por nombre no).
    #[test]
    fn a_link_under_the_scope_is_judged_where_it_leads() {
        let root = std::env::temp_dir().join(format!("synsema-v0645-capslink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("data")).unwrap();
        std::fs::create_dir_all(root.join("outside")).unwrap();
        std::fs::write(root.join("outside/secret.txt"), "x").unwrap();
        #[cfg(windows)]
        assert!(std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(root.join("data").join("ext"))
            .arg(root.join("outside"))
            .output()
            .unwrap()
            .status
            .success());
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("outside"), root.join("data/ext")).unwrap();
        let r = root.to_string_lossy().replace('\\', "/");
        let via_link = cap(CapabilityType::FileRead, Some(&format!("{}/data/ext/secret.txt", r)));
        let grant = cap(CapabilityType::FileRead, Some(&format!("{}/data/**", r)));
        assert!(grant.covers_by_name(&via_link));
        assert!(!grant.covers(&via_link), "el link saca la ruta del scope");
        let mut set = CapabilitySet::new("t");
        set.grant(grant.clone());
        let err = set.require(&via_link, "test").unwrap_err();
        assert!(err.message.contains("a link (symlink or junction) on the way leads outside"), "{}", err.message);
        assert!(set.audit_log.iter().any(|e| e.reason == LINK_ESCAPE));
        // Un deny del destino alcanza la ruta por el link.
        let mut set = CapabilitySet::new("t");
        set.grant(cap(CapabilityType::FileRead, None));
        set.deny(cap(CapabilityType::FileRead, Some(&format!("{}/outside/*", r))));
        assert!(matches!(set.check_cause(&via_link, "test"), Err(DenyCause::ExplicitlyDenied(_))));
        // Lo que está de verdad adentro sigue cubierto.
        assert!(grant.covers(&cap(CapabilityType::FileRead, Some(&format!("{}/data/nuevo.txt", r)))));
        let _ = std::fs::remove_dir_all(&root);
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
                    Some(ty) => {
                        let cap = Capability::new(ty, scope);
                        // v0.6.46 (E1): `secret=K@h` ata K a sus hosts, con la gramática de una
                        // atadura (nada de `*` suelto).
                        if let (CapabilityType::Secret, Some((_, Some(hosts)))) =
                            (ty, cap.scope.as_deref().map(split_secret_scope))
                        {
                            for h in hosts.split('|') {
                                if let Some(e) = synsema_core::capscope::bound_host_error(h) {
                                    return Err(format!("--cap-set: {}: {}", item, e));
                                }
                            }
                        }
                        caps.push(cap)
                    }
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

/// v0.6.50 (E-a): los avisos de un techo ya armado. `llm=P`/`judge=P` sin `@` deja que el programa
/// declare `require llm("P")`, pero no manda los datos de P a ningún modelo (`ceiling_names` pide el
/// provider): se avisa al arrancar, no en la primera llamada. `flag` es el nombre del flag.
pub fn ceiling_warnings(caps: &[Capability], flag: &str) -> Vec<String> {
    caps.iter()
        .filter(|c| matches!(c.ty, CapabilityType::Llm | CapabilityType::Judge))
        .filter_map(|c| {
            let p = c.scope.as_deref().filter(|s| !s.contains('@'))?;
            // Ronda 1 (N1): otro ítem del techo que nombra el provider para ese principal ya lo cubre.
            let named = caps.iter().any(|a| {
                a.ty == c.ty
                    && a.scope.as_deref().and_then(|s| s.rsplit_once('@')).is_some_and(|(ap, _)| ap == p || fnmatch(p, ap))
            });
            if named {
                return None;
            }
            let ty = c.ty.name_lower();
            Some(format!(
                "warning: {flag} {ty}={p}: the program may declare `require {ty}(\"{p}\")`, but data private to {p} goes to no model until the item names the provider: {ty}={p}@<provider host> (`@local` for a model in the process, `{p}@*` for any)"
            ))
        })
        .collect()
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

    /// v0.6.46 (E5): el scope de `llm`/`judge` nombra a quién pertenece lo privado y, opcional, el
    /// host del provider. Sin scope = sólo datos públicos.
    #[test]
    fn e5_llm_scope_covers() {
        let c = |s: Option<&str>| Capability::new(CapabilityType::Llm, s.map(|s| s.to_string()));
        let covers = |g: Option<&str>, r: Option<&str>| c(g).covers(&c(r));
        // Datos públicos: los cubre cualquier grant, con o sin scope.
        assert!(covers(None, None) && covers(Some("a"), None) && covers(Some("a@api.x"), None));
        // Sin scope no cubre ningún principal.
        assert!(!covers(None, Some("a@api.x")) && !covers(None, Some("a")));
        // El principal, exacto o glob; el host, si los dos lo nombran.
        assert!(covers(Some("a"), Some("a@api.x")) && covers(Some("a@api.x"), Some("a@api.x")));
        assert!(covers(Some("a@api.x"), Some("a")), "el techo `a@host` acepta el `require llm(\"a\")`");
        assert!(!covers(Some("a@api.x"), Some("a@otro.y")) && !covers(Some("a@local"), Some("a@api.x")));
        assert!(!covers(Some("b"), Some("a@api.x")));
        assert!(covers(Some("*@local"), Some("b@local")) && covers(Some("a@*.x.com"), Some("a@api.x.com")));
        assert!(covers(Some("a@API.X"), Some("a@api.x")));
        // `judge` igual; `llm` no cubre `judge`.
        let j = Capability::new(CapabilityType::Judge, Some("a@local".to_string()));
        assert!(j.covers(&Capability::new(CapabilityType::Judge, Some("a@local".to_string()))));
        assert!(!c(Some("a@local")).covers(&j));
        // Ronda 1 (M2): para datos privados el techo tiene que nombrar el provider.
        let set = |items: &[&str]| {
            let mut cs = CapabilitySet::new("t");
            cs.ceiling = Some(Rc::new(items.iter().map(|s| c(Some(s))).collect()));
            cs
        };
        let req = c(Some("a@api.x"));
        assert!(!set(&["a"]).ceiling_names(&req) && !set(&["*"]).ceiling_names(&req));
        assert!(set(&["a@api.x"]).ceiling_names(&req) && set(&["a@*"]).ceiling_names(&req));
        assert!(!set(&["a@otro.y"]).ceiling_names(&req) && !CapabilitySet::new("t").ceiling_names(&req));
    }

    /// v0.6.46 (D4): la lista de nombres de core (con la que el parser rechaza un `require`
    /// desconocido) y los tipos son la misma cosa: cada nombre tiene su tipo y cada tipo su nombre.
    #[test]
    fn core_capability_names_match_the_types() {
        use CapabilityType::*;
        for name in KNOWN_CAPABILITY_NAMES.split(", ") {
            assert!(capability_type_from_name(name).is_some(), "{} no tiene tipo", name);
        }
        let all = [Net, FileRead, FileWrite, File, Exec, Env, Time, Random, Stdout, Stdin, Llm, Judge, Db, Serve, Secret, Reveal, Sign, Wallet, Spend, Memory, SandboxRun, Attest, Declassify];
        for ty in all {
            assert!(synsema_core::capscope::is_capability_name(ty.wire_name()), "{:?}", ty);
            assert!(synsema_core::capscope::is_capability_name(ty.name_lower()), "{:?}", ty);
        }
        assert_eq!(KNOWN_CAPABILITY_NAMES.split(", ").count(), all.len());
    }

    #[test]
    fn cap_set_item_round_trips_every_type() {
        use CapabilityType::*;
        for ty in [Net, FileRead, FileWrite, File, Exec, Env, Time, Random, Stdout, Stdin, Llm, Judge, Db, Serve, Secret, Reveal, Sign, Wallet, Spend, Memory, SandboxRun, Attest, Declassify] {
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
        // net: un host no distingue mayúsculas en ningún sistema (v0.6.42, auditoría ronda 2:
        // un grant o un `deny` escrito sin esquema y con mayúsculas no cubría el host pedido).
        let net = Capability::new(CapabilityType::Net, Some("api.x".into()));
        assert!(net.covers(&Capability::new(CapabilityType::Net, Some("API.X".into()))));
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

#[cfg(test)]
mod e7_private_dest {
    //! v0.6.46 (E7): `net` mira la IP a la que conecta.
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(scope: Option<&str>) -> Capability {
        Capability::new(CapabilityType::Net, scope.map(str::to_string))
    }

    #[test]
    fn the_private_ranges() {
        for p in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
            "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "192.0.2.5", "198.18.0.1",
            "::1", "::", "fd00::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.5",
            "64:ff9b::a00:5", "2002:a00:5::1", "2001:db8::1", "2001::1", "::127.0.0.1",
        ] {
            assert!(!is_public_ip(ip(p)), "{} es privada", p);
        }
        for p in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "100.128.0.1", "2606:4700::1111", "64:ff9b::808:808", "::ffff:8.8.8.8"] {
            assert!(is_public_ip(ip(p)), "{} es pública", p);
        }
    }

    #[test]
    fn a_wildcard_never_names_a_private_address() {
        let a = ip("10.0.0.5");
        assert!(net_scope_names("db", "db:5432", a));
        assert!(net_scope_names("db:5432", "db:5432", a));
        assert!(!net_scope_names("db:6379", "db:5432", a));
        assert!(net_scope_names("10.0.0.5", "db:5432", a));
        assert!(net_scope_names("10.0.0.0/8", "db:5432", a));
        assert!(!net_scope_names("10.0.0.0/16", "db:5432", ip("10.1.0.5")));
        assert!(net_scope_names("fd00::/8", "db:80", ip("fd12::1")));
        assert!(net_scope_names("127.0.0.1", "x:80", ip("::ffff:127.0.0.1")));
        for w in ["*", "*.internal", "d?"] {
            assert!(!net_scope_names(w, "db:5432", a), "{}", w);
        }
    }

    #[test]
    fn every_layer_has_to_name_it() {
        let a = ip("10.0.0.5");
        let mut s = CapabilitySet::new("t");
        s.grant(net(None));
        assert_eq!(s.net_layers().admits("db:5432", a), Err(DenyCause::NoGrant));
        assert_eq!(s.net_layers().admits("api.x.com:443", ip("93.184.216.34")), Ok(()));
        s.grant(net(Some("10.0.0.0/8")));
        assert_eq!(s.net_layers().admits("db:5432", a), Ok(()));
        // Un techo con comodín sólo deja lo público.
        s.ceiling = Some(Rc::new(vec![net(None)]));
        assert_eq!(s.net_layers().admits("db:5432", a), Err(DenyCause::AboveCeiling));
        s.ceiling = Some(Rc::new(vec![net(Some("db"))]));
        assert_eq!(s.net_layers().admits("db:5432", a), Ok(()));
        // Un `sandbox under` con comodín, igual.
        s.push_delegation(Delegation::block(vec![net(Some("*"))]));
        assert!(matches!(s.net_layers().admits("db:5432", a), Err(DenyCause::Delegated(_))));
        s.pop_delegation();
        // Los grants de un padre cuentan; un `deny` de CIDR alcanza a un nombre que resuelve adentro.
        let parent = Rc::new(RefCell::new(CapabilitySet::new("p")));
        parent.borrow_mut().grant(net(Some("db")));
        let mut child = CapabilitySet::create_child(&parent, "c");
        assert_eq!(child.net_layers().admits("db:5432", a), Ok(()));
        child.deny(net(Some("10.0.0.0/24")));
        assert!(matches!(child.net_layers().admits("db:5432", a), Err(DenyCause::ExplicitlyDenied(_))));
    }

    #[test]
    fn a_cidr_grant_covers_an_ip_literal_by_name() {
        let mut s = CapabilitySet::new("t");
        s.grant(net(Some("10.0.0.0/8")));
        assert!(s.require(&net(Some("10.2.3.4:80")), "t").is_ok());
        assert!(s.require(&net(Some("11.2.3.4")), "t").is_err());
        assert!(s.require(&net(Some("db")), "t").is_err());
    }

    #[test]
    fn the_message_says_what_to_write() {
        let m = private_dest_message("http_get()", "db:5432", ip("10.0.0.5"), &DenyCause::NoGrant);
        assert!(m.contains("`db` resolved to 10.0.0.5, a private address") && m.contains("require net(\"db:5432\")"), "{}", m);
        let m = private_dest_message("http_get()", "x:80", ip("::ffff:127.0.0.1"), &DenyCause::AboveCeiling);
        assert!(m.contains("127.0.0.1") && m.contains("--cap-set net=x:80"), "{}", m);
    }

}

#[cfg(test)]
mod t2_tests {
    use super::*;

    fn cap(ty: CapabilityType, scope: Option<&str>) -> Capability {
        Capability::new(ty, scope.map(|x| x.to_string()))
    }

    // v0.6.47 (T2): el audit nombra el grant (o el deny) más específico, el mismo en cada corrida y
    // en cualquier orden de declaración. Con `HashSet` la semilla del hash elegía cuál.
    fn reason_for(grants: &[Capability], denies: &[Capability], requested: &Capability) -> String {
        let mut set = CapabilitySet::new("t");
        for g in grants {
            set.grant(g.clone());
        }
        for d in denies {
            set.deny(d.clone());
        }
        let _ = set.check_cause(requested, "t");
        set.audit_log.last().unwrap().reason.clone()
    }

    fn every_order(caps: &[Capability]) -> Vec<Vec<Capability>> {
        let mut out = Vec::new();
        for first in 0..caps.len() {
            for rev in [false, true] {
                let mut v: Vec<Capability> = caps[first..].iter().chain(caps[..first].iter()).cloned().collect();
                if rev {
                    v.reverse();
                }
                out.push(v);
            }
        }
        out
    }

    #[test]
    fn t2_the_most_specific_grant_is_named_in_any_order() {
        let net = |s: &str| cap(CapabilityType::Net, Some(s));
        let grants = [net("*.com"), net("api.example.com"), net("*.example.com"), cap(CapabilityType::Net, None)];
        let want = format!("Granted by {}", net("api.example.com"));
        for order in every_order(&grants) {
            // Cada set nuevo trae otra semilla: con `HashSet` alguna vuelta nombraba otro.
            for _ in 0..8 {
                assert_eq!(reason_for(&order, &[], &net("api.example.com")), want, "{:?}", order);
            }
        }
        // Un glob que cubre con el mismo literal que el exacto (`*` vacío): gana el exacto.
        let grants = [net("a*.io"), net("a.io")];
        for order in every_order(&grants) {
            assert_eq!(reason_for(&order, &[], &net("a.io")), format!("Granted by {}", net("a.io")));
        }
        // Sin el exacto, el glob con más literal.
        let grants = [net("*.com"), net("*.example.com"), cap(CapabilityType::Net, None)];
        for order in every_order(&grants) {
            assert_eq!(reason_for(&order, &[], &net("api.example.com")), format!("Granted by {}", net("*.example.com")));
        }
    }

    #[test]
    fn t2_specificity_crosses_types_and_ties_break_by_a_fixed_order() {
        // `file` cubre a `file.read`: gana el scope más específico, sea del tipo que sea.
        let read = cap(CapabilityType::FileRead, Some("/t2-no-existe/x.txt"));
        let grants = [cap(CapabilityType::File, Some("/t2-no-existe/**")), cap(CapabilityType::FileRead, Some("/t2-no-existe/x.txt"))];
        for order in every_order(&grants) {
            assert_eq!(reason_for(&order, &[], &read), format!("Granted by {}", grants[1]));
        }
        let grants = [cap(CapabilityType::FileRead, Some("/t2-no-existe/**")), cap(CapabilityType::File, Some("/t2-no-existe/x.txt"))];
        for order in every_order(&grants) {
            assert_eq!(reason_for(&order, &[], &read), format!("Granted by {}", grants[1]));
        }
        // Mismo scope en los dos tipos: el tipo más angosto (`file.read`, antes en la declaración).
        let grants = [cap(CapabilityType::File, Some("/t2-no-existe/x.txt")), cap(CapabilityType::FileRead, Some("/t2-no-existe/x.txt"))];
        for order in every_order(&grants) {
            assert_eq!(reason_for(&order, &[], &read), format!("Granted by {}", grants[1]));
        }
        // Empate de especificidad (dos globs con el mismo literal): el orden fijo del scope.
        let net = |s: &str| cap(CapabilityType::Net, Some(s));
        let grants = [net("a*.x.com"), net("*b.x.com")];
        let want = reason_for(&grants, &[], &net("ab.x.com"));
        assert_eq!(want, format!("Granted by {}", net("*b.x.com")));
        for order in every_order(&grants) {
            for _ in 0..8 {
                assert_eq!(reason_for(&order, &[], &net("ab.x.com")), want);
            }
        }
    }

    #[test]
    fn t2_the_lookup_stays_in_the_family_and_finds_the_unscoped_grants() {
        // El pedido sin scope recorre desde atrás el tramo sin scope: tiene que quedarse con el primero
        // del orden canónico (`file.read` antes que `file`) y no tomar uno de otra familia.
        let grants = [
            cap(CapabilityType::Net, Some("a.x.com")),
            cap(CapabilityType::Net, None),
            cap(CapabilityType::Time, None),
            cap(CapabilityType::FileRead, Some("/t2-no-existe/a")),
            cap(CapabilityType::FileRead, None),
            cap(CapabilityType::File, None),
            cap(CapabilityType::Secret, Some("K")),
        ];
        for order in every_order(&grants) {
            let reason = |r: Capability| reason_for(&order, &[], &r);
            assert_eq!(reason(cap(CapabilityType::Time, None)), format!("Granted by {}", cap(CapabilityType::Time, None)));
            assert_eq!(reason(cap(CapabilityType::FileRead, None)), format!("Granted by {}", cap(CapabilityType::FileRead, None)));
            assert_eq!(reason(cap(CapabilityType::FileWrite, None)), format!("Granted by {}", cap(CapabilityType::File, None)));
            assert_eq!(reason(cap(CapabilityType::Net, None)), format!("Granted by {}", cap(CapabilityType::Net, None)));
            assert_eq!(reason(cap(CapabilityType::Net, Some("b.x.com"))), format!("Granted by {}", cap(CapabilityType::Net, None)));
            assert_eq!(reason(cap(CapabilityType::FileWrite, Some("/t2-no-existe/b"))), format!("Granted by {}", cap(CapabilityType::File, None)));
            assert_eq!(reason(cap(CapabilityType::Random, None)), "No matching grant found");
        }
    }

    #[test]
    fn t2_in_llm_and_judge_the_unscoped_grant_is_the_narrowest() {
        // Filas 8-11 del modelo. En `llm`/`judge` el grant sin scope cubre sólo lo público: es el más
        // angosto, y la llamada pública lo nombra. Con sólo `llm("P")` la llamada pública pasa igual
        // (el atajo de los sin scope no vale acá) y lo nombra a él.
        for ty in [CapabilityType::Llm, CapabilityType::Judge] {
            let c = |s: Option<&str>| cap(ty, s);
            for order in every_order(&[c(None), c(Some("P")), cap(CapabilityType::Time, None)]) {
                assert_eq!(reason_for(&order, &[], &c(None)), format!("Granted by {}", c(None)));
            }
            assert_eq!(reason_for(&[c(Some("P"))], &[], &c(None)), format!("Granted by {}", c(Some("P"))));
            let grants = [c(None), c(Some("*")), c(Some("P")), c(Some("P@embedder"))];
            for order in every_order(&grants) {
                assert_eq!(reason_for(&order, &[], &c(Some("P@embedder"))), format!("Granted by {}", c(Some("P@embedder"))));
                assert_eq!(reason_for(&order, &[], &c(Some("P@otro"))), format!("Granted by {}", c(Some("P"))));
            }
        }
    }

    #[test]
    fn t2_specificity_reads_the_scope_like_covers_does() {
        // Filas 2-7 del modelo (`specs/t2-especificidad-modelo.md`): los pares de B1 de la auditoría.
        let case = |grants: &[Capability], req: Capability, want: &Capability| {
            for order in every_order(grants) {
                assert_eq!(reason_for(&order, &[], &req), format!("Granted by {}", want), "{:?} → {}", order, req);
            }
        };
        let net = |s: &str| cap(CapabilityType::Net, Some(s));
        // Un CIDR es un rango: la IP exacta antes que cualquier CIDR, y el prefijo más largo antes.
        case(&[net("10.0.0.0/8"), net("10.1.0.0/16"), net("10.1.2.3")], net("10.1.2.3:9"), &net("10.1.2.3"));
        case(&[net("10.0.0.0/8"), net("10.1.0.0/16")], net("10.1.2.3"), &net("10.1.0.0/16"));
        case(&[net("0.0.0.0/0"), net("10.0.0.0/8")], net("10.1.2.3"), &net("10.0.0.0/8"));
        // Los corchetes de una IPv6 con puerto no son comodín: con puerto antes que sin.
        case(&[net("::1"), net("[::1]:9")], net("[::1]:9"), &net("[::1]:9"));
        // Un CIDR con puerto es más angosto que el mismo sin puerto (ronda 2, B1).
        case(&[net("10.0.0.0/8"), net("10.0.0.0/8:9")], net("10.1.2.3:9"), &net("10.0.0.0/8:9"));
        case(&[net("fd00::/8"), net("[fd00::/8]:443")], net("[fd00::1]:443"), &net("[fd00::/8]:443"));
        // En `file`, `[` es literal: el nombre exacto antes que el glob con el mismo literal.
        let read = |s: &str| cap(CapabilityType::FileRead, Some(s));
        case(&[read("/t2-no-existe/*[x].txt"), read("/t2-no-existe/[x].txt")], read("/t2-no-existe/[x].txt"), &read("/t2-no-existe/[x].txt"));
        // La atadura de un secret lo achica, aunque sea `*.x.com`.
        let secret = |s: &str| cap(CapabilityType::Secret, Some(s));
        case(&[secret("k"), secret("k@*.x.com")], secret("k@*.x.com"), &secret("k@*.x.com"));
        let three = [secret("k"), secret("k@*.x.com"), secret("k@api.x.com")];
        // `check` de un pedido atado a un host:
        case(&three, secret("k@api.x.com"), &secret("k@api.x.com"));
        // lo que pide `secret("k")` con esos grants: la unión de las ataduras (`secret_binding`), que
        // `k@api.x.com` no cubre (ronda 2, N1).
        case(&three, secret("k@api.x.com|*.x.com"), &secret("k@*.x.com"));
    }

    #[test]
    fn t2_the_most_specific_deny_is_named_and_the_secret_hosts_keep_a_fixed_order() {
        let net = |s: &str| cap(CapabilityType::Net, Some(s));
        let denies = [net("*.com"), net("api.example.com"), net("*.example.com")];
        for order in every_order(&denies) {
            for _ in 0..8 {
                assert_eq!(reason_for(&[], &order, &net("api.example.com")), format!("Explicitly denied by {}", net("api.example.com")));
            }
        }
        let secret = |s: &str| cap(CapabilityType::Secret, Some(s));
        let grants = [secret("K@zeta.com"), secret("K@alfa.com"), secret("K@mid.com")];
        let mut seen = std::collections::HashSet::new();
        for order in every_order(&grants) {
            for _ in 0..8 {
                let mut set = CapabilitySet::new("t");
                for g in &order {
                    set.grant(g.clone());
                }
                seen.insert(set.secret_binding("K").unwrap());
            }
        }
        assert_eq!(seen.len(), 1, "{:?}", seen);
    }
}

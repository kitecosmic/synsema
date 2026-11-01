//! v0.6.52 (auditoría r1, A2) — las carpetas que un hijo aislado pudo escribir.
//!
//! Un hijo con `{"isolate": {"file.write": "./work/**"}}` es código no confiable que puede crear
//! links dentro de `./work`. La regla de v0.6.45 deja seguir un link que es la base de un grant
//! (`file.read("./work/sub/**")` con `sub` → otro lugar): el grant nombra ese lugar. Con un hijo
//! aislado esa base la puede poner él, así que, desde que se delega la carpeta y por el resto de la
//! corrida, **una ruta no sigue un link que está dentro de esa carpeta**. Lo que el hijo escribió se
//! lee por su lugar real; un link suyo no lleva a ningún lado.
//!
//! Ronda 4 (A1): **mientras el hijo corre, su carpeta está prestada** (como un `&mut` de Rust):
//! ninguna ruta que pase por ella o termine en ella se concede hasta que `run` vuelve y el grupo
//! del hijo murió. Así el juicio de una sola vez vale: entre el juicio y lo que hace el builtin por
//! nombre (borrar, listar, crear carpetas) nadie cambia un link ahí adentro.
//!
//! Lo que ya estaba en curso cuando empieza el préstamo también cuenta: cada builtin sostiene la
//! ruta que juzgó hasta volver (`synsema_core::op_hold`), y el préstamo espera a que se suelten las
//! de los otros hilos que tocan la carpeta antes de lanzar al hijo (como tomar un `RwLock` para
//! escribir).
//!
//! Ronda 5: se sostiene **cada** ruta que juzga un builtin, no sólo la primera (A1); una carpeta se
//! reconoce también por su identidad en disco, no sólo por su nombre (M1: otras mayúsculas en un
//! sistema de archivos que no las distingue, un bind mount); y los `run` aislados arrancan de a uno
//! (M2), y sueltan lo que juzgaron apenas lanzan al hijo.
//!
//! El estado es de la corrida (`RunScope::ext`); fuera de una corrida, del proceso. El chequeo
//! (`crossing`) no cuesta nada mientras ningún hijo aislado haya recibido una carpeta de escritura.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use synsema_core::capscope;

use crate::model::{Capability, CapabilityType};

/// Si alguna vez se registró una carpeta en este proceso (el camino común no toca nada más).
static ANY: AtomicBool = AtomicBool::new(false);

/// La identidad de un archivo en disco: dispositivo, inodo y cuándo se creó.
///
/// Ronda 7 (N1): ext4 le da a la próxima carpeta el inodo de una que se borró; la fecha de creación
/// es la de la nueva. Viene en el mismo `statx` que el resto (std pide `STATX_ALL`); donde el
/// sistema de archivos no la da (drvfs), `None`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct FileId {
    dev: u64,
    ino: u64,
    born: Option<std::time::SystemTime>,
}

fn file_id(m: &std::fs::Metadata) -> Option<FileId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(FileId { dev: m.dev(), ino: m.ino(), born: m.created().ok() })
    }
    #[cfg(not(unix))]
    {
        let _ = m;
        None
    }
}

/// Las identidades de `p` y de cada carpeta de arriba que existe (siguiendo links).
fn chain(p: &Path) -> Vec<FileId> {
    p.ancestors().filter_map(|a| std::fs::metadata(a).ok().and_then(|m| file_id(&m))).collect()
}

/// Una carpeta delegada: dónde estaba cuando se delegó y qué es en disco (ronda 5, M1: el mismo
/// lugar puede tener otro nombre, y el nombre solo no alcanza).
#[derive(Clone)]
struct Area {
    path: PathBuf,
    id: Option<FileId>,
}

impl Area {
    fn new(path: &Path) -> Area {
        Area { path: path.to_path_buf(), id: std::fs::metadata(path).ok().and_then(|m| file_id(&m)) }
    }

    fn same(&self, other: &Area) -> bool {
        self.path == other.path || other.id.is_some_and(|id| self.is(&id))
    }

    /// ¿`p` (con `p_chain = chain(p)`) es esta carpeta o está dentro de ella?
    fn contains(&self, p: &Path, p_chain: &[FileId]) -> bool {
        p.starts_with(&self.path) || p_chain.iter().any(|c| self.is(c))
    }

    /// ¿`id` (visto ahora) es esta carpeta?
    ///
    /// Ronda 7 (N1): el mismo inodo con otra fecha de creación es otra carpeta que lo reusó, salvo
    /// que el nombre del área todavía lleve a ese inodo: la misma carpeta con la fecha cambiada
    /// (overlayfs, al copiarla a la capa de arriba, da la de la copia). Ese `stat` sólo se hace en
    /// ese caso. Sin fecha de un lado, cuenta el inodo, como antes.
    fn is(&self, id: &FileId) -> bool {
        let Some(mine) = &self.id else {
            return false;
        };
        if (mine.dev, mine.ino) != (id.dev, id.ino) {
            return false;
        }
        if mine.born == id.born || mine.born.is_none() || id.born.is_none() {
            return true;
        }
        std::fs::metadata(&self.path).ok().and_then(|m| file_id(&m)).is_some_and(|now| (now.dev, now.ino) == (id.dev, id.ino))
    }
}

#[derive(Default)]
struct State {
    /// Las carpetas delegadas para escribir en esta corrida (no se siguen links adentro).
    areas: Vec<Area>,
    /// Las prestadas ahora: una entrada por hijo que corre (dos hijos, la misma dos veces).
    busy: Vec<Area>,
    /// Lo que juzgaron los builtins en curso (ronda 4, A1): una entrada por builtin (ronda 6, M1),
    /// así que son pocas (las que corren a la vez).
    holds: Vec<(u64, HoldEntry)>,
    next: u64,
    /// Un `run` aislado está entre su juicio y el lanzamiento del hijo (ronda 5, M2: `startup`).
    starting: bool,
}

struct HoldEntry {
    thread: std::thread::ThreadId,
    /// Los scopes tal como se juzgaron, en orden: se vuelven absolutos sólo si un préstamo tiene que
    /// mirarlos.
    scopes: Vec<String>,
}

#[derive(Default)]
struct Areas(Mutex<State>, Condvar);

static OUTSIDE_A_RUN: Areas =
    Areas(Mutex::new(State { areas: Vec::new(), busy: Vec::new(), holds: Vec::new(), next: 0, starting: false }), Condvar::new());

/// Dónde vive el estado: el de la corrida actual o el del proceso.
#[derive(Clone)]
enum Home {
    Run(Arc<Areas>),
    Outside,
}

impl Home {
    fn current() -> Home {
        match synsema_core::run_scope::current() {
            Some(run) => Home::Run(run.ext::<Areas>()),
            None => Home::Outside,
        }
    }

    fn areas(&self) -> &Areas {
        match self {
            Home::Run(a) => a,
            Home::Outside => &OUTSIDE_A_RUN,
        }
    }

    fn key(&self) -> usize {
        self.areas() as *const Areas as usize
    }

    fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        let mut g = self.areas().0.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut g)
    }
}

thread_local! {
    /// La entrada de cada builtin en curso de este hilo (anidan: unas pocas), con la última ruta que
    /// sumó.
    static OPEN: RefCell<Vec<Open>> = const { RefCell::new(Vec::new()) };
}

struct Open {
    key: usize,
    frame: u64,
    id: u64,
    last: String,
}

/// Lo que juzgó un builtin en curso; se suelta entero cuando el builtin vuelve.
struct Hold {
    home: Home,
    id: u64,
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.home.with(|s| {
            if let Some(i) = s.holds.iter().position(|(id, _)| *id == self.id) {
                s.holds.swap_remove(i);
            }
        });
        self.home.areas().1.notify_all();
        OPEN.with(|o| o.borrow_mut().retain(|e| e.id != self.id));
    }
}

/// Sostiene `scope` (una ruta) mientras corre el builtin que la juzgó.
///
/// Ronda 5 (A1): cada ruta distinta, no sólo la primera. Un extractor juzga todas sus entradas y
/// después crea las carpetas por nombre: el préstamo tiene que ver la que toca la carpeta aunque
/// antes se hayan juzgado otras lejos de ella.
///
/// Ronda 6 (M1): todas las de un builtin van en una sola entrada, que se suelta de una vez (un
/// lock y un aviso por builtin; una por ruta costaba O(n²) al soltar). La misma ruta seguida (se
/// juzga para leer y para escribir, o por nombre y por el fd) se anota una vez; otra repetida sólo
/// ocupa lugar.
fn hold(scope: &str) {
    if !synsema_core::op_hold::enabled() {
        return;
    }
    // Fuera de un builtin no se sostiene nada.
    let frame = synsema_core::op_hold::frame();
    if frame == 0 {
        return;
    }
    let home = Home::current();
    let key = home.key();
    let open = OPEN.with(|o| {
        let mut o = o.borrow_mut();
        let e = o.iter_mut().rev().find(|e| e.key == key && e.frame == frame)?;
        if e.last == scope {
            return Some(None);
        }
        e.last = scope.to_string();
        Some(Some(e.id))
    });
    match open {
        Some(None) => {}
        Some(Some(id)) => home.with(|s| {
            if let Some((_, e)) = s.holds.iter_mut().find(|(i, _)| *i == id) {
                e.scopes.push(scope.to_string());
            }
        }),
        None => {
            let me = std::thread::current().id();
            let id = home.with(|s| {
                s.next += 1;
                s.holds.push((s.next, HoldEntry { thread: me, scopes: vec![scope.to_string()] }));
                s.next
            });
            OPEN.with(|o| o.borrow_mut().push(Open { key, frame, id, last: scope.to_string() }));
            synsema_core::op_hold::hold(Box::new(Hold { home, id }));
        }
    }
}

/// Cuánto espera un préstamo a que terminen las operaciones en curso sobre la carpeta.
#[cfg(not(test))]
const HOLD_WAIT: Duration = Duration::from_secs(10);
#[cfg(test)]
const HOLD_WAIT: Duration = Duration::from_secs(1);

/// Dónde lleva hoy una ruta juzgada: `resolve_existing`, su identidad si existe, y `chain`.
struct Place {
    real: PathBuf,
    here: Option<FileId>,
    chain: Vec<FileId>,
}

/// Ronda 6 (M1): resuelve muchas rutas con un `lstat` cada una. Lo caro (`canonicalize` y `chain`)
/// se hace una vez por carpeta: las entradas de un extractor comparten unas pocas.
#[derive(Default)]
struct Resolver {
    dirs: HashMap<PathBuf, Rc<(PathBuf, Vec<FileId>)>>,
}

impl Resolver {
    fn dir(&mut self, d: &Path) -> Rc<(PathBuf, Vec<FileId>)> {
        if let Some(r) = self.dirs.get(d) {
            return r.clone();
        }
        let real = resolve_existing(d);
        let c = chain(&real);
        let r = Rc::new((real, c));
        self.dirs.insert(d.to_path_buf(), r.clone());
        r
    }

    fn place(&mut self, p: &Path) -> Place {
        let simple = matches!(p.components().next_back(), Some(Component::Normal(_)));
        if let (true, Some(parent), Some(name)) = (simple, p.parent(), p.file_name()) {
            match std::fs::symlink_metadata(p) {
                // Un link (del programa) se resuelve entero.
                Ok(m) if m.file_type().is_symlink() => {}
                Ok(m) => {
                    let d = self.dir(parent);
                    let here = file_id(&m);
                    return Place { real: d.0.join(name), here, chain: here.into_iter().chain(d.1.iter().copied()).collect() };
                }
                Err(_) => {
                    let d = self.dir(parent);
                    return Place { real: d.0.join(name), here: None, chain: d.1.clone() };
                }
            }
        }
        let real = resolve_existing(p);
        let here = std::fs::metadata(&real).ok().and_then(|m| file_id(&m));
        let chain = chain(&real);
        Place { real, here, chain }
    }
}

/// ¿La operación sobre `p` (que hoy lleva a `at`) puede tocar `area`? Por nombre o por donde lleva
/// hoy (los links del programa: el hijo todavía no corre), en cualquiera de los dos sentidos
/// (borrar la carpeta de arriba también la toca). `area_chain` es `chain(&area.path)`.
fn related(p: &Path, at: &Place, area: &Area, area_chain: &[FileId]) -> bool {
    if [p, at.real.as_path()].iter().any(|x| x.starts_with(&area.path) || area.path.starts_with(x)) {
        return true;
    }
    // Ronda 5 (M1): otro nombre del mismo lugar.
    at.chain.iter().any(|c| area.is(c)) || at.here.is_some_and(|id| area_chain.contains(&id))
}

/// `canonicalize` de la parte que existe, más el resto tal cual.
fn resolve_existing(p: &Path) -> PathBuf {
    let mut base = p.to_path_buf();
    let mut rest = Vec::new();
    loop {
        if let Ok(mut c) = std::fs::canonicalize(&base) {
            for r in rest.iter().rev() {
                c.push(r);
            }
            return c;
        }
        match (base.file_name().map(|n| n.to_os_string()), base.parent().map(Path::to_path_buf)) {
            (Some(n), Some(parent)) => {
                rest.push(n);
                base = parent;
            }
            _ => return p.to_path_buf(),
        }
    }
}

/// Las carpetas de un hijo que va a correr, prestadas hasta que se suelte el `Borrow`.
pub struct Borrow {
    home: Home,
    lent: Vec<Area>,
    group: Option<u32>,
}

/// Lo que no terminó a tiempo: la ruta que juzgó otra tarea y la carpeta delegada que toca.
#[derive(Debug)]
pub struct StillInUse {
    pub held: PathBuf,
    pub area: PathBuf,
}

/// Registra `reals` (las ubicaciones físicas de las carpetas delegadas para escribir) antes de
/// lanzar y las presta mientras viva lo que devuelve. Desde que se prestan, nada nuevo las toca;
/// lo que otro hilo ya había juzgado se espera (hasta `HOLD_WAIT`). Si no termina, `Err` con esa
/// ruta y la carpeta, y no se presta nada.
pub fn borrow(reals: &[PathBuf]) -> Result<Borrow, StillInUse> {
    ANY.store(true, Ordering::Relaxed);
    let home = Home::current();
    let lent: Vec<Area> = reals.iter().map(|r| Area::new(r)).collect();
    home.with(|s| {
        for a in &lent {
            if !s.areas.iter().any(|x| x.same(a)) {
                s.areas.push(a.clone());
            }
            s.busy.push(a.clone());
        }
    });
    let chains: Vec<Vec<FileId>> = lent.iter().map(|a| chain(&a.path)).collect();
    let b = Borrow { home: home.clone(), lent: lent.clone(), group: None };
    let me = std::thread::current().id();
    let deadline = Instant::now() + HOLD_WAIT;
    // Por entrada: cuántas de sus rutas ya se miraron, y la primera que toca un área. Una entrada
    // sigue creciendo mientras su builtin juzga: se miran sólo las rutas nuevas.
    let mut seen: HashMap<u64, (usize, Option<StillInUse>)> = HashMap::new();
    let mut resolver = Resolver::default();
    loop {
        // Las de otros hilos (las de éste son del mismo `run`, o de un builtin que lo llamó).
        let (present, fresh) = home.with(|s| {
            let mut present = Vec::new();
            let mut fresh: Vec<(u64, usize, Vec<String>)> = Vec::new();
            for (id, e) in s.holds.iter().filter(|(_, e)| e.thread != me) {
                present.push(*id);
                let (done, hit) = seen.get(id).map(|(d, h)| (*d, h.is_some())).unwrap_or((0, false));
                if !hit && e.scopes.len() > done {
                    fresh.push((*id, e.scopes.len(), e.scopes[done..].to_vec()));
                }
            }
            (present, fresh)
        });
        for (id, len, scopes) in fresh {
            let hit = scopes.iter().find_map(|scope| {
                let p = PathBuf::from(capscope::absolute_literal(scope));
                let at = resolver.place(&p);
                let hit = lent.iter().zip(&chains).find(|(a, c)| related(&p, &at, a, c));
                hit.map(|(a, _)| StillInUse { held: p.clone(), area: a.path.clone() })
            });
            let slot = seen.entry(id).or_insert((0, None));
            slot.0 = len;
            if slot.1.is_none() {
                slot.1 = hit;
            }
        }
        let pending = present.into_iter().find(|id| seen.get(id).is_some_and(|(_, h)| h.is_some()));
        let Some(id) = pending else {
            return Ok(b);
        };
        let now = Instant::now();
        if now >= deadline {
            return Err(seen.remove(&id).and_then(|(_, h)| h).expect("se guardó al encontrarla"));
        }
        let a = home.areas();
        let g = a.0.lock().unwrap_or_else(|p| p.into_inner());
        if g.holds.iter().any(|(i, _)| *i == id) {
            let _ = a.1.wait_timeout(g, (deadline - now).min(Duration::from_millis(50)));
        }
    }
}

impl Borrow {
    /// El grupo del hijo que se lanzó: al soltar, se espera a que no quede nadie en él.
    pub fn child_group(&mut self, pid: u32) {
        self.group = Some(pid);
    }
}

/// Lo que se espera a que el grupo quede vacío después de matarlo (un `rename` en curso termina).
const GROUP_GONE_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// v0.6.53 (1a): el grupo de un hijo aislado **sin** carpetas de escritura (sin [`Borrow`]). Al
/// soltarse, si synsema recoge a los huérfanos (PID 1 o subreaper), recoge lo que el hijo dejó
/// corriendo y se mató; si no, no espera nada. Se suelta por donde vuelva `run`.
pub struct Adopted(pub u32);

impl Drop for Adopted {
    fn drop(&mut self) {
        synsema_isolate::reap_adopted(self.0, GROUP_GONE_WAIT);
    }
}

impl Drop for Borrow {
    fn drop(&mut self) {
        // Un proceso del grupo con el SIGKILL pendiente todavía puede terminar la syscall en la que
        // está. Si no se vacía a tiempo, la carpeta queda prestada por el resto de la corrida.
        if let Some(pid) = self.group {
            if !synsema_isolate::group_gone(pid, GROUP_GONE_WAIT) {
                return;
            }
        }
        let lent = std::mem::take(&mut self.lent);
        self.home.with(|s| {
            for a in &lent {
                if let Some(i) = s.busy.iter().position(|b| b.path == a.path) {
                    s.busy.remove(i);
                }
            }
        });
    }
}

/// Ronda 5 (M2): el turno de un `run` aislado, desde antes de juzgar nada hasta que lanza al hijo
/// (como el `ForkLock` de Go). Dos `run` que arrancaban juntos se esperaban uno al otro: cada
/// préstamo esperaba lo que el otro ya había juzgado. De a uno, el primero ya soltó lo suyo
/// (`op_hold::release` al lanzar) cuando el segundo juzga y presta, así que un préstamo sólo
/// espera builtins comunes, que vuelven solos.
pub struct Startup {
    home: Home,
}

/// Espera el turno. Se pide antes de juzgar nada en ese `run`: mientras espera no sostiene nada.
pub fn startup() -> Startup {
    let home = Home::current();
    let a = home.areas();
    let mut g = a.0.lock().unwrap_or_else(|p| p.into_inner());
    while g.starting {
        g = a.1.wait(g).unwrap_or_else(|p| p.into_inner());
    }
    g.starting = true;
    drop(g);
    Startup { home }
}

impl Drop for Startup {
    fn drop(&mut self) {
        self.home.with(|s| s.starting = false);
        self.home.areas().1.notify_all();
    }
}

/// Por qué una ruta no se concede.
#[derive(Debug, PartialEq, Eq)]
pub enum Crossing {
    /// Pasa por un link dentro de esta carpeta.
    Link(PathBuf),
    /// Pasa por esta carpeta o termina en ella mientras un hijo con escritura corre (ronda 4, A1).
    InUse(PathBuf),
}

/// Si `requested` es una ruta que pasa por un link puesto dentro de una de esas carpetas, o por una
/// carpeta prestada ahora, por qué (con la carpeta, para el mensaje).
///
/// Ronda 3 (A1): con un lugar fijado (`capscope::with_physical`: un handle abierto en E8, el `pin`
/// de `isolate`, la entrada de un link que se borra) la ruta por nombre se resuelve igual, sin
/// seguir links de las áreas, y tiene que llegar a ese lugar: si el hijo cambió un link entre el
/// primer juicio y la apertura, no coinciden y se deniega. Lo que el fd dice es la verdad; la
/// resolución por nombre no puede pasar por un link del hijo.
pub fn crossing(requested: &Capability) -> Option<Crossing> {
    if !ANY.load(Ordering::Relaxed) && !synsema_core::op_hold::enabled() {
        return None;
    }
    let scope = requested.scope()?;
    let is_path = match requested.ty() {
        CapabilityType::File | CapabilityType::FileRead | CapabilityType::FileWrite => true,
        CapabilityType::Db => !capscope::is_db_url(scope),
        // Ronda 2 (N1): el programa a correr, cuando se nombra con ruta (`./work/tool`).
        CapabilityType::Exec => scope.contains(['/', '\\']),
        _ => false,
    };
    if !is_path {
        return None;
    }
    hold(scope);
    if !ANY.load(Ordering::Relaxed) {
        return None;
    }
    let (areas, busy) = Home::current().with(|s| (s.areas.clone(), s.busy.clone()));
    if areas.is_empty() {
        return None;
    }
    let lit = PathBuf::from(capscope::absolute_literal(scope));
    match capscope::physical_override(&lit.to_string_lossy()) {
        None => plain_crossing(&areas, &busy, &lit),
        Some(real) => fixed_place_crossing(&areas, &busy, &lit, Path::new(&real)),
    }
}

/// Sin lugar fijado: un link de un área en el camino, o un área prestada en el camino o al final.
fn plain_crossing(areas: &[Area], busy: &[Area], path: &Path) -> Option<Crossing> {
    let w = walk(areas, path);
    if let Some(b) = w.in_use(busy, None) {
        return Some(Crossing::InUse(b));
    }
    match &w.end {
        Err(Stop::Link(a)) => Some(Crossing::Link(a.clone())),
        // Ronda 4 (N1): un ciclo (o un link que no se lee) lejos de las áreas no es asunto de esta
        // regla: el sistema da su error al abrir.
        Err(Stop::Unresolved) => w.touched.first().map(|a| Crossing::Link(a.path.clone())),
        Ok(_) => None,
    }
}

/// El lugar fijado `real` contra la ruta por nombre `lit` (ver `crossing`).
fn fixed_place_crossing(areas: &[Area], busy: &[Area], lit: &Path, real: &Path) -> Option<Crossing> {
    let mut touched: Option<PathBuf> = None;
    // La entrada (su carpeta resuelta + el nombre, sin seguirlo): como `unlink`, `rename`, crear.
    if let (Some(lp), Some(rp)) = (lit.parent(), real.parent()) {
        if lit.file_name() == real.file_name() {
            let w = walk(areas, lp);
            if let Some(b) = w.in_use(busy, Some(real)) {
                return Some(Crossing::InUse(b));
            }
            match &w.end {
                Err(Stop::Link(a)) => return Some(Crossing::Link(a.clone())),
                Ok(p) if p == rp => return None,
                _ => touched = w.touched.first().map(|a| a.path.clone()),
            }
            if matches!(w.end, Err(Stop::Unresolved)) && touched.is_some() {
                return touched.map(Crossing::Link);
            }
        }
    }
    // Lo que el nombre resuelve entero.
    let w = walk(areas, lit);
    if let Some(b) = w.in_use(busy, Some(real)) {
        return Some(Crossing::InUse(b));
    }
    match &w.end {
        Err(Stop::Link(a)) => Some(Crossing::Link(a.clone())),
        Ok(p) if p == real => None,
        _ => {
            // No coinciden (o no se resuelve): algo cambió entre la apertura y ahora, o el sistema
            // ve otra forma de la misma ruta. Sólo importa si pasa por un área o termina en una.
            let rc = chain(real);
            let inside = areas.iter().find(|a| a.contains(real, &rc)).map(|a| a.path.clone());
            inside.or_else(|| w.touched.first().map(|a| a.path.clone())).or(touched).map(Crossing::Link)
        }
    }
}

/// Ronda 2 (N1): lo mismo para una carpeta donde arranca un hijo (`cwd` de `run`/`proc_spawn`).
pub fn crossing_dir(dir: &str) -> Option<Crossing> {
    if !ANY.load(Ordering::Relaxed) && !synsema_core::op_hold::enabled() {
        return None;
    }
    hold(dir);
    if !ANY.load(Ordering::Relaxed) {
        return None;
    }
    let (areas, busy) = Home::current().with(|s| (s.areas.clone(), s.busy.clone()));
    if areas.is_empty() {
        return None;
    }
    plain_crossing(&areas, &busy, Path::new(&capscope::absolute_literal(dir)))
}

/// Cuántos links seguidos se resuelven antes de rendirse (Linux usa 40).
const MAX_HOPS: usize = 40;

/// Por qué no se terminó de resolver.
enum Stop {
    /// Un link dentro de esta área.
    Link(PathBuf),
    /// Demasiados links, o uno que no se lee.
    Unresolved,
}

/// El resultado de `walk`: adónde lleva, y por qué carpetas de las áreas pasó.
struct Walk {
    end: Result<PathBuf, Stop>,
    touched: Vec<Area>,
    /// Las identidades de lo que existe de `end`: ella y sus carpetas (ronda 5, M1).
    end_ids: Vec<FileId>,
}

impl Walk {
    /// La carpeta prestada por la que pasa o en la que termina (o en la que está `real`).
    fn in_use(&self, busy: &[Area], real: Option<&Path>) -> Option<PathBuf> {
        if busy.is_empty() {
            return None;
        }
        let rc = real.map(chain).unwrap_or_default();
        busy.iter()
            .find(|b| {
                self.touched.iter().any(|t| t.same(b))
                    || matches!(&self.end, Ok(p) if p.starts_with(&b.path))
                    || self.end_ids.iter().any(|c| b.is(c))
                    || real.is_some_and(|r| b.contains(r, &rc))
            })
            .map(|b| b.path.clone())
    }
}

/// Resuelve `path` a mano, componente por componente, siguiendo los links que NO están dentro de un
/// área. Lo que no existe se agrega tal cual (son nombres por crear).
///
/// Ronda 3: a mano y no con `canonicalize`, porque un link del programa puede llevar a un link del
/// hijo (`./x` → `work/sub` → afuera) y `canonicalize` lo seguía sin mostrarlo.
fn walk(areas: &[Area], path: &Path) -> Walk {
    let mut queue: std::collections::VecDeque<std::ffi::OsString> = std::collections::VecDeque::new();
    let mut cur = PathBuf::new();
    // Ronda 5 (M1): la identidad de cada componente de `cur` (`None` si no existe o es la raíz). Por
    // ella se sabe que `cur` está dentro de un área aunque la nombre distinto (`./WORK` donde no hay
    // mayúsculas, un bind mount).
    let mut ids: Vec<Option<FileId>> = Vec::new();
    let mut touched: Vec<Area> = Vec::new();
    let mut hops = 0;
    let inside = |cur: &Path, ids: &[Option<FileId>], a: &Area| {
        cur.starts_with(&a.path) || ids.iter().flatten().any(|c| a.is(c))
    };
    let push_front = |q: &mut std::collections::VecDeque<std::ffi::OsString>,
                      cur: &mut PathBuf,
                      ids: &mut Vec<Option<FileId>>,
                      p: &Path| {
        if p.has_root() {
            // Absoluto: se arranca de nuevo desde la raíz.
            *cur = PathBuf::new();
            ids.clear();
        }
        let comps: Vec<std::ffi::OsString> = p.components().map(|c| c.as_os_str().to_os_string()).collect();
        for c in comps.into_iter().rev() {
            q.push_front(c);
        }
    };
    push_front(&mut queue, &mut cur, &mut ids, path);
    while let Some(c) = queue.pop_front() {
        let comp = Path::new(&c);
        match comp.components().next() {
            Some(Component::Prefix(_)) | Some(Component::RootDir) => {
                cur.push(&c);
                ids.push(None);
                continue;
            }
            Some(Component::CurDir) | None => continue,
            Some(Component::ParentDir) => {
                if cur.pop() {
                    ids.pop();
                }
                continue;
            }
            Some(Component::Normal(_)) => {}
        }
        for a in areas {
            if inside(&cur, &ids, a) && !touched.iter().any(|t| t.path == a.path) {
                touched.push(a.clone());
            }
        }
        let next = cur.join(&c);
        match std::fs::symlink_metadata(&next) {
            Ok(m) if m.file_type().is_symlink() => {
                if let Some(a) = areas.iter().find(|a| inside(&cur, &ids, a)) {
                    return Walk { end: Err(Stop::Link(a.path.clone())), touched, end_ids: Vec::new() };
                }
                hops += 1;
                let target = match std::fs::read_link(&next) {
                    Ok(t) if hops <= MAX_HOPS => t,
                    _ => return Walk { end: Err(Stop::Unresolved), touched, end_ids: Vec::new() },
                };
                push_front(&mut queue, &mut cur, &mut ids, &target);
            }
            Ok(m) => {
                cur = next;
                ids.push(file_id(&m));
            }
            Err(_) => {
                // No existe: el resto son nombres por crear.
                cur = next;
                for rest in queue.drain(..) {
                    cur.push(rest);
                }
                break;
            }
        }
    }
    Walk { end: Ok(cur), touched, end_ids: ids.into_iter().flatten().collect() }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("synsema-areas-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    /// Ronda 6 (M1): todo lo que juzga un builtin es una sola tenencia, que se suelta de una vez
    /// (antes, una por ruta, y soltarlas costaba O(n²)); la misma ruta seguida se anota una vez. Un
    /// builtin de adentro tiene la suya.
    #[test]
    fn one_builtin_is_one_hold() {
        synsema_core::op_hold::enable();
        let run = synsema_core::run_scope::RunScope::new();
        let _in = run.enter();
        let home = Home::current();
        let outer = synsema_core::op_hold::enter();
        for i in 0..1000 {
            hold(&format!("./out/f{}.txt", i));
            hold(&format!("./out/f{}.txt", i));
        }
        let lens = || home.with(|s| s.holds.iter().map(|(_, e)| e.scopes.len()).collect::<Vec<_>>());
        assert_eq!(lens(), [1000]);
        {
            let _inner = synsema_core::op_hold::enter();
            hold("./out/f1.txt");
            hold("./other.txt");
            let mut l = lens();
            l.sort();
            assert_eq!(l, [2, 1000], "el de adentro tiene la suya");
        }
        assert_eq!(lens(), [1000]);
        drop(outer);
        assert!(lens().is_empty());
        assert!(OPEN.with(|o| o.borrow().iter().all(|e| e.key != home.key())));
    }

    /// Ronda 7 (N1): el mismo inodo con otra fecha de creación es la misma carpeta sólo si el nombre
    /// del área todavía lleva a ella (overlayfs cambia la fecha al copiar); borrada, es otra.
    #[test]
    fn the_same_inode_born_again_is_another_folder() {
        let d = scratch("born");
        let a = d.join("a");
        std::fs::create_dir(&a).unwrap();
        let now = file_id(&std::fs::metadata(&a).unwrap()).unwrap();
        let mut area = Area::new(&a);
        assert!(area.is(&now));
        area.id = Some(FileId { born: Some(std::time::UNIX_EPOCH), ..now });
        assert!(area.is(&now), "otra fecha, pero el nombre todavía lleva ahí: la misma");
        assert!(area.is(&FileId { born: None, ..now }), "sin fecha de un lado cuenta el inodo");
        std::fs::remove_dir(&a).unwrap();
        assert!(!area.is(&now), "borrada: ese inodo con otra fecha es otra carpeta");
        assert!(!Area::new(&d).is(&now));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ronda 6 (M1): `Resolver::place` da lo mismo que resolver cada ruta entera, con una sola
    /// resolución por carpeta.
    #[test]
    fn the_resolver_gives_what_resolving_each_path_gives() {
        let d = scratch("resolver");
        std::fs::create_dir_all(d.join("work").join("sub")).unwrap();
        std::fs::create_dir_all(d.join("out")).unwrap();
        std::fs::write(d.join("out").join("a.txt"), "a").unwrap();
        std::os::unix::fs::symlink(d.join("work"), d.join("out").join("x")).unwrap();
        let mut res = Resolver::default();
        let paths = [
            d.join("out").join("a.txt"),
            d.join("out").join("nueva.txt"),
            d.join("out").join("x"),
            d.join("out").join("x").join("sub"),
            d.join("out").join("no").join("y"),
            d.join("work"),
        ];
        for p in &paths {
            let got = res.place(p);
            let real = resolve_existing(p);
            let here = std::fs::metadata(&real).ok().and_then(|m| file_id(&m));
            assert_eq!(got.real, real, "{}", p.display());
            assert_eq!(got.here, here, "{}", p.display());
            assert_eq!(got.chain, chain(&real), "{}", p.display());
        }
        let before = res.dirs.len();
        for i in 0..100 {
            res.place(&d.join("out").join(format!("f{}.txt", i)));
        }
        assert_eq!(res.dirs.len(), before, "la carpeta ya estaba resuelta");
        assert!(res.dirs.contains_key(&d.join("out")));
        let _ = std::fs::remove_dir_all(&d);
    }
}

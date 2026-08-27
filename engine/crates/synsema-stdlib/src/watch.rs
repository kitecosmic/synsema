//! File-watch (`watch`, `watch_recv`, `watch_stats`, `watch_close`) — cambios en disco
//! como handle con eventos, en el mismo hub que procesos, sockets y bus (`select`).
//!
//! - **Polling con snapshot**, no inotify/FSEvents/ReadDirectoryChangesW. Los tres
//!   backends nativos difieren en semántica (coalescing, orden, renames, overflow,
//!   límites de watches) y arrastran `*-sys`. Un scanner que compara `(mtime, tamaño)`
//!   por entrada cada `interval` da EXACTAMENTE los mismos eventos en Linux, macOS y
//!   Windows, no tiene límites del kernel, y la latencia es el intervalo (default
//!   500 ms — un agente que reacciona a "cambió un archivo" no necesita menos). El
//!   costo es un `read_dir` recursivo por tick: por eso hay `ignore` (default `.git`,
//!   `node_modules`, `target`) y un tope de entradas (`max_entries`, default 100k) que
//!   falla en voz alta en vez de quemar CPU en silencio.
//! - **Eventos**: `create` / `modify` / `delete` con `path` (separador `/`, relativa si
//!   la raíz era relativa) e `is_dir`. Un rename = `delete` + `create`. Los directorios
//!   sólo emiten `create`/`delete` (su mtime cambia con cada hijo: ruido). Cambios que
//!   ocurren y se deshacen dentro de un mismo intervalo no se ven (es polling: se
//!   entrega el estado, no el historial). No hay eventos por el contenido inicial.
//! - **Cola acotada** (`max_queue`, default 4096) con `drop_oldest` y contador
//!   `dropped` (visible en `watch_stats`): un `select` que no drena no acumula memoria.
//! - **Gate**: `file_read(path)` — mirar un árbol es leerlo (mismo scope que `list_dir`).
//! - **Ciclo de vida**: `watch_close` (o dropear el hub: fin de request/programa/agente)
//!   apaga el hilo. Nunca sobrevive al intérprete.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime};

use crate::proc::WakeFn;

pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(500);
pub const MIN_INTERVAL: Duration = Duration::from_millis(20);
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;
pub const MAX_ENTRIES_CEILING: usize = 5_000_000;
pub const DEFAULT_MAX_QUEUE: usize = 4096;
pub const MAX_QUEUE_CEILING: usize = 1_000_000;
pub const DEFAULT_IGNORE: &[&str] = &[".git", "node_modules", "target"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchKind {
    Create,
    Modify,
    Delete,
}

impl WatchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            WatchKind::Create => "create",
            WatchKind::Modify => "modify",
            WatchKind::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WatchEvent {
    pub kind: WatchKind,
    /// Ruta con `/` como separador; relativa si la raíz lo era.
    pub path: String,
    pub is_dir: bool,
}

pub struct WatchOpts {
    pub recursive: bool,
    pub interval: Duration,
    /// Nombres de entrada a saltear (match exacto sobre el nombre, o glob simple con `*`).
    pub ignore: Vec<String>,
    pub max_entries: usize,
    pub max_queue: usize,
}

impl Default for WatchOpts {
    fn default() -> Self {
        WatchOpts {
            recursive: true,
            interval: DEFAULT_INTERVAL,
            ignore: DEFAULT_IGNORE.iter().map(|s| s.to_string()).collect(),
            max_entries: DEFAULT_MAX_ENTRIES,
            max_queue: DEFAULT_MAX_QUEUE,
        }
    }
}

struct Queue {
    events: VecDeque<WatchEvent>,
    dropped: u64,
    /// Error terminal (p. ej. tope de entradas superado): el próximo recv lo entrega.
    error: Option<String>,
}

/// Estado compartido entre el hub (consumidor) y el hilo scanner (productor).
pub struct WatchShared {
    queue: Mutex<Queue>,
    max_queue: usize,
    closed: AtomicBool,
    /// El scanner duerme acá entre ticks; `close` lo despierta para que salga ya.
    tick: Condvar,
    tick_lock: Mutex<()>,
    wake: Mutex<Option<WakeFn>>,
    pub root: String,
    pub interval: Duration,
    pub recursive: bool,
    entries: AtomicUsize,
    scans: AtomicU64,
}

impl WatchShared {
    fn push(&self, ev: WatchEvent) {
        let Ok(mut q) = self.queue.lock() else { return };
        if q.error.is_some() || self.closed.load(Ordering::Relaxed) {
            return;
        }
        while q.events.len() >= self.max_queue {
            q.events.pop_front();
            q.dropped += 1;
        }
        q.events.push_back(ev);
        drop(q);
        self.wake_now();
    }

    fn fail(&self, msg: String) {
        if let Ok(mut q) = self.queue.lock() {
            q.error = Some(msg);
            q.events.clear();
        }
        self.wake_now();
    }

    fn wake_now(&self) {
        let w = self.wake.lock().ok().and_then(|g| g.clone());
        if let Some(w) = w {
            w();
        }
    }

    pub fn set_wake(&self, wake: Option<WakeFn>) {
        if let Ok(mut g) = self.wake.lock() {
            *g = wake;
        }
    }

    pub fn is_ready(&self) -> bool {
        self.queue.lock().map(|q| !q.events.is_empty() || q.error.is_some()).unwrap_or(false)
    }

    /// Próximo evento; `Err` = error terminal (el handle debe retirarse).
    pub fn try_recv(&self) -> Result<Option<WatchEvent>, String> {
        let mut q = self.queue.lock().map_err(|_| "watch: queue poisoned".to_string())?;
        if let Some(ev) = q.events.pop_front() {
            return Ok(Some(ev));
        }
        if let Some(e) = q.error.take() {
            return Err(e);
        }
        Ok(None)
    }

    /// `(queued, dropped, entries, scans)`.
    pub fn stats(&self) -> (usize, u64, usize, u64) {
        let (queued, dropped) = self.queue.lock().map(|q| (q.events.len(), q.dropped)).unwrap_or((0, 0));
        (queued, dropped, self.entries.load(Ordering::Relaxed), self.scans.load(Ordering::Relaxed))
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.tick.notify_all();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Duerme `d` o hasta `close`, lo que llegue primero.
    fn sleep(&self, d: Duration) {
        let Ok(g) = self.tick_lock.lock() else { return };
        if self.is_closed() {
            return;
        }
        let _ = self.tick.wait_timeout(g, d);
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Entry {
    mtime: Option<SystemTime>,
    len: u64,
    is_dir: bool,
}

type Snapshot = HashMap<PathBuf, Entry>;

fn name_matches(name: &str, pat: &str) -> bool {
    match pat.find('*') {
        None => name == pat,
        Some(_) => {
            // Glob mínimo: `*` comodín (uno o varios). Suficiente para `*.log`, `tmp*`.
            let parts: Vec<&str> = pat.split('*').collect();
            let mut pos = 0usize;
            for (i, part) in parts.iter().enumerate() {
                if part.is_empty() {
                    continue;
                }
                let first = i == 0;
                let last = i == parts.len() - 1;
                if first {
                    if !name.starts_with(part) {
                        return false;
                    }
                    pos = part.len();
                } else if last {
                    return name.len() >= pos + part.len() && name.ends_with(part);
                } else {
                    match name[pos..].find(part) {
                        Some(k) => pos += k + part.len(),
                        None => return false,
                    }
                }
            }
            true
        }
    }
}

fn ignored(name: &std::ffi::OsStr, ignore: &[String]) -> bool {
    let n = name.to_string_lossy();
    ignore.iter().any(|p| name_matches(&n, p))
}

/// Toma la foto del árbol. `Err` si se supera `max_entries` (fallo en voz alta).
fn snapshot(root: &Path, opts: &WatchOpts, out: &mut Snapshot) -> Result<(), String> {
    let Ok(meta) = std::fs::symlink_metadata(root) else {
        // Raíz ausente: foto vacía (el diff emite `delete` de lo que había).
        return Ok(());
    };
    let entry = Entry { mtime: meta.modified().ok(), len: meta.len(), is_dir: meta.is_dir() };
    let is_dir = meta.is_dir();
    out.insert(root.to_path_buf(), entry);
    if !is_dir {
        return Ok(());
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let name = e.file_name();
            if ignored(&name, &opts.ignore) {
                continue;
            }
            let p = e.path();
            // symlink_metadata: no seguir symlinks (un enlace a `/` haría explotar el
            // scan; un enlace a un archivo se ve como el enlace, no como el destino).
            let Ok(m) = std::fs::symlink_metadata(&p) else { continue };
            let is_dir = m.is_dir();
            out.insert(p.clone(), Entry { mtime: m.modified().ok(), len: m.len(), is_dir });
            if out.len() > opts.max_entries {
                return Err(format!(
                    "the watched tree has more than {} entries; narrow the path, add ignore patterns, or raise max_entries",
                    opts.max_entries
                ));
            }
            if is_dir && opts.recursive {
                stack.push(p);
            }
        }
    }
    Ok(())
}

fn display_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Diff ordenado (determinista) entre dos fotos.
fn diff(old: &Snapshot, new: &Snapshot) -> Vec<WatchEvent> {
    let mut evs = Vec::new();
    let mut created: Vec<&PathBuf> = new.keys().filter(|k| !old.contains_key(*k)).collect();
    let mut deleted: Vec<&PathBuf> = old.keys().filter(|k| !new.contains_key(*k)).collect();
    let mut modified: Vec<&PathBuf> = new
        .iter()
        .filter(|(k, v)| !v.is_dir && old.get(*k).map(|o| o != *v).unwrap_or(false))
        .map(|(k, _)| k)
        .collect();
    created.sort();
    deleted.sort();
    modified.sort();
    for p in deleted {
        evs.push(WatchEvent { kind: WatchKind::Delete, path: display_path(p), is_dir: old[p].is_dir });
    }
    for p in created {
        evs.push(WatchEvent { kind: WatchKind::Create, path: display_path(p), is_dir: new[p].is_dir });
    }
    for p in modified {
        evs.push(WatchEvent { kind: WatchKind::Modify, path: display_path(p), is_dir: false });
    }
    evs
}

/// Un watch vivo, propiedad del hub. Dropearlo apaga el scanner.
pub struct Watch {
    pub shared: Arc<WatchShared>,
}

impl Watch {
    /// Toma la foto inicial (síncrona: los errores de raíz/tope se ven en `watch()`)
    /// y arranca el scanner. NO chequea capabilities (lo hace el builtin).
    pub fn start(root: &str, opts: WatchOpts) -> Result<Watch, String> {
        let root_path = PathBuf::from(root);
        if std::fs::symlink_metadata(&root_path).is_err() {
            return Err(format!("cannot watch \"{}\": no such file or directory", root));
        }
        let mut first = Snapshot::new();
        snapshot(&root_path, &opts, &mut first)?;
        let shared = Arc::new(WatchShared {
            queue: Mutex::new(Queue { events: VecDeque::new(), dropped: 0, error: None }),
            max_queue: opts.max_queue.clamp(1, MAX_QUEUE_CEILING),
            closed: AtomicBool::new(false),
            tick: Condvar::new(),
            tick_lock: Mutex::new(()),
            wake: Mutex::new(None),
            root: root.to_string(),
            interval: opts.interval.max(MIN_INTERVAL),
            recursive: opts.recursive,
            entries: AtomicUsize::new(first.len()),
            scans: AtomicU64::new(1),
        });
        let sh = shared.clone();
        std::thread::Builder::new()
            .name("synsema-watch".into())
            .spawn(move || scanner_loop(root_path, opts, first, sh))
            .map_err(|e| format!("cannot start the watch scanner: {}", e))?;
        Ok(Watch { shared })
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.shared.close();
    }
}

fn scanner_loop(root: PathBuf, opts: WatchOpts, mut prev: Snapshot, sh: Arc<WatchShared>) {
    let interval = sh.interval;
    loop {
        sh.sleep(interval);
        if sh.is_closed() {
            return;
        }
        let mut cur = Snapshot::with_capacity(prev.len());
        if let Err(e) = snapshot(&root, &opts, &mut cur) {
            sh.fail(e);
            return;
        }
        sh.scans.fetch_add(1, Ordering::Relaxed);
        sh.entries.store(cur.len(), Ordering::Relaxed);
        for ev in diff(&prev, &cur) {
            sh.push(ev);
        }
        prev = cur;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_minimo() {
        assert!(name_matches("a.log", "*.log"));
        assert!(name_matches("tmp123", "tmp*"));
        assert!(name_matches("a-b-c", "a*c"));
        assert!(name_matches("node_modules", "node_modules"));
        assert!(!name_matches("node_modules2", "node_modules"));
        assert!(!name_matches("a.txt", "*.log"));
        assert!(name_matches("x", "*"));
    }
}

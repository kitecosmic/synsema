//! Blackboard — estado compartido para coordinación multi-agente.
//!
//! Port de `synsema/agents/blackboard.py`. Thread-safe (los agentes corren en
//! hilos reales), observable (cada read/write se loguea), versionado (guarda
//! historial). Almacena `SendValue` (owned, `Send`) — el `share`/`observe` hacen
//! la conversión `SynValue`↔`SendValue` (snapshot, modelo CSP).

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};

use indexmap::IndexMap;
use synsema_core::interpreter::RunCut;
use synsema_core::types::SendValue;

thread_local! {
    /// v0.6.47 (T1): la corrida (`RunCut`) en cuyo nombre escribe este hilo, sólo con etiquetas.
    static SCOPE: RefCell<Option<Arc<RunCut>>> = const { RefCell::new(None) };
}

/// v0.6.47 (T1): fija (o saca) la corrida de este hilo. Con una puesta, cada escritura queda en el
/// diario de esa corrida hasta que se confirma (`commit`) o se deshace (`rollback`).
pub fn set_thread_scope(scope: Option<Arc<RunCut>>) {
    SCOPE.with(|s| *s.borrow_mut() = scope);
}

/// v0.6.47 (T1): la corrida de este hilo, si tiene (las señales la anotan igual que el blackboard).
pub fn thread_scope() -> Option<Arc<RunCut>> {
    SCOPE.with(|s| s.borrow().clone())
}

/// v0.6.47 (T1) — lo que las corridas abiertas escribieron en una clave. Bajo `serve` con etiquetas,
/// un request que escribe en el blackboard en cada vuelta y se corta en la del secreto dejaba esas
/// claves para los requests siguientes (el diario de `state_*` del T5 no lo cubría): cuántas
/// quedaban era el dato.
///
/// Mientras alguna corrida abierta escribió la clave, la clave lleva la cadena de sus versiones, cada
/// una con la corrida que la escribió (el request, sus agentes y los agentes de sus agentes son la
/// misma). Deshacer una corrida es sacar sus versiones de la cadena: la clave queda en la última que
/// sobrevive, como si la corrida cortada no hubiera escrito nunca, sin importar cuánto avanzó ni
/// cómo se intercaló con otras (A, B, A: queda lo de B). Cuando todo lo de la cadena está
/// confirmado, la cadena se suelta.
///
/// **Acotada** (ronda 7): la clave queda siempre en la versión más alta que sobrevive, así que de cada
/// corrida sólo importa su versión más alta, y nada de lo que está debajo de una confirmada (que no se
/// saca nunca) puede volver. `compact` deja una versión por corrida con algo vivo (su dueño o un
/// agente suyo, aunque el request haya cerrado hace mucho) más la base: un agente que vive lo que el
/// server (lanzado en el preámbulo, o un worker que no termina) y se alterna con los requests no la
/// hace crecer. La cota son los agentes vivos, que ya son un recurso (ronda 9, N2).
///
/// **Ojo (ronda 7, N1):** la entrada que vuelve tras deshacer trae en `history` y en `version` lo que
/// escribió la corrida cortada (y `events` anota todo). Ningún builtin los muestra; si alguno los
/// mostrara, habría que reconstruirlos de las versiones que sobreviven, o serían un canal.
struct Chain {
    /// La entrada antes de la primera versión de la cadena (`None` = no existía).
    base: Option<BlackboardEntry>,
    versions: Vec<Version>,
}

struct Version {
    /// `None` = confirmada.
    scope: Option<Arc<RunCut>>,
    /// La entrada como la dejó esta versión (`None` adentro = borrada). La de la última versión es la
    /// viva (`data`), así que se copia recién cuando otra corrida escribe encima.
    entry: Option<Option<BlackboardEntry>>,
}

impl Chain {
    /// De arriba hacia abajo, deja la versión más alta de cada corrida abierta y corta en la primera
    /// confirmada: lo de abajo ya no puede volver (pasa a ser la base). `false` si no queda nada
    /// abierto: la cadena sobra.
    ///
    /// Basta la versión más alta de cada corrida porque una corrida se confirma o se deshace **entera**
    /// (dueño y agentes, `RunState`): todas sus versiones comparten destino. Con confirmaciones por
    /// agente o por tramo esto dejaría de valer (ronda 8, N2).
    fn compact(&mut self) -> bool {
        let mut kept: Vec<Version> = Vec::new();
        for v in std::mem::take(&mut self.versions).into_iter().rev() {
            if v.scope.is_none() {
                match v.entry {
                    // La de arriba confirmada: no hay nada abierto encima.
                    None => return false,
                    Some(e) => self.base = e,
                }
                break;
            }
            if !kept.iter().any(|k| same_run(&k.scope, &v.scope)) {
                kept.push(v);
            }
        }
        kept.reverse();
        self.versions = kept;
        !self.versions.is_empty()
    }
}

fn same_run(a: &Option<Arc<RunCut>>, b: &Option<Arc<RunCut>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        (None, None) => true,
        _ => false,
    }
}

fn now_secs() -> f64 {
    synsema_core::clock::now_secs_f64()
}

/// Una entrada del blackboard, con historial.
#[derive(Clone, Debug)]
pub struct BlackboardEntry {
    pub key: String,
    pub value: SendValue,
    pub version: u64,
    pub written_by: String,
    pub written_at: f64,
    /// (value, version, agent, time) de versiones previas.
    pub history: Vec<(SendValue, u64, String, f64)>,
}

/// Un evento emitido por el blackboard.
#[derive(Clone, Debug)]
pub struct BlackboardEvent {
    pub event_type: String, // "write" | "read" | "delete"
    pub key: String,
    pub agent: String,
    pub value: Option<SendValue>,
    pub timestamp: f64,
}

/// Callback de watcher: (key, value, agent). Debe ser `Send` (se llama desde
/// cualquier hilo).
pub type Watcher = Box<dyn Fn(&str, &SendValue, &str) + Send>;

struct Inner {
    data: IndexMap<String, BlackboardEntry>,
    watchers: HashMap<String, Vec<Watcher>>,
    events: Vec<BlackboardEvent>,
    /// v0.6.47 (T1): las cadenas de versiones de las claves que escribió una corrida abierta.
    chains: HashMap<String, Chain>,
    /// v0.6.47 (T1): el estado de cada corrida con agentes o con su dueño todavía abierto (ver
    /// `specs/t1-diario-modelo.md`). Guarda el `Arc`: la dirección no se reusa mientras está acá.
    runs: Vec<(Arc<RunCut>, RunState)>,
}

impl Inner {
    /// Anota que `key` (que valía `prev`) va a cambiar: en la cadena de la clave si la tiene, o en una
    /// nueva si este hilo escribe por una corrida.
    fn record(&mut self, key: &str, prev: Option<BlackboardEntry>) {
        let scope = thread_scope();
        let Some(chain) = self.chains.get_mut(key) else {
            if scope.is_some() {
                self.chains.insert(key.to_string(), Chain { base: prev, versions: vec![Version { scope, entry: None }] });
            }
            return;
        };
        if let Some(top) = chain.versions.last_mut() {
            if same_run(&top.scope, &scope) {
                return;
            }
            top.entry = Some(prev);
        }
        chain.versions.push(Version { scope, entry: None });
        if !chain.compact() {
            self.chains.remove(key);
        }
    }

    /// Deshace lo que la corrida `scope` escribió y no confirmó (de todos sus hilos): saca sus
    /// versiones y cada clave queda en la última que sobrevive.
    fn rollback(&mut self, scope: &Arc<RunCut>) {
        let mine = Some(scope.clone());
        for (key, chain) in self.chains.iter_mut() {
            let top_was_mine = chain.versions.last().is_some_and(|v| same_run(&v.scope, &mine));
            chain.versions.retain(|v| !same_run(&v.scope, &mine));
            if !top_was_mine {
                continue;
            }
            let now = match chain.versions.last_mut() {
                Some(top) => top.entry.take().flatten(),
                None => chain.base.clone(),
            };
            match now {
                Some(e) => {
                    self.data.insert(key.clone(), e);
                }
                None => {
                    self.data.shift_remove(key);
                }
            }
        }
        self.settle();
    }

    /// Compacta cada cadena y suelta las que no tienen nada abierto.
    fn settle(&mut self) {
        self.chains.retain(|_, c| c.compact());
    }

    /// Confirma todas las versiones de `scope` (la corrida terminó entera sin corte).
    fn commit(&mut self, scope: &Arc<RunCut>) {
        let mine = Some(scope.clone());
        for chain in self.chains.values_mut() {
            for v in chain.versions.iter_mut().filter(|v| same_run(&v.scope, &mine)) {
                v.scope = None;
            }
        }
        self.settle();
    }

    fn run_state(&mut self, scope: &Arc<RunCut>) -> &mut RunState {
        let i = match self.runs.iter().position(|(r, _)| Arc::ptr_eq(r, scope)) {
            Some(i) => i,
            None => {
                self.runs.push((scope.clone(), RunState::default()));
                self.runs.len() - 1
            }
        };
        &mut self.runs[i].1
    }

    /// Después de cada evento de la corrida: si terminó entera (dueño cerrado y sin agentes vivos),
    /// se confirma (o, si se cortó, ya se deshizo) y se suelta su estado.
    fn finish_if_done(&mut self, scope: &Arc<RunCut>) {
        let st = *self.run_state(scope);
        if st.live > 0 || !st.closed {
            return;
        }
        if !st.cut {
            self.commit(scope);
        }
        self.runs.retain(|(r, _)| !Arc::ptr_eq(r, scope));
    }

    /// La corrida se cortó (el dueño o cualquier agente): se deshace entera y queda marcada, así lo que
    /// escriba después un agente vivo se deshace cuando termine.
    fn cut_run(&mut self, scope: &Arc<RunCut>) {
        self.run_state(scope).cut = true;
        self.rollback(scope);
    }
}

/// v0.6.47 (T1) — el estado de una corrida para el diario (`specs/t1-diario-modelo.md`). La corrida es
/// la unidad: se confirma una sola vez, cuando terminó entera sin corte (el dueño cerró y no le queda
/// ningún agente vivo), y se deshace entera si cualquier parte se corta. Una confirmación parcial
/// (por agente, o lo escrito hasta el cierre del dueño) dejaría un tercer resultado que dice cuándo
/// cayó el corte.
#[derive(Clone, Copy, Default)]
struct RunState {
    /// Agentes vivos de la corrida (`+1` en el hilo que lanza, antes de crear el del agente).
    live: usize,
    /// El dueño cerró.
    closed: bool,
    /// Alguna parte se cortó.
    cut: bool,
}

/// Estado compartido thread-safe. Se usa tras un `Arc<Blackboard>`.
pub struct Blackboard {
    inner: Mutex<Inner>,
    /// Notifica a quienes esperan en `wait_for_key` cuando se escribe cualquier clave.
    cvar: Condvar,
}

impl Default for Blackboard {
    fn default() -> Self {
        Self::new()
    }
}

impl Blackboard {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                data: IndexMap::new(),
                watchers: HashMap::new(),
                events: Vec::new(),
                chains: HashMap::new(),
                runs: Vec::new(),
            }),
            cvar: Condvar::new(),
        }
    }

    pub fn write(&self, key: &str, value: SendValue, agent: &str) {
        let mut g = self.inner.lock().unwrap();
        let now = now_secs();
        let prev = g.data.get(key).cloned();
        g.record(key, prev);
        if let Some(entry) = g.data.get_mut(key) {
            entry.history.push((
                entry.value.clone(),
                entry.version,
                entry.written_by.clone(),
                entry.written_at,
            ));
            entry.value = value.clone();
            entry.version += 1;
            entry.written_by = agent.to_string();
            entry.written_at = now;
        } else {
            g.data.insert(
                key.to_string(),
                BlackboardEntry {
                    key: key.to_string(),
                    value: value.clone(),
                    version: 1,
                    written_by: agent.to_string(),
                    written_at: now,
                    history: Vec::new(),
                },
            );
        }
        g.events.push(BlackboardEvent {
            event_type: "write".to_string(),
            key: key.to_string(),
            agent: agent.to_string(),
            value: Some(value.clone()),
            timestamp: now,
        });
        // Notificar watchers (mientras se sostiene el lock, como el oráculo).
        if let Some(cbs) = g.watchers.get(key) {
            for cb in cbs {
                cb(key, &value, agent);
            }
        }
        drop(g);
        // Despertar a quienes esperan una clave.
        self.cvar.notify_all();
    }

    /// v0.6.47 (T1): el dueño de la corrida `scope` (la entrada de `serve`, o el preámbulo) terminó.
    /// Devuelve si se deshizo la corrida.
    pub(crate) fn close_run(&self, scope: &Arc<RunCut>, cut: bool) -> bool {
        let mut g = self.inner.lock().unwrap();
        let was_cut = g.run_state(scope).cut;
        g.run_state(scope).closed = true;
        let undo = cut || was_cut;
        if undo {
            g.cut_run(scope);
        }
        g.finish_if_done(scope);
        undo
    }

    /// v0.6.47 (T1): se lanzó un agente de la corrida `scope`. Se llama en el hilo que lanza, antes
    /// de crear el del agente: así un agente que lanza otro y termina suma antes de restar.
    pub(crate) fn agent_started(&self, scope: &Arc<RunCut>) {
        self.inner.lock().unwrap().run_state(scope).live += 1;
    }

    /// v0.6.47 (T1): un agente de la corrida `scope` terminó. Con corte (o si la corrida ya estaba
    /// cortada), se deshace entera; si no, espera al resto. La decisión se toma acá, bajo el lock, con
    /// el estado de la corrida: nunca leyendo el `RunCut` por fuera. Devuelve si se deshizo.
    pub(crate) fn agent_done(&self, scope: &Arc<RunCut>, cut: bool) -> bool {
        let mut g = self.inner.lock().unwrap();
        let st = g.run_state(scope);
        st.live = st.live.saturating_sub(1);
        let undo = cut || st.cut;
        if undo {
            g.cut_run(scope);
        }
        g.finish_if_done(scope);
        undo
    }

    pub fn read(&self, key: &str, agent: &str) -> Option<SendValue> {
        let mut g = self.inner.lock().unwrap();
        let value = g.data.get(key).map(|e| e.value.clone());
        g.events.push(BlackboardEvent {
            event_type: "read".to_string(),
            key: key.to_string(),
            agent: agent.to_string(),
            value: value.clone(),
            timestamp: now_secs(),
        });
        value
    }

    pub fn delete(&self, key: &str, agent: &str) {
        let mut g = self.inner.lock().unwrap();
        let prev = g.data.shift_remove(key);
        g.record(key, prev);
        g.events.push(BlackboardEvent {
            event_type: "delete".to_string(),
            key: key.to_string(),
            agent: agent.to_string(),
            value: None,
            timestamp: now_secs(),
        });
    }

    pub fn watch(&self, key: &str, callback: Watcher) {
        let mut g = self.inner.lock().unwrap();
        g.watchers.entry(key.to_string()).or_default().push(callback);
    }

    /// Bloquea hasta que la clave se escriba; devuelve su valor (o None por timeout).
    pub fn wait_for_key(&self, key: &str, timeout: Option<std::time::Duration>) -> Option<SendValue> {
        let mut g = self.inner.lock().unwrap();
        loop {
            if let Some(e) = g.data.get(key) {
                return Some(e.value.clone());
            }
            match timeout {
                Some(dur) => {
                    let (ng, res) = self.cvar.wait_timeout(g, dur).unwrap();
                    g = ng;
                    if res.timed_out() && g.data.get(key).is_none() {
                        return None;
                    }
                }
                None => {
                    g = self.cvar.wait(g).unwrap();
                }
            }
        }
    }

    pub fn keys(&self) -> Vec<String> {
        self.inner.lock().unwrap().data.keys().cloned().collect()
    }

    /// Snapshot de los valores actuales (clave → valor).
    pub fn snapshot(&self) -> IndexMap<String, SendValue> {
        self.inner
            .lock()
            .unwrap()
            .data
            .iter()
            .map(|(k, e)| (k.clone(), e.value.clone()))
            .collect()
    }

    pub fn get_events(&self) -> Vec<BlackboardEvent> {
        self.inner.lock().unwrap().events.clone()
    }

    /// Info de una clave: version, history_length, written_by, value.
    pub fn get_entry_info(&self, key: &str) -> Option<EntryInfo> {
        self.inner.lock().unwrap().data.get(key).map(|e| EntryInfo {
            key: e.key.clone(),
            value: e.value.clone(),
            version: e.version,
            written_by: e.written_by.clone(),
            history_length: e.history.len(),
        })
    }

    /// Vista interna (para el dashboard del swarm): (key, value, version, written_by).
    pub fn entries_view(&self) -> Vec<(String, SendValue, u64, String)> {
        self.inner
            .lock()
            .unwrap()
            .data
            .iter()
            .map(|(k, e)| (k.clone(), e.value.clone(), e.version, e.written_by.clone()))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct EntryInfo {
    pub key: String,
    pub value: SendValue,
    pub version: u64,
    pub written_by: String,
    pub history_length: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};
    use synsema_core::number::Number;

    fn text(s: &str) -> SendValue {
        SendValue::Text(s.to_string())
    }
    fn num(n: i64) -> SendValue {
        SendValue::Number(Number::Int(n))
    }

    #[test]
    fn blackboard_write_read() {
        let bb = Blackboard::new();
        bb.write("key1", text("hello"), "agent1");
        let val = bb.read("key1", "agent2");
        assert_eq!(val, Some(text("hello")));
    }

    #[test]
    fn blackboard_read_nonexistent() {
        let bb = Blackboard::new();
        assert_eq!(bb.read("nonexistent", ""), None);
    }

    #[test]
    fn blackboard_versioning() {
        let bb = Blackboard::new();
        bb.write("counter", num(1), "a1");
        bb.write("counter", num(2), "a1");
        bb.write("counter", num(3), "a2");
        let info = bb.get_entry_info("counter").unwrap();
        assert_eq!(info.version, 3);
        assert_eq!(info.history_length, 2);
    }

    #[test]
    fn blackboard_watcher() {
        let bb = Blackboard::new();
        let received: Arc<StdMutex<Vec<(String, String, String)>>> = Arc::new(StdMutex::new(Vec::new()));
        let r = received.clone();
        bb.watch(
            "events",
            Box::new(move |k, v, a| {
                r.lock().unwrap().push((k.to_string(), v.to_string(), a.to_string()));
            }),
        );
        bb.write("events", text("event1"), "producer");
        bb.write("events", text("event2"), "producer");
        let got = received.lock().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], ("events".into(), "event1".into(), "producer".into()));
    }

    #[test]
    fn blackboard_snapshot() {
        let bb = Blackboard::new();
        bb.write("a", num(1), "");
        bb.write("b", num(2), "");
        let snap = bb.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get("a"), Some(&num(1)));
        assert_eq!(snap.get("b"), Some(&num(2)));
    }

    #[test]
    fn blackboard_delete() {
        let bb = Blackboard::new();
        bb.write("temp", text("data"), "");
        bb.delete("temp", "");
        assert_eq!(bb.read("temp", ""), None);
    }

    #[test]
    fn blackboard_events() {
        let bb = Blackboard::new();
        bb.write("x", num(1), "a1");
        bb.read("x", "a2");
        let events = bb.get_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "write");
        assert_eq!(events[1].event_type, "read");
    }
    // v0.6.47 (T1, ronda 5): el diario por corrida. `as_run` escribe desde otro hilo con su corrida.
    fn as_run(bb: &Arc<Blackboard>, run: &Arc<RunCut>, f: impl FnOnce(&Blackboard) + Send + 'static) {
        let (bb, run) = (bb.clone(), run.clone());
        std::thread::spawn(move || {
            set_thread_scope(Some(run));
            f(&bb);
            set_thread_scope(None);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn a_cut_run_written_by_two_threads_leaves_nothing() {
        // El request y su agente (o un agente y su subagente), en los dos órdenes.
        for first_writes_last in [false, true] {
            let bb = Arc::new(Blackboard::new());
            bb.write("k", text("antes"), "");
            let run = Arc::new(RunCut::default());
            as_run(&bb, &run, |b| b.write("k", text("del request"), ""));
            as_run(&bb, &run, |b| b.write("k", text("del agente"), ""));
            if first_writes_last {
                as_run(&bb, &run, |b| b.write("k", text("del request otra vez"), ""));
            }
            bb.close_run(&run, true);
            assert_eq!(bb.read("k", ""), Some(text("antes")));
            // Con el sello de antes: otra corrida que lo había escrito todavía puede deshacerse.
            let run = Arc::new(RunCut::default());
            as_run(&bb, &run, |b| b.write("n", num(1), ""));
            as_run(&bb, &run, |b| b.write("n", num(2), ""));
            bb.close_run(&run, true);
            assert_eq!(bb.read("n", ""), None);
        }
    }

    #[test]
    fn a_later_run_that_is_cut_too_does_not_bring_back_the_first() {
        // Las dos cortadas, en los dos órdenes de cierre.
        for a_closes_first in [true, false] {
            let bb = Arc::new(Blackboard::new());
            bb.write("k", text("antes"), "");
            let (a, b) = (Arc::new(RunCut::default()), Arc::new(RunCut::default()));
            as_run(&bb, &a, |x| x.write("k", text("de a, antes del corte"), ""));
            as_run(&bb, &b, |x| x.write("k", text("de b"), ""));
            if a_closes_first {
                bb.close_run(&a, true);
                assert_eq!(bb.read("k", ""), Some(text("de b")), "lo de otra corrida no se toca");
                bb.close_run(&b, true);
            } else {
                bb.close_run(&b, true);
                assert_eq!(bb.read("k", ""), Some(text("de a, antes del corte")));
                bb.close_run(&a, true);
            }
            assert_eq!(bb.read("k", ""), Some(text("antes")));
        }
    }

    #[test]
    fn a_delete_is_a_version_like_a_write() {
        let bb = Arc::new(Blackboard::new());
        bb.write("k", text("antes"), "");
        let (a, b) = (Arc::new(RunCut::default()), Arc::new(RunCut::default()));
        as_run(&bb, &a, |x| x.delete("k", ""));
        as_run(&bb, &b, |x| {
            x.write("k", text("de b"), "");
            x.delete("k", "");
        });
        bb.close_run(&b, false);
        bb.close_run(&a, true);
        assert_eq!(bb.read("k", ""), None, "el borrado confirmado de b no se pisa");
        // Un borrado de una corrida cortada se deshace como una escritura.
        bb.write("k", text("antes"), "");
        let c = Arc::new(RunCut::default());
        as_run(&bb, &c, |x| x.delete("k", ""));
        bb.close_run(&c, true);
        assert_eq!(bb.read("k", ""), Some(text("antes")));
    }

    #[test]
    fn interleaved_runs_a_b_a_keep_what_b_confirmed() {
        // A, B (que confirma), A otra vez, y A se corta: queda lo de B, avance A lo que avance.
        for a_writes_again in [false, true] {
            let bb = Arc::new(Blackboard::new());
            bb.write("k", text("antes"), "");
            let (a, b) = (Arc::new(RunCut::default()), Arc::new(RunCut::default()));
            as_run(&bb, &a, |x| x.write("k", text("a1"), ""));
            as_run(&bb, &b, |x| x.write("k", text("de b"), ""));
            bb.close_run(&b, false);
            if a_writes_again {
                as_run(&bb, &a, |x| x.write("k", text("a2"), ""));
            }
            bb.close_run(&a, true);
            assert_eq!(bb.read("k", ""), Some(text("de b")), "A escribió otra vez: {}", a_writes_again);
            assert!(bb.inner.lock().unwrap().chains.is_empty(), "todo cerrado: no quedan cadenas");
        }
        // Escrituras sin corrida en el medio (otro hilo fuera de toda corrida) también sobreviven.
        let bb = Arc::new(Blackboard::new());
        let a = Arc::new(RunCut::default());
        as_run(&bb, &a, |x| x.write("k", text("a1"), ""));
        bb.write("k", text("sin corrida"), "");
        as_run(&bb, &a, |x| x.write("k", text("a2"), ""));
        bb.close_run(&a, true);
        assert_eq!(bb.read("k", ""), Some(text("sin corrida")));
    }

    #[test]
    fn a_confirmed_run_leaves_no_chain_and_many_writes_one_version() {
        let bb = Arc::new(Blackboard::new());
        let a = Arc::new(RunCut::default());
        as_run(&bb, &a, |x| {
            for i in 0..100 {
                x.write("k", num(i), "");
            }
        });
        assert_eq!(bb.inner.lock().unwrap().chains["k"].versions.len(), 1);
        bb.close_run(&a, false);
        assert!(bb.inner.lock().unwrap().chains.is_empty());
        assert_eq!(bb.read("k", ""), Some(num(99)));
    }

    #[test]
    fn a_run_that_never_closes_keeps_the_chain_bounded() {
        // Un agente del preámbulo (su corrida no se cierra mientras vive) y cien requests que
        // confirman, alternándose sobre la misma clave: la cadena no crece.
        let bb = Arc::new(Blackboard::new());
        let p = Arc::new(RunCut::default());
        bb.agent_started(&p);
        for i in 0..100 {
            as_run(&bb, &p, move |x| x.write("k", num(1000 + i), ""));
            let r = Arc::new(RunCut::default());
            as_run(&bb, &r, move |x| x.write("k", num(i), ""));
            bb.close_run(&r, false);
            let n = bb.inner.lock().unwrap().chains.get("k").map_or(0, |c| c.versions.len());
            assert!(n <= 1, "vuelta {}: {} versiones", i, n);
        }
        as_run(&bb, &p, |x| x.write("k", num(-1), ""));
        bb.agent_done(&p, true);
        assert_eq!(bb.read("k", ""), Some(num(99)), "queda lo último confirmado");
        assert!(bb.inner.lock().unwrap().chains.is_empty());

        // El otro orden: el request escribe, el agente escribe encima y recién ahí cierra el request
        // (la confirmada queda debajo de la abierta).
        let bb = Arc::new(Blackboard::new());
        let p = Arc::new(RunCut::default());
        bb.agent_started(&p);
        for i in 0..100 {
            let r = Arc::new(RunCut::default());
            as_run(&bb, &r, move |x| x.write("k", num(i), ""));
            as_run(&bb, &p, move |x| x.write("k", num(1000 + i), ""));
            bb.close_run(&r, false);
            let n = bb.inner.lock().unwrap().chains.get("k").map_or(0, |c| c.versions.len());
            assert!(n <= 1, "vuelta {}: {} versiones", i, n);
        }
        bb.agent_done(&p, true);
        assert_eq!(bb.read("k", ""), Some(num(99)));

        // Dos corridas abiertas alternándose: una versión por corrida.
        let bb = Arc::new(Blackboard::new());
        bb.write("k", text("antes"), "");
        let (a, b) = (Arc::new(RunCut::default()), Arc::new(RunCut::default()));
        for i in 0..50 {
            as_run(&bb, &a, move |x| x.write("k", num(i), ""));
            as_run(&bb, &b, move |x| x.write("k", num(100 + i), ""));
        }
        assert_eq!(bb.inner.lock().unwrap().chains["k"].versions.len(), 2);
        bb.close_run(&b, true);
        assert_eq!(bb.read("k", ""), Some(num(49)), "queda lo último de a");
        bb.close_run(&a, true);
        assert_eq!(bb.read("k", ""), Some(text("antes")));
    }

    // Los casos de `specs/t1-diario-modelo.md` (la corrida entera es la unidad). El fin de un agente
    // no depende del hilo: los tests manejan el contador de vivos directamente.

    fn open_chains(bb: &Blackboard) -> usize {
        bb.inner.lock().unwrap().chains.len()
    }

    #[test]
    fn caso_3_an_agent_that_ended_well_is_undone_with_its_cut_request() {
        let bb = Arc::new(Blackboard::new());
        let r = Arc::new(RunCut::default());
        bb.agent_started(&r);
        as_run(&bb, &r, |x| x.write("a", num(1), ""));
        assert!(!bb.agent_done(&r, false));
        as_run(&bb, &r, |x| x.write("r", num(1), ""));
        assert!(bb.close_run(&r, true));
        assert_eq!((bb.read("a", ""), bb.read("r", "")), (None, None));
        assert_eq!(open_chains(&bb), 0);
    }

    #[test]
    fn caso_4_the_run_confirms_when_its_last_agent_ends() {
        let bb = Arc::new(Blackboard::new());
        let r = Arc::new(RunCut::default());
        as_run(&bb, &r, |x| x.write("r", num(1), ""));
        bb.agent_started(&r);
        assert!(!bb.close_run(&r, false));
        assert_eq!(open_chains(&bb), 1, "con un agente vivo, la corrida no se confirma");
        as_run(&bb, &r, |x| x.write("a", num(2), ""));
        assert!(!bb.agent_done(&r, false));
        assert_eq!(open_chains(&bb), 0);
        assert_eq!((bb.read("r", ""), bb.read("a", "")), (Some(num(1)), Some(num(2))));
        assert!(bb.inner.lock().unwrap().runs.is_empty());
    }

    #[test]
    fn caso_5_an_agent_cut_after_its_request_closed_undoes_the_whole_run() {
        let bb = Arc::new(Blackboard::new());
        let r = Arc::new(RunCut::default());
        as_run(&bb, &r, |x| x.write("r", num(1), ""));
        bb.agent_started(&r);
        bb.close_run(&r, false);
        as_run(&bb, &r, |x| x.write("a", num(2), ""));
        assert!(bb.agent_done(&r, true));
        assert_eq!((bb.read("r", ""), bb.read("a", "")), (None, None));
    }

    #[test]
    fn caso_6_y_7_whether_the_cut_agent_wrote_or_not_everything_is_undone() {
        for cut_one_wrote in [true, false] {
            let bb = Arc::new(Blackboard::new());
            let r = Arc::new(RunCut::default());
            bb.agent_started(&r);
            bb.agent_started(&r);
            bb.close_run(&r, false);
            as_run(&bb, &r, |x| x.write("k", text("del que termina bien"), ""));
            if cut_one_wrote {
                as_run(&bb, &r, |x| x.write("k", text("del cortado"), ""));
            }
            assert!(!bb.agent_done(&r, false));
            assert!(bb.agent_done(&r, true));
            assert_eq!(bb.read("k", ""), None, "el cortado escribió: {}", cut_one_wrote);
        }
    }

    #[test]
    fn caso_12_what_a_live_agent_writes_after_its_run_was_cut_is_undone_when_it_ends() {
        let bb = Arc::new(Blackboard::new());
        let r = Arc::new(RunCut::default());
        bb.agent_started(&r);
        bb.agent_started(&r);
        bb.close_run(&r, false);
        assert!(bb.agent_done(&r, true));
        as_run(&bb, &r, |x| x.write("tarde", num(1), ""));
        assert!(bb.agent_done(&r, false), "la corrida ya estaba cortada");
        assert_eq!(bb.read("tarde", ""), None);
        assert!(bb.inner.lock().unwrap().runs.is_empty());
    }

    #[test]
    fn caso_21_an_agent_cut_before_the_owner_closes_undoes_what_the_owner_writes_later() {
        // El dueño decide con el estado de la corrida en el diario, no con su propio `RunCut`: aunque
        // cierre sin corte, la corrida ya estaba cortada y lo suyo se deshace (y avisa, para las señales).
        let bb = Arc::new(Blackboard::new());
        let r = Arc::new(RunCut::default());
        bb.agent_started(&r);
        assert!(bb.agent_done(&r, true));
        as_run(&bb, &r, |x| x.write("r", num(1), ""));
        assert!(bb.close_run(&r, false));
        assert_eq!(bb.read("r", ""), None);
        assert!(bb.inner.lock().unwrap().runs.is_empty());
    }

    #[test]
    fn caso_19_owner_close_and_agent_end_give_the_same_in_both_orders() {
        // Secuencial a propósito: todo pasa bajo el lock de `inner`, así que estos dos órdenes son los
        // únicos posibles (no es un test de concurrencia; ronda 10, N2).
        for owner_first in [true, false] {
            let bb = Arc::new(Blackboard::new());
            let r = Arc::new(RunCut::default());
            bb.agent_started(&r);
            as_run(&bb, &r, |x| x.write("k", num(1), ""));
            if owner_first {
                bb.close_run(&r, false);
                bb.agent_done(&r, false);
            } else {
                bb.agent_done(&r, false);
                bb.close_run(&r, false);
            }
            assert_eq!(bb.read("k", ""), Some(num(1)));
            assert_eq!(open_chains(&bb), 0, "confirmada (dueño primero: {})", owner_first);
        }
    }

    #[test]
    fn caso_20_an_agent_that_launches_another_before_ending_keeps_the_run_open() {
        let bb = Arc::new(Blackboard::new());
        let r = Arc::new(RunCut::default());
        bb.agent_started(&r);
        bb.close_run(&r, false);
        // El agente lanza otro (suma en su hilo, antes de restar) y termina.
        bb.agent_started(&r);
        as_run(&bb, &r, |x| x.write("k", num(1), ""));
        bb.agent_done(&r, false);
        assert_eq!(open_chains(&bb), 1, "el nuevo sigue vivo: no se confirma");
        assert!(bb.agent_done(&r, true));
        assert_eq!(bb.read("k", ""), None);
    }
}

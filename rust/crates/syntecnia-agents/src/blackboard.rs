//! Blackboard — estado compartido para coordinación multi-agente.
//!
//! Port de `syntecnia/agents/blackboard.py`. Thread-safe (los agentes corren en
//! hilos reales), observable (cada read/write se loguea), versionado (guarda
//! historial). Almacena `SendValue` (owned, `Send`) — el `share`/`observe` hacen
//! la conversión `SynValue`↔`SendValue` (snapshot, modelo CSP).

use std::collections::HashMap;
use std::sync::{Condvar, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;
use syntecnia_core::types::SendValue;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
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
            }),
            cvar: Condvar::new(),
        }
    }

    pub fn write(&self, key: &str, value: SendValue, agent: &str) {
        let mut g = self.inner.lock().unwrap();
        let now = now_secs();
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
        g.data.shift_remove(key);
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
    use syntecnia_core::number::Number;

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
}

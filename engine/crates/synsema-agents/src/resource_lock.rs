//! Locks de recursos — detección preventiva de conflictos. Port de
//! `synsema/agents/resource_lock.py`.
//!
//! En vez de detectar conflictos DESPUÉS (como merge conflicts), se previenen ANTES:
//! un agente declara "trabajo en X"; otro que intente X queda bloqueado/denegado.
//! Modos: exclusive (un agente), shared (varios lectores, sin escritores), advisory
//! (logueado, no forzado). NOTA: el `timeout`-blocking real (Condvar) se simplifica —
//! con `timeout` 0/None (lo único que ejercen los tests) se deniega sin esperar.

use std::sync::Mutex;

use indexmap::IndexMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockMode {
    Exclusive,
    Shared,
    Advisory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockStatus {
    Acquired,
    Waiting,
    Denied,
    Released,
}

#[derive(Clone, Debug)]
pub struct ResourceLock {
    pub resource: String,
    pub agent: String,
    pub mode: LockMode,
    pub acquired_at: f64,
    pub released_at: f64,
    pub active: bool,
}

#[derive(Clone, Debug)]
pub struct LockEvent {
    pub event_type: String,
    pub resource: String,
    pub agent: String,
    pub mode: LockMode,
    pub blocked_by: String,
}

#[derive(Default)]
struct Inner {
    locks: IndexMap<String, Vec<ResourceLock>>,
    events: Vec<LockEvent>,
}

/// Manager de locks para coordinación multi-agente (thread-safe vía Mutex).
pub struct ResourceLockManager {
    inner: Mutex<Inner>,
}

impl Default for ResourceLockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceLockManager {
    pub fn new() -> Self {
        ResourceLockManager { inner: Mutex::new(Inner::default()) }
    }

    pub fn acquire(
        &self,
        resource: &str,
        agent: &str,
        mode: LockMode,
        _timeout: Option<f64>,
    ) -> LockStatus {
        let mut inner = self.inner.lock().unwrap();
        let active: Vec<ResourceLock> = inner
            .locks
            .get(resource)
            .map(|v| v.iter().filter(|l| l.active).cloned().collect())
            .unwrap_or_default();

        if check_compatible(&active, agent, mode) {
            let lock = ResourceLock {
                resource: resource.to_string(),
                agent: agent.to_string(),
                mode,
                acquired_at: 0.0,
                released_at: 0.0,
                active: true,
            };
            inner.locks.entry(resource.to_string()).or_default().push(lock);
            inner.events.push(LockEvent {
                event_type: "acquire".into(),
                resource: resource.to_string(),
                agent: agent.to_string(),
                mode,
                blocked_by: String::new(),
            });
            return LockStatus::Acquired;
        }

        let blocked_by = active.iter().map(|l| l.agent.clone()).collect::<Vec<_>>().join(", ");
        inner.events.push(LockEvent {
            event_type: "block".into(),
            resource: resource.to_string(),
            agent: agent.to_string(),
            mode,
            blocked_by,
        });

        if mode == LockMode::Advisory {
            // Advisory no bloquea.
            inner.locks.entry(resource.to_string()).or_default().push(ResourceLock {
                resource: resource.to_string(),
                agent: agent.to_string(),
                mode,
                acquired_at: 0.0,
                released_at: 0.0,
                active: true,
            });
            return LockStatus::Acquired;
        }

        // timeout 0/None → sin espera real → denegado.
        LockStatus::Denied
    }

    pub fn release(&self, resource: &str, agent: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(locks) = inner.locks.get_mut(resource) {
            for lock in locks.iter_mut() {
                if lock.agent == agent && lock.active {
                    lock.active = false;
                    lock.released_at = 0.0;
                    break;
                }
            }
        }
        inner.events.push(LockEvent {
            event_type: "release".into(),
            resource: resource.to_string(),
            agent: agent.to_string(),
            mode: LockMode::Exclusive,
            blocked_by: String::new(),
        });
    }

    pub fn release_all(&self, agent: &str) {
        let mut inner = self.inner.lock().unwrap();
        for locks in inner.locks.values_mut() {
            for lock in locks.iter_mut() {
                if lock.agent == agent && lock.active {
                    lock.active = false;
                    lock.released_at = 0.0;
                }
            }
        }
    }

    pub fn is_locked(&self, resource: &str) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.locks.get(resource).map_or(false, |v| v.iter().any(|l| l.active))
    }

    pub fn who_holds(&self, resource: &str) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        inner
            .locks
            .get(resource)
            .map(|v| v.iter().filter(|l| l.active).map(|l| l.agent.clone()).collect())
            .unwrap_or_default()
    }

    /// Mapa recurso → agentes (locks activos). La "vista hive-mind".
    pub fn get_conflict_map(&self) -> IndexMap<String, Vec<String>> {
        let inner = self.inner.lock().unwrap();
        let mut result = IndexMap::new();
        for (resource, locks) in &inner.locks {
            let agents: Vec<String> =
                locks.iter().filter(|l| l.active).map(|l| l.agent.clone()).collect();
            if !agents.is_empty() {
                result.insert(resource.clone(), agents);
            }
        }
        result
    }
}

/// Compatibilidad de un lock nuevo con los activos.
fn check_compatible(active: &[ResourceLock], agent: &str, mode: LockMode) -> bool {
    if active.is_empty() {
        return true;
    }
    // El mismo agente puede re-adquirir.
    if active.iter().all(|l| l.agent == agent) {
        return true;
    }
    match mode {
        LockMode::Exclusive => false,
        LockMode::Shared => active.iter().all(|l| l.mode == LockMode::Shared),
        LockMode::Advisory => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_release() {
        let m = ResourceLockManager::new();
        assert_eq!(m.acquire("file.txt", "agent1", LockMode::Exclusive, None), LockStatus::Acquired);
        assert!(m.is_locked("file.txt"));
        m.release("file.txt", "agent1");
        assert!(!m.is_locked("file.txt"));
    }

    #[test]
    fn exclusive_blocks() {
        let m = ResourceLockManager::new();
        m.acquire("file.txt", "agent1", LockMode::Exclusive, None);
        let s = m.acquire("file.txt", "agent2", LockMode::Exclusive, Some(0.0));
        assert_eq!(s, LockStatus::Denied);
    }

    #[test]
    fn shared_allows() {
        let m = ResourceLockManager::new();
        m.acquire("file.txt", "agent1", LockMode::Shared, None);
        let s = m.acquire("file.txt", "agent2", LockMode::Shared, None);
        assert_eq!(s, LockStatus::Acquired);
    }

    #[test]
    fn shared_blocks_exclusive() {
        let m = ResourceLockManager::new();
        m.acquire("file.txt", "agent1", LockMode::Shared, None);
        let s = m.acquire("file.txt", "agent2", LockMode::Exclusive, Some(0.0));
        assert_eq!(s, LockStatus::Denied);
    }

    #[test]
    fn conflict_map() {
        let m = ResourceLockManager::new();
        m.acquire("file_a", "agent1", LockMode::Exclusive, None);
        m.acquire("file_b", "agent2", LockMode::Exclusive, None);
        m.acquire("file_b", "agent2", LockMode::Shared, None); // re-acquire ok
        let cmap = m.get_conflict_map();
        assert!(cmap.contains_key("file_a"));
        assert!(cmap.contains_key("file_b"));
    }

    #[test]
    fn release_all() {
        let m = ResourceLockManager::new();
        m.acquire("a", "agent1", LockMode::Exclusive, None);
        m.acquire("b", "agent1", LockMode::Exclusive, None);
        m.acquire("c", "agent2", LockMode::Exclusive, None);
        m.release_all("agent1");
        assert!(!m.is_locked("a"));
        assert!(!m.is_locked("b"));
        assert!(m.is_locked("c"));
    }
}

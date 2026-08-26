//! Swarm de agentes. Port de `synsema/agents/swarm.py` (paridad, `std::thread`).
//!
//! Coordinación pura: estados de agentes, señales (cola **consumible**, no
//! latcheada), blackboard, dashboard, join de hilos. El motor (`synsema-runtime`)
//! es quien crea el `Interpreter` de cada agente y lanza su hilo; este módulo sólo
//! mantiene el estado compartido (`Arc<Swarm>`).

use std::collections::{HashMap, VecDeque};
use std::sync::{Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use synsema_core::interpreter::CancelToken;
use synsema_core::types::SendValue;

use crate::blackboard::Blackboard;
use crate::bus::Bus;

fn now_secs() -> f64 {
    synsema_core::clock::now_secs_f64()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentState {
    Idle,
    Starting,
    Working,
    Waiting,
    Done,
    Error,
    Stopped,
}

impl AgentState {
    pub fn name(&self) -> &'static str {
        match self {
            AgentState::Idle => "IDLE",
            AgentState::Starting => "STARTING",
            AgentState::Working => "WORKING",
            AgentState::Waiting => "WAITING",
            AgentState::Done => "DONE",
            AgentState::Error => "ERROR",
            AgentState::Stopped => "STOPPED",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AgentInfo {
    pub name: String,
    pub state: AgentState,
    pub error: Option<String>,
    pub started_at: f64,
    pub finished_at: f64,
    /// Token de cancelación cooperativa del agente (`agent_stop`): el intérprete del
    /// agente lo adopta al arrancar; `agent_stop(id)` lo cancela desde cualquier hilo.
    pub cancel: CancelToken,
}

#[derive(Clone, Debug)]
pub struct Signal {
    pub name: String,
    pub sender: String,
    pub data: Option<SendValue>,
    pub timestamp: f64,
}

struct SwarmState {
    agents: IndexMap<String, AgentInfo>,
    pending: HashMap<String, VecDeque<Signal>>,
    history: Vec<Signal>,
}

/// Estado compartido del swarm (tras `Arc<Swarm>`).
pub struct Swarm {
    pub blackboard: Blackboard,
    /// Bus de eventos pub/sub del proceso (fan-out; ver `bus.rs`).
    pub bus: std::sync::Arc<Bus>,
    state: Mutex<SwarmState>,
    cvar: Condvar,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl Default for Swarm {
    fn default() -> Self {
        Self::new()
    }
}

impl Swarm {
    pub fn new() -> Self {
        Self::with_bus(std::sync::Arc::new(Bus::new()))
    }

    /// Un swarm que COMPARTE el bus de otro (ticks de cron en modo `run`: su swarm es
    /// propio, pero los eventos deben ser los mismos que ve el programa principal).
    pub fn with_bus(bus: std::sync::Arc<Bus>) -> Self {
        Self {
            blackboard: Blackboard::new(),
            bus,
            state: Mutex::new(SwarmState {
                agents: IndexMap::new(),
                pending: HashMap::new(),
                history: Vec::new(),
            }),
            cvar: Condvar::new(),
            threads: Mutex::new(Vec::new()),
        }
    }

    /// Registra un nuevo agente y devuelve su instance_id = "{name}_{N}" (N = nº de
    /// agentes ya registrados), igual que el oráculo. Estado inicial STARTING.
    pub fn register_new_agent(&self, agent_name: &str) -> String {
        let mut g = self.state.lock().unwrap();
        let id = format!("{}_{}", agent_name, g.agents.len());
        g.agents.insert(
            id.clone(),
            AgentInfo {
                name: id.clone(),
                state: AgentState::Starting,
                error: None,
                started_at: now_secs(),
                finished_at: 0.0,
                cancel: CancelToken::new(),
            },
        );
        id
    }

    /// Token de cancelación de un agente registrado (para que su intérprete lo adopte).
    pub fn cancel_token(&self, id: &str) -> Option<CancelToken> {
        self.state.lock().unwrap().agents.get(id).map(|a| a.cancel.clone())
    }

    /// `agent_stop(id)`: cancela cooperativamente un agente vivo. `false` si no existe
    /// o ya terminó (nunca silencio: el caller lo reporta).
    pub fn stop_agent(&self, id: &str, reason: &str) -> bool {
        let token = {
            let g = self.state.lock().unwrap();
            match g.agents.get(id) {
                Some(a) if matches!(a.state, AgentState::Starting | AgentState::Working | AgentState::Waiting) => {
                    Some(a.cancel.clone())
                }
                _ => None,
            }
        };
        match token {
            Some(t) => {
                t.cancel(reason);
                // Despertar a quien esté bloqueado en wait_for_signal.
                self.cvar.notify_all();
                true
            }
            None => false,
        }
    }

    /// Cancela TODOS los agentes vivos (shutdown ordenado del proceso).
    pub fn stop_all_agents(&self, reason: &str) -> usize {
        let ids: Vec<String> = self.state.lock().unwrap().agents.keys().cloned().collect();
        ids.iter().filter(|id| self.stop_agent(id, reason)).count()
    }

    /// Snapshot de todos los agentes (para `agents()`).
    pub fn agents_info(&self) -> Vec<(String, AgentInfo)> {
        self.state.lock().unwrap().agents.iter().map(|(id, a)| (id.clone(), a.clone())).collect()
    }

    pub fn set_state(&self, id: &str, state: AgentState) {
        {
            let mut g = self.state.lock().unwrap();
            if let Some(a) = g.agents.get_mut(id) {
                a.state = state;
            }
        }
        self.cvar.notify_all();
    }

    pub fn set_error(&self, id: &str, msg: String) {
        {
            let mut g = self.state.lock().unwrap();
            if let Some(a) = g.agents.get_mut(id) {
                a.state = AgentState::Error;
                a.error = Some(msg);
            }
        }
        self.cvar.notify_all();
    }

    pub fn set_finished(&self, id: &str) {
        let mut g = self.state.lock().unwrap();
        if let Some(a) = g.agents.get_mut(id) {
            a.finished_at = now_secs();
        }
    }

    /// Encola una señal (no latcheada) y despierta a los que esperan.
    pub fn signal(&self, name: &str, sender: &str, data: Option<SendValue>) {
        {
            let mut g = self.state.lock().unwrap();
            g.pending.entry(name.to_string()).or_default().push_back(Signal {
                name: name.to_string(),
                sender: sender.to_string(),
                data,
                timestamp: now_secs(),
            });
        }
        self.cvar.notify_all();
    }

    /// Espera y CONSUME una señal. Devuelve None por timeout, o antes si NINGÚN
    /// agente sigue activo (STARTING/WORKING/WAITING) y por tanto nadie podrá emitir.
    ///
    /// Nota de paridad: contamos WAITING como "activo" igual que el oráculo. Excluirlo
    /// (optimización previa) causaba una carrera: si el receptor llega a wait_for ANTES
    /// de que el hilo principal haya hecho `spawn` del emisor, el único agente es él
    /// mismo (WAITING) → "no hay productor" → bail con None y la señal nunca se espera.
    /// El `timeout` acota los deadlocks reales (waiter sin emisor posible).
    pub fn wait_for_signal(&self, name: &str, timeout: Duration) -> Option<Signal> {
        self.wait_for_signal_cancellable(name, timeout, &|| false)
    }

    /// Como `wait_for_signal`, pero sale (con `None`) apenas `cancelled()` sea true
    /// (timeout de handler, shutdown, `agent_stop`). El chequeo corre en cada
    /// despertar de la condvar y como mucho cada 100 ms.
    pub fn wait_for_signal_cancellable(&self, name: &str, timeout: Duration, cancelled: &dyn Fn() -> bool) -> Option<Signal> {
        let deadline = Instant::now() + timeout;
        let mut g = self.state.lock().unwrap();
        loop {
            if let Some(q) = g.pending.get_mut(name) {
                if let Some(sig) = q.pop_front() {
                    g.history.push(sig.clone());
                    return Some(sig);
                }
            }
            let producer_alive = g.agents.values().any(|a| {
                matches!(
                    a.state,
                    AgentState::Starting | AgentState::Working | AgentState::Waiting
                )
            });
            if !producer_alive && !g.agents.is_empty() {
                return None;
            }
            if cancelled() {
                return None;
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let wait = (deadline - now).min(Duration::from_millis(100));
            let (ng, _res) = self.cvar.wait_timeout(g, wait).unwrap();
            g = ng;
            // Re-chequeo arriba del loop (señal, productor muerto, cancelación, deadline).
        }
    }

    pub fn add_thread(&self, handle: JoinHandle<()>) {
        self.threads.lock().unwrap().push(handle);
    }

    /// Espera (join) a que todos los hilos de agentes terminen.
    pub fn wait_all(&self) {
        let handles: Vec<JoinHandle<()>> = self.threads.lock().unwrap().drain(..).collect();
        for h in handles {
            let _ = h.join();
        }
    }

    pub fn total_agents(&self) -> usize {
        self.state.lock().unwrap().agents.len()
    }

    /// Estados de todos los agentes: (instance_id, state).
    pub fn agent_states(&self) -> Vec<(String, AgentState)> {
        self.state
            .lock()
            .unwrap()
            .agents
            .iter()
            .map(|(id, info)| (id.clone(), info.state))
            .collect()
    }

    pub fn agent_error(&self, id: &str) -> Option<String> {
        self.state.lock().unwrap().agents.get(id).and_then(|a| a.error.clone())
    }
}

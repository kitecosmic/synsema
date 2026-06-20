//! Swarm de agentes. Port de `syntecnia/agents/swarm.py` (paridad, `std::thread`).
//!
//! Coordinación pura: estados de agentes, señales (cola **consumible**, no
//! latcheada), blackboard, dashboard, join de hilos. El motor (`syntecnia-runtime`)
//! es quien crea el `Interpreter` de cada agente y lanza su hilo; este módulo sólo
//! mantiene el estado compartido (`Arc<Swarm>`).

use std::collections::{HashMap, VecDeque};
use std::sync::{Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;
use syntecnia_core::types::SendValue;

use crate::blackboard::Blackboard;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
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
        Self {
            blackboard: Blackboard::new(),
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
            },
        );
        id
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

    /// Espera y CONSUME una señal. Devuelve None por timeout o si ningún agente
    /// está STARTING/WORKING (nadie podrá emitir → evita deadlock/hang).
    ///
    /// Nota de paridad: el oráculo cuenta WAITING como "vivo" (puede colgar 30s con
    /// un emisor muerto); acá excluimos WAITING → más determinista (rompe deadlocks).
    /// El gate no llega a ese caso (los emisores siempre emiten).
    pub fn wait_for_signal(&self, name: &str, timeout: Duration) -> Option<Signal> {
        let deadline = Instant::now() + timeout;
        let mut g = self.state.lock().unwrap();
        loop {
            if let Some(q) = g.pending.get_mut(name) {
                if let Some(sig) = q.pop_front() {
                    g.history.push(sig.clone());
                    return Some(sig);
                }
            }
            let producer_alive = g
                .agents
                .values()
                .any(|a| matches!(a.state, AgentState::Starting | AgentState::Working));
            if !producer_alive && !g.agents.is_empty() {
                return None;
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (ng, res) = self.cvar.wait_timeout(g, deadline - now).unwrap();
            g = ng;
            if res.timed_out() {
                // Re-chequeo una vez más arriba del loop; si nada, saldrá por deadline.
            }
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

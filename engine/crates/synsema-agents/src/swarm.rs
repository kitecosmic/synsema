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
    /// v0.6.47 (T1, A1): `(texto, detalle)` si el agente terminó cortado por etiquetas. Quien lo
    /// observa (`agents()`) adopta el corte: su estado es un dato que eligió el privado.
    pub labels_cut: Option<(String, String)>,
    /// v0.6.47 (T1): la corrida que lo lanzó (su `RunCut`): un request, un tick del cron, el
    /// preámbulo o el `run` entero. `agents()` y `agent_stop` sólo ven los de la propia corrida.
    pub scope: Option<std::sync::Arc<synsema_core::interpreter::RunCut>>,
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
    pending: HashMap<String, VecDeque<(Signal, Option<std::sync::Arc<synsema_core::interpreter::RunCut>>)>>,
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
    /// v0.6.47 (T1, A1): el corte de la corrida que usa este swarm (`run`, `test`); el principal y
    /// los agentes que lanza lo comparten. Bajo `serve` cada request lleva el suyo.
    pub run_cut: std::sync::Arc<synsema_core::interpreter::RunCut>,
    /// v0.6.47 (T1, A1): con etiquetas, el eco de los agentes (`[id] línea`) se retiene hasta el fin
    /// de la corrida, como la salida del principal (`None` = en vivo).
    held_echo: Option<Mutex<Vec<String>>>,
    /// v0.6.47 (T1): lo mismo para el stderr del principal y de los agentes.
    held_err: Option<Mutex<Vec<String>>>,
    /// v0.6.47 (T1): bajo `serve` con etiquetas el eco y el stderr de los agentes no se escriben
    /// (viven más que el request: no hay un fin de corrida donde soltarlos sin delatar cuál cortó).
    drop_output: bool,
    /// v0.6.47 (T1): lleva el diario por corrida del blackboard (serve con etiquetas).
    journal_runs: bool,
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
            run_cut: std::sync::Arc::new(synsema_core::interpreter::RunCut::default()),
            held_echo: None,
            held_err: None,
            drop_output: false,
            journal_runs: false,
        }
    }

    /// v0.6.47 (T1, A1): un swarm que retiene el eco de sus agentes (`run`/`test` con etiquetas).
    pub fn holding_echo() -> Self {
        let mut s = Self::new();
        s.held_echo = Some(Mutex::new(Vec::new()));
        s.held_err = Some(Mutex::new(Vec::new()));
        s
    }

    /// v0.6.47 (T1): un swarm cuyos agentes no escriben eco ni stderr (`serve` con etiquetas).
    pub fn dropping_output(mut self) -> Self {
        self.drop_output = true;
        self
    }

    /// v0.6.47 (T1): con etiquetas bajo `serve`, cada corrida (una entrada de `with_serve_interp`, con
    /// sus agentes) se confirma o se deshace en el blackboard y la cola de señales. Bajo `run` no
    /// hace falta: la corrida es el programa entero, no se cierra hasta el final, y desde un corte
    /// todo sumidero de la corrida corta (nadie más lee el blackboard).
    pub fn journaling_runs(mut self) -> Self {
        self.journal_runs = true;
        self
    }

    pub fn journals_runs(&self) -> bool {
        self.journal_runs
    }

    /// ¿Descarta este swarm el eco y el stderr de sus agentes?
    pub fn drops_output(&self) -> bool {
        self.drop_output
    }

    /// ¿Retiene este swarm el eco y el stderr?
    pub fn holds_output(&self) -> bool {
        self.held_err.is_some()
    }

    /// Retiene una línea de stderr (no hace nada si el swarm no retiene).
    pub fn hold_err(&self, line: String) {
        if let Some(m) = &self.held_err {
            m.lock().unwrap().push(line);
        }
    }

    /// El stderr retenido (se vacía al leerlo).
    pub fn take_err(&self) -> Vec<String> {
        self.held_err.as_ref().map(|m| std::mem::take(&mut *m.lock().unwrap())).unwrap_or_default()
    }

    /// Retiene una línea de eco; `false` si el eco va en vivo.
    pub fn hold_echo(&self, line: String) -> bool {
        if self.drop_output {
            return true;
        }
        match &self.held_echo {
            Some(m) => {
                m.lock().unwrap().push(line);
                true
            }
            None => false,
        }
    }

    /// El eco retenido (se vacía al leerlo).
    pub fn take_echo(&self) -> Vec<String> {
        self.held_echo.as_ref().map(|m| std::mem::take(&mut *m.lock().unwrap())).unwrap_or_default()
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
                labels_cut: None,
                scope: None,
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

    /// v0.6.47 (T1): anota la corrida dueña del agente (ver `AgentInfo::scope`).
    pub fn set_agent_scope(&self, id: &str, scope: std::sync::Arc<synsema_core::interpreter::RunCut>) {
        if let Some(a) = self.state.lock().unwrap().agents.get_mut(id) {
            a.scope = Some(scope);
        }
    }

    /// v0.6.47 (T1): el dueño de la corrida `scope` (la entrada de `serve`) la cierra. Con corte, lo
    /// que dejó en el estado compartido del swarm y nadie tomó todavía se deshace: el blackboard (con
    /// su diario) y las señales que siguen en cola. Lo ya entregado (una señal que alguien consumió,
    /// un evento del bus) es el prefijo de efectos, como un `http_post` antes del corte.
    pub fn close_run(&self, scope: &std::sync::Arc<synsema_core::interpreter::RunCut>, cut: bool) {
        if self.blackboard.close_run(scope, cut) {
            self.drop_signals_of(scope);
        }
    }

    /// v0.6.47 (T1): se lanzó un agente de la corrida `scope` (ver `Blackboard::agent_started`).
    pub fn agent_started(&self, scope: &std::sync::Arc<synsema_core::interpreter::RunCut>) {
        self.blackboard.agent_started(scope);
    }

    /// v0.6.47 (T1): un agente de la corrida `scope` terminó (ver `Blackboard::agent_done`).
    pub fn agent_done(&self, scope: &std::sync::Arc<synsema_core::interpreter::RunCut>, cut: bool) {
        if self.blackboard.agent_done(scope, cut) {
            self.drop_signals_of(scope);
        }
    }

    fn drop_signals_of(&self, scope: &std::sync::Arc<synsema_core::interpreter::RunCut>) {
        let mut g = self.state.lock().unwrap();
        for q in g.pending.values_mut() {
            q.retain(|(_, s)| !s.as_ref().is_some_and(|s| std::sync::Arc::ptr_eq(s, scope)));
        }
    }

    /// ¿El agente es de la corrida `scope`? (`false` si no existe o si no tiene dueño anotado.)
    pub fn in_scope(&self, id: &str, scope: &std::sync::Arc<synsema_core::interpreter::RunCut>) -> bool {
        match self.state.lock().unwrap().agents.get(id) {
            // Falla cerrado: un agente sin corrida no es de nadie.
            Some(a) => a.scope.as_ref().is_some_and(|s| std::sync::Arc::ptr_eq(s, scope)),
            None => false,
        }
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

    /// v0.6.47 (T1, A1): el agente terminó cortado por etiquetas. Estado `Error` con el texto que ve
    /// el programa, y SIN la señal `__agent_error`: quien espera señales no distingue este fin del
    /// de un agente que terminó bien.
    pub fn set_labels_cut(&self, id: &str, message: String, detail: String) {
        {
            let mut g = self.state.lock().unwrap();
            if let Some(a) = g.agents.get_mut(id) {
                a.state = AgentState::Error;
                a.error = Some(message.clone());
                a.labels_cut = Some((message, detail));
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
            // v0.6.47 (T1): con la corrida del hilo, para sacarla de la cola si esa corrida se corta.
            let scope = crate::blackboard::thread_scope();
            g.pending.entry(name.to_string()).or_default().push_back((
                Signal { name: name.to_string(), sender: sender.to_string(), data, timestamp: now_secs() },
                scope,
            ));
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
                if let Some((sig, _)) = q.pop_front() {
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

    /// Espera (join) a que todos los hilos de agentes terminen, también los que un agente lanza
    /// mientras se espera. v0.6.50: vaciaba la lista una vez, y el hilo de un agente lanzado por
    /// otro después de eso no se esperaba (su salida y su corte se perdían si el de afuera
    /// terminaba antes). El que lanza agrega el hilo antes de terminar, así que al juntar al de
    /// afuera el de adentro ya está en la lista.
    pub fn wait_all(&self) {
        while self.join_round() > 0 {}
    }

    /// Una ronda de `wait_all`: junta los hilos que hay ahora y dice cuántos eran.
    pub fn join_round(&self) -> usize {
        let handles: Vec<JoinHandle<()>> = self.threads.lock().unwrap().drain(..).collect();
        let n = handles.len();
        for h in handles {
            let _ = h.join();
        }
        n
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

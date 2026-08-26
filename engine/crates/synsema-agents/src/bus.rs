//! Bus de eventos in-process (pub/sub con FAN-OUT). Complementa a las señales del
//! swarm (`signal`/`wait_for`: cola CONSUMIBLE, un receptor) con el patrón que una UI
//! en vivo necesita: N suscriptores (un handler SSE/socket por cliente) reciben el
//! MISMO evento que publicó un agente, un cron o cualquier request.
//!
//! - Vive en el `Swarm` (`Arc`, uno por proceso): lo ven handlers de todos los
//!   workers, ticks de cron, agentes `spawn`eados y el top-level. No cruza procesos
//!   (eso es Redis pub/sub, roadmap DB-M5, con la misma API).
//! - **Memoria acotada por suscriptor** en DOS dimensiones (cantidad y bytes).
//!   Política default `DropOldest`: un suscriptor lento NO frena al publicador (a
//!   diferencia del backpressure TCP de ws — acá el publicador es local y no debe
//!   bloquearse por un cliente lento); `Error` opt-in entrega un error atrapable.
//! - Sin hilo de fondo: `publish` copia el evento a cada cola y despierta a los
//!   suscriptores por su `wake` (un `mio::Waker` del hub de I/O del intérprete, o
//!   una condvar). Cero acoplamiento con mio: el waker es un `Fn()` opaco.
//! - Los topics de suscripción admiten glob (`agent.*`), mismo `fnmatch` que los
//!   scopes de capabilities.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use synsema_core::types::SendValue;

/// Política al llenarse la cola del suscriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnFull {
    /// Descarta el más viejo (default): el publicador nunca se frena.
    DropOldest,
    /// La suscripción falla: el próximo `recv` entrega un error atrapable y retira
    /// la suscripción.
    Error,
}

/// Un evento entregado a un suscriptor.
#[derive(Clone, Debug)]
pub struct Event {
    pub topic: String,
    pub data: SendValue,
    pub timestamp: f64,
}

pub type WakeFn = Arc<dyn Fn() + Send + Sync>;

struct SubQueue {
    events: VecDeque<Event>,
    queued_bytes: usize,
    /// Error terminal (overflow con política `Error`), entregado una vez.
    error: Option<String>,
    dropped: u64,
    received: u64,
}

/// Suscriptor: cola acotada + waker. `Arc` compartido entre el bus (que publica) y
/// el hub de I/O del intérprete (que consume).
pub struct Subscriber {
    pub id: u64,
    pub patterns: Vec<String>,
    max_queue: usize,
    max_queue_bytes: usize,
    on_full: OnFull,
    queue: Mutex<SubQueue>,
    wake: Mutex<Option<WakeFn>>,
    cvar: Condvar,
}

impl Subscriber {
    /// Instala/reemplaza el waker (el hub lo pone al adoptar la suscripción).
    pub fn set_wake(&self, wake: Option<WakeFn>) {
        if let Ok(mut g) = self.wake.lock() {
            *g = wake;
        }
    }

    /// ¿Hay algo para entregar (evento o error)?
    pub fn is_ready(&self) -> bool {
        self.queue.lock().map(|q| !q.events.is_empty() || q.error.is_some()).unwrap_or(false)
    }

    /// Saca el próximo evento. `Err(msg)` si la suscripción falló (overflow con
    /// política Error) y la cola está vacía — el error es terminal.
    pub fn try_recv(&self) -> Result<Option<Event>, String> {
        let mut q = self.queue.lock().map_err(|_| "bus: subscriber poisoned".to_string())?;
        if let Some(ev) = q.events.pop_front() {
            q.queued_bytes = q.queued_bytes.saturating_sub(send_size(&ev.data));
            return Ok(Some(ev));
        }
        if let Some(e) = q.error.take() {
            return Err(e);
        }
        Ok(None)
    }

    /// Espera bloqueante (sin hub de I/O): condvar hasta `timeout`. Devuelve al
    /// primer evento, error, o deadline. `cancelled` se consulta cada 100 ms.
    pub fn recv_timeout(&self, timeout: Duration, cancelled: &dyn Fn() -> bool) -> Result<Option<Event>, String> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.try_recv() {
                Ok(None) => {}
                other => return other,
            }
            if cancelled() {
                return Ok(None);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let wait = (deadline - now).min(Duration::from_millis(100));
            let g = match self.queue.lock() {
                Ok(g) => g,
                Err(_) => return Err("bus: subscriber poisoned".to_string()),
            };
            if !g.events.is_empty() || g.error.is_some() {
                continue;
            }
            let _ = self.cvar.wait_timeout(g, wait);
        }
    }

    pub fn stats(&self) -> (usize, usize, u64, u64) {
        self.queue
            .lock()
            .map(|q| (q.events.len(), q.queued_bytes, q.received, q.dropped))
            .unwrap_or((0, 0, 0, 0))
    }

    fn push(&self, ev: Event) {
        let size = send_size(&ev.data);
        {
            let Ok(mut q) = self.queue.lock() else { return };
            if q.error.is_some() {
                return; // ya falló; no acumular
            }
            q.received += 1;
            let full = q.events.len() >= self.max_queue || q.queued_bytes + size > self.max_queue_bytes;
            if full {
                match self.on_full {
                    OnFull::DropOldest => {
                        while !q.events.is_empty()
                            && (q.events.len() >= self.max_queue || q.queued_bytes + size > self.max_queue_bytes)
                        {
                            if let Some(old) = q.events.pop_front() {
                                q.queued_bytes = q.queued_bytes.saturating_sub(send_size(&old.data));
                                q.dropped += 1;
                            }
                        }
                    }
                    OnFull::Error => {
                        q.error = Some(format!(
                            "the subscriber queue overflowed ({} events / {} bytes queued; the program reads slower than the bus publishes) — drain with bus_recv/select more often, raise max_queue/max_queue_bytes, or use on_full \"drop_oldest\"",
                            q.events.len(),
                            q.queued_bytes
                        ));
                        q.events.clear();
                        q.queued_bytes = 0;
                        self.cvar.notify_all();
                        drop(q);
                        self.wake_now();
                        return;
                    }
                }
            }
            q.events.push_back(ev);
            q.queued_bytes += size;
        }
        self.cvar.notify_all();
        self.wake_now();
    }

    fn wake_now(&self) {
        let w = self.wake.lock().ok().and_then(|g| g.clone());
        if let Some(w) = w {
            w();
        }
    }
}

/// Tamaño aproximado del payload (para la cota en bytes).
pub fn send_size(v: &SendValue) -> usize {
    match v {
        SendValue::Number(_) => 16,
        SendValue::Text(s) => s.len(),
        SendValue::Bool(_) | SendValue::Nothing => 1,
        SendValue::List(l) => l.iter().map(send_size).sum::<usize>() + 8,
        SendValue::Map(m) => m.iter().map(|(k, v)| k.len() + send_size(v)).sum::<usize>() + 8,
        SendValue::Bytes(b) => b.len(),
        SendValue::Complex(_, _) => 16,
        SendValue::Array(_, d) => d.len() * 8 + 8,
    }
}

pub struct SubscribeOpts {
    pub max_queue: usize,
    pub max_queue_bytes: usize,
    pub on_full: OnFull,
}

impl Default for SubscribeOpts {
    fn default() -> Self {
        SubscribeOpts { max_queue: DEFAULT_MAX_QUEUE, max_queue_bytes: DEFAULT_MAX_QUEUE_BYTES, on_full: OnFull::DropOldest }
    }
}

pub const DEFAULT_MAX_QUEUE: usize = 1024;
pub const DEFAULT_MAX_QUEUE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_QUEUE_CEILING: usize = 1_000_000;
pub const MAX_QUEUE_BYTES_CEILING: usize = 1024 * 1024 * 1024;

/// Tope de suscriptores vivos por proceso (anti-fuga: cada suscriptor retiene su cola).
pub const DEFAULT_MAX_SUBSCRIBERS: usize = 65536;

struct BusState {
    subs: HashMap<u64, Arc<Subscriber>>,
    next_id: u64,
    published: u64,
}

/// El bus del proceso.
pub struct Bus {
    state: Mutex<BusState>,
    max_subscribers: usize,
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}

impl Bus {
    pub fn new() -> Self {
        Bus {
            state: Mutex::new(BusState { subs: HashMap::new(), next_id: 1, published: 0 }),
            max_subscribers: DEFAULT_MAX_SUBSCRIBERS,
        }
    }

    /// Crea una suscripción a uno o más topics (literal o glob). El `Arc` devuelto
    /// es la única referencia fuerte además de la del bus; `unsubscribe` la retira.
    pub fn subscribe(&self, patterns: Vec<String>, opts: SubscribeOpts) -> Result<Arc<Subscriber>, String> {
        let mut st = self.state.lock().map_err(|_| "bus: poisoned".to_string())?;
        if st.subs.len() >= self.max_subscribers {
            return Err(format!(
                "bus_subscribe: too many live subscriptions ({}); unsubscribe the ones you no longer read",
                st.subs.len()
            ));
        }
        let id = st.next_id;
        st.next_id += 1;
        let sub = Arc::new(Subscriber {
            id,
            patterns,
            max_queue: opts.max_queue.clamp(1, MAX_QUEUE_CEILING),
            max_queue_bytes: opts.max_queue_bytes.clamp(1, MAX_QUEUE_BYTES_CEILING),
            on_full: opts.on_full,
            queue: Mutex::new(SubQueue { events: VecDeque::new(), queued_bytes: 0, error: None, dropped: 0, received: 0 }),
            wake: Mutex::new(None),
            cvar: Condvar::new(),
        });
        st.subs.insert(id, sub.clone());
        Ok(sub)
    }

    pub fn unsubscribe(&self, id: u64) -> bool {
        self.state.lock().map(|mut st| st.subs.remove(&id).is_some()).unwrap_or(false)
    }

    /// Publica: copia el evento a cada suscriptor cuyo patrón matchea. Devuelve
    /// cuántos lo recibieron. O(#subs) — el bus es in-process, no un broker.
    pub fn publish(&self, topic: &str, data: SendValue) -> usize {
        let targets: Vec<Arc<Subscriber>> = {
            let Ok(mut st) = self.state.lock() else { return 0 };
            st.published += 1;
            st.subs.values().filter(|s| s.patterns.iter().any(|p| topic_matches(p, topic))).cloned().collect()
        };
        let ts = synsema_core::clock::now_secs_f64();
        let n = targets.len();
        let mut data = Some(data);
        for (i, s) in targets.into_iter().enumerate() {
            // La última copia se MUEVE; las demás clonan (un evento grande a un solo
            // suscriptor no se duplica).
            let payload = if i + 1 == n { data.take().unwrap_or(SendValue::Nothing) } else { data.clone().unwrap_or(SendValue::Nothing) };
            s.push(Event { topic: topic.to_string(), data: payload, timestamp: ts });
        }
        n
    }

    /// Topics observables: patrón → cantidad de suscriptores (para `bus_topics`).
    pub fn topics(&self) -> Vec<(String, usize)> {
        let Ok(st) = self.state.lock() else { return Vec::new() };
        let mut counts: HashMap<String, usize> = HashMap::new();
        for s in st.subs.values() {
            for p in &s.patterns {
                *counts.entry(p.clone()).or_insert(0) += 1;
            }
        }
        let mut v: Vec<(String, usize)> = counts.into_iter().collect();
        v.sort();
        v
    }

    pub fn subscriber_count(&self) -> usize {
        self.state.lock().map(|st| st.subs.len()).unwrap_or(0)
    }

    pub fn published_count(&self) -> u64 {
        self.state.lock().map(|st| st.published).unwrap_or(0)
    }
}

/// Match de topic: literal, o glob con `*` (cualquier secuencia) y `?` (un char) —
/// el mismo `fnmatch` de los scopes de capabilities.
pub fn topic_matches(pattern: &str, topic: &str) -> bool {
    if pattern == topic {
        return true;
    }
    if !pattern.contains('*') && !pattern.contains('?') {
        return false;
    }
    synsema_capabilities::model::fnmatch(topic, pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fan_out_reaches_every_matching_subscriber() {
        let bus = Bus::new();
        let a = bus.subscribe(vec!["agent.*".into()], SubscribeOpts::default()).unwrap();
        let b = bus.subscribe(vec!["agent.done".into()], SubscribeOpts::default()).unwrap();
        let c = bus.subscribe(vec!["other".into()], SubscribeOpts::default()).unwrap();
        assert_eq!(bus.publish("agent.done", SendValue::Text("x".into())), 2);
        assert!(a.is_ready());
        assert!(b.is_ready());
        assert!(!c.is_ready());
        assert_eq!(a.try_recv().unwrap().unwrap().topic, "agent.done");
        assert!(a.try_recv().unwrap().is_none());
    }

    #[test]
    fn drop_oldest_bounds_the_queue_by_count_and_bytes() {
        let bus = Bus::new();
        let s = bus
            .subscribe(vec!["t".into()], SubscribeOpts { max_queue: 2, max_queue_bytes: 1_000_000, on_full: OnFull::DropOldest })
            .unwrap();
        for i in 0..5 {
            bus.publish("t", SendValue::Number(synsema_core::number::Number::Int(i)));
        }
        let (len, _, received, dropped) = s.stats();
        assert_eq!(len, 2);
        assert_eq!(received, 5);
        assert_eq!(dropped, 3);
        let s2 = bus
            .subscribe(vec!["u".into()], SubscribeOpts { max_queue: 100, max_queue_bytes: 10, on_full: OnFull::DropOldest })
            .unwrap();
        bus.publish("u", SendValue::Text("123456".into()));
        bus.publish("u", SendValue::Text("abcdef".into()));
        let (len, bytes, _, dropped) = s2.stats();
        assert_eq!(len, 1);
        assert!(bytes <= 10);
        assert_eq!(dropped, 1);
    }

    #[test]
    fn error_policy_is_terminal_and_loud() {
        let bus = Bus::new();
        let s = bus.subscribe(vec!["t".into()], SubscribeOpts { max_queue: 1, max_queue_bytes: 1_000, on_full: OnFull::Error }).unwrap();
        bus.publish("t", SendValue::Nothing);
        bus.publish("t", SendValue::Nothing);
        let e = s.try_recv().unwrap_err();
        assert!(e.contains("overflowed"));
    }

    #[test]
    fn unsubscribe_stops_delivery_and_frees_the_slot() {
        let bus = Bus::new();
        let s = bus.subscribe(vec!["t".into()], SubscribeOpts::default()).unwrap();
        assert!(bus.unsubscribe(s.id));
        assert_eq!(bus.publish("t", SendValue::Nothing), 0);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[test]
    fn recv_timeout_wakes_on_publish() {
        let bus = Arc::new(Bus::new());
        let s = bus.subscribe(vec!["t".into()], SubscribeOpts::default()).unwrap();
        let b2 = bus.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            b2.publish("t", SendValue::Bool(true));
        });
        let t0 = Instant::now();
        let ev = s.recv_timeout(Duration::from_secs(5), &|| false).unwrap().unwrap();
        assert_eq!(ev.topic, "t");
        assert!(t0.elapsed() < Duration::from_secs(2));
    }
}

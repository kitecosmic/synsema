//! Cron nativo. Port de `syntecnia/stdlib/cron.py`.
//!
//! Cada job corre en su propio hilo (como `threading.Timer` del oráculo): duerme
//! el intervalo y ejecuta; si es repetitivo, reprograma. La cancelación setea un
//! flag y despierta el hilo (`unpark`) para que salga limpio.
//!
//! Capa 6: la registración (cron_every/list/status/cancel) es lo que se testea. La
//! ejecución de tasks Syntecnia desde un hilo de cron es un tema de concurrencia
//! (diferido, como agents); el builtin del motor registra un task no-op por ahora.

use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use indexmap::IndexMap;

use syntecnia_core::interpreter::{Control, Interpreter};
use syntecnia_core::number::py_float_str;
use syntecnia_core::types::{syn_bool, syn_float, syn_int, syn_list, syn_map, syn_text, SynValue};

/// Tarea de un job (thread-safe, corre en el hilo del timer).
pub type Task = Box<dyn Fn() + Send + 'static>;

/// Vista de un job para list_jobs/format_status.
#[derive(Clone, Debug)]
pub struct JobInfo {
    pub name: String,
    pub interval: f64,
    pub repeating: bool,
    pub active: bool,
    pub run_count: u64,
    pub errors: u64,
}

struct JobHandle {
    interval: f64,
    repeating: bool,
    cancelled: Arc<AtomicBool>,
    run_count: Arc<AtomicU64>,
    thread: thread::Thread,
}

/// Scheduler de tareas en background. No bloquea.
pub struct CronScheduler {
    jobs: Mutex<IndexMap<String, JobHandle>>,
}

impl Default for CronScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl CronScheduler {
    pub fn new() -> Self {
        Self {
            jobs: Mutex::new(IndexMap::new()),
        }
    }

    pub fn every(&self, interval_seconds: f64, name: &str, task: Task) {
        self.schedule(interval_seconds, name, task, true);
    }

    pub fn after(&self, delay_seconds: f64, name: &str, task: Task) {
        self.schedule(delay_seconds, name, task, false);
    }

    fn schedule(&self, interval: f64, name: &str, task: Task, repeating: bool) {
        // Cancela un job existente con el mismo nombre.
        self.cancel(name);

        let cancelled = Arc::new(AtomicBool::new(false));
        let run_count = Arc::new(AtomicU64::new(0));
        let dur = Duration::from_secs_f64(interval.max(0.0));
        let c = cancelled.clone();
        let rc = run_count.clone();

        let jh = thread::spawn(move || loop {
            // Espera `dur`, despertable por unpark (cancelación), robusto a wakeups espurios.
            let deadline = Instant::now() + dur;
            loop {
                if c.load(Ordering::SeqCst) {
                    return;
                }
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                thread::park_timeout(deadline - now);
            }
            if c.load(Ordering::SeqCst) {
                return;
            }
            rc.fetch_add(1, Ordering::SeqCst);
            task();
            if !repeating {
                return;
            }
        });

        let thread = jh.thread().clone(); // jh se dropea → hilo desacoplado (detached)
        self.jobs.lock().unwrap().insert(
            name.to_string(),
            JobHandle {
                interval,
                repeating,
                cancelled,
                run_count,
                thread,
            },
        );
    }

    pub fn cancel(&self, name: &str) -> bool {
        if let Some(job) = self.jobs.lock().unwrap().shift_remove(name) {
            job.cancelled.store(true, Ordering::SeqCst);
            job.thread.unpark();
            true
        } else {
            false
        }
    }

    pub fn cancel_all(&self) {
        let mut jobs = self.jobs.lock().unwrap();
        for (_, job) in jobs.drain(..) {
            job.cancelled.store(true, Ordering::SeqCst);
            job.thread.unpark();
        }
    }

    pub fn list_jobs(&self) -> Vec<JobInfo> {
        self.jobs
            .lock()
            .unwrap()
            .iter()
            .map(|(name, j)| JobInfo {
                name: name.clone(),
                interval: j.interval,
                repeating: j.repeating,
                active: true,
                run_count: j.run_count.load(Ordering::SeqCst),
                errors: 0,
            })
            .collect()
    }

    pub fn format_status(&self) -> String {
        let jobs = self.list_jobs();
        if jobs.is_empty() {
            return "No scheduled tasks.".to_string();
        }
        let mut lines = vec![format!("Scheduled Tasks ({}):", jobs.len())];
        for j in &jobs {
            let repeat = if j.repeating {
                format!("every {}s", py_float_str(j.interval))
            } else {
                "once".to_string()
            };
            let status = if j.active { "active" } else { "cancelled" };
            lines.push(format!(
                "  [{}] {}: {}, runs: {}, errors: {}",
                status, j.name, repeat, j.run_count, j.errors
            ));
        }
        lines.join("\n")
    }
}

impl Drop for CronScheduler {
    fn drop(&mut self) {
        self.cancel_all();
    }
}

// -- Builtins --

fn raw_str(v: &SynValue) -> String {
    match v {
        SynValue::Text(s) => s.to_string(),
        SynValue::Number(n) => n.to_string(),
        SynValue::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        SynValue::Nothing => "None".to_string(),
        other => other.to_string(),
    }
}

fn arg_f64(v: &SynValue) -> f64 {
    match v {
        SynValue::Number(n) => n.to_f64(),
        SynValue::Text(s) => s.trim().parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// Nombre del task (de un SynTaskValue/Builtin) o str del valor.
fn task_name(v: &SynValue) -> String {
    match v {
        SynValue::Task(t) => t.name.clone(),
        SynValue::Builtin(b) => b.name.clone(),
        other => raw_str(other),
    }
}

fn err(msg: &str) -> Control {
    Control::Error(syntecnia_core::interpreter::RuntimeError::new(msg))
}

/// Registra los builtins de cron, compartiendo el scheduler.
pub fn register_cron_builtins(interp: &Interpreter, scheduler: Rc<CronScheduler>) {
    // cron_every(seconds, task) — registra (la ejecución del task es diferida).
    {
        let sched = scheduler.clone();
        interp.register_builtin(
            "cron_every",
            2,
            Rc::new(move |_i, args, _loc| {
                let interval = arg_f64(args.first().ok_or_else(|| err("missing argument"))?);
                let name = task_name(args.get(1).ok_or_else(|| err("missing argument"))?);
                sched.every(interval, &name, Box::new(|| {}));
                Ok(syn_text(name))
            }),
        );
    }

    // cron_after(seconds, task)
    {
        let sched = scheduler.clone();
        interp.register_builtin(
            "cron_after",
            2,
            Rc::new(move |_i, args, _loc| {
                let delay = arg_f64(args.first().ok_or_else(|| err("missing argument"))?);
                let name = task_name(args.get(1).ok_or_else(|| err("missing argument"))?);
                sched.after(delay, &name, Box::new(|| {}));
                Ok(syn_text(name))
            }),
        );
    }

    // cron_cancel(name) → bool
    {
        let sched = scheduler.clone();
        interp.register_builtin(
            "cron_cancel",
            1,
            Rc::new(move |_i, args, _loc| {
                let name = raw_str(args.first().ok_or_else(|| err("missing argument"))?);
                Ok(syn_bool(sched.cancel(&name)))
            }),
        );
    }

    // cron_list() → lista de maps {name, interval, repeating, active, run_count}
    {
        let sched = scheduler.clone();
        interp.register_builtin(
            "cron_list",
            0,
            Rc::new(move |_i, _args, _loc| {
                let result: Vec<SynValue> = sched
                    .list_jobs()
                    .into_iter()
                    .map(|j| {
                        let mut m = IndexMap::new();
                        m.insert("name".to_string(), syn_text(j.name.as_str()));
                        m.insert("interval".to_string(), syn_float(j.interval));
                        m.insert("repeating".to_string(), syn_bool(j.repeating));
                        m.insert("active".to_string(), syn_bool(j.active));
                        m.insert("run_count".to_string(), syn_int(j.run_count as i64));
                        syn_map(m)
                    })
                    .collect();
                Ok(syn_list(result))
            }),
        );
    }

    // cron_status() → texto
    {
        let sched = scheduler.clone();
        interp.register_builtin(
            "cron_status",
            0,
            Rc::new(move |_i, _args, _loc| Ok(syn_text(sched.format_status()))),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn cron_scheduler_basic() {
        let sched = CronScheduler::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        sched.every(0.1, "counter", Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }));
        thread::sleep(Duration::from_millis(350));
        sched.cancel("counter");
        assert!(counter.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn cron_after_runs_once() {
        let sched = CronScheduler::new();
        let result = Arc::new(Mutex::new(None::<String>));
        let r = result.clone();
        sched.after(0.1, "delayed", Box::new(move || {
            *r.lock().unwrap() = Some("done".to_string());
        }));
        thread::sleep(Duration::from_millis(300));
        assert_eq!(*result.lock().unwrap(), Some("done".to_string()));
        *result.lock().unwrap() = None;
        thread::sleep(Duration::from_millis(200));
        assert_eq!(*result.lock().unwrap(), None); // no repite
    }

    #[test]
    fn cron_cancel_stops() {
        let sched = CronScheduler::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        sched.every(0.1, "test", Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }));
        thread::sleep(Duration::from_millis(150));
        sched.cancel("test");
        let at_cancel = counter.load(Ordering::SeqCst);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(counter.load(Ordering::SeqCst), at_cancel);
    }

    #[test]
    fn cron_list_jobs() {
        let sched = CronScheduler::new();
        sched.every(60.0, "job1", Box::new(|| {}));
        sched.every(120.0, "job2", Box::new(|| {}));
        let jobs = sched.list_jobs();
        assert_eq!(jobs.len(), 2);
        let names: Vec<&str> = jobs.iter().map(|j| j.name.as_str()).collect();
        assert!(names.contains(&"job1"));
        assert!(names.contains(&"job2"));
        sched.cancel_all();
    }
}

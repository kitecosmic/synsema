//! Cron nativo. Port de `synsema/stdlib/cron.py`.
//!
//! Cada job corre en su propio hilo (como `threading.Timer` del oráculo): espera el
//! intervalo PARKED (cero CPU — `park_timeout`, jamás un busy-loop), ejecuta el task
//! REAL que le inyectó el runtime, y si es repetitivo reprograma. La cancelación
//! setea un flag y despierta el hilo (`unpark`) para que salga limpio.
//!
//! Semántica (documentada):
//! - **Intervalos**: delay fijo entre FIN y próximo inicio. **Expresiones cron** (de
//!   pared, `cronexpr`): próximo minuto que matchea DESPUÉS de terminar la corrida
//!   anterior (las ocurrencias que cayeron durante una corrida larga se saltean).
//!   En ambos casos un job jamás se solapa consigo mismo (hilo único por job).
//! - **Verdad observacional:** `run_count` sólo avanza cuando el task ejecutó
//!   COMPLETO; un tick que termina en error incrementa `errors` (ya logueado por el
//!   ejecutor). `run_count + errors` == ticks disparados.
//! - **Mismo nombre = reemplaza** el job anterior (se cancela primero).
//! - El scheduler puede nacer **diferido** (`deferred()`): registra jobs pero no
//!   arranca sus hilos hasta `start()` — bajo serve, los jobs del top-level recién
//!   arrancan cuando el bind del server está listo.
//! - Estado in-memory: un reinicio re-registra desde cero (sin catch-up).

use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use indexmap::IndexMap;

use chrono::FixedOffset;

use synsema_core::clock::now_secs_f64;
use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::number::py_float_str;
use synsema_core::types::{syn_bool, syn_float, syn_int, syn_list, syn_map, syn_text, SynValue};

use crate::cronexpr::{self, CronExpr};

/// Tarea de un job (thread-safe, corre en el hilo del timer). Devuelve `Ok(())` si
/// el task ejecutó completo y `Err(())` si terminó en error (el ejecutor ya lo
/// logueó — acá sólo se cuenta, G3).
pub type Task = Box<dyn Fn() -> Result<(), ()> + Send + 'static>;

/// Fabrica el ejecutor real de un job: recibe el intérprete que registra, el valor
/// del task y el nombre del builtin (para mensajes), valida en la REGISTRACIÓN
/// (existe como task top-level, 0 parámetros obligatorios) y devuelve
/// `(nombre, ejecutor)`. La inyecta el runtime (serve/run) — este módulo no sabe
/// construir intérpretes.
pub type ExecutorFactory =
    Rc<dyn Fn(&Interpreter, &SynValue, &str) -> Result<(String, Task), String>>;

/// Cuándo dispara un job.
#[derive(Clone, Debug)]
pub enum Schedule {
    /// Cada N segundos entre fin y próximo inicio.
    Every(f64),
    /// Una sola vez tras N segundos.
    After(f64),
    /// Expresión cron de pared en un offset fijo.
    At { expr: CronExpr, off: FixedOffset },
}

impl Schedule {
    /// Texto para `cron_list()["schedule"]` / `cron_status()`.
    pub fn label(&self) -> String {
        match self {
            Schedule::Every(s) => format!("every {}s", py_float_str(*s)),
            Schedule::After(s) => format!("after {}s", py_float_str(*s)),
            Schedule::At { expr, .. } => expr.source().to_string(),
        }
    }
    pub fn repeating(&self) -> bool {
        !matches!(self, Schedule::After(_))
    }
    pub fn interval(&self) -> Option<f64> {
        match self {
            Schedule::Every(s) | Schedule::After(s) => Some(*s),
            Schedule::At { .. } => None,
        }
    }
    pub fn tz(&self) -> Option<String> {
        match self {
            Schedule::At { off, .. } => Some(cronexpr::offset_label(*off)),
            _ => None,
        }
    }
    /// Próximo disparo desde ahora (unix secs) — lo que el hilo del job va a esperar.
    fn first_fire(&self) -> Option<f64> {
        match self {
            Schedule::Every(s) | Schedule::After(s) => Some(now_secs_f64() + s.max(0.0)),
            Schedule::At { expr, off } => expr.next_after(now_secs_f64().floor() as i64, *off).map(|t| t as f64),
        }
    }
}

/// Vista de un job para list_jobs/format_status.
#[derive(Clone, Debug)]
pub struct JobInfo {
    pub name: String,
    pub schedule: String,
    /// `Some` en jobs de intervalo/after; `None` en expresiones cron.
    pub interval: Option<f64>,
    pub repeating: bool,
    pub active: bool,
    pub run_count: u64,
    pub errors: u64,
    /// Próximo disparo (unix secs); `None` si ya no hay (after ejecutado, pendiente de start).
    pub next_run: Option<f64>,
    pub tz: Option<String>,
}

/// Próximo disparo publicado por el hilo del job (unix secs, reloj de pared).
type NextAt = Arc<Mutex<Option<f64>>>;

struct JobHandle {
    schedule: Schedule,
    next_at: NextAt,
    cancelled: Arc<AtomicBool>,
    run_count: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    /// `Some` = hilo vivo (unpark para cancelar); `None` = pendiente de `start()`.
    thread: Option<thread::Thread>,
    /// Task a la espera de `start()` (scheduler diferido). Se consume al arrancar.
    pending: Option<Task>,
}

/// Scheduler de tareas en background. No bloquea. UNO por proceso bajo serve
/// (estado compartido, como `SharedDb`); por-intérprete bajo run/test.
pub struct CronScheduler {
    jobs: Mutex<IndexMap<String, JobHandle>>,
    /// `false` = diferido: los jobs quedan pendientes hasta `start()`. Se lee y
    /// escribe bajo el lock de `jobs` (el atomic evita `&mut self` en `start`).
    started: AtomicBool,
}

impl Default for CronScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl CronScheduler {
    /// Scheduler que arranca cada job al registrarlo (modo run/test).
    pub fn new() -> Self {
        Self { jobs: Mutex::new(IndexMap::new()), started: AtomicBool::new(true) }
    }

    /// Scheduler diferido: registra jobs sin arrancar hilos hasta `start()`.
    /// Bajo serve, `start()` se llama recién con el bind listo — ningún tick
    /// ejecuta contra un server a medio levantar.
    pub fn deferred() -> Self {
        Self { jobs: Mutex::new(IndexMap::new()), started: AtomicBool::new(false) }
    }

    pub fn every(&self, interval_seconds: f64, name: &str, task: Task) {
        self.schedule(Schedule::Every(interval_seconds), name, task);
    }

    pub fn after(&self, delay_seconds: f64, name: &str, task: Task) {
        self.schedule(Schedule::After(delay_seconds), name, task);
    }

    /// Expresión cron de pared (`"0 9 * * *"`) en un offset fijo.
    pub fn at(&self, expr: CronExpr, off: FixedOffset, name: &str, task: Task) {
        self.schedule(Schedule::At { expr, off }, name, task);
    }

    /// Espera `dur` parked (cero CPU), despertable por unpark (cancelación), robusta a
    /// wakeups espurios. `true` si se canceló.
    fn wait_parked(dur: Duration, cancelled: &AtomicBool) -> bool {
        let deadline = Instant::now() + dur;
        loop {
            if cancelled.load(Ordering::SeqCst) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            thread::park_timeout(deadline - now);
        }
    }

    /// Hilo de un job: espera parked → ejecuta → cuenta → reprograma (si repite).
    /// El conteo va DESPUÉS de la ejecución (verdad observacional): completo →
    /// `run_count`; error → `errors`. El lock de jobs NO se sostiene nunca durante
    /// la ejecución (un task puede registrar otro cron sin deadlock).
    fn spawn_job_thread(
        schedule: Schedule,
        cancelled: Arc<AtomicBool>,
        run_count: Arc<AtomicU64>,
        errors: Arc<AtomicU64>,
        next_at: NextAt,
        task: Task,
    ) -> thread::Thread {
        let set_next = move |v: Option<f64>| {
            if let Ok(mut g) = next_at.lock() {
                *g = v;
            }
        };
        let jh = thread::spawn(move || loop {
            match &schedule {
                Schedule::Every(secs) | Schedule::After(secs) => {
                    let dur = Duration::from_secs_f64(secs.max(0.0));
                    set_next(Some(now_secs_f64() + dur.as_secs_f64()));
                    if Self::wait_parked(dur, &cancelled) {
                        return;
                    }
                }
                Schedule::At { expr, off } => {
                    // Próximo minuto de pared que matchea, DESPUÉS de ahora. Se espera
                    // en tramos de ≤ 60 s recomputando contra el reloj de pared: un
                    // salto del reloj (NTP) no deja al job dormido de más ni de menos.
                    let target = match expr.next_after(now_secs_f64().floor() as i64, *off) {
                        Some(t) => t as f64,
                        None => {
                            set_next(None);
                            return; // validado al registrar; defensivo
                        }
                    };
                    set_next(Some(target));
                    loop {
                        let remaining = target - now_secs_f64();
                        if remaining <= 0.0 {
                            break;
                        }
                        let slice = Duration::from_secs_f64(remaining.min(60.0));
                        if Self::wait_parked(slice, &cancelled) {
                            return;
                        }
                    }
                }
            }
            if cancelled.load(Ordering::SeqCst) {
                return;
            }
            set_next(None);
            match task() {
                Ok(()) => {
                    run_count.fetch_add(1, Ordering::SeqCst);
                }
                Err(()) => {
                    errors.fetch_add(1, Ordering::SeqCst);
                }
            }
            if !schedule.repeating() {
                return;
            }
        });
        jh.thread().clone() // jh se dropea → hilo desacoplado (detached)
    }

    fn schedule(&self, schedule: Schedule, name: &str, task: Task) {
        // Cancela un job existente con el mismo nombre (mismo nombre = reemplaza).
        self.cancel(name);

        let cancelled = Arc::new(AtomicBool::new(false));
        let run_count = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        let next_at: NextAt = Arc::new(Mutex::new(None));

        // La decisión spawn-ahora vs pendiente se toma BAJO el lock de jobs (misma
        // sección crítica que `start()`): un job no puede ni perderse ni arrancar
        // dos veces por una carrera registración/arranque.
        let mut jobs = self.jobs.lock().unwrap();
        let (thread, pending) = if self.started.load(Ordering::SeqCst) {
            // `next_run` visible YA en cron_list() (el hilo lo refina al arrancar).
            *next_at.lock().unwrap() = schedule.first_fire();
            let t = Self::spawn_job_thread(
                schedule.clone(),
                cancelled.clone(),
                run_count.clone(),
                errors.clone(),
                next_at.clone(),
                task,
            );
            (Some(t), None)
        } else {
            (None, Some(task))
        };
        jobs.insert(
            name.to_string(),
            JobHandle { schedule, next_at, cancelled, run_count, errors, thread, pending },
        );
    }

    /// Arranca los jobs pendientes (scheduler diferido). Idempotente; los jobs
    /// registrados después arrancan solos. Se llama con el runtime YA listo (bajo
    /// serve: post-bind, con el entorno de ejecución publicado).
    pub fn start(&self) {
        let mut jobs = self.jobs.lock().unwrap();
        self.started.store(true, Ordering::SeqCst);
        for (_, job) in jobs.iter_mut() {
            if let Some(task) = job.pending.take() {
                *job.next_at.lock().unwrap() = job.schedule.first_fire();
                job.thread = Some(Self::spawn_job_thread(
                    job.schedule.clone(),
                    job.cancelled.clone(),
                    job.run_count.clone(),
                    job.errors.clone(),
                    job.next_at.clone(),
                    task,
                ));
            }
        }
    }

    /// Cantidad de jobs registrados (para el camino "serve sólo con jobs").
    pub fn job_count(&self) -> usize {
        self.jobs.lock().unwrap().len()
    }

    pub fn cancel(&self, name: &str) -> bool {
        if let Some(job) = self.jobs.lock().unwrap().shift_remove(name) {
            job.cancelled.store(true, Ordering::SeqCst);
            if let Some(t) = &job.thread {
                t.unpark();
            }
            true
        } else {
            false
        }
    }

    pub fn cancel_all(&self) {
        let mut jobs = self.jobs.lock().unwrap();
        for (_, job) in jobs.drain(..) {
            job.cancelled.store(true, Ordering::SeqCst);
            if let Some(t) = &job.thread {
                t.unpark();
            }
        }
    }

    pub fn list_jobs(&self) -> Vec<JobInfo> {
        self.jobs
            .lock()
            .unwrap()
            .iter()
            .map(|(name, j)| JobInfo {
                name: name.clone(),
                schedule: j.schedule.label(),
                interval: j.schedule.interval(),
                repeating: j.schedule.repeating(),
                active: true,
                run_count: j.run_count.load(Ordering::SeqCst),
                errors: j.errors.load(Ordering::SeqCst),
                next_run: j.next_at.lock().ok().and_then(|g| *g),
                tz: j.schedule.tz(),
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
            let when = match (&j.tz, j.repeating) {
                (Some(tz), _) => format!("at '{}' ({})", j.schedule, tz),
                (None, true) => j.schedule.clone(),
                (None, false) => "once".to_string(),
            };
            let next = match j.next_run {
                Some(t) => format!(", next {}", iso_utc(t)),
                None => String::new(),
            };
            let status = if j.active { "active" } else { "cancelled" };
            lines.push(format!(
                "  [{}] {}: {}{}, runs: {}, errors: {}",
                status, j.name, when, next, j.run_count, j.errors
            ));
        }
        lines.join("\n")
    }
}

/// ISO-8601 UTC de un timestamp (para `cron_status()`; misma forma que `format_time`).
fn iso_utc(ts: f64) -> String {
    match chrono::DateTime::from_timestamp(ts.floor() as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        None => py_float_str(ts),
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

fn err(msg: &str) -> Control {
    Control::Error(synsema_core::interpreter::RuntimeError::new(msg))
}

/// Referencia al scheduler para los builtins. `Strong` en los intérpretes
/// PRINCIPALES (dueños del ciclo de vida: al dropear el intérprete de un `run`, el
/// scheduler se dropea y `cancel_all` apaga los hilos). `Weak` en los intérpretes
/// de worker/tick: un tick que retiene fuerte a su propio scheduler sería un ciclo
/// Arc (scheduler → job → task → scheduler) que dejaría hilos zombies para siempre.
#[derive(Clone)]
pub enum SchedRef {
    Strong(Arc<CronScheduler>),
    Weak(std::sync::Weak<CronScheduler>),
}

impl SchedRef {
    fn get(&self) -> Option<Arc<CronScheduler>> {
        match self {
            SchedRef::Strong(s) => Some(s.clone()),
            SchedRef::Weak(w) => w.upgrade(),
        }
    }
}

fn sched_of(r: &SchedRef, builtin: &str) -> Result<Arc<CronScheduler>, Control> {
    r.get().ok_or_else(|| {
        err(&format!("{}: the cron scheduler for this program is shutting down", builtin))
    })
}

/// Registra los builtins de cron. El `scheduler` es estado del PROCESO bajo serve
/// (compartido entre workers — un `cron_every` desde una ruta es visible en todas)
/// y por-intérprete bajo run/test. El `executor` fabrica el ejecutor REAL del task
/// (lo inyecta el runtime): valida en la registración y ejecuta en cada tick.
pub fn register_cron_builtins(
    interp: &Interpreter,
    scheduler: SchedRef,
    executor: ExecutorFactory,
) {
    // cron_every(seconds, task) — job repetitivo: delay fijo entre fin y próximo inicio.
    // cron_every(expr, task, opts?) — expresión cron de pared ("0 9 * * *", "@daily");
    // opts: {"tz": "UTC" | "+HH:MM" | "-HH:MM"} (offset fijo; default UTC).
    {
        let sched = scheduler.clone();
        let exec = executor.clone();
        interp.register_builtin(
            "cron_every",
            -1,
            Rc::new(move |i, args, _loc| {
                if args.len() < 2 || args.len() > 3 {
                    return Err(err(&format!(
                        "cron_every: expected (seconds, task) or (expression, task, options?), got {} argument(s)",
                        args.len()
                    )));
                }
                let first = &args[0];
                let task_v = &args[1];
                // Un número (o texto numérico, compat) sigue siendo un intervalo.
                let numeric = match first {
                    SynValue::Number(n) => Some(n.to_f64()),
                    SynValue::Text(s) => s.trim().parse::<f64>().ok(),
                    _ => None,
                };
                if let Some(interval) = numeric {
                    if args.len() == 3 {
                        return Err(err(
                            "cron_every: options are only accepted with a cron expression (cron_every(\"0 9 * * *\", task, {\"tz\": \"-03:00\"}))",
                        ));
                    }
                    if !interval.is_finite() || interval <= 0.0 {
                        // Un intervalo 0/negativo sería un loop de ejecución continua que
                        // se come un core — error claro, jamás un spinner silencioso.
                        return Err(err(&format!(
                            "cron_every: the interval must be a positive number of seconds, got {}",
                            py_float_str(interval)
                        )));
                    }
                    let (name, task) = exec(i, task_v, "cron_every").map_err(|m| err(&m))?;
                    sched_of(&sched, "cron_every")?.every(interval, &name, task);
                    return Ok(syn_text(name));
                }
                let expr_src = match first {
                    SynValue::Text(s) => s.to_string(),
                    other => {
                        return Err(err(&format!(
                            "cron_every: the first argument must be a number of seconds or a cron expression (text), got {}",
                            other.type_name()
                        )))
                    }
                };
                let expr = cronexpr::parse(&expr_src).map_err(|m| {
                    err(&format!("cron_every: bad cron expression \"{}\": {}", expr_src.trim(), m))
                })?;
                let mut off = FixedOffset::east_opt(0).unwrap();
                if let Some(opts) = args.get(2) {
                    match opts {
                        SynValue::Map(m) => {
                            for (k, v) in m.borrow().iter() {
                                match k.as_str() {
                                    "tz" => {
                                        off = cronexpr::parse_offset(&raw_str(v))
                                            .map_err(|m| err(&format!("cron_every: {}", m)))?;
                                    }
                                    other => {
                                        return Err(err(&format!(
                                            "cron_every: unknown option \"{}\" (only \"tz\")",
                                            other
                                        )))
                                    }
                                }
                            }
                        }
                        SynValue::Nothing => {}
                        other => {
                            return Err(err(&format!(
                                "cron_every: options must be a map, got {}",
                                other.type_name()
                            )))
                        }
                    }
                }
                if expr.next_after(now_secs_f64().floor() as i64, off).is_none() {
                    return Err(err(&format!(
                        "cron_every: the cron expression \"{}\" never matches within the next 5 years",
                        expr_src.trim()
                    )));
                }
                let (name, task) = exec(i, task_v, "cron_every").map_err(|m| err(&m))?;
                sched_of(&sched, "cron_every")?.at(expr, off, &name, task);
                Ok(syn_text(name))
            }),
        );
    }

    // cron_after(seconds, task) — una sola vez tras el delay (0 = ya mismo).
    {
        let sched = scheduler.clone();
        let exec = executor.clone();
        interp.register_builtin(
            "cron_after",
            2,
            Rc::new(move |i, args, _loc| {
                let delay = arg_f64(args.first().ok_or_else(|| err("missing argument"))?);
                if !delay.is_finite() || delay < 0.0 {
                    return Err(err(&format!(
                        "cron_after: the delay must be a non-negative number of seconds, got {}",
                        py_float_str(delay)
                    )));
                }
                let task_v = args.get(1).ok_or_else(|| err("missing argument"))?;
                let (name, task) =
                    exec(i, task_v, "cron_after").map_err(|m| err(&m))?;
                sched_of(&sched, "cron_after")?.after(delay, &name, task);
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
                Ok(syn_bool(sched_of(&sched, "cron_cancel")?.cancel(&name)))
            }),
        );
    }

    // cron_list() → lista de maps {name, interval, repeating, active, run_count, errors}
    {
        let sched = scheduler.clone();
        interp.register_builtin(
            "cron_list",
            0,
            Rc::new(move |_i, _args, _loc| {
                let result: Vec<SynValue> = sched_of(&sched, "cron_list")?
                    .list_jobs()
                    .into_iter()
                    .map(|j| {
                        let mut m = IndexMap::new();
                        m.insert("name".to_string(), syn_text(j.name.as_str()));
                        m.insert("schedule".to_string(), syn_text(j.schedule.as_str()));
                        m.insert(
                            "interval".to_string(),
                            j.interval.map(syn_float).unwrap_or(SynValue::Nothing),
                        );
                        m.insert("repeating".to_string(), syn_bool(j.repeating));
                        m.insert("active".to_string(), syn_bool(j.active));
                        m.insert("run_count".to_string(), syn_int(j.run_count as i64));
                        m.insert("errors".to_string(), syn_int(j.errors as i64));
                        m.insert(
                            "next_run".to_string(),
                            j.next_run.map(syn_float).unwrap_or(SynValue::Nothing),
                        );
                        m.insert(
                            "tz".to_string(),
                            j.tz.as_deref().map(syn_text).unwrap_or(SynValue::Nothing),
                        );
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
            Rc::new(move |_i, _args, _loc| {
                Ok(syn_text(sched_of(&sched, "cron_status")?.format_status()))
            }),
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
        sched.every(
            0.1,
            "counter",
            Box::new(move || {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        );
        thread::sleep(Duration::from_millis(350));
        sched.cancel("counter");
        assert!(counter.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn cron_after_runs_once() {
        let sched = CronScheduler::new();
        let result = Arc::new(Mutex::new(None::<String>));
        let r = result.clone();
        sched.after(
            0.1,
            "delayed",
            Box::new(move || {
                *r.lock().unwrap() = Some("done".to_string());
                Ok(())
            }),
        );
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
        sched.every(
            0.1,
            "test",
            Box::new(move || {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        );
        thread::sleep(Duration::from_millis(150));
        sched.cancel("test");
        let at_cancel = counter.load(Ordering::SeqCst);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(counter.load(Ordering::SeqCst), at_cancel);
    }

    #[test]
    fn cron_list_jobs() {
        let sched = CronScheduler::new();
        sched.every(60.0, "job1", Box::new(|| Ok(())));
        sched.every(120.0, "job2", Box::new(|| Ok(())));
        let jobs = sched.list_jobs();
        assert_eq!(jobs.len(), 2);
        let names: Vec<&str> = jobs.iter().map(|j| j.name.as_str()).collect();
        assert!(names.contains(&"job1"));
        assert!(names.contains(&"job2"));
        sched.cancel_all();
    }

    // MF-013: el conteo es VERDAD observacional — el closure inyectado SE EJECUTA,
    // run_count avanza sólo tras ejecutar completo, errors cuenta los ticks fallidos.
    #[test]
    fn run_count_counts_completions_and_errors_count_failures() {
        let sched = CronScheduler::new();
        let ticks = Arc::new(AtomicUsize::new(0));
        let t = ticks.clone();
        // Falla los primeros 2 ticks, después ejecuta OK.
        sched.every(
            0.05,
            "flaky",
            Box::new(move || {
                let n = t.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err(())
                } else {
                    Ok(())
                }
            }),
        );
        // Poll hasta un estado estable (entre ticks): 2 errores, ≥1 completo, y
        // run_count + errors == ticks disparados (G3: cero conteos fantasma).
        let mut ok = false;
        for _ in 0..100 {
            thread::sleep(Duration::from_millis(20));
            let jobs = sched.list_jobs();
            let j = jobs.iter().find(|j| j.name == "flaky").expect("job listado");
            let total = ticks.load(Ordering::SeqCst) as u64;
            if j.errors == 2 && j.run_count >= 1 && j.run_count + j.errors == total {
                ok = true;
                break;
            }
        }
        assert!(ok, "run_count/errors nunca alcanzaron el estado esperado: {:?}", sched.list_jobs());
        sched.cancel_all();
    }

    // El job de un scheduler diferido NO ejecuta hasta `start()`; después sí. Un
    // job cancelado ANTES de start jamás corre.
    #[test]
    fn deferred_scheduler_waits_for_start() {
        let sched = CronScheduler::deferred();
        let ran = Arc::new(AtomicUsize::new(0));
        let r = ran.clone();
        sched.after(
            0.05,
            "boot",
            Box::new(move || {
                r.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        );
        let never = Arc::new(AtomicUsize::new(0));
        let n = never.clone();
        sched.after(
            0.05,
            "cancelado",
            Box::new(move || {
                n.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        );
        thread::sleep(Duration::from_millis(200));
        assert_eq!(ran.load(Ordering::SeqCst), 0, "diferido: nada corre antes de start()");
        assert!(sched.cancel("cancelado"), "cancelar un pendiente funciona");
        sched.start();
        thread::sleep(Duration::from_millis(300));
        assert_eq!(ran.load(Ordering::SeqCst), 1, "tras start() el pendiente ejecuta");
        assert_eq!(never.load(Ordering::SeqCst), 0, "el cancelado pre-start jamás corre");
        // Un job registrado DESPUÉS de start arranca solo.
        let late = Arc::new(AtomicUsize::new(0));
        let l = late.clone();
        sched.after(
            0.05,
            "tarde",
            Box::new(move || {
                l.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        );
        thread::sleep(Duration::from_millis(250));
        assert_eq!(late.load(Ordering::SeqCst), 1);
        sched.cancel_all();
    }
}

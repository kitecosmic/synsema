//! Procesos VIVOS (`proc_*`) — la contraparte incremental de `run()`.
//!
//! `run(cmd, args)` es one-shot: captura todo y devuelve al final. Un agente que corre
//! `cargo test`, `npm run build` o un worker de largo aliento necesita **ver la salida
//! a medida que sale**, mandar stdin en vivo y matar el proceso: eso es un proceso como
//! handle con eventos (`{type: "stdout"|"stderr"|"exit", data}`).
//!
//! - **Sin PTY** (a propósito): son pipes. Un programa que detecta "no es una tty" se
//!   comporta como en CI. La terminal interactiva es un problema de sidecar, no de
//!   lenguaje; si aparece demanda entra como `pty: true` sin cambiar la API.
//! - **Un hilo lector por pipe** (stdout, stderr): es el único modo portable — los
//!   pipes no entran en `mio` en Windows — y `run()` ya lo hace. Cada lector encola en
//!   la cola del proceso y despierta al hub de I/O (`wake`); el hub (ws.rs) hace el
//!   `select` sobre el mismo `mio::Poll` que los sockets.
//! - **Memoria acotada** en dos dimensiones (cantidad y bytes). Política default
//!   `block`: el lector deja de leer el pipe → el hijo se frena en su `write` (la
//!   ventana del pipe hace backpressure real, sin pérdida). `drop_oldest`/`error`
//!   opt-in — espejo exacto de la cola inbound de ws.
//! - **Nunca huérfanos**: `proc_close` mata si sigue vivo; al dropear el hub (fin de
//!   request/programa) se matan todos. Un handler no deja procesos fantasma.
//! - **Gate**: `exec(cmd)` — idéntico a `run` (scope = el cmd pre-PATH); `sandbox` lo
//!   deniega. Sin shell jamás (args es lista).

use std::collections::VecDeque;
use std::io::Read;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Un evento del proceso (crudo; el hub lo convierte a `SynValue`).
#[derive(Debug, Clone)]
pub enum ProcEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    /// `(exit_code, signal)` — `exit_code = -1` cuando murió por señal (Unix).
    Exit(i64, Option<i32>),
}

impl ProcEvent {
    pub fn size(&self) -> usize {
        match self {
            ProcEvent::Stdout(b) | ProcEvent::Stderr(b) => b.len(),
            ProcEvent::Exit(..) => 0,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OnFull {
    /// Backpressure de pipe (default): el lector espera a que la cola drene.
    Block,
    DropOldest,
    /// La cola falla: el próximo recv entrega un error atrapable y el proceso se mata.
    Error,
}

pub const DEFAULT_MAX_QUEUE: usize = 4096;
pub const DEFAULT_MAX_QUEUE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_QUEUE_CEILING: usize = 1_000_000;
pub const MAX_QUEUE_BYTES_CEILING: usize = 1024 * 1024 * 1024;
/// Chunk de lectura en modo crudo (`line_mode: false`).
pub const RAW_CHUNK: usize = 64 * 1024;
/// Una línea más larga que esto se entrega partida (anti-OOM con un hijo hostil que
/// jamás emite `\n`).
pub const MAX_LINE: usize = 1024 * 1024;

pub type WakeFn = Arc<dyn Fn() + Send + Sync>;

struct Queue {
    events: VecDeque<ProcEvent>,
    queued_bytes: usize,
    error: Option<String>,
    dropped: u64,
}

/// Estado compartido entre el hub (consumidor) y los hilos lectores (productores).
pub struct ProcShared {
    queue: Mutex<Queue>,
    /// Los lectores esperan acá cuando la cola está llena (política Block).
    drained: Condvar,
    max_queue: usize,
    max_queue_bytes: usize,
    on_full: OnFull,
    /// Lectores que terminaron (EOF o error): 2 = ambos pipes cerrados.
    readers_done: AtomicUsize,
    /// Señal a los lectores de que el hub cerró (no bloquear más).
    closed: AtomicBool,
    wake: Mutex<Option<WakeFn>>,
}

impl ProcShared {
    fn push(&self, ev: ProcEvent) -> bool {
        let size = ev.size();
        let mut q = match self.queue.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        loop {
            if q.error.is_some() || self.closed.load(Ordering::Relaxed) {
                return false;
            }
            let full = q.events.len() >= self.max_queue || q.queued_bytes + size > self.max_queue_bytes;
            if !full || q.events.is_empty() {
                break;
            }
            match self.on_full {
                OnFull::Block => {
                    // Esperar a que el consumidor drene (con tope de espera para
                    // re-chequear `closed`).
                    let (g, _) = match self.drained.wait_timeout(q, Duration::from_millis(200)) {
                        Ok(x) => x,
                        Err(_) => return false,
                    };
                    q = g;
                }
                OnFull::DropOldest => {
                    while !q.events.is_empty()
                        && (q.events.len() >= self.max_queue || q.queued_bytes + size > self.max_queue_bytes)
                    {
                        if let Some(old) = q.events.pop_front() {
                            q.queued_bytes = q.queued_bytes.saturating_sub(old.size());
                            q.dropped += 1;
                        }
                    }
                    break;
                }
                OnFull::Error => {
                    q.error = Some(format!(
                        "the process output queue overflowed ({} events / {} bytes queued; the program reads slower than the child writes) — drain with proc_recv/select more often, raise max_queue/max_queue_bytes, or use on_full \"block\" (pipe backpressure) or \"drop_oldest\"",
                        q.events.len(),
                        q.queued_bytes
                    ));
                    q.events.clear();
                    q.queued_bytes = 0;
                    drop(q);
                    self.wake_now();
                    return false;
                }
            }
        }
        q.events.push_back(ev);
        q.queued_bytes += size;
        drop(q);
        self.wake_now();
        true
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

    /// Saca el próximo evento; `Err` si la cola falló (terminal).
    pub fn try_recv(&self) -> Result<Option<ProcEvent>, String> {
        let mut q = self.queue.lock().map_err(|_| "proc: queue poisoned".to_string())?;
        if let Some(ev) = q.events.pop_front() {
            q.queued_bytes = q.queued_bytes.saturating_sub(ev.size());
            drop(q);
            self.drained.notify_all();
            return Ok(Some(ev));
        }
        if let Some(e) = q.error.take() {
            return Err(e);
        }
        Ok(None)
    }

    pub fn readers_done(&self) -> bool {
        self.readers_done.load(Ordering::Acquire) >= 2
    }

    /// Da por terminados los lectores (un nieto retiene el pipe tras el exit del hijo:
    /// no se espera para siempre a un EOF que no va a llegar).
    pub fn force_readers_done(&self) {
        self.readers_done.store(2, Ordering::Release);
        self.close();
    }

    pub fn stats(&self) -> (usize, usize, u64) {
        self.queue.lock().map(|q| (q.events.len(), q.queued_bytes, q.dropped)).unwrap_or((0, 0, 0))
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.drained.notify_all();
    }
}

pub struct SpawnOpts {
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub max_queue: usize,
    pub max_queue_bytes: usize,
    pub on_full: OnFull,
    pub line_mode: bool,
    pub merge_stderr: bool,
}

impl Default for SpawnOpts {
    fn default() -> Self {
        SpawnOpts {
            cwd: None,
            env: Vec::new(),
            max_queue: DEFAULT_MAX_QUEUE,
            max_queue_bytes: DEFAULT_MAX_QUEUE_BYTES,
            on_full: OnFull::Block,
            line_mode: true,
            merge_stderr: false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcStatus {
    Running,
    Exited,
    Killed,
}

/// Un proceso vivo, propiedad del hub.
pub struct LiveProc {
    pub cmd: String,
    pub pid: u32,
    child: Child,
    stdin: Option<ChildStdin>,
    pub shared: Arc<ProcShared>,
    pub status: ProcStatus,
    /// Exit ya entregado como evento (para no repetirlo).
    pub exit_emitted: bool,
    pub exit_code: Option<i64>,
    pub exit_signal: Option<i32>,
    pub started_at: Instant,
    /// Momento en que se cosechó el exit (para el plazo de gracia de los lectores).
    pub exited_at: Option<Instant>,
    killed_by_us: bool,
}

impl LiveProc {
    /// Lanza el proceso con sus lectores. NO chequea capabilities (lo hace el builtin).
    pub fn spawn(cmd: &str, args: &[String], opts: SpawnOpts) -> Result<LiveProc, String> {
        let mut c = Command::new(cmd);
        c.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(dir) = &opts.cwd {
            c.current_dir(dir);
        }
        for (k, v) in &opts.env {
            c.env(k, v);
        }
        let mut child = c.spawn().map_err(|e| format!("cannot start \"{}\": {}", cmd, e))?;
        let shared = Arc::new(ProcShared {
            queue: Mutex::new(Queue { events: VecDeque::new(), queued_bytes: 0, error: None, dropped: 0 }),
            drained: Condvar::new(),
            max_queue: opts.max_queue.clamp(1, MAX_QUEUE_CEILING),
            max_queue_bytes: opts.max_queue_bytes.clamp(1, MAX_QUEUE_BYTES_CEILING),
            on_full: opts.on_full,
            readers_done: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            wake: Mutex::new(None),
        });
        let stdin = child.stdin.take();
        let out = child.stdout.take();
        let err = child.stderr.take();
        let line_mode = opts.line_mode;
        let merge = opts.merge_stderr;
        if let Some(out) = out {
            let sh = shared.clone();
            std::thread::Builder::new()
                .name("synsema-proc-out".into())
                .spawn(move || reader_loop(out, sh, line_mode, false))
                .map_err(|e| format!("cannot start the stdout reader: {}", e))?;
        } else {
            shared.readers_done.fetch_add(1, Ordering::AcqRel);
        }
        if let Some(err) = err {
            let sh = shared.clone();
            std::thread::Builder::new()
                .name("synsema-proc-err".into())
                .spawn(move || reader_loop(err, sh, line_mode, !merge))
                .map_err(|e| format!("cannot start the stderr reader: {}", e))?;
        } else {
            shared.readers_done.fetch_add(1, Ordering::AcqRel);
        }
        Ok(LiveProc {
            cmd: cmd.to_string(),
            pid: child.id(),
            child,
            stdin,
            shared,
            status: ProcStatus::Running,
            exit_emitted: false,
            exit_code: None,
            exit_signal: None,
            started_at: Instant::now(),
            exited_at: None,
            killed_by_us: false,
        })
    }

    /// Escribe a stdin (bloqueante: stdin de un hijo que no lee frena al escritor —
    /// es la semántica honesta de un pipe; `proc_send` lo documenta).
    pub fn send_stdin(&mut self, data: &[u8]) -> Result<(), String> {
        use std::io::Write;
        match self.stdin.as_mut() {
            Some(si) => si.write_all(data).and_then(|_| si.flush()).map_err(|e| format!("stdin write failed: {}", e)),
            None => Err("stdin is closed".to_string()),
        }
    }

    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// `try_wait` no bloqueante: si el hijo terminó, registra el exit. Devuelve true
    /// si terminó (ahora o antes).
    pub fn poll_exit(&mut self) -> bool {
        if self.exit_code.is_some() {
            return true;
        }
        match self.child.try_wait() {
            Ok(Some(st)) => {
                self.record_exit(st);
                true
            }
            Ok(None) => false,
            Err(_) => {
                self.exit_code = Some(-1);
                self.exited_at = Some(Instant::now());
                self.status = ProcStatus::Exited;
                true
            }
        }
    }

    fn record_exit(&mut self, st: std::process::ExitStatus) {
        let code = st.code().map(|c| c as i64).unwrap_or(-1);
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            self.exit_signal = st.signal();
        }
        self.exit_code = Some(code);
        self.exited_at = Some(Instant::now());
        self.status = if self.killed_by_us { ProcStatus::Killed } else { ProcStatus::Exited };
        self.stdin = None;
    }

    /// Mata al proceso. `graceful` = TERM en Unix (KILL si no); en Windows siempre
    /// TerminateProcess. Idempotente sobre un proceso ya terminado.
    pub fn kill(&mut self, graceful: bool) -> Result<(), String> {
        if self.poll_exit() {
            return Ok(());
        }
        self.killed_by_us = true;
        #[cfg(unix)]
        {
            if graceful {
                // SIGTERM: el hijo puede limpiar. (`libc::kill` sobre un pid que ya
                // cosechamos sería peligroso — por eso `poll_exit` va antes.)
                let r = unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGTERM) };
                if r == 0 {
                    return Ok(());
                }
            }
        }
        let _ = graceful;
        self.child.kill().map_err(|e| format!("kill failed: {}", e))
    }

    /// Espera bloqueante (acotada) a que termine. Devuelve true si terminó.
    pub fn wait_timeout(&mut self, timeout: Duration, cancelled: &dyn Fn() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.poll_exit() {
                return true;
            }
            if cancelled() || Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Cierre definitivo: mata si sigue vivo (TERM, luego KILL a los 2 s), cosecha, y
    /// libera los lectores. Nunca deja un zombie ni un huérfano.
    pub fn shutdown(&mut self) {
        self.shared.close();
        if !self.poll_exit() {
            let _ = self.kill(true);
            if !self.wait_timeout(Duration::from_secs(2), &|| false) {
                let _ = self.kill(false);
                let _ = self.child.wait();
                if self.exit_code.is_none() {
                    self.exit_code = Some(-1);
                    self.status = ProcStatus::Killed;
                }
            }
        }
        self.stdin = None;
    }
}

impl Drop for LiveProc {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn reader_loop<R: Read>(mut r: R, shared: Arc<ProcShared>, line_mode: bool, is_stderr: bool) {
    let mk = |b: Vec<u8>| if is_stderr { ProcEvent::Stderr(b) } else { ProcEvent::Stdout(b) };
    let mut buf = vec![0u8; RAW_CHUNK];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        if shared.closed.load(Ordering::Relaxed) {
            break;
        }
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if !line_mode {
            if !shared.push(mk(buf[..n].to_vec())) {
                break;
            }
            continue;
        }
        pending.extend_from_slice(&buf[..n]);
        let mut start = 0usize;
        let mut stop = false;
        while let Some(pos) = pending[start..].iter().position(|&b| b == b'\n') {
            let mut line = pending[start..start + pos].to_vec();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            start += pos + 1;
            if !shared.push(mk(line)) {
                stop = true;
                break;
            }
        }
        if stop {
            break;
        }
        pending.drain(..start);
        // Línea gigante sin `\n`: entregar partida (anti-OOM).
        if pending.len() >= MAX_LINE {
            let chunk = std::mem::take(&mut pending);
            if !shared.push(mk(chunk)) {
                break;
            }
        }
    }
    if line_mode && !pending.is_empty() && !shared.closed.load(Ordering::Relaxed) {
        let mut line = std::mem::take(&mut pending);
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let _ = shared.push(mk(line));
    }
    shared.readers_done.fetch_add(1, Ordering::AcqRel);
    shared.wake_now();
}

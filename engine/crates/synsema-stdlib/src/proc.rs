//! Procesos VIVOS (`proc_*`) — la contraparte incremental de `run()`.
//!
//! `run(cmd, args)` es one-shot: captura todo y devuelve al final. Un agente que corre
//! `cargo test`, `npm run build` o un worker de largo aliento necesita **ver la salida
//! a medida que sale**, mandar stdin en vivo y matar el proceso: eso es un proceso como
//! handle con eventos (`{type: "stdout"|"stderr"|"exit", data}`).
//!
//! - **Pipes por defecto**: un programa que detecta "no es una tty" se comporta como en
//!   CI. Con `pty: true` el hijo corre dentro de un pseudo-terminal (openpty en Unix,
//!   ConPTY en Windows, vía `portable-pty`): prompts y/n, contraseñas, menús con
//!   flechas, TUIs (`vim`, `htop`, un CLI agéntico) y programas que exigen tty. MISMA
//!   API y mismos eventos; diferencias honestas: un solo stream (`stdout`, la tty no
//!   separa stderr), bytes crudos con secuencias ANSI (`line_mode: false` implícito),
//!   eco activo (lo que mandás vuelve), y `proc_resize(h, cols, rows)`. El runtime NO
//!   interpreta VT: eso es del consumidor (xterm.js, `strip_ansi()`).
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
//! - **El árbol, no sólo el hijo**: por defecto (`process_group: true`) el hijo nace
//!   en su propio grupo de procesos (Unix) / Job Object con KILL_ON_JOB_CLOSE (Windows)
//!   y `kill`/`close` alcanzan a los nietos (`sh -c "npm run dev"` → muere también el
//!   `node`). En Windows el job se cierra con el handle: ni un crash del intérprete
//!   deja el árbol vivo. `process_group: false` desprende un daemon a propósito.
//! - **Gate**: `exec(cmd)` — idéntico a `run` (scope = el cmd pre-PATH); `sandbox` lo
//!   deniega. Sin shell jamás (args es lista).

use std::collections::VecDeque;
use std::io::Read;
use std::io::Write;
use std::process::{Child, ChildStdin, Command, Stdio};

use portable_pty::{CommandBuilder, MasterPty, PtySize};
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
    /// Pseudo-terminal en vez de pipes.
    pub pty: bool,
    pub cols: u16,
    pub rows: u16,
    /// `TERM` del hijo en modo pty (default `xterm-256color`; `env.TERM` gana).
    pub term: Option<String>,
    /// El hijo nace en su propio grupo de procesos (Unix) / Job Object (Windows), y
    /// `kill`/`close` matan el ÁRBOL entero (nietos incluidos). `false` = sólo el hijo
    /// directo (para desprender deliberadamente un daemon que deba sobrevivir).
    pub process_group: bool,
    /// Nombres de variables de entorno a QUITAR del hijo (los secretos de Synsema: claves
    /// de proveedor, `.env`). Se aplica antes de `env` (que puede volver a pasar una
    /// explícitamente). F3 de la auditoría de seguridad.
    pub strip_env: Vec<String>,
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
            pty: false,
            cols: 80,
            rows: 24,
            term: None,
            process_group: true,
            strip_env: Vec::new(),
        }
    }
}

/// Job Object de Windows: el hijo (y todo lo que engendre) queda dentro de un job con
/// `KILL_ON_JOB_CLOSE`. `terminate` mata el árbol de un golpe; soltar el handle (drop —
/// incluso si el intérprete muere sin pasar por `shutdown`) también lo mata. Es el
/// equivalente honesto del `kill(-pgid)` de Unix (Windows no tiene grupos de procesos
/// matables). Windows ≥ 8 permite jobs anidados, así que funciona aunque synsema mismo
/// corra dentro de otro job (cargo, un CI, un servicio).
#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};

    pub struct Job(HANDLE);

    // Un HANDLE de job es un recurso del kernel sin afinidad de hilo.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    impl Job {
        fn create() -> Option<Job> {
            let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if h == 0 {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = unsafe {
                SetInformationJobObject(
                    h,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if ok == 0 {
                unsafe { CloseHandle(h) };
                return None;
            }
            Some(Job(h))
        }

        /// Mete al proceso `ph` en un job nuevo. `None` si el SO lo rechaza (el caller
        /// degrada a matar sólo el hijo directo y lo reporta en `tree: false`).
        pub fn attach_handle(ph: HANDLE) -> Option<Job> {
            let job = Self::create()?;
            let ok = unsafe { AssignProcessToJobObject(job.0, ph) };
            if ok == 0 {
                return None;
            }
            Some(job)
        }

        pub fn attach_pid(pid: u32) -> Option<Job> {
            if pid == 0 {
                return None;
            }
            let ph = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
            if ph == 0 {
                return None;
            }
            let r = Self::attach_handle(ph);
            unsafe { CloseHandle(ph) };
            r
        }

        /// Mata TODO lo que hay en el job (exit code 1, el de `TerminateProcess`).
        pub fn terminate(&self) -> bool {
            unsafe { TerminateJobObject(self.0, 1) != 0 }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // KILL_ON_JOB_CLOSE: cerrar el último handle mata lo que quede.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Transporte del hijo: pipes (`std::process`) o pseudo-terminal (`portable-pty`).
enum Io {
    Pipe {
        child: Child,
        stdin: Option<ChildStdin>,
    },
    Pty {
        child: Box<dyn portable_pty::Child + Send + Sync>,
        /// `None` tras `shutdown`: soltar el master es lo que desbloquea al lector
        /// (EIO en Unix; en Windows el pipe de ConPTY no cierra hasta `ClosePseudoConsole`).
        master: Option<Box<dyn MasterPty + Send>>,
        /// Compartido con el lector: en Windows contesta el handshake de ConPTY.
        writer: PtyWriter,
    },
}

type PtyWriter = Arc<Mutex<Option<Box<dyn Write + Send>>>>;

/// Handshake de ConPTY (Windows): al arrancar, la pseudo-consola emite `ESC[6n`
/// (consulta de posición del cursor) y NO entrega ninguna salida del hijo hasta recibir
/// la respuesta `ESC[row;colR`. Un terminal real contesta solo; un programa que lee la
/// salida como datos no — y el hijo parecería mudo. El lector contesta ese primer
/// `ESC[6n` y lo quita del stream (un xterm.js del otro lado no lo ve, así no contesta
/// dos veces). Los `ESC[6n` posteriores son de la aplicación y pasan intactos.
const CONPTY_DSR: &[u8] = b"\x1b[6n";
const CONPTY_DSR_REPLY: &[u8] = b"\x1b[1;1R";

/// Tope de bytes iniciales dentro de los que se busca el DSR; pasado eso, no es un
/// ConPTY que haga handshake y todo sigue de largo.
const CONPTY_HANDSHAKE_WINDOW: usize = 512;

/// Devuelve `Some(salida)` cuando el handshake está resuelto (respondido y quitado, o
/// descartado por no aparecer en la ventana); `None` mientras haga falta leer más bytes.
/// El DSR no siempre es lo primero que emite ConPTY (a veces van antes los modos
/// `ESC[?9001h` / `ESC[?1004h`), por eso se busca dentro de la ventana y no al inicio.
fn conpty_handshake(buf: &[u8], writer: &PtyWriter) -> Option<Vec<u8>> {
    if let Some(pos) = buf.windows(CONPTY_DSR.len()).position(|w| w == CONPTY_DSR) {
        if let Ok(mut g) = writer.lock() {
            if let Some(w) = g.as_mut() {
                let _ = w.write_all(CONPTY_DSR_REPLY).and_then(|_| w.flush());
            }
        }
        let mut out = buf[..pos].to_vec();
        out.extend_from_slice(&buf[pos + CONPTY_DSR.len()..]);
        return Some(out);
    }
    if buf.len() >= CONPTY_HANDSHAKE_WINDOW {
        return Some(buf.to_vec());
    }
    None
}

/// Nombre de señal de `portable-pty` (strsignal) → número; `None` si no es una de las
/// conocidas (el `exit_code` -1 ya dice "murió por señal").
fn signal_number(name: &str) -> Option<i32> {
    let n = name.to_ascii_lowercase();
    if n.starts_with("hangup") {
        Some(1)
    } else if n.starts_with("interrupt") {
        Some(2)
    } else if n.starts_with("killed") {
        Some(9)
    } else if n.starts_with("terminated") {
        Some(15)
    } else if n.starts_with("segmentation") {
        Some(11)
    } else if n.starts_with("abort") {
        Some(6)
    } else {
        n.strip_prefix("signal ").and_then(|d| d.trim().parse().ok())
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
    io: Io,
    pub pty: bool,
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
    /// `kill`/`close` alcanzan al árbol entero (grupo de procesos en Unix, Job Object
    /// en Windows). `false` si se pidió `process_group: false` o el SO rechazó el job.
    pub tree: bool,
    #[cfg(windows)]
    job: Option<win::Job>,
}

impl LiveProc {
    /// Lanza el proceso con sus lectores. NO chequea capabilities (lo hace el builtin).
    pub fn spawn(cmd: &str, args: &[String], opts: SpawnOpts) -> Result<LiveProc, String> {
        if opts.pty {
            return Self::spawn_pty(cmd, args, opts);
        }
        let mut c = Command::new(cmd);
        c.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(dir) = &opts.cwd {
            c.current_dir(dir);
        }
        for k in &opts.strip_env {
            c.env_remove(k);
        }
        for k in &opts.strip_env {
            c.env_remove(k);
        }
        for (k, v) in &opts.env {
            c.env(k, v);
        }
        #[cfg(unix)]
        if opts.process_group {
            // Grupo propio (pgid = pid del hijo): `kill(-pid)` alcanza a los nietos.
            use std::os::unix::process::CommandExt;
            c.process_group(0);
        }
        let mut child = c.spawn().map_err(|e| format!("cannot start \"{}\": {}", cmd, e))?;
        #[cfg(windows)]
        let job = if opts.process_group {
            use std::os::windows::io::AsRawHandle;
            win::Job::attach_handle(child.as_raw_handle() as _)
        } else {
            None
        };
        #[cfg(windows)]
        let tree = job.is_some();
        #[cfg(not(windows))]
        let tree = opts.process_group;
        let shared = Self::new_shared(&opts);
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
            io: Io::Pipe { child, stdin },
            pty: false,
            shared,
            status: ProcStatus::Running,
            exit_emitted: false,
            exit_code: None,
            exit_signal: None,
            started_at: Instant::now(),
            exited_at: None,
            killed_by_us: false,
            tree,
            #[cfg(windows)]
            job,
        })
    }

    fn new_shared(opts: &SpawnOpts) -> Arc<ProcShared> {
        Arc::new(ProcShared {
            queue: Mutex::new(Queue { events: VecDeque::new(), queued_bytes: 0, error: None, dropped: 0 }),
            drained: Condvar::new(),
            max_queue: opts.max_queue.clamp(1, MAX_QUEUE_CEILING),
            max_queue_bytes: opts.max_queue_bytes.clamp(1, MAX_QUEUE_BYTES_CEILING),
            on_full: opts.on_full,
            readers_done: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            wake: Mutex::new(None),
        })
    }

    /// Lanza el proceso dentro de un pseudo-terminal. Un único lector (el master); el
    /// contador de lectores arranca en 1 porque no hay stderr aparte.
    fn spawn_pty(cmd: &str, args: &[String], opts: SpawnOpts) -> Result<LiveProc, String> {
        let size = PtySize { rows: opts.rows.max(1), cols: opts.cols.max(1), pixel_width: 0, pixel_height: 0 };
        let pair = portable_pty::native_pty_system()
            .openpty(size)
            .map_err(|e| format!("cannot open a pseudo-terminal: {}", e))?;
        let mut b = CommandBuilder::new(cmd);
        b.args(args);
        // portable-pty NO hereda el cwd del proceso (en Windows arranca en el del sistema):
        // sin `cwd` explícito, el hijo pty ve el mismo directorio que el modo pipe.
        match &opts.cwd {
            Some(dir) => b.cwd(dir),
            None => {
                if let Ok(here) = std::env::current_dir() {
                    b.cwd(here);
                }
            }
        }
        let mut has_term = false;
        for (k, v) in &opts.env {
            if k == "TERM" {
                has_term = true;
            }
            b.env(k, v);
        }
        if !has_term {
            b.env("TERM", opts.term.as_deref().unwrap_or("xterm-256color"));
        }
        let child = pair.slave.spawn_command(b).map_err(|e| format!("cannot start \"{}\" in a pty: {}", cmd, e))?;
        // Soltar el lado esclavo: el único dueño pasa a ser el hijo (así el EOF/EIO del
        // master llega cuando el hijo termina).
        drop(pair.slave);
        let master = pair.master;
        let reader = master.try_clone_reader().map_err(|e| format!("cannot read the pty: {}", e))?;
        let writer = master.take_writer().map_err(|e| format!("cannot write to the pty: {}", e))?;
        let writer: PtyWriter = Arc::new(Mutex::new(Some(writer)));
        let shared = Self::new_shared(&opts);
        shared.readers_done.fetch_add(1, Ordering::AcqRel);
        let sh = shared.clone();
        let line_mode = opts.line_mode;
        let handshake = if cfg!(windows) { Some(writer.clone()) } else { None };
        std::thread::Builder::new()
            .name("synsema-proc-pty".into())
            .spawn(move || reader_loop(PtyReader { inner: reader, handshake, held: Vec::new() }, sh, line_mode, false))
            .map_err(|e| format!("cannot start the pty reader: {}", e))?;
        let pid = child.process_id().unwrap_or(0);
        // Unix: el hijo del pty ya es líder de sesión (setsid) → el kill al grupo
        // siempre es de árbol. Windows: mismo Job Object que en modo pipe.
        #[cfg(windows)]
        let job = if opts.process_group { win::Job::attach_pid(pid) } else { None };
        #[cfg(windows)]
        let tree = job.is_some();
        #[cfg(not(windows))]
        let tree = true;
        Ok(LiveProc {
            cmd: cmd.to_string(),
            pid,
            io: Io::Pty { child, master: Some(master), writer },
            pty: true,
            shared,
            status: ProcStatus::Running,
            exit_emitted: false,
            exit_code: None,
            exit_signal: None,
            started_at: Instant::now(),
            exited_at: None,
            killed_by_us: false,
            tree,
            #[cfg(windows)]
            job,
        })
    }

    /// Cambia el tamaño del pseudo-terminal (SIGWINCH / ResizePseudoConsole).
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<(), String> {
        match &self.io {
            Io::Pty { master: Some(m), .. } => m
                .resize(PtySize { rows: rows.max(1), cols: cols.max(1), pixel_width: 0, pixel_height: 0 })
                .map_err(|e| format!("resize failed: {}", e)),
            Io::Pty { master: None, .. } => Err("the pty is closed".to_string()),
            Io::Pipe { .. } => Err("the process has no pty (spawn it with {pty: true})".to_string()),
        }
    }

    /// Escribe a stdin (bloqueante: stdin de un hijo que no lee frena al escritor —
    /// es la semántica honesta de un pipe; `proc_send` lo documenta).
    pub fn send_stdin(&mut self, data: &[u8]) -> Result<(), String> {
        let write = |w: &mut dyn Write| w.write_all(data).and_then(|_| w.flush()).map_err(|e| format!("stdin write failed: {}", e));
        match &mut self.io {
            Io::Pipe { stdin, .. } => match stdin.as_mut() {
                Some(si) => write(si),
                None => Err("stdin is closed".to_string()),
            },
            Io::Pty { writer, .. } => {
                let mut g = writer.lock().map_err(|_| "pty writer poisoned".to_string())?;
                match g.as_mut() {
                    Some(w) => write(w.as_mut()),
                    None => Err("stdin is closed".to_string()),
                }
            }
        }
    }

    /// EOF al hijo. Un pty no tiene un stdin aparte que cerrar: el EOF es una tecla
    /// (Ctrl-D en Unix, Ctrl-Z + Enter en Windows) y depende del modo de la tty, así
    /// que se le pide al programa que la mande explícitamente.
    pub fn close_stdin(&mut self) -> Result<(), String> {
        match &mut self.io {
            Io::Pipe { stdin, .. } => {
                *stdin = None;
                Ok(())
            }
            Io::Pty { .. } => Err(
                "a pty has no separate stdin to close; send the EOF key yourself: proc_send(h, bytes([4])) is Ctrl-D on Unix, bytes([26, 13]) is Ctrl-Z + Enter on Windows"
                    .to_string(),
            ),
        }
    }

    /// `try_wait` no bloqueante: si el hijo terminó, registra el exit. Devuelve true
    /// si terminó (ahora o antes).
    pub fn poll_exit(&mut self) -> bool {
        if self.exit_code.is_some() {
            return true;
        }
        let polled: Result<Option<(i64, Option<i32>)>, ()> = match &mut self.io {
            Io::Pipe { child, .. } => match child.try_wait() {
                Ok(Some(st)) => {
                    let code = st.code().map(|c| c as i64).unwrap_or(-1);
                    #[allow(unused_mut)]
                    let mut sig = None;
                    #[cfg(unix)]
                    {
                        use std::os::unix::process::ExitStatusExt;
                        sig = st.signal();
                    }
                    Ok(Some((code, sig)))
                }
                Ok(None) => Ok(None),
                Err(_) => Err(()),
            },
            Io::Pty { child, .. } => match child.try_wait() {
                Ok(Some(st)) => match st.signal() {
                    Some(name) => Ok(Some((-1, signal_number(name)))),
                    None => Ok(Some((st.exit_code() as i64, None))),
                },
                Ok(None) => Ok(None),
                Err(_) => Err(()),
            },
        };
        match polled {
            Ok(Some((code, sig))) => {
                self.record_exit(code, sig);
                true
            }
            Ok(None) => false,
            Err(()) => {
                self.exit_code = Some(-1);
                self.exited_at = Some(Instant::now());
                self.status = ProcStatus::Exited;
                true
            }
        }
    }

    fn record_exit(&mut self, code: i64, signal: Option<i32>) {
        self.exit_signal = signal;
        self.exit_code = Some(code);
        self.exited_at = Some(Instant::now());
        self.status = if self.killed_by_us { ProcStatus::Killed } else { ProcStatus::Exited };
        self.drop_writer();
    }

    fn drop_writer(&mut self) {
        match &mut self.io {
            Io::Pipe { stdin, .. } => *stdin = None,
            Io::Pty { writer, .. } => {
                if let Ok(mut g) = writer.lock() {
                    *g = None;
                }
            }
        }
    }

    /// Mata al proceso. `graceful` = TERM en Unix (KILL si no); en Windows siempre
    /// TerminateProcess. Con `tree` (default) la señal alcanza al árbol entero: el
    /// grupo de procesos en Unix (`kill(-pgid)`), el Job Object en Windows.
    /// Idempotente sobre un proceso ya terminado.
    pub fn kill(&mut self, graceful: bool) -> Result<(), String> {
        if self.poll_exit() {
            return Ok(());
        }
        self.killed_by_us = true;
        #[cfg(windows)]
        if let Some(job) = &self.job {
            if job.terminate() {
                return Ok(());
            }
        }
        #[cfg(unix)]
        {
            // (`libc::kill` sobre un pid que ya cosechamos sería peligroso — por eso
            // `poll_exit` va antes.)
            if self.tree && self.pid > 0 {
                // El hijo es líder de grupo (process_group(0) en pipe, setsid en pty):
                // matar el GRUPO entero (pgid = pid) para no dejar nietos huérfanos.
                let sig = if graceful { libc::SIGTERM } else { libc::SIGKILL };
                let r = unsafe { libc::kill(-(self.pid as libc::pid_t), sig) };
                if r == 0 {
                    return Ok(());
                }
            } else if graceful {
                // SIGTERM: el hijo puede limpiar.
                let r = unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGTERM) };
                if r == 0 {
                    return Ok(());
                }
            }
        }
        let _ = graceful;
        match &mut self.io {
            Io::Pipe { child, .. } => child.kill().map_err(|e| format!("kill failed: {}", e)),
            Io::Pty { child, .. } => child.kill().map_err(|e| format!("kill failed: {}", e)),
        }
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
                match &mut self.io {
                    Io::Pipe { child, .. } => {
                        let _ = child.wait();
                    }
                    Io::Pty { child, .. } => {
                        let _ = child.wait();
                    }
                }
                if self.exit_code.is_none() {
                    self.exit_code = Some(-1);
                    self.status = ProcStatus::Killed;
                }
            }
        }
        self.drop_writer();
        if let Io::Pty { master, .. } = &mut self.io {
            // Cerrar el master libera al hilo lector (ver `Io::Pty`).
            *master = None;
        }
    }
}

impl Drop for LiveProc {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Lector del master con el handshake de ConPTY por delante (no-op fuera de Windows).
struct PtyReader {
    inner: Box<dyn Read + Send>,
    handshake: Option<PtyWriter>,
    held: Vec<u8>,
}

impl Read for PtyReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if !self.held.is_empty() {
            let k = self.held.len().min(out.len());
            out[..k].copy_from_slice(&self.held[..k]);
            self.held.drain(..k);
            return Ok(k);
        }
        let Some(writer) = self.handshake.clone() else {
            return self.inner.read(out);
        };
        loop {
            let mut tmp = vec![0u8; out.len().max(64)];
            let n = self.inner.read(&mut tmp)?;
            if n == 0 {
                // EOF sin handshake: entregar lo retenido antes de cerrar.
                self.handshake = None;
                if self.held.is_empty() {
                    return Ok(0);
                }
                let k = self.held.len().min(out.len());
                out[..k].copy_from_slice(&self.held[..k]);
                self.held.drain(..k);
                return Ok(k);
            }
            self.held.extend_from_slice(&tmp[..n]);
            if let Some(rest) = conpty_handshake(&self.held, &writer) {
                self.handshake = None;
                self.held = rest;
                if self.held.is_empty() {
                    // Resuelto y sin resto: de acá en más lectura directa.
                    return self.inner.read(out);
                }
                let k = self.held.len().min(out.len());
                out[..k].copy_from_slice(&self.held[..k]);
                self.held.drain(..k);
                // Lo que no entró lo devuelve la próxima lectura (handshake ya None).
                return Ok(k);
            }
        }
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
            // Modo crudo: chunks tal cual, pero sin partir un carácter UTF-8 entre dos
            // chunks (una tty escupe secuencias multibyte a mitad de `read`).
            pending.extend_from_slice(&buf[..n]);
            let cut = utf8_cut(&pending);
            if cut > 0 {
                let chunk: Vec<u8> = pending.drain(..cut).collect();
                if !shared.push(mk(chunk)) {
                    break;
                }
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
    if !pending.is_empty() && !shared.closed.load(Ordering::Relaxed) {
        let mut line = std::mem::take(&mut pending);
        if line_mode && line.last() == Some(&b'\r') {
            line.pop();
        }
        let _ = shared.push(mk(line));
    }
    shared.readers_done.fetch_add(1, Ordering::AcqRel);
    shared.wake_now();
}

/// Longitud del prefijo de `b` que termina en un límite de carácter UTF-8 (retiene a lo
/// sumo los 3 bytes finales de una secuencia incompleta). Bytes inválidos no se retienen.
fn utf8_cut(b: &[u8]) -> usize {
    let n = b.len();
    let start = n.saturating_sub(3);
    let mut i = n;
    while i > start {
        let c = b[i - 1];
        if c & 0xC0 != 0x80 {
            // Byte inicial: ¿cuántos bytes debería tener la secuencia?
            let need = if c >= 0xF0 {
                4
            } else if c >= 0xE0 {
                3
            } else if c >= 0xC0 {
                2
            } else {
                1
            };
            return if n - (i - 1) < need { i - 1 } else { n };
        }
        i -= 1;
    }
    n
}

/// Un proceso hijo cualquiera (p. ej. el propio motor en `run_program`) que hay que
/// poder matar como ÁRBOL: Job Object en Windows, grupo de procesos en Unix. No lee
/// su salida: el caller maneja los pipes. Mismo mecanismo que `LiveProc`.
pub struct TreeChild {
    pub child: Child,
    #[cfg(windows)]
    job: Option<win::Job>,
    tree: bool,
}

/// Lanza `cmd` en su propio grupo/job. `stdin/stdout/stderr` los configura el caller.
pub fn spawn_tree(cmd: &mut Command) -> Result<TreeChild, String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let child = cmd.spawn().map_err(|e| format!("cannot start the child process: {}", e))?;
    #[cfg(windows)]
    let job = {
        use std::os::windows::io::AsRawHandle;
        win::Job::attach_handle(child.as_raw_handle() as _)
    };
    #[cfg(windows)]
    let tree = job.is_some();
    #[cfg(not(windows))]
    let tree = true;
    Ok(TreeChild {
        child,
        #[cfg(windows)]
        job,
        tree,
    })
}

impl TreeChild {
    /// Mata el árbol entero (idempotente sobre un proceso ya terminado).
    pub fn kill_tree(&mut self) {
        if let Ok(Some(_)) = self.child.try_wait() {
            return;
        }
        #[cfg(windows)]
        if let Some(job) = &self.job {
            if job.terminate() {
                return;
            }
        }
        #[cfg(unix)]
        if self.tree {
            let pid = self.child.id();
            if pid > 0 {
                let r = unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
                if r == 0 {
                    return;
                }
            }
        }
        let _ = self.tree;
        let _ = self.child.kill();
    }
}

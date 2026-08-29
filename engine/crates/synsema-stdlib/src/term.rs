//! Terminal interactiva (`term_open`, `term_recv`, `term_size`, `term_write`, `term_stats`,
//! `term_close`) — la terminal PROPIA del programa como handle del hub, en el mismo
//! `select` que procesos, sockets, bus y watches.
//!
//! - **Qué hace el runtime**: pone stdin en raw/no-echo, lee teclas en un hilo y las entrega
//!   como eventos de texto (`key` / `paste` / `resize` / `focus` / `eof`), informa el tamaño y
//!   escribe a stdout sin pasar por el buffer de `print`. Nada más: ni widgets, ni editor de
//!   línea, ni interpretación de VT — eso se escribe en Synsema, del lado de la app.
//! - **Restaurar es invariante del runtime**: `term_close`, drop del handle (fin del
//!   programa, error, `stop`, fin del hub) y el hook de pánico restauran SÓLO lo que el
//!   runtime activó (raw, bracketed paste, kitty flags). Los escapes que emita el script
//!   (cursor oculto, colores) los deshace el script.
//! - **Un solo dueño por proceso**: la terminal es un recurso del proceso, no del intérprete;
//!   un agente no puede abrirla mientras el main la tiene.
//! - **Sin TTY no hay terminal**: `Term::open` devuelve `Err(TermError::NoTty)` y el builtin lo
//!   mapea a `nothing` (pipe/CI/serve/test caen al `read_line` de siempre, sin cuelgues).
//! - **Ctrl+C**: en raw mode no genera SIGINT. Por default (`ctrl_c: "exit"`) el hilo lector
//!   restaura la terminal y termina el proceso con 130, como haría SIGINT; con `"key"` llega
//!   como `{key: "char", text: "c", ctrl: true}` y el script decide.
//! - **`ask`/`approve` con terminal abierta**: el handler de consola suspende el raw mode
//!   mientras hace su `read_line` cocinado (vía `synsema_core::term_guard`) y lo reanuda.
//! - **Paste**: bracketed paste (un evento `paste` con todo el texto) sólo en Unix; en
//!   Windows un pegado llega como ráfaga de `key` (limitación de ConPTY/crossterm).
//! - Dependencia: crossterm 0.29 sin `event-stream`/`serde`; cero `*-sys` nuevo.

use std::collections::VecDeque;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal;

use crate::proc::WakeFn;

pub const DEFAULT_MAX_QUEUE: usize = 16_384;
/// Latencia máxima del cierre: el lector duerme en `poll` de a este tanto y revisa `closed`.
const POLL_SLICE: Duration = Duration::from_millis(100);
const PAUSE_SLICE: Duration = Duration::from_millis(20);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermEvent {
    Key { key: String, text: String, ctrl: bool, alt: bool, shift: bool },
    Paste(String),
    Resize { cols: u16, rows: u16 },
    Focus(bool),
    /// stdin cerrado / hangup / error del lector: el handle se retira.
    Eof,
}

#[derive(Debug, Clone)]
pub struct TermOpts {
    pub paste: bool,
    pub kitty: bool,
    /// `true` = Ctrl+C restaura y sale con 130 (default); `false` = llega como tecla.
    pub ctrl_c_exit: bool,
    pub max_queue: usize,
}

impl Default for TermOpts {
    fn default() -> Self {
        TermOpts { paste: true, kitty: true, ctrl_c_exit: true, max_queue: DEFAULT_MAX_QUEUE }
    }
}

#[derive(Debug)]
pub enum TermError {
    /// stdin o stdout no son una terminal: el builtin devuelve `nothing`.
    NoTty,
    /// Ya hay una terminal abierta en este proceso (este u otro intérprete).
    Busy,
    Other(String),
}

impl std::fmt::Display for TermError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TermError::NoTty => write!(f, "stdin/stdout is not a terminal"),
            TermError::Busy => write!(f, "the terminal is already open in this process"),
            TermError::Other(s) => write!(f, "{}", s),
        }
    }
}

struct Queue {
    events: VecDeque<TermEvent>,
    dropped: u64,
    eof: bool,
}

/// Estado compartido entre el hub (consumidor) y el hilo lector (productor).
pub struct TermShared {
    queue: Mutex<Queue>,
    max_queue: usize,
    closed: AtomicBool,
    /// Suspendido (raw apagado por `ask`/`approve`): el lector no toca stdin.
    paused: AtomicBool,
    wake: Mutex<Option<WakeFn>>,
    ctrl_c_exit: bool,
    /// Qué activó el runtime (para restaurar exactamente eso).
    pub kitty: bool,
    pub paste: bool,
    /// stdout acepta escapes ANSI (en Windows: VT processing habilitado).
    pub ansi: bool,
    keys: AtomicU64,
}

impl TermShared {
    fn push(&self, ev: TermEvent) {
        let Ok(mut q) = self.queue.lock() else { return };
        if q.eof || self.closed.load(Ordering::Relaxed) {
            return;
        }
        if matches!(ev, TermEvent::Eof) {
            q.eof = true;
        } else {
            while q.events.len() >= self.max_queue {
                q.events.pop_front();
                q.dropped += 1;
            }
            if matches!(ev, TermEvent::Key { .. }) {
                self.keys.fetch_add(1, Ordering::Relaxed);
            }
            q.events.push_back(ev);
        }
        drop(q);
        self.wake_now();
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
        self.queue.lock().map(|q| !q.events.is_empty() || q.eof).unwrap_or(false)
    }

    /// Próximo evento. `Some(Eof)` una sola vez: después el handle debe retirarse.
    pub fn try_recv(&self) -> Option<TermEvent> {
        let mut q = self.queue.lock().ok()?;
        if let Some(ev) = q.events.pop_front() {
            return Some(ev);
        }
        if q.eof {
            q.eof = false;
            self.closed.store(true, Ordering::Relaxed);
            return Some(TermEvent::Eof);
        }
        None
    }

    /// `(queued, dropped, keys)`.
    pub fn stats(&self) -> (usize, u64, u64) {
        let (queued, dropped) = self.queue.lock().map(|q| (q.events.len(), q.dropped)).unwrap_or((0, 0));
        (queued, dropped, self.keys.load(Ordering::Relaxed))
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Estado de la consola por proceso: dueño único, restauración y hook de pánico
// ---------------------------------------------------------------------------

/// Qué está activo AHORA en la consola (lo que hay que deshacer al restaurar).
#[derive(Clone, Copy, Default)]
struct Active {
    raw: bool,
    paste: bool,
    kitty: bool,
}

static OWNED: AtomicBool = AtomicBool::new(false);
static ACTIVE: Mutex<Active> = Mutex::new(Active { raw: false, paste: false, kitty: false });
static PANIC_HOOK: OnceLock<()> = OnceLock::new();

/// Restaura todo lo que el runtime activó. Best-effort, nunca falla ni entra en pánico
/// (se llama desde drops y desde el hook de pánico).
fn restore_all() {
    let Ok(mut a) = ACTIVE.lock() else { return };
    let mut out = std::io::stdout();
    if a.kitty {
        let _ = crossterm::execute!(out, event::PopKeyboardEnhancementFlags);
        a.kitty = false;
    }
    if a.paste {
        let _ = crossterm::execute!(out, event::DisableBracketedPaste);
        a.paste = false;
    }
    if a.raw {
        let _ = terminal::disable_raw_mode();
        a.raw = false;
    }
    let _ = out.flush();
    synsema_core::term_guard::set_raw(false);
}

/// Activa raw (+ paste/kitty según `want`). Devuelve lo que quedó activo.
fn activate(want_paste: bool, want_kitty: bool) -> Result<Active, String> {
    let Ok(mut a) = ACTIVE.lock() else { return Err("terminal state poisoned".into()) };
    if !a.raw {
        terminal::enable_raw_mode().map_err(|e| format!("cannot enable raw mode: {}", e))?;
        a.raw = true;
    }
    let mut out = std::io::stdout();
    // Bracketed paste: sólo Unix. En Windows ni ConPTY pasa las marcas ni crossterm emite
    // `Paste` (un pegado llega como ráfaga de teclas; `term_stats.paste` lo dice: false).
    #[cfg(not(windows))]
    if want_paste && !a.paste {
        a.paste = crossterm::execute!(out, event::EnableBracketedPaste).is_ok();
    }
    #[cfg(windows)]
    let _ = want_paste;
    if want_kitty && !a.kitty {
        // Si la terminal no lo soporta (conhost, Terminal.app) se sigue sin él: NO es error.
        let supported = terminal::supports_keyboard_enhancement().unwrap_or(false);
        if supported {
            let flags = event::KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
                | event::KeyboardEnhancementFlags::REPORT_ALTERNATE_KEYS;
            a.kitty = crossterm::execute!(out, event::PushKeyboardEnhancementFlags(flags)).is_ok();
        }
    }
    let _ = out.flush();
    synsema_core::term_guard::set_raw(a.raw);
    Ok(*a)
}

fn install_panic_hook() {
    PANIC_HOOK.get_or_init(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_all();
            prev(info);
        }));
    });
}

/// Una terminal abierta, propiedad del hub. Dropearla restaura la consola y apaga el lector.
pub struct Term {
    pub shared: Arc<TermShared>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Term {
    /// NO chequea capabilities ni el modo del intérprete (lo hace el builtin).
    pub fn open(opts: TermOpts) -> Result<Term, TermError> {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            return Err(TermError::NoTty);
        }
        if OWNED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Err(TermError::Busy);
        }
        install_panic_hook();
        // En Windows el raw mode sólo toca stdin; el VT de SALIDA (para que `\x1b[2K` y
        // compañía funcionen en conhost) lo habilita `supports_ansi` una vez por proceso.
        #[cfg(windows)]
        let ansi = crossterm::ansi_support::supports_ansi();
        #[cfg(not(windows))]
        let ansi = true;
        let active = match activate(opts.paste, opts.kitty) {
            Ok(a) => a,
            Err(e) => {
                OWNED.store(false, Ordering::Release);
                return Err(TermError::Other(e));
            }
        };
        let shared = Arc::new(TermShared {
            queue: Mutex::new(Queue { events: VecDeque::new(), dropped: 0, eof: false }),
            max_queue: opts.max_queue.max(16),
            closed: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            wake: Mutex::new(None),
            ctrl_c_exit: opts.ctrl_c_exit,
            kitty: active.kitty,
            paste: active.paste,
            ansi,
            keys: AtomicU64::new(0),
        });
        // Puente para `ask`/`approve`: suspender = apagar raw y pausar el lector.
        let sh = shared.clone();
        let want_paste = opts.paste;
        let want_kitty = opts.kitty;
        synsema_core::term_guard::set_owner(Some(Box::new(move |resume| {
            if resume {
                let _ = activate(want_paste, want_kitty);
                sh.paused.store(false, Ordering::Release);
            } else {
                sh.paused.store(true, Ordering::Release);
                // Dar tiempo a que el lector salga del `poll` en curso antes de tocar el modo.
                std::thread::sleep(POLL_SLICE + Duration::from_millis(10));
                restore_all();
            }
        })));
        let sh = shared.clone();
        let reader = std::thread::Builder::new()
            .name("synsema-term".into())
            .spawn(move || reader_loop(sh))
            .map_err(|e| {
                restore_all();
                synsema_core::term_guard::set_owner(None);
                OWNED.store(false, Ordering::Release);
                TermError::Other(format!("cannot start the terminal reader: {}", e))
            })?;
        Ok(Term { shared, reader: Some(reader) })
    }

    pub fn size() -> Result<(u16, u16), String> {
        terminal::size().map_err(|e| format!("cannot read the terminal size: {}", e))
    }

    /// Escribe a stdout ya (sin pasar por el buffer de `print`).
    pub fn write(text: &str) -> Result<(), String> {
        let mut out = std::io::stdout();
        out.write_all(text.as_bytes()).and_then(|_| out.flush()).map_err(|e| e.to_string())
    }
}

impl Drop for Term {
    fn drop(&mut self) {
        self.shared.close();
        synsema_core::term_guard::set_owner(None);
        restore_all();
        // El lector sale en ≤ POLL_SLICE (revisa `closed` entre polls). Si está en medio de
        // un `read` bloqueante (llegó el evento justo), sale al procesarlo.
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
        OWNED.store(false, Ordering::Release);
    }
}

fn reader_loop(sh: Arc<TermShared>) {
    loop {
        if sh.is_closed() {
            return;
        }
        if sh.paused.load(Ordering::Acquire) {
            std::thread::sleep(PAUSE_SLICE);
            continue;
        }
        match event::poll(POLL_SLICE) {
            Ok(false) => continue,
            Ok(true) => match event::read() {
                Ok(ev) => {
                    if let Some(t) = map_event(ev) {
                        if sh.ctrl_c_exit && is_ctrl_c(&t) {
                            restore_all();
                            let _ = std::io::stdout().write_all(b"\r\n");
                            std::process::exit(130);
                        }
                        sh.push(t);
                    }
                }
                Err(_) => {
                    sh.push(TermEvent::Eof);
                    return;
                }
            },
            Err(_) => {
                sh.push(TermEvent::Eof);
                return;
            }
        }
    }
}

fn is_ctrl_c(ev: &TermEvent) -> bool {
    matches!(ev, TermEvent::Key { key, text, ctrl: true, .. } if key == "char" && text == "c")
}

/// crossterm → evento del lenguaje. Sólo `Press` (Release/Repeat del kitty protocol se
/// filtran: una semántica en todos los SO). Tab/Enter nunca llegan como `\t`/`\r`.
pub fn map_event(ev: Event) -> Option<TermEvent> {
    match ev {
        Event::Key(k) => map_key(k),
        Event::Paste(s) => Some(TermEvent::Paste(s)),
        Event::Resize(cols, rows) => Some(TermEvent::Resize { cols, rows }),
        Event::FocusGained => Some(TermEvent::Focus(true)),
        Event::FocusLost => Some(TermEvent::Focus(false)),
        Event::Mouse(_) => None,
    }
}

pub fn map_key(k: KeyEvent) -> Option<TermEvent> {
    if k.kind != KeyEventKind::Press {
        return None;
    }
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    let alt = k.modifiers.contains(KeyModifiers::ALT);
    let mut shift = k.modifiers.contains(KeyModifiers::SHIFT);
    let (key, text): (String, String) = match k.code {
        KeyCode::Char(c) => {
            // Con Ctrl el texto es la letra minúscula (Ctrl+O = "o"); sin Ctrl el carácter
            // ya viene con Shift aplicado ("A") y `shift` sólo informa.
            let t = if ctrl { c.to_lowercase().to_string() } else { c.to_string() };
            if !ctrl && c.is_uppercase() {
                shift = true;
            }
            ("char".into(), t)
        }
        KeyCode::Enter => ("enter".into(), String::new()),
        KeyCode::Tab => ("tab".into(), String::new()),
        KeyCode::BackTab => {
            shift = true;
            ("backtab".into(), String::new())
        }
        KeyCode::Backspace => ("backspace".into(), String::new()),
        KeyCode::Delete => ("delete".into(), String::new()),
        KeyCode::Insert => ("insert".into(), String::new()),
        KeyCode::Esc => ("escape".into(), String::new()),
        KeyCode::Up => ("up".into(), String::new()),
        KeyCode::Down => ("down".into(), String::new()),
        KeyCode::Left => ("left".into(), String::new()),
        KeyCode::Right => ("right".into(), String::new()),
        KeyCode::Home => ("home".into(), String::new()),
        KeyCode::End => ("end".into(), String::new()),
        KeyCode::PageUp => ("pageup".into(), String::new()),
        KeyCode::PageDown => ("pagedown".into(), String::new()),
        KeyCode::F(n) => (format!("f{}", n), String::new()),
        KeyCode::Null => return None,
        _ => ("other".into(), String::new()),
    };
    Some(TermEvent::Key { key, text, ctrl, alt, shift })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode, m: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, m)
    }
    fn k(ev: TermEvent) -> (String, String, bool, bool, bool) {
        match ev {
            TermEvent::Key { key, text, ctrl, alt, shift } => (key, text, ctrl, alt, shift),
            other => panic!("not a key: {:?}", other),
        }
    }

    #[test]
    fn tab_and_enter_are_names_not_control_chars() {
        assert_eq!(k(map_key(key(KeyCode::Tab, KeyModifiers::NONE)).unwrap()).0, "tab");
        let (name, text, _, _, _) = k(map_key(key(KeyCode::Enter, KeyModifiers::NONE)).unwrap());
        assert_eq!((name.as_str(), text.as_str()), ("enter", ""));
    }

    #[test]
    fn alt_enter_and_shift_enter_keep_modifiers() {
        let (name, _, ctrl, alt, shift) = k(map_key(key(KeyCode::Enter, KeyModifiers::ALT)).unwrap());
        assert_eq!((name.as_str(), ctrl, alt, shift), ("enter", false, true, false));
        let (_, _, _, _, shift) = k(map_key(key(KeyCode::Enter, KeyModifiers::SHIFT)).unwrap());
        assert!(shift);
    }

    #[test]
    fn shift_is_applied_to_text_and_reported() {
        let (name, text, _, _, shift) = k(map_key(key(KeyCode::Char('A'), KeyModifiers::SHIFT)).unwrap());
        assert_eq!((name.as_str(), text.as_str(), shift), ("char", "A", true));
        // Sin el modificador explícito (terminales que no lo mandan) igual se infiere.
        let (_, text, _, _, shift) = k(map_key(key(KeyCode::Char('A'), KeyModifiers::NONE)).unwrap());
        assert_eq!((text.as_str(), shift), ("A", true));
    }

    #[test]
    fn ctrl_letter_is_lowercase_text() {
        let (name, text, ctrl, _, _) = k(map_key(key(KeyCode::Char('O'), KeyModifiers::CONTROL)).unwrap());
        assert_eq!((name.as_str(), text.as_str(), ctrl), ("char", "o", true));
        assert!(is_ctrl_c(&map_key(key(KeyCode::Char('c'), KeyModifiers::CONTROL)).unwrap()));
        assert!(!is_ctrl_c(&map_key(key(KeyCode::Char('c'), KeyModifiers::NONE)).unwrap()));
    }

    #[test]
    fn release_and_repeat_are_filtered_and_fkeys_named() {
        let mut ev = key(KeyCode::Char('a'), KeyModifiers::NONE);
        ev.kind = KeyEventKind::Release;
        assert!(map_key(ev).is_none());
        ev.kind = KeyEventKind::Repeat;
        assert!(map_key(ev).is_none());
        assert_eq!(k(map_key(key(KeyCode::F(5), KeyModifiers::NONE)).unwrap()).0, "f5");
        assert_eq!(k(map_key(key(KeyCode::BackTab, KeyModifiers::NONE)).unwrap()).4, true);
    }

    #[test]
    fn paste_resize_focus_map_and_mouse_is_dropped() {
        assert_eq!(map_event(Event::Paste("a\nb".into())), Some(TermEvent::Paste("a\nb".into())));
        assert_eq!(map_event(Event::Resize(80, 24)), Some(TermEvent::Resize { cols: 80, rows: 24 }));
        assert_eq!(map_event(Event::FocusLost), Some(TermEvent::Focus(false)));
    }

    #[test]
    fn open_without_tty_is_no_tty_and_touches_nothing() {
        // Bajo el harness stdin no es un TTY: debe fallar con NoTty, sin tomar el dueño.
        if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            return; // corrida a mano en una consola real: no aplica
        }
        match Term::open(TermOpts::default()) {
            Err(TermError::NoTty) => {}
            other => panic!("expected NoTty, got {:?}", other.map(|_| ())),
        }
        assert!(!OWNED.load(Ordering::Relaxed));
        assert!(!synsema_core::term_guard::is_raw());
    }

    #[test]
    fn queue_drops_oldest_and_reports_eof_once() {
        let sh = TermShared {
            queue: Mutex::new(Queue { events: VecDeque::new(), dropped: 0, eof: false }),
            max_queue: 2,
            closed: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            wake: Mutex::new(None),
            ctrl_c_exit: true,
            kitty: false,
            paste: false,
            ansi: true,
            keys: AtomicU64::new(0),
        };
        for c in ["a", "b", "c"] {
            sh.push(TermEvent::Key { key: "char".into(), text: c.into(), ctrl: false, alt: false, shift: false });
        }
        assert_eq!(sh.stats(), (2, 1, 3));
        sh.push(TermEvent::Eof);
        assert!(matches!(sh.try_recv(), Some(TermEvent::Key { text, .. }) if text == "b"));
        assert!(matches!(sh.try_recv(), Some(TermEvent::Key { text, .. }) if text == "c"));
        assert_eq!(sh.try_recv(), Some(TermEvent::Eof));
        assert_eq!(sh.try_recv(), None);
        assert!(sh.is_closed());
    }
}

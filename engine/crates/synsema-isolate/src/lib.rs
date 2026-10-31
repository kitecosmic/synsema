//! Correr un proceso hijo aislado por el kernel (v0.6.52, `specs/aislamiento-procesos-propuesta.md`).
//!
//! Crate hoja: no conoce el lenguaje. Recibe una [`Policy`] (qué puede leer y escribir el hijo, cuánta
//! memoria) y prepara un `std::process::Command`. En Linux:
//! - **Landlock** (ABI ≥ 6): el hijo sólo ve las carpetas del sistema que tienen programas y
//!   bibliotecas (lectura), las que nombra la política, una carpeta temporal propia y `/dev/null`.
//!   Sin red TCP, sin sockets UNIX abstractos y sin señales a procesos de afuera.
//! - **seccomp**: sin `ptrace`, `mount`, namespaces, `bpf`, `io_uring`, `setsid` ni `socket()`.
//! - **rlimits**: memoria (espacio de direcciones) y sin core dumps.
//! - **grupo de procesos** propio: [`kill_group`] termina el árbol entero.
//!
//! Lo que el kernel no puede imponer falla cerrado ([`Error`]): nunca corre sin aislar.
//! El ruleset y el filtro se arman en el padre; en el hijo, entre `fork` y `exec`, sólo hay syscalls
//! que no reservan memoria.

use std::fmt;
use std::path::PathBuf;
use std::process::Command;

#[cfg(target_os = "linux")]
mod linux;

/// El ABI de Landlock más viejo que se acepta. Con menos (Linux < 6.12) el hijo podría mandar
/// señales a otros procesos del usuario o hablar por sockets UNIX abstractos.
pub const MIN_LANDLOCK_ABI: u32 = 6;

/// Un lugar que se le concede al hijo.
#[derive(Clone, Debug)]
pub enum Place {
    /// Una ruta absoluta: se abre al preparar (sigue links). Para lo que no juzgó nadie (tests,
    /// rutas del sistema).
    Path(PathBuf),
    /// Un lugar ya abierto por [`pin`]: el kernel concede exactamente lo que se juzgó, aunque
    /// después cambie un link en el camino.
    #[cfg(target_os = "linux")]
    Pinned(std::sync::Arc<std::os::fd::OwnedFd>),
}

impl From<PathBuf> for Place {
    fn from(p: PathBuf) -> Place {
        Place::Path(p)
    }
}

/// Qué puede hacer el hijo. Lo arma el adaptador desde los permisos del programa.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// Carpetas o archivos que el hijo puede leer (y ejecutar).
    pub read: Vec<Place>,
    /// Carpetas o archivos que el hijo puede leer, escribir, crear y borrar (no links a
    /// dispositivos, FIFOs ni sockets: ver `linux.rs`).
    pub write: Vec<Place>,
    /// Tope del espacio de direcciones del hijo (`RLIMIT_AS`), en bytes.
    pub max_memory_bytes: Option<u64>,
}

/// Lo que se impuso de verdad (para el resultado de `run` y el audit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub landlock_abi: u32,
    /// `"none"`: el hijo no tiene red.
    pub network: &'static str,
    pub max_memory_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// El sistema no tiene el mecanismo (Windows, macOS, wasm).
    Unsupported(String),
    /// El kernel no tiene lo necesario (Landlock apagado o un ABI viejo).
    Kernel(String),
    /// Una ruta de la política no sirve.
    Path(String),
    /// Una llamada al sistema falló al armar el aislamiento.
    Os(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unsupported(m) | Error::Kernel(m) | Error::Path(m) | Error::Os(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

/// El aislamiento preparado. Tiene que vivir hasta que el hijo termine: al soltarlo se borra la
/// carpeta temporal del hijo.
pub struct Prepared {
    pub report: Report,
    #[cfg(target_os = "linux")]
    _inner: linux::Inner,
}

/// Prepara `cmd` para correr aislado según `policy`: el entorno queda limpio (`PATH`, `LANG`, y
/// `HOME`/`TMPDIR` en una carpeta temporal propia; lo demás lo agrega el que llama después), y el
/// aislamiento se aplica en el hijo antes del `exec`. Si algo no se puede imponer, `Err` y el
/// comando no se toca.
pub fn prepare(cmd: &mut Command, policy: &Policy) -> Result<Prepared, Error> {
    #[cfg(target_os = "linux")]
    {
        let (report, inner) = linux::prepare(cmd, policy)?;
        Ok(Prepared { report, _inner: inner })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cmd, policy);
        Err(Error::Unsupported(unsupported_message()))
    }
}

#[cfg(not(target_os = "linux"))]
fn unsupported_message() -> String {
    format!(
        "isolate is available on Linux only for now (this is {}); macOS and Windows are planned — nothing ran, rather than run without isolation",
        std::env::consts::OS
    )
}

/// Un lugar abierto una sola vez: dónde quedó de verdad (sin links) y si es carpeta. El que juzga
/// el permiso juzga `real`, y el kernel recibe `place`, el mismo inodo (sin ventana entre las dos
/// cosas). En Linux, `open(O_PATH)` y la ruta del fd; en el resto, `canonicalize` (no hay kernel que
/// imponga nada: `prepare` falla cerrado igual).
pub struct Pin {
    pub place: Place,
    pub real: PathBuf,
    pub is_dir: bool,
}

pub fn pin(path: &std::path::Path) -> std::io::Result<Pin> {
    #[cfg(target_os = "linux")]
    {
        linux::pin(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let real = std::fs::canonicalize(path)?;
        let is_dir = real.is_dir();
        Ok(Pin { place: Place::Path(real.clone()), real, is_dir })
    }
}

/// Lo que [`exited`] sabe de un hijo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildState {
    /// Sigue corriendo.
    Running,
    /// Terminó y no se recogió: es un zombie, su número sigue tomado.
    Exited,
    /// `waitid` no lo encuentra: ya lo recogió otro, o el proceso arrancó con `SIGCHLD` ignorado y
    /// el kernel lo recoge solo. No hay zombie que retenga el número: el del grupo sigue a salvo
    /// mientras quede vivo alguien del grupo, y [`kill_group`] se llama igual (ronda 4, N4). Si ya
    /// no queda nadie, el número pudo volver a usarse: hace falta que dé la vuelta y que otro
    /// proceso se haga líder de un grupo con él justo en ese momento. La CLI no llega acá (pone
    /// `SIGCHLD` por defecto al arrancar); un embebedor con `SIGCHLD` ignorado, sí.
    Gone,
}

/// ¿El hijo `pid` ya terminó? Sin recogerlo (`waitid` con `WNOWAIT`): mientras es un zombie su
/// número sigue tomado, así que [`kill_group`] no puede caer en otro grupo (salvo con
/// [`ChildState::Gone`], que no deja zombie). Fuera de Linux, `Running`.
pub fn exited(pid: u32) -> ChildState {
    #[cfg(target_os = "linux")]
    {
        linux::exited(pid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        ChildState::Running
    }
}

/// Ronda 4 (A1): espera, hasta `wait`, a que el grupo de `pid` (ya matado con [`kill_group`]) quede
/// vacío: un proceso con el SIGKILL pendiente todavía puede terminar la syscall en la que está.
/// `false` si no se vació a tiempo. Fuera de Linux, `true`.
///
/// Ronda 5 (M3): si este proceso recoge a los huérfanos (PID 1 de un contenedor, o subreaper), los
/// del grupo que ya murieron son hijos suyos y se recogen acá; si no, quedarían zombies en el grupo.
///
/// Ronda 6 (M2): un grupo con sólo zombies cuenta como vacío (un zombie no corre nada), aunque los
/// adopte otro proceso que no los recoge. Se mira en `/proc`, hilo por hilo.
///
/// Ronda 7 (B1): sólo si `/proc` es el de este espacio de pid (si no, sus números son otros) y
/// muestra a alguien del grupo; si no, se espera a que el grupo desaparezca, como antes.
pub fn group_gone(pid: u32, wait: std::time::Duration) -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::group_gone(pid, wait)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, wait);
        true
    }
}

/// Ronda 3 (B1): vuelve `SIGCHLD` a su acción por defecto. Si el proceso arrancó con `SIGCHLD`
/// ignorado (lo hereda de quien lo lanzó), el kernel recoge solo a los hijos: no queda el zombie que
/// retiene el número del grupo, y `run` pierde el código de salida. Se llama al arrancar, antes de
/// cualquier hilo. No hace nada fuera de Linux.
pub fn default_sigchld() {
    #[cfg(target_os = "linux")]
    linux::default_sigchld();
}

/// El ABI de Landlock de este kernel (`None`: sin Landlock, o no es Linux).
pub fn landlock_abi() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        linux::landlock_abi()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Termina el grupo de procesos de un hijo preparado (él y todo lo que lanzó: `setsid` le está
/// denegado, así que nadie sale del grupo). No hace nada fuera de Linux. Llamarla **antes** de
/// recoger al hijo (ver [`exited`]): recogido, su número queda libre y podría ser de otro grupo.
pub fn kill_group(pid: u32) {
    #[cfg(target_os = "linux")]
    linux::kill_group(pid);
    #[cfg(not(target_os = "linux"))]
    let _ = pid;
}

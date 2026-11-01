//! v0.6.46 (E8): abrir un archivo cerrando la carrera entre el chequeo y la apertura.
//!
//! Antes (v0.6.45) el builtin chequeaba la ruta en disco (`path_within_physically`) y DESPUÉS la
//! abría por nombre: un link cambiado entre las dos llevaba la apertura afuera del grant. Ahora:
//! - **Sin links en el camino** (el caso común): se abre la ruta léxica absoluta sin seguir ningún
//!   link en ningún componente (`openat2` con `RESOLVE_NO_SYMLINKS` en Linux, `NtCreateFile` con
//!   `OBJ_DONT_REPARSE` en Windows). Si abre, es exactamente el archivo que el chequeo juzgó por
//!   nombre; una llamada, la misma que antes.
//! - **Con un link en el camino:** se abre siguiendo los links pero SIN crear ni truncar, se le pide
//!   al sistema la ruta real del handle y el chequeo de siempre se corre otra vez juzgando esa ruta
//!   (`capscope::with_physical`). Lo que se juzga es lo que se abrió. Para crear un archivo que no
//!   existe: lo mismo con la carpeta padre, y el archivo se crea relativo a su handle sin seguir un
//!   link en el nombre.
//! - **Reemplazar un archivo** (`write_file`, `edit_file`: temporal + rename): la carpeta padre se
//!   abre igual (sin links, o siguiéndolos y juzgando su ubicación real + el nombre), y el temporal,
//!   el rename y la limpieza van todos RELATIVOS a ese handle (`Beneath`): el nombre no se vuelve a
//!   resolver entre el chequeo y el rename.
//! - Donde no hay con qué (macOS, wasm, un kernel sin `openat2`, una ruta UNC): como v0.6.45.
//!
//! El `unsafe` es sólo de Windows (`NtCreateFile`, `GetFinalPathNameByHandleW`): está en la lista
//! de `synsema-jit/tests/unsafe_allowlist.rs`. Linux va por `rustix`, sin `unsafe`.

use std::fs::File;
use std::io;

/// Cómo se abre.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenFor {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub create: bool,
}

impl OpenFor {
    pub const READ: OpenFor = OpenFor { read: true, write: false, append: false, create: false };
    pub const APPEND: OpenFor = OpenFor { read: false, write: false, append: true, create: true };
}

/// Por qué no abrió.
#[derive(Debug)]
pub enum Refused<E> {
    /// El sistema no pudo (no existe, permiso, una carpeta…): el error de siempre.
    Io(io::Error),
    /// El chequeo, juzgando la ubicación real del handle, lo negó.
    Denied(E),
}

/// Abre `path` (la ruta que ya pasó el chequeo) sin dejar ventana entre el chequeo y la apertura.
/// `recheck(real)` corre el chequeo de capabilities juzgando la ruta por `real`, su ubicación en
/// disco; sólo se llama cuando hay un link en el camino.
pub fn open_checked<E>(path: &str, how: OpenFor, recheck: &dyn Fn(&str) -> Result<(), E>) -> Result<File, Refused<E>> {
    let Some(abs) = synsema_core::capscope::absolute_path(path) else {
        return plain(path, how).map_err(Refused::Io);
    };
    match sys::open_nofollow(&abs, how) {
        Ok(f) => Ok(f),
        Err(Nf::Io(e)) => Err(Refused::Io(e)),
        Err(Nf::Unsupported) => plain(path, how).map_err(Refused::Io),
        Err(Nf::Link) => through_link(&abs, how, recheck),
    }
}

/// La apertura de v0.6.45 (por nombre, siguiendo links): donde no hay con qué hacerlo mejor.
fn plain(path: &str, how: OpenFor) -> io::Result<File> {
    std::fs::OpenOptions::new().read(how.read).write(how.write).append(how.append).create(how.create).open(path)
}

/// Hay un link en el camino: abrir siguiendo y juzgar dónde quedó el handle.
///
/// Ronda 1 (E8-B2): se abre primero SIN acceso a los datos (Linux `O_PATH`, Windows sólo atributos),
/// se juzga la ruta real, y recién entonces se reabre el MISMO objeto con el acceso pedido (Linux
/// `/proc/self/fd/N`, Windows `ReOpenFile`). Abrir con el acceso pedido antes de juzgar no siempre es
/// inocuo: un FIFO de afuera del grant bloqueaba la lectura, un dispositivo puede tener efectos al
/// abrirse, y en Windows se rompían los oplocks de otro proceso.
fn through_link<E>(abs: &str, how: OpenFor, recheck: &dyn Fn(&str) -> Result<(), E>) -> Result<File, Refused<E>> {
    match sys::open_path(abs) {
        Ok(f) => {
            let real = sys::real_path(&f).ok_or_else(|| Refused::Io(io::Error::other("cannot tell where the open file is")))?;
            recheck(&real).map_err(Refused::Denied)?;
            sys::reopen(&f, how).map_err(Refused::Io)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && how.create => {
            // No existe: la carpeta padre, siguiendo links; su ubicación real + el nombre se
            // juzga, y el archivo se crea relativo al handle de la carpeta, sin seguir un link en
            // el nombre (un link roto ahí no se sigue: se niega).
            let Some((parent, name)) = split_parent(abs) else {
                return Err(Refused::Io(e));
            };
            let dir = parent_through_link(&parent, name, recheck)?;
            match sys::create_beneath(&dir, name, how) {
                Ok(f) => Ok(f),
                Err(Nf::Io(e)) => Err(Refused::Io(e)),
                Err(Nf::Link) => Err(Refused::Io(io::Error::other(format!("{} is a link that leads nowhere; it is not followed to create a file", name)))),
                Err(Nf::Unsupported) => Err(Refused::Io(io::Error::other("cannot create the file relative to its folder"))),
            }
        }
        Err(e) => Err(Refused::Io(e)),
    }
}

/// `C:/a/b.txt` → (`C:/a`, `b.txt`); la raíz queda con su barra (`C:/`, `/`).
fn split_parent(abs: &str) -> Option<(String, &str)> {
    match abs.rsplit_once('/') {
        Some((p, n)) if !n.is_empty() => Some((if p.is_empty() || p.ends_with(':') { format!("{}/", p) } else { p.to_string() }, n)),
        _ => None,
    }
}

/// La carpeta padre tiene un link en el camino: abrirla siguiéndolo y juzgar su ubicación real con
/// el nombre adentro.
fn parent_through_link<E>(parent: &str, name: &str, recheck: &dyn Fn(&str) -> Result<(), E>) -> Result<File, Refused<E>> {
    let dir = sys::open_dir(parent).map_err(Refused::Io)?;
    let real_dir = sys::real_path(&dir).ok_or_else(|| Refused::Io(io::Error::other("cannot tell where the folder is")))?;
    let real = format!("{}/{}", real_dir.trim_end_matches(['/', '\\']), name);
    recheck(&real).map_err(Refused::Denied)?;
    Ok(dir)
}

/// La carpeta de un archivo, abierta y ya juzgada, para reemplazar el archivo adentro sin volver a
/// resolver su nombre: el temporal, el rename y la limpieza van relativos a este handle.
pub struct Beneath {
    dir: File,
    name: String,
}

/// Abre la carpeta de `path` (que ya pasó el chequeo) como `open_checked` abre un archivo. `None`
/// donde no hay con qué hacerlo (el llamador sigue como v0.6.45).
pub fn parent_checked<E>(path: &str, recheck: &dyn Fn(&str) -> Result<(), E>) -> Result<Option<Beneath>, Refused<E>> {
    let Some(abs) = synsema_core::capscope::absolute_path(path) else {
        return Ok(None);
    };
    let Some((parent, name)) = split_parent(&abs) else {
        return Ok(None);
    };
    let dir = match sys::open_dir_nofollow(&parent) {
        Ok(d) => d,
        Err(Nf::Unsupported) => return Ok(None),
        Err(Nf::Io(e)) => return Err(Refused::Io(e)),
        Err(Nf::Link) => parent_through_link(&parent, name, recheck)?,
    };
    Ok(Some(Beneath { dir, name: name.to_string() }))
}

impl Beneath {
    /// v0.6.52 (ronda 3, A1): borra la entrada `name` de la carpeta abierta sin seguirla (un link se
    /// borra a sí mismo). En Linux relativo al handle (`unlinkat`): el nombre de la carpeta no se
    /// vuelve a resolver. Donde no hay con qué, por nombre (`path`).
    pub fn remove_entry(&self, path: &str) -> io::Result<()> {
        sys::unlink_beneath(&self.dir, &self.name, path)
    }

    /// v0.6.53 (`make_dir`): crea la carpeta `name` en la carpeta abierta, sin seguir un link en el
    /// nombre (si ya hay algo ahí, link o no, `AlreadyExists`). Relativa al handle en Linux
    /// (`mkdirat`) y en Windows (`NtCreateFile` sin reparse); donde no hay con qué, por nombre.
    pub fn make_dir(&self, path: &str) -> io::Result<()> {
        sys::mkdir_beneath(&self.dir, &self.name, path)
    }

    /// Reemplaza el archivo con `data`: temporal nuevo al lado (un nombre al azar creado en
    /// exclusiva, que nunca sigue un link), escrito, y renombrado encima del nombre. En Unix el
    /// reemplazo conserva los permisos del archivo que reemplaza, aplicados antes de escribir.
    pub fn replace_with(&self, data: &[u8]) -> io::Result<()> {
        use std::io::Write;
        let mut last = None;
        for _ in 0..8 {
            let tmp = format!("{}.{:016x}.synsema.tmp", self.name, rand::random::<u64>());
            let mut file = match sys::create_new_beneath(&self.dir, &tmp) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    last = Some(e);
                    continue;
                }
                Err(e) => return Err(e),
            };
            sys::copy_mode(&self.dir, &self.name, &file);
            let done = file.write_all(data).and_then(|_| sys::rename_beneath(&self.dir, &file, &tmp, &self.name));
            if done.is_err() {
                sys::discard_beneath(&self.dir, &file, &tmp);
            }
            return done;
        }
        Err(last.unwrap_or_else(|| io::Error::other("could not create a temporary file")))
    }
}

/// Borra un link por nombre, sin seguirlo (donde `parent_checked` no tiene con qué). En Windows un
/// link a carpeta (o una junction) se borra como carpeta; ronda 3 (N3): sólo si la entrada ES un
/// link a carpeta, así un error de `remove_file` no queda tapado y una carpeta de verdad que
/// apareció en el medio no se borra.
pub fn remove_link(path: &str) -> io::Result<()> {
    if is_dir_link(std::fs::symlink_metadata(path).ok()) {
        std::fs::remove_dir(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// ¿La entrada es un link a carpeta que Windows borra como carpeta?
#[cfg(windows)]
fn is_dir_link(m: Option<std::fs::Metadata>) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.is_some_and(|m| m.file_type().is_symlink() && m.file_attributes() & 0x10 != 0) // FILE_ATTRIBUTE_DIRECTORY
}

#[cfg(not(windows))]
fn is_dir_link(_m: Option<std::fs::Metadata>) -> bool {
    false
}

/// v0.6.53 (ronda 1, M1): abre un archivo de estado PRIVADO del proceso (las aprobaciones
/// pendientes y su lock). Nunca sigue un link en el último componente (Unix `O_NOFOLLOW`, Windows
/// `FILE_FLAG_OPEN_REPARSE_POINT` y rechazo si es un reparse point), tiene que ser un archivo
/// regular y, en Unix, privado (`mode & 0o077 == 0`) y del euid. Con `create`, lo crea
/// con 0600 si no existe (lectura y escritura). El motivo de un rechazo va en el texto del error,
/// redactado para seguir a la ruta (`… is a link; it is not followed`).
pub fn open_private(path: &std::path::Path, create: bool) -> io::Result<File> {
    let f = private_open(path, create)?;
    let m = f.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            // FILE_ATTRIBUTE_REPARSE_POINT: un symlink o una junction, abierto como tal.
            return Err(io::Error::other("is a link; it is not followed"));
        }
    }
    if !m.is_file() {
        return Err(io::Error::other("is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "can be read or written by other users (mode {:o}); it has to be private (chmod 600; a filesystem that does not keep Unix permissions, like a Windows drive mounted in WSL, cannot hold it)",
                    m.mode() & 0o777
                ),
            ));
        }
        if m.uid() != rustix::process::geteuid().as_raw() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "belongs to another user"));
        }
    }
    Ok(f)
}

// Ronda 2, R2-3: la misma rama en todo Unix (macOS incluido: `O_NOFOLLOW` da `ELOOP` también ahí).
#[cfg(unix)]
fn private_open(path: &std::path::Path, create: bool) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};
    let mut flags = OFlags::NOFOLLOW | OFlags::CLOEXEC;
    flags |= if create { OFlags::RDWR | OFlags::CREATE } else { OFlags::RDONLY };
    match rustix::fs::open(path, flags, Mode::from_raw_mode(0o600)) {
        Ok(fd) => Ok(File::from(fd)),
        Err(rustix::io::Errno::LOOP) => Err(io::Error::other("is a link; it is not followed")),
        Err(e) => Err(e.into()),
    }
}

#[cfg(windows)]
fn private_open(path: &std::path::Path, create: bool) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    if create {
        o.write(true).create(true);
    }
    // FILE_FLAG_OPEN_REPARSE_POINT: un link se abre a sí mismo (y se rechaza arriba), no se sigue.
    o.custom_flags(0x0020_0000);
    o.open(path)
}

#[cfg(not(any(unix, windows)))]
fn private_open(path: &std::path::Path, create: bool) -> io::Result<File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    if create {
        o.write(true).create(true);
    }
    o.open(path)
}

/// El resultado de una apertura sin links.
#[derive(Debug)]
#[allow(dead_code)]
enum Nf {
    Io(io::Error),
    /// Hay un link (symlink, junction, cualquier reparse point) en algún componente.
    Link,
    /// No hay con qué (macOS, un kernel sin `openat2`, una ruta que no es de una unidad local).
    Unsupported,
}

#[cfg(target_os = "linux")]
mod sys {
    use super::{Nf, OpenFor};
    use rustix::fs::{Mode, OFlags, ResolveFlags, CWD};
    use std::fs::File;
    use std::io;

    fn flags(how: OpenFor) -> OFlags {
        let mut f = OFlags::CLOEXEC;
        f |= match (how.read, how.write || how.append) {
            (true, true) => OFlags::RDWR,
            (false, true) => OFlags::WRONLY,
            _ => OFlags::RDONLY,
        };
        if how.append {
            f |= OFlags::APPEND;
        }
        if how.create {
            f |= OFlags::CREATE;
        }
        f
    }

    fn map(e: rustix::io::Errno) -> Nf {
        match e {
            rustix::io::Errno::LOOP => Nf::Link,
            // Sin `openat2` (kernel < 5.6, o el seccomp de un contenedor que la conoce y la niega).
            rustix::io::Errno::NOSYS => Nf::Unsupported,
            e => Nf::Io(io::Error::from_raw_os_error(e.raw_os_error())),
        }
    }

    /// Ronda 1 (E8-B1): `openat2` bloqueada por un seccomp viejo (Docker < 20.10 daba EPERM, no
    /// ENOSYS, a las syscalls que no conocía). Se sabe la primera vez y queda anotado.
    static OPENAT2_BLOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// `openat2` sin seguir links, con el caso de arriba: un EPERM se contrasta abriendo `/` (que
    /// siempre se puede); si ése también da EPERM, es la syscall la bloqueada y se sigue como v0.6.45.
    fn openat2_nf(abs: &str, flags: OFlags, mode: Mode) -> Result<File, Nf> {
        use std::sync::atomic::Ordering;
        if OPENAT2_BLOCKED.load(Ordering::Relaxed) {
            return Err(Nf::Unsupported);
        }
        match rustix::fs::openat2(CWD, abs, flags, mode, ResolveFlags::NO_SYMLINKS) {
            Ok(fd) => Ok(File::from(fd)),
            Err(rustix::io::Errno::PERM) => {
                let root = rustix::fs::openat2(CWD, "/", OFlags::PATH | OFlags::CLOEXEC, Mode::empty(), ResolveFlags::NO_SYMLINKS);
                Err(perm_or_blocked(root.map(|_| ()), &OPENAT2_BLOCKED))
            }
            Err(e) => Err(map(e)),
        }
    }

    /// Un EPERM de `openat2`: si abrir `/` también lo da, la syscall está bloqueada (se anota en
    /// `blocked`); si no, es el permiso de ese archivo.
    fn perm_or_blocked(root: Result<(), rustix::io::Errno>, blocked: &std::sync::atomic::AtomicBool) -> Nf {
        match root {
            Err(rustix::io::Errno::PERM) => {
                blocked.store(true, std::sync::atomic::Ordering::Relaxed);
                Nf::Unsupported
            }
            _ => map(rustix::io::Errno::PERM),
        }
    }

    #[cfg(test)]
    #[test]
    fn a_blocked_openat2_falls_back_and_a_real_eperm_does_not() {
        let blocked = std::sync::atomic::AtomicBool::new(false);
        assert!(matches!(perm_or_blocked(Ok(()), &blocked), Nf::Io(e) if e.raw_os_error() == Some(rustix::io::Errno::PERM.raw_os_error())));
        assert!(!blocked.load(std::sync::atomic::Ordering::Relaxed));
        assert!(matches!(perm_or_blocked(Err(rustix::io::Errno::PERM), &blocked), Nf::Unsupported));
        assert!(blocked.load(std::sync::atomic::Ordering::Relaxed));
    }

    pub(super) fn open_nofollow(abs: &str, how: OpenFor) -> Result<File, Nf> {
        // `openat2`, a diferencia de `openat`, da EINVAL con un modo distinto de cero sin O_CREAT.
        let mode = if how.create { Mode::from_raw_mode(0o666) } else { Mode::empty() };
        openat2_nf(abs, flags(how), mode)
    }

    /// Abre siguiendo links, sin acceso a los datos (`O_PATH`): no abre el FIFO ni el dispositivo.
    pub(super) fn open_path(abs: &str) -> io::Result<File> {
        rustix::fs::open(abs, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).map(File::from).map_err(os)
    }

    /// Reabre el mismo objeto con el acceso pedido (el link mágico de `/proc/self/fd`).
    pub(super) fn reopen(f: &File, how: OpenFor) -> io::Result<File> {
        use std::os::fd::AsRawFd;
        let how = OpenFor { create: false, ..how };
        rustix::fs::open(format!("/proc/self/fd/{}", f.as_raw_fd()), flags(how), Mode::empty()).map(File::from).map_err(os)
    }

    pub(super) fn real_path(f: &File) -> Option<String> {
        use std::os::fd::AsRawFd;
        let p = std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd())).ok()?;
        let s = p.to_string_lossy().into_owned();
        // Un archivo borrado mientras estaba abierto: no hay dónde juzgarlo.
        (!s.ends_with(" (deleted)")).then_some(s)
    }

    pub(super) fn open_dir(path: &str) -> io::Result<File> {
        File::open(path)
    }

    pub(super) fn create_beneath(dir: &File, name: &str, how: OpenFor) -> Result<File, Nf> {
        rustix::fs::openat(dir, name, flags(how) | OFlags::NOFOLLOW, Mode::from_raw_mode(0o666))
            .map(File::from)
            .map_err(map)
    }

    pub(super) fn open_dir_nofollow(abs: &str) -> Result<File, Nf> {
        openat2_nf(abs, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
    }

    fn os(e: rustix::io::Errno) -> io::Error {
        io::Error::from_raw_os_error(e.raw_os_error())
    }

    pub(super) fn create_new_beneath(dir: &File, name: &str) -> io::Result<File> {
        let f = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        rustix::fs::openat(dir, name, f, Mode::from_raw_mode(0o666)).map(File::from).map_err(os)
    }

    /// Los permisos del archivo que se reemplaza (si es un archivo: un link no se sigue).
    pub(super) fn copy_mode(dir: &File, name: &str, to: &File) {
        if let Ok(st) = rustix::fs::statat(dir, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            if rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::RegularFile {
                let _ = rustix::fs::fchmod(to, Mode::from_raw_mode(st.st_mode & 0o7777));
            }
        }
    }

    pub(super) fn rename_beneath(dir: &File, _tmp_file: &File, tmp: &str, name: &str) -> io::Result<()> {
        rustix::fs::renameat(dir, tmp, dir, name).map_err(os)
    }

    pub(super) fn discard_beneath(dir: &File, _tmp_file: &File, tmp: &str) {
        let _ = rustix::fs::unlinkat(dir, tmp, rustix::fs::AtFlags::empty());
    }

    pub(super) fn unlink_beneath(dir: &File, name: &str, _path: &str) -> io::Result<()> {
        rustix::fs::unlinkat(dir, name, rustix::fs::AtFlags::empty()).map_err(os)
    }

    pub(super) fn mkdir_beneath(dir: &File, name: &str, _path: &str) -> io::Result<()> {
        rustix::fs::mkdirat(dir, name, Mode::from_raw_mode(0o777)).map_err(os)
    }
}

#[cfg(windows)]
mod sys {
    use super::{Nf, OpenFor};
    use std::collections::HashMap;
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::sync::{Arc, Mutex, OnceLock};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        NtCreateFile, NtSetInformationFile, FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Wdk::Storage::FileSystem::FILE_DIRECTORY_FILE;
    use windows_sys::Win32::Foundation::{
        RtlNtStatusToDosError, HANDLE, INVALID_HANDLE_VALUE, STATUS_REPARSE_POINT_ENCOUNTERED, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, GetDriveTypeW, GetFinalPathNameByHandleW, QueryDosDeviceW, ReOpenFile, SetFileInformationByHandle,
        DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
        FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
        VOLUME_NAME_DOS,
    };
    use windows_sys::Win32::System::Kernel::{OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE};
    use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    /// El handle de la raíz de la unidad (`C:\`): la ruta se abre RELATIVA a él, así el nombre no pasa
    /// por `\??\C:` (un link del object manager que `OBJ_DONT_REPARSE` también rechazaría).
    ///
    /// Ronda 1 (E8-M5): queda en caché sólo la de un disco fijo, y se valida en cada apertura con el
    /// destino de la letra (`QueryDosDeviceW`, ~2 µs): un `subst` o un `mountvol` que la remapea cambia
    /// ese destino y se reabre (antes se abría en el volumen o la carpeta de antes, distinto del
    /// juzgado). Una unidad extraíble, de red o de CD se abre cada vez: no queda tomada (el USB se
    /// puede expulsar) ni muerta si se desmonta; abrirla no toma el candado del caché (ronda 2).
    fn root(drive: u8) -> io::Result<Arc<File>> {
        type Roots = HashMap<u8, (Vec<u16>, Option<Arc<File>>)>;
        static ROOTS: OnceLock<Mutex<Roots>> = OnceLock::new();
        let open = || -> io::Result<Arc<File>> {
            #[cfg(test)]
            if SLOW_ROOT.load(std::sync::atomic::Ordering::Relaxed) == drive {
                std::thread::sleep(std::time::Duration::from_millis(1500));
            }
            let f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(format!("{}:\\", drive as char))?;
            Ok(Arc::new(f))
        };
        let target = dos_device(drive)?;
        let roots = ROOTS.get_or_init(|| Mutex::new(HashMap::new()));
        // Ronda 2 (R2-B3): el candado sólo para mirar y guardar; la apertura y `GetDriveTypeW` van sin
        // él (en una unidad de red tardan lo que tarde el servidor, y frenaban las aperturas en `C:`).
        let known = match roots.lock().unwrap_or_else(|p| p.into_inner()).get(&drive) {
            Some((t, cached)) if *t == target => Some(cached.clone()),
            _ => None,
        };
        match known {
            Some(Some(f)) => Ok(f),
            Some(None) => open(),
            None => {
                let root_w: Vec<u16> = format!("{}:\\", drive as char).encode_utf16().chain(Some(0)).collect();
                // SAFETY: `root_w` es una cadena UTF-16 terminada en cero que vive durante la llamada.
                let fixed = unsafe { GetDriveTypeW(root_w.as_ptr()) } == DRIVE_FIXED;
                let f = open()?;
                // Ronda 3 (N2): si la letra cambió de destino mientras se abría, este handle no es el
                // de `target`: se usa una vez (el chequeo de después lo juzga) pero no se guarda.
                if dos_device(drive).ok().as_ref() != Some(&target) {
                    return Ok(f);
                }
                // Dos hilos que llegan juntos abren los dos; queda el último, y el otro handle se
                // cierra al soltarse su `Arc`.
                roots.lock().unwrap_or_else(|p| p.into_inner()).insert(drive, (target, fixed.then(|| f.clone())));
                Ok(f)
            }
        }
    }

    /// La raíz de esta letra tarda en abrirse (como una unidad de red lenta): el test de R2-B3.
    #[cfg(test)]
    pub(super) static SLOW_ROOT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

    /// El destino de la letra en el object manager (`\Device\HarddiskVolume3`, `\??\C:\carpeta` de un
    /// `subst`).
    fn dos_device(drive: u8) -> io::Result<Vec<u16>> {
        let name: Vec<u16> = format!("{}:", drive as char).encode_utf16().chain(Some(0)).collect();
        let mut buf = vec![0u16; 1024];
        // SAFETY: `name` está terminada en cero y `buf` tiene `buf.len()` u16 escribibles.
        let n = unsafe { QueryDosDeviceW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(n as usize);
        Ok(buf)
    }

    fn access(how: OpenFor) -> u32 {
        let mut a = SYNCHRONIZE | FILE_READ_ATTRIBUTES;
        if how.read {
            a |= FILE_GENERIC_READ;
        }
        if how.write {
            a |= FILE_GENERIC_WRITE;
        }
        if how.append {
            // Como la std: escribir sólo al final (sin FILE_WRITE_DATA).
            a |= FILE_APPEND_DATA | (FILE_GENERIC_WRITE & !windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA);
        }
        a
    }

    /// `NtCreateFile` de `name` relativo a `dir`, sin seguir ningún reparse point.
    fn nt_open(dir: HANDLE, name: &str, how: OpenFor, create_new: bool) -> Result<File, Nf> {
        let disposition = match (how.create, create_new) {
            (_, true) => FILE_CREATE,
            (true, false) => FILE_OPEN_IF,
            (false, false) => FILE_OPEN,
        };
        nt_create(dir, name, access(how), disposition, FILE_NON_DIRECTORY_FILE)
    }

    fn nt_create(dir: HANDLE, name: &str, access: u32, disposition: u32, kind: u32) -> Result<File, Nf> {
        let wide: Vec<u16> = name.encode_utf16().collect();
        let bytes = u16::try_from(wide.len() * 2).map_err(|_| Nf::Unsupported)?;
        let us = UNICODE_STRING { Length: bytes, MaximumLength: bytes, Buffer: wide.as_ptr() as *mut u16 };
        let oa = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: dir,
            ObjectName: &us,
            Attributes: (OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE) as u32,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut h: HANDLE = 0;
        // SAFETY: `IO_STATUS_BLOCK` es POD (una unión de un NTSTATUS y un puntero, más un usize):
        // todo en cero es un valor válido, y NtCreateFile lo escribe.
        let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        // SAFETY: `oa`, `us` y `wide` viven hasta que vuelve la llamada; `dir` es un handle abierto
        // de una carpeta (la raíz cacheada o una carpeta abierta por el llamador); los punteros
        // nulos son opcionales según la documentación de NtCreateFile.
        let status = unsafe {
            NtCreateFile(
                &mut h,
                access,
                &oa,
                &mut iosb,
                std::ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                disposition,
                kind | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null(),
                0,
            )
        };
        if status == STATUS_REPARSE_POINT_ENCOUNTERED {
            return Err(Nf::Link);
        }
        if status < 0 {
            // SAFETY: función pura de ntdll, sin punteros.
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(Nf::Io(io::Error::from_raw_os_error(code as i32)));
        }
        // SAFETY: NtCreateFile devolvió éxito: `h` es un handle de archivo nuevo, de nadie más.
        Ok(unsafe { File::from_raw_handle(h as _) })
    }

    /// La raíz de la unidad y el resto de la ruta, para abrirla relativa a la raíz. Sólo una ruta de
    /// unidad local (`C:/…`); UNC y otras, como v0.6.45.
    fn under_root(abs: &str) -> Result<(Arc<File>, String), Nf> {
        let b = abs.as_bytes();
        if b.len() < 4 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'/' {
            return Err(Nf::Unsupported);
        }
        let rest = abs[3..].replace('/', "\\");
        if rest.is_empty() {
            return Err(Nf::Unsupported);
        }
        Ok((root(b[0].to_ascii_uppercase()).map_err(|_| Nf::Unsupported)?, rest))
    }

    pub(super) fn open_nofollow(abs: &str, how: OpenFor) -> Result<File, Nf> {
        let (dir, rest) = under_root(abs)?;
        nt_open(dir.as_raw_handle() as HANDLE, &rest, how, false)
    }

    pub(super) fn open_dir_nofollow(abs: &str) -> Result<File, Nf> {
        let (dir, rest) = under_root(abs)?;
        let access = SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE;
        nt_create(dir.as_raw_handle() as HANDLE, &rest, access, FILE_OPEN, FILE_DIRECTORY_FILE)
    }

    fn io(e: Nf) -> io::Error {
        match e {
            Nf::Io(e) => e,
            // Un reparse point con el nombre al azar del temporal: se prueba otro.
            Nf::Link => io::Error::from(io::ErrorKind::AlreadyExists),
            Nf::Unsupported => io::Error::other("cannot create the file relative to its folder"),
        }
    }

    pub(super) fn create_new_beneath(dir: &File, name: &str) -> io::Result<File> {
        // DELETE: el rename y la limpieza van por este handle.
        let access = SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_GENERIC_WRITE | DELETE;
        nt_create(dir.as_raw_handle() as HANDLE, name, access, FILE_CREATE, FILE_NON_DIRECTORY_FILE).map_err(io)
    }

    pub(super) fn copy_mode(_dir: &File, _name: &str, _to: &File) {}

    /// Renombra el archivo abierto a `name`, por el handle y con `RootDirectory` = la carpeta ya
    /// juzgada: el nombre es relativo a ella, no una ruta que se resuelva de nuevo. Va directo a
    /// `NtSetInformationFile`: `SetFileInformationByHandle` convierte un nombre relativo en una ruta
    /// del directorio ACTUAL. Primero con semántica POSIX (reemplaza aunque otro lo tenga abierto), y
    /// si el sistema de archivos no la tiene, el rename clásico; como la std.
    pub(super) fn rename_beneath(dir: &File, tmp_file: &File, _tmp: &str, name: &str) -> io::Result<()> {
        // FILE_INFORMATION_CLASS (ntifs.h); no están en windows-sys 0.52.
        const FILE_RENAME_INFORMATION: i32 = 10;
        const FILE_RENAME_INFORMATION_EX: i32 = 65;
        const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x1;
        const FILE_RENAME_FLAG_POSIX_SEMANTICS: u32 = 0x2;
        // STATUS_INVALID_PARAMETER / STATUS_INVALID_INFO_CLASS / STATUS_NOT_SUPPORTED: sin la Ex.
        const NO_EX: [i32; 3] = [0xC000000Du32 as i32, 0xC0000003u32 as i32, 0xC00000BBu32 as i32];
        let wide: Vec<u16> = name.encode_utf16().collect();
        let name_bytes = wide.len() * 2;
        let at = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        let size = (at + name_bytes).max(std::mem::size_of::<FILE_RENAME_INFO>());
        // u64: alineado para la estructura (tiene un HANDLE).
        let mut buf = vec![0u64; size.div_ceil(8)];
        let info = buf.as_mut_ptr() as *mut FILE_RENAME_INFO;
        let set = |flags: u32, class: i32| {
            // SAFETY: todo en cero es un IO_STATUS_BLOCK válido (ver `nt_create`).
            let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
            // SAFETY: `buf` tiene `size` bytes, alineado a 8, en cero; `info` apunta a su inicio y los
            // campos se escriben dentro de él; el nombre entra (se contó en `size`) y no lleva
            // terminador (va el largo). Los dos handles están abiertos.
            unsafe {
                (*info).Anonymous.Flags = flags;
                (*info).RootDirectory = dir.as_raw_handle() as HANDLE;
                (*info).FileNameLength = name_bytes as u32;
                std::ptr::copy_nonoverlapping(wide.as_ptr(), (info as *mut u8).add(at) as *mut u16, wide.len());
                NtSetInformationFile(tmp_file.as_raw_handle() as HANDLE, &mut iosb, info as *const _, size as u32, class)
            }
        };
        let mut status = set(FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS, FILE_RENAME_INFORMATION_EX);
        if NO_EX.contains(&status) {
            // `ReplaceIfExists` es el primer byte de la misma unión: 1 en `Flags` lo deja en verdadero.
            status = set(1, FILE_RENAME_INFORMATION);
        }
        if status < 0 {
            // SAFETY: función pura de ntdll, sin punteros.
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(())
    }

    pub(super) fn discard_beneath(_dir: &File, tmp_file: &File, _tmp: &str) {
        let info = FILE_DISPOSITION_INFO { DeleteFile: 1 };
        // SAFETY: `info` vive hasta que vuelve la llamada; el handle se abrió con DELETE.
        unsafe {
            SetFileInformationByHandle(
                tmp_file.as_raw_handle() as HANDLE,
                FileDispositionInfo,
                &info as *const _ as *const _,
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            );
        }
    }

    pub(super) fn mkdir_beneath(dir: &File, name: &str, _path: &str) -> io::Result<()> {
        // FILE_CREATE con OBJ_DONT_REPARSE: si el nombre ya existe (un link también) falla; el
        // handle de la carpeta nueva se cierra enseguida.
        let access = SYNCHRONIZE | FILE_LIST_DIRECTORY;
        nt_create(dir.as_raw_handle() as HANDLE, name, access, FILE_CREATE, FILE_DIRECTORY_FILE)
            .map(drop)
            .map_err(io)
    }

    pub(super) fn unlink_beneath(_dir: &File, _name: &str, path: &str) -> io::Result<()> {
        // Por handle haría falta `NtCreateFile` con `RootDirectory` y `FILE_FLAG_OPEN_REPARSE_POINT`;
        // en Windows no hay hijos aislados que cambien el link en el medio.
        super::remove_link(path)
    }

    pub(super) fn real_path(f: &File) -> Option<String> {
        let mut buf = vec![0u16; 512];
        loop {
            // SAFETY: `buf` es escribible con el largo que se pasa; el handle es de `f`, abierto.
            let n = unsafe {
                GetFinalPathNameByHandleW(f.as_raw_handle() as HANDLE, buf.as_mut_ptr(), buf.len() as u32, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)
            } as usize;
            if n == 0 {
                return None;
            }
            if n < buf.len() {
                buf.truncate(n);
                return Some(std::ffi::OsString::from_wide(&buf).to_string_lossy().into_owned());
            }
            buf.resize(n + 1, 0);
        }
    }

    pub(super) fn open_dir(path: &str) -> io::Result<File> {
        std::fs::OpenOptions::new().read(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(path)
    }

    /// Abre siguiendo links, sólo con acceso a los atributos: no toca los datos ni rompe oplocks.
    pub(super) fn open_path(abs: &str) -> io::Result<File> {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().access_mode(SYNCHRONIZE | FILE_READ_ATTRIBUTES).open(abs)
    }

    /// Reabre el mismo objeto con el acceso pedido.
    pub(super) fn reopen(f: &File, how: OpenFor) -> io::Result<File> {
        // SAFETY: el handle es de `f`, abierto; `ReOpenFile` devuelve uno nuevo (o INVALID_HANDLE_VALUE).
        let h = unsafe {
            ReOpenFile(f.as_raw_handle() as HANDLE, access(how), FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0)
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `h` es un handle nuevo y válido que nadie más posee.
        Ok(unsafe { File::from_raw_handle(h as _) })
    }

    pub(super) fn create_beneath(dir: &File, name: &str, how: OpenFor) -> Result<File, Nf> {
        nt_open(dir.as_raw_handle() as HANDLE, name, how, false)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod sys {
    use super::{Nf, OpenFor};
    use std::fs::File;
    use std::io;

    pub(super) fn open_nofollow(_abs: &str, _how: OpenFor) -> Result<File, Nf> {
        Err(Nf::Unsupported)
    }

    pub(super) fn real_path(_f: &File) -> Option<String> {
        None
    }

    pub(super) fn open_dir(path: &str) -> io::Result<File> {
        File::open(path)
    }

    // Sin `open_nofollow` no hay link que seguir: no se llaman.
    pub(super) fn open_path(_abs: &str) -> io::Result<File> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub(super) fn reopen(_f: &File, _how: OpenFor) -> io::Result<File> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub(super) fn create_beneath(_dir: &File, _name: &str, _how: OpenFor) -> Result<File, Nf> {
        Err(Nf::Unsupported)
    }

    pub(super) fn open_dir_nofollow(_abs: &str) -> Result<File, Nf> {
        Err(Nf::Unsupported)
    }

    // Sin `open_dir_nofollow` nunca hay un `Beneath`: estas no se llaman.
    pub(super) fn create_new_beneath(_dir: &File, _name: &str) -> io::Result<File> {
        Err(io::Error::other("unsupported"))
    }

    pub(super) fn copy_mode(_dir: &File, _name: &str, _to: &File) {}

    pub(super) fn rename_beneath(_dir: &File, _tmp_file: &File, _tmp: &str, _name: &str) -> io::Result<()> {
        Err(io::Error::other("unsupported"))
    }

    pub(super) fn discard_beneath(_dir: &File, _tmp_file: &File, _tmp: &str) {}

    pub(super) fn unlink_beneath(_dir: &File, _name: &str, path: &str) -> io::Result<()> {
        super::remove_link(path)
    }

    pub(super) fn mkdir_beneath(_dir: &File, _name: &str, path: &str) -> io::Result<()> {
        std::fs::create_dir(path)
    }
}

#[cfg(all(test, any(target_os = "linux", windows)))]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("synsema-e8-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn link_dir(target: &Path, link: &Path) {
        #[cfg(windows)]
        {
            let ok = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link.to_string_lossy().replace('/', "\\"))
                .arg(target.to_string_lossy().replace('/', "\\"))
                .output()
                .expect("mklink")
                .status
                .success();
            assert!(ok);
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    fn s(p: &Path) -> String {
        p.to_string_lossy().replace('\\', "/")
    }

    /// Ronda 3 (N3): sólo un link a carpeta se borra como carpeta. Una carpeta de verdad que apareció
    /// en lugar del link no (`delete_file` de una carpeta es un error), y el error de un link de
    /// archivo es el de `remove_file`.
    #[test]
    fn only_a_link_to_a_folder_is_removed_as_a_folder() {
        let d = tmp("rmlink");
        std::fs::create_dir_all(d.join("real")).unwrap();
        std::fs::create_dir_all(d.join("plain")).unwrap();
        std::fs::write(d.join("f.txt"), "x").unwrap();
        link_dir(&d.join("real"), &d.join("j"));
        let md = |p: &str| std::fs::symlink_metadata(d.join(p)).ok();
        assert_eq!(is_dir_link(md("j")), cfg!(windows));
        assert!(!is_dir_link(md("plain")) && !is_dir_link(md("f.txt")) && !is_dir_link(md("nada")));
        assert!(remove_link(&s(&d.join("plain"))).is_err(), "una carpeta de verdad no se borra");
        assert!(d.join("plain").exists());
        remove_link(&s(&d.join("j"))).unwrap();
        assert!(std::fs::symlink_metadata(d.join("j")).is_err() && d.join("real").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn without_a_link_it_opens_and_does_not_recheck() {
        let d = tmp("plain");
        std::fs::write(d.join("a.txt"), "hola").unwrap();
        let calls = RefCell::new(0);
        let mut f = open_checked::<()>(&s(&d.join("a.txt")), OpenFor::READ, &|_| {
            *calls.borrow_mut() += 1;
            Ok(())
        })
        .unwrap();
        let mut t = String::new();
        f.read_to_string(&mut t).unwrap();
        assert_eq!((t.as_str(), *calls.borrow()), ("hola", 0));
        assert!(matches!(open_checked::<()>(&s(&d.join("no.txt")), OpenFor::READ, &|_| Ok(())), Err(Refused::Io(e)) if e.kind() == io::ErrorKind::NotFound));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn through_a_link_the_real_place_is_judged() {
        let d = tmp("link");
        std::fs::create_dir_all(d.join("real")).unwrap();
        std::fs::write(d.join("real/f.txt"), "x").unwrap();
        link_dir(&d.join("real"), &d.join("j"));
        let seen = RefCell::new(Vec::new());
        let judge = |real: &str| {
            seen.borrow_mut().push(real.replace('\\', "/"));
            Ok::<(), ()>(())
        };
        open_checked(&s(&d.join("j/f.txt")), OpenFor::READ, &judge).unwrap();
        // Crear a través del link: se juzga la carpeta real + el nombre, y el archivo queda ahí.
        let mut f = open_checked(&s(&d.join("j/nuevo.txt")), OpenFor::APPEND, &judge).unwrap();
        f.write_all(b"y").unwrap();
        drop(f);
        assert_eq!(std::fs::read_to_string(d.join("real/nuevo.txt")).unwrap(), "y");
        let seen = seen.borrow();
        assert_eq!(seen.len(), 2, "{:?}", seen);
        assert!(seen[0].ends_with("/real/f.txt") && seen[1].ends_with("/real/nuevo.txt"), "{:?}", seen);
        assert!(matches!(open_checked(&s(&d.join("j/f.txt")), OpenFor::READ, &|_| Err("no")), Err(Refused::Denied("no"))));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La carrera: el chequeo vio `d/sub` como carpeta de verdad; antes de abrir, alguien la cambia
    /// por un link a otro lado. Lo que se juzga es dónde quedó el handle, y se niega.
    #[test]
    fn a_link_swapped_after_the_check_is_judged_where_it_leads() {
        let d = tmp("race");
        std::fs::create_dir_all(d.join("proj/sub")).unwrap();
        std::fs::create_dir_all(d.join("afuera")).unwrap();
        std::fs::write(d.join("proj/sub/f.txt"), "adentro").unwrap();
        std::fs::write(d.join("afuera/f.txt"), "SECRETO").unwrap();
        let path = s(&d.join("proj/sub/f.txt"));
        // (el chequeo pasa acá) … y entonces:
        std::fs::remove_dir_all(d.join("proj/sub")).unwrap();
        link_dir(&d.join("afuera"), &d.join("proj/sub"));
        let inside = |real: &str| if real.replace('\\', "/").contains("/proj/") { Ok(()) } else { Err(real.to_string()) };
        match open_checked(&path, OpenFor::READ, &inside) {
            Err(Refused::Denied(real)) => assert!(real.replace('\\', "/").ends_with("/afuera/f.txt"), "{}", real),
            Ok(mut f) => {
                let mut t = String::new();
                f.read_to_string(&mut t).unwrap();
                panic!("abrió {:?}", t);
            }
            Err(Refused::Io(e)) => panic!("{}", e),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// v0.6.46 (E8): lo que cuesta abrir así contra la apertura de antes. Correr con
    /// `cargo test --release -p synsema-capabilities --lib open_cost -- --ignored --nocapture`.
    /// Ronda 1 (E8-B2): por un link, lo de afuera del grant se juzga ANTES de abrirlo con el acceso
    /// pedido: un FIFO de afuera se niega en vez de bloquear la lectura para siempre.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_fifo_outside_is_judged_before_it_is_opened() {
        let d = tmp("fifo");
        rustix::fs::mknodat(rustix::fs::CWD, d.join("cola"), rustix::fs::FileType::Fifo, rustix::fs::Mode::from_raw_mode(0o600), 0).unwrap();
        std::os::unix::fs::symlink(d.join("cola"), d.join("link")).unwrap();
        let path = s(&d.join("link"));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = open_checked::<&str>(&path, OpenFor::READ, &|_| Err("afuera"));
            let _ = tx.send(matches!(r, Err(Refused::Denied("afuera"))));
        });
        let denied = rx.recv_timeout(std::time::Duration::from_secs(5));
        // Si quedó bloqueado, se destraba abriendo el otro extremo.
        if denied.is_err() {
            let _ = std::fs::OpenOptions::new().write(true).open(d.join("cola"));
        }
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(denied, Ok(true), "la apertura bloqueó (o no se negó) antes de juzgar");
    }

    /// Ronda 1 (E8-M5): una letra que cambia de destino (`subst`) se abre en el destino nuevo, el que
    /// juzgó el chequeo. Con la raíz en caché sin validar se abría en la carpeta de antes.
    #[cfg(windows)]
    #[test]
    fn a_remapped_drive_letter_opens_where_it_points_now() {
        let d = tmp("subst");
        std::fs::create_dir_all(d.join("a")).unwrap();
        std::fs::create_dir_all(d.join("b")).unwrap();
        std::fs::write(d.join("a/f.txt"), "DE_A").unwrap();
        std::fs::write(d.join("b/f.txt"), "DE_B").unwrap();
        let subst = |args: &[&str]| std::process::Command::new("subst").args(args).output().map(|o| o.status.success()).unwrap_or(false);
        let win = |p: &std::path::Path| p.to_string_lossy().replace('/', "\\");
        // Una letra libre (sin destino en el object manager).
        let Some(letter) = (b'M'..=b'Y').rev().map(|c| c as char).find(|c| !std::path::Path::new(&format!("{}:\\", c)).exists()) else {
            eprintln!("sin letra libre: no se prueba");
            return;
        };
        let drive = format!("{}:", letter);
        struct Quita(String);
        impl Drop for Quita {
            fn drop(&mut self) {
                let _ = std::process::Command::new("subst").args([self.0.as_str(), "/d"]).output();
            }
        }
        let _quita = Quita(drive.clone());
        assert!(subst(&[&drive, &win(&d.join("a"))]), "subst");
        let read = || {
            let mut t = String::new();
            open_checked::<()>(&format!("{}/f.txt", drive), OpenFor::READ, &|_| Ok(())).unwrap().read_to_string(&mut t).unwrap();
            t
        };
        assert_eq!(read(), "DE_A");
        assert!(subst(&[&drive, "/d"]));
        assert!(subst(&[&drive, &win(&d.join("b"))]), "subst");
        assert_eq!(read(), "DE_B", "se abrió en el destino viejo de la letra");
        drop(_quita);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ronda 2 (R2-B3): mientras una letra tarda en abrir su raíz (una unidad de red lenta), una
    /// apertura en otra unidad no la espera. Antes la raíz se abría con el candado del caché tomado.
    #[cfg(windows)]
    #[test]
    fn a_slow_drive_does_not_hold_the_others() {
        let d = tmp("slowroot");
        std::fs::create_dir_all(d.join("a")).unwrap();
        std::fs::write(d.join("a/f.txt"), "DE_A").unwrap();
        std::fs::write(d.join("g.txt"), "AQUI").unwrap();
        let read = |p: &str| {
            let mut t = String::new();
            open_checked::<()>(p, OpenFor::READ, &|_| Ok(())).unwrap().read_to_string(&mut t).unwrap();
            t
        };
        let here = s(&d.join("g.txt"));
        assert_eq!(read(&here), "AQUI");
        // Otro rango de letras que el test de `subst` de arriba: corren en paralelo.
        let Some(letter) = (b'G'..=b'L').rev().find(|c| !std::path::Path::new(&format!("{}:\\", *c as char)).exists()) else {
            eprintln!("sin letra libre: no se prueba");
            return;
        };
        let drive = format!("{}:", letter as char);
        struct Quita(String);
        impl Drop for Quita {
            fn drop(&mut self) {
                sys::SLOW_ROOT.store(0, std::sync::atomic::Ordering::Relaxed);
                let _ = std::process::Command::new("subst").args([self.0.as_str(), "/d"]).output();
            }
        }
        let _quita = Quita(drive.clone());
        let ok = std::process::Command::new("subst")
            .args([drive.as_str(), &d.join("a").to_string_lossy().replace('/', "\\")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        assert!(ok, "subst");
        sys::SLOW_ROOT.store(letter, std::sync::atomic::Ordering::Relaxed);
        let far = format!("{}/f.txt", drive);
        let slow = std::thread::spawn(move || read(&far));
        std::thread::sleep(std::time::Duration::from_millis(300));
        let t = std::time::Instant::now();
        assert_eq!(read(&here), "AQUI");
        let waited = t.elapsed();
        assert_eq!(slow.join().unwrap(), "DE_A");
        assert!(waited < std::time::Duration::from_millis(900), "la otra unidad esperó {:?}", waited);
        drop(_quita);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    #[ignore]
    fn open_cost() {
        let d = tmp("cost");
        std::fs::create_dir_all(d.join("data/a/b/c/e")).unwrap();
        std::fs::write(d.join("data/x.txt"), "hola\n").unwrap();
        std::fs::write(d.join("data/a/b/c/e/x.txt"), "hola\n").unwrap();
        link_dir(&d.join("data"), &d.join("j"));
        let n = 1000;
        let time = |f: &dyn Fn()| {
            let t = std::time::Instant::now();
            for _ in 0..n {
                f();
            }
            t.elapsed().as_secs_f64() / n as f64 * 1e6
        };
        let read_std = |p: &str| std::hint::black_box(std::fs::read_to_string(p).unwrap());
        let read_e8 = |p: &str| {
            let mut t = String::new();
            open_checked::<()>(p, OpenFor::READ, &|_| Ok(())).unwrap().read_to_string(&mut t).unwrap();
            std::hint::black_box(t)
        };
        for (name, p) in [
            ("depth 1", s(&d.join("data/x.txt"))),
            ("depth 5", s(&d.join("data/a/b/c/e/x.txt"))),
            ("junction depth 1", s(&d.join("j/x.txt"))),
        ] {
            // Alternados, el mejor de 7 lotes de cada lado (el disco y el antivirus meten ruido).
            let (mut a, mut b) = (f64::MAX, f64::MAX);
            for _ in 0..7 {
                a = a.min(time(&|| {
                    read_std(&p);
                }));
                b = b.min(time(&|| {
                    read_e8(&p);
                }));
            }
            println!("{:<18} std {:>6.1} us | open_checked {:>6.1} us", name, a, b);
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}

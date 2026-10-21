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

/// Hay un link en el camino: abrir siguiendo, sin efectos, y juzgar dónde quedó el handle.
fn through_link<E>(abs: &str, how: OpenFor, recheck: &dyn Fn(&str) -> Result<(), E>) -> Result<File, Refused<E>> {
    let existing = std::fs::OpenOptions::new().read(how.read).write(how.write).append(how.append).open(abs);
    match existing {
        Ok(f) => {
            let real = sys::real_path(&f).ok_or_else(|| Refused::Io(io::Error::other("cannot tell where the open file is")))?;
            recheck(&real).map_err(Refused::Denied)?;
            Ok(f)
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
            // Sin `openat2` (kernel < 5.6, o el seccomp de un contenedor viejo).
            rustix::io::Errno::NOSYS => Nf::Unsupported,
            e => Nf::Io(io::Error::from_raw_os_error(e.raw_os_error())),
        }
    }

    pub(super) fn open_nofollow(abs: &str, how: OpenFor) -> Result<File, Nf> {
        // `openat2`, a diferencia de `openat`, da EINVAL con un modo distinto de cero sin O_CREAT.
        let mode = if how.create { Mode::from_raw_mode(0o666) } else { Mode::empty() };
        rustix::fs::openat2(CWD, abs, flags(how), mode, ResolveFlags::NO_SYMLINKS)
            .map(File::from)
            .map_err(map)
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
        rustix::fs::openat2(CWD, abs, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty(), ResolveFlags::NO_SYMLINKS)
            .map(File::from)
            .map_err(map)
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
    use std::sync::{Mutex, OnceLock};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        NtCreateFile, NtSetInformationFile, FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Wdk::Storage::FileSystem::FILE_DIRECTORY_FILE;
    use windows_sys::Win32::Foundation::{
        RtlNtStatusToDosError, HANDLE, STATUS_REPARSE_POINT_ENCOUNTERED, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, GetFinalPathNameByHandleW, SetFileInformationByHandle,
        DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
        FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
        VOLUME_NAME_DOS,
    };
    use windows_sys::Win32::System::Kernel::{OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE};
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    /// El handle de la raíz de cada unidad (`C:\`), abierto una vez: la ruta se abre RELATIVA a él,
    /// así el nombre no pasa por `\??\C:` (un link del object manager que `OBJ_DONT_REPARSE`
    /// también rechazaría).
    fn root(drive: u8) -> io::Result<HANDLE> {
        static ROOTS: OnceLock<Mutex<HashMap<u8, File>>> = OnceLock::new();
        let mut m = ROOTS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap_or_else(|p| p.into_inner());
        if let Some(f) = m.get(&drive) {
            return Ok(f.as_raw_handle() as HANDLE);
        }
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(format!("{}:\\", drive as char))?;
        let h = f.as_raw_handle() as HANDLE;
        m.insert(drive, f);
        Ok(h)
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
    fn under_root(abs: &str) -> Result<(HANDLE, String), Nf> {
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
        nt_open(dir, &rest, how, false)
    }

    pub(super) fn open_dir_nofollow(abs: &str) -> Result<File, Nf> {
        let (dir, rest) = under_root(abs)?;
        let access = SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE;
        nt_create(dir, &rest, access, FILE_OPEN, FILE_DIRECTORY_FILE)
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

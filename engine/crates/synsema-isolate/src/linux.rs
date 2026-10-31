//! Linux: Landlock (syscalls directas) + seccomp (`seccompiler`) + rlimits + grupo de procesos.
//!
//! Todo lo que reserva memoria o puede fallar por una ruta se hace en el padre (`prepare`). El
//! cierre de `pre_exec` corre entre `fork` y `exec` de un proceso con varios hilos: ahí sólo hay
//! syscalls sobre valores ya armados (sin `malloc`, sin locks).

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    TargetArch,
};

use crate::{Error, Pin, Place, Policy, Report, MIN_LANDLOCK_ABI};

// ---------------------------------------------------------------------------------------------
// Landlock (include/uapi/linux/landlock.h)
// ---------------------------------------------------------------------------------------------

const CREATE_RULESET_VERSION: u32 = 1 << 0;
const RULE_PATH_BENEATH: u32 = 1;

const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_MAKE_SOCK: u64 = 1 << 9;
const FS_MAKE_FIFO: u64 = 1 << 10;
const FS_MAKE_BLOCK: u64 = 1 << 11;
const FS_MAKE_SYM: u64 = 1 << 12;
const FS_REFER: u64 = 1 << 13; // ABI 2
const FS_TRUNCATE: u64 = 1 << 14; // ABI 3
const FS_IOCTL_DEV: u64 = 1 << 15; // ABI 5

const NET_BIND_TCP: u64 = 1 << 0; // ABI 4
const NET_CONNECT_TCP: u64 = 1 << 1; // ABI 4

const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0; // ABI 6
const SCOPE_SIGNAL: u64 = 1 << 1; // ABI 6

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Los derechos de archivos que maneja un ABI (todo lo que no se concede, queda prohibido).
fn fs_handled(abi: u32) -> u64 {
    let mut a = FS_EXECUTE // ABI 1
        | FS_WRITE_FILE
        | FS_READ_FILE
        | FS_READ_DIR
        | FS_REMOVE_DIR
        | FS_REMOVE_FILE
        | FS_MAKE_CHAR
        | FS_MAKE_DIR
        | FS_MAKE_REG
        | FS_MAKE_SOCK
        | FS_MAKE_FIFO
        | FS_MAKE_BLOCK
        | FS_MAKE_SYM;
    if abi >= 2 {
        a |= FS_REFER;
    }
    if abi >= 3 {
        a |= FS_TRUNCATE;
    }
    if abi >= 5 {
        a |= FS_IOCTL_DEV;
    }
    a
}

const READ_DIR_RIGHTS: u64 = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR;
const READ_FILE_RIGHTS: u64 = FS_EXECUTE | FS_READ_FILE;
/// Una carpeta de escritura: todo menos crear dispositivos, FIFOs y sockets, e `ioctl` sobre
/// dispositivos. Una FIFO que el hijo deja en su salida cuelga al padre que la lee (el `open` espera
/// un escritor que ya no existe); un socket sin `socket()` no le sirve de nada.
const WRITE_DIR_RIGHTS: u64 = FS_EXECUTE
    | FS_WRITE_FILE
    | FS_READ_FILE
    | FS_READ_DIR
    | FS_REMOVE_DIR
    | FS_REMOVE_FILE
    | FS_MAKE_DIR
    | FS_MAKE_REG
    | FS_MAKE_SYM
    | FS_REFER
    | FS_TRUNCATE;
const WRITE_FILE_RIGHTS: u64 = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE;

/// Las carpetas del sistema con programas, bibliotecas y configuración pública (certificados,
/// zona horaria, `ld.so.cache`). Lectura y ejecución. Nada de `/home`, `/root`, `/proc`, `/sys`,
/// `/run` ni `/var`: ahí viven las claves y los sockets de otros procesos.
const SYSTEM_READ: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/opt"];

pub fn landlock_abi() -> Option<u32> {
    // SAFETY: la consulta de versión no lee el puntero (NULL, tamaño 0).
    let r = unsafe {
        libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<RulesetAttr>(), 0usize, CREATE_RULESET_VERSION)
    };
    (r >= 1).then_some(r as u32)
}

fn create_ruleset(abi: u32) -> Result<OwnedFd, Error> {
    let attr = RulesetAttr {
        handled_access_fs: fs_handled(abi),
        // Sin reglas de puerto: ningún `bind`/`connect` TCP (seccomp además niega `socket()`).
        handled_access_net: if abi >= 4 { NET_BIND_TCP | NET_CONNECT_TCP } else { 0 },
        scoped: if abi >= 6 { SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL } else { 0 },
    };
    // SAFETY: `attr` vive durante la llamada; el kernel copia `size_of` bytes.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if fd < 0 {
        return Err(Error::Os(format!("isolate: landlock_create_ruleset: {}", io::Error::last_os_error())));
    }
    // SAFETY: el kernel devolvió un fd nuevo (con O_CLOEXEC) que es nuestro.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Abre `path` con `O_PATH` (sigue links; no lee el contenido).
fn open_path(path: &Path) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `c` es una cadena C válida; O_PATH no lee el contenido.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd recién abierto, nuestro.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// ¿El fd es una carpeta? (`fstat`: `O_PATH` lo permite.)
fn fd_is_dir(fd: &OwnedFd) -> io::Result<bool> {
    // SAFETY: `st` es un buffer del tamaño de `stat`; el kernel lo llena.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

pub fn pin(path: &Path) -> io::Result<Pin> {
    let fd = open_path(path)?;
    // La ruta del inodo abierto, según el kernel (el padre sí tiene `/proc`).
    let real = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
    let is_dir = fd_is_dir(&fd)?;
    Ok(Pin { place: Place::Pinned(std::sync::Arc::new(fd)), real, is_dir })
}

pub fn exited(pid: u32) -> crate::ChildState {
    // SAFETY: `info` es un buffer de `siginfo_t`; WNOWAIT no recoge al hijo.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT)
    };
    if r != 0 {
        // ECHILD: nadie que esperar (con `SIGCHLD` ignorado el kernel lo recogió solo).
        return crate::ChildState::Gone;
    }
    // SAFETY: con WNOHANG, `si_pid` queda en 0 si el hijo sigue vivo.
    if unsafe { info.si_pid() } != 0 {
        crate::ChildState::Exited
    } else {
        crate::ChildState::Running
    }
}

/// Una regla para `place` con los derechos de carpeta o de archivo, según lo que sea.
fn add_place_rule(ruleset: &OwnedFd, place: &Place, dir_rights: u64, file_rights: u64, handled: u64) -> Result<(), Error> {
    let opened;
    let (fd, shown): (&OwnedFd, String) = match place {
        Place::Path(p) => {
            check_absolute(p)?;
            opened = open_path(p).map_err(|e| Error::Path(format!("isolate: cannot open {}: {}", p.display(), e)))?;
            (&opened, p.display().to_string())
        }
        Place::Pinned(fd) => (fd, format!("fd {}", fd.as_raw_fd())),
    };
    let is_dir = fd_is_dir(fd).map_err(|e| Error::Path(format!("isolate: {}: {}", shown, e)))?;
    add_fd_rule(ruleset, fd, &shown, if is_dir { dir_rights } else { file_rights }, handled)
}

fn add_path_rule(ruleset: &OwnedFd, path: &Path, rights: u64, handled: u64) -> Result<(), Error> {
    let fd = open_path(path).map_err(|e| Error::Path(format!("isolate: cannot open {}: {}", path.display(), e)))?;
    add_fd_rule(ruleset, &fd, &path.display().to_string(), rights, handled)
}

fn add_fd_rule(ruleset: &OwnedFd, fd: &OwnedFd, shown: &str, rights: u64, handled: u64) -> Result<(), Error> {
    let attr = PathBeneathAttr { allowed_access: rights & handled, parent_fd: fd.as_raw_fd() };
    // SAFETY: `attr` vive durante la llamada.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            &attr as *const PathBeneathAttr,
            0u32,
        )
    };
    if r < 0 {
        return Err(Error::Os(format!("isolate: landlock_add_rule {}: {}", shown, io::Error::last_os_error())));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// seccomp
// ---------------------------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;
#[cfg(target_arch = "riscv64")]
const ARCH: TargetArch = TargetArch::riscv64;

/// Lo que el hijo no puede llamar (EPERM): depurar o leer la memoria de otros, montar, namespaces,
/// módulos y `kexec`, BPF, `io_uring` (otra puerta a las syscalls), llaves del kernel, abrir por
/// handle, `setsid`/`setpgid` (saldría del grupo que se mata entero) y `socket()` (sin red ni
/// sockets UNIX: `docker.sock`, dbus). `socketpair` sigue (no sale del proceso).
fn denied_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_userfaultfd,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        libc::SYS_acct,
        libc::SYS_quotactl,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_fanotify_init,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_fsconfig,
        libc::SYS_fspick,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_mount_setattr,
        libc::SYS_setsid,
        libc::SYS_setpgid,
        libc::SYS_socket,
        // El log del kernel (con `dmesg_restrict=0` lo lee cualquiera) y la tabla de montajes sin
        // `/proc` (`statmount`/`listmount`, Linux 6.8: el mismo número en todas las arquitecturas
        // desde la tabla unificada; `libc` 0.2 todavía no los nombra).
        libc::SYS_syslog,
        SYS_STATMOUNT,
        SYS_LISTMOUNT,
    ]
}

const SYS_STATMOUNT: i64 = 457;
const SYS_LISTMOUNT: i64 = 458;

/// Los valores de `personality` que deja pasar el perfil de Docker (`moby/profiles`,
/// `seccomp/default.json`): consultar (`0xffffffff`), el normal (`0`), `PER_LINUX32` (`0x8`),
/// `UNAME26` (`0x20000`) y los dos juntos (`0x20008`, `setarch i386 --uname-2.6`). Lo demás
/// (`ADDR_NO_RANDOMIZE`, sacar el ASLR) es EPERM.
const PERSONALITY_ALLOWED: [u64; 5] = [0x0, 0x8, 0x20000, 0x20008, 0xffff_ffff];

fn compile(f: Result<SeccompFilter, seccompiler::BackendError>) -> Result<BpfProgram, Error> {
    f.and_then(BpfProgram::try_from).map_err(|e| Error::Os(format!("isolate: seccomp filter: {}", e)))
}

fn filters() -> Result<Vec<BpfProgram>, Error> {
    let eperm = SeccompAction::Errno(libc::EPERM as u32);
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = denied_syscalls().into_iter().map(|n| (n, Vec::new())).collect();
    // `clone` con un flag de namespace (el `unshare` de `clone`). Un `clone` común sigue.
    let ns = [
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWNS,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWCGROUP,
    ];
    let mut clone_rules = Vec::new();
    for f in ns {
        let f = f as u64;
        let cond = SeccompCondition::new(0, SeccompCmpArgLen::Qword, SeccompCmpOp::MaskedEq(f), f)
            .map_err(|e| Error::Os(format!("isolate: seccomp: {}", e)))?;
        clone_rules.push(SeccompRule::new(vec![cond]).map_err(|e| Error::Os(format!("isolate: seccomp: {}", e)))?);
    }
    rules.insert(libc::SYS_clone, clone_rules);
    // Una regla con una condición por valor (todas deben valer): coincide, y da EPERM, si el valor no es
    // ninguno de los permitidos.
    let not_allowed = PERSONALITY_ALLOWED
        .iter()
        .map(|&v| SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, v))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::Os(format!("isolate: seccomp: {}", e)))?;
    rules.insert(
        libc::SYS_personality,
        vec![SeccompRule::new(not_allowed).map_err(|e| Error::Os(format!("isolate: seccomp: {}", e)))?],
    );
    let main = compile(SeccompFilter::new(rules, SeccompAction::Allow, eperm, ARCH))?;
    // `clone3` pasa los flags por puntero (seccomp no los ve): ENOSYS, y glibc vuelve a `clone`.
    let clone3 = compile(SeccompFilter::new(
        [(libc::SYS_clone3, Vec::new())].into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        ARCH,
    ))?;
    let mut out = vec![main, clone3];
    #[cfg(target_arch = "x86_64")]
    out.push(x32_filter());
    Ok(out)
}

/// x86_64: las syscalls x32 llevan el bit 30 en el número y la misma arquitectura de audit. Un
/// filtro por número no las ve: se niegan todas (ENOSYS).
#[cfg(target_arch = "x86_64")]
fn x32_filter() -> BpfProgram {
    use seccompiler::sock_filter;
    const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JSET_K: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
    const RET_K: u16 = 0x06; // BPF_RET | BPF_K
    const RET_ERRNO: u32 = 0x0005_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;
    vec![
        sock_filter { code: LD_W_ABS, jt: 0, jf: 0, k: 0 }, // seccomp_data.nr
        sock_filter { code: JSET_K, jt: 0, jf: 1, k: 0x4000_0000 },
        sock_filter { code: RET_K, jt: 0, jf: 0, k: RET_ERRNO | libc::ENOSYS as u32 },
        sock_filter { code: RET_K, jt: 0, jf: 0, k: RET_ALLOW },
    ]
}

// ---------------------------------------------------------------------------------------------
// prepare
// ---------------------------------------------------------------------------------------------

/// Lo que vive mientras corre el hijo: el ruleset (el hijo lo hereda hasta el `exec`) y su carpeta
/// temporal, que se borra al soltarlo.
pub struct Inner {
    _ruleset: OwnedFd,
    tmp: PathBuf,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn private_tmp() -> Result<PathBuf, Error> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = std::env::temp_dir().join(format!(
        "synsema-isolate-{}-{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| Error::Os(format!("isolate: cannot create the child's temporary folder {}: {}", dir.display(), e)))?;
    Ok(dir)
}

pub fn prepare(cmd: &mut Command, policy: &Policy) -> Result<(Report, Inner), Error> {
    let abi = match landlock_abi() {
        Some(a) if a >= MIN_LANDLOCK_ABI => a,
        found => {
            return Err(Error::Kernel(format!(
                "isolate needs Landlock ABI {} or newer (Linux 6.12+); this kernel {} — nothing ran, rather than run without isolation",
                MIN_LANDLOCK_ABI,
                match found {
                    Some(a) => format!("offers ABI {}", a),
                    None => "has Landlock off (it is in the kernel's `lsm=` list, CONFIG_SECURITY_LANDLOCK)".to_string(),
                }
            )))
        }
    };
    let handled = fs_handled(abi);
    let ruleset = create_ruleset(abi)?;
    for p in SYSTEM_READ.iter().map(Path::new).filter(|p| p.exists()) {
        add_path_rule(&ruleset, p, READ_DIR_RIGHTS, handled)?;
    }
    // Lo mínimo de /dev: tirar salida, ceros y entropía. Nada de /dev/tty ni de discos.
    for (dev, rights) in [
        ("/dev/null", FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE),
        ("/dev/zero", FS_READ_FILE),
        ("/dev/full", FS_READ_FILE | FS_WRITE_FILE),
        ("/dev/random", FS_READ_FILE),
        ("/dev/urandom", FS_READ_FILE),
    ] {
        if Path::new(dev).exists() {
            add_path_rule(&ruleset, Path::new(dev), rights, handled)?;
        }
    }
    for p in &policy.read {
        add_place_rule(&ruleset, p, READ_DIR_RIGHTS, READ_FILE_RIGHTS, handled)?;
    }
    for p in &policy.write {
        add_place_rule(&ruleset, p, WRITE_DIR_RIGHTS, WRITE_FILE_RIGHTS, handled)?;
    }
    let tmp = private_tmp()?;
    // En su carpeta temporal el hijo sí crea FIFOs (el jobserver de GNU make ≥ 4.4 vive ahí): el
    // padre nunca la abre y se borra al terminar.
    add_path_rule(&ruleset, &tmp, WRITE_DIR_RIGHTS | FS_MAKE_FIFO, handled)?;
    let progs = filters()?;

    // Entorno limpio: lo que el que llama agregue después (su `env`) va encima.
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
    let lang = std::env::var_os("LANG");
    cmd.env_clear();
    cmd.env("PATH", path).env("HOME", &tmp).env("TMPDIR", &tmp);
    if let Some(l) = lang {
        cmd.env("LANG", l);
    }

    let rs = ruleset.as_raw_fd();
    let mem = policy.max_memory_bytes;
    // SAFETY: el cierre corre entre fork y exec. Sólo hace syscalls con valores ya armados (el fd
    // del ruleset, los programas BPF, enteros); no reserva memoria ni toma locks.
    unsafe {
        cmd.pre_exec(move || {
            // Todo fd heredado de más (sin CLOEXEC) se cierra en el exec.
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0 {
                return Err(io::Error::last_os_error());
            }
            if let Some(b) = mem {
                let lim = libc::rlimit { rlim_cur: b as libc::rlim_t, rlim_max: b as libc::rlim_t };
                if libc::setrlimit(libc::RLIMIT_AS, &lim) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::syscall(libc::SYS_landlock_restrict_self, rs, 0u32) != 0 {
                return Err(io::Error::last_os_error());
            }
            for p in &progs {
                seccompiler::apply_filter(p).map_err(|_| io::Error::last_os_error())?;
            }
            Ok(())
        });
    }
    let report = Report { landlock_abi: abi, network: "none", max_memory_bytes: mem };
    Ok((report, Inner { _ruleset: ruleset, tmp }))
}

fn check_absolute(p: &Path) -> Result<(), Error> {
    if p.is_absolute() {
        Ok(())
    } else {
        Err(Error::Path(format!("isolate: {} is not an absolute path", p.display())))
    }
}

pub fn group_gone(pid: u32, wait: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + wait;
    let reaper = reaps_orphans();
    let proc = Proc::new(Path::new("/proc"));
    loop {
        if reaper {
            reap_group(pid);
        }
        // SAFETY: señal 0 a un grupo: sólo pregunta si existe; no toca memoria.
        let r = unsafe { libc::kill(-(pid as libc::pid_t), 0) };
        if r != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return true;
        }
        // Ronda 6 (M2): los que quedan pueden ser zombies que recoge otro proceso (o nadie: un
        // lanzador que sólo espera a su hijo, como el de npm siendo PID 1). Un zombie no corre nada.
        if proc.only_zombies(pid) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// Ronda 7 (B1): lo que dice un `/proc` (`root`; en los tests, uno armado) sobre un grupo.
struct Proc {
    root: PathBuf,
    /// ¿Es el de este espacio de pid? Si no, sus números no son los de `kill`.
    ours: bool,
}

impl Proc {
    fn new(root: &Path) -> Proc {
        Proc { root: root.to_path_buf(), ours: proc_is_ours(root) }
    }

    /// ¿El grupo `pgid` sólo tiene zombies? `false` si `/proc` no es el propio.
    fn only_zombies(&self, pgid: u32) -> bool {
        self.ours && only_zombies(&self.root, pgid)
    }
}

/// ¿`root` es el `/proc` de este espacio de pid? `NSpid` da el número de este proceso en cada
/// espacio, desde el de ese `/proc` hasta el suyo: si es uno solo, y es el de `getpid`, los números
/// de `/proc` son los de `kill`. Con el `/proc` de afuera (`unshare -p` sin montar el suyo) son dos;
/// con uno de otro espacio, `self` no existe.
fn proc_is_ours(root: &Path) -> bool {
    let Ok(status) = std::fs::read_to_string(root.join("self").join("status")) else {
        return false;
    };
    // SAFETY: getpid no toca memoria.
    let me = unsafe { libc::getpid() }.to_string();
    status
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:"))
        .is_some_and(|ns| ns.split_whitespace().eq([me.as_str()]))
}

/// ¿El grupo `pgid` sólo tiene zombies? Se mira en `root` cada hilo de cada proceso del grupo: un
/// proceso cuyo hilo principal terminó figura como zombie mientras sus otros hilos siguen. Sin
/// `/proc`, `false` (se sigue esperando a que el grupo desaparezca). Ya matado el grupo, nadie
/// entra en él: el kernel no deja terminar un `fork` con un SIGKILL pendiente.
///
/// Ronda 7 (B1): `kill` acaba de decir que el grupo existe; si `/proc` no muestra a nadie de él,
/// no es «sólo zombies» (otro `/proc`, uno a medias): `false`.
fn only_zombies(root: &Path, pgid: u32) -> bool {
    let Ok(procs) = std::fs::read_dir(root) else {
        return false;
    };
    let mut found = false;
    for p in procs.flatten() {
        let name = p.file_name();
        if !name.to_str().is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit())) {
            continue;
        }
        match stat_of(&p.path().join("stat")) {
            Some((_, pgrp)) if pgrp == pgid => {}
            _ => continue,
        }
        let Ok(tasks) = std::fs::read_dir(p.path().join("task")) else {
            continue;
        };
        found = true;
        for t in tasks.flatten() {
            if let Some((state, _)) = stat_of(&t.path().join("stat")) {
                if state != 'Z' && state != 'X' {
                    return false;
                }
            }
        }
    }
    found
}

/// El estado y el grupo de `/proc/<pid>/stat` (o de un hilo). El nombre va entre paréntesis y puede
/// tener espacios y paréntesis: se corta en el último `)`.
fn stat_of(path: &Path) -> Option<(char, u32)> {
    let s = std::fs::read_to_string(path).ok()?;
    let rest = &s[s.rfind(')')? + 1..];
    let mut f = rest.split_whitespace();
    let state = f.next()?.chars().next()?;
    let _ppid = f.next()?;
    let pgrp = f.next()?.parse().ok()?;
    Some((state, pgrp))
}

/// Ronda 5 (M3): ¿los huérfanos vienen a este proceso? Pasa siendo PID 1 (un contenedor sin
/// `--init`) o subreaper (`PR_SET_CHILD_SUBREAPER`, que se conserva en `execve`). Entonces los
/// nietos de un hijo aislado que murió son hijos nuestros: si no se recogen, quedan zombies en el
/// grupo y el grupo no se vacía nunca.
fn reaps_orphans() -> bool {
    // SAFETY: `getpid` no falla; `PR_GET_CHILD_SUBREAPER` escribe un `c_int` en `flag`.
    unsafe {
        if libc::getpid() == 1 {
            return true;
        }
        let mut flag: libc::c_int = 0;
        libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut flag as *mut libc::c_int) == 0 && flag != 0
    }
}

/// Recoge los zombies del grupo `pgid` que son hijos de este proceso: los nietos adoptados (y el
/// hijo, si nadie lo esperó). Se llama con el grupo ya matado, y el número del grupo no se reusa
/// mientras quede alguien en él.
fn reap_group(pgid: u32) {
    loop {
        // SAFETY: `info` es un buffer de `siginfo_t`; con WNOHANG, `si_pid` queda en 0 si no hay a
        // quién recoger.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::waitid(libc::P_PGID, pgid as libc::id_t, &mut info, libc::WEXITED | libc::WNOHANG) };
        if r != 0 || unsafe { info.si_pid() } == 0 {
            return;
        }
    }
}

pub fn default_sigchld() {
    // SAFETY: SIG_DFL no instala ningún handler; se llama antes de lanzar hilos.
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
    }
}

pub fn kill_group(pid: u32) {
    // SAFETY: kill sobre un número de grupo; no toca memoria.
    unsafe {
        libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ronda 7 (B1): con el `/proc` propio, un grupo que `/proc` no muestra no es «sólo zombies».
    #[test]
    fn a_group_nobody_is_in_is_not_only_zombies() {
        let proc = Proc::new(Path::new("/proc"));
        assert!(proc.ours);
        // `pid_max` no lo usa ningún proceso (los números van de 1 a `pid_max - 1`).
        let max: u32 = std::fs::read_to_string("/proc/sys/kernel/pid_max").unwrap().trim().parse().unwrap();
        assert!(!proc.only_zombies(max));
    }

    /// Ronda 7 (B1): un `/proc` armado, con un grupo 2 de sólo zombies. Si es de otro espacio de pid
    /// (`NSpid` con dos números, aunque el último sea el de este proceso) ese grupo 2 no es el
    /// nuestro; si es el propio, sí; un miembro vivo lo cambia.
    #[test]
    fn a_proc_of_another_pid_namespace_says_nothing_about_our_groups() {
        let root = std::env::temp_dir().join(format!("synsema-fakeproc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let me = std::process::id();
        let put = |rel: &str, text: &str| {
            let f = root.join(rel);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, text).unwrap();
        };
        put("5/stat", "5 (a b) c) Z 1 2 2 0");
        put("5/task/5/stat", "5 (a b) c) Z 1 2 2 0");
        put("self/status", &format!("Name:\tx\nNSpid:\t617\t{}\n", me));
        assert!(!Proc::new(&root).only_zombies(2), "otro espacio de pid");
        put("self/status", &format!("Name:\tx\nNSpid:\t{}\n", me));
        assert!(Proc::new(&root).only_zombies(2), "el propio: sólo zombies");
        put("6/stat", "6 (x) S 1 2 2 0");
        put("6/task/6/stat", "6 (x) S 1 2 2 0");
        assert!(!Proc::new(&root).only_zombies(2), "uno vivo");
        let _ = std::fs::remove_dir_all(&root);
    }
}

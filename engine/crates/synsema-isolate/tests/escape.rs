//! Sondas de escape (v0.6.52, `specs/aislamiento-procesos-propuesta.md` § 4). Cada test lanza este
//! mismo binario, aislado, en modo sonda (`probe_entry`): la sonda hace UNA cosa que el aislamiento
//! tiene que impedir (o permitir) y escribe `PROBE:<resultado>`, que es `ok` o el errno.
//!
//! Corren en Linux con Landlock ABI ≥ 6 (la WSL de desarrollo, 6.18). Sin eso, cada test comprueba
//! que `prepare` falla cerrado y termina.
#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use synsema_isolate::{exited, group_gone, kill_group, ChildState, landlock_abi, pin, prepare, Error, Place, Policy, MIN_LANDLOCK_ABI};

fn supported() -> bool {
    if landlock_abi().is_some_and(|a| a >= MIN_LANDLOCK_ABI) {
        return true;
    }
    let mut c = Command::new("/bin/true");
    assert!(matches!(prepare(&mut c, &Policy::default()), Err(Error::Kernel(_))), "sin ABI {} tiene que fallar cerrado", MIN_LANDLOCK_ABI);
    false
}

/// Una carpeta de prueba con `inside/` (para conceder), `outside/secret.txt` (nunca concedido) y
/// `out/` (para escribir).
struct Area {
    root: PathBuf,
}

impl Area {
    fn new(tag: &str) -> Area {
        let root = std::env::temp_dir().join(format!("synsema-isolate-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["inside", "outside", "out"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("inside/data.txt"), "datos").unwrap();
        std::fs::write(root.join("outside/secret.txt"), "secreto").unwrap();
        Area { root }
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
    fn s(&self, rel: &str) -> String {
        self.p(rel).to_string_lossy().into_owned()
    }
    fn policy(&self) -> Policy {
        Policy { read: vec![self.p("inside").into()], write: vec![self.p("out").into()], max_memory_bytes: None }
    }
}

impl Drop for Area {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Corre la sonda `what` con `arg` bajo `policy`. Devuelve lo que la sonda escribió tras `PROBE:`.
fn probe(policy: &Policy, what: &str, arg: &str) -> String {
    let exe = std::env::current_exe().unwrap();
    let mut pol = policy.clone();
    pol.read.push(exe.clone().into()); // el binario de la sonda tiene que poder ejecutarse
    let mut c = Command::new(&exe);
    c.args(["--exact", "probe_entry", "--nocapture", "--test-threads=1"]);
    let prepared = prepare(&mut c, &pol).expect("prepare");
    assert_eq!(prepared.report.network, "none");
    c.env("ISOLATE_PROBE", what).env("ISOLATE_ARG", arg).stdin(Stdio::null());
    let out = c.output().expect("spawn de la sonda");
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(probe_line)
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!("no-probe-line status={:?} stdout={} stderr={}", out.status, stdout, String::from_utf8_lossy(&out.stderr))
        })
}

/// Lo que sigue a `PROBE:` en una línea (libtest escribe `test probe_entry ... ` antes).
fn probe_line(l: &str) -> Option<&str> {
    l.split_once("PROBE:").map(|(_, r)| r)
}

fn errno_name(e: i32) -> String {
    match e {
        libc::EPERM => "EPERM".into(),
        libc::EACCES => "EACCES".into(),
        libc::ENOSYS => "ENOSYS".into(),
        libc::EXDEV => "EXDEV".into(),
        libc::ENOMEM => "ENOMEM".into(),
        libc::ENOENT => "ENOENT".into(),
        other => format!("errno{}", other),
    }
}

fn res(r: i64) -> String {
    if r < 0 {
        errno_name(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        "ok".into()
    }
}

fn io_res<T>(r: std::io::Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => errno_name(e.raw_os_error().unwrap_or(0)),
    }
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// El lado de adentro: sólo hace algo si lo lanzó `probe` (con `ISOLATE_PROBE`).
#[test]
fn probe_entry() {
    let Ok(what) = std::env::var("ISOLATE_PROBE") else { return };
    let arg = std::env::var("ISOLATE_ARG").unwrap_or_default();
    // SAFETY (todo el bloque): syscalls de prueba con punteros a valores locales vivos.
    let r: String = unsafe {
        match what.as_str() {
            "read" => io_res(std::fs::read(&arg)),
            "write" => io_res(std::fs::write(&arg, "x")),
            "list" => io_res(std::fs::read_dir(&arg)),
            "socket_tcp" => res(libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) as i64),
            "socket_udp" => res(libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) as i64),
            "socket_udp6" => res(libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) as i64),
            "socket_unix" => res(libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) as i64),
            "socket_netlink" => res(libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 0) as i64),
            "socketpair" => {
                let mut sv = [0i32; 2];
                res(libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) as i64)
            }
            "kill_parent" => res(libc::kill(libc::getppid(), 0) as i64),
            "ptrace_parent" => res(libc::ptrace(libc::PTRACE_ATTACH, libc::getppid(), 0, 0)),
            "unshare_user" => res(libc::unshare(libc::CLONE_NEWUSER) as i64),
            "clone_newuser" => {
                let r = libc::syscall(libc::SYS_clone, (libc::CLONE_NEWUSER | libc::SIGCHLD) as u64, 0u64, 0u64, 0u64, 0u64);
                if r == 0 {
                    libc::_exit(0);
                }
                res(r)
            }
            "parent_environ" => io_res(std::fs::read(format!("/proc/{}/environ", libc::getppid()))),
            "hardlink" => {
                let dst = format!("{}/hl", std::env::var("TMPDIR").unwrap());
                res(libc::link(cstr(&arg).as_ptr(), cstr(&dst).as_ptr()) as i64)
            }
            "symlink_read" => {
                let l = format!("{}/sl", std::env::var("TMPDIR").unwrap());
                let _ = std::os::unix::fs::symlink(&arg, &l);
                io_res(std::fs::read(&l))
            }
            "rename_out" => {
                // Sacar un archivo concedido para escribir hacia afuera.
                let (from, to) = arg.split_once('|').unwrap();
                res(libc::rename(cstr(from).as_ptr(), cstr(to).as_ptr()) as i64)
            }
            "truncate" => res(libc::truncate(cstr(&arg).as_ptr(), 0) as i64),
            "setsid" => res(libc::setsid() as i64),
            "io_uring" => {
                let mut params = [0u8; 120];
                res(libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()))
            }
            #[cfg(target_arch = "x86_64")]
            "x32" => res(libc::syscall(libc::SYS_getpid | 0x4000_0000)),
            "syslog" => {
                let mut buf = [0u8; 256];
                res(libc::klogctl(3, buf.as_mut_ptr() as *mut libc::c_char, buf.len() as i32) as i64)
            }
            // ADDR_NO_RANDOMIZE: sacarse el ASLR.
            "personality_aslr" => res(libc::personality(0x0040000) as i64),
            "personality_query" => res(libc::personality(0xffff_ffff) as i64),
            "personality_linux32_uname26" => res(libc::personality(0x20008) as i64),
            "mkfifo" => res(libc::mkfifo(cstr(&arg).as_ptr(), 0o600) as i64),
            "mkfifo_tmp" => {
                let at = format!("{}/fifo", std::env::var("TMPDIR").unwrap());
                res(libc::mkfifo(cstr(&at).as_ptr(), 0o600) as i64)
            }
            "mknod_sock" => res(libc::mknod(cstr(&arg).as_ptr(), libc::S_IFSOCK | 0o600, 0) as i64),
            "mkdir" => res(libc::mkdir(cstr(&arg).as_ptr(), 0o700) as i64),
            "symlink" => {
                let (to, at) = arg.split_once('|').unwrap();
                res(libc::symlink(cstr(to).as_ptr(), cstr(at).as_ptr()) as i64)
            }
            "tmp_write" => io_res(std::fs::write(format!("{}/f", std::env::var("TMPDIR").unwrap()), "x")),
            "env" => {
                let mut keys: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
                keys.sort();
                keys.join(",")
            }
            "mmap_mb" => {
                let n: usize = arg.parse::<usize>().unwrap() * 1024 * 1024;
                let p = libc::mmap(std::ptr::null_mut(), n, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
                if p == libc::MAP_FAILED { errno_name(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)) } else { "ok".into() }
            }
            "grandchild" => {
                // Un nieto que queda vivo: imprime su pid y la sonda termina.
                let child = Command::new("/bin/sleep").arg("300").stdout(Stdio::null()).spawn().unwrap();
                child.id().to_string()
            }
            "live_group" => {
                // Ronda 7 (B1): un grupo vivo, sin matar, y después muerto.
                use std::os::unix::process::CommandExt;
                let mut child = Command::new("/bin/sleep").arg("30").process_group(0).stdout(Stdio::null()).spawn().unwrap();
                let pid = child.id();
                let alive = group_gone(pid, std::time::Duration::from_millis(200));
                kill_group(pid);
                child.wait().unwrap();
                let dead = group_gone(pid, std::time::Duration::from_secs(5));
                format!("vivo={} muerto={}", alive, dead)
            }
            other => format!("unknown probe {}", other),
        }
    };
    // Directo a stdout: `println!` pasa por la captura de libtest y el `exit` la descarta.
    use std::io::Write;
    let mut o = std::io::stdout();
    let _ = writeln!(o, "PROBE:{}", r);
    let _ = o.flush();
    std::process::exit(0);
}

#[test]
fn files_only_where_the_policy_says() {
    if !supported() {
        return;
    }
    let a = Area::new("files");
    let pol = a.policy();
    assert_eq!(probe(&pol, "read", &a.s("inside/data.txt")), "ok");
    assert_eq!(probe(&pol, "list", &a.s("inside")), "ok");
    assert_eq!(probe(&pol, "read", &a.s("outside/secret.txt")), "EACCES");
    assert_eq!(probe(&pol, "list", &a.s("outside")), "EACCES");
    assert_eq!(probe(&pol, "write", &a.s("out/new.txt")), "ok");
    assert_eq!(probe(&pol, "mkdir", &a.s("out/d")), "ok");
    assert_eq!(probe(&pol, "symlink", &format!("{}|{}", a.s("out/new.txt"), a.s("out/l"))), "ok", "links sí (npm, venv, tar)");
    // Una FIFO en la salida colgaría al padre que la lee; un socket no sirve sin `socket()`.
    assert_eq!(probe(&pol, "mkfifo", &a.s("out/fifo")), "EACCES");
    // Ronda 2 (N5): en su carpeta temporal sí (el padre no la abre).
    assert_eq!(probe(&pol, "mkfifo_tmp", ""), "ok");
    assert_eq!(probe(&pol, "mknod_sock", &a.s("out/sock")), "EACCES");
    assert_eq!(probe(&pol, "write", &a.s("inside/new.txt")), "EACCES", "lectura no es escritura");
    assert_eq!(probe(&pol, "write", &a.s("outside/new.txt")), "EACCES");
    assert_eq!(probe(&pol, "truncate", &a.s("outside/secret.txt")), "EACCES");
    assert_eq!(probe(&pol, "tmp_write", ""), "ok");
    // El home del usuario (claves, .ssh) no está.
    if let Ok(home) = std::env::var("HOME") {
        assert_eq!(probe(&pol, "list", &home), "EACCES");
    }
    assert_eq!(std::fs::read_to_string(a.p("outside/secret.txt")).unwrap(), "secreto");
}

#[test]
fn links_do_not_lead_out() {
    if !supported() {
        return;
    }
    let a = Area::new("links");
    let pol = a.policy();
    assert_ne!(probe(&pol, "hardlink", &a.s("outside/secret.txt")), "ok");
    assert_eq!(probe(&pol, "symlink_read", &a.s("outside/secret.txt")), "EACCES");
    std::fs::write(a.p("out/mine.txt"), "x").unwrap();
    let mv = format!("{}|{}", a.s("out/mine.txt"), a.s("outside/moved.txt"));
    assert_ne!(probe(&pol, "rename_out", &mv), "ok");
    assert!(!a.p("outside/moved.txt").exists());
}

#[test]
fn no_network_no_sockets_but_socketpair() {
    if !supported() {
        return;
    }
    let a = Area::new("net");
    let pol = a.policy();
    for s in ["socket_tcp", "socket_udp", "socket_udp6", "socket_unix", "socket_netlink"] {
        assert_eq!(probe(&pol, s, ""), "EPERM", "{}", s);
    }
    assert_eq!(probe(&pol, "socketpair", ""), "ok");
}

#[test]
fn no_reaching_other_processes() {
    if !supported() {
        return;
    }
    let a = Area::new("procs");
    let pol = a.policy();
    assert_eq!(probe(&pol, "kill_parent", ""), "EPERM");
    assert_eq!(probe(&pol, "ptrace_parent", ""), "EPERM");
    assert_eq!(probe(&pol, "parent_environ", ""), "EACCES");
    assert_eq!(probe(&pol, "unshare_user", ""), "EPERM");
    assert_eq!(probe(&pol, "clone_newuser", ""), "EPERM");
    assert_eq!(probe(&pol, "setsid", ""), "EPERM");
    assert_eq!(probe(&pol, "io_uring", ""), "EPERM");
    assert_eq!(probe(&pol, "syslog", ""), "EPERM", "el log del kernel");
    assert_eq!(probe(&pol, "personality_aslr", ""), "EPERM");
    assert_eq!(probe(&pol, "personality_query", ""), "ok");
    assert_eq!(probe(&pol, "personality_linux32_uname26", ""), "ok", "Docker deja pasar 0x20008");
    #[cfg(target_arch = "x86_64")]
    assert_eq!(probe(&pol, "x32", ""), "ENOSYS");
}

#[test]
fn the_environment_is_clean() {
    if !supported() {
        return;
    }
    std::env::set_var("SYNSEMA_ISOLATE_TEST_SECRET", "x");
    let a = Area::new("env");
    let keys = probe(&a.policy(), "env", "");
    std::env::remove_var("SYNSEMA_ISOLATE_TEST_SECRET");
    assert!(!keys.contains("SECRET"), "{}", keys);
    for k in ["HOME", "PATH", "TMPDIR"] {
        assert!(keys.split(',').any(|x| x == k), "{}: {}", k, keys);
    }
}

#[test]
fn memory_has_a_ceiling() {
    if !supported() {
        return;
    }
    let a = Area::new("mem");
    let mut pol = a.policy();
    pol.max_memory_bytes = Some(256 * 1024 * 1024);
    assert_eq!(probe(&pol, "mmap_mb", "1024"), "ENOMEM");
    assert_eq!(probe(&pol, "mmap_mb", "16"), "ok");
}

#[test]
fn the_whole_group_dies() {
    if !supported() {
        return;
    }
    let a = Area::new("group");
    let pol = a.policy();
    let exe = std::env::current_exe().unwrap();
    let mut p = pol.clone();
    p.read.push(exe.clone().into());
    let mut c = Command::new(&exe);
    c.args(["--exact", "probe_entry", "--nocapture", "--test-threads=1"]);
    let _prep = prepare(&mut c, &p).unwrap();
    c.env("ISOLATE_PROBE", "grandchild").stdout(Stdio::piped()).stdin(Stdio::null());
    let child = c.spawn().unwrap();
    let pgid = child.id();
    let out = child.wait_with_output().unwrap();
    let gc: i32 = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(probe_line)
        .and_then(|s| s.trim().parse().ok())
        .expect("pid del nieto");
    // SAFETY: kill(pid, 0) sólo pregunta si existe.
    assert_eq!(unsafe { libc::kill(gc, 0) }, 0, "el nieto sigue vivo después de que la sonda terminó");
    kill_group(pgid);
    std::thread::sleep(std::time::Duration::from_millis(200));
    // Es nieto de este proceso por adopción no: lo reapea init; alcanza con que no exista o sea zombie.
    let state = std::fs::read_to_string(format!("/proc/{}/stat", gc)).unwrap_or_default();
    assert!(state.is_empty() || state.contains(") Z "), "el nieto sobrevivió a kill_group: {}", state);
}

#[test]
fn real_programs_still_run() {
    if !supported() {
        return;
    }
    let a = Area::new("real");
    let mut c = Command::new("/bin/sh");
    c.args(["-c", &format!("cat {} && echo hola > {}/x && cat {}/x", a.s("inside/data.txt"), a.s("out"), a.s("out"))]);
    let _prep = prepare(&mut c, &a.policy()).unwrap();
    let out = c.output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "datoshola\n");
    if Path::new("/usr/bin/python3").exists() {
        let mut c = Command::new("/usr/bin/python3");
        c.args(["-c", "import json,sys; print(json.dumps({'ok': sum(range(10))}))"]);
        let _prep = prepare(&mut c, &a.policy()).unwrap();
        let out = c.output().unwrap();
        assert!(out.status.success(), "python: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "{\"ok\": 45}");
    }
}

#[test]
fn relative_or_missing_paths_are_refused() {
    if !supported() {
        return;
    }
    let mut c = Command::new("/bin/true");
    let pol = Policy { read: vec![PathBuf::from("rel/dir").into()], ..Default::default() };
    assert!(matches!(prepare(&mut c, &pol), Err(Error::Path(_))));
    let pol = Policy { read: vec![PathBuf::from("/no/such/dir/synsema").into()], ..Default::default() };
    assert!(matches!(prepare(&mut c, &pol), Err(Error::Path(_))));
}

/// Un lugar atado con `pin` es el que se juzgó: si después se cambia por un link a otro lado, el
/// hijo sigue viendo el de antes (y no el nuevo destino).
#[test]
fn a_pinned_place_does_not_move_when_a_link_changes() {
    if !supported() {
        return;
    }
    let a = Area::new("pin");
    std::fs::create_dir_all(a.p("tree/real")).unwrap();
    std::fs::write(a.p("tree/real/f.txt"), "juzgado").unwrap();
    let pinned = pin(&a.p("tree/real")).unwrap();
    assert!(pinned.is_dir && pinned.real.ends_with("tree/real"), "{:?}", pinned.real);
    // Entre el juicio y el `prepare`, alguien cambia el lugar por un link afuera.
    std::fs::rename(a.p("tree/real"), a.p("tree/moved")).unwrap();
    std::os::unix::fs::symlink(a.p("outside"), a.p("tree/real")).unwrap();
    let pol = Policy { read: vec![pinned.place], write: vec![], max_memory_bytes: None };
    assert_eq!(probe(&pol, "read", &a.s("tree/moved/f.txt")), "ok", "el inodo juzgado");
    assert_eq!(probe(&pol, "read", &a.s("outside/secret.txt")), "EACCES", "no el destino nuevo");
    let _ = Place::Path(a.p("x")); // la otra forma sigue existiendo
}

/// `exited` ve la salida sin recoger al hijo: su número sigue tomado (zombie) y el `kill` al grupo
/// llega a los nietos y a nadie más.
#[test]
fn the_group_dies_before_the_reap() {
    if !supported() {
        return;
    }
    let a = Area::new("reap");
    let mut c = Command::new("/bin/sh");
    c.args(["-c", "/bin/sleep 300 </dev/null >/dev/null 2>&1 & exit 0"]).stdin(Stdio::null()).stdout(Stdio::null());
    let _prep = prepare(&mut c, &a.policy()).unwrap();
    let mut child = c.spawn().unwrap();
    let pid = child.id();
    let t0 = std::time::Instant::now();
    while exited(pid) != ChildState::Exited {
        assert!(t0.elapsed() < std::time::Duration::from_secs(10), "exited nunca dio true");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).unwrap();
    assert!(stat.contains(") Z "), "sin recoger, el hijo es un zombie: {}", stat);
    // Ronda 4 (A1): con el nieto vivo, el grupo no está vacío.
    assert!(!group_gone(pid, std::time::Duration::from_millis(100)), "el nieto sigue en el grupo");
    kill_group(pid);
    child.wait().unwrap();
    // Nadie queda en el grupo (el nieto muerto puede ser un zombie un momento, hasta que init lo
    // recoge).
    assert!(group_gone(pid, std::time::Duration::from_secs(5)), "quedó alguien en el grupo");
}

/// Ronda 6 (M2): un proceso cuyo hilo principal terminó figura como zombie mientras otro hilo sigue
/// corriendo; el grupo no está vacío hasta que ese hilo termina.
#[test]
fn a_zombie_leader_with_a_live_thread_keeps_the_group() {
    use std::os::unix::process::CommandExt;
    if Command::new("python3").args(["-c", "pass"]).status().map(|s| !s.success()).unwrap_or(true) {
        return;
    }
    let script = "import ctypes, threading, time\n\
                  threading.Thread(target=time.sleep, args=(300,)).start()\n\
                  ctypes.CDLL(None).pthread_exit(None)\n";
    let mut child = Command::new("python3").args(["-c", script]).stdin(Stdio::null()).process_group(0).spawn().unwrap();
    let pid = child.id();
    let t0 = std::time::Instant::now();
    loop {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).unwrap();
        if stat.contains(") Z ") {
            break;
        }
        assert!(t0.elapsed() < std::time::Duration::from_secs(10), "el hilo principal nunca terminó: {}", stat);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(!group_gone(pid, std::time::Duration::from_millis(100)), "el otro hilo sigue corriendo");
    kill_group(pid);
    child.wait().unwrap();
    assert!(group_gone(pid, std::time::Duration::from_secs(5)), "quedó alguien en el grupo");
}

/// Ronda 7 (B1): con el `/proc` de otro espacio de pid (`unshare -p` sin montar el suyo), sus
/// números no son los de `kill`: un grupo vivo no puede contar como «sólo zombies». Se corre la
/// sonda sin aislar, como PID 1 de un espacio de pid nuevo, con el `/proc` de afuera y (control)
/// con el suyo.
#[test]
fn a_proc_of_another_pid_namespace_does_not_empty_a_live_group() {
    let exe = std::env::current_exe().unwrap();
    for mount_proc in [false, true] {
        let mut c = Command::new("unshare");
        c.args(["-Urpf", "--kill-child"]);
        if mount_proc {
            c.arg("--mount-proc");
        }
        c.arg(&exe).args(["--exact", "probe_entry", "--nocapture", "--test-threads=1"]);
        c.env("ISOLATE_PROBE", "live_group").stdin(Stdio::null());
        let Ok(out) = c.output() else {
            eprintln!("sin unshare: no se prueba");
            return;
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        let Some(r) = stdout.lines().find_map(probe_line) else {
            // Sin espacios de usuario sin privilegios (o sin `unshare`), no se prueba.
            eprintln!("unshare no corrió: {} {}", stdout, String::from_utf8_lossy(&out.stderr));
            return;
        };
        assert_eq!(r, "vivo=false muerto=true", "--mount-proc={}", mount_proc);
    }
}

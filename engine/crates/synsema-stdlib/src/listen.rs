//! v0.6.53 (G1): el socket donde escucha un `serve` (el puerto principal, el 301 de `:80` y el
//! challenge ACME). Tres orígenes, en este orden:
//!
//! 1. **Heredado** (Unix, activación por socket de systemd: `LISTEN_PID` + `LISTEN_FDS`). systemd
//!    tiene el puerto abierto entre un proceso y el siguiente: con `systemctl restart`, las
//!    conexiones que llegan mientras arranca el nuevo esperan en la cola del socket en vez de ser
//!    rechazadas. Se toma el que escucha en el puerto pedido.
//! 2. **Puerto compartido** (Unix, `SYNSEMA_REUSE_PORT=1`): `SO_REUSEPORT`, así el proceso nuevo
//!    escucha en el mismo puerto mientras el viejo drena (el viejo deja de aceptar al recibir
//!    SIGTERM). Es explícito: sin él, un segundo `serve` en el mismo puerto es «address in use», y
//!    no dos procesos repartiéndose el tráfico sin que nadie lo pidiera.
//! 3. **Un bind común**, como siempre.
//!
//! En Windows sólo el 3: el traspaso es el drenado de `SYNSEMA_SHUTDOWN_GRACE`.

use std::io;
use std::net::TcpListener;
use std::sync::Mutex;

/// Los sockets que pasó systemd y todavía no tomó ningún `serve`: (puerto, socket).
static INHERITED: Mutex<Vec<(u16, TcpListener)>> = Mutex::new(Vec::new());

/// Toma los sockets que systemd le pasó a este proceso (`LISTEN_PID` es el suyo) y los marca para
/// que no los herede ningún hijo. Se llama al arrancar, antes de lanzar hilos o procesos. Sólo toma
/// los que son sockets TCP escuchando; los demás descriptores no se tocan. Sin `LISTEN_FDS`, o con
/// el `LISTEN_PID` de otro proceso (un padre que lo dejó en el entorno), no hace nada.
pub fn adopt_inherited() {
    #[cfg(unix)]
    {
        let mut taken = unix::adopt(std::env::var("LISTEN_PID").ok().as_deref(), std::env::var("LISTEN_FDS").ok().as_deref());
        // Ronda 1, B5: son de este proceso; un hijo (`run`, `proc_*`) no los recibe.
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
        if !taken.is_empty() {
            if let Ok(mut g) = INHERITED.lock() {
                g.append(&mut taken);
            }
        }
    }
}

/// El socket que escucha en `addr:port`: el heredado de ese puerto, uno con `SO_REUSEPORT` si lo
/// pide `SYNSEMA_REUSE_PORT`, o un bind común.
pub fn bind(addr: &str, port: u16) -> io::Result<TcpListener> {
    if let Some(l) = take_inherited(port)? {
        eprintln!("[serve] port {}: listening on the socket systemd passed in (socket activation)", port);
        return Ok(l);
    }
    if reuse_port() {
        #[cfg(unix)]
        return unix::bind_reuse_port(addr, port);
        #[cfg(not(unix))]
        {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| eprintln!("[serve] SYNSEMA_REUSE_PORT is ignored on this system (Unix only): binding as usual"));
        }
    }
    TcpListener::bind((addr, port))
}

/// Ronda 1, B5: más de un socket para el mismo puerto (`ListenStream=0.0.0.0:80` y
/// `ListenStream=[::]:80` con `BindIPv6Only=ipv6-only`) es un error: `serve` escucha en uno, y las
/// conexiones del otro se quedarían en su cola para siempre.
fn take_inherited(port: u16) -> io::Result<Option<TcpListener>> {
    let Ok(mut g) = INHERITED.lock() else { return Ok(None) };
    let n = g.iter().filter(|(p, _)| *p == port).count();
    if n > 1 {
        return Err(io::Error::other(format!(
            "systemd passed {} sockets for port {}; serve listens on one, so the connections of the others would never be accepted. Pass one socket per port (one ListenStream, or BindIPv6Only=both)",
            n, port
        )));
    }
    Ok(g.iter().position(|(p, _)| *p == port).map(|i| g.remove(i).1))
}

/// `SYNSEMA_REUSE_PORT`: `1`/`true`/`yes` lo prende.
fn reuse_port() -> bool {
    std::env::var("SYNSEMA_REUSE_PORT").is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

#[cfg(unix)]
mod unix {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::io;
    use std::net::{TcpListener, ToSocketAddrs};
    use std::os::fd::{FromRawFd, IntoRawFd};

    /// El primer descriptor que pasa systemd (`SD_LISTEN_FDS_START`).
    const FIRST_FD: i32 = 3;

    /// Los sockets heredados que escuchan TCP, con su puerto. `pid` y `fds` son `LISTEN_PID` y
    /// `LISTEN_FDS`.
    pub(super) fn adopt(pid: Option<&str>, fds: Option<&str>) -> Vec<(u16, TcpListener)> {
        let ours = pid.and_then(|p| p.trim().parse::<u32>().ok()) == Some(std::process::id());
        let n = fds.and_then(|n| n.trim().parse::<i32>().ok()).unwrap_or(0);
        if !ours || !(1..=1024).contains(&n) {
            return Vec::new();
        }
        adopt_range(FIRST_FD, n)
    }

    /// ¿El socket está escuchando? `SO_ACCEPTCONN`, que existe en Linux y en macOS
    /// (`Socket::is_listener` de socket2 sólo está en Linux).
    fn accepts_connections(s: &socket2::Socket) -> bool {
        use std::os::fd::AsRawFd;
        let mut v: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `v` y `len` son de este marco y del tamaño que `getsockopt` espera para un
        // `int`; el descriptor lo tiene `s` mientras dura la llamada.
        let r = unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                (&mut v as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        r == 0 && v != 0
    }

    /// Los descriptores `first..first+n` (ver `adopt`).
    pub(super) fn adopt_range(first: i32, n: i32) -> Vec<(u16, TcpListener)> {
        let mut out = Vec::new();
        for fd in first..first + n {
            // SAFETY: `LISTEN_PID` es este proceso, así que systemd le pasó los descriptores
            // 3..3+LISTEN_FDS y nadie más los abrió ni los usa. Si el descriptor no resulta un
            // socket TCP escuchando, se suelta sin cerrarlo (`into_raw_fd`).
            let s = unsafe { Socket::from_raw_fd(fd) };
            let listening = s.r#type().is_ok_and(|t| t == Type::STREAM) && accepts_connections(&s);
            let port = s.local_addr().ok().and_then(|a| a.as_socket()).map(|a| a.port());
            match (listening, port) {
                (true, Some(port)) => {
                    let _ = s.set_cloexec(true);
                    out.push((port, TcpListener::from(s)));
                }
                _ => {
                    // Ronda 1, B5: tampoco lo hereda un hijo.
                    let _ = s.set_cloexec(true);
                    let _ = s.into_raw_fd();
                }
            }
        }
        out
    }

    pub(super) fn bind_reuse_port(addr: &str, port: u16) -> io::Result<TcpListener> {
        let sa = (addr, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("cannot resolve {}", addr)))?;
        let s = Socket::new(Domain::for_address(sa), Type::STREAM, Some(Protocol::TCP))?;
        s.set_cloexec(true)?;
        s.set_reuse_address(true)?;
        s.set_reuse_port(true)?;
        s.bind(&sa.into())?;
        s.listen(1024)?;
        Ok(TcpListener::from(s))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Con `SO_REUSEPORT`, dos sockets escuchan en el mismo puerto; sin él, el segundo bind falla.
    #[test]
    fn reuse_port_lets_a_second_listener_share_the_port() {
        let a = unix::bind_reuse_port("127.0.0.1", 0).unwrap();
        let port = a.local_addr().unwrap().port();
        let b = unix::bind_reuse_port("127.0.0.1", port).expect("el segundo no pudo compartir el puerto");
        assert_eq!(b.local_addr().unwrap().port(), port);
        assert!(TcpListener::bind(("127.0.0.1", port)).is_err(), "un bind común no comparte");
    }

    /// Ronda 1, B5: un descriptor heredado que no se adopta (acá, un socket UDP en el lugar del 3)
    /// queda abierto pero con `FD_CLOEXEC`: un hijo no lo hereda.
    #[test]
    fn a_descriptor_that_is_not_adopted_is_not_inherited_by_children() {
        use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // El test corre en un proceso con muchos descriptores: se duplica al primero libre >= 3
        // y se le pasa a `adopt` como si systemd lo hubiera puesto ahí.
        let fd = udp.as_raw_fd();
        let s = socket2::Socket::from(udp);
        s.set_cloexec(false).unwrap();
        let raw = s.into_raw_fd();
        assert_eq!(raw, fd);
        let got = unix::adopt_range(raw, 1);
        assert!(got.is_empty(), "un UDP no se adopta");
        // SAFETY: `raw` es el socket de arriba, abierto y de este test; se cierra al soltar `s`.
        let s = unsafe { socket2::Socket::from_raw_fd(raw) };
        let flags = unsafe { libc::fcntl(s.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0, "quedó heredable");
    }

    /// Ronda 1, B5: dos sockets heredados para el mismo puerto son un error.
    #[test]
    fn two_inherited_sockets_for_one_port_are_an_error() {
        let a = unix::bind_reuse_port("127.0.0.1", 0).unwrap();
        let port = a.local_addr().unwrap().port();
        let b = unix::bind_reuse_port("127.0.0.1", port).unwrap();
        INHERITED.lock().unwrap().extend([(port, a), (port, b)]);
        let e = take_inherited(port).unwrap_err().to_string();
        INHERITED.lock().unwrap().retain(|(p, _)| *p != port);
        assert!(e.contains("2 sockets for port"), "{}", e);
    }

    /// `LISTEN_PID` de otro proceso o sin `LISTEN_FDS`: no se toca nada.
    #[test]
    fn another_process_listen_pid_adopts_nothing() {
        let other = (std::process::id() + 1).to_string();
        assert!(unix::adopt(Some(&other), Some("1")).is_empty());
        assert!(unix::adopt(Some(&std::process::id().to_string()), None).is_empty());
    }
}

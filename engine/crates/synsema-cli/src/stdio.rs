//! Salidas honestas del binario (tanda escritorio, segunda vuelta):
//!
//! 1. **Tubería muerta ≠ pánico.** Escribir a un stdout/stderr que ya no tiene lector (el padre
//!    cerró la tubería, `synsema run x.syn | head -1`, PowerShell capturando la salida de un
//!    programa GUI al que no espera) hace que `println!`/`eprintln!` entren en pánico
//!    (`failed printing to stdout: …`). Un hook de pánico lo convierte en salida silenciosa con
//!    exit 0: nadie está leyendo, no hay a quién contarle nada — el análogo de morir por SIGPIPE,
//!    lo que hacen las herramientas de consola serias (ripgrep, p. ej.). Todo otro pánico sigue
//!    su curso normal.
//! 2. **Windows, modo `--engine` de un build `--no-console`.** Un ejecutable de subsistema GUI
//!    nace sin consola, así que `desk.exe --engine version` no mostraba nada. Si el padre tiene
//!    consola (cmd, PowerShell), el proceso se pega a ella (`AttachConsole(ATTACH_PARENT_PROCESS)`)
//!    y reabre `CONOUT$`/`CONIN$` SÓLO para los handles estándar que estén inválidos — una
//!    tubería o un archivo que el padre nos dio se respeta tal cual. Sin padre con consola (doble
//!    clic, Explorador, un servicio) no cambia nada: silencio, como corresponde a una app de
//!    escritorio. Sólo en modo `--engine`: en modo programa (la app de escritorio sirviendo) NO se
//!    pega a la consola del padre — si lo hiciera, un Ctrl-C en esa terminal apagaría la app.
//!
//! Sin dependencias: tres funciones de kernel32 por FFI.

/// Instala el guardián de tubería muerta. Llamar antes del primer `println!`.
pub fn install_broken_pipe_guard() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or("");
        if msg.starts_with("failed printing to stdout") || msg.starts_with("failed printing to stderr") {
            std::process::exit(0);
        }
        default(info);
    }));
}

/// Windows: si el proceso no tiene consola pero el padre sí, se pega a ella y apunta los handles
/// estándar INVÁLIDOS al console. Devuelve `true` si se pegó. En otros SO no hace nada.
#[cfg(windows)]
pub fn attach_parent_console() -> bool {
    use std::ffi::c_void;

    type Handle = *mut c_void;
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const OPEN_EXISTING: u32 = 3;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleWindow() -> Handle;
        fn AttachConsole(process_id: u32) -> i32;
        fn GetStdHandle(std_handle: u32) -> Handle;
        fn SetStdHandle(std_handle: u32, handle: Handle) -> i32;
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *const c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: Handle,
        ) -> Handle;
    }

    fn invalid(h: Handle) -> bool {
        h.is_null() || h == INVALID_HANDLE_VALUE
    }

    unsafe fn open(name: &str, access: u32) -> Handle {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    }

    // SAFETY: llamadas a kernel32 con los argumentos que documenta Microsoft; los handles que
    // se abren quedan vivos hasta que el proceso termina (son los estándar).
    unsafe {
        if !GetConsoleWindow().is_null() {
            return false; // ya tenemos consola (el synsema.exe normal)
        }
        let (h_in, h_out, h_err) = (
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
            GetStdHandle(STD_ERROR_HANDLE),
        );
        if !invalid(h_out) && !invalid(h_err) {
            return false; // el padre nos dio salidas (tubería/archivo): se respetan
        }
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            return false; // sin consola padre: doble clic, Explorador, servicio
        }
        if invalid(h_out) {
            let h = open("CONOUT$", GENERIC_READ | GENERIC_WRITE);
            if !invalid(h) {
                SetStdHandle(STD_OUTPUT_HANDLE, h);
            }
        }
        if invalid(h_err) {
            let h = open("CONOUT$", GENERIC_READ | GENERIC_WRITE);
            if !invalid(h) {
                SetStdHandle(STD_ERROR_HANDLE, h);
            }
        }
        if invalid(h_in) {
            let h = open("CONIN$", GENERIC_READ | GENERIC_WRITE);
            if !invalid(h) {
                SetStdHandle(STD_INPUT_HANDLE, h);
            }
        }
        true
    }
}

#[cfg(not(windows))]
pub fn attach_parent_console() -> bool {
    false
}

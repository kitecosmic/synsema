//! `attest`: pedirle a la PLATAFORMA un documento de attestation que ate `report_data`
//! (≤ 64 bytes) a la medida del código que corre. Es el caso de un contenedor o una VM
//! atestados donde Synsema es su propio host; no hay ABI ajena, así que es motor, con nombre
//! genérico y capability.
//!
//! Contrato del lenguaje:
//! - `attest(opts?) → map` gateado por `require attest` (deny-by-default, jamás ambiente,
//!   negada bajo `--deterministic` y bajo cualquier techo que no la liste).
//!   `opts = {"report_data"?: bytes (≤ 64), "nonce"?: bytes, "public_key"?: bytes}` →
//!   `{"format": "nitro"|"tdx"|"sev-snp", "document": bytes, "driver": text, "report_data":
//!   bytes, "aux"?: bytes, "event_log"?: text, "root"?: bytes}` (`root` SÓLO lo devuelve el
//!   driver `mock`, para que el cliente de CI lo pase como `opts.root` a `attestation_verify`).
//! - `attest_key(purpose) → secret`: clave sellada a la medida donde la plataforma la deriva
//!   (dstack `GetKey`; `mock` = HKDF de la semilla). Nitro/TDX/SNP crudos no sellan: error que
//!   apunta a la receta del KMS (`packages/attested/README.md`).
//! - `attestation_document() → map` y `attestation_key() → secret`: la identidad de un
//!   `synsema serve --attested` (la que publica `GET /.well-known/attestation`); fuera de ese
//!   modo fallan con error claro.
//!
//! Drivers (elegidos por `SYNSEMA_ATTEST` o autodetectados en Linux; el `mock` JAMÁS se elige
//! solo):
//! - `nitro` (Linux): NSM por `/dev/nsm`, ioctl `_IOWR(0x0A, 0, sizeof(NsmMessage))` con
//!   request/response CBOR — números y forma confirmados contra `aws-nitro-enclaves-nsm-api`
//!   (`src/driver/mod.rs`: `NSM_IOCTL_MAGIC = 0x0A`, request ≤ 0x1000, response 0x3000). SIN
//!   PROBAR en hardware (regla del repo: sin sonda no hay doc).
//! - `tsm` (Linux ≥ 6.7): configfs-tsm (`/sys/kernel/config/tsm/report/<n>/{inblob,outblob,
//!   provider,auxblob}`). `provider` decide el formato (`tdx_guest` → `tdx`, `sev_guest` →
//!   `sev-snp`). Sin fallback a `/dev/tdx_guest`/`/dev/sev-guest` por ahora. SIN PROBAR.
//! - `dstack` (Unix): HTTP/1.1 mínimo sobre el socket unix del guest agent. Rutas y JSON
//!   confirmados contra el SDK Go de `Dstack-TEE/dstack` (`sdk/go/dstack/client_v0.go`,
//!   `transport.go`) y `sdk/curl/api-tappd.md` (el `tappd.sock` viejo). SIN PROBAR contra el
//!   simulador ni contra una VM real.
//! - `mock` (cualquier SO, el driver de CI; `format = "mock"`): par P-384 DETERMINISTA desde
//!   `SYNSEMA_ATTEST_MOCK_SEED`, cadena X.509 mínima (raíz autofirmada → hoja) codificada a
//!   mano, documento con la forma EXACTA de un `AttestationDoc` de Nitro (`module_id`,
//!   `digest`, `timestamp`, `pcrs`, `certificate`, `cabundle`, `public_key`, `user_data`,
//!   `nonce`) firmado como `COSE_Sign1` ES384 sin tag (como devuelve NSM). PCRs desde
//!   `SYNSEMA_ATTEST_MOCK_PCRS`, timestamp desde `SYNSEMA_ATTEST_MOCK_TIMESTAMP`.
//!
//! Falla cerrado: cualquier duda (driver desconocido, provider raro, respuesta que no parsea,
//! `report_data` de más de 64 bytes) es un error explícito, nunca un documento dudoso.
//!
//! De la auditoría externa: `report_data` ata además un digest de CONFIGURACIÓN
//! (`AttestConfig`: etiquetas, techo, modo TLS, motor, perfil); la clave de identidad sale como
//! secret SELLADO (no revelable); `tls_key` va en el JSON; el mock avisa por stderr y marca
//! `mock: true`; `DSTACK_SIMULATOR_ENDPOINT` sólo con
//! `SYNSEMA_ATTEST=dstack` explícito; parser HTTP sobre bytes con tope; `generation`
//! de configfs-tsm antes y después de leer.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, OnceLock};

use indexmap::IndexMap;
use sha2::{Digest, Sha256};

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::bytesutil::{b64_encode, hex_decode, hex_encode};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::secret::SecretInner;
use synsema_core::types::{syn_bool, syn_bytes, syn_map, syn_secret_bytes, syn_text, SynValue};

use crate::cbor::{cose_protected_alg, Cbor, CoseSign1, COSE_ALG_ES384};

/// Knobs del HOST que lee este módulo (lista CANÓNICA, espejo de `SERVE_ENV_VARS`): el test
/// anti-rot del CLI (`env_example_in_sync_with_engine_knobs`) la cruza con el `.env.example`
/// de `init`. Son del ENTORNO DEL PROCESO (Docker `-e`, systemd), no del `.env`.
pub const ATTEST_ENV_VARS: &[&str] = &[
    "SYNSEMA_ATTEST",
    "SYNSEMA_ATTEST_MOCK_SEED",
    "SYNSEMA_ATTEST_MOCK_PCRS",
    "SYNSEMA_ATTEST_MOCK_TIMESTAMP",
    // Auditoría externa: la misma variable del SDK de dstack; sólo se honra con
    // `SYNSEMA_ATTEST=dstack` explícito, jamás elige el driver por sí sola.
    "DSTACK_SIMULATOR_ENDPOINT",
];

/// Auditoría externa: aviso único por proceso cuando el driver es el `mock`.
static MOCK_WARNED: std::sync::Once = std::sync::Once::new();

/// Avisa (una vez, por stderr) que los documentos del `mock` son forjables. Lo llaman el propio
/// driver y el CLI al validar el driver antes de correr.
pub fn warn_if_mock(driver: Driver) {
    if driver == Driver::Mock {
        MOCK_WARNED.call_once(|| {
            eprintln!("synsema: warning: SYNSEMA_ATTEST=mock: documents are FORGEABLE (deterministic test key), never trust them outside CI");
        });
    }
}

/// Semilla por defecto del driver `mock`.
pub const MOCK_DEFAULT_SEED: &str = "synsema-mock";
/// Timestamp por defecto del documento `mock` (ms desde epoch).
pub const MOCK_DEFAULT_TIMESTAMP_MS: i128 = 1_700_000_000_000;
/// Tope de `report_data` (Nitro `user_data` lo acepta más largo, pero TDX/SNP son 64 bytes
/// fijos; un solo contrato para todas las plataformas).
pub const MAX_REPORT_DATA: usize = 64;

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

// =========================================================
// Hashes compartidos (los usan el CLI y serve para report_data / state_root)
// =========================================================

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Keccak-256 pre-NIST (Ethereum), el mismo del builtin `keccak256` — para `state_root`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest as _;
    let mut h = sha3::Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// SHA-256 del PROGRAMA: el fuente principal más cada módulo `use` (recursivo, en el orden
/// en que el check estático los resuelve, mismas reglas que el runtime). Es lo que va en
/// `report_data` de `serve --attested` y `run --attest`: la imagen es genérica y la medida de
/// la plataforma cubre la imagen; este hash dice QUÉ `.syn` corre. No cubre templates ni
/// estáticos (van en la imagen). Forma: `sha256(main ‖ 0x00 ‖ sha256(mod_1) ‖ … ‖ sha256(mod_n))`.
/// El sha del programa que corre en ESTE proceso (T4: el recibo lo lleva). Lo fija `run`,
/// `test` y `serve` al arrancar; sin él (REPL, embebido sin fuente) el recibo lo omite.
static PROGRAM_SHA: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

/// Anota el sha del programa principal (+ módulos) de este proceso. Best-effort: si el
/// hash falla (un `use` que no resuelve) no se anota y el recibo lo omite.
pub fn note_program_sha(source: &str, filename: &str) {
    if let Ok(sha) = program_sha(source, filename) {
        let _ = PROGRAM_SHA.set(sha);
    }
}

pub fn current_program_sha() -> Option<[u8; 32]> {
    PROGRAM_SHA.get().copied()
}

pub fn program_sha(source: &str, filename: &str) -> Result<[u8; 32], String> {
    let program = synsema_core::parser::parse_source(source, filename).map_err(|e| e.to_string())?;
    let modules: RefCell<Vec<[u8; 32]>> = RefCell::new(Vec::new());
    let load = |resolved: &str, raw: &str| -> Result<synsema_core::ast::Program, String> {
        // Overlay del bundle (`synsema build`) primero, disco después — como `load_module_inner`.
        let src = match synsema_core::bundle::get(resolved) {
            Some(bytes) => String::from_utf8(bytes.to_vec()).map_err(|_| format!("module is not UTF-8: {}", raw))?,
            None => std::fs::read_to_string(resolved).map_err(|_| format!("module not found: {}", raw))?,
        };
        let prog = synsema_core::parser::parse_source(&src, resolved).map_err(|e| e.to_string())?;
        modules.borrow_mut().push(sha256(src.as_bytes()));
        Ok(prog)
    };
    synsema_core::templates::check_program_static_with(&program, filename, &load)?;
    let mut h = Sha256::new();
    h.update(source.as_bytes());
    h.update([0u8]);
    for m in modules.borrow().iter() {
        h.update(m);
    }
    Ok(h.finalize().into())
}

// =========================================================
// API Rust: request / result / drivers
// =========================================================

/// Lo que se le pide a la plataforma.
#[derive(Clone, Debug, Default)]
pub struct AttestRequest {
    /// ≤ 64 bytes. Nitro lo lleva en `user_data` tal cual; TDX/SNP/dstack lo rellenan con
    /// ceros hasta 64 (el `report_data` del quote es fijo).
    pub report_data: Vec<u8>,
    /// Sólo Nitro lo lleva aparte; las demás plataformas exigen plegarlo en `report_data`.
    pub nonce: Option<Vec<u8>>,
    /// Ídem `nonce`.
    pub public_key: Option<Vec<u8>>,
}

/// El documento y su procedencia.
#[derive(Clone, Debug)]
pub struct AttestResult {
    /// `"nitro"` (COSE_Sign1 de NSM), `"tdx"` (quote DCAP), `"sev-snp"`, `"mock"` (auditoría externa:
    /// el driver de desarrollo declara su PROPIO formato — misma forma COSE que Nitro, pero un
    /// cliente que sólo mire `format` no puede confundirlo con un documento de plataforma;
    /// `attestation_verify` lo acepta sólo con `opts.root` explícito).
    pub format: &'static str,
    pub document: Vec<u8>,
    /// `"nitro"` | `"tsm"` | `"dstack"` | `"mock"`.
    pub driver: &'static str,
    /// Los bytes efectivamente atados (con el padding de la plataforma, si lo hubo).
    pub report_data: Vec<u8>,
    /// configfs-tsm `auxblob` (cadena de certificados de SEV-SNP), si la plataforma lo da.
    pub aux: Option<Vec<u8>>,
    /// dstack: el event log (JSON) para reproducir RTMR3.
    pub event_log: Option<String>,
    /// SÓLO el mock: el DER de su raíz, para pasarlo como `opts.root` al verificador.
    pub root: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Driver {
    Nitro,
    Tsm,
    Dstack,
    Mock,
}

impl Driver {
    pub fn name(self) -> &'static str {
        match self {
            Driver::Nitro => "nitro",
            Driver::Tsm => "tsm",
            Driver::Dstack => "dstack",
            Driver::Mock => "mock",
        }
    }
}

/// Error canónico cuando no hay plataforma.
pub const NO_PLATFORM: &str = "attest: no attestation platform detected (set SYNSEMA_ATTEST=nitro|tsm|dstack, or SYNSEMA_ATTEST=mock for development)";

/// Rutas donde puede vivir el socket del guest agent de dstack (las mismas que prueba su SDK
/// Go, más el `tappd.sock` de las versiones < 0.3).
#[allow(dead_code)]
const DSTACK_SOCKETS: &[&str] = &[
    "/var/run/dstack.sock",
    "/run/dstack.sock",
    "/var/run/dstack/dstack.sock",
    "/run/dstack/dstack.sock",
];
#[allow(dead_code)]
const TAPPD_SOCKET: &str = "/var/run/tappd.sock";

/// Elige el driver: `SYNSEMA_ATTEST` manda; sin él, autodetección en Linux por la presencia
/// del dispositivo/socket. El `mock` sólo entra por la variable, jamás por detección.
pub fn select_driver() -> Result<Driver, String> {
    if let Ok(v) = std::env::var("SYNSEMA_ATTEST") {
        let v = v.trim().to_ascii_lowercase();
        if !v.is_empty() {
            return match v.as_str() {
                "nitro" | "nsm" => Ok(Driver::Nitro),
                "tsm" | "tdx" | "sev-snp" | "sev_snp" | "snp" => Ok(Driver::Tsm),
                "dstack" | "tappd" => Ok(Driver::Dstack),
                "mock" => Ok(Driver::Mock),
                other => Err(format!(
                    "attest: unknown driver '{}' in SYNSEMA_ATTEST (expected nitro|tsm|dstack, or mock for development)",
                    other
                )),
            };
        }
    }
    #[cfg(target_os = "linux")]
    {
        if std::path::Path::new("/dev/nsm").exists() {
            return Ok(Driver::Nitro);
        }
        if std::path::Path::new(TSM_REPORT_DIR).is_dir() {
            return Ok(Driver::Tsm);
        }
    }
    #[cfg(unix)]
    {
        // Sólo los sockets REALES del guest agent autodetectan dstack; el simulador
        // (`DSTACK_SIMULATOR_ENDPOINT`) exige `SYNSEMA_ATTEST=dstack` explícito (auditoría externa).
        if DSTACK_SOCKETS.iter().chain(std::iter::once(&TAPPD_SOCKET)).any(|p| std::path::Path::new(p).exists()) {
            return Ok(Driver::Dstack);
        }
    }
    Err(NO_PLATFORM.to_string())
}

/// Auditoría externa: elige el driver Y comprueba que su plataforma está al alcance (dispositivo,
/// directorio o socket presentes; SO correcto) SIN pedir un documento. Es lo que `run --attest`
/// corre ANTES de ejecutar el programa: sin plataforma no se ejecuta nada.
pub fn preflight() -> Result<Driver, String> {
    let driver = select_driver()?;
    match driver {
        Driver::Mock => {}
        Driver::Nitro => {
            if !cfg!(target_os = "linux") {
                return Err("attest: the nitro driver is Linux-only (it talks to /dev/nsm inside a Nitro enclave)".to_string());
            }
            if !std::path::Path::new("/dev/nsm").exists() {
                return Err("attest: /dev/nsm is missing; is this a Nitro enclave?".to_string());
            }
        }
        Driver::Tsm => {
            #[cfg(target_os = "linux")]
            {
                if !std::path::Path::new(TSM_REPORT_DIR).is_dir() {
                    return Err(format!("attest: configfs-tsm is not available ({} missing; Linux >= 6.7 in a TDX or SEV-SNP guest)", TSM_REPORT_DIR));
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err("attest: the tsm driver is Linux-only (configfs-tsm, Linux >= 6.7 in a TDX or SEV-SNP guest)".to_string());
            }
        }
        Driver::Dstack => {
            #[cfg(unix)]
            {
                if dstack_endpoint().is_none() {
                    return Err(format!(
                        "attest: dstack guest agent not found (looked for {} and {}; or set DSTACK_SIMULATOR_ENDPOINT)",
                        DSTACK_SOCKETS.join(", "),
                        TAPPD_SOCKET
                    ));
                }
            }
            #[cfg(not(unix))]
            {
                return Err("attest: the dstack driver needs the guest agent's unix socket (this OS has none)".to_string());
            }
        }
    }
    Ok(driver)
}

/// Pide el documento al driver elegido. Es la API que usan `serve --attested` y
/// `run --attest` sin pasar por el intérprete (la capability la gatea el builtin).
pub fn attest_document(req: &AttestRequest) -> Result<AttestResult, String> {
    if req.report_data.len() > MAX_REPORT_DATA {
        return Err(format!(
            "attest: report_data must be at most {} bytes, got {} (hash it first: sha256(...) is 32)",
            MAX_REPORT_DATA,
            req.report_data.len()
        ));
    }
    match select_driver()? {
        Driver::Mock => mock::attest(req),
        Driver::Nitro => nitro::attest(req),
        Driver::Tsm => tsm::attest(req),
        Driver::Dstack => dstack::attest(req),
    }
}

/// Clave sellada a la medida, como bytes (el builtin la envuelve en `secret`).
pub fn attest_key_bytes(purpose: &str) -> Result<Vec<u8>, String> {
    if purpose.trim().is_empty() {
        return Err("attest_key: purpose must be a non-empty text (it derives a distinct key per purpose)".to_string());
    }
    match select_driver()? {
        Driver::Mock => Ok(mock::derive_key(purpose)),
        Driver::Dstack => dstack::get_key(purpose),
        Driver::Nitro | Driver::Tsm => Err(
            "attest_key: this platform does not derive sealed keys; release the key from a KMS against the attestation (see the attested serve recipe)"
                .to_string(),
        ),
    }
}

/// Las demás plataformas no llevan `nonce`/`public_key` aparte: fallar cerrado antes que
/// descartarlos en silencio.
#[allow(dead_code)]
fn reject_side_fields(req: &AttestRequest, platform: &str) -> Result<(), String> {
    if req.nonce.is_some() || req.public_key.is_some() {
        return Err(format!(
            "attest: {} binds only report_data (64 bytes); fold the nonce and public key into it (e.g. sha256(public_key ‖ nonce)) instead of passing them separately",
            platform
        ));
    }
    Ok(())
}

/// `report_data` rellenado con ceros hasta 64 bytes (TDX/SNP/dstack).
#[allow(dead_code)]
fn padded_report_data(req: &AttestRequest) -> Vec<u8> {
    let mut rd = req.report_data.clone();
    rd.resize(MAX_REPORT_DATA, 0);
    rd
}

// =========================================================
// Driver nitro — NSM por /dev/nsm (Linux)
// =========================================================

mod nitro {
    use super::*;

    #[cfg(target_os = "linux")]
    pub fn attest(req: &AttestRequest) -> Result<AttestResult, String> {
        use std::os::unix::io::AsRawFd;

        /// `NSM_IOCTL_MAGIC` del driver (`aws-nitro-enclaves-nsm-api/src/driver/mod.rs`).
        const NSM_IOCTL_MAGIC: u64 = 0x0A;
        const NSM_REQUEST_MAX_SIZE: usize = 0x1000;
        const NSM_RESPONSE_MAX_SIZE: usize = 0x3000;

        /// La estructura que viaja por el ioctl: dos `iovec` (request, response). El
        /// driver del kernel actualiza `response.iov_len` con lo que escribió.
        #[repr(C)]
        struct NsmMessage {
            request: libc::iovec,
            response: libc::iovec,
        }

        // `_IOWR(type, nr, size)` con la codificación genérica de Linux (x86_64/aarch64,
        // que es donde corre Nitro): dir (2 bits: READ|WRITE = 3) << 30 | size << 16 |
        // type << 8 | nr. Equivale al `request_code_readwrite!(0x0A, 0, size_of::<NsmMessage>())`
        // de nix que usa la crate oficial.
        let request_code: u64 = (3u64 << 30)
            | ((std::mem::size_of::<NsmMessage>() as u64) << 16)
            | (NSM_IOCTL_MAGIC << 8);

        let opt = |v: &Option<Vec<u8>>| match v {
            Some(b) => Cbor::bytes(b),
            None => Cbor::Null,
        };
        // `Request::Attestation { user_data, nonce, public_key }` tal como lo serializa
        // serde_cbor: `{"Attestation": {"user_data": bytes|null, "nonce": …, "public_key": …}}`.
        let request = Cbor::map_text(vec![(
            "Attestation",
            Cbor::map_text(vec![
                ("user_data", Cbor::bytes(&req.report_data)),
                ("nonce", opt(&req.nonce)),
                ("public_key", opt(&req.public_key)),
            ]),
        )])
        .encode();
        if request.len() > NSM_REQUEST_MAX_SIZE {
            return Err(format!("attest: NSM request is {} bytes, the driver takes at most {}", request.len(), NSM_REQUEST_MAX_SIZE));
        }
        let dev = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/nsm")
            .map_err(|e| format!("attest: cannot open /dev/nsm ({}); is this a Nitro enclave?", e))?;
        let mut response = vec![0u8; NSM_RESPONSE_MAX_SIZE];
        let mut msg = NsmMessage {
            request: libc::iovec { iov_base: request.as_ptr() as *mut libc::c_void, iov_len: request.len() },
            response: libc::iovec { iov_base: response.as_mut_ptr() as *mut libc::c_void, iov_len: response.len() },
        };
        // SAFETY: `msg` apunta a buffers vivos durante la llamada; el driver sólo escribe
        // dentro de `response` (acotado por `iov_len`) y actualiza los `iovec`.
        let rc = unsafe { libc::ioctl(dev.as_raw_fd(), request_code as _, &mut msg as *mut NsmMessage) };
        if rc != 0 {
            return Err(format!("attest: NSM ioctl failed: {}", std::io::Error::last_os_error()));
        }
        let n = msg.response.iov_len.min(NSM_RESPONSE_MAX_SIZE);
        let item = match crate::cbor::decode(&response[..n]) {
            Ok(i) => i,
            // Por si un driver no recortara `iov_len`: el ítem al inicio del buffer.
            Err(_) => crate::cbor::decode_prefix(&response).map(|(i, _)| i).map_err(|e| format!("attest: NSM response is not CBOR: {}", e))?,
        };
        if let Some(e) = item.get("Error") {
            return Err(format!("attest: NSM returned an error: {}", e.as_text().unwrap_or("?")));
        }
        let doc = item
            .get("Attestation")
            .and_then(|a| a.get("document"))
            .and_then(Cbor::as_bytes)
            .ok_or_else(|| "attest: NSM response has no Attestation.document".to_string())?;
        Ok(AttestResult {
            format: "nitro",
            document: doc.to_vec(),
            driver: "nitro",
            report_data: req.report_data.clone(),
            aux: None,
            event_log: None,
            root: None,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn attest(_req: &AttestRequest) -> Result<AttestResult, String> {
        Err("attest: the nitro driver is Linux-only (it talks to /dev/nsm inside a Nitro enclave)".to_string())
    }
}

// =========================================================
// Driver tsm — configfs-tsm (Linux >= 6.7): TDX y SEV-SNP
// =========================================================

#[cfg(target_os = "linux")]
const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";

mod tsm {
    use super::*;

    #[cfg(target_os = "linux")]
    pub fn attest(req: &AttestRequest) -> Result<AttestResult, String> {
        use std::path::Path;
        reject_side_fields(req, "configfs-tsm (TDX/SEV-SNP)")?;
        let base = Path::new(TSM_REPORT_DIR);
        if !base.is_dir() {
            return Err(format!(
                "attest: configfs-tsm is not available ({} missing; it needs Linux >= 6.7 with the TDX or SEV-SNP guest driver, and configfs mounted)",
                TSM_REPORT_DIR
            ));
        }
        // Un directorio por pedido; el kernel lo puebla con inblob/outblob/provider/….
        let mut dir = None;
        for n in 0..64u32 {
            let d = base.join(format!("synsema-{}-{}", std::process::id(), n));
            match std::fs::create_dir(&d) {
                Ok(()) => {
                    dir = Some(d);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("attest: cannot create a configfs-tsm report ({}): {}", d.display(), e)),
            }
        }
        let dir = dir.ok_or_else(|| "attest: too many stale configfs-tsm reports for this pid".to_string())?;
        // rmdir al salir, pase lo que pase.
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());

        let inblob = padded_report_data(req);
        std::fs::write(dir.join("inblob"), &inblob).map_err(|e| format!("attest: configfs-tsm inblob: {}", e))?;
        // Auditoría externa: `generation` cuenta las escrituras a los inputs del reporte; se lee
        // antes y después de `outblob`/`auxblob`/`provider` y si cambió, alguien pisó el
        // reporte a mitad de camino → rechazar (el dir por pid lo hace improbable, no imposible).
        let generation = || -> Result<String, String> {
            std::fs::read_to_string(dir.join("generation"))
                .map(|g| g.trim().to_string())
                .map_err(|e| format!("attest: configfs-tsm generation: {} (the report ABI requires it)", e))
        };
        let gen_before = generation()?;
        let provider = std::fs::read_to_string(dir.join("provider"))
            .map_err(|e| format!("attest: configfs-tsm provider: {}", e))?
            .trim()
            .to_string();
        let format: &'static str = match provider.as_str() {
            "tdx_guest" => "tdx",
            "sev_guest" => "sev-snp",
            other => {
                return Err(format!(
                    "attest: unknown configfs-tsm provider '{}' (expected tdx_guest or sev_guest); refusing to label the report",
                    other
                ))
            }
        };
        let outblob = std::fs::read(dir.join("outblob")).map_err(|e| format!("attest: configfs-tsm outblob: {}", e))?;
        if outblob.is_empty() {
            return Err("attest: configfs-tsm returned an empty outblob".to_string());
        }
        let aux = std::fs::read(dir.join("auxblob")).ok().filter(|b| !b.is_empty());
        let gen_after = generation()?;
        if gen_before != gen_after {
            return Err(format!(
                "attest: configfs-tsm report changed while reading it (generation {} → {}); refusing the outblob",
                gen_before, gen_after
            ));
        }
        Ok(AttestResult { format, document: outblob, driver: "tsm", report_data: inblob, aux, event_log: None, root: None })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn attest(_req: &AttestRequest) -> Result<AttestResult, String> {
        Err("attest: the tsm driver is Linux-only (configfs-tsm, Linux >= 6.7 in a TDX or SEV-SNP guest)".to_string())
    }
}

// =========================================================
// Driver dstack — HTTP/1.1 sobre el socket unix del guest agent
// =========================================================

/// Dónde está el guest agent: `DSTACK_SIMULATOR_ENDPOINT` (una ruta de socket o `http://…`,
/// como honra el SDK oficial) o el primer socket conocido que exista.
#[cfg(unix)]
fn dstack_endpoint() -> Option<dstack::Endpoint> {
    if let Ok(v) = std::env::var("DSTACK_SIMULATOR_ENDPOINT") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            if let Some(rest) = v.strip_prefix("http://") {
                return Some(dstack::Endpoint::Tcp(rest.trim_end_matches('/').to_string()));
            }
            return Some(dstack::Endpoint::Unix { path: v, legacy: false });
        }
    }
    for p in DSTACK_SOCKETS {
        if std::path::Path::new(p).exists() {
            return Some(dstack::Endpoint::Unix { path: p.to_string(), legacy: false });
        }
    }
    if std::path::Path::new(TAPPD_SOCKET).exists() {
        return Some(dstack::Endpoint::Unix { path: TAPPD_SOCKET.to_string(), legacy: true });
    }
    None
}

mod dstack {
    use super::*;

    #[cfg(unix)]
    #[derive(Clone, Debug)]
    pub enum Endpoint {
        /// Socket unix; `legacy` = el `tappd.sock` (< 0.3) con las rutas `/prpc/Tappd.*`.
        Unix { path: String, legacy: bool },
        /// `host:port` (el simulador publicado por HTTP).
        Tcp(String),
    }

    #[cfg(unix)]
    fn endpoint() -> Result<Endpoint, String> {
        dstack_endpoint().ok_or_else(|| {
            format!(
                "attest: dstack guest agent not found (looked for {} and {}; or set DSTACK_SIMULATOR_ENDPOINT)",
                DSTACK_SOCKETS.join(", "),
                TAPPD_SOCKET
            )
        })
    }

    /// `POST <path>` con body JSON; devuelve el body de un 200 o el error con el status.
    #[cfg(unix)]
    fn post_json(ep: &Endpoint, path: &str, body: &str) -> Result<String, String> {
        use std::io::{Read, Write};
        let timeout = Some(std::time::Duration::from_secs(20));
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nUser-Agent: synsema-attest\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            path,
            body.len(),
            body
        );
        let mut raw = Vec::new();
        // Auditoría externa: tope de lectura (un quote + event log entran de sobra en 1 MiB).
        const MAX_RESPONSE: u64 = 1 << 20;
        match ep {
            Endpoint::Unix { path: sock, .. } => {
                let mut s = std::os::unix::net::UnixStream::connect(sock)
                    .map_err(|e| format!("attest: cannot connect to the dstack socket {}: {}", sock, e))?;
                let _ = s.set_read_timeout(timeout);
                let _ = s.set_write_timeout(timeout);
                s.write_all(req.as_bytes()).map_err(|e| format!("attest: dstack write: {}", e))?;
                s.take(MAX_RESPONSE).read_to_end(&mut raw).map_err(|e| format!("attest: dstack read: {}", e))?;
            }
            Endpoint::Tcp(addr) => {
                let mut s = std::net::TcpStream::connect(addr)
                    .map_err(|e| format!("attest: cannot connect to the dstack endpoint {}: {}", addr, e))?;
                let _ = s.set_read_timeout(timeout);
                let _ = s.set_write_timeout(timeout);
                s.write_all(req.as_bytes()).map_err(|e| format!("attest: dstack write: {}", e))?;
                s.take(MAX_RESPONSE).read_to_end(&mut raw).map_err(|e| format!("attest: dstack read: {}", e))?;
            }
        }
        if raw.len() as u64 >= MAX_RESPONSE {
            return Err(format!("attest: dstack {} response exceeds {} bytes", path, MAX_RESPONSE));
        }
        let (status, body) = parse_http_response(&raw)?;
        if status != 200 {
            return Err(format!("attest: dstack {} answered {}: {}", path, status, body.chars().take(300).collect::<String>()));
        }
        Ok(body)
    }

    #[cfg(unix)]
    pub fn attest(req: &AttestRequest) -> Result<AttestResult, String> {
        reject_side_fields(req, "dstack (TDX)")?;
        let ep = endpoint()?;
        let rd = padded_report_data(req);
        let legacy = matches!(ep, Endpoint::Unix { legacy: true, .. });
        // v0.5+: `POST /GetQuote {"report_data": hex}` → `{"quote": hex, "event_log": …}`.
        // tappd (< 0.3): `POST /prpc/Tappd.TdxQuote?json {"report_data": hex, "hash_algorithm": "raw"}`
        // (`raw` = los 64 bytes van tal cual, sin prefijo `app-data:` ni hash).
        let (path, body) = if legacy {
            ("/prpc/Tappd.TdxQuote?json", format!("{{\"report_data\":\"{}\",\"hash_algorithm\":\"raw\"}}", hex_encode(&rd)))
        } else {
            ("/GetQuote", format!("{{\"report_data\":\"{}\"}}", hex_encode(&rd)))
        };
        let resp = post_json(&ep, path, &body)?;
        let v: serde_json::Value = serde_json::from_str(&resp).map_err(|e| format!("attest: dstack {} returned non-JSON: {}", path, e))?;
        let quote_hex = v.get("quote").and_then(|q| q.as_str()).ok_or_else(|| format!("attest: dstack {} response has no `quote`", path))?;
        let quote = hex_decode(quote_hex.trim().trim_start_matches("0x")).map_err(|e| format!("attest: dstack quote is not hex: {}", e))?;
        if quote.is_empty() {
            return Err("attest: dstack returned an empty quote".to_string());
        }
        let event_log = v.get("event_log").map(|e| match e {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        });
        Ok(AttestResult { format: "tdx", document: quote, driver: "dstack", report_data: rd, aux: None, event_log, root: None })
    }

    #[cfg(unix)]
    pub fn get_key(purpose: &str) -> Result<Vec<u8>, String> {
        let ep = endpoint()?;
        if matches!(ep, Endpoint::Unix { legacy: true, .. }) {
            return Err(
                "attest_key: the legacy tappd socket derives certificate keys (DeriveKey returns a PEM), not sealing keys; use dstack >= 0.5 (/GetKey)"
                    .to_string(),
            );
        }
        // `POST /GetKey {"path": …, "purpose": …}` → `{"key": hex, "signature_chain": [hex]}`.
        let body = serde_json::json!({ "path": purpose, "purpose": "" }).to_string();
        let resp = post_json(&ep, "/GetKey", &body)?;
        let v: serde_json::Value = serde_json::from_str(&resp).map_err(|e| format!("attest_key: dstack /GetKey returned non-JSON: {}", e))?;
        let key_hex = v.get("key").and_then(|k| k.as_str()).ok_or_else(|| "attest_key: dstack /GetKey response has no `key`".to_string())?;
        let key = hex_decode(key_hex.trim().trim_start_matches("0x")).map_err(|e| format!("attest_key: dstack key is not hex: {}", e))?;
        if key.is_empty() {
            return Err("attest_key: dstack returned an empty key".to_string());
        }
        Ok(key)
    }

    #[cfg(not(unix))]
    pub fn attest(_req: &AttestRequest) -> Result<AttestResult, String> {
        Err("attest: the dstack driver needs the guest agent's unix socket (this OS has none)".to_string())
    }

    #[cfg(not(unix))]
    pub fn get_key(_purpose: &str) -> Result<Vec<u8>, String> {
        Err("attest_key: the dstack driver needs the guest agent's unix socket (this OS has none)".to_string())
    }
}

/// Parser mínimo de una respuesta HTTP/1.1 (status + body; `Transfer-Encoding: chunked`
/// soportado). Trabaja sobre BYTES de punta a punta (auditoría externa: un corte de chunk en medio
/// de un carácter multibyte no puede hacer panic) y sólo al final convierte el body a texto.
pub fn parse_http_response(raw: &[u8]) -> Result<(u16, String), String> {
    fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
        if needle.is_empty() || hay.len() < needle.len() {
            return None;
        }
        (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
    }
    let split = find(raw, b"\r\n\r\n", 0).ok_or_else(|| "attest: malformed HTTP response (no header terminator)".to_string())?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let body = &raw[split + 4..];
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("attest: malformed HTTP status line: {:?}", status_line))?;
    let chunked = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    if !chunked {
        return Ok((status, String::from_utf8_lossy(body).into_owned()));
    }
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    loop {
        let eol = find(body, b"\r\n", pos).ok_or_else(|| "attest: truncated chunked body".to_string())?;
        let size_line = String::from_utf8_lossy(&body[pos..eol]);
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| format!("attest: bad chunk size {:?}", size_line))?;
        pos = eol + 2;
        if size == 0 {
            break;
        }
        if body.len() < pos + size {
            return Err("attest: truncated chunk".to_string());
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size;
        if body[pos..].starts_with(b"\r\n") {
            pos += 2;
        }
    }
    Ok((status, String::from_utf8_lossy(&out).into_owned()))
}

// =========================================================
// DER mínimo (para la cadena X.509 del mock y el SPKI/PKCS#8 de serve --attested)
// =========================================================

pub mod der {
    /// TLV con longitud en forma corta/larga.
    pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let n = content.len();
        if n < 0x80 {
            out.push(n as u8);
        } else {
            let bytes = n.to_be_bytes();
            let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len() - 1);
            let sig = &bytes[first..];
            out.push(0x80 | sig.len() as u8);
            out.extend_from_slice(sig);
        }
        out.extend_from_slice(content);
        out
    }
    pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }
    pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x31, &parts.concat())
    }
    /// INTEGER sin signo desde bytes big-endian (recorta ceros a la izquierda, antepone
    /// 0x00 si el bit alto está prendido).
    pub fn uint(be: &[u8]) -> Vec<u8> {
        let mut i = 0;
        while i + 1 < be.len() && be[i] == 0 {
            i += 1;
        }
        let body = &be[i..];
        let mut v = Vec::with_capacity(body.len() + 1);
        if body.is_empty() || body[0] & 0x80 != 0 {
            v.push(0);
        }
        v.extend_from_slice(body);
        tlv(0x02, &v)
    }
    pub fn oid(body: &[u8]) -> Vec<u8> {
        tlv(0x06, body)
    }
    pub fn octets(b: &[u8]) -> Vec<u8> {
        tlv(0x04, b)
    }
    pub fn bitstring(b: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8];
        v.extend_from_slice(b);
        tlv(0x03, &v)
    }
    pub fn boolean(b: bool) -> Vec<u8> {
        tlv(0x01, &[if b { 0xff } else { 0x00 }])
    }
    pub fn utf8(s: &str) -> Vec<u8> {
        tlv(0x0c, s.as_bytes())
    }
    pub fn utc_time(s: &str) -> Vec<u8> {
        tlv(0x17, s.as_bytes())
    }
    pub fn generalized_time(s: &str) -> Vec<u8> {
        tlv(0x18, s.as_bytes())
    }
    /// `[n] EXPLICIT`.
    pub fn ctx(n: u8, inner: &[u8]) -> Vec<u8> {
        tlv(0xa0 | n, inner)
    }

    // OIDs (cuerpo ya codificado).
    pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // 1.2.840.10045.2.1
    pub const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7
    pub const OID_SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22]; // 1.3.132.0.34
    pub const OID_ECDSA_WITH_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]; // 1.2.840.10045.4.3.3
    pub const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03]; // 2.5.4.3
    pub const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13]; // 2.5.29.19

    /// SubjectPublicKeyInfo de una clave EC (punto SEC1 sin comprimir).
    pub fn ec_spki(curve_oid: &[u8], point: &[u8]) -> Vec<u8> {
        seq(&[seq(&[oid(OID_EC_PUBLIC_KEY), oid(curve_oid)]), bitstring(point)])
    }

    /// PKCS#8 (v1) de una clave EC: `SEQUENCE { 0, AlgorithmIdentifier, OCTET STRING(ECPrivateKey) }`
    /// con la pública incluida (ring la exige para validar el par).
    pub fn ec_pkcs8(curve_oid: &[u8], scalar: &[u8], point: &[u8]) -> Vec<u8> {
        let ec_private_key = seq(&[uint(&[1]), octets(scalar), ctx(1, &bitstring(point))]);
        seq(&[uint(&[0]), seq(&[oid(OID_EC_PUBLIC_KEY), oid(curve_oid)]), octets(&ec_private_key)])
    }

    /// `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` desde `r ‖ s` crudo.
    pub fn ecdsa_sig_value(raw: &[u8]) -> Vec<u8> {
        let half = raw.len() / 2;
        seq(&[uint(&raw[..half]), uint(&raw[half..])])
    }

    /// Inverso de `ecdsa_sig_value`: `r ‖ s` de `n` bytes cada uno desde el DER.
    pub fn ecdsa_sig_raw(der: &[u8], n: usize) -> Result<Vec<u8>, String> {
        let (tag, body, rest) = read_tlv(der)?;
        if tag != 0x30 || !rest.is_empty() {
            return Err("ECDSA signature is not a DER SEQUENCE".to_string());
        }
        let (t1, r, rest) = read_tlv(body)?;
        let (t2, s, rest) = read_tlv(rest)?;
        if t1 != 0x02 || t2 != 0x02 || !rest.is_empty() {
            return Err("ECDSA signature SEQUENCE is not two INTEGERs".to_string());
        }
        let fix = |v: &[u8]| -> Result<Vec<u8>, String> {
            let v = if v.len() > 1 && v[0] == 0 { &v[1..] } else { v };
            if v.len() > n {
                return Err("ECDSA signature integer is too long for the curve".to_string());
            }
            let mut out = vec![0u8; n - v.len()];
            out.extend_from_slice(v);
            Ok(out)
        };
        let mut out = fix(r)?;
        out.extend(fix(s)?);
        Ok(out)
    }

    /// Lee un TLV: `(tag, contenido, resto)`.
    pub fn read_tlv(b: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
        if b.len() < 2 {
            return Err("DER: truncated".to_string());
        }
        let tag = b[0];
        let (len, off) = if b[1] < 0x80 {
            (b[1] as usize, 2)
        } else {
            let k = (b[1] & 0x7f) as usize;
            if k == 0 || k > 4 || b.len() < 2 + k {
                return Err("DER: bad length".to_string());
            }
            let mut n = 0usize;
            for i in 0..k {
                n = (n << 8) | b[2 + i] as usize;
            }
            (n, 2 + k)
        };
        if b.len() < off + len {
            return Err("DER: length exceeds input".to_string());
        }
        Ok((tag, &b[off..off + len], &b[off + len..]))
    }
}

// =========================================================
// Driver mock — documento Nitro-shaped firmado por una cadena P-384 determinista
// =========================================================

pub mod mock {
    use super::*;
    use p384::ecdsa::signature::Signer;

    pub const ROOT_CN: &str = "synsema mock root";
    pub const LEAF_CN: &str = "synsema mock enclave";
    pub const MODULE_ID: &str = "i-mock-enc0";

    fn seed() -> String {
        std::env::var("SYNSEMA_ATTEST_MOCK_SEED").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| MOCK_DEFAULT_SEED.to_string())
    }

    /// Escalar P-384 determinista: `sha256(seed ‖ label)` como entero (32 bytes, alineado a
    /// la derecha en los 48 del orden — siempre < n; si diera 0, se reintenta con un contador).
    fn scalar(seed: &str, label: &str) -> p384::ecdsa::SigningKey {
        for counter in 0u32..16 {
            let mut h = Sha256::new();
            h.update(seed.as_bytes());
            h.update(label.as_bytes());
            if counter > 0 {
                h.update(counter.to_be_bytes());
            }
            let d: [u8; 32] = h.finalize().into();
            let mut wide = [0u8; 48];
            wide[16..].copy_from_slice(&d);
            if let Ok(k) = p384::ecdsa::SigningKey::from_slice(&wide) {
                return k;
            }
        }
        unreachable!("sha256 output is a valid P-384 scalar except for zero")
    }

    fn sec1_point(k: &p384::ecdsa::SigningKey) -> Vec<u8> {
        k.verifying_key().to_encoded_point(false).as_bytes().to_vec()
    }

    fn name(cn: &str) -> Vec<u8> {
        der::seq(&[der::set(&[der::seq(&[der::oid(der::OID_COMMON_NAME), der::utf8(cn)])])])
    }

    /// Certificado X.509 v3 mínimo firmado con `signer` (ecdsa-with-SHA384).
    fn certificate(serial: u8, issuer_cn: &str, subject_cn: &str, subject_key: &p384::ecdsa::SigningKey, is_ca: bool, signer: &p384::ecdsa::SigningKey) -> Vec<u8> {
        let alg = der::seq(&[der::oid(der::OID_ECDSA_WITH_SHA384)]);
        let basic = if is_ca { der::seq(&[der::boolean(true)]) } else { der::seq(&[]) };
        let extensions = der::ctx(
            3,
            &der::seq(&[der::seq(&[der::oid(der::OID_BASIC_CONSTRAINTS), der::boolean(true), der::octets(&basic)])]),
        );
        let tbs = der::seq(&[
            der::ctx(0, &der::uint(&[2])), // v3
            der::uint(&[serial]),
            alg.clone(),
            name(issuer_cn),
            // RFC 5280: hasta 2049 UTCTime, desde 2050 GeneralizedTime.
            der::seq(&[der::utc_time("200101000000Z"), der::generalized_time("20991231235959Z")]),
            name(subject_cn),
            der::ec_spki(der::OID_SECP384R1, &sec1_point(subject_key)),
            extensions,
        ]);
        let sig: p384::ecdsa::Signature = signer.sign(&tbs);
        der::seq(&[tbs, alg, der::bitstring(&der::ecdsa_sig_value(&sig.to_bytes()))])
    }

    /// La cadena del mock para la semilla en vigor: `(raíz DER, hoja DER, clave de la hoja)`.
    pub fn chain() -> (Vec<u8>, Vec<u8>, p384::ecdsa::SigningKey) {
        let seed = seed();
        let root_key = scalar(&seed, "root");
        let leaf_key = scalar(&seed, "leaf");
        let root = certificate(1, ROOT_CN, ROOT_CN, &root_key, true, &root_key);
        let leaf = certificate(2, ROOT_CN, LEAF_CN, &leaf_key, false, &root_key);
        (root, leaf, leaf_key)
    }

    /// Sólo el DER de la raíz (lo que un cliente de CI pinea).
    pub fn root_der() -> Vec<u8> {
        chain().0
    }

    /// PCRs 0..=15 (48 bytes cada uno): ceros salvo lo que diga `SYNSEMA_ATTEST_MOCK_PCRS`
    /// (`"0=<96 hex>,1=<96 hex>"`). Un valor mal formado es error, no un PCR en cero.
    pub fn pcrs() -> Result<Vec<(Cbor, Cbor)>, String> {
        let mut regs: Vec<Vec<u8>> = vec![vec![0u8; 48]; 16];
        if let Ok(spec) = std::env::var("SYNSEMA_ATTEST_MOCK_PCRS") {
            for item in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let (idx, hex) = item
                    .split_once('=')
                    .ok_or_else(|| format!("attest: SYNSEMA_ATTEST_MOCK_PCRS: expected `index=<96 hex>`, got {:?}", item))?;
                let idx: usize = idx.trim().parse().map_err(|_| format!("attest: SYNSEMA_ATTEST_MOCK_PCRS: bad PCR index {:?}", idx))?;
                if idx > 15 {
                    return Err(format!("attest: SYNSEMA_ATTEST_MOCK_PCRS: PCR index {} out of range (0..=15)", idx));
                }
                let bytes = hex_decode(hex.trim()).map_err(|e| format!("attest: SYNSEMA_ATTEST_MOCK_PCRS: PCR{}: {}", idx, e))?;
                if bytes.len() != 48 {
                    return Err(format!("attest: SYNSEMA_ATTEST_MOCK_PCRS: PCR{} must be 48 bytes (96 hex), got {}", idx, bytes.len()));
                }
                regs[idx] = bytes;
            }
        }
        Ok(regs.into_iter().enumerate().map(|(i, v)| (Cbor::Int(i as i128), Cbor::Bytes(v))).collect())
    }

    fn timestamp_ms() -> Result<i128, String> {
        match std::env::var("SYNSEMA_ATTEST_MOCK_TIMESTAMP") {
            Ok(v) if !v.trim().is_empty() => v
                .trim()
                .parse::<i128>()
                .ok()
                .filter(|t| *t >= 0)
                .ok_or_else(|| format!("attest: SYNSEMA_ATTEST_MOCK_TIMESTAMP must be milliseconds since the epoch, got {:?}", v)),
            _ => Ok(MOCK_DEFAULT_TIMESTAMP_MS),
        }
    }

    pub fn attest(req: &AttestRequest) -> Result<AttestResult, String> {
        warn_if_mock(Driver::Mock);
        let (root, leaf, leaf_key) = chain();
        let opt = |v: &Option<Vec<u8>>| match v {
            Some(b) => Cbor::bytes(b),
            None => Cbor::Null,
        };
        // El orden de las claves es el del struct `AttestationDoc` de la crate de AWS.
        let payload = Cbor::map_text(vec![
            ("module_id", Cbor::text(MODULE_ID)),
            ("digest", Cbor::text("SHA384")),
            ("timestamp", Cbor::Int(timestamp_ms()?)),
            ("pcrs", Cbor::Map(pcrs()?)),
            ("certificate", Cbor::bytes(&leaf)),
            ("cabundle", Cbor::Array(vec![Cbor::bytes(&root)])),
            ("public_key", opt(&req.public_key)),
            ("user_data", if req.report_data.is_empty() { Cbor::Null } else { Cbor::bytes(&req.report_data) }),
            ("nonce", opt(&req.nonce)),
        ])
        .encode();
        let protected = cose_protected_alg(COSE_ALG_ES384);
        let sig_structure = crate::cbor::cose_sign1_sig_structure(&protected, &payload);
        let sig: p384::ecdsa::Signature = leaf_key.sign(&sig_structure);
        let cose = CoseSign1 { protected, unprotected: Cbor::Map(Vec::new()), payload: Some(payload), signature: sig.to_bytes().to_vec() };
        Ok(AttestResult {
            // Auditoría externa: el formato dice `mock`, no `nitro`. El documento es COSE_Sign1 con la
            // MISMA forma que el de NSM (por eso `attestation_verify` lo verifica con el mismo
            // código), pero su etiqueta no miente sobre de dónde viene.
            format: "mock",
            document: cose.encode_untagged(),
            driver: "mock",
            report_data: req.report_data.clone(),
            aux: None,
            event_log: None,
            root: Some(root),
        })
    }

    /// Clave "sellada" del mock: HKDF-SHA256(ikm = semilla, salt fijo, info = purpose), 32 bytes.
    pub fn derive_key(purpose: &str) -> Vec<u8> {
        warn_if_mock(Driver::Mock);
        let hk = hkdf::Hkdf::<Sha256>::new(Some(b"synsema-attest-key"), seed().as_bytes());
        let mut out = vec![0u8; 32];
        hk.expand(purpose.as_bytes(), &mut out).expect("32 bytes is a valid HKDF length");
        out
    }
}

// =========================================================
// Verificador mínimo (formato nitro): firma COSE ES384 con la hoja + hoja firmada por la raíz
// =========================================================

/// Verifica un documento con formato `nitro` contra UNA raíz dada (DER): firma ES384 del
/// `COSE_Sign1` con la clave de `certificate`, `cabundle[0] == root` y la hoja firmada por la
/// raíz. Devuelve el payload decodificado. Es el verificador de los tests y del CI para el
/// driver `mock`; el builtin completo (raíz de AWS pineada, validez, TDX/SNP) es
/// `attestation_verify`.
pub fn verify_nitro_document_with_root(document: &[u8], root_der: &[u8]) -> Result<Cbor, String> {
    use p384::ecdsa::signature::Verifier;
    use x509_parser::prelude::*;

    let cose = CoseSign1::parse(document)?;
    if cose.alg()? != COSE_ALG_ES384 {
        return Err(format!("attestation: unexpected COSE alg {} (expected ES384 = -35)", cose.alg()?));
    }
    let payload_bytes = cose.payload.clone().ok_or("attestation: detached payload")?;
    let payload = crate::cbor::decode(&payload_bytes).map_err(|e| format!("attestation: payload: {}", e))?;
    let leaf_der = payload.get("certificate").and_then(Cbor::as_bytes).ok_or("attestation: payload has no `certificate`")?;
    let bundle = payload.get("cabundle").and_then(Cbor::as_array).ok_or("attestation: payload has no `cabundle`")?;
    match bundle.first().and_then(Cbor::as_bytes) {
        Some(first) if first == root_der => {}
        _ => return Err("attestation: cabundle[0] is not the pinned root".to_string()),
    }
    let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(|e| format!("attestation: leaf certificate: {:?}", e))?;
    let (_, root) = X509Certificate::from_der(root_der).map_err(|e| format!("attestation: root certificate: {:?}", e))?;
    if !root.is_ca() {
        return Err("attestation: the root is not a CA".to_string());
    }
    if leaf.issuer() != root.subject() {
        return Err("attestation: the leaf was not issued by the root".to_string());
    }
    // Hoja firmada por la raíz (ecdsa-with-SHA384, firma DER).
    let root_vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&root.public_key().subject_public_key.data).map_err(|_| "attestation: root key is not P-384".to_string())?;
    let leaf_sig_raw = der::ecdsa_sig_raw(&leaf.signature_value.data, 48)?;
    let leaf_sig = p384::ecdsa::Signature::from_slice(&leaf_sig_raw).map_err(|_| "attestation: leaf signature is malformed".to_string())?;
    root_vk.verify(leaf.tbs_certificate.as_ref(), &leaf_sig).map_err(|_| "attestation: leaf certificate signature does not verify against the root".to_string())?;
    // COSE firmado por la hoja (ES384 cruda r‖s).
    let leaf_vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&leaf.public_key().subject_public_key.data).map_err(|_| "attestation: leaf key is not P-384".to_string())?;
    let cose_sig = p384::ecdsa::Signature::from_slice(&cose.signature).map_err(|_| "attestation: COSE signature must be 96 bytes (r ‖ s)".to_string())?;
    leaf_vk.verify(&cose.sig_structure(), &cose_sig).map_err(|_| "attestation: COSE_Sign1 signature does not verify".to_string())?;
    Ok(payload)
}

// =========================================================
// Identidad atestada de `serve --attested`
// =========================================================

/// Auditoría externa — la CONFIGURACIÓN bajo la que corre el programa, atada en `report_data`: un
/// cliente sabe no sólo QUÉ `.syn` corre sino si las etiquetas estaban activas, qué techo de
/// capabilities tenía el host, si la clave anunciada es la del cert TLS, y con qué motor y
/// perfil. Se serializa a un JSON CANÓNICO (claves en orden alfabético fijo, sin espacios) y se
/// publica entero junto con su `config_sha` para que se pueda recomputar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestConfig {
    /// Etiquetas de flujo (`--labels`; `serve --attested` las enciende siempre).
    pub labels: bool,
    /// Techo del host: `None` = sin techo ("unbounded"); `Some(vacío)` = "none"; si no, la
    /// lista `cap_set_item()` ORDENADA.
    pub ceiling: Option<Vec<Capability>>,
    /// `"attested"` (el cert TLS se emite con la clave anunciada) | `"operator"` (`--tls-cert`
    /// / `--tls-auto` / cláusulas `tls` del archivo: la clave anunciada NO es la del canal TLS)
    /// | `"none"` (`run --attest`, sin servidor).
    pub tls_key: &'static str,
    /// `"native"` | `"pure"`.
    pub profile: &'static str,
}

impl AttestConfig {
    /// JSON canónico: `{"ceiling":…,"engine":"…","labels":bool,"profile":"…","tls_key":"…"}`.
    pub fn canonical_json(&self) -> String {
        let q = |s: &str| serde_json::Value::String(s.to_string()).to_string();
        let ceiling = match &self.ceiling {
            None => q("unbounded"),
            Some(c) if c.is_empty() => q("none"),
            Some(c) => {
                let mut items: Vec<String> = c.iter().map(|x| x.cap_set_item()).collect();
                items.sort();
                items.dedup();
                format!("[{}]", items.iter().map(|i| q(i)).collect::<Vec<_>>().join(","))
            }
        };
        format!(
            "{{\"ceiling\":{},\"engine\":{},\"labels\":{},\"profile\":{},\"tls_key\":{}}}",
            ceiling,
            q(engine_version()),
            self.labels,
            q(self.profile),
            q(self.tls_key)
        )
    }

    /// El objeto (para publicarlo en el JSON de la identidad / de `run --attest`).
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.canonical_json()).expect("canonical config is valid JSON")
    }

    /// `config_sha = sha256(json canónico)`.
    pub fn sha(&self) -> [u8; 32] {
        sha256(self.canonical_json().as_bytes())
    }
}

/// Lo que un `synsema serve --attested` genera al arrancar y publica en
/// `GET /.well-known/attestation`: un par P-256 efímero, el hash del programa, la
/// configuración y el documento que ata `sha256(spki ‖ program_sha ‖ config_sha)`.
pub struct AttestedIdentity {
    /// Escalar privado P-256 (32 bytes) — el formato que `ecdh_shared_secret` acepta.
    pub private_scalar: Vec<u8>,
    /// PKCS#8 DER de la misma clave (para el certificado TLS autofirmado).
    pub pkcs8_der: Vec<u8>,
    /// SubjectPublicKeyInfo DER.
    pub spki_der: Vec<u8>,
    pub program_sha: [u8; 32],
    pub config: AttestConfig,
    pub config_sha: [u8; 32],
    pub report_data: [u8; 32],
    pub attestation: AttestResult,
}

impl AttestedIdentity {
    pub fn public_key_pem(&self) -> String {
        pem("PUBLIC KEY", &self.spki_der)
    }

    /// El JSON de `GET /.well-known/attestation` (también lo devuelve `attestation_document()`).
    pub fn json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "format": self.attestation.format,
            "document": b64_encode(&self.attestation.document),
            "public_key": self.public_key_pem(),
            "public_key_hex": hex_encode(&self.spki_der),
            "program_sha": hex_encode(&self.program_sha),
            "config": self.config.json(),
            "config_sha": hex_encode(&self.config_sha),
            // Auditoría externa: si el cert TLS lleva la clave anunciada o la del operador.
            "tls_key": self.config.tls_key,
            "engine": engine_version(),
            "driver": self.attestation.driver,
        });
        if let Some(aux) = &self.attestation.aux {
            v["aux"] = serde_json::Value::String(b64_encode(aux));
        }
        if let Some(log) = &self.attestation.event_log {
            v["event_log"] = serde_json::Value::String(log.clone());
        }
        if self.attestation.driver == "mock" {
            v["mock"] = serde_json::Value::Bool(true);
            // Auditoría MEDIO 2: el cliente de CI necesita la raíz del mock para poder llamar
            // `attestation_verify(doc, {"format": "mock", "now": …, "root": …})` — sin ella la
            // receta documentada no corre. Sólo la publica el mock (una raíz de desarrollo,
            // forjable a propósito); ninguna plataforma real manda su raíz por este canal.
            if let Some(root) = &self.attestation.root {
                v["root"] = serde_json::Value::String(b64_encode(root));
            }
        }
        v
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = b64_encode(der);
    let mut out = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {}-----\n", label));
    out
}

/// Versión del motor (la del release o la del crate), como en `/healthz`.
pub fn engine_version() -> &'static str {
    option_env!("SYNSEMA_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

/// Genera el par P-256 desde OsRng y pide la attestation con
/// `report_data = sha256(spki ‖ program_sha ‖ config_sha)`. Falla → el servidor no arranca.
pub fn build_attested_identity(source: &str, filename: &str, config: AttestConfig) -> Result<AttestedIdentity, String> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let program_sha = program_sha(source, filename).map_err(|e| format!("serve --attested: cannot hash the program: {}", e))?;
    let mut scalar = None;
    for _ in 0..16 {
        let bytes = crate::webauth::os_random(32, "serve --attested").map_err(|e| match e {
            Control::Error(re) => re.into_message(),
            _ => "serve --attested: OS random source unavailable".to_string(),
        })?;
        if p256::SecretKey::from_slice(&bytes).is_ok() {
            scalar = Some(bytes);
            break;
        }
    }
    let private_scalar = scalar.ok_or_else(|| "serve --attested: could not draw a valid P-256 scalar".to_string())?;
    let sk = p256::SecretKey::from_slice(&private_scalar).map_err(|_| "serve --attested: invalid scalar".to_string())?;
    let point = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
    let spki_der = der::ec_spki(der::OID_PRIME256V1, &point);
    let pkcs8_der = der::ec_pkcs8(der::OID_PRIME256V1, &private_scalar, &point);
    let config_sha = config.sha();
    let mut h = Sha256::new();
    h.update(&spki_der);
    h.update(program_sha);
    h.update(config_sha);
    let report_data: [u8; 32] = h.finalize().into();
    let attestation = attest_document(&AttestRequest { report_data: report_data.to_vec(), nonce: None, public_key: None })
        .map_err(|e| format!("serve --attested: {}", e))?;
    Ok(AttestedIdentity { private_scalar, pkcs8_der, spki_der, program_sha, config, config_sha, report_data, attestation })
}

/// Certificado TLS autofirmado (DER) emitido con LA MISMA clave P-256 de la identidad: el
/// cliente pinea el SPKI del cert al `public_key_hex` anunciado. Nada se escribe a disco.
/// `sans`: nombres/IPs del certificado (`localhost`, la dirección de bind).
#[cfg(feature = "native")]
pub fn self_signed_cert_der(id: &AttestedIdentity, sans: &[String]) -> Result<Vec<u8>, String> {
    let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(id.pkcs8_der.clone());
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| format!("serve --attested: cannot load the attested key for TLS: {}", e))?;
    let mut params = rcgen::CertificateParams::new(sans.to_vec()).map_err(|e| format!("serve --attested: bad TLS name: {}", e))?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "synsema attested serve");
    let cert = params.self_signed(&key).map_err(|e| format!("serve --attested: cannot self-sign the TLS certificate: {}", e))?;
    Ok(cert.der().to_vec())
}

static IDENTITY: OnceLock<Arc<AttestedIdentity>> = OnceLock::new();

/// Publica la identidad del proceso (una sola vez; la lee todo intérprete del serve).
pub fn install_attested_identity(id: AttestedIdentity) -> Result<(), String> {
    IDENTITY.set(Arc::new(id)).map_err(|_| "serve --attested: the attested identity was already installed".to_string())
}

pub fn attested_identity() -> Option<Arc<AttestedIdentity>> {
    IDENTITY.get().cloned()
}

// =========================================================
// Builtins
// =========================================================

fn require_attest(caps: &Rc<RefCell<CapabilitySet>>, source: &str) -> Result<(), Control> {
    caps.borrow_mut()
        .require(&Capability::new(CapabilityType::Attest, None), source)
        .map_err(|v| Control::Error(v.into_error()))
}

fn opt_bytes(m: &IndexMap<String, SynValue>, key: &str, who: &str) -> Result<Option<Vec<u8>>, Control> {
    match m.get(key) {
        None | Some(SynValue::Nothing) => Ok(None),
        Some(SynValue::Bytes(b)) => Ok(Some(b.to_vec())),
        Some(SynValue::Text(t)) => Ok(Some(t.as_bytes().to_vec())),
        Some(other) => Err(err(format!("{}: {} must be bytes, got {}", who, key, other.type_name()))),
    }
}

fn result_to_map(res: &AttestResult) -> SynValue {
    let mut out = IndexMap::new();
    out.insert("format".to_string(), syn_text(res.format));
    out.insert("document".to_string(), syn_bytes(res.document.clone()));
    out.insert("driver".to_string(), syn_text(res.driver));
    out.insert("report_data".to_string(), syn_bytes(res.report_data.clone()));
    if let Some(aux) = &res.aux {
        out.insert("aux".to_string(), syn_bytes(aux.clone()));
    }
    if let Some(log) = &res.event_log {
        out.insert("event_log".to_string(), syn_text(log.clone()));
    }
    if let Some(root) = &res.root {
        out.insert("root".to_string(), syn_bytes(root.clone()));
    }
    // Auditoría externa: que nadie confunda un documento del mock con uno de plataforma.
    if res.driver == "mock" {
        out.insert("mock".to_string(), syn_bool(true));
    }
    syn_map(out)
}

/// `serde_json::Value` → SynValue (para `attestation_document()`; sólo texto/objeto).
fn json_to_syn(v: &serde_json::Value) -> SynValue {
    match v {
        serde_json::Value::String(s) => syn_text(s.clone()),
        serde_json::Value::Object(o) => {
            let mut m = IndexMap::new();
            for (k, val) in o {
                m.insert(k.clone(), json_to_syn(val));
            }
            syn_map(m)
        }
        other => syn_text(other.to_string()),
    }
}

fn b_attest(caps: &Rc<RefCell<CapabilitySet>>, args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "attest";
    if args.len() > 1 {
        return Err(err(format!("{}(opts?) takes at most 1 argument", F)));
    }
    let mut req = AttestRequest::default();
    match args.first() {
        None | Some(SynValue::Nothing) => {}
        Some(SynValue::Map(m)) => {
            let m = m.borrow();
            req.report_data = opt_bytes(&m, "report_data", F)?.unwrap_or_default();
            req.nonce = opt_bytes(&m, "nonce", F)?;
            req.public_key = opt_bytes(&m, "public_key", F)?;
        }
        Some(other) => return Err(err(format!("{}: opts must be a map, got {}", F, other.type_name()))),
    }
    if req.report_data.len() > MAX_REPORT_DATA {
        return Err(err(format!("{}: report_data must be at most {} bytes, got {} (hash it first: sha256(...) is 32)", F, MAX_REPORT_DATA, req.report_data.len())));
    }
    // El gate va ANTES de tocar cualquier dispositivo.
    require_attest(caps, "attest()")?;
    let res = attest_document(&req).map_err(err)?;
    Ok(result_to_map(&res))
}

fn b_attest_key(caps: &Rc<RefCell<CapabilitySet>>, args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "attest_key";
    let purpose = match args {
        [SynValue::Text(t)] => t.to_string(),
        [other] => return Err(err(format!("{}: purpose must be text, got {}", F, other.type_name()))),
        _ => return Err(err(format!("{}(purpose) takes exactly 1 argument", F))),
    };
    require_attest(caps, "attest_key()")?;
    let key = attest_key_bytes(&purpose).map_err(err)?;
    Ok(syn_secret_bytes(format!("attest_key:{}", purpose), key))
}

const NOT_ATTESTED: &str = "this server is not attested (start it with `synsema serve --attested`)";

fn b_attestation_document(_args: &[SynValue]) -> Result<SynValue, Control> {
    match attested_identity() {
        Some(id) => Ok(json_to_syn(&id.json())),
        None => Err(err(format!("attestation_document: {}", NOT_ATTESTED))),
    }
}

fn b_attestation_key(caps: &Rc<RefCell<CapabilitySet>>, _args: &[SynValue]) -> Result<SynValue, Control> {
    require_attest(caps, "attestation_key()")?;
    match attested_identity() {
        // Auditoría externa: secret SELLADO — `reveal()` lo rechaza siempre; sólo lo consumen
        // `ecdh_shared_secret`/firma vía `expose_bytes`. Es la clave que ancla TLS y el
        // documento: exportarla anularía la attestation.
        Some(id) => Ok(SynValue::Secret(Rc::new(SecretInner::new_bytes_sealed("attestation_key", id.private_scalar.clone())))),
        None => Err(err(format!("attestation_key: {}", NOT_ATTESTED))),
    }
}

/// Registra `attest`, `attest_key`, `attestation_document`, `attestation_key`. Los cuatro
/// existen en todo intérprete (run/serve/workers); los gateados cierran sobre el
/// `CapabilitySet` del contexto, así que un techo que no liste `attest` los niega.
pub fn register_attest_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    {
        let caps = caps.clone();
        interp.register_builtin("attest", -1, Rc::new(move |_i, a, _l| b_attest(&caps, a)));
    }
    {
        let caps = caps.clone();
        interp.register_builtin("attest_key", 1, Rc::new(move |_i, a, _l| b_attest_key(&caps, a)));
    }
    interp.register_builtin("attestation_document", 0, Rc::new(|_i, a, _l| b_attestation_document(a)));
    interp.register_builtin("attestation_key", 0, Rc::new(move |_i, a, _l| b_attestation_key(&caps, a)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializa los tests que tocan las env-vars del mock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with_env<T>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
        let _g = env_lock();
        let saved: Vec<(String, Option<String>)> = vars.iter().map(|(k, _)| (k.to_string(), std::env::var(k).ok())).collect();
        for (k, v) in vars {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        let out = f();
        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(&k, v),
                None => std::env::remove_var(&k),
            }
        }
        out
    }

    const MOCK_ON: &[(&str, Option<&str>)] = &[
        ("SYNSEMA_ATTEST", Some("mock")),
        ("SYNSEMA_ATTEST_MOCK_SEED", None),
        ("SYNSEMA_ATTEST_MOCK_PCRS", None),
        ("SYNSEMA_ATTEST_MOCK_TIMESTAMP", None),
    ];

    #[test]
    fn mock_document_is_deterministic_and_seed_sensitive() {
        let req = AttestRequest { report_data: vec![7u8; 32], nonce: Some(b"n".to_vec()), public_key: None };
        let a = with_env(MOCK_ON, || attest_document(&req).unwrap());
        let b = with_env(MOCK_ON, || attest_document(&req).unwrap());
        assert_eq!(a.document, b.document, "misma semilla → mismo documento");
        // Auditoría externa: el formato NO se hace pasar por `nitro`.
        assert_eq!(a.format, "mock");
        assert_eq!(a.driver, "mock");
        assert!(a.root.is_some(), "el mock devuelve su raíz");
        let c = with_env(&[("SYNSEMA_ATTEST", Some("mock")), ("SYNSEMA_ATTEST_MOCK_SEED", Some("otra"))], || attest_document(&req).unwrap());
        assert_ne!(a.document, c.document, "otra semilla → otro documento");
        assert_ne!(a.root, c.root);
        // El documento de la semilla B no verifica contra la raíz de la semilla A.
        assert!(verify_nitro_document_with_root(&c.document, a.root.as_ref().unwrap()).is_err());
    }

    #[test]
    fn mock_document_verifies_cose_and_chain_and_carries_fields() {
        let req = AttestRequest { report_data: vec![1, 2, 3], nonce: Some(vec![9, 9]), public_key: Some(vec![4; 65]) };
        let res = with_env(MOCK_ON, || attest_document(&req).unwrap());
        let payload = verify_nitro_document_with_root(&res.document, res.root.as_ref().unwrap()).expect("firma COSE + cadena válidas");
        assert_eq!(payload.get("module_id").unwrap().as_text().unwrap(), mock::MODULE_ID);
        assert_eq!(payload.get("digest").unwrap().as_text().unwrap(), "SHA384");
        assert_eq!(payload.get("timestamp").unwrap().as_int().unwrap(), MOCK_DEFAULT_TIMESTAMP_MS);
        assert_eq!(payload.get("user_data").unwrap().as_bytes().unwrap(), &[1, 2, 3]);
        assert_eq!(payload.get("nonce").unwrap().as_bytes().unwrap(), &[9, 9]);
        assert_eq!(payload.get("public_key").unwrap().as_bytes().unwrap().len(), 65);
        let pcrs = payload.get("pcrs").unwrap().as_map().unwrap();
        assert_eq!(pcrs.len(), 16);
        assert!(pcrs.iter().all(|(_, v)| v.as_bytes().unwrap() == [0u8; 48]));
        // Sin tag 18, como NSM.
        assert_eq!(res.document[0] & 0xe0, 0x80, "array CBOR pelado");
        // Un byte cambiado en el payload rompe la firma.
        let mut bad = res.document.clone();
        let idx = bad.len() / 2;
        bad[idx] ^= 0x01;
        assert!(verify_nitro_document_with_root(&bad, res.root.as_ref().unwrap()).is_err());
    }

    #[test]
    fn mock_pcrs_and_timestamp_come_from_env_and_are_validated() {
        let pcr0 = "ab".repeat(48);
        let pcr2 = "01".repeat(48);
        let spec = format!("0={},2={}", pcr0, pcr2);
        let res = with_env(
            &[("SYNSEMA_ATTEST", Some("mock")), ("SYNSEMA_ATTEST_MOCK_PCRS", Some(spec.as_str())), ("SYNSEMA_ATTEST_MOCK_TIMESTAMP", Some("1234"))],
            || attest_document(&AttestRequest::default()).unwrap(),
        );
        let payload = verify_nitro_document_with_root(&res.document, res.root.as_ref().unwrap()).unwrap();
        assert_eq!(payload.get("timestamp").unwrap().as_int().unwrap(), 1234);
        let pcrs = payload.get("pcrs").unwrap();
        assert_eq!(pcrs.get_int(0).unwrap().as_bytes().unwrap(), &[0xab; 48]);
        assert_eq!(pcrs.get_int(1).unwrap().as_bytes().unwrap(), &[0u8; 48]);
        assert_eq!(pcrs.get_int(2).unwrap().as_bytes().unwrap(), &[0x01; 48]);
        assert!(payload.get("user_data").unwrap().is_null(), "sin report_data → null");
        // Mal formado → error, no ceros silenciosos.
        for bad in ["0=abcd", "16=aa", "x=00", "0"] {
            let r = with_env(&[("SYNSEMA_ATTEST", Some("mock")), ("SYNSEMA_ATTEST_MOCK_PCRS", Some(bad))], || attest_document(&AttestRequest::default()));
            assert!(r.is_err(), "{:?} debería fallar", bad);
        }
        let r = with_env(&[("SYNSEMA_ATTEST", Some("mock")), ("SYNSEMA_ATTEST_MOCK_TIMESTAMP", Some("ayer"))], || attest_document(&AttestRequest::default()));
        assert!(r.unwrap_err().contains("SYNSEMA_ATTEST_MOCK_TIMESTAMP"));
    }

    #[test]
    fn report_data_over_64_bytes_is_rejected_and_mock_is_never_autodetected() {
        let r = with_env(MOCK_ON, || attest_document(&AttestRequest { report_data: vec![0; 65], ..Default::default() }));
        assert!(r.unwrap_err().contains("at most 64"));
        // Sin SYNSEMA_ATTEST: en Windows/macOS no hay plataforma → el error canónico; en
        // Linux sólo habría driver si existe el dispositivo real (jamás `mock`).
        let r = with_env(&[("SYNSEMA_ATTEST", None), ("DSTACK_SIMULATOR_ENDPOINT", None)], select_driver);
        match r {
            Ok(d) => assert_ne!(d, Driver::Mock, "el mock jamás se autodetecta"),
            Err(e) => assert_eq!(e, NO_PLATFORM),
        }
        let r = with_env(&[("SYNSEMA_ATTEST", Some("banana"))], select_driver);
        assert!(r.unwrap_err().contains("unknown driver 'banana'"));
        assert_eq!(with_env(&[("SYNSEMA_ATTEST", Some(" TDX "))], select_driver).unwrap(), Driver::Tsm);
        // L7: el endpoint del simulador de dstack NO elige el driver por sí solo.
        let r = with_env(&[("SYNSEMA_ATTEST", None), ("DSTACK_SIMULATOR_ENDPOINT", Some("/tmp/does-not-matter.sock"))], select_driver);
        match r {
            Ok(d) => assert_ne!(d, Driver::Dstack, "sólo un socket real autodetecta dstack"),
            Err(e) => assert_eq!(e, NO_PLATFORM),
        }
        assert_eq!(with_env(&[("SYNSEMA_ATTEST", Some("dstack")), ("DSTACK_SIMULATOR_ENDPOINT", Some("/tmp/x.sock"))], select_driver).unwrap(), Driver::Dstack);
        // L20: `preflight` detecta la plataforma ausente sin pedir un documento (nitro fuera
        // de un enclave: Linux-only o sin /dev/nsm); con mock pasa.
        if !std::path::Path::new("/dev/nsm").exists() {
            assert!(with_env(&[("SYNSEMA_ATTEST", Some("nitro"))], preflight).unwrap_err().contains("nsm"));
        }
        assert_eq!(with_env(MOCK_ON, preflight).unwrap(), Driver::Mock);
    }

    #[test]
    fn attest_map_flags_the_mock_and_attestation_key_is_sealed() {
        let res = with_env(MOCK_ON, || attest_document(&AttestRequest::default()).unwrap());
        let m = result_to_map(&res);
        let SynValue::Map(m) = m else { panic!() };
        assert!(matches!(m.borrow().get("mock"), Some(SynValue::Bool(true))), "L6: attest() marca mock");
        assert!(m.borrow().get("root").is_some());
        // M8: la clave de identidad sale sellada (reveal la rechaza; expose_bytes funciona).
        let sealed = SecretInner::new_bytes_sealed("attestation_key", vec![1, 2, 3]);
        assert!(sealed.is_sealed());
        assert_eq!(sealed.expose_bytes(), &[1, 2, 3]);
        assert!(!SecretInner::new_bytes("x", vec![1]).is_sealed());
        assert_eq!(sealed.to_string(), "secret(attestation_key)");
    }

    #[test]
    fn mock_key_is_deterministic_per_purpose_and_seed() {
        let a = with_env(MOCK_ON, || attest_key_bytes("state").unwrap());
        let b = with_env(MOCK_ON, || attest_key_bytes("state").unwrap());
        let c = with_env(MOCK_ON, || attest_key_bytes("other").unwrap());
        let d = with_env(&[("SYNSEMA_ATTEST", Some("mock")), ("SYNSEMA_ATTEST_MOCK_SEED", Some("s2"))], || attest_key_bytes("state").unwrap());
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert!(with_env(MOCK_ON, || attest_key_bytes("  ")).is_err());
    }

    #[test]
    fn attest_is_denied_without_require_and_under_deterministic_ceiling() {
        use synsema_core::interpreter::Interpreter;
        let run = |ceiling: Option<Vec<Capability>>, grant: bool| -> Result<SynValue, String> {
            let interp = Interpreter::new();
            let mut cs = CapabilitySet::new("program");
            if let Some(c) = ceiling {
                cs.ceiling = Some(Rc::new(c));
            }
            if grant {
                cs.grant(Capability::new(CapabilityType::Attest, None));
            }
            let caps = Rc::new(RefCell::new(cs));
            register_attest_builtins(&interp, caps.clone());
            let r = b_attest(&caps, &[]);
            r.map_err(|c| match c {
                Control::Error(e) => e.into_message(),
                _ => "?".to_string(),
            })
        };
        with_env(MOCK_ON, || {
            // Sin `require attest` → negado (deny-by-default), sin tocar el driver.
            let e = run(None, false).unwrap_err();
            assert!(e.contains("attest"), "{}", e);
            // Con require y sin techo → documento.
            let v = run(None, true).unwrap();
            assert!(matches!(v, SynValue::Map(_)));
            // Bajo el techo determinista (sólo stdout), el require no concede nada.
            let e = run(Some(synsema_capabilities::model::build_ceiling_deterministic()), true).unwrap_err();
            assert!(e.contains("attest"), "{}", e);
            // Bajo --sandbox tampoco.
            let e = run(synsema_capabilities::model::build_ceiling(true, None).unwrap(), true).unwrap_err();
            assert!(e.contains("attest"), "{}", e);
        });
    }

    /// Auditoría externa: la familia de CUSTODIA entraba por `key_material`
    /// (`blockchain.rs`) con `expose_bytes()` crudo, así que `keystore_export`,
    /// `mnemonic_from_entropy` y `hd_derive` exportaban la clave de identidad atestada entera
    /// (keystore V3 con contraseña del programa; 24 palabras BIP-39 en claro). `key_material` es
    /// el embudo de toda la familia —firma incluida—, así que cerrarlo cierra los cinco caminos.
    #[test]
    fn the_custody_family_refuses_a_sealed_key() {
        let sealed = SynValue::Secret(Rc::new(SecretInner::new_bytes_sealed("attestation_key", vec![7u8; 32])));
        for who in ["keystore_export", "mnemonic_from_entropy", "hd_derive", "secp256k1_sign", "ed25519_sign"] {
            let e = match crate::blockchain::key_material(&sealed, who) {
                Err(Control::Error(e)) => e.into_message(),
                Ok(_) => panic!("{}: la clave sellada NO puede salir por key_material", who),
                Err(_) => panic!("{}: control flow", who),
            };
            assert!(e.contains("sealed") && e.contains(who), "{}: {}", who, e);
        }
        // Un secret de clave normal sigue funcionando (no se nerfea la custodia legítima).
        let normal = SynValue::Secret(Rc::new(SecretInner::new_bytes("HOT_KEY", vec![3u8; 32])));
        let (name, key) = match crate::blockchain::key_material(&normal, "secp256k1_sign") {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("clave normal rechazada: {}", e.message),
            Err(_) => panic!("control flow"),
        };
        assert_eq!((name.as_str(), key.len()), ("HOT_KEY", 32));
    }

    #[test]
    fn attestation_document_and_key_need_an_attested_server() {
        let interp = Interpreter::new();
        let mut cs = CapabilitySet::new("program");
        cs.grant(Capability::new(CapabilityType::Attest, None));
        let caps = Rc::new(RefCell::new(cs));
        register_attest_builtins(&interp, caps.clone());
        if attested_identity().is_none() {
            let e = match b_attestation_document(&[]) {
                Err(Control::Error(e)) => e.into_message(),
                _ => panic!(),
            };
            assert!(e.contains("--attested"), "{}", e);
            let e = match b_attestation_key(&caps, &[]) {
                Err(Control::Error(e)) => e.into_message(),
                _ => panic!(),
            };
            assert!(e.contains("--attested"), "{}", e);
        }
        // Sin la capability, attestation_key se niega ANTES de mirar la identidad.
        let bare = Rc::new(RefCell::new(CapabilitySet::new("program")));
        let e = match b_attestation_key(&bare, &[]) {
            Err(Control::Error(e)) => e.into_message(),
            _ => panic!(),
        };
        assert!(e.contains("attest"), "{}", e);
    }

    fn test_config() -> AttestConfig {
        AttestConfig { labels: true, ceiling: None, tls_key: "attested", profile: "native" }
    }

    #[test]
    fn attested_identity_binds_spki_program_sha_and_config_sha() {
        let src = "print(1 + 1)\n";
        let id = with_env(MOCK_ON, || build_attested_identity(src, "p.syn", test_config()).unwrap());
        assert_eq!(id.program_sha, program_sha(src, "p.syn").unwrap());
        // M7: report_data = sha256(spki ‖ program_sha ‖ config_sha), con el config publicado.
        assert_eq!(id.config_sha, test_config().sha());
        let mut h = Sha256::new();
        h.update(&id.spki_der);
        h.update(id.program_sha);
        h.update(id.config_sha);
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(id.report_data, want);
        // Otra configuración (etiquetas apagadas) → otro report_data con la misma clave.
        let other = AttestConfig { labels: false, ..test_config() };
        assert_ne!(other.sha(), id.config_sha);
        assert_eq!(
            test_config().canonical_json(),
            format!("{{\"ceiling\":\"unbounded\",\"engine\":\"{}\",\"labels\":true,\"profile\":\"native\",\"tls_key\":\"attested\"}}", engine_version())
        );
        let ceiled = AttestConfig {
            ceiling: Some(vec![Capability::new(CapabilityType::Time, None), Capability::new(CapabilityType::Net, Some("b.x".into())), Capability::new(CapabilityType::Net, Some("a.x".into()))]),
            ..test_config()
        };
        assert!(ceiled.canonical_json().contains("\"ceiling\":[\"net=a.x\",\"net=b.x\",\"time\"]"), "{}", ceiled.canonical_json());
        assert!(AttestConfig { ceiling: Some(vec![]), ..test_config() }.canonical_json().contains("\"ceiling\":\"none\""));
        let payload = verify_nitro_document_with_root(&id.attestation.document, id.attestation.root.as_ref().unwrap()).unwrap();
        assert_eq!(payload.get("user_data").unwrap().as_bytes().unwrap(), &want);
        // El SPKI parsea y es P-256; el PKCS#8 lo acepta p256 y es coherente con el escalar.
        assert_eq!(id.spki_der[0], 0x30);
        assert_eq!(id.spki_der.len(), 91, "SPKI P-256 sin comprimir");
        assert_eq!(id.private_scalar.len(), 32);
        assert!(id.public_key_pem().starts_with("-----BEGIN PUBLIC KEY-----\n"));
        let j = id.json();
        assert_eq!(j["format"], "mock");
        assert_eq!(j["driver"], "mock");
        assert_eq!(j["mock"], true, "L6: el mock se declara");
        assert_eq!(j["tls_key"], "attested", "M9");
        assert_eq!(j["config"]["labels"], true);
        assert_eq!(j["config"]["ceiling"], "unbounded");
        assert_eq!(j["config_sha"], hex_encode(&id.config_sha));
        assert_eq!(j["public_key_hex"], hex_encode(&id.spki_der));
        assert_eq!(j["program_sha"], hex_encode(&id.program_sha));
        assert!(j["document"].as_str().unwrap().len() > 100);
        // El programa con un módulo cambia el hash cuando cambia el módulo.
        let dir = std::env::temp_dir().join(format!("syn_attest_psha_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("m.syn"), "let x be 1\n").unwrap();
        let main = dir.join("main.syn");
        let main_src = "use \"m.syn\" as m\nprint(m.x)\n";
        std::fs::write(&main, main_src).unwrap();
        let h1 = program_sha(main_src, &main.to_string_lossy()).unwrap();
        std::fs::write(dir.join("m.syn"), "let x be 2\n").unwrap();
        let h2 = program_sha(main_src, &main.to_string_lossy()).unwrap();
        assert_ne!(h1, h2, "el hash cubre los módulos");
        assert_ne!(h1, sha256(main_src.as_bytes()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn der_helpers_round_trip_signatures_and_http_parser_handles_chunked() {
        let raw: Vec<u8> = (0..96).map(|i| if i < 48 { 0x80 + i as u8 } else { i as u8 }).collect();
        let d = der::ecdsa_sig_value(&raw);
        assert_eq!(der::ecdsa_sig_raw(&d, 48).unwrap(), raw);
        let long = der::tlv(0x04, &[1u8; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2c]);
        let (tag, body, rest) = der::read_tlv(&long).unwrap();
        assert_eq!((tag, body.len(), rest.len()), (0x04, 300, 0));
        let plain = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"quote\":\"00\"}";
        assert_eq!(parse_http_response(plain).unwrap(), (200, "{\"quote\":\"00\"}".to_string()));
        let chunked = b"HTTP/1.1 500 Oops\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(chunked).unwrap(), (500, "hello!".to_string()));
        assert!(parse_http_response(b"garbage").is_err());
        // L8: un chunk que corta un carácter multibyte ("ñ" = c3 b1) no puede hacer panic.
        let mut split_utf8: Vec<u8> = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\na\xc3\r\n2\r\n\xb1b\r\n0\r\n\r\n".to_vec();
        assert_eq!(parse_http_response(&split_utf8).unwrap(), (200, "añb".to_string()));
        split_utf8.truncate(split_utf8.len() - 7);
        assert!(parse_http_response(&split_utf8).is_err(), "truncado → error, no panic");
        // Y un status line con bytes inválidos tampoco.
        assert!(parse_http_response(b"HTTP/1.1 \xff\xfe\r\n\r\nx").is_err());
    }
}

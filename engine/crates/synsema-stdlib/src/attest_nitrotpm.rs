//! Driver `nitro-tpm` de `attest`: pide un documento de EC2 instance attestation al NitroTPM de
//! una VM de AWS hablando con el TPM directamente (sin `nitro-tpm-attest` ni ningún binario
//! externo). El documento es el `COSE_Sign1` que `attestation_verify` acepta con
//! `format: "nitro-tpm"`.
//!
//! Protocolo, replicado de `aws/NitroTPM-Tools` (`nitro-tpm-attest`, commit 441fe31, 2026-05-22):
//! 1. `TPM2_CreatePrimary` de la EK RSA-2048 (plantilla L-1 del TCG EK Credential Profile) bajo la
//!    jerarquía de endorsement: es la clave que sala la sesión del paso 4;
//! 2. `TPM2_NV_DefineSpace` de un índice NV de 8192 bytes (AUTHREAD|AUTHWRITE, nameAlg SHA-512)
//!    con un `authValue` aleatorio: es el buffer del mensaje;
//! 3. `TPM2_NV_Write` del pedido NSM en CBOR (`{"Attestation": {user_data, nonce, public_key}}`) y
//!    `TPM2_NV_ReadPublic` para el nombre del índice (ya con `TPMA_NV_WRITTEN`);
//! 4. `TPM2_StartAuthSession` HMAC/SHA-512 salada con la EK (sal de 32 bytes, RSA-OAEP SHA-256 con
//!    la etiqueta `"SECRET\0"`, clave de sesión por KDFa) y el comando de proveedor
//!    `TPM2_VENDOR_AWS_NSM_REQUEST` (0x20000001) con el índice como `authHandle` y `nvIndex`,
//!    autorizado con HMAC sobre `cpHash = SHA-512(cc ‖ nombre ‖ nombre)`: el hipervisor deja la
//!    respuesta NSM en el mismo índice;
//! 5. `TPM2_NV_Read` de la respuesta, `TPM2_NV_UndefineSpace` y `TPM2_FlushContext` de la sesión y
//!    la EK (también si algo falló en el medio).
//!
//! Diferencia con la referencia, a propósito: los comandos NV con la clave del índice usan una
//! sesión de contraseña (`TPM_RS_PW`) en lugar de una sesión salada con cifrado de parámetros. El
//! `authValue` del buffer cruza la interfaz del TPM en claro: dentro de la VM sólo root abre
//! `/dev/tpm0` (y root ya puede todo), y del otro lado está el hipervisor de Nitro. No cambia lo que
//! el documento prueba: lo firma AWS y `attestation_verify` lo verifica contra la raíz pineada.
//!
//! Autodetección: hay NitroTPM si el TPM responde al comando de proveedor con algo distinto de
//! `TPM_RC_COMMAND_CODE` (un TPM cualquiera no lo implementa). Se prueba con un pedido sin efectos
//! (handles nulos), no por el nombre del dispositivo. SIN PROBAR en hardware en esta release.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::attest::{AttestRequest, AttestResult};
use crate::cbor::Cbor;

/// Error canónico cuando no hay TPM.
pub const NOT_AVAILABLE: &str = "attest: NitroTPM is not available: the AMI needs TpmSupport=v2.0 and UEFI";

/// Dispositivos que se prueban, en orden: el TPM crudo (lo que usa `nitro-tpm-attest`) y el del
/// gestor de recursos del kernel.
///
/// `/dev/tpm0` va primero a propósito: Linux lo abre en exclusiva, así que mientras lo tenemos nadie
/// más está a mitad de una operación sobre el TPM y se puede barrer lo que dejó un proceso muerto
/// (ver [`sweep_orphans`]). Si está ocupado se espera ([`TPM0_WAIT`]) para que dos procesos se
/// turnen en vez de pisarse; sólo si sigue ocupado (un daemon que lo tiene tomado) se usa
/// `/dev/tpmrm0`, sin barrido.
pub const DEVICES: &[&str] = &["/dev/tpm0", "/dev/tpmrm0"];

/// Cuánto se espera a que `/dev/tpm0` se libere antes de usar `/dev/tpmrm0`.
pub const TPM0_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Un solo uso del TPM a la vez por proceso: la renovación de `serve --attested` y un `attest()` de
/// un worker no pueden pisarse el índice NV ni la limpieza del otro.
#[cfg(target_os = "linux")]
static TPM_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(target_os = "linux")]
fn tpm_lock() -> std::sync::MutexGuard<'static, ()> {
    TPM_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// Topes del pedido NSM (los mismos que el NSM de un enclave).
pub const MAX_FIELD: usize = 1024;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_CC_NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM_CC_NV_WRITE: u32 = 0x0000_0137;
const TPM_CC_NV_READ: u32 = 0x0000_014E;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
const TPM_CC_START_AUTH_SESSION: u32 = 0x0000_0176;
const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017A;
/// `TPM2_VENDOR_AWS_NSM_REQUEST`.
pub const TPM_CC_AWS_NSM_REQUEST: u32 = 0x2000_0001;
const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_RH_NULL: u32 = 0x4000_0007;
const TPM_RS_PW: u32 = 0x4000_0009;
const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_SHA512: u16 = 0x000D;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_CFB: u16 = 0x0043;
const TPM_SE_HMAC: u8 = 0x00;
const TPM_CAP_HANDLES: u32 = 0x0000_0001;
const TPM_CAP_COMMANDS: u32 = 0x0000_0002;
/// Formato 0, "comando no implementado".
pub const TPM_RC_COMMAND_CODE: u32 = 0x0143;
const NV_INDEX_FIRST: u32 = 0x0100_0000;
const NV_INDEX_LAST: u32 = 0x01FF_FFFF;
const TRANSIENT_FIRST: u32 = 0x8000_0000;
const LOADED_SESSION_FIRST: u32 = 0x0200_0000;
/// `TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD` (índice ordinario).
pub const NV_ATTRIBUTES: u32 = (1 << 2) | (1 << 18);
/// `TPMA_NV_WRITTEN`.
pub const TPMA_NV_WRITTEN: u32 = 1 << 29;
/// Tamaño del buffer de mensaje (un documento sin campos opcionales ronda 5 KiB).
pub const NV_SIZE: u16 = 8192;
/// Trozo de `NV_Write`/`NV_Read` (todo TPM acepta al menos esto).
const NV_CHUNK: usize = 512;
/// Continuar la sesión tras el comando (la cierra `FlushContext`).
const SESSION_CONTINUE: u8 = 0x01;

/// `PolicyA` SHA-256 de la plantilla de EK L-1 (TCG EK Credential Profile, B.3.3).
const EK_POLICY_A: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda,
    0x1b, 0x33, 0x14, 0x69, 0xaa,
];
/// fixedTPM | fixedParent | sensitiveDataOrigin | adminWithPolicy | restricted | decrypt.
const EK_ATTRIBUTES: u32 = 0x0003_00B2;

/// Un canal de comandos TPM (el dispositivo, o un TPM simulado en los tests).
pub trait Transport {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, String>;
}

// =========================================================
// Marshalling (TPM 2.0 Part 2/3: big-endian, TPM2B = u16 tamaño + bytes)
// =========================================================

struct Cmd {
    buf: Vec<u8>,
}

impl Cmd {
    fn new(tag: u16, cc: u32) -> Cmd {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&tag.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&cc.to_be_bytes());
        Cmd { buf }
    }
    fn u8(mut self, v: u8) -> Cmd {
        self.buf.push(v);
        self
    }
    fn u16(mut self, v: u16) -> Cmd {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u32(mut self, v: u32) -> Cmd {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn tpm2b(mut self, b: &[u8]) -> Cmd {
        self.buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(b);
        self
    }
    fn raw(mut self, b: &[u8]) -> Cmd {
        self.buf.extend_from_slice(b);
        self
    }
    /// Área de autorización: tamaño u32 + la sesión.
    fn auth(self, session: &[u8]) -> Cmd {
        self.u32(session.len() as u32).raw(session)
    }
    fn build(mut self) -> Vec<u8> {
        let n = self.buf.len() as u32;
        self.buf[2..6].copy_from_slice(&n.to_be_bytes());
        self.buf
    }
}

/// Sesión de contraseña (`TPM_RS_PW`) con `password` como HMAC.
fn pw_session(password: &[u8]) -> Vec<u8> {
    let mut s = TPM_RS_PW.to_be_bytes().to_vec();
    s.extend_from_slice(&0u16.to_be_bytes());
    s.push(0);
    s.extend_from_slice(&(password.len() as u16).to_be_bytes());
    s.extend_from_slice(password);
    s
}

/// Lector de una respuesta: valida el encabezado y el código de respuesta.
pub struct Resp<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Resp<'a> {
    pub fn parse(raw: &'a [u8], what: &str) -> Result<Resp<'a>, String> {
        if raw.len() < 10 {
            return Err(format!("attest: NitroTPM {}: truncated TPM response ({} bytes)", what, raw.len()));
        }
        let size = u32::from_be_bytes(raw[2..6].try_into().expect("4")) as usize;
        if size != raw.len() {
            return Err(format!("attest: NitroTPM {}: the TPM response says {} bytes but has {}", what, size, raw.len()));
        }
        let rc = u32::from_be_bytes(raw[6..10].try_into().expect("4"));
        if rc != 0 {
            return Err(format!("attest: NitroTPM {} failed: TPM response code 0x{:03x}", what, rc));
        }
        Ok(Resp { data: raw, pos: 10 })
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.data.len()).ok_or("attest: NitroTPM: truncated TPM response field")?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2")))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4")))
    }
    fn tpm2b(&mut self) -> Result<&'a [u8], String> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// El código de respuesta de una respuesta cruda (para la sonda).
pub fn response_code(raw: &[u8]) -> Option<u32> {
    raw.get(6..10).map(|b| u32::from_be_bytes(b.try_into().expect("4")))
}

fn call(t: &mut dyn Transport, cmd: Vec<u8>, what: &str) -> Result<Vec<u8>, String> {
    t.transact(&cmd).map_err(|e| format!("attest: NitroTPM {}: {}", what, e))
}

/// `TPMT_PUBLIC` de la EK RSA-2048 (plantilla L-1).
pub fn ek_template() -> Vec<u8> {
    Cmd { buf: Vec::new() }
        .u16(TPM_ALG_RSA)
        .u16(TPM_ALG_SHA256)
        .u32(EK_ATTRIBUTES)
        .tpm2b(&EK_POLICY_A)
        .u16(TPM_ALG_AES)
        .u16(128)
        .u16(TPM_ALG_CFB)
        .u16(TPM_ALG_NULL)
        .u16(2048)
        .u32(0)
        .tpm2b(&[0u8; 256])
        .buf
}

/// `TPMS_NV_PUBLIC` del buffer de mensaje.
pub fn nv_public(index: u32, attributes: u32) -> Vec<u8> {
    Cmd { buf: Vec::new() }.u32(index).u16(TPM_ALG_SHA512).u32(attributes).tpm2b(&[]).u16(NV_SIZE).buf
}

/// KDFa (TPM 2.0 Part 1, 11.4.10.2) con HMAC-SHA-512 y salida de 512 bits (una vuelta).
pub fn kdfa_sha512_512(key: &[u8], label: &[u8], context_u: &[u8], context_v: &[u8]) -> [u8; 64] {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(&1u32.to_be_bytes());
    mac.update(label);
    mac.update(&[0]);
    mac.update(context_u);
    mac.update(context_v);
    mac.update(&512u32.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// `cpHash` del comando de proveedor: no lleva parámetros, sólo los nombres de sus dos handles.
pub fn nsm_cp_hash(nv_name: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(TPM_CC_AWS_NSM_REQUEST.to_be_bytes());
    h.update(nv_name);
    h.update(nv_name);
    h.finalize().into()
}

/// HMAC de la sesión (Part 1, 19.6.5): clave = `sessionKey ‖ authValue`.
pub fn session_hmac(session_key: &[u8], auth_value: &[u8], cp_hash: &[u8], nonce_caller: &[u8], nonce_tpm: &[u8], attributes: u8) -> [u8; 64] {
    let mut key = session_key.to_vec();
    key.extend_from_slice(auth_value);
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&key).expect("HMAC takes any key length");
    mac.update(cp_hash);
    mac.update(nonce_caller);
    mac.update(nonce_tpm);
    mac.update(&[attributes]);
    mac.finalize().into_bytes().into()
}

/// El pedido NSM tal como lo serializa `aws-nitro-enclaves-nsm-api` (serde/CBOR).
pub fn nsm_request(req: &AttestRequest) -> Vec<u8> {
    let opt = |v: &Option<Vec<u8>>| match v {
        Some(b) => Cbor::bytes(b),
        None => Cbor::Null,
    };
    Cbor::map_text(vec![(
        "Attestation",
        Cbor::map_text(vec![
            ("user_data", if req.report_data.is_empty() { Cbor::Null } else { Cbor::bytes(&req.report_data) }),
            ("nonce", opt(&req.nonce)),
            ("public_key", opt(&req.public_key)),
        ]),
    )])
    .encode()
}

/// La sonda de autodetección: el comando de proveedor con handles nulos. Un TPM que no lo
/// implementa responde `TPM_RC_COMMAND_CODE`; NitroTPM lo reconoce y rechaza los handles.
pub fn probe_command() -> Vec<u8> {
    Cmd::new(TPM_ST_SESSIONS, TPM_CC_AWS_NSM_REQUEST).u32(TPM_RH_NULL).u32(TPM_RH_NULL).auth(&pw_session(&[])).build()
}

/// `TPM2_GetCapability(TPM_CAP_COMMANDS)` desde el código del comando de proveedor.
pub fn capability_command() -> Vec<u8> {
    Cmd::new(TPM_ST_NO_SESSIONS, TPM_CC_GET_CAPABILITY).u32(TPM_CAP_COMMANDS).u32(TPM_CC_AWS_NSM_REQUEST).u32(1).build()
}

/// ¿Es un NitroTPM? Positivo sólo si el TPM declara el comando de proveedor en
/// `TPM_CAP_COMMANDS` (TPMA_CC con V=1 e índice 0x0001), o si responde a [`probe_command`] con un
/// error de formato 1 (handle/sesión/parámetro): esos sólo salen cuando el TPM ya reconoció el
/// comando y está desarmando sus handles. Un TPM que no lo implementa responde
/// `TPM_RC_COMMAND_CODE` (formato 0) antes de mirar nada: un vTPM cualquiera no alcanza.
pub fn probe_with(t: &mut dyn Transport) -> bool {
    if let Ok(raw) = t.transact(&capability_command()) {
        if let Ok(mut r) = Resp::parse(&raw, "GetCapability(commands)") {
            let listed = (|| -> Result<bool, String> {
                let _more = r.u8()?;
                if r.u32()? != TPM_CAP_COMMANDS {
                    return Ok(false);
                }
                let n = r.u32()?;
                for _ in 0..n.min(64) {
                    let a = r.u32()?;
                    if a & (1 << 29) != 0 && a & 0xffff == TPM_CC_AWS_NSM_REQUEST & 0xffff {
                        return Ok(true);
                    }
                }
                Ok(false)
            })();
            if listed == Ok(true) {
                return true;
            }
        }
    }
    match t.transact(&probe_command()) {
        Ok(raw) => matches!(response_code(&raw), Some(rc) if rc != TPM_RC_COMMAND_CODE && rc & 0x80 != 0),
        Err(_) => false,
    }
}

/// Los handles desde `first` hasta el fin de su rango (el byte alto de `first`).
fn handles_from(t: &mut dyn Transport, first: u32) -> Result<Vec<u32>, String> {
    let top = first | 0x00FF_FFFF;
    let mut used: Vec<u32> = Vec::new();
    let mut from = first;
    for _ in 0..64 {
        let raw = call(t, Cmd::new(TPM_ST_NO_SESSIONS, TPM_CC_GET_CAPABILITY).u32(TPM_CAP_HANDLES).u32(from).u32(256).build(), "GetCapability(handles)")?;
        let mut r = Resp::parse(&raw, "GetCapability(handles)")?;
        let more = r.u8()? != 0;
        if r.u32()? != TPM_CAP_HANDLES {
            return Err("attest: NitroTPM GetCapability(handles) answered another capability".to_string());
        }
        let n = r.u32()?;
        let mut last = from;
        for _ in 0..n {
            let h = r.u32()?;
            if h & 0xFF00_0000 == first & 0xFF00_0000 {
                used.push(h);
            }
            last = last.max(h);
        }
        if !more || n == 0 || last >= top {
            break;
        }
        from = last + 1;
    }
    Ok(used)
}

/// Primer índice NV libre desde `NV_INDEX_FIRST` (como `find_free_handle` de la referencia).
fn free_nv_index(t: &mut dyn Transport) -> Result<u32, String> {
    let used = handles_from(t, NV_INDEX_FIRST)?;
    (NV_INDEX_FIRST..=NV_INDEX_LAST).find(|h| !used.contains(h)).ok_or_else(|| "attest: NitroTPM has no free NV index".to_string())
}

/// ¿Es un buffer de mensaje como los nuestros (o los de `nitro-tpm-attest`)? SHA-512,
/// AUTHREAD|AUTHWRITE (más los bits que pone el TPM al usarlo), sin policy, 8192 bytes.
fn is_message_buffer(t: &mut dyn Transport, nv: u32) -> Result<bool, String> {
    let raw = call(t, Cmd::new(TPM_ST_NO_SESSIONS, TPM_CC_NV_READ_PUBLIC).u32(nv).build(), "NV_ReadPublic")?;
    let Ok(mut r) = Resp::parse(&raw, "NV_ReadPublic") else { return Ok(false) };
    let public = r.tpm2b()?;
    let mut wrapped = vec![0u8; 10];
    wrapped.extend_from_slice(public);
    let mut p = Resp { data: &wrapped, pos: 10 };
    let index = p.u32()?;
    let name_alg = p.u16()?;
    let attributes = p.u32()?;
    let policy = p.tpm2b()?;
    let size = p.u16()?;
    Ok(index == nv && name_alg == TPM_ALG_SHA512 && attributes & !TPMA_NV_WRITTEN == NV_ATTRIBUTES && policy.is_empty() && size == NV_SIZE)
}

/// Lo que dejó un proceso que murió a mitad de un pedido (SIGKILL, OOM): la EK y la sesión
/// cargadas y el buffer NV de 8 KiB, que el TPM guarda para siempre. Sin esto, unos pocos cortes
/// agotan los slots y el driver queda roto hasta limpiarlo a mano.
///
/// SÓLO con `/dev/tpm0` abierto en exclusiva: ningún otro proceso puede estar a mitad de una
/// operación con él, y el gestor del kernel (`/dev/tpmrm0`) guarda y descarga sus objetos después
/// de cada comando, así que lo cargado y los buffers con nuestra forma son restos. Un error del
/// barrido no frena el pedido (que dirá lo suyo si falta lugar).
pub fn sweep_orphans(t: &mut dyn Transport) -> usize {
    let mut swept = 0;
    for first in [TRANSIENT_FIRST, LOADED_SESSION_FIRST] {
        for h in handles_from(t, first).unwrap_or_default() {
            if call(t, Cmd::new(TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT).u32(h).build(), "FlushContext").and_then(|raw| Resp::parse(&raw, "FlushContext").map(|_| ())).is_ok() {
                swept += 1;
            }
        }
    }
    for nv in handles_from(t, NV_INDEX_FIRST).unwrap_or_default() {
        if is_message_buffer(t, nv).unwrap_or(false) {
            let cmd = Cmd::new(TPM_ST_SESSIONS, TPM_CC_NV_UNDEFINE_SPACE).u32(TPM_RH_OWNER).u32(nv).auth(&pw_session(&[])).build();
            if call(t, cmd, "NV_UndefineSpace").and_then(|raw| Resp::parse(&raw, "NV_UndefineSpace").map(|_| ())).is_ok() {
                swept += 1;
            }
        }
    }
    swept
}

/// RSA-OAEP (SHA-256, MGF1-SHA-256, etiqueta `"SECRET\0"`) de la sal con la EK (Part 1, B.10.2).
fn encrypt_salt(modulus: &[u8], exponent: u32, salt: &[u8]) -> Result<Vec<u8>, String> {
    let e = if exponent == 0 { 65537 } else { exponent };
    let key = rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(modulus), rsa::BigUint::from(e)).map_err(|err| format!("attest: NitroTPM endorsement key is not usable: {}", err))?;
    key.encrypt(&mut rand::rngs::OsRng, rsa::Oaep::new_with_label::<Sha256, _>("SECRET\0"), salt)
        .map_err(|err| format!("attest: NitroTPM cannot encrypt the session salt: {}", err))
}

/// La EK desde `TPM2B_PUBLIC`: `(módulo, exponente)`.
fn parse_rsa_public(outer: &[u8]) -> Result<(Vec<u8>, u32), String> {
    let mut wrapped = vec![0u8; 10];
    wrapped.extend_from_slice(outer);
    let n = wrapped.len() as u32;
    wrapped[2..6].copy_from_slice(&n.to_be_bytes());
    let mut r = Resp { data: &wrapped, pos: 10 };
    if r.u16()? != TPM_ALG_RSA {
        return Err("attest: NitroTPM endorsement key is not RSA".to_string());
    }
    let _name_alg = r.u16()?;
    let _attrs = r.u32()?;
    let _policy = r.tpm2b()?;
    if r.u16()? != TPM_ALG_NULL {
        r.u16()?;
        r.u16()?;
    }
    if r.u16()? != TPM_ALG_NULL {
        r.u16()?;
    }
    let _bits = r.u16()?;
    let exponent = r.u32()?;
    let modulus = r.tpm2b()?.to_vec();
    if modulus.len() != 256 {
        return Err(format!("attest: NitroTPM endorsement key has a {}-byte modulus, expected 256", modulus.len()));
    }
    Ok((modulus, exponent))
}

fn random(n: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; n];
    rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut out).map_err(|_| "attest: NitroTPM: the OS random source is unavailable".to_string())?;
    Ok(out)
}

/// Lo que hay que liberar pase lo que pase.
#[derive(Default)]
struct Held {
    ek: Option<u32>,
    session: Option<u32>,
    nv: Option<u32>,
}

/// Pide el documento por `t`. Público para el TPM simulado de los tests.
pub fn attest_with(t: &mut dyn Transport, req: &AttestRequest) -> Result<Vec<u8>, String> {
    for (name, v) in [("report_data", Some(&req.report_data)), ("nonce", req.nonce.as_ref()), ("public_key", req.public_key.as_ref())] {
        if let Some(v) = v {
            if v.len() > MAX_FIELD {
                return Err(format!("attest: NitroTPM {} must be at most {} bytes, got {}", name, MAX_FIELD, v.len()));
            }
        }
    }
    let mut held = Held::default();
    let out = run(t, req, &mut held);
    // Limpieza: el índice NV no se libera solo (persiste en el TPM); la sesión y la EK sí con
    // tpmrm0, pero no con tpm0. Un error de limpieza no tapa el error principal.
    let mut cleanup_err = None;
    if let Some(nv) = held.nv {
        let cmd = Cmd::new(TPM_ST_SESSIONS, TPM_CC_NV_UNDEFINE_SPACE).u32(TPM_RH_OWNER).u32(nv).auth(&pw_session(&[])).build();
        if let Err(e) = call(t, cmd, "NV_UndefineSpace").and_then(|raw| Resp::parse(&raw, "NV_UndefineSpace").map(|_| ())) {
            cleanup_err = Some(e);
        }
    }
    for h in [held.session, held.ek].into_iter().flatten() {
        let _ = call(t, Cmd::new(TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT).u32(h).build(), "FlushContext");
    }
    match (out, cleanup_err) {
        (Ok(doc), None) => Ok(doc),
        (Ok(_), Some(e)) => Err(format!("{} (the message buffer could not be released)", e)),
        (Err(e), _) => Err(e),
    }
}

fn run(t: &mut dyn Transport, req: &AttestRequest, held: &mut Held) -> Result<Vec<u8>, String> {
    // 1. EK.
    let cmd = Cmd::new(TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY)
        .u32(TPM_RH_ENDORSEMENT)
        .auth(&pw_session(&[]))
        .tpm2b(&Cmd { buf: Vec::new() }.tpm2b(&[]).tpm2b(&[]).buf)
        .tpm2b(&ek_template())
        .tpm2b(&[])
        .u32(0)
        .build();
    let raw = call(t, cmd, "CreatePrimary(EK)")?;
    let mut r = Resp::parse(&raw, "CreatePrimary(EK)")?;
    let ek = r.u32()?;
    held.ek = Some(ek);
    let _param_size = r.u32()?;
    let (modulus, exponent) = parse_rsa_public(r.tpm2b()?)?;

    // 2. Buffer de mensaje.
    let nv = free_nv_index(t)?;
    let mut auth_value = random(64)?;
    // El TPM quita los ceros finales del authValue (Part 1, 19.6.4.3): que no haya.
    if auth_value[63] == 0 {
        auth_value[63] = 1;
    }
    let cmd = Cmd::new(TPM_ST_SESSIONS, TPM_CC_NV_DEFINE_SPACE)
        .u32(TPM_RH_OWNER)
        .auth(&pw_session(&[]))
        .tpm2b(&auth_value)
        .tpm2b(&nv_public(nv, NV_ATTRIBUTES))
        .build();
    // Se marca ANTES: si la respuesta se pierde (el TPM pudo haberlo definido), la limpieza intenta
    // liberarlo igual. Si el TPM lo rechazó, no es nuestro y se desmarca.
    held.nv = Some(nv);
    let raw = call(t, cmd, "NV_DefineSpace")?;
    if let Err(e) = Resp::parse(&raw, "NV_DefineSpace") {
        held.nv = None;
        return Err(e);
    }

    // 3. Pedido + nombre.
    let request = nsm_request(req);
    if request.len() > NV_SIZE as usize {
        return Err(format!("attest: NitroTPM request is {} bytes, the message buffer holds {}", request.len(), NV_SIZE));
    }
    for (k, chunk) in request.chunks(NV_CHUNK).enumerate() {
        let cmd = Cmd::new(TPM_ST_SESSIONS, TPM_CC_NV_WRITE).u32(nv).u32(nv).auth(&pw_session(&auth_value)).tpm2b(chunk).u16((k * NV_CHUNK) as u16).build();
        let raw = call(t, cmd, "NV_Write")?;
        Resp::parse(&raw, "NV_Write")?;
    }
    let raw = call(t, Cmd::new(TPM_ST_NO_SESSIONS, TPM_CC_NV_READ_PUBLIC).u32(nv).build(), "NV_ReadPublic")?;
    let mut r = Resp::parse(&raw, "NV_ReadPublic")?;
    let _public = r.tpm2b()?;
    let nv_name = r.tpm2b()?.to_vec();
    if nv_name.len() != 2 + 64 || nv_name[..2] != TPM_ALG_SHA512.to_be_bytes() {
        return Err("attest: NitroTPM NV_ReadPublic returned a name that is not SHA-512".to_string());
    }

    // 4. Sesión salada + comando de proveedor.
    let salt = random(32)?;
    let encrypted_salt = encrypt_salt(&modulus, exponent, &salt)?;
    let nonce_caller = random(64)?;
    let cmd = Cmd::new(TPM_ST_NO_SESSIONS, TPM_CC_START_AUTH_SESSION)
        .u32(ek)
        .u32(TPM_RH_NULL)
        .tpm2b(&nonce_caller)
        .tpm2b(&encrypted_salt)
        .u8(TPM_SE_HMAC)
        .u16(TPM_ALG_NULL)
        .u16(TPM_ALG_SHA512)
        .build();
    let raw = call(t, cmd, "StartAuthSession")?;
    let mut r = Resp::parse(&raw, "StartAuthSession")?;
    let session = r.u32()?;
    held.session = Some(session);
    let nonce_tpm = r.tpm2b()?.to_vec();
    let session_key = kdfa_sha512_512(&salt, b"ATH", &nonce_tpm, &nonce_caller);
    let nonce_caller2 = random(64)?;
    let hmac = session_hmac(&session_key, &auth_value, &nsm_cp_hash(&nv_name), &nonce_caller2, &nonce_tpm, SESSION_CONTINUE);
    let mut auth = session.to_be_bytes().to_vec();
    auth.extend_from_slice(&(nonce_caller2.len() as u16).to_be_bytes());
    auth.extend_from_slice(&nonce_caller2);
    auth.push(SESSION_CONTINUE);
    auth.extend_from_slice(&(hmac.len() as u16).to_be_bytes());
    auth.extend_from_slice(&hmac);
    let raw = call(t, Cmd::new(TPM_ST_SESSIONS, TPM_CC_AWS_NSM_REQUEST).u32(nv).u32(nv).auth(&auth).build(), "NSM request")?;
    Resp::parse(&raw, "NSM request")?;

    // 5. Respuesta.
    let mut response = Vec::with_capacity(NV_SIZE as usize);
    for off in (0..NV_SIZE as usize).step_by(NV_CHUNK) {
        let cmd = Cmd::new(TPM_ST_SESSIONS, TPM_CC_NV_READ).u32(nv).u32(nv).auth(&pw_session(&auth_value)).u16(NV_CHUNK as u16).u16(off as u16).build();
        let raw = call(t, cmd, "NV_Read")?;
        let mut r = Resp::parse(&raw, "NV_Read")?;
        let _param_size = r.u32()?;
        let data = r.tpm2b()?;
        if data.len() != NV_CHUNK {
            return Err(format!("attest: NitroTPM NV_Read returned {} bytes, asked {}", data.len(), NV_CHUNK));
        }
        response.extend_from_slice(data);
    }
    let (item, _) = crate::cbor::decode_prefix_allow_indefinite(&response).map_err(|e| format!("attest: NitroTPM response is not CBOR: {}", e))?;
    if let Some(e) = item.get("Error") {
        return Err(format!("attest: NitroTPM NSM returned an error: {}", e.as_text().unwrap_or("?")));
    }
    let doc = item
        .get("Attestation")
        .and_then(|a| a.get("document"))
        .and_then(Cbor::as_bytes)
        .ok_or_else(|| "attest: NitroTPM response has no Attestation.document".to_string())?;
    if doc.is_empty() {
        return Err("attest: NitroTPM returned an empty document".to_string());
    }
    Ok(doc.to_vec())
}

// =========================================================
// Dispositivo (Linux)
// =========================================================

#[cfg(target_os = "linux")]
struct Device(std::fs::File);

#[cfg(target_os = "linux")]
impl Transport for Device {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, String> {
        use std::io::{Read, Write};
        self.0.write_all(command).map_err(|e| format!("write to the TPM: {}", e))?;
        let mut buf = vec![0u8; 8192];
        let mut n = 0usize;
        loop {
            // Una señal en medio de la lectura (EINTR) no es un error del TPM: se reintenta. Cortar
            // acá dejaría el índice NV definido.
            let k = match self.0.read(&mut buf[n..]) {
                Ok(k) => k,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("read from the TPM: {}", e)),
            };
            if k == 0 {
                break;
            }
            n += k;
            if n >= 6 {
                let want = u32::from_be_bytes(buf[2..6].try_into().expect("4")) as usize;
                if n >= want || want > buf.len() {
                    break;
                }
            }
        }
        buf.truncate(n);
        Ok(buf)
    }
}

/// El primer dispositivo TPM que abre, y si es `/dev/tpm0` (exclusivo: se puede barrer).
/// `/dev/tpm0` ocupado (EBUSY) se reintenta hasta [`TPM0_WAIT`] antes de pasar a `/dev/tpmrm0`.
#[cfg(target_os = "linux")]
fn open_device() -> Result<(Device, bool), String> {
    let open = |path: &str| std::fs::OpenOptions::new().read(true).write(true).open(path);
    let mut last = None;
    if std::path::Path::new(DEVICES[0]).exists() {
        let deadline = std::time::Instant::now() + TPM0_WAIT;
        loop {
            match open(DEVICES[0]) {
                Ok(f) => return Ok((Device(f), true)),
                Err(e) if e.raw_os_error() == Some(16) && std::time::Instant::now() < deadline => std::thread::sleep(std::time::Duration::from_millis(100)),
                Err(e) => {
                    last = Some(format!("attest: cannot open {} ({}); another TPM user may hold it", DEVICES[0], e));
                    break;
                }
            }
        }
    }
    for path in &DEVICES[1..] {
        if !std::path::Path::new(path).exists() {
            continue;
        }
        match open(path) {
            Ok(f) => return Ok((Device(f), false)),
            Err(e) => last = Some(format!("attest: cannot open {} ({}); another TPM user may hold it", path, e)),
        }
    }
    Err(last.unwrap_or_else(|| NOT_AVAILABLE.to_string()))
}

/// ¿Hay un TPM? (sin hablarle)
pub fn device_present() -> bool {
    cfg!(target_os = "linux") && DEVICES.iter().any(|p| std::path::Path::new(p).exists())
}

/// ¿Hay un NitroTPM? Abre el TPM y le manda la sonda UNA vez por proceso (no en cada `attest()`,
/// ni chocando con la renovación de `serve --attested` que puede tener el dispositivo tomado).
pub fn probe() -> bool {
    static PROBED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *PROBED.get_or_init(probe_device)
}

fn probe_device() -> bool {
    #[cfg(target_os = "linux")]
    {
        if !device_present() {
            return false;
        }
        let _guard = tpm_lock();
        match open_device() {
            Ok((mut d, _)) => probe_with(&mut d),
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// El driver: documento `nitro-tpm` para `req`.
pub fn attest(req: &AttestRequest) -> Result<AttestResult, String> {
    #[cfg(target_os = "linux")]
    {
        if !device_present() {
            return Err(NOT_AVAILABLE.to_string());
        }
        let _guard = tpm_lock();
        let (mut dev, exclusive) = open_device()?;
        if exclusive {
            sweep_orphans(&mut dev);
        }
        let document = attest_with(&mut dev, req)?;
        Ok(AttestResult {
            format: "nitro-tpm",
            document,
            driver: "nitro-tpm",
            report_data: req.report_data.clone(),
            aux: None,
            event_log: None,
            root: None,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = req;
        Err("attest: the nitro-tpm driver is Linux-only (it talks to the TPM of an EC2 instance)".to_string())
    }
}

#[cfg(test)]
mod tests {
    //! TPM simulado: implementa, de forma independiente al driver, lo que hace un TPM con estos
    //! comandos (descifra la sal con la EK, deriva la clave de sesión, recalcula el nombre del índice
    //! NV y el HMAC) y hace de hipervisor de Nitro al recibir el comando de proveedor. Prueba que el
    //! driver arma bien el protocolo; NO prueba el hardware (eso queda para la corrida en AWS).
    use super::*;
    use rsa::traits::PublicKeyParts;

    /// Lo mismo que hace `nitro-tpm-attest` (aws-lc `kbkdf_ctr_hmac` con info
    /// `"ATH\0" ‖ nonceTPM ‖ nonceCaller ‖ 512`), escrito acá sin usar las funciones del driver.
    fn ref_session_key(salt: &[u8], nonce_tpm: &[u8], nonce_caller: &[u8]) -> Vec<u8> {
        let mut m = <Hmac<Sha512> as Mac>::new_from_slice(salt).unwrap();
        let info = [&1u32.to_be_bytes()[..], b"ATH\0", nonce_tpm, nonce_caller, &512u32.to_be_bytes()].concat();
        m.update(&info);
        m.finalize().into_bytes().to_vec()
    }

    fn ref_auth_hmac(key: &[u8], auth_value: &[u8], nv_name: &[u8], nonce_caller: &[u8], nonce_tpm: &[u8], attrs: u8) -> Vec<u8> {
        let cp = Sha512::digest([&0x2000_0001u32.to_be_bytes()[..], nv_name, nv_name].concat());
        let mut m = <Hmac<Sha512> as Mac>::new_from_slice(&[key, auth_value].concat()).unwrap();
        m.update(&[&cp[..], nonce_caller, nonce_tpm, &[attrs]].concat());
        m.finalize().into_bytes().to_vec()
    }

    struct FakeTpm {
        ek: rsa::RsaPrivateKey,
        ek_handle: Option<u32>,
        nv: Option<(u32, Vec<u8>, u32, Vec<u8>)>,
        session: Option<(u32, Vec<u8>, Vec<u8>)>,
        flushed: Vec<u32>,
        undefined: Vec<u32>,
        nsm_error: bool,
        commands: Vec<u32>,
    }

    fn ok_resp(tag: u16, body: &[u8]) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn rc_resp(rc: u32) -> Vec<u8> {
        let mut out = TPM_ST_NO_SESSIONS.to_be_bytes().to_vec();
        out.extend_from_slice(&10u32.to_be_bytes());
        out.extend_from_slice(&rc.to_be_bytes());
        out
    }

    fn b2(b: &[u8]) -> Vec<u8> {
        let mut v = (b.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(b);
        v
    }

    struct Rd<'a>(&'a [u8], usize);
    impl<'a> Rd<'a> {
        fn take(&mut self, n: usize) -> &'a [u8] {
            let s = &self.0[self.1..self.1 + n];
            self.1 += n;
            s
        }
        fn u8(&mut self) -> u8 {
            self.take(1)[0]
        }
        fn u16(&mut self) -> u16 {
            u16::from_be_bytes(self.take(2).try_into().unwrap())
        }
        fn u32(&mut self) -> u32 {
            u32::from_be_bytes(self.take(4).try_into().unwrap())
        }
        fn b2(&mut self) -> &'a [u8] {
            let n = self.u16() as usize;
            self.take(n)
        }
        /// Área de autorización con UNA sesión: (handle, nonce, attrs, hmac).
        fn auth(&mut self) -> (u32, Vec<u8>, u8, Vec<u8>) {
            let size = self.u32() as usize;
            let start = self.1;
            let h = self.u32();
            let nonce = self.b2().to_vec();
            let attrs = self.u8();
            let hmac = self.b2().to_vec();
            assert_eq!(self.1 - start, size, "tamaño del área de autorización");
            (h, nonce, attrs, hmac)
        }
    }

    impl FakeTpm {
        fn new() -> FakeTpm {
            FakeTpm {
                ek: rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap(),
                ek_handle: None,
                nv: None,
                session: None,
                flushed: Vec::new(),
                undefined: Vec::new(),
                nsm_error: false,
                commands: Vec::new(),
            }
        }

        /// Nombre del índice: nameAlg ‖ SHA-512(TPMS_NV_PUBLIC), recalculado acá a mano.
        fn nv_name(&self) -> Vec<u8> {
            let (idx, _, attrs, _) = self.nv.as_ref().unwrap();
            let mut public = idx.to_be_bytes().to_vec();
            public.extend_from_slice(&0x000Du16.to_be_bytes());
            public.extend_from_slice(&attrs.to_be_bytes());
            public.extend_from_slice(&0u16.to_be_bytes());
            public.extend_from_slice(&8192u16.to_be_bytes());
            let mut name = 0x000Du16.to_be_bytes().to_vec();
            name.extend_from_slice(&Sha512::digest(&public));
            name
        }

        fn check_pw(&self, auth: &(u32, Vec<u8>, u8, Vec<u8>), want: &[u8]) -> bool {
            auth.0 == TPM_RS_PW && auth.1.is_empty() && auth.3 == want
        }
    }

    impl Transport for FakeTpm {
        fn transact(&mut self, cmd: &[u8]) -> Result<Vec<u8>, String> {
            let mut r = Rd(cmd, 0);
            let tag = r.u16();
            assert_eq!(r.u32() as usize, cmd.len(), "tamaño del comando");
            let cc = r.u32();
            self.commands.push(cc);
            match cc {
                TPM_CC_GET_CAPABILITY => {
                    let cap = r.u32();
                    if cap == TPM_CAP_COMMANDS {
                        // Este TPM simulado no declara el comando (como un TPM que no lo lista).
                        let mut body = vec![0u8];
                        body.extend_from_slice(&TPM_CAP_COMMANDS.to_be_bytes());
                        body.extend_from_slice(&0u32.to_be_bytes());
                        return Ok(ok_resp(tag, &body));
                    }
                    assert_eq!((cap, r.u32()), (TPM_CAP_HANDLES, NV_INDEX_FIRST));
                    // El primer índice está ocupado: el driver toma el siguiente.
                    let mut body = vec![0u8];
                    body.extend_from_slice(&TPM_CAP_HANDLES.to_be_bytes());
                    body.extend_from_slice(&1u32.to_be_bytes());
                    body.extend_from_slice(&NV_INDEX_FIRST.to_be_bytes());
                    Ok(ok_resp(tag, &body))
                }
                TPM_CC_CREATE_PRIMARY => {
                    assert_eq!(r.u32(), TPM_RH_ENDORSEMENT);
                    let a = r.auth();
                    assert!(self.check_pw(&a, &[]));
                    assert_eq!(r.b2(), &[0, 0, 0, 0]);
                    let template = r.b2().to_vec();
                    assert_eq!(template, ek_template(), "plantilla L-1");
                    let mut public = template[..template.len() - 258].to_vec();
                    public.extend_from_slice(&b2(&self.ek.n().to_bytes_be()));
                    let params = b2(&public);
                    let mut body = 0x8000_0000u32.to_be_bytes().to_vec();
                    body.extend_from_slice(&(params.len() as u32).to_be_bytes());
                    body.extend_from_slice(&params);
                    self.ek_handle = Some(0x8000_0000);
                    Ok(ok_resp(tag, &body))
                }
                TPM_CC_NV_DEFINE_SPACE => {
                    assert_eq!(r.u32(), TPM_RH_OWNER);
                    let a = r.auth();
                    assert!(self.check_pw(&a, &[]));
                    let auth_value = r.b2().to_vec();
                    assert_eq!(auth_value.len(), 64);
                    assert_ne!(auth_value[63], 0, "sin ceros finales");
                    let public = r.b2();
                    let mut p = Rd(public, 0);
                    let idx = p.u32();
                    assert_eq!(p.u16(), TPM_ALG_SHA512);
                    let attrs = p.u32();
                    assert_eq!(attrs, NV_ATTRIBUTES);
                    assert!(p.b2().is_empty());
                    assert_eq!(p.u16(), 8192);
                    self.nv = Some((idx, auth_value, attrs, vec![0u8; 8192]));
                    Ok(ok_resp(tag, &0u32.to_be_bytes()))
                }
                TPM_CC_NV_WRITE => {
                    let (h1, h2) = (r.u32(), r.u32());
                    let a = r.auth();
                    let data = r.b2().to_vec();
                    let off = r.u16() as usize;
                    let (idx, auth, _, _) = self.nv.as_ref().unwrap();
                    assert_eq!((h1, h2), (*idx, *idx));
                    if !self.check_pw(&a, auth) {
                        return Ok(rc_resp(0x98E));
                    }
                    let nv = self.nv.as_mut().unwrap();
                    nv.3[off..off + data.len()].copy_from_slice(&data);
                    nv.2 |= TPMA_NV_WRITTEN;
                    Ok(ok_resp(tag, &0u32.to_be_bytes()))
                }
                TPM_CC_NV_READ_PUBLIC => {
                    let idx = r.u32();
                    let (i, _, attrs, _) = self.nv.as_ref().unwrap();
                    assert_eq!(idx, *i);
                    let public = nv_public(*i, *attrs);
                    let mut body = b2(&public);
                    body.extend_from_slice(&b2(&self.nv_name()));
                    Ok(ok_resp(tag, &body))
                }
                TPM_CC_START_AUTH_SESSION => {
                    assert_eq!(r.u32(), self.ek_handle.unwrap(), "sesión salada con la EK");
                    assert_eq!(r.u32(), TPM_RH_NULL);
                    let nonce_caller = r.b2().to_vec();
                    let enc_salt = r.b2().to_vec();
                    assert_eq!((r.u8(), r.u16(), r.u16()), (TPM_SE_HMAC, TPM_ALG_NULL, TPM_ALG_SHA512));
                    let salt = self.ek.decrypt(rsa::Oaep::new_with_label::<Sha256, _>("SECRET\0"), &enc_salt).expect("la sal descifra con la EK");
                    assert_eq!(salt.len(), 32);
                    let nonce_tpm = vec![0x5au8; 64];
                    let key = ref_session_key(&salt, &nonce_tpm, &nonce_caller);
                    self.session = Some((0x0200_0000, key, nonce_tpm.clone()));
                    let mut body = 0x0200_0000u32.to_be_bytes().to_vec();
                    body.extend_from_slice(&b2(&nonce_tpm));
                    Ok(ok_resp(tag, &body))
                }
                TPM_CC_AWS_NSM_REQUEST => {
                    let (h1, h2) = (r.u32(), r.u32());
                    let a = r.auth();
                    let Some((sh, key, nonce_tpm)) = self.session.clone() else {
                        // La sonda: handles nulos → error de handle (formato 1).
                        assert_eq!((h1, h2), (TPM_RH_NULL, TPM_RH_NULL));
                        return Ok(rc_resp(0x18B));
                    };
                    let (idx, auth_value, _, data) = self.nv.clone().unwrap();
                    assert_eq!((h1, h2, a.0, a.2), (idx, idx, sh, SESSION_CONTINUE));
                    let want = ref_auth_hmac(&key, &auth_value, &self.nv_name(), &a.1, &nonce_tpm, a.2);
                    if a.3 != want {
                        return Ok(rc_resp(0x98E));
                    }
                    let (request, _) = crate::cbor::decode_prefix(&data).unwrap();
                    let att = request.get("Attestation").unwrap();
                    let ud = att.get("user_data").unwrap().as_bytes().unwrap().to_vec();
                    let response = if self.nsm_error {
                        Cbor::map_text(vec![("Error", Cbor::text("InvalidArgument"))]).encode()
                    } else {
                        let mut doc = b"doc:".to_vec();
                        doc.extend_from_slice(&ud);
                        // El hipervisor puede codificar indefinido: el driver lo acepta.
                        let inner = Cbor::map_text(vec![("document", Cbor::Bytes(doc))]).encode();
                        let mut out = vec![0xbf];
                        out.extend_from_slice(&Cbor::text("Attestation").encode());
                        out.extend_from_slice(&inner);
                        out.push(0xff);
                        out
                    };
                    let nv = self.nv.as_mut().unwrap();
                    nv.3 = vec![0u8; 8192];
                    nv.3[..response.len()].copy_from_slice(&response);
                    Ok(ok_resp(tag, &0u32.to_be_bytes()))
                }
                TPM_CC_NV_READ => {
                    let (h1, _) = (r.u32(), r.u32());
                    let a = r.auth();
                    let (size, off) = (r.u16() as usize, r.u16() as usize);
                    let (idx, auth, _, data) = self.nv.as_ref().unwrap();
                    assert_eq!(h1, *idx);
                    if !self.check_pw(&a, auth) {
                        return Ok(rc_resp(0x98E));
                    }
                    let chunk = b2(&data[off..off + size]);
                    let mut body = (chunk.len() as u32).to_be_bytes().to_vec();
                    body.extend_from_slice(&chunk);
                    Ok(ok_resp(tag, &body))
                }
                TPM_CC_NV_UNDEFINE_SPACE => {
                    assert_eq!(r.u32(), TPM_RH_OWNER);
                    let idx = r.u32();
                    self.undefined.push(idx);
                    self.nv = None;
                    Ok(ok_resp(tag, &0u32.to_be_bytes()))
                }
                TPM_CC_FLUSH_CONTEXT => {
                    self.flushed.push(r.u32());
                    Ok(ok_resp(tag, &[]))
                }
                other => panic!("comando inesperado 0x{:x}", other),
            }
        }
    }

    #[test]
    fn the_driver_speaks_the_protocol_end_to_end_against_a_simulated_tpm() {
        let mut tpm = FakeTpm::new();
        let req = AttestRequest { report_data: vec![7u8; 32], nonce: None, public_key: None };
        let doc = attest_with(&mut tpm, &req).unwrap();
        let mut want = b"doc:".to_vec();
        want.extend_from_slice(&[7u8; 32]);
        assert_eq!(doc, want, "el user_data viaja y el documento vuelve");
        assert_eq!(tpm.undefined, vec![NV_INDEX_FIRST + 1], "el buffer NV (el primer índice libre) se libera");
        assert!(tpm.nv.is_none());
        assert!(tpm.flushed.contains(&0x0200_0000) && tpm.flushed.contains(&0x8000_0000), "sesión y EK liberadas: {:x?}", tpm.flushed);
        assert!(tpm.commands.contains(&TPM_CC_AWS_NSM_REQUEST));
    }

    #[test]
    fn errors_still_release_the_buffer_and_name_the_step() {
        let mut tpm = FakeTpm::new();
        tpm.nsm_error = true;
        let e = attest_with(&mut tpm, &AttestRequest { report_data: vec![1; 32], ..Default::default() }).unwrap_err();
        assert_eq!(e, "attest: NitroTPM NSM returned an error: InvalidArgument");
        assert_eq!(tpm.undefined, vec![NV_INDEX_FIRST + 1]);
        // Topes del pedido: se rechazan sin tocar el TPM.
        let mut tpm = FakeTpm::new();
        let e = attest_with(&mut tpm, &AttestRequest { report_data: vec![], nonce: Some(vec![0; 1025]), public_key: None }).unwrap_err();
        assert!(e.contains("nonce must be at most 1024 bytes"), "{}", e);
        assert!(tpm.commands.is_empty(), "no toca el TPM");
    }

    /// Lo que dejó un proceso muerto se barre: objetos transitorios, sesiones cargadas y SÓLO los
    /// índices NV con la forma exacta de nuestro buffer (no los de otros dueños).
    #[test]
    fn the_sweep_releases_only_what_a_dead_attest_left_behind() {
        struct Leftovers {
            flushed: Vec<u32>,
            undefined: Vec<u32>,
        }
        const OURS: u32 = NV_INDEX_FIRST + 3;
        const OURS_WRITTEN: u32 = NV_INDEX_FIRST + 4;
        const FOREIGN_SIZE: u32 = NV_INDEX_FIRST + 5;
        const FOREIGN_POLICY: u32 = NV_INDEX_FIRST + 6;
        impl Transport for Leftovers {
            fn transact(&mut self, cmd: &[u8]) -> Result<Vec<u8>, String> {
                let mut r = Rd(cmd, 0);
                let tag = r.u16();
                r.u32();
                let handles = |hs: &[u32]| {
                    let mut body = vec![0u8];
                    body.extend_from_slice(&TPM_CAP_HANDLES.to_be_bytes());
                    body.extend_from_slice(&(hs.len() as u32).to_be_bytes());
                    for h in hs {
                        body.extend_from_slice(&h.to_be_bytes());
                    }
                    ok_resp(tag, &body)
                };
                match r.u32() {
                    TPM_CC_GET_CAPABILITY => {
                        assert_eq!(r.u32(), TPM_CAP_HANDLES);
                        Ok(match r.u32() {
                            TRANSIENT_FIRST => handles(&[0x8000_0000, 0x8000_0001]),
                            LOADED_SESSION_FIRST => handles(&[0x0200_0000]),
                            NV_INDEX_FIRST => handles(&[OURS, OURS_WRITTEN, FOREIGN_SIZE, FOREIGN_POLICY]),
                            other => panic!("rango 0x{:x}", other),
                        })
                    }
                    TPM_CC_FLUSH_CONTEXT => {
                        self.flushed.push(r.u32());
                        Ok(ok_resp(tag, &[]))
                    }
                    TPM_CC_NV_READ_PUBLIC => {
                        let idx = r.u32();
                        let mut public = idx.to_be_bytes().to_vec();
                        public.extend_from_slice(&TPM_ALG_SHA512.to_be_bytes());
                        let attrs = if idx == OURS_WRITTEN { NV_ATTRIBUTES | TPMA_NV_WRITTEN } else { NV_ATTRIBUTES };
                        public.extend_from_slice(&attrs.to_be_bytes());
                        public.extend_from_slice(&b2(if idx == FOREIGN_POLICY { &[1; 32] } else { &[] }));
                        public.extend_from_slice(&(if idx == FOREIGN_SIZE { 100u16 } else { NV_SIZE }).to_be_bytes());
                        let mut body = b2(&public);
                        body.extend_from_slice(&b2(&[0; 66]));
                        Ok(ok_resp(tag, &body))
                    }
                    TPM_CC_NV_UNDEFINE_SPACE => {
                        assert_eq!(r.u32(), TPM_RH_OWNER);
                        self.undefined.push(r.u32());
                        Ok(ok_resp(tag, &0u32.to_be_bytes()))
                    }
                    other => panic!("comando inesperado 0x{:x}", other),
                }
            }
        }
        let mut t = Leftovers { flushed: Vec::new(), undefined: Vec::new() };
        assert_eq!(sweep_orphans(&mut t), 5);
        assert_eq!(t.flushed, vec![0x8000_0000, 0x8000_0001, 0x0200_0000]);
        assert_eq!(t.undefined, vec![OURS, OURS_WRITTEN], "los índices de otros dueños no se tocan");
    }

    #[test]
    fn the_probe_tells_a_nitro_tpm_from_any_tpm() {
        // Reconoce el comando y rechaza los handles nulos (formato 1): NitroTPM.
        assert!(probe_with(&mut FakeTpm::new()));
        // Un TPM que no lo implementa: TPM_RC_COMMAND_CODE.
        struct Plain;
        impl Transport for Plain {
            fn transact(&mut self, cmd: &[u8]) -> Result<Vec<u8>, String> {
                let cc = u32::from_be_bytes(cmd[6..10].try_into().unwrap());
                Ok(if cc == TPM_CC_GET_CAPABILITY { ok_resp(TPM_ST_NO_SESSIONS, &[0, 0, 0, 0, 2, 0, 0, 0, 0]) } else { rc_resp(TPM_RC_COMMAND_CODE) })
            }
        }
        assert!(!probe_with(&mut Plain));
        // Uno que falla con otro error de formato 0 tampoco alcanza.
        struct Failing;
        impl Transport for Failing {
            fn transact(&mut self, _cmd: &[u8]) -> Result<Vec<u8>, String> {
                Ok(rc_resp(0x101))
            }
        }
        assert!(!probe_with(&mut Failing));
        // Uno que lo declara en TPM_CAP_COMMANDS (V=1, índice 0x0001).
        struct Listed;
        impl Transport for Listed {
            fn transact(&mut self, _cmd: &[u8]) -> Result<Vec<u8>, String> {
                let mut body = vec![0u8, 0, 0, 0, 2, 0, 0, 0, 1];
                body.extend_from_slice(&((1u32 << 29) | 0x0001).to_be_bytes());
                Ok(ok_resp(TPM_ST_NO_SESSIONS, &body))
            }
        }
        assert!(probe_with(&mut Listed));
    }

    #[test]
    fn marshalling_shapes() {
        let t = ek_template();
        assert_eq!(t.len(), 2 + 2 + 4 + 34 + 6 + 2 + 2 + 4 + 258);
        assert_eq!(&t[4..8], &EK_ATTRIBUTES.to_be_bytes());
        // La sonda: ST_SESSIONS, tamaño correcto, handles nulos y una sesión de contraseña vacía.
        let p = probe_command();
        assert_eq!(&p[..2], &TPM_ST_SESSIONS.to_be_bytes());
        assert_eq!(u32::from_be_bytes(p[2..6].try_into().unwrap()) as usize, p.len());
        assert_eq!(&p[6..10], &TPM_CC_AWS_NSM_REQUEST.to_be_bytes());
        // El pedido NSM: user_data vacío → null, como `Option::None` en serde.
        let r = crate::cbor::decode(&nsm_request(&AttestRequest::default())).unwrap();
        assert!(r.get("Attestation").unwrap().get("user_data").unwrap().is_null());
        assert!(Resp::parse(&[0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x09, 0x8e], "x").err().unwrap().contains("TPM response code 0x98e"));
        assert!(Resp::parse(&[0x80, 0x01, 0, 0, 0, 11, 0, 0, 0, 0], "x").err().unwrap().contains("says 11 bytes but has 10"));
    }
}

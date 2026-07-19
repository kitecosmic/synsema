//! Read-side de blockchain (Batch 14): JSON-RPC EVM (Ethereum/Avalanche C-Chain),
//! RPC de Solana y REST de algod (Algorand) — leer→construir→enviar→confirmar sin
//! hand-rollear JSON-RPC ni hex-quantities. Cierra el loop autónomo: el batch 13
//! dejó al agente FIRMANDO bytes perfectos; este le da el nonce/fees/blockhash/
//! params para CONSTRUIR, el broadcast para ENVIAR y el receipt para CONFIRMAR.
//!
//! Doctrina (spec batch-14 §1, hereda G1–G21):
//! - **G22 — cero capability nueva.** Todo lo de acá es `net(host)`-gated (la MISMA
//!   capability y scope que `http_*`/`fetch`/`ws_connect`) y por lo demás PURO.
//!   Nada mueve valor: `sign` sigue siendo la ÚNICA puerta que autoriza gastar.
//!   `eth_send_raw`/`solana_send`/`algorand_send` difunden bytes YA firmados — sin
//!   una firma válida (que exigió `sign`) el nodo los rechaza.
//! - **G23 — un nodo RPC es input NO confiable.** Puede mentir, estar comprometido
//!   o devolver basura. Todo decode es ESTRICTO: hex-quantity malformado o con
//!   ceros a la izquierda, respuesta gigante (>16 MiB), forma distinta a la pedida
//!   → error atrapable, jamás panic, jamás data incorrecta en silencio. Los
//!   errores nombran el HOST, nunca el URL completo (la API key suele viajar en el
//!   path — Infura/Alchemy).
//! - **G24 — sin defaults de fee/gas.** `tx_eip1559` exige cada campo que mueve
//!   valor explícito (leído con los helpers o declarado) y DEVUELVE los números en
//!   el map para que un `confirm`/`show` los muestre ANTES de firmar.
//! - **Polling acotado.** `eth_wait_receipt`/`solana_confirm`/`algorand_wait`
//!   vencen a `nothing` (mismo criterio que `ws_recv`) — jamás cuelgan.
//!
//! Convención de tipos de salida (una sola regla): lo que se **re-inyecta** a un
//! builtin de construcción/decode va como `bytes` (retorno de `eth_call` →
//! `abi_decode`; blockhash → `solana_message`; `gh` → el txn map de Algorand); lo
//! que se **muestra o compara** va como `text` (tx hashes `0x…`, direcciones
//! EIP-55, signature base58, txid base32).

use std::cell::RefCell;
use std::rc::Rc;
use std::thread;
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use num_bigint::BigInt;
use sha3::{Digest, Keccak256};

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_capabilities::secure::url_hostname;
use synsema_core::bytesutil::{b64_decode, b64_encode, base58_decode, base58_encode, hex_encode};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::Number;
use synsema_core::types::{
    syn_bool, syn_bytes, syn_int, syn_list, syn_map, syn_number, syn_text, SynValue,
};

use crate::blockchain::{arg, arg_bytes, arg_bytes_len, eip55, err, rlp_encode_val};
use crate::blockchain_abi::addr20;
use crate::blockchain_algorand::address_to_pubkey;
use crate::blockchain_solana::{ata_address, pubkey32, token_program_default};
use crate::http::{header_pairs, http_request, http_request_body_bytes, HttpResult};
use crate::server::{dumps, json_to_syn, Json};

/// Timeout HTTP de cada request RPC individual (mismo default que `http_*`).
const RPC_HTTP_TIMEOUT_SECS: u64 = 30;
/// Techo anti-DoS del body de una respuesta RPC (G23: "array gigante" → error
/// atrapable, no un parse de gigabytes de un nodo hostil).
const MAX_RPC_RESPONSE: usize = 16 * 1024 * 1024;
/// Un hex-quantity EVM es un uint de a lo sumo 256 bits (64 nibbles). Más largo =
/// basura u hostilidad, jamás un valor real.
const MAX_HEXQ_NIBBLES: usize = 64;
/// Timeout default de los helpers de espera (`*_wait`/`*_confirm`).
const DEFAULT_WAIT_SECS: f64 = 60.0;
/// Paso de polling por cadena (≪ el block time de cada una).
const EVM_POLL: Duration = Duration::from_millis(2000);
const SOLANA_POLL: Duration = Duration::from_millis(500);
const ALGORAND_POLL: Duration = Duration::from_millis(1000);
/// Ventana de validez máxima del protocolo Algorand: `lv = fv + 1000`.
const ALGORAND_MAX_VALIDITY: u64 = 1000;
/// Cota de recursión de la conversión de params (espeja RLP/ABI/msgpack).
const MAX_DEPTH: usize = 64;

// =========================================================
// Capability + transporte
// =========================================================

/// La MISMA capability `net(host)` que http_*/fetch/ws_connect (G22): scope =
/// hostname minúsculas sin puerto; sin host extraíble → URL crudo (fail-closed).
fn require_net(caps: &Rc<RefCell<CapabilitySet>>, url: &str, source: &str) -> Result<(), Control> {
    let host = match url_hostname(url) {
        Some(h) if !h.is_empty() => h,
        _ => url.to_string(),
    };
    caps.borrow_mut()
        .require(&Capability::new(CapabilityType::Net, Some(host)), source)
        .map_err(|v| Control::Error(RuntimeError::new(v.message)))
}

/// Host para mensajes de error — JAMÁS el URL completo (la API key del RPC suele
/// viajar en el path; un error que la ecoa la filtra a logs/respuestas).
fn host_of(url: &str) -> String {
    url_hostname(url).unwrap_or_else(|| "<invalid url>".to_string())
}

fn url_arg(v: &SynValue, fname: &str) -> Result<String, Control> {
    match v {
        SynValue::Text(s) => Ok(s.to_string()),
        other => Err(err(format!("{}: the URL must be text, got {}", fname, other.type_name()))),
    }
}

fn text_arg(v: &SynValue, what: &str, fname: &str) -> Result<String, Control> {
    match v {
        SynValue::Text(s) => Ok(s.to_string()),
        other => Err(err(format!(
            "{}: {} must be text, got {}",
            fname,
            what,
            other.type_name()
        ))),
    }
}

/// Primeros ~200 chars de un body/mensaje de error del nodo, sin controles (el
/// contenido es input no confiable que va a parar a un mensaje de error).
fn snippet(s: &str) -> String {
    let clean: String = s.chars().filter(|c| !c.is_control()).take(200).collect();
    if s.len() > clean.len() {
        format!("{}…", clean)
    } else {
        clean
    }
}

/// Falla de un poll: **transitoria** (el transporte falló o el nodo devolvió
/// 5xx — un blip de red no dice nada sobre la cadena) o **definitiva** (4xx,
/// JSON inválido, envelope ajeno, error RPC del nodo, decode hostil G23 —
/// reintentarle a un mentiroso no es resiliencia). Los one-shots colapsan ambas
/// al mismo error atrapable; SOLO los waiters (`*_wait`/`*_confirm`) reintentan
/// las transitorias hasta su deadline.
enum PollError {
    Transient(Control),
    Definitive(Control),
}

impl PollError {
    fn into_control(self) -> Control {
        match self {
            PollError::Transient(c) | PollError::Definitive(c) => c,
        }
    }
}

/// HttpResult → JSON parseado con los chequeos G23, clasificado: error de
/// transporte y HTTP 5xx → `Transient`; body sobre el techo, 4xx y JSON
/// inválido → `Definitive`.
fn http_result_to_json_classified(
    r: HttpResult,
    url: &str,
    fname: &str,
) -> Result<serde_json::Value, PollError> {
    if let Some(e) = r.error {
        return Err(PollError::Transient(err(format!(
            "{}: request to {} failed: {}",
            fname,
            host_of(url),
            e
        ))));
    }
    if r.body.len() > MAX_RPC_RESPONSE {
        return Err(PollError::Definitive(err(format!(
            "{}: the response from {} exceeds the {} MiB limit — refusing to parse it",
            fname,
            host_of(url),
            MAX_RPC_RESPONSE / (1024 * 1024)
        ))));
    }
    if !r.ok {
        let c = err(format!(
            "{}: {} returned HTTP {}: {}",
            fname,
            host_of(url),
            r.status,
            snippet(&r.body)
        ));
        return Err(if r.status >= 500 {
            PollError::Transient(c)
        } else {
            PollError::Definitive(c)
        });
    }
    serde_json::from_str(&r.body).map_err(|e| {
        PollError::Definitive(err(format!(
            "{}: {} returned invalid JSON: {}",
            fname,
            host_of(url),
            e
        )))
    })
}

/// Versión sin clasificar (one-shots): cualquier falla → error atrapable.
fn http_result_to_json(
    r: HttpResult,
    url: &str,
    fname: &str,
) -> Result<serde_json::Value, Control> {
    http_result_to_json_classified(r, url, fname).map_err(PollError::into_control)
}

/// Llamada JSON-RPC 2.0 estricta y clasificada: el envelope debe ser un objeto
/// con `id` == el enviado; `error` del nodo → `Definitive` con code+message
/// (una respuesta del nodo, por hostil que sea, no es un blip de red); sin
/// `result` → `Definitive`. Devuelve el `result` crudo (`Null` es un result
/// legítimo, p.ej. un receipt que todavía no existe).
fn jsonrpc_call_classified(
    url: &str,
    method: &str,
    params: Json,
    fname: &str,
    timeout_secs: u64,
) -> Result<serde_json::Value, PollError> {
    let body = dumps(&Json::Object(vec![
        ("jsonrpc".to_string(), Json::Str("2.0".to_string())),
        ("id".to_string(), Json::Int(1)),
        ("method".to_string(), Json::Str(method.to_string())),
        ("params".to_string(), params),
    ]));
    let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    let r = http_request("POST", url, Some(&headers), None, Some(&body), timeout_secs);
    let v = http_result_to_json_classified(r, url, fname)?;
    let obj = v.as_object().ok_or_else(|| {
        PollError::Definitive(err(format!(
            "{}: the RPC response from {} is not a JSON object",
            fname,
            host_of(url)
        )))
    })?;
    if let Some(e) = obj.get("error") {
        let code = e
            .get("code")
            .and_then(serde_json::Value::as_i64)
            .map(|c| format!(" {}", c))
            .unwrap_or_default();
        let msg = e.get("message").and_then(serde_json::Value::as_str).unwrap_or("");
        return Err(PollError::Definitive(err(format!(
            "{}: RPC error{}: {}",
            fname,
            code,
            snippet(msg)
        ))));
    }
    if obj.get("id").and_then(serde_json::Value::as_i64) != Some(1) {
        return Err(PollError::Definitive(err(format!(
            "{}: the RPC response from {} does not match the request id",
            fname,
            host_of(url)
        ))));
    }
    obj.get("result").cloned().ok_or_else(|| {
        PollError::Definitive(err(format!(
            "{}: the RPC response from {} has no result",
            fname,
            host_of(url)
        )))
    })
}

/// Versión sin clasificar (one-shots): cualquier falla → error atrapable.
fn jsonrpc_call(
    url: &str,
    method: &str,
    params: Json,
    fname: &str,
    timeout_secs: u64,
) -> Result<serde_json::Value, Control> {
    jsonrpc_call_classified(url, method, params, fname, timeout_secs)
        .map_err(PollError::into_control)
}

// =========================================================
// Espera acotada (polling que jamás cuelga)
// =========================================================

/// Timeout de espera en segundos (estricto, como ws.rs): default 60 s, cap 24 h.
fn wait_timeout_arg(v: Option<&SynValue>, fname: &str) -> Result<Duration, Control> {
    let secs = match v {
        None | Some(SynValue::Nothing) => DEFAULT_WAIT_SECS,
        Some(SynValue::Number(n)) => {
            let f = n.to_f64();
            if !f.is_finite() || f < 0.0 {
                return Err(err(format!(
                    "{}: the timeout must be a non-negative number of seconds",
                    fname
                )));
            }
            f
        }
        Some(other) => {
            return Err(err(format!(
                "{}: the timeout must be a number of seconds, got {}",
                fname,
                other.type_name()
            )))
        }
    };
    Ok(Duration::from_secs_f64(secs.min(24.0 * 3600.0)))
}

/// Duerme un paso de polling ACOTADO por el deadline. `false` si ya venció (el
/// caller devuelve `nothing` — mismo contrato que `ws_recv`).
fn sleep_step(deadline: Instant, step: Duration) -> bool {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return false;
    }
    thread::sleep(remaining.min(step));
    true
}

/// Timeout HTTP de un poll individual: lo que reste del deadline, con piso 1 s y
/// techo el default — un nodo mudo no puede estirar la espera total.
fn poll_http_timeout(deadline: Instant) -> u64 {
    deadline
        .saturating_duration_since(Instant::now())
        .as_secs()
        .clamp(1, RPC_HTTP_TIMEOUT_SECS)
}

/// Aviso runtime (UNA vez por espera) cuando un poll falla transitoriamente y el
/// waiter va a reintentar. Autocontenido y LLM-safe: dice quién actúa (el propio
/// waiter) y que el agente NO tiene que hacer nada.
fn warn_transient_once(warned: &mut bool, c: &Control, fname: &str) {
    if *warned {
        return;
    }
    *warned = true;
    if let Control::Error(e) = c {
        eprintln!(
            "synsema: warning: {}: transient RPC failure while waiting ({}); the waiter keeps retrying until its deadline by itself — no agent action is needed",
            fname, e.message
        );
    }
}

/// Falla de un poll DENTRO de un waiter: transitoria con al menos un poll
/// exitoso previo → aviso (una vez) y `Ok` (el loop reintenta); transitoria en
/// el PRIMER poll (URL equivocada / nodo muerto: fail-fast, no 60 s de mentira)
/// o definitiva → propaga.
fn handle_poll_err(
    e: PollError,
    polled_ok: bool,
    warned: &mut bool,
    last_transient: &mut Option<Control>,
    fname: &str,
) -> Result<(), Control> {
    match e {
        PollError::Transient(c) if polled_ok => {
            warn_transient_once(warned, &c, fname);
            *last_transient = Some(c);
            Ok(())
        }
        other => Err(other.into_control()),
    }
}

/// El deadline venció DURANTE una racha de fallas transitorias: sube el último
/// error (no `nothing`) — "no confirmó" y "el nodo dejó de responder" son
/// verdades distintas y el agente debe poder distinguirlas.
fn deadline_result(last_transient: Option<Control>) -> Result<SynValue, Control> {
    match last_transient {
        Some(Control::Error(e)) => Err(err(format!(
            "{} (the wait deadline expired during this failure)",
            e.message
        ))),
        Some(c) => Err(c),
        None => Ok(SynValue::Nothing),
    }
}

// =========================================================
// Hex-quantity (el borde filoso #1 del JSON-RPC de EVM)
// =========================================================

/// Entero no-negativo → hex-quantity canónico: `0x` + mínimo, sin ceros a la
/// izquierda; cero → `"0x0"`.
fn number_to_hexq(n: &Number, what: &str, fname: &str) -> Result<String, Control> {
    let be = n.to_be_bytes_min().ok_or_else(|| {
        err(format!(
            "{}: {} must be a non-negative integer (quantities are exact — no floats)",
            fname, what
        ))
    })?;
    if be.is_empty() {
        return Ok("0x0".to_string());
    }
    let h = hex_encode(&be);
    // El primer byte no es 0 (bytes mínimos); a lo sumo sobra el primer NIBBLE.
    let h = h.strip_prefix('0').unwrap_or(&h);
    Ok(format!("0x{}", h))
}

/// Hex-quantity → Number, ESTRICTO (G23): exige `0x`, al menos un dígito, sin
/// ceros a la izquierda (salvo `"0x0"`), máximo 256 bits. Un valor malformado de
/// un nodo hostil → error atrapable, jamás un número incorrecto en silencio.
fn hexq_to_number(s: &str, what: &str, fname: &str) -> Result<Number, Control> {
    let h = s.strip_prefix("0x").ok_or_else(|| {
        err(format!(
            "{}: {} is not a hex quantity (must start with 0x), got {:?}",
            fname,
            what,
            snippet(s)
        ))
    })?;
    if h.is_empty() {
        return Err(err(format!("{}: {} is an empty hex quantity (\"0x\")", fname, what)));
    }
    if h.len() > 1 && h.starts_with('0') {
        return Err(err(format!(
            "{}: {} is a non-canonical hex quantity (leading zeros): {:?}",
            fname,
            what,
            snippet(s)
        )));
    }
    if h.len() > MAX_HEXQ_NIBBLES {
        return Err(err(format!(
            "{}: {} is over 256 bits ({} hex digits) — not a real EVM quantity",
            fname,
            what,
            h.len()
        )));
    }
    let mut big = BigInt::from(0u8);
    for c in h.chars() {
        let d = c.to_digit(16).ok_or_else(|| {
            err(format!(
                "{}: {} has a non-hex character in a hex quantity: {:?}",
                fname,
                what,
                snippet(s)
            ))
        })?;
        big = big * 16 + d;
    }
    Ok(Number::from_bigint(big))
}

/// Hex-data (`0x` + hex de largo PAR) → bytes, con techo de tamaño.
fn hexdata_to_bytes(s: &str, what: &str, fname: &str) -> Result<Vec<u8>, Control> {
    let h = s.strip_prefix("0x").ok_or_else(|| {
        err(format!("{}: {} is not hex data (must start with 0x)", fname, what))
    })?;
    if h.len() / 2 > MAX_RPC_RESPONSE {
        return Err(err(format!("{}: {} is over the response size limit", fname, what)));
    }
    synsema_core::bytesutil::hex_decode(h)
        .map_err(|e| err(format!("{}: {} is not valid hex data: {}", fname, what, e)))
}

fn bytes_to_hexdata(b: &[u8]) -> String {
    format!("0x{}", hex_encode(b))
}

// =========================================================
// Navegación estricta de la respuesta (serde_json → error atrapable)
// =========================================================

fn as_obj<'a>(
    v: &'a serde_json::Value,
    what: &str,
    fname: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, Control> {
    v.as_object()
        .ok_or_else(|| err(format!("{}: {} is not a JSON object", fname, what)))
}

fn get_str<'a>(
    m: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
    what: &str,
    fname: &str,
) -> Result<&'a str, Control> {
    m.get(key).and_then(serde_json::Value::as_str).ok_or_else(|| {
        err(format!("{}: {} has no string field {:?}", fname, what, key))
    })
}

fn get_u64(
    m: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    what: &str,
    fname: &str,
) -> Result<u64, Control> {
    m.get(key).and_then(serde_json::Value::as_u64).ok_or_else(|| {
        err(format!("{}: {} has no unsigned integer field {:?}", fname, what, key))
    })
}

/// u64 exacto → Number (`Int` si entra en i64, si no `Big` — jamás float lossy).
fn u64_number(u: u64) -> SynValue {
    match i64::try_from(u) {
        Ok(i) => syn_int(i),
        Err(_) => syn_number(Number::Big(BigInt::from(u))),
    }
}

// =========================================================
// Conversión de params (Synsema → JSON del wire)
// =========================================================

/// Params EVM: int → hex-quantity, bytes → `0x…`; text/bool pasan; maps/listas
/// recursivos. Un `secret` jamás entra a un request RPC.
fn syn_to_eth_json(v: &SynValue, path: &str, fname: &str, depth: usize) -> Result<Json, Control> {
    if depth > MAX_DEPTH {
        return Err(err(format!("{}: {} is nested too deeply", fname, path)));
    }
    match v {
        SynValue::Number(n) => Ok(Json::Str(number_to_hexq(n, path, fname)?)),
        SynValue::Bytes(b) => Ok(Json::Str(bytes_to_hexdata(b))),
        SynValue::Text(s) => Ok(Json::Str(s.to_string())),
        SynValue::Bool(b) => Ok(Json::Bool(*b)),
        SynValue::Nothing => Ok(Json::Null),
        SynValue::List(l) => {
            let items = l.borrow().clone();
            let mut out = Vec::with_capacity(items.len());
            for (i, it) in items.iter().enumerate() {
                out.push(syn_to_eth_json(it, &format!("{}[{}]", path, i), fname, depth + 1)?);
            }
            Ok(Json::Array(out))
        }
        SynValue::Map(m) => {
            let m = m.borrow().clone();
            let mut out = Vec::with_capacity(m.len());
            for (k, val) in m.iter() {
                out.push((
                    k.clone(),
                    syn_to_eth_json(val, &format!("{}.{}", path, k), fname, depth + 1)?,
                ));
            }
            Ok(Json::Object(out))
        }
        SynValue::Secret(_) => Err(err(format!(
            "{}: {} is a secret — a secret never goes into an RPC request",
            fname, path
        ))),
        other => Err(err(format!(
            "{}: {} has unsupported type {} for an RPC param",
            fname,
            path,
            other.type_name()
        ))),
    }
}

/// Params Solana/JSON planos: los números viajan como números JSON (no hexq).
/// `bytes` crudos → error dirigido (¿base58 o base64? el caller decide con
/// `decode(x, "base58"/"base64")` — no se adivina la codificación).
fn syn_to_plain_json(v: &SynValue, path: &str, fname: &str, depth: usize) -> Result<Json, Control> {
    if depth > MAX_DEPTH {
        return Err(err(format!("{}: {} is nested too deeply", fname, path)));
    }
    match v {
        SynValue::Number(n) => match n {
            Number::Int(i) => Ok(Json::Int(*i)),
            Number::Big(b) => Ok(Json::BigInt(b.to_string())),
            Number::Float(f) => Ok(Json::Float(*f)),
            Number::Decimal(d) => Ok(Json::BigInt(d.to_string())),
        },
        SynValue::Text(s) => Ok(Json::Str(s.to_string())),
        SynValue::Bool(b) => Ok(Json::Bool(*b)),
        SynValue::Nothing => Ok(Json::Null),
        SynValue::Bytes(_) => Err(err(format!(
            "{}: {} is raw bytes — encode it explicitly (decode(x, \"base58\") or decode(x, \"base64\")); the RPC wire format is JSON text",
            fname, path
        ))),
        SynValue::List(l) => {
            let items = l.borrow().clone();
            let mut out = Vec::with_capacity(items.len());
            for (i, it) in items.iter().enumerate() {
                out.push(syn_to_plain_json(it, &format!("{}[{}]", path, i), fname, depth + 1)?);
            }
            Ok(Json::Array(out))
        }
        SynValue::Map(m) => {
            let m = m.borrow().clone();
            let mut out = Vec::with_capacity(m.len());
            for (k, val) in m.iter() {
                out.push((
                    k.clone(),
                    syn_to_plain_json(val, &format!("{}.{}", path, k), fname, depth + 1)?,
                ));
            }
            Ok(Json::Object(out))
        }
        SynValue::Secret(_) => Err(err(format!(
            "{}: {} is a secret — a secret never goes into an RPC request",
            fname, path
        ))),
        other => Err(err(format!(
            "{}: {} has unsupported type {} for an RPC param",
            fname,
            path,
            other.type_name()
        ))),
    }
}

/// Lista de params (arg opcional) → `Json::Array` con el conversor dado.
fn params_arg(
    v: Option<&SynValue>,
    fname: &str,
    convert: impl Fn(&SynValue, &str, &str, usize) -> Result<Json, Control>,
) -> Result<Json, Control> {
    match v {
        None | Some(SynValue::Nothing) => Ok(Json::Array(Vec::new())),
        Some(SynValue::List(l)) => {
            let items = l.borrow().clone();
            let mut out = Vec::with_capacity(items.len());
            for (i, it) in items.iter().enumerate() {
                out.push(convert(it, &format!("params[{}]", i), fname, 0)?);
            }
            Ok(Json::Array(out))
        }
        Some(other) => Err(err(format!(
            "{}: params must be a list, got {}",
            fname,
            other.type_name()
        ))),
    }
}

// =========================================================
// Alcance A — EVM JSON-RPC
// =========================================================

/// Dirección → `"0x…"` minúsculas para el wire (validada con la regla EIP-55 de
/// blockchain_abi: mixed-case declara checksum y se verifica).
fn eth_addr_hex(v: &SynValue, what: &str, fname: &str) -> Result<String, Control> {
    let a = addr20(v, what, fname)?;
    Ok(bytes_to_hexdata(&a))
}

/// Hash de tx (bytes32 o text `0x…64hex`) → `"0x…"` minúsculas.
fn tx_hash_hex(v: &SynValue, fname: &str) -> Result<String, Control> {
    match v {
        SynValue::Bytes(b) => {
            if b.len() != 32 {
                return Err(err(format!(
                    "{}: the transaction hash must be 32 bytes, got {}",
                    fname,
                    b.len()
                )));
            }
            Ok(bytes_to_hexdata(b))
        }
        SynValue::Text(s) => {
            let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).ok_or_else(|| {
                err(format!("{}: the transaction hash must be \"0x…\" (64 hex chars) or 32 bytes", fname))
            })?;
            if h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(err(format!(
                    "{}: the transaction hash must be exactly 64 hex chars after 0x",
                    fname
                )));
            }
            Ok(format!("0x{}", h.to_lowercase()))
        }
        other => Err(err(format!(
            "{}: the transaction hash must be \"0x…\" text or 32 bytes, got {}",
            fname,
            other.type_name()
        ))),
    }
}

/// Tag de bloque opcional: default `"latest"`; un número → hex-quantity; los tags
/// con nombre se validan (un typo es error, no un request roto).
fn block_tag(v: Option<&SynValue>, fname: &str) -> Result<Json, Control> {
    match v {
        None | Some(SynValue::Nothing) => Ok(Json::Str("latest".to_string())),
        Some(SynValue::Number(n)) => Ok(Json::Str(number_to_hexq(n, "the block number", fname)?)),
        Some(SynValue::Text(s)) => {
            let tag = s.to_string();
            if matches!(tag.as_str(), "latest" | "earliest" | "pending" | "safe" | "finalized") {
                Ok(Json::Str(tag))
            } else {
                Err(err(format!(
                    "{}: unknown block tag {:?} (use latest, earliest, pending, safe, finalized, or a number)",
                    fname, tag
                )))
            }
        }
        Some(other) => Err(err(format!(
            "{}: the block must be a tag or a number, got {}",
            fname,
            other.type_name()
        ))),
    }
}

/// El result debe ser un hex-quantity string → Number.
fn expect_hexq(v: &serde_json::Value, what: &str, fname: &str) -> Result<Number, Control> {
    let s = v.as_str().ok_or_else(|| {
        err(format!("{}: expected {} as a hex quantity string, the node sent something else", fname, what))
    })?;
    hexq_to_number(s, what, fname)
}

fn eth_rpc(
    args: &[SynValue],
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "eth_rpc";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "eth_rpc()")?;
    let method = text_arg(arg(args, 1, F)?, "the method", F)?;
    let params = params_arg(args.get(2), F, syn_to_eth_json)?;
    let result = jsonrpc_call(&url, &method, params, F, RPC_HTTP_TIMEOUT_SECS)?;
    Ok(json_to_syn(&result))
}

/// Helper: llamada tipada que devuelve un hex-quantity → int.
fn eth_qty_call(
    url: &str,
    method: &str,
    params: Json,
    what: &str,
    fname: &str,
) -> Result<SynValue, Control> {
    let result = jsonrpc_call(url, method, params, fname, RPC_HTTP_TIMEOUT_SECS)?;
    Ok(syn_number(expect_hexq(&result, what, fname)?))
}

fn eth_nonce(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "eth_nonce";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "eth_nonce()")?;
    let addr = eth_addr_hex(arg(args, 1, F)?, "the address", F)?;
    // Tag "pending": el nonce que sigue contando las txs ya difundidas y aún no
    // minadas — el que se usa para construir la PRÓXIMA tx.
    let params = Json::Array(vec![Json::Str(addr), Json::Str("pending".to_string())]);
    eth_qty_call(&url, "eth_getTransactionCount", params, "the nonce", F)
}

fn eth_balance(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "eth_balance";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "eth_balance()")?;
    let addr = eth_addr_hex(arg(args, 1, F)?, "the address", F)?;
    let tag = block_tag(args.get(2), F)?;
    let params = Json::Array(vec![Json::Str(addr), tag]);
    eth_qty_call(&url, "eth_getBalance", params, "the balance", F)
}

fn eth_gas_price(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "eth_gas_price";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "eth_gas_price()")?;
    eth_qty_call(&url, "eth_gasPrice", Json::Array(Vec::new()), "the gas price", F)
}

fn eth_chain_id(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "eth_chain_id";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "eth_chain_id()")?;
    eth_qty_call(&url, "eth_chainId", Json::Array(Vec::new()), "the chain id", F)
}

fn eth_estimate_gas(
    args: &[SynValue],
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "eth_estimate_gas";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "eth_estimate_gas()")?;
    let tx = match arg(args, 1, F)? {
        v @ SynValue::Map(_) => syn_to_eth_json(v, "the tx", F, 0)?,
        other => {
            return Err(err(format!(
                "{}: the tx must be a map ({{from, to, value, data, …}}), got {}",
                F,
                other.type_name()
            )))
        }
    };
    eth_qty_call(&url, "eth_estimateGas", Json::Array(vec![tx]), "the gas estimate", F)
}

fn eth_call(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "eth_call";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "eth_call()")?;
    let tx = match arg(args, 1, F)? {
        v @ SynValue::Map(_) => syn_to_eth_json(v, "the call", F, 0)?,
        other => {
            return Err(err(format!(
                "{}: the call must be a map ({{to, data, …}}), got {}",
                F,
                other.type_name()
            )))
        }
    };
    let tag = block_tag(args.get(2), F)?;
    let result = jsonrpc_call(&url, "eth_call", Json::Array(vec![tx, tag]), F, RPC_HTTP_TIMEOUT_SECS)?;
    let s = result.as_str().ok_or_else(|| {
        err(format!("{}: expected the return data as a hex string, the node sent something else", F))
    })?;
    // Retorno CRUDO como bytes — se decodifica con abi_decode (la salida se
    // re-inyecta a un decoder, no se muestra).
    Ok(syn_bytes(hexdata_to_bytes(s, "the return data", F)?))
}

fn eth_send_raw(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "eth_send_raw";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "eth_send_raw()")?;
    let raw = arg_bytes(arg(args, 1, F)?, F, "the signed transaction")?;
    let params = Json::Array(vec![Json::Str(bytes_to_hexdata(raw))]);
    let result = jsonrpc_call(&url, "eth_sendRawTransaction", params, F, RPC_HTTP_TIMEOUT_SECS)?;
    let s = result.as_str().ok_or_else(|| {
        err(format!("{}: expected the tx hash as a string, the node sent something else", F))
    })?;
    let h = hexdata_to_bytes(s, "the tx hash", F)?;
    if h.len() != 32 {
        return Err(err(format!("{}: the node returned a tx hash of {} bytes (expected 32)", F, h.len())));
    }
    Ok(syn_text(bytes_to_hexdata(&h)))
}

// -- Receipt: decode tipado y estricto de los campos conocidos --

const RECEIPT_QTY_KEYS: &[&str] = &[
    "blockNumber",
    "cumulativeGasUsed",
    "effectiveGasPrice",
    "gasUsed",
    "status",
    "transactionIndex",
    "type",
    "blobGasUsed",
    "blobGasPrice",
];
const RECEIPT_ADDR_KEYS: &[&str] = &["from", "to", "contractAddress"];
const RECEIPT_HASH_KEYS: &[&str] = &["blockHash", "transactionHash"];
const LOG_QTY_KEYS: &[&str] = &["blockNumber", "logIndex", "transactionIndex"];

/// Dirección del wire (`0x` + 40 hex) → text EIP-55; `null` → nothing.
fn decode_wire_address(v: &serde_json::Value, what: &str, fname: &str) -> Result<SynValue, Control> {
    if v.is_null() {
        return Ok(SynValue::Nothing);
    }
    let s = v.as_str().ok_or_else(|| {
        err(format!("{}: {} is not an address string", fname, what))
    })?;
    let b = hexdata_to_bytes(s, what, fname)?;
    if b.len() != 20 {
        return Err(err(format!("{}: {} is {} bytes, an address has 20", fname, what, b.len())));
    }
    Ok(syn_text(eip55(&b)))
}

/// Hash del wire (`0x` + 64 hex) → text `0x…` minúsculas validado.
fn decode_wire_hash(v: &serde_json::Value, what: &str, fname: &str) -> Result<SynValue, Control> {
    if v.is_null() {
        return Ok(SynValue::Nothing);
    }
    let s = v.as_str().ok_or_else(|| err(format!("{}: {} is not a hash string", fname, what)))?;
    let b = hexdata_to_bytes(s, what, fname)?;
    if b.len() != 32 {
        return Err(err(format!("{}: {} is {} bytes, a hash has 32", fname, what, b.len())));
    }
    Ok(syn_text(bytes_to_hexdata(&b)))
}

fn decode_wire_qty(v: &serde_json::Value, what: &str, fname: &str) -> Result<SynValue, Control> {
    if v.is_null() {
        return Ok(SynValue::Nothing);
    }
    Ok(syn_number(expect_hexq(v, what, fname)?))
}

/// Un log del receipt → map tipado: address EIP-55, topics `0x…` text, data bytes
/// (se re-inyecta a `abi_decode`), cantidades int. Claves desconocidas pasan tal
/// cual (json_to_syn) — no se pierde información.
fn decode_log(v: &serde_json::Value, idx: usize, fname: &str) -> Result<SynValue, Control> {
    let what = format!("logs[{}]", idx);
    let obj = as_obj(v, &what, fname)?;
    let mut out = IndexMap::new();
    for (k, val) in obj {
        let path = format!("{}.{}", what, k);
        let dv = if k == "address" {
            decode_wire_address(val, &path, fname)?
        } else if k == "topics" {
            let arr = val.as_array().ok_or_else(|| {
                err(format!("{}: {} is not a list", fname, path))
            })?;
            let mut topics = Vec::with_capacity(arr.len());
            for (i, t) in arr.iter().enumerate() {
                topics.push(decode_wire_hash(t, &format!("{}[{}]", path, i), fname)?);
            }
            syn_list(topics)
        } else if k == "data" {
            let s = val.as_str().ok_or_else(|| {
                err(format!("{}: {} is not a hex string", fname, path))
            })?;
            syn_bytes(hexdata_to_bytes(s, &path, fname)?)
        } else if LOG_QTY_KEYS.contains(&k.as_str()) {
            decode_wire_qty(val, &path, fname)?
        } else if RECEIPT_HASH_KEYS.contains(&k.as_str()) {
            decode_wire_hash(val, &path, fname)?
        } else if k == "removed" {
            match val.as_bool() {
                Some(b) => syn_bool(b),
                None => json_to_syn(val),
            }
        } else {
            json_to_syn(val)
        };
        out.insert(k.clone(), dv);
    }
    Ok(syn_map(out))
}

/// Receipt del wire → map tipado (cantidades int, direcciones EIP-55, hashes
/// `0x…` text, logs decodificados). Estricto en los campos conocidos (G23);
/// claves desconocidas pasan tal cual.
fn decode_receipt(v: &serde_json::Value, fname: &str) -> Result<SynValue, Control> {
    let obj = as_obj(v, "the receipt", fname)?;
    let mut out = IndexMap::new();
    for (k, val) in obj {
        let path = format!("receipt.{}", k);
        let dv = if RECEIPT_QTY_KEYS.contains(&k.as_str()) {
            decode_wire_qty(val, &path, fname)?
        } else if RECEIPT_ADDR_KEYS.contains(&k.as_str()) {
            decode_wire_address(val, &path, fname)?
        } else if RECEIPT_HASH_KEYS.contains(&k.as_str()) {
            decode_wire_hash(val, &path, fname)?
        } else if k == "logs" {
            let arr = val.as_array().ok_or_else(|| {
                err(format!("{}: receipt.logs is not a list", fname))
            })?;
            let mut logs = Vec::with_capacity(arr.len());
            for (i, l) in arr.iter().enumerate() {
                logs.push(decode_log(l, i, fname)?);
            }
            syn_list(logs)
        } else {
            json_to_syn(val)
        };
        out.insert(k.clone(), dv);
    }
    Ok(syn_map(out))
}

fn eth_receipt(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "eth_receipt";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "eth_receipt()")?;
    let hash = tx_hash_hex(arg(args, 1, F)?, F)?;
    let result = jsonrpc_call(
        &url,
        "eth_getTransactionReceipt",
        Json::Array(vec![Json::Str(hash)]),
        F,
        RPC_HTTP_TIMEOUT_SECS,
    )?;
    if result.is_null() {
        return Ok(SynValue::Nothing);
    }
    decode_receipt(&result, F)
}

fn eth_wait_receipt(
    args: &[SynValue],
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "eth_wait_receipt";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "eth_wait_receipt()")?;
    let hash = tx_hash_hex(arg(args, 1, F)?, F)?;
    let confirmations: i64 = match args.get(2) {
        None | Some(SynValue::Nothing) => 1,
        Some(SynValue::Number(n)) => match n.to_i64_trunc() {
            Some(c @ 1..=1000) if n.is_integer() => c,
            _ => {
                return Err(err(format!(
                    "{}: confirmations must be an integer 1..=1000",
                    F
                )))
            }
        },
        Some(other) => {
            return Err(err(format!(
                "{}: confirmations must be a number, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let timeout = wait_timeout_arg(args.get(3), F)?;
    let deadline = Instant::now() + timeout;
    let mut polled_ok = false;
    let mut warned = false;
    let mut last_transient: Option<Control> = None;
    loop {
        let result = match jsonrpc_call_classified(
            &url,
            "eth_getTransactionReceipt",
            Json::Array(vec![Json::Str(hash.clone())]),
            F,
            poll_http_timeout(deadline),
        ) {
            Ok(v) => {
                polled_ok = true;
                last_transient = None;
                v
            }
            Err(e) => {
                handle_poll_err(e, polled_ok, &mut warned, &mut last_transient, F)?;
                if !sleep_step(deadline, EVM_POLL) {
                    return deadline_result(last_transient);
                }
                continue;
            }
        };
        if !result.is_null() {
            // ¿Alcanzan las confirmaciones? (1 = incluido en un bloque.)
            let ok = if confirmations <= 1 {
                true
            } else {
                let block = as_obj(&result, "the receipt", F)?
                    .get("blockNumber")
                    .map(|v| expect_hexq(v, "receipt.blockNumber", F))
                    .transpose()?
                    .and_then(|n| n.to_i64_trunc());
                match block {
                    Some(mined) => {
                        let latest = match jsonrpc_call_classified(
                            &url,
                            "eth_blockNumber",
                            Json::Array(Vec::new()),
                            F,
                            poll_http_timeout(deadline),
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                handle_poll_err(e, polled_ok, &mut warned, &mut last_transient, F)?;
                                if !sleep_step(deadline, EVM_POLL) {
                                    return deadline_result(last_transient);
                                }
                                continue;
                            }
                        };
                        let latest = expect_hexq(&latest, "the block number", F)?
                            .to_i64_trunc()
                            .unwrap_or(0);
                        latest - mined + 1 >= confirmations
                    }
                    None => false, // receipt sin blockNumber: aún no minado de verdad
                }
            };
            if ok {
                return decode_receipt(&result, F);
            }
        }
        if !sleep_step(deadline, EVM_POLL) {
            return Ok(SynValue::Nothing);
        }
    }
}

// -- eth_fee_history: la lectura EIP-1559 con la derivación transparente --

fn eth_fee_history(
    args: &[SynValue],
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "eth_fee_history";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "eth_fee_history()")?;
    let blocks: i64 = match args.get(1) {
        None | Some(SynValue::Nothing) => 5,
        Some(SynValue::Number(n)) => match n.to_i64_trunc() {
            Some(b @ 1..=1024) if n.is_integer() => b,
            _ => return Err(err(format!("{}: blocks must be an integer 1..=1024", F))),
        },
        Some(other) => {
            return Err(err(format!("{}: blocks must be a number, got {}", F, other.type_name())))
        }
    };
    let percentiles: Vec<Json> = match args.get(2) {
        None | Some(SynValue::Nothing) => vec![Json::Int(50)],
        Some(SynValue::List(l)) => {
            let items = l.borrow().clone();
            if items.is_empty() {
                return Err(err(format!("{}: percentiles cannot be empty", F)));
            }
            let mut out = Vec::with_capacity(items.len());
            for (i, it) in items.iter().enumerate() {
                match it {
                    SynValue::Number(n) => {
                        let f = n.to_f64();
                        if !(0.0..=100.0).contains(&f) {
                            return Err(err(format!(
                                "{}: percentiles[{}] must be between 0 and 100",
                                F, i
                            )));
                        }
                        out.push(if n.is_integer() {
                            Json::Int(n.to_i64_trunc().unwrap_or(0))
                        } else {
                            Json::Float(f)
                        });
                    }
                    other => {
                        return Err(err(format!(
                            "{}: percentiles[{}] must be a number, got {}",
                            F,
                            i,
                            other.type_name()
                        )))
                    }
                }
            }
            out
        }
        Some(other) => {
            return Err(err(format!(
                "{}: percentiles must be a list of numbers, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let params = Json::Array(vec![
        Json::Str(number_to_hexq(&Number::Int(blocks), "blocks", F)?),
        Json::Str("latest".to_string()),
        Json::Array(percentiles),
    ]);
    let result = jsonrpc_call(&url, "eth_feeHistory", params, F, RPC_HTTP_TIMEOUT_SECS)?;
    let obj = as_obj(&result, "the fee history", F)?;

    // baseFeePerGas: blocks+1 entradas; la ÚLTIMA es el base fee del PRÓXIMO
    // bloque — el número que corresponde a la tx que se está construyendo.
    let base_raw = obj
        .get("baseFeePerGas")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| err(format!("{}: the node sent no baseFeePerGas list", F)))?;
    if base_raw.is_empty() {
        return Err(err(format!("{}: the node sent an empty baseFeePerGas list", F)));
    }
    let mut base_fees = Vec::with_capacity(base_raw.len());
    for (i, b) in base_raw.iter().enumerate() {
        base_fees.push(expect_hexq(b, &format!("baseFeePerGas[{}]", i), F)?);
    }
    let base_fee = base_fees.last().cloned().unwrap_or(Number::Int(0));

    // reward: por bloque, una entrada por percentil pedido. La sugerencia
    // `priority` es la MEDIANA de la PRIMERA columna (el primer percentil pedido;
    // con el default [50], la mediana de las medianas). Los arrays crudos se
    // devuelven enteros: la derivación es transparente, no un oráculo opaco (G24).
    let rewards_raw = obj
        .get("reward")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| err(format!("{}: the node sent no reward list", F)))?;
    let mut rewards: Vec<SynValue> = Vec::with_capacity(rewards_raw.len());
    let mut first_col: Vec<BigInt> = Vec::new();
    for (i, row) in rewards_raw.iter().enumerate() {
        let row_arr = row.as_array().ok_or_else(|| {
            err(format!("{}: reward[{}] is not a list", F, i))
        })?;
        let mut row_out = Vec::with_capacity(row_arr.len());
        for (j, r) in row_arr.iter().enumerate() {
            let n = expect_hexq(r, &format!("reward[{}][{}]", i, j), F)?;
            if j == 0 {
                if let Some(b) = n.as_bigint() {
                    first_col.push(b);
                }
            }
            row_out.push(syn_number(n));
        }
        rewards.push(syn_list(row_out));
    }
    if first_col.is_empty() {
        return Err(err(format!(
            "{}: the node sent no reward data — cannot derive a priority fee suggestion (G24: refusing to invent one)",
            F
        )));
    }
    first_col.sort();
    let priority = Number::from_bigint(first_col[first_col.len() / 2].clone());

    let mut m = IndexMap::new();
    m.insert("base_fee".to_string(), syn_number(base_fee));
    m.insert("priority".to_string(), syn_number(priority));
    m.insert(
        "base_fees".to_string(),
        syn_list(base_fees.into_iter().map(syn_number).collect()),
    );
    m.insert("rewards".to_string(), syn_list(rewards));
    Ok(syn_map(m))
}

// =========================================================
// tx_eip1559 — builder PURO (G24: todo explícito, los números quedan a la vista)
// =========================================================

/// Campo entero requerido de `bits` como máximo. El error de campo faltante nombra
/// el helper que lo LEE de la cadena — no hay default silencioso (G24).
fn uint_field(
    m: &IndexMap<String, SynValue>,
    key: &str,
    bits: u64,
    read_hint: &str,
    fname: &str,
) -> Result<Number, Control> {
    let v = m.get(key).ok_or_else(|| {
        err(format!(
            "{}: missing \"{}\" — every value-moving field is explicit (G24): read it with {} or state it; nothing is defaulted",
            fname, key, read_hint
        ))
    })?;
    let n = match v {
        SynValue::Number(n) => n,
        other => {
            return Err(err(format!(
                "{}: \"{}\" must be an integer, got {}",
                fname,
                key,
                other.type_name()
            )))
        }
    };
    let big = n.as_bigint().ok_or_else(|| {
        err(format!(
            "{}: \"{}\" must be an exact integer (no floats — amounts are exact)",
            fname, key
        ))
    })?;
    if big.sign() == num_bigint::Sign::Minus {
        return Err(err(format!("{}: \"{}\" cannot be negative", fname, key)));
    }
    if big.bits() > bits {
        return Err(err(format!(
            "{}: \"{}\" does not fit in uint{} (needs {} bits)",
            fname,
            key,
            bits,
            big.bits()
        )));
    }
    Ok(n.clone())
}

/// access_list opcional → SynValue listo para RLP: `[[addr20, [key32, …]], …]`.
fn access_list_field(v: Option<&SynValue>, fname: &str) -> Result<SynValue, Control> {
    let list = match v {
        None | Some(SynValue::Nothing) => return Ok(syn_list(Vec::new())),
        Some(SynValue::List(l)) => l.borrow().clone(),
        Some(other) => {
            return Err(err(format!(
                "{}: \"access_list\" must be a list, got {}",
                fname,
                other.type_name()
            )))
        }
    };
    let mut out = Vec::with_capacity(list.len());
    for (i, item) in list.iter().enumerate() {
        let what = format!("access_list[{}]", i);
        let m = match item {
            SynValue::Map(m) => m.borrow().clone(),
            other => {
                return Err(err(format!(
                    "{}: {} must be a map {{address, storage_keys}}, got {}",
                    fname,
                    what,
                    other.type_name()
                )))
            }
        };
        for k in m.keys() {
            if !matches!(k.as_str(), "address" | "storage_keys") {
                return Err(err(format!(
                    "{}: unknown key {:?} in {} (allowed: address, storage_keys)",
                    fname, k, what
                )));
            }
        }
        let addr = addr20(
            m.get("address")
                .ok_or_else(|| err(format!("{}: {} is missing \"address\"", fname, what)))?,
            &format!("{}.address", what),
            fname,
        )?;
        let keys = match m.get("storage_keys") {
            None | Some(SynValue::Nothing) => Vec::new(),
            Some(SynValue::List(l)) => {
                let items = l.borrow().clone();
                let mut ks = Vec::with_capacity(items.len());
                for (j, k) in items.iter().enumerate() {
                    let kb = arg_bytes_len(
                        k,
                        fname,
                        &format!("{}.storage_keys[{}]", what, j),
                        32,
                    )?;
                    ks.push(syn_bytes(kb.to_vec()));
                }
                ks
            }
            Some(other) => {
                return Err(err(format!(
                    "{}: {}.storage_keys must be a list of 32-byte keys, got {}",
                    fname,
                    what,
                    other.type_name()
                )))
            }
        };
        out.push(syn_list(vec![syn_bytes(addr.to_vec()), syn_list(keys)]));
    }
    Ok(syn_list(out))
}

/// `tx_eip1559(params)` → map `{digest, fields, …eco de los números}`. PURO: no
/// firma ni difunde nada. El flujo completo (sin hand-rollear el ensamblado):
/// ```text
/// let tx be tx_eip1559({…})
/// -- confirm con tx["max_fee"]/tx["value"] A LA VISTA (G24)
/// let sig be secp256k1_sign(tx["digest"], secret("KEY"))   -- la ÚNICA puerta
/// let raw be tx_eip1559_raw(tx, sig)
/// let hash be eth_send_raw(url, raw)
/// ```
fn tx_eip1559(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "tx_eip1559";
    let m = match arg(args, 0, F)? {
        SynValue::Map(m) => m.borrow().clone(),
        other => {
            return Err(err(format!(
                "{}: params must be a map, got {}",
                F,
                other.type_name()
            )))
        }
    };
    for k in m.keys() {
        if !matches!(
            k.as_str(),
            "chain_id" | "nonce" | "to" | "value" | "data" | "gas" | "max_fee" | "max_priority"
                | "access_list"
        ) {
            return Err(err(format!(
                "{}: unknown key {:?} in params (allowed: chain_id, nonce, to, value, data, gas, max_fee, max_priority, access_list)",
                F, k
            )));
        }
    }
    let chain_id = uint_field(&m, "chain_id", 64, "eth_chain_id(url)", F)?;
    let nonce = uint_field(&m, "nonce", 64, "eth_nonce(url, from)", F)?;
    let gas = uint_field(&m, "gas", 64, "eth_estimate_gas(url, tx)", F)?;
    let value = uint_field(&m, "value", 256, "an explicit amount (0 for a pure contract call)", F)?;
    let max_fee = uint_field(&m, "max_fee", 256, "eth_fee_history(url)", F)?;
    let max_priority = uint_field(&m, "max_priority", 256, "eth_fee_history(url)", F)?;
    // El nodo rechazaría igual, pero acá el error llega ANTES de firmar.
    if let (Some(mf), Some(mp)) = (max_fee.as_bigint(), max_priority.as_bigint()) {
        if mp > mf {
            return Err(err(format!(
                "{}: \"max_priority\" is greater than \"max_fee\" — the tip can never exceed the fee cap",
                F
            )));
        }
    }
    let to = addr20(
        m.get("to").ok_or_else(|| {
            err(format!(
                "{}: missing \"to\" — the destination is explicit; contract creation is not supported here",
                F
            ))
        })?,
        "\"to\"",
        F,
    )?;
    let data: Vec<u8> = match m.get("data") {
        None | Some(SynValue::Nothing) => Vec::new(),
        Some(v) => arg_bytes(v, F, "\"data\"")?.to_vec(),
    };
    let access_list = access_list_field(m.get("access_list"), F)?;

    // Orden EIP-1559: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
    // gasLimit, to, value, data, accessList].
    let fields = syn_list(vec![
        syn_number(chain_id.clone()),
        syn_number(nonce.clone()),
        syn_number(max_priority.clone()),
        syn_number(max_fee.clone()),
        syn_number(gas.clone()),
        syn_bytes(to.to_vec()),
        syn_number(value.clone()),
        syn_bytes(data),
        access_list,
    ]);
    let mut payload = Vec::new();
    rlp_encode_val(&fields, 0, &mut payload)?;
    let mut unsigned = Vec::with_capacity(1 + payload.len());
    unsigned.push(0x02);
    unsigned.extend_from_slice(&payload);
    let digest = Keccak256::digest(&unsigned);

    let mut out = IndexMap::new();
    out.insert("digest".to_string(), syn_bytes(digest.to_vec()));
    out.insert("fields".to_string(), fields);
    // Eco de los números que mueven valor — para el confirm/show PREVIO a la
    // firma (G24): nada queda escondido dentro de un blob.
    out.insert("chain_id".to_string(), syn_number(chain_id));
    out.insert("nonce".to_string(), syn_number(nonce));
    out.insert("to".to_string(), syn_text(eip55(&to)));
    out.insert("value".to_string(), syn_number(value));
    out.insert("gas".to_string(), syn_number(gas));
    out.insert("max_fee".to_string(), syn_number(max_fee));
    out.insert("max_priority".to_string(), syn_number(max_priority));
    Ok(syn_map(out))
}

/// `tx_eip1559_raw(tx, signature)` → bytes de la tx firmada lista para
/// `eth_send_raw`. `tx` es el map de `tx_eip1559`; `signature` los 65 bytes de
/// `secp256k1_sign` (r‖s‖recovery_id). PURO: sólo ensambla.
fn tx_eip1559_raw(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "tx_eip1559_raw";
    let m = match arg(args, 0, F)? {
        SynValue::Map(m) => m.borrow().clone(),
        other => {
            return Err(err(format!(
                "{}: the first argument must be the map returned by tx_eip1559, got {}",
                F,
                other.type_name()
            )))
        }
    };
    let fields = match m.get("fields") {
        Some(SynValue::List(l)) => l.borrow().clone(),
        _ => {
            return Err(err(format!(
                "{}: the map has no \"fields\" list — pass the map returned by tx_eip1559",
                F
            )))
        }
    };
    if fields.len() != 9 {
        return Err(err(format!(
            "{}: \"fields\" has {} items, an EIP-1559 tx has 9 — pass the map returned by tx_eip1559 unmodified",
            F,
            fields.len()
        )));
    }
    let sig = arg_bytes_len(arg(args, 1, F)?, F, "the signature", 65)?;
    let v = sig[64];
    if v > 1 {
        return Err(err(format!(
            "{}: the recovery id (signature byte 65) must be 0 or 1, got {} — pass the signature from secp256k1_sign as-is (no 27/28 adjustment: typed txs use y-parity)",
            F, v
        )));
    }
    let r = Number::from_be_bytes(&sig[..32]);
    let s = Number::from_be_bytes(&sig[32..64]);
    let mut signed = fields;
    signed.push(syn_int(v as i64));
    signed.push(syn_number(r));
    signed.push(syn_number(s));
    let mut payload = Vec::new();
    rlp_encode_val(&syn_list(signed), 0, &mut payload)?;
    let mut raw = Vec::with_capacity(1 + payload.len());
    raw.push(0x02);
    raw.extend_from_slice(&payload);
    Ok(syn_bytes(raw))
}

// =========================================================
// Alcance B — Solana RPC
// =========================================================

fn solana_rpc(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "solana_rpc";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "solana_rpc()")?;
    let method = text_arg(arg(args, 1, F)?, "the method", F)?;
    let params = params_arg(args.get(2), F, syn_to_plain_json)?;
    let result = jsonrpc_call(&url, &method, params, F, RPC_HTTP_TIMEOUT_SECS)?;
    Ok(json_to_syn(&result))
}

/// El envelope `{context, value}` de los métodos "commitment-aware" de Solana.
fn solana_value(result: &serde_json::Value, fname: &str) -> Result<serde_json::Value, Control> {
    as_obj(result, "the RPC result", fname)?
        .get("value")
        .cloned()
        .ok_or_else(|| err(format!("{}: the RPC result has no \"value\" field", fname)))
}

fn solana_latest_blockhash(
    args: &[SynValue],
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "solana_latest_blockhash";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "solana_latest_blockhash()")?;
    let result = jsonrpc_call(&url, "getLatestBlockhash", Json::Array(Vec::new()), F, RPC_HTTP_TIMEOUT_SECS)?;
    let value = solana_value(&result, F)?;
    let vh = as_obj(&value, "the blockhash value", F)?;
    let b58 = get_str(vh, "blockhash", "the blockhash value", F)?;
    let raw = base58_decode(b58)
        .map_err(|e| err(format!("{}: the node sent an invalid base58 blockhash: {}", F, e)))?;
    if raw.len() != 32 {
        return Err(err(format!(
            "{}: the blockhash decodes to {} bytes (expected 32)",
            F,
            raw.len()
        )));
    }
    // bytes32 directo: se re-inyecta a solana_message({"recent_blockhash": …}).
    Ok(syn_bytes(raw))
}

fn solana_balance(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "solana_balance";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "solana_balance()")?;
    let pk = pubkey32(arg(args, 1, F)?, "the pubkey", F)?;
    let params = Json::Array(vec![Json::Str(base58_encode(&pk))]);
    let result = jsonrpc_call(&url, "getBalance", params, F, RPC_HTTP_TIMEOUT_SECS)?;
    let value = solana_value(&result, F)?;
    let lamports = value.as_u64().ok_or_else(|| {
        err(format!("{}: the node sent a non-integer balance", F))
    })?;
    Ok(u64_number(lamports))
}

fn solana_send(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "solana_send";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "solana_send()")?;
    let tx = arg_bytes(arg(args, 1, F)?, F, "the signed transaction")?;
    let params = Json::Array(vec![
        Json::Str(b64_encode(tx)),
        Json::Object(vec![("encoding".to_string(), Json::Str("base64".to_string()))]),
    ]);
    let result = jsonrpc_call(&url, "sendTransaction", params, F, RPC_HTTP_TIMEOUT_SECS)?;
    let sig = result.as_str().ok_or_else(|| {
        err(format!("{}: expected the signature as a string, the node sent something else", F))
    })?;
    // Validar que la firma decodifique a 64 bytes (G23) — y devolverla como el
    // text base58 con el que se consulta/muestra.
    match base58_decode(sig) {
        Ok(raw) if raw.len() == 64 => Ok(syn_text(sig)),
        Ok(raw) => Err(err(format!(
            "{}: the node returned a signature of {} bytes (expected 64)",
            F,
            raw.len()
        ))),
        Err(e) => Err(err(format!("{}: the node returned an invalid base58 signature: {}", F, e))),
    }
}

/// Firma (text base58 o bytes 64) → text base58 validado.
fn solana_sig_arg(v: &SynValue, fname: &str) -> Result<String, Control> {
    match v {
        SynValue::Text(s) => match base58_decode(s) {
            Ok(raw) if raw.len() == 64 => Ok(s.to_string()),
            Ok(raw) => Err(err(format!(
                "{}: the signature decodes to {} bytes (expected 64)",
                fname,
                raw.len()
            ))),
            Err(e) => Err(err(format!("{}: the signature is not valid base58: {}", fname, e))),
        },
        SynValue::Bytes(b) => {
            if b.len() != 64 {
                return Err(err(format!(
                    "{}: the signature must be 64 bytes, got {}",
                    fname,
                    b.len()
                )));
            }
            Ok(base58_encode(b))
        }
        other => Err(err(format!(
            "{}: the signature must be base58 text or 64 bytes, got {}",
            fname,
            other.type_name()
        ))),
    }
}

fn solana_confirm(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "solana_confirm";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "solana_confirm()")?;
    let sig = solana_sig_arg(arg(args, 1, F)?, F)?;
    let timeout = wait_timeout_arg(args.get(2), F)?;
    let deadline = Instant::now() + timeout;
    let mut polled_ok = false;
    let mut warned = false;
    let mut last_transient: Option<Control> = None;
    loop {
        let params = Json::Array(vec![Json::Array(vec![Json::Str(sig.clone())])]);
        let result = match jsonrpc_call_classified(
            &url,
            "getSignatureStatuses",
            params,
            F,
            poll_http_timeout(deadline),
        ) {
            Ok(v) => {
                polled_ok = true;
                last_transient = None;
                v
            }
            Err(e) => {
                handle_poll_err(e, polled_ok, &mut warned, &mut last_transient, F)?;
                if !sleep_step(deadline, SOLANA_POLL) {
                    return deadline_result(last_transient);
                }
                continue;
            }
        };
        let value = solana_value(&result, F)?;
        let status = value
            .as_array()
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if !status.is_null() {
            let obj = as_obj(&status, "the signature status", F)?;
            let confirmation_status = obj
                .get("confirmationStatus")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            let tx_err = obj.get("err").cloned().unwrap_or(serde_json::Value::Null);
            // Definitivo: falló on-chain (err) o alcanzó confirmed/finalized.
            // "processed" puede revertirse → se sigue esperando.
            let done = !tx_err.is_null()
                || matches!(confirmation_status.as_deref(), Some("confirmed") | Some("finalized"));
            if done {
                let mut m = IndexMap::new();
                m.insert(
                    "slot".to_string(),
                    obj.get("slot")
                        .and_then(serde_json::Value::as_u64)
                        .map(u64_number)
                        .unwrap_or(SynValue::Nothing),
                );
                m.insert(
                    "confirmations".to_string(),
                    obj.get("confirmations")
                        .and_then(serde_json::Value::as_u64)
                        .map(u64_number)
                        .unwrap_or(SynValue::Nothing),
                );
                m.insert(
                    "confirmation_status".to_string(),
                    confirmation_status.map(syn_text).unwrap_or(SynValue::Nothing),
                );
                // "err" nothing = éxito; cualquier otra cosa = la tx ATERRIZÓ
                // pero FALLÓ — el caller SIEMPRE chequea este campo.
                m.insert(
                    "err".to_string(),
                    if tx_err.is_null() { SynValue::Nothing } else { json_to_syn(&tx_err) },
                );
                return Ok(syn_map(m));
            }
        }
        if !sleep_step(deadline, SOLANA_POLL) {
            return Ok(SynValue::Nothing);
        }
    }
}

fn spl_balance(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "spl_balance";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "spl_balance()")?;
    let owner = pubkey32(arg(args, 1, F)?, "the owner", F)?;
    let mint = pubkey32(arg(args, 2, F)?, "the mint", F)?;
    let token_program = match args.get(3) {
        None | Some(SynValue::Nothing) => token_program_default(),
        Some(v) => pubkey32(v, "the token program", F)?,
    };
    let ata = ata_address(&owner, &mint, &token_program, F)?;
    let params = Json::Array(vec![Json::Str(base58_encode(&ata))]);
    // Un ATA inexistente es un RPC error → error ATRAPABLE, no un 0 silencioso:
    // un owner/mint equivocado leería 0 para siempre (la mentira que G23 prohíbe).
    let result = jsonrpc_call(&url, "getTokenAccountBalance", params, F, RPC_HTTP_TIMEOUT_SECS)?;
    let value = solana_value(&result, F)?;
    let vo = as_obj(&value, "the token balance", F)?;
    let amount_s = get_str(vo, "amount", "the token balance", F)?;
    if amount_s.is_empty() || !amount_s.bytes().all(|c| c.is_ascii_digit()) {
        return Err(err(format!("{}: the node sent a non-integer token amount", F)));
    }
    let amount = amount_s
        .parse::<BigInt>()
        .map_err(|_| err(format!("{}: the node sent an unparseable token amount", F)))?;
    let decimals = get_u64(vo, "decimals", "the token balance", F)?;
    if decimals > 255 {
        return Err(err(format!("{}: the node sent decimals over 255", F)));
    }
    let mut m = IndexMap::new();
    m.insert("amount".to_string(), syn_number(Number::from_bigint(amount)));
    m.insert("decimals".to_string(), syn_int(decimals as i64));
    m.insert("ata".to_string(), syn_bytes(ata.to_vec()));
    Ok(syn_map(m))
}

// =========================================================
// Alcance C — Algorand REST (algod)
// =========================================================

/// URL base + path del endpoint (sin dobles barras).
fn algod_url(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// GET a algod → JSON parseado y clasificado, con los headers del caller (p.ej.
/// `X-Algo-API-Token` como secret — se materializa en el borde del socket).
fn algod_get_classified(
    base: &str,
    path: &str,
    headers: Option<&SynValue>,
    fname: &str,
    timeout_secs: u64,
) -> Result<serde_json::Value, PollError> {
    let url = algod_url(base, path);
    let hs = header_pairs(headers);
    let r = http_request("GET", &url, hs.as_deref(), None, None, timeout_secs);
    http_result_to_json_classified(r, &url, fname)
}

/// Versión sin clasificar (one-shots): cualquier falla → error atrapable.
fn algod_get(
    base: &str,
    path: &str,
    headers: Option<&SynValue>,
    fname: &str,
    timeout_secs: u64,
) -> Result<serde_json::Value, Control> {
    algod_get_classified(base, path, headers, fname, timeout_secs).map_err(PollError::into_control)
}

fn algorand_params(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "algorand_params";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "algorand_params()")?;
    let v = algod_get(&url, "/v2/transactions/params", args.get(1), F, RPC_HTTP_TIMEOUT_SECS)?;
    let obj = as_obj(&v, "the suggested params", F)?;
    // ⚠️ El "fee" de algod es POR BYTE (usualmente 0); el flat mínimo real es
    // "min-fee" (1000 µAlgo). Devolver los DOS evita el bug clásico de usar el
    // per-byte como flat (tx rechazada) o el min como per-byte (fee inflado).
    let fee = get_u64(obj, "fee", "the suggested params", F)?;
    let min_fee = get_u64(obj, "min-fee", "the suggested params", F)?;
    let last_round = get_u64(obj, "last-round", "the suggested params", F)?;
    let gh_b64 = get_str(obj, "genesis-hash", "the suggested params", F)?;
    let gh = b64_decode(gh_b64)
        .map_err(|e| err(format!("{}: the node sent an invalid base64 genesis hash: {}", F, e)))?;
    if gh.len() != 32 {
        return Err(err(format!(
            "{}: the genesis hash decodes to {} bytes (expected 32)",
            F,
            gh.len()
        )));
    }
    let gen = get_str(obj, "genesis-id", "the suggested params", F)?;
    // lv = fv + 1000: la ventana de validez MÁXIMA del protocolo (la misma que
    // arman los SDKs oficiales) — no mueve valor, sólo acota cuándo vence.
    // checked_add: un last-round cerca de u64::MAX es basura de un nodo hostil
    // (G23) — error atrapable, jamás un wrap silencioso ni un panic de overflow.
    let lv = last_round.checked_add(ALGORAND_MAX_VALIDITY).ok_or_else(|| {
        err(format!(
            "{}: the node sent an absurd last-round ({}) — not a real Algorand round",
            F, last_round
        ))
    })?;
    let mut m = IndexMap::new();
    m.insert("fee".to_string(), u64_number(fee));
    m.insert("min_fee".to_string(), u64_number(min_fee));
    m.insert("fv".to_string(), u64_number(last_round));
    m.insert("lv".to_string(), u64_number(lv));
    m.insert("gh".to_string(), syn_bytes(gh));
    m.insert("gen".to_string(), syn_text(gen));
    Ok(syn_map(m))
}

fn algorand_account(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "algorand_account";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "algorand_account()")?;
    let addr = text_arg(arg(args, 1, F)?, "the address", F)?;
    // Checksum validado ANTES de tocar la red (una dirección con typo no se consulta).
    address_to_pubkey(&addr, "the address", F)?;
    let v = algod_get(&url, &format!("/v2/accounts/{}", addr), args.get(2), F, RPC_HTTP_TIMEOUT_SECS)?;
    Ok(json_to_syn(&v))
}

fn algorand_send(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "algorand_send";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "algorand_send()")?;
    let tx = arg_bytes(arg(args, 1, F)?, F, "the signed transaction")?;
    let full = algod_url(&url, "/v2/transactions");
    // El Content-Type del protocolo SIEMPRE gana: un caller que puso el suyo en
    // los headers duplicaría el header (un algod estricto rechaza el request).
    let mut hs = header_pairs(args.get(2)).unwrap_or_default();
    hs.retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
    hs.push(("Content-Type".to_string(), "application/x-binary".to_string()));
    // Body BINARIO (el SignedTxn msgpack) — por eso no alcanza http_post.
    let r = http_request_body_bytes("POST", &full, Some(&hs), tx, RPC_HTTP_TIMEOUT_SECS);
    let v = http_result_to_json(r, &full, F)?;
    let obj = as_obj(&v, "the send response", F)?;
    let txid = get_str(obj, "txId", "the send response", F)?;
    Ok(syn_text(txid))
}

/// TXID de Algorand: 52 chars base32 (A–Z, 2–7). Validado ANTES de interpolarlo
/// en el path del endpoint (input hostil jamás construye una URL arbitraria).
fn algorand_txid_arg(v: &SynValue, fname: &str) -> Result<String, Control> {
    let s = text_arg(v, "the txid", fname)?;
    if s.len() != 52 || !s.bytes().all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c)) {
        return Err(err(format!(
            "{}: the txid must be 52 base32 characters (A-Z, 2-7)",
            fname
        )));
    }
    Ok(s)
}

fn algorand_wait(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "algorand_wait";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "algorand_wait()")?;
    let txid = algorand_txid_arg(arg(args, 1, F)?, F)?;
    let timeout = wait_timeout_arg(args.get(2), F)?;
    let deadline = Instant::now() + timeout;
    let path = format!("/v2/transactions/pending/{}?format=json", txid);
    let mut polled_ok = false;
    let mut warned = false;
    let mut last_transient: Option<Control> = None;
    loop {
        let v = match algod_get_classified(&url, &path, args.get(3), F, poll_http_timeout(deadline))
        {
            Ok(v) => {
                polled_ok = true;
                last_transient = None;
                v
            }
            Err(e) => {
                handle_poll_err(e, polled_ok, &mut warned, &mut last_transient, F)?;
                if !sleep_step(deadline, ALGORAND_POLL) {
                    return deadline_result(last_transient);
                }
                continue;
            }
        };
        let obj = as_obj(&v, "the pending transaction info", F)?;
        // Rechazo del pool: DEFINITIVO — la tx jamás va a confirmar; error
        // atrapable (seguir esperando sería mentir por omisión).
        if let Some(pe) = obj.get("pool-error").and_then(serde_json::Value::as_str) {
            if !pe.is_empty() {
                return Err(err(format!("{}: the transaction was rejected: {}", F, snippet(pe))));
            }
        }
        if let Some(round) = obj.get("confirmed-round").and_then(serde_json::Value::as_u64) {
            if round > 0 {
                return Ok(json_to_syn(&v));
            }
        }
        if !sleep_step(deadline, ALGORAND_POLL) {
            return Ok(SynValue::Nothing);
        }
    }
}

// =========================================================
// Registro
// =========================================================

/// Registra el read-side. TODO lo que toca red cierra sobre el `CapabilitySet`
/// para el gate `net(host)` (G22 — sandbox lo vacía, deny-by-default); los
/// builders `tx_eip1559`/`tx_eip1559_raw` son PUROS. Wired desde
/// `register_blockchain_builtins`.
pub(crate) fn register(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    macro_rules! net_builtin {
        ($name:literal, $arity:expr, $f:ident) => {{
            let caps = caps.clone();
            interp.register_builtin($name, $arity, Rc::new(move |_i, a, _l| $f(a, &caps)));
        }};
    }
    // -- EVM --
    net_builtin!("eth_rpc", -1, eth_rpc);
    net_builtin!("eth_nonce", 2, eth_nonce);
    net_builtin!("eth_balance", -1, eth_balance);
    net_builtin!("eth_gas_price", 1, eth_gas_price);
    net_builtin!("eth_chain_id", 1, eth_chain_id);
    net_builtin!("eth_estimate_gas", 2, eth_estimate_gas);
    net_builtin!("eth_call", -1, eth_call);
    net_builtin!("eth_fee_history", -1, eth_fee_history);
    net_builtin!("eth_send_raw", 2, eth_send_raw);
    net_builtin!("eth_receipt", 2, eth_receipt);
    net_builtin!("eth_wait_receipt", -1, eth_wait_receipt);
    // -- builders EIP-1559 (PUROS: G13/G22 — firmar sigue siendo la única puerta) --
    interp.register_builtin("tx_eip1559", 1, Rc::new(|_i, a, _l| tx_eip1559(a)));
    interp.register_builtin("tx_eip1559_raw", 2, Rc::new(|_i, a, _l| tx_eip1559_raw(a)));
    // -- Solana --
    net_builtin!("solana_rpc", -1, solana_rpc);
    net_builtin!("solana_latest_blockhash", 1, solana_latest_blockhash);
    net_builtin!("solana_balance", 2, solana_balance);
    net_builtin!("solana_send", 2, solana_send);
    net_builtin!("solana_confirm", -1, solana_confirm);
    net_builtin!("spl_balance", -1, spl_balance);
    // -- Algorand --
    net_builtin!("algorand_params", -1, algorand_params);
    net_builtin!("algorand_account", -1, algorand_account);
    net_builtin!("algorand_send", -1, algorand_send);
    net_builtin!("algorand_wait", -1, algorand_wait);
}

// =========================================================
// Tests (partes PURAS: hexq, builders contra el vector de eth-account)
// =========================================================

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::bytesutil::hex_decode;

    /// `Control` no implementa Debug — unwrap con el mensaje del error.
    fn ok<T>(r: Result<T, Control>) -> T {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
            Err(_) => panic!("control-flow inesperado"),
        }
    }

    // -- hex-quantity: el borde filoso #1, canónico en ambos sentidos --

    #[test]
    fn hexq_encode_canonical() {
        let cases: &[(i64, &str)] = &[(0, "0x0"), (1, "0x1"), (15, "0xf"), (16, "0x10"), (1024, "0x400")];
        for (n, want) in cases {
            assert_eq!(ok(number_to_hexq(&Number::Int(*n), "x", "t")), *want);
        }
        // Big > i64: exacto, sin ceros a la izquierda.
        let big = Number::Big(BigInt::parse_bytes(b"1000000000000000000000", 10).unwrap());
        assert_eq!(ok(number_to_hexq(&big, "x", "t")), "0x3635c9adc5dea00000");
        // Negativo y float → error.
        assert!(number_to_hexq(&Number::Int(-1), "x", "t").is_err());
        assert!(number_to_hexq(&Number::Float(1.5), "x", "t").is_err());
    }

    #[test]
    fn hexq_decode_strict() {
        // Válidos.
        assert_eq!(ok(hexq_to_number("0x0", "x", "t")).to_i64_trunc(), Some(0));
        assert_eq!(ok(hexq_to_number("0x1", "x", "t")).to_i64_trunc(), Some(1));
        assert_eq!(ok(hexq_to_number("0x400", "x", "t")).to_i64_trunc(), Some(1024));
        // > i64 → Big exacto.
        let wei = ok(hexq_to_number("0x3635c9adc5dea00000", "x", "t"));
        assert_eq!(wei.as_bigint().unwrap().to_string(), "1000000000000000000000");
        // Hostiles (G23): todos error atrapable.
        for bad in ["0x", "400", "0x01", "0x00", "0xzz", "0X1", "", "0x 1"] {
            assert!(hexq_to_number(bad, "x", "t").is_err(), "debió rechazar {:?}", bad);
        }
        // Más de 256 bits: basura u hostil.
        let huge = format!("0x1{}", "0".repeat(64));
        assert!(hexq_to_number(&huge, "x", "t").is_err());
    }

    #[test]
    fn hexq_roundtrip() {
        for s in ["0x0", "0x1", "0xff", "0x100", "0xde0b6b3a7640000"] {
            let n = ok(hexq_to_number(s, "x", "t"));
            assert_eq!(ok(number_to_hexq(&n, "x", "t")), s);
        }
    }

    // -- Vectores eth-account (SDK de la Ethereum Foundation; ver procedencia en
    //    la suite batch14 del runtime): clave m/44'/60'/0'/0/0 del mnemónico
    //    estándar (la MISMA pineada en batch13_hd_conformance). --

    /// Transfer simple: chainId 1, nonce 7, 0.1 ETH.
    const VEC1_RAW: &str = "02f87301078459682f008506fc23ac00825208946fac4d18c912343bf86fa7049364dd4e424ab9c088016345785d8a000080c080a054afb059cc17c8b3726db836c4d9093aaabfb6d422c9c190ae8e9c561e285fffa03f3c2eb5d5b609d2544817eb1ce8a4e64dfc8d4dbbc9db06f5ce2f2352b13f41";
    const VEC1_HASH: &str = "6fb18223cd52476122a18a2b59a6c9faca40b36937217962a4f81b0da1c79880";
    /// Con calldata ERC-20 + access list: chainId 43114 (Avalanche C-Chain).
    const VEC2_RAW: &str = "02f8eb82a86a808477359400850ba43b740082ea60946fac4d18c912343bf86fa7049364dd4e424ab9c080b844a9059cbb000000000000000000000000b6716976a3ebe8d39aceb04372f22ff8e6802d7a0000000000000000000000000000000000000000000000000de0b6b3a7640000f838f7949858effd232b4033e47d90003d41ec34ecaeda94e1a0000000000000000000000000000000000000000000000000000000000000000180a0e69bb33daf6938e2fd0113452b781e1ebd72c982be1e74081c1f0ebd93b3cabda02a75eb7e6a97ea9a8a77e2d2d594b27280817ef35d1488db50e9c8fba3cf493c";
    const VEC2_HASH: &str = "2ab8b14a5a355473033a5675f879e30ef1fccc7210e3d5913a0f37fc0a9d0569";

    fn map(pairs: Vec<(&str, SynValue)>) -> SynValue {
        let mut m = IndexMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        syn_map(m)
    }

    fn get(m: &SynValue, key: &str) -> SynValue {
        match m {
            SynValue::Map(mm) => mm.borrow().get(key).cloned().expect("key"),
            _ => panic!("not a map"),
        }
    }

    /// Extrae (r‖s‖v) de la raw firmada del SDK: los últimos 3 items RLP.
    fn sig_from_raw(raw_hex: &str) -> Vec<u8> {
        let raw = hex_decode(raw_hex).unwrap();
        // Parse mínimo: decodificar la lista RLP tras el 0x02 con el decoder del
        // batch 11 vía el camino público sería circular; acá extraemos r/s/v con
        // el conocimiento de que van al final: v (0x80 o 0x01), a0 + r(32), a0 + s(32).
        let s_start = raw.len() - 32;
        let r_start = s_start - 1 - 32;
        let v_byte = raw[r_start - 2];
        let v = if v_byte == 0x80 { 0u8 } else { v_byte };
        assert_eq!(raw[r_start - 1], 0xa0, "prefijo RLP de r");
        assert_eq!(raw[s_start - 1], 0xa0, "prefijo RLP de s");
        let mut sig = Vec::with_capacity(65);
        sig.extend_from_slice(&raw[r_start..r_start + 32]);
        sig.extend_from_slice(&raw[s_start..]);
        sig.push(v);
        sig
    }

    #[test]
    fn tx_eip1559_matches_eth_account_vector_simple() {
        let params = map(vec![
            ("chain_id", syn_int(1)),
            ("nonce", syn_int(7)),
            ("to", syn_text("0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0")),
            ("value", syn_number(Number::Big(BigInt::parse_bytes(b"100000000000000000", 10).unwrap()))),
            ("gas", syn_int(21000)),
            ("max_fee", syn_int(30000000000)),
            ("max_priority", syn_int(1500000000)),
        ]);
        let tx = ok(tx_eip1559(&[params]));
        // El digest es el keccak de la raw SIN firma; verificable contra el hash
        // de la FIRMADA re-ensamblando con la firma del vector:
        let sig = sig_from_raw(VEC1_RAW);
        let raw = ok(tx_eip1559_raw(&[tx.clone(), syn_bytes(sig)]));
        let raw_bytes = match &raw {
            SynValue::Bytes(b) => b[..].to_vec(),
            _ => panic!("raw debe ser bytes"),
        };
        assert_eq!(hex_encode(&raw_bytes), VEC1_RAW, "raw != vector eth-account");
        assert_eq!(hex_encode(&Keccak256::digest(&raw_bytes)), VEC1_HASH, "tx hash != vector");
        // Eco G24: los números que mueven valor están a la vista para el confirm.
        assert_eq!(get(&tx, "max_fee").to_string(), "30000000000");
        assert_eq!(get(&tx, "to").to_string(), "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0");
    }

    #[test]
    fn tx_eip1559_matches_eth_account_vector_calldata_access_list() {
        let calldata = hex_decode("a9059cbb000000000000000000000000b6716976a3ebe8d39aceb04372f22ff8e6802d7a0000000000000000000000000000000000000000000000000de0b6b3a7640000").unwrap();
        let key1 = {
            let mut k = vec![0u8; 32];
            k[31] = 1;
            k
        };
        let params = map(vec![
            ("chain_id", syn_int(43114)),
            ("nonce", syn_int(0)),
            ("to", syn_text("0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0")),
            ("value", syn_int(0)),
            ("data", syn_bytes(calldata)),
            ("gas", syn_int(60000)),
            ("max_fee", syn_int(50000000000)),
            ("max_priority", syn_int(2000000000)),
            (
                "access_list",
                syn_list(vec![map(vec![
                    ("address", syn_text("0x9858EfFD232B4033E47d90003D41EC34EcaEda94")),
                    ("storage_keys", syn_list(vec![syn_bytes(key1)])),
                ])]),
            ),
        ]);
        let tx = ok(tx_eip1559(&[params]));
        let sig = sig_from_raw(VEC2_RAW);
        let raw = ok(tx_eip1559_raw(&[tx, syn_bytes(sig)]));
        let raw_bytes = match &raw {
            SynValue::Bytes(b) => b[..].to_vec(),
            _ => panic!("raw debe ser bytes"),
        };
        assert_eq!(hex_encode(&raw_bytes), VEC2_RAW, "raw != vector eth-account");
        assert_eq!(hex_encode(&Keccak256::digest(&raw_bytes)), VEC2_HASH, "tx hash != vector");
    }

    #[test]
    fn tx_eip1559_g24_no_silent_defaults() {
        // Sin max_fee → error que nombra el helper de lectura, no un default.
        let params = map(vec![
            ("chain_id", syn_int(1)),
            ("nonce", syn_int(0)),
            ("to", syn_text("0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0")),
            ("value", syn_int(0)),
            ("gas", syn_int(21000)),
            ("max_priority", syn_int(1)),
        ]);
        let e = match tx_eip1559(&[params]) {
            Err(Control::Error(e)) => e.message,
            other => panic!("esperaba error, vino {:?}", other.is_ok()),
        };
        assert!(e.contains("max_fee") && e.contains("G24"), "error G24 dirigido: {}", e);
        // value también es explícito (0 se declara, no se asume).
        let params = map(vec![
            ("chain_id", syn_int(1)),
            ("nonce", syn_int(0)),
            ("to", syn_text("0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0")),
            ("gas", syn_int(21000)),
            ("max_fee", syn_int(2)),
            ("max_priority", syn_int(1)),
        ]);
        assert!(tx_eip1559(&[params]).is_err());
    }

    #[test]
    fn tx_eip1559_tip_over_cap_rejected() {
        let params = map(vec![
            ("chain_id", syn_int(1)),
            ("nonce", syn_int(0)),
            ("to", syn_text("0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0")),
            ("value", syn_int(0)),
            ("gas", syn_int(21000)),
            ("max_fee", syn_int(10)),
            ("max_priority", syn_int(11)),
        ]);
        let e = match tx_eip1559(&[params]) {
            Err(Control::Error(e)) => e.message,
            _ => panic!("esperaba error"),
        };
        assert!(e.contains("max_priority"), "{}", e);
    }

    #[test]
    fn tx_eip1559_raw_rejects_v27() {
        let params = map(vec![
            ("chain_id", syn_int(1)),
            ("nonce", syn_int(7)),
            ("to", syn_text("0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0")),
            ("value", syn_int(1)),
            ("gas", syn_int(21000)),
            ("max_fee", syn_int(2)),
            ("max_priority", syn_int(1)),
        ]);
        let tx = ok(tx_eip1559(&[params]));
        let mut sig = vec![1u8; 65];
        sig[64] = 27; // el clásico v legacy — acá es y-parity 0/1
        let e = match tx_eip1559_raw(&[tx, syn_bytes(sig)]) {
            Err(Control::Error(e)) => e.message,
            _ => panic!("esperaba error"),
        };
        assert!(e.contains("recovery id"), "{}", e);
    }

    // -- decode del receipt: estricto ante un nodo hostil (G23) --

    #[test]
    fn receipt_decode_typed_and_hostile() {
        let good: serde_json::Value = serde_json::from_str(
            r#"{"blockNumber":"0x10","status":"0x1","gasUsed":"0x5208",
                "from":"0x9858effd232b4033e47d90003d41ec34ecaeda94","to":null,
                "transactionHash":"0x6fb18223cd52476122a18a2b59a6c9faca40b36937217962a4f81b0da1c79880",
                "logs":[{"address":"0x6fac4d18c912343bf86fa7049364dd4e424ab9c0",
                         "topics":["0x6fb18223cd52476122a18a2b59a6c9faca40b36937217962a4f81b0da1c79880"],
                         "data":"0x0001","logIndex":"0x0"}],
                "extraStuff":"passthrough"}"#,
        )
        .unwrap();
        let r = ok(decode_receipt(&good, "t"));
        assert_eq!(get(&r, "status").to_string(), "1");
        assert_eq!(get(&r, "gasUsed").to_string(), "21000");
        assert_eq!(get(&r, "from").to_string(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert!(matches!(get(&r, "to"), SynValue::Nothing));
        let log0 = match get(&r, "logs") {
            SynValue::List(l) => l.borrow()[0].clone(),
            _ => panic!("logs"),
        };
        assert!(matches!(get(&log0, "data"), SynValue::Bytes(b) if b.len() == 2));

        // Hostil: status con ceros a la izquierda → error, no un int inventado.
        let bad: serde_json::Value =
            serde_json::from_str(r#"{"status":"0x01"}"#).unwrap();
        assert!(decode_receipt(&bad, "t").is_err());
        // Hostil: hash corto.
        let bad: serde_json::Value =
            serde_json::from_str(r#"{"transactionHash":"0xabcd"}"#).unwrap();
        assert!(decode_receipt(&bad, "t").is_err());
    }

    #[test]
    fn poll_error_classification() {
        let mk = |status: i64, ok_flag: bool, body: &str, error: Option<&str>| HttpResult {
            status,
            ok: ok_flag,
            body: body.to_string(),
            headers: Vec::new(),
            error: error.map(str::to_string),
        };
        // Transporte caído → transitorio (un blip no dice nada sobre la cadena).
        assert!(matches!(
            http_result_to_json_classified(mk(0, false, "", Some("connection refused")), "http://h", "t"),
            Err(PollError::Transient(_))
        ));
        // 5xx → transitorio; 4xx → definitivo.
        assert!(matches!(
            http_result_to_json_classified(mk(502, false, "bad gateway", None), "http://h", "t"),
            Err(PollError::Transient(_))
        ));
        assert!(matches!(
            http_result_to_json_classified(mk(404, false, "nope", None), "http://h", "t"),
            Err(PollError::Definitive(_))
        ));
        // 200 con JSON inválido → definitivo (nodo hostil, no un blip — G23).
        assert!(matches!(
            http_result_to_json_classified(mk(200, true, "not json", None), "http://h", "t"),
            Err(PollError::Definitive(_))
        ));
        // Un poll sano parsea.
        assert!(http_result_to_json_classified(mk(200, true, "{\"a\":1}", None), "http://h", "t").is_ok());
    }

    #[test]
    fn algorand_txid_charset_enforced() {
        // 52 chars válidos pasa; path traversal / chars raros no.
        let ok = "A".repeat(52);
        assert!(algorand_txid_arg(&syn_text(ok), "t").is_ok());
        for bad in ["../../../etc", "abc", &"a".repeat(52), &format!("{}/", "A".repeat(51))] {
            assert!(algorand_txid_arg(&syn_text(bad.to_string()), "t").is_err(), "{:?}", bad);
        }
    }
}

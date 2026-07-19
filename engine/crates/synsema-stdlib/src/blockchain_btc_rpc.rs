//! Read-side de Bitcoin (Batch 16, alcance D): Esplora REST (blockstream.info /
//! mempool.space / self-hosted, sin auth) como primario y el JSON-RPC de Bitcoin
//! Core (`btc_rpc`) como escape hatch. Cierra el loop autónomo:
//! `btc_utxos` → `btc_tx` → firmar (gate `sign`) → `btc_tx_raw` → `btc_send` →
//! `btc_wait` — o la variante fría con PSBT en el medio.
//!
//! Misma doctrina G22–G23 del batch 14:
//! - **Todo `net(host)`-gated** (la MISMA capability que http_*/fetch) y por lo
//!   demás puro. Nada de acá mueve valor: `btc_send` difunde bytes YA firmados.
//! - **Un nodo es input NO confiable.** Decode estricto: txids que no son 64 hex,
//!   amounts fuera de los 21M de BTC, formas ajenas → error atrapable, jamás un
//!   número inventado. Los errores nombran el HOST, no el URL completo.
//! - **Waiters acotados** con el contrato transitorio/definitivo del batch 14:
//!   transporte/5xx reintenta tras un poll exitoso; deadline durante una racha de
//!   fallas → sube el error (no `nothing`); "no confirmó" → `nothing`.
//!   Particularidad de Esplora: `GET /tx/{txid}/status` responde **404** para una
//!   tx que aún no está en el mempool — eso es "todavía no", NO un error: el
//!   waiter sigue hasta su deadline.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use indexmap::IndexMap;

use synsema_capabilities::model::CapabilitySet;
use zeroize::Zeroize;
use synsema_core::bytesutil::{b64_encode, hex_encode};
use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::number::Number;
use synsema_core::types::{syn_bool, syn_int, syn_list, syn_map, syn_number, syn_text, SynValue};

use crate::blockchain::{arg, arg_bytes, err};
use crate::blockchain_btc::{decode_address, parse_tx, txid_of, MAX_SATS};
use crate::blockchain_rpc::{
    as_obj, deadline_result, handle_poll_err, host_of, http_result_to_json_classified,
    jsonrpc_call_headers_classified, params_arg, poll_http_timeout, require_net, sleep_step,
    snippet, syn_to_plain_json, text_arg, url_arg, wait_timeout_arg, PollError,
    MAX_RPC_RESPONSE, RPC_HTTP_TIMEOUT_SECS,
};
use crate::http::{http_request, HttpResult};
use crate::server::json_to_syn;

/// Paso de polling de `btc_wait` (los bloques tardan ~10 min, pero la aparición
/// en mempool es inmediata y los tests usan mocks — 2 s equilibra ambos).
const BTC_POLL: Duration = Duration::from_millis(2000);

// =========================================================
// Transporte Esplora (REST; algunas respuestas son TEXTO plano)
// =========================================================

fn esplora_url(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// GET clasificado con body de TEXTO (Esplora devuelve texto plano en
/// `/blocks/tip/height` y en el POST de `/tx`). `not_found_is` permite mapear un
/// 404 a un valor sentinela (el "todavía no" de `btc_wait`).
fn esplora_text_classified(
    r: HttpResult,
    url: &str,
    fname: &str,
) -> Result<String, PollError> {
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
    Ok(r.body)
}

fn esplora_get_json(
    base: &str,
    path: &str,
    fname: &str,
    timeout_secs: u64,
) -> Result<serde_json::Value, Control> {
    let url = esplora_url(base, path);
    let r = http_request("GET", &url, None, None, None, timeout_secs);
    http_result_to_json_classified(r, &url, fname).map_err(PollError::into_control)
}

fn esplora_get_text(
    base: &str,
    path: &str,
    fname: &str,
    timeout_secs: u64,
) -> Result<String, Control> {
    let url = esplora_url(base, path);
    let r = http_request("GET", &url, None, None, None, timeout_secs);
    esplora_text_classified(r, &url, fname).map_err(PollError::into_control)
}

// =========================================================
// Decodificación estricta de lo que el nodo dice (G23)
// =========================================================

/// Un amount en sats del NODO: entero exacto dentro de los 21M de BTC.
fn node_sats(v: &serde_json::Value, what: &str, fname: &str) -> Result<i64, Control> {
    let n = v.as_u64().ok_or_else(|| {
        err(format!("{}: the node sent {} as a non-integer amount", fname, what))
    })?;
    let i = i64::try_from(n)
        .ok()
        .filter(|&i| i <= MAX_SATS)
        .ok_or_else(|| {
            err(format!(
                "{}: the node sent {} = {} sats — over the 21M BTC supply, not a real amount",
                fname, what, n
            ))
        })?;
    Ok(i)
}

/// Un txid del nodo / del caller: exactamente 64 hex (la forma display).
fn txid_text(s: &str, what: &str, fname: &str) -> Result<String, Control> {
    let t = s.trim();
    if t.len() != 64 || !t.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(format!(
            "{}: {} must be a 64-hex txid, got {:?}",
            fname,
            what,
            snippet(t)
        )));
    }
    Ok(t.to_lowercase())
}

/// Dirección del caller: checksum + tipo validados ANTES de tocar la red (una
/// dirección con typo no se consulta) y ANTES de interpolarla en el path.
fn address_arg(v: &SynValue, fname: &str) -> Result<String, Control> {
    let s = text_arg(v, "the address", fname)?;
    decode_address(&s, fname)?;
    Ok(s)
}

/// Altura del tip (`/blocks/tip/height` — texto plano).
fn tip_height(base: &str, fname: &str, timeout_secs: u64) -> Result<i64, Control> {
    let body = esplora_get_text(base, "/blocks/tip/height", fname, timeout_secs)?;
    let t = body.trim();
    if t.is_empty() || t.len() > 10 || !t.bytes().all(|c| c.is_ascii_digit()) {
        return Err(err(format!(
            "{}: the node sent a non-numeric tip height: {:?}",
            fname,
            snippet(t)
        )));
    }
    t.parse::<i64>()
        .map_err(|_| err(format!("{}: the node sent an unparseable tip height", fname)))
}

// =========================================================
// btc_utxos / btc_balance / btc_fee_estimates
// =========================================================

fn btc_utxos(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "btc_utxos";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "btc_utxos()")?;
    let addr = address_arg(arg(args, 1, F)?, F)?;
    let v = esplora_get_json(&url, &format!("/address/{}/utxo", addr), F, RPC_HTTP_TIMEOUT_SECS)?;
    let arr = v
        .as_array()
        .ok_or_else(|| err(format!("{}: the node did not send a UTXO list", F)))?;
    // El tip sólo se consulta si hay algún UTXO confirmado (para las confirmaciones).
    let any_confirmed = arr.iter().any(|u| {
        u.get("status")
            .and_then(|s| s.get("confirmed"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    });
    let tip = if any_confirmed { Some(tip_height(&url, F, RPC_HTTP_TIMEOUT_SECS)?) } else { None };
    let mut out = Vec::with_capacity(arr.len());
    for (i, u) in arr.iter().enumerate() {
        let what = format!("utxo[{}]", i);
        let obj = as_obj(u, &what, F)?;
        let txid = txid_text(
            obj.get("txid").and_then(serde_json::Value::as_str).ok_or_else(|| {
                err(format!("{}: {} has no txid", F, what))
            })?,
            &format!("{}.txid", what),
            F,
        )?;
        let vout = obj
            .get("vout")
            .and_then(serde_json::Value::as_u64)
            .filter(|&v| v <= u32::MAX as u64)
            .ok_or_else(|| err(format!("{}: {} has no valid vout", F, what)))?;
        let amount = node_sats(
            obj.get("value").unwrap_or(&serde_json::Value::Null),
            &format!("{}.value", what),
            F,
        )?;
        let status = obj
            .get("status")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| err(format!("{}: {} has no status", F, what)))?;
        let confirmed = status
            .get("confirmed")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| err(format!("{}: {} has no confirmed flag", F, what)))?;
        // Confirmaciones = tip − altura + 1. Un tip momentáneamente por detrás
        // (reorg entre las dos lecturas) se reporta como 1, no negativo.
        let confirmations = if confirmed {
            let h = status
                .get("block_height")
                .and_then(serde_json::Value::as_u64)
                .and_then(|h| i64::try_from(h).ok())
                .ok_or_else(|| {
                    err(format!("{}: {} is confirmed but has no block_height", F, what))
                })?;
            (tip.expect("tip leído si hay confirmados") - h + 1).max(1)
        } else {
            0
        };
        let mut m = IndexMap::new();
        m.insert("txid".to_string(), syn_text(txid));
        m.insert("vout".to_string(), syn_int(vout as i64));
        m.insert("amount".to_string(), syn_int(amount));
        m.insert("confirmations".to_string(), syn_int(confirmations));
        m.insert("confirmed".to_string(), syn_bool(confirmed));
        out.push(syn_map(m));
    }
    Ok(syn_list(out))
}

fn btc_balance(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "btc_balance";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "btc_balance()")?;
    let addr = address_arg(arg(args, 1, F)?, F)?;
    let v = esplora_get_json(&url, &format!("/address/{}", addr), F, RPC_HTTP_TIMEOUT_SECS)?;
    let obj = as_obj(&v, "the address info", F)?;
    // funded − spent por lado; el delta de mempool puede ser NEGATIVO (gastando
    // UTXOs confirmados en una tx aún sin confirmar).
    let sums = |key: &str| -> Result<(i64, i64), Control> {
        let s = obj
            .get(key)
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| err(format!("{}: the node sent no {}", F, key)))?;
        let funded = node_sats(
            s.get("funded_txo_sum").unwrap_or(&serde_json::Value::Null),
            &format!("{}.funded_txo_sum", key),
            F,
        )?;
        let spent = node_sats(
            s.get("spent_txo_sum").unwrap_or(&serde_json::Value::Null),
            &format!("{}.spent_txo_sum", key),
            F,
        )?;
        Ok((funded, spent))
    };
    let (cf, cs) = sums("chain_stats")?;
    let (mf, ms) = sums("mempool_stats")?;
    let confirmed = cf.checked_sub(cs).filter(|&c| c >= 0).ok_or_else(|| {
        err(format!("{}: the node claims more spent than funded on-chain — inconsistent data", F))
    })?;
    let mempool = mf - ms; // puede ser negativo (gasto pendiente)
    let total = confirmed + mempool;
    if total < 0 {
        return Err(err(format!(
            "{}: the node claims a negative total balance — inconsistent data",
            F
        )));
    }
    let mut m = IndexMap::new();
    m.insert("confirmed".to_string(), syn_int(confirmed));
    m.insert("mempool".to_string(), syn_int(mempool));
    m.insert("total".to_string(), syn_int(total));
    Ok(syn_map(m))
}

fn btc_fee_estimates(
    args: &[SynValue],
    caps: &Rc<RefCell<CapabilitySet>>,
) -> Result<SynValue, Control> {
    const F: &str = "btc_fee_estimates";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "btc_fee_estimates()")?;
    let v = esplora_get_json(&url, "/fee-estimates", F, RPC_HTTP_TIMEOUT_SECS)?;
    let obj = as_obj(&v, "the fee estimates", F)?;
    // Números CRUDOS objetivo-de-bloques → sat/vB (derivación transparente, no
    // un oráculo — patrón eth_fee_history). Orden numérico ascendente estable.
    let mut entries: Vec<(u64, f64)> = Vec::with_capacity(obj.len());
    for (k, val) in obj {
        let target: u64 = k.parse().map_err(|_| {
            err(format!("{}: the node sent a non-numeric block target {:?}", F, snippet(k)))
        })?;
        let rate = val.as_f64().filter(|r| r.is_finite() && *r > 0.0).ok_or_else(|| {
            err(format!("{}: the node sent an invalid fee rate for target {}", F, target))
        })?;
        entries.push((target, rate));
    }
    entries.sort_by_key(|(t, _)| *t);
    let mut m = IndexMap::new();
    for (t, r) in entries {
        m.insert(t.to_string(), syn_number(Number::Float(r)));
    }
    Ok(syn_map(m))
}

// =========================================================
// btc_send / btc_wait
// =========================================================

fn btc_send(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "btc_send";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "btc_send()")?;
    let raw = arg_bytes(arg(args, 1, F)?, F, "the signed transaction")?;
    // Parsear ANTES de difundir: valida la forma y da el txid local esperado.
    let local_txid = txid_of(&parse_tx(raw, F)?);
    let full = esplora_url(&url, "/tx");
    let headers = vec![("Content-Type".to_string(), "text/plain".to_string())];
    let hex_body = hex_encode(raw);
    let r = http_request("POST", &full, Some(&headers), None, Some(&hex_body), RPC_HTTP_TIMEOUT_SECS);
    let body = esplora_text_classified(r, &full, F).map_err(PollError::into_control)?;
    let txid = txid_text(&body, "the returned txid", F)?;
    // El nodo debe devolver EL MISMO txid que estos bytes hashean (G23): otro
    // txid = un nodo mintiendo o un proxy corrompiendo — jamás se reporta.
    if txid != local_txid {
        return Err(err(format!(
            "{}: {} returned txid {} but the broadcast bytes hash to {} — refusing to trust the node's answer",
            F,
            host_of(&url),
            txid,
            local_txid
        )));
    }
    Ok(syn_text(txid))
}

fn btc_wait(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "btc_wait";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "btc_wait()")?;
    let txid = txid_text(&text_arg(arg(args, 1, F)?, "the txid", F)?, "the txid", F)?;
    let confirmations: i64 = match args.get(2) {
        None | Some(SynValue::Nothing) => 1,
        Some(SynValue::Number(n)) => match n.to_i64_trunc() {
            Some(c @ 1..=1000) if n.is_integer() => c,
            _ => return Err(err(format!("{}: confirmations must be an integer 1..=1000", F))),
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
    let path = format!("/tx/{}/status", txid);
    let mut polled_ok = false;
    let mut warned = false;
    let mut last_transient: Option<Control> = None;
    loop {
        let full = esplora_url(&url, &path);
        let r = http_request("GET", &full, None, None, None, poll_http_timeout(deadline));
        // 404 = la tx aún no está en el mempool del nodo — "todavía no", se
        // sigue esperando (el equivalente al receipt null de EVM).
        let not_found = r.error.is_none() && r.status == 404;
        if not_found {
            polled_ok = true;
            last_transient = None;
            if !sleep_step(deadline, BTC_POLL) {
                return Ok(SynValue::Nothing);
            }
            continue;
        }
        let v = match http_result_to_json_classified(r, &full, F) {
            Ok(v) => {
                polled_ok = true;
                last_transient = None;
                v
            }
            Err(e) => {
                handle_poll_err(e, polled_ok, &mut warned, &mut last_transient, F)?;
                if !sleep_step(deadline, BTC_POLL) {
                    return deadline_result(last_transient);
                }
                continue;
            }
        };
        let obj = as_obj(&v, "the tx status", F)?;
        let confirmed = obj
            .get("confirmed")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| err(format!("{}: the tx status has no confirmed flag", F)))?;
        if confirmed {
            let height = obj
                .get("block_height")
                .and_then(serde_json::Value::as_u64)
                .and_then(|h| i64::try_from(h).ok())
                .ok_or_else(|| {
                    err(format!("{}: the tx is confirmed but the node sent no block_height", F))
                })?;
            let confs = if confirmations <= 1 {
                1
            } else {
                match tip_height(&url, F, poll_http_timeout(deadline)) {
                    Ok(tip) => (tip - height + 1).max(1),
                    Err(c) => {
                        handle_poll_err(
                            PollError::Transient(c),
                            polled_ok,
                            &mut warned,
                            &mut last_transient,
                            F,
                        )?;
                        if !sleep_step(deadline, BTC_POLL) {
                            return deadline_result(last_transient);
                        }
                        continue;
                    }
                }
            };
            if confs >= confirmations {
                let mut m = IndexMap::new();
                m.insert("confirmed".to_string(), syn_bool(true));
                m.insert("block_height".to_string(), syn_int(height));
                if let Some(bh) = obj.get("block_hash").and_then(serde_json::Value::as_str) {
                    m.insert("block_hash".to_string(), syn_text(bh));
                }
                if let Some(bt) = obj.get("block_time").and_then(serde_json::Value::as_u64) {
                    m.insert("block_time".to_string(), syn_int(bt as i64));
                }
                m.insert("confirmations".to_string(), syn_int(confs));
                return Ok(syn_map(m));
            }
        }
        if !sleep_step(deadline, BTC_POLL) {
            return Ok(SynValue::Nothing);
        }
    }
}

// =========================================================
// btc_rpc — escape hatch: JSON-RPC de Bitcoin Core (regtest / nodos propios)
// =========================================================

/// `auth` = `{user, pass}`; `pass` puede ser un `secret` — se materializa SOLO
/// acá, en el borde del socket, como Basic auth (patrón headers de algod).
fn basic_auth_header(v: Option<&SynValue>, fname: &str) -> Result<Vec<(String, String)>, Control> {
    let m = match v {
        None | Some(SynValue::Nothing) => return Ok(Vec::new()),
        Some(SynValue::Map(m)) => m.borrow().clone(),
        Some(other) => {
            return Err(err(format!(
                "{}: auth must be a map {{user, pass}}, got {}",
                fname,
                other.type_name()
            )))
        }
    };
    for k in m.keys() {
        if !matches!(k.as_str(), "user" | "pass") {
            return Err(err(format!(
                "{}: unknown auth key {:?} (allowed: user, pass)",
                fname, k
            )));
        }
    }
    let user = match m.get("user") {
        Some(SynValue::Text(s)) => s.to_string(),
        _ => return Err(err(format!("{}: auth needs a text \"user\"", fname))),
    };
    let pass = match m.get("pass") {
        Some(SynValue::Secret(inner)) => inner.expose().into_owned(),
        Some(SynValue::Text(s)) => s.to_string(),
        _ => {
            return Err(err(format!(
                "{}: auth needs \"pass\" (ideally a secret — it only materializes at the socket edge)",
                fname
            )))
        }
    };
    let mut token = format!("{}:{}", user, pass);
    let header = format!("Basic {}", b64_encode(token.as_bytes()));
    // Best-effort: borrar la copia con el pass en claro (misma higiene que secret).
    token.zeroize();
    Ok(vec![("Authorization".to_string(), header)])
}

fn btc_rpc(args: &[SynValue], caps: &Rc<RefCell<CapabilitySet>>) -> Result<SynValue, Control> {
    const F: &str = "btc_rpc";
    let url = url_arg(arg(args, 0, F)?, F)?;
    require_net(caps, &url, "btc_rpc()")?;
    let method = text_arg(arg(args, 1, F)?, "the method", F)?;
    let params = params_arg(args.get(2), F, syn_to_plain_json)?;
    let headers = basic_auth_header(args.get(3), F)?;
    let result =
        jsonrpc_call_headers_classified(&url, &method, params, F, RPC_HTTP_TIMEOUT_SECS, &headers)
            .map_err(PollError::into_control)?;
    Ok(json_to_syn(&result))
}

// =========================================================
// Registro
// =========================================================

/// Registra el read-side de Bitcoin — TODO `net(host)`-gated (G22/G30; sandbox
/// lo vacía, deny-by-default). Wired desde `register_blockchain_builtins`.
pub(crate) fn register(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    macro_rules! net_builtin {
        ($name:literal, $arity:expr, $f:ident) => {{
            let caps = caps.clone();
            interp.register_builtin($name, $arity, Rc::new(move |_i, a, _l| $f(a, &caps)));
        }};
    }
    net_builtin!("btc_utxos", 2, btc_utxos);
    net_builtin!("btc_balance", 2, btc_balance);
    net_builtin!("btc_fee_estimates", 1, btc_fee_estimates);
    net_builtin!("btc_send", 2, btc_send);
    net_builtin!("btc_wait", -1, btc_wait);
    net_builtin!("btc_rpc", -1, btc_rpc);
}

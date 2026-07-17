//! Solana transaccionable (Batch 12, alcance B): serialización del message
//! (legacy y v0) + ensamblado wire-format. TODO PURO (G13): el message que sale
//! de acá se firma con `ed25519_sign(msg_bytes, key)` — ed25519 firma el mensaje
//! CRUDO, que ya es la semántica del batch 11 — y se difunde por JSON-RPC con
//! `http_post` en userland (`decode(tx, "base64")` → `sendTransaction`).
//!
//! - **Ordenamiento de cuentas:** las reglas del SDK oficial de Solana (la
//!   referencia Rust que solders envuelve): fee payer PRIMERO, después cada
//!   bucket — signers escribibles, signers readonly, no-signers escribibles,
//!   no-signers readonly — ordenado por los bytes de la pubkey (así los vectores
//!   pineados de la SDK reproducen byte a byte).
//! - **shortvec MÍNIMO (G15):** el compact-u16 se emite en su forma más corta.
//! - **v0:** `{"version": 0}` emite el prefijo 0x80 (la firma LO CUBRE — así lo
//!   serializa `VersionedMessage`) y el shortvec vacío de address-table-lookups.
//!   Pasar `lookup_tables` es un error claro: etapa 3, no silencio.

use std::rc::Rc;

use synsema_core::bytesutil::base58_decode;
use synsema_core::interpreter::{Control, Interpreter};
use synsema_core::types::{syn_bytes, SynValue};

use crate::blockchain::{arg, arg_bytes, err};

// =========================================================
// Helpers
// =========================================================

/// Pubkey de 32 bytes desde bytes(32) o text base58.
fn pubkey32(v: &SynValue, what: &str, fname: &str) -> Result<[u8; 32], Control> {
    let raw: Vec<u8> = match v {
        SynValue::Bytes(b) => b[..].to_vec(),
        SynValue::Text(s) => base58_decode(s)
            .map_err(|e| err(format!("{}: {} is not valid base58: {}", fname, what, e)))?,
        SynValue::Secret(_) => {
            return Err(err(format!(
                "{}: {} must be a PUBLIC key (bytes or base58 text) — derive it with ed25519_pubkey(secret), never pass the secret itself",
                fname, what
            )))
        }
        other => {
            return Err(err(format!(
                "{}: {} must be a 32-byte pubkey (bytes or base58 text), got {}",
                fname,
                what,
                other.type_name()
            )))
        }
    };
    raw.try_into().map_err(|v: Vec<u8>| {
        err(format!(
            "{}: {} must decode to exactly 32 bytes, got {}",
            fname,
            what,
            v.len()
        ))
    })
}

/// compact-u16 de Solana (shortvec), emisión MÍNIMA: 7 bits por byte, LSB
/// primero, bit alto = continúa. Máximo 3 bytes (u16).
fn shortvec(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
}

struct ParsedInstruction {
    program: [u8; 32],
    accounts: Vec<([u8; 32], bool, bool)>, // (pubkey, signer, writable)
    data: Vec<u8>,
}

fn get_map(v: &SynValue, what: &str, fname: &str) -> Result<indexmap::IndexMap<String, SynValue>, Control> {
    match v {
        SynValue::Map(m) => Ok(m.borrow().clone()),
        other => Err(err(format!(
            "{}: {} must be a map, got {}",
            fname,
            what,
            other.type_name()
        ))),
    }
}

fn get_bool(m: &indexmap::IndexMap<String, SynValue>, key: &str, what: &str, fname: &str) -> Result<bool, Control> {
    match m.get(key) {
        None | Some(SynValue::Nothing) => Ok(false),
        Some(SynValue::Bool(b)) => Ok(*b),
        Some(other) => Err(err(format!(
            "{}: {}.{} must be true or false, got {}",
            fname,
            what,
            key,
            other.type_name()
        ))),
    }
}

// =========================================================
// solana_message
// =========================================================

fn solana_message(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "solana_message";
    let params = get_map(arg(args, 0, F)?, "params", F)?;

    // Claves conocidas; un typo es error, no silencio.
    for k in params.keys() {
        match k.as_str() {
            "fee_payer" | "recent_blockhash" | "instructions" | "version" => {}
            "lookup_tables" => {
                return Err(err(format!(
                    "{}: address lookup tables are not supported yet — remove \"lookup_tables\"; a v0 message without tables works today",
                    F
                )))
            }
            other => {
                return Err(err(format!(
                    "{}: unknown key {:?} in params (allowed: fee_payer, recent_blockhash, instructions, version)",
                    F, other
                )))
            }
        }
    }

    let v0 = match params.get("version") {
        None | Some(SynValue::Nothing) => false,
        Some(SynValue::Number(n)) if n.to_i64_trunc() == Some(0) && n.is_integer() => true,
        Some(other) => {
            return Err(err(format!(
                "{}: version must be 0 (v0) or absent (legacy), got {}",
                F,
                other
            )))
        }
    };

    let fee_payer = pubkey32(
        params.get("fee_payer").ok_or_else(|| err(format!("{}: missing \"fee_payer\"", F)))?,
        "fee_payer",
        F,
    )?;
    let blockhash = match params.get("recent_blockhash") {
        Some(v) => pubkey32(v, "recent_blockhash", F)?,
        None => return Err(err(format!("{}: missing \"recent_blockhash\"", F))),
    };
    let instr_list = match params.get("instructions") {
        Some(SynValue::List(l)) => l.borrow().clone(),
        Some(other) => {
            return Err(err(format!(
                "{}: instructions must be a list, got {}",
                F,
                other.type_name()
            )))
        }
        None => return Err(err(format!("{}: missing \"instructions\"", F))),
    };
    if instr_list.is_empty() {
        return Err(err(format!("{}: instructions cannot be empty", F)));
    }

    let mut instructions = Vec::with_capacity(instr_list.len());
    for (i, iv) in instr_list.iter().enumerate() {
        let what = format!("instruction {}", i + 1);
        let im = get_map(iv, &what, F)?;
        for k in im.keys() {
            if !matches!(k.as_str(), "program" | "accounts" | "data") {
                return Err(err(format!(
                    "{}: unknown key {:?} in {} (allowed: program, accounts, data)",
                    F, k, what
                )));
            }
        }
        let program = pubkey32(
            im.get("program")
                .ok_or_else(|| err(format!("{}: {} is missing \"program\"", F, what)))?,
            &format!("{}.program", what),
            F,
        )?;
        let mut accounts = Vec::new();
        if let Some(av) = im.get("accounts") {
            let alist = match av {
                SynValue::List(l) => l.borrow().clone(),
                other => {
                    return Err(err(format!(
                        "{}: {}.accounts must be a list, got {}",
                        F,
                        what,
                        other.type_name()
                    )))
                }
            };
            for (j, am) in alist.iter().enumerate() {
                let awhat = format!("{}.accounts[{}]", what, j);
                let a = get_map(am, &awhat, F)?;
                for k in a.keys() {
                    if !matches!(k.as_str(), "pubkey" | "signer" | "writable") {
                        return Err(err(format!(
                            "{}: unknown key {:?} in {} (allowed: pubkey, signer, writable)",
                            F, k, awhat
                        )));
                    }
                }
                let pk = pubkey32(
                    a.get("pubkey")
                        .ok_or_else(|| err(format!("{}: {} is missing \"pubkey\"", F, awhat)))?,
                    &format!("{}.pubkey", awhat),
                    F,
                )?;
                let signer = get_bool(&a, "signer", &awhat, F)?;
                let writable = get_bool(&a, "writable", &awhat, F)?;
                accounts.push((pk, signer, writable));
            }
        }
        let data: Vec<u8> = match im.get("data") {
            None | Some(SynValue::Nothing) => Vec::new(),
            Some(v) => arg_bytes(v, F, &format!("{}.data", what))?.to_vec(),
        };
        instructions.push(ParsedInstruction { program, accounts, data });
    }

    // -- Compilar el set de cuentas: OR de flags por pubkey; el fee payer va
    //    forzado (signer, writable) y SIEMPRE primero.
    let mut metas: indexmap::IndexMap<[u8; 32], (bool, bool)> = indexmap::IndexMap::new();
    metas.insert(fee_payer, (true, true));
    for ins in &instructions {
        for (pk, s, w) in &ins.accounts {
            let e = metas.entry(*pk).or_insert((false, false));
            e.0 |= *s;
            e.1 |= *w;
        }
        metas.entry(ins.program).or_insert((false, false));
    }
    // El fee payer conserva (true,true) aunque una instrucción lo liste readonly.
    metas.insert(fee_payer, (true, true));

    // Buckets (sin el payer), ordenados por los bytes de la pubkey — la regla
    // del SDK de Solana (BTreeMap), que los vectores pineados reproducen.
    let mut ws: Vec<[u8; 32]> = Vec::new(); // writable signers
    let mut rs: Vec<[u8; 32]> = Vec::new(); // readonly signers
    let mut wn: Vec<[u8; 32]> = Vec::new(); // writable non-signers
    let mut rn: Vec<[u8; 32]> = Vec::new(); // readonly non-signers
    for (pk, (s, w)) in &metas {
        if *pk == fee_payer {
            continue;
        }
        match (s, w) {
            (true, true) => ws.push(*pk),
            (true, false) => rs.push(*pk),
            (false, true) => wn.push(*pk),
            (false, false) => rn.push(*pk),
        }
    }
    for b in [&mut ws, &mut rs, &mut wn, &mut rn] {
        b.sort_unstable();
    }
    let num_required = 1 + ws.len() + rs.len();
    let num_ro_signed = rs.len();
    let num_ro_unsigned = rn.len();
    // El header usa u8 y el bit alto del primer byte distingue legacy de v0:
    // más de 127 firmantes no es serializable (ni entra en un packet real).
    if num_required > 127 {
        return Err(err(format!(
            "{}: {} required signers do not fit in a Solana message (max 127)",
            F, num_required
        )));
    }

    let mut keys: Vec<[u8; 32]> = Vec::with_capacity(metas.len());
    keys.push(fee_payer);
    keys.extend(ws);
    keys.extend(rs);
    keys.extend(wn);
    keys.extend(rn);
    if keys.len() > 256 {
        return Err(err(format!(
            "{}: too many distinct accounts ({}, the message format caps indices at 256)",
            F,
            keys.len()
        )));
    }
    let index_of = |pk: &[u8; 32]| -> u8 {
        keys.iter().position(|k| k == pk).expect("compilado arriba") as u8
    };

    // -- Serializar --
    let mut out: Vec<u8> = Vec::new();
    if v0 {
        out.push(0x80); // prefijo de versión (v0) — la firma cubre este byte
    }
    out.push(num_required as u8);
    out.push(num_ro_signed as u8);
    out.push(num_ro_unsigned as u8);
    shortvec(keys.len(), &mut out);
    for k in &keys {
        out.extend_from_slice(k);
    }
    out.extend_from_slice(&blockhash);
    shortvec(instructions.len(), &mut out);
    for ins in &instructions {
        out.push(index_of(&ins.program));
        shortvec(ins.accounts.len(), &mut out);
        for (pk, _, _) in &ins.accounts {
            out.push(index_of(pk));
        }
        shortvec(ins.data.len(), &mut out);
        out.extend_from_slice(&ins.data);
    }
    if v0 {
        shortvec(0, &mut out); // address-table-lookups: vacío en esta etapa
    }
    Ok(syn_bytes(out))
}

// =========================================================
// solana_tx — wire format listo para sendTransaction
// =========================================================

fn solana_tx(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "solana_tx";
    let msg = arg_bytes(arg(args, 0, F)?, F, "the message")?;
    if msg.len() < 4 {
        return Err(err(format!("{}: the message is too short to be a Solana message", F)));
    }
    // Cuántas firmas exige el message: header[0] (legacy) o header tras el
    // prefijo de versión (v0). Un legacy jamás empieza con bit alto (128+
    // firmantes no entran en una tx).
    let required = if msg[0] & 0x80 != 0 {
        if msg[0] & 0x7f != 0 {
            return Err(err(format!(
                "{}: unsupported message version {} (only v0 and legacy exist)",
                F,
                msg[0] & 0x7f
            )));
        }
        msg[1] as usize
    } else {
        msg[0] as usize
    };
    let sigs: Vec<Vec<u8>> = match arg(args, 1, F)? {
        SynValue::Bytes(b) => vec![b[..].to_vec()],
        SynValue::List(l) => {
            let items = l.borrow().clone();
            let mut out = Vec::with_capacity(items.len());
            for (i, s) in items.iter().enumerate() {
                out.push(
                    arg_bytes(s, F, &format!("signature {}", i + 1))?.to_vec(),
                );
            }
            out
        }
        other => {
            return Err(err(format!(
                "{}: signatures must be 64-byte bytes or a list of them, got {}",
                F,
                other.type_name()
            )))
        }
    };
    for (i, s) in sigs.iter().enumerate() {
        if s.len() != 64 {
            return Err(err(format!(
                "{}: signature {} must be exactly 64 bytes, got {}",
                F,
                i + 1,
                s.len()
            )));
        }
    }
    if sigs.len() != required {
        return Err(err(format!(
            "{}: the message requires {} signature(s), got {}",
            F, required, sigs.len()
        )));
    }
    let mut out: Vec<u8> = Vec::new();
    shortvec(sigs.len(), &mut out);
    for s in &sigs {
        out.extend_from_slice(s);
    }
    out.extend_from_slice(msg);
    Ok(syn_bytes(out))
}

// =========================================================
// Registro (todos PUROS — G13)
// =========================================================

pub(crate) fn register(interp: &Interpreter) {
    interp.register_builtin("solana_message", 1, Rc::new(|_i, a, _l| solana_message(a)));
    interp.register_builtin("solana_tx", 2, Rc::new(|_i, a, _l| solana_tx(a)));
}

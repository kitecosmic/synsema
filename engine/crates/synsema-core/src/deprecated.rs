//! Nombres que cambiaron antes de v1.0 (v0.6.29, specs/lenguaje/v1-compatibilidad.md).
//!
//! Cada fila es `(viejo, nuevo)`. El viejo SIGUE funcionando hasta el corte de v1.0 —como
//! alias del nuevo, o con su comportamiento de siempre cuando el nuevo cambió la forma del
//! resultado (`capture` → `regex_capture`)—, pero `synsema check` lo avisa y la primera
//! carga de un programa que lo usa lo dice una vez por stderr. En v1.0 el viejo se va.

use std::collections::HashSet;
use std::sync::Mutex;

use crate::ast::{NodeKind, Program};

pub const DEPRECATED_NAMES: &[(&str, &str)] = &[
    // Texto y regex (V1-D1, V1-D2): una familia `regex_*`, `replace` para texto plano, y el
    // plegado de mayúsculas + acentos con un nombre que dice lo que hace.
    ("replace_text", "replace"),
    ("find_all", "regex_find_all"),
    ("capture", "regex_capture"),
    ("replace_re", "regex_replace"),
    ("fold", "fold_text"),
    // Criptografía (V1-D3): la MAC es bytes como cualquier hash (`hex(hmac(d, k))` para verla).
    ("hmac_sha256", "hmac"),
    // Álgebra (DATOS-10): un nombre por concepto.
    ("eye", "identity"),
    // Blockchain (V1-BC1): `<familia>_<acción>`; EVM es la familia, no Ethereum.
    ("eth_rpc", "evm_rpc"),
    ("eth_nonce", "evm_nonce"),
    ("eth_balance", "evm_balance"),
    ("eth_gas_price", "evm_gas_price"),
    ("eth_chain_id", "evm_chain_id"),
    ("eth_estimate_gas", "evm_estimate_gas"),
    ("eth_call", "evm_call"),
    ("eth_fee_history", "evm_fee_history"),
    ("eth_send_raw", "evm_send"),
    ("eth_receipt", "evm_receipt"),
    ("eth_wait_receipt", "evm_wait"),
    ("eth_address", "evm_address"),
    ("tx_eip1559", "evm_tx"),
    ("tx_eip1559_raw", "evm_tx_raw"),
    ("algo_address", "algorand_address"),
    ("algorand_tx_encode", "algorand_tx"),
    ("solana_message", "solana_tx"),
    ("solana_confirm", "solana_wait"),
];

/// El nombre nuevo de `old`, si está deprecado.
pub fn replacement(old: &str) -> Option<&'static str> {
    DEPRECATED_NAMES.iter().find(|(o, _)| *o == old).map(|(_, n)| *n)
}

/// Nombres deprecados que el programa LLAMA (o referencia como valor), en orden de aparición
/// y sin repetir, con la línea de la primera vez.
pub fn used_in(program: &Program) -> Vec<(String, &'static str, usize)> {
    let mut out: Vec<(String, &'static str, usize)> = Vec::new();
    let mut seen = HashSet::new();
    let mut declared = HashSet::new();
    // Un task o variable del programa con ese nombre lo sombrea: no es el builtin.
    for st in &program.statements {
        crate::ast_api::walk(st, &mut |n| match &n.kind {
            NodeKind::TaskDefinition { name, .. } | NodeKind::LetBinding { name, .. } => {
                declared.insert(name.clone());
            }
            _ => {}
        });
    }
    for st in &program.statements {
        crate::ast_api::walk(st, &mut |n| {
            if let NodeKind::Identifier { name } = &n.kind {
                if let Some(new) = replacement(name) {
                    if !declared.contains(name) && seen.insert(name.clone()) {
                        out.push((name.clone(), new, n.location.line));
                    }
                }
            }
        });
    }
    out
}

/// Builtins que CAMBIARON de comportamiento en v0.6.29 sin cambiar de nombre: `synsema check`
/// lo dice una vez por nombre usado (hasta v1.0), con lo que hay que revisar.
pub const CHANGED_IN_0629: &[(&str, &str)] = &[
    ("std", "`std` is now the SAMPLE standard deviation (ddof = 1, like pandas); the population one is std(xs, ddof = 0)"),
    ("var", "`var` is now the SAMPLE variance (ddof = 1, like pandas); the population one is var(xs, ddof = 0)"),
    ("group_by", "`group_by` now returns [{key, items}] in first-appearance order with the key's own type (it was a map keyed by text)"),
    ("dot", "`dot` is now the inner product of two vectors only; for matrices use matmul(a, b)"),
];

/// Avisos de `synsema check`.
pub fn check_warnings(program: &Program, file_path: &str, warnings: &mut Vec<String>) {
    for (old, new, line) in used_in(program) {
        warnings.push(format!(
            "warning: {}:{}: `{}` is deprecated — use `{}` (the old name goes away in v1.0)",
            file_path, line, old, new
        ));
    }
    let mut seen = HashSet::new();
    for st in &program.statements {
        crate::ast_api::walk(st, &mut |n| {
            if let NodeKind::TaskCall { name, arguments } = &n.kind {
                let Some(id) = name.as_identifier() else { return };
                if let Some((_, note)) = CHANGED_IN_0629.iter().find(|(c, _)| *c == id) {
                    if seen.insert(id.to_string()) {
                        warnings.push(format!("warning: {}:{}: changed in v0.6.29: {}", file_path, n.location.line, note));
                    }
                }
                // `percentile(x, 0.5)`: el nivel va de 0 a 100; un literal en (0, 1) casi seguro
                // quería `quantile`.
                if id == "percentile" {
                    if let Some(a) = arguments.get(1) {
                        if let NodeKind::NumberLiteral { value } = &a.value.kind {
                            let p = value.to_f64();
                            if p > 0.0 && p < 1.0 {
                                warnings.push(format!(
                                    "warning: {}:{}: percentile takes p from 0 to 100 — percentile(x, {}) is the {}th percentile; for a fraction use quantile(x, {})",
                                    file_path, n.location.line, value, value, value
                                ));
                            }
                        }
                    }
                }
            }
        });
    }
}

/// Aviso en tiempo de carga: una vez por nombre y por proceso (un `serve` con N workers
/// no lo repite N veces).
pub fn warn_once_at_load(program: &Program, file_path: &str) {
    static SEEN: Mutex<Option<HashSet<String>>> = Mutex::new(None);
    let used = used_in(program);
    if used.is_empty() {
        return;
    }
    let mut guard = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    let seen = guard.get_or_insert_with(HashSet::new);
    for (old, new, line) in used {
        if seen.insert(old.clone()) {
            eprintln!(
                "warning: {}:{}: `{}` is deprecated — use `{}` (the old name goes away in v1.0)",
                file_path, line, old, new
            );
        }
    }
}

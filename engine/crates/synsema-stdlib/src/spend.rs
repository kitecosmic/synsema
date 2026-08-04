//! `spend` + techos de gasto y de firmas (FRAMEWORK F1 / F-B + F-C).
//!
//! `spend(monto, unidad, motivo)` es la declaración AUDITADA de un gasto externo: no
//! mueve valor por sí misma (eso lo hace la llamada al PSP/exchange del programa),
//! pero deja el rastro forense ANTES de moverlo y aplica el techo del host.
//!
//! Doctrina (espejo de `sign`/`reveal`):
//! - **Deny-by-default SIEMPRE** (`require spend("USD")`): jamás auto-granted, ni en
//!   modo no-secure. `sandbox` la deniega (caps vaciadas) y `call_tool` la intersecta
//!   (una tool que no declara `spend` no puede gastar aunque el programa pueda).
//! - **Audit fail-loud** en `spend.log`: sin entrada escrita NO hay gasto aprobado.
//!   Las denegaciones también se auditan (best-effort — el gasto ya no ocurre).
//! - **Techo del host**: `SYNSEMA_SPEND_CEILING="USD:500,ETH:0.1"` (environ > `.env`).
//!   El breach es **error duro catchable** (`try`/`recover`) — asimetría deliberada
//!   con el budget LLM (que degrada): `spend` guarda una acción externa irreversible y
//!   el caller NO debe seguir a la llamada del PSP.
//! - **Montos por el camino Decimal** (`synsema-core/src/number.rs`): acumulador
//!   exacto base-10, sin error binario en centavos. En el ledger el monto va como
//!   TEXTO canónico.
//! - **Acumulador monotónico POR PROCESO** (`spend_total(unidad)`, introspección sin
//!   gate). Ventanas de tiempo = política del framework leyendo `spend.log`.
//!
//! F-C (techo de CANTIDAD de firmas) vive acá también: comparte la gramática
//! `name:amount` (`SYNSEMA_SIGN_CEILING="HOT_KEY:100"`) y el patrón de contador por
//! proceso; `blockchain::gate_and_audit` llama a [`sign_ceiling_reserve`].

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Mutex, OnceLock};

use rust_decimal::Decimal;

use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::Number;
use synsema_core::tokens::SourceLocation;
use synsema_core::types::{syn_number, SynValue};

use crate::secrets::{write_sign_ceiling_audit, write_spend_audit, EnvStore};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

// =========================================================
// Configuración de techos (gramática compartida `name:amount`)
// =========================================================

/// Vars de techo del host que este módulo reconoce. Lista CANÓNICA (espejo de
/// `LLM_ENV_VARS`/`HUMAN_ENV_VARS` en el runtime): el test anti-rot del CLI
/// (`env_example_in_sync_with_engine_knobs`) la cruza con el `.env.example` de
/// `init` — sumar un techo acá sin tocar el template rompe el build a propósito.
pub const CEILING_ENV_VARS: &[&str] = &["SYNSEMA_SPEND_CEILING", "SYNSEMA_SIGN_CEILING"];

/// Resuelve una variable de techo con la MISMA precedencia que el resto de la config
/// (`resolve_knob`): environ del proceso > `.env` (EnvStore). Vacío = ausente.
fn resolve_ceiling_var(name: &str) -> Option<String> {
    if let Ok(v) = std::env::var(name) {
        if !v.trim().is_empty() {
            return Some(v);
        }
    }
    EnvStore::load_default().get(name).filter(|v| !v.trim().is_empty())
}

/// Gramática compartida de techos: `name:amount` separados por comas, whitespace
/// tolerado. Nombres/unidades = strings arbitrarios (el `:` separador es el ÚLTIMO
/// de la entrada, así un name con `:` raro no rompe el amount). Una entrada inválida
/// se DESCARTA con warn — nunca en silencio: un techo mal escrito e ignorado sin aviso
/// sería un agujero de seguridad invisible.
fn parse_ceiling_pairs(var: &str, raw: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        match entry.rsplit_once(':') {
            Some((name, amount)) if !name.trim().is_empty() && !amount.trim().is_empty() => {
                out.push((name.trim().to_string(), amount.trim().to_string()));
            }
            _ => {
                eprintln!(
                    "synsema: warning: ignoring malformed {} entry '{}' — expected name:amount \
                     (e.g. USD:500), entries separated by commas",
                    var, entry
                );
            }
        }
    }
    out
}

/// `SYNSEMA_SPEND_CEILING` parseado a `unidad → techo Decimal`. Cacheado por proceso
/// (OnceLock): el techo es config del HOST, no cambia en caliente.
fn spend_ceilings() -> &'static HashMap<String, Decimal> {
    static CEILINGS: OnceLock<HashMap<String, Decimal>> = OnceLock::new();
    CEILINGS.get_or_init(|| {
        let mut map = HashMap::new();
        if let Some(raw) = resolve_ceiling_var("SYNSEMA_SPEND_CEILING") {
            for (unit, amount) in parse_ceiling_pairs("SYNSEMA_SPEND_CEILING", &raw) {
                match Decimal::from_str_exact(&amount) {
                    Ok(d) if d > Decimal::ZERO => {
                        map.insert(unit, d);
                    }
                    _ => eprintln!(
                        "synsema: warning: ignoring SYNSEMA_SPEND_CEILING entry '{}:{}' — the \
                         amount must be a positive decimal number",
                        unit, amount
                    ),
                }
            }
        }
        map
    })
}

/// `SYNSEMA_SIGN_CEILING` parseado a `name de clave → máximo de firmas u64`.
fn sign_ceilings() -> &'static HashMap<String, u64> {
    static CEILINGS: OnceLock<HashMap<String, u64>> = OnceLock::new();
    CEILINGS.get_or_init(|| {
        let mut map = HashMap::new();
        if let Some(raw) = resolve_ceiling_var("SYNSEMA_SIGN_CEILING") {
            for (name, amount) in parse_ceiling_pairs("SYNSEMA_SIGN_CEILING", &raw) {
                match amount.parse::<u64>() {
                    Ok(n) if n > 0 => {
                        map.insert(name, n);
                    }
                    _ => eprintln!(
                        "synsema: warning: ignoring SYNSEMA_SIGN_CEILING entry '{}:{}' — the \
                         count must be a positive integer",
                        name, amount
                    ),
                }
            }
        }
        map
    })
}

// =========================================================
// Acumuladores por proceso
// =========================================================

/// Total gastado por unidad en ESTE proceso (Decimal exacto). Mutex (no thread-local):
/// bajo `serve` los workers comparten el mismo techo del host.
fn spend_totals() -> &'static Mutex<HashMap<String, Decimal>> {
    static TOTALS: OnceLock<Mutex<HashMap<String, Decimal>>> = OnceLock::new();
    TOTALS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Firmas realizadas por name de clave en ESTE proceso (F-C).
fn sign_counts() -> &'static Mutex<HashMap<String, u64>> {
    static COUNTS: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    COUNTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_unpoisoned<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// =========================================================
// F-C — techo de cantidad de firmas (lo llama blockchain::gate_and_audit)
// =========================================================

/// Chequea el techo de firmas para `name` y, si hay cupo, lo RESERVA bajo el mismo
/// lock (sin TOCTOU entre handlers concurrentes de `serve`). Sin config para esa
/// clave → no-op byte-idéntico al comportamiento previo.
///
/// Denegado → audit `denied_by=ceiling` en `sign.log` (best-effort: la firma ya no va
/// a ocurrir) + error CATCHABLE (`try`/`recover`).
///
/// La reserva ocurre ANTES del audit concedido de la firma (que escribe el caller):
/// si ese audit luego falla, la firma no ocurre y el cupo queda consumido — dirección
/// fail-closed (nunca más firmas que el techo; jamás al revés).
pub fn sign_ceiling_reserve(
    name: &str,
    curve: &str,
    loc: &SourceLocation,
) -> Result<(), Control> {
    let Some(&ceiling) = sign_ceilings().get(name) else {
        return Ok(());
    };
    let mut counts = lock_unpoisoned(sign_counts());
    let used = counts.get(name).copied().unwrap_or(0);
    if used + 1 > ceiling {
        drop(counts);
        let _ = write_sign_ceiling_audit(name, curve, loc);
        return Err(err(format!(
            "sign ceiling exceeded for \"{}\": {} of {} signatures already used in this \
             process — the ceiling is set by the host via SYNSEMA_SIGN_CEILING. Do not \
             retry in this process.",
            name, used, ceiling
        )));
    }
    counts.insert(name.to_string(), used + 1);
    Ok(())
}

// =========================================================
// F-B — builtins `spend` / `spend_total`
// =========================================================

/// Monto → Decimal exacto. Int/Big/Decimal entran directo; un Float entra por su
/// forma de TEXTO (round-trip por dígitos decimales, sin arrastrar el error binario
/// al acumulador). No representable → error claro.
fn amount_to_decimal(n: &Number) -> Result<Decimal, String> {
    if let Some(d) = n.to_decimal() {
        return Ok(d);
    }
    Decimal::from_str_exact(&n.to_string()).map_err(|_| {
        format!(
            "spend: the amount {} cannot be represented as an exact decimal — pass a \
             decimal amount (e.g. 12.50)",
            n
        )
    })
}

fn spend_cap_denied(unit: &str) -> Control {
    err(format!(
        "Capability not granted: spend(\"{unit}\") — add `require spend(\"{unit}\")` \
         (spending is deny-by-default and writes a persistent audit entry)"
    ))
}

/// Registra `spend(monto, unidad, motivo)` y `spend_total(unidad)`.
pub fn register_spend_builtins(interp: &Interpreter, caps: Rc<RefCell<CapabilitySet>>) {
    // spend(monto, unidad, motivo) → total acumulado de esa unidad tras el gasto.
    // Orden estricto (espejo de sign): validar → capability (audita ambas) → techo →
    // audit fail-loud → acumular.
    interp.register_builtin(
        "spend",
        3,
        Rc::new(move |_i, args, loc| {
            // 1) Validación de argumentos.
            let amount = match args.first() {
                Some(SynValue::Number(n)) => {
                    if n.is_negative() || n.is_zero() {
                        return Err(err(format!(
                            "spend: the amount must be a positive number, got {}",
                            n
                        )));
                    }
                    amount_to_decimal(n).map_err(err)?
                }
                Some(other) => {
                    return Err(err(format!(
                        "spend: the amount must be a positive number, got {}",
                        other.type_name()
                    )))
                }
                None => return Err(err("spend: missing argument 1 (amount)")),
            };
            let unit = match args.get(1) {
                Some(SynValue::Text(s)) if !s.trim().is_empty() => s.trim().to_string(),
                Some(SynValue::Text(_)) => {
                    return Err(err("spend: the unit must be a non-empty text, e.g. \"USD\""))
                }
                Some(other) => {
                    return Err(err(format!(
                        "spend: the unit must be text (e.g. \"USD\"), got {}",
                        other.type_name()
                    )))
                }
                None => return Err(err("spend: missing argument 2 (unit)")),
            };
            let reason = match args.get(2) {
                Some(SynValue::Text(s)) if !s.trim().is_empty() => s.trim().to_string(),
                Some(SynValue::Text(_)) => {
                    return Err(err(
                        "spend: the reason must be a non-empty text describing why this \
                         spend happens (it goes to the audit log)",
                    ))
                }
                Some(other) => {
                    return Err(err(format!(
                        "spend: the reason must be text, got {}",
                        other.type_name()
                    )))
                }
                None => return Err(err("spend: missing argument 3 (reason)")),
            };
            let amount_text = amount.to_string();

            // 2) Capability `spend(unidad)` — el chequeo queda en el audit-log del
            // CapabilitySet; concedida O denegada se registra también en spend.log.
            let granted = caps
                .borrow_mut()
                .check(&Capability::new(CapabilityType::Spend, Some(unit.clone())), "spend-builtin");
            if !granted {
                // 3) Denegación por capability: auditada best-effort (el gasto ya no ocurre).
                let _ = write_spend_audit(&unit, &amount_text, &reason, loc, false, false);
                return Err(spend_cap_denied(&unit));
            }

            // 4-6) Techo + audit + acumulación BAJO EL MISMO LOCK: sin ventana entre el
            // chequeo del techo y el commit (dos handlers de serve no pueden colarse).
            let mut totals = lock_unpoisoned(spend_totals());
            let current = totals.get(&unit).copied().unwrap_or(Decimal::ZERO);
            let new_total = current
                .checked_add(amount)
                .ok_or_else(|| err("spend: the accumulated total overflows the decimal range"))?;
            if let Some(&ceiling) = spend_ceilings().get(&unit) {
                if new_total > ceiling {
                    drop(totals);
                    // Denegación por techo: auditada (best-effort) con denied_by=ceiling.
                    let _ = write_spend_audit(&unit, &amount_text, &reason, loc, false, true);
                    return Err(err(format!(
                        "spend ceiling exceeded for \"{}\": spent {} + {} > {} — the ceiling \
                         is set by the host via SYNSEMA_SPEND_CEILING. Do not proceed with \
                         the external payment call.",
                        unit, current, amount_text, ceiling
                    )));
                }
            }
            // 5) Audit del gasto concedido — FAIL-LOUD: sin entrada escrita no hay gasto.
            write_spend_audit(&unit, &amount_text, &reason, loc, true, false).map_err(|e| {
                err(format!(
                    "spend(\"{}\") failed: cannot write the audit log ({}). Refusing to \
                     record a spend without an audit trail.",
                    unit, e
                ))
            })?;
            // 6) Commit + total acumulado como retorno.
            totals.insert(unit, new_total);
            Ok(syn_number(Number::Decimal(new_total)))
        }),
    );

    // spend_total(unidad) → total acumulado del proceso (0 si nada). Introspección
    // SIN gate (como llm_usage/llm_available): leer el propio contador no gasta.
    interp.register_builtin(
        "spend_total",
        1,
        Rc::new(move |_i, args, _loc| {
            let unit = match args.first() {
                Some(SynValue::Text(s)) => s.trim().to_string(),
                Some(other) => {
                    return Err(err(format!(
                        "spend_total: the unit must be text (e.g. \"USD\"), got {}",
                        other.type_name()
                    )))
                }
                None => return Err(err("spend_total: missing argument 1 (unit)")),
            };
            let total = lock_unpoisoned(spend_totals())
                .get(&unit)
                .copied()
                .unwrap_or(Decimal::ZERO);
            Ok(syn_number(Number::Decimal(total)))
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Gramática de techos --

    #[test]
    fn ceiling_pairs_grammar() {
        let pairs = parse_ceiling_pairs("X", "USD:500, ETH:0.1 ,HOT_KEY:100");
        assert_eq!(
            pairs,
            vec![
                ("USD".to_string(), "500".to_string()),
                ("ETH".to_string(), "0.1".to_string()),
                ("HOT_KEY".to_string(), "100".to_string()),
            ]
        );
        // Entradas malformadas se descartan (con warn), las buenas sobreviven.
        let pairs = parse_ceiling_pairs("X", "USD:500,,bad,:5,USD:,ok:1");
        assert_eq!(
            pairs,
            vec![("USD".to_string(), "500".to_string()), ("ok".to_string(), "1".to_string())]
        );
        assert!(parse_ceiling_pairs("X", "").is_empty());
    }

    // -- Conversión de montos --

    #[test]
    fn amounts_take_the_decimal_path() {
        use std::str::FromStr;
        // Int y Decimal exactos.
        assert_eq!(amount_to_decimal(&Number::Int(50)).unwrap(), Decimal::from(50));
        let d = Decimal::from_str("12.50").unwrap();
        assert_eq!(amount_to_decimal(&Number::Decimal(d)).unwrap(), d);
        // Float entra por su forma de texto: 0.1 acumula como 0.1 EXACTO (no binario).
        let f = amount_to_decimal(&Number::Float(0.1)).unwrap();
        assert_eq!(f, Decimal::from_str("0.1").unwrap());
        let sum = f + f + f;
        assert_eq!(sum, Decimal::from_str("0.3").unwrap(), "sin error binario en centavos");
    }

    // -- F-C: reserva del techo de firmas (lógica pura del contador) --
    // El techo real por env se cubre e2e (framework_f1_e2e.rs fija la env-var una vez
    // por proceso de test); acá se valida el contador con claves únicas por test.

    #[test]
    fn sign_counts_reserve_and_are_per_key() {
        let key = format!("K_{}", std::process::id());
        let mut counts = lock_unpoisoned(sign_counts());
        assert_eq!(counts.get(&key), None);
        counts.insert(key.clone(), 1);
        assert_eq!(counts.get(&key), Some(&1));
        counts.remove(&key);
    }
}

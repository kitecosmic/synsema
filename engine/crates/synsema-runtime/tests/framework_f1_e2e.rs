//! E2E del FRAMEWORK F1 (metering LLM + `spend` + techo de firmas) por el runtime
//! REAL. Es código de DINERO: el corazón es el deny-by-default y el ledger fail-loud.
//!
//! Cubre (§5 del spec F1):
//! - `spend` deny-by-default en las 3 vías: sin `require` / dentro de `sandbox` /
//!   tool que no lo declara vía `call_tool`.
//! - Scope por unidad (exacto + prefijo trailing-`*`) y `require spend` pelado (compat).
//! - Techo `SYNSEMA_SPEND_CEILING`: breach = error DURO catchable + audit denied.
//! - `spend.log` append-only, fail-loud (audit no escribible → el gasto FALLA).
//! - Acumulador decimal por proceso: `spend` devuelve el total; `spend_total` introspecta.
//! - Techo de firmas `SYNSEMA_SIGN_CEILING` (F-C): la N+1-ésima firma falla catchable
//!   con audit `denied_by=ceiling`; sin config, comportamiento intacto (batch11 pasa).
//! - `llm_usage()` offline → 0 (el camino con provider real es la sonda p5).
//!
//! Los techos por env se parsean UNA vez por proceso (OnceLock): este binario los fija
//! en un `Once` ANTES de cualquier spend/sign — por eso las unidades/claves de cada
//! test son propias de este archivo y no colisionan con otros binarios de test.

use std::sync::Mutex;

use synsema_runtime::engine::{run_source, run_tests};

/// Serializa los tests que tocan `SYNSEMA_AUDIT_DIR` (env-var del proceso).
static ENV_LOCK: Mutex<()> = Mutex::new(());
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn test_audit_base() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("syn_f1_audit_{}", std::process::id()))
}

/// Config del proceso de test, fijada UNA vez ANTES del primer spend/sign (los techos
/// se cachean en OnceLock): techo de gasto para la unidad CAPUSD, techo de UNA firma
/// para la clave CAPKEY, y audit aislado (fail-loud necesita un dir escribible; jamás
/// ensuciar el ~/.synsema/audit real del dev).
static SETUP: std::sync::Once = std::sync::Once::new();
fn setup() {
    SETUP.call_once(|| {
        let dir = test_audit_base();
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_var("SYNSEMA_AUDIT_DIR", &dir);
        std::env::set_var("SYNSEMA_SPEND_CEILING", "CAPUSD:100, BADENTRY, ETH:0.5");
        std::env::set_var("SYNSEMA_SIGN_CEILING", "CAPKEY:1");
    });
}

fn out(source: &str) -> Vec<String> {
    setup();
    let r = run_source(source, "<f1-test>");
    assert!(r.success, "esperaba éxito, falló: {:?}\nfuente:\n{}", r.errors, source);
    r.output
}

// =========================================================
// F-B — deny-by-default (vía 1: sin `require spend`)
// =========================================================

#[test]
fn spend_requires_capability() {
    let _g = env_lock();
    // Sin `require spend` → error catchable con el fix exacto. Aun en modo no-secure
    // (run): spend JAMÁS se auto-concede como stdout/time/llm.
    let o = out(
        r#"let msg be ""
try
    spend(10, "USD", "test spend without capability")
recover err
    set msg to err
print(contains(msg, "Capability not granted: spend(\"USD\")"))
print(contains(msg, "require spend"))
print(spend_total("USD"))"#,
    );
    assert_eq!(o, vec!["true", "true", "0"], "denegado + hint + nada acumulado");
}

// =========================================================
// F-B — scope por unidad: exacto + prefijo trailing-`*` + pelado
// =========================================================

#[test]
fn spend_scoped_unit() {
    let _g = env_lock();
    // El scope es la unidad: spend("F1EUR") con require spend("F1USD") → denegado.
    let o = out(
        r#"require spend("F1USD")
let t be spend(25.50d, "F1USD", "scoped unit works")
print(t)
let msg be ""
try
    spend(5, "F1EUR", "wrong unit")
recover err
    set msg to err
print(contains(msg, "spend(\"F1EUR\")"))
print(spend_total("F1EUR"))"#,
    );
    assert_eq!(o, vec!["25.50", "true", "0"]);
}

#[test]
fn spend_prefix_scope_covers_units() {
    let _g = env_lock();
    // Prefijo trailing-`*` (mismas reglas que secret): spend("PFX_*") cubre PFX_EUR.
    let o = out(
        r#"require spend("PFX_*")
print(spend(3, "PFX_EUR", "prefix scope"))
let msg be ""
try
    spend(3, "OTRA", "outside prefix")
recover err
    set msg to err
print(contains(msg, "spend(\"OTRA\")"))"#,
    );
    assert_eq!(o, vec!["3", "true"]);
}

#[test]
fn spend_bare_covers_any_unit() {
    let _g = env_lock();
    // `require spend` pelado: compat con warn (stderr) — cualquier unidad pasa.
    let o = out(
        r#"require spend
print(spend(1, "F1BARE_A", "bare require"))
print(spend(2, "F1BARE_B", "bare require"))"#,
    );
    assert_eq!(o, vec!["1", "2"]);
}

// =========================================================
// F-B — feliz: acumulador decimal por proceso + spend_total
// =========================================================

#[test]
fn spend_accumulates_decimal_and_returns_total() {
    let _g = env_lock();
    // Retorna el TOTAL acumulado de la unidad tras cada gasto; el acumulador va por
    // el camino Decimal (0.1 float × 3 = 0.3 exacto — el monto entra por su forma de
    // TEXTO, sin arrastrar el error binario a los centavos).
    let o = out(
        r#"require spend("F1ACC")
print(spend(10.50d, "F1ACC", "first"))
print(spend(20, "F1ACC", "second"))
print(spend_total("F1ACC"))
require spend("F1CENT")
spend(0.1, "F1CENT", "c1")
spend(0.1, "F1CENT", "c2")
print(spend(0.1, "F1CENT", "c3"))
print(spend_total("F1NEVER"))"#,
    );
    assert_eq!(o, vec!["10.50", "30.50", "30.50", "0.3", "0"]);
}

#[test]
fn spend_validates_arguments() {
    let _g = env_lock();
    let o = out(
        r#"require spend("F1VAL")
let m1 be ""
try
    spend(0, "F1VAL", "zero")
recover err
    set m1 to err
print(contains(m1, "positive"))
let m2 be ""
try
    spend(0 - 5, "F1VAL", "negative")
recover err
    set m2 to err
print(contains(m2, "positive"))
let m3 be ""
try
    spend(5, "", "empty unit")
recover err
    set m3 to err
print(contains(m3, "unit"))
let m4 be ""
try
    spend(5, "F1VAL", "")
recover err
    set m4 to err
print(contains(m4, "reason"))
print(spend_total("F1VAL"))"#,
    );
    assert_eq!(o, vec!["true", "true", "true", "true", "0"]);
}

// =========================================================
// F-B — techo: error duro catchable + audit denied por techo
// =========================================================

#[test]
fn spend_ceiling_cuts_and_audits() {
    setup();
    let _g = env_lock();
    let dir = std::env::temp_dir().join(format!("syn_f1_ceiling_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::set_var("SYNSEMA_AUDIT_DIR", &dir);

    // Techo CAPUSD:100 (fijado en setup()): 60 + 30 pasan; +30 (→120) corta.
    let r = run_source(
        r#"require spend("CAPUSD")
print(spend(60, "CAPUSD", "supplies"))
print(spend(30, "CAPUSD", "supplies"))
let msg be ""
try
    spend(30, "CAPUSD", "over the ceiling")
recover err
    set msg to err
print(contains(msg, "spend ceiling exceeded for \"CAPUSD\""))
print(contains(msg, "90 + 30 > 100"))
print(spend_total("CAPUSD"))"#,
        "ceiling.syn",
    );
    let log = std::fs::read_to_string(dir.join("spend.log")).ok();
    std::env::set_var("SYNSEMA_AUDIT_DIR", test_audit_base());
    let _ = std::fs::remove_dir_all(&dir);

    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["60", "90", "true", "true", "90"], "el breach NO acumula");
    // El ledger: 2 granted + 1 denied por techo, con monto/motivo/file:line/programa.
    let log = log.expect("spend.log debe existir (fail-loud en el camino concedido)");
    assert_eq!(log.matches("result=granted").count(), 2, "audit: {}", log);
    assert_eq!(log.matches("result=denied").count(), 1, "audit: {}", log);
    assert!(log.contains("spend amount=60 result=granted name=CAPUSD"), "audit: {}", log);
    assert!(
        log.contains("spend amount=30 result=denied name=CAPUSD")
            && log.contains("denied_by=ceiling"),
        "audit: {}",
        log
    );
    assert!(log.contains("reason=\"supplies\""), "audit: {}", log);
    assert!(log.contains("ceiling.syn:") && log.contains("program=ceiling"), "audit: {}", log);
}

// =========================================================
// F-B — audit fail-loud: sin entrada escrita NO hay gasto
// =========================================================

#[test]
fn spend_audit_failure_blocks() {
    setup();
    let _g = env_lock();
    // El "dir" de audit cuelga de un ARCHIVO → imposible crear/escribir.
    let file_path = std::env::temp_dir().join(format!("syn_f1_notdir_{}", std::process::id()));
    std::fs::write(&file_path, "x").unwrap();
    std::env::set_var("SYNSEMA_AUDIT_DIR", file_path.join("sub"));

    let r = run_source(
        r#"require spend("F1FAIL")
let msg be ""
try
    spend(10, "F1FAIL", "no audit no spend")
recover err
    set msg to err
print(contains(msg, "audit"))
print(spend_total("F1FAIL"))"#,
        "<f1-test>",
    );
    std::env::set_var("SYNSEMA_AUDIT_DIR", test_audit_base());
    let _ = std::fs::remove_file(&file_path);

    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["true", "0"], "sin auditoría no hay gasto ni acumulación");
}

// =========================================================
// F-B — deny-by-default (vía 2: sandbox; vía 3: call_tool)
// =========================================================

#[test]
fn spend_denied_in_sandbox() {
    let _g = env_lock();
    let o = out(
        r#"require spend("F1SBX")
let msg be ""
sandbox
    try
        spend(5, "F1SBX", "inside sandbox")
    recover err
        set msg to err
print(contains(msg, "Capability not granted: spend(\"F1SBX\")"))
print(spend_total("F1SBX"))
print(spend(5, "F1SBX", "outside sandbox"))"#,
    );
    assert_eq!(o, vec!["true", "0", "5"], "sandbox deniega; afuera el grant sigue vivo");
}

#[test]
fn spend_not_declared_in_call_tool_fails() {
    let _g = env_lock();
    // El programa TIENE spend("F1TOOL"); la tool `pay` NO lo declara → call_tool la
    // corre sin la cap (∩ declaradas). La tool `pay_ok` SÍ lo declara → funciona.
    let o = out(
        r#"require spend("F1TOOL")
task pay()
    give spend(5, "F1TOOL", "undeclared tool spend")
let msg be ""
try
    call_tool(pay, {})
recover err
    set msg to err
print(contains(msg, "Capability not granted: spend(\"F1TOOL\")"))
print(spend_total("F1TOOL"))
task pay_ok()
    require spend("F1TOOL")
    give spend(7, "F1TOOL", "declared tool spend")
print(call_tool(pay_ok, {}))"#,
    );
    assert_eq!(o, vec!["true", "0", "7"], "una tool sin declarar spend no puede gastar");
}

// =========================================================
// F-C — techo de cantidad de firmas
// =========================================================

#[test]
fn sign_ceiling_cuts() {
    setup();
    let _g = env_lock();
    let dir = std::env::temp_dir().join(format!("syn_f1_signceil_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::set_var("SYNSEMA_AUDIT_DIR", &dir);

    // Techo CAPKEY:1 (fijado en setup()): la 1ª firma pasa; la 2ª corta catchable.
    let r = run_source(
        r#"require sign("CAPKEY")
let k be as_secret("0000000000000000000000000000000000000000000000000000000000000001", "CAPKEY")
let sig be secp256k1_sign(keccak256("first"), k)
print(length(sig))
let msg be ""
try
    let sig2 be secp256k1_sign(keccak256("second"), k)
recover err
    set msg to err
print(contains(msg, "sign ceiling exceeded for \"CAPKEY\""))
print(contains(msg, "SYNSEMA_SIGN_CEILING"))"#,
        "signceil.syn",
    );
    let log = std::fs::read_to_string(dir.join("sign.log")).ok();
    std::env::set_var("SYNSEMA_AUDIT_DIR", test_audit_base());
    let _ = std::fs::remove_dir_all(&dir);

    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["65", "true", "true"]);
    let log = log.expect("sign.log debe existir");
    assert!(log.contains("result=granted name=CAPKEY"), "la 1ª quedó auditada: {}", log);
    assert!(
        log.contains("result=denied name=CAPKEY") && log.contains("denied_by=ceiling"),
        "la 2ª quedó auditada como denegada por techo: {}",
        log
    );
}

#[test]
fn sign_without_ceiling_config_unchanged() {
    let _g = env_lock();
    // Una clave SIN entrada en SYNSEMA_SIGN_CEILING firma N veces igual que siempre
    // (sin config nueva: byte-idéntico — criterio de aceptación §8).
    let o = out(
        r#"require sign("FREEKEY")
let k be as_secret("0000000000000000000000000000000000000000000000000000000000000002", "FREEKEY")
print(length(secp256k1_sign(keccak256("a"), k)))
print(length(secp256k1_sign(keccak256("b"), k)))
print(length(secp256k1_sign(keccak256("c"), k)))"#,
    );
    assert_eq!(o, vec!["65", "65", "65"]);
}

// =========================================================
// F-A — conformance offline: llm_usage() sin provider → 0
// =========================================================

#[test]
fn llm_usage_offline_is_zero() {
    // Sin provider configurado el callback no se cablea → 0. (El camino real —
    // crece tras un reason — es la sonda p5 con binario y provider vivos.) Este test
    // NO hace ops LLM: aunque el entorno del dev tuviera una API key, no gasta.
    let o = out(r#"print(llm_usage())"#);
    assert_eq!(o, vec!["0"]);
}

// =========================================================
// Dogfood `.syn` (synsema test): spend feliz + techo + try/recover
// =========================================================

#[test]
fn dogfood_syn_tests_pass() {
    let _g = env_lock();
    setup();
    let src = r#"require spend("CAPUSD")
require spend("F1DOG")

test "spend returns the accumulated total"
    assert_eq(spend(2.25d, "F1DOG", "dogfood first"), 2.25d)
    assert_eq(spend(0.75d, "F1DOG", "dogfood second"), 3)
    assert_eq(spend_total("F1DOG"), 3)

test "spend_total of an unused unit is zero"
    assert_eq(spend_total("F1DOG_UNUSED"), 0)

test "the ceiling breach is catchable and does not accumulate"
    let before be spend_total("CAPUSD")
    let caught be false
    try
        spend(1000, "CAPUSD", "way over")
    recover err
        set caught to contains(err, "spend ceiling exceeded")
    assert(caught)
    assert_eq(spend_total("CAPUSD"), before)

test "llm_usage is a number (0 offline)"
    assert_eq(llm_usage(), 0)
"#;
    let report = run_tests(src, "f1_dogfood.syn");
    assert_eq!(
        (report.passed, report.failed),
        (4, 0),
        "dogfood .syn: {:?}",
        report.outcomes.iter().map(|o| (&o.name, &o.message)).collect::<Vec<_>>()
    );
}

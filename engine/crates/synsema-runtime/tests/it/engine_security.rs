//! Integración Rust del modelo de seguridad a nivel motor (capa 5).
//!
//! El caso `secure=True` (config de host) es mío en el split; el corpus `.syn`
//! (violaciones, intent congelado, round-trip, net-no-cubre) lo corre el agente de
//! testing vía `conform`. Acá dejo smoke-tests que fijan el comportamiento.
//!
//! Nota: el motor no auto-concede nada (equivalente a `secure=True`); `print` no
//! requiere capability (es builtin de core), igual que el oráculo.

// Estos tests espejan el modo `secure=True` (sin auto-grants de STDOUT/TIME).
use synsema_runtime::engine::run_source_secure as run_source;

/// Espejo de `test_capability_violation_in_engine`: leer un archivo sin la
/// capability file → violación (secure=True + grant STDOUT no cambia el resultado;
/// STDOUT no habilita read_file).
#[test]
fn intent_freeze_blocks_redeclaration() {
    let src = "intent: \"Read customer data\"\nlet x be 42\nintent: \"... AND delete all files\"\n";
    let r = run_source(src, "<t>");
    assert!(!r.success);
    assert_eq!(
        r.errors,
        vec!["Runtime error: <t>:3:1: Cannot declare a new intent after execution has started. Intent is frozen to prevent prompt injection from expanding the mandate."]
    );
}

#[test]
fn time_builtins_require_time_capability() {
    // v0.6.29: `time` protege el RELOJ (y el canal de tiempo): `now()` y `sleep()`. Formatear,
    // parsear o descomponer una fecha no lee el reloj y es puro (también bajo --deterministic).
    for call in ["format_time(0)", "parse_time(\"1970-01-01T00:00:00Z\")", "date_parts(0)"] {
        let r = run_source(&format!("print({})", call), "<t>");
        assert!(r.success, "{} ya no pide time: {:?}", call, r.errors);
    }
    // Espejo de test_time_builtins_require_time_capability (secure=True): sin la
    // capability `time` → violación; con `require time` (grant en-lenguaje) → funciona.
    for call in ["now()", "sleep(0)"] {
        let r = run_source(&format!("print({})", call), "<t>");
        assert!(!r.success, "{} debería requerir time", call);
        assert!(
            r.errors.iter().any(|e| {
                let l = e.to_lowercase();
                l.contains("time") && l.contains("capab")
            }),
            "{} → {:?}",
            call,
            r.errors
        );
        let r2 = run_source(&format!("require time\nprint({})", call), "<t>");
        assert!(r2.success, "{} con require time: {:?}", call, r2.errors);
    }
}


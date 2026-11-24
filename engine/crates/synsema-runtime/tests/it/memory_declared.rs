//! DB-M1 — memoria declarada del agente (`require memory("<nombre>")`), plan §4.
//!
//! La declaración ES la identidad: sin ella no hay persistencia (ni archivos, G-1) y
//! toda la familia de estado persistente (memory + rules + progress) falla con el error
//! de capability + el fix exacto. Con ella: un `.db` por nombre declarado, deny-by-default
//! real (sandbox / call_tool / --cap-set, G-2), namespaces por `source` (decisión #4) y
//! esquema intacto (G-5).
//!
//! Cada test usa su propio temp dir y NO toca env vars del proceso (los casos de
//! `SYNSEMA_STATE_DIR`/`SYNSEMA_STATE_NAME` viven en `state_path_resolution.rs`).

use std::path::PathBuf;

use synsema_capabilities::model::{Capability, CapabilityType};
use synsema_runtime::engine::{run_program, run_program_ceiled, run_source};

fn unique_tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("synsema_memdecl_{}_{}", std::process::id(), tag));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn state_db(proj: &std::path::Path, name: &str) -> PathBuf {
    proj.join(".synsema").join("state").join(format!("{}.db", name))
}

fn cleanup(d: &std::path::Path) {
    let _ = std::fs::remove_dir_all(d);
}

// ── §4.1 + G-1: sin declaración → error claro con sugerencia, y CERO archivos ──────

#[test]
fn no_declaration_denies_whole_family_and_creates_nothing() {
    let proj = unique_tmp("nodecl");
    let prog = proj.join("myprog.syn");
    for src in [
        "remember(\"context\", \"x\")",
        "recall(\"context\")",
        "create_progress(\"plan\", [\"a\"])",
        "add_rule(\"r\", \"must\", \"desc\")",
        "memory_summary()",
    ] {
        let r = run_source(src, prog.to_str().unwrap());
        assert!(!r.success, "debió fallar sin declaración: {}", src);
        let e = r.errors.join(" ");
        assert!(e.contains("Capability not granted: memory"), "mensaje de capability en `{}`: {}", src, e);
        assert!(
            e.contains("require memory(\"myprog\")"),
            "el error debe sugerir el fix exacto (stem) en `{}`: {}",
            src,
            e
        );
    }
    // G-1: nada se creó — ni `.synsema/` ni ningún .db.
    assert!(!proj.join(".synsema").exists(), "G-1: no debe crearse .synsema/ sin declaración");
    cleanup(&proj);
}

// ── §4.5: dos declaraciones con nombres distintos → error de arranque ──────────────

#[test]
fn two_distinct_declarations_is_startup_error() {
    let proj = unique_tmp("twodecl");
    let prog = proj.join("p.syn");
    let r = run_source(
        "require memory(\"a\")\nrequire memory(\"b\")\nprint(\"ran\")",
        prog.to_str().unwrap(),
    );
    assert!(!r.success);
    assert!(r.output.is_empty(), "no debe ejecutarse nada: {:?}", r.output);
    let e = r.errors.join(" ");
    assert!(e.contains("Multiple memory declarations"), "err: {}", e);
    assert!(!proj.join(".synsema").exists(), "error de arranque no debe crear archivos");

    // La MISMA declaración repetida es una sola identidad (no es error).
    let ok = run_source(
        "require memory(\"a\")\nrequire memory(\"a\")\nprint(\"ran\")",
        prog.to_str().unwrap(),
    );
    assert!(ok.success, "{:?}", ok.errors);
    cleanup(&proj);
}

// ── §4.6 / G-6: nombres inválidos fallan EN LA DECLARACIÓN, no al persistir ────────

#[test]
fn invalid_names_error_at_declaration_time() {
    let proj = unique_tmp("badname");
    let prog = proj.join("p.syn");
    for bad in ["../x", "a/b", "a\\\\b", "", "a b", "x.db"] {
        let src = format!("require memory(\"{}\")\nprint(\"ran\")", bad);
        let r = run_source(&src, prog.to_str().unwrap());
        assert!(!r.success, "nombre inválido debió fallar: {:?}", bad);
        assert!(r.output.is_empty(), "falla ANTES de ejecutar: {:?}", r.output);
        let e = r.errors.join(" ");
        assert!(e.contains("Invalid memory name"), "err para {:?}: {}", bad, e);
    }
    assert!(!proj.join(".synsema").exists(), "G-6: nombre inválido no debe crear archivos");
    cleanup(&proj);
}

#[test]
fn bare_require_memory_is_a_parse_error() {
    let r = run_source("require memory\nprint(\"ran\")", "<test>");
    assert!(!r.success);
    let e = r.errors.join(" ");
    assert!(e.contains("Parse error"), "err: {}", e);
    assert!(e.contains("require memory needs a name"), "err: {}", e);
}

// ── §4.7a: `sandbox` deniega la memoria (el CapabilitySet se vacía) ─────────────────

// ── §4.7b: `call_tool` — una tool que no declara memory no la hereda ────────────────

// ── §4.7c / G-2: el techo del host (--cap-set) gatea, con prefijos `memory=shop-*` ──

#[test]
fn host_ceiling_gates_memory_with_prefix_scopes() {
    let proj = unique_tmp("ceiling");
    let prog = proj.join("shop.syn");
    let src = "require memory(\"shop-eu\")\nremember(\"context\", \"x\")\nprint(\"ok\")";
    let base = vec![
        Capability::new(CapabilityType::Stdout, None),
        Capability::new(CapabilityType::Time, None),
    ];

    // Techo SIN memory → denegado (aunque el programa declare).
    let r = run_program_ceiled(src, prog.to_str().unwrap(), Some(base.clone()));
    assert!(!r.success, "el techo sin memory debe denegar");
    assert!(
        r.errors.join(" ").contains("Capability not granted: memory"),
        "err: {:?}",
        r.errors
    );
    // Y NO deja efectos en disco: un techo que deniega la memoria no debe dejar
    // un `.db` vacío como colateral del arranque (espíritu G-1).
    assert!(
        !proj.join(".synsema").exists(),
        "el techo denegante no debe crear .synsema/ ni un .db vacío"
    );

    // Techo con `memory=shop-*` → el nombre declarado cae dentro del prefijo → permitido.
    let mut with_prefix = base.clone();
    with_prefix.push(Capability::new(CapabilityType::Memory, Some("shop-*".to_string())));
    let r2 = run_program_ceiled(src, prog.to_str().unwrap(), Some(with_prefix));
    assert!(r2.success, "{:?}", r2.errors);

    // Techo con `memory=shop-*` pero declaración FUERA del prefijo → denegado.
    let src_out = "require memory(\"billing\")\nremember(\"context\", \"x\")";
    let mut with_prefix2 = base;
    with_prefix2.push(Capability::new(CapabilityType::Memory, Some("shop-*".to_string())));
    let r3 = run_program_ceiled(src_out, prog.to_str().unwrap(), Some(with_prefix2));
    assert!(!r3.success, "billing está fuera del prefijo shop-*");
    cleanup(&proj);
}

// ── §4.8 / G-4: transición — un .db viejo sin declaración no se toca ni se carga ────

#[test]
fn transition_old_db_without_declaration_is_untouched() {
    let proj = unique_tmp("transition");
    let state = proj.join(".synsema").join("state");
    std::fs::create_dir_all(&state).unwrap();
    let old = state.join("myprog.db");
    std::fs::write(&old, b"viejo-contenido-opaco").unwrap();
    let prog = proj.join("myprog.syn");

    // Programa sin declaración: corre normal (warning a stderr), nada se carga/escribe.
    let r = run_source("print(\"hi\")", prog.to_str().unwrap());
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, vec!["hi"]);
    assert_eq!(std::fs::read(&old).unwrap(), b"viejo-contenido-opaco", "el .db viejo no se toca");

    // Declaración con OTRO nombre: crea brain.db y deja el viejo intacto (sin warning).
    let r2 = run_source(
        "require memory(\"brain\")\nremember(\"context\", \"x\")",
        prog.to_str().unwrap(),
    );
    assert!(r2.success, "{:?}", r2.errors);
    assert!(state.join("brain.db").is_file());
    assert_eq!(std::fs::read(&old).unwrap(), b"viejo-contenido-opaco");
    cleanup(&proj);
}

// ── §4.9 / G-5: migración = renombrar el archivo (esquema intacto) ──────────────────

#[test]
fn schema_compat_rename_db_is_the_migration() {
    let proj = unique_tmp("rename");
    let prog = proj.join("p.syn");
    let r = run_source(
        "require memory(\"one\")\nremember(\"context\", \"payload-uno\")\nadd_rule(\"r1\", \"must\", \"desc\")",
        prog.to_str().unwrap(),
    );
    assert!(r.success, "{:?}", r.errors);
    let one = state_db(&proj, "one");
    assert!(one.is_file());

    // Migración de identidad = renombrar el archivo. Cero migración de datos (G-5).
    std::fs::rename(&one, state_db(&proj, "two")).unwrap();
    let r2 = run_source(
        "require memory(\"two\")\n\
         print(length(recall(\"context\")))\n\
         print(length(get_rules()))",
        prog.to_str().unwrap(),
    );
    assert!(r2.success, "{:?}", r2.errors);
    assert_eq!(r2.output, vec!["1", "1"], "el .db renombrado carga completo: {:?}", r2.output);
    cleanup(&proj);
}

// ── §4.10: namespaces por `source` (decisión #4) — camino in-process ────────────────

// ── §4.10b: camino SWARM — el `source` es el nombre del agente, stores compartidos ──

#[test]
fn swarm_agents_share_declared_store_with_their_name_as_source() {
    let proj = unique_tmp("swarm");
    let prog = proj.join("p.syn");
    let r = run_program(
        "require memory(\"brain\")\nagent Writer\n    remember(\"context\", \"w\")\nspawn Writer\n",
        prog.to_str().unwrap(),
    );
    assert!(r.success, "{:?}", r.errors);
    // Segundo run: lo escrito por el agente (hilo propio) persistió bajo su nombre.
    let r2 = run_source(
        "require memory(\"brain\")\nprint(length(recall(from = \"Writer\")))",
        prog.to_str().unwrap(),
    );
    assert!(r2.success, "{:?}", r2.errors);
    assert_eq!(r2.output, vec!["1"], "el agente swarm escribe en la memoria declarada: {:?}", r2.output);
    cleanup(&proj);
}

// ── workers de parallel_map comparten la memoria declarada ──────────────────────────

// ── §4.12 / G-7: un secret snapshotteado a memoria queda redactado en el .db ────────

// ── round-trip básico entre procesos (dos runs) + el error incluye el nombre ────────

#[test]
fn declared_roundtrip_and_progress_survive_runs() {
    let proj = unique_tmp("roundtrip");
    let prog = proj.join("p.syn");
    let r = run_source(
        "require memory(\"brain\")\n\
         remember(\"context\", \"hola\")\n\
         create_progress(\"plan\", [\"uno\", \"dos\"])\n\
         start_step(\"plan\", \"uno\")\n\
         complete_step(\"plan\", \"uno\", \"listo\")",
        prog.to_str().unwrap(),
    );
    assert!(r.success, "{:?}", r.errors);
    let r2 = run_source(
        "require memory(\"brain\")\n\
         print(length(recall(\"context\")))\n\
         print(resume_point(\"plan\"))",
        prog.to_str().unwrap(),
    );
    assert!(r2.success, "{:?}", r2.errors);
    assert_eq!(r2.output, vec!["1", "dos"], "memoria Y progress sobreviven runs: {:?}", r2.output);
    cleanup(&proj);
}

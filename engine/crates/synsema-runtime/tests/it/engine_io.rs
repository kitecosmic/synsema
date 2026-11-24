//! Conformidad de las primitivas de I/O (spec IO-P1): navegación, lectura por rango
//! y fix de seguridad del scope de ruta (`covers()` normaliza, cierra el bypass `..`).
//! También IO-P2: `grep` (búsqueda streaming), `edit_file` (edición quirúrgica),
//! `append_file` (agregar al final). Y IO-P3: `run` (ejecutar procesos del SO, cap `exec`).
//! Los tests de ejecución real de `run` están cfg-gateados por SO (acá corren los de
//! Windows; los de unix son para CI). El deny-by-default es portable.
//!
//! Corre en modo `secure` (sin auto-grants): cada sonda lleva su `require file...`.
//! Patrón calcado de `engine_security.rs` / `engine_db.rs` (temp_dir + pid; sin
//! `tempfile`). Las rutas se pasan con `/` (normalize_path unifica separadores igual,
//! pero `/` evita escapes en los literales de string Synsema).

use std::path::{Path, PathBuf};

use synsema_runtime::engine::run_source_secure as run;

/// Crea un directorio temporal único por test (mismo pid en el binario de tests → el
/// `tag` lo desambigua entre tests que corren en paralelo). Limpio antes de crear.
fn tdir(tag: &str) -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!("syn_io_{}_{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Ruta como string apto para un literal Synsema (separadores `/`).
fn syn(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

// =========================================================
// Capability: deny-by-default (sin require → violación, string exacto)
// =========================================================

// =========================================================
// Fix #5: el scope de ruta es FIEL (el bypass `..` queda cerrado)
// =========================================================

// =========================================================
// list_dir: enumera ordenado, metadata correcta, errores
// =========================================================

// =========================================================
// file_info / file_exists
// =========================================================

// =========================================================
// read_file: rango por líneas 1-based, fin observable, EOL preservado, errores
// =========================================================

// =========================================================
// write_file: atómico (round-trip + sin .synsema.tmp residual)
// =========================================================

// =========================================================
// Least-privilege de archivo: `require file.read(...)` / `file.write(...)`
// (DE-023 / MF-009 — la capacidad punteada ya parsea y concede grano fino)
// =========================================================

// =========================================================
// IO-P2: deny-by-default (string exacto)
// =========================================================

// =========================================================
// grep
// =========================================================

// =========================================================
// edit_file
// =========================================================

// =========================================================
// append_file
// =========================================================

// =========================================================
// IO-P3: run — deny-by-default + validación de args (portable, sin comando real)
// =========================================================

// =========================================================
// IO-P3: run — ejecución real en Windows (corre acá)
// =========================================================

#[cfg(windows)]
mod run_windows {
    use super::*;

    #[test]
    fn run_echo_exit_zero() {
        let r = run(
            "require exec(\"cmd\")\n\
             let r be run(\"cmd\", [\"/C\", \"echo\", \"hi\"])\n\
             print(text(r[\"exit_code\"]))\n\
             print(text(contains(r[\"stdout\"], \"hi\")))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["0".to_string(), "true".to_string()]);
    }

    #[test]
    fn run_nonzero_exit_is_data_not_error() {
        // exit ≠ 0 NO es raise: es dato en exit_code.
        let r = run(
            "require exec(\"cmd\")\n\
             let r be run(\"cmd\", [\"/C\", \"exit\", \"3\"])\n\
             print(text(r[\"exit_code\"]))\n",
            "<t>",
        );
        assert!(r.success, "exit≠0 no debe ser error: {:?}", r.errors);
        assert_eq!(r.output, vec!["3".to_string()]);
    }

    #[test]
    fn run_stdin_is_piped() {
        let r = run(
            "require exec(\"sort\")\n\
             let r be run(\"sort\", [], 10, {\"stdin\": \"abc\\n\"})\n\
             print(text(contains(r[\"stdout\"], \"abc\")))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
    }

    #[test]
    fn run_cwd_opt() {
        let d = tdir("run_cwd");
        let base = syn(&d);
        let dirname = d.file_name().unwrap().to_string_lossy().into_owned();
        let r = run(
            &format!(
                "require exec(\"cmd\")\n\
                 let r be run(\"cmd\", [\"/C\", \"cd\"], 10, {{\"cwd\": \"{base}\"}})\n\
                 print(text(contains(r[\"stdout\"], \"{dirname}\")))\n"
            ),
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn run_env_override() {
        let r = run(
            "require exec(\"cmd\")\n\
             let r be run(\"cmd\", [\"/C\", \"echo\", \"%MYV%\"], 10, {\"env\": {\"MYV\": \"hello123\"}})\n\
             print(text(contains(r[\"stdout\"], \"hello123\")))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
    }

    #[test]
    fn run_timeout_raises() {
        // ping -n 10 tarda ~9s; timeout 1s → mata + raise.
        let r = run(
            "require exec(\"ping\")\n\
             let r be run(\"ping\", [\"-n\", \"10\", \"127.0.0.1\"], 1)\n",
            "<t>",
        );
        assert!(!r.success, "debería expirar");
        assert!(
            r.errors.iter().any(|e| e.contains("timed out")),
            "got {:?}",
            r.errors
        );
    }

    #[test]
    fn run_output_truncation() {
        let r = run(
            "require exec(\"cmd\")\n\
             let r be run(\"cmd\", [\"/C\", \"echo\", \"abcdef\"], 10, {\"max_output\": 2})\n\
             print(text(r[\"stdout_truncated\"]))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
    }

    #[test]
    fn run_command_not_found_raises() {
        let r = run(
            "require exec(\"*\")\n\
             let r be run(\"definitely_not_a_cmd_xyz_123\", [])\n",
            "<t>",
        );
        assert!(!r.success);
        assert!(
            r.errors.iter().any(|e| e.contains("cannot start")),
            "got {:?}",
            r.errors
        );
    }
}

// =========================================================
// IO-P3: run — ejecución real en unix (para CI; cfg-gated)
// =========================================================

#[cfg(unix)]
mod run_unix {
    use super::*;

    #[test]
    fn run_echo_exit_zero() {
        let r = run(
            "require exec(\"echo\")\n\
             let r be run(\"echo\", [\"hi\"])\n\
             print(text(r[\"exit_code\"]))\n\
             print(text(contains(r[\"stdout\"], \"hi\")))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["0".to_string(), "true".to_string()]);
    }

    #[test]
    fn run_nonzero_exit_is_data_not_error() {
        let r = run(
            "require exec(\"false\")\n\
             let r be run(\"false\", [])\n\
             print(text(r[\"exit_code\"]))\n",
            "<t>",
        );
        assert!(r.success, "exit≠0 no debe ser error: {:?}", r.errors);
        assert_eq!(r.output, vec!["1".to_string()]);
    }

    #[test]
    fn run_stdin_is_piped() {
        let r = run(
            "require exec(\"cat\")\n\
             let r be run(\"cat\", [], 10, {\"stdin\": \"abc\"})\n\
             print(r[\"stdout\"])\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["abc".to_string()]);
    }

    #[test]
    fn run_cwd_opt() {
        let d = tdir("run_cwd");
        let base = syn(&d);
        let dirname = d.file_name().unwrap().to_string_lossy().into_owned();
        let r = run(
            &format!(
                "require exec(\"pwd\")\n\
                 let r be run(\"pwd\", [], 10, {{\"cwd\": \"{base}\"}})\n\
                 print(text(contains(r[\"stdout\"], \"{dirname}\")))\n"
            ),
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn run_env_override() {
        let r = run(
            "require exec(\"sh\")\n\
             let r be run(\"sh\", [\"-c\", \"echo $MYV\"], 10, {\"env\": {\"MYV\": \"hello123\"}})\n\
             print(text(contains(r[\"stdout\"], \"hello123\")))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
    }

    #[test]
    fn run_timeout_raises() {
        let r = run(
            "require exec(\"sleep\")\n\
             let r be run(\"sleep\", [\"5\"], 1)\n",
            "<t>",
        );
        assert!(!r.success, "debería expirar");
        assert!(
            r.errors.iter().any(|e| e.contains("timed out")),
            "got {:?}",
            r.errors
        );
    }

    #[test]
    fn run_output_truncation() {
        // seq produce salida grande pero FINITA → drena + trunca (sin colgar).
        let r = run(
            "require exec(\"seq\")\n\
             let r be run(\"seq\", [\"1\", \"50000\"], 30, {\"max_output\": 10})\n\
             print(text(r[\"stdout_truncated\"]))\n",
            "<t>",
        );
        assert!(r.success, "{:?}", r.errors);
        assert_eq!(r.output, vec!["true".to_string()]);
    }

    #[test]
    fn run_command_not_found_raises() {
        let r = run(
            "require exec(\"*\")\n\
             let r be run(\"definitely_not_a_cmd_xyz_123\", [])\n",
            "<t>",
        );
        assert!(!r.success);
        assert!(
            r.errors.iter().any(|e| e.contains("cannot start")),
            "got {:?}",
            r.errors
        );
    }
}

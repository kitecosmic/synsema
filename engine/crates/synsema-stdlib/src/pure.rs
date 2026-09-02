//! El perfil PURO como pared, en cualquier host: los builtins OS-facing (archivos,
//! procesos, sockets crudos, drivers de DB, scheduler) se REEMPLAZAN por stubs que
//! existen (nunca `Undefined variable`) y fallan con la verdad del entorno. Es la
//! segunda pared, independiente del techo de capabilities: un bug del intérprete no
//! puede dar acceso a lo que no está registrado.
//!
//! Una sola lista para los tres hosts: el binario nativo bajo `--profile pure`
//! (`synsema run --profile pure`), el bin wasip1 y el cdylib web. Se registra DESPUÉS
//! del wiring normal: `register_builtin` inserta por nombre en el env global, así que la
//! última registración gana (el mismo truco con el que el motor sobrescribe `render`).
//!
//! Formato del error, idéntico en todos los hosts salvo el `hint` final:
//! `<name>: not available in the pure profile — <why> (<hint>)`.

use std::rc::Rc;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::SynValue;

/// Sugerencia para el binario nativo bajo `--profile pure`.
pub const NATIVE_HINT: &str = "drop --profile pure to run it natively";
/// Sugerencia para los artefactos wasm.
pub const WASM_HINT: &str = "run the program with the native `synsema` binary";
/// Sugerencia del cdylib web para la familia de archivos (sin FS en ningún host).
pub const WEB_NO_FS_HINT: &str = "pass data in through the program's source/env, or run the program \
                                  with the native `synsema` binary (or the wasip1 build under \
                                  wasmtime with --dir)";

pub const WHY_NO_FS: &str = "this run has no filesystem";
pub const WHY_NO_EXEC: &str = "this run has no child processes";
pub const WHY_NO_HUB: &str = "this run has no child processes nor an I/O hub (select/proc_* need a process)";
pub const WHY_NO_SOCKETS: &str =
    "this run has no raw network sockets (WebSocket/TLS identity need an event loop and a process)";
pub const WHY_NO_DB: &str = "this run has no database drivers";
pub const WHY_NO_CRON: &str = "this run has no scheduler threads";
pub const WHY_NO_BUS: &str = "this run has no event bus (a single embedded interpreter has no swarm)";
pub const WHY_NO_AGENT_THREADS: &str = "this run has no agent threads";
pub const WHY_NO_PROCESS: &str = "this run has no process";

pub const FS: &[&str] = &[
    "read_file", "read_file_bytes", "write_file", "append_file", "edit_file", "list_dir",
    "file_info", "file_exists", "grep",
];
pub const EXEC: &[&str] = &["run"];
pub const SOCKETS: &[&str] = &[
    "mtls_identity",
    "ws_connect", "ws_send", "ws_recv", "ws_close", "ws_status", "ws_stats",
    "ws_select", "ws_select_all", "ws_broadcast",
];
pub const DB: &[&str] = &[
    "db_open", "db_close", "sql", "sql_exec", "sql_tables", "sql_batch", "paged",
    "mongo_find", "mongo_find_one", "mongo_insert", "mongo_insert_many", "mongo_update",
    "mongo_delete", "mongo_count", "mongo_aggregate", "mongo_collections",
    "redis_get", "redis_set", "redis_del", "redis_exists", "redis_expire", "redis_ttl",
    "redis_persist", "redis_type", "redis_keys", "redis_incr", "redis_incrby",
    "redis_decr", "redis_mget", "redis_mset", "redis_hget", "redis_hset", "redis_hdel",
    "redis_hgetall", "redis_hincrby", "redis_lpush", "redis_rpush", "redis_lpop",
    "redis_rpop", "redis_lrange", "redis_llen", "redis_sadd", "redis_srem",
    "redis_smembers", "redis_sismember", "redis_lock", "redis_unlock",
];
pub const CRON: &[&str] = &["cron_every", "cron_after", "cron_cancel", "cron_list", "cron_status"];
/// Hub de I/O (select unificado + procesos vivos + watch + terminal). `term_open` NO
/// está acá: devuelve `nothing` (como sin TTY) para que el fallback a `read_line` sea el
/// mismo programa.
pub const HUB: &[&str] = &[
    "select", "proc_spawn", "proc_send", "proc_close_stdin", "proc_resize", "proc_recv",
    "proc_select", "proc_status", "proc_kill", "proc_wait", "proc_close", "proc_stats",
    "watch", "watch_recv", "watch_stats", "watch_close",
    "term_recv", "term_size", "term_write", "term_stats", "term_close",
];
/// Sólo wasm (un intérprete embebido no tiene hilos): el nativo puro los conserva.
pub const BUS: &[&str] = &["bus_publish", "bus_subscribe", "bus_recv", "bus_unsubscribe", "bus_topics"];
pub const AGENTS: &[&str] = &["agents", "agent_stop"];
/// Sólo wasm: sin proceso no hay `self_path`, un hijo que spawnear, ni un proceso que apagar
/// (`shutdown()` es el drain ordenado de `synsema serve`).
pub const PROCESS: &[&str] = &["self_path", "run_program", "shutdown"];

/// La tabla del perfil puro NATIVO (`synsema run --profile pure`): (familia, nombres,
/// por qué). Es la fuente de verdad de la tabla "Not in the pure profile" de las docs y
/// del test que la fija.
pub const NATIVE_PURE_TABLE: &[(&str, &[&str], &str)] = &[
    ("filesystem", FS, WHY_NO_FS),
    ("exec", EXEC, WHY_NO_EXEC),
    ("hub/proc", HUB, WHY_NO_HUB),
    ("sockets", SOCKETS, WHY_NO_SOCKETS),
    ("database", DB, WHY_NO_DB),
    ("cron", CRON, WHY_NO_CRON),
];

/// El texto canónico de un stub del perfil puro.
pub fn unavailable_message(name: &str, why: &str, hint: &str) -> String {
    format!("{}: not available in the pure profile — {} ({})", name, why, hint)
}

fn stub_family(interp: &Interpreter, names: &[&'static str], why: &'static str, hint: &'static str) {
    for name in names {
        let name: &'static str = name;
        interp.register_builtin(
            name,
            -1,
            Rc::new(move |_i, _args, _loc| {
                Err(Control::Error(RuntimeError::new(unavailable_message(name, why, hint))))
            }),
        );
    }
}

/// Familias OS-facing que el perfil puro no tiene en NINGÚN host: sockets crudos, DB,
/// cron y el hub de procesos. `term_open` devuelve `nothing`.
pub fn register_os_stubs(interp: &Interpreter, hint: &'static str) {
    interp.register_builtin("term_open", -1, Rc::new(|_i, _args, _loc| Ok(SynValue::Nothing)));
    stub_family(interp, SOCKETS, WHY_NO_SOCKETS, hint);
    stub_family(interp, DB, WHY_NO_DB, hint);
    stub_family(interp, CRON, WHY_NO_CRON, hint);
    stub_family(interp, HUB, WHY_NO_HUB, hint);
}

/// Archivos + `run`: sin filesystem ni procesos hijos. Los builtins de LECTURA de
/// archivos siguen sirviendo del bundle de `synsema build` (es parte del programa, no
/// filesystem); sin bundle fallan con el error puro. `run` y las escrituras siempre fallan.
pub fn register_no_fs_stubs(interp: &Interpreter, hint: &'static str) {
    synsema_capabilities::secure::register_pure_fs(interp, hint);
    stub_family(interp, EXEC, WHY_NO_EXEC, hint);
}

/// Sólo wasm: sin hilos (bus/agentes) ni proceso (`self_path`/`run_program`).
pub fn register_no_threads_stubs(interp: &Interpreter, hint: &'static str) {
    stub_family(interp, BUS, WHY_NO_BUS, hint);
    stub_family(interp, AGENTS, WHY_NO_AGENT_THREADS, hint);
    stub_family(interp, PROCESS, WHY_NO_PROCESS, hint);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_stub_names_are_the_documented_table() {
        // Cada familia tiene nombres, ningún nombre se repite entre familias, y `term_open`
        // NO es un stub que falle (queda fuera de la tabla a propósito).
        let mut seen = std::collections::HashSet::new();
        for (family, names, why) in NATIVE_PURE_TABLE {
            assert!(!names.is_empty(), "{}", family);
            assert!(!why.is_empty());
            for n in *names {
                assert!(seen.insert(*n), "duplicado en la tabla: {}", n);
                assert_ne!(*n, "term_open");
            }
        }
        assert_eq!(
            unavailable_message("sql", WHY_NO_DB, NATIVE_HINT),
            "sql: not available in the pure profile — this run has no database drivers (drop --profile pure to run it natively)"
        );
    }
}

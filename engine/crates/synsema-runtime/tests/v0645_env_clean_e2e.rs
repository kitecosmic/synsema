//! v0.6.45 (A9): `{"env_clean": true}` en `run` y `proc_spawn` — el hijo arranca sin el entorno del
//! padre (sólo lo que el programa pasa en `env`). Y un hallazgo de la tanda: el camino `pty` de
//! `proc_spawn` no quitaba los secretos de Synsema del entorno del hijo (F3 sólo cubría pipes).
//! Binario propio: muta el entorno del proceso.

use synsema_runtime::engine::run_program;

const VISIBLE: &str = "SYNSEMA_V0645_A9_VISIBLE";

fn shell() -> (&'static str, &'static str) {
    if cfg!(windows) { ("cmd", "/C") } else { ("sh", "-c") }
}

fn echo(var: &str) -> String {
    if cfg!(windows) { format!("echo [%{var}%]") } else { format!("echo [${var}]") }
}

/// Lo que imprime el hijo, leyendo los eventos de `proc_spawn` hasta el `exit`.
const DRAIN: &str = r#"task drain(p)
    let out be ""
    let live be true
    while live
        let ev be proc_recv(p, 10)
        when ev == nothing or ev["type"] == "exit"
            set live to false
        otherwise when ev["type"] == "stdout"
            set out to out + text(ev["data"])
    give strip_ansi(out)
"#;

#[test]
fn env_clean_children_do_not_inherit_and_pty_children_do_not_get_secrets() {
    std::env::set_var(VISIBLE, "si");
    std::env::set_var("ANTHROPIC_API_KEY", "sk-v0645-no-debe-salir");
    std::env::set_var("SYNSEMA_ENV_FILE", "");
    let (sh, flag) = shell();
    let src = format!(
        r#"require exec("{sh}")
{DRAIN}
let inherited be run("{sh}", ["{flag}", "{e1}"], 10)
print(contains(inherited["stdout"], "[si]"))
let clean be run("{sh}", ["{flag}", "{e1}"], 10, {{"env_clean": true}})
print(contains(clean["stdout"], "[si]"))
let given be run("{sh}", ["{flag}", "{e2}"], 10, {{"env_clean": true, "env": {{"PASADA": "ok"}}}})
print(contains(given["stdout"], "[ok]"))
let p be proc_spawn("{sh}", ["{flag}", "{e1}"], {{"env_clean": true}})
print(contains(drain(p), "[si]"))
let t be proc_spawn("{sh}", ["{flag}", "{e3}"], {{"pty": true}})
print(contains(drain(t), "sk-v0645"))
"#,
        e1 = echo(VISIBLE),
        e2 = echo("PASADA"),
        e3 = echo("ANTHROPIC_API_KEY"),
    );
    let r = run_program(&src, "<a9>");
    assert!(r.success, "{:?}", r.errors);
    // heredado: sí; limpio: no; pasado explícito: sí; proc_spawn limpio: no; pty con secreto: no.
    assert_eq!(r.output, ["true", "false", "true", "false", "false"], "{:?}", r.output);
}

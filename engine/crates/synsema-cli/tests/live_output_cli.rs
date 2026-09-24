//! v0.6.29 (auditoría, B4): `synsema run` escribe cada línea al momento y en orden — `log`,
//! `show` y `print` por el mismo camino (antes sólo `print` salía en vivo y `log`/`show`
//! aparecían todas al final, desordenadas).

use std::process::Command;

#[test]
fn log_show_print_are_live_and_in_order() {
    let dir = std::env::temp_dir().join(format!("synsema-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("order.syn");
    std::fs::write(&p, "log \"one\"\nprint(\"two\")\nshow \"three\"\nprint(\"four\")\nlog \"five\"\n").unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_synsema")).arg("run").arg(&p).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let text = String::from_utf8_lossy(&o.stdout).replace("\r\n", "\n");
    assert_eq!(text, "[LOG] one\ntwo\nthree\nfour\n[LOG] five\n");
}

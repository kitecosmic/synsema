//! v0.6.46 (E3b): el bin `synsema-wasm` (el de wasip1, acá compilado nativo) toma `--trusted`,
//! `--trusted-cap-set` y `--labels` con las mismas formas que `synsema run`.

use std::path::PathBuf;
use std::process::Command;

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("synsema-wasm-bin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("t.syn"), "export task inicial(c)\n    require declassify(\"clientes\")\n    give declassify(c.nombre, \"la inicial\")\n").unwrap();
    let head = "use \"trusted:t\" as t\nlet c be private({\"nombre\": \"Ana\"}, \"clientes\")\n";
    std::fs::write(d.join("a.syn"), format!("{head}print(t.inicial(c))\n")).unwrap();
    std::fs::write(d.join("b.syn"), format!("{head}print(declassify(c.nombre, \"m\"))\n")).unwrap();
    d
}

fn bin(d: &PathBuf, args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_synsema-wasm")).args(args).current_dir(d).output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

/// v0.6.47 (T1): el comienzo del texto fijo de un corte de etiquetas.
const FIXED: &str = "label_violation: the flow checker stopped the run (private to ";

#[test]
fn e3b_wasip1_bin_takes_trusted_modules() {
    let d = dir();
    let (code, out, err) = bin(&d, &["--labels", "--cap-set", "stdout", "--trusted", "t=t.syn", "a.syn"]);
    assert_eq!((code, out.trim()), (0, "Ana"), "{}", err);
    // Directo, el techo no da `declassify`; con un techo de confianza que no lo nombra, la tool tampoco.
    // v0.6.47 (T1): con techo el programa ve el texto fijo; el motivo no sale por stderr.
    let (code, out, err) = bin(&d, &["--labels", "--cap-set", "stdout", "--trusted", "t=t.syn", "b.syn"]);
    let all = out + &err;
    assert!(code != 0 && all.contains(FIXED) && !all.contains("declassify is not granted"), "{}", all);
    let (code, out, err) = bin(&d, &["--labels", "--cap-set", "stdout", "--trusted", "t=t.syn", "--trusted-cap-set", "stdout", "a.syn"]);
    let all = out + &err;
    assert!(code != 0 && all.contains(FIXED) && !all.contains("declassify is not granted"), "{}", all);
    // Sin techo, el dueño ve el motivo.
    std::fs::write(d.join("c.syn"), "let s be private(1, \"app\")\nwhen s == 1\n    print(\"x\")\n").unwrap();
    let (code, _, err) = bin(&d, &["--labels", "c.syn"]);
    assert!(code != 0 && err.contains("print called under private control flow"), "{}", err);
    let (code, _, err) = bin(&d, &["--labels", "--sandbox", "c.syn"]);
    assert!(code != 0 && err.contains(FIXED) && !err.contains("print called"), "{}", err);
    // `--test` igual: el dueño ve el sitio sin techo y el texto fijo con techo.
    std::fs::write(d.join("tc.syn"), "let s be private(1, \"app\")\ntest \"corte\"\n    when s == 1\n        print(\"x\")\n").unwrap();
    let (code, out, _) = bin(&d, &["--test", "--labels", "tc.syn"]);
    assert!(code != 0 && out.contains("print called under private control flow"), "{}", out);
    let (code, out, _) = bin(&d, &["--test", "--labels", "--sandbox", "tc.syn"]);
    assert!(code != 0 && out.contains(FIXED) && !out.contains("print called"), "{}", out);
    let (code, out, err) = bin(&d, &["--labels", "a.syn"]);
    assert!(code != 0 && (out + &err).contains("no trusted module named 't'"), "{}", err);
    let (code, _, err) = bin(&d, &["--trusted", "sin-ruta", "a.syn"]);
    assert!(code == 2 && err.contains("--trusted takes name=path"), "{}", err);
    let (code, _, err) = bin(&d, &["--trusted-cap-set", "stdout", "a.syn"]);
    assert!(code == 2 && err.contains("pass --trusted"), "{}", err);
}

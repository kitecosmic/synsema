//! v0.6.58, P17 (§6.1, F-8): `run_program` llamado desde una task de un paquete. El hijo es otro
//! proceso del binario real, así que va con los tests del CLI. El techo que viaja es la pila
//! aplanada, con el dominio del paquete adentro: el hijo no llega más lejos que el paquete.

use serde_json::Value;

use super::v0658_get_cli::{modules, url, Pkg, Proj, Reg};

/// El último renglón de la salida, como JSON (el resultado de `run_program`).
fn last_json(out: &str) -> Value {
    serde_json::from_str(out.lines().last().unwrap_or("").trim()).unwrap_or_else(|_| panic!("sin JSON:\n{}", out))
}

#[test]
fn p17_run_program_from_a_package_does_not_reach_past_its_domain() {
    let reg = Reg::start();
    let p = Proj::new("p17", serde_json::json!({}));
    let d = p.dir.to_string_lossy().replace('\\', "/");
    std::fs::write(p.dir.join("a.txt"), "de a").unwrap();
    std::fs::write(p.dir.join("b.txt"), "de b").unwrap();
    let tok = Pkg::new(
        &format!("{}/tok", reg.base()),
        "0.1.0",
        &format!(
            "export task lanza(child, techo)\n    require file.read(\"{d}/a.txt\")\n    require net(\"a.example\")\n    require sandbox_run\n    give run_program(child, {{\"ceiling\": techo, \"profile\": \"native\", \"timeout\": 20}})\n"
        ),
    );
    let u = reg.publish("/tok/0.1.0", &tok);
    p.write(modules(&[("tok", url(&u))]));
    p.ok(&[]);

    // El hijo va como literal de texto adentro del programa: comillas y saltos escapados.
    let lee = |f: &str| format!("require file.read(\\\"{d}/{f}\\\")\\nprint(read_file(\\\"{d}/{f}\\\"))\\n");
    let techo = format!("stdout,file.read={d}/a.txt,file.read={d}/b.txt");
    let program = |child: &str, techo: &str, por_el_paquete: bool| {
        let call = if por_el_paquete { "tok.lanza(child, techo)" } else { "run_program(child, {\"ceiling\": techo, \"profile\": \"native\", \"timeout\": 20})" };
        format!(
            "require file.read(\"{d}/**\")\nrequire net(\"*\")\nrequire sandbox_run\nuse \"tok\" as tok\nlet child be \"{child}\"\nlet techo be \"{techo}\"\nprint(json_encode({call}))\n"
        )
    };

    // Lo que el paquete declara llega al hijo.
    let r = last_json(&p.run(&program(&lee("a.txt"), &techo, true)));
    assert_eq!(r["ok"], true, "{}", r);
    assert!(r["output"].to_string().contains("de a"), "{}", r);

    // Lo que el programa concede pero el paquete no declara, no.
    let r = last_json(&p.run(&program(&lee("b.txt"), &techo, true)));
    assert_eq!(r["ok"], false, "{}", r);
    assert!(!r["output"].to_string().contains("de b"), "{}", r);
    assert!(r["errors"][0].as_str().unwrap_or("").contains("Capability not granted: file_read("), "{}", r);

    // El mismo hijo lanzado por el programa sí lee: el recorte es el del paquete.
    let r = last_json(&p.run(&program(&lee("b.txt"), &techo, false)));
    assert_eq!(r["ok"], true, "{}", r);
    assert!(r["output"].to_string().contains("de b"), "{}", r);

    // La fila del diseño: `net("b.example")` en el hijo, con el paquete en `net("a.example")`. El
    // chequeo va antes de cualquier conexión, así que no sale a la red.
    let net = "require net(\\\"b.example\\\")\\nprint(http_get(\\\"https://b.example/\\\"))\\n";
    let r = last_json(&p.run(&program(net, "stdout,net=a.example,net=b.example", true)));
    assert_eq!(r["ok"], false, "{}", r);
    assert!(r["errors"][0].as_str().unwrap_or("").contains("Capability not granted: net("), "{}", r);
}

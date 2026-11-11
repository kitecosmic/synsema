//! v0.6.58 (§12): el proyecto y los paquetes que pasa el host de wasm-web por `call_json` (W2, W3,
//! W5, W9). Una sola función de test: lo verificado y el contador son de la instancia (del proceso),
//! y otro test en paralelo los movería.

use serde_json::{json, Value};
use synsema_core::modtable::{sha256_hex, tree_hash};
use synsema_wasm_web::call_json;

/// Un paquete: `(índice, archivos)` y su hash de árbol.
fn package(id: &str, version: &str, files: &[(&str, &str)]) -> (String, Value) {
    let entries: Vec<Value> = files.iter().map(|(p, t)| json!({"path": p, "sha256": sha256_hex(t.as_bytes())})).collect();
    let index = serde_json::to_string_pretty(&json!({"id": id, "version": version, "main": "m.syn", "files": entries})).unwrap();
    let index_sha = sha256_hex(index.as_bytes());
    let shas: Vec<(String, String)> = files.iter().map(|(p, t)| (p.to_string(), sha256_hex(t.as_bytes()))).collect();
    let hash = tree_hash(shas.iter().map(|(p, s)| (p.as_str(), s.as_str())).chain(std::iter::once(("synsema.json", index_sha.as_str()))));
    let mut m = serde_json::Map::new();
    m.insert("synsema.json".into(), json!(index));
    for (p, t) in files {
        m.insert(p.to_string(), json!(t));
    }
    (hash, Value::Object(m))
}

fn project(name: &str, id: &str, version: &str, hash: &str) -> String {
    json!({"synsema": "0.6.58", "modules": {name: {"url": format!("https://{}", id), "id": id, "version": version, "hash": hash}}}).to_string()
}

fn call(req: Value) -> Value {
    serde_json::from_str(&call_json(&req.to_string())).unwrap()
}

fn hashed() -> u64 {
    call(json!({"op": "stats"}))["packages_hashed"].as_u64().unwrap()
}

#[test]
fn w2_w3_w5_w9_the_host_passes_the_project_and_its_packages() {
    let src = "use \"tok\" as tok\nprint(tok.cual())\n";
    let (h, files) = package("example.com/tok", "0.1.0", &[("m.syn", "export task cual()\n    give \"tok de wasm\"\n")]);
    let proj = project("tok", "example.com/tok", "0.1.0", &h);

    // W3: sin el paquete en `packages`.
    let r = call(json!({"op": "run", "source": src, "project": proj}));
    assert_eq!(r["ok"], json!(false), "{}", r);
    assert_eq!(r["errors"][0].as_str().unwrap(), "Runtime error: use \"tok\": module tok 0.1.0 is not in the packages the host passed", "{}", r);

    // W2: un byte cambiado, el texto de N13 sin «delete <dir>».
    let mut bad = files.clone();
    bad["m.syn"] = json!("export task cual()\n    give \"tok de wasM\"\n");
    let r = call(json!({"op": "run", "source": src, "project": proj, "packages": {h.clone(): bad}}));
    assert_eq!(r["ok"], json!(false), "{}", r);
    let e = r["errors"][0].as_str().unwrap();
    assert!(e.starts_with("Runtime error: use \"tok\": the files of tok (tree-sha256:") && e.ends_with(") do not match their hash"), "{}", e);
    assert!(!e.contains("delete"), "{}", e);
    assert_eq!(r["packages_held"], json!([]), "{}", r);

    // W2: anda, y el recibo dice qué paquete corrió.
    let before = hashed();
    let r = call(json!({"op": "run", "source": src, "project": proj, "packages": {h.clone(): files.clone()}}));
    assert_eq!(r["ok"], json!(true), "{}", r);
    assert_eq!(r["output"], json!(["tok de wasm"]), "{}", r);
    assert_eq!(r["packages_held"], json!([h.clone()]), "{}", r);
    assert_eq!(hashed(), before + 1);
    // `run` arma la tabla cada vez: con el hash ya verificado, no lo vuelve a hashear.
    for _ in 0..10 {
        let r = call(json!({"op": "run", "source": src, "project": proj, "packages": {h.clone(): files.clone()}}));
        assert_eq!(r["output"], json!(["tok de wasm"]), "{}", r);
    }
    assert_eq!(hashed(), before + 1);

    // W9: cien llamadas más con el mismo `packages` (y otras cien sin mandarlo) no lo vuelven a hashear.
    let handler = "require serve(8080)\nuse \"tok\" as tok\nserve on 8080\n    route \"GET /\"\n        give {\"t\": tok.cual()}\n";
    for i in 0..200 {
        let mut req = json!({"op": "handle", "source": handler, "project": proj, "request": {"method": "GET", "path": "/"}});
        if i < 100 {
            req["packages"] = json!({h.clone(): files.clone()});
        }
        let r = call(req);
        assert_eq!(r["status"], json!(200), "{}", r);
        assert!(r["body"].as_str().unwrap().contains("tok de wasm"), "{}", r);
    }
    assert_eq!(hashed(), before + 1, "one hashing per package");

    // El mismo fuente con otro proyecto es otra app (la cacheada no se reusa).
    let (h2, files2) = package("example.com/tok", "0.2.0", &[("m.syn", "export task cual()\n    give \"tok dos\"\n")]);
    let proj2 = project("tok", "example.com/tok", "0.2.0", &h2);
    let r = call(json!({"op": "handle", "source": handler, "project": proj2, "packages": {h2.clone(): files2}, "request": {"method": "GET", "path": "/"}}));
    assert!(r["body"].as_str().unwrap().contains("tok dos"), "{}", r);
    let r = call(json!({"op": "handle", "source": handler, "project": proj, "request": {"method": "GET", "path": "/"}}));
    assert!(r["body"].as_str().unwrap().contains("tok de wasm"), "{}", r);

    // Los paquetes de la corrida van al recibo y al header sellado.
    let rs = "use \"tok\" as tok\nprint(json_encode(receipt().credentialSubject.modules.packages))\n";
    let r = call(json!({"op": "run", "source": rs, "project": proj, "auditor": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}));
    assert_eq!(r["ok"], json!(true), "{}", r);
    let m: Value = serde_json::from_str(r["output"][0].as_str().unwrap()).unwrap();
    assert_eq!(m["example.com/tok"]["hash"], json!(h.clone()), "{}", r);
    let header = &r["receipt"]["header"];
    assert_eq!(header["modules"]["packages"]["example.com/tok"]["hash"], json!(h.clone()), "{}", r);

    // `packages` sin `project` no tiene a qué atarse.
    let r = call(json!({"op": "run", "source": "print(1)", "packages": {h.clone(): files.clone()}}));
    assert_eq!(r["errors"][0].as_str().unwrap(), "packages: there is no project to use them (pass project, the text of synsema.json)", "{}", r);

    // Sin `project`, `use "tok"` no es un paquete (y lo verificado de antes no lo vuelve uno).
    let r = call(json!({"op": "run", "source": src}));
    assert_eq!(r["ok"], json!(false), "{}", r);

    // Ronda 2 (N-r2-3): toda respuesta del motor dice lo que la instancia guarda (una sin proyecto, un
    // error, `version`, un pedido roto): el host sólo olvida lo guardado cuando no hubo respuesta.
    let held_now = call(json!({"op": "stats"}))["packages_held"].clone();
    assert!(held_now.as_array().is_some_and(|a| a.contains(&json!(h))), "{}", held_now);
    for r in [r, call(json!({"op": "version"})), call(json!({"op": "run", "source": "print(1)"})), call(json!(["no es un objeto"]))] {
        assert_eq!(r["packages_held"], held_now, "{}", r);
    }

    // W5: un proyecto que pide un motor más nuevo.
    let r = call(json!({"op": "run", "source": "print(1)", "project": "{\"synsema\": \"9.9.9\"}"}));
    assert_eq!(r["ok"], json!(false), "{}", r);
    let e = r["errors"][0].as_str().unwrap();
    let needs = format!("this project needs synsema >= 9.9.9; this is {}: synsema update", synsema_core::project::DEV_VERSION);
    assert!(e.contains(&needs), "{}", e);

    // N8 (ronda 1): lo guardado tiene tope en bytes; al terminar una llamada se descartan los menos
    // usados y `packages_held` dice lo que quedó.
    let size = |f: &Value| f.as_object().unwrap().values().map(|v| v.as_str().unwrap().len() as u64).sum::<u64>();
    let s1 = size(&files);
    let (h3, files3) = package("example.com/tok", "0.3.0", &[("m.syn", "export task cual()\n    give \"tok tres\"\n")]);
    let proj3 = project("tok", "example.com/tok", "0.3.0", &h3);
    let r = call(json!({"op": "run", "source": src, "project": proj3, "packages": {h3.clone(): files3.clone()}}));
    assert_eq!(r["output"], json!(["tok tres"]), "{}", r);
    let held: Vec<String> = serde_json::from_value(r["packages_held"].clone()).unwrap();
    assert!(held.contains(&h) && held.contains(&h2) && held.contains(&h3), "{}", r);
    // Con lugar para uno solo, queda el último que se usó.
    synsema_core::modtable::set_host_held_cap(s1.max(size(&files3)));
    let r = call(json!({"op": "run", "source": src, "project": proj}));
    assert_eq!(r["output"], json!(["tok de wasm"]), "{}", r);
    assert_eq!(r["packages_held"], json!([h.clone()]), "{}", r);
    // Lo descartado se vuelve a pedir: sin mandarlo falla; mandándolo anda (y se hashea otra vez).
    let r = call(json!({"op": "run", "source": src, "project": proj3}));
    assert_eq!(r["errors"][0].as_str().unwrap(), "Runtime error: use \"tok\": module tok 0.3.0 is not in the packages the host passed", "{}", r);
    let before = hashed();
    let r = call(json!({"op": "run", "source": src, "project": proj3, "packages": {h3.clone(): files3}}));
    assert_eq!(r["output"], json!(["tok tres"]), "{}", r);
    assert_eq!(r["packages_held"], json!([h3.clone()]), "{}", r);
    assert_eq!(hashed(), before + 1);
    synsema_core::modtable::set_host_held_cap(synsema_core::modtable::MAX_HOST_HELD_BYTES);
}

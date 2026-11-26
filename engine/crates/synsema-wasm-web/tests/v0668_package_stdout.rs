//! v0.6.68: `stdout` bajo el dominio de paquetes en el host wasm (el hook gemelo de `wire_pure`).
//! Una sola función de test: lo verificado y la tabla de paquetes son de la instancia (del proceso),
//! y otro test en paralelo los movería.

use serde_json::{json, Value};
use synsema_core::modtable::{sha256_hex, tree_hash};
use synsema_wasm_web::call_json;

/// El rechazo del paquete que no declara.
const DENIED: &str = "the package mudo does not declare it; add `require stdout` inside its tasks";

/// Un paquete con una task que imprime y un handler: `(hash, archivos)` como los toma `packages`.
fn package(id: &str, decl: &str) -> (String, Value) {
    let files = [(
        "m.syn",
        format!("export task decir()\n{decl}    print(\"PKG\")\nexport task handler()\n{decl}    print(\"PKG-H\")\n    give {{\"said\": \"PKG-H\"}}\n"),
    )];
    let entries: Vec<Value> = files.iter().map(|(p, t)| json!({"path": p, "sha256": sha256_hex(t.as_bytes())})).collect();
    let index = serde_json::to_string_pretty(&json!({"id": id, "version": "0.1.0", "main": "m.syn", "files": entries})).unwrap();
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

fn entry(name: &str, id: &str, hash: &str) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert(name.into(), json!({"url": format!("https://{id}"), "id": id, "version": "0.1.0", "hash": hash}));
    m
}

fn call(req: Value) -> Value {
    serde_json::from_str(&call_json(&req.to_string())).unwrap()
}

#[test]
fn a_package_prints_only_if_it_declares_stdout() {
    let (h_mudo, mudo) = package("example.com/mudo", "");
    let (h_tok, tok) = package("example.com/tok", "    require stdout\n");
    let mut modules = entry("tok", "example.com/tok", &h_tok);
    modules.extend(entry("mudo", "example.com/mudo", &h_mudo));
    let proj = json!({"synsema": "0.6.58", "modules": modules}).to_string();
    let packages = json!({h_tok.clone(): tok.clone(), h_mudo.clone(): mudo.clone()});
    let run = |src: &str| call(json!({"op": "run", "source": src, "project": proj, "packages": packages}));

    // Sin `recover`: nada del paquete sale y lo que seguía no corre.
    let r = run("use \"mudo\" as mudo\nmudo.decir()\nprint(\"after\")\n");
    assert_eq!((r["ok"].clone(), r["output"].clone()), (json!(false), json!([])), "{r}");
    let e = r["errors"][0].as_str().unwrap();
    assert!(e.contains("Capability not granted: stdout") && e.contains(DENIED), "{r}");
    // Atrapable: el programa imprime antes y después con lo suyo.
    let r = run("use \"mudo\" as mudo\nprint(\"one\")\ntry\n    mudo.decir()\nrecover e\n    print(\"caught\")\nprint(\"after\")\n");
    assert_eq!((r["ok"].clone(), r["output"].clone()), (json!(true), json!(["one", "caught", "after"])), "{r}");
    // El que declara imprime cada vez, y el gate se audita una vez por cadena, no por llamada.
    let r = run("use \"tok\" as tok\ntok.decir()\ntok.decir()\nprint(\"after\")\n");
    assert_eq!((r["ok"].clone(), r["output"].clone()), (json!(true), json!(["PKG", "PKG", "after"])), "{r}");
    let asked: Vec<String> = r["audit"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["capability"] == "stdout" && e["source"] == "print()")
        .map(|e| format!("{} {}", e["reason"].as_str().unwrap(), e["granted"]))
        .collect();
    assert_eq!(asked, ["Granted by stdout true"]);
    let r = run("use \"mudo\" as mudo\nuse \"tok\" as tok\ntok.decir()\ntry\n    mudo.decir()\nrecover e\n    print(\"caught\")\ntok.decir()\n");
    let asked: Vec<String> = r["audit"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["capability"] == "stdout" && e["source"] == "print()")
        .map(|e| format!("{} {}", e["reason"].as_str().unwrap(), e["granted"]))
        .collect();
    assert_eq!((r["ok"].clone(), r["output"].clone()), (json!(true), json!(["PKG", "caught", "PKG"])), "{r}");
    assert_eq!(asked, ["Granted by stdout true", "the package mudo does not declare it false"]);

    // Modo handler: un intérprete que se reusa entre requests. Cada request es su unidad de trabajo.
    let handler = "require serve(8080)\nuse \"tok\" as tok\nuse \"mudo\" as mudo\nserve on 8080\n    route \"GET /si\"\n        give tok.handler()\n\n    route \"GET /no\"\n        give mudo.handler()\n";
    for i in 0..12 {
        let loud = i % 2 == 0;
        let r = call(json!({"op": "handle", "source": handler, "project": proj, "packages": packages, "request": {"method": "GET", "path": if loud { "/si" } else { "/no" }, "headers": [], "body": ""}}));
        let logged = r["log"].to_string();
        if loud {
            assert_eq!(r["status"], json!(200), "{r}");
            assert!(r["body"].as_str().unwrap().contains("PKG-H") && logged.contains("PKG-H"), "{r}");
        } else {
            assert_eq!(r["status"], json!(500), "{r}");
            assert!(r["body"].as_str().unwrap().contains(DENIED) && !logged.contains("PKG-H"), "{r}");
        }
    }
}

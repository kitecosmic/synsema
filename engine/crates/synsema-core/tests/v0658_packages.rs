//! v0.6.58 (§4, §5; filas N y K de `specs/v0.6.58-diseno.md`): `use "nombre"`, la tabla del proceso
//! y lo que se revisa adentro de un paquete. Binario propio: fija `SYNSEMA_MODULE_CACHE` (una sola
//! carpeta para todo el binario, con el mismo valor en cada test).
//!
//! Los paquetes se escriben a mano en el caché, como los dejaría `synsema get`: el índice con el
//! sha256 de cada archivo y la carpeta con el hash del árbol.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use synsema_core::interpreter::run_source;
use synsema_core::modtable::{sha256_hex, tree_hash};
use synsema_core::project;

fn cache() -> &'static Path {
    static C: OnceLock<PathBuf> = OnceLock::new();
    C.get_or_init(|| {
        let c = std::env::temp_dir().join(format!("synsema-v0658-cache-{}", std::process::id()));
        std::fs::create_dir_all(&c).unwrap();
        std::env::set_var("SYNSEMA_MODULE_CACHE", &c);
        project::set_owner_check(|_| Ok(true));
        c
    })
}

/// Un paquete en el caché: `files` (ruta, contenido); devuelve el hash del árbol.
fn publish(id: &str, version: &str, main: &str, files: &[(&str, &str)], deps: &str) -> String {
    let cache = cache();
    let entries: Vec<String> = files
        .iter()
        .map(|(p, c)| format!("{{\"path\": \"{}\", \"sha256\": \"{}\"}}", p, sha256_hex(c.as_bytes())))
        .collect();
    let index = format!(
        "{{\"id\": \"{}\", \"version\": \"{}\", \"main\": \"{}\", \"files\": [{}]{}}}",
        id,
        version,
        main,
        entries.join(", "),
        if deps.is_empty() { String::new() } else { format!(", \"modules\": {}", deps) }
    );
    let shas: Vec<(String, String)> = files.iter().map(|(p, c)| (p.to_string(), sha256_hex(c.as_bytes()))).collect();
    let index_sha = sha256_hex(index.as_bytes());
    let hash = tree_hash(
        shas.iter().map(|(p, s)| (p.as_str(), s.as_str())).chain(std::iter::once(("synsema.json", index_sha.as_str()))),
    );
    let dir = cache.join(hash.replacen(':', "-", 1));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("synsema.json"), &index).unwrap();
    for (p, c) in files {
        let f = dir.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, c).unwrap();
    }
    hash
}

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(tag: &str) -> Tree {
        cache();
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        let root = std::env::temp_dir().join(format!("synsema-v0658p-{}-{}-{}", std::process::id(), tag, nanos));
        std::fs::create_dir_all(&root).unwrap();
        Tree { root }
    }
    fn write(&self, rel: &str, content: &str) -> String {
        let p = self.root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().to_string()
    }
    fn dir(&self) -> String {
        self.root.to_string_lossy().to_string()
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn module_entry(name: &str, id: &str, version: &str, hash: &str) -> String {
    format!(
        "\"{}\": {{\"url\": \"{}/{}/synsema.json\", \"id\": \"{}\", \"version\": \"{}\", \"hash\": \"{}\"}}",
        name, id, version, id, version, hash
    )
}

fn project_json(entries: &[String], indirect: &[String]) -> String {
    let mut s = format!("{{\"modules\": {{{}}}", entries.join(", "));
    if !indirect.is_empty() {
        s.push_str(&format!(", \"indirect\": {{{}}}", indirect.join(", ")));
    }
    s.push('}');
    s
}

fn ok(t: &Tree, src: &str) -> Vec<String> {
    let entry = t.write("main.syn", src);
    let r = run_source(src, &entry);
    assert!(r.success, "esperaba éxito: {:?}", r.errors);
    r.output
}

fn fails(t: &Tree, src: &str, needle: &str) {
    let entry = t.write("main.syn", src);
    let r = run_source(src, &entry);
    assert!(!r.success, "esperaba fallo, salida: {:?}", r.output);
    assert!(r.errors.iter().any(|e| e.contains(needle)), "esperaba '{}', got {:?}", needle, r.errors);
}

const TOK_ID: &str = "https://reg.example/tokenizador";

fn tok() -> String {
    publish(
        TOK_ID,
        "0.1.0",
        "tokenizador.syn",
        &[
            ("tokenizador.syn", "use \"./capas.syn\" as capas\nexport task encode(t)\n    give capas.partir(t)\n"),
            ("capas.syn", "export task partir(t)\n    give split(t, \" \")\n"),
        ],
        "",
    )
}

/// N1: `use "tok"` carga `main` desde la tabla; K1: su `use "./capas.syn"` es relativo al paquete.
#[test]
fn n1_k1_a_module_by_name() {
    let t = Tree::new("n1");
    let h = tok();
    t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, "0.1.0", &h)], &[]));
    assert_eq!(ok(&t, "use \"tok\" as tok\nprint(length(tok.encode(\"a b c\")))\n"), vec!["3"]);
}

/// N2: sin `synsema.json`.
#[test]
fn n2_without_synsema_json() {
    let t = Tree::new("n2");
    fails(
        &t,
        "use \"tok\" as tok\n",
        &format!(
            "use \"tok\": a module by name is declared in synsema.json, and there is none in {} or above; add {{\"modules\": {{\"tok\": {{\"url\": \"…\"}}}}}} and run synsema get",
            t.dir()
        ),
    );
}

/// N3: el nombre no está; N4: sin hash; N5: fuera del caché.
#[test]
fn n3_n4_n5_missing_name_hash_or_download() {
    let t = Tree::new("n3");
    t.write("synsema.json", "{\"modules\": {\"otro\": {\"url\": \"https://x.example/o/synsema.json\"}}}");
    fails(
        &t,
        "use \"tok\" as tok\n",
        &format!("use \"tok\": synsema.json ({}) has no module \"tok\"; add it under \"modules\" and run synsema get", t.dir()),
    );
    t.write("synsema.json", "{\"modules\": {\"tok\": {\"url\": \"https://reg.example/tokenizador/0.1.0/synsema.json\"}}}");
    fails(&t, "use \"tok\" as tok\n", "use \"tok\": module tok has no hash yet: run synsema get (it needs the network)");
    let missing = format!("tree-sha256:{}", "ab".repeat(32));
    t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, "0.1.0", &missing)], &[]));
    fails(&t, "use \"tok\" as tok\n", "use \"tok\": module tok 0.1.0 is not downloaded: run synsema get (it needs the network)");
}

/// N6 y N7: una URL o un texto que no es nombre ni ruta.
#[test]
fn n6_n7_not_a_name() {
    let t = Tree::new("n6");
    fails(
        &t,
        "use \"https://x.com/t.syn\" as t\n",
        "use \"https://x.com/t.syn\": a module from a URL goes in synsema.json, not in the code: add {\"modules\": {\"t\": {\"url\": \"https://x.com/t.syn\"}}}, run synsema get, then use \"t\" as t",
    );
    for bad in ["Tok", "a/b", "a.b"] {
        fails(
            &t,
            &format!("use \"{}\" as m\n", bad),
            &format!("use \"{}\": not a module name (lowercase letters, digits, '-' and '_') nor a path to a .syn file", bad),
        );
    }
}

/// N8: un `use "./tok.syn"` del programa y `use "tok"` son dos módulos distintos.
#[test]
fn n8_a_file_and_a_name_are_two_modules() {
    let t = Tree::new("n8");
    let h = tok();
    t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, "0.1.0", &h)], &[]));
    t.write("tok.syn", "export task encode(t)\n    give \"local\"\n");
    assert_eq!(
        ok(&t, "use \"./tok.syn\" as a\nuse \"tok\" as b\nprint(a.encode(\"x y\"))\nprint(length(b.encode(\"x y\")))\n"),
        vec!["local", "2"]
    );
}

/// N10: un `use "tok"` en una rama que no corre, fuera del caché, falla antes de ejecutar.
#[test]
fn n10_checked_before_the_first_statement() {
    let t = Tree::new("n10");
    let missing = format!("tree-sha256:{}", "cd".repeat(32));
    t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, "0.1.0", &missing)], &[]));
    let entry = t.write("main.syn", "print(\"antes\")\nwhen false\n    use \"tok\" as tok\n");
    let r = run_source(&std::fs::read_to_string(&entry).unwrap(), &entry);
    assert!(!r.success);
    assert!(r.output.is_empty(), "no imprime nada de lo anterior: {:?}", r.output);
    assert!(r.errors.iter().any(|e| e.contains("is not downloaded")), "{:?}", r.errors);
}

/// N13: un byte cambiado en el caché.
#[test]
fn n13_a_changed_byte_in_the_cache() {
    let t = Tree::new("n13");
    let h = publish(TOK_ID, "0.2.0", "m.syn", &[("m.syn", "export let v be 1\n")], "");
    t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, "0.2.0", &h)], &[]));
    let dir = cache().join(h.replacen(':', "-", 1));
    std::fs::write(dir.join("m.syn"), "export let v be 2\n").unwrap();
    fails(
        &t,
        "use \"tok\" as tok\nprint(tok.v)\n",
        &format!(
            "use \"tok\": the cached files of tok ({}…) no longer match their hash (changed on disk?); delete {} and run synsema get",
            &h[..16],
            dir.display()
        ),
    );
}

/// N13 (el hash del árbol): el archivo cambiado y el índice del caché reescrito con su sha256
/// coherente. Cada archivo coincide con el índice; lo que no coincide es el árbol con el hash que
/// escribió el proyecto.
#[test]
fn n13_the_tree_hash_with_a_rewritten_index() {
    let t = Tree::new("n13b");
    let h = publish(TOK_ID, "0.2.9", "m.syn", &[("m.syn", "export let v be 13\n")], "");
    t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, "0.2.9", &h)], &[]));
    let dir = cache().join(h.replacen(':', "-", 1));
    let body = "export let v be 14\n";
    std::fs::write(dir.join("m.syn"), body).unwrap();
    let index = format!(
        "{{\"id\": \"{}\", \"version\": \"0.2.9\", \"main\": \"m.syn\", \"files\": [{{\"path\": \"m.syn\", \"sha256\": \"{}\"}}]}}",
        TOK_ID,
        sha256_hex(body.as_bytes())
    );
    std::fs::write(dir.join("synsema.json"), index).unwrap();
    fails(
        &t,
        "use \"tok\" as tok\nprint(tok.v)\n",
        &format!(
            "use \"tok\": the cached files of tok ({}…) no longer match their hash (changed on disk?); delete {} and run synsema get",
            &h[..16],
            dir.display()
        ),
    );
}

/// N14: el paquete pide un motor más nuevo.
#[test]
fn n14_the_package_needs_a_newer_engine() {
    let t = Tree::new("n14");
    let cache = cache();
    // El índice con `synsema` adentro: se arma a mano (publish no lo escribe).
    let body = "export let v be 1\n";
    let index = format!(
        "{{\"id\": \"{}\", \"version\": \"0.2.0\", \"main\": \"m.syn\", \"synsema\": \"99.0.0\", \"files\": [{{\"path\": \"m.syn\", \"sha256\": \"{}\"}}]}}",
        TOK_ID,
        sha256_hex(body.as_bytes())
    );
    let index_sha = sha256_hex(index.as_bytes());
    let body_sha = sha256_hex(body.as_bytes());
    let h = tree_hash([("m.syn", body_sha.as_str()), ("synsema.json", index_sha.as_str())]);
    let dir = cache.join(h.replacen(':', "-", 1));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("synsema.json"), &index).unwrap();
    std::fs::write(dir.join("m.syn"), body).unwrap();
    t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, "0.2.0", &h)], &[]));
    fails(
        &t,
        "use \"tok\" as tok\n",
        &format!("module tok (0.2.0) needs synsema >= 99.0.0; this is {}: synsema update", project::DEV_VERSION),
    );
}

/// K2: `../` no sale del paquete; K3: lo que no está en `files` no existe (aunque esté en el disco).
#[test]
fn k2_k3_the_package_is_the_boundary() {
    let t = Tree::new("k2");
    let h = publish(TOK_ID, "0.3.0", "m.syn", &[("m.syn", "export task f()\n    use \"../x.syn\" as x\n    give x.v\n")], "");
    t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, "0.3.0", &h)], &[]));
    t.write("x.syn", "export let v be 1\n");
    fails(&t, "use \"tok\" as tok\nprint(tok.f())\n", "module path escapes the package: '../x.syn'");
    let h = publish(TOK_ID, "0.3.1", "m.syn", &[("m.syn", "export task f()\n    use \"./otro.syn\" as o\n    give o.v\n")], "");
    std::fs::write(cache().join(h.replacen(':', "-", 1)).join("otro.syn"), "export let v be 1\n").unwrap();
    t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, "0.3.1", &h)], &[]));
    fails(&t, "use \"tok\" as tok\nprint(tok.f())\n", "module not found: ./otro.syn");
}

/// K4: `use "bpe"` adentro de `tok` carga la versión que eligió el proyecto; N17: un `id` que el
/// proyecto no escribió.
#[test]
fn k4_n17_dependencies_follow_the_project() {
    let t = Tree::new("k4");
    let bpe_id = "https://reg.example/bpe-core";
    let b030 = publish(bpe_id, "0.3.0", "b.syn", &[("b.syn", "export let v be \"0.3.0\"\n")], "");
    let b031 = publish(bpe_id, "0.3.1", "b.syn", &[("b.syn", "export let v be \"0.3.1\"\n")], "");
    let deps = format!("{{{}}}", module_entry("bpe", bpe_id, "0.3.0", &b030));
    let h = publish(TOK_ID, "0.4.0", "m.syn", &[("m.syn", "use \"bpe\" as bpe\nexport let v be bpe.v\n")], &deps);
    let ind = format!(
        "\"{}\": {{\"url\": \"{}/0.3.1/synsema.json\", \"version\": \"0.3.1\", \"hash\": \"{}\"}}",
        bpe_id, bpe_id, b031
    );
    t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, "0.4.0", &h)], &[ind]));
    assert_eq!(ok(&t, "use \"tok\" as tok\nprint(tok.v)\n"), vec!["0.3.1"]);
    t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, "0.4.0", &h)], &[]));
    fails(
        &t,
        "use \"tok\" as tok\n",
        "use \"bpe\" in tok: the dependency https://reg.example/bpe-core is not in synsema.json: run synsema get",
    );
}

/// K5, K6, K37 y el `require` no literal: lo que `get` no habría instalado, con el caché alterado a
/// mano, lo rechaza el cargador antes de ejecutar.
#[test]
fn k5_k6_k37_what_a_package_cannot_have() {
    let cases: [(&str, &str); 5] = [
        ("when true\n    require net(\"x.example\")\nexport let v be 1\n", "has a 'require' outside a task (m.syn:2)"),
        ("serve on 8080\n    route \"GET /x\"\n        give 1\n", "must not contain a 'serve' block"),
        (
            "use \"trusted:t\" as t\nexport let v be 1\n",
            "tok: use \"trusted:t\" in m.syn: a package cannot use the host's trusted tools; the program passes it a callback instead",
        ),
        (
            "let h be \"x.example\"\nexport task pedir()\n    require net(h)\n    give 1\n",
            "tok: require net(h) in task pedir is not a literal; a package declares its capabilities with literals so they can be reviewed",
        ),
        ("test \"t\"\n    require net(\"x.example\")\n", "has a 'require' inside a test block"),
    ];
    for (i, (body, needle)) in cases.iter().enumerate() {
        let t = Tree::new(&format!("k5-{}", i));
        let h = publish(TOK_ID, &format!("0.5.{}", i), "m.syn", &[("m.syn", body)], "");
        t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, &format!("0.5.{}", i), &h)], &[]));
        let entry = t.write("main.syn", "print(\"antes\")\nuse \"tok\" as tok\n");
        let r = run_source(&std::fs::read_to_string(&entry).unwrap(), &entry);
        assert!(!r.success, "{}: esperaba fallo", needle);
        assert!(r.output.is_empty(), "antes de ejecutar: {:?}", r.output);
        assert!(r.errors.iter().any(|e| e.contains(needle)), "esperaba '{}', got {:?}", needle, r.errors);
    }
}

/// K31: desde el programa, ninguna escritura llega a las exportaciones de un paquete (por su nombre,
/// por un alias, por un argumento, adentro de un mapa, anidada o religando); K38: una copia leída de
/// una exportación se escribe sin tocar el paquete. Desde adentro, el paquete escribe su estado.
#[test]
fn k31_k38_a_package_exports_are_read_only_from_outside() {
    let t = Tree::new("k31");
    let h = publish(
        "https://reg.example/vocab",
        "0.1.0",
        "v.syn",
        &[(
            "v.syn",
            "export let VOCAB be {\"a\": 1}\nexport let N be 0\nexport task ver(k)\n    give VOCAB[k]\nexport task contar()\n    set N to N + 1\n    set VOCAB[\"b\"] to N\n    give N\nexport task encode(x)\n    give x\n",
        )],
        "",
    );
    t.write("synsema.json", &project_json(&[module_entry("tok", "https://reg.example/vocab", "0.1.0", &h)], &[]));
    let ro = |what: &str| format!("set tok.{}: a package's exports are read-only; its code is fixed by its hash", what);
    for (src, what) in [
        ("set tok.encode to (x) => x\n", "encode"),
        ("set tok.VOCAB[\"a\"] to 9\n", "VOCAB"),
        ("set tok.VOCAB to {}\n", "VOCAB"),
        ("let m be tok\nset m.VOCAB[\"a\"] to 9\n", "VOCAB"),
        ("let m be tok\nset m.VOCAB to {}\n", "VOCAB"),
        ("task tocar(mod)\n    set mod.VOCAB[\"a\"] to 9\ntocar(tok)\n", "VOCAB"),
        ("let caja be {\"t\": tok}\nset caja[\"t\"].VOCAB[\"a\"] to 9\n", "VOCAB"),
        ("set tok[\"N\"] to 5\n", "N"),
        ("set tok.VOCAB to merge(tok.VOCAB, {\"z\": 1})\n", "VOCAB"),
        // El lugar único con índice sobre el mapa del módulo (`with_unique_place`, brazo `IndexAccess`).
        ("set tok[\"VOCAB\"] to merge(tok[\"VOCAB\"], {\"z\": 1})\n", "VOCAB"),
    ] {
        fails(&t, &format!("use \"tok\" as tok\n{}", src), &ro(what));
    }
    // K38 y el paquete por dentro.
    assert_eq!(
        ok(&t, "use \"tok\" as tok\nlet v be tok.VOCAB\nset v[\"a\"] to 9\nprint(tok.ver(\"a\"))\nprint(v[\"a\"])\nprint(tok.contar())\nprint(tok.contar())\nprint(tok.N)\nprint(tok.ver(\"b\"))\n"),
        vec!["1", "9", "1", "2", "2", "2"]
    );
}

/// N2 (ronda 1): K2 da su texto sin prefijo; K5 nombra el paquete por su `main` y el lugar por el
/// archivo donde está el `require`.
#[test]
fn n2_k2_k5_texts() {
    let t = Tree::new("n2");
    let h = publish(TOK_ID, "0.9.0", "m.syn", &[("m.syn", "export task f()\n    use \"../x.syn\" as x\n    give x.v\n")], "");
    t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, "0.9.0", &h)], &[]));
    let entry = t.write("main.syn", "use \"tok\" as tok\nprint(tok.f())\n");
    let r = run_source("use \"tok\" as tok\nprint(tok.f())\n", &entry);
    assert!(!r.success);
    assert!(r.errors.iter().any(|e| e.contains("module path escapes the package: '../x.syn'") && !e.contains("pkg:")), "{:?}", r.errors);
    let h = publish(
        TOK_ID,
        "0.9.1",
        "tokenizador.syn",
        &[("tokenizador.syn", "use \"./capas.syn\" as capas\nexport let v be 1\n"), ("capas.syn", "require net(\"x.example\")\nexport let w be 2\n")],
        "",
    );
    t.write("synsema.json", &project_json(&[module_entry("tok", TOK_ID, "0.9.1", &h)], &[]));
    fails(&t, "use \"tok\" as tok\n", "/tokenizador.syn' has a 'require' outside a task (capas.syn:1)");
}

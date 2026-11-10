//! v0.6.58 (§6; filas K de `specs/v0.6.58-diseno.md`): todo código escrito en un paquete corre con
//! el `requires` del paquete ∩ lo vigente. Con el modelo de capabilities real (el runtime).
//!
//! Los paquetes se escriben a mano en el caché, como los dejaría `synsema get`. `SYNSEMA_MODULE_CACHE`
//! es del proceso: una sola carpeta para todo el binario, con el mismo valor en cada test.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use synsema_core::modtable::{sha256_hex, tree_hash};
use synsema_runtime::engine::run_source;

fn cache() -> &'static Path {
    static C: OnceLock<PathBuf> = OnceLock::new();
    C.get_or_init(|| {
        let c = std::env::temp_dir().join(format!("synsema-v0658a-cache-{}", std::process::id()));
        std::fs::create_dir_all(&c).unwrap();
        std::env::set_var("SYNSEMA_MODULE_CACHE", &c);
        c
    })
}

/// Un paquete en el caché; devuelve su hash. `deps` es el objeto `modules` del índice (o vacío).
fn publish(id: &str, version: &str, main: &str, files: &[(&str, &str)], deps: &str) -> String {
    let cache = cache();
    let entries: Vec<String> =
        files.iter().map(|(p, c)| format!("{{\"path\": \"{}\", \"sha256\": \"{}\"}}", p, sha256_hex(c.as_bytes()))).collect();
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
        std::fs::write(dir.join(p), c).unwrap();
    }
    hash
}

fn entry(name: &str, id: &str, version: &str, hash: &str) -> String {
    format!("\"{}\": {{\"url\": \"{}/{}/synsema.json\", \"id\": \"{}\", \"version\": \"{}\", \"hash\": \"{}\"}}", name, id, version, id, version, hash)
}

pub struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(tag: &str, modules: &[String], indirect: &[String]) -> Tree {
        cache();
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        let root = std::env::temp_dir().join(format!("synsema-v0658a-{}-{}-{}", std::process::id(), tag, nanos));
        std::fs::create_dir_all(&root).unwrap();
        let mut json = format!("{{\"modules\": {{{}}}", modules.join(", "));
        if !indirect.is_empty() {
            json.push_str(&format!(", \"indirect\": {{{}}}", indirect.join(", ")));
        }
        json.push('}');
        std::fs::write(root.join("synsema.json"), json).unwrap();
        std::fs::write(root.join("dato.txt"), "secreto").unwrap();
        Tree { root }
    }
    /// La carpeta con `/` (va adentro de literales de Synsema).
    fn dir(&self) -> String {
        self.root.to_string_lossy().replace('\\', "/")
    }
    pub fn run(&self, src: &str) -> synsema_core::interpreter::RunResult {
        let entry = self.root.join("main.syn");
        std::fs::write(&entry, src).unwrap();
        run_source(src, &entry.to_string_lossy())
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

const TOK: &str = "https://reg.example/tok";

fn errors(r: &synsema_core::interpreter::RunResult) -> String {
    r.errors.join("\n")
}

/// Un paquete `tok` con estas fuentes en `m.syn` (y el `main` en `m.syn`).
fn tok_tree(tag: &str, src: &str) -> Tree {
    let h = publish(TOK, "0.1.0", "m.syn", &[("m.syn", src)], "");
    Tree::new(tag, &[entry("tok", TOK, "0.1.0", &h)], &[])
}

/// K8: una task del paquete sin `require` no usa lo que el programa concedió.
#[test]
pub fn k8_a_package_task_without_require_cannot_use_what_the_program_granted() {
    let t = tok_tree("k8", "export task leer(p)\n    give read_file(p)\n");
    let d = t.dir();
    let r = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nprint(read_file(\"{d}/dato.txt\"))\nprint(tok.leer(\"{d}/dato.txt\"))\n"));
    assert!(!r.success, "{:?}", r.output);
    assert_eq!(r.output, vec!["secreto".to_string()], "el programa lee; el paquete no");
    assert!(errors(&r).contains("Capability not granted") && errors(&r).contains("the package tok does not declare it"), "{}", errors(&r));
}

/// K7 + K11: el dominio es el paquete entero (la unión de sus `require`), y sólo resta: sin la
/// concesión del programa, nada.
#[test]
fn k7_k11_the_domain_is_the_whole_package_and_only_takes_away() {
    // El dominio nombra la carpeta del árbol: el paquete se arma con la ruta real.
    let t = Tree::new("k11", &[], &[]);
    let d = t.dir();
    let src = format!("task privada()\n    require file.read(\"{d}/**\")\n    give 1\nexport task leer(p)\n    give read_file(p)\n");
    let h = publish(TOK, "0.1.1", "m.syn", &[("m.syn", &src)], "");
    std::fs::write(t.root.join("synsema.json"), format!("{{\"modules\": {{{}}}}}", entry("tok", TOK, "0.1.1", &h))).unwrap();
    let ok = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nprint(tok.leer(\"{d}/dato.txt\"))\n"));
    assert!(ok.success, "{}", errors(&ok));
    assert_eq!(ok.output, vec!["secreto".to_string()]);
    // K7: el programa no lo concede.
    let no = t.run(&format!("use \"tok\" as tok\nprint(tok.leer(\"{d}/dato.txt\"))\n"));
    assert!(!no.success && errors(&no).contains("Capability not granted"), "{}", errors(&no));
}

/// K8c: el nivel superior del paquete corre con un dominio vacío.
#[test]
fn k8c_the_top_level_of_a_package_has_an_empty_domain() {
    let t = Tree::new("k8c-dir", &[], &[]);
    let d = t.dir();
    let h = publish(TOK, "0.1.2", "m.syn", &[("m.syn", &format!("export let V be read_file(\"{d}/dato.txt\")\n"))], "");
    std::fs::write(t.root.join("synsema.json"), format!("{{\"modules\": {{{}}}}}", entry("tok", TOK, "0.1.2", &h))).unwrap();
    let r = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nprint(tok.V)\n"));
    assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "{}", errors(&r));
}

/// K8c con `require`: el paquete declara `file.read` en una task. La task lee (su dominio es el
/// paquete entero); el nivel superior del mismo paquete no (su dominio es vacío, no el del paquete).
#[test]
fn k8c_the_top_level_does_not_take_the_package_domain() {
    let t = Tree::new("k8c-req", &[], &[]);
    let d = t.dir();
    let task = format!("export task leer(p)\n    require file.read(\"{d}/**\")\n    give read_file(p)\n");
    let h = publish(TOK, "0.8.0", "m.syn", &[("m.syn", &task)], "");
    std::fs::write(t.root.join("synsema.json"), format!("{{\"modules\": {{{}}}}}", entry("tok", TOK, "0.8.0", &h))).unwrap();
    let ok = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nprint(tok.leer(\"{d}/dato.txt\"))\n"));
    assert!(ok.success, "{}", errors(&ok));
    assert_eq!(ok.output, vec!["secreto".to_string()]);
    let top = format!("{task}export let V be read_file(\"{d}/dato.txt\")\n");
    let h = publish(TOK, "0.8.1", "m.syn", &[("m.syn", &top)], "");
    std::fs::write(t.root.join("synsema.json"), format!("{{\"modules\": {{{}}}}}", entry("tok", TOK, "0.8.1", &h))).unwrap();
    let r = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nprint(tok.V)\n"));
    assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "{} {:?}", errors(&r), r.output);
}

/// K12: una lambda del programa que el paquete llama corre con la intersección.
#[test]
pub fn k12_a_program_callback_called_by_the_package_runs_with_the_intersection() {
    let t = tok_tree("k12", "export task llamar(f)\n    give f()\n");
    let d = t.dir();
    let r = t.run(&format!(
        "require file.read(\"{d}/**\")\nuse \"tok\" as tok\nprint(tok.llamar(() => \"sin leer\"))\nprint(tok.llamar(() => read_file(\"{d}/dato.txt\")))\n"
    ));
    assert_eq!(r.output, vec!["sin leer".to_string()]);
    assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "{}", errors(&r));
    // Al volver, el programa lee como antes (no quedó nada apilado).
    let r = t.run(&format!(
        "require file.read(\"{d}/**\")\nuse \"tok\" as tok\ntry\n    print(tok.llamar(() => read_file(\"{d}/dato.txt\")))\nrecover e\n    print(\"no\")\nprint(read_file(\"{d}/dato.txt\"))\n"
    ));
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output.last().map(String::as_str), Some("secreto"));
}

/// K14 + K21: una lambda escrita en el paquete lleva su marca por donde salga (devuelta o en una
/// exportación) y corre en su dominio.
#[test]
pub fn k14_k21_a_lambda_written_in_the_package_keeps_its_domain() {
    let t = tok_tree("k14", "export let CB be nothing\nexport task hacer(p)\n    set CB to () => read_file(p)\n    give () => read_file(p)\n");
    let d = t.dir();
    let r = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nlet f be tok.hacer(\"{d}/dato.txt\")\nprint(f())\n"));
    assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "{}", errors(&r));
    let r = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nlet f be tok.hacer(\"{d}/dato.txt\")\nprint(tok.CB())\n"));
    assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "{}", errors(&r));
}

/// K19: un `require` adentro de un paquete no concede nada, y después el programa tampoco tiene
/// lo que no concedió.
#[test]
fn k19_a_require_inside_a_package_grants_nothing() {
    let t = Tree::new("k19-dir", &[], &[]);
    let d = t.dir();
    let h = publish(
        TOK,
        "0.1.3",
        "m.syn",
        &[("m.syn", &format!("export task leer(p)\n    when true\n        require file.read(\"{d}/**\")\n    give read_file(p)\n"))],
        "",
    );
    std::fs::write(t.root.join("synsema.json"), format!("{{\"modules\": {{{}}}}}", entry("tok", TOK, "0.1.3", &h))).unwrap();
    let r = t.run(&format!(
        "use \"tok\" as tok\ntry\n    print(tok.leer(\"{d}/dato.txt\"))\nrecover e\n    print(\"adentro no\")\nprint(read_file(\"{d}/dato.txt\"))\n"
    ));
    assert_eq!(r.output, vec!["adentro no".to_string()]);
    assert!(!r.success && errors(&r).contains("Capability not granted"), "{}", errors(&r));
}

/// K15: un paquete que llama a otro: la intersección de los dos dominios.
#[test]
fn k15_a_package_calling_another_takes_both_domains() {
    let t = Tree::new("k15-dir", &[], &[]);
    let d = t.dir();
    let bpe_id = "https://reg.example/bpe";
    let hb = publish(bpe_id, "0.3.0", "b.syn", &[("b.syn", "export task leer(p)\n    give read_file(p)\n")], "");
    let deps = format!("{{{}}}", entry("bpe", bpe_id, "0.3.0", &hb));
    let ht = publish(
        TOK,
        "0.1.4",
        "m.syn",
        &[("m.syn", &format!("use \"bpe\" as bpe\nexport task leer(p)\n    require file.read(\"{d}/**\")\n    give bpe.leer(p)\n"))],
        &deps,
    );
    std::fs::write(
        t.root.join("synsema.json"),
        format!(
            "{{\"modules\": {{{}}}, \"indirect\": {{\"{}\": {{\"url\": \"{}/0.3.0/synsema.json\", \"version\": \"0.3.0\", \"hash\": \"{}\"}}}}}}",
            entry("tok", TOK, "0.1.4", &ht),
            bpe_id,
            bpe_id,
            hb
        ),
    )
    .unwrap();
    let r = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nprint(tok.leer(\"{d}/dato.txt\"))\n"));
    // Un paquete transitivo se nombra por su `id` (§5.2: no tiene nombre directo en el proyecto).
    assert!(!r.success && errors(&r).contains("the package https://reg.example/bpe does not declare it"), "{}", errors(&r));
}

/// K15 al revés: el de adentro (`bpe`) declara `file.read` y el de afuera (`tok`) no. La llamada
/// de `tok` a `bpe` sigue negada: el dominio de `bpe` se apila sobre el de `tok`, no lo reemplaza.
#[test]
fn k15_the_inner_package_does_not_widen_the_outer() {
    let t = Tree::new("k15b-dir", &[], &[]);
    let d = t.dir();
    let bpe_id = "https://reg.example/bpe-k15b";
    let hb = publish(bpe_id, "0.3.0", "b.syn", &[("b.syn", &format!("export task leer(p)\n    require file.read(\"{d}/**\")\n    give read_file(p)\n"))], "");
    let deps = format!("{{{}}}", entry("bpe", bpe_id, "0.3.0", &hb));
    let ht = publish(TOK, "0.8.2", "m.syn", &[("m.syn", "use \"bpe\" as bpe\nexport task leer(p)\n    give bpe.leer(p)\n")], &deps);
    std::fs::write(
        t.root.join("synsema.json"),
        format!(
            "{{\"modules\": {{{}}}, \"indirect\": {{\"{}\": {{\"url\": \"{}/0.3.0/synsema.json\", \"version\": \"0.3.0\", \"hash\": \"{}\"}}}}}}",
            entry("tok", TOK, "0.8.2", &ht),
            bpe_id,
            bpe_id,
            hb
        ),
    )
    .unwrap();
    let r = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nprint(tok.leer(\"{d}/dato.txt\"))\n"));
    assert!(!r.success && errors(&r).contains("Capability not granted"), "{} {:?}", errors(&r), r.output);
    assert!(r.output.is_empty(), "{:?}", r.output);
}

/// La VM: un bucle caliente del programa que llama a la task del paquete (pasa el umbral de
/// compilación) sigue cruzando en cada llamada.
#[test]
pub fn a_hot_loop_of_the_program_still_crosses_into_the_package() {
    let t = tok_tree("vm", "export task doble(x)\n    give x * 2\nexport task leer(p)\n    give read_file(p)\n");
    let d = t.dir();
    let r = t.run(&format!(
        "require file.read(\"{d}/**\")\nuse \"tok\" as tok\ntask vuelta(n)\n    let s be 0\n    each i in range(0, n)\n        set s to s + tok.doble(i)\n    give s\nlet total be 0\neach k in range(0, 50)\n    set total to total + vuelta(20)\nprint(total)\nprint(tok.leer(\"{d}/dato.txt\"))\n"
    ));
    assert_eq!(r.output, vec!["19000".to_string()]);
    assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "{}", errors(&r));
}

/// K23: lo que corre después no se agenda con un paquete en la pila.
#[test]
fn k23_cron_after_inside_a_package() {
    let t = tok_tree("k23", "export task agendar(f)\n    give cron_after(1, f)\nexport task nada()\n    give 1\n");
    let r = t.run("use \"tok\" as tok\nprint(tok.agendar(tok.nada))\n");
    assert!(
        !r.success && errors(&r).contains("cron_after: not allowed inside the package tok — the task would run later without the package's limits"),
        "{}",
        errors(&r)
    );
}

/// K24: un paquete no define ni lanza agentes.
#[test]
fn k24_a_package_cannot_spawn_agents() {
    let t = tok_tree("k24", "export task lanzar(f)\n    give f()\n");
    let r = t.run("agent A\n    print(\"hola\")\nuse \"tok\" as tok\ntask lanzar_a()\n    spawn A\n    give 1\nprint(tok.lanzar(lanzar_a))\n");
    assert!(!r.success && errors(&r).contains("agent 'A': a package cannot define or spawn agents"), "{}", errors(&r));
}

/// M8 y B1 (ronda 1): lo mismo desde un worker de `parallel_map` que el paquete llamó, con un callback
/// del programa: ahí el dominio llegó como delegación y la pila de paquetes del worker está vacía.
#[test]
fn m8_b1_a_worker_called_by_the_package_is_inside_the_package() {
    let t = tok_tree("m8", "export task por_worker(f)\n    give parallel_map(f, [1])\n");
    let r = t.run("agent A\n    print(\"agente corrio\")\nuse \"tok\" as tok\ntask lanzar(x)\n    spawn A\n    give \"lanzado\"\nprint(tok.por_worker(lanzar))\n");
    assert!(!r.success && errors(&r).contains("agent 'A': a package cannot define or spawn agents"), "{} {:?}", errors(&r), r.output);
    assert!(!r.output.iter().any(|l| l.contains("agente corrio")), "{:?}", r.output);
    let r = t.run("use \"tok\" as tok\ntask tarde(x)\n    give \"t\"\ntask agenda(x)\n    cron_after(1, tarde)\n    give \"agendado\"\nprint(tok.por_worker(agenda))\n");
    assert!(
        !r.success && errors(&r).contains("cron_after: not allowed inside the package tok — the task would run later without the package's limits"),
        "{}",
        errors(&r)
    );
    // Sin el paquete, el mismo worker lanza el agente.
    let r = t.run("agent A\n    print(\"agente corrio\")\ntask lanzar(x)\n    spawn A\n    give \"lanzado\"\nprint(parallel_map(lanzar, [1]))\n");
    assert!(r.success, "{}", errors(&r));
}

/// K25: una task de paquete cruza a un worker de `parallel_map` con su marca: anda, y adentro del
/// worker el dominio es el del paquete.
#[test]
fn k25_a_package_task_in_parallel_map() {
    let t = tok_tree("k25", "export task doble(x)\n    give x * 2\nexport task leer(p)\n    give read_file(p)\n");
    let d = t.dir();
    let r = t.run("use \"tok\" as tok\nprint(parallel_map(tok.doble, [1, 2, 3]))\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, vec!["[2, 4, 6]".to_string()]);
    let r = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nprint(parallel_map(tok.leer, [\"{d}/dato.txt\"]))\n"));
    assert!(!r.success && errors(&r).contains("Capability not granted"), "{} {:?}", errors(&r), r.output);
}

/// K25 (el otro lado): si el paquete declara la lectura y el programa la concede, en el worker anda;
/// el rechazo de arriba es el del dominio, no un worker sin permisos.
#[test]
fn k25_the_worker_keeps_the_program_grant_inside_the_domain() {
    let t = Tree::new("k25b", &[], &[]);
    let d = t.dir();
    let h = publish(TOK, "0.1.5", "m.syn", &[("m.syn", &format!("export task leer(p)\n    require file.read(\"{d}/**\")\n    give read_file(p)\n"))], "");
    std::fs::write(t.root.join("synsema.json"), format!("{{\"modules\": {{{}}}}}", entry("tok", TOK, "0.1.5", &h))).unwrap();
    let r = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nprint(parallel_map(tok.leer, [\"{d}/dato.txt\"]))\n"));
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, vec!["[\"secreto\"]".to_string()]);
}

/// Un archivo en el directorio actual mientras dura el test (las plantillas del programa se leen de
/// ahí). Cada test usa su propio nombre.
pub struct CwdFile(PathBuf);

impl CwdFile {
    pub fn new(name: &str, text: &str) -> CwdFile {
        let p = std::env::current_dir().unwrap().join(name);
        std::fs::write(&p, text).unwrap();
        CwdFile(p)
    }
}

impl Drop for CwdFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Un paquete `tok` con `m.syn` y sus plantillas.
pub fn tok_tree_files(tag: &str, files: &[(&str, &str)]) -> Tree {
    let h = publish(TOK, "0.2.0", "m.syn", files, "");
    Tree::new(tag, &[entry("tok", TOK, "0.2.0", &h)], &[])
}

/// K10: `render` adentro del paquete usa su plantilla, sin `file.read` y aunque el directorio
/// actual tenga otra con el mismo nombre.
#[test]
fn k10_a_package_renders_its_own_template_without_file_read() {
    let _f = CwdFile::new("v0658-k10-vista.html", "DEL PROGRAMA");
    let t = tok_tree_files(
        "k10",
        &[
            ("m.syn", "export task ver(n)\n    give body of render(\"v0658-k10-vista.html\", {\"n\": n})\n"),
            ("v0658-k10-vista.html", "DEL PAQUETE { n }"),
        ],
    );
    let r = t.run("use \"tok\" as tok\nprint(tok.ver(7))\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, vec!["DEL PAQUETE 7".to_string()]);
}

/// K17: un nombre calculado que no está en el paquete da `template not found`; no lee el disco.
#[test]
fn k17_a_computed_name_not_in_the_package_is_not_found() {
    let _f = CwdFile::new("v0658-k17-otra.html", "DEL PROGRAMA");
    let t = tok_tree_files("k17", &[("m.syn", "export task ver(n)\n    give body of render(n)\n"), ("vista.html", "x")]);
    let r = t.run("require file.read(\"**\")\nuse \"tok\" as tok\nprint(tok.ver(\"v0658-k17-otra.html\"))\n");
    assert!(!r.success && errors(&r).contains("template not found: v0658-k17-otra.html"), "{} {:?}", errors(&r), r.output);
}

/// K16: una plantilla del programa que hace `layout` de una del paquete no la encuentra (el programa
/// no ve los archivos del paquete).
#[test]
fn k16_a_program_template_cannot_layout_a_package_template() {
    let _f = CwdFile::new("v0658-k16-pagina.html", "{ layout \"v0658-k16-base.html\" }hola");
    let t = tok_tree_files("k16", &[("m.syn", "export let X be 1\n"), ("v0658-k16-base.html", "<b>{ slot }</b>")]);
    let r = t.run("require file.read(\"**\")\nuse \"tok\" as tok\nprint(body of render(\"v0658-k16-pagina.html\"))\n");
    assert!(!r.success && errors(&r).contains("template not found: v0658-k16-base.html"), "{} {:?}", errors(&r), r.output);
}

/// K28: el entorno de una plantilla del paquete es la base del paquete: no ve el `helper` del
/// programa, sí lo del paquete.
#[test]
fn k28_a_package_template_does_not_see_the_program() {
    let t = tok_tree_files(
        "k28",
        &[
            ("m.syn", "task propio(x)\n    give x + 100\nexport task ver(t)\n    give body of render(t)\n"),
            ("con_helper.html", "{ helper(1) }"),
            ("con_propio.html", "{ propio(1) } { upper(\"a\") }"),
        ],
    );
    let r = t.run("use \"tok\" as tok\ntask helper(x)\n    give \"DEL PROGRAMA\"\nprint(tok.ver(\"con_propio.html\"))\nprint(tok.ver(\"con_helper.html\"))\n");
    assert_eq!(r.output, vec!["101 A".to_string()], "{}", errors(&r));
    assert!(!r.success && errors(&r).contains("Undefined variable: 'helper'"), "{}", errors(&r));
}

/// K29: un `include` en una plantilla del paquete que nombra una del programa da `template not found`.
#[test]
fn k29_a_package_include_does_not_reach_the_program() {
    let _f = CwdFile::new("v0658-k29-header.html", "DEL PROGRAMA");
    let t = tok_tree_files(
        "k29",
        &[("m.syn", "export task ver()\n    give body of render(\"pagina.html\")\n"), ("pagina.html", "{ include \"v0658-k29-header.html\" }")],
    );
    let r = t.run("require file.read(\"**\")\nuse \"tok\" as tok\nprint(tok.ver())\n");
    assert!(!r.success && errors(&r).contains("template not found: v0658-k29-header.html"), "{} {:?}", errors(&r), r.output);
}

/// K27: un callback del programa que renderiza adentro de una task del paquete usa la plantilla del
/// programa, con el gate `file.read` y la intersección: el paquete no lo declara, así que se niega;
/// nunca sale la del paquete. Fuera del paquete, el mismo callback anda.
#[test]
fn k27_a_program_callback_renders_the_program_template_with_the_intersection() {
    let _f = CwdFile::new("v0658-k27-vista.html", "DEL PROGRAMA");
    let t = tok_tree_files(
        "k27",
        &[("m.syn", "export task llamar(f)\n    give f()\n"), ("v0658-k27-vista.html", "DEL PAQUETE")],
    );
    let r = t.run(
        "require file.read(\"**\")\nuse \"tok\" as tok\nlet cb be () => body of render(\"v0658-k27-vista.html\")\nprint(cb())\nprint(tok.llamar(cb))\n",
    );
    assert_eq!(r.output, vec!["DEL PROGRAMA".to_string()], "{}", errors(&r));
    assert!(!r.success && errors(&r).contains("Capability not granted") && errors(&r).contains("the package tok does not declare it"), "{}", errors(&r));
}

// Las filas que dependen del modo (VM, tree-walker de referencia, nivel nativo, etiquetas): acá
// corren en la VM; `tests/v0658_attenuation_modes.rs` las repite en los otros modos, en orden.
// Usan `file.read` en lugar de la red: el chequeo es el mismo y no depende del DNS.

/// K32: `apply`, `where` y `reduce` del programa con una task del paquete: cruza (K8).
#[test]
pub fn k32_apply_where_reduce_cross_into_the_package() {
    let t = tok_tree("k32", "export task f(p)\n    give read_file(p)\nexport task g(acc, p)\n    give read_file(p)\nexport task ok(x)\n    give x * 2\n");
    let d = t.dir();
    let ok = t.run("use \"tok\" as tok\nprint(apply([1, 2], tok.ok))\n");
    assert!(ok.success, "{}", errors(&ok));
    assert_eq!(ok.output, vec!["[2, 4]".to_string()]);
    for call in [
        format!("apply([\"{d}/dato.txt\"], tok.f)"),
        format!("where([\"{d}/dato.txt\"], tok.f)"),
        format!("reduce([\"{d}/dato.txt\"], (acc, p) => tok.f(p), 0)"),
    ] {
        let r = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nprint({call})\n"));
        assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "{call}: {} {:?}", errors(&r), r.output);
    }
    let r = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nprint(reduce([\"{d}/dato.txt\"], tok.g, 0))\n"));
    assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "reduce directo: {} {:?}", errors(&r), r.output);
}

/// K35: la lambda del default de un parámetro del paquete lleva la marca del paquete, la llame
/// quien la llame (directo, por `apply` y en un bucle caliente).
#[test]
pub fn k35_a_default_lambda_of_the_package_keeps_its_mark() {
    let t = Tree::new("k35", &[], &[]);
    let d = t.dir();
    let h = publish(TOK, "0.3.5", "m.syn", &[("m.syn", &format!("export task f(x = 0, cb = () => read_file(\"{d}/dato.txt\"))\n    give cb\n"))], "");
    std::fs::write(t.root.join("synsema.json"), format!("{{\"modules\": {{{}}}}}", entry("tok", TOK, "0.3.5", &h))).unwrap();
    for (how, get) in [
        ("directo", "let cb be tok.f()"),
        ("apply", "let cb be apply([1], tok.f)[0]"),
        ("bucle", "let cb be nothing\neach i in range(0, 300)\n    set cb to tok.f()"),
    ] {
        let r = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\n{get}\nprint(cb())\n"));
        assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "{how}: {} {:?}", errors(&r), r.output);
    }
}

fn k40_tree(tag: &str) -> (Tree, String) {
    let t = Tree::new(tag, &[], &[]);
    let d = t.dir();
    let src = format!(
        "export task t(cb)\n    cb()\n    give () => read_file(\"{d}/dato.txt\")\n\
         export task t_req(cb)\n    cb()\n    task otra()\n        require file.read(\"{d}/otro/**\")\n        give read_file(\"{d}/dato.txt\")\n    give otra\n\
         export task t_tpl(cb)\n    cb()\n    give () => body of render(\"v0658-k40-vista.html\")\n\
         export task t_rec(cb)\n    try\n        cb()\n    recover e\n        print(\"atrapado\")\n    give () => read_file(\"{d}/dato.txt\")\n\
         export task primero(xs)\n    each x in xs\n        give x\n    give nothing\n\
         export task fib(n)\n    when n < 2\n        give n\n    give fib(n - 1) + fib(n - 2)\n"
    );
    let h = publish(TOK, "0.4.0", "m.syn", &[("m.syn", &src), ("v0658-k40-vista.html", "DEL PAQUETE")], "");
    std::fs::write(t.root.join("synsema.json"), format!("{{\"modules\": {{{}}}}}", entry("tok", TOK, "0.4.0", &h))).unwrap();
    (t, d)
}

/// K40: después de llamar directo a un callback del programa, la task sigue en el dominio del
/// paquete: la lambda que devuelve no lee, su `require` no concede (dos veces) y su plantilla es la
/// del paquete.
#[test]
pub fn k40_after_a_direct_callback_the_package_is_still_running() {
    let (t, d) = k40_tree("k40");
    let _f = CwdFile::new("v0658-k40-vista.html", "DEL PROGRAMA");
    let pre = format!("require file.read(\"{d}/**\")\nrequire file.read(\"**\")\nuse \"tok\" as tok\ntask cb()\n    give 1\n");
    let r = t.run(&format!("{pre}let f be tok.t(cb)\nprint(f())\n"));
    assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "lambda: {} {:?}", errors(&r), r.output);
    let r = t.run(&format!("{pre}let f be tok.t_req(cb)\ntry\n    print(f())\nrecover e\n    print(\"no\")\nprint(f())\n"));
    assert_eq!(r.output, vec!["no".to_string()], "{}", errors(&r));
    assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "require: {}", errors(&r));
    let r = t.run(&format!("{pre}let f be tok.t_tpl(cb)\nprint(f())\n"));
    assert!(r.success, "plantilla: {}", errors(&r));
    assert_eq!(r.output, vec!["DEL PAQUETE".to_string()]);
}

/// K41: un callback del programa que lanza un error que el paquete atrapa: después, lo mismo de K40.
#[test]
pub fn k41_after_a_caught_error_of_the_callback_the_package_is_still_running() {
    let (t, d) = k40_tree("k41");
    let r = t.run(&format!(
        "require file.read(\"{d}/**\")\nuse \"tok\" as tok\ntask malo()\n    raise \"boom\"\nlet f be tok.t_rec(malo)\nprint(f())\n"
    ));
    assert_eq!(r.output, vec!["atrapado".to_string()], "{}", errors(&r));
    assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "{}", errors(&r));
}

/// K42 + K43: un `give` adentro de un `each` del paquete y una recursión del paquete devuelven la
/// pila como estaba: el programa sigue leyendo con lo suyo (marca 0, ningún techo de más).
#[test]
pub fn k42_k43_the_program_is_restored_after_give_in_a_loop_and_recursion() {
    let (t, d) = k40_tree("k42");
    let r = t.run(&format!(
        "require file.read(\"{d}/**\")\nuse \"tok\" as tok\neach i in range(0, 3)\n    print(tok.primero([i, 9]))\nprint(tok.fib(15))\nlet g be () => read_file(\"{d}/dato.txt\")\nprint(g())\nprint(read_file(\"{d}/dato.txt\"))\n"
    ));
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, vec!["0", "1", "2", "610", "secreto", "secreto"].into_iter().map(String::from).collect::<Vec<_>>());
}

/// Las filas que se repiten en cada modo (`tests/v0658_attenuation_modes.rs`).
#[allow(dead_code)]
pub const MODES: &[(&str, fn())] = &[
    ("k8", k8_a_package_task_without_require_cannot_use_what_the_program_granted),
    ("k12", k12_a_program_callback_called_by_the_package_runs_with_the_intersection),
    ("k14_k21", k14_k21_a_lambda_written_in_the_package_keeps_its_domain),
    ("k32", k32_apply_where_reduce_cross_into_the_package),
    ("k35", k35_a_default_lambda_of_the_package_keeps_its_mark),
    ("k40", k40_after_a_direct_callback_the_package_is_still_running),
    ("k41", k41_after_a_caught_error_of_the_callback_the_package_is_still_running),
    ("k42_k43", k42_k43_the_program_is_restored_after_give_in_a_loop_and_recursion),
    ("vm", a_hot_loop_of_the_program_still_crosses_into_the_package),
    ("k36_k36b", k36_k36b_hot_calls_into_the_package_cross_every_time),
    ("k40_k42_vm", k40_k42_with_the_package_compiled),
    ("k41_unwind", k41_a_package_frame_that_leaves_without_leave_pkg_is_undone),
];

/// El paquete de K30 (la corre `tests/v0658_attenuation_modes.rs`, con etiquetas).
#[allow(dead_code)]
pub fn k30_tree() -> Tree {
    tok_tree_files("k30", &[("m.syn", "export task largo(x)\n    give length(x)\nexport task decir()\n    print(\"x\")\n")])
}

mod serve_rows {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    fn free_port() -> u16 {
        TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
    }

    fn wait_ready(port: u16) {
        for _ in 0..120 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                std::thread::sleep(Duration::from_millis(150));
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("el server no quedó listo en :{}", port);
    }

    fn get(port: u16, target: &str, headers: &str) -> String {
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        sock.write_all(format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Connection: close\r\n\r\n", target, headers).as_bytes()).unwrap();
        let mut buf = Vec::new();
        let _ = sock.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Arranca el `serve` del árbol (el programa en `main.syn`) en un hilo.
    fn serve(t: &Tree, port: u16, src: String) {
        let entry = t.root.join("main.syn");
        std::fs::write(&entry, &src).unwrap();
        let entry = entry.to_string_lossy().into_owned();
        std::thread::spawn(move || {
            let _ = synsema_runtime::serve::run_serve_program(&src, &entry, false);
        });
        wait_ready(port);
    }

    /// K34 + K25: una ruta montada del paquete y un handler que llama a `tok.handler` corren en el
    /// dominio del paquete (500 con `Capability not granted`); lo que el paquete no toca anda.
    #[test]
    fn k34_k25_mounted_routes_and_a_package_handler_run_in_the_domain() {
        let t = Tree::new("k34", &[], &[]);
        let d = t.dir();
        let src = format!(
            "export routes rutas\n    route \"GET /pkg/leer\"\n        give {{\"t\": read_file(\"{d}/dato.txt\")}}\n    route \"GET /pkg/ok\"\n        give {{\"ok\": 1}}\n\
             export task handler(p)\n    give {{\"t\": read_file(p)}}\n"
        );
        let h = publish(TOK, "0.5.0", "m.syn", &[("m.syn", &src)], "");
        std::fs::write(t.root.join("synsema.json"), format!("{{\"modules\": {{{}}}}}", entry("tok", TOK, "0.5.0", &h))).unwrap();
        let port = free_port();
        serve(
            &t,
            port,
            format!(
                "require serve({port})\nrequire file.read(\"{d}/**\")\nuse \"tok\" as tok\nserve on {port}\n    mount tok.rutas\n\
                 \n    route \"GET /prog\"\n        give {{\"t\": read_file(\"{d}/dato.txt\")}}\n\
                 \n    route \"GET /h\"\n        give tok.handler(\"{d}/dato.txt\")\n"
            ),
        );
        let r = get(port, "/pkg/ok", "");
        assert!(r.starts_with("HTTP/1.1 200"), "{}", r);
        let r = get(port, "/prog", "");
        assert!(r.starts_with("HTTP/1.1 200") && r.contains("secreto"), "{}", r);
        for path in ["/pkg/leer", "/h"] {
            let r = get(port, path, "");
            assert!(r.starts_with("HTTP/1.1 500") && r.contains("Capability not granted"), "{path}: {}", r);
            assert!(!r.contains("secreto"), "{path}: {}", r);
        }
    }

    /// K26: el techo de un captoken y el dominio del paquete se intersecan: el paquete declara una
    /// carpeta que el token no delega, y el programa concede las dos → no se lee. Sin el token, el
    /// mismo handler lee. Con `sandbox under` en lugar del token, lo mismo.
    #[test]
    fn k26_a_captoken_ceiling_and_the_package_domain_intersect() {
        let t = Tree::new("k26", &[], &[]);
        let d = t.dir();
        std::fs::create_dir_all(t.root.join("b")).unwrap();
        std::fs::write(t.root.join("b").join("x.txt"), "de b").unwrap();
        let src = format!("export task leer_b()\n    require file.read(\"{d}/b/*\")\n    give read_file(\"{d}/b/x.txt\")\n");
        let h = publish(TOK, "0.5.1", "m.syn", &[("m.syn", &src)], "");
        std::fs::write(t.root.join("synsema.json"), format!("{{\"modules\": {{{}}}}}", entry("tok", TOK, "0.5.1", &h))).unwrap();
        let port = free_port();
        serve(
            &t,
            port,
            format!(
                "require serve({port})\nrequire random\nrequire file.read(\"{d}/**\")\nuse \"tok\" as tok\n\
                 let root be \"root-key-de-prueba\"\n\
                 task check(token, request)\n    give captoken_verify(token, root, {{\"aud\": \"k26\"}})\n\
                 task probar()\n    try\n        give {{\"t\": tok.leer_b()}}\n    recover e\n        give {{\"e\": text(e)}}\n\
                 serve on {port}\n    auth with check\n\
                 \n    route \"GET /token\"\n        give {{\"t\": captoken_mint({{\"file.read\": \"{d}/a/*\"}}, root, {{\"aud\": \"k26\", \"ttl\": 600, \"id\": \"k26\"}})}}\n\
                 \n    route \"GET /sin\"\n        give probar()\n\
                 \n    route \"GET /con\" requires auth\n        give probar()\n\
                 \n    route \"GET /sandbox\"\n        sandbox under {{\"file.read\": \"{d}/a/*\"}}\n            give probar()\n"
            ),
        );
        let r = get(port, "/sin", "");
        assert!(r.contains("de b"), "sin techo, el paquete lee lo que declara: {}", r);
        let tok_resp = get(port, "/token", "");
        let token = tok_resp.split("\"t\": \"").nth(1).and_then(|s| s.split('"').next()).unwrap_or_else(|| panic!("{}", tok_resp)).to_string();
        let r = get(port, "/con", &format!("Authorization: Bearer {}\r\n", token));
        assert!(!r.contains("de b") && r.contains("Capability not granted"), "con el token: {}", r);
        let r = get(port, "/sandbox", "");
        assert!(!r.contains("de b") && r.contains("Capability not granted"), "con sandbox under: {}", r);
    }
}

/// K25b: `parallel_map` llamado adentro de una task del paquete, con una lambda del paquete: cada
/// item corre con la pila de techos de la llamada (K8 en el item). Y las exportaciones siguen siendo
/// de sólo lectura en el worker (K31).
#[test]
fn k25b_parallel_map_inside_the_package_keeps_the_domain() {
    let t = tok_tree(
        "k25b",
        "export let VOCAB be {\"a\": 1}\nexport task todos(ps)\n    give parallel_map((p) => read_file(p), ps)\nexport task dobles(xs)\n    give parallel_map((x) => x * 2, xs)\n",
    );
    let d = t.dir();
    let r = t.run("use \"tok\" as tok\nprint(tok.dobles([1, 2]))\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, vec!["[2, 4]".to_string()]);
    let r = t.run(&format!("require file.read(\"{d}/**\")\nuse \"tok\" as tok\nprint(tok.todos([\"{d}/dato.txt\"]))\n"));
    assert!(!r.success && errors(&r).contains("Capability not granted"), "{} {:?}", errors(&r), r.output);
    let r = t.run("use \"tok\" as tok\ntask tocar(x)\n    set tok.VOCAB[\"a\"] to x\n    give x\nprint(parallel_map(tocar, [9]))\n");
    assert!(!r.success && errors(&r).contains("a package's exports are read-only"), "{} {:?}", errors(&r), r.output);
}

/// K36 + K36b + VM caliente: el programa llama miles de veces a una task del paquete (directo y por
/// un alias), con la VM y el nivel nativo compilando: cada llamada cruza (cada lectura se niega) y
/// una que no toca nada da el mismo resultado.
#[test]
pub fn k36_k36b_hot_calls_into_the_package_cross_every_time() {
    let t = tok_tree(
        "k36",
        "export task codificar(x)\n    give x * 2 + 1\nexport task leer(p, de_verdad)\n    when de_verdad\n        give read_file(p)\n    give 1\n",
    );
    let d = t.dir();
    let r = t.run("use \"tok\" as tok\nlet enc be tok.codificar\nlet a be 0\nlet b be 0\neach i in range(0, 3000)\n    set a to a + enc(i)\n    set b to b + tok.codificar(i)\nprint(a)\nprint(b)\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, vec!["9000000".to_string(), "9000000".to_string()]);
    // El mismo sitio caliente del bucle (el `Call` de la VM, sin `try` alrededor, que es del
    // tree-walker), miles de veces sin leer y la última leyendo: la lectura se niega.
    for (how, call) in [("alias", "leer"), ("directo", "tok.leer")] {
        let r = t.run(&format!(
            "require file.read(\"{d}/**\")\nuse \"tok\" as tok\nlet leer be tok.leer\nlet n be 0\neach i in range(0, 3000)\n    set n to n + {call}(\"{d}/dato.txt\", i == 2999)\nprint(n)\n"
        ));
        assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "{how}: {} {:?}", errors(&r), r.output);
        assert!(r.output.is_empty(), "{how}: {:?}", r.output);
    }
}

/// K40–K42 con las tasks del paquete ya compiladas (la VM compila en la segunda llamada): el
/// callback del programa, el error atrapado y el `give` adentro de un `each` restauran todo.
#[test]
pub fn k40_k42_with_the_package_compiled() {
    let (t, d) = k40_tree("k40vm");
    let _f = CwdFile::new("v0658-k40-vista.html", "DEL PROGRAMA");
    let pre = format!("require file.read(\"{d}/**\")\nrequire file.read(\"**\")\nuse \"tok\" as tok\ntask cb()\n    give 1\ntask malo()\n    raise \"boom\"\n");
    let warm = "each i in range(0, 5)\n    tok.t(cb)\n    tok.t_req(cb)\n    tok.t_tpl(cb)\n    tok.primero([i])\n";
    let r = t.run(&format!("{pre}{warm}let f be tok.t(cb)\nprint(f())\n"));
    assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "lambda: {} {:?}", errors(&r), r.output);
    let r = t.run(&format!("{pre}{warm}let f be tok.t_tpl(cb)\nprint(f())\n"));
    assert!(r.success, "plantilla: {}", errors(&r));
    assert_eq!(r.output, vec!["DEL PAQUETE".to_string()]);
    let r = t.run(&format!("{pre}{warm}each i in range(0, 4)\n    tok.t_rec(malo)\nprint(read_file(\"{d}/dato.txt\"))\nlet g be tok.t_rec(malo)\nprint(g())\n"));
    assert_eq!(r.output.iter().filter(|l| *l == "atrapado").count(), 5, "{:?} {}", r.output, errors(&r));
    assert!(r.output.contains(&"secreto".to_string()), "el programa lee después: {:?}", r.output);
    assert!(!r.success && errors(&r).contains("the package tok does not declare it"), "{}", errors(&r));
    let r = t.run(&format!(
        "{pre}{warm}each i in range(0, 50)\n    tok.primero([i, 9])\nprint(tok.fib(18))\nlet g be () => read_file(\"{d}/dato.txt\")\nprint(g())\n"
    ));
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, vec!["2584".to_string(), "secreto".to_string()]);
}

/// El paquete de K36c: un bucle adentro del paquete que llama a una task privada.
#[allow(dead_code)]
pub fn k36c_tree() -> Tree {
    tok_tree_files(
        "k36c",
        &[("m.syn", "task paso(x)\n    give x + 1\nexport task cod(x)\n    give x * 2 + 1\nexport task encode(n)\n    let s be 0\n    let i be 0\n    while i < n\n        set s to paso(s)\n        set i to i + 1\n    give s\n")],
    )
}

/// K41 (el desapilado en la VM): un chunk del paquete que entró por el `Call` de la VM y sale sin
/// su `LeavePkg` —un error que el programa atrapa más arriba, o un `give` adentro de un `try` del
/// paquete (sale de un nodo del tree-walker)— deja todo como estaba: el programa sigue leyendo. Con
/// `por_dentro`, el error nace en una task del paquete llamada por otra del paquete: el frame que
/// cruzó es el de afuera, y el error lo atraviesa (por `envoltura2`: el `try` llama por el
/// tree-walker, que cruza solo; la task del programa llama por el `Call` de la VM).
#[test]
pub fn k41_a_package_frame_that_leaves_without_leave_pkg_is_undone() {
    let t = tok_tree(
        "k41u",
        "export task por_dentro(x)\n    give falla(x)\nexport task falla(x)\n    when x > 2\n        raise \"boom\"\n    give x\nexport task en_try(x)\n    try\n        give x + 1\n    recover e\n        give 0\n",
    );
    let d = t.dir();
    let r = t.run(&format!(
        "require file.read(\"{d}/**\")\nuse \"tok\" as tok\ntask envoltura(x)\n    give tok.falla(x)\ntask envoltura2(x)\n    give tok.por_dentro(x)\n\
         each i in range(0, 6)\n    try\n        envoltura(i)\n    recover e\n        print(\"atrapado\")\n\
         print(read_file(\"{d}/dato.txt\"))\n\
         each i in range(0, 5)\n    try\n        envoltura2(i)\n    recover e\n        print(\"adentro\")\n\
         print(read_file(\"{d}/dato.txt\"))\n\
         let s be 0\neach i in range(0, 50)\n    set s to s + tok.en_try(i)\nprint(s)\nprint(read_file(\"{d}/dato.txt\"))\n"
    ));
    assert!(r.success, "{} {:?}", errors(&r), r.output);
    let want = ["atrapado", "atrapado", "atrapado", "secreto", "adentro", "adentro", "secreto", "1275", "secreto"];
    assert_eq!(r.output, want.into_iter().map(String::from).collect::<Vec<_>>());
}

/// B18 (ronda 1): `direct` del recibo lleva los nombres que usa el programa (§13). Un paquete que el
/// proyecto declara pero el programa alcanza sólo por otro no entra; pasarlo a `indirect` (mismo hash)
/// no cambia el recibo.
#[test]
fn b18_direct_holds_only_the_names_the_program_uses() {
    let bpe_id = "https://reg.example/bpe";
    let hb = publish(bpe_id, "0.3.2", "b.syn", &[("b.syn", "export task n()\n    give 7\n")], "");
    let deps = format!("{{{}}}", entry("bpe", bpe_id, "0.3.2", &hb));
    let ht = publish(TOK, "0.1.8", "m.syn", &[("m.syn", "use \"bpe\" as bpe\nexport task n()\n    give bpe.n()\n")], &deps);
    let both = Tree::new("b18-both", &[entry("tok", TOK, "0.1.8", &ht), entry("bpe", bpe_id, "0.3.2", &hb)], &[]);
    let ind = Tree::new(
        "b18-ind",
        &[entry("tok", TOK, "0.1.8", &ht)],
        &[format!("\"{}\": {{\"url\": \"{}/0.3.2/synsema.json\", \"version\": \"0.3.2\", \"hash\": \"{}\"}}", bpe_id, bpe_id, hb)],
    );
    let src = "use \"tok\" as tok\nprint(tok.n())\n";
    // Corre (y el motor instala el chequeo de dueño del proyecto).
    let r = both.run(src);
    assert!(r.success && r.output == vec!["7"], "{}", errors(&r));
    let of =|t: &Tree, src: &str| {
        let e = t.root.join("main.syn");
        std::fs::write(&e, src).unwrap();
        synsema_core::modtable::run_modules_of(src, &e.to_string_lossy()).unwrap().unwrap().to_json()
    };
    let a = of(&both, src);
    assert_eq!(a["direct"], serde_json::json!({"tok": TOK}), "{}", a);
    assert_eq!(a, of(&ind, src));
    // Si el programa usa los dos, los dos son directos.
    let a = of(&both, "use \"tok\" as tok\nuse \"bpe\" as bpe\nprint(tok.n() + bpe.n())\n");
    assert_eq!(a["direct"], serde_json::json!({"bpe": bpe_id, "tok": TOK}), "{}", a);
}

/// N6 (ronda 1): `code` sigue un `use "bpe"` escrito en un archivo de `tok` (en el caché) hasta la
/// versión que eligió el proyecto (`indirect`), no la que escribió el índice de `tok`.
#[test]
fn n6_code_follows_the_project_selection_inside_a_package() {
    let bpe_id = "https://reg.example/bpe";
    let b0 = publish(bpe_id, "0.4.0", "b.syn", &[("b.syn", "export let v be 0\n")], "");
    let b1 = publish(bpe_id, "0.4.1", "b.syn", &[("b.syn", "export let v be 1\n")], "");
    let deps = format!("{{{}}}", entry("bpe", bpe_id, "0.4.0", &b0));
    let ht = publish(TOK, "0.2.0", "m.syn", &[("m.syn", "use \"bpe\" as bpe\nexport let v be bpe.v\n")], &deps);
    let t = Tree::new(
        "n6",
        &[entry("tok", TOK, "0.2.0", &ht)],
        &[format!("\"{}\": {{\"url\": \"{}/0.4.1/synsema.json\", \"version\": \"0.4.1\", \"hash\": \"{}\"}}", bpe_id, bpe_id, b1)],
    );
    let r = t.run("use \"tok\" as tok\nprint(tok.v)\n");
    assert!(r.success && r.output == vec!["1"], "{}", errors(&r));
    let main = t.root.join("main.syn");
    let tok_file = cache().join(ht.replacen(':', "-", 1)).join("m.syn");
    let (dir, m) = synsema_core::modtable::static_main_path_in(&main.to_string_lossy(), &tok_file.to_string_lossy(), "bpe").unwrap();
    assert_eq!((dir, m.as_str()), (cache().join(b1.replacen(':', "-", 1)), "b.syn"));
    // Desde el programa, el paquete directo.
    let (dir, _) = synsema_core::modtable::static_main_path_in(&main.to_string_lossy(), &main.to_string_lossy(), "tok").unwrap();
    assert_eq!(dir, cache().join(ht.replacen(':', "-", 1)));
}

/// N7 (ronda 1): la tabla no copia los bytes de cada `.syn` para su AST: `parsed` comparte el `Arc`
/// de `files` (un módulo del programa) o de `Package::files` (uno de un paquete).
#[test]
fn n7_parsed_shares_the_bytes() {
    let t = tok_tree("n7", "export let v be 3\n");
    std::fs::write(t.root.join("lib.syn"), "export let w be 4\n").unwrap();
    let src = "use \"tok\" as tok\nuse \"./lib.syn\" as lib\nprint(tok.v + lib.w)\n";
    let r = t.run(src);
    assert!(r.success && r.output == vec!["7"], "{}", errors(&r));
    let main = t.root.join("main.syn");
    let table = synsema_core::modtable::table_for(src, &main.to_string_lossy()).unwrap().unwrap();
    let pkg = &table.packages[0];
    let pkg_bytes = pkg.files.get("m.syn").unwrap();
    let (key, (bytes, _)) = table.parsed.iter().find(|(k, _)| k.starts_with("pkg:")).unwrap();
    assert!(std::ptr::eq(bytes.as_ptr(), pkg_bytes.as_ptr()), "{}", key);
    let (fk, fsrc) = table.files.iter().next().unwrap();
    let (fbytes, _) = &table.parsed[fk];
    assert!(std::ptr::eq(fbytes.as_ptr(), fsrc.as_ptr()), "{}", fk);
}

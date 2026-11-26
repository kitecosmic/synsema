//! v0.6.68: la salida de un paquete necesita `require stdout` dentro de él, además del permiso del
//! programa y del techo del host. `requires nothing` pasa a incluir el silencio.
//!
//! Cada negativa afirma que el marcador no salió y que el error dice `Capability not granted`,
//! `stdout` y el paquete; cada positiva afirma el marcador exacto. Las filas de [`TABLE`] dan lo
//! mismo en la VM, en el tree-walker de referencia, con el nivel nativo y con etiquetas
//! (`tests/v0658_attenuation_modes.rs`). El binario de la CLI mira además los bytes de stderr y el
//! prompt (`synsema-cli/tests/it/v0668_package_stdout_cli.rs`); el host wasm, en
//! `synsema-wasm-web/tests/v0668_package_stdout.rs`.

use synsema_capabilities::model::{Capability, CapabilityType};

use super::v0658_attenuation as pkg;
use pkg::{entry, errors, publish, tok_tree, Tree};

const BASE: &str = "https://reg.example/v0668-";
/// Un paquete que imprime sin declarar `stdout`.
const QUIET: &str = "export task decir()\n    print(\"PKG\")\n";
/// El mismo, declarándolo dentro de la task.
const LOUD: &str = "export task decir()\n    require stdout\n    print(\"PKG\")\n    give 7\n";

/// El rechazo entero de un paquete: nombra `stdout`, el paquete y el `require` que lo arregla.
fn denial(package: &str) -> String {
    format!("Capability not granted: stdout — the package {package} does not declare it; add `require stdout` inside its tasks")
}

fn lines(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

/// Lo que exige toda negativa: falló, el error es el del paquete y el marcador no salió.
fn denied(r: &synsema_core::interpreter::RunResult, package: &str) {
    assert!(!r.success, "tenía que fallar: {:?}", r.output);
    assert!(errors(r).contains(&denial(package)), "{package}: {}", errors(r));
    assert!(!r.output.iter().any(|line| line.contains("PKG")), "{package}: salió el marcador: {:?}", r.output);
}

/// Dos paquetes en el proyecto: `si` declara `stdout` en su task, `no` no. El dominio es el
/// paquete entero, así que un paquete que a veces calla y a veces imprime son dos paquetes.
fn two_packages(tag: &str) -> Tree {
    let (si, no) = (format!("{BASE}si"), format!("{BASE}no"));
    let h_si = publish(&si, "0.1.0", "m.syn", &[("m.syn", "export task decir()\n    require stdout\n    print(\"PKG-SI\")\n")], "");
    let h_no = publish(&no, "0.1.0", "m.syn", &[("m.syn", "export task decir()\n    print(\"PKG-NO\")\n")], "");
    Tree::new(tag, &[entry("si", &si, "0.1.0", &h_si), entry("no", &no, "0.1.0", &h_no)], &[])
}

/// Un proyecto con `tok` (su `m.syn` declara `f`, cuyo cuerpo es `body`) que usa `bpe` (su `b.syn`
/// es `inner`), sólo alcanzable a través de `tok`. Devuelve el árbol y el `id` de `bpe`: un
/// paquete transitivo se nombra por su `id`.
fn nested(tag: &str, body: &str, inner: &str) -> (Tree, String) {
    let inner_id = format!("{BASE}bpe-{tag}");
    let hi = publish(&inner_id, "0.3.0", "b.syn", &[("b.syn", inner)], "");
    let deps = format!("{{{}}}", entry("bpe", &inner_id, "0.3.0", &hi));
    let outer_id = format!("{BASE}tok-{tag}");
    let ho = publish(&outer_id, "0.1.0", "m.syn", &[("m.syn", &format!("use \"bpe\" as bpe\nexport task f()\n{body}"))], &deps);
    let indirect = format!("\"{}\": {{\"url\": \"{}/0.3.0/synsema.json\", \"version\": \"0.3.0\", \"hash\": \"{}\"}}", inner_id, inner_id, hi);
    (Tree::new(tag, &[entry("tok", &outer_id, "0.1.0", &ho)], &[indirect]), inner_id)
}

/// Programa imprime; el paquete sin declaración intenta; `recover`; el programa imprime de nuevo.
/// Después, sin `recover`: sale lo de antes del error y nada del paquete.
fn row_prints_before_and_after() {
    let t = tok_tree("v0668-antes-despues", QUIET);
    let caught = format!("atrapado: {}", denial("tok"));
    let r = t.run("use \"tok\" as tok\nprint(\"uno\")\ntry\n    tok.decir()\nrecover e\n    print(\"atrapado: \" + text(e))\nprint(\"dos\")\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["uno", &caught, "dos"]));
    let r = t.run("use \"tok\" as tok\nprint(\"uno\")\ntry\n    tok.decir()\nrecover e\n    print(\"atrapado\")\nprint(\"dos\")\ntok.decir()\nprint(\"tres\")\n");
    denied(&r, "tok");
    assert_eq!(r.output, lines(&["uno", "atrapado", "dos"]));
}

/// El paquete que declara `stdout` imprime, cada vez que se lo llama.
fn row_a_package_that_declares_prints() {
    let t = tok_tree("v0668-declara", LOUD);
    let r = t.run("use \"tok\" as tok\nprint(\"uno\")\ntok.decir()\nprint(tok.decir())\nprint(\"dos\")\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["uno", "PKG", "PKG", "7", "dos"]));
}

/// El permiso del programa (el de ambiente bajo `run`, o un `require stdout` explícito) no llega a
/// un paquete que no lo declara: rechazo antes de emitir, y lo que seguía no corre.
fn row_the_program_grant_does_not_reach_an_undeclared_package() {
    let t = tok_tree("v0668-sin-declarar", QUIET);
    for preamble in ["", "require stdout\n"] {
        let r = t.run(&format!("{preamble}use \"tok\" as tok\ntok.decir()\nprint(\"despues\")\n"));
        denied(&r, "tok");
        assert!(r.output.is_empty(), "{preamble:?}: {:?}", r.output);
    }
}

/// Dos paquetes sucesivos, en los dos órdenes: cada uno recibe su propio veredicto, y el de uno
/// no se le pega al otro ni al programa.
fn row_two_packages_each_get_their_own_verdict() {
    let t = two_packages("v0668-dos");
    let catch = "try\n    no.decir()\nrecover e\n    print(\"no: \" + text(e))\n";
    let no = format!("no: {}", denial("no"));
    let r = t.run(&format!("use \"si\" as si\nuse \"no\" as no\n{catch}si.decir()\n{catch}si.decir()\n"));
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&[&no, "PKG-SI", &no, "PKG-SI"]));
    let r = t.run(&format!("use \"si\" as si\nuse \"no\" as no\nsi.decir()\n{catch}si.decir()\n{catch}"));
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["PKG-SI", &no, "PKG-SI", &no]));
}

/// Paquetes anidados: rige la intersección. El de afuera manda aunque el de adentro declare, y el
/// de adentro no se apoya en el de afuera.
fn row_nested_packages_intersect() {
    let call = "use \"tok\" as tok\ntry\n    tok.f()\nrecover e\n    print(\"e: \" + text(e))\nprint(\"fin\")\n";
    let loud = "export task g()\n    require stdout\n    print(\"PKG-IN\")\n";
    let quiet = "export task g()\n    print(\"PKG-IN\")\n";
    let (t, _) = nested("v0668-nido-1", "    give bpe.g()\n", loud);
    let r = t.run(call);
    let e = format!("e: {}", denial("tok"));
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&[&e, "fin"]));
    let (t, inner) = nested("v0668-nido-2", "    require stdout\n    print(\"PKG-OUT\")\n    give bpe.g()\n", quiet);
    let r = t.run(call);
    let e = format!("e: {}", denial(&inner));
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["PKG-OUT", &e, "fin"]));
    let (t, _) = nested("v0668-nido-3", "    require stdout\n    print(\"PKG-OUT\")\n    give bpe.g()\n", loud);
    let r = t.run(call);
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["PKG-OUT", "PKG-IN", "fin"]));
}

/// Un callback del programa llamado desde el paquete corre con la intersección: si el paquete no
/// declara `stdout`, el callback no imprime. Al volver, el programa imprime con lo suyo, también
/// desde su propio `parallel_map`.
fn row_a_program_callback_prints_only_if_the_package_declares() {
    let program = "use \"tok\" as tok\ntask cb()\n    print(\"CB\")\n    give 1\ntry\n    tok.llamar(cb)\nrecover e\n    print(\"cb: \" + text(e))\nprint(\"programa\")\nprint(parallel_map(cb, [1]))\n";
    let t = tok_tree("v0668-callback", "export task llamar(f)\n    give f()\n");
    let r = t.run(program);
    let e = format!("cb: {}", denial("tok"));
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&[&e, "programa", "[1]"]));
    let t = tok_tree("v0668-callback-declara", "export task llamar(f)\n    require stdout\n    give f()\n");
    let r = t.run(program);
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["CB", "programa", "[1]"]));
}

/// El nivel superior de un paquete corre con un dominio vacío: ni un `require stdout` de sus tasks
/// lo habilita a imprimir al cargarse, y lo que seguía en el programa no corre.
fn row_the_top_level_of_a_package_is_denied() {
    for src in ["print(\"PKG-INIT\")\n", "export task f()\n    require stdout\n    give 1\nprint(\"PKG-INIT\")\n"] {
        let t = tok_tree("v0668-nivel-superior", src);
        let r = t.run("use \"tok\" as tok\nprint(\"cargo\")\n");
        assert!(!r.success);
        assert!(errors(&r).contains("the package tok is running at top level; move this operation into a task that declares `require stdout`"), "{}", errors(&r));
        assert!(r.output.is_empty(), "{src:?}: {:?}", r.output);
    }
}

/// Un worker de `parallel_map` hereda el dominio, en ambos sentidos: el callback del programa
/// dentro del `parallel_map` del paquete no imprime, y la task del paquete que el programa reparte
/// tampoco; el error es el del paquete. El que declara deja correr y devolver. (Lo que imprime un
/// worker sale por su propio intérprete y no llega a `RunResult.output`: los bytes están en el test
/// de la CLI.)
fn row_workers_inherit_the_package_domain() {
    for (body, loud) in [("", false), ("    require stdout\n", true)] {
        let t = tok_tree("v0668-worker-a", &format!("export task por_worker(f)\n{body}    give parallel_map(f, [1])\n"));
        let r = t.run("use \"tok\" as tok\ntask cb(x)\n    print(\"CB\")\n    give x\nprint(tok.por_worker(cb))\nprint(\"programa\")\n");
        if loud {
            assert!(r.success, "{}", errors(&r));
            assert_eq!(r.output, lines(&["[1]", "programa"]));
        } else {
            denied(&r, "tok");
            assert!(r.output.is_empty(), "{:?}", r.output);
        }
    }
    for (body, loud) in [("", false), ("    require stdout\n", true)] {
        let t = tok_tree("v0668-worker-b", &format!("export task eco(x)\n{body}    print(\"E\" + text(x))\n    give x\n"));
        let r = t.run("use \"tok\" as tok\nlet r be parallel_map(tok.eco, [1, 2, 3])\nprint(r)\n");
        if loud {
            assert!(r.success, "{}", errors(&r));
            assert_eq!(r.output, lines(&["[1, 2, 3]"]));
        } else {
            denied(&r, "tok");
            assert!(r.output.is_empty(), "{:?}", r.output);
        }
    }
    // Después de un worker denegado, el `parallel_map` del programa corre y devuelve.
    let t = tok_tree("v0668-worker-c", "export task por_worker(f)\n    give parallel_map(f, [1])\n");
    let r = t.run("use \"tok\" as tok\ntask cb(x)\n    print(\"CB\")\n    give x\ntry\n    tok.por_worker(cb)\nrecover e\n    print(\"no\")\nprint(parallel_map(cb, [1]))\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["no", "[1]"]));
}

/// Todas las salidas pasan por el gate: `print`, `show`, `log`, `eprint`, `term_write` y el prompt
/// de `read_line` (antes de la pregunta y de consumir la entrada).
fn row_every_output_is_denied_before_the_first_byte() {
    for statement in ["print(\"PKG\")", "show \"PKG\"", "log \"PKG\"", "eprint(\"PKG\")", "term_write(999, \"PKG\")", "read_line(\"PKG>\")"] {
        let t = tok_tree("v0668-salidas", &format!("export task f()\n    require stdin\n    {statement}\n    give 1\n"));
        let r = t.run("require stdin\nuse \"tok\" as tok\ntok.f()\nprint(\"despues\")\n");
        denied(&r, "tok");
        assert!(r.output.is_empty(), "{statement}: {:?}", r.output);
    }
    // El que declara pasa el gate: `print` y `show` salen, `term_write` llega a su propio error.
    let t = tok_tree(
        "v0668-salidas-declara",
        "export task f()\n    require stdout\n    print(\"PKG\")\n    show \"PKG\"\n    give 1\nexport task t()\n    require stdout\n    term_write(999, \"PKG\")\n    give 1\n",
    );
    let r = t.run("use \"tok\" as tok\ntok.f()\nprint(\"despues\")\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["PKG", "PKG", "despues"]));
    let r = t.run("use \"tok\" as tok\ntok.t()\n");
    assert!(!r.success && errors(&r).contains("term_write") && !errors(&r).contains("Capability not granted"), "{}", errors(&r));
}

/// El techo del host, el `sandbox` pelado y el modo sin grants de ambiente siguen mandando; un
/// `sandbox under {}` deja pasar; una declaración del paquete no es un permiso del programa.
fn row_host_ceiling_sandbox_and_the_program_grant_still_rule() {
    let t = tok_tree("v0668-techo", LOUD);
    let r = t.run_ceiled("require stdout\nuse \"tok\" as tok\ntok.decir()\n", vec![Capability::new(CapabilityType::Time, None)]);
    assert!(!r.success && errors(&r).contains("Capability not granted: stdout") && errors(&r).contains("host ceiling"), "{} {:?}", errors(&r), r.output);
    assert!(r.output.is_empty(), "{:?}", r.output);
    let r = t.run("require stdout\nuse \"tok\" as tok\ntry\n    sandbox\n        tok.decir()\nrecover e\n    print(contains(text(e), \"sandbox\"))\nprint(\"despues\")\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["true", "despues"]));
    let r = t.run("require stdout\nuse \"tok\" as tok\nsandbox under {}\n    tok.decir()\nprint(\"despues\")\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["PKG", "despues"]));
    let r = t.run_secure("use \"tok\" as tok\ntok.decir()\nprint(\"despues\")\n");
    assert!(!r.success && errors(&r).contains("Capability not granted: stdout") && errors(&r).contains("add `require stdout` to the program's preamble"), "{}", errors(&r));
    assert!(!errors(&r).contains("package") && r.output.is_empty(), "{} {:?}", errors(&r), r.output);
    let r = t.run_secure("require stdout\nuse \"tok\" as tok\ntok.decir()\nprint(\"despues\")\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["PKG", "despues"]));
}

/// Bucles calientes y salidas no lineales: cada llamada cruza, cada vuelta restaura. Lo que el
/// paquete imprime adentro de su propio bucle pasa el gate una vez; un error que el programa
/// atrapa y un `give` adentro de un `each` dejan al programa con lo suyo y al paquete con lo suyo.
fn row_hot_loops_and_unwinding_restore_every_layer() {
    let t = tok_tree(
        "v0668-bucles",
        "export task una(x)\n    require stdout\n    print(\"U\" + text(x))\n    give x\n\
         export task eco(n)\n    require stdout\n    each i in range(0, n)\n        print(\"E\" + text(i))\n    give n\n\
         export task estalla(x)\n    require stdout\n    print(\"A\" + text(x))\n    when x == 3\n        raise \"boom\"\n    give x\n\
         export task primero(xs)\n    require stdout\n    each x in xs\n        print(\"P\" + text(x))\n        give x\n    give nothing\n",
    );
    let r = t.run("use \"tok\" as tok\nlet s be 0\neach i in range(0, 300)\n    set s to s + tok.una(i)\nprint(s)\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output.len(), 301, "{:?}", r.output);
    assert_eq!((r.output[0].as_str(), r.output[299].as_str(), r.output[300].as_str()), ("U0", "U299", "44850"));
    let r = t.run("use \"tok\" as tok\ntok.eco(300)\nprint(\"fin\")\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output.len(), 301, "{:?}", r.output);
    assert_eq!((r.output[0].as_str(), r.output[299].as_str(), r.output[300].as_str()), ("E0", "E299", "fin"));
    let r = t.run("use \"tok\" as tok\nlet n be 0\neach i in range(0, 5)\n    try\n        tok.estalla(i)\n    recover e\n        set n to n + 1\nprint(n)\nprint(\"fin\")\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["A0", "A1", "A2", "A3", "A4", "1", "fin"]));
    let r = t.run("use \"tok\" as tok\nlet s be 0\neach i in range(0, 4)\n    set s to s + tok.primero([i, 9])\nprint(s)\nprint(\"fin\")\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["P0", "P1", "P2", "P3", "6", "fin"]));
}

/// En un bucle caliente, dos paquetes alternados: el que declara imprime en cada vuelta y el que
/// no, nunca; ni un veredicto se le pega al otro, ni al programa.
fn row_two_packages_in_a_hot_loop_keep_their_verdicts() {
    let t = two_packages("v0668-dos-bucle");
    let r = t.run("use \"si\" as si\nuse \"no\" as no\nlet n be 0\neach i in range(0, 300)\n    try\n        no.decir()\n    recover e\n        set n to n + 1\n    si.decir()\nprint(n)\nprint(\"fin\")\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output.iter().filter(|l| l.as_str() == "PKG-SI").count(), 300, "{}", errors(&r));
    assert!(!r.output.iter().any(|l| l.as_str() == "PKG-NO"), "{:?}", r.output);
    assert_eq!(r.output.len(), 302, "{:?}", r.output);
    assert_eq!(&r.output[300..], &lines(&["300", "fin"]));
}

/// Cadena distinta, veredicto distinto: la task del paquete de adentro se niega sola y también
/// cuando la llama el de afuera, que sí imprime lo suyo; en los dos casos el error nombra al de
/// adentro. Ninguna se prende de la otra.
fn row_each_chain_keeps_its_own_verdict() {
    let inner_id = format!("{BASE}bpe-cadena");
    let hi = publish(&inner_id, "0.3.0", "b.syn", &[("b.syn", "export task g()\n    print(\"PKG-IN\")\n")], "");
    let deps = format!("{{{}}}", entry("bpe", &inner_id, "0.3.0", &hi));
    let outer_id = format!("{BASE}tok-cadena");
    let ho = publish(
        &outer_id,
        "0.1.0",
        "m.syn",
        &[("m.syn", "use \"bpe\" as bpe\nexport task f()\n    require stdout\n    print(\"PKG-EXT\")\n    give bpe.g()\n")],
        &deps,
    );
    let indirect = format!("\"{}\": {{\"url\": \"{}/0.3.0/synsema.json\", \"version\": \"0.3.0\", \"hash\": \"{}\"}}", inner_id, inner_id, hi);
    let t = Tree::new("v0668-cadena", &[entry("ext", &outer_id, "0.1.0", &ho), entry("int", &inner_id, "0.3.0", &hi)], &[indirect]);
    let r = t.run(
        "use \"ext\" as ext\nuse \"int\" as int\nlet a be true\nlet b be true\neach i in range(0, 50)\n    try\n        int.g()\n    recover e\n        when contains(text(e), \"stdout\") == false\n            set a to false\n        when contains(text(e), \"the package int does not declare it\") == false\n            set a to false\n    try\n        ext.f()\n    recover e\n        when contains(text(e), \"stdout\") == false\n            set b to false\n        when contains(text(e), \"does not declare it\") == false\n            set b to false\n        when contains(text(e), \"the package int does not declare it\") == false\n            set b to false\nprint(a)\nprint(b)\nprint(\"fin\")\n",
    );
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output.iter().filter(|l| l.as_str() == "PKG-EXT").count(), 50, "{:?}", r.output);
    assert!(!r.output.iter().any(|l| l.contains("PKG-IN")), "{:?}", r.output);
    assert_eq!(r.output.len(), 53, "{:?}", r.output);
    assert_eq!(&r.output[50..], &lines(&["true", "true", "fin"]));
}

/// El paquete de afuera sigue imprimiendo con lo suyo después de una llamada negada al de adentro:
/// `tok` declara, `bpe` no. La cadena de `bpe` se niega y queda en la caché por delante de la de
/// `tok`; las salidas siguientes de `tok` salen por la marca y tienen que leer la suya.
fn row_the_outer_package_keeps_printing_after_a_denied_call() {
    let quiet = "export task g()\n    print(\"PKG-IN\")\n";
    let body = "    require stdout\n    print(\"PKG-OUT-1\")\n    try\n        bpe.g()\n    recover e\n        print(\"dentro: \" + text(e))\n    print(\"PKG-OUT-2\")\n    print(\"PKG-OUT-3\")\n";
    let (t, inner) = nested("v0668-sigue", body, quiet);
    let r = t.run("use \"tok\" as tok\ntry\n    tok.f()\nrecover e\n    print(\"fuera: \" + text(e))\nprint(\"fin\")\n");
    assert!(r.success, "{}", errors(&r));
    let inside = format!("dentro: {}", denial(&inner));
    assert_eq!(r.output, lines(&["PKG-OUT-1", &inside, "PKG-OUT-2", "PKG-OUT-3", "fin"]));
}

/// Una lambda escrita en el paquete (la de un default, o una que exporta) lleva su dominio por
/// donde salga: llamada desde el programa, no imprime si el paquete no declara `stdout`.
fn row_a_lambda_written_in_the_package_keeps_its_domain() {
    for (body, loud) in [("", false), ("    require stdout\n", true)] {
        let t = tok_tree("v0668-lambda", &format!("export let CB be nothing\nexport task f(cb = () => print(\"D\"))\n{body}    set CB to () => print(\"D\")\n    give cb\n"));
        let r = t.run("use \"tok\" as tok\nlet cb be tok.f()\ntry\n    cb()\nrecover e\n    print(\"e: \" + text(e))\ntry\n    tok.CB()\nrecover e\n    print(\"e: \" + text(e))\nprint(\"fin\")\n");
        assert!(r.success, "{}", errors(&r));
        if loud {
            assert_eq!(r.output, lines(&["D", "D", "fin"]));
        } else {
            let e = format!("e: {}", denial("tok"));
            assert_eq!(r.output, lines(&[&e, &e, "fin"]));
        }
    }
}

/// Las filas que dan lo mismo en cada modo de ejecución.
pub const TABLE: &[(&str, fn())] = &[
    ("antes_despues", row_prints_before_and_after),
    ("declara", row_a_package_that_declares_prints),
    ("sin_declarar", row_the_program_grant_does_not_reach_an_undeclared_package),
    ("dos_paquetes", row_two_packages_each_get_their_own_verdict),
    ("anidados", row_nested_packages_intersect),
    ("callback", row_a_program_callback_prints_only_if_the_package_declares),
    ("nivel_superior", row_the_top_level_of_a_package_is_denied),
    ("workers", row_workers_inherit_the_package_domain),
    ("salidas", row_every_output_is_denied_before_the_first_byte),
    ("techo_sandbox", row_host_ceiling_sandbox_and_the_program_grant_still_rule),
    ("bucles", row_hot_loops_and_unwinding_restore_every_layer),
    ("dos_bucle", row_two_packages_in_a_hot_loop_keep_their_verdicts),
    ("cadena", row_each_chain_keeps_its_own_verdict),
    ("sigue", row_the_outer_package_keeps_printing_after_a_denied_call),
    ("lambda", row_a_lambda_written_in_the_package_keeps_its_domain),
];

#[test]
fn v0668_stdout_table() {
    for (_, row) in TABLE {
        row();
    }
}

/// El audit ve el gate una vez por cadena, no por llamada: la denegación nombra al paquete, el
/// permiso del que declara es el del programa, y el `require stdout` del paquete no concede nada.
/// (Sin etiquetas: `receipt()` bajo etiquetas es otro contrato.)
pub fn v0668_stdout_audit_table() {
    let t = two_packages("v0668-audit");
    let r = t.run("use \"si\" as si\nuse \"no\" as no\nlet n be 0\neach i in range(0, 3)\n    try\n        no.decir()\n    recover e\n        set n to n + 1\n    si.decir()\nprint(json_encode(receipt().credentialSubject.capabilities))\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output.iter().filter(|l| l.as_str() == "PKG-SI").count(), 3);
    let entries: Vec<serde_json::Value> = serde_json::from_str(r.output.last().unwrap()).unwrap();
    let stdout: Vec<String> = entries
        .iter()
        .filter(|e| e["capability"] == "stdout")
        .map(|e| format!("{} {} {} {}", e["origin"].as_str().unwrap(), e["source"].as_str().unwrap(), e["reason"].as_str().unwrap(), e["granted"]))
        .collect();
    assert_eq!(
        stdout,
        lines(&[
            "runtime ambient auto-granted by the runtime true",
            "program print() the package no does not declare it false",
            "program print() Granted by stdout true",
        ])
    );
}

#[test]
fn v0668_stdout_audit() {
    v0668_stdout_audit_table();
}

/// Con etiquetas, el gate no cambia la regla de las etiquetas ni al revés: el paquete que declara
/// imprime un valor público (y una task es pura: su resultado no es privado), imprimir bajo una
/// rama privada lo corta el flujo, y el mudo se niega con el mismo texto. La corre
/// `tests/v0658_attenuation_modes.rs`, al final y con las etiquetas ya encendidas.
#[allow(dead_code)]
pub fn v0668_stdout_under_labels() {
    let t = tok_tree("v0668-labels", "export task decir(x)\n    require stdout\n    print(x)\n    give 1\n");
    let r = t.run("use \"tok\" as tok\ntok.decir(\"PKG\")\nprint(is_private(tok.decir(1)))\n");
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["PKG", "1", "false"]));
    let r = t.run("use \"tok\" as tok\nwhen private(true, \"bank\")\n    tok.decir(\"PKG\")\n");
    assert!(!r.success && !r.output.iter().any(|l| l.contains("PKG")), "{:?} {}", r.output, errors(&r));
    let t = tok_tree("v0668-labels-mudo", QUIET);
    let r = t.run("use \"tok\" as tok\nprint(\"uno\")\ntry\n    tok.decir()\nrecover e\n    print(\"atrapado: \" + text(e))\n");
    let caught = format!("atrapado: {}", denial("tok"));
    assert!(r.success, "{}", errors(&r));
    assert_eq!(r.output, lines(&["uno", &caught]));
}

/// Bajo `serve`, cada request es su unidad de trabajo en un worker que se reusa: la ruta del
/// paquete mudo falla con el error del paquete antes de imprimir, la del que declara y las del
/// programa responden, en cualquier orden y con pedidos concurrentes.
#[test]
fn v0668_serve_requests_each_get_their_own_verdict() {
    use pkg::serve_rows::{free_port, get, serve};
    let (tok, mudo) = (format!("{BASE}srv-si"), format!("{BASE}srv-no"));
    let h_tok = publish(
        &tok,
        "0.1.0",
        "m.syn",
        &[(
            "m.syn",
            "task decl()\n    require stdout\n    give 1\nexport routes rutas\n    route \"GET /pkg-si\"\n        print(\"PKG-SI\")\n        give {\"said\": \"PKG-SI\"}\nexport task handler()\n    print(\"PKG-H-SI\")\n    give {\"said\": \"PKG-H-SI\"}\n",
        )],
        "",
    );
    let h_mudo = publish(
        &mudo,
        "0.1.0",
        "m.syn",
        &[(
            "m.syn",
            "export routes rutas\n    route \"GET /pkg-no\"\n        print(\"PKG-NO\")\n        give {\"said\": \"PKG-NO\"}\nexport task handler()\n    print(\"PKG-H-NO\")\n    give {\"said\": \"PKG-H-NO\"}\n",
        )],
        "",
    );
    let t = Tree::new("v0668-serve", &[entry("tok", &tok, "0.1.0", &h_tok), entry("mudo", &mudo, "0.1.0", &h_mudo)], &[]);
    let port = free_port();
    serve(
        &t,
        port,
        format!(
            "require serve({port})\nuse \"tok\" as tok\nuse \"mudo\" as mudo\nserve on {port}\n    mount tok.rutas\n\n    mount mudo.rutas\n\n    route \"GET /prog\"\n        print(\"PROG\")\n        give {{\"said\": \"PROG\"}}\n\n    route \"GET /si\"\n        give tok.handler()\n\n    route \"GET /no\"\n        give mudo.handler()\n"
        ),
    );
    let check = |path: &str, r: String| {
        let said = match path {
            "/prog" => "PROG",
            "/si" => "PKG-H-SI",
            "/pkg-si" => "PKG-SI",
            _ => "",
        };
        if said.is_empty() {
            // El paquete mudo: 500 con su error, y el handler no llegó a responder.
            let hushed = if path == "/no" { "PKG-H-NO" } else { "PKG-NO" };
            assert!(r.starts_with("HTTP/1.1 500") && r.contains("Capability not granted: stdout"), "{path}: {r}");
            assert!(r.contains("the package mudo does not declare it; add `require stdout` inside its tasks"), "{path}: {r}");
            assert!(!r.contains(hushed) && !r.contains("\"said\""), "{path}: {r}");
        } else {
            assert!(r.starts_with("HTTP/1.1 200") && r.contains(said), "{path}: {r}");
            assert!(!r.contains("Capability not granted"), "{path}: {r}");
        }
    };
    let paths = ["/prog", "/pkg-si", "/pkg-no", "/si", "/no"];
    for _ in 0..6 {
        for path in paths {
            check(path, get(port, path, ""));
        }
    }
    // Pedidos a la vez: varios workers, cada uno con su veredicto.
    let threads: Vec<_> = (0..24)
        .map(|i| {
            let path = paths[i % paths.len()];
            std::thread::spawn(move || { check(path, get(port, path, "")); })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    // Después de todo, en orden y sin errores: el programa imprime.
    for path in ["/prog", "/si", "/pkg-si"] {
        check(path, get(port, path, ""));
    }
}

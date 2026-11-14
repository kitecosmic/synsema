//! v0.6.58 (§6.1): las filas de la atenuación que dependen del modo (K8, K12, K14, K32, K35, K40–K43)
//! dan lo mismo en la VM, en el tree-walker de referencia, con el nivel nativo y con etiquetas (K30).
//! Es un binario aparte porque el modo referencia, el JIT y las etiquetas son del proceso: las
//! pasadas van en orden, en un solo test; las etiquetas al final (no se apagan).

#[path = "it/v0658_attenuation.rs"]
mod table;

fn pass(mode: &str) {
    table::v0661_process_local_package_table();
    for (name, row) in table::MODES {
        if let Err(e) = std::panic::catch_unwind(row) {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            panic!("{} en {}: {}", name, mode, msg);
        }
    }
}

#[test]
fn the_attenuation_holds_in_every_mode() {
    pass("vm");
    synsema_core::interpreter::set_reference_mode(true);
    pass("ref");
    synsema_core::interpreter::set_reference_mode(false);
    synsema_jit::install();
    synsema_core::native_tier::set_eager(true);
    pass("jit");
    k36_the_program_loop_calls_the_package_as_foreign();
    k36b_the_program_site_never_goes_native();
    k36c_a_loop_inside_the_package_goes_native();
    a1_a_native_loop_of_the_package_crosses_back_to_the_program();
    assert!(synsema_runtime::host::set_labels(true) || synsema_runtime::host::labels());
    pass("labels");
    k30_labels_flow_through_a_package_task();
}

/// K36: un bucle del programa que llama a `enc` (un alias de una task del paquete) pasa a nativo,
/// pero `enc` no entra a la unidad (`LoadCallee`): es una llamada ajena, por la VM, que cruza. Se
/// ve en el contador de entradas a bucles con llamadas ajenas.
fn k36_the_program_loop_calls_the_package_as_foreign() {
    let t = table::k36c_tree();
    let before = synsema_core::native_tier::stats();
    let r = t.run("use \"tok\" as tok\nlet enc be tok.cod\nlet s be 0\neach i in range(0, 3000)\n    set s to s + enc(i)\nprint(s)\n");
    let after = synsema_core::native_tier::stats();
    assert!(r.success, "{}", r.errors.join("\n"));
    assert_eq!(r.output, vec!["9000000".to_string()]);
    eprintln!("k36: {:?} -> {:?}", before, after);
    assert!(after.foreign > before.foreign, "el bucle metió la task del paquete en la unidad: {:?} -> {:?}", before, after);
}

/// K36b (G-2): el sitio del programa que llama miles de veces a una task del paquete (pura, que el
/// nivel nativo compilaría) nunca pasa a `CallNative`: entra siempre por el prólogo. Se ve en las
/// entradas nativas (con el sitio reescrito serían ~3000; los otros tests del binario corren en
/// paralelo, de ahí el margen).
fn k36b_the_program_site_never_goes_native() {
    let t = table::k36c_tree();
    let before = synsema_core::native_tier::stats();
    // El `try` (un nodo del tree-walker) deja el bucle en la VM: así corre el sitio `Call` del
    // programa (si no, el bucle entero pasa a nativo y llama al paquete como llamada ajena).
    let r = t.run("use \"tok\" as tok\nlet s be 0\nlet z be 0\neach i in range(0, 3000)\n    set s to s + tok.cod(i)\n    try\n        set z to 1\n    recover e\n        set z to 2\nprint(s)\n");
    let after = synsema_core::native_tier::stats();
    assert!(r.success, "{}", r.errors.join("\n"));
    assert_eq!(r.output, vec!["9000000".to_string()]);
    eprintln!("k36b: {:?} -> {:?}", before, after);
    assert!(after.entries - before.entries < 1000, "el sitio del programa pasó a nativo: {:?} -> {:?}", before, after);
}

/// K36c: adentro de una task del paquete, un bucle que llama a una task privada del paquete pasa al
/// nivel nativo (el cruce no lo saca de ahí).
fn k36c_a_loop_inside_the_package_goes_native() {
    let t = table::k36c_tree();
    let before = synsema_core::native_tier::stats();
    let r = t.run("use \"tok\" as tok\nlet s be 0\neach i in range(0, 300)\n    set s to s + tok.encode(50)\nprint(s)\n");
    let after = synsema_core::native_tier::stats();
    assert!(r.success, "{}", r.errors.join("\n"));
    assert_eq!(r.output, vec!["15000".to_string()]);
    let native = (after.entries + after.osr) - (before.entries + before.osr);
    eprintln!("k36c: {:?} -> {:?}", before, after);
    assert!(native >= 300, "el bucle del paquete no pasó a nativo: {:?} -> {:?}", before, after);
}

/// K30: con etiquetas, lo que devuelve una task del paquete lleva la etiqueta de su argumento, y la
/// task corre con el PC del que llama (un efecto adentro de un `when` privado se corta).
fn k30_labels_flow_through_a_package_task() {
    let t = table::k30_tree();
    let r = t.run("use \"tok\" as tok\nlet n be tok.largo(private(\"abc\", \"bank\"))\nprint(is_private(n))\nprint(is_private(tok.largo(\"abc\")))\n");
    assert!(r.success, "{}", r.errors.join("\n"));
    // El resultado lleva la etiqueta del argumento (y lo que se deriva de él también: al imprimirlo
    // sale retenido como `private(bank)`); sin etiqueta, nada.
    assert_eq!(r.output, vec!["private(bank)".to_string(), "false".to_string()]);
    let r = t.run("use \"tok\" as tok\ntok.decir()\n");
    assert!(r.success, "{}", r.errors.join("\n"));
    let r = t.run("use \"tok\" as tok\nwhen private(true, \"bank\")\n    tok.decir()\n");
    assert!(!r.success, "el efecto del paquete bajo un PC privado se corta: {:?}", r.output);
}

/// A1 (ronda 1): un bucle nativo del paquete que llama a un callback del programa guardado en una
/// global del paquete (el bucle lo carga como llamada ajena) cruza a 0: el callback no escribe las
/// exportaciones (K31) ni renderiza la plantilla del paquete (K27). Antes de A1, con jit, el
/// callback corría con el dominio del paquete; en la VM ya daba el error.
fn a1_a_native_loop_of_the_package_crosses_back_to_the_program() {
    let t = table::tok_tree_files(
        "a1k31",
        &[(
            "m.syn",
            "export let ESTADO be \"original\"\nlet G be nothing\nexport task correr(cb, n)\n    set G to cb\n    let s be 0\n    each i in range(0, n)\n        set s to s + G(i)\n    give s\nexport task estado()\n    give ESTADO\n",
        )],
    );
    let before = synsema_core::native_tier::stats();
    let r = t.run("use \"tok\" as tok\ntask cb(i)\n    when i == 4999\n        set tok.ESTADO to \"pisado\"\n    give 1\nprint(tok.correr(cb, 5000))\nprint(tok.estado())\n");
    let after = synsema_core::native_tier::stats();
    eprintln!("a1 k31: {:?} -> {:?}", before, after);
    assert!(after.foreign > before.foreign, "el bucle del paquete no corrió en nativo con la llamada ajena: {:?} -> {:?}", before, after);
    let e = r.errors.join("\n");
    assert!(!r.success && e.contains("a package's exports are read-only"), "salida {:?}, errores {}", r.output, e);
    assert!(r.output.is_empty(), "{:?}", r.output);

    let _f = table::CwdFile::new("v0658-a1-vista.html", "DEL PROGRAMA");
    let t = table::tok_tree_files(
        "a1k27",
        &[
            ("m.syn", "let G be nothing\nexport task correr(cb, n)\n    set G to cb\n    let s be \"\"\n    each i in range(0, n)\n        set s to G(i)\n    give s\n"),
            ("v0658-a1-vista.html", "DEL PAQUETE"),
        ],
    );
    let before = synsema_core::native_tier::stats();
    let r = t.run(
        "require file.read(\"**\")\nuse \"tok\" as tok\ntask cb(i)\n    when i == 4999\n        give body of render(\"v0658-a1-vista.html\", {})\n    give \"\"\nprint(body of render(\"v0658-a1-vista.html\", {}))\nprint(tok.correr(cb, 5000))\n",
    );
    let after = synsema_core::native_tier::stats();
    eprintln!("a1 k27: {:?} -> {:?}", before, after);
    assert!(after.foreign > before.foreign, "el bucle del paquete no corrió en nativo con la llamada ajena: {:?} -> {:?}", before, after);
    let e = r.errors.join("\n");
    assert_eq!(r.output, vec!["DEL PROGRAMA".to_string()], "{}", e);
    assert!(!r.success && e.contains("Capability not granted") && e.contains("the package tok does not declare it"), "{}", e);
}

//! Conformidad de las etiquetas de flujo de información por principal (`private` /
//! `declassify`, `labels.rs`). Corre el intérprete DIRECTO con `set_labels(true)` y mira
//! salida, valores del entorno global y sus etiquetas; también prueba que con las
//! etiquetas apagadas todo es idéntico (mismos `steps`, `private` → error, `declassify`
//! identidad).

use synsema_core::interpreter::{env_get, Control, Interpreter};
use synsema_core::labels::{self, check_flow, label_deep, label_display_raw, mark, strip_deep};
use synsema_core::parser::parse_source;
use synsema_core::types::{syn_int, syn_list, syn_map, syn_text, SynValue};

/// Corre `source` con etiquetas encendidas (o no) y devuelve el intérprete (para mirar
/// `output`, el entorno global, `steps()`, `declassify_log()`).
fn run(source: &str, labels_on: bool) -> (Interpreter, Result<SynValue, Control>) {
    let program = parse_source(source, "<labels>").unwrap_or_else(|e| panic!("parse: {}\n{}", e, source));
    let mut interp = Interpreter::new();
    interp.set_labels(labels_on);
    let r = interp.execute(&program);
    (interp, r)
}

fn run_ok(source: &str) -> Interpreter {
    let (interp, r) = run(source, true);
    if let Err(Control::Error(e)) = &r {
        panic!("el programa falló: {}\nfuente:\n{}", e, source);
    }
    interp
}

fn run_err(source: &str) -> String {
    let (_interp, r) = run(source, true);
    match r {
        Err(Control::Error(e)) => e.to_string(),
        _ => panic!("se esperaba un error.\nfuente:\n{}", source),
    }
}

/// Etiqueta (profunda) de una variable global, como `a,b`.
fn label_of(interp: &Interpreter, name: &str) -> String {
    let v = env_get(&interp.global_env, name).unwrap_or_else(|| panic!("sin variable {}", name));
    label_display_raw(&label_deep(&v))
}

/// Valor interno (sin etiquetas) de una variable global, como texto.
fn plain_of(interp: &Interpreter, name: &str) -> String {
    let v = env_get(&interp.global_env, name).unwrap_or_else(|| panic!("sin variable {}", name));
    strip_deep(&v).to_string()
}

// ---------------------------------------------------------------------------------
// Flujos explícitos
// ---------------------------------------------------------------------------------

#[test]
fn explicit_flow_through_arithmetic() {
    let i = run_ok("let x be private(3, \"a\") + 1\n");
    assert_eq!(label_of(&i, "x"), "a");
    assert_eq!(plain_of(&i, "x"), "4");
}

#[test]
fn join_of_two_principals_is_the_union() {
    let i = run_ok("let x be private(3, \"a\") * private(2, \"b\")\nlet y be x == 6\nlet z be -x\nlet w be not x\n");
    assert_eq!(label_of(&i, "x"), "a,b");
    assert_eq!(plain_of(&i, "x"), "6");
    // Comparaciones y unarios también salen privados.
    assert_eq!(label_of(&i, "y"), "a,b");
    assert_eq!(plain_of(&i, "y"), "true");
    assert_eq!(label_of(&i, "z"), "a,b");
    assert_eq!(label_of(&i, "w"), "a,b");
}

#[test]
fn text_concat_and_lists_propagate() {
    let i = run_ok(
        "let p be private(\"bob\", \"hr\")\nlet t be \"hi \" + p\nlet l be [1] + private([2], \"a\")\nlet b be p and true\nlet o be false or p\n",
    );
    assert_eq!(label_of(&i, "t"), "hr");
    assert_eq!(plain_of(&i, "t"), "hi bob");
    assert_eq!(label_of(&i, "l"), "a");
    assert_eq!(plain_of(&i, "l"), "[1, 2]");
    assert_eq!(label_of(&i, "b"), "hr");
    assert_eq!(label_of(&i, "o"), "hr");
}

#[test]
fn field_and_index_of_a_private_map_are_private() {
    let i = run_ok(
        "let m be private({\"amount\": 5, \"items\": [7, 8]}, \"app\")\nlet a be m.amount\nlet b be m[\"items\"][1]\nlet c be amount of m\nlet xs be [10, 20, 30]\nlet d be xs[private(1, \"k\")]\n",
    );
    assert_eq!(label_of(&i, "a"), "app");
    assert_eq!(plain_of(&i, "a"), "5");
    assert_eq!(label_of(&i, "b"), "app");
    assert_eq!(plain_of(&i, "b"), "8");
    assert_eq!(label_of(&i, "c"), "app");
    // Índice privado sobre una lista pública → el elemento sale con la etiqueta del índice.
    assert_eq!(label_of(&i, "d"), "k");
    assert_eq!(plain_of(&i, "d"), "20");
}

#[test]
fn builtins_propagate_the_deep_union_of_their_arguments() {
    let i = run_ok(
        "let p be private(3, \"a\")\nlet t be text(p)\nlet n be length([p, private(1, \"b\"), 2])\nlet s be sum([p, 1])\nlet ty be type_of(p)\nlet u be upper(private(\"x\", \"c\"))\nlet j be join([p, 2], \",\")\n",
    );
    assert_eq!(label_of(&i, "t"), "a");
    assert_eq!(plain_of(&i, "t"), "3");
    // Elementos privados dentro de una lista: la etiqueta profunda es la unión.
    assert_eq!(label_of(&i, "n"), "a,b");
    assert_eq!(plain_of(&i, "n"), "3");
    assert_eq!(label_of(&i, "s"), "a");
    assert_eq!(plain_of(&i, "s"), "4");
    // type_of reporta el tipo del valor INTERNO, privado.
    assert_eq!(label_of(&i, "ty"), "a");
    assert_eq!(plain_of(&i, "ty"), "number");
    assert_eq!(label_of(&i, "u"), "c");
    assert_eq!(plain_of(&i, "u"), "X");
    assert_eq!(label_of(&i, "j"), "a");
    assert_eq!(plain_of(&i, "j"), "3,2");
}

#[test]
fn callbacks_inside_builtins_inherit_the_label() {
    let src = "let leak be private(0, \"a\")\n\
task grab(x)\n    set leak to x\n    give x * 2\n\
let xs be private([3, 1, 2], \"a\")\n\
let ys be apply(xs, grab)\n\
let sorted be sort_by(xs, (v) => v)\n\
let groups be group_by(xs, (v) => v % 2)\n\
let big be where(xs, (v) => v > 1)\n";
    let i = run_ok(src);
    // El callback corrió bajo la etiqueta de la lista: el `set` a una variable que ya cubre
    // el PC funciona y los resultados salen privados y CORRECTOS.
    assert_eq!(label_of(&i, "leak"), "a");
    assert_eq!(plain_of(&i, "leak"), "2");
    // A una variable PÚBLICA, en cambio, es label_violation (NSU estricto).
    let msg = run_err("let leak be 0\ntask grab(x)\n    set leak to x\n    give x\nlet ys be apply(private([1], \"a\"), grab)\n");
    assert!(msg.contains("label_violation") && msg.contains("'leak'"), "{}", msg);
    assert_eq!(label_of(&i, "ys"), "a");
    assert_eq!(plain_of(&i, "ys"), "[6, 2, 4]");
    assert_eq!(label_of(&i, "sorted"), "a");
    assert_eq!(plain_of(&i, "sorted"), "[1, 2, 3]");
    assert_eq!(label_of(&i, "groups"), "a");
    assert_eq!(plain_of(&i, "groups"), "{1: [3, 1], 0: [2]}");
    assert_eq!(plain_of(&i, "big"), "[3, 2]");
}

// ---------------------------------------------------------------------------------
// Flujos implícitos (PC)
// ---------------------------------------------------------------------------------

#[test]
fn implicit_flow_through_when_needs_an_already_private_variable() {
    // NSU estricto: la variable asignada bajo PC tiene que cubrir el PC.
    let src = "let secret_flag be private(true, \"a\")\nlet out be private(0, \"a\")\nwhen secret_flag\n    set out to 1\notherwise\n    set out to 2\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "out"), "a");
    assert_eq!(plain_of(&i, "out"), "1");
    // También por `otherwise when`, y un `let` NUEVO dentro de la rama nace privado.
    let src2 = "let f be private(false, \"b\")\nlet out be private(0, \"b\")\nwhen f\n    set out to 1\notherwise when f == false\n    set out to 3\n    let fresh be 9\n";
    let i2 = run_ok(src2);
    assert_eq!(label_of(&i2, "out"), "b");
    assert_eq!(plain_of(&i2, "out"), "3");
    assert_eq!(label_of(&i2, "fresh"), "b");
    // Una variable pública → label_violation (antes se "convertía").
    let msg = run_err("let f be private(true, \"a\")\nlet out be 0\nwhen f\n    set out to 1\n");
    assert!(msg.contains("label_violation") && msg.contains("'out'") && msg.contains("pc = [a]"), "{}", msg);
    // Una variable privada de OTRO principal tampoco cubre el PC.
    // Una variable privada de OTRO principal tampoco cubre el PC. Ronda 7: el mensaje ya no
    // nombra CUAL —el texto de un diagnostico no puede depender de la etiqueta del valor— sino
    // el conjunto declarado del programa, que es constante.
    let msg = run_err("let f be private(true, \"a\")\nlet out be private(0, \"b\")\nwhen f\n    set out to 1\n");
    assert!(msg.contains("label_violation") && msg.contains("'out'") && msg.contains("private to a,b"), "{}", msg);
}

#[test]
fn implicit_flow_through_loops() {
    let src = "let n be private(3, \"a\")\nlet i be private(0, \"a\")\nlet acc be private(0, \"a\")\nwhile i < n\n    set acc to acc + 1\n    set i to i + 1\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "acc"), "a");
    assert_eq!(plain_of(&i, "acc"), "3");
    let src2 = "let xs be private([1, 2, 3], \"b\")\nlet total be private(0, \"b\")\neach x in xs\n    set total to total + x\nlet count be 0\neach x in [1, 2]\n    set count to count + 1\n";
    let i2 = run_ok(src2);
    assert_eq!(label_of(&i2, "total"), "b");
    assert_eq!(plain_of(&i2, "total"), "6");
    // Un bucle público no etiqueta nada.
    assert_eq!(label_of(&i2, "count"), "");
    // Acumulador público bajo un bucle privado → label_violation.
    let msg = run_err("let xs be private([1, 2], \"b\")\nlet total be 0\neach x in xs\n    set total to total + x\n");
    assert!(msg.contains("label_violation") && msg.contains("'total'"), "{}", msg);
    let msg = run_err("let n be private(2, \"a\")\nlet i be 0\nwhile i < n\n    set i to i + 1\n");
    assert!(msg.contains("label_violation") && msg.contains("'i'"), "{}", msg);
}

#[test]
fn implicit_flow_through_match() {
    let src = "let v be private(2, \"a\")\nlet out be private(\"\", \"a\")\nmatch v\n    is 1\n        set out to \"one\"\n    is 2\n        set out to \"two\"\n    otherwise\n        set out to \"many\"\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "out"), "a");
    assert_eq!(plain_of(&i, "out"), "two");
    let msg = run_err("let v be private(2, \"a\")\nlet out be \"\"\nmatch v\n    is 2\n        set out to \"two\"\n");
    assert!(msg.contains("label_violation"), "{}", msg);
}

#[test]
fn give_from_a_private_context_is_private() {
    // El `give` devuelve el valor con el PC y NO tiñe la continuacion del llamador: `s`,
    // calculado despues con datos publicos, sigue publico.
    let src = "task classify(x)\n    when x > 10\n        give \"big\"\n    give \"small\"\n\
let r be classify(private(20, \"a\"))\nlet s be classify(5)\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "r"), "a");
    assert_eq!(plain_of(&i, "r"), "big");
    assert_eq!(label_of(&i, "s"), "");
    assert_eq!(plain_of(&i, "s"), "small");
}

#[test]
fn an_early_give_under_pc_does_not_taint_the_caller() {
    // Un `give` temprano desde una rama privada NO deja PC residual: su punto de llegada es el
    // sitio de la llamada (un join point) y la informacion viaja en el VALOR, que sale
    // etiquetado. Teñir la continuacion rompia codigo enteramente publico del llamador.
    let src = "task guard(x)\n    when x > 0\n        give \"yes\"\n    give \"no\"\n\
let r be guard(private(5, \"app\"))\n\
let allowed be {}\nset allowed[\"ETH\"] to true\nlet n be length(keys(allowed))\nlet pub be 0\nset pub to 1\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "r"), "app");
    assert_eq!(plain_of(&i, "r"), "yes");
    // Todo lo de despues sigue publico: el contenedor, su lectura y una variable publica.
    assert_eq!(label_of(&i, "allowed"), "");
    assert_eq!(plain_of(&i, "allowed"), "{ETH: true}");
    assert_eq!(label_of(&i, "n"), "");
    assert_eq!(plain_of(&i, "n"), "1");
    assert_eq!(label_of(&i, "pub"), "");
}

#[test]
fn two_consecutive_tasks_do_not_contaminate_each_other() {
    // La primera corre con un valor privado (y vuelve por una rama privada); la segunda es
    // enteramente publica y tiene que seguir siendolo, incluso escribiendo un contenedor.
    let src = "task guard(x)\n    when x > 0\n        give \"yes\"\n    give \"no\"\n\
task eth_only()\n    let allowed be {}\n    set allowed[\"ETH\"] to true\n    give allowed\n\
let a be guard(private(5, \"app\"))\nlet b be eth_only()\nlet n be length(keys(b))\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "a"), "app");
    assert_eq!(label_of(&i, "b"), "");
    assert_eq!(plain_of(&i, "b"), "{ETH: true}");
    assert_eq!(label_of(&i, "n"), "");
    assert_eq!(plain_of(&i, "n"), "1");
    // Y al reves: una task publica despues de una que uso privados adentro de un bucle.
    let src2 = "task scan(xs)\n    each x in xs\n        when x > 1\n            give x\n    give 0\n\
task pubwork()\n    let m be {}\n    set m[\"k\"] to 1\n    give m\n\
let a be scan(private([1, 2, 3], \"app\"))\nlet b be pubwork()\n";
    let i2 = run_ok(src2);
    assert_eq!(label_of(&i2, "a"), "app");
    assert_eq!(label_of(&i2, "b"), "");
}

#[test]
fn a_public_test_block_after_a_private_one_still_passes() {
    // Repro exacta del adaptador: dos bloques `test`, el primero llama a una task con un valor
    // privado (que vuelve por una rama privada) y el segundo es enteramente publico.
    let src = "task guard(x)\n    when x > 0\n        give \"yes\"\n    give \"no\"\n\
task eth_only()\n    let allowed be {}\n    set allowed[\"ETH\"] to true\n    give allowed\n\
test \"1. a guard returns early from a private branch\"\n    assert_eq(guard(private(5, \"app\")), \"yes\")\n\
test \"2. eth_only(), que es enteramente publica\"\n    assert_eq(length(keys(eth_only())), 1)\n";
    let program = parse_source(src, "<labels>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    let outcomes = interp.run_test_blocks(&program);
    assert_eq!(outcomes.len(), 2);
    for o in &outcomes {
        assert!(o.passed, "{}: {:?}", o.name, o.message);
    }
}

#[test]
fn a_labelled_callable_runs_under_its_label() {
    let src = "let f be private(true, \"a\")\nlet g be private(0, \"a\")\nwhen f\n    set g to (x) => x + 1\nlet r be g(1)\nlet h be private((x) => x * 2, \"b\")\nlet s be h(4)\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "g"), "a");
    assert_eq!(label_of(&i, "r"), "a");
    assert_eq!(plain_of(&i, "r"), "2");
    assert_eq!(label_of(&i, "s"), "b");
    assert_eq!(plain_of(&i, "s"), "8");
}

#[test]
fn an_error_that_depends_on_private_data_is_not_catchable() {
    // Ronda 6 (B1). Hasta acá este error se atrapaba: nacía con el PC vacío (el índice es
    // privado, pero no hay rama privada), así que sólo se redactaba el mensaje. Eso era la
    // asimetría: la redacción miraba el PC UNIDO a lo que el nodo tocó y la atrapabilidad
    // miraba sólo el PC. Por esa grieta, `try / each i / let v be 1 / (secret - i) / recover`
    // terminaba bien y dejaba el secreto entero en un contador público — medido: 42 y 181
    // exactos, con `code check` en verde. Que se pueda observar —o recuperar— si la operación
    // falló ES el bit que la regla 1.a prohíbe, así que ahora es fatal.
    let src = "let i be private(9, \"a\")\nlet xs be [1, 2]\nlet e be private(\"\", \"a\")\ntry\n    let y be xs[i]\nrecover err\n    set e to err\n";
    let (_i, r) = run(src, true);
    let msg = match r {
        Err(Control::Error(e)) => {
            assert!(e.is_fatal_for_labels(), "tiene que ser no atrapable");
            e.message
        }
        _ => panic!("un error causado por un privado no se atrapa"),
    };
    assert_eq!(msg, "private(a)", "y sale redactado: {}", msg);

    // La repro entera del informe: el prefijo del bucle ya no llega a escribir el secreto.
    let leak = "let secret be private(181, \"app\")\nlet counter be 0\n\
try\n    each i in range(0, 300)\n        let v be 1 / (secret - i)\n        set counter to counter + 1\n\
recover e\n    let x be 1\n";
    let (i, r) = run(leak, true);
    assert!(matches!(r, Err(Control::Error(_))), "la corrida tiene que morir");
    // `counter` quedó donde el corte lo dejó, pero la corrida no entrega nada: ni el valor ni
    // la salida (el prefijo de `print` es el canal de progreso, ver `redact_output_for_host`).
    assert!(i.output.is_empty() || i.output.len() == 1, "{:?}", i.output);
}

#[test]
fn an_error_independent_of_the_private_data_is_still_catchable() {
    // La otra mitad, que sigue igual: un error que NO depende de lo privado se atrapa, y el
    // mensaje sale etiquetado con lo que el `try` tocó (`try_seen`), porque el cuerpo del
    // `recover` corre bajo esa etiqueta (regla 1.c). Es lo que hace que `e` deba ser privada.
    let src = "let secret be private(5, \"a\")\nlet xs be [1, 2]\nlet e be private(\"\", \"a\")\n\
try\n    let unused be secret + 1\n    let y be xs[9]\nrecover err\n    set e to err\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "e"), "a");
    assert!(plain_of(&i, "e").contains("out of bounds"), "{}", plain_of(&i, "e"));
    // Con `e` pública, el cuerpo del recover ya no puede escribirla: que el recover CORRA es
    // información sobre lo que pasó adentro del try.
    let msg = run_err("let secret be private(5, \"a\")\nlet xs be [1, 2]\nlet e be \"\"\n\
try\n    let unused be secret + 1\n    let y be xs[9]\nrecover err\n    set e to err\n");
    assert!(msg.contains("label_violation") && msg.contains("'e'"), "{}", msg);
    // Y sin privados de por medio, `try/recover` es exactamente lo de siempre.
    let i = run_ok("let e be \"\"\nlet xs be [1, 2]\ntry\n    let y be xs[9]\nrecover err\n    set e to err\n");
    assert_eq!(label_of(&i, "e"), "");
    assert!(plain_of(&i, "e").contains("out of bounds"));
}

#[test]
fn writing_a_private_key_into_an_at_least_as_private_container_proceeds() {
    // (a) el caso central de un enclave: estado {app}, clave del payload {app}.
    let src = "let s be private({\"b\": {}}, \"app\")\nset s[\"b\"][private(\"alice\", \"app\")] to 1\nlet v be s[\"b\"][\"alice\"]\nlet n be length(s[\"b\"])\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "s"), "app");
    assert_eq!(label_of(&i, "v"), "app");
    assert_eq!(plain_of(&i, "v"), "1");
    assert_eq!(plain_of(&i, "n"), "1");
    // El Rc interno es el mismo: la etiqueta vive en la variable y no se pierde.
    let s = env_get(&i.global_env, "s").unwrap();
    assert!(s.is_private());
    assert_eq!(strip_deep(&s).to_string(), "{b: {alice: 1}}");
}

#[test]
fn writing_a_private_key_into_a_public_container_is_refused() {
    // (b) NSU estricto (B1/M4): `m` es público → no se "convierte", es label_violation (la
    // conversión dejaba públicos los alias del mismo Rc).
    let msg = run_err("let m be {}\nset m[private(\"k\", \"a\")] to 1\n");
    assert!(msg.contains("label_violation") && msg.contains("'m'") && msg.contains("private to a"), "{}", msg);
    let msg = run_err("let xs be [1, 2, 3]\nset xs[private(1, \"a\")] to 9\n");
    assert!(msg.contains("label_violation") && msg.contains("'xs'"), "{}", msg);
    let msg = run_err("let m be {\"inner\": {}}\nset m.inner[private(\"k\", \"a\")] to 1\n");
    assert!(msg.contains("label_violation") && msg.contains("'m'"), "{}", msg);
    // La forma correcta: declarar el contenedor privado primero.
    let i = run_ok("let m be private({}, \"a\")\nset m[private(\"k\", \"a\")] to 1\nlet v be m[\"k\"]\n");
    assert_eq!(label_of(&i, "m"), "a");
    assert_eq!(plain_of(&i, "m"), "{k: 1}");
    assert_eq!(label_of(&i, "v"), "a");
}

#[test]
fn writing_a_key_of_another_principal_is_refused() {
    // (c) contenedor {a}, clave {b}: {b} ⊄ {a} → label_violation (no se une).
    let msg = run_err("let m be private({}, \"a\")\nset m[private(\"k\", \"b\")] to 1\n");
    // Ronda 7: el mensaje nombra el conjunto DECLARADO (constante), no cual de los dos era el
    // contenedor y cual la clave — esa distincion dependia del valor y era el canal.
    assert!(msg.contains("label_violation") && msg.contains("'m'") && msg.contains("private to a,b"), "{}", msg);
    // Contenedor {a,b} sí cubre una clave {b}.
    let i = run_ok("let m be private({}, [\"a\", \"b\"])\nset m[private(\"k\", \"b\")] to 1\n");
    assert_eq!(label_of(&i, "m"), "a,b");
    // Una clave pública en un contenedor privado no cambia nada.
    let i2 = run_ok("let m be private({}, \"a\")\nset m[\"k\"] to 1\n");
    assert_eq!(label_of(&i2, "m"), "a");
}

#[test]
fn writing_a_private_key_into_a_non_rebindable_target_is_refused() {
    // (d) el destino no nace de una variable: no hay a quién subirle la etiqueta.
    let src = "let store be {}\ntask box()\n    give store\nset box()[private(\"k\", \"a\")] to 1\n";
    let msg = run_err(src);
    assert!(msg.contains("label_violation"), "{}", msg);
    assert!(msg.contains("private to a"), "{}", msg);
    // Con clave pública el mismo destino sigue funcionando.
    let i = run_ok("let store be {}\ntask box()\n    give store\nset box()[\"k\"] to 1\n");
    assert_eq!(plain_of(&i, "store"), "{k: 1}");
}

#[test]
fn writing_under_a_private_pc_needs_a_container_that_covers_it() {
    // Bajo PC la posición escrita depende de la rama: un contenedor público → label_violation.
    let msg = run_err("let f be private(true, \"a\")\nlet m be {}\nwhen f\n    set m[\"x\"] to 1\n");
    assert!(msg.contains("label_violation") && msg.contains("'m'"), "{}", msg);
    let msg = run_err("let f be private(true, \"a\")\nlet m be {}\nwhen f\n    set m.x to 1\n");
    assert!(msg.contains("label_violation") && msg.contains("'m'"), "{}", msg);
    // El contenedor ya cubría el PC: funciona (el valor escrito sale con el PC).
    let i = run_ok("let f be private(true, \"a\")\nlet s be private({}, \"a\")\nwhen f\n    set s.y to 2\n    set s[\"z\"] to 3\n");
    assert_eq!(label_of(&i, "s"), "a");
    assert_eq!(plain_of(&i, "s"), "{y: 2, z: 3}");
}

// ---------------------------------------------------------------------------------
// declassify / label_of / is_private / print
// ---------------------------------------------------------------------------------

#[test]
fn declassify_total_and_partial() {
    let src = "let x be private(3, \"a\") + private(4, \"b\")\n\
let pub be declassify(x, \"aggregate only\")\n\
let only_a be declassify(x, \"a may see the total\", [\"a\"])\n\
let same be declassify(only_a, \"noop\", \"a\")\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "x"), "a,b");
    assert_eq!(label_of(&i, "pub"), "");
    assert_eq!(plain_of(&i, "pub"), "7");
    assert_eq!(label_of(&i, "only_a"), "a");
    assert_eq!(label_of(&i, "same"), "a");
    let log = i.declassify_log();
    assert_eq!(log.len(), 3);
    assert_eq!(log[0].reason, "aggregate only");
    assert_eq!(label_display_raw(&log[0].from), "a,b");
    assert_eq!(label_display_raw(&log[0].to), "");
    assert_eq!(log[1].reason, "a may see the total");
    assert_eq!(label_display_raw(&log[1].to), "a");
    assert_eq!(log[1].loc.line, 3);
}

// ---------------------------------------------------------------------------------
// declassify como lado derecho de let/set/give escapa al PC (la única vía de escape)
// ---------------------------------------------------------------------------------

#[test]
fn let_declassify_inside_a_private_context_keeps_the_declared_label() {
    // (a) un handler corre bajo PC {a} (match sobre datos privados); el receipt
    // declassificado inline sale público, el resto sigue privado.
    let src = "let v be private(1, \"a\")\n\
task handle(x)\n    let r be declassify(x, \"public receipt\")\n    give {\"pub\": r, \"other\": x}\n\
let result be private(0, \"a\")\n\
match v\n    is 1\n        set result to handle(v)\n";
    let i = run_ok(src);
    let result = env_get(&i.global_env, "result").unwrap();
    // Regla 2: el PC no envuelve contenedores — el mapa sale sin envoltorio y lo privado lo
    // llevan sus campos (`label_deep` los ve, y un sumidero publico lo rechaza igual).
    assert_eq!(label_display_raw(&labels::label(&result)), "");
    assert_eq!(label_display_raw(&label_deep(&result)), "a");
    assert!(check_flow(&result, &[], "result").is_err());
    let inner = labels::unwrap(&result).clone();
    let (pub_v, other_v) = match &inner {
        SynValue::Map(m) => (m.borrow()["pub"].clone(), m.borrow()["other"].clone()),
        _ => panic!("map"),
    };
    assert_eq!(label_display_raw(&label_deep(&pub_v)), "");
    assert_eq!(pub_v.to_string(), "1");
    assert_eq!(label_display_raw(&label_deep(&other_v)), "a");
}

#[test]
fn set_declassify_to_an_outer_public_variable_keeps_it_public() {
    // (b) `set r to declassify(...)` bajo PC no convierte la variable externa; ídem por
    // índice/campo: el contenedor destino no sube al PC.
    let src = "let v be private(5, \"a\")\nlet r be 0\nlet out be {}\nwhen v > 1\n    set r to declassify(v, \"why\")\n    set out[\"total\"] to declassify(v, \"why\")\n    set out.count to declassify(1, \"why\")\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "r"), "");
    assert_eq!(plain_of(&i, "r"), "5");
    assert_eq!(label_of(&i, "out"), "");
    assert_eq!(plain_of(&i, "out"), "{total: 5, count: 1}");
}

#[test]
fn give_declassify_under_pc_returns_a_public_value() {
    // (c)
    let src = "let v be private(5, \"a\")\ntask f(x)\n    when x > 1\n        give declassify(x, \"why\")\n    give 0\nlet r be f(v)\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "r"), "");
    assert_eq!(plain_of(&i, "r"), "5");
    assert_eq!(label_display_raw(&i.declassify_log()[0].from), "a");
}

#[test]
fn partial_declassify_under_a_wider_pc_keeps_only_to() {
    // (d) PC {a,b}; `to = ["a"]` → la variable queda {a}, no {a,b}.
    let src = "let v be private(1, \"a\") + private(2, \"b\")\nlet r be private(0, \"a\")\nwhen v > 1\n    set r to declassify(v, \"why\", [\"a\"])\n    let q be declassify(v, \"why\", [\"a\"])\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "r"), "a");
    assert_eq!(label_of(&i, "q"), "a");
    assert_eq!(plain_of(&i, "q"), "3");
}

#[test]
fn a_plain_binding_under_pc_still_relabels() {
    // (e) control: sólo `declassify(...)` inline escapa; `let r be x` sigue re-etiquetando,
    // igual que un `let` de un valor ya declassificado y que un mapa que lo contiene.
    let src = "let f be private(true, \"a\")\nlet pub be 1\nlet d be private(0, \"a\")\nwhen f\n    let r be pub\n    let dd be declassify(private(2, \"a\"), \"why\")\n    set d to dd\n    let m be {\"k\": declassify(private(3, \"a\"), \"why\")}\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "r"), "a");
    assert_eq!(label_of(&i, "dd"), "");
    // `set d to dd` (un identificador, no una llamada a declassify) sí re-etiqueta.
    assert_eq!(label_of(&i, "d"), "a");
    // Regla 2: el literal de mapa NO se envuelve con el PC; su unico elemento fue
    // declassificado explicitamente, asi que el mapa queda publico de verdad (es lo que
    // permite publicar un recibo armado dentro de la rama).
    assert_eq!(label_of(&i, "m"), "");
    // Y `set pub to dd` a una variable pública sigue siendo label_violation (NSU estricto).
    let msg = run_err("let f be private(true, \"a\")\nlet pub be 1\nwhen f\n    let dd be declassify(2, \"why\")\n    set pub to dd\n");
    assert!(msg.contains("label_violation"), "{}", msg);
}

#[test]
fn declassify_never_widens_and_needs_a_reason() {
    let msg = run_err("let x be private(3, \"a\")\nlet y be declassify(x, \"oops\", [\"a\", \"b\"])\n");
    assert!(msg.contains("declassify: cannot widen a label"), "{}", msg);
    let msg = run_err("let x be private(3, \"a\")\nlet y be declassify(x, \"\")\n");
    assert!(msg.contains("declassify: reason must be a non-empty text"), "{}", msg);
    let msg = run_err("let x be private(3, \"a\")\nlet y be declassify(x)\n");
    assert!(msg.contains("declassify: expects 2 or 3 arguments"), "{}", msg);
}

#[test]
fn label_of_and_is_private() {
    // Regla 3.b: el resultado de `label_of`/`is_private` sale etiquetado con lo que describe
    // (por eso `print` lo redacta); sobre un valor publico sigue siendo publico.
    let src = "let x be private(3, \"b\") + private(1, \"a\")\n\
print(label_of(x))\nprint(label_of(7))\nprint(is_private(x))\nprint(is_private([1, x]))\nprint(is_private(\"t\"))\n";
    let i = run_ok(src);
    assert_eq!(
        i.output,
        vec!["[private(a,b), private(a,b)]", "[]", "private(a,b)", "private(a,b)", "false"]
    );
    // El contenido es el correcto (el host lo lee sin redactar).
    let i = run_ok("let x be private(3, \"b\") + private(1, \"a\")\nlet l be label_of(x)\nlet p be is_private(x)\nlet q be is_private(7)\n");
    assert_eq!(plain_of(&i, "l"), "[\"a\", \"b\"]");
    assert_eq!(label_of(&i, "l"), "a,b");
    assert_eq!(plain_of(&i, "p"), "true");
    assert_eq!(label_of(&i, "p"), "a,b");
    assert_eq!(plain_of(&i, "q"), "false");
    assert_eq!(label_of(&i, "q"), "");
}

#[test]
fn print_show_and_log_redact() {
    // Con el PC PUBLICO, un valor privado sale redactado por Display: eso no cambia.
    let src = "let x be private(3, \"b\") + private(1, \"a\")\nprint(x)\nprint(\"v=\" + x)\nshow x\nlog \"got \" + x\n";
    let i = run_ok(src);
    assert_eq!(i.output, vec!["private(a,b)", "private(a,b)", "private(a,b)", "[LOG] private(a,b)"]);
}

// ---------------------------------------------------------------------------------
// Auditoria externa, ronda 4: los bloqueantes vivos V1 (la tinta de continuacion no cruzaba
// el borde de llamada) y V4 (la cantidad de lineas de stdout no se redactaba).
// ---------------------------------------------------------------------------------

#[test]
fn audit_r4_v4_stdout_is_a_public_sink_under_a_private_branch() {
    // V4: el valor se redactaba y la CANTIDAD de lineas no, asi que una linea por vuelta sobre
    // datos privados los deletrea a quien lee la salida (bajo el guest de un enclave, el log del
    // Executor vive FUERA de el). Las tres bocas del stdout fallan cerrado bajo PC privado,
    // ANTES de escribir.
    for (src, what) in [
        ("let x be private(3, \"a\")\nwhen x > 1\n    print(\"branch\")\n", "print"),
        ("let x be private(3, \"a\")\nwhen x > 1\n    show \"branch\"\n", "show"),
        ("let x be private(3, \"a\")\nwhen x > 1\n    log \"branch\"\n", "log"),
    ] {
        let (i, r) = run(src, true);
        let msg = match r {
            Err(Control::Error(e)) => e.message,
            _ => panic!("{} tenia que violar bajo PC privado", what),
        };
        assert!(msg.contains("label_violation") && msg.contains(what), "{}: {}", what, msg);
        assert!(msg.contains("pc = [a]"), "el mensaje nombra el principal: {}", msg);
        // Falla ANTES de escribir: la linea no llego a la salida, ni siquiera redactada.
        assert!(i.output.is_empty(), "{}: {:?}", what, i.output);
    }
    // El canal completo: un `print` por vuelta sobre una coleccion privada deletrea su largo.
    let loop_src = "let xs be private([1, 2, 3], \"app\")\neach x in xs\n    print(x)\n";
    let msg = run_err(loop_src);
    assert!(msg.contains("label_violation") && msg.contains("print"), "{}", msg);
    // Con las etiquetas apagadas nada de esto existe: es el mismo programa de siempre
    // (`private` ni siquiera carga sin `--labels`, asi que el equivalente es la lista pelada).
    let (i, r) = run("let xs be [1, 2, 3]\neach x in xs\n    print(x)\n", false);
    assert!(r.is_ok(), "con --labels apagado no cambia nada");
    assert_eq!(i.output, vec!["1", "2", "3"]);
}

#[test]
fn audit_r4_v1_the_taint_travels_into_a_helper_with_no_arguments() {
    // V1: el borde de llamada VACIABA la tinta de continuacion al ENTRAR a la task, asi que un
    // helper sin argumentos llamado desde un bucle ya tenido corria con tinta limpia y escribia
    // estado publico sin chequeo. La repro del auditor sacaba el secreto entero (181) por un
    // contador global, con `label_of` → []. El mismo helper CON argumento fallaba cerrado solo
    // por accidente: el argumento se evalua en el llamador, bajo su tinta.
    let src = "let counter be 0\n\
task bump()\n    set counter to counter + 1\n\
task probe(secret)\n    each i in range(0, 256)\n        when secret == i\n            give \"found\"\n        bump()\n    give \"no\"\n\
let r be probe(private(181, \"app\"))\n";
    assert_closed_on(src, "counter");
    // Helper anidado: la tinta tiene que llegar dos llamadas abajo.
    let nested = "let counter be 0\n\
task inner()\n    set counter to counter + 1\n\
task outer()\n    inner()\n\
task probe(secret)\n    each i in range(0, 256)\n        when secret == i\n            give \"found\"\n        outer()\n    give \"no\"\n\
let r be probe(private(77, \"app\"))\n";
    assert_closed_on(nested, "counter");
    // Y con `stop` en vez de `give`.
    let with_stop = "let counter be 0\n\
task bump()\n    set counter to counter + 1\n\
task probe(secret)\n    each i in range(0, 256)\n        when secret == i\n            stop\n        bump()\n    give \"done\"\n\
let r be probe(private(99, \"app\"))\n";
    assert_closed_on(with_stop, "counter");
}

#[test]
fn audit_r4_v1_a_call_does_not_leave_residual_taint_on_the_caller() {
    // La otra mitad del mismo cambio, que es la que los tres tests de regresion de la ronda 3
    // exigen: lo que la task tine ADENTRO no queda sobre la continuacion del llamador. El `give`
    // llega a un join point y la informacion viaja en el VALOR, que sale etiquetado.
    let src = "task guard(x)\n    when x > 0\n        give \"yes\"\n    give \"no\"\n\
let r be guard(private(5, \"app\"))\n\
let allowed be {}\nset allowed[\"ETH\"] to true\nlet pub be 0\nset pub to 1\nprint(\"public work\")\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "r"), "app");
    assert_eq!(label_of(&i, "allowed"), "");
    assert_eq!(label_of(&i, "pub"), "");
    assert_eq!(i.output, vec!["public work"], "el stdout publico del llamador sigue abierto");
}

#[test]
fn private_over_a_secret_is_refused_and_principals_are_validated() {
    // as_secret vive en el stdlib; acá un secret se fabrica por el borde del core.
    let program = parse_source("let y be private(k, \"a\")\n", "<labels>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    interp.set_global("k", synsema_core::types::syn_secret("K", "plain"));
    match interp.execute(&program) {
        Err(Control::Error(e)) => assert!(e.message.contains("a secret is already opaque"), "{}", e),
        _ => panic!("se esperaba error"),
    }
    let msg = run_err("let y be private(1, \"\")\n");
    assert!(msg.contains("private: principal must be a non-empty text"), "{}", msg);
    let msg = run_err("let y be private(1, [])\n");
    assert!(msg.contains("private: principal must be"), "{}", msg);
    let msg = run_err("let y be private(1)\n");
    assert!(msg.contains("private: expects 2 arguments"), "{}", msg);
}

#[test]
fn private_plus_secret_in_an_operation_is_refused() {
    let program = parse_source("let y be private(\"x\", \"a\") + k\n", "<labels>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    interp.set_global("k", synsema_core::types::syn_secret("K", "plain"));
    match interp.execute(&program) {
        Err(Control::Error(e)) => assert!(e.message.contains("a secret is already opaque"), "{}", e),
        _ => panic!("se esperaba error"),
    }
}

// ---------------------------------------------------------------------------------
// API del host: check_flow / strip_deep / mark
// ---------------------------------------------------------------------------------

#[test]
fn check_flow_accepts_and_rejects_with_the_right_path() {
    let src = "let ev be {\"kind\": \"cleared\", \"data\": {\"amount\": private(5, \"a\"), \"n\": 2}}\nlet events be [ev]\n";
    let i = run_ok(src);
    let events = env_get(&i.global_env, "events").unwrap();
    assert!(check_flow(&events, &["a", "b"], "events").is_ok());
    assert!(check_flow(&events, &["a"], "events").is_ok());
    let err = check_flow(&events, &[], "events").unwrap_err();
    assert_eq!(err.path, "events[0].data.amount");
    assert_eq!(label_display_raw(&err.label), "a");
    assert!(
        err.to_string().starts_with(
            "label_violation: events[0].data.amount is private to a, the sink accepts (public); declassify("
        ),
        "{}",
        err
    );
    let err = check_flow(&events, &["b"], "events").unwrap_err();
    assert!(
        err.to_string().starts_with("label_violation: events[0].data.amount is private to a, the sink accepts b;"),
        "{}",
        err
    );
    // Un valor público pasa por cualquier sumidero.
    assert!(check_flow(&syn_int(1), &[], "x").is_ok());
}

#[test]
fn strip_deep_removes_every_label_and_shares_clean_containers() {
    let src = "let m be private({\"a\": [private(1, \"x\"), 2], \"b\": private(\"t\", \"y\")}, \"z\")\n";
    let i = run_ok(src);
    let m = env_get(&i.global_env, "m").unwrap();
    assert_eq!(label_display_raw(&label_deep(&m)), "x,y,z");
    let s = strip_deep(&m);
    assert!(label_deep(&s).is_empty());
    assert_eq!(s.to_string(), "{a: [1, 2], b: \"t\"}");
    // mark desde el host (una fuente): envuelve y une; etiqueta vacía = valor pelado.
    let src_v = mark(syn_list(vec![syn_int(1)]), labels::label_from(&["app"]));
    assert_eq!(label_display_raw(&labels::label(&src_v)), "app");
    assert!(matches!(mark(syn_text("x"), labels::empty()), SynValue::Text(_)));
    let mut mm = indexmap::IndexMap::new();
    mm.insert("k".to_string(), syn_int(1));
    let mv = mark(syn_map(mm), labels::label_from(&["b", "a"]));
    assert_eq!(label_display_raw(&label_deep(&mv)), "a,b");
}

#[test]
fn host_declared_label_aware_builtin_receives_wrapped_values() {
    use std::cell::RefCell;
    use std::rc::Rc;
    let seen: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let program = parse_source("let x be private(5, \"a\")\nsink(x)\nsink2(x)\n", "<labels>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    let s1 = seen.clone();
    interp.register_builtin(
        "sink",
        1,
        Rc::new(move |_i, args, _l| {
            s1.borrow_mut().push(format!("sink:{}", label_display_raw(&label_deep(&args[0]))));
            Ok(SynValue::Nothing)
        }),
    );
    let s2 = seen.clone();
    interp.register_builtin(
        "sink2",
        1,
        Rc::new(move |_i, args, _l| {
            s2.borrow_mut().push(format!("sink2:{}", label_display_raw(&label_deep(&args[0]))));
            Ok(SynValue::Nothing)
        }),
    );
    // Sólo `sink` se declara consciente: recibe el valor envuelto; `sink2` recibe el valor
    // sin etiquetas (regla genérica) — y su resultado sale envuelto.
    interp.register_label_aware("sink");
    interp.execute(&program).unwrap_or_else(|_| panic!("falló"));
    assert_eq!(*seen.borrow(), vec!["sink:a".to_string(), "sink2:".to_string()]);
}

#[test]
fn pc_label_is_visible_to_the_host_during_a_private_branch() {
    use std::cell::RefCell;
    use std::rc::Rc;
    let seen: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let program =
        parse_source("let f be private(true, \"a\")\nwhen f\n    probe()\nprobe()\n", "<labels>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    let s = seen.clone();
    interp.register_builtin(
        "probe",
        0,
        Rc::new(move |i, _args, _l| {
            s.borrow_mut().push(label_display_raw(&i.pc_label()));
            Ok(SynValue::Nothing)
        }),
    );
    interp.register_label_aware("probe");
    interp.execute(&program).unwrap_or_else(|_| panic!("falló"));
    assert_eq!(*seen.borrow(), vec!["a".to_string(), "".to_string()]);
    assert!(label_display_raw(&interp.pc_label()).is_empty());
}

// ---------------------------------------------------------------------------------
// codeintel: listado estático de sitios de declassify (lo que un auditor revisa)
// ---------------------------------------------------------------------------------

#[test]
fn codeintel_lists_declassify_sites_statically() {
    use synsema_core::codeintel::{check, declassify_sites, Root};
    let src = "let x be private(3, \"a\")\n\
task report(v)\n    give declassify(v, \"aggregate only\", [\"a\", \"b\"])\n\
let why be \"dyn\"\n\
let y be declassify(x, why)\n\
let z be declassify(x, \"to one\", \"a\")\n\
let w be declassify(x, \"public\")\n";
    let program = parse_source(src, "<labels>").unwrap();
    let sites = declassify_sites(&program);
    assert_eq!(sites.len(), 4);
    assert_eq!(sites[0].line, 3);
    assert_eq!(sites[0].reason.as_deref(), Some("aggregate only"));
    assert_eq!(sites[0].to, Some(vec!["a".to_string(), "b".to_string()]));
    assert!(!sites[0].constant);
    // Motivo no literal → None (el auditor tiene que mirar el código).
    assert_eq!(sites[1].line, 5);
    assert_eq!(sites[1].reason, None);
    assert_eq!(sites[1].to, None);
    assert_eq!(sites[2].reason.as_deref(), Some("to one"));
    assert_eq!(sites[2].to, Some(vec!["a".to_string()]));
    assert_eq!(sites[3].reason.as_deref(), Some("public"));
    assert_eq!(sites[3].to, None);

    // `constant` = el argumento es un literal (o un nombre ligado a un literal top-level):
    // declassificación pura de PC. L2: también se ve dentro de una lambda.
    let src2 = "let TIER be \"gold\"\nlet v be private(1, \"a\")\n\
let a be declassify(1, \"literal\")\n\
let b be declassify(TIER, \"top const\")\n\
let c be declassify({\"k\": [1, \"x\"]}, \"literal map\")\n\
let d be declassify(v, \"data\")\n\
let f be (x) => declassify(x, \"in lambda\")\n";
    // Un alias directo () SI se sigue: sin esto el listado del auditor
    // quedaba vacio con una linea de indireccion.
    let aliased = "let d be declassify
let e be d
let x be private(1, \"a\")
let y be d(x, \"via alias\")
let z be e(x, \"via alias del alias\")
";
    let asites = declassify_sites(&parse_source(aliased, "<labels>").unwrap());
    assert_eq!(asites.len(), 2, "{:?}", asites);
    assert_eq!(asites[0].reason.as_deref(), Some("via alias"));
    assert_eq!(asites[1].reason.as_deref(), Some("via alias del alias"));

    let sites2 = declassify_sites(&parse_source(src2, "<labels>").unwrap());
    let flags: Vec<(usize, bool)> = sites2.iter().map(|s| (s.line, s.constant)).collect();
    assert_eq!(flags, vec![(3, true), (4, true), (5, true), (6, false), (7, false)]);
    assert_eq!(sites2[4].reason.as_deref(), Some("in lambda"));

    // `check` los publica bajo "declassify" (lista vacía si no hay), módulos incluidos.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("synsema-labels-{}-{}", std::process::id(), nanos));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("main.syn"), "use \"./util.syn\" as util\nlet y be declassify(1, \"main\")\nprint(y)\n").unwrap();
    std::fs::write(dir.join("util.syn"), "export task f(v)\n    give declassify(v, \"in module\", \"a\")\n").unwrap();
    let root = Root::new(&dir);
    let out = check(&root, None);
    let sites = out["declassify"].as_array().expect("declassify key");
    assert_eq!(sites.len(), 2, "{}", out);
    let reasons: Vec<&str> = sites.iter().map(|s| s["reason"].as_str().unwrap_or("")).collect();
    assert!(reasons.contains(&"main"), "{}", out);
    assert!(reasons.contains(&"in module"), "{}", out);
    let module = sites.iter().find(|s| s["reason"] == "in module").unwrap();
    assert_eq!(module["to"], serde_json::json!(["a"]));
    assert_eq!(module["line"], serde_json::json!(2));
    assert_eq!(module["constant"], serde_json::json!(false));
    assert!(module["file"].as_str().unwrap().ends_with("util.syn"));
    let main = sites.iter().find(|s| s["reason"] == "main").unwrap();
    assert_eq!(main["constant"], serde_json::json!(true));
    // El listado es estatico y lo dice (un alias que viajo como parametro no es decidible).
    assert_eq!(out["declassify_static_only"], serde_json::json!(true));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------
// Auditoría externa: cada caso reproducido tal cual.
// Todos FALLABAN antes de la corrección (extraían el valor / lo publicaban / lavaban).
// ---------------------------------------------------------------------------------

#[test]
fn audit_b1_two_branch_extraction_is_a_label_violation() {
    // El contraejemplo Austin–Flanagan del informe: antes imprimía 181 con label_of [].
    let src = "let secret be private(181, \"app\")\nlet found be -1\nlet skip be 0\n\
each i in range(0, 256)\n    let flag be false\n    when secret != i\n        set flag to true\n    when flag\n        set skip to 1\n    otherwise\n        set found to i\n\
print(found)\nprint(label_of(found))\n";
    let msg = run_err(src);
    assert!(msg.contains("label_violation"), "{}", msg);
    assert!(msg.contains("'flag'") && msg.contains("pc = [app]"), "{}", msg);
}

#[test]
fn audit_b2_implicit_task_value_carries_the_pc() {
    // Antes: `print(r)` → big, `label_of(r)` → [].
    let src = "task classify(x)\n    when x > 10\n        \"big\"\n    otherwise\n        \"small\"\n\
let r be classify(private(20, \"a\"))\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "r"), "a");
    assert_eq!(plain_of(&i, "r"), "big");
    // También cuando la expresión final no es un literal (una variable pública) y con match.
    let src2 = "let pubv be 7\ntask f(x)\n    when x > 1\n        pubv\n    otherwise\n        pubv\n\
task g(x)\n    match x\n        is 1\n            pubv\n        otherwise\n            pubv\n\
let r be f(private(2, \"a\"))\nlet s be g(private(1, \"b\"))\nlet t be f(2)\n";
    let i2 = run_ok(src2);
    assert_eq!(label_of(&i2, "r"), "a");
    assert_eq!(label_of(&i2, "s"), "b");
    assert_eq!(label_of(&i2, "t"), "");
}

#[test]
fn audit_b3_match_guard_pattern_and_container_push_the_pc() {
    // Los cuatro casos del informe imprimían la rama con label_of → [].
    let guard = "let secret be private(5, \"a\")\ntask f()\n    match 1\n        is 1 when secret > 3\n            \"yes\"\n        otherwise\n            \"no\"\nlet r be f()\n";
    let i = run_ok(guard);
    assert_eq!(label_of(&i, "r"), "a");
    assert_eq!(plain_of(&i, "r"), "yes");
    let pattern = "let secret be private(5, \"a\")\ntask f()\n    match 5\n        is secret\n            \"eq\"\n        otherwise\n            \"ne\"\nlet r be f()\n";
    let i = run_ok(pattern);
    assert_eq!(label_of(&i, "r"), "a");
    assert_eq!(plain_of(&i, "r"), "eq");
    // Sujeto público en la superficie con un elemento privado: patrón estructural.
    let container = "let m be {\"kind\": private(\"x\", \"a\"), \"n\": 1}\ntask f()\n    match m\n        is {kind: k, n: n}\n            [k, n, \"has\"]\n        otherwise\n            \"none\"\nlet r be f()\n";
    let i = run_ok(container);
    assert_eq!(label_of(&i, "r"), "a");
    let inner = strip_deep(&env_get(&i.global_env, "r").unwrap());
    assert_eq!(inner.to_string(), "[\"x\", 1, \"has\"]");
    // El binder público `n` también sale con el PC del sujeto.
    let r = env_get(&i.global_env, "r").unwrap();
    if let SynValue::List(l) = labels::unwrap(&r) {
        assert_eq!(label_display_raw(&label_deep(&l.borrow()[1])), "a");
    } else {
        panic!("list");
    }
    // Control: un match público sigue público; la rama `otherwise` también va bajo PC.
    let i = run_ok("task f()\n    match 1\n        is 1\n            \"one\"\nlet r be f()\n");
    assert_eq!(label_of(&i, "r"), "");
    let i = run_ok("let s be private(9, \"a\")\ntask f()\n    match 1\n        is s\n            \"eq\"\n        otherwise\n            \"ne\"\nlet r be f()\n");
    assert_eq!(label_of(&i, "r"), "a");
    assert_eq!(plain_of(&i, "r"), "ne");
}

#[test]
fn audit_b4_deep_equality_is_private() {
    // Antes: `{"k": private(1,"a")} == {"k": 1}` → true con label_of → [].
    let src = "let e be {\"k\": private(1, \"a\")} == {\"k\": 1}\nlet ne be [private(1, \"a\")] != [2]\nlet c be {\"k\": private(1, \"a\")} and true\nlet nn be not [private(1, \"a\")]\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "e"), "a");
    assert_eq!(plain_of(&i, "e"), "true");
    assert_eq!(label_of(&i, "ne"), "a");
    assert_eq!(label_of(&i, "c"), "a");
    assert_eq!(label_of(&i, "nn"), "a");
    // Y un `when` sobre ese contenedor empuja PC.
    let msg = run_err("let m be {\"k\": private(1, \"a\")}\nlet out be 0\nwhen m\n    set out to 1\n");
    assert!(msg.contains("label_violation"), "{}", msg);
}

#[test]
fn audit_b5_scalar_literals_under_pc_carry_the_pc() {
    // Antes: `{"tier": "gold"}` en la rama privada salía público campo a campo.
    let src = "let s be {\"secret\": private(42, \"app\")}\nwhen s[\"secret\"] > 10\n    let ev be {\"data\": {\"tier\": \"gold\"}}\notherwise\n    let ev be {\"data\": {\"tier\": \"silver\"}}\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "ev"), "app");
    // La variable lleva el PC por el `let`; el LITERAL escalar de adentro también: al
    // desenvolver el nivel superior, `data.tier` sigue siendo privado.
    let ev = env_get(&i.global_env, "ev").unwrap();
    let top = labels::unwrap(&ev).clone();
    assert!(matches!(top, SynValue::Map(_)), "el literal Map no se envuelve como contenedor");
    let data = match &top {
        SynValue::Map(m) => m.borrow()["data"].clone(),
        _ => unreachable!(),
    };
    assert!(matches!(data, SynValue::Map(_)));
    let tier = match &data {
        SynValue::Map(m) => m.borrow()["tier"].clone(),
        _ => unreachable!(),
    };
    assert_eq!(label_display_raw(&label_deep(&tier)), "app");
    assert_eq!(strip_deep(&tier).to_string(), "gold");
    assert!(check_flow(&top, &[], "result").is_err());
    // Un `declassify(...)` inline dentro del literal sí queda público (y con `from [app]`).
    let src2 = "let f be private(true, \"app\")\ntask mk()\n    when f\n        give {\"pub\": declassify(\"gold\", \"tier is public\"), \"n\": 1}\n    give {}\nlet r be mk()\n";
    let i2 = run_ok(src2);
    let r = labels::unwrap(&env_get(&i2.global_env, "r").unwrap()).clone();
    let (p, n) = match &r {
        SynValue::Map(m) => (m.borrow()["pub"].clone(), m.borrow()["n"].clone()),
        _ => panic!("map"),
    };
    assert_eq!(label_display_raw(&label_deep(&p)), "");
    assert_eq!(label_display_raw(&label_deep(&n)), "app");
    assert_eq!(label_display_raw(&i2.declassify_log()[0].from), "app");
}

#[test]
fn audit_b6_declassify_of_a_constant_under_pc_records_the_real_from() {
    // Antes: `from [] to []` y el PC se borraba. Ahora from = label_deep(v) ∪ PC.
    let src = "let p be {\"type\": private(\"a\", \"app\")}\nlet r be 0\nwhen p[\"type\"] == \"a\"\n    set r to declassify(1, \"branch a\")\notherwise\n    set r to declassify(2, \"branch b\")\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "r"), "");
    assert_eq!(plain_of(&i, "r"), "1");
    let log = i.declassify_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].reason, "branch a");
    assert_eq!(label_display_raw(&log[0].from), "app");
    assert_eq!(label_display_raw(&log[0].to), "");
    // El programa del informe TAL CUAL (`otherwise 2` sin declassify): la rama pública
    // asigna bajo PC a una variable pública → label_violation, no `r = 2` público.
    let msg = run_err("let p be {\"type\": private(\"b\", \"app\")}\nlet r be 0\nwhen p[\"type\"] == \"a\"\n    set r to declassify(1, \"branch a\")\notherwise\n    set r to 2\n");
    assert!(msg.contains("label_violation") && msg.contains("'r'"), "{}", msg);
    // Contador dentro de un each privado: cada declassify registra el PC real.
    let i = run_ok("let lst be private([1, 2, 3], \"b\")\nlet n be 0\neach x in lst\n    set n to declassify(n + 1, \"count\")\n");
    assert_eq!(label_of(&i, "n"), "");
    assert_eq!(plain_of(&i, "n"), "3");
    assert!(i.declassify_log().iter().all(|e| label_display_raw(&e.from) == "b"));
    // `give declassify(...)` bajo PC: público, pero registrado desde [a].
    let i = run_ok("let x be private(9, \"a\")\ntask f()\n    when x > 5\n        give declassify(\"big\", \"threshold\")\n    give \"small\"\nlet r be f()\n");
    assert_eq!(label_of(&i, "r"), "");
    assert_eq!(label_display_raw(&i.declassify_log()[0].from), "a");
    // Reducir a un `to` que el PC cubre funciona; ampliar más allá de from ∪ PC no.
    let i = run_ok("let f be private(true, \"a\")\nlet r be 0\nwhen f\n    set r to declassify(1, \"keep a\", [\"a\"])\n");
    assert_eq!(label_of(&i, "r"), "a");
    let msg = run_err("let f be private(true, \"a\")\nlet r be 0\nwhen f\n    set r to declassify(1, \"widen\", [\"a\", \"b\"])\n");
    // Ronda 8: el mensaje no nombra la etiqueta del VALOR (variaba con cual era); nombra el
    // `to` que se escribio en esta llamada, que es un literal, y que hacer en su lugar.
    assert!(msg.contains("cannot widen a label") && msg.contains("[a,b] is not a subset"), "{}", msg);
}

#[test]
fn audit_b7_sinks_are_checked_before_running() {
    use std::cell::RefCell;
    use std::rc::Rc;
    fn with_sink(src: &str) -> (Interpreter, Result<SynValue, Control>, Rc<RefCell<Vec<String>>>) {
        let seen: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let program = parse_source(src, "<labels>").unwrap();
        let mut interp = Interpreter::new();
        interp.set_labels(true);
        let s = seen.clone();
        interp.register_builtin(
            "emit",
            1,
            Rc::new(move |_i, args, _l| {
                s.borrow_mut().push(args[0].to_string());
                Ok(SynValue::Nothing)
            }),
        );
        interp.register_label_sink("emit");
        let r = interp.execute(&program);
        (interp, r, seen)
    }
    fn err_of(r: Result<SynValue, Control>) -> String {
        match r {
            Err(Control::Error(e)) => e.message,
            _ => panic!("se esperaba error"),
        }
    }
    // Valor privado (antes el sumidero lo recibía en claro): el builtin NO corre. El
    // diagnóstico del sistema de etiquetas (sin valores) llega intacto al host.
    let (_i, r, seen) = with_sink("emit(private(5, \"a\"))\n");
    let msg = err_of(r);
    assert!(
        msg.starts_with("label_violation: emit(argument 0) is private to a, the sink accepts (public);"),
        "{}",
        msg
    );
    assert!(seen.borrow().is_empty());
    // Anidado: camino completo. Y el veredicto del enforcement NO se atrapa con try/recover
    // (regla 1.a): el programa muere con el mismo mensaje.
    let (_i, r, _) = with_sink("let e be \"\"\ntry\n    emit({\"k\": [private(1, \"a\")]})\nrecover err\n    set e to err\n");
    assert!(err_of(r).starts_with("label_violation: emit(argument 0).k[0] is private to a, the sink accepts (public);"));
    // Bajo PC, aun con argumento público.
    let (_i, r, _) = with_sink("let f be private(true, \"a\")\nwhen f\n    emit(1)\n");
    assert!(err_of(r).contains("emit called under private control flow (pc = [a])"));
    // Público y sin PC: corre. Declassificado: corre.
    let (_i, r, seen) = with_sink("emit(1)\nemit(declassify(private(5, \"a\"), \"ok\"))\n");
    assert!(r.is_ok());
    assert_eq!(*seen.borrow(), vec!["1".to_string(), "5".to_string()]);
    // Los sumideros del core: `llm_step` con un prompt privado no llega al proveedor.
    assert!(synsema_core::interpreter::CORE_SINK_BUILTINS.contains(&"llm_step"));
    let msg = run_err("let p be private(\"secret prompt\", \"a\")\nlet r be llm_step(p, [], {})\n");
    assert!(msg.contains("label_violation: llm_step(argument 0) is private to a"), "{}", msg);
    // Sentencias con efecto: `share` bajo PC / con valor privado.
    let msg = run_err("share private(1, \"a\") as \"k\"\n");
    assert!(msg.contains("label_violation: share(argument 0) is private to a"), "{}", msg);
    let msg = run_err("let f be private(true, \"a\")\nwhen f\n    share 1 as \"k\"\n");
    assert!(msg.contains("share called under private control flow (pc = [a])"), "{}", msg);
    // try/recover no lo atrapa (regla 1.a).
    let msg = run_err("let e be \"\"\ntry\n    share private(1, \"a\") as \"k\"\nrecover err\n    set e to err\n");
    assert!(msg.contains("label_violation: share(argument 0) is private to a"), "{}", msg);
}

#[test]
fn audit_b8_protected_names_cannot_be_redefined() {
    // Antes: `task private(v, p) give v` ganaba al builtin y `label_of(x)` → [].
    let src = "task private(v, p)\n    give v\ntask declassify(v, r)\n    give v\nlet x be private(5, \"app\")\nprint(label_of(x))\n";
    let (_i, r) = run(src, true);
    let msg = match r {
        Err(Control::Error(e)) => e.to_string(),
        _ => panic!("se esperaba error de carga"),
    };
    assert!(msg.contains("'private' is a protected builtin"), "{}", msg);
    assert!(msg.starts_with("<labels>:1:"), "ubicación de la task: {}", msg);
    // Con etiquetas apagadas también (es error de carga, no del modo).
    let (_i, r) = run("task label_of(v)\n    give v\n", false);
    assert!(matches!(r, Err(Control::Error(e)) if e.message.contains("'label_of' is a protected builtin")));
    // Ligar el nombre a algo INVOCABLE sigue siendo error de carga (el ataque era interceptar
    // la llamada): task, lambda, tipo/enum/grupo de rutas.
    for src in [
        "let declassify be (v, r) => v\n",
        "task private(v, p)\n    give v\n",
    ] {
        let (_i, r) = run(src, false);
        assert!(matches!(r, Err(Control::Error(e)) if e.message.contains("protected builtin")), "{}", src);
    }
    // NERFEO revertido : son palabras clave BLANDAS, así que ligarlas a un valor que
    // no se puede invocar vuelve a cargar — `conformance/core/053` es exactamente esto.
    let i = run_ok("let private be 5\nprint(private)\n");
    assert_eq!(i.output, vec!["5"]);
    let i = run_ok("let declassify be 1\nlet label_of be 2\nprint(text(declassify + label_of))\n");
    assert_eq!(i.output, vec!["3"]);
    // Pero si ese nombre se USA como llamada y no resuelve al builtin, es error (cubre los
    // caminos dinámicos que el chequeo estático no ve: un parámetro, un alias de módulo).
    let msg = run_err("task f(private)\n    give private(1, \"a\")\nlet r be f((v, p) => v)\n");
    assert!(msg.contains("does not resolve to it"), "{}", msg);
    let msg = run_err("let private be 5\nlet x be private(1, \"a\")\n");
    assert!(msg.contains("does not resolve to it"), "{}", msg);
    // El programa correcto sigue funcionando.
    let i = run_ok("let x be private(5, \"app\")\nlet l be label_of(x)\n");
    assert_eq!(plain_of(&i, "l"), "[\"app\"]");
}

#[test]
fn audit_m1_uncaught_errors_are_redacted_when_the_error_touched_privates() {
    // Antes: `Runtime error: balance is 1234`.
    let (i, r) = run("let x be private(1234, \"a\")\nraise \"balance is \" + text(x)\n", true);
    match r {
        Err(Control::Error(e)) => {
            assert_eq!(e.message, "private(a)");
            // Regresión detectada en auditoría: `raise` conserva file:line:col.
            assert_eq!(e.location.as_ref().map(|l| l.line), Some(2), "la ubicación se conserva");
        }
        _ => panic!("se esperaba error"),
    }
    assert!(i.private_seen());
    // La ubicación se conserva (un error que la tiene).
    let (_i, r) = run("let xs be [1]\nlet i be private(9, \"a\")\nlet y be xs[i]\n", true);
    match r {
        Err(Control::Error(e)) => {
            assert_eq!(e.message, "private(a)");
            assert_eq!(e.location.as_ref().map(|l| l.line), Some(3), "la ubicación se conserva");
        }
        _ => panic!("se esperaba error"),
    }
    // Los diagnósticos del propio sistema de etiquetas (sin valores adentro) NO se redactan.
    let (_i, r) = run("let f be private(true, \"a\")\nlet out be 0\nwhen f\n    set out to 1\n", true);
    assert!(matches!(r, Err(Control::Error(e)) if e.message.starts_with("label_violation:")));
    // Índice fuera de rango con índice privado, clave inexistente en un mapa privado,
    // invariante sobre un privado, conversión: todos redactados.
    for src in [
        "let xs be [1]\nlet i be private(9, \"a\")\nlet y be xs[i]\n",
        "let m be private({\"k\": 1}, \"a\")\nlet y be m[\"secretkey\"]\n",
        "let x be private(-1, \"a\")\ninvariant \"positive\": x > 0\n",
        "let f be private(true, \"a\")\nwhen f\n    let n be number(\"abc\")\n",
    ] {
        let (_i, r) = run(src, true);
        match r {
            Err(Control::Error(e)) => assert_eq!(e.message, "private(a)", "{}", src),
            _ => panic!("se esperaba error: {}", src),
        }
    }
    // Sin privados en la corrida el mensaje sigue intacto; con etiquetas apagadas también.
    let (i, r) = run("let y be 5 % 0\n", true);
    assert!(matches!(r, Err(Control::Error(e)) if e.message == "Modulo by zero"));
    assert!(!i.private_seen());
    let (_i, r) = run("let x be 1234\nraise \"balance is \" + text(x)\n", false);
    assert!(matches!(r, Err(Control::Error(e)) if e.message == "balance is 1234"));
}

#[test]
fn audit_m2_secret_under_pc_is_refused() {
    // Antes: elegir entre dos secrets por un privado dejaba `s` con label_of → [].
    let program = parse_source("let f be private(true, \"a\")\nlet s be k2\nwhen f\n    set s to k1\n", "<labels>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    interp.set_global("k1", synsema_core::types::syn_secret("K1", "yes"));
    interp.set_global("k2", synsema_core::types::syn_secret("K2", "no"));
    match interp.execute(&program) {
        Err(Control::Error(e)) => assert!(e.message.contains("private(a)") || e.message.contains("a secret is already opaque"), "{}", e),
        _ => panic!("se esperaba error"),
    }
    // También un `let` nuevo de un secret dentro de la rama.
    let program = parse_source("let f be private(true, \"a\")\nwhen f\n    let s be k1\n", "<labels>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    interp.set_global("k1", synsema_core::types::syn_secret("K1", "yes"));
    assert!(matches!(interp.execute(&program), Err(Control::Error(_))));
}

#[test]
fn audit_m3_principal_and_reason_must_be_public() {
    // Antes: `private(1, private("alice-secret","app"))` → label_of → [alice-secret].
    let msg = run_err("let x be private(1, private(\"alice-secret\", \"app\"))\n");
    assert!(msg.contains("private: the principal must be a text literal"), "{}", msg);
    let msg = run_err("let x be private(1, \"a\")\nlet y be declassify(x, private(\"why\", \"a\"))\n");
    assert!(msg.contains("declassify: reason must be public"), "{}", msg);
    let msg = run_err("let x be private(1, \"a\")\nlet y be declassify(x, \"why\", private(\"a\", \"a\"))\n");
    assert!(msg.contains("declassify: the principal must be a text literal"), "{}", msg);
}

#[test]
fn audit_m4_aliases_cannot_be_written_under_pc() {
    // Antes: se religaba la raíz en el env actual y el alias conservaba el wrapper público.
    let msg = run_err("let m be {}\nlet n be m\nlet f be private(true, \"a\")\nwhen f\n    set n[\"k\"] to 1\n");
    assert!(msg.contains("label_violation") && msg.contains("'n'"), "{}", msg);
    let msg = run_err("let m be {}\ntask w(t)\n    set t[\"k\"] to 1\nlet f be private(true, \"a\")\nwhen f\n    w(m)\n");
    assert!(msg.contains("label_violation") && msg.contains("'t'"), "{}", msg);
    // Escribir en la copia de un contenedor privado que cubre el PC funciona; desde v0.6.29
    // (semántica de valor) la escritura queda en `t` y no llega a `s`.
    let i = run_ok("let s be private({}, \"a\")\nlet t be s\nlet f be private(true, \"a\")\nwhen f\n    set t[\"k\"] to 1\nlet v be t[\"k\"]\nlet had be contains(s, \"k\")\n");
    assert_eq!(label_of(&i, "v"), "a");
    assert_eq!(plain_of(&i, "v"), "1");
    assert_eq!(plain_of(&i, "had"), "false");
}

#[test]
fn audit_l1_steps_carries_what_the_run_touched() {
    // Mientras la corrida no toco nada privado, `steps()` es un numero publico y se puede
    // guardar en una variable publica de instrumentacion: eso no cambia.
    let i = run_ok("let st0 be steps()\nlet contador be 0\nset contador to steps()\n");
    assert_eq!(label_of(&i, "st0"), "");
    assert_eq!(label_of(&i, "contador"), "");

    // Ronda 5: en cuanto la corrida TOCA un privado, `steps()` sale con la union de lo tocado.
    // La decision anterior —"es un canal publico, sale con el PC del sitio donde se lo llama"—
    // se tomo antes de medir el canal: el contador es un paso por nodo del AST, o sea lineal en
    // lo que el programa recorrio, asi que despues de un bucle cuya condicion dependio de un
    // secreto ES el secreto con una multiplicacion y una suma encima. Medido: `(steps() - base
    // - 24) / 4` lo reconstruia exacto, en una linea, sin `declassify` y sin violacion.
    let i = run_ok("let base be steps()\nlet x be private(1, \"a\") + 1\nlet st be steps()\n");
    assert_eq!(label_of(&i, "base"), "", "lo de antes de tocar nada sigue publico");
    assert_eq!(label_of(&i, "st"), "a");

    // La repro del auditor, cerrada: el numero recuperado sale etiquetado.
    let src = "task probe(secret)\n    each i in range(0, 256)\n        when secret == i\n            give \"found\"\n    give \"no\"\n\
let base be steps()\nlet r be probe(private(181, \"app\"))\nlet recovered be (steps() - base - 24) / 4\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "recovered"), "app", "el escalar reconstruido no puede salir publico");

    // Dentro de una rama privada lleva ademas el PC, como cualquier valor calculado ahi.
    let i = run_ok("let f be private(true, \"a\")\nlet s be private(0, \"a\")\nwhen f\n    set s to steps()\n");
    assert_eq!(label_of(&i, "s"), "a");

    // La salida declarada para instrumentacion despues de tocar privados es `declassify`, que
    // queda auditado y listado por `code check` — publicar el costo es una decision, no un
    // descuido.
    let i = run_ok("let x be private(1, \"a\") + 1\nlet cost be declassify(steps(), \"the step count is published as a cost metric\")\n");
    assert_eq!(label_of(&i, "cost"), "");
    assert_eq!(i.declassify_log().len(), 1);
}

// ---------------------------------------------------------------------------------
// Etiquetas apagadas: coste y semántica cero
// ---------------------------------------------------------------------------------

#[test]
fn labels_off_private_errors_and_declassify_is_identity() {
    let (_i, r) = run("let x be private(1, \"a\")\n", false);
    match r {
        Err(Control::Error(e)) => assert!(e.message.contains("private: labels are off"), "{}", e),
        _ => panic!("se esperaba error"),
    }
    let (i, r) = run("let x be declassify(41, \"why\") + 1\nprint(x)\nprint(label_of(x))\nprint(is_private(x))\n", false);
    assert!(matches!(r, Ok(_)));
    assert_eq!(i.output, vec!["42", "[]", "false"]);
    assert!(i.declassify_log().is_empty());
    assert!(!i.labels_enabled());
    // El motivo se valida igual (es parte del programa).
    let (_i, r) = run("let x be declassify(41, \"\")\n", false);
    assert!(matches!(r, Err(Control::Error(_))));
}

#[test]
fn steps_and_output_do_not_change_with_labels_on_for_a_program_without_labels() {
    let src = "let xs be [3, 1, 2]\nlet total be 0\neach x in xs\n    when x > 1\n        set total to total + x\n\
task twice(v)\n    give v * 2\n\
let ys be apply(xs, twice)\nlet m be {\"k\": total}\nprint(text(total) + \" \" + text(m.k))\nprint(join(sort_by(ys, (v) => v), \",\"))\n\
try\n    let z be xs[9]\nrecover e\n    print(e)\n";
    let (off, r_off) = run(src, false);
    let (on, r_on) = run(src, true);
    assert!(matches!(r_off, Ok(_)));
    assert!(matches!(r_on, Ok(_)));
    assert_eq!(off.output, on.output);
    assert_eq!(off.steps(), on.steps());
    assert_eq!(off.output[0], "5 5");
    assert_eq!(off.output[1], "2,4,6");
}

// ---------------------------------------------------------------------------------
// Auditoría externa — salida temprana desde control privado: las diez variantes
// con el programa EXACTO del informe. Todas extraían el valor privado entero a una
// variable pública (`label_of` → []), sin un solo `declassify`.
// ---------------------------------------------------------------------------------

/// El valor privado nunca terminó en una variable pública: o el programa murió, o lo que
/// quedó lleva etiqueta. Devuelve el mensaje de error si murió.
fn assert_not_extracted(src: &str, var: &str) -> Option<String> {
    let (i, r) = run(src, true);
    match r {
        Err(Control::Error(e)) => Some(e.message),
        Err(_) => Some("give/stop fuera de lugar".to_string()),
        Ok(_) => {
            let v = env_get(&i.global_env, var).unwrap_or_else(|| panic!("sin variable {}", var));
            let plain = strip_deep(&v).to_string();
            assert!(
                !label_deep(&v).is_empty(),
                "EXTRAIDO: {} = {} con label_of = [] \nfuente:\n{}",
                var,
                plain,
                src
            );
            None
        }
    }
}

#[test]
fn audit_r2_1a_nsu_violation_caught_with_try_recover() {
    // El enforcement ERA el canal: el NSU abortaba, el aborto se atrapaba, y atraparlo era un
    // bit público por iteración (Austin–Flanagan restaurado). Ahora un error nacido bajo PC
    // privado no es atrapable: la corrida muere.
    let src = "let secret be private(181, \"app\")\nlet found be -1\nlet sink be 0\n\
each i in range(0, 256)\n    try\n        when secret == i\n            set sink to 1\n    recover e\n        set found to i\n\
print(found)\nprint(label_of(found))\nprint(is_private(found))\n";
    let msg = assert_not_extracted(src, "found").expect("la corrida tiene que morir");
    assert!(msg.contains("label_violation") && msg.contains("'sink'"), "{}", msg);
}

#[test]
fn audit_r2_1b_raise_inside_a_private_branch_is_not_catchable() {
    // Sin violación de NSU: un `raise` legítimo dentro de la rama privada.
    let src = "let secret be private(181, \"app\")\nlet found be -1\n\
each i in range(0, 256)\n    try\n        when secret == i\n            raise \"hit\"\n    recover e\n        set found to i\n\
print(found)\n";
    let msg = assert_not_extracted(src, "found").expect("la corrida tiene que morir");
    // Sale redactado hacia el host (el mensaje del programa no viaja).
    assert_eq!(msg, "private(app)", "{}", msg);
}

#[test]
fn audit_r2_1c_stop_under_a_private_condition_taints_what_follows() {
    // `stop` bajo condición privada, sin `try` y sin violación alguna: el contador delataba
    // el secreto. Ahora el `stop` tiñe lo que sigue (hasta el borde de la task).
    let src = "let secret be private(181, \"app\")\nlet counter be 0\nlet found be -1\n\
each i in range(0, 256)\n    when secret == i\n        stop\n    set counter to counter + 1\n\
set found to counter\n";
    let msg = assert_not_extracted(src, "found").expect("la corrida tiene que morir");
    // Con la tinta en la RAMA la corrida muere en la vuelta 0, al escribir el contador — antes
    // de que el secreto llegue a ninguna variable.
    assert!(msg.contains("label_violation") && msg.contains("'counter'"), "{}", msg);

    // Ronda 3: la tinta va en la RAMA, así que el contador público viola en la vuelta 0 — el
    // secreto NUNCA llega a escribirse (antes se escribía y recién después se teñía).
    let src2 = "let secret be private(181, \"app\")\nlet counter be 0\n\
each i in range(0, 256)\n    when secret == i\n        stop\n    set counter to counter + 1\n\
print(counter)\n";
    let msg = run_err(src2);
    assert!(msg.contains("label_violation") && msg.contains("'counter'"), "{}", msg);
    // Declarado privado, el contador funciona y su valor queda etiquetado.
    let src2b = "let secret be private(181, \"app\")\nlet counter be private(0, \"app\")\n\
each i in range(0, 256)\n    when secret == i\n        stop\n    set counter to counter + 1\n";
    let i = run_ok(src2b);
    assert_eq!(label_of(&i, "counter"), "app");
    assert_eq!(plain_of(&i, "counter"), "181");
    // Ronda 4 (V4): DENTRO del bucle tenido, un `print` por vuelta cuenta las vueltas —o sea el
    // secreto— en la CANTIDAD de lineas, y eso la redaccion del valor no lo tapa.
    let per_iteration = "let secret be private(181, \"app\")\n\
each i in range(0, 256)\n    when secret == i\n        stop\n    print(\"tick\")\n";
    let msg = run_err(per_iteration);
    assert!(msg.contains("label_violation") && msg.contains("print"), "{}", msg);
    // Ronda 5: DESPUES del bucle, en cambio, los dos caminos convergen y la tinta del `stop` ya
    // no rige. Una linea publica y constante ahi no lleva ni un bit, y volvio a compilar — lo
    // contrario empujaba a declassificar la condicion secreta para poder registrar algo publico.
    let i = run_ok(&format!("{}print(counter)\n", src2b));
    assert_eq!(i.output, vec!["private(app)"], "el VALOR sigue redactandose");
    let after_loop = "let secret be private(181, \"app\")\nlet orders be [80, 70, 60, 40, 90]\n\
each o in orders\n    when o < secret\n        stop\n\
log \"screening done: \" + text(length(orders))\n";
    let i = run_ok(after_loop);
    assert_eq!(i.output, vec!["[LOG] screening done: 5"]);
    let per_iteration = "let secret be private(181, \"app\")\n\
each i in range(0, 256)\n    when secret == i\n        stop\n    print(\"tick\")\n";
    let msg = run_err(per_iteration);
    assert!(msg.contains("label_violation") && msg.contains("print"), "{}", msg);

    // El alcance es acotado: al salir de la task se limpia (lo de adentro no tiñe al llamador).
    let src3 = "let secret be private(181, \"app\")\n\
task scan()\n    each i in range(0, 256)\n        when secret == i\n            stop\n    give 0\n\
let r be scan()\nlet pub be 0\nset pub to 1\nlet m be {}\nset m[\"k\"] to 1\n";
    let i3 = run_ok(src3);
    assert_eq!(label_of(&i3, "pub"), "");
    assert_eq!(label_of(&i3, "m"), "");
}

#[test]
fn audit_r2_1d_early_termination_inside_the_try_is_not_observable() {
    // Terminación temprana dentro del mismo `try`, sin usar el `recover`: `after` quedaba
    // "reached" o "not-reached" según el secreto, público.
    let src = "let secret be private(true, \"app\")\nlet after be \"not-reached\"\n\
try\n    when secret\n        raise \"stop here\"\n    set after to \"reached\"\nrecover e\n    print(\"(recovered)\")\n";
    let msg = assert_not_extracted(src, "after").expect("la corrida tiene que morir");
    assert_eq!(msg, "private(app)", "{}", msg);
    // El `recover` no llegó a correr (si no, sería observable que corrió).
    let (i, _) = run(src, true);
    assert!(i.output.is_empty(), "{:?}", i.output);
}

#[test]
fn audit_r2_1e_a_literal_index_no_longer_inflates_the_container_label() {
    // La protección dependía de la sintaxis: `set m.a.b` fallaba y `set m["a"]["b"]` pasaba,
    // porque el índice literal marcado por el PC inflaba la etiqueta del intermedio.
    let bracket = "let secret be private(true, \"app\")\nlet m be {\"a\": {}}\n\
when secret\n    set m[\"a\"][\"b\"] to 77\n";
    let msg = run_err(bracket);
    assert!(msg.contains("label_violation") && msg.contains("'m'"), "{}", msg);
    // La forma con punto falla igual (misma regla, misma explicación).
    let dotted = "let secret be private(true, \"app\")\nlet m be {\"a\": {}}\n\
when secret\n    set m.a.b to 77\n";
    let msg2 = run_err(dotted);
    assert!(msg2.contains("label_violation") && msg2.contains("'m'"), "{}", msg2);
    // Y con el contenedor declarado privado, las dos formas funcionan.
    let ok = "let secret be private(true, \"app\")\nlet m be private({\"a\": {}}, \"app\")\n\
when secret\n    set m[\"a\"][\"b\"] to 77\n    set m.a.c to 78\n";
    let i = run_ok(ok);
    assert_eq!(label_of(&i, "m"), "app");
    assert_eq!(plain_of(&i, "m"), "{a: {b: 77, c: 78}}");
}

#[test]
fn audit_r2_1f_private_of_a_public_container_copies_it() {
    // `private(pub, "app")` fabricaba un alias privado sobre el objeto PÚBLICO: escribir por
    // el alias (legal, cubre el PC) mutaba el original, que se leía después sin etiqueta.
    let src = "let pub be {}\nlet priv be private(pub, \"app\")\nset priv[\"k\"] to 123\n";
    let i = run_ok(src);
    assert_eq!(plain_of(&i, "priv"), "{k: 123}");
    assert_eq!(plain_of(&i, "pub"), "{}", "el objeto público no se mutó");
    assert_eq!(label_of(&i, "pub"), "");
    // Anidado: la copia es profunda.
    let src2 = "let pub be {\"inner\": {}}\nlet priv be private(pub, \"app\")\nset priv[\"inner\"][\"k\"] to 1\n";
    let i2 = run_ok(src2);
    assert_eq!(plain_of(&i2, "pub"), "{inner: {}}");
    // Lo mismo por el camino del parámetro de una task (el contenedor es del llamador).
    let src3 = "let pub be {}\ntask mark(t)\n    let p be private(t, \"app\")\n    set p[\"k\"] to 200\n    give 0\n\
let r be mark(pub)\n";
    let i3 = run_ok(src3);
    assert_eq!(plain_of(&i3, "pub"), "{}");
}

#[test]
fn audit_r2_1g_label_of_is_not_an_oracle() {
    // Escribir en un contenedor ya privado un valor con OTRO principal es legal, y `label_of`
    // devolvía la lista de principales como dato público.
    let src = "let secret be private(3, \"a\")\nlet m be private({}, \"a\")\nlet found be -1\n\
each i in range(0, 5)\n    when secret == i\n        set m[\"x\"] to private(1, \"b\")\n\
when length(label_of(m)) == 2\n    set found to 99\n";
    let msg = assert_not_extracted(src, "found").expect("la corrida tiene que morir");
    assert!(msg.contains("label_violation") && msg.contains("'found'"), "{}", msg);
    // `label_of`/`is_private` describen un valor privado → su resultado es privado.
    let i = run_ok("let m be private({}, \"a\")\nset m[\"x\"] to private(1, \"b\")\nlet l be label_of(m)\nlet n be length(l)\nlet p be is_private(m)\n");
    assert_eq!(plain_of(&i, "l"), "[\"a\", \"b\"]");
    assert_eq!(label_of(&i, "l"), "a,b");
    assert_eq!(label_of(&i, "n"), "a,b");
    assert_eq!(label_of(&i, "p"), "a,b");
}

#[test]
fn audit_r2_1h_the_principal_cannot_be_private_data() {
    // El texto del principal se volvía NOMBRE de etiqueta, que `label_of` devuelve público:
    // el auditor escribió un número de documento en claro a disco por esa vía.
    let src = "let ssn be private(\"123-45-6789\", \"app\")\nlet r be private(1, ssn)\nlet stolen be label_of(r)[0]\n";
    let msg = run_err(src);
    assert!(msg.contains("private: the principal must be a text literal"), "{}", msg);
    // Tampoco dentro de una rama privada (donde antes `⊆ PC` lo dejaba pasar).
    let src2 = "let ssn be private(\"123-45-6789\", \"app\")\nlet f be private(true, \"app\")\n\
when f\n    let r be private(1, ssn)\n";
    let msg2 = run_err(src2);
    assert!(msg2.contains("private: the principal must be a text literal"), "{}", msg2);
    // Un literal escrito en la llamada SÍ vale, aunque esté dentro de la rama privada.
    let i = run_ok("let f be private(true, \"app\")\nwhen f\n    let q be private(1, \"app\")\n");
    assert_eq!(label_of(&i, "q"), "app");
    // M1 : se va el escape "valor sin etiquetas" — una variable pública con texto
    // arbitrario entraba como nombre de principal y salía verbatim por los diagnósticos.
    let msg3 = run_err("let P be \"app\"\nlet q be private(1, P)\n");
    assert!(msg3.contains("private: the principal must be a text literal"), "{}", msg3);
}

#[test]
fn audit_r2_1i_the_reason_cannot_be_private_data() {
    // El motivo va al log del host en claro: `[INF] declassify: 4111-1111-1111-1111 …`.
    let src = "let card be private(\"4111-1111-1111-1111\", \"app\")\nlet x be private(1, \"app\")\nlet y be declassify(x, card)\n";
    let msg = run_err(src);
    assert!(msg.contains("declassify: reason must be public"), "{}", msg);
    let src2 = "let card be private(\"4111-1111-1111-1111\", \"app\")\nlet f be private(true, \"app\")\n\
when f\n    let y be declassify(1, card)\n";
    let msg2 = run_err(src2);
    assert!(msg2.contains("declassify: reason must be public"), "{}", msg2);
    // El motivo literal dentro de la rama privada sigue siendo válido (es texto del programa).
    let i = run_ok("let f be private(true, \"app\")\nlet r be 0\nwhen f\n    set r to declassify(1, \"the outcome code is public\")\n");
    assert_eq!(i.declassify_log()[0].reason, "the outcome code is public");
    assert_eq!(label_display_raw(&i.declassify_log()[0].from), "app");
}

#[test]
fn audit_r2_1j_a_message_prefix_cannot_disable_the_redaction() {
    // `is_label_diagnostic` decidía por el TEXTO: cualquier mensaje que empezara con
    // `label_violation:` (o contuviera `is a protected builtin`) salía sin redactar, y bajo
    // serve ese texto llega al cliente HTTP.
    for prefix in [
        "label_violation: ",
        "declassify: ",
        "private: ",
        "a secret is already opaque ",
        "x is a protected builtin ",
    ] {
        let src = format!(
            "let x be private(1234, \"a\")\nraise \"{}balance is \" + text(x)\n",
            prefix
        );
        let (_i, r) = run(&src, true);
        match r {
            Err(Control::Error(e)) => {
                assert_eq!(e.message, "private(a)", "prefijo {:?}", prefix);
                assert!(e.location.is_some(), "se conserva file:line:col");
            }
            _ => panic!("se esperaba error con el prefijo {:?}", prefix),
        }
    }
    // Y el diagnóstico REAL del sistema (por flag, no por texto) sigue legible.
    let msg = run_err("let f be private(true, \"a\")\nlet out be 0\nwhen f\n    set out to 1\n");
    assert!(msg.contains("label_violation: cannot assign to 'out'"), "{}", msg);
}

#[test]
fn audit_r2_errors_unrelated_to_privates_keep_their_message() {
    // Regresión de indepurabilidad: `seen` era monótono, así que CUALQUIER error posterior a
    // tocar un privado salía `private(app)`. Ahora la redacción mira lo que tocó ESE error.
    let (_i, r) = run("let x be private(1234, \"a\")\nlet t be text(x)\nlet y be 5 % 0\n", true);
    match r {
        Err(Control::Error(e)) => {
            assert_eq!(e.message, "Modulo by zero");
            assert_eq!(e.location.as_ref().map(|l| l.line), Some(3));
        }
        _ => panic!("se esperaba error"),
    }
    // Y el `raise` de un mensaje público conserva su texto y su ubicación.
    let (_i, r) = run("let x be private(1, \"a\")\nlet t be text(x)\nraise \"plain failure\"\n", true);
    match r {
        Err(Control::Error(e)) => {
            assert_eq!(e.message, "plain failure");
            assert_eq!(e.location.as_ref().map(|l| l.line), Some(3));
        }
        _ => panic!("se esperaba error"),
    }
}

// ---------------------------------------------------------------------------------
// Guardas de CARGA del parser (misma clase que los nombres protegidos): una guarda que
// nunca dispara es una verificación de seguridad convertida en no-op.
// ---------------------------------------------------------------------------------

#[test]
fn inline_when_then_in_statement_position_is_a_load_error() {
    // Antes: `when a != b then raise "mismatch"` seguía de largo SIN AVISO (la forma inline es
    // una expresión y su valor se descarta), así que la guarda jamás saltaba.
    let bad = "let a be 1\nlet b be 2\nwhen a != b then raise \"mismatch\"\nprint(\"siguió\")\n";
    let e = parse_source(bad, "<test>").err().map(|e| e.to_string()).unwrap_or_default();
    assert!(e.contains("inline form"), "{}", e);
    assert!(e.contains("when <condition>"), "el mensaje muestra la forma en bloque: {}", e);
    // Con etiquetas encendidas o apagadas es el mismo error: es de carga, no del modo.
    assert!(parse_source(bad, "<test>").is_err());

    // La forma en bloque sí dispara.
    let good = "let a be 1\nlet b be 2\nwhen a != b\n    raise \"mismatch\"\nprint(\"siguió\")\n";
    let (i, r) = run(good, false);
    match &r {
        Err(Control::Error(e)) => assert_eq!(e.message, "mismatch"),
        _ => panic!("se esperaba el error de la guarda"),
    }
    assert!(i.output.is_empty());

    // Un `otherwise when … then …` de una cadena en posición de sentencia, igual.
    let chained = "let a be 1\nwhen a == 2\n    print(\"x\")\notherwise when a == 1 then raise \"y\"\n";
    let e2 = parse_source(chained, "<test>").err().map(|e| e.to_string()).unwrap_or_default();
    assert!(e2.contains("inline form"), "{}", e2);

    // Y la forma inline en posición de EXPRESIÓN sigue siendo válida (93 usos en el repo).
    let ok = "let a be 1\nlet x be when a == 1 then \"sí\" otherwise \"no\"\n\
let m be {\"k\": when a == 1 then 10 otherwise 20}\n\
task f(v)\n    give when v > 0 then \"pos\" otherwise \"neg\"\n\
let y be f(5)\nprint(x + \" \" + text(m[\"k\"]) + \" \" + y)\n";
    let (i2, r2) = run(ok, false);
    assert!(matches!(r2, Ok(_)), "el programa con la forma inline en expresion tiene que correr");
    assert_eq!(i2.output, vec!["sí 10 pos"]);
}

// ---------------------------------------------------------------------------------
// Auditoría externa, ronda 3, BLOQUEANTE 1: la salida temprana
// desde control privado, por `give` Y por `stop`. Las nueve formas de la tabla
// "Superficie completa", los cuatro tipos de estado que alcanzaban, y la repro con forma
// de producto. Todas extraían el secreto entero con `label_of` → [].
//
// El fix es la tinta en la RAMA: al evaluar un `when`/`match`/bucle con condición privada
// cuyo cuerpo puede salir antes de tiempo, la continuación queda teñida ahí mismo, se tome
// o no la rama — así el `set counter` viola en la vuelta 0, antes de que el secreto llegue
// a ninguna variable pública (teñir en el salto llegaba 181 vueltas tarde).
// ---------------------------------------------------------------------------------

/// Corre el programa y exige que muera con un `label_violation` sobre `var`.
fn assert_closed_on(src: &str, var: &str) -> String {
    let (i, r) = run(src, true);
    match r {
        Err(Control::Error(e)) => {
            assert!(
                e.message.contains("label_violation"),
                "murió con otro error: {}\nfuente:\n{}",
                e.message,
                src
            );
            assert!(
                e.message.contains(&format!("'{}'", var)),
                "esperaba la violación sobre '{}': {}\nfuente:\n{}",
                var,
                e.message,
                src
            );
            e.message
        }
        Err(_) => panic!("give/stop fuera de lugar\nfuente:\n{}", src),
        Ok(_) => {
            let v = env_get(&i.global_env, var).map(|v| strip_deep(&v).to_string()).unwrap_or_default();
            panic!("EXTRAIDO: {} = {} sin etiqueta\nfuente:\n{}", var, v, src);
        }
    }
}

#[test]
fn audit_r3_1a_give_with_value_inside_each() {
    // La repro exacta del informe: hoy imprimía 181 con label_of [].
    let src = "let counter be 0\n\
task probe(secret)\n    each i in range(0, 256)\n        when secret == i\n            give \"found\"\n        set counter to counter + 1\n    give \"no\"\n\
let r be probe(private(181, \"app\"))\nprint(counter)\nprint(label_of(counter))\n";
    assert_closed_on(src, "counter");
}

#[test]
fn audit_r3_1b_give_without_value() {
    let src = "let counter be 0\n\
task probe(secret)\n    each i in range(0, 256)\n        when secret == i\n            give\n        set counter to counter + 1\n    give \"no\"\n\
let r be probe(private(181, \"app\"))\n";
    assert_closed_on(src, "counter");
}

#[test]
fn audit_r3_1c_give_inside_while() {
    let src = "let counter be 0\n\
task probe(secret)\n    let i be 0\n    while i < 256\n        when secret == i\n            give \"found\"\n        set counter to counter + 1\n        set i to i + 1\n    give \"no\"\n\
let r be probe(private(77, \"app\"))\n";
    assert_closed_on(src, "counter");
}

#[test]
fn audit_r3_1d_give_inside_a_try_body() {
    let src = "let counter be 0\n\
task probe(secret)\n    each i in range(0, 256)\n        try\n            when secret == i\n                give \"found\"\n        recover e\n            print(\"x\")\n        set counter to counter + 1\n    give \"no\"\n\
let r be probe(private(44, \"app\"))\n";
    assert_closed_on(src, "counter");
}

#[test]
fn audit_r3_1e_give_nested_in_two_loops() {
    let src = "let counter be 0\n\
task probe(secret)\n    each a in range(0, 32)\n        each b in range(0, 16)\n            when secret == a * 16 + b\n                give \"found\"\n            set counter to counter + 1\n    give \"no\"\n\
let r be probe(private(500, \"app\"))\n";
    assert_closed_on(src, "counter");
}

#[test]
fn audit_r3_1f_give_from_a_lambda_evaluated_in_the_branch() {
    // La lambda se evalúa dentro de la rama privada; su `give` sale de la lambda, pero el
    // cuerpo del `when` igual corta el bloque de afuera.
    let src = "let counter be 0\n\
task probe(secret)\n    each i in range(0, 256)\n        when secret == i\n            let f be (x) => x\n            give f(\"found\")\n        set counter to counter + 1\n    give \"no\"\n\
let r be probe(private(21, \"app\"))\n";
    assert_closed_on(src, "counter");
}

#[test]
fn audit_r3_1g_condition_computed_by_another_task() {
    // La condición la calcula otra task que devuelve un privado: el `when` la ve igual.
    let src = "let counter be 0\n\
task eq(secret, i)\n    give secret == i\n\
task probe(secret)\n    each i in range(0, 256)\n        when eq(secret, i)\n            give \"found\"\n        set counter to counter + 1\n    give \"no\"\n\
let r be probe(private(55, \"app\"))\n";
    assert_closed_on(src, "counter");
}

#[test]
fn audit_r3_1h_stop_inside_a_task_read_from_outside() {
    let src = "let counter be 0\n\
task probe(secret)\n    each i in range(0, 256)\n        when secret == i\n            stop\n        set counter to counter + 1\n    give \"done\"\n\
let r be probe(private(99, \"app\"))\nprint(counter)\n";
    assert_closed_on(src, "counter");
}

#[test]
fn audit_r3_1i_stop_at_top_level_read_from_a_test_block() {
    // El bloque `test` corría con la tinta ya lavada y leía el contador público.
    let src = "let counter be 0\nlet secret be private(181, \"app\")\n\
each i in range(0, 256)\n    when secret == i\n        stop\n    set counter to counter + 1\n\
test \"lee el contador\"\n    assert_eq(counter, 181)\n";
    let program = parse_source(src, "<labels>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    let outcomes = interp.run_test_blocks(&program);
    // El setup muere con la violación: el contador nunca llega a tener el secreto.
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].name, "<setup>");
    let msg = outcomes[0].message.clone().unwrap_or_default();
    assert!(msg.contains("label_violation") && msg.contains("'counter'"), "{}", msg);
}

#[test]
fn audit_r3_reaches_every_kind_of_public_state() {
    // Los cuatro tipos de estado que el informe enumera.
    // 1) campo de un mapa global
    let src_map = "let acc be {\"n\": 0}\n\
task probe(secret)\n    each i in range(0, 256)\n        when secret == i\n            give 0\n        set acc[\"n\"] to i\n    give 0\n\
let r be probe(private(181, \"app\"))\n";
    assert_closed_on(src_map, "acc");
    // 2) lista global
    let src_list = "let seen be []\n\
task probe(secret)\n    each i in range(0, 256)\n        when secret == i\n            give 0\n        set seen to append(seen, i)\n    give 0\n\
let r be probe(private(37, \"app\"))\n";
    assert_closed_on(src_list, "seen");
    // 3) local del llamador capturada por closure (el mapa es del llamador)
    let src_closure = "task outer()\n    let box be {\"n\": 0}\n    task inner(secret)\n        each i in range(0, 256)\n            when secret == i\n                give 0\n            set box[\"n\"] to i\n        give 0\n    let r be inner(private(12, \"app\"))\n    give box\n\
let out be outer()\n";
    let (_i, r) = run(src_closure, true);
    match r {
        Err(Control::Error(e)) => assert!(e.message.contains("label_violation"), "{}", e.message),
        _ => panic!("se esperaba label_violation en el closure del llamador"),
    }
    // 4) estado de módulo: el mismo patrón sobre un global del programa importador
    let src_mod = "let state be {\"v\": 0}\n\
task probe(secret)\n    each i in range(0, 256)\n        when secret == i\n            stop\n        set state[\"v\"] to i\n    give 0\n\
let r be probe(private(7, \"app\"))\n";
    assert_closed_on(src_mod, "state");
}

#[test]
fn audit_r3_product_shaped_repro_output_container_by_reference() {
    // "20 bits en una sola llamada": el contenedor de salida se pasa por referencia a un
    // helper, que sale temprano de la rama privada. Daba {n: 999999} con etiqueta vacía.
    let src = "task helper(out, secret)\n    each i in range(0, 1048576)\n        when secret == i\n            give 0\n        set out[\"n\"] to i\n    give 0\n\
let out be {}\nlet r be helper(out, private(999999, \"app\"))\nprint(out)\n";
    let (i, r) = run(src, true);
    match r {
        Err(Control::Error(e)) => assert!(e.message.contains("label_violation"), "{}", e.message),
        _ => panic!(
            "EXTRAIDO por el contenedor de salida: {:?}",
            env_get(&i.global_env, "out").map(|v| strip_deep(&v).to_string())
        ),
    }
}

#[test]
fn audit_r3_the_fix_does_not_taint_what_it_should_not() {
    // La contraparte: un bucle privado que NO sale temprano no tiñe nada de lo que sigue, y
    // una guarda sin bucle sigue devolviendo su valor etiquetado sin ensuciar al llamador.
    let src = "let total be 0\n\
task sum_public(xs)\n    each x in xs\n        set total to total + x\n    give total\n\
let t be sum_public([1, 2, 3])\n\
task guard(x)\n    when x > 0\n        give \"yes\"\n    give \"no\"\n\
let g be guard(private(5, \"app\"))\n\
let allowed be {}\nset allowed[\"ETH\"] to true\nlet n be length(keys(allowed))\n";
    let i = run_ok(src);
    assert_eq!(label_of(&i, "t"), "");
    assert_eq!(label_of(&i, "g"), "app");
    assert_eq!(label_of(&i, "allowed"), "");
    assert_eq!(label_of(&i, "n"), "");
    assert_eq!(plain_of(&i, "n"), "1");
    // Y un contador PRIVADO dentro del bucle con salida temprana sí funciona (es la forma
    // correcta de escribir la app).
    let ok = "let counter be private(0, \"app\")\n\
task probe(secret)\n    each i in range(0, 256)\n        when secret == i\n            give \"found\"\n        set counter to counter + 1\n    give \"no\"\n\
let r be probe(private(5, \"app\"))\n";
    let i2 = run_ok(ok);
    assert_eq!(label_of(&i2, "counter"), "app");
    assert_eq!(plain_of(&i2, "counter"), "5");
}

#[test]
fn audit_r3_m6_leftover_tokens_are_a_load_error() {
    // La clase "no-op silencioso" completa: el parser descartaba los tokens sobrantes.
    for bad in [
        "let x be 1 \"junk\"\n",
        "print \"hola\"\n",
        "let c be true\nlet x be when c then raise \"boom\"\n",
    ] {
        let e = parse_source(bad, "<test>").err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e.contains("after the end of this statement"), "{:?} → {}", bad, e);
    }
    // Las formas correctas siguen andando.
    let i = run_ok("let x be 1\nprint(\"hola\")\nlet c be true\nlet y be when c then 1 otherwise 2\nprint(text(x + y))\n");
    assert_eq!(i.output, vec!["hola", "2"]);
}

// ---------------------------------------------------------------------------------
// Anti-rot de CARGA sobre el corpus del repo (el conformance no corre en CI, y por eso
// nadie vio que un guard de carga rompía `conformance/core/053`). Esto no compara contra
// el oráculo: comprueba lo que los guards nuevos pueden romper — que cada `.syn`/`.fsyn`
// del árbol PARSEA y pasa los chequeos de carga (nombres protegidos).
// ---------------------------------------------------------------------------------

#[test]
fn every_syn_file_in_the_repo_still_loads() {
    use std::path::{Path, PathBuf};
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..");
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let skip = ["target", "node_modules", ".git", "dist", "build", ".synsema"];
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return,
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().and_then(|s| s.to_str()).is_some_and(|n| skip.contains(&n)) {
                    continue;
                }
                walk(&p, out);
            } else if p.extension().and_then(|s| s.to_str()).is_some_and(|x| x == "syn") {
                // Los casos NEGATIVOS del corpus existen para no parsear, y  tiene su
                // propio parser (flat_syntax): ninguno de los dos dice nada de los guards.
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
                let generated = p.components().any(|c| c.as_os_str() == "serve_tmp");
                // EXCEPCION DECLARADA: `tests/python_diff.test.syn` escribe a proposito el
                // `return 5` de Python y hoy afirma en RUNTIME que falla (`assert_error`). Con
                // el guard de tokens sobrantes eso pasa a ser error de PARSEO (que es lo que la
                // tabla Python->Synsema quiere ensenar), asi que el archivo necesita mover esa
                // afirmacion; lo toca su dueno, no este test.
                let known = name == "python_diff.test.syn";
                if !name.contains("fails") && !name.contains("error") && !generated && !known {
                    out.push(p);
                }
            }
        }
    }
    let mut files = Vec::new();
    walk(&root, &mut files);
    // El umbral sólo protege contra "la ruta quedó mal y no recorrí nada": NO puede asumir el
    // corpus local. `conformance/` (1400 de los ~1480 `.syn` del disco) está en `.gitignore`, así
    // que en un CHECKOUT LIMPIO —que es lo que hace CI— sólo existen los ~42 versionados. Con el
    // umbral en 300 este test fallaba en el primer push con "el corpus no se encontró": verde en
    // la máquina del autor, rojo en CI. El test sigue recorriendo TODO lo que encuentre, que es
    // su trabajo; si algún día se versiona `conformance/`, cubrirá el corpus entero sin tocar nada.
    assert!(files.len() > 30, "el corpus no se encontró (¿ruta?): {}", files.len());

    let mut broken: Vec<String> = Vec::new();
    for f in &files {
        let src = match std::fs::read_to_string(f) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let name = f.to_string_lossy().to_string();
        match parse_source(&src, &name) {
            Err(e) => broken.push(format!("PARSE {}: {}", name, e)),
            Ok(program) => {
                // Los guards de carga (nombres protegidos) corren con etiquetas apagadas
                // también: es exactamente lo que rompió el 053 de conformance.
                if let Err(Control::Error(e)) = synsema_core::interpreter::check_protected_names(&program) {
                    broken.push(format!("LOAD {}: {}", name, e.message));
                }
            }
        }
    }
    assert!(broken.is_empty(), "{} archivo(s) dejaron de cargar:\n{}", broken.len(), broken.join("\n"));
}

#[test]
fn a_principal_set_by_the_host_is_printed_by_name_not_by_index() {
    // Hallazgo del adaptador (ronda 3): con la fuente marcada por el HOST (`input.sources` de
    // la op `run`, que es el camino del guest), la redacción decía `private(#0)` y el operador
    // del log perdía de quién era el dato. Esos nombres los fija el host en Rust, no el
    // programa, así que son tan confiables como un literal del fuente: se imprimen por nombre.
    let program =
        parse_source("let v be ctx[\"balance\"]
raise \"balance is \" + text(v)
", "<labels>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    let mut m = indexmap::IndexMap::new();
    m.insert("balance".to_string(), syn_int(500));
    // Exactamente lo que hace el host: marcar la fuente desde Rust e inyectarla.
    interp.set_global("ctx", mark(syn_map(m), labels::label_from(&["app"])));
    match interp.execute(&program) {
        Err(Control::Error(e)) => {
            assert_eq!(e.message, "private(app)", "se perdió el nombre del principal");
            assert!(e.location.is_some(), "se conserva file:line");
        }
        _ => panic!("se esperaba el error redactado"),
    }

    // Lo mismo por el camino de un `label_violation` (que nunca se redacta) con la fuente del
    // host: el mensaje nombra al principal.
    let program2 = parse_source("let out be 0
when ctx[\"balance\"] > 1
    set out to 1
", "<labels>").unwrap();
    let mut i2 = Interpreter::new();
    i2.set_labels(true);
    let mut m2 = indexmap::IndexMap::new();
    m2.insert("balance".to_string(), syn_int(500));
    i2.set_global("ctx", mark(syn_map(m2), labels::label_from(&["app"])));
    let msg = match i2.execute(&program2) {
        Err(Control::Error(e)) => e.message,
        _ => panic!("se esperaba label_violation"),
    };
    assert!(msg.contains("pc = [app]") && !msg.contains("#0"), "{}", msg);
}

// ---------------------------------------------------------------------------------
// Auditoria externa, ronda 5: el canal de `steps()`, el veredicto por bloque de `test`,
// el alcance de la tinta de un `stop` y el `stop` que sale de la task.
// ---------------------------------------------------------------------------------

#[test]
fn audit_r5_a_stop_that_crosses_the_call_boundary_taints_the_callers_loop() {
    // La fuga V1 en el sentido contrario, encontrada al revisar el alcance: la rama esta en el
    // CALLEE y el `stop` corta el bucle del LLAMADOR. La tinta del callee se descartaba al
    // volver, asi que el contador publico del llamador contaba las vueltas en claro (medido:
    // 181, `label_of` vacio). Ahora la parte que ESCAPA del cuerpo del callee se suma a la
    // tinta del bucle de acá, y el contador viola en la vuelta 0.
    let src = "let counter be 0\n\
task helper(secret, i)\n    when secret == i\n        stop\n\
task probe(secret)\n    each i in range(0, 256)\n        helper(secret, i)\n        set counter to counter + 1\n    give \"no\"\n\
let r be probe(private(181, \"app\"))\n";
    assert_closed_on(src, "counter");
}

#[test]
fn audit_r5_a_stop_may_not_leave_its_task_under_private_control() {
    // El caso que el predicado estatico NO puede ver: la rama esta en el LLAMADOR y el salto es
    // indirecto (`when secret == i / bail()`, con `task bail() / stop`). Saber si una llamada
    // corta el bucle es interprocedural, asi que para cuando el `stop` dispara en la vuelta 181
    // las 181 vueltas anteriores ya escribieron el contador en claro. Se rechaza el constructo.
    let src = "let counter be 0\n\
task bail()\n    stop\n\
task probe(secret)\n    each i in range(0, 256)\n        when secret == i\n            bail()\n        set counter to counter + 1\n    give \"no\"\n\
let r be probe(private(181, \"app\"))\n";
    let (i, r) = run(src, true);
    let msg = match r {
        Err(Control::Error(e)) => e.message,
        _ => panic!("un `stop` bajo control privado no puede dejar su task"),
    };
    assert!(msg.contains("label_violation") && msg.contains("'stop' left the task 'bail'"), "{}", msg);
    assert!(msg.contains("pc = [app]"), "{}", msg);
    let _ = i;
    // Con control PUBLICO el mismo programa no cambia: `stop` sigue cortando el bucle de afuera.
    let public = "let counter be 0\n\
task bail()\n    stop\n\
each i in range(0, 10)\n    when i == 4\n        bail()\n    set counter to counter + 1\n";
    let i = run_ok(public);
    assert_eq!(plain_of(&i, "counter"), "4");
}

#[test]
fn audit_r5_the_taint_of_a_stop_ends_with_its_loop() {
    // El nerfeo que la ronda 5 midio: la tinta de un `stop` valia hasta el fin de la task, asi
    // que trabajo publico DESPUES del bucle no compilaba aunque no llevara un bit. Adentro del
    // bucle sigue cerrado (es donde un contador cuenta las vueltas); al salir, los dos caminos
    // convergen y no puede quedar nada publico con la cuenta, porque habria violado adentro.
    let inside = "let counter be 0\nlet secret be private(3, \"app\")\n\
each i in range(0, 10)\n    when secret == i\n        stop\n    set counter to counter + 1\n";
    assert_closed_on(inside, "counter");

    // Una linea de registro publica y constante despues del bucle.
    let after = "let secret be private(3, \"app\")\nlet orders be [80, 70, 60]\n\
each o in orders\n    when o < secret\n        stop\n\
log \"screening done\"\n";
    let i = run_ok(after);
    assert_eq!(i.output, vec!["[LOG] screening done"]);

    // Dos bucles sin relacion en la misma task: el segundo escribe publico sin problema.
    let two = concat!(
        "let secret be private(3, \"app\")\n",
        "let total be 0\n",
        "task both(secret)\n",
        "    each i in range(0, 10)\n",
        "        when secret == i\n",
        "            stop\n",
        "    each j in range(0, 5)\n",
        "        set total to total + 1\n",
        "    give total\n",
        "let r be both(secret)\n",
    );
    let i = run_ok(two);
    assert_eq!(plain_of(&i, "total"), "5");
    assert_eq!(label_of(&i, "total"), "");

    // Un `give`, en cambio, SI tine hasta el fin de la task: alcanzar la linea siguiente ya es
    // el bit, porque los caminos no convergen. La asimetria es a proposito.
    let with_give = "let counter be 0\nlet secret be private(99, \"app\")\n\
task probe(secret)\n    each i in range(0, 10)\n        when secret == i\n            give \"found\"\n    set counter to 1\n    give \"no\"\n\
let r be probe(secret)\n";
    assert_closed_on(with_give, "counter");
}

#[test]
fn audit_r5_a_label_violation_stops_the_whole_test_run() {
    // Regla 1.a: el veredicto del enforcement no es observable. El runner lo convertia en un
    // ✗ por bloque, que es atraparlo: con ocho bloques que prueban un bit cada uno, la columna
    // de ✓/✗ deletrea el byte. La corrida entera se corta con UN outcome.
    let src = "let secret be private(181, \"app\")\nlet pub0 be 0\nlet pub1 be 0\n\
test \"bit 0\"\n    when secret > 128\n        set pub0 to 1\n    assert_eq(pub0, 1)\n\
test \"bit 1\"\n    when secret > 64\n        set pub1 to 1\n    assert_eq(pub1, 1)\n";
    let program = parse_source(src, "<labels>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    let outcomes = interp.run_test_blocks(&program);
    assert_eq!(outcomes.len(), 1, "un outcome, no uno por bloque: {:?}", outcomes.iter().map(|o| &o.name).collect::<Vec<_>>());
    assert!(!outcomes[0].passed);
    let msg = outcomes[0].message.clone().unwrap_or_default();
    assert!(msg.contains("label_violation"), "{}", msg);
    assert!(msg.contains("one bit of private data per block"), "{}", msg);

    // Un fallo NORMAL (una asercion) sigue siendo un veredicto por bloque, como siempre.
    let plain = "test \"a\"\n    assert_eq(1, 2)\ntest \"b\"\n    assert_eq(1, 1)\n";
    let program = parse_source(plain, "<labels>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    let outcomes = interp.run_test_blocks(&program);
    assert_eq!(outcomes.len(), 2);
    assert!(!outcomes[0].passed && outcomes[1].passed);
}

#[test]
fn audit_r5_nested_loops_scope_a_stop_to_the_inner_one() {
    // El chequeo mas filoso del alcance nuevo. El `stop` del bucle INTERNO no cambia cuantas
    // vueltas da el EXTERNO, asi que un contador publico en el cuerpo del externo vale 32 con
    // cualquier secreto: no lleva informacion y tiene que compilar.
    let inner_stop = concat!(
        "let counter be 0\n",
        "task probe(secret)\n",
        "    each a in range(0, 32)\n",
        "        each b in range(0, 16)\n",
        "            when secret == a * 16 + b\n",
        "                stop\n",
        "        set counter to counter + 1\n",
        "    give \"no\"\n",
        "let r be probe(private(500, \"app\"))\n",
    );
    let i = run_ok(inner_stop);
    assert_eq!(plain_of(&i, "counter"), "32");
    assert_eq!(label_of(&i, "counter"), "");

    // Con `give` en el bucle interno, en cambio, el salto sale de la TASK: llegar al contador
    // significa que no disparo, y eso si es el bit. Sigue cerrado.
    let inner_give = concat!(
        "let counter be 0\n",
        "task probe(secret)\n",
        "    each a in range(0, 32)\n",
        "        each b in range(0, 16)\n",
        "            when secret == a * 16 + b\n",
        "                give \"found\"\n",
        "        set counter to counter + 1\n",
        "    give \"no\"\n",
        "let r be probe(private(5000, \"app\"))\n",
    );
    assert_closed_on(inner_give, "counter");

    // Y un contador publico sobre una coleccion PRIVADA sigue violando: ahi la cantidad de
    // vueltas es el largo de la coleccion, que es privado.
    let over_private = "let counter be 0\nlet xs be private([1, 2, 3], \"app\")\neach x in xs\n    set counter to counter + 1\n";
    assert_closed_on(over_private, "counter");
}

// ---------------------------------------------------------------------------------
// Auditoria externa, ronda 6: la asimetria entre redactar y atrapar, el veredicto por
// bloque via un error ordinario, el canal de progreso y el contador entre peticiones.
// ---------------------------------------------------------------------------------

#[test]
fn audit_r6_b4_an_ordinary_error_conditioned_by_the_secret_stops_the_test_run() {
    // El corte del runner (ronda 5) sólo cubría violaciones de etiqueta y errores nacidos bajo
    // PC privado. Un error ORDINARIO condicionado por el secreto —`1 / (secret - n)`— seguía
    // siendo un fallo por bloque, y ocho bloques dan los ocho bits. Con la union de B1 ese
    // error es fatal, asi que el runner lo corta como cualquier otro veredicto del enforcement.
    let src = "let secret be private(181, \"app\")\n\
task bit_at(t)\n    let v be 1 / (secret - t)\n    give \"no-error\"\n\
test \"a\"\n    assert_eq(bit_at(181), \"no-error\")\n\
test \"b\"\n    assert_eq(bit_at(42), \"no-error\")\n\
test \"c\"\n    assert_eq(bit_at(7), \"no-error\")\n";
    let program = parse_source(src, "<labels>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    let outcomes = interp.run_test_blocks(&program);
    assert_eq!(outcomes.len(), 1, "un outcome, no uno por bloque: {:?}", outcomes.iter().map(|o| &o.name).collect::<Vec<_>>());
    assert!(!outcomes[0].passed);
    let msg = outcomes[0].message.clone().unwrap_or_default();
    assert!(msg.contains("one bit of private data per block"), "{}", msg);
}

#[test]
fn audit_r6_b2_the_output_of_a_run_stopped_by_the_checker_is_withheld() {
    // El canal de PROGRESO: `block_exits_early` no modela "esta rama puede fallar", asi que el
    // prefijo del bucle alcanza a imprimir en claro y la CANTIDAD de lineas deletrea el
    // secreto. Con el error ya fatal la corrida se corta, y el buffer no se entrega: lo que
    // queda observable es que murio, no cuantas vueltas dio.
    let mut sizes = Vec::new();
    for secret in [3u32, 9, 40] {
        let src = format!(
            "let secret be private({}, \"app\")\neach i in range(0, 300)\n    when secret == i\n        let v be 1 / 0\n    print(\"tick\")\n",
            secret
        );
        let (i, r) = run(&src, true);
        assert!(matches!(r, Err(Control::Error(_))), "la corrida tiene que morir");
        sizes.push(i.output.len());
        assert_eq!(i.output.len(), 1, "una linea fija, no {} ticks", i.output.len());
        assert!(i.output[0].contains("output is withheld"), "{}", i.output[0]);
    }
    assert!(sizes.windows(2).all(|w| w[0] == w[1]), "el tamano no puede depender del secreto: {:?}", sizes);
    // Sin etiquetas, y sin corte por etiquetas, la salida es la de siempre.
    let (i, r) = run("print(\"a\")\nprint(\"b\")\n", true);
    assert!(r.is_ok());
    assert_eq!(i.output, vec!["a", "b"]);
}

#[test]
fn audit_r6_b3_the_step_counter_is_per_request() {
    // El serve reusa el interprete entre peticiones. `reset_for_request` limpiaba la etiqueta
    // ambiente pero no el contador, asi que la peticion siguiente leia —sin etiqueta— el
    // trabajo privado de la anterior. Medido por el auditor: magnitudes con un factor de 15.
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    let heavy = parse_source("let s be private(40, \"app\")\nlet acc be private(0, \"app\")\neach i in range(0, s)\n    set acc to acc + 1\n", "<a>").unwrap();
    assert!(interp.execute(&heavy).is_ok());
    let after_heavy = interp.steps();
    assert!(after_heavy > 100, "la primera corrida tiene que gastar pasos: {}", after_heavy);
    interp.reset_for_request();
    assert_eq!(interp.steps(), 0, "el contador arranca de cero en la peticion siguiente");
    // Y lo que la peticion nueva lee es SU propio costo, sin la etiqueta del vecino.
    let probe = parse_source("let n be steps()\n", "<b>").unwrap();
    assert!(interp.execute(&probe).is_ok());
    assert_eq!(label_of(&interp, "n"), "", "sin privados propios, el contador es publico");
}

// ---------------------------------------------------------------------------------
// Auditoria externa, ronda 7: la REDACCION era el canal, la ubicacion del error tambien,
// y sin variante total no habia forma de validar entrada no confiable.
// ---------------------------------------------------------------------------------

#[test]
fn audit_r7_the_redaction_text_does_not_depend_on_the_value() {
    // El agujero mas elegante de las siete rondas: `private(<los principales de ESE valor>)`
    // varia con cual se selecciono, asi que el texto que existe para tapar el dato lo publicaba.
    // Con una tabla de 256 entradas salia el byte entero en una linea, con salida exitosa.
    let mut seen: Vec<String> = Vec::new();
    for n in [0, 1] {
        let src = format!(
            "let a be private(10, \"p0\")\nlet b be private(20, \"p1\")\nlet xs be [a, b]\nlet idx be private({}, \"app\")\nprint(xs[idx])\n",
            n
        );
        let i = run_ok(&src);
        seen.push(i.output.join("|"));
    }
    assert_eq!(seen[0], seen[1], "la redaccion delata el indice: {:?}", seen);
    assert_eq!(seen[0], "private(app,p0,p1)", "sale el conjunto DECLARADO, constante");

    // El mismo canal salia por el mensaje de violacion, que bajo servidor llega al cliente.
    let mut msgs: Vec<String> = Vec::new();
    for n in [0, 1] {
        let src = format!(
            "let a be private(10, \"p0\")\nlet b be private(20, \"p1\")\nlet xs be [a, b]\nlet idx be private({}, \"app\")\nlet out be [xs[idx]]\nlet s be json_encode(out)\n",
            n
        );
        let (_i, r) = run(&src, true);
        if let Err(Control::Error(e)) = r {
            msgs.push(e.message);
        }
    }
    if msgs.len() == 2 {
        assert_eq!(msgs[0], msgs[1], "el mensaje de violacion delata el indice: {:?}", msgs);
    }

    // Y el caso normal —un solo principal, el del guest y el de cualquier enclave— no cambia.
    let i = run_ok("let x be private(5, \"app\")\nprint(x)\n");
    assert_eq!(i.output, vec!["private(app)"]);
}

#[test]
fn audit_r7_a_runtime_private_call_cannot_move_the_redaction_text() {
    // El conjunto sale del AST, no de que `private` haya CORRIDO: si lo alimentara el runtime,
    // `when s == 0 / private(1, "p0") / otherwise / private(1, "p1")` volveria a variar el texto.
    let mut seen: Vec<String> = Vec::new();
    for n in [0, 1] {
        let src = format!(
            "let s be private({}, \"app\")
when s == 0
    let a be private(1, \"p0\")
otherwise
    let a be private(1, \"p1\")
let z be private(0, \"app\")
print(z)
",
            n
        );
        let i = run_ok(&src);
        seen.push(i.output.join("|"));
    }
    assert_eq!(seen[0], seen[1], "el texto depende de que rama corrio: {:?}", seen);
}

#[test]
fn audit_r7_a_label_error_toward_the_host_carries_no_location() {
    // Si el secreto elige CUAL de N sitios falla, `file:line:col` vale log2(N) bits. El texto ya
    // salia redactado; la linea no. Hacia el host (respuesta HTTP, reporte del guest, runner de
    // pruebas) el mensaje va sin ubicacion. El CLI local la conserva: ahi el host es el dueño.
    let src = "let s be private(1, \"app\")\nlet xs be [1, 2]\nlet y be xs[s + 9]\n";
    let (_i, r) = run(src, true);
    let e = match r {
        Err(Control::Error(e)) => e,
        _ => panic!("tenia que morir"),
    };
    assert!(e.is_fatal_for_labels());
    assert_eq!(e.to_string_for_client(), "private(app)", "sin ubicacion hacia el cliente");
    assert!(e.location.is_some(), "y la ubicacion sigue disponible para el CLI local");

    // El runner de pruebas tampoco nombra el bloque: el nombre lo pone el atacante.
    let src = "let secret be private(181, \"app\")\ntest \"bit 7\"\n    let v be 1 / (secret - 181)\n";
    let program = parse_source(src, "<labels>").unwrap();
    let mut interp = Interpreter::new();
    interp.set_labels(true);
    let outcomes = interp.run_test_blocks(&program);
    assert_eq!(outcomes.len(), 1);
    assert!(!outcomes[0].name.contains("bit 7"), "no nombra el bloque: {}", outcomes[0].name);
    let msg = outcomes[0].message.clone().unwrap_or_default();
    assert!(!msg.contains("<labels>:"), "ni la ubicacion: {}", msg);
}

#[test]
fn audit_r7_total_variants_let_a_program_validate_untrusted_input() {
    // El costo del arreglo de la ronda 6, medido por el auditor: sin una operacion TOTAL no
    // quedaba ninguna frase que escribir para validar entrada malformada — ni `try/recover`, ni
    // declarar privado el destino. Es el caso de un enclave, que recibe cargas de cualquiera.
    // (La mitad de `json_decode` vive en el stdlib; se prueba alli.)
    let src = "let campo be private(\"no-es-numero\", \"app\")\nlet n be number(campo, nothing)\nlet ok be private(n != nothing, \"app\")\n";
    let i = run_ok(src);
    assert_eq!(plain_of(&i, "ok"), "false");
    let src = "let campo be private(\"42\", \"app\")\nlet n be number(campo, nothing)\n";
    let i = run_ok(src);
    assert_eq!(plain_of(&i, "n"), "42.0");
    assert_eq!(label_of(&i, "n"), "app", "el valor convertido sigue siendo del principal");

    // Sin fallback sigue lanzando, y el error enseña la salida.
    let msg = run_err("let n be number(\"x\")\n");
    assert!(msg.contains("number(<value>, nothing)"), "{}", msg);

    // Con las etiquetas apagadas, la forma de un argumento es la de siempre.
    let (i, r) = run("let n be number(\"2\")\nlet m be number(\"x\", 0)\n", false);
    assert!(r.is_ok());
    assert_eq!(plain_of(&i, "n"), "2.0");
    assert_eq!(plain_of(&i, "m"), "0");
}

#[test]
fn audit_r8_no_builtin_returns_a_result_less_labelled_than_what_its_callback_touched() {
    // LA prueba que faltaba, y la que habria atrapado esto en la ronda 1.
    //
    // Las ocho rondas auditaron el flujo de control DEL LENGUAJE. Ninguna auditó el flujo de
    // control DE RUST: un builtin recibe un callable, el callable lee un privado POR CAPTURA, el
    // predicado decide adentro de Rust, y la etiqueta del resultado se calculaba solo con los
    // argumentos. `count_where(range(0,256), (v) => v < SECRET)` devolvia 165 con `label_of` [].
    //
    // En vez de una lista escrita a mano —que deja afuera al builtin que alguien agregue mañana—
    // esto BARRE LA TABLA, y la propiedad que comprueba es la definicion misma:
    // **no-interferencia**. Dos corridas que difieren SOLO en el valor privado tienen que dar el
    // mismo resultado publico; si difieren, el resultado tiene que salir etiquetado.
    //
    // La formulacion se calibra sola: un builtin que recibe la lambda y nunca la llama (`append`
    // la mete en la lista) da el mismo resultado con los dos secretos y no exige nada.
    let names: Vec<String> = {
        let interp = Interpreter::new();
        let env = interp.global_env.borrow();
        let mut v: Vec<String> = env
            .bindings
            .iter()
            .filter(|(_, val)| matches!(val, SynValue::Builtin(_)))
            .map(|(k, _)| k.clone())
            .collect();
        v.sort();
        v
    };
    assert!(names.len() > 100, "solo {} builtins: ¿se rompio la enumeracion?", names.len());

    // Los que no se pueden invocar a ciegas: cortan la corrida, esperan a alguien, o son los
    // conscientes de etiquetas (deciden ellos, y tienen sus propios tests).
    const SKIP: &[&str] = &[
        "raise", "exit", "shutdown", "sleep", "wait_for", "ask", "approve", "confirm",
        "private", "declassify", "label_of", "is_private", "print", "show", "log",
        "assert", "assert_eq", "assert_ne", "assert_error", "steps", "now", "random",
        "random_int", "uuid", "reason", "decide", "analyze", "generate",
    ];

    // Formas de llamada; la lambda lee `SECRET` por captura en todas.
    const SHAPES: &[&str] = &[
        "{}([1, 2, 3, 4], (v) => v < SECRET)",
        "{}([1, 2, 3, 4], (v) => v < SECRET, 0)",
        "{}((v) => v < SECRET, [1, 2, 3, 4])",
        "{}({\"a\": 1, \"b\": 9}, (k, v) => v < SECRET)",
    ];

    /// Corre la forma con ese secreto: `Some((resultado_sin_etiquetas, tiene_etiqueta))`.
    fn once(call: &str, secret: i64) -> Option<(String, bool)> {
        let src = format!("let SECRET be private({}, \"app\")\nlet r be {}\n", secret, call);
        let program = parse_source(&src, "<hof>").ok()?;
        let mut i = Interpreter::new();
        i.set_labels(true);
        i.execute(&program).ok()?;
        let v = env_get(&i.global_env, "r")?;
        Some((strip_deep(&v).to_string(), !label_deep(&v).is_empty()))
    }

    let mut exercised = 0usize;
    let mut leaked: Vec<String> = Vec::new();
    for name in &names {
        if SKIP.contains(&name.as_str()) {
            continue;
        }
        for shape in SHAPES {
            let call = shape.replace("{}", name);
            let (Some((a, la)), Some((b, lb))) = (once(&call, 2), once(&call, 99)) else { continue };
            if a == b {
                continue; // el secreto no influyo en el resultado: nada que exigir
            }
            exercised += 1;
            if !la || !lb {
                leaked.push(format!("{}  →  {} / {} (sin etiqueta)", call, a, b));
            }
        }
    }
    assert!(exercised >= 8, "el barrido no ejercito nada ({} formas influyentes)", exercised);
    assert!(
        leaked.is_empty(),
        "{} builtin(s) devuelven un resultado influido por un privado SIN etiqueta:\n{}",
        leaked.len(),
        leaked.join("\n")
    );
}

#[test]
fn audit_r8_the_eight_higher_order_builtins_by_name() {
    // El barrido de arriba es el que no se queda viejo; éste fija por nombre los ocho que el
    // informe midió, para que el diagnóstico diga cuál se rompió si alguna vez se rompe.
    for call in [
        "count_where(range(0, 256), (v) => v < SECRET)",
        "length(where(range(0, 256), (v) => v < SECRET))",
        "find_first(range(0, 256), (v) => v >= SECRET)",
        "index_of(range(0, 256), (v) => v >= SECRET)",
        "every(range(0, 10), (v) => v < SECRET)",
        "some(range(0, 10), (v) => v >= SECRET)",
        "sort_by([3, 1, 2], (v) => v * SECRET)[0]",
        "length(keys(group_by(range(0, 4), (v) => text(v < SECRET))))",
    ] {
        let src = format!("let SECRET be private(165, \"app\")\nlet r be {}\n", call);
        let i = run_ok(&src);
        assert_eq!(label_of(&i, "r"), "app", "{} devolvió un resultado sin etiqueta", call);
    }
    // Y lo que NO toca privados sigue público: el invariante no tiñe de más.
    let i = run_ok("let SECRET be private(165, \"app\")\nlet r be count_where([1, 2, 3], (v) => v < 2)\n");
    assert_eq!(label_of(&i, "r"), "");
    assert_eq!(plain_of(&i, "r"), "1");
}

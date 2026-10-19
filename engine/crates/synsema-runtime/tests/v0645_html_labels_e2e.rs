//! v0.6.45 (B9): leer una página privada con los builtins de HTML no la vuelve pública — son puros y
//! heredan la etiqueta de la entrada. Binario propio: enciende las etiquetas para todo el proceso.

use synsema_runtime::engine::run_source;

#[test]
fn html_of_a_private_page_stays_private() {
    assert!(synsema_runtime::host::set_labels(true) || synsema_runtime::host::labels());
    let src = "let page be private(\"<p>tarjeta 4111</p>\", \"cliente\")\nlet t be html_text(page)\nprint(t)\n";
    let r = run_source(src, "<b9-labels>");
    // `print` redacta un privado: si `html_text` hubiera devuelto texto público, saldría "tarjeta 4111".
    assert!(r.success, "{:?}", r.errors);
    assert_eq!(r.output, ["private(cliente)"], "el texto extraído perdió la etiqueta");
}

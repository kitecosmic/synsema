//! v0.6.45 (B9): HTML real. Leer la web es el trabajo diario de un agente, y el HTML es por donde
//! llega la inyección de prompts: un lenguaje de agentes tiene que leerlo bien. `xml_parse` falla con
//! HTML real (etiquetas sin cerrar, atributos sin comillas, entidades), y las regex se rompen.
//!
//! - `html_select(html, selector)` → lista de `{tag, attrs, text, html}`, en orden de documento.
//!   Selectores CSS completos (`a.btn[href^="https"]`, `ul > li:nth-child(2)`, listas con coma).
//! - `html_text(html)` → el texto legible (lo que se le pasa a un modelo): sin `script`/`style`/
//!   `template`/`noscript`, un salto de línea por bloque, espacios colapsados.
//! - `html_unescape(texto)` → las entidades decodificadas (`&amp;` `&eacute;` `&#x1F680;`), con la
//!   tabla de entidades de WHATWG; el resto del texto queda tal cual.
//!
//! Parseo WHATWG con `html5ever` y selectores de `selectors` (los dos de Servo) vía `scraper`.
//! Puros, sin I/O; un tope de 16 MiB de entrada. Lo que devuelven hereda la etiqueta de la entrada
//! (son builtins puros): leer una página privada no la vuelve pública.

use std::rc::Rc;

use scraper::{ElementRef, Html, Node, Selector};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_list, syn_map, syn_text, SynMap, SynValue};

const MAX_INPUT: usize = 16 << 20;

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

fn html_arg<'a>(args: &'a [SynValue], f: &str) -> Result<&'a str, Control> {
    let s: &str = match args.first() {
        Some(SynValue::Text(t)) => t,
        Some(SynValue::Secret(_)) => return Err(err(format!("{}: cannot parse a secret", f))),
        Some(other) => return Err(err(format!("{}: expects HTML text, got {}", f, other.type_name()))),
        None => return Err(err(format!("{}: missing the HTML", f))),
    };
    if s.len() > MAX_INPUT {
        return Err(err(format!("{}: the input is {} bytes; the limit is {} (16 MiB)", f, s.len(), MAX_INPUT)));
    }
    Ok(s)
}

/// Un documento completo o un fragmento: `parse_document` agrega `html`/`body` si faltan, así que
/// sirve para los dos.
fn parse(s: &str) -> Html {
    Html::parse_document(s)
}

const SKIP: [&str; 4] = ["script", "style", "template", "noscript"];

/// El texto visible de un elemento, sin los bloques que no se leen.
fn text_of(el: ElementRef<'_>) -> String {
    let mut out = String::new();
    for node in el.descendants() {
        if let Node::Text(t) = node.value() {
            let hidden = node.ancestors().any(|a| a.value().as_element().is_some_and(|e| SKIP.contains(&e.name())));
            if !hidden {
                out.push_str(t);
            }
        }
    }
    out
}

fn html_select(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "html_select";
    let html = html_arg(args, F)?;
    let sel = match args.get(1) {
        Some(SynValue::Text(t)) => t.to_string(),
        Some(other) => return Err(err(format!("{}: the selector must be CSS text, got {}", F, other.type_name()))),
        None => return Err(err(format!("{}: missing the CSS selector", F))),
    };
    let selector = Selector::parse(&sel).map_err(|e| err(format!("{}: invalid CSS selector {:?}: {}", F, sel, e)))?;
    let doc = parse(html);
    let mut out = Vec::new();
    for el in doc.select(&selector) {
        let mut m = SynMap::new();
        m.insert("tag", syn_text(el.value().name()));
        let mut attrs = SynMap::new();
        for (k, v) in el.value().attrs() {
            attrs.insert(k, syn_text(v));
        }
        m.insert("attrs", syn_map(attrs));
        m.insert("text", syn_text(collapse(&text_of(el))));
        m.insert("html", syn_text(el.inner_html()));
        out.push(syn_map(m));
    }
    Ok(syn_list(out))
}

const BLOCKS: [&str; 24] = [
    "p", "div", "br", "li", "ul", "ol", "tr", "table", "section", "article", "header", "footer", "h1", "h2", "h3",
    "h4", "h5", "h6", "pre", "blockquote", "nav", "main", "aside", "dd",
];

/// Colapsa los espacios de cada línea y deja una línea por bloque (sin líneas vacías).
fn collapse(s: &str) -> String {
    s.split('\n')
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn html_text(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "html_text";
    let html = html_arg(args, F)?;
    let doc = parse(html);
    let mut out = String::new();
    // Recorrido en orden con un salto antes y después de cada bloque.
    fn walk(node: ego_tree::NodeRef<'_, Node>, out: &mut String) {
        match node.value() {
            Node::Text(t) => out.push_str(&t[..]),
            Node::Element(e) => {
                if SKIP.contains(&e.name()) {
                    return;
                }
                let block = BLOCKS.contains(&e.name());
                if block {
                    out.push('\n');
                }
                for c in node.children() {
                    walk(c, out);
                }
                if block {
                    out.push('\n');
                }
            }
            _ => {
                for c in node.children() {
                    walk(c, out);
                }
            }
        }
    }
    walk(doc.tree.root(), &mut out);
    Ok(syn_text(collapse(&out)))
}

fn html_unescape(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "html_unescape";
    let s = match args.first() {
        Some(SynValue::Text(t)) => t.to_string(),
        Some(other) => return Err(err(format!("{}: expects text, got {}", F, other.type_name()))),
        None => return Err(err(format!("{}: missing the text", F))),
    };
    if s.len() > MAX_INPUT {
        return Err(err(format!("{}: the input is larger than 16 MiB", F)));
    }
    if !s.contains('&') {
        return Ok(syn_text(s));
    }
    // El parser de HTML decodifica las entidades con la tabla de WHATWG; `<` se protege antes para
    // que el texto no se lea como marcado (y quede tal cual).
    let frag = Html::parse_fragment(&s.replace('<', "&lt;"));
    let mut out = String::new();
    for node in frag.tree.root().descendants() {
        if let Node::Text(t) = node.value() {
            out.push_str(t);
        }
    }
    Ok(syn_text(out))
}

pub fn register_html_builtins(interp: &Interpreter) {
    interp.register_builtin("html_select", 2, Rc::new(|_i, a, _l| html_select(a)));
    interp.register_builtin("html_text", 1, Rc::new(|_i, a, _l| html_text(a)));
    interp.register_builtin("html_unescape", 1, Rc::new(|_i, a, _l| html_unescape(a)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> SynValue {
        syn_text(s)
    }

    #[test]
    fn select_reads_real_html() {
        // Sin cerrar, atributos sin comillas, entidades: lo que xml_parse no lee.
        let page = r#"<ul><li class=item><a href=https://x.test/1>Uno &amp; dos</a><li class="item sel"><a href="/2">Dos</a></ul><p>fin"#;
        let r = html_select(&[t(page), t("li.item > a")]).ok().unwrap().to_string();
        assert!(r.contains("Uno & dos") && r.contains("https://x.test/1") && r.contains("/2"), "{}", r);
        let sel = html_select(&[t(page), t("li.sel a")]).ok().unwrap().to_string();
        assert!(sel.contains("Dos") && !sel.contains("Uno"), "{}", sel);
        assert!(matches!(html_select(&[t(page), t("li[")]), Err(Control::Error(_))));
    }

    #[test]
    fn text_skips_scripts_and_keeps_blocks() {
        let page = "<h1>Título</h1><script>alert(1)</script><p>uno   dos</p><style>p{}</style><div>tres</div>";
        let r = html_text(&[t(page)]).ok().unwrap().to_string();
        assert_eq!(r, "Título\nuno dos\ntres");
    }

    #[test]
    fn unescape_uses_the_whatwg_table_and_keeps_markup() {
        let r = html_unescape(&[t("a &amp; b &eacute; &#x1F680; <b>x</b> &nbsp;")]).ok().unwrap().to_string();
        assert_eq!(r, "a & b é 🚀 <b>x</b> \u{a0}");
        assert_eq!(html_unescape(&[t("sin entidades")]).ok().unwrap().to_string(), "sin entidades");
    }
}

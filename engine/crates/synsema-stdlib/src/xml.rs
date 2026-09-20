//! v0.6.20 — `xml_parse(text) → map`: XML a mapas y listas, a la altura de `json_decode`.
//!
//! Convención de `xmltodict` (conocida, determinista): un elemento es un mapa; sus atributos
//! van con prefijo `@`; el texto va en `#text` (o es el valor directo si el elemento sólo
//! tiene texto); los hijos con el MISMO nombre se juntan en una lista, en orden de
//! documento; los prefijos de namespace se conservan en el nombre tal cual aparecen
//! (`cfdi:Emisor`). La raíz es `{"<tag raíz>": …}`. Un elemento vacío es `nothing`.
//!
//! Lo que NO hace, a propósito: no resuelve DTD ni entidades externas (roxmltree no las
//! procesa: no hay XXE por construcción; un documento con DOCTYPE falla con un error claro),
//! no expone las declaraciones `xmlns` como atributos, y no hay `xml_encode` (nadie lo pidió).
//! Puro: sin I/O, mismo resultado en los tres perfiles.
//!
//! Origen: la factura electrónica de los mercados de la plataforma es XML (CFDI en México,
//! NF-e en Brasil, Facturae en España, AFIP en Argentina); se extrae sin LLM y el LLM sólo
//! revisa.

use std::rc::Rc;

use indexmap::IndexMap;

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::types::{syn_list, syn_map, syn_text, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

/// Nombre calificado tal cual se escribió: `prefijo:local` si el namespace tiene prefijo
/// declarado en el ámbito del nodo, `local` si no (o si es el namespace por defecto).
fn qname(node: &roxmltree::Node<'_, '_>, local: &str, ns: Option<&str>) -> String {
    match ns.and_then(|uri| node.lookup_prefix(uri)) {
        Some(p) if !p.is_empty() => format!("{}:{}", p, local),
        _ => local.to_string(),
    }
}

fn element_to_syn(node: roxmltree::Node<'_, '_>) -> SynValue {
    let mut m: IndexMap<String, SynValue> = IndexMap::new();
    for a in node.attributes() {
        m.insert(format!("@{}", qname(&node, a.name(), a.namespace())), syn_text(a.value()));
    }
    let mut text = String::new();
    let mut child_elements = 0usize;
    for child in node.children() {
        if child.is_element() {
            child_elements += 1;
            let key = qname(&child, child.tag_name().name(), child.tag_name().namespace());
            let val = element_to_syn(child);
            match m.get_mut(&key) {
                None => {
                    m.insert(key, val);
                }
                // Repetido → lista (un elemento nunca se convierte a lista por sí mismo, así
                // que una lista existente siempre es "los repetidos hasta ahora").
                Some(SynValue::List(l)) => l.borrow_mut().push(val),
                Some(existing) => {
                    let prev = existing.clone();
                    *existing = syn_list(vec![prev, val]);
                }
            }
        } else if child.is_text() {
            if let Some(t) = child.text() {
                text.push_str(t);
            }
        }
    }
    let text = text.trim();
    if m.is_empty() && child_elements == 0 {
        return if text.is_empty() { SynValue::Nothing } else { syn_text(text) };
    }
    if !text.is_empty() {
        m.insert("#text".to_string(), syn_text(text));
    }
    syn_map(m)
}

pub fn xml_parse(args: &[SynValue]) -> Result<SynValue, Control> {
    const F: &str = "xml_parse";
    let text = match args.first() {
        Some(SynValue::Text(s)) => s.to_string(),
        Some(SynValue::Bytes(b)) => String::from_utf8(b.to_vec())
            .map_err(|_| err(format!("{}: the bytes are not valid UTF-8 text", F)))?,
        Some(other) => {
            return Err(err(format!("{}: expected XML text, got {}", F, other.type_name())))
        }
        None => return Err(err(format!("{}(text) takes the XML document as text", F))),
    };
    let doc = roxmltree::Document::parse(&text).map_err(|e| {
        err(format!(
            "{}: {} (DTDs and external entities are not processed on purpose)",
            F, e
        ))
    })?;
    let root = doc.root_element();
    let key = qname(&root, root.tag_name().name(), root.tag_name().namespace());
    let mut out = IndexMap::new();
    out.insert(key, element_to_syn(root));
    Ok(syn_map(out))
}

pub fn register_xml_builtins(interp: &Interpreter) {
    interp.register_builtin("xml_parse", 1, Rc::new(|_i, a, _l| xml_parse(a)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> SynValue {
        match xml_parse(&[syn_text(s)]) {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("{}", e),
            Err(_) => panic!("control"),
        }
    }

    fn get<'a>(v: &'a SynValue, k: &str) -> SynValue {
        match v {
            SynValue::Map(m) => m.borrow().get(k).cloned().unwrap_or_else(|| panic!("sin clave {}", k)),
            other => panic!("no es un map: {}", other),
        }
    }

    #[test]
    fn cfdi_like_document_attributes_prefixes_and_text() {
        let doc = r#"<?xml version="1.0" encoding="UTF-8"?>
<cfdi:Comprobante xmlns:cfdi="http://www.sat.gob.mx/cfd/4" Version="4.0" Total="1160.00">
  <cfdi:Emisor Rfc="AAA010101AAA" Nombre="ACME"/>
  <cfdi:Conceptos>
    <cfdi:Concepto Cantidad="1" Descripcion="Servicio"/>
    <cfdi:Concepto Cantidad="2" Descripcion="Otro"/>
  </cfdi:Conceptos>
  <Nota>hola <![CDATA[mundo]]></Nota>
</cfdi:Comprobante>"#;
        let v = parse(doc);
        let root = get(&v, "cfdi:Comprobante");
        assert_eq!(get(&root, "@Version").to_string(), "4.0");
        assert_eq!(get(&get(&root, "cfdi:Emisor"), "@Rfc").to_string(), "AAA010101AAA");
        let conceptos = get(&get(&root, "cfdi:Conceptos"), "cfdi:Concepto");
        match &conceptos {
            SynValue::List(l) => {
                assert_eq!(l.borrow().len(), 2);
                assert_eq!(get(&l.borrow()[1], "@Cantidad").to_string(), "2");
            }
            other => panic!("esperaba lista de repetidos, got {}", other),
        }
        assert_eq!(get(&root, "Nota").to_string(), "hola mundo");
    }

    #[test]
    fn empty_element_is_nothing_and_mixed_content_keeps_text() {
        let v = parse("<a><b/><c x=\"1\">t</c></a>");
        let a = get(&v, "a");
        assert!(matches!(get(&a, "b"), SynValue::Nothing));
        let c = get(&a, "c");
        assert_eq!(get(&c, "@x").to_string(), "1");
        assert_eq!(get(&c, "#text").to_string(), "t");
    }

    #[test]
    fn malformed_xml_and_doctype_fail_clearly() {
        let e = match xml_parse(&[syn_text("<a><b></a>")]) {
            Err(Control::Error(e)) => e.to_string(),
            _ => panic!("esperaba error"),
        };
        assert!(e.contains("xml_parse:"), "{}", e);
        let e = match xml_parse(&[syn_text("<!DOCTYPE a [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><a>&x;</a>")]) {
            Err(Control::Error(e)) => e.to_string(),
            Ok(_) => panic!("un DOCTYPE con entidad externa no debe parsear"),
            _ => panic!("control"),
        };
        assert!(e.contains("xml_parse:"), "{}", e);
    }
}

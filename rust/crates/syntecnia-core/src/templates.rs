//! Templates SSR. Port de `syntecnia/stdlib/templates.py`.
//!
//! HTML con holes `{ ... }`: interpolación (AUTO-ESCAPADA), `{ each x in xs }…{ end }`,
//! `{ when c }…{ otherwise }…{ end }`, `{ raw expr }` (opt-out de escape). El control
//! de flujo reusa el `each`/`when` de Syntecnia. Vive en core porque está acoplado al
//! parser (expresiones de los holes) y al intérprete (evaluarlas).

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::ast::Node;
use crate::interpreter::{env_get, env_set, Control, Environment, Interpreter, RuntimeError};
use crate::parser::{parse_each_clause, parse_expression_source};
use crate::types::{ServerValue, SynValue};

/// Valor "raw response" (lo que devuelve `render`/`html`/`respond`): un valor del
/// servidor con tag `_RAW` ({body, content_type, status}). El corpus lo observa
/// con `body of …` (property access sobre el Server value).
pub fn make_raw(body: String, content_type: &str, status: i64) -> SynValue {
    SynValue::Server(Rc::new(ServerValue::Raw {
        body,
        content_type: content_type.to_string(),
        status,
    }))
}

fn terr(file: &str, line: usize, msg: &str) -> Control {
    Control::Error(RuntimeError::new(format!("{}:{}: {}", file, line, msg)))
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

fn is_bare_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(f) if f.is_ascii_alphabetic() || f == '_' => {}
        _ => return false,
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    !matches!(s, "true" | "false" | "nothing")
}

/// Resuelve un path de template (relativo al cwd, sin traversal).
fn resolve_template_path(path: &str) -> Result<PathBuf, String> {
    let cwd = std::env::current_dir()
        .and_then(|p| p.canonicalize())
        .map_err(|e| e.to_string())?;
    if Path::new(path).is_absolute() {
        return Err(format!("template path must be relative to the working dir: '{}'", path));
    }
    let target = match cwd.join(path).canonicalize() {
        Ok(t) => t,
        Err(_) => return Err(format!("template not found: {}", path)),
    };
    if target != cwd && !target.starts_with(&cwd) {
        return Err(format!("template path escapes the working directory: '{}'", path));
    }
    if !target.is_file() {
        return Err(format!("template not found: {}", path));
    }
    Ok(target)
}

enum Seg {
    Text(String),
    Hole(String, usize),
}

enum TNode {
    Text(String),
    Name { name: String, escape: bool },
    Expr { node: Node, escape: bool },
    Each { var: String, coll: Node, body: Vec<TNode> },
    When { cond: Node, then: Vec<TNode>, els: Vec<TNode> },
}

/// Divide el source en segmentos texto/hole (quote-aware: `}` dentro de `"…"` no cierra).
fn segments(src: &str, filename: &str) -> Result<Vec<Seg>, Control> {
    let chars: Vec<char> = src.chars().collect();
    let n = chars.len();
    let mut segs = Vec::new();
    let mut buf = String::new();
    let mut i = 0;
    let mut line = 1usize;
    while i < n {
        let c = chars[i];
        if c == '{' {
            if !buf.is_empty() {
                segs.push(Seg::Text(std::mem::take(&mut buf)));
            }
            let hole_line = line;
            let mut j = i + 1;
            let mut content = String::new();
            let mut in_str = false;
            let mut esc = false;
            let mut closed = false;
            while j < n {
                let cj = chars[j];
                if cj == '\n' {
                    line += 1;
                }
                if in_str {
                    content.push(cj);
                    if esc {
                        esc = false;
                    } else if cj == '\\' {
                        esc = true;
                    } else if cj == '"' {
                        in_str = false;
                    }
                } else if cj == '"' {
                    in_str = true;
                    content.push(cj);
                } else if cj == '}' {
                    closed = true;
                    break;
                } else {
                    content.push(cj);
                }
                j += 1;
            }
            if !closed {
                return Err(terr(filename, hole_line, "unclosed '{' in template"));
            }
            segs.push(Seg::Hole(content.trim().to_string(), hole_line));
            i = j + 1;
        } else {
            if c == '\n' {
                line += 1;
            }
            buf.push(c);
            i += 1;
        }
    }
    if !buf.is_empty() {
        segs.push(Seg::Text(buf));
    }
    Ok(segs)
}

fn split_head(content: &str) -> (String, String) {
    let t = content.trim();
    match t.split_once(char::is_whitespace) {
        Some((h, r)) => (h.to_string(), r.trim_start().to_string()),
        None => (t.to_string(), String::new()),
    }
}

fn value_node(src: &str, escape: bool, filename: &str, line: usize) -> Result<TNode, Control> {
    let s = src.trim();
    if is_bare_name(s) {
        Ok(TNode::Name { name: s.to_string(), escape })
    } else {
        let node = parse_expression_source(s, filename)
            .map_err(|e| terr(filename, line, &format!("invalid expression {{ {} }}: {}", s, e)))?;
        Ok(TNode::Expr { node, escape })
    }
}

/// Construye una lista de nodos hasta encontrar un hole cuyo head esté en `stop`
/// (o EOF). Devuelve (nodos, head_terminador | "" si EOF).
fn parse_block(
    segs: &[Seg],
    pos: &mut usize,
    filename: &str,
    stop: &[&str],
) -> Result<(Vec<TNode>, String), Control> {
    let mut out = Vec::new();
    while *pos < segs.len() {
        let idx = *pos;
        *pos += 1;
        match &segs[idx] {
            Seg::Text(s) => out.push(TNode::Text(s.clone())),
            Seg::Hole(content, line) => {
                let line = *line;
                let (head, rest) = split_head(content);
                if stop.contains(&head.as_str()) {
                    return Ok((out, head));
                }
                match head.as_str() {
                    "each" => {
                        let (var, coll) = parse_each_clause(&rest, filename)
                            .map_err(|e| terr(filename, line, &format!("invalid 'each' directive: {}", e)))?;
                        let (body, term) = parse_block(segs, pos, filename, &["end"])?;
                        if term != "end" {
                            return Err(terr(filename, line, "missing '{ end }' for '{ each ... }'"));
                        }
                        out.push(TNode::Each { var, coll, body });
                    }
                    "when" => {
                        let cond = parse_expression_source(&rest, filename)
                            .map_err(|e| terr(filename, line, &format!("invalid expression {{ {} }}: {}", rest, e)))?;
                        let (then, term) = parse_block(segs, pos, filename, &["otherwise", "end"])?;
                        let els = if term == "otherwise" {
                            let (e, t2) = parse_block(segs, pos, filename, &["end"])?;
                            if t2 != "end" {
                                return Err(terr(filename, line, "missing '{ end }' for '{ when ... }'"));
                            }
                            e
                        } else if term == "end" {
                            Vec::new()
                        } else {
                            return Err(terr(filename, line, "missing '{ end }' for '{ when ... }'"));
                        };
                        out.push(TNode::When { cond, then, els });
                    }
                    "raw" => out.push(value_node(&rest, false, filename, line)?),
                    "end" => return Err(terr(filename, line, "'{ end }' without a matching block")),
                    "otherwise" => return Err(terr(filename, line, "'otherwise' outside a 'when' block")),
                    _ => out.push(value_node(content, true, filename, line)?),
                }
            }
        }
    }
    Ok((out, String::new()))
}

fn emit(value: &SynValue, escape: bool, out: &mut String) {
    let s = value.to_string();
    if escape {
        out.push_str(&html_escape(&s));
    } else {
        out.push_str(&s);
    }
}

fn render_nodes(
    nodes: &[TNode],
    interp: &mut Interpreter,
    env: &Rc<RefCell<Environment>>,
    out: &mut String,
    filename: &str,
) -> Result<(), Control> {
    for node in nodes {
        match node {
            TNode::Text(s) => out.push_str(s),
            TNode::Name { name, escape } => {
                let val = env_get(env, name).ok_or_else(|| {
                    Control::Error(RuntimeError::new(format!(
                        "{}: field '{}' is not in the template data",
                        filename, name
                    )))
                })?;
                emit(&val, *escape, out);
            }
            TNode::Expr { node, escape } => {
                let val = interp.eval(node, env)?;
                emit(&val, *escape, out);
            }
            TNode::Each { var, coll, body } => {
                let c = interp.eval(coll, env)?;
                let items = match &c {
                    SynValue::List(l) => l.borrow().clone(),
                    _ => Vec::new(),
                };
                for item in items {
                    let child = Environment::child(env, "template:each");
                    env_set(&child, var, item);
                    render_nodes(body, interp, &child, out, filename)?;
                }
            }
            TNode::When { cond, then, els } => {
                let c = interp.eval(cond, env)?;
                let branch = if c.is_truthy() { then } else { els };
                render_nodes(branch, interp, env, out, filename)?;
            }
        }
    }
    Ok(())
}

/// Renderiza el template `path` con `data` (un SynMap) bindeado como variables → HTML.
pub fn render_template(
    interp: &mut Interpreter,
    path: &str,
    data: Option<&SynValue>,
) -> Result<String, Control> {
    let target = resolve_template_path(path).map_err(|m| Control::Error(RuntimeError::new(m)))?;
    let src = std::fs::read_to_string(&target)
        .map_err(|_| Control::Error(RuntimeError::new(format!("template not found: {}", path))))?;
    let filename = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string());
    let segs = segments(&src, &filename)?;
    let mut pos = 0;
    let (tree, _) = parse_block(&segs, &mut pos, &filename, &[])?;
    let env = Environment::child(&interp.global_env, &format!("template:{}", filename));
    if let Some(SynValue::Map(m)) = data {
        for (k, v) in m.borrow().iter() {
            env_set(&env, k, v.clone());
        }
    }
    let mut out = String::new();
    render_nodes(&tree, interp, &env, &mut out, &filename)?;
    Ok(out)
}

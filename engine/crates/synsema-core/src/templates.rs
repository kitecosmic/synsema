//! Templates SSR. Port de `synsema/stdlib/templates.py`, extendido en Rust.
//!
//! HTML con holes `{ ... }`: interpolación (AUTO-ESCAPADA), `{ each x in xs }…{ end }`
//! (con `{ otherwise }` como rama lista-vacía), `{ when c }…{ otherwise when c2 }…
//! { otherwise }…{ end }` (encadenado, paridad con el `when` del lenguaje), `{ raw expr }`
//! (opt-out de escape), `{ raw }`…`{ end }` (bloque VERBATIM: CSS/JS inline con llaves
//! literales), `{ include "p" }` / `{ include "p" with expr }` (partial; `with` = props
//! aislados), `{ layout "L" }` + `{ slot }` / `{ slot "name" }` + `{ fill "name" }…{ end }`
//! (composición con slots nombrados), `{ -- comentario }` (no emite nada).
//!
//! El control de flujo reusa el `each`/`when` de Synsema. Vive en core porque está
//! acoplado al parser (expresiones de los holes) y al intérprete (evaluarlas).
//!
//! Los templates parseados se CACHEAN por (path canónico → mtime+size), así que el
//! hot-reload por request se conserva (editar el archivo invalida la entrada) sin
//! releer+reparsear en cada `render()` ni en cada `include` dentro de un loop.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::SystemTime;

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

/// Normaliza un path LÉXICAMENTE (colapsa `.` y `..`), sin tocar el filesystem.
/// A diferencia de `canonicalize`, funciona sobre paths inexistentes y NO agrega
/// el prefijo verbatim `\\?\` de Windows — clave para que el string resuelto sea
/// byte-idéntico al del oráculo Python (`os.path.normpath`).
fn lexical_normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Resuelve el path de un módulo local relativo al directorio del archivo que lo
/// importa. Mismo criterio de seguridad que `resolve_template_path` (sólo
/// relativo + `..` no puede escapar), anclado al dir del importador y exigiendo
/// sufijo `.syn`. Usa normalización LÉXICA en vez de `canonicalize` para que el
/// string resuelto coincida con el del puerto Python (en Windows `canonicalize`
/// emite un prefijo `\\?\` que `realpath` no; rompería la paridad de cualquier
/// path que aparezca en un error/ubicación). Los errores citan el path RAW
/// (nunca el resuelto), para no filtrar formas de path divergentes.
pub(crate) fn resolve_module_path(raw_path: &str, base_dir: &Path) -> Result<String, String> {
    // Una ruta drive-absoluta O con `/`/`\` inicial (root-relativa) se rechaza. El
    // chequeo del slash inicial mantiene la decisión idéntica entre plataformas/impls
    // (os.path.isabs y Path::is_absolute difieren en "/x" en Windows).
    if Path::new(raw_path).is_absolute()
        || raw_path.starts_with('/')
        || raw_path.starts_with('\\')
    {
        return Err(format!(
            "module path must be relative to the importing file: '{}'",
            raw_path
        ));
    }
    if !raw_path.ends_with(".syn") {
        return Err(format!("module path must end in '.syn': '{}'", raw_path));
    }
    let base = lexical_normalize(base_dir);
    let target = lexical_normalize(&base.join(raw_path));
    if target != base && !target.starts_with(&base) {
        return Err(format!(
            "module path escapes the importing directory: '{}'",
            raw_path
        ));
    }
    if !target.is_file() {
        return Err(format!("module not found: {}", raw_path));
    }
    Ok(target.to_string_lossy().to_string())
}

enum Seg {
    Text(String),
    Hole(String, usize),
}

enum TNode {
    Text(String),
    Name { name: String, escape: bool },
    Expr { node: Node, escape: bool },
    Each { var: String, coll: Node, body: Vec<TNode>, els: Vec<TNode>, line: usize },
    When { cond: Node, then: Vec<TNode>, els: Vec<TNode> },
    Slot { name: Option<String> },
    Include { path: String, with_expr: Option<Node> },
    Layout { path: String },
    Fill { name: String, body: Vec<TNode> },
}

/// ¿`chars[at..]` matchea `{` ws* `end` ws* `}`? Devuelve el índice del `}` final.
fn match_end_hole(chars: &[char], at: usize) -> Option<usize> {
    if chars.get(at) != Some(&'{') {
        return None;
    }
    let n = chars.len();
    let mut m = at + 1;
    while m < n && chars[m].is_whitespace() {
        m += 1;
    }
    if m + 3 > n || chars[m] != 'e' || chars[m + 1] != 'n' || chars[m + 2] != 'd' {
        return None;
    }
    let mut m2 = m + 3;
    while m2 < n && chars[m2].is_whitespace() {
        m2 += 1;
    }
    if chars.get(m2) == Some(&'}') {
        Some(m2)
    } else {
        None
    }
}

/// Divide el source en segmentos texto/hole (quote-aware: `}` dentro de `"…"` no cierra).
/// Un hole `{ raw }` SIN expresión abre un bloque VERBATIM: todo lo que sigue se copia
/// literal (llaves de CSS/JS incluidas) hasta el `{ end }` — resuelto acá, a nivel
/// scanner, para que el contenido jamás pase por el parser de expresiones.
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
            let mut depth = 0usize; // llaves anidadas fuera de strings (map literals en el hole)
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
                } else if cj == '{' {
                    depth += 1;
                    content.push(cj);
                } else if cj == '}' {
                    if depth > 0 {
                        depth -= 1;
                        content.push(cj);
                    } else {
                        closed = true;
                        break;
                    }
                } else {
                    content.push(cj);
                }
                j += 1;
            }
            if !closed {
                return Err(terr(filename, hole_line, "unclosed '{' in template"));
            }
            let trimmed = content.trim().to_string();
            if trimmed == "raw" {
                // Bloque verbatim: buscar el `{ end }` y copiar todo lo intermedio tal cual.
                let start = j + 1;
                let mut k = start;
                let mut found: Option<(usize, usize)> = None;
                while k < n {
                    if let Some(close) = match_end_hole(&chars, k) {
                        found = Some((k, close));
                        break;
                    }
                    k += 1;
                }
                let (end_open, end_close) = found.ok_or_else(|| {
                    terr(filename, hole_line, "missing '{ end }' for '{ raw }' verbatim block")
                })?;
                let text: String = chars[start..end_open].iter().collect();
                for &ch in &chars[start..=end_close] {
                    if ch == '\n' {
                        line += 1;
                    }
                }
                if !text.is_empty() {
                    segs.push(Seg::Text(text));
                }
                i = end_close + 1;
                continue;
            }
            segs.push(Seg::Hole(trimmed, hole_line));
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

fn parse_str_literal(rest: &str, filename: &str, line: usize, kw: &str) -> Result<String, Control> {
    let s = rest.trim();
    match s.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        Some(p) if !s.is_empty() && s.len() >= 2 => Ok(p.to_string()),
        _ => Err(terr(filename, line, &format!("'{{ {} ... }}' needs a quoted path, got: {}", kw, rest))),
    }
}

/// `include`: `"path"` u opcionalmente `"path" with <expr>` (props aislados).
fn parse_include_args(
    rest: &str,
    filename: &str,
    line: usize,
) -> Result<(String, Option<Node>), Control> {
    let s = rest.trim();
    let inner = s.strip_prefix('"').ok_or_else(|| {
        terr(filename, line, &format!("'{{ include ... }}' needs a quoted path, got: {}", rest))
    })?;
    let close = inner.find('"').ok_or_else(|| {
        terr(filename, line, &format!("'{{ include ... }}' needs a quoted path, got: {}", rest))
    })?;
    let path = inner[..close].to_string();
    let after = inner[close + 1..].trim();
    if after.is_empty() {
        return Ok((path, None));
    }
    let props_src = after.strip_prefix("with").map(str::trim_start).ok_or_else(|| {
        terr(filename, line, &format!(
            "unexpected text after the include path (only 'with <expr>' is allowed): {}",
            after
        ))
    })?;
    if props_src.is_empty() {
        return Err(terr(filename, line, "'{ include \"p\" with ... }' needs an expression after 'with'"));
    }
    let node = parse_expression_source(props_src, filename)
        .map_err(|e| terr(filename, line, &format!("invalid 'with' expression: {}", e)))?;
    Ok((path, Some(node)))
}

fn value_node(src: &str, escape: bool, filename: &str, line: usize) -> Result<TNode, Control> {
    let s = src.trim();
    if is_bare_name(s) {
        Ok(TNode::Name { name: s.to_string(), escape })
    } else {
        let node = parse_expression_source(s, filename).map_err(|e| {
            terr(filename, line, &format!(
                "invalid expression {{ {} }}: {} — '{{' and '}}' delimit template holes; \
                 wrap literal CSS/JS blocks in {{ raw }} ... {{ end }}, or serve them from a static file",
                s, e
            ))
        })?;
        Ok(TNode::Expr { node, escape })
    }
}

/// Cola de un `when`: cuerpo hasta `otherwise` / `otherwise when c` / `end`, con
/// encadenado recursivo — paridad con el `otherwise when` del lenguaje.
fn parse_when_tail(
    segs: &[Seg],
    pos: &mut usize,
    filename: &str,
    cond: Node,
    line: usize,
) -> Result<TNode, Control> {
    let (then, term) = parse_block(segs, pos, filename, &["otherwise", "end"])?;
    let (head, rest) = split_head(&term);
    match head.as_str() {
        "end" => Ok(TNode::When { cond, then, els: Vec::new() }),
        "otherwise" if rest.is_empty() => {
            let (els, t2) = parse_block(segs, pos, filename, &["end"])?;
            if split_head(&t2).0 != "end" {
                return Err(terr(filename, line, "missing '{ end }' for '{ when ... }'"));
            }
            Ok(TNode::When { cond, then, els })
        }
        "otherwise" => {
            let (h2, r2) = split_head(&rest);
            if h2 != "when" || r2.is_empty() {
                return Err(terr(filename, line, &format!(
                    "expected '{{ otherwise }}' or '{{ otherwise when <cond> }}', got: {{ {} }}",
                    term
                )));
            }
            let cond2 = parse_expression_source(&r2, filename)
                .map_err(|e| terr(filename, line, &format!("invalid expression {{ {} }}: {}", r2, e)))?;
            let nested = parse_when_tail(segs, pos, filename, cond2, line)?;
            Ok(TNode::When { cond, then, els: vec![nested] })
        }
        _ => Err(terr(filename, line, "missing '{ end }' for '{ when ... }'")),
    }
}

/// Construye una lista de nodos hasta encontrar un hole cuyo head esté en `stop`
/// (o EOF). Devuelve (nodos, contenido COMPLETO del hole terminador | "" si EOF).
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
                if content.starts_with("--") {
                    continue; // { -- comentario } — no emite nada
                }
                let (head, rest) = split_head(content);
                if stop.contains(&head.as_str()) {
                    return Ok((out, content.clone()));
                }
                match head.as_str() {
                    "each" => {
                        let (var, coll) = parse_each_clause(&rest, filename)
                            .map_err(|e| terr(filename, line, &format!("invalid 'each' directive: {}", e)))?;
                        let (body, term) = parse_block(segs, pos, filename, &["end", "otherwise"])?;
                        let (th, tr) = split_head(&term);
                        let els = match th.as_str() {
                            "end" => Vec::new(),
                            "otherwise" if tr.is_empty() => {
                                let (e, t2) = parse_block(segs, pos, filename, &["end"])?;
                                if split_head(&t2).0 != "end" {
                                    return Err(terr(filename, line, "missing '{ end }' for '{ each ... }'"));
                                }
                                e
                            }
                            "otherwise" => {
                                return Err(terr(filename, line,
                                    "'{ otherwise when ... }' is not valid in an 'each' block \
                                     (only a bare '{ otherwise }' as the empty-list branch)"));
                            }
                            _ => return Err(terr(filename, line, "missing '{ end }' for '{ each ... }'")),
                        };
                        out.push(TNode::Each { var, coll, body, els, line });
                    }
                    "when" => {
                        let cond = parse_expression_source(&rest, filename)
                            .map_err(|e| terr(filename, line, &format!("invalid expression {{ {} }}: {}", rest, e)))?;
                        out.push(parse_when_tail(segs, pos, filename, cond, line)?);
                    }
                    "raw" => out.push(value_node(&rest, false, filename, line)?),
                    "include" => {
                        let (path, with_expr) = parse_include_args(&rest, filename, line)?;
                        out.push(TNode::Include { path, with_expr });
                    }
                    "layout" => out.push(TNode::Layout {
                        path: parse_str_literal(&rest, filename, line, "layout")?,
                    }),
                    "slot" => {
                        let name = if rest.is_empty() {
                            None
                        } else {
                            Some(parse_str_literal(&rest, filename, line, "slot")?)
                        };
                        out.push(TNode::Slot { name });
                    }
                    "fill" => {
                        let name = parse_str_literal(&rest, filename, line, "fill")?;
                        let (body, term) = parse_block(segs, pos, filename, &["end"])?;
                        if split_head(&term).0 != "end" {
                            return Err(terr(filename, line, "missing '{ end }' for '{ fill ... }'"));
                        }
                        out.push(TNode::Fill { name, body });
                    }
                    "end" => return Err(terr(filename, line, "'{ end }' without a matching block")),
                    "otherwise" => return Err(terr(filename, line, "'otherwise' outside a 'when' or 'each' block")),
                    _ => out.push(value_node(content, true, filename, line)?),
                }
            }
        }
    }
    Ok((out, String::new()))
}

// ---------------------------------------------------------------------------
// Caché de templates parseados: path canónico → (mtime, size, árbol). El árbol
// se comparte por Rc; una edición del archivo (mtime o size distintos) invalida
// la entrada, así que el hot-reload por request se mantiene. thread_local: cada
// worker de serve tiene su caché (los árboles contienen Node, que no es Sync).
// ---------------------------------------------------------------------------

struct CachedTpl {
    mtime: SystemTime,
    size: u64,
    tree: Rc<Vec<TNode>>,
}

thread_local! {
    static TPL_CACHE: RefCell<HashMap<PathBuf, CachedTpl>> = RefCell::new(HashMap::new());
}

/// Carga (con caché) el árbol de un template ya resuelto. `display` es el nombre
/// que aparece en los errores (file_name, como siempre).
fn load_template(target: &PathBuf, display: &str, raw_path: &str) -> Result<Rc<Vec<TNode>>, Control> {
    let meta = std::fs::metadata(target)
        .map_err(|_| Control::Error(RuntimeError::new(format!("template not found: {}", raw_path))))?;
    let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let size = meta.len();
    let hit = TPL_CACHE.with(|c| {
        c.borrow().get(target).and_then(|e| {
            if e.mtime == mtime && e.size == size {
                Some(Rc::clone(&e.tree))
            } else {
                None
            }
        })
    });
    if let Some(tree) = hit {
        return Ok(tree);
    }
    let src = std::fs::read_to_string(target)
        .map_err(|_| Control::Error(RuntimeError::new(format!("template not found: {}", raw_path))))?;
    let segs = segments(&src, display)?;
    let mut pos = 0;
    let (tree, term) = parse_block(&segs, &mut pos, display, &[])?;
    if !term.is_empty() {
        return Err(terr(display, 1, &format!("'{{ {} }}' without a matching block", term)));
    }
    let tree = Rc::new(tree);
    TPL_CACHE.with(|c| {
        c.borrow_mut().insert(target.clone(), CachedTpl { mtime, size, tree: Rc::clone(&tree) })
    });
    Ok(tree)
}

/// Contenido de slots durante el render: `default` es el HTML de la página (para
/// `{ slot }`), `named` los bloques `{ fill "x" }` (para `{ slot "x" }`).
struct Slots<'a> {
    default: &'a str,
    named: &'a HashMap<String, String>,
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
    slots: &Slots,
    depth: usize,
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
            TNode::Each { var, coll, body, els, line } => {
                let c = interp.eval(coll, env)?;
                let items = match &c {
                    SynValue::List(l) => l.borrow().clone(),
                    SynValue::Map(_) => {
                        return Err(terr(filename, *line,
                            "Cannot iterate over map in '{ each }' — iterate its keys: { each k in keys(m) }"));
                    }
                    other => {
                        return Err(terr(filename, *line,
                            &format!("Cannot iterate over {} in '{{ each }}'", other.type_name())));
                    }
                };
                if items.is_empty() {
                    render_nodes(els, interp, env, out, filename, slots, depth)?;
                } else {
                    for item in items {
                        let child = Environment::child(env, "template:each");
                        env_set(&child, var, item);
                        render_nodes(body, interp, &child, out, filename, slots, depth)?;
                    }
                }
            }
            TNode::When { cond, then, els } => {
                let c = interp.eval(cond, env)?;
                let branch = if c.is_truthy() { then } else { els };
                render_nodes(branch, interp, env, out, filename, slots, depth)?;
            }
            // El HTML ya renderizado de la página hija, inyectado raw en un layout.
            TNode::Slot { name } => match name {
                None => out.push_str(slots.default),
                Some(n) => {
                    if let Some(html) = slots.named.get(n) {
                        out.push_str(html);
                    }
                    // Sin fill correspondiente → slot opcional, no emite nada.
                }
            },
            // Una declaración de layout no emite nada inline (la maneja render_file).
            TNode::Layout { .. } => {}
            // Un fill anidado (dentro de when/each/include) no tiene destino claro.
            TNode::Fill { name, .. } => {
                return Err(Control::Error(RuntimeError::new(format!(
                    "{}: '{{ fill \"{}\" }}' must be at the top level of the page",
                    filename, name
                ))));
            }
            // Un partial: con `with` renderiza con SOLO esos props (aislado);
            // sin `with` hereda el env actual (data + variables de loop).
            TNode::Include { path, with_expr } => {
                if depth > 50 {
                    return Err(Control::Error(RuntimeError::new(format!(
                        "{}: template include nesting too deep", filename
                    ))));
                }
                let target = resolve_template_path(path)
                    .map_err(|m| Control::Error(RuntimeError::new(m)))?;
                let inc_name = target
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.clone());
                let inc_tree = load_template(&target, &inc_name, path)?;
                match with_expr {
                    None => {
                        render_nodes(&inc_tree, interp, env, out, &inc_name, slots, depth + 1)?;
                    }
                    Some(expr) => {
                        let props = interp.eval(expr, env)?;
                        let m = match &props {
                            SynValue::Map(m) => m.clone(),
                            other => {
                                return Err(Control::Error(RuntimeError::new(format!(
                                    "{}: '{{ include \"{}\" with ... }}' expects a map of props, got {}",
                                    filename, path, other.type_name()
                                ))));
                            }
                        };
                        let child = Environment::child(&interp.global_env, "template:include");
                        for (k, v) in m.borrow().iter() {
                            env_set(&child, k, v.clone());
                        }
                        render_nodes(&inc_tree, interp, &child, out, &inc_name, slots, depth + 1)?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Renderiza un archivo de template. Si declara `{ layout "L" }`, renderiza su cuerpo
/// (los bloques `{ fill "x" }` de nivel superior van a slots nombrados) y luego
/// renderiza L inyectando el cuerpo en `{ slot }` y cada fill en su `{ slot "x" }`
/// (recursivo: un layout puede tener su propio layout). Soporta `{ include }`.
fn render_file(
    interp: &mut Interpreter,
    path: &str,
    data: Option<&SynValue>,
    slots: &Slots,
    depth: usize,
) -> Result<String, Control> {
    if depth > 50 {
        return Err(Control::Error(RuntimeError::new(format!(
            "template layout nesting too deep ({})", path
        ))));
    }
    let target = resolve_template_path(path).map_err(|m| Control::Error(RuntimeError::new(m)))?;
    let filename = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string());
    let tree = load_template(&target, &filename, path)?;
    let layout_path = tree.iter().find_map(|n| match n {
        TNode::Layout { path } => Some(path.clone()),
        _ => None,
    });
    let env = Environment::child(&interp.global_env, &format!("template:{}", filename));
    if let Some(SynValue::Map(m)) = data {
        for (k, v) in m.borrow().iter() {
            env_set(&env, k, v.clone());
        }
    }
    let mut out = String::new();
    let mut fills: HashMap<String, String> = HashMap::new();
    for node in tree.iter() {
        if let TNode::Fill { name, body } = node {
            if layout_path.is_none() {
                return Err(Control::Error(RuntimeError::new(format!(
                    "{}: '{{ fill \"{}\" }}' requires a '{{ layout \"...\" }}' declaration",
                    filename, name
                ))));
            }
            let mut fill_out = String::new();
            render_nodes(body, interp, &env, &mut fill_out, &filename, slots, depth)?;
            fills.insert(name.clone(), fill_out);
        } else {
            render_nodes(std::slice::from_ref(node), interp, &env, &mut out, &filename, slots, depth)?;
        }
    }
    if let Some(lp) = layout_path {
        let layout_slots = Slots { default: &out, named: &fills };
        return render_file(interp, &lp, data, &layout_slots, depth + 1);
    }
    Ok(out)
}

/// Renderiza el template `path` con `data` (un SynMap) bindeado como variables → HTML.
/// Soporta composición: `{ include }` (con o sin `with`), `{ layout }` / `{ slot }` /
/// `{ slot "name" }` + `{ fill "name" }`.
pub fn render_template(
    interp: &mut Interpreter,
    path: &str,
    data: Option<&SynValue>,
) -> Result<String, Control> {
    let named = HashMap::new();
    let slots = Slots { default: "", named: &named };
    render_file(interp, path, data, &slots, 0)
}

/// Chequeo ESTÁTICO (sin ejecutar) de un programa ya parseado — el corazón de
/// `synsema check`:
/// - resuelve y parsea recursivamente los módulos `use "..."` (mismas reglas que el
///   runtime: relativo al importador, sufijo `.syn`, sin escapar el directorio, sin
///   `serve` ni `require` top-level dentro de un módulo, ciclo → error),
/// - valida cada `render("literal.html")` (el archivo existe y parsea, junto con sus
///   `include`/`layout` literales).
/// Devuelve (módulos chequeados, templates validados) o el primer error.
pub fn check_program_static(
    program: &crate::ast::Program,
    file_path: &str,
) -> Result<(usize, usize), String> {
    fn scan(
        program: &crate::ast::Program,
        file_path: &str,
        is_module: bool,
        seen: &mut Vec<String>,
        stack: &mut Vec<String>,
        modules: &mut usize,
        templates_seen: &mut Vec<String>,
    ) -> Result<(), String> {
        use crate::ast::NodeKind as NK;
        if is_module {
            for stmt in &program.statements {
                match &stmt.kind {
                    NK::ServeBlock { .. } => {
                        return Err(format!(
                            "module '{}' must not contain a 'serve' block",
                            file_path
                        ))
                    }
                    NK::RequireStatement { .. } => {
                        return Err(format!(
                            "module '{}' must not have a top-level 'require'",
                            file_path
                        ))
                    }
                    _ => {}
                }
            }
        }
        let base_dir = Path::new(file_path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_default();
        let mut uses: Vec<String> = Vec::new();
        let mut renders: Vec<String> = Vec::new();
        for stmt in &program.statements {
            crate::ast_api::walk(stmt, &mut |n| match &n.kind {
                NK::UseImport { path, .. } => uses.push(path.clone()),
                NK::TaskCall { name, arguments } => {
                    if matches!(&name.kind, NK::Identifier { name } if name == "render") {
                        if let Some(first) = arguments.first() {
                            if first.name.is_none() {
                                if let NK::TextLiteral { value } = &first.value.kind {
                                    renders.push(value.clone());
                                }
                            }
                        }
                    }
                }
                _ => {}
            });
        }
        for tpath in renders {
            if !templates_seen.contains(&tpath) {
                templates_seen.push(tpath.clone());
                validate_template(&tpath).map_err(|e| {
                    format!(
                        "{}: template validation failed for render(\"{}\"): {}",
                        file_path, tpath, e
                    )
                })?;
            }
        }
        for raw in uses {
            let resolved = resolve_module_path(&raw, &base_dir)
                .map_err(|e| format!("{}: {}", file_path, e))?;
            if stack.contains(&resolved) {
                return Err(format!(
                    "circular import: module '{}' is already being loaded",
                    raw
                ));
            }
            if seen.contains(&resolved) {
                continue;
            }
            seen.push(resolved.clone());
            *modules += 1;
            let src = std::fs::read_to_string(&resolved)
                .map_err(|_| format!("module not found: {}", raw))?;
            let prog = crate::parser::parse_source(&src, &resolved).map_err(|e| e.to_string())?;
            stack.push(resolved.clone());
            let r = scan(&prog, &resolved, true, seen, stack, modules, templates_seen);
            stack.pop();
            r?;
        }
        Ok(())
    }
    let mut seen = Vec::new();
    let mut stack = vec![file_path.to_string()];
    let mut modules = 0usize;
    let mut templates_seen = Vec::new();
    scan(program, file_path, false, &mut seen, &mut stack, &mut modules, &mut templates_seen)?;
    Ok((modules, templates_seen.len()))
}

/// Valida (parsea) un template y, recursivamente, sus `include`/`layout` literales.
/// Lo usa la validación al arranque de `serve` y `synsema check` — un typo en un
/// `render("literal.html")` debe fallar ANTES del primer request.
pub fn validate_template(path: &str) -> Result<(), String> {
    fn walk(path: &str, depth: usize, seen: &mut Vec<String>) -> Result<(), String> {
        if depth > 50 {
            return Err(format!("template nesting too deep ({})", path));
        }
        if seen.iter().any(|p| p == path) {
            return Ok(());
        }
        seen.push(path.to_string());
        let target = resolve_template_path(path)?;
        let display = target
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());
        let tree = load_template(&target, &display, path).map_err(|c| match c {
            Control::Error(e) => e.message,
            _ => "template error".to_string(),
        })?;
        fn refs(nodes: &[TNode], acc: &mut Vec<String>) {
            for n in nodes {
                match n {
                    TNode::Include { path, .. } | TNode::Layout { path } => acc.push(path.clone()),
                    TNode::Each { body, els, .. } => {
                        refs(body, acc);
                        refs(els, acc);
                    }
                    TNode::When { then, els, .. } => {
                        refs(then, acc);
                        refs(els, acc);
                    }
                    TNode::Fill { body, .. } => refs(body, acc),
                    _ => {}
                }
            }
        }
        let mut children = Vec::new();
        refs(&tree, &mut children);
        for child in children {
            walk(&child, depth + 1, seen)?;
        }
        Ok(())
    }
    walk(path, 0, &mut Vec::new())
}

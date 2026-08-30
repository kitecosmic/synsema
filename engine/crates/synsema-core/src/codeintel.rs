//! Inteligencia de código para agentes (`synsema code`, spec `specs/code-intelligence.md`).
//!
//! Todo sale del parser: outline (símbolos sin cuerpos), definiciones, referencias, tabla de
//! rutas estática, contrato de capabilities (declaradas vs. necesarias), check multi-archivo,
//! búsqueda de texto y grafo de dependencias. **Nunca ejecuta el programa** y nunca habla con
//! una app corriendo: es development-time sobre los archivos de un root. Sin índice en disco:
//! cada consulta parsea lo que necesita.
//!
//! Salida: `serde_json::Value` determinista (claves en orden fijo — `preserve_order`; listas
//! ordenadas por `file, line`). El CLI la imprime en JSON o en tablas; el servidor MCP la
//! envuelve en `content[].text`.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use serde_json::{json, Value};

use crate::ast::{Node, NodeKind, Program};
use crate::ast_api::{get_dependency_graph, walk};
use crate::parser::{parse_source, CompileError};
use crate::route_meta::{
    self, api_routes_static, builtin_cap, callee_name, require_pair, ApiRoute, ResponseKind,
    StaticProgram,
};

/// Extensiones que `search` recorre por defecto.
pub const DEFAULT_SEARCH_KINDS: &[&str] =
    &["syn", "fsyn", "html", "css", "js", "ts", "md", "json", "toml", "txt", "example"];

/// Directorios que nunca se recorren (build/vendor/estado).
const SKIP_DIRS: &[&str] = &["node_modules", "target", "dist", "build", ".synsema", ".git"];

/// Tope de tamaño de archivo para `search` (2 MiB).
const MAX_SEARCH_FILE: u64 = 2 * 1024 * 1024;

/// Traza de tiempos por fase a stderr cuando `SYNSEMA_CODE_TRACE=1` (diagnóstico; nunca a stdout).
fn trace(label: &str, since: std::time::Instant) {
    if std::env::var("SYNSEMA_CODE_TRACE").map(|v| v == "1").unwrap_or(false) {
        eprintln!("[code] {} {} ms", label, since.elapsed().as_millis());
    }
}

/// Raíz del proyecto (cwd por defecto). Todas las rutas de salida son relativas a ella.
#[derive(Clone, Debug)]
pub struct Root {
    pub dir: PathBuf,
}

impl Root {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Root { dir: canon(&dir.into()) }
    }

    /// `path` relativo al root (o absoluto) → absoluto.
    fn abs(&self, path: &str) -> PathBuf {
        let p = Path::new(path);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.dir.join(p)
        }
    }

    /// Absoluto → relativo al root con `/` (o el path tal cual si no cuelga del root).
    fn rel(&self, p: &Path) -> String {
        let r = p.strip_prefix(&self.dir).unwrap_or(p);
        r.to_string_lossy().replace('\\', "/")
    }
}

fn skip_dir(name: &str) -> bool {
    SKIP_DIRS.contains(&name) || (name.starts_with('.') && name != ".")
}

fn walk_files(dir: &Path, out: &mut Vec<PathBuf>, keep: &dyn Fn(&Path) -> bool) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !skip_dir(name) {
                walk_files(&p, out, keep);
            }
        } else if keep(&p) {
            out.push(p);
        }
    }
}

fn ext_of(p: &Path) -> String {
    p.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase()
}

/// Archivos del proyecto con alguna de las extensiones dadas (recursivo, con exclusiones).
pub fn project_files(root: &Root, path: Option<&str>, kinds: &[&str]) -> Vec<PathBuf> {
    let base = root.abs(path.unwrap_or("."));
    if base.is_file() {
        return vec![base];
    }
    let mut out = Vec::new();
    walk_files(&base, &mut out, &|p| kinds.iter().any(|k| ext_of(p) == *k));
    out
}

/// Los `.syn`/`.fsyn` bajo `path` (o el archivo mismo).
pub fn syn_files(root: &Root, path: Option<&str>) -> Vec<PathBuf> {
    project_files(root, path, &["syn", "fsyn"])
}

// ---------------------------------------------------------------------------
// Parseo
// ---------------------------------------------------------------------------

/// Error de parseo/lexer con ubicación (para `check`/`outline`).
#[derive(Clone, Debug)]
pub struct Diag {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub message: String,
}

impl Diag {
    fn to_json(&self) -> Value {
        json!({"file": self.file, "line": self.line, "column": self.column, "message": self.message})
    }
}

thread_local! {
    /// Cache de parseo por (path, mtime): una consulta que toca N archivos parsea cada uno
    /// una vez, y el proceso MCP (long-lived) no re-parsea lo que no cambió.
    static PARSED: RefCell<HashMap<PathBuf, (Option<std::time::SystemTime>, Rc<Program>)>> = RefCell::new(HashMap::new());
}

/// Parsea un archivo (`.fsyn` se traduce primero, como `run --flat`). Cacheado por mtime.
pub fn parse_file(root: &Root, abs: &Path) -> Result<Program, Diag> {
    let mtime = std::fs::metadata(abs).ok().and_then(|m| m.modified().ok());
    let key = abs.to_path_buf();
    let hit = PARSED.with(|c| {
        c.borrow().get(&key).and_then(|(t, p)| if *t == mtime && mtime.is_some() { Some(p.clone()) } else { None })
    });
    if let Some(p) = hit {
        return Ok((*p).clone());
    }
    let parsed = parse_file_uncached(root, abs)?;
    PARSED.with(|c| {
        c.borrow_mut().insert(key, (mtime, Rc::new(parsed.clone())));
    });
    Ok(parsed)
}

fn parse_file_uncached(root: &Root, abs: &Path) -> Result<Program, Diag> {
    let rel = root.rel(abs);
    let src = std::fs::read_to_string(abs).map_err(|e| Diag {
        file: rel.clone(),
        line: 0,
        column: 0,
        message: format!("cannot read: {}", e),
    })?;
    let src = if ext_of(abs) == "fsyn" { crate::flat_syntax::translate_flat(&src) } else { src };
    parse_source(&src, &rel).map_err(|e| {
        let (loc, msg) = match &e {
            CompileError::Lex(l) => (l.location.clone(), l.message.clone()),
            CompileError::Parse(p) => (p.location.clone(), p.message.clone()),
        };
        Diag { file: rel.clone(), line: loc.line, column: loc.column, message: msg }
    })
}

// ---------------------------------------------------------------------------
// Símbolos
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Sym {
    pub kind: &'static str,
    pub name: String,
    pub line: usize,
    pub end_line: usize,
    /// Campos extra por tipo de símbolo (params, fields, auth, …).
    pub extra: Vec<(&'static str, Value)>,
}

impl Sym {
    fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("kind".into(), json!(self.kind));
        m.insert("name".into(), json!(self.name));
        m.insert("line".into(), json!(self.line));
        m.insert("end_line".into(), json!(self.end_line));
        for (k, v) in &self.extra {
            m.insert((*k).into(), v.clone());
        }
        Value::Object(m)
    }
}

/// Mayor línea alcanzada por un nodo (él mismo o cualquier descendiente).
fn max_line(node: &Node) -> usize {
    let mut m = node.location.line;
    walk(node, &mut |n| {
        if n.location.line > m {
            m = n.location.line;
        }
    });
    m
}

fn body_end(start: usize, body: &[Node]) -> usize {
    body.iter().map(max_line).max().unwrap_or(start).max(start)
}

/// Nombres de builtins/tasks llamados directamente en un cuerpo (orden de aparición).
fn direct_calls(body: &[Node]) -> Vec<String> {
    let mut calls: Vec<String> = Vec::new();
    for stmt in body {
        walk(stmt, &mut |n| {
            if let NodeKind::TaskCall { name, .. } = &n.kind {
                if let Some(c) = callee_name(name) {
                    if !calls.contains(&c) {
                        calls.push(c);
                    }
                }
            }
        });
    }
    calls
}

/// Hostname de una URL literal (`scheme://[user@]host[:port]/...`), en minúsculas.
fn url_host(url: &str) -> Option<String> {
    let after = url.find("://").map(|i| &url[i + 3..])?;
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let auth = &after[..end];
    let host = auth.rsplit('@').next().unwrap_or(auth);
    let host = if host.starts_with('[') {
        host.split(']').next().unwrap_or(host).trim_start_matches('[')
    } else {
        host.split(':').next().unwrap_or(host)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Contexto para resolver argumentos "casi literales": constantes top-level (`let base be
/// "https://…"`) y candidatos por parámetro (lo que los llamadores pasan como literal).
#[derive(Clone, Default)]
struct ScopeCtx {
    consts: HashMap<String, String>,
    params: HashMap<String, Vec<String>>,
}

/// Valor(es) textual(es) que puede tomar una expresión, estáticamente: literal, constante
/// top-level, parámetro con literales de los llamadores, o concatenación cuyo PREFIJO se
/// resuelve (`base + "/x"` → `"https://api.x/x"`, `"https://" + host` → prefijo `"https://"`).
/// `partial = true` cuando sólo se conoce el prefijo. Vacío = dinámico.
fn resolve_text(node: &Node, ctx: &ScopeCtx, depth: usize) -> Vec<(String, bool)> {
    if depth > 8 {
        return Vec::new();
    }
    match &node.kind {
        NodeKind::TextLiteral { value } => vec![(value.clone(), false)],
        NodeKind::Identifier { name } => {
            if let Some(v) = ctx.consts.get(name) {
                return vec![(v.clone(), false)];
            }
            ctx.params.get(name).map(|vs| vs.iter().map(|v| (v.clone(), false)).collect()).unwrap_or_default()
        }
        NodeKind::BinaryOp { left, operator, right } if operator == "+" => {
            let lefts = resolve_text(left, ctx, depth + 1);
            if lefts.is_empty() {
                return Vec::new();
            }
            let rights = resolve_text(right, ctx, depth + 1);
            let mut out = Vec::new();
            for (l, lp) in &lefts {
                if *lp || rights.is_empty() {
                    out.push((l.clone(), true));
                } else {
                    for (r, rp) in &rights {
                        out.push((format!("{}{}", l, r), *rp));
                    }
                }
            }
            out
        }
        _ => Vec::new(),
    }
}

/// Scope de una llamada gateada a partir de sus valores posibles: `net` → host (vale con un
/// prefijo si el host ya está completo), `file.*` → path (sólo completo), `exec` → comando
/// (primera palabra; vale con prefijo si ya hay un espacio). `None` = dinámico.
fn scope_from_values(cap: &str, values: &[(String, bool)]) -> Vec<Option<String>> {
    if values.is_empty() {
        return vec![None];
    }
    let mut out: Vec<Option<String>> = Vec::new();
    for (v, partial) in values {
        let sc = match cap {
            "net" => {
                // Con prefijo: el host está completo si después de `://` ya apareció `/`.
                let complete = !*partial || v.find("://").map(|i| v[i + 3..].contains('/')).unwrap_or(false);
                if complete { url_host(v) } else { None }
            }
            "file.read" | "file.write" => if *partial { None } else { Some(v.clone()) },
            "exec" => {
                if !*partial || v.contains(' ') { v.split_whitespace().next().map(String::from) } else { None }
            }
            _ => None,
        };
        if !out.contains(&sc) {
            out.push(sc);
        }
    }
    out
}

/// Capabilities DIRECTAS de un cuerpo en un solo recorrido: builtins gateados (con scope
/// resuelto para net/file/exec, sin scope para el resto), `llm` por nodo (reason/decide/
/// analyze/generate) y los `require` del propio cuerpo — el mismo criterio que
/// `route_meta::capabilities`, más la resolución de scopes.
fn direct_caps(body: &[Node], ctx: &ScopeCtx) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    let mut push = |e: (String, Option<String>)| {
        if !out.contains(&e) {
            out.push(e);
        }
    };
    for stmt in body {
        if let NodeKind::RequireStatement { capability, scope } = &stmt.kind {
            push(require_pair(capability, scope));
        }
        walk(stmt, &mut |n| match &n.kind {
            NodeKind::TaskCall { name, arguments } => {
                if let Some(c) = callee_name(name) {
                    if let Some(cap) = builtin_cap(&c) {
                        if matches!(cap, "net" | "file.read" | "file.write" | "exec") {
                            let first = arguments.iter().find(|a| a.name.is_none()).map(|a| &a.value);
                            let values = first.map(|f| resolve_text(f, ctx, 0)).unwrap_or_default();
                            for sc in scope_from_values(cap, &values) {
                                push((cap.to_string(), sc));
                            }
                        } else {
                            push((cap.to_string(), None));
                        }
                    }
                }
            }
            NodeKind::ReasonExpression { .. }
            | NodeKind::DecideExpression { .. }
            | NodeKind::AnalyzeExpression { .. }
            | NodeKind::GenerateExpression { .. } => push(("llm".to_string(), None)),
            _ => {}
        });
    }
    out
}

/// Sitios de llamada por callee en un cuerpo: los argumentos posicionales de cada llamada
/// (un solo recorrido; después se resuelven por task sin volver a caminar el AST).
fn call_sites(body: &[Node]) -> HashMap<String, Vec<Vec<Node>>> {
    let mut out: HashMap<String, Vec<Vec<Node>>> = HashMap::new();
    for stmt in body {
        walk(stmt, &mut |n| {
            if let NodeKind::TaskCall { name, arguments } = &n.kind {
                if let Some(c) = callee_name(name) {
                    if builtin_cap(&c).is_none() {
                        out.entry(c).or_default().push(arguments.iter().filter(|a| a.name.is_none()).map(|a| a.value.clone()).collect());
                    }
                }
            }
        });
    }
    out
}

/// Candidatos por parámetro a partir de los sitios de llamada ya recolectados.
fn params_from_sites(sites: &[Vec<Node>], param_names: &[String], ctx: &ScopeCtx) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for args in sites {
        for (i, pn) in param_names.iter().enumerate() {
            if let Some(arg) = args.get(i) {
                for (v, partial) in resolve_text(arg, ctx, 0) {
                    if !partial {
                        out.entry(pn.clone()).or_default().push(v);
                    }
                }
            }
        }
    }
    out
}

/// Constantes top-level de texto (o concatenaciones resolubles) de un programa.
fn top_consts(program: &Program) -> HashMap<String, String> {
    let mut consts = HashMap::new();
    for stmt in &program.statements {
        let inner = match &stmt.kind {
            NodeKind::ExportDeclaration { declaration } => declaration.as_ref(),
            _ => stmt,
        };
        if let NodeKind::LetBinding { name, value, .. } = &inner.kind {
            let ctx = ScopeCtx { consts: consts.clone(), params: HashMap::new() };
            let vals = resolve_text(value, &ctx, 0);
            if let [(v, false)] = vals.as_slice() {
                consts.insert(name.clone(), v.clone());
            }
        }
    }
    consts
}

/// Nombres de parámetros por task (`f` y `m.f`), para pasar literales de los llamadores.
fn task_params(sp: &StaticProgram) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::new();
    let mut add = |prefix: &str, prog: &Program| {
        for stmt in &prog.statements {
            let inner = match &stmt.kind {
                NodeKind::ExportDeclaration { declaration } => declaration.as_ref(),
                _ => stmt,
            };
            if let NodeKind::TaskDefinition { name, parameters, .. } = &inner.kind {
                out.insert(format!("{}{}", prefix, name), parameters.iter().map(|p| p.name.clone()).collect());
            }
        }
    };
    add("", &sp.main);
    for (alias, m) in &sp.modules {
        add(&format!("{}.", alias), m);
    }
    out
}

thread_local! {
    /// Memo por invocación: resultado de `scoped_transitive` de una task llamada SIN literales
    /// de parámetros (el caso común). Se limpia al empezar cada `caps`.
    static SCOPED_MEMO: RefCell<HashMap<String, Vec<(String, Option<String>)>>> = RefCell::new(HashMap::new());
}

/// Capabilities TRANSITIVAS de un cuerpo: las directas + las de cada task del programa que
/// invoca (una vez por task; lo que la task `require` ella misma cubre sus propias
/// necesidades). Los literales que el llamador pasa viajan como candidatos de parámetros.
fn caps_transitive(
    body: &[Node],
    lookup: &dyn Fn(&str) -> Option<route_meta::TaskSrc>,
    params_of: &HashMap<String, Vec<String>>,
    ctx: &ScopeCtx,
    seen: &mut Vec<String>,
    out: &mut Vec<(String, Option<String>)>,
) {
    for e in direct_caps(body, ctx) {
        if !out.contains(&e) {
            out.push(e);
        }
    }
    let sites = call_sites(body);
    let mut callees: Vec<&String> = sites.keys().collect();
    callees.sort();
    for c in callees {
        let c = c.clone();
        if seen.contains(&c) {
            continue;
        }
        seen.push(c.clone());
        if let Some(src) = lookup(&c) {
            // Lo que ESTE cuerpo le pasa a la task viaja como candidatos de sus parámetros.
            let names = params_of.get(&c).cloned().unwrap_or_default();
            let callee_ctx = ScopeCtx { consts: ctx.consts.clone(), params: params_from_sites(&sites[&c], &names, ctx) };
            let memo_key = if callee_ctx.params.is_empty() { Some(c.clone()) } else { None };
            let cached = memo_key.as_ref().and_then(|k| SCOPED_MEMO.with(|m| m.borrow().get(k).cloned()));
            let inner: Vec<(String, Option<String>)> = match cached {
                Some(v) => v,
                None => {
                    let mut inner: Vec<(String, Option<String>)> = Vec::new();
                    let mut local_seen: Vec<String> = seen.clone();
                    caps_transitive(&src.body, lookup, params_of, &callee_ctx, &mut local_seen, &mut inner);
                    if let Some(k) = &memo_key {
                        SCOPED_MEMO.with(|m| m.borrow_mut().insert(k.clone(), inner.clone()));
                    }
                    inner
                }
            };
            for (cap, sc) in inner {
                if covered(&src.requires, &cap, &sc) {
                    continue; // la task lo declara ella misma
                }
                if !out.contains(&(cap.clone(), sc.clone())) {
                    out.push((cap, sc));
                }
            }
        }
    }
}

/// Templates referenciados por literal (`render("x.html")`, `page(...)`, `include`) en un cuerpo.
fn templates_of(body: &[Node]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for stmt in body {
        walk(stmt, &mut |n| {
            if let NodeKind::TaskCall { name, arguments } = &n.kind {
                if matches!(callee_name(name).as_deref(), Some("render") | Some("page")) {
                    if let Some(NodeKind::TextLiteral { value }) = arguments.first().map(|a| &a.value.kind) {
                        if value.contains('.') && !out.contains(value) {
                            out.push(value.clone());
                        }
                    }
                }
            }
        });
    }
    out
}

fn text_lit(node: Option<&Node>) -> Option<String> {
    match node.map(|n| &n.kind) {
        Some(NodeKind::TextLiteral { value }) => Some(value.clone()),
        Some(NodeKind::NumberLiteral { value }) => Some(value.to_string()),
        _ => None,
    }
}

fn route_syms(routes: &[Node], host: Option<&str>, out: &mut Vec<Sym>) {
    for r in routes {
        if let NodeKind::RouteDefinition { method, path, requires_auth, streaming, socket, body, .. } =
            &r.kind
        {
            let proxy = body.len() == 1 && matches!(body[0].kind, NodeKind::ProxyStatement { .. });
            out.push(Sym {
                kind: "route",
                name: format!("{} {}", method, path),
                line: r.location.line,
                end_line: body_end(r.location.line, body),
                extra: vec![
                    ("auth", json!(requires_auth)),
                    ("stream", json!(streaming)),
                    ("socket", json!(socket)),
                    ("proxy", json!(proxy)),
                    ("host", json!(host)),
                    ("calls", json!(direct_calls(body))),
                    ("templates", json!(templates_of(body))),
                ],
            });
        }
    }
}

fn static_mounts_json(mounts: &[Node]) -> Vec<Value> {
    mounts
        .iter()
        .filter_map(|m| match &m.kind {
            NodeKind::StaticMount { directory, prefix, fallback, .. } => Some(json!({
                "dir": text_lit(Some(directory)),
                "prefix": text_lit(prefix.as_deref()).unwrap_or_else(|| "/".into()),
                "fallback": text_lit(fallback.as_deref()),
                "line": m.location.line,
            })),
            _ => None,
        })
        .collect()
}

fn sym_of(stmt: &Node, exported: bool, out: &mut Vec<Sym>) {
    let line = stmt.location.line;
    match &stmt.kind {
        NodeKind::ExportDeclaration { declaration } => sym_of(declaration, true, out),
        NodeKind::TaskDefinition { name, parameters, body, return_type, .. } => out.push(Sym {
            kind: "task",
            name: name.clone(),
            line,
            end_line: body_end(line, body),
            extra: vec![
                ("params", json!(parameters.iter().map(|p| p.name.clone()).collect::<Vec<_>>())),
                ("returns", json!(return_type)),
                ("exported", json!(exported)),
                ("calls", json!(direct_calls(body))),
                ("templates", json!(templates_of(body))),
            ],
        }),
        NodeKind::AgentDefinition { name, initial_state, body, .. } => out.push(Sym {
            kind: "agent",
            name: name.clone(),
            line,
            end_line: body_end(line, body),
            extra: vec![
                ("initial_state", json!(initial_state)),
                ("exported", json!(exported)),
                ("calls", json!(direct_calls(body))),
            ],
        }),
        NodeKind::TypeDefinition { name, fields } => out.push(Sym {
            kind: "type",
            name: name.clone(),
            line,
            end_line: max_line(stmt),
            extra: vec![
                ("fields", json!(fields.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>())),
                ("exported", json!(exported)),
            ],
        }),
        NodeKind::EnumDefinition { name, variants } => out.push(Sym {
            kind: "enum",
            name: name.clone(),
            line,
            end_line: max_line(stmt),
            extra: vec![
                ("variants", json!(variants.iter().map(|(v, _)| v.clone()).collect::<Vec<_>>())),
                ("exported", json!(exported)),
            ],
        }),
        NodeKind::LetBinding { name, .. } => out.push(Sym {
            kind: "let",
            name: name.clone(),
            line,
            end_line: max_line(stmt),
            extra: vec![("exported", json!(exported))],
        }),
        NodeKind::RoutesDeclaration { name, routes } => {
            out.push(Sym {
                kind: "routes",
                name: name.clone(),
                line,
                end_line: max_line(stmt),
                extra: vec![("routes", json!(routes.len())), ("exported", json!(exported))],
            });
            route_syms(routes, None, out);
        }
        NodeKind::ServeBlock { port, routes, hosts, mounts, static_mounts, auth_handler, .. } => {
            let port_s = text_lit(Some(port)).unwrap_or_else(|| "?".into());
            let mut n_routes = routes.len();
            let mut host_names: Vec<String> = Vec::new();
            let mut statics = static_mounts_json(static_mounts);
            for h in hosts {
                if let NodeKind::HostBlock { pattern, routes: hr, static_mounts: hs, .. } = &h.kind {
                    n_routes += hr.len();
                    let hn = text_lit(Some(pattern)).unwrap_or_else(|| "?".into());
                    for mut m in static_mounts_json(hs) {
                        m["host"] = json!(hn);
                        statics.push(m);
                    }
                    host_names.push(hn);
                }
            }
            let auth = match auth_handler.as_deref().map(|n| &n.kind) {
                Some(NodeKind::Identifier { name }) => Some(name.clone()),
                Some(_) => Some("<expr>".to_string()),
                None => None,
            };
            out.push(Sym {
                kind: "serve",
                name: format!("serve {}", port_s),
                line,
                end_line: max_line(stmt),
                extra: vec![
                    ("routes", json!(n_routes)),
                    ("mounts", json!(mounts.len())),
                    ("hosts", json!(host_names)),
                    ("static", json!(statics)),
                    ("auth_with", json!(auth)),
                ],
            });
            route_syms(routes, None, out);
            for h in hosts {
                if let NodeKind::HostBlock { pattern, routes: hr, .. } = &h.kind {
                    let hn = text_lit(Some(pattern)).unwrap_or_else(|| "?".into());
                    route_syms(hr, Some(&hn), out);
                }
            }
        }
        NodeKind::TestBlock { name, body } => out.push(Sym {
            kind: "test",
            name: name.clone(),
            line,
            end_line: body_end(line, body),
            extra: vec![],
        }),
        NodeKind::InvariantDeclaration { description, .. } => out.push(Sym {
            kind: "invariant",
            name: description.clone().unwrap_or_default(),
            line,
            end_line: max_line(stmt),
            extra: vec![],
        }),
        _ => {}
    }
}

/// Símbolos top-level de un programa (tasks, agentes, tipos, lets, serve/rutas, tests…).
pub fn symbols_of(program: &Program) -> Vec<Sym> {
    let mut out = Vec::new();
    for stmt in &program.statements {
        sym_of(stmt, false, &mut out);
    }
    out.sort_by_key(|s| s.line);
    out
}

fn intent_of(program: &Program) -> Option<String> {
    program.statements.iter().find_map(|s| match &s.kind {
        NodeKind::IntentDeclaration { description } => Some(description.clone()),
        _ => None,
    })
}

fn requires_of(program: &Program) -> Vec<Value> {
    program
        .statements
        .iter()
        .filter_map(|s| match &s.kind {
            NodeKind::RequireStatement { capability, scope } => {
                let (cap, sc) = require_pair(capability, scope);
                Some(json!({"cap": cap, "scope": sc, "line": s.location.line}))
            }
            _ => None,
        })
        .collect()
}

fn imports_of(program: &Program) -> Vec<(String, String, usize)> {
    program
        .statements
        .iter()
        .filter_map(|s| match &s.kind {
            NodeKind::UseImport { path, alias } => Some((path.clone(), alias.clone(), s.location.line)),
            _ => None,
        })
        .collect()
}

/// Símbolo top-level que contiene la línea (`"top-level"` si ninguno).
fn enclosing(syms: &[Sym], line: usize) -> String {
    // El más interno: entre los que contienen la línea, el de inicio más tardío.
    syms.iter()
        .filter(|s| s.line <= line && line <= s.end_line && s.kind != "serve")
        .max_by_key(|s| s.line)
        .map(|s| format!("{} {}", s.kind, s.name))
        .unwrap_or_else(|| "top-level".to_string())
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

/// `outline(path?, full?)`: estructura de cada `.syn`, sin cuerpos. Con más de un archivo
/// y `full = false`, cada entrada es **compacta** (intent, contadores, nombres acotados,
/// `imported_by`): el mapa del proyecto en una pantalla. Un archivo solo, o `full`, da todo.
pub fn outline(root: &Root, path: Option<&str>, full: bool) -> Value {
    let mut files = Vec::new();
    let t0 = std::time::Instant::now();
    let targets = syn_files(root, path);
    trace("outline: list files", t0);
    let brief = !full && targets.len() > 1;
    let t1 = std::time::Instant::now();
    let g = if brief { Some(import_graph(root)) } else { None };
    trace("outline: import graph", t1);
    let t2 = std::time::Instant::now();
    for abs in targets {
        let rel = root.rel(&abs);
        match parse_file(root, &abs) {
            Ok(prog) if brief => files.push(brief_entry(root, &abs, &prog, g.as_ref().unwrap())),
            Ok(prog) => {
                let syms: Vec<Value> = symbols_of(&prog).iter().map(Sym::to_json).collect();
                let imports: Vec<Value> = imports_of(&prog)
                    .into_iter()
                    .map(|(p, a, l)| json!({"path": p, "alias": a, "line": l}))
                    .collect();
                files.push(json!({
                    "file": rel,
                    "intent": intent_of(&prog),
                    "requires": requires_of(&prog),
                    "imports": imports,
                    "symbols": syms,
                    "parse_error": Value::Null,
                }));
            }
            Err(d) => files.push(json!({
                "file": rel,
                "intent": Value::Null,
                "requires": [],
                "imports": [],
                "symbols": [],
                "parse_error": {"line": d.line, "column": d.column, "message": d.message},
            })),
        }
    }
    trace("outline: entries", t2);
    json!({"files": files, "brief": brief})
}

/// Resuelve `m.f` desde el archivo que importa `m`.
fn resolve_alias(root: &Root, from_abs: &Path, prog: &Program, alias: &str) -> Option<PathBuf> {
    let (path, _, _) = imports_of(prog).into_iter().find(|(_, a, _)| a == alias)?;
    resolve_import(root, from_abs, &path)
}

/// Path canónico de un `use "<path>"` visto desde `from_abs`.
fn resolve_import(root: &Root, from_abs: &Path, path: &str) -> Option<PathBuf> {
    let base = from_abs.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let _ = root;
    let p = PathBuf::from(crate::templates::resolve_module_path(path, &base).ok()?);
    Some(canon(&p))
}

/// Path canónico sin el prefijo verbatim de Windows (`\?\C:\…` → `C:\…`), para que
/// `strip_prefix(root)` funcione y las rutas de salida queden legibles.
pub fn canon(p: &Path) -> PathBuf {
    thread_local! {
        static CANON: RefCell<HashMap<PathBuf, PathBuf>> = RefCell::new(HashMap::new());
    }
    if let Some(c) = CANON.with(|m| m.borrow().get(p).cloned()) {
        return c;
    }
    let out = canon_uncached(p);
    CANON.with(|m| m.borrow_mut().insert(p.to_path_buf(), out.clone()));
    out
}

fn canon_uncached(p: &Path) -> PathBuf {
    let c = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let s = c.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC") => PathBuf::from(rest),
        _ => c,
    }
}

/// Grafo de imports del proyecto: `imports[f]` = (módulo canónico, alias); `importers[m]` = archivos que lo importan.
struct ImportGraph {
    imports: HashMap<PathBuf, Vec<(PathBuf, String)>>,
    importers: HashMap<PathBuf, Vec<PathBuf>>,
}

thread_local! {
    /// Grafo de imports memoizado por root, con la firma (archivos, mtimes) que lo produjo:
    /// dentro de una invocación se calcula una vez; en el proceso MCP se recalcula sólo si
    /// algún `.syn` cambió, apareció o desapareció.
    static GRAPH: RefCell<Option<(PathBuf, Vec<(PathBuf, Option<std::time::SystemTime>)>, Rc<ImportGraph>)>> = RefCell::new(None);
}

fn import_graph(root: &Root) -> Rc<ImportGraph> {
    let files = syn_files(root, None);
    let sig: Vec<(PathBuf, Option<std::time::SystemTime>)> =
        files.iter().map(|f| (f.clone(), std::fs::metadata(f).ok().and_then(|m| m.modified().ok()))).collect();
    if let Some(g) = GRAPH.with(|c| c.borrow().as_ref().and_then(|(r, s, g)| if *r == root.dir && *s == sig { Some(g.clone()) } else { None })) {
        return g;
    }
    let g = Rc::new(build_import_graph(root, &files));
    GRAPH.with(|c| *c.borrow_mut() = Some((root.dir.clone(), sig, g.clone())));
    g
}

fn build_import_graph(root: &Root, files: &[PathBuf]) -> ImportGraph {
    let t0 = std::time::Instant::now();
    let mut g = ImportGraph { imports: HashMap::new(), importers: HashMap::new() };
    for abs in files.iter().cloned() {
        let tp = std::time::Instant::now();
        let Ok(prog) = parse_file(root, &abs) else { continue };
        trace(&format!("graph: parse {}", root.rel(&abs)), tp);
        let me = canon(&abs);
        let mut list = Vec::new();
        for (path, alias, _) in imports_of(&prog) {
            if let Some(m) = resolve_import(root, &abs, &path) {
                g.importers.entry(m.clone()).or_default().push(me.clone());
                list.push((m, alias));
            }
        }
        g.imports.insert(me, list);
    }
    for v in g.importers.values_mut() {
        v.sort();
        v.dedup();
    }
    trace("graph: total", t0);
    g
}

/// Todos los archivos que importan `m`, directa o transitivamente (orden estable).
fn importers_transitive(g: &ImportGraph, m: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<PathBuf> = g.importers.get(m).cloned().unwrap_or_default();
    while let Some(f) = stack.pop() {
        if out.contains(&f) {
            continue;
        }
        out.push(f.clone());
        if let Some(more) = g.importers.get(&f) {
            stack.extend(more.iter().cloned());
        }
    }
    out.sort();
    out
}

/// `StaticProgram` con los módulos `use` resueltos a través de la cache de parseo
/// (el `load` de route_meta lee y parsea cada módulo de nuevo en cada llamada).
fn load_static(root: &Root, abs: &Path, main: Program) -> StaticProgram {
    let mut modules = HashMap::new();
    for (path, alias, _) in imports_of(&main) {
        if let Some(m) = resolve_import(root, abs, &path) {
            if let Ok(p) = parse_file(root, &m) {
                modules.insert(alias, p);
            }
        }
    }
    StaticProgram { main, modules }
}

fn top_requires(prog: &Program) -> Vec<(String, Option<String>)> {
    prog.statements
        .iter()
        .filter_map(|s| match &s.kind {
            NodeKind::RequireStatement { capability, scope } => Some(require_pair(capability, scope)),
            _ => None,
        })
        .collect()
}

/// `outline` compacto de un archivo: intent, contadores por tipo, nombres (acotados).
fn brief_entry(root: &Root, abs: &Path, prog: &Program, g: &ImportGraph) -> Value {
    let syms = symbols_of(prog);
    let mut counts = serde_json::Map::new();
    for k in ["task", "agent", "type", "enum", "let", "serve", "route", "routes", "test", "invariant"] {
        let n = syms.iter().filter(|s| s.kind == k).count();
        if n > 0 {
            counts.insert(k.to_string(), json!(n));
        }
    }
    let names = |kind: &str, max: usize| -> Value {
        let all: Vec<&str> = syms.iter().filter(|s| s.kind == kind).map(|s| s.name.as_str()).collect();
        let mut v: Vec<Value> = all.iter().take(max).map(|n| json!(n)).collect();
        if all.len() > max {
            v.push(json!(format!("+{} more", all.len() - max)));
        }
        Value::Array(v)
    };
    let me = canon(abs);
    json!({
        "file": root.rel(abs),
        "intent": intent_of(prog),
        "lines": std::fs::read_to_string(abs).map(|t| t.lines().count()).unwrap_or(0),
        "requires": top_requires(prog).len(),
        "imports": imports_of(prog).into_iter().map(|(_, a, _)| a).collect::<Vec<_>>(),
        "imported_by": g.importers.get(&me).map(|v| v.iter().map(|p| root.rel(p)).collect::<Vec<_>>()).unwrap_or_default(),
        "symbols": Value::Object(counts),
        "tasks": names("task", 40),
        "agents": names("agent", 20),
        "routes": names("route", 40),
        "parse_error": Value::Null,
    })
}

/// `symbol(name, path?)`: definiciones de `name` (o `alias.name`).
pub fn symbol(root: &Root, name: &str, path: Option<&str>) -> Value {
    let mut defs = Vec::new();
    let (alias, bare) = match name.split_once('.') {
        Some((a, b)) => (Some(a.to_string()), b.to_string()),
        None => (None, name.to_string()),
    };
    for abs in syn_files(root, path) {
        let Ok(prog) = parse_file(root, &abs) else { continue };
        let targets: Vec<(PathBuf, Program)> = match &alias {
            Some(a) => match resolve_alias(root, &abs, &prog, a) {
                Some(p) => match parse_file(root, &p) {
                    Ok(mp) => vec![(p, mp)],
                    Err(_) => vec![],
                },
                None => vec![],
            },
            None => vec![(abs.clone(), prog)],
        };
        for (file, p) in targets {
            let rel = root.rel(&file);
            for s in symbols_of(&p) {
                if s.name == bare || (s.kind == "route" && s.name.eq_ignore_ascii_case(&bare)) {
                    let mut j = s.to_json();
                    if let Value::Object(m) = &mut j {
                        m.insert("file".into(), json!(rel));
                    }
                    defs.push(j);
                }
            }
        }
    }
    dedup_sorted(&mut defs);
    json!({"name": name, "definitions": defs})
}

fn dedup_sorted(v: &mut Vec<Value>) {
    v.sort_by(|a, b| {
        let fa = a.get("file").and_then(Value::as_str).unwrap_or("");
        let fb = b.get("file").and_then(Value::as_str).unwrap_or("");
        let la = a.get("line").and_then(Value::as_u64).unwrap_or(0);
        let lb = b.get("line").and_then(Value::as_u64).unwrap_or(0);
        (fa, la).cmp(&(fb, lb))
    });
    v.dedup();
}

/// `refs(name, path?)`: usos de `name` en todo el proyecto — `call`/`identifier`/`spawn`
/// locales, y `module_call`/`module_ref` desde cualquier archivo que importe el módulo que
/// lo define, con el alias que ese archivo use. `alias.name` fija el módulo por el alias.
pub fn refs(root: &Root, name: &str, path: Option<&str>) -> Value {
    let mut out = Vec::new();
    let (alias, bare) = match name.split_once('.') {
        Some((a, b)) => (Some(a.to_string()), b.to_string()),
        None => (None, name.to_string()),
    };
    let g = import_graph(root);
    // Archivos que DEFINEN el símbolo (tasks/agents/types/lets exportables).
    let mut def_files: Vec<PathBuf> = Vec::new();
    match &alias {
        Some(a) => {
            for abs in syn_files(root, None) {
                let Ok(prog) = parse_file(root, &abs) else { continue };
                if let Some(m) = resolve_alias(root, &abs, &prog, a) {
                    if !def_files.contains(&m) {
                        def_files.push(m);
                    }
                }
            }
        }
        None => {
            for abs in syn_files(root, None) {
                let Ok(prog) = parse_file(root, &abs) else { continue };
                if symbols_of(&prog).iter().any(|s| s.name == bare && s.kind != "route") {
                    def_files.push(canon(&abs));
                }
            }
        }
    }
    for abs in syn_files(root, path) {
        let Ok(prog) = parse_file(root, &abs) else { continue };
        let rel = root.rel(&abs);
        let me = canon(&abs);
        let syms = symbols_of(&prog);
        // Alias con los que ESTE archivo importa alguno de los módulos que definen el símbolo.
        let my_aliases: Vec<String> = g
            .imports
            .get(&me)
            .map(|v| v.iter().filter(|(m, _)| def_files.contains(m)).map(|(_, a)| a.clone()).collect())
            .unwrap_or_default();
        // Usos locales (sin alias): sólo si la consulta no fijó un alias. Si el símbolo se
        // define en otro archivo y éste no lo importa, un identificador local con el mismo
        // nombre es otra cosa — se omite salvo que el archivo lo defina él mismo.
        let local_ok = def_files.contains(&me) || (alias.is_none() && def_files.is_empty());
        let def_lines: BTreeSet<usize> =
            syms.iter().filter(|s| s.name == bare && s.kind != "route").map(|s| s.line).collect();
        // Posición del callee de cada TaskCall: no se cuenta dos veces (call + identifier/ref).
        let mut callee_pos: BTreeSet<(usize, usize)> = BTreeSet::new();
        for stmt in &prog.statements {
            walk(stmt, &mut |n| {
                if let NodeKind::TaskCall { name: callee, .. } = &n.kind {
                    callee_pos.insert((callee.location.line, callee.location.column));
                }
            });
        }
        let is_alias = |node: &Node| -> bool {
            matches!(&node.kind, NodeKind::Identifier { name: o } if my_aliases.contains(o))
        };
        for stmt in &prog.statements {
            walk(stmt, &mut |n| {
                if matches!(n.kind, NodeKind::Identifier { .. } | NodeKind::PropertyAccess { .. })
                    && callee_pos.contains(&(n.location.line, n.location.column))
                {
                    return;
                }
                let (kind, hit) = match &n.kind {
                    NodeKind::TaskCall { name: callee, .. } => match &callee.kind {
                        NodeKind::Identifier { name: id } => ("call", local_ok && *id == bare),
                        NodeKind::PropertyAccess { object, property_name, .. } => {
                            ("module_call", is_alias(object) && *property_name == bare)
                        }
                        _ => ("call", false),
                    },
                    NodeKind::Identifier { name: id } => ("identifier", local_ok && *id == bare),
                    NodeKind::SpawnStatement { agent_name, .. } => ("spawn", local_ok && *agent_name == bare),
                    NodeKind::PropertyAccess { object, property_name, .. } => {
                        ("module_ref", is_alias(object) && *property_name == bare)
                    }
                    _ => ("", false),
                };
                if hit && !(kind == "identifier" && def_lines.contains(&n.location.line)) {
                    out.push(json!({
                        "file": rel,
                        "line": n.location.line,
                        "column": n.location.column,
                        "kind": kind,
                        "in": enclosing(&syms, n.location.line),
                    }));
                }
            });
        }
    }
    dedup_sorted(&mut out);
    let count = out.len();
    let defined_in: Vec<String> = def_files.iter().map(|p| root.rel(p)).collect();
    json!({"name": name, "defined_in": defined_in, "references": out, "count": count})
}

fn response_name(k: &Option<ResponseKind>) -> Value {
    match k {
        Some(ResponseKind::Json) => json!("json"),
        Some(ResponseKind::Html) => json!("html"),
        Some(ResponseKind::Content) => json!("content"),
        Some(ResponseKind::Stream) => json!("stream"),
        Some(ResponseKind::Socket) => json!("socket"),
        Some(ResponseKind::Redirect) => json!("redirect"),
        Some(_) => json!("unknown"),
        None => Value::Null,
    }
}

/// Inferencia del tipo de respuesta cuando `route_meta` no lo sabe: sigue el último `give`
/// a través de tasks del programa, desenvuelve `with_header`/`set_cookie`, y reconoce texto
/// (`join`, `text`, `format`, literal + …) y valores ligados por `let` en el cuerpo.
/// No toca `route_meta::response_kind` (lo que publica `/openapi.json` no cambia).
fn infer_response(body: &[Node], lookup: &dyn Fn(&str) -> Option<route_meta::TaskSrc>, depth: usize) -> Option<&'static str> {
    if depth > 6 {
        return None;
    }
    // Todos los `give` del cuerpo, también dentro de try/when/each (el último de nivel
    // superior no alcanza en handlers reales). `give fail(...)` es un error HTTP, no la
    // respuesta. Si todos coinciden → ese tipo; si difieren → no se inventa.
    let mut kinds: Vec<Option<&'static str>> = Vec::new();
    for stmt in body {
        walk(stmt, &mut |n| {
            if let NodeKind::GiveStatement { value } = &n.kind {
                match value.as_deref() {
                    None => kinds.push(Some("json")),
                    Some(v) => {
                        let is_fail = matches!(&v.kind, NodeKind::TaskCall { name, .. } if callee_name(name).as_deref() == Some("fail"));
                        if !is_fail {
                            kinds.push(infer_value(v, body, lookup, depth));
                        }
                    }
                }
            }
        });
    }
    let mut known: Vec<&'static str> = kinds.iter().filter_map(|k| *k).collect();
    known.sort();
    known.dedup();
    match known.as_slice() {
        [one] if kinds.iter().all(|k| k.is_some()) => Some(one),
        [one] => Some(one), // algunos gives no inferibles + uno solo conocido: se informa el conocido
        _ => None,
    }
}

fn infer_value(value: &Node, body: &[Node], lookup: &dyn Fn(&str) -> Option<route_meta::TaskSrc>, depth: usize) -> Option<&'static str> {
    if depth > 6 {
        return None;
    }
    match &value.kind {
        NodeKind::TaskCall { name, arguments } => {
            let callee = callee_name(name)?;
            match callee.as_str() {
                "content" => Some("content"),
                "html" | "render" | "page" => Some("html"),
                "redirect" => Some("redirect"),
                "with_header" | "set_cookie" => {
                    arguments.iter().find(|a| a.name.is_none()).and_then(|a| infer_value(&a.value, body, lookup, depth + 1))
                }
                "join" | "text" | "format" | "upper" | "lower" | "trim" | "replace" | "repeat" | "csv_encode" | "markdown" => Some("text"),
                "respond" | "raw" | "binary" => None,
                n if builtin_cap(n).is_some() => Some("json"),
                _ => lookup(&callee).and_then(|src| infer_response(&src.body, lookup, depth + 1)),
            }
        }
        NodeKind::MapLiteral { .. } | NodeKind::ListLiteral { .. } | NodeKind::NumberLiteral { .. } | NodeKind::BoolLiteral { .. } => Some("json"),
        NodeKind::TextLiteral { .. } => Some("text"),
        NodeKind::BinaryOp { left, operator, .. } if operator == "+" => {
            match infer_value(left, body, lookup, depth + 1) {
                Some("text") => Some("text"),
                other => other,
            }
        }
        NodeKind::Identifier { name } => {
            // `let x be <expr>` en el mismo cuerpo (la última ligadura antes del give).
            let bound = body.iter().rev().find_map(|s| match &s.kind {
                NodeKind::LetBinding { name: n, value, .. } if n == name => Some(value.as_ref()),
                _ => None,
            })?;
            infer_value(bound, body, lookup, depth + 1)
        }
        _ => None,
    }
}

fn caps_json(caps: &[(String, Option<String>)]) -> Vec<Value> {
    caps.iter().map(|(c, s)| json!({"cap": c, "scope": s})).collect()
}

fn api_route_json(r: &ApiRoute, file: &str, line: Option<usize>, host: Option<&str>, inferred: Option<&'static str>) -> Value {
    json!({
        "method": r.method,
        "path": r.path,
        "file": file,
        "line": line,
        "host": host,
        "auth": r.requires_auth,
        "stream": r.streaming,
        "socket": r.socket,
        "proxy": r.proxy,
        "rate_limit": r.rate_limit.map(|(c, w)| json!({"count": c, "window_seconds": w})),
        "rate_unlimited": r.rate_unlimited,
        "expect": r.meta.expect_shape.as_ref().map(|f| f.iter().map(|(n, t)| json!({"field": n, "type": t})).collect::<Vec<_>>()),
        "response": if r.proxy { json!("proxy") } else {
            match response_name(&r.meta.response_kind) {
                Value::String(k) if k != "unknown" => json!(k),
                _ => inferred.map(|k| json!(k)).unwrap_or_else(|| json!("unknown")),
            }
        },
        "capabilities": caps_json(&r.meta.capabilities),
    })
}

/// `routes(path?)`: la tabla HTTP estática de cada archivo con `serve`.
pub fn routes(root: &Root, path: Option<&str>) -> Value {
    let mut servers = Vec::new();
    for abs in syn_files(root, path) {
        let Ok(prog) = parse_file(root, &abs) else { continue };
        let rel = root.rel(&abs);
        let has_serve = prog.statements.iter().any(|s| matches!(s.kind, NodeKind::ServeBlock { .. }));
        if !has_serve {
            continue;
        }
        // Líneas por (method, path) en orden de aparición (host default y vhosts).
        let mut lines: Vec<(String, String, usize, Vec<Node>)> = Vec::new();
        let mut host_routes: Vec<(String, Vec<Node>)> = Vec::new();
        let mut serve_line = 0;
        for s in &prog.statements {
            if let NodeKind::ServeBlock { routes: rs, hosts, .. } = &s.kind {
                serve_line = s.location.line;
                for r in rs {
                    if let NodeKind::RouteDefinition { method, path, body, .. } = &r.kind {
                        lines.push((method.clone(), path.clone(), r.location.line, body.clone()));
                    }
                }
                for h in hosts {
                    if let NodeKind::HostBlock { pattern, routes: hr, .. } = &h.kind {
                        host_routes.push((text_lit(Some(pattern)).unwrap_or_else(|| "?".into()), hr.clone()));
                    }
                }
                break;
            }
        }
        let sp = load_static(root, &abs, prog);
        let (info, api) = match api_routes_static(&sp) {
            Ok(Some(x)) => x,
            Ok(None) => continue,
            Err(e) => {
                servers.push(json!({"file": rel, "line": serve_line, "error": e, "routes": []}));
                continue;
            }
        };
        let lookup = sp.lookup();
        let mut used: Vec<bool> = vec![false; lines.len()];
        let mut rs: Vec<Value> = Vec::new();
        for r in &api {
            let mut line = None;
            let mut inferred = None;
            for (i, (m, p, l, body)) in lines.iter().enumerate() {
                if !used[i] && *m == r.method && *p == r.path {
                    used[i] = true;
                    line = Some(*l);
                    inferred = infer_response(body, &lookup, 0);
                    break;
                }
            }
            rs.push(api_route_json(r, &rel, line, None, inferred));
        }
        // vhosts: meta por ruta con el mismo lookup estático.
        for (host, hr) in &host_routes {
            for r in hr {
                if let NodeKind::RouteDefinition { method, path, param_names, requires_auth, streaming, socket, body, rate_limit, .. } = &r.kind {
                    let proxy = body.len() == 1 && matches!(body[0].kind, NodeKind::ProxyStatement { .. });
                    let ar = ApiRoute {
                        method: method.clone(),
                        path: path.clone(),
                        param_names: param_names.clone(),
                        requires_auth: *requires_auth,
                        streaming: *streaming,
                        socket: *socket,
                        rate_limit: rate_limit.as_deref().and_then(rate_of),
                        rate_unlimited: matches!(rate_limit.as_deref().map(|n| &n.kind), Some(NodeKind::RateLimitClause { unlimited: true, .. })),
                        proxy,
                        meta: route_meta::route_meta(body, *streaming, &lookup),
                    };
                    let inferred = infer_response(body, &lookup, 0);
                    rs.push(api_route_json(&ar, &rel, Some(r.location.line), Some(host), inferred));
                }
            }
        }
        servers.push(json!({
            "file": rel,
            "line": serve_line,
            "intent": info.intent,
            "describe": info.describe_about,
            "domain": info.domain,
            "private": info.private,
            "docs_off": info.docs_off,
            "has_auth_handler": info.has_auth_handler,
            "hosts": host_routes.iter().map(|(h, _)| h.clone()).collect::<Vec<_>>(),
            "routes": rs,
        }));
    }
    json!({"servers": servers})
}

fn rate_of(n: &Node) -> Option<(i64, f64)> {
    if let NodeKind::RateLimitClause { count, window, unlimited } = &n.kind {
        if *unlimited {
            return None;
        }
        let c = match count.as_deref().map(|c| &c.kind) {
            Some(NodeKind::NumberLiteral { value }) => value.to_f64() as i64,
            _ => return None,
        };
        let w = match window.as_str() {
            "second" => 1.0,
            "minute" => 60.0,
            "hour" => 3600.0,
            "day" => 86400.0,
            _ => return None,
        };
        return Some((c, w));
    }
    None
}

/// ¿`declared` cubre la capability necesaria `(cap, scope)`?
fn covered(declared: &[(String, Option<String>)], cap: &str, scope: &Option<String>) -> bool {
    declared.iter().any(|(dc, ds)| {
        // `require file(...)` cubre `file.read`/`file.write` (como el runtime: File ⊇ FileRead/FileWrite).
        let same = dc == cap || (dc == "file" && cap.starts_with("file."));
        if !same {
            return false;
        }
        match (ds, scope) {
            (None, _) => true,          // `require net` sin scope cubre todo
            (Some(_), None) => true,     // scope dinámico/desconocido: el tipo declarado alcanza (sin falsos positivos)
            (Some(d), Some(s)) => d == "*" || d == s || s.starts_with(&format!("{}/", d)) || s.ends_with(&format!(".{}", d.trim_start_matches("*."))) && d.starts_with("*."),
        }
    })
}

/// `caps(path?)`: contrato de capabilities por archivo (declaradas, necesarias, faltantes).
pub fn caps(root: &Root, path: Option<&str>) -> Value {
    let mut files = Vec::new();
    let g = import_graph(root);
    SCOPED_MEMO.with(|m| m.borrow_mut().clear());
    for abs in syn_files(root, path) {
        let Ok(prog) = parse_file(root, &abs) else { continue };
        let rel = root.rel(&abs);
        let own = top_requires(&prog);
        // Un módulo (`use`d por otros) corre con las capabilities del programa que lo importa:
        // su contrato efectivo es el propio ∪ el de todos sus importadores (transitivo).
        let importers = importers_transitive(&g, &canon(&abs));
        let mut declared = own.clone();
        let mut inherited_from: Vec<String> = Vec::new();
        for imp in &importers {
            if let Ok(ip) = parse_file(root, imp) {
                let theirs = top_requires(&ip);
                if !theirs.is_empty() {
                    inherited_from.push(root.rel(imp));
                }
                for c in theirs {
                    if !declared.contains(&c) {
                        declared.push(c);
                    }
                }
            }
        }
        let tf = std::time::Instant::now();
        let sp = load_static(root, &abs, prog);
        let lookup = sp.lookup();
        trace(&format!("caps: lookup {}", rel), tf);
        let tf = std::time::Instant::now();
        SCOPED_MEMO.with(|m| m.borrow_mut().clear()); // el lookup cambia por archivo
        let params_of = task_params(&sp);
        let base_ctx = ScopeCtx { consts: top_consts(&sp.main), params: HashMap::new() };
        // Un cuerpo de task top-level también recibe los literales que le pasan sus llamadores
        // en el mismo archivo: sitios de llamada de todo el programa, recolectados una vez.
        let main_sites = call_sites(&sp.main.statements);
        let mut needed: Vec<Value> = Vec::new();
        let mut missing: Vec<(String, Option<String>, String, usize)> = Vec::new();
        let mut consider = |label: String, line: usize, body: &[Node]| {
            let ctx = match label.strip_prefix("task ") {
                Some(tname) => ScopeCtx {
                    consts: base_ctx.consts.clone(),
                    params: main_sites.get(tname).map(|sites| params_from_sites(sites, &params_of.get(tname).cloned().unwrap_or_default(), &base_ctx)).unwrap_or_default(),
                },
                None => base_ctx.clone(),
            };
            // Una sola pasada transitiva (memoizada por task): capabilities sin scope (llm, db,
            // time, …) y con scope resuelto (net/file/exec) — `fetch("https://api.x.com/…")` en
            // una task llamada tres niveles abajo sigue diciendo `net("api.x.com")`.
            let mut caps: Vec<(String, Option<String>)> = Vec::new();
            caps_transitive(body, &lookup, &params_of, &ctx, &mut Vec::new(), &mut caps);
            caps.sort();
            caps.dedup();
            // Las capabilities de un cuerpo incluyen sus propios `require` internos (tasks
            // con `require`): esos ya están cubiertos por definición.
            let own: Vec<(String, Option<String>)> = body
                .iter()
                .filter_map(|s| match &s.kind {
                    NodeKind::RequireStatement { capability, scope } => Some(require_pair(capability, scope)),
                    _ => None,
                })
                .collect();
            if !caps.is_empty() {
                needed.push(json!({"symbol": label, "line": line, "capabilities": caps_json(&caps)}));
            }
            for (c, s) in caps {
                if !covered(&declared, &c, &s) && !covered(&own, &c, &s) {
                    missing.push((c, s, label.clone(), line));
                }
            }
        };
        let mut top: Vec<Node> = Vec::new();
        for s in &sp.main.statements {
            let inner = match &s.kind {
                NodeKind::ExportDeclaration { declaration } => declaration.as_ref(),
                _ => s,
            };
            match &inner.kind {
                NodeKind::TaskDefinition { name, body, .. } => consider(format!("task {}", name), s.location.line, body),
                NodeKind::AgentDefinition { name, body, .. } => consider(format!("agent {}", name), s.location.line, body),
                NodeKind::TestBlock { name, body } => consider(format!("test {}", name), s.location.line, body),
                NodeKind::ServeBlock { routes, hosts, .. } => {
                    for r in routes {
                        if let NodeKind::RouteDefinition { method, path, body, .. } = &r.kind {
                            consider(format!("route {} {}", method, path), r.location.line, body);
                        }
                    }
                    for h in hosts {
                        if let NodeKind::HostBlock { routes: hr, .. } = &h.kind {
                            for r in hr {
                                if let NodeKind::RouteDefinition { method, path, body, .. } = &r.kind {
                                    consider(format!("route {} {}", method, path), r.location.line, body);
                                }
                            }
                        }
                    }
                }
                NodeKind::RequireStatement { .. } => {}
                _ => top.push(s.clone()),
            }
        }
        if !top.is_empty() {
            consider("top-level".to_string(), top[0].location.line, &top);
        }
        // Agrupar missing por (cap, scope).
        let mut grouped: Vec<Value> = Vec::new();
        missing.sort();
        let mut i = 0;
        while i < missing.len() {
            let (c, s, _, _) = missing[i].clone();
            let mut by: Vec<Value> = Vec::new();
            while i < missing.len() && missing[i].0 == c && missing[i].1 == s {
                by.push(json!({"symbol": missing[i].2, "line": missing[i].3}));
                i += 1;
            }
            let hint = match &s {
                Some(sc) => format!("add `require {}(\"{}\")`", c, sc),
                None => format!("add `require {}` (or `require {}(\"<scope>\")` for the exact scope)", c, c),
            };
            // `time`/`llm`/`stdout` se auto-conceden bajo `synsema run` (ergonomía); bajo
            // `serve` y `--secure` hay que declararlas. Se marcan para no gritar en vano.
            let ambient = matches!(c.as_str(), "time" | "llm" | "stdout");
            grouped.push(json!({"cap": c, "scope": s, "needed_by": by, "hint": hint, "ambient": ambient}));
        }
        trace(&format!("caps: analyze {}", rel), tf);
        files.push(json!({
            "file": rel,
            "declared": caps_json(&own),
            "inherited_from": inherited_from,
            "effective": caps_json(&declared),
            "needed": needed,
            "missing": grouped,
        }));
    }
    json!({"files": files})
}

/// `check(path?)`: parse + imports + templates sobre uno o todos los `.syn`, en JSON.
pub fn check(root: &Root, path: Option<&str>) -> Value {
    let mut errors: Vec<Value> = Vec::new();
    let mut warnings: Vec<Value> = Vec::new();
    let files = syn_files(root, path);
    let g = import_graph(root);
    for abs in &files {
        let rel = root.rel(abs);
        match parse_file(root, abs) {
            Err(d) => errors.push(d.to_json()),
            // Un módulo importado se valida (imports + templates) desde su importador —
            // repetirlo por módulo es trabajo redundante en un proyecto grande.
            Ok(_) if g.importers.get(&canon(abs)).map(|v| !v.is_empty()).unwrap_or(false) => {}
            Ok(prog) => {
                let loader = |resolved: &str, raw: &str| -> Result<Program, String> {
                    if !Path::new(resolved).exists() {
                        return Err(format!("module not found: {}", raw));
                    }
                    parse_file(root, Path::new(resolved)).map_err(|d| format!("{}:{}:{}: {}", d.file, d.line, d.column, d.message))
                };
                if let Err(e) = crate::templates::check_program_static_with(&prog, abs.to_string_lossy().as_ref(), &loader) {
                    let line = regex::Regex::new(r":(\d+)(?::\d+)?")
                        .ok()
                        .and_then(|re| re.captures(&e).and_then(|c| c.get(1)).and_then(|m| m.as_str().parse::<usize>().ok()))
                        .unwrap_or(0);
                    errors.push(json!({"file": rel, "line": line, "column": 0, "message": e}));
                }
            }
        }
    }
    // Warnings: capabilities faltantes (el runtime las va a negar).
    if let Some(fs) = caps(root, path).get("files").and_then(Value::as_array) {
        for f in fs {
            let file = f["file"].as_str().unwrap_or("");
            if let Some(ms) = f["missing"].as_array() {
                for m in ms {
                    let first_line = m["needed_by"].as_array().and_then(|a| a.first()).and_then(|x| x["line"].as_u64()).unwrap_or(0);
                    let mut who: Vec<String> = m["needed_by"].as_array().map(|a| a.iter().filter_map(|x| x["symbol"].as_str().map(String::from)).collect()).unwrap_or_default();
                    if who.len() > 3 {
                        let extra = who.len() - 3;
                        who.truncate(3);
                        who.push(format!("+{} more", extra));
                    }
                    let ambient = m["ambient"] == json!(true);
                    warnings.push(json!({
                        "file": file,
                        "line": first_line,
                        "column": 0,
                        "message": format!("{} needs capability `{}`{} but the program never requires it{} — {}",
                            who.join(", "),
                            m["cap"].as_str().unwrap_or(""),
                            m["scope"].as_str().map(|s| format!("(\"{}\")", s)).unwrap_or_default(),
                            if ambient { " (granted automatically under `synsema run`; required under `serve` and `--secure`)" } else { "" },
                            m["hint"].as_str().unwrap_or("")),
                    }));
                }
            }
        }
    }
    dedup_sorted(&mut errors);
    dedup_sorted(&mut warnings);
    json!({"ok": errors.is_empty(), "files": files.len(), "errors": errors, "warnings": warnings})
}

/// `search(pattern, path?, kinds?, regex?, limit?)`: texto en los archivos del proyecto.
pub fn search(root: &Root, pattern: &str, path: Option<&str>, kinds: Option<&[&str]>, use_regex: bool, limit: usize) -> Value {
    let kinds = kinds.unwrap_or(DEFAULT_SEARCH_KINDS);
    let re = if use_regex {
        match regex::RegexBuilder::new(pattern).case_insensitive(true).build() {
            Ok(r) => Some(r),
            Err(e) => return json!({"error": format!("invalid regex: {}", e), "matches": [], "count": 0, "truncated": false}),
        }
    } else {
        None
    };
    let needle = pattern.to_lowercase();
    let mut matches: Vec<Value> = Vec::new();
    let mut truncated = false;
    'files: for abs in project_files(root, path, kinds) {
        if std::fs::metadata(&abs).map(|m| m.len() > MAX_SEARCH_FILE).unwrap_or(true) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&abs) else { continue };
        if bytes.contains(&0) {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        let rel = root.rel(&abs);
        let is_syn = matches!(ext_of(&abs).as_str(), "syn" | "fsyn");
        let syms = if is_syn { parse_file(root, &abs).map(|p| symbols_of(&p)).unwrap_or_default() } else { Vec::new() };
        for (i, line) in text.lines().enumerate() {
            let col = match &re {
                Some(r) => r.find(line).map(|m| m.start()),
                None => line.to_lowercase().find(&needle),
            };
            if let Some(c) = col {
                if matches.len() >= limit {
                    truncated = true;
                    break 'files;
                }
                let shown: String = line.chars().take(200).collect();
                matches.push(json!({
                    "file": rel,
                    "line": i + 1,
                    "column": c + 1,
                    "text": shown.trim_end(),
                    "in": if is_syn { json!(enclosing(&syms, i + 1)) } else { Value::Null },
                }));
            }
        }
    }
    let count = matches.len();
    json!({"pattern": pattern, "matches": matches, "count": count, "truncated": truncated})
}

/// `deps(path?)`: grafo task → tasks llamadas por archivo + imports.
pub fn deps(root: &Root, path: Option<&str>) -> Value {
    let mut files = Vec::new();
    let g = import_graph(root);
    for abs in syn_files(root, path) {
        let Ok(prog) = parse_file(root, &abs) else { continue };
        let graph = get_dependency_graph(&prog);
        let mut tasks = serde_json::Map::new();
        for (k, v) in graph {
            // Sólo tasks del programa (los builtins no son dependencias del grafo).
            let user: Vec<String> = v.into_iter().filter(|c| builtin_cap(c).is_none()).collect();
            tasks.insert(k, json!(user));
        }
        files.push(json!({
            "file": root.rel(&abs),
            "tasks": Value::Object(tasks),
            "imports": imports_of(&prog).into_iter().map(|(p, a, _)| json!({"path": p, "alias": a})).collect::<Vec<_>>(),
            "imported_by": g.importers.get(&canon(&abs)).map(|v| v.iter().map(|p| root.rel(p)).collect::<Vec<_>>()).unwrap_or_default(),
        }));
    }
    json!({"files": files})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(files: &[(&str, &str)]) -> Root {
        let dir = std::env::temp_dir().join(format!(
            "syn_codeintel_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, content) in files {
            let p = dir.join(name);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(p, content).unwrap();
        }
        Root::new(dir)
    }

    const APP: &str = r#"intent: "orders api"
require serve(8080)
require net("api.example.com")

type Order
    id: number
    total: number

let config be {"x": 1}

task price(o)
    give o["total"] * 2

task notify()
    let r be fetch("https://api.example.com/x")
    log "sent"

agent writer
    log "writing"
    share 1 as "done"

serve on 8080
    auth with check_token
    route "GET /orders/:id"
        give price({"total": 1})
    route "POST /orders" requires auth
        expect body { total: number }
        give notify()
    host "docs.example"
        route "GET /"
            give "hi"

test "prices double"
    assert_eq(price({"total": 2}), 4)

task check_token(req)
    give {"ok": true}
"#;

    #[test]
    fn outline_lists_symbols_with_ranges() {
        let root = tmp_root(&[("app.syn", APP)]);
        let o = outline(&root, None, true);
        let f = &o["files"][0];
        assert_eq!(f["file"], "app.syn");
        assert_eq!(f["intent"], "orders api");
        assert_eq!(f["requires"].as_array().unwrap().len(), 2);
        let syms = f["symbols"].as_array().unwrap();
        let kinds: Vec<&str> = syms.iter().map(|s| s["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, vec!["type", "let", "task", "task", "agent", "serve", "route", "route", "route", "test", "task"]);
        let price = syms.iter().find(|s| s["name"] == "price").unwrap();
        assert_eq!(price["line"], 11);
        assert_eq!(price["end_line"], 12);
        assert_eq!(price["params"], json!(["o"]));
        let notify = syms.iter().find(|s| s["name"] == "notify").unwrap();
        assert_eq!(notify["calls"], json!(["fetch"]));
        let serve = syms.iter().find(|s| s["kind"] == "serve").unwrap();
        assert_eq!(serve["auth_with"], "check_token");
        assert_eq!(serve["static"], json!([]));
        let host_route = syms.iter().find(|s| s["name"] == "GET /").unwrap();
        assert_eq!(host_route["host"], "docs.example");
        let post = syms.iter().find(|s| s["name"] == "POST /orders").unwrap();
        assert_eq!(post["auth"], true);
        assert!(f["parse_error"].is_null());
    }

    #[test]
    fn refs_find_calls_identifiers_and_skip_definition() {
        let root = tmp_root(&[("app.syn", APP)]);
        let r = refs(&root, "price", None);
        let refs = r["references"].as_array().unwrap();
        assert_eq!(r["count"], 2, "{:?}", refs);
        assert!(refs.iter().all(|x| x["line"] != 11));
        assert!(refs.iter().any(|x| x["in"] == "route GET /orders/:id" && x["kind"] == "call"));
        assert!(refs.iter().any(|x| x["in"] == "test prices double"));
    }

    #[test]
    fn routes_are_static_with_lines_and_hosts() {
        let root = tmp_root(&[("app.syn", APP)]);
        let r = routes(&root, None);
        let s = &r["servers"][0];
        let rs = s["routes"].as_array().unwrap();
        assert_eq!(rs.len(), 3, "{}", r);
        let post = rs.iter().find(|x| x["path"] == "/orders").unwrap();
        assert_eq!(post["auth"], true);
        assert_eq!(post["line"], 26);
        assert_eq!(post["expect"][0]["field"], "total");
        assert!(post["capabilities"].as_array().unwrap().iter().any(|c| c["cap"] == "net"));
        let home = rs.iter().find(|x| x["host"] == "docs.example").unwrap();
        assert_eq!(home["path"], "/");
        assert_eq!(s["hosts"], json!(["docs.example"]));
    }

    #[test]
    fn caps_report_missing_with_hint() {
        let root = tmp_root(&[("bad.syn", "task go()\n    let r be fetch(\"https://a.b/x\")\n    log \"x\"\ngo()\n")]);
        let c = caps(&root, None);
        let f = &c["files"][0];
        let missing = f["missing"].as_array().unwrap();
        assert!(missing.iter().any(|m| m["cap"] == "net"), "{}", c);
        let net = missing.iter().find(|m| m["cap"] == "net").unwrap();
        assert!(net["hint"].as_str().unwrap().contains("require net"));
        assert!(net["needed_by"].as_array().unwrap().iter().any(|x| x["symbol"] == "task go"));
        // Declarado → sin missing.
        let ok = tmp_root(&[("ok.syn", "require net(\"a.b\")\ntask go()\n    let r be fetch(\"https://a.b/x\")\n    log \"x\"\n")]);
        let c2 = caps(&ok, None);
        assert_eq!(c2["files"][0]["missing"].as_array().unwrap().len(), 0, "{}", c2);
        let any = tmp_root(&[("ok.syn", "require net\ntask go()\n    let r be fetch(\"https://a.b/x\")\n    log \"x\"\n")]);
        assert_eq!(caps(&any, None)["files"][0]["missing"].as_array().unwrap().len(), 0);
        // Scope literal: declara a.b pero llama a c.d → missing CON el host y el hint exacto.
        let wrong = tmp_root(&[("w.syn", "require net(\"a.b\")\ntask go()\n    let r be fetch(\"https://c.d:8443/x?q=1\")\n    log \"x\"\n")]);
        let c3 = caps(&wrong, None);
        let m = &c3["files"][0]["missing"][0];
        assert_eq!(m["cap"], "net");
        assert_eq!(m["scope"], "c.d");
        assert_eq!(m["hint"], "add `require net(\"c.d\")`");
        // Wildcard de subdominio y path de archivo bajo el prefijo declarado.
        let wild = tmp_root(&[("x.syn", "require net(\"*.c.d\")\nrequire file(\"data\")\ntask go()\n    let r be fetch(\"https://api.c.d/x\")\n    write_file(\"data/out.txt\", \"1\")\n")]);
        assert_eq!(caps(&wild, None)["files"][0]["missing"].as_array().unwrap().len(), 0, "{}", caps(&wild, None));
    }

    #[test]
    fn check_reports_parse_errors_and_warnings() {
        let root = tmp_root(&[("a.syn", "task ok()\n    give 1\n"), ("b.syn", "task broken(\n"), ("c.syn", "task go()\n    let r be fetch(\"https://a.b/x\")\n    log \"x\"\n")]);
        let c = check(&root, None);
        assert_eq!(c["ok"], false);
        assert_eq!(c["files"], 3);
        let errs = c["errors"].as_array().unwrap();
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0]["file"], "b.syn");
        assert!(errs[0]["line"].as_u64().unwrap() >= 1);
        let warns = c["warnings"].as_array().unwrap();
        assert!(warns.iter().any(|w| w["file"] == "c.syn" && w["message"].as_str().unwrap().contains("`net`")), "{}", c);
        // Un archivo roto no rompe el outline de los demás.
        let o = outline(&root, None, true);
        assert!(o["files"][1]["parse_error"].is_object());
        assert_eq!(o["files"][0]["symbols"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn search_literal_and_regex_with_enclosing_symbol() {
        let root = tmp_root(&[("app.syn", APP), ("web/index.html", "<h1>Orders</h1>\n"), ("node_modules/x.js", "orders\n")]);
        let s = search(&root, "orders", None, None, false, 100);
        let ms = s["matches"].as_array().unwrap();
        assert!(ms.iter().any(|m| m["file"] == "web/index.html"));
        assert!(ms.iter().all(|m| m["file"] != "node_modules/x.js"));
        assert!(ms.iter().any(|m| m["file"] == "app.syn" && m["in"] == "route GET /orders/:id"));
        let r = search(&root, r#"route "(GET|POST)"#, None, Some(&["syn"][..]), true, 1);
        assert_eq!(r["count"], 1);
        assert_eq!(r["truncated"], true);
        assert!(search(&root, "(", None, None, true, 10)["error"].is_string());
    }

    #[test]
    fn modules_inherit_caps_and_refs_cross_aliases() {
        let root = tmp_root(&[
            ("app.syn", "require net(\"api.x\")\nuse \"./lib/http.syn\" as h\nlet r be h.get(\"/a\")\nprint(h.get(\"/b\"))\n"),
            ("other.syn", "use \"./lib/http.syn\" as client\nlet z be client.get(\"/z\")\n"),
            ("lib/http.syn", "export task get(p)\n    give fetch(\"https://api.x\" + p)\ntask twice(p)\n    give get(p)\n"),
            ("loose.syn", "task get()\n    give 1\nlet q be get()\n"),
        ]);
        // El módulo no declara nada, pero app.syn (que lo importa) declara net("api.x") → sin missing.
        let c = caps(&root, Some("lib/http.syn"));
        let f = &c["files"][0];
        assert_eq!(f["inherited_from"], json!(["app.syn"]), "{}", c);
        assert_eq!(f["missing"].as_array().unwrap().len(), 0, "{}", c);
        // refs por alias y bare cruzan archivos con el alias de cada importador.
        let r = refs(&root, "h.get", None);
        let kinds: Vec<(String, String)> = r["references"].as_array().unwrap().iter().map(|x| (x["file"].as_str().unwrap().to_string(), x["kind"].as_str().unwrap().to_string())).collect();
        assert!(kinds.contains(&("app.syn".into(), "module_call".into())), "{:?}", kinds);
        assert!(kinds.contains(&("other.syn".into(), "module_call".into())), "{:?}", kinds);
        assert!(kinds.contains(&("lib/http.syn".into(), "call".into())), "{:?}", kinds);
        assert_eq!(r["count"], 4, "{}", r);
        // `get` a secas: loose.syn define SU propio get → se cuenta el suyo, no se mezcla.
        let r2 = refs(&root, "get", None);
        assert!(r2["references"].as_array().unwrap().iter().any(|x| x["file"] == "loose.syn"));
        assert_eq!(r2["defined_in"], json!(["lib/http.syn", "loose.syn"]));
        // outline compacto del proyecto: contadores + imported_by.
        let o = outline(&root, None, false);
        assert_eq!(o["brief"], true);
        let lib = o["files"].as_array().unwrap().iter().find(|f| f["file"] == "lib/http.syn").unwrap();
        assert_eq!(lib["imported_by"], json!(["app.syn", "other.syn"]));
        assert_eq!(lib["symbols"]["task"], 2);
        let d = deps(&root, Some("lib/http.syn"));
        assert_eq!(d["files"][0]["imported_by"], json!(["app.syn", "other.syn"]));
    }

    #[test]
    fn scopes_resolve_consts_concat_and_caller_literals() {
        let root = tmp_root(&[("s.syn", "require net(\"a.b\")\nlet base be \"https://api.x.com\"\nlet v2 be base + \"/v2\"\ntask get(url)\n    give fetch(url)\ntask go()\n    let a be fetch(base + \"/users\")\n    let b be get(\"https://c.d/x\")\n    let c be fetch(v2 + \"/items\")\n    let d be run(\"git status\")\n    give a\n")]);
        let c = caps(&root, None);
        let f = &c["files"][0];
        let missing: Vec<(String, String)> = f["missing"].as_array().unwrap().iter().map(|m| (m["cap"].as_str().unwrap().to_string(), m["scope"].as_str().unwrap_or("").to_string())).collect();
        assert!(missing.contains(&("net".into(), "api.x.com".into())), "{}", c);
        assert!(missing.contains(&("net".into(), "c.d".into())), "{}", c);
        assert!(missing.contains(&("exec".into(), "git".into())), "{}", c);
        // Ningún `net` sin scope: todo se resolvió estáticamente.
        assert!(!missing.iter().any(|(cap, sc)| cap == "net" && sc.is_empty()), "{}", c);
        // `task get(url)` sola: su parámetro viene del llamador → net(c.d), no dinámico.
        let get = f["needed"].as_array().unwrap().iter().find(|n| n["symbol"] == "task get").unwrap();
        assert!(get["capabilities"].as_array().unwrap().iter().any(|x| x["cap"] == "net" && x["scope"] == "c.d"), "{}", get);
    }

    #[test]
    fn response_inference_follows_tasks_and_text() {
        let root = tmp_root(&[("r.syn", "require serve(8080)\ntask page_for(x)\n    give render(\"p.html\", {\"x\": x})\ntask lines()\n    let parts be [\"a\", \"b\"]\n    give join(parts, \"\\n\")\nserve on 8080\n    route \"GET /p\"\n        give page_for(1)\n    route \"GET /t\"\n        give lines()\n    route \"GET /h\"\n        give with_header(page_for(2), \"X-A\", \"1\")\n    route \"GET /l\"\n        let out be \"hi \" + text(1)\n        give out\n")]);
        let r = routes(&root, None);
        let rs = r["servers"][0]["routes"].as_array().unwrap();
        let of = |p: &str| rs.iter().find(|x| x["path"] == p).unwrap()["response"].clone();
        assert_eq!(of("/p"), "html", "{}", r);
        assert_eq!(of("/t"), "text", "{}", r);
        assert_eq!(of("/h"), "html", "{}", r);
        assert_eq!(of("/l"), "text", "{}", r);
        // `give` anidado en try/when (handlers reales): `fail(...)` no cuenta; el resto coincide.
        let nested = tmp_root(&[("n.syn", "require serve(8080)
serve on 8080
    route \"POST /x\"
        when 1 > 2
            give fail(400, \"bad\")
        try
            give {\"ok\": true}
        recover err
            give {\"ok\": false, \"error\": err}
    route \"GET /m\"
        when 1 > 2
            give \"text\"
        give {\"a\": 1}
")]);
        let r2 = routes(&nested, None);
        let rs2 = r2["servers"][0]["routes"].as_array().unwrap();
        assert_eq!(rs2.iter().find(|x| x["path"] == "/x").unwrap()["response"], "json", "{}", r2);
        assert_eq!(rs2.iter().find(|x| x["path"] == "/m").unwrap()["response"], "json", "el último give de nivel superior manda (contrato de route_meta): {}", r2);
    }

    #[test]
    fn symbol_and_deps_and_flat() {
        let root = tmp_root(&[("app.syn", APP), ("flat.fsyn", "task hi():\n    log \"hi\".\n")]);
        let d = symbol(&root, "notify", None);
        assert_eq!(d["definitions"][0]["line"], 14);
        let g = deps(&root, Some("app.syn"));
        assert_eq!(g["files"][0]["tasks"]["notify"], json!([]));
        let o = outline(&root, Some("flat.fsyn"), false);
        assert_eq!(o["files"][0]["symbols"][0]["name"], "hi");
    }
}

//! Metadatos ESTÁTICOS de una ruta HTTP, derivados del AST sin ejecutar nada
//! (tanda discovery — `specs/discovery-openapi.md`).
//!
//! Tres preguntas que un `/openapi.json` necesita contestar por operación y que el
//! server no conocía hasta ahora:
//!
//! 1. ¿Qué body acepta? — el primer `expect body {…}` de NIVEL SUPERIOR del cuerpo
//!    (uno dentro de `when` no cuenta: no es un contrato, es una rama).
//! 2. ¿Qué devuelve? — best-effort a partir del último `give` de nivel superior:
//!    `content()` (negociado), `html()`/`render()` (HTML), `redirect()`, o JSON.
//! 3. ¿Qué PUEDE tocar? — la unión de las capabilities que el contrato declara:
//!    los `require` de las tasks que la ruta invoca (transitivo, con ciclos) más las
//!    que implican los builtins llamados directamente (`fetch` → `net`, `sql` →
//!    `db`, …). Es estático y honesto: dice lo que la ruta puede hacer según su
//!    contrato, no lo que hizo.
//!
//! La misma extracción sirve al server en vivo (`serve on`, con el entorno ya
//! evaluado — `env_lookup`) y a la CLI `synsema openapi` (sin arrancar nada —
//! `static_lookup` + `api_routes_static`).

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

use crate::ast::{Node, NodeKind, Program};
use crate::ast_api::walk;
use crate::interpreter::{env_get, Environment};
use crate::types::SynValue;

/// Qué devuelve una ruta, inferido del último `give` de nivel superior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseKind {
    /// Un valor de datos (map/list/texto) → `application/json`.
    Json,
    /// `html(...)` / `render(...)` / `page(...)` → `text/html`.
    Html,
    /// `content(...)` → negociado: HTML, Markdown o JSON según `Accept`.
    Content,
    /// Ruta `stream` → `text/event-stream`.
    Stream,
    /// Ruta `socket` → `101 Switching Protocols` (WebSocket entrante).
    Socket,
    /// `redirect(...)` → 3xx sin body.
    Redirect,
    /// No se pudo inferir (sin `give`, o un `give` de una variable/task).
    Unknown,
}

/// Lo que `/openapi.json` sabe de una ruta además de método/path/auth/rate.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RouteMeta {
    /// `expect body { campo: tipo, … }` de nivel superior (campo, tipo).
    pub expect_shape: Option<Vec<(String, String)>>,
    pub response_kind: Option<ResponseKind>,
    /// Capabilities (nombre, scope) que la ruta puede ejercer, ordenadas y sin duplicados.
    pub capabilities: Vec<(String, Option<String>)>,
}

/// Una ruta "seca" (sin handler): lo que la CLI extrae del AST y lo que el server
/// deriva de su tabla. `synsema_stdlib::discovery` emite OpenAPI/sitemap desde esto.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiRoute {
    pub method: String,
    pub path: String,
    pub param_names: Vec<String>,
    pub requires_auth: bool,
    pub streaming: bool,
    /// Ruta `socket` (WebSocket entrante).
    pub socket: bool,
    /// `(count, window_seconds)` efectivo, o `None` si no hay límite.
    pub rate_limit: Option<(i64, f64)>,
    /// `rate_limit unlimited` explícito (distinto de "sin límite declarado").
    pub rate_unlimited: bool,
    /// `proxy to <url>`: la ruta forwardea; no entra al sitemap.
    pub proxy: bool,
    pub meta: RouteMeta,
}

/// Lo que la CLI puede saber del serve block sin ejecutarlo.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServeInfoStatic {
    pub intent: Option<String>,
    pub describe_about: Option<String>,
    pub describe_api: Vec<String>,
    pub describe_version: Option<String>,
    pub domain: Option<String>,
    pub private: bool,
    pub docs_off: bool,
    pub has_auth_handler: bool,
}

/// Fuente de una task para el cierre transitivo: su cuerpo y sus `require`.
pub struct TaskSrc {
    pub body: Vec<Node>,
    pub requires: Vec<(String, Option<String>)>,
}

/// Tabla builtin → capability que implica. Es la misma verdad que cada builtin
/// hace cumplir en runtime con `caps.check(...)` (http_common.rs, database.rs,
/// secure.rs, secrets.rs, blockchain*.rs, engine.rs), reunida en un solo lugar
/// para poder mirarla sin ejecutar. Un builtin ausente acá simplemente no aporta
/// capability al contrato estático (la ruta sigue gateada en runtime igual).
pub const BUILTIN_CAPS: &[(&str, &str)] = &[
    // red
    ("fetch", "net"), ("http", "net"), ("http_get", "net"), ("http_post", "net"),
    ("http_put", "net"), ("http_delete", "net"), ("mtls_identity", "net"),
    ("ws_connect", "net"),
    ("eth_rpc", "net"), ("eth_call", "net"), ("eth_send_raw", "net"), ("solana_rpc", "net"),
    ("algod", "net"), ("esplora", "net"),
    // bases de datos
    ("db_open", "db"), ("db_close", "db"), ("sql", "db"), ("sql_exec", "db"),
    ("sql_tables", "db"), ("sql_batch", "db"), ("paged", "db"),
    ("mongo_find", "db"), ("mongo_find_one", "db"), ("mongo_insert", "db"),
    ("mongo_insert_many", "db"), ("mongo_update", "db"), ("mongo_delete", "db"),
    ("mongo_count", "db"), ("mongo_aggregate", "db"), ("mongo_collections", "db"),
    ("redis_get", "db"), ("redis_set", "db"), ("redis_del", "db"), ("redis_exists", "db"),
    ("redis_expire", "db"), ("redis_ttl", "db"), ("redis_persist", "db"), ("redis_type", "db"),
    ("redis_keys", "db"), ("redis_incr", "db"), ("redis_incrby", "db"), ("redis_decr", "db"),
    ("redis_mget", "db"), ("redis_mset", "db"), ("redis_hget", "db"), ("redis_hset", "db"),
    ("redis_hdel", "db"), ("redis_hgetall", "db"), ("redis_hincrby", "db"),
    ("redis_lpush", "db"), ("redis_rpush", "db"), ("redis_lpop", "db"), ("redis_rpop", "db"),
    ("redis_lrange", "db"), ("redis_llen", "db"), ("redis_sadd", "db"), ("redis_srem", "db"),
    ("redis_smembers", "db"), ("redis_sismember", "db"), ("redis_lock", "db"),
    ("redis_unlock", "db"),
    // archivos y procesos
    ("read_file", "file.read"), ("read_file_bytes", "file.read"), ("list_dir", "file.read"),
    ("file_info", "file.read"), ("file_exists", "file.read"), ("grep", "file.read"),
    ("watch", "file.read"),
    ("term_open", "stdin"),
    ("write_file", "file.write"), ("edit_file", "file.write"), ("append_file", "file.write"),
    ("run", "exec"), ("proc_spawn", "exec"),
    // tiempo y azar
    ("now", "time"), ("sleep", "time"), ("format_time", "time"), ("parse_time", "time"),
    ("date_parts", "time"),
    ("random", "random"), ("random_int", "random"), ("random_bytes", "random"),
    ("token", "random"),
    // llm (las expresiones reason/decide/analyze/generate se detectan por nodo)
    ("llm_step", "llm"),
    // entorno y secretos
    ("env", "env"), ("secret", "secret"), ("reveal", "reveal"),
    // memoria persistente del agente
    ("remember", "memory"), ("recall", "memory"), ("memory_summary", "memory"),
    ("add_rule", "memory"), ("check_rules", "memory"), ("get_rules", "memory"),
    // valor: firmar, custodiar, gastar
    ("secp256k1_sign", "sign"), ("ed25519_sign", "sign"), ("schnorr_sign", "sign"),
    ("tx_eip1559", "sign"), ("tx_eip1559_raw", "sign"), ("solana_tx", "sign"),
    ("algorand_tx", "sign"), ("btc_tx", "sign"), ("psbt_finalize", "sign"),
    ("mnemonic_generate", "wallet"), ("mnemonic_to_seed", "wallet"),
    ("mnemonic_from_entropy", "wallet"), ("mnemonic_to_entropy", "wallet"),
    ("hd_derive", "wallet"), ("algorand_mnemonic", "wallet"),
    ("algorand_mnemonic_to_key", "wallet"), ("keystore_import", "wallet"),
    ("keystore_export", "wallet"),
    ("spend", "spend"),
];

pub fn builtin_cap(name: &str) -> Option<&'static str> {
    BUILTIN_CAPS.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
}

/// El primer `expect body {…}` de nivel superior del cuerpo.
pub fn expect_shape(body: &[Node]) -> Option<Vec<(String, String)>> {
    body.iter().find_map(|s| match &s.kind {
        NodeKind::ExpectStatement { shape, .. } => Some(shape.clone()),
        _ => None,
    })
}

/// Clase de respuesta según el último `give` de nivel superior (best-effort).
pub fn response_kind(body: &[Node], streaming: bool) -> Option<ResponseKind> {
    if body.iter().any(|s| matches!(s.kind, NodeKind::SocketBlock { .. })) {
        return Some(ResponseKind::Socket);
    }
    if streaming {
        return Some(ResponseKind::Stream);
    }
    if body.len() == 1 && matches!(body[0].kind, NodeKind::ProxyStatement { .. }) {
        return None;
    }
    let last_give = body.iter().rev().find_map(|s| match &s.kind {
        NodeKind::GiveStatement { value } => Some(value.as_deref()),
        _ => None,
    });
    let value = match last_give {
        Some(Some(v)) => v,
        Some(None) => return Some(ResponseKind::Json),
        None => return None,
    };
    Some(match &value.kind {
        NodeKind::TaskCall { name, .. } => match callee_name(name).as_deref() {
            Some("content") => ResponseKind::Content,
            Some("html") | Some("render") | Some("page") => ResponseKind::Html,
            Some("redirect") => ResponseKind::Redirect,
            Some("respond") | Some("raw") | Some("binary") => ResponseKind::Unknown,
            Some(n) if builtin_cap(n).is_some() => ResponseKind::Json,
            _ => ResponseKind::Unknown,
        },
        NodeKind::MapLiteral { .. }
        | NodeKind::ListLiteral { .. }
        | NodeKind::TextLiteral { .. }
        | NodeKind::NumberLiteral { .. }
        | NodeKind::BoolLiteral { .. } => ResponseKind::Json,
        _ => ResponseKind::Unknown,
    })
}

/// `f` → "f"; `m.f` → "m.f" (un nivel: módulo.task). Otra cosa → None.
pub fn callee_name(name: &Node) -> Option<String> {
    match &name.kind {
        NodeKind::Identifier { name } => Some(name.clone()),
        NodeKind::PropertyAccess { property_name, object, .. } => match &object.kind {
            NodeKind::Identifier { name } => Some(format!("{}.{}", name, property_name)),
            _ => None,
        },
        _ => None,
    }
}

/// Un `require x(scope)` con scope literal → Some(texto); scope no literal → None.
pub fn require_pair(capability: &str, scope: &Option<Box<Node>>) -> (String, Option<String>) {
    let s = scope.as_ref().and_then(|n| match &n.kind {
        NodeKind::TextLiteral { value } => Some(value.clone()),
        NodeKind::NumberLiteral { value } => Some(value.to_string()),
        _ => None,
    });
    (capability.to_string(), s)
}

/// Capabilities que un cuerpo puede ejercer: sus `require` de nivel superior, los
/// builtins que llama (directamente, en cualquier profundidad) y, transitivamente,
/// las tasks que invoca (resueltas por `lookup`). Ciclos y diamantes se visitan una
/// vez. Salida ordenada y deduplicada (determinismo del spec §1.4).
pub fn capabilities(
    body: &[Node],
    lookup: &dyn Fn(&str) -> Option<TaskSrc>,
) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    collect_caps(body, lookup, &mut out, &mut seen);
    out.sort();
    out.dedup();
    out
}

fn collect_caps(
    body: &[Node],
    lookup: &dyn Fn(&str) -> Option<TaskSrc>,
    out: &mut Vec<(String, Option<String>)>,
    seen: &mut Vec<String>,
) {
    let mut calls: Vec<String> = Vec::new();
    for stmt in body {
        if let NodeKind::RequireStatement { capability, scope } = &stmt.kind {
            out.push(require_pair(capability, scope));
        }
        walk(stmt, &mut |n: &Node| match &n.kind {
            NodeKind::TaskCall { name, .. } => {
                if let Some(c) = callee_name(name) {
                    if !calls.contains(&c) {
                        calls.push(c);
                    }
                }
            }
            NodeKind::ReasonExpression { .. }
            | NodeKind::DecideExpression { .. }
            | NodeKind::AnalyzeExpression { .. }
            | NodeKind::GenerateExpression { .. } => out.push(("llm".to_string(), None)),
            _ => {}
        });
    }
    for c in calls {
        if let Some(cap) = builtin_cap(&c) {
            out.push((cap.to_string(), None));
            continue;
        }
        if seen.contains(&c) {
            continue;
        }
        seen.push(c.clone());
        if let Some(src) = lookup(&c) {
            out.extend(src.requires.iter().cloned());
            collect_caps(&src.body, lookup, out, seen);
        }
    }
}

/// Los tres metadatos de una ruta de una vez.
pub fn route_meta(
    body: &[Node],
    streaming: bool,
    lookup: &dyn Fn(&str) -> Option<TaskSrc>,
) -> RouteMeta {
    RouteMeta {
        expect_shape: expect_shape(body),
        response_kind: response_kind(body, streaming),
        capabilities: capabilities(body, lookup),
    }
}

// ---- lookup en vivo (serve): el entorno ya evaluado ----

/// Resuelve `f` o `m.f` contra el entorno del serve block: una task de usuario
/// (con sus `require` ya extraídos por el intérprete) o un task dentro de un
/// módulo importado. Los builtins no se resuelven acá (los cubre la tabla).
pub fn env_lookup(env: &Rc<RefCell<Environment>>) -> impl Fn(&str) -> Option<TaskSrc> + '_ {
    move |name: &str| {
        let value = match name.split_once('.') {
            Some((module, member)) => match env_get(env, module)? {
                SynValue::Map(m) => m.borrow().get(member).cloned()?,
                _ => return None,
            },
            None => env_get(env, name)?,
        };
        match value {
            SynValue::Task(t) => Some(TaskSrc {
                body: t.body.clone(),
                requires: t.required_capabilities.clone(),
            }),
            _ => None,
        }
    }
}

// ---- lookup estático (CLI): sólo el AST, sin ejecutar ----

/// Tasks definidas en un programa (top-level o exportadas): nombre → fuente.
fn task_table(program: &Program) -> HashMap<String, TaskSrc> {
    let mut out = HashMap::new();
    for stmt in &program.statements {
        let decl = match &stmt.kind {
            NodeKind::ExportDeclaration { declaration } => declaration.as_ref(),
            _ => stmt,
        };
        if let NodeKind::TaskDefinition { name, body, .. } = &decl.kind {
            let requires = body
                .iter()
                .filter_map(|s| match &s.kind {
                    NodeKind::RequireStatement { capability, scope } => Some(require_pair(capability, scope)),
                    _ => None,
                })
                .collect();
            out.insert(name.clone(), TaskSrc { body: body.clone(), requires });
        }
    }
    out
}

/// Programa principal + módulos importados (alias → programa), resueltos como lo
/// hace el runtime (`use "./x.syn" as m`), sin ejecutar nada.
pub struct StaticProgram {
    pub main: Program,
    pub modules: HashMap<String, Program>,
}

impl StaticProgram {
    /// Parsea los `use` del programa (un nivel: los que el serve block puede nombrar).
    pub fn load(main: Program, file_path: &str) -> Result<StaticProgram, String> {
        let base_dir = Path::new(file_path).parent().map(|p| p.to_path_buf()).unwrap_or_default();
        let mut modules = HashMap::new();
        for stmt in &main.statements {
            if let NodeKind::UseImport { path, alias } = &stmt.kind {
                let resolved = crate::templates::resolve_module_path(path, &base_dir)
                    .map_err(|e| format!("{}: {}", file_path, e))?;
                let src = std::fs::read_to_string(&resolved).map_err(|_| format!("module not found: {}", path))?;
                let prog = crate::parser::parse_source(&src, &resolved).map_err(|e| e.to_string())?;
                modules.insert(alias.clone(), prog);
            }
        }
        Ok(StaticProgram { main, modules })
    }

    /// `f` en el principal; `m.f` en el módulo con alias `m`.
    pub fn lookup(&self) -> impl Fn(&str) -> Option<TaskSrc> + '_ {
        let main = task_table(&self.main);
        let mods: HashMap<String, HashMap<String, TaskSrc>> =
            self.modules.iter().map(|(k, p)| (k.clone(), task_table(p))).collect();
        move |name: &str| {
            let src = match name.split_once('.') {
                Some((m, f)) => mods.get(m)?.get(f)?,
                None => main.get(name)?,
            };
            Some(TaskSrc { body: src.body.clone(), requires: src.requires.clone() })
        }
    }
}

fn text_of(node: Option<&Node>) -> Option<String> {
    match node.map(|n| &n.kind) {
        Some(NodeKind::TextLiteral { value }) => Some(value.clone()),
        _ => None,
    }
}

fn window_seconds(window: &str) -> f64 {
    match window {
        "second" => 1.0,
        "hour" => 3600.0,
        _ => 60.0,
    }
}

fn static_rate(clause: Option<&Node>) -> (Option<(i64, f64)>, bool) {
    match clause.map(|c| &c.kind) {
        Some(NodeKind::RateLimitClause { unlimited: true, .. }) => (None, true),
        Some(NodeKind::RateLimitClause { count, window, .. }) => {
            let n = match count.as_deref().map(|c| &c.kind) {
                Some(NodeKind::NumberLiteral { value }) => value.to_i64_trunc().unwrap_or(0),
                _ => 0,
            };
            (Some((n, window_seconds(window))), false)
        }
        _ => (None, false),
    }
}

fn static_route(
    r: &Node,
    prefix: &str,
    block_rate: Option<(i64, f64)>,
    lookup: &dyn Fn(&str) -> Option<TaskSrc>,
) -> Option<ApiRoute> {
    let NodeKind::RouteDefinition { method, path, param_names, requires_auth, streaming, socket, rate_limit, body, .. } = &r.kind
    else {
        return None;
    };
    let (own_rate, unlimited) = static_rate(rate_limit.as_deref());
    let rate = if unlimited { None } else { own_rate.or(block_rate) };
    let full_path = if prefix.is_empty() {
        path.clone()
    } else if path == "/" {
        prefix.to_string()
    } else {
        format!("{}{}", prefix, path)
    };
    Some(ApiRoute {
        method: method.clone(),
        path: full_path,
        param_names: param_names.clone(),
        requires_auth: *requires_auth,
        streaming: *streaming,
        socket: *socket,
        rate_limit: rate,
        rate_unlimited: unlimited,
        proxy: body.len() == 1 && matches!(body[0].kind, NodeKind::ProxyStatement { .. }),
        meta: route_meta(body, *streaming, lookup),
    })
}

/// Las rutas del host default del primer `serve` del programa, sin ejecutarlo:
/// rutas declaradas + `mount m.grupo [at "/prefijo"]` resueltos sintácticamente.
/// Los `host "..."` (vhosts) no entran: publican su propia tabla bajo su Host.
/// Devuelve `Ok(None)` si el programa no tiene `serve`.
pub fn api_routes_static(sp: &StaticProgram) -> Result<Option<(ServeInfoStatic, Vec<ApiRoute>)>, String> {
    let serve = sp.main.statements.iter().find(|s| matches!(s.kind, NodeKind::ServeBlock { .. }));
    let Some(serve) = serve else { return Ok(None) };
    let NodeKind::ServeBlock {
        auth_handler, rate_limit, describe, private, docs_off, routes, domain, mounts, ..
    } = &serve.kind
    else {
        return Ok(None);
    };
    let lookup = sp.lookup();
    let mut info = ServeInfoStatic {
        private: *private,
        docs_off: *docs_off,
        has_auth_handler: auth_handler.is_some(),
        domain: text_of(domain.as_deref()),
        ..Default::default()
    };
    for stmt in &sp.main.statements {
        if let NodeKind::IntentDeclaration { description } = &stmt.kind {
            info.intent = Some(description.clone());
        }
    }
    if let Some(NodeKind::DescribeClause { about, api, version }) = describe.as_deref().map(|d| &d.kind) {
        info.describe_about = text_of(about.as_deref());
        info.describe_version = text_of(version.as_deref());
        if let Some(NodeKind::ListLiteral { elements }) = api.as_deref().map(|a| &a.kind) {
            info.describe_api = elements.iter().filter_map(|e| text_of(Some(e))).collect();
        }
    }
    let (block_rate, _) = static_rate(rate_limit.as_deref());
    let mut out: Vec<ApiRoute> = routes.iter().filter_map(|r| static_route(r, "", block_rate, &lookup)).collect();
    for m in mounts {
        let NodeKind::MountClause { source, prefix } = &m.kind else { continue };
        let (alias, group) = match &source.kind {
            NodeKind::PropertyAccess { property_name, object, .. } => match &object.kind {
                NodeKind::Identifier { name } => (name.clone(), property_name.clone()),
                _ => return Err("mount: the source must be `<module>.<routes group>` to be read statically".into()),
            },
            _ => return Err("mount: the source must be `<module>.<routes group>` to be read statically".into()),
        };
        let prefix_s = match prefix.as_deref() {
            None => String::new(),
            Some(p) => match text_of(Some(p)) {
                Some(s) => s.trim_end_matches('/').to_string(),
                None => return Err("mount: the prefix must be a text literal to be read statically".into()),
            },
        };
        let module = sp.modules.get(&alias).ok_or_else(|| format!("mount: unknown module alias '{}'", alias))?;
        let decl = module.statements.iter().find_map(|s| {
            let d = match &s.kind {
                NodeKind::ExportDeclaration { declaration } => declaration.as_ref(),
                _ => s,
            };
            match &d.kind {
                NodeKind::RoutesDeclaration { name, routes } if *name == group => Some(routes),
                _ => None,
            }
        });
        let group_routes = decl.ok_or_else(|| format!("mount: module '{}' exports no routes group '{}'", alias, group))?;
        // Las tasks que una ruta montada llama viven en SU módulo: `f` ahí es `m.f` acá.
        let mlookup = |name: &str| -> Option<TaskSrc> {
            if name.contains('.') {
                lookup(name)
            } else {
                lookup(&format!("{}.{}", alias, name))
            }
        };
        out.extend(group_routes.iter().filter_map(|r| static_route(r, &prefix_s, block_rate, &mlookup)));
    }
    Ok(Some((info, out)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_source;

    fn prog(src: &str) -> Program {
        parse_source(src, "t.syn").expect("parse")
    }

    #[test]
    fn expect_only_top_level() {
        let p = prog("serve on 8080\n    route \"POST /a\"\n        expect body {name: text, n: number}\n        give {\"ok\": true}\n    route \"POST /b\"\n        when true\n            expect body {x: text}\n        give 1\n");
        let sp = StaticProgram { main: p, modules: HashMap::new() };
        let (_, routes) = api_routes_static(&sp).unwrap().unwrap();
        assert_eq!(routes[0].meta.expect_shape, Some(vec![("name".into(), "text".into()), ("n".into(), "number".into())]));
        assert_eq!(routes[1].meta.expect_shape, None);
        assert_eq!(routes[0].meta.response_kind, Some(ResponseKind::Json));
    }

    #[test]
    fn capabilities_are_transitive_and_deduped() {
        let p = prog("task inner()\n    require db(\"./x.db\")\n    give outer()\ntask outer()\n    require net(\"api.example\")\n    give inner()\nserve on 8080\n    route \"GET /a\"\n        let r be fetch(\"https://x\")\n        give outer()\n    route \"GET /b\"\n        give html(\"<p>hi</p>\")\n");
        let sp = StaticProgram { main: p, modules: HashMap::new() };
        let (_, routes) = api_routes_static(&sp).unwrap().unwrap();
        assert_eq!(
            routes[0].meta.capabilities,
            vec![("db".to_string(), Some("./x.db".to_string())), ("net".to_string(), None), ("net".to_string(), Some("api.example".to_string()))]
        );
        assert!(routes[1].meta.capabilities.is_empty());
        assert_eq!(routes[1].meta.response_kind, Some(ResponseKind::Html));
        assert_eq!(routes[0].meta.response_kind, Some(ResponseKind::Unknown));
    }
}

//! `serve` en modo HANDLER (WASM fase 2, F5): sin sockets — el host entrega un request
//! (método, path, headers, body) y recibe la respuesta. Es lo que necesita un edge
//! runtime (Cloudflare Workers, Fastly Compute, Fermyon Spin, Vercel Edge): cargar el
//! `.wasm` y llamar un handler por request.
//!
//! Reusa el router y el contrato de respuesta PUROS de `synsema_stdlib::routing`
//! (extraídos verbatim de server.rs) y `respond.rs`: match por especificidad, 404/405
//! con `Allow`, negociación de `content()` por sufijo/Accept, `auth with` (bearer o
//! request completo), `errors with`, `expect` → 400, `with_header`/`set_cookie`,
//! `redirect`, paginación de colecciones, el mismo map `request` del handler nativo.
//! `state_*` van al KV del host (namespace `state`) si lo ofrece; la memoria
//! declarada igual (F4).
//!
//! Lo que NO hay en este modo (documentado, y falla diciendo por qué): `stream`/SSE
//! (necesita un socket vivo), `proxy to` (transporte del server), rate limit por IP
//! (no hay proceso que acumule buckets — el edge lo hace antes), `static` mounts (el
//! host sirve sus assets; el mount se avisa y se ignora), vhosts (`host` blocks),
//! TLS/ACME (terminan en el host).
//!
//! El programa se prepara UNA vez por instancia (parse + top-level + captura de la
//! tabla de rutas) y se cachea por (fuente, opciones): el handler se llama muchas
//! veces por isolate; sólo el request cambia.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use indexmap::IndexMap;
use synsema_capabilities::model::{Capability, CapabilitySet, CapabilityType};
use synsema_core::ast::{Node, NodeKind};
use synsema_core::interpreter::{Control, Environment, Interpreter, RuntimeError};
use synsema_core::parser::parse_source;
use synsema_core::types::{syn_int, syn_text, ServerValue, SynValue};
use synsema_stdlib::json::{dumps, obj, Json};
use synsema_stdlib::routing::{
    bearer_token, build_request_syn, build_response, delegated_spend_of, header_value, identity_of,
    negotiate_format, param_last_segment, parse_path_query, path_match, render_content,
    request_bindings, specificity, split_format_suffix, Ctx, GiveOutcome, ResponseBody,
};

use crate::{export_audit, prepare, AuditEntry, RunOptions};

/// Un request tal como lo entrega el host. `path` puede traer `?query`.
pub struct HttpRequestIn {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub client_ip: String,
}

/// La respuesta para el host. `content_type` va también como header en la frontera.
pub struct HttpResponseOut {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub content_type: String,
    pub body: Vec<u8>,
}

pub struct HandleReport {
    pub response: HttpResponseOut,
    /// Líneas de `print` del handler (en nativo van al log de serve).
    pub log: Vec<String>,
    /// Errores de PREPARACIÓN (parse, top-level, serve sin soporte): el response es
    /// entonces un 500 genérico y acá está el porqué.
    pub errors: Vec<String>,
    pub audit: Vec<AuditEntry>,
}

struct RouteEntry {
    method: String,
    path: String,
    requires_auth: bool,
    streaming: bool,
    proxy: bool,
    body: Vec<Node>,
}

struct Captured {
    routes: Vec<RouteEntry>,
    /// Nodo del `auth with` + aridad declarada del task (1 = token, 2 = token + request).
    auth: Option<(Node, usize)>,
    error_handler: Option<Node>,
}

struct App {
    key: String,
    interp: Interpreter,
    caps: Rc<RefCell<CapabilitySet>>,
    captured: Rc<RefCell<Option<Captured>>>,
    /// Caps concedidas al terminar el top-level: cada request arranca de acá (como el
    /// snapshot de caps por worker del serve nativo).
    granted: HashSet<Capability>,
    /// Globales al terminar el top-level (copia PROFUNDA de listas/mapas): cada request
    /// corre sobre este snapshot — un `set` sobre un global dentro de un handler NO
    /// persiste al request siguiente, exactamente como en el serve nativo (serve.md:
    /// "use `state_*` for shared state"). Sin esto el intérprete reusado filtraría
    /// estado entre requests.
    globals: Vec<(String, SynValue)>,
    /// Agentes definidos en el top-level (`reset_for_request` los borra; vuelven de acá).
    agents: HashMap<String, (Vec<Node>, Rc<RefCell<Environment>>)>,
}

/// Copia profunda de los contenedores mutables (List/Map); el resto (números, texto,
/// tasks, secrets, bytes…) es inmutable o Rc compartido de valor inmutable → clone.
/// NO pasa por `to_send`: ese camino redacta los secrets, y un `{"key": secret("X")}`
/// del top-level debe seguir siendo un secret en el request siguiente.
fn deep_clone(v: &SynValue) -> SynValue {
    match v {
        SynValue::List(l) => SynValue::List(Rc::new(RefCell::new(l.borrow().iter().map(deep_clone).collect()))),
        SynValue::Map(m) => {
            let mut out = IndexMap::new();
            for (k, x) in m.borrow().iter() {
                out.insert(k.clone(), deep_clone(x));
            }
            SynValue::Map(Rc::new(RefCell::new(out)))
        }
        other => other.clone(),
    }
}

/// Snapshot de los globales (copia profunda) al terminar el top-level.
fn snapshot_globals(interp: &Interpreter) -> Vec<(String, SynValue)> {
    interp
        .global_env
        .borrow()
        .bindings
        .iter()
        .map(|(k, v)| (k.clone(), deep_clone(v)))
        .collect()
}

/// Vuelve el intérprete al estado post-top-level: estado transitorio (output,
/// blackboard, identidad, agentes de handler), globales al snapshot, y sin los
/// globales que un handler haya creado. Espejo de `with_serve_interp` del nativo.
fn restore_after_request(app: &mut App) {
    app.interp.reset_for_request();
    for (name, (body, env)) in &app.agents {
        app.interp.agent_definitions.insert(name.clone(), (body.clone(), env.clone()));
    }
    let keep: HashSet<&String> = app.globals.iter().map(|(k, _)| k).collect();
    {
        let mut g = app.interp.global_env.borrow_mut();
        let extra: Vec<String> = g.bindings.keys().filter(|k| !keep.contains(k)).cloned().collect();
        for k in extra {
            g.bindings.remove(&k);
        }
    }
    for (k, v) in &app.globals {
        app.interp.set_global(k, deep_clone(v));
    }
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

fn cache_key(source: &str, opts: &RunOptions) -> String {
    let mut env: Vec<String> = opts
        .env
        .as_ref()
        .map(|m| m.iter().map(|(k, v)| format!("{}={}", k, v)).collect())
        .unwrap_or_default();
    env.sort();
    let ceiling: Vec<String> = opts
        .ceiling
        .as_ref()
        .map(|c| c.iter().map(|x| x.to_string()).collect())
        .unwrap_or_default();
    format!("{}\u{0}{}\u{0}{}\u{0}{}", opts.filename, env.join(";"), ceiling.join(","), source)
}

fn json_err(status: u16, msg: &str) -> (u16, ResponseBody) {
    (
        status,
        ResponseBody::Json(obj(vec![
            ("error", Json::Str(msg.to_string())),
            ("status", Json::Int(i64::from(status))),
        ])),
    )
}

/// Prepara (o reusa) la app: parse + wiring + top-level con el serve hook que CAPTURA
/// la tabla en vez de escuchar.
fn prepare_app(source: &str, opts: &RunOptions) -> Result<(), Vec<String>> {
    let key = cache_key(source, opts);
    let reuse = APP.with(|a| a.borrow().as_ref().is_some_and(|app| app.key == key));
    if reuse {
        return Ok(());
    }
    APP.with(|a| *a.borrow_mut() = None);

    let program = match parse_source(source, &opts.filename) {
        Err(e) => return Err(vec![crate::parse_errors(e)]),
        Ok(p) => p,
    };
    let (mut interp, caps) = prepare(&program, opts);
    let captured: Rc<RefCell<Option<Captured>>> = Rc::new(RefCell::new(None));
    let cap_hook = captured.clone();
    let caps_hook = caps.clone();
    interp.set_serve_hook(Rc::new(move |interp: &mut Interpreter, node: &Node, env| {
        let NodeKind::ServeBlock {
            port,
            auth_handler,
            error_handler,
            static_mounts,
            routes,
            hosts,
            mounts,
            ..
        } = &node.kind
        else {
            return Err(crate::rt_err("serve hook: expected a serve block"));
        };
        // `require serve(<puerto>)` se exige IGUAL que en el serve nativo: no hay socket,
        // pero la declaración es el manifiesto ("este programa sirve") — el perfil wasm
        // no relaja el modelo. Mismo mensaje que serve.rs.
        let port_str = match interp.eval(port, env)? {
            SynValue::Number(n) => n.to_i64_trunc().unwrap_or(0).to_string(),
            other => {
                return Err(Control::Error(RuntimeError::new(format!(
                    "serve port must be a number, got {}",
                    other
                ))))
            }
        };
        let cap = Capability::new(CapabilityType::Serve, Some(port_str.clone()));
        if !caps_hook.borrow_mut().check(&cap, &format!("serve on {}", port_str)) {
            return Err(Control::Error(RuntimeError::new(format!(
                "serve on {0} is not permitted: missing capability serve({0}). Add `require serve({0})` at the top of your program.",
                port_str
            ))));
        }
        if !hosts.is_empty() {
            return Err(crate::rt_err(
                "serve: `host` blocks (virtual hosts) are not supported in handler mode — the \
                 edge host routes by hostname before calling the handler; use one table",
            ));
        }
        if !mounts.is_empty() {
            return Err(crate::rt_err(
                "serve: `mount` of exported route groups is not supported in handler mode yet — \
                 declare the routes in the serve block",
            ));
        }
        if !static_mounts.is_empty() {
            synsema_stdlib::hostcap::log(
                "synsema: warning: `static` mounts are ignored in handler mode — the host serves \
                 its own assets; requests to those paths get 404 from the handler",
            );
        }
        let auth = match auth_handler {
            None => None,
            Some(an) => {
                let arity: usize = match interp.eval(an, env) {
                    Ok(SynValue::Task(t)) => t.parameters.len(),
                    _ => 1,
                };
                if arity != 1 && arity != 2 {
                    return Err(crate::rt_err(&format!(
                        "auth task must take 1 (token) or 2 (token, request) parameters, got {}",
                        arity
                    )));
                }
                Some(((**an).clone(), arity))
            }
        };
        let mut table: Vec<RouteEntry> = Vec::new();
        for r in routes {
            if let NodeKind::RouteDefinition { method, path, requires_auth, streaming, body, .. } = &r.kind {
                let proxy = body.len() == 1 && matches!(body[0].kind, NodeKind::ProxyStatement { .. });
                table.push(RouteEntry {
                    method: method.clone(),
                    path: path.clone(),
                    requires_auth: *requires_auth,
                    streaming: *streaming,
                    proxy,
                    body: body.clone(),
                });
            }
        }
        // Orden por especificidad (más específica primero): el primer match gana —
        // idéntico a HostRouter::new.
        table.sort_by_key(|e| specificity(&e.path));
        *cap_hook.borrow_mut() = Some(Captured {
            routes: table,
            auth,
            error_handler: error_handler.as_ref().map(|n| (**n).clone()),
        });
        Ok(SynValue::Nothing)
    }));

    let result = interp.execute(&program);
    let r = crate::finish_keep(&mut interp, result);
    if !r.success {
        let mut errs = r.errors;
        errs.extend(r.output.into_iter().map(|l| format!("[top-level output] {}", l)));
        return Err(errs);
    }
    if captured.borrow().is_none() {
        return Err(vec![
            "handle: the program has no `serve` block — nothing to route the request to".to_string(),
        ]);
    }
    let granted = caps.borrow().granted.clone();
    let globals = snapshot_globals(&interp);
    let agents = interp.agent_definitions.clone();
    APP.with(|a| *a.borrow_mut() = Some(App { key, interp, caps, captured, granted, globals, agents }));
    Ok(())
}

/// `errors with`: la task da forma al BODY del error; el STATUS se conserva (salvo
/// `redirect()`, cuyo 3xx + Location se respetan). `nothing`/error en la task → None
/// (JSON por defecto). Espeja `ServeRuntime::custom_error`.
fn custom_error(
    interp: &mut Interpreter,
    handler: &Node,
    status: u16,
    message: &str,
    ctx: &Ctx,
) -> Option<(u16, ResponseBody, Vec<(String, String)>)> {
    let genv = interp.global_env.clone();
    let task = interp.eval(handler, &genv).ok()?;
    let v = interp
        .call_task(task, vec![syn_int(i64::from(status)), syn_text(message), build_request_syn(ctx)])
        .ok()?;
    if matches!(v, SynValue::Nothing) {
        return None;
    }
    let mut hdrs: Vec<(String, String)> = Vec::new();
    let v = match v {
        SynValue::Server(s) => match &*s {
            ServerValue::WithHeaders { inner, headers } => {
                hdrs = headers.clone();
                (**inner).clone()
            }
            _ => SynValue::Server(s),
        },
        other => other,
    };
    let is_content = matches!(&v, SynValue::Server(s) if matches!(&**s, ServerValue::Content(_)));
    if is_content {
        let fmt = negotiate_format(&header_value(&ctx.headers, "accept"));
        let raw = render_content(&v, &fmt);
        return Some((status, ResponseBody::Raw(raw), hdrs));
    }
    match build_response(Some(&v), &ctx.query) {
        Ok((st, body)) => match body {
            ResponseBody::Redirect { .. } => Some((st, body, hdrs)),
            other => Some((status, other, hdrs)),
        },
        Err(_) => None,
    }
}

fn finalize(status: u16, body: ResponseBody, mut headers: Vec<(String, String)>) -> HttpResponseOut {
    let (content_type, bytes) = match body {
        ResponseBody::Json(j) => ("application/json".to_string(), dumps(&j).into_bytes()),
        ResponseBody::Raw(r) => (r.content_type, r.body),
        ResponseBody::Redirect { location, .. } => {
            headers.push(("Location".to_string(), location));
            ("text/plain; charset=utf-8".to_string(), Vec::new())
        }
    };
    HttpResponseOut { status, headers, content_type, body: bytes }
}

fn dispatch(app: &mut App, req: &HttpRequestIn) -> (HttpResponseOut, Vec<String>) {
    let (path, query) = parse_path_query(&req.path);
    let method = req.method.to_ascii_uppercase();
    let body_str = String::from_utf8_lossy(&req.body).to_string();
    let captured = app.captured.clone();
    let cap = captured.borrow();
    let cap = cap.as_ref().expect("app prepared");

    // Cada request arranca de las caps del top-level (sin lo que un request previo
    // haya concedido o denegado) y sin identidad.
    {
        let mut cs = app.caps.borrow_mut();
        cs.granted = app.granted.clone();
        cs.denied.clear();
    }
    app.interp.output.clear();
    app.interp.set_request_identity(None, Vec::new());

    let mut route_idx: Option<usize> = None;
    let mut params: IndexMap<String, String> = IndexMap::new();
    for (i, r) in cap.routes.iter().enumerate() {
        if r.method != method {
            continue;
        }
        if let Some(p) = path_match(&r.path, &path) {
            route_idx = Some(i);
            params = p;
            break;
        }
    }
    // Negociación por sufijo (.md/.json/.html): sólo si un :param se tragó el sufijo.
    let mut explicit_fmt: Option<String> = None;
    let (logical_path, sfx) = split_format_suffix(&path);
    if let (Some(s), Some(idx)) = (sfx, route_idx) {
        if param_last_segment(&cap.routes[idx].path) {
            for (i, r) in cap.routes.iter().enumerate() {
                if r.method != method {
                    continue;
                }
                if let Some(p) = path_match(&r.path, &logical_path) {
                    route_idx = Some(i);
                    params = p;
                    explicit_fmt = Some(s);
                    break;
                }
            }
        }
    }

    let min_ctx = |params: IndexMap<String, String>, json: Option<serde_json::Value>| Ctx {
        method: method.clone(),
        path: path.clone(),
        query: query.clone(),
        params,
        headers: req.headers.clone(),
        body: body_str.clone(),
        body_raw: req.body.clone(),
        body_file: None,
        json,
        client_ip: req.client_ip.clone(),
        user: None,
        cancel: synsema_core::interpreter::CancelToken::new(),
    };

    let idx = match route_idx {
        Some(i) => i,
        None => {
            let mut allowed: Vec<String> = Vec::new();
            for r in &cap.routes {
                if path_match(&r.path, &path).is_some() && !allowed.contains(&r.method) {
                    allowed.push(r.method.clone());
                }
            }
            allowed.sort();
            let ectx = min_ctx(IndexMap::new(), None);
            if !allowed.is_empty() {
                let allow = ("Allow".to_string(), allowed.join(", "));
                if let Some(h) = &cap.error_handler {
                    if let Some((st, body, mut hdrs)) = custom_error(&mut app.interp, h, 405, "method not allowed", &ectx) {
                        hdrs.push(allow);
                        return (finalize(st, body, hdrs), std::mem::take(&mut app.interp.output));
                    }
                }
                let (st, body) = json_err(405, "method not allowed");
                return (finalize(st, body, vec![allow]), std::mem::take(&mut app.interp.output));
            }
            let msg = format!("no route for {} {}", method, path);
            if let Some(h) = &cap.error_handler {
                if let Some((st, body, hdrs)) = custom_error(&mut app.interp, h, 404, &msg, &ectx) {
                    return (finalize(st, body, hdrs), std::mem::take(&mut app.interp.output));
                }
            }
            let (st, body) = json_err(404, &msg);
            return (finalize(st, body, Vec::new()), std::mem::take(&mut app.interp.output));
        }
    };
    let route = &cap.routes[idx];

    // Parse del body JSON (sólo error si el cliente declaró JSON).
    let mut json_obj: Option<serde_json::Value> = None;
    if !body_str.is_empty() {
        let ctype = header_value(&req.headers, "content-type").to_lowercase();
        match serde_json::from_str::<serde_json::Value>(&body_str) {
            Ok(v) => json_obj = Some(v),
            Err(_) => {
                if ctype.contains("json") {
                    let (st, body) = json_err(400, "malformed JSON body");
                    return (finalize(st, body, Vec::new()), std::mem::take(&mut app.interp.output));
                }
            }
        }
    }
    let mut ctx = min_ctx(params, json_obj);

    // Auth: bearer (o request completo para tasks de 2 parámetros).
    if route.requires_auth {
        let token = bearer_token(&req.headers);
        let user = cap.auth.as_ref().and_then(|(node, arity)| {
            let genv = app.interp.global_env.clone();
            let task = app.interp.eval(node, &genv).ok()?;
            let args = if *arity == 2 {
                vec![syn_text(token.as_str()), build_request_syn(&ctx)]
            } else {
                vec![syn_text(token.as_str())]
            };
            app.interp.call_task(task, args).ok()
        });
        match &user {
            None | Some(SynValue::Nothing) => {
                if let Some(h) = &cap.error_handler {
                    if let Some((st, body, hdrs)) = custom_error(&mut app.interp, h, 401, "unauthorized", &ctx) {
                        return (finalize(st, body, hdrs), std::mem::take(&mut app.interp.output));
                    }
                }
                let (st, body) = json_err(401, "unauthorized");
                return (finalize(st, body, Vec::new()), std::mem::take(&mut app.interp.output));
            }
            Some(_) => ctx.user = user,
        }
    }

    if route.streaming {
        let (st, body) = json_err(501, "stream routes (SSE) are not supported in handler mode — they need a live socket; run this program with the native `synsema serve`");
        return (finalize(st, body, Vec::new()), std::mem::take(&mut app.interp.output));
    }
    if route.proxy {
        let (st, body) = json_err(501, "`proxy to` is not supported in handler mode — forward from the host, or run this program with the native `synsema serve`");
        return (finalize(st, body, Vec::new()), std::mem::take(&mut app.interp.output));
    }

    // Correr el handler (mismo mapeo que run_route + la cola de dispatch).
    let (identity, limits) = match &ctx.user {
        Some(u) => (identity_of(u), delegated_spend_of(u)),
        None => (None, Vec::new()),
    };
    app.interp.set_request_identity(identity, limits);
    let outcome = match app.interp.run_request_block(&route.body, request_bindings(&ctx)) {
        Ok(_) => GiveOutcome::Give(None),
        Err(Control::Give(v)) => GiveOutcome::Give(Some(v)),
        Err(Control::Error(e)) if e.is_validation => {
            GiveOutcome::Validation { message: e.message.clone(), field: e.field.clone() }
        }
        Err(Control::Error(e)) => GiveOutcome::Error(e.to_string()),
        Err(Control::Stop(_)) => GiveOutcome::Error("'give'/'stop' used outside of a task or loop".to_string()),
    };
    app.interp.set_request_identity(None, Vec::new());

    let mut custom_headers: Vec<(String, String)> = Vec::new();
    let shape_500 = |interp: &mut Interpreter, detail: &str, ctx: &Ctx, extra: &mut Vec<(String, String)>| -> (u16, ResponseBody) {
        if let Some(h) = &cap.error_handler {
            if let Some((st, body, hdrs)) = custom_error(interp, h, 500, detail, ctx) {
                extra.extend(hdrs);
                return (st, body);
            }
        }
        json_err(500, detail)
    };
    let (status, body) = match outcome {
        GiveOutcome::Give(v) => {
            let v = match v {
                Some(SynValue::Server(s)) => match &*s {
                    ServerValue::WithHeaders { inner, headers } => {
                        custom_headers = headers.clone();
                        Some((**inner).clone())
                    }
                    _ => Some(SynValue::Server(s)),
                },
                other => other,
            };
            let is_content = matches!(
                v.as_ref(),
                Some(SynValue::Server(s)) if matches!(&**s, ServerValue::Content(_))
            );
            if is_content {
                let fmt = explicit_fmt
                    .clone()
                    .unwrap_or_else(|| negotiate_format(&header_value(&ctx.headers, "accept")));
                let raw = render_content(v.as_ref().unwrap(), &fmt);
                (raw.status, ResponseBody::Raw(raw))
            } else {
                match build_response(v.as_ref(), &ctx.query) {
                    Ok(sb) => sb,
                    Err(e) => shape_500(&mut app.interp, &e, &ctx, &mut custom_headers),
                }
            }
        }
        GiveOutcome::Validation { message, field } => (
            400,
            ResponseBody::Json(obj(vec![
                ("error", Json::Str(message)),
                ("status", Json::Int(400)),
                ("field", field.map(Json::Str).unwrap_or(Json::Null)),
            ])),
        ),
        GiveOutcome::Error(msg) => shape_500(&mut app.interp, &msg, &ctx, &mut custom_headers),
    };
    (finalize(status, body, custom_headers), std::mem::take(&mut app.interp.output))
}

/// Un request → una respuesta. La app se prepara una vez y se cachea por (fuente,
/// opciones). Nunca panica por un error del programa: los errores de preparación van
/// a `errors` con un 500 genérico.
pub fn handle(source: &str, opts: &RunOptions, req: &HttpRequestIn) -> HandleReport {
    if let Err(errors) = prepare_app(source, opts) {
        let (st, body) = json_err(500, "the program could not be prepared (see errors)");
        return HandleReport { response: finalize(st, body, Vec::new()), log: Vec::new(), errors, audit: Vec::new() };
    }
    APP.with(|a| {
        let mut guard = a.borrow_mut();
        let app = guard.as_mut().expect("prepared");
        let (response, log) = dispatch(app, req);
        let audit = export_audit(&app.caps);
        // Aislamiento entre requests (como `with_serve_interp`): el próximo request
        // arranca del estado post-top-level, no del que dejó este handler.
        restore_after_request(app);
        HandleReport { response, log, errors: Vec::new(), audit }
    })
}

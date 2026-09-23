//! Discovery derivado de la tabla de rutas:
//! `/openapi.json`, `/sitemap.xml` y `/docs` (HTML para humanos, Markdown para agentes).
//!
//! Principio: todo sale de lo que el server realmente tiene cableado — `RouteSpec`
//! en vivo o el AST en la CLI (`synsema openapi`), ambos como `ApiRoute`. Lo que no
//! se puede derivar con verdad (schema de respuesta) se omite, no se inventa. La
//! salida es determinista (paths asc, métodos en orden fijo) para ser diffeable y
//! anclable byte a byte.

use synsema_core::route_meta::{ApiRoute, ResponseKind};

use crate::json::{dumps, obj, Json};

/// Lo que `info`/`servers`/`securitySchemes` necesitan saber del serve block.
#[derive(Debug, Clone, Default)]
pub struct ApiInfo {
    pub title: String,
    pub description: Option<String>,
    pub version: String,
    pub base_url: Option<String>,
    /// Alguna ruta pide auth Y hay `auth with` → se anuncian los esquemas.
    pub has_auth: bool,
    pub describe_api: Vec<String>,
}

impl ApiInfo {
    /// La cadena de título que `/llms.txt` y `/.well-known/synsema-auth` ya usan:
    /// `describe about` → `intent` → "Synsema service".
    pub fn title_of(about: Option<&str>, intent: Option<&str>) -> String {
        about.or(intent).unwrap_or("Synsema service").to_string()
    }
}

/// Paths que el runtime reserva y un crawler/OpenAPI no debe listar.
pub const RESERVED_PATHS: &[&str] = &["/llms.txt", "/robots.txt", "/sitemap.xml", "/openapi.json", "/docs"];

fn method_rank(m: &str) -> usize {
    match m {
        "GET" => 0,
        "POST" => 1,
        "PUT" => 2,
        "PATCH" => 3,
        "DELETE" => 4,
        "HEAD" => 5,
        "OPTIONS" => 6,
        _ => 7,
    }
}

/// Orden canónico: path ascendente, método GET/POST/PUT/PATCH/DELETE.
pub fn sorted_routes(routes: &[ApiRoute]) -> Vec<&ApiRoute> {
    let mut v: Vec<&ApiRoute> = routes.iter().collect();
    v.sort_by(|a, b| a.path.cmp(&b.path).then(method_rank(&a.method).cmp(&method_rank(&b.method))).then(a.method.cmp(&b.method)));
    v.dedup_by(|a, b| a.path == b.path && a.method == b.method);
    v
}

/// `/blog/:slug` → `/blog/{slug}`; `/files/*path` → `/files/{path}`.
pub fn openapi_path(path: &str) -> String {
    path.split('/')
        .map(|seg| {
            if let Some(p) = seg.strip_prefix(':').or_else(|| seg.strip_prefix('*')) {
                format!("{{{}}}", p)
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// `GET /blog/:slug` → `get_blog_slug`; `GET /` → `get_root`.
pub fn operation_id(method: &str, path: &str) -> String {
    let mut id = method.to_ascii_lowercase();
    let mut segs: Vec<String> = Vec::new();
    for seg in path.split('/') {
        let s = seg.trim_start_matches(':').trim_start_matches('*');
        if s.is_empty() {
            continue;
        }
        let clean: String = s.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect();
        segs.push(clean);
    }
    if segs.is_empty() {
        id.push_str("_root");
    } else {
        for s in segs {
            id.push('_');
            id.push_str(&s);
        }
    }
    id
}

fn schema_type(t: &str) -> &'static str {
    match t {
        "text" => "string",
        "number" => "number",
        "bool" => "boolean",
        "list" => "array",
        "map" => "object",
        _ => "string",
    }
}

fn s(v: &str) -> Json {
    Json::Str(v.to_string())
}

fn media(ct: &str, schema: Option<Json>) -> (String, Json) {
    let inner = match schema {
        Some(sc) => obj(vec![("schema", sc)]),
        None => Json::Object(Vec::new()),
    };
    (ct.to_string(), inner)
}

fn response(desc: &str, contents: Vec<(String, Json)>) -> Json {
    let mut r = vec![("description", s(desc))];
    if !contents.is_empty() {
        r.push(("content", Json::Object(contents)));
    }
    obj(r)
}

/// `[net:api.stripe.com, llm]` — el sufijo textual de `/llms.txt`; vacío si no hay.
pub fn caps_suffix(route: &ApiRoute) -> String {
    if route.meta.capabilities.is_empty() {
        return String::new();
    }
    let items: Vec<String> = route
        .meta
        .capabilities
        .iter()
        .map(|(n, sc)| match sc {
            Some(sc) => format!("{}:{}", n, sc),
            None => n.clone(),
        })
        .collect();
    format!("  [{}]", items.join(", "))
}

fn caps_json(route: &ApiRoute) -> Json {
    Json::Array(
        route
            .meta
            .capabilities
            .iter()
            .map(|(n, sc)| {
                let mut o = vec![("name", s(n))];
                if let Some(sc) = sc {
                    o.push(("scope", s(sc)));
                }
                obj(o)
            })
            .collect(),
    )
}

/// La entrada de `describe api:` cuyo prefijo es `"GET /path"`, si existe.
fn describe_entry<'a>(info: &'a ApiInfo, method: &str, path: &str) -> Option<&'a str> {
    let key = format!("{} {}", method, path);
    info.describe_api.iter().find_map(|item| {
        let rest = item.strip_prefix(&key)?;
        // Prefijo EXACTO: "GET /" no debe tragarse "GET /books/:id -- …".
        if !(rest.is_empty() || rest.starts_with(char::is_whitespace)) {
            return None;
        }
        let rest = rest.trim_start_matches([' ', '-', '—', ':', '·']).trim();
        Some(if rest.is_empty() { item.as_str() } else { rest })
    })
}

fn operation(info: &ApiInfo, r: &ApiRoute) -> Json {
    let mut op: Vec<(&str, Json)> = vec![("operationId", Json::Str(operation_id(&r.method, &r.path)))];
    if let Some(d) = describe_entry(info, &r.method, &r.path) {
        op.push(("description", s(d)));
    }
    if !r.param_names.is_empty() {
        op.push((
            "parameters",
            Json::Array(
                r.param_names
                    .iter()
                    .map(|p| {
                        obj(vec![
                            ("name", s(p)),
                            ("in", s("path")),
                            ("required", Json::Bool(true)),
                            ("schema", obj(vec![("type", s("string"))])),
                        ])
                    })
                    .collect(),
            ),
        ));
    }
    if let Some(shape) = &r.meta.expect_shape {
        let props: Vec<(String, Json)> =
            shape.iter().map(|(f, t)| (f.clone(), obj(vec![("type", s(schema_type(t)))]))).collect();
        let required: Vec<Json> = shape.iter().map(|(f, _)| s(f)).collect();
        let schema = obj(vec![
            ("type", s("object")),
            ("properties", Json::Object(props)),
            ("required", Json::Array(required)),
        ]);
        op.push((
            "requestBody",
            obj(vec![
                ("required", Json::Bool(true)),
                ("content", Json::Object(vec![media("application/json", Some(schema))])),
            ]),
        ));
    }
    // responses
    let mut responses: Vec<(String, Json)> = Vec::new();
    match r.meta.response_kind {
        Some(ResponseKind::Redirect) => {
            responses.push(("302".into(), response("redirect", Vec::new())));
        }
        Some(ResponseKind::Stream) => {
            responses.push(("200".into(), response("event stream", vec![media("text/event-stream", None)])));
        }
        Some(ResponseKind::Socket) => {
            responses.push(("101".into(), response("WebSocket (Switching Protocols)", Vec::new())));
            responses.push(("426".into(), response("Upgrade Required (the request did not ask for a WebSocket upgrade)", vec![media("application/json", None)])));
        }
        Some(ResponseKind::Html) => {
            responses.push(("200".into(), response("HTML page", vec![media("text/html", None)])));
        }
        Some(ResponseKind::Content) => {
            responses.push((
                "200".into(),
                response(
                    "negotiated by Accept (HTML, Markdown or JSON)",
                    vec![media("text/html", None), media("text/markdown", None), media("application/json", None)],
                ),
            ));
        }
        _ => {
            responses.push(("200".into(), response("OK", vec![media("application/json", None)])));
        }
    }
    if r.meta.expect_shape.is_some() {
        responses.push(("400".into(), response("body does not match `expect body`", vec![media("application/json", None)])));
    }
    if r.requires_auth {
        responses.push(("401".into(), response("authentication required", vec![media("application/json", None)])));
    }
    if r.rate_limit.is_some() {
        responses.push(("429".into(), response("rate limit exceeded", vec![media("application/json", None)])));
    }
    op.push(("responses", Json::Object(responses)));
    if r.requires_auth {
        op.push((
            "security",
            Json::Array(vec![
                obj(vec![("bearer", Json::Array(Vec::new()))]),
                obj(vec![("cookie", Json::Array(Vec::new()))]),
                obj(vec![("httpsig", Json::Array(Vec::new()))]),
            ]),
        ));
    }
    if r.rate_unlimited {
        op.push(("x-synsema-rate-limit", s("unlimited")));
    } else if let Some((count, window)) = r.rate_limit {
        op.push(("x-synsema-rate-limit", obj(vec![("count", Json::Int(count)), ("window", Json::Float(window))])));
    }
    if r.streaming {
        op.push(("x-synsema-streaming", Json::Bool(true)));
    }
    if r.socket {
        op.push(("x-synsema-socket", Json::Bool(true)));
    }
    if r.proxy {
        op.push(("x-synsema-proxy", Json::Bool(true)));
    }
    op.push(("x-synsema-capabilities", caps_json(r)));
    obj(op)
}

/// El documento OpenAPI 3.1 de la tabla.
pub fn openapi_json(info: &ApiInfo, routes: &[ApiRoute]) -> Json {
    let mut info_o = vec![("title", s(&info.title))];
    if let Some(d) = &info.description {
        if *d != info.title {
            info_o.push(("description", s(d)));
        }
    }
    info_o.push(("version", s(&info.version)));
    let mut doc: Vec<(&str, Json)> = vec![("openapi", s("3.1.0")), ("info", obj(info_o))];
    if let Some(b) = &info.base_url {
        doc.push(("servers", Json::Array(vec![obj(vec![("url", s(b))])])));
    }
    let mut paths: Vec<(String, Json)> = Vec::new();
    for r in sorted_routes(routes) {
        if RESERVED_PATHS.contains(&r.path.as_str()) {
            continue;
        }
        let p = openapi_path(&r.path);
        let op = operation(info, r);
        match paths.iter_mut().find(|(k, _)| *k == p) {
            Some((_, Json::Object(ops))) => ops.push((r.method.to_ascii_lowercase(), op)),
            _ => paths.push((p, Json::Object(vec![(r.method.to_ascii_lowercase(), op)]))),
        }
    }
    doc.push(("paths", Json::Object(paths)));
    if info.has_auth {
        doc.push((
            "components",
            obj(vec![(
                "securitySchemes",
                obj(vec![
                    ("bearer", obj(vec![("type", s("http")), ("scheme", s("bearer")), ("description", s("Authorization: Bearer <token> — captoken, JWT or an opaque token the program's `auth with` task accepts"))])),
                    ("cookie", obj(vec![("type", s("apiKey")), ("in", s("cookie")), ("name", s("session")), ("description", s("session cookie — the name is whatever the program's `auth with` task reads"))])),
                    ("httpsig", obj(vec![("type", s("http")), ("scheme", s("Signature")), ("description", s("HTTP Message Signatures (RFC 9421), profile rfc9421-pinned: @method, @target-uri, content-digest; ed25519 or hmac-sha256"))])),
                ]),
            )]),
        ));
    }
    obj(doc)
}

/// Sólo lo que un crawler puede visitar sin contexto: GET, sin parámetros, sin
/// auth, sin stream/proxy, y ningún path reservado. Sin `lastmod`: no hay verdad.
pub fn sitemap_paths(routes: &[ApiRoute]) -> Vec<String> {
    sorted_routes(routes)
        .into_iter()
        .filter(|r| {
            r.method == "GET"
                && r.param_names.is_empty()
                && !r.requires_auth
                && !r.streaming
                && !r.socket
                && !r.proxy
                && !RESERVED_PATHS.contains(&r.path.as_str())
                && !r.path.starts_with("/.well-known/")
        })
        .map(|r| r.path.clone())
        .collect()
}

fn xml_escape(v: &str) -> String {
    v.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn sitemap_xml(base: &str, routes: &[ApiRoute]) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");
    for p in sitemap_paths(routes) {
        out.push_str("  <url><loc>");
        out.push_str(&xml_escape(&format!("{}{}", base.trim_end_matches('/'), p)));
        out.push_str("</loc></url>\n");
    }
    out.push_str("</urlset>\n");
    out
}

/// La referencia textual de `/docs` para un agente (`Accept: text/markdown`).
pub fn docs_markdown(info: &ApiInfo, routes: &[ApiRoute]) -> String {
    let mut out = format!("# {} — API reference\n", info.title);
    if let Some(d) = &info.description {
        if *d != info.title {
            out.push_str(&format!("\n> {}\n", d));
        }
    }
    out.push_str(&format!("\nVersion {}", info.version));
    if let Some(b) = &info.base_url {
        out.push_str(&format!(" · base URL {}", b));
    }
    out.push_str(" · machine-readable: /openapi.json · /llms.txt · /sitemap.xml\n");
    if info.has_auth {
        out.push_str("\nAuthentication (protected operations): `Authorization: Bearer <token>`, a session cookie, or an HTTP Message Signature (RFC 9421). Details: /.well-known/synsema-auth\n");
    }
    let mut any = false;
    for r in sorted_routes(routes) {
        if RESERVED_PATHS.contains(&r.path.as_str()) {
            continue;
        }
        any = true;
        out.push_str(&format!("\n## {} {}\n", r.method, openapi_path(&r.path)));
        if let Some(d) = describe_entry(info, &r.method, &r.path) {
            out.push_str(&format!("\n{}\n", d));
        }
        let mut facts: Vec<String> = Vec::new();
        if r.requires_auth {
            facts.push("requires auth".into());
        }
        if r.rate_unlimited {
            facts.push("rate limit: unlimited".into());
        } else if let Some((c, w)) = r.rate_limit {
            facts.push(format!("rate limit: {} per {}s", c, w));
        }
        if r.streaming {
            facts.push("streams server-sent events".into());
        }
        if r.socket {
            facts.push("WebSocket endpoint (upgrade)".into());
        }
        if r.proxy {
            facts.push("reverse proxy".into());
        }
        let caps = caps_suffix(r);
        if !caps.is_empty() {
            facts.push(format!("capabilities: {}", caps.trim()));
        }
        if !facts.is_empty() {
            out.push_str(&format!("\n- {}\n", facts.join("\n- ")));
        }
        if !r.param_names.is_empty() {
            out.push_str(&format!("\nPath parameters: {}\n", r.param_names.iter().map(|p| format!("`{}`", p)).collect::<Vec<_>>().join(", ")));
        }
        if let Some(shape) = &r.meta.expect_shape {
            out.push_str("\nRequest body (application/json, every field required):\n\n");
            for (f, t) in shape {
                out.push_str(&format!("- `{}`: {}\n", f, t));
            }
        }
        let resp = match r.meta.response_kind {
            Some(ResponseKind::Redirect) => "302 redirect",
            Some(ResponseKind::Stream) => "200 text/event-stream",
            Some(ResponseKind::Socket) => "101 Switching Protocols (WebSocket)",
            Some(ResponseKind::Html) => "200 text/html",
            Some(ResponseKind::Content) => "200 negotiated by Accept: text/html, text/markdown or application/json",
            _ => "200 application/json",
        };
        out.push_str(&format!("\nResponse: {}\n", resp));
    }
    if !any {
        out.push_str("\n_No routes declared._\n");
    }
    out
}

/// La página `/docs`: HTML propio (sin CDN ni scripts de terceros) que lee
/// `/openapi.json` y deja probar cada operación desde el navegador.
pub fn docs_html(info: &ApiInfo) -> String {
    let title = info.title.replace('<', "&lt;").replace('&', "&amp;");
    DOCS_HTML.replace("{{TITLE}}", &title)
}

const DOCS_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}} — API</title>
<style>
:root{--bg:#fbfbf9;--fg:#1c1d1a;--mut:#6b6d63;--line:#e2e1d8;--soft:#f1f0ea;--acc:#25588c;--get:#2c6e49;--post:#8a5a00;--put:#4f5d9c;--del:#9b3b2e;--err:#9b3b2e;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media(prefers-color-scheme:dark){:root{--bg:#141513;--fg:#e8e7df;--mut:#9a9b90;--line:#2c2d28;--soft:#1d1e1b;--acc:#8fb4dc;--get:#7fc59a;--post:#e0b565;--put:#a7b1e8;--del:#e08c7c;--err:#e08c7c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{display:flex;flex-wrap:wrap;gap:12px 20px;align-items:baseline;padding:18px 28px;border-bottom:1px solid var(--line)}
header h1{font-size:1.25rem;margin:0}header .v{color:var(--mut);font-family:var(--mono);font-size:.85rem}header .links{margin-left:auto;font-size:.85rem}header a{color:var(--acc);text-decoration:none;margin-left:12px}
.auth{display:flex;gap:8px;align-items:center;padding:12px 28px;border-bottom:1px solid var(--line);background:var(--soft);font-size:.85rem}
.auth input{flex:1;max-width:520px;font:13px var(--mono);padding:6px 8px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--fg)}
main{max-width:980px;margin:0 auto;padding:22px 28px 60px}
.desc{color:var(--mut);margin:0 0 18px}
details{border:1px solid var(--line);border-radius:6px;margin:10px 0;background:var(--bg)}
summary{display:flex;gap:12px;align-items:center;padding:10px 14px;cursor:pointer;list-style:none}summary::-webkit-details-marker{display:none}
.m{font:600 11px/1 var(--mono);letter-spacing:.06em;padding:5px 8px;border-radius:4px;color:#fff;min-width:58px;text-align:center}
.m.get{background:var(--get)}.m.post{background:var(--post)}.m.put,.m.patch{background:var(--put)}.m.delete{background:var(--del)}
.p{font:14px var(--mono)}.s{color:var(--mut);font-size:.85rem;margin-left:auto;white-space:nowrap}
.body{padding:4px 14px 14px;border-top:1px solid var(--line)}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}.tag{font:11px var(--mono);padding:3px 7px;border:1px solid var(--line);border-radius:999px;color:var(--mut)}.tag.cap{color:var(--fg);border-color:var(--acc)}
label{display:block;font-size:.8rem;color:var(--mut);margin:10px 0 4px}
input.f,textarea{width:100%;font:13px var(--mono);padding:7px 9px;border:1px solid var(--line);border-radius:4px;background:var(--soft);color:var(--fg)}textarea{min-height:110px;resize:vertical}
button{font:600 12px system-ui,sans-serif;letter-spacing:.04em;text-transform:uppercase;padding:8px 14px;border:0;border-radius:4px;background:var(--acc);color:#fff;cursor:pointer;margin-top:12px}
pre{margin:10px 0 0;padding:10px 12px;background:var(--soft);border:1px solid var(--line);border-radius:4px;font:12.5px/1.5 var(--mono);white-space:pre-wrap;overflow:auto;max-height:420px}
.st{font-family:var(--mono);font-size:.85rem;margin-top:12px}.st.ok{color:var(--get)}.st.err{color:var(--err)}
.empty{color:var(--mut)}
</style>
</head>
<body>
<header><h1 id="title">{{TITLE}}</h1><span class="v" id="version"></span>
<span class="links"><a href="/openapi.json">openapi.json</a><a href="/llms.txt">llms.txt</a><a href="/sitemap.xml">sitemap.xml</a></span></header>
<div class="auth" id="auth" hidden><span>Bearer token</span><input id="token" placeholder="sent as Authorization: Bearer … on every Try it (kept in this tab only)"></div>
<main>
<p class="desc" id="desc"></p>
<div id="ops"><p class="empty">loading /openapi.json…</p></div>
</main>
<script>
(async function(){
  const $=(t,a,...c)=>{const e=document.createElement(t);for(const k in a||{})k==='class'?e.className=a[k]:k==='text'?e.textContent=a[k]:e.setAttribute(k,a[k]);e.append(...c);return e;};
  const tok=document.getElementById('token');
  try{tok.value=sessionStorage.getItem('synsema-docs-token')||'';}catch(e){}
  tok.addEventListener('input',()=>{try{sessionStorage.setItem('synsema-docs-token',tok.value);}catch(e){}});
  let spec;
  try{const r=await fetch('/openapi.json');if(!r.ok)throw new Error(r.status+' '+r.statusText);spec=await r.json();}
  catch(e){document.getElementById('ops').innerHTML='<p class="empty">could not load /openapi.json: '+e.message+'</p>';return;}
  document.getElementById('version').textContent='v'+(spec.info&&spec.info.version||'0.0.0');
  if(spec.info&&spec.info.description)document.getElementById('desc').textContent=spec.info.description;
  if(spec.components&&spec.components.securitySchemes)document.getElementById('auth').hidden=false;
  const ops=document.getElementById('ops');ops.textContent='';
  const order=['get','post','put','patch','delete'];
  const paths=Object.keys(spec.paths||{});
  if(!paths.length)ops.append($('p',{class:'empty',text:'no routes declared'}));
  for(const path of paths){
    const item=spec.paths[path];
    for(const method of order.concat(Object.keys(item).filter(m=>!order.includes(m)))){
      const op=item[method];if(!op)continue;
      const d=$('details',{});
      const sum=$('summary',{},$('span',{class:'m '+method,text:method.toUpperCase()}),$('span',{class:'p',text:path}));
      if(op.description)sum.append($('span',{class:'s',text:op.description}));
      d.append(sum);
      const body=$('div',{class:'body'});
      const tags=$('div',{class:'tags'});
      if(op.security)tags.append($('span',{class:'tag',text:'requires auth'}));
      const rl=op['x-synsema-rate-limit'];
      if(rl)tags.append($('span',{class:'tag',text:rl==='unlimited'?'rate limit: unlimited':'rate limit: '+rl.count+' / '+rl.window+'s'}));
      if(op['x-synsema-streaming'])tags.append($('span',{class:'tag',text:'server-sent events'}));
      if(op['x-synsema-socket'])tags.append($('span',{class:'tag',text:'websocket'}));
      if(op['x-synsema-proxy'])tags.append($('span',{class:'tag',text:'reverse proxy'}));
      for(const c of op['x-synsema-capabilities']||[])tags.append($('span',{class:'tag cap',text:c.scope?c.name+':'+c.scope:c.name}));
      if(tags.children.length)body.append(tags);
      const params=(op.parameters||[]).filter(p=>p.in==='path');
      const inputs={};
      for(const p of params){body.append($('label',{text:'path · '+p.name}));const i=$('input',{class:'f',placeholder:p.name});inputs[p.name]=i;body.append(i);}
      let bodyArea=null;
      const rb=op.requestBody&&op.requestBody.content&&op.requestBody.content['application/json'];
      if(rb){const sc=rb.schema||{};const sample={};for(const k in sc.properties||{}){const t=sc.properties[k].type;sample[k]=t==='string'?'':t==='number'?0:t==='boolean'?false:t==='array'?[]:{};}
        body.append($('label',{text:'request body · application/json (every field required)'}));bodyArea=$('textarea',{});bodyArea.value=JSON.stringify(sample,null,2);body.append(bodyArea);}
      else if(!['get','head','delete'].includes(method)){body.append($('label',{text:'request body (optional)'}));bodyArea=$('textarea',{});body.append(bodyArea);}
      const resp=Object.keys(op.responses||{}).map(k=>k+' '+(op.responses[k].description||'')+(op.responses[k].content?' · '+Object.keys(op.responses[k].content).join(', '):'')).join('\n');
      body.append($('label',{text:'responses'}),$('pre',{text:resp}));
      const btn=$('button',{text:'Try it'});const st=$('div',{class:'st'});const out=$('pre',{});out.hidden=true;
      btn.addEventListener('click',async()=>{
        let url=path;for(const n in inputs)url=url.replace('{'+n+'}',encodeURIComponent(inputs[n].value));
        const headers={'Accept':'application/json, text/markdown;q=0.9, text/html;q=0.8, */*;q=0.5'};
        if(tok.value)headers['Authorization']='Bearer '+tok.value;
        const init={method:method.toUpperCase(),headers,credentials:'same-origin'};
        if(bodyArea&&bodyArea.value.trim()){init.body=bodyArea.value;headers['Content-Type']='application/json';}
        st.className='st';st.textContent='…';out.hidden=true;
        try{const t0=performance.now();const r=await fetch(url,init);const txt=await r.text();const ms=Math.round(performance.now()-t0);
          st.className='st '+(r.ok?'ok':'err');st.textContent=r.status+' '+r.statusText+' · '+ms+' ms · '+(r.headers.get('content-type')||'');
          let shown=txt;try{shown=JSON.stringify(JSON.parse(txt),null,2);}catch(e){}
          const hs=[];r.headers.forEach((v,k)=>hs.push(k+': '+v));out.textContent=hs.join('\n')+'\n\n'+shown;out.hidden=false;}
        catch(e){st.className='st err';st.textContent='request failed: '+e.message;}
      });
      body.append(btn,st,out);d.append(body);ops.append(d);
    }
  }
})();
</script>
</body>
</html>
"##;

/// Serialización canónica (la misma que el server manda).
pub fn openapi_text(info: &ApiInfo, routes: &[ApiRoute]) -> String {
    dumps(&openapi_json(info, routes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_paths() {
        assert_eq!(operation_id("GET", "/blog/:slug"), "get_blog_slug");
        assert_eq!(operation_id("GET", "/"), "get_root");
        assert_eq!(operation_id("POST", "/files/*path"), "post_files_path");
        assert_eq!(openapi_path("/a/:id/b/*rest"), "/a/{id}/b/{rest}");
    }
}

// =========================================================
// T3 (identidad): la Agent Card firmada — `/.well-known/agent-card.json`
// =========================================================
//
// La tarjeta del server, DERIVADA de la tabla de rutas viva (como `/openapi.json`) y con la
// forma EXACTA de la **Agent Card de A2A 1.0** (`message AgentCard` de `a2a.proto`, package
// `lf.a2a.v1`, en su mapping proto-JSON: nombres lowerCamelCase, los `oneof` como su propio
// campo): `name`/`description`/`version`/`documentationUrl`, `supportedInterfaces`,
// `capabilities` (con `extensions` ADENTRO), `securitySchemes` (`httpAuthSecurityScheme` /
// `apiKeySecurityScheme`), `securityRequirements`, los modos, `skills` y `signatures`. Lo que
// 1.0 no tiene (`url`, `security`, `stateTransitionHistory`, campos sueltos) no va: un parser
// proto-JSON estricto rechaza la tarjeta entera por un campo desconocido (auditoría T1–T4,
// ronda 1).
//
// Lo que A2A no modela va en UNA extensión declarada (`capabilities.extensions[0]`, uri
// `https://synsema.org/ext/identity/v1`): el `did:key` del server, la URL base, `/openapi.json`,
// `/.well-known/synsema-auth`, `/.well-known/attestation` (bajo `--attested`), la versión del
// motor y la regla del techo delegado (`capabilityTokens: true`: los `caps` de un captoken son
// el techo de la request).
//
// **Verdad derivada, jamás declarada:** `supportedInterfaces` va VACÍO porque este server no
// habla el transporte A2A (`message/send` por JSON-RPC/gRPC/HTTP+JSON). Una tarjeta que dijera
// lo contrario mentiría; lo que sí es cierto — quién es, qué sabe hacer, cómo se autentica —
// lo lee cualquier cliente A2A y lo apunta un registro ERC-8004 (`services: [{name: "A2A",
// endpoint: ".../.well-known/agent-card.json"}, {name: "DID", endpoint: "did:key:…"}]`).
//
// **La firma es la de A2A (§8.4):** JWS (RFC 7515) en serialización JSON, `signatures:
// [{protected, signature}]`, con el payload = JCS (RFC 8785) de la tarjeta SIN `signatures`,
// header protegido `{alg, kid, typ: "JOSE"}` y `kid` = la URL de verificación del `did:key`
// del server (`did:key:z…#z…`): un verificador resuelve la clave offline, sin JWKS ni red.
// Con la ed25519 de `SYNSEMA_IDENTITY_KEY` el alg es `EdDSA`; bajo `serve --attested` firma la
// P-256 atestada (`ES256`), y entonces la identidad de la tarjeta ES la del documento de
// attestation. Sin clave configurada la tarjeta sale sin `signatures` y sin `did` (lo que no
// se deriva con verdad se omite). Verificarla desde Synsema: `jwt_verify(protected + "." +
// b64url(canonical_json(card_sin_signatures)) + "." + signature, {"did": kid}, {…})`.

pub const AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
/// Alias que los clientes A2A anteriores a 0.3 piden.
pub const AGENT_CARD_LEGACY_PATH: &str = "/.well-known/agent.json";
pub const SYNSEMA_EXTENSION_URI: &str = "https://synsema.org/ext/identity/v1";

/// La identidad que firma la tarjeta: la clave del server y su `did:key`.
pub enum CardSigner {
    Ed25519 { key: ed25519_dalek::SigningKey, did: String },
    P256 { key: p256::SecretKey, did: String },
}

impl CardSigner {
    pub fn ed25519_from_seed(seed: [u8; 32]) -> CardSigner {
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let did = crate::didkey::encode(crate::didkey::KeyAlg::Ed25519, &key.verifying_key().to_bytes())
            .expect("una clave ed25519 válida siempre codifica");
        CardSigner::Ed25519 { key, did }
    }

    /// Desde el escalar P-256 (32 bytes) de la identidad atestada.
    pub fn p256_from_scalar(scalar: &[u8]) -> Result<CardSigner, String> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let key = p256::SecretKey::from_slice(scalar).map_err(|_| "not a valid P-256 scalar".to_string())?;
        let pk = key.public_key().to_encoded_point(true).as_bytes().to_vec();
        let did = crate::didkey::encode(crate::didkey::KeyAlg::P256, &pk)?;
        Ok(CardSigner::P256 { key, did })
    }

    pub fn did(&self) -> &str {
        match self {
            CardSigner::Ed25519 { did, .. } | CardSigner::P256 { did, .. } => did,
        }
    }

    /// `did:key:z…#z…` — la URL del verificationMethod (y el `kid` del JWS).
    pub fn kid(&self) -> String {
        let did = self.did();
        let mb = did.strip_prefix("did:key:").unwrap_or(did);
        format!("{}#{}", did, mb)
    }

    pub fn alg(&self) -> &'static str {
        match self {
            CardSigner::Ed25519 { .. } => "EdDSA",
            CardSigner::P256 { .. } => "ES256",
        }
    }

    fn sign(&self, input: &[u8]) -> Vec<u8> {
        match self {
            CardSigner::Ed25519 { key, .. } => {
                use ed25519_dalek::Signer as _;
                key.sign(input).to_bytes().to_vec()
            }
            CardSigner::P256 { key, .. } => crate::webauth::es256_sign(key, input),
        }
    }
}

/// Qué autenticación anuncia el server (las mismas condiciones que `/.well-known/synsema-auth`).
pub struct CardAuth {
    pub bearer: bool,
    pub cookie: bool,
    pub httpsig: bool,
}

fn str_list(items: &[&str]) -> Json {
    Json::Array(items.iter().map(|s| Json::Str((*s).to_string())).collect())
}

/// `SecurityRequirement` de A2A: `{schemes: {<name>: {list: [...]}}}` (un `map<string,
/// StringList>` en proto-JSON).
fn security_requirement(name: &str) -> Json {
    obj(vec![("schemes", obj(vec![(name, obj(vec![("list", Json::Array(Vec::new()))]))]))])
}

/// La Agent Card sin firmar, derivada de la tabla de rutas.
pub fn agent_card(
    info: &ApiInfo,
    routes: &[ApiRoute],
    auth: Option<&CardAuth>,
    docs_enabled: bool,
    attested: bool,
    signer: Option<&CardSigner>,
) -> Json {
    let base = info.base_url.clone().unwrap_or_default();
    let join = |p: &str| {
        if base.is_empty() {
            p.to_string()
        } else {
            format!("{}{}", base.trim_end_matches('/'), p)
        }
    };
    let mut card: Vec<(&str, Json)> = Vec::new();
    card.push(("name", Json::Str(info.title.clone())));
    card.push((
        "description",
        Json::Str(info.description.clone().unwrap_or_else(|| "Synsema service".to_string())),
    ));
    // Verdad derivada: ningún transporte A2A. Ver el doc del bloque.
    card.push(("supportedInterfaces", Json::Array(Vec::new())));
    card.push(("version", Json::Str(info.version.clone())));
    if docs_enabled && !base.is_empty() {
        card.push(("documentationUrl", Json::Str(join("/docs"))));
    }
    // Lo que A2A no modela, como extensión declarada dentro de `capabilities` (donde el
    // proto la pone), no como campos sueltos que un parser estricto rechazaría.
    let mut params: Vec<(&str, Json)> = Vec::new();
    if let Some(s) = signer {
        params.push(("did", Json::Str(s.did().to_string())));
    }
    if !base.is_empty() {
        params.push(("baseUrl", Json::Str(base.clone())));
    }
    params.push(("openapi", Json::Str(join("/openapi.json"))));
    params.push(("auth", Json::Str(join("/.well-known/synsema-auth"))));
    if attested {
        params.push(("attestation", Json::Str(join("/.well-known/attestation"))));
    }
    params.push(("engine", Json::Str(crate::attest::engine_version().to_string())));
    params.push(("capabilityTokens", Json::Bool(true)));
    let extension = obj(vec![
        ("uri", Json::Str(SYNSEMA_EXTENSION_URI.into())),
        (
            "description",
            Json::Str(
                "Synsema identity: did:key of this server, base URL, OpenAPI, auth discovery, attestation; a captoken's caps are the request's ceiling"
                    .into(),
            ),
        ),
        ("required", Json::Bool(false)),
        ("params", obj(params)),
    ]);
    let streaming = routes.iter().any(|r| r.streaming);
    card.push((
        "capabilities",
        obj(vec![
            ("streaming", Json::Bool(streaming)),
            ("pushNotifications", Json::Bool(false)),
            ("extensions", Json::Array(vec![extension])),
            ("extendedAgentCard", Json::Bool(false)),
        ]),
    ));
    if let Some(a) = auth {
        let mut schemes: Vec<(&str, Json)> = Vec::new();
        let mut requirements: Vec<Json> = Vec::new();
        if a.bearer {
            schemes.push((
                "bearer",
                obj(vec![(
                    "httpAuthSecurityScheme",
                    obj(vec![
                        ("description", Json::Str("Authorization: Bearer <token>".into())),
                        ("scheme", Json::Str("bearer".into())),
                        ("bearerFormat", Json::Str("captoken | jwt | opaque".into())),
                    ]),
                )]),
            ));
            requirements.push(security_requirement("bearer"));
        }
        if a.cookie {
            schemes.push((
                "cookie",
                obj(vec![(
                    "apiKeySecurityScheme",
                    obj(vec![
                        ("description", Json::Str("session cookie".into())),
                        ("location", Json::Str("cookie".into())),
                        ("name", Json::Str("session".into())),
                    ]),
                )]),
            ));
            requirements.push(security_requirement("cookie"));
        }
        if a.httpsig {
            schemes.push((
                "httpsig",
                obj(vec![(
                    "httpAuthSecurityScheme",
                    obj(vec![
                        (
                            "description",
                            Json::Str(
                                "RFC 9421 HTTP Message Signature, pinned profile: @method, @target-uri, content-digest; ed25519 or hmac-sha256"
                                    .into(),
                            ),
                        ),
                        ("scheme", Json::Str("signature".into())),
                    ]),
                )]),
            ));
            requirements.push(security_requirement("httpsig"));
        }
        card.push(("securitySchemes", obj(schemes)));
        card.push(("securityRequirements", Json::Array(requirements)));
    }
    card.push(("defaultInputModes", str_list(&["application/json"])));
    let negotiates = routes.iter().any(|r| matches!(r.meta.response_kind, Some(ResponseKind::Content)));
    card.push((
        "defaultOutputModes",
        if negotiates {
            str_list(&["application/json", "text/markdown", "text/html"])
        } else {
            str_list(&["application/json"])
        },
    ));
    // Skills: una por ruta pública, en el orden de OpenAPI. `tags` es REQUIRED en 1.0.
    let skills: Vec<Json> = sorted_routes(routes)
        .into_iter()
        .map(|r| {
            let mut tags = vec![r.method.to_ascii_lowercase()];
            if r.requires_auth {
                tags.push("auth".to_string());
            }
            if r.streaming {
                tags.push("stream".to_string());
            }
            if r.socket {
                tags.push("socket".to_string());
            }
            let output = match r.meta.response_kind {
                Some(ResponseKind::Html) => str_list(&["text/html"]),
                Some(ResponseKind::Content) => str_list(&["application/json", "text/markdown", "text/html"]),
                Some(ResponseKind::Stream) => str_list(&["text/event-stream"]),
                _ => str_list(&["application/json"]),
            };
            obj(vec![
                ("id", Json::Str(operation_id(&r.method, &r.path))),
                ("name", Json::Str(format!("{} {}", r.method, r.path))),
                ("description", Json::Str(format!("{} {}{}", r.method, r.path, caps_suffix(r)))),
                ("tags", Json::Array(tags.into_iter().map(Json::Str).collect())),
                ("inputModes", str_list(&["application/json"])),
                ("outputModes", output),
            ])
        })
        .collect();
    card.push(("skills", Json::Array(skills)));
    obj(card)
}

/// JCS (RFC 8785) de un `Json` de discovery.
fn canonical_of(j: &Json) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(&dumps(j)).map_err(|e| e.to_string())?;
    crate::canonical::canonical_json(&crate::json::json_to_syn(&v)).map_err(|e| match e {
        synsema_core::interpreter::Control::Error(e) => e.to_string(),
        _ => "canonical_json: control flow".to_string(),
    })
}

/// Firma la tarjeta como manda A2A §8.4: JWS (serialización JSON) sobre el JCS de la tarjeta
/// sin `signatures`, header protegido `{alg, kid, typ: "JOSE"}`.
pub fn sign_card(card: &Json, signer: &CardSigner) -> Result<Json, String> {
    use synsema_core::bytesutil::b64url_encode;
    let Json::Object(fields) = card else {
        return Err("the card must be an object".to_string());
    };
    let unsigned: Vec<(String, Json)> = fields.iter().filter(|(k, _)| k != "signatures").cloned().collect();
    let payload = canonical_of(&Json::Object(unsigned.clone()))?;
    // Header protegido ya canónico (claves en orden: alg, kid, typ).
    let protected = format!(
        "{{\"alg\":\"{}\",\"kid\":{},\"typ\":\"JOSE\"}}",
        signer.alg(),
        serde_json::Value::String(signer.kid())
    );
    let protected_b64 = b64url_encode(protected.as_bytes());
    let input = format!("{}.{}", protected_b64, b64url_encode(payload.as_bytes()));
    let sig = signer.sign(input.as_bytes());
    let mut out = unsigned;
    out.push((
        "signatures".to_string(),
        Json::Array(vec![obj(vec![
            ("protected", Json::Str(protected_b64)),
            ("signature", Json::Str(b64url_encode(&sig))),
        ])]),
    ));
    Ok(Json::Object(out))
}

#[cfg(test)]
mod agent_card_tests {
    use super::*;
    use synsema_core::route_meta::RouteMeta;

    /// Los campos de `message AgentCard` de a2a.proto (1.0, package lf.a2a.v1) en proto-JSON.
    /// Cualquier otro campo en el nivel superior rompe un parser estricto.
    const AGENT_CARD_FIELDS: [&str; 14] = [
        "name",
        "description",
        "supportedInterfaces",
        "provider",
        "version",
        "documentationUrl",
        "capabilities",
        "securitySchemes",
        "securityRequirements",
        "defaultInputModes",
        "defaultOutputModes",
        "skills",
        "signatures",
        "iconUrl",
    ];
    const CAPABILITIES_FIELDS: [&str; 4] = ["streaming", "pushNotifications", "extensions", "extendedAgentCard"];
    const SKILL_FIELDS: [&str; 8] = ["id", "name", "description", "tags", "examples", "inputModes", "outputModes", "securityRequirements"];

    fn route(method: &str, path: &str, auth: bool) -> ApiRoute {
        ApiRoute {
            method: method.to_string(),
            path: path.to_string(),
            param_names: Vec::new(),
            requires_auth: auth,
            streaming: false,
            socket: false,
            private: false,
            rate_limit: None,
            rate_unlimited: false,
            proxy: false,
            meta: RouteMeta::default(),
        }
    }

    fn info() -> ApiInfo {
        ApiInfo {
            title: "Demo".into(),
            description: Some("a demo".into()),
            version: "1.0.0".into(),
            base_url: Some("https://demo.test".into()),
            has_auth: true,
            describe_api: Vec::new(),
        }
    }

    fn only_known(v: &serde_json::Value, known: &[&str], what: &str) {
        for k in v.as_object().unwrap().keys() {
            assert!(known.contains(&k.as_str()), "{} carries {:?}, which a2a.proto 1.0 does not define", what, k);
        }
    }

    #[test]
    fn card_is_a2a_1_0_shaped_and_derived() {
        let routes = vec![route("GET", "/health", false), route("POST", "/ask", true)];
        let auth = CardAuth { bearer: true, cookie: true, httpsig: true };
        let signer = CardSigner::ed25519_from_seed([7u8; 32]);
        let card = agent_card(&info(), &routes, Some(&auth), true, false, Some(&signer));
        let signed = sign_card(&card, &signer).unwrap();
        let v: serde_json::Value = serde_json::from_str(&dumps(&signed)).unwrap();
        only_known(&v, &AGENT_CARD_FIELDS, "the card");
        only_known(&v["capabilities"], &CAPABILITIES_FIELDS, "capabilities");
        for s in v["skills"].as_array().unwrap() {
            only_known(s, &SKILL_FIELDS, "a skill");
        }
        assert_eq!(v["name"], "Demo");
        assert_eq!(v["documentationUrl"], "https://demo.test/docs");
        assert!(v.get("url").is_none() && v.get("security").is_none(), "campos de 0.3 que 1.0 no tiene");
        assert_eq!(v["supportedInterfaces"].as_array().unwrap().len(), 0, "no A2A transport → no interfaces");
        let skills = v["skills"].as_array().unwrap();
        assert_eq!(skills.len(), 2);
        assert_eq!(skills[0]["id"], "post_ask");
        assert!(skills[0]["tags"].as_array().unwrap().iter().any(|t| t == "auth"));
        assert_eq!(skills[1]["id"], "get_health");
        // securitySchemes: el oneof como campo propio; securityRequirements: {schemes: {name: {list}}}
        assert_eq!(v["securitySchemes"]["bearer"]["httpAuthSecurityScheme"]["scheme"], "bearer");
        assert_eq!(v["securitySchemes"]["cookie"]["apiKeySecurityScheme"]["location"], "cookie");
        assert_eq!(v["securitySchemes"]["httpsig"]["httpAuthSecurityScheme"]["scheme"], "signature");
        let reqs = v["securityRequirements"].as_array().unwrap();
        assert_eq!(reqs.len(), 3);
        assert!(reqs[0]["schemes"]["bearer"]["list"].as_array().unwrap().is_empty());
        // La extensión vive en capabilities.extensions, con el did y las URLs.
        let ext = &v["capabilities"]["extensions"][0];
        assert_eq!(ext["uri"], SYNSEMA_EXTENSION_URI);
        assert_eq!(ext["params"]["did"], signer.did());
        assert_eq!(ext["params"]["baseUrl"], "https://demo.test");
        assert_eq!(ext["params"]["openapi"], "https://demo.test/openapi.json");
        assert!(ext["params"].get("attestation").is_none());
        assert_eq!(v["signatures"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn without_signer_or_auth_nothing_is_invented() {
        let routes = vec![route("GET", "/", false)];
        let card = agent_card(&info(), &routes, None, false, false, None);
        let v: serde_json::Value = serde_json::from_str(&dumps(&card)).unwrap();
        only_known(&v, &AGENT_CARD_FIELDS, "the card");
        assert!(v.get("securitySchemes").is_none() && v.get("securityRequirements").is_none());
        assert!(v.get("signatures").is_none());
        assert!(v["capabilities"]["extensions"][0]["params"].get("did").is_none(), "sin firmante no se inventa un did");
        assert!(v.get("documentationUrl").is_none(), "docs off");
    }

    #[test]
    fn signed_card_verifies_as_jws_over_jcs() {
        use ed25519_dalek::Verifier as _;
        let signer = CardSigner::ed25519_from_seed([7u8; 32]);
        assert!(signer.did().starts_with("did:key:z6Mk"));
        assert_eq!(signer.kid(), format!("{}#{}", signer.did(), &signer.did()[8..]));
        let routes = vec![route("GET", "/", false)];
        let card = agent_card(&info(), &routes, None, false, false, Some(&signer));
        let signed = sign_card(&card, &signer).unwrap();
        let v: serde_json::Value = serde_json::from_str(&dumps(&signed)).unwrap();
        assert_eq!(v["capabilities"]["extensions"][0]["params"]["did"], signer.did());
        let sig = &v["signatures"][0];
        let protected: serde_json::Value = serde_json::from_slice(
            &synsema_core::bytesutil::b64url_decode(sig["protected"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(protected["alg"], "EdDSA");
        assert_eq!(protected["kid"], signer.kid());
        assert_eq!(protected["typ"], "JOSE");
        // Reconstruir el input firmado: JCS de la tarjeta sin `signatures`.
        let mut unsigned = v.clone();
        unsigned.as_object_mut().unwrap().remove("signatures");
        let payload = crate::canonical::canonical_json(&crate::json::json_to_syn(&unsigned)).map_err(|_| ()).unwrap();
        let input = format!(
            "{}.{}",
            sig["protected"].as_str().unwrap(),
            synsema_core::bytesutil::b64url_encode(payload.as_bytes())
        );
        let raw = synsema_core::bytesutil::b64url_decode(sig["signature"].as_str().unwrap()).unwrap();
        let CardSigner::Ed25519 { key, .. } = &signer else { unreachable!() };
        let s = ed25519_dalek::Signature::from_slice(&raw).unwrap();
        key.verifying_key().verify(input.as_bytes(), &s).unwrap();
        // Y la misma clave se resuelve desde el did (offline).
        let (alg, pk, _mb) = crate::didkey::decode(signer.did()).unwrap();
        assert_eq!(alg, crate::didkey::KeyAlg::Ed25519);
        assert_eq!(pk, key.verifying_key().to_bytes());
    }

    #[test]
    fn p256_signer_from_attested_scalar() {
        let scalar = [9u8; 32];
        let signer = CardSigner::p256_from_scalar(&scalar).unwrap();
        assert!(signer.did().starts_with("did:key:zDn"));
        assert_eq!(signer.alg(), "ES256");
        assert!(CardSigner::p256_from_scalar(&[0u8; 32]).is_err(), "el escalar 0 no es una clave");
    }
}

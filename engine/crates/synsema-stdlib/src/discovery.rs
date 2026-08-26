//! Discovery derivado de la tabla de rutas (tanda discovery — `specs/discovery-openapi.md`):
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

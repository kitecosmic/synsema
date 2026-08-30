//! `synsema code` — inteligencia de código para agentes (spec `specs/code-intelligence.md`).
//!
//! Dos superficies sobre el mismo índice (`synsema_core::codeintel`):
//! - CLI: `synsema code <tool> [args] [--json]` (humano por defecto, JSON para scripts).
//! - MCP: `synsema code --mcp` — JSON-RPC 2.0 por stdin/stdout, una línea por mensaje,
//!   registrado como `synsema-code`. stdout es SÓLO protocolo; todo lo demás va a stderr.
//!
//! Es development-time sobre el código de la carpeta actual: nunca ejecuta el programa ni
//! habla con una app corriendo. Por eso NO se llama `synsema mcp`: ese nombre queda para el
//! MCP que un `serve` expone por introspección a otros agentes.

use std::io::{BufRead, Write};
use std::process::ExitCode;

use serde_json::{json, Value};
use synsema_core::codeintel::{self, Root};

const SERVER_NAME: &str = "synsema-code";
const PROTOCOL_VERSION: &str = "2025-06-18";
const STATIC_NOTE: &str = "Static: derived from the parser, never from running the program.";
const INSTRUCTIONS: &str = "Code intelligence for the Synsema project in the current folder (development-time; it does not talk to a running app). Call `outline` before reading a .syn file, `routes`/`caps` before editing a server, `check` after editing, `search` instead of reading whole files.";

/// Una tool: nombre, descripción, esquema de entrada. Única fuente para el usage del CLI y
/// para `tools/list` del MCP.
struct ToolSpec {
    name: &'static str,
    description: &'static str,
    /// (nombre, tipo JSON, descripción, requerido)
    params: &'static [(&'static str, &'static str, &'static str, bool)],
}

const P_PATH: (&str, &str, &str, bool) = ("path", "string", "File or directory relative to the project root (default: whole project).", false);

const TOOLS: &[ToolSpec] = &[
    ToolSpec { name: "outline", description: "Structure WITHOUT bodies. One file (or `full: true`): intent, requires, imports, and every top-level symbol (task, agent, type, enum, let, serve, route, test) with line/end_line, params, calls, templates. Several files: a compact project map per file (intent, line count, symbol counts, task/route names, imports and imported_by). Read this before reading a file.", params: &[P_PATH, ("full", "boolean", "Full per-symbol outline even for many files (default: compact map when more than one file).", false)] },
    ToolSpec { name: "symbol", description: "Where `name` is defined (task/agent/type/enum/let, or a route as \"GET /path\"; `alias.name` looks inside the module imported with `use`). Returns file, line, end_line and the signature.", params: &[("name", "string", "Symbol name, or `alias.name` for a module export.", true), P_PATH] },
    ToolSpec { name: "refs", description: "Every use of `name`: calls, identifiers, `spawn`, and `alias.name` module calls, each with file, line, column and the enclosing symbol. The definition itself is excluded.", params: &[("name", "string", "Symbol name, or `alias.name`.", true), P_PATH] },
    ToolSpec { name: "routes", description: "The HTTP table each `serve` would publish: method, path, line, host (vhost), auth, stream/socket/proxy, rate limit, `expect body` fields, response kind and the static transitive capabilities of every route (incl. `mount`ed groups).", params: &[P_PATH] },
    ToolSpec { name: "caps", description: "Capability contract per file: `declared` (top-level require), `needed` per symbol (builtins it calls, transitively through tasks, `llm` for reason/decide/…), and `missing` with a hint (`add require net(\"host\")`). Conservative: a dynamic scope is compared by type only.", params: &[P_PATH] },
    ToolSpec { name: "check", description: "Parse + resolve `use` imports + validate render(\"literal\") templates over one or all .syn files. `errors` (file, line, column, message) block; `warnings` are missing capabilities the runtime would deny.", params: &[P_PATH] },
    ToolSpec { name: "search", description: "Text search over project files (.syn .fsyn .html .css .js .ts .md .json .toml .txt by default; `kinds` restricts). Case-insensitive literal, or `regex: true`. Skips .git/node_modules/target/dist/build, hidden dirs, binaries and files > 2 MiB. Each match carries the enclosing Synsema symbol.", params: &[("pattern", "string", "Literal text (case-insensitive) or a regex when `regex` is true.", true), P_PATH, ("kinds", "array", "File extensions to include, e.g. [\"syn\", \"html\"].", false), ("regex", "boolean", "Treat `pattern` as a regular expression.", false), ("limit", "integer", "Maximum matches (default 200); `truncated` tells if it was hit.", false)] },
    ToolSpec { name: "deps", description: "Task → tasks-it-calls graph per file (builtins excluded) plus the `use` imports between files.", params: &[P_PATH] },
];

fn tool_schema(t: &ToolSpec) -> Value {
    let mut props = serde_json::Map::new();
    let mut required = Vec::new();
    for (name, ty, desc, req) in t.params {
        let mut p = json!({"type": ty, "description": desc});
        if *ty == "array" {
            p["items"] = json!({"type": "string"});
        }
        props.insert((*name).to_string(), p);
        if *req {
            required.push(json!(name));
        }
    }
    json!({"type": "object", "properties": Value::Object(props), "required": required, "additionalProperties": false})
}

fn usage() -> String {
    let mut s = String::from(
        "uso: synsema code <tool> [args] [--json] [--root <dir>]\n       synsema code --mcp        (servidor MCP por stdio, registrar como `synsema-code`)\n\ntools (development-time, sobre el código de la carpeta; nunca ejecuta el programa):\n",
    );
    for t in TOOLS {
        let args: Vec<String> = t
            .params
            .iter()
            .map(|(n, _, _, req)| if *req { format!("<{}>", n) } else { format!("[{}]", n) })
            .collect();
        s.push_str(&format!("  {:<8} {}\n", t.name, args.join(" ")));
    }
    s.push_str("\nsearch: [--kinds syn,html,...] [--regex] [--limit N]    outline: [--full]\n");
    s
}

fn as_str_list(v: &Value) -> Option<Vec<String>> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
}

/// Ejecuta una tool con argumentos JSON (compartido por CLI y MCP).
fn run_tool(root: &Root, name: &str, args: &Value) -> Result<Value, String> {
    let path = args.get("path").and_then(Value::as_str).filter(|s| !s.is_empty());
    let name_arg = |a: &Value| -> Result<String, String> {
        a.get("name").and_then(Value::as_str).filter(|s| !s.is_empty()).map(String::from).ok_or_else(|| "missing required argument `name`".to_string())
    };
    if let Some(p) = path {
        if !root.dir.join(p).exists() && !std::path::Path::new(p).exists() {
            return Err(format!("path not found: {}", p));
        }
    }
    Ok(match name {
        "outline" => codeintel::outline(root, path, args.get("full").and_then(Value::as_bool).unwrap_or(false)),
        "symbol" => codeintel::symbol(root, &name_arg(args)?, path),
        "refs" => codeintel::refs(root, &name_arg(args)?, path),
        "routes" => codeintel::routes(root, path),
        "caps" => codeintel::caps(root, path),
        "check" => codeintel::check(root, path),
        "deps" => codeintel::deps(root, path),
        "search" => {
            let pattern = args.get("pattern").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| "missing required argument `pattern`".to_string())?;
            let kinds = args.get("kinds").and_then(as_str_list);
            let kinds_ref: Option<Vec<&str>> = kinds.as_ref().map(|k| k.iter().map(String::as_str).collect());
            let use_regex = args.get("regex").and_then(Value::as_bool).unwrap_or(false);
            let limit = args.get("limit").and_then(Value::as_u64).map(|n| n.max(1) as usize).unwrap_or(200);
            let out = codeintel::search(root, pattern, path, kinds_ref.as_deref(), use_regex, limit);
            if let Some(e) = out.get("error").and_then(Value::as_str) {
                return Err(e.to_string());
            }
            out
        }
        other => return Err(format!("unknown tool `{}` (available: {})", other, TOOLS.iter().map(|t| t.name).collect::<Vec<_>>().join(", "))),
    })
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

pub fn cmd_code(args: &[String]) -> ExitCode {
    let mut json_out = false;
    let mut mcp = false;
    let mut root_dir: Option<String> = None;
    let mut kinds: Option<Vec<String>> = None;
    let mut use_regex = false;
    let mut full = false;
    let mut limit: Option<u64> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json_out = true,
            "--mcp" => mcp = true,
            "--regex" => use_regex = true,
            "--full" => full = true,
            "--root" => {
                i += 1;
                root_dir = args.get(i).cloned();
            }
            "--kinds" => {
                i += 1;
                kinds = args.get(i).map(|s| s.split(',').map(|k| k.trim().trim_start_matches('.').to_string()).filter(|k| !k.is_empty()).collect());
            }
            "--limit" => {
                i += 1;
                limit = args.get(i).and_then(|s| s.parse().ok());
            }
            "-h" | "--help" => {
                print!("{}", usage());
                return ExitCode::SUCCESS;
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }
    let root = Root::new(root_dir.map(std::path::PathBuf::from).unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into())));
    if mcp {
        return mcp::serve_stdio(&root);
    }
    let Some(tool) = positional.first().cloned() else {
        eprint!("{}", usage());
        return ExitCode::from(2);
    };
    let spec = match TOOLS.iter().find(|t| t.name == tool) {
        Some(t) => t,
        None => {
            eprintln!("synsema code: tool desconocida '{}'.\n{}", tool, usage());
            return ExitCode::from(2);
        }
    };
    // Posicionales → argumentos por orden de `params`.
    let mut call = serde_json::Map::new();
    for (idx, (pname, _, _, _)) in spec.params.iter().filter(|(n, ..)| *n != "kinds" && *n != "regex" && *n != "limit" && *n != "full").enumerate() {
        if let Some(v) = positional.get(idx + 1) {
            call.insert((*pname).to_string(), json!(v));
        }
    }
    if let Some(k) = kinds {
        call.insert("kinds".into(), json!(k));
    }
    if use_regex {
        call.insert("regex".into(), json!(true));
    }
    if full {
        call.insert("full".into(), json!(true));
    }
    if let Some(l) = limit {
        call.insert("limit".into(), json!(l));
    }
    let result = match run_tool(&root, &tool, &Value::Object(call)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("synsema code {}: {}", tool, e);
            return ExitCode::from(2);
        }
    };
    if json_out {
        println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
    } else {
        print!("{}", render_human(&tool, &result));
    }
    if tool == "check" && result.get("ok") == Some(&json!(false)) {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn s(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Tablas cortas para humanos (el JSON es el contrato; esto es cortesía).
fn render_human(tool: &str, v: &Value) -> String {
    let mut out = String::new();
    match tool {
        "outline" if v["brief"] == json!(true) => {
            for f in v["files"].as_array().unwrap_or(&vec![]) {
                let counts: Vec<String> = f["symbols"].as_object().map(|m| m.iter().map(|(k, n)| format!("{} {}", s(n), k)).collect()).unwrap_or_default();
                out.push_str(&format!("{}  ({} lines; {})", s(&f["file"]), s(&f["lines"]), if counts.is_empty() { "no symbols".into() } else { counts.join(", ") }));
                if let Some(i) = f["intent"].as_str() {
                    out.push_str(&format!("\n    — {}", i));
                }
                if let Some(pe) = f["parse_error"].as_object() {
                    out.push_str(&format!("\n    PARSE ERROR {}:{}: {}", s(&pe["line"]), s(&pe["column"]), s(&pe["message"])));
                }
                for (label, key) in [("tasks", "tasks"), ("agents", "agents"), ("routes", "routes")] {
                    let names: Vec<String> = f[key].as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default();
                    if !names.is_empty() {
                        out.push_str(&format!("\n    {}: {}", label, names.join(", ")));
                    }
                }
                let imps: Vec<String> = f["imports"].as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default();
                if !imps.is_empty() {
                    out.push_str(&format!("\n    imports: {}", imps.join(", ")));
                }
                let by: Vec<String> = f["imported_by"].as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default();
                if !by.is_empty() {
                    out.push_str(&format!("\n    imported by: {}", by.join(", ")));
                }
                out.push('\n');
            }
        }
        "outline" => {
            for f in v["files"].as_array().unwrap_or(&vec![]) {
                out.push_str(&format!("{}", s(&f["file"])));
                if let Some(i) = f["intent"].as_str() {
                    out.push_str(&format!("  — {}", i));
                }
                out.push('\n');
                if let Some(pe) = f["parse_error"].as_object() {
                    out.push_str(&format!("  PARSE ERROR {}:{}: {}\n", s(&pe["line"]), s(&pe["column"]), s(&pe["message"])));
                }
                for r in f["requires"].as_array().unwrap_or(&vec![]) {
                    let sc = r["scope"].as_str().map(|x| format!("(\"{}\")", x)).unwrap_or_default();
                    out.push_str(&format!("  L{:<4} require {}{}\n", s(&r["line"]), s(&r["cap"]), sc));
                }
                for im in f["imports"].as_array().unwrap_or(&vec![]) {
                    out.push_str(&format!("  L{:<4} use {} as {}\n", s(&im["line"]), s(&im["path"]), s(&im["alias"])));
                }
                for sym in f["symbols"].as_array().unwrap_or(&vec![]) {
                    let mut extra = String::new();
                    if let Some(p) = sym["params"].as_array() {
                        extra = format!("({})", p.iter().map(s).collect::<Vec<_>>().join(", "));
                    }
                    let mut flags = Vec::new();
                    for (k, label) in [("auth", "auth"), ("stream", "stream"), ("socket", "socket"), ("proxy", "proxy"), ("exported", "export")] {
                        if sym[k] == json!(true) {
                            flags.push(label);
                        }
                    }
                    if let Some(h) = sym["host"].as_str() {
                        flags.push("host");
                        extra.push_str(&format!(" @{}", h));
                    }
                    let fl = if flags.is_empty() { String::new() } else { format!("  [{}]", flags.join(" ")) };
                    out.push_str(&format!("  L{:<4}-{:<4} {:<9} {}{}{}\n", s(&sym["line"]), s(&sym["end_line"]), s(&sym["kind"]), s(&sym["name"]), extra, fl));
                }
            }
        }
        "symbol" => {
            for d in v["definitions"].as_array().unwrap_or(&vec![]) {
                out.push_str(&format!("{}:{}-{}  {} {}\n", s(&d["file"]), s(&d["line"]), s(&d["end_line"]), s(&d["kind"]), s(&d["name"])));
            }
            if out.is_empty() {
                out.push_str(&format!("no definition of `{}`\n", s(&v["name"])));
            }
        }
        "refs" => {
            let def: Vec<String> = v["defined_in"].as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default();
            if !def.is_empty() {
                out.push_str(&format!("defined in: {}\n", def.join(", ")));
            }
            for r in v["references"].as_array().unwrap_or(&vec![]) {
                out.push_str(&format!("{}:{}:{}  {:<12} in {}\n", s(&r["file"]), s(&r["line"]), s(&r["column"]), s(&r["kind"]), s(&r["in"])));
            }
            out.push_str(&format!("{} reference(s)\n", s(&v["count"])));
        }
        "routes" => {
            for srv in v["servers"].as_array().unwrap_or(&vec![]) {
                out.push_str(&format!("{}:{}  serve", s(&srv["file"]), s(&srv["line"])));
                if let Some(e) = srv["error"].as_str() {
                    out.push_str(&format!("  ERROR: {}", e));
                }
                out.push('\n');
                for r in srv["routes"].as_array().unwrap_or(&vec![]) {
                    let mut flags = Vec::new();
                    for k in ["auth", "stream", "socket", "proxy"] {
                        if r[k] == json!(true) {
                            flags.push(k.to_string());
                        }
                    }
                    if let Some(h) = r["host"].as_str() {
                        flags.push(format!("host={}", h));
                    }
                    let caps: Vec<String> = r["capabilities"].as_array().map(|a| a.iter().map(|c| match c["scope"].as_str() { Some(sc) => format!("{}({})", s(&c["cap"]), sc), None => s(&c["cap"]) }).collect()).unwrap_or_default();
                    out.push_str(&format!("  L{:<4} {:<6} {:<28} {:<8} {}{}\n", s(&r["line"]), s(&r["method"]), s(&r["path"]), s(&r["response"]), flags.join(" "), if caps.is_empty() { String::new() } else { format!("  caps: {}", caps.join(", ")) }));
                }
            }
        }
        "caps" => {
            for f in v["files"].as_array().unwrap_or(&vec![]) {
                let decl: Vec<String> = f["declared"].as_array().map(|a| a.iter().map(|c| match c["scope"].as_str() { Some(sc) => format!("{}({})", s(&c["cap"]), sc), None => s(&c["cap"]) }).collect()).unwrap_or_default();
                out.push_str(&format!("{}\n  declared: {}\n", s(&f["file"]), if decl.is_empty() { "(none)".into() } else { decl.join(", ") }));
                let inh: Vec<String> = f["inherited_from"].as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default();
                if !inh.is_empty() {
                    out.push_str(&format!("  inherits the capabilities of: {} (module)\n", inh.join(", ")));
                }
                for n in f["needed"].as_array().unwrap_or(&vec![]) {
                    let caps: Vec<String> = n["capabilities"].as_array().map(|a| a.iter().map(|c| match c["scope"].as_str() { Some(sc) => format!("{}({})", s(&c["cap"]), sc), None => s(&c["cap"]) }).collect()).unwrap_or_default();
                    out.push_str(&format!("  L{:<4} {:<28} needs {}\n", s(&n["line"]), s(&n["symbol"]), caps.join(", ")));
                }
                for m in f["missing"].as_array().unwrap_or(&vec![]) {
                    out.push_str(&format!("  MISSING {}{} — {}\n", s(&m["cap"]), m["scope"].as_str().map(|x| format!("(\"{}\")", x)).unwrap_or_default(), s(&m["hint"])));
                }
            }
        }
        "check" => {
            for e in v["errors"].as_array().unwrap_or(&vec![]) {
                out.push_str(&format!("error: {}:{}:{}: {}\n", s(&e["file"]), s(&e["line"]), s(&e["column"]), s(&e["message"])));
            }
            for w in v["warnings"].as_array().unwrap_or(&vec![]) {
                out.push_str(&format!("warning: {}:{}: {}\n", s(&w["file"]), s(&w["line"]), s(&w["message"])));
            }
            out.push_str(&format!("{}: {} file(s), {} error(s), {} warning(s)\n", if v["ok"] == json!(true) { "OK" } else { "FAILED" }, s(&v["files"]), v["errors"].as_array().map(|a| a.len()).unwrap_or(0), v["warnings"].as_array().map(|a| a.len()).unwrap_or(0)));
        }
        "search" => {
            for m in v["matches"].as_array().unwrap_or(&vec![]) {
                let inn = m["in"].as_str().map(|x| format!("  ({})", x)).unwrap_or_default();
                out.push_str(&format!("{}:{}:{}  {}{}\n", s(&m["file"]), s(&m["line"]), s(&m["column"]), s(&m["text"]), inn));
            }
            out.push_str(&format!("{} match(es){}\n", s(&v["count"]), if v["truncated"] == json!(true) { " (truncated)" } else { "" }));
        }
        "deps" => {
            for f in v["files"].as_array().unwrap_or(&vec![]) {
                out.push_str(&format!("{}\n", s(&f["file"])));
                for im in f["imports"].as_array().unwrap_or(&vec![]) {
                    out.push_str(&format!("  use {} as {}\n", s(&im["path"]), s(&im["alias"])));
                }
                if let Some(t) = f["tasks"].as_object() {
                    for (k, calls) in t {
                        let c: Vec<String> = calls.as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default();
                        out.push_str(&format!("  {} -> {}\n", k, if c.is_empty() { "(no tasks)".into() } else { c.join(", ") }));
                    }
                }
            }
        }
        _ => out = serde_json::to_string_pretty(v).unwrap_or_default(),
    }
    out
}

// ---------------------------------------------------------------------------
// MCP (stdio, JSON-RPC 2.0, una línea por mensaje)
// ---------------------------------------------------------------------------

pub mod mcp {
    use super::*;

    fn rpc_error(id: Value, code: i64, message: &str) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
    }

    fn rpc_result(id: Value, result: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "result": result})
    }

    fn tools_list() -> Value {
        let tools: Vec<Value> = TOOLS
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": format!("{} {}", t.description, STATIC_NOTE),
                    "inputSchema": tool_schema(t),
                })
            })
            .collect();
        json!({"tools": tools})
    }

    /// Procesa un mensaje; `None` = sin respuesta (notificación).
    pub fn handle(root: &Root, msg: &Value) -> Option<Value> {
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let Some(method) = msg.get("method").and_then(Value::as_str) else {
            // Respuesta de un cliente (a un ping nuestro) o basura sin método.
            return if msg.get("id").is_some() && msg.get("result").is_none() && msg.get("error").is_none() {
                Some(rpc_error(id, -32600, "invalid request: missing method"))
            } else {
                None
            };
        };
        let is_notification = msg.get("id").is_none();
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        match method {
            "initialize" => Some(rpc_result(
                id,
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": SERVER_NAME, "version": crate::update::current_version()},
                    "instructions": INSTRUCTIONS,
                }),
            )),
            "ping" => Some(rpc_result(id, json!({}))),
            "tools/list" => Some(rpc_result(id, tools_list())),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                let (text, is_error) = match run_tool(root, name, &args) {
                    Ok(v) => (serde_json::to_string(&v).unwrap_or_default(), false),
                    Err(e) => (e, true),
                };
                Some(rpc_result(id, json!({"content": [{"type": "text", "text": text}], "isError": is_error})))
            }
            m if m.starts_with("notifications/") || is_notification => None,
            other => Some(rpc_error(id, -32601, &format!("method not found: {}", other))),
        }
    }

    /// Loop stdio: una línea JSON por mensaje; EOF → salida limpia.
    pub fn serve_stdio(root: &Root) -> ExitCode {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let reply = match serde_json::from_str::<Value>(trimmed) {
                Ok(msg) => handle(root, &msg),
                Err(e) => Some(rpc_error(Value::Null, -32700, &format!("parse error: {}", e))),
            };
            if let Some(r) = reply {
                if writeln!(out, "{}", serde_json::to_string(&r).unwrap_or_default()).is_err() {
                    break;
                }
                let _ = out.flush();
            }
        }
        ExitCode::SUCCESS
    }
}

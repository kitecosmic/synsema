//! E2E de `synsema code` sobre el binario real (spec `specs/code-intelligence.md`): CLI con
//! `--json`, exit codes, y el servidor MCP por stdio (initialize → tools/list → tools/call →
//! método desconocido → EOF), verificando que stdout sea SÓLO JSON, una línea por mensaje.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Manda una notificación seguida de un `ping` en la misma escritura: el server no responde
/// la notificación y sí el ping, así el flujo de lectura queda alineado.
fn ask_notify(ask: &mut dyn FnMut(&str) -> serde_json::Value, notification: &str) {
    let combined = format!("{}
{{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"ping\"}}", notification);
    let r = ask(&combined);
    assert_eq!(r["id"], 99, "la notificación no debe tener respuesta: {}", r);
}

fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synsema-code-cli-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("web")).unwrap();
    std::fs::write(
        dir.join("app.syn"),
        "intent: \"demo\"\nrequire serve(8080)\n\ntask price(o)\n    give o[\"total\"] * 2\n\ntask fetch_it()\n    let r be fetch(\"https://api.example.com/x\")\n    give r\n\ntask check(req)\n    give {\"ok\": true}\n\nserve on 8080\n    auth with check\n    route \"GET /orders/:id\"\n        give price({\"total\": 1})\n    route \"POST /orders\" requires auth\n        give fetch_it()\n",
    )
    .unwrap();
    std::fs::write(dir.join("web").join("index.html"), "<h1>Orders</h1>\n").unwrap();
    dir
}

fn run_code(dir: &PathBuf, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .arg("code")
        .args(args)
        .current_dir(dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .expect("spawn synsema code");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn outline_routes_and_search_json() {
    let dir = project("json");
    let (code, out, err) = run_code(&dir, &["outline", "--json"]);
    assert_eq!(code, 0, "{}", err);
    let v: serde_json::Value = serde_json::from_str(&out).expect("outline es JSON");
    let syms = v["files"][0]["symbols"].as_array().unwrap();
    assert!(syms.iter().any(|s| s["kind"] == "task" && s["name"] == "price"));
    assert!(syms.iter().any(|s| s["kind"] == "route" && s["name"] == "POST /orders" && s["auth"] == true));

    let (code, out, _) = run_code(&dir, &["routes", "app.syn", "--json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let rs = v["servers"][0]["routes"].as_array().unwrap();
    assert_eq!(rs.len(), 2);
    let post = rs.iter().find(|r| r["path"] == "/orders").unwrap();
    assert!(post["capabilities"].as_array().unwrap().iter().any(|c| c["cap"] == "net"));

    let (code, out, _) = run_code(&dir, &["search", "orders", "--json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let files: Vec<&str> = v["matches"].as_array().unwrap().iter().map(|m| m["file"].as_str().unwrap()).collect();
    assert!(files.contains(&"web/index.html") && files.contains(&"app.syn"), "{:?}", files);

    // Humano: tabla, no JSON.
    let (code, out, _) = run_code(&dir, &["outline"]);
    assert_eq!(code, 0);
    assert!(out.contains("task") && out.contains("price") && !out.trim_start().starts_with('{'));
}

#[test]
fn check_exit_code_and_missing_caps_warning() {
    let dir = project("check");
    // Sin `require net` → warning (no error): ok true, exit 0.
    let (code, out, _) = run_code(&dir, &["check", "--json"]);
    assert_eq!(code, 0, "{}", out);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ok"], true);
    assert!(v["warnings"].as_array().unwrap().iter().any(|w| w["message"].as_str().unwrap().contains("`net`")), "{}", out);
    // Archivo roto → error, exit 1.
    std::fs::write(dir.join("broken.syn"), "task oops(\n").unwrap();
    let (code, out, _) = run_code(&dir, &["check", "--json"]);
    assert_eq!(code, 1);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["errors"][0]["file"], "broken.syn");
    // Tool desconocida / path inexistente → exit 2.
    assert_eq!(run_code(&dir, &["nope"]).0, 2);
    assert_eq!(run_code(&dir, &["outline", "missing.syn"]).0, 2);
}

#[test]
fn mcp_stdio_round_trip() {
    let dir = project("mcp");
    let mut child = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["code", "--mcp"])
        .current_dir(&dir)
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn synsema code --mcp");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    fn ask_io(stdin: &mut std::process::ChildStdin, stdout: &mut BufReader<std::process::ChildStdout>, msg: &str) -> serde_json::Value {
        writeln!(stdin, "{}", msg).unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("stdout no es JSON: {:?} ({})", line, e))
    }
    let mut ask = |msg: &str| ask_io(&mut stdin, &mut stdout, msg);
    let init = ask(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#);
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["serverInfo"]["name"], "synsema-code");
    assert!(init["result"]["instructions"].as_str().unwrap().contains("development-time"));
    // Notificación: sin respuesta (la siguiente línea que leemos es la de tools/list).
    ask_notify(&mut ask, r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    let list = ask(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
    assert_eq!(list["id"], 2);
    let tools = list["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["outline", "symbol", "refs", "routes", "caps", "check", "search", "deps"]);
    assert!(tools.iter().all(|t| t["description"].as_str().unwrap().ends_with("never from running the program.")));
    let call = ask(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"outline","arguments":{"path":"app.syn"}}}"#);
    assert_eq!(call["result"]["isError"], false);
    let text = call["result"]["content"][0]["text"].as_str().unwrap();
    let inner: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(inner["files"][0]["file"], "app.syn");
    let bad = ask(r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"refs","arguments":{}}}"#);
    assert_eq!(bad["result"]["isError"], true);
    let unknown = ask(r#"{"jsonrpc":"2.0","id":5,"method":"resources/list"}"#);
    assert_eq!(unknown["error"]["code"], -32601);
    let ping = ask(r#"{"jsonrpc":"2.0","id":6,"method":"ping"}"#);
    assert!(ping["result"].is_object());
    drop(stdin); // EOF → salida limpia
    let status = child.wait().unwrap();
    assert!(status.success(), "exit tras EOF: {:?}", status);
    // stdout no tiene nada más que las respuestas (una por línea).
    let mut rest = String::new();
    let _ = std::io::Read::read_to_string(&mut stdout, &mut rest);
    assert!(rest.trim().is_empty(), "stdout extra: {:?}", rest);
}

#[test]
fn init_writes_mcp_json() {
    let dir = std::env::temp_dir().join(format!("synsema-code-init-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let out = Command::new(env!("CARGO_BIN_EXE_synsema"))
        .args(["init", dir.to_str().unwrap()])
        .env("SYNSEMA_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
    let mcp = std::fs::read_to_string(dir.join(".mcp.json")).expect(".mcp.json creado por init");
    let v: serde_json::Value = serde_json::from_str(&mcp).unwrap();
    assert_eq!(v["mcpServers"]["synsema-code"]["args"], serde_json::json!(["code", "--mcp"]));
}

# `synsema code` — code intelligence for agents (v0.6.13+)

Understand a Synsema repo **without reading whole files**. Everything comes from the parser —
symbols, references, the HTTP table, the capability contract, parse errors — never from running
the program. Two surfaces over the same index:

| surface | how |
|---|---|
| CLI | `synsema code <tool> [args] [--json]` — tables for humans, `--json` for scripts/agents |
| MCP | `synsema code --mcp` — a stdio MCP server named **`synsema-code`**; `synsema init` writes the `.mcp.json` that registers it, so any agent opening the folder discovers the tools by itself |

> **Not the MCP of your app.** `synsema-code` is *development-time*: it answers questions about
> the source in the current folder and never talks to a running server. (Exposing a running app
> to agents is discovery: `/openapi.json`, `/llms.txt` — see serve.md.)

The workflow that saves context: `outline` before opening a `.syn`; `routes` / `caps` before
touching a server; `refs` before renaming or changing a task; `check` after every edit;
`search` instead of reading files to find where something lives.

## Tools (same names in CLI and MCP; `path` = file or dir relative to the root, default = whole project)

| tool | returns |
|---|---|
| `outline [path]` | **Project map** when it covers more than one file: per file `intent`, `lines`, symbol counts, task/agent/route names (capped), `imports` and `imported_by` — a 58-file / 15k-line project fits in ~200 lines. One file (or `--full` / `full: true`): per `.syn`/`.fsyn`: `intent`, `requires` (cap + scope + line), `imports` (`use … as`), and every top-level symbol — `task` (params, returns, `calls`, `templates` it renders), `agent`, `type` (fields), `enum` (variants), `let`, `serve` (routes/hosts/mounts count, `static` mounts with prefix/dir/fallback, `auth_with`), `route` (`GET /x`, `auth`/`stream`/`socket`/`proxy`, `host` for vhosts, `calls`, `templates`), `test`, `invariant` — each with `line` and `end_line`. A file with a parse error reports `parse_error {line, column, message}` and keeps the rest of the repo's outline intact |
| `symbol <name> [path]` | definitions of `name` (`alias.name` resolves the module imported with `use`; a route as `"GET /orders"`) with file/line/end_line and signature |
| `refs <name> [path]` | every use across the project: `call`/`identifier`/`spawn` in the files that define it, and `module_call`/`module_ref` from every file that imports the defining module — **with whatever alias that file uses** (`refs registry` and `refs tools.registry` both find `client.registry(...)` elsewhere). Returns `defined_in` too. The definition itself is excluded |
| `routes [path]` | the table each `serve` would publish, statically: method, path, line, host, auth, stream/socket/proxy, rate limit, `expect` fields, `response` (`json`/`html`/`text`/`content`/`stream`/`socket`/`redirect`/`proxy`; inferred through the tasks the `give` calls, `with_header`/`set_cookie` unwrapped, `let`-bound values followed — `unknown` only when it truly depends on runtime), `capabilities` (transitive through the tasks it calls), `mount`ed groups included |
| `caps [path]` | `declared` (top-level `require`), `inherited_from` + `effective` (a module imported with `use` runs with the capabilities of the programs that import it — transitively — so `lib/*.syn` without `require` lines are checked against their importers, not flagged), `needed` per symbol, `missing` with the exact `require` to add. Scopes are resolved statically through the call graph: literals (`fetch("https://api.x.com/…")` → `net("api.x.com")`), top-level constants (`let base be "https://api.x.com"` … `fetch(base + "/users")`), concatenations whose prefix is known, and **parameters fed by callers** (`task get(url) … fetch(url)` called as `get("https://c.d/x")` → `net("c.d")`); `write_file("data/x")` → `file.write("data/x")`, `run("git …")` → `exec("git")`. A value that really comes from runtime (a file, `env()`, the network, the model) is checked by type only (no false alarms, but no scope check either). `require net("*.x.com")`, `require file("data")` (prefix) and `require file(...)` ⊇ `file.read`/`file.write` are understood. `time`/`llm`/`stdout` are flagged `ambient: true` (auto-granted under `synsema run`, required under `serve`/`--secure`) |
| `check [path]` | what `synsema check` does (parse + every `use` + `render("literal")` templates), over one or all files, as JSON: `errors` block (exit 1), `warnings` = the `missing` capabilities the runtime would deny (exit 0) |
| `search <pattern> [path]` | case-insensitive literal (or `--regex`) over `.syn .fsyn .html .css .js .ts .md .json .toml .txt` (`--kinds syn,html` restricts); skips `.git`, `node_modules`, `target`, `dist`, `build`, hidden dirs, binaries, files > 2 MiB; each match carries `in` (the enclosing Synsema symbol) — `--limit N` (default 200, `truncated: true` when hit) |
| `deps [path]` | task → tasks-it-calls graph per file (builtins excluded) + `use` imports |

Exit codes: `0` ok · `1` `check` found errors · `2` usage / unknown tool / path not found.
`--root <dir>` changes the root (default: cwd). Output paths are root-relative with `/`.

```sh
synsema code outline                 # the whole project, no bodies
synsema code outline app.syn --json
synsema code routes app.syn          # L23 GET /orders/:id  json  auth  caps: db
synsema code refs send_report        # app.syn:41:9  call  in route POST /reports
synsema code caps                    # MISSING net("api.x.com") — add `require net("api.x.com")`
synsema code check                   # error: b.syn:3:11: Expected ')' …   → exit 1
synsema code search "proxy to" --kinds syn
```

## MCP

`.mcp.json` (written by `synsema init`; add it by hand to older projects):

```json
{ "mcpServers": { "synsema-code": { "command": "synsema", "args": ["code", "--mcp"] } } }
```

Or: `claude mcp add synsema-code -- synsema code --mcp`. The server speaks JSON-RPC 2.0 over
stdio (one JSON line per message; stdout is protocol only, diagnostics go to stderr), advertises
the eight tools with typed `inputSchema`, returns each result as `content[0].text` (the same JSON
as `--json`), and flags tool errors with `isError: true` (bad arguments, missing path). It keeps
no index on disk: parsed files are cached in-process by mtime. Measured on a 58-file / 15k-line
project with the release binary, cold process: `outline` 0.3 s, `routes` 0.2 s, `refs`/`search`/`deps`
~0.3 s, `caps`/`check` ~0.9 s (the whole-project capability analysis; the MCP process keeps the cache
warm across calls). `SYNSEMA_CODE_TRACE=1` prints per-phase timings to stderr. EOF on stdin ends it cleanly. Unknown methods → `-32601`.

## Limits (honest)

- Static means static: `caps` cannot see a URL built at runtime (reported as `scope: null`), and a
  warning is not a guarantee the runtime will accept the program — it is the list of things the
  runtime *will* refuse.
- `use` imports resolve one level (like `synsema openapi`); `refs alias.name` crosses files only
  from the file that imports the alias.
- No LSP (editor protocol) yet — the index is what an LSP would wrap; no rename/refactor tools
  (the AST API has them; they are not exposed).

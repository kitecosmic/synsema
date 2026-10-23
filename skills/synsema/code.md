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
| `outline [path]` | **Project map** when it covers more than one file: per file `intent`, `lines`, symbol counts, task/agent/route names (capped), `imports` and `imported_by` — a 58-file / 15k-line project fits in ~200 lines. One file (or `--full` / `full: true`): per `.syn`/`.fsyn`: `intent`, `requires` (cap + scope + line), `imports` (`use … as`), and every top-level symbol — `task` (`params`, `parameters`, `input_schema`, returns, `calls`, `templates` it renders — see § Task signatures below), `agent`, `type` (fields), `enum` (variants), `let`, `serve` (routes/hosts/mounts count, `static` mounts with prefix/dir/fallback, `auth_with`), `route` (`GET /x`, `auth`/`stream`/`socket`/`proxy`, `host` for vhosts, `calls`, `templates`), `test`, `invariant` — each with `line` and `end_line`. A file with a parse error reports `parse_error {line, column, message}` and keeps the rest of the repo's outline intact |
| `symbol <name> [path]` | definitions of `name` (`alias.name` resolves the module imported with `use`; a route as `"GET /orders"`) with file/line/end_line and signature |
| `refs <name> [path]` | every use across the project: `call`/`identifier`/`spawn` in the files that define it, and `module_call`/`module_ref` from every file that imports the defining module — **with whatever alias that file uses** (`refs registry` and `refs tools.registry` both find `client.registry(...)` elsewhere). Returns `defined_in` too. The definition itself is excluded |
| `routes [path]` | the table each `serve` would publish, statically: method, path, line, host, auth, stream/socket/proxy, rate limit, `expect` fields, `response` (`json`/`html`/`text`/`content`/`stream`/`socket`/`redirect`/`proxy`; inferred through the tasks the `give` calls, `with_header`/`set_cookie` unwrapped, `let`-bound values followed — `unknown` only when it truly depends on runtime), `capabilities` (transitive through the tasks it calls), `mount`ed groups included |
| `caps [path]` | `declared` (top-level `require`), `inherited_from` + `effective` (a module imported with `use` runs with the capabilities of the programs that import it — transitively — so `lib/*.syn` without `require` lines are checked against their importers, not flagged), `needed` per symbol, `missing` with the exact `require` to add. Scopes are resolved statically through the call graph: literals (`fetch("https://api.x.com/…")` → `net("api.x.com")`), top-level constants (`let base be "https://api.x.com"` … `fetch(base + "/users")`), concatenations whose prefix is known, and **parameters fed by callers** (`task get(url) … fetch(url)` called as `get("https://c.d/x")` → `net("c.d")`); `write_file("data/x")` → `file.write("data/x")`, `run("git …")` → `exec("git")`; every chain reader/sender (`evm_*`, `solana_*`, `algorand_*`, `btc_*`, `spl_balance`) and its deprecated name (`eth_balance` needs what `evm_balance` needs) → `net` (v0.6.29+). A value that really comes from runtime (a file, `env()`, the network, the model) is checked by type only (no false alarms, but no scope check either). `require net("*.x.com")`, `require file("data")` (prefix) and `require file(...)` ⊇ `file.read`/`file.write` are understood. `time`/`llm`/`stdout` are flagged `ambient: true` (auto-granted under `synsema run`, required under `serve`/`--secure`) |
| `check [path]` | what `synsema check` does (parse + every `use` + `render("literal")` templates), over one or all files: `errors` block (exit 1); `warnings` never change the exit code (0). Since v0.6.46 the warnings are **the same ones `synsema check` prints**, each with `file` and `line` (CLI and the MCP `check` tool alike) — see § What `check` warns below. Before v0.6.46 it listed only the missing capabilities, and the lint warnings came out only from `synsema check file.syn` |
| `search <pattern> [path]` | case-insensitive literal (or `--regex`) over `.syn .fsyn .html .css .js .ts .md .json .toml .txt` (`--kinds syn,html` restricts); skips `.git`, `node_modules`, `target`, `dist`, `build`, hidden dirs, binaries, files > 2 MiB; each match carries `in` (the enclosing Synsema symbol) — `--limit N` (default 200, `truncated: true` when hit) |
| `deps [path]` | task → tasks-it-calls graph per file (builtins excluded) + `use` imports |
| `sha <file>` (v0.6.43+) | the `program_sha` that `serve --attested` / `run --attest` (and `receipt()`) bind for that entry file: `sha256(source ‖ 0x00 ‖ sha256(module_1) ‖ … ‖ sha256(module_n))`, each `use`d module once, depth first in the order the `use` lines appear. Human output is the hex alone (for scripts); `--json` → `{program_sha, modules: [{path, sha256}]}`. See attestation.md |

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

## What `check` warns (v0.6.46+)

`synsema code check [path]` and the MCP tool `check` report every warning `synsema check` prints
for the file, plus the capability analysis, over the whole project:

| warning | message (start) | fix |
|---|---|---|
| a missing capability | ``top-level needs capability `net`("api.x.com") but the program never requires it — add `require net("api.x.com")` `` | add that `require`. Its `line` is where the symbol that needs it starts (the task, or the first top-level statement after the `require` lines), not the call |
| a call to a name that exists nowhere in the file | ``\`len(...)\` — there is no task, variable or builtin named 'len' in this file; it fails when that line runs — did you mean length(x)?`` | the suggested builtin, or define the task |
| a positional `fetch` | `fetch(url, method, headers, body, timeout) is deprecated and goes away in v1 — write fetch(url, {"method": …, …})` | the options map |
| a third optional argument by position in `http`/`http_bytes`/`http_get`/`http_post`/`http_put` | `http_post() takes at most two optional arguments by position; pass timeout by name (timeout = …) — the positional form goes away in v1` | name it (`timeout = 5`) |
| a secret in the URL, query, body or form of a request, not bound to a host | ``secret("K") goes in the url of http_get() but is not bound to a host, and an unbound secret only goes in a header: write `require secret("K") for net("api.x.com")` `` | that line (secrets.md) |
| a name that shadows a module alias | ``task parameter 'l' shadows the module alias `use ... as l` (line 1) — in its scope `l.x` reads the variable, not the module; rename one of them`` | rename one |
| a missing export | ``\`l.nope\` — the module `./lib.syn` (use on line 1) does not export 'nope'; it fails when that line runs. Add `export` to it in the module, or check the name`` | `export` it, or fix the name |
| a parametric route that captures reserved URLs | `route "GET /:page" would capture /openapi.json, /docs, /llms.txt, … — the runtime serves these reserved URLs before a parametric route (v0.6.20+); declare a literal route if you really mean to override one` | a literal route, or another prefix |

Human output: one `warning: <file>:<line>: <message>` per line, then
`OK: <n> file(s), 0 error(s), <k> warning(s)` (exit 0) or `FAILED: …` (exit 1, an error such as a
parse error or `module not found`). `--json` (and the MCP result's `content[0].text`):

```json
{ "ok": true, "files": 1, "errors": [],
  "warnings": [ { "file": "app.syn", "line": 5, "column": 0, "message": "`len(...)` — there is no task, …" } ],
  "declassify": [ { "file": "app.syn", "line": 9, "column": 20, "reason": "ok", "to": null, "constant": false } ] }
```

`errors` have the same `{file, line, column, message}` shape; `declassify` is the inventory of
every `declassify` call (labels.md). A warning is a fact about the source, not a guarantee: a
program with no warnings can still fail at run time.

## Task signatures in `outline --json` (v0.6.46+)

Each `task` symbol of a one-file outline (or `--full`, or MCP `outline` with `full: true`) carries,
next to `params` (the names, unchanged):

- `parameters` — one entry per parameter, in order: `name`, `type` (`"text"`, `"number"`,
  `"bool"`, `"list"`, `"map"`, or `null` when the parameter has no type), `required` (`true` when
  it has no default) and `default` — present only when the default is a literal (a number, a
  text, a bool, `nothing` → `null`, a list or a map of literals, `-1`); a computed default
  (`n = 1 + 2`) has no `default` key.
- `input_schema` — the signature as JSON Schema: `{"type": "object", "properties": {…},
  "required": [the parameters without a default]}`; each property has `type` (`string`,
  `number`, `boolean`, `array`, `object`) when the parameter is typed and `default` when it is a
  literal other than `nothing`. An untyped parameter is `{}`.

```text
task estado(id: text, items: bool = false, note = nothing)
→ "parameters": [ {"name": "id", "type": "text", "required": true},
                  {"name": "items", "type": "bool", "required": false, "default": false},
                  {"name": "note", "type": null, "required": false, "default": null} ]
  "input_schema": {"type": "object", "properties": {"id": {"type": "string"},
                   "items": {"type": "boolean", "default": false}, "note": {}}, "required": ["id"]}
```

The project map (more than one file, without `--full`) lists only task names. Agents are listed
without their tasks. The text output (`synsema code outline file.syn`) shows the names only. The
parameter types themselves (what they check, `tool_spec`) are in types.md / llm.md.

## MCP

`.mcp.json` (written by `synsema init`; add it by hand to older projects):

```json
{ "mcpServers": { "synsema-code": { "command": "synsema", "args": ["code", "--mcp"] } } }
```

Or by command: `claude mcp add synsema-code -- synsema code --mcp` (Claude Code),
`codex mcp add synsema-code -- synsema code --mcp` (Codex); opencode takes `{"mcp": {"synsema-code": {"type": "local", "command": ["synsema", "code", "--mcp"]}}}`
in `opencode.json`. The server speaks JSON-RPC 2.0 over
stdio (one JSON line per message; stdout is protocol only, diagnostics go to stderr), advertises
the nine tools with typed `inputSchema`, returns each result as `content[0].text` (the same JSON
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

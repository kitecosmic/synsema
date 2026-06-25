# Synsema Pitfalls — Common Errors and Solutions

Read this FIRST if something fails. Each row is a real mistake that costs hours to debug.

## Errors

| Error message | Cause | Solution |
|---|---|---|
| `Unterminated string` | Literal newline inside `"..."` | Use `\n` escape. Strings are single-line only. |
| `Capability not granted: file_write(...)` | Missing `require` or scope too narrow | Add `require file("/path/*")` at top of program |
| `Capability not granted: net(...)` | Missing `require` for the domain | Add `require net("domain.com")` |
| `Invalid memory category: 'preferencia'` | Categories are English-only | Use exactly: `preference`, `rule`, `learning`, `decision`, `context` |
| `No agent defined with name 'X'` | `spawn X` before `agent X` definition | Define the agent before spawning it |
| `Division by zero` | Divisor is 0 | Guard with `when divisor != 0` or use `try/recover` |
| `Cannot iterate over number` | `each` on a non-list value | Check type with `type_of()` or wrap in `[value]` |
| `Map has no key 'X'` | Accessing a property that doesn't exist | Check with `contains(map, "X")` first |
| `Cannot set undefined variable` | Using `set` before `let` | Define with `let x be value` first, then `set x to new_value` |
| `Loop exceeded maximum iterations` | Infinite loop (condition never false) | Check that loop variable actually changes |
| `Expected indented block` | Missing indentation after when/each/task/etc | Indent body with 4 spaces |
| `'while' is a reserved word in Synsema` | Using a hard keyword as a name | Pick another name. (HTTP words like `route`/`auth` ARE allowed as names — they're soft keywords.) |

## HTTP server (serve)

### Errors

| Error message | Cause | Solution |
|---|---|---|
| `serve on 8080 is not permitted: missing capability serve(8080)` | No `require serve(PORT)` | Add `require serve(8080)` at the top |
| `route "..." uses 'requires auth' but ... no 'auth with'` | A route has `requires auth` but the block has no auth task | Declare `auth with <task>` in the `serve` block |
| `send can only be used inside a stream` | `send` used outside a `stream` block | Put `send` inside a route's `stream` block |
| `500` from a route using `paged(...)` | Your query has its own `LIMIT`/`;` | Remove them — `paged()` adds `LIMIT`/`OFFSET`; the runtime owns pagination |
| `503 too many concurrent streams` | Open SSE streams > `max_streams` | Raise `max_streams N`, or shorten streams (each holds a thread) |
| `429 rate limit exceeded` | More requests than `rate_limit` allows for that IP | Slow down, or raise/relax the route's `rate_limit` |
| `413 payload too large` | Request body over `max_body` (default 1 MB) | Raise `max_body "10mb"`, or stream large uploads |

### Behavioral surprises

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `give sql("... LIMIT 10")` reports `total: 10` | `give <list>` paginates what you return; `total` = what you gave | Return the full collection (no `LIMIT`). For big tables use `paged()` |
| `give <list>` of a huge table is fine | Loads the whole collection into memory per request | Use `paged("SELECT ...")` — `LIMIT`/`OFFSET` pushdown + exact `COUNT(*)` |
| `rate_limit 100 per minute` on the block = 100 per route | It's 100/min per IP **shared** across all routes using the default | For independent budgets, set `rate_limit` per route (own zone) |
| No `rate_limit` and I'm already protected | No — rate limiting is **opt-in** | Declare `rate_limit` on the block and/or sensitive routes |
| `read_body()` returns binary intact | Decodes as UTF-8 (lossy for binary) | Use `read_body_bytes()` for byte-exact binary uploads |
| A reverse-proxy forwards a binary upstream/downstream body intact | The proxy path is still UTF-8-lossy | Known limitation; don't rely on `proxy to` for binary yet |
| A `stream` route also runs `give` | `stream` and `give` are mutually exclusive | A route either streams (with `send`) or gives — not both |
| POST with invalid JSON is silently ignored | With `Content-Type: application/json` it's a `400` | Send valid JSON, or omit the JSON content-type to get the raw body |
| `serve on PORT` returns and the program exits | The CLI keeps the process alive while servers run (Ctrl+C to stop) | Expected; the server runs in the background |
| `X-Forwarded-For` sets the client for rate limiting | The real peer IP is used; XFF is ignored | XFF is forgeable; trusted-proxy/per-user keying is future work |
| `give "<h1>Hi</h1>"` renders as an HTML page | It's JSON — the response is the quoted string `"<h1>Hi</h1>"` | Use `html("<h1>Hi</h1>")` (or `respond(...)`) for a real page |
| `static "./public"` also needs `require file(...)` | No — the `static` declaration **is** the read permission for that dir | Just declare `static "./public"`; the path is relative to the working dir |
| `cors "*"` works with `Authorization`/cookies | The CORS spec forbids `*` for credentialed requests | Use a specific origin: `cors "https://app.example.com"` |
| A static file shadows my declared route | Declared routes always win; static is only the fallback | Expected — rename the file or the route if you really want the file |
| A catch-all `*path` swallows a more specific route | Precedence is by specificity, not order: exact > `:param` > `*catchall` | Expected — the exact/`:param` route wins even if declared after the catch-all |
| `route "GET /files/*path"` matches bare `/files` | A catch-all needs ≥1 segment to capture | Add `route "GET /files"` if you want to handle the bare path |
| Two `static "./a"` / `static "./b"` (both root) | Silent shadowing is now a startup **error** | Mount one under a prefix: `static "/b" from "./b"` |
| `*rest` not the last path segment | Parse error — a catch-all must be last | Put `*name` as the final segment: `/files/*path` |
| User HTML in a `content()` page renders as a live tag | `content()` HTML **auto-escapes** all text (XSS-safe) | That's the point; use `raw(html)` to embed trusted HTML on purpose |
| `/blog/hola.json` runs `:slug` = "hola.json" | The `.md`/`.json`/`.html` suffix is stripped first; slug is "hola" | Expected for `content()` routes; a real `hola.json` file or a literal route wins |
| `Accept: text/markdown` changes my JSON/`{map}` route | Negotiation applies **only** to `content()` values | Wrap the tree in `content(...)`; plain `give {map}` is always JSON |
| `give heading(...)` renders an HTML heading | Without `content()` a node degrades to its **JSON** form | Wrap the tree in `content(page([...]))` to get HTML/Markdown |
| My internal server exposes `/llms.txt` with all its routes | `/llms.txt` + `/robots.txt` are ON by default (agent-discoverable) | Add `private` to the serve block: `/llms.txt` → 404, robots `Disallow: /` |
| `describe`/`private` can't be used as variable names | They're soft keywords — only special in a serve block | `let private be 1` and `let describe be x` are still valid |
| CSS `body { }` in a `render()` template breaks | `{`/`}` are template hole delimiters | Put CSS/JS in external files served by `static`; literal brace via `{ "{" }` |
| User HTML in `{ expr }` renders as a live tag | `render()` auto-escapes every hole (XSS-safe) | Use `{ raw expr }` for trusted HTML on purpose |
| `render("/etc/passwd", ...)` reads any file | Template paths are cwd-relative; escaping the cwd is blocked | Keep templates under the project; absolute/`..` paths error |
| `{ type }` in a template fails ("reserved word") | A single-name hole is a direct data lookup — reserved words work | Just use `{ type }`; the field resolves from the data |
| A typo in a `render("x.html")` path only fails on first request | `render("literal")` templates are validated **at startup** (fail-fast) | Fix the path/syntax; the program won't start until it's valid |
| My `500` leaks a stack/message in production | Detail is shown in **dev**; `--secure` returns a generic body | Run with `--secure` in prod; the full detail still goes to the server log |

### Anti-patterns

| Pattern | Problem | Better approach |
|---|---|---|
| `give sql(...)` for a large table | Loads everything into memory each request | `paged()` for anything that can grow |
| Trusting `X-Forwarded-For` for identity | Rate limit uses the real peer IP (XFF is forgeable) | Don't trust XFF; per-user/trusted-proxy is future work |
| `give <list>` with `LIMIT` in your SQL | `total` becomes wrong (it counts only what you returned) | Return the full list, or use `paged()` |
| Long-lived SSE streams with default `max_streams` | Each holds a thread; you hit `503` under load | Size `max_streams` to your thread budget; keep streams short |

## Language features — bytes, complex, arrays, match, params, tests

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `text(bytes(...))` decodes to a string | Shows a hex repr like `bytes(48656c6c6f)` | By design (non-lossy). Use `decode(b)` to get the text (UTF-8 strict). |
| `decode(b)` on non-UTF-8 returns garbage | It **errors** (UTF-8 is strict by default) | Use `decode(b, "utf8_lossy")` to replace invalid bytes with `U+FFFD` |
| `bytes("abc") == "abc"` | `false` — bytes never equals text | Compare `decode(b) == "abc"` instead |
| `sqrt(-1)` returns a complex number | Returns `NaN` (real math is unchanged) | Use `sqrt(complex(-1, 0))` → `complex(0,1)` for the complex root |
| `complex(1,0) < complex(2,0)` works | Error: "complex numbers are not ordered" | Complex has no ordering (like Python). Compare `abs(z)` if you need magnitude. |
| `array * array` is the matrix product | It's **elementwise** (Hadamard) | Use `matmul(a, b)` (or `dot`) for the matrix product. `*` is elementwise. |
| `inv`/`solve` of a singular matrix returns NaN | It **errors** (no silent NaN) | Check `det(A)` first, or `try/recover` |
| Linear algebra works on n-D arrays | LA (`solve`/`det`/`eig`/`svd`) is **2D only** | Reshape to 2D; n-D is for storage/vectorized math (like `numpy.linalg`) |
| An array holds ints/strings | Arrays are **f64** only (this version) | Use a `list` for mixed/other types; `to_list(a)` converts back |
| `match x is {}` matches an empty map | Matches **any** map (`{}` is a map pattern) | To match an empty map use a guard: `is m when length(m) == 0` |
| `match x is myvar` binds `myvar` | Top-level `is myvar` **compares** against the value of `myvar` (does NOT bind) | Binders live only inside `[...]`/`{...}`/variant patterns and `_`. To always match, use `is _`. |
| `match x is {status}` works on a serve response value | Map patterns match plain `map` values, not server response values | Match the underlying map, or check fields with `of` |
| `f(1)` to `task f(a, b)` errors (missing arg) | `b` becomes `nothing` (permissive arity) | Give `b` a default: `task f(a, b = 0)`; or pass it. |
| `f(x = 1)` and `f(x == 1)` are the same | `=` is a **named arg**; `==` is an equality expression passed positionally | Use `=` for named args/defaults, `==` for comparison |
| `test "..."` blocks run under `synsema run` | They're **skipped** by `run`; only `synsema test` runs them | Run `synsema test file.syn`. See [testing.md](testing.md). |
| `assert_error(() => give 5)` passes | A `give` is not an error → it **fails** | `assert_error` passes only if the function raises a runtime error |
| `try/recover` lets the error bubble up | `recover` **swallows** it — the task/agent ends normally (DONE) | To re-propagate, call `raise(err)` inside `recover` (agent ends ERROR). `fail()` is HTTP-only, not for this. |
| `signal "x:" + text(id)` must be a literal | The channel name is an **expression** — dynamic names work | Use `signal`/`wait_for` with a computed name for per-job channels (see agents.md) |

## Behavioral surprises

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| String on multiple lines | `Unterminated string` error | Use `\n` or concatenate: `"line1\n" + "line2"` |
| `remember("preferencia", ...)` works | Error: invalid category | Categories are English: `preference`, `rule`, `learning`, `decision`, `context` |
| `intent: "..."` restricts what the program can do | No — the intent is descriptive only | Security is enforced by capabilities (`require`), in any language. The intent text never blocks. |
| `wait_for` wakes all waiters on one `signal` | Only ONE waiter gets it | Signals are a queue (consumed on read). For fan-out, emit N signals or use blackboard. |
| `wait_for` hangs forever on dead agent | Returns `nothing` quickly | The runtime detects no alive agents and returns. But only if ALL agents are dead. |
| Agent shares state with main program | Each agent has its own interpreter | Use `share`/`observe` via blackboard to communicate. |
| `number("1200")` gives integer | Gives `1200.0` (float) | `text()` on integers shows no decimal. Use `text(number(...))` for display. |
| `/tmp/file.txt` works on Windows | Maps to `C:\tmp\file.txt` | Use absolute paths. For agent data, use `~/.synsema/` paths. |
| Cron output appears after program ends | Output is buffered | Fixed in recent versions. Update to latest. Use `synsema serve` to keep the process alive for live output. |

## Anti-patterns

| Pattern | Problem | Better approach |
|---|---|---|
| No `try/recover` around HTTP/SQL/LLM | Agent dies on first network error | Wrap I/O in `try/recover` with fallback |
| Relying on the `intent:` text to restrict actions | The intent doesn't authorize anything | Declare permissions with `require`; the intent is only a description |
| One `signal` for N consumers | Only one gets it | Use blackboard keys per worker, or emit N signals |
| `share x as "result"` from N workers | Last write wins, others lost | Use dynamic keys: `share x as "result_" + text(n)` |
| No `require` and wondering why I/O fails | Zero-access-by-default | Always declare `require` at top of program |
| `set x to 5` without prior `let x be ...` | Runtime error | Always `let` before `set` |

## Secrets & config (see [secrets.md](secrets.md))

| Pattern | Problem | Better approach |
|---|---|---|
| Using `reveal()` to "get the value" | Defeats the whole point; it's loud and audited | Use `bearer()`/`hmac_sha256()`/`verify_hmac()`/`constant_time_eq()` — they consume the secret without exposing it. `reveal` is a last resort. |
| Committing `.env` | Leaks real secrets into git history | `.gitignore` the `.env`; commit a `.env.example` with keys (no values) |
| `print(my_secret)` to debug | You only ever see `secret(NAME)` (redacted by design) | That's expected — secrets never print their value. If you truly need the value, `reveal()` (audited). |
| `secret("X")` without `require secret("X")` | `secret("X") not permitted: missing capability` | Add `require secret("X")` (or a `require secret("X_*")` prefix). Same for `env`. |
| Comparing a secret with `==` in a loop over guesses | Fine — `==` on a secret is constant-time | For HMAC/signature checks use `verify_hmac` (also constant-time) |
| Expecting `env("X")` to return `nothing` when unset | It raises a clear error (fail-loud) | Pass a default: `env("X", "devvalue")`, or set it in `.env`/the environment |
| Putting a secret in a query param or JSON body | Redacted (fail-closed) → the upstream gets `secret(NAME)` | Send credentials via a header: `{"Authorization": bearer(secret("KEY"))}` |

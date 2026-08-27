# Synsema Pitfalls — Common Errors and Solutions

Read this FIRST if something fails. Each row is a real mistake that costs hours to debug.

> **Jump to the `## ` section that matches your failure:** Errors (parse/runtime messages) ·
> Database SQL · Database MongoDB · Database Redis · HTTP server (serve) · Language features
> (bytes, complex, arrays, match, params, tests) · Data & charts · Blockchain ·
> Behavioral surprises · Anti-patterns · Secrets & config
> Coming from Python? The traps that LOOK like Python but aren't are also collected in
> [python-diff.md](python-diff.md).

## Errors

| Error message | Cause | Solution |
|---|---|---|
| `Unterminated string` | Literal newline inside `"..."` | Use `\n` escape. Strings are single-line only. |
| `Capability not granted: file_write(...)` | Missing `require` or scope too narrow | Add `require file("/path/*")` at top of program |
| `Capability not granted: net(...)` | Missing `require` for the domain | Add `require net("domain.com")` |
| `Invalid memory category: 'preferencia'` | Categories are English-only | Use exactly: `preference`, `rule`, `learning`, `decision`, `context` |
| `Capability not granted: memory` on `remember`/`recall`/`add_rule`/`create_progress` | Persistent state is opt-in: the program declares no memory (it is NOT auto-granted, even under `run`) | Add `require memory("<name>")` at the top — the name keys `<dir>/.synsema/state/<name>.db` ([memory.md](memory.md)) |
| `require memory needs a name` (parse error) | Bare `require memory` — a declaration with no name has no identity (no `.db` to open) | Give it a name: `require memory("my-agent")` (`[a-zA-Z0-9_-]+` only) |
| `Multiple memory declarations` at startup | Two `require memory` with different names — a program has exactly ONE declared memory | Keep one declaration (two entry files that DECLARE THE SAME name share one memory) |
| Old memory "disappeared" after upgrading | Identity moved from file-stem to the **declared name**; a warning on stderr names the old `.db` and the exact line to add | Add `require memory("<old-stem>")` to keep the same file, or rename the `.db` to the new declared name |
| `remember` in one agent, `recall()` in another finds nothing | `recall()` inside an agent defaults to its OWN namespace (`source` = agent name) | Cross explicitly: `recall(from = "writer")`, or `from = "*"` for everything ([memory.md](memory.md)) |
| `No agent defined with name 'X'` | `spawn X` before `agent X` definition (the error lists the agents the context DOES know) | Define the agent before spawning it. If the error says "no agents are defined in this execution context" and your agent IS defined top-level, that's the runtime, not your code — on engine ≤ v0.4.9, `spawn` inside a route fails from the 2nd request on a reused serve worker (fixed in v0.5.0; workaround: spawn a long-lived worker at boot and enqueue via `signal`) |
| `Division by zero` | Divisor is 0 | Guard with `when divisor != 0` or use `try/recover` |
| `Cannot iterate over number` | `each` on a non-list value | Check type with `type_of()` or wrap in `[value]` |
| `Map has no key 'X'` | Accessing a property that doesn't exist | Check with `contains(map, "X")` first — in a **separate/nested `when`**, NOT `contains(m,"X") and m["X"]…`: `and` does not short-circuit, so the index still runs |
| `contains(m,"k") and m["k"] == v` errors anyway | **`and`/`or` never short-circuit** — both sides always evaluate | Nest: `when contains(m, "k")` … then index inside. Same for `or`: don't rely on it to skip a side effect |
| `raise "msg"` does nothing (no error raised) | **Engine ≤ v0.5.1**: without parens it parsed as TWO inert expressions — a silent no-op | Upgrade (newer engines accept the statement form `raise "msg"` / `raise err`, and a bare `raise` errors loudly); on old binaries always `raise("msg")` |
| `'decide' is a reserved word` naming an export/member (older engines: `Expected IDENTIFIER, got DECIDE`) | A hard keyword used as an export/member/param name — `mod.decide(...)`, `task wait(reason)` | LLM words `reason`/`decide`/`analyze`/`generate` are reserved everywhere; rename (`resolve`, `why`) — see [syntax.md](syntax.md) |
| `Cannot set undefined variable` | Using `set` before `let` | Define with `let x be value` first, then `set x to new_value` |
| `Loop exceeded maximum iterations` | Infinite loop (condition never false) | Check that loop variable actually changes |
| `Expected indented block` | Missing indentation after when/each/task/etc | Indent body with 4 spaces |
| `'while' is a reserved word in Synsema` | Using a hard keyword as a name | Pick another name. (HTTP words like `route`/`auth` ARE allowed as names — they're soft keywords.) |

## Database — SQL (SQLite / Postgres / MySQL)

One universal API (`db_open`/`sql`/`sql_exec`/…) routed by the `db_open` target: a file path → SQLite,
`postgres://…` → Postgres, `mysql://…` → MySQL. (MongoDB is a separate document API, Redis a separate
key-value API — see below.) Use `?` placeholders everywhere.

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `require db("postgres://user:pw@host:5432/appdb")` is the scope | Credentials/port/query are stripped: scope is `postgres://host/appdb` | Grant the **canonical URL** `db("postgres://host/appdb")` (same for `mysql://`). A path scope never covers a URL |
| `sql_exec(INSERT)` returns the new id on Postgres | Postgres `last_id` is always `0` | Use `INSERT … RETURNING id` and read it from `sql(...)`. (MySQL `last_id` = `last_insert_id()`, real; SQLite = rowid) |
| Postgres connects without TLS by default | TLS is **on** by default | Add `?sslmode=disable` for plaintext (e.g. local dev) |
| MySQL connects with TLS by default | MySQL TLS is **opt-in** (plaintext default) | Add `?ssl-mode=REQUIRED` to enable rustls TLS |
| `db_open("postgres://deadhost/db")` hangs | A 10s connect-timeout applies, then errors | Expected: a dead host fails fast, never hangs the agent |
| A `BLOB`/`BYTEA` column round-trips as text | It returns `bytes` (`type_of` "bytes"); `decode()` for text | Binary is byte-exact — use `bytes(...)` to insert, `decode(...)` to read text |
| `DECIMAL`/`NUMERIC` comes back as a float | It's a `decimal` (`type_of` "decimal"), exact | Keep it as `decimal` for money; don't coerce through float |
| `?` in a Postgres query must be `$1` | The runtime rewrites `?`→`$n` for you (MySQL uses `?` natively) | Just write `?` everywhere; for pgvector pass a list as `?::vector` |
| A SQL trigger can call a Synsema task (e.g. re-embed on INSERT) | Triggers run inside the database — they can NEVER call back into your program | Keep the write-path in ONE task (e.g. `insert_product` that also updates the vector table) and use it everywhere; triggers are fine for SQL-only sync (like FTS5 external-content) |

## Database — MongoDB (document store, `mongo_*`)

`db_open("mongodb://…")` then `mongo_find`/`mongo_insert`/… — **not** `sql()`. Filters and docs are
Synsema maps ↔ BSON.

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `sql("SELECT …")` works on a Mongo connection | Errors: "this is a MongoDB connection — use mongo_*" | Use `mongo_find`/`mongo_aggregate`/etc. (and `mongo_*` on a SQL connection errors symmetrically) |
| `mongo_update(c, filt, {"age": 31})` sets age | Mongo rejects a plain doc as the update | Use an operator: `{"$set": {"age": 31}}` (also `$inc`, `$push`, …) |
| `mongo_find(c, {"_id": "<hex>"})` finds nothing | Without coercion a string ≠ ObjectId | The runtime coerces a 24-hex string under `_id` (incl. in `$in`) to an ObjectId — pass the hex you got back from `mongo_insert` |
| `"price": 9.99` stores an exact decimal | `9.99` is a **float** → BSON Double → reads back `number` | Use a decimal literal `9.99d` (or `decimal("9.99")`) → BSON Decimal128 → reads back `decimal` |
| `require db("mongodb://u:p@host:27017/appdb?authSource=admin")` is the scope | Credentials/port/query stripped: scope is `mongodb://host/appdb` | Grant the canonical URL `db("mongodb://host/appdb")` |
| `db_open("mongodb://…")` is lazy and always succeeds | It pings on open — a dead host / bad auth fails there (within 10s) | Expected: connectivity is validated at `db_open`, like the SQL backends |
| `mongo_insert` returns the doc | It returns the new `_id` (text hex for ObjectId) | Read it back with `mongo_find_one(c, {"_id": id})` |

## Database — Redis (key-value/cache/structures, `redis_*`)

`db_open("redis://…")` then `redis_get`/`redis_set`/`redis_hset`/… — **not** `sql()` or `mongo_*`. Values are
byte-strings (text/bytes/number); structured data goes via `json_encode`/`json_decode`.

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `sql("SELECT …")` works on a Redis connection | Errors: "this is a Redis connection — use the redis_* builtins" | Use `redis_*` (and `redis_*` on a SQL/Mongo connection errors symmetrically) |
| `require db("redis://localhost")` covers `db_open("redis://localhost:6379/0")` | **No** — `:6379` (no path) → scope `redis://localhost`, but `/0` → scope `redis://localhost/0` (different) | Match the `require db(...)` form to `db_open(...)` exactly: no `/N` ⇒ no db in the scope; `/0` ⇒ `/0` in the scope |
| `redis_set(k, {"a": 1})` stores the map | Errors: redis values must be text/bytes/number | Serialize: `redis_set(k, json_encode({"a": 1}))`, read with `json_decode(redis_get(k))` |
| `redis_get` of UTF-8 data returns `bytes` | Returns `text` if the bytes are valid UTF-8, else `bytes` | Binary-safe heuristic; raw/non-UTF8 values round-trip as `bytes` byte-exactly |
| `redis_unlock(k)` frees the lock | It needs the **token** from `redis_lock` and only frees if it still matches | Keep the token: `let t be redis_lock(k, ttl)`; `if t != nothing` … `redis_unlock(k, t)`. A 2nd `redis_lock` on a held key returns `nothing` |
| `redis_lock` blocks until the lock is free | Non-blocking: returns `nothing` immediately if held | Check the return; the TTL auto-releases if the holder dies (single-node Redlock, not multi-node) |
| `redis_keys("*")` is fine in prod | `KEYS` is O(N) — scans the whole keyspace | Use a bounded pattern (`user:*`); a non-blocking `redis_scan` may come later |

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
| `request` works inside a helper task called from a route | `Undefined variable: 'request'` — `request`/`query`/`params` exist ONLY in the handler's scope (the error says so) | Pass it as a parameter: `task handle(request)` and call `handle(request)` from the route |
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
| My internal server exposes `/llms.txt` with all its routes | `/llms.txt`, `/robots.txt`, `/sitemap.xml`, `/openapi.json` and `/docs` are ON by default (agent-discoverable) | Add `private` to the serve block: the generated documents → 404, robots `Disallow: /` (`docs off` removes only the `/docs` page) |
| `/openapi.json` shows no `requestBody` for my route | Only a **top-level** `expect body` in the route is a contract; one inside a `when` is a branch | Move the `expect` to the top of the route body |
| I declared `route "GET /docs"` and the API page vanished | Your route/static file wins over every generated document (`/llms.txt`, `/openapi.json`, `/docs`…) | Intended; rename your route, or use `docs off` if you only wanted the page gone |
| `/sitemap.xml` lacks `/blog/:slug` | Parametric routes are never expanded (the runtime can't know the slugs); auth/stream/proxy routes are excluded too | Expected — declare literal routes for pages you want listed |
| `x-synsema-capabilities` lists `net` for a route that never called `fetch` | It's static: the `require` of every task the route may call, transitively, plus builtin implications | Expected — it's the contract, not a trace; the runtime still gates each call |
| `this host provides no audit sink for sign.log` (wasm) | `sign`/`spend`/`wallet`/`reveal` need an audit line; a wasm host has no files | Offer `kv` to the embedded runtime — the line lands in `kv` under the `audit` namespace |
| `synsema openapi` exits 2 | The file has no `serve` block (or the path is missing) | Point it at the entry file that serves |
| `describe`/`private`/`docs` can't be used as variable names | They're soft keywords — only special in a serve block | `let private be 1`, `let docs be 2` and `let describe be x` are still valid |
| CSS `body { }` inline in a `render()` template breaks | `{`/`}` are template hole delimiters | Wrap the CSS/JS block in `{ raw }` … `{ end }` (verbatim), or serve it from `static`; single literal brace via `{ "{" }` |
| `<script>const D = { raw json_encode(x) };</script>` is safe | It's XSS — a value containing `</script>` breaks out of the tag | Use `{ raw json_for_script(x) }` (escapes `<`/`>`/`&` as `\u00XX`) |
| User HTML in `{ expr }` renders as a live tag | `render()` auto-escapes every hole (XSS-safe) | Use `{ raw expr }` for trusted HTML on purpose |
| `render("/etc/passwd", ...)` reads any file | Template paths are cwd-relative; escaping the cwd is blocked | Keep templates under the project; absolute/`..` paths error |
| `{ type }` in a template fails ("reserved word") | A single-name hole is a direct data lookup — reserved words work | Just use `{ type }`; the field resolves from the data |
| `{ include "partials/nav.html" }` inside `pages/home.html` looks in `pages/partials/` | Include/layout paths resolve against the **working dir**, not the including template | Write all template paths from the project root (`partials/nav.html` everywhere) |
| `{ fmt(x) }` in a template → `Undefined variable` under serve | The task was defined **after** the `serve` block — the per-request snapshot is taken there | Define tasks **before** `serve on`; then they're callable in holes |
| `{ each x in m }` over a map iterates entries | Hard error (`Cannot iterate over map`) | Iterate `{ each k in keys(m) }`; for indexes use `enumerate(list)` |
| Editing a template/CSS needs a server restart | Templates & statics hot-reload **per request** (mtime-based) | Just refresh the browser; only `.syn` changes need a restart (`serve --watch` automates it) |
| A typo in a `render("x.html")` path only fails on first request | `render("literal")` templates are validated **at startup** (fail-fast), and by `synsema check` | Fix the path/syntax; the program won't start until it's valid |
| `f.email` on a form without that field gives nothing | A missing map key is a hard error (`Map has no key`) | Check first: `contains(keys(f), "email")` |
| A CRLF (Windows) file with blank lines inside a block fails to parse | Fixed — blank `\r\n` lines no longer emit a phantom dedent (engine > v0.5.9) | Update the binary if you see `Unexpected token: INDENT` on a CRLF file |
| My `500` leaks a stack/message in production | Detail is shown in **dev**; `--secure` returns a generic body | Run with `--secure` in prod; the full detail still goes to the server log; an `errors with` task receives the redacted message under `--secure` |
| A slow handler is cut off after 30 s | Only if you declared `timeout` — **by default there is no limit** | `timeout N` on the serve block / `timeout none` per route; at the deadline: `504` + the handler is cancelled (v0.6.7+) |
| `try`/`recover` around a cancelled wait keeps the handler alive | Cancellation (`cancelled: …`) is observable but not curable — the next statement raises again | Clean up in `recover` and leave; kill/close what you own |
| `timeout 30` inside a `when` / a task | Runtime error: it is a clause of the serve block or the top of a route body | Move it to the top of the route body (once) or to the serve block |
| Opening a WebSocket to a `socket` route returns 426 | The request lacked the upgrade headers (or came over HTTP/2) | Use a real WebSocket client (`new WebSocket(url)`, `ws_connect`); the browser does it right |
| A `socket` route declared as `POST` | Parse error — the handshake is a GET (RFC 6455) | `route "GET /ws"` + `socket` |
| A `socket` handle stored in `state_*` to push from a cron | Handles don't cross requests (isolation) | Each socket handler subscribes to the bus (`bus_subscribe`) and forwards; the cron does `bus_publish` |
| My SSE clients need a "ping" event so proxies don't cut them | The server already writes `: keepalive` every 15 s idle (`SYNSEMA_SSE_KEEPALIVE`) | Drop the ping loop; keep `bus_recv(sub, 25)`-style bounded waits |
| Ctrl-C kills in-flight requests instantly | It drains: no new connections, streams/sockets cancelled, sized requests get `SYNSEMA_SHUTDOWN_GRACE` (10 s), exit 0 | Second Ctrl-C = exit 130 now; `SYNSEMA_SHUTDOWN_GRACE=0` for immediate |
| `give agents()` returns `{"items": …}` | `give <list>` always paginates | Expected — read `items`; or `give {"agents": agents()}` |

### Anti-patterns

| Pattern | Problem | Better approach |
|---|---|---|
| `give sql(...)` for a large table | Loads everything into memory each request | `paged()` for anything that can grow |
| Trusting `X-Forwarded-For` for identity | Rate limit uses the real peer IP (XFF is forgeable) | Don't trust XFF; per-user/trusted-proxy is future work |
| `give <list>` with `LIMIT` in your SQL | `total` becomes wrong (it counts only what you returned) | Return the full list, or use `paged()` |
| Long-lived SSE streams with default `max_streams` | Each holds a thread; you hit `503` under load | Size `max_streams` to your thread budget; keep streams short |

### Web auth (cookies, passwords, JWT, TOTP)

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `sha256(pw)` is fine for passwords | Fast hashes are crackable offline at GPU speed | ALWAYS `password_hash`/`password_verify` (argon2id, salted, tuned). `sha256`/`hmac_sha256` are for integrity, never for passwords |
| `set_cookie(..., {"same_site": "None"})` just works | Error: `SameSite=None` requires `secure: true` | Browsers reject SameSite=None cookies without `Secure` — the builtin fails at write time instead of you debugging a cookie that "never arrives" |
| Cookies work on `http://localhost` despite the `Secure` default | They DO — localhost is a secure context in modern browsers | If something odd remains, `{"secure": false}` in dev ONLY; never ship it |
| `totp(secret("TOTP_B32"))` with a base32 secret | The text is taken as raw UTF-8 → wrong codes | The classic TOTP confusion: decode first — `totp(bytes(seed_b32, "base32"))` |
| Any value can go in a cookie | RFC 6265 forbids spaces, quotes, `;`, `,`, `\` | Encode it: `set_cookie(resp, "v", decode(bytes(v), "base64url"))` (the error message says so) |
| `cors "*"` + cookie sessions | The CORS spec forbids `*` for credentialed requests | Use a specific origin: `cors "https://app.example.com"` |
| `jwt_verify` tells you WHY a token failed | It returns `nothing` for every failure (signature/exp/malformed) | By design: an endpoint must not be distinguishable by rejection cause. Log the attempt server-side if you need forensics |
| `token(8)` for a short session id | Error: minimum is 16 bytes | Fewer than 16 bytes of entropy is guessable; the default 32 is right for sessions |
| `token()`/`random_bytes()` work without a `require` | Capability error: `random` not granted | Randomness is deny-by-default, same gate as `random()` — add `require random`. The pure transforms (`password_hash`/`jwt_*`/`totp*`) need nothing |
| `totp_verify(seed, 094287)` (code as number) | Error: the code must be text | Leading zeros matter — quote the code |
| Store the PAT/API key as-is in the DB | A DB leak leaks every live credential | Store `sha256(token)`, compare hashes with `constant_time_eq` |

### Spend ledger — units

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| The ledger is for money, so amounts are cents-sized | The unit is **free text and no currency is privileged** — fiat, crypto, commodities, credits, kWh | `spend(0.000000000000000001, "ETH", …)` (a wei) and `spend(1500, "JPY", …)` (no decimals) are equally valid; the scope of `require spend("…")` is whatever string you use |
| Any tiny amount works | Up to **28 decimal places**; finer errors clearly | 18-decimal crypto fits whole. Below that, spend in the base unit (wei instead of ether) rather than losing precision silently |
| `SYNSEMA_SPEND_CEILING="agent-1:EUR:50"` caps that agent | That's parsed as the **unit** `agent-1:EUR` | Per-identity ceilings live in their own variable with `=`: `SYNSEMA_SPEND_CEILING_PER_IDENTITY="agent-1=EUR:50"` — kept apart so a unit containing `:` can never collide with an identity |

### Agent identity (captokens, signed requests, OIDC, mTLS)

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `let key be secret("X")` at the top level works inside a route | The handler gets it **redacted as text** (`http_sign`/`hmac` then error with "got text") | Globals are snapshotted per request and secrets are redacted crossing that boundary — by design. Resolve it **inside** the handler: `route "…"` → `let key be secret("X")` |
| `captoken_attenuate(t, caps, opts)` needs the root key | It deliberately does **not** take one — attenuating offline is the whole point | Only `mint` and `verify` take the key. If you find yourself passing it to attenuate, you're re-minting, not delegating |
| A sub-agent's attenuated token gets its own rate-limit budget | It keeps the **root token's `id`**, so it shares the delegator's quota | On purpose: delegating must not multiply the budget. Mint separate tokens (different `id`) if you really want separate quotas |
| `captoken_verify` tells you the token expired vs was forged | It returns `nothing` for every failure | Same doctrine as `jwt_verify`: an endpoint must not be distinguishable by rejection cause. Log server-side if you need forensics |
| A token with an `aud`/`ip`/`method` caveat verifies without passing that context | It's **rejected** (fail-closed) | You can't claim a condition holds if you never checked it. Pass it: `captoken_verify(t, k, {"aud": "orders-api"})` |
| `http_signature_verify(req, key)` picks the algorithm from the message | Error: `opts.alg` is required | Reading `alg` from the message is the classic confusion forgery (sign with the *public* key as an HMAC secret). The verifier pins it |
| A signed request verifies with a different body | The `Content-Digest` is part of the signature → rejected | Expected. Sign and verify the **same bytes**: serialize once (`json_encode`) and pass that exact text as `body` |
| `http_sign` works with a plain-string key | The key must be a sealed `secret` (its name is what scopes `require sign(...)`) | `secret("SIG_KEY")`, plus `require sign("SIG_KEY")`. Without the capability it's denied and audited, like signing on-chain |
| An hmac-sha256 signing key can be any text | Yes — but an **ed25519** key as text must be **hex** | Each algorithm keeps the engine-wide rule for its material: curve keys are hex/bytes, shared HMAC strings are raw |
| `jwt_verify` can check a Google/Auth0 token with `{"alg": "RS256"}` | It can't — that's `oidc_verify`, a different builtin | `jwt_verify` = HS256 with a secret you own (pure). `oidc_verify` = third-party RS256/ES256, mandatory `iss`+`aud`, and JWKS over the network (`require net(host)`) |
| `oidc_verify` without `aud` just checks the signature | It's an **error**, on purpose | A valid token minted for *another app of the same provider* would verify — the confused-deputy attack. `aud` is mandatory |
| A JWKS fetch failure means the token is invalid | Fetch failures are **errors**, not `nothing` | "I couldn't verify it" must never look like "it isn't valid". Only token problems are `nothing` |
| `mtls_identity` applies to one request | It's **per process** (the certificate identifies the workload, SPIFFE-style) | Call it once at startup. Needs `require file.read` on both PEMs |
| Without `opts.hosts`, the certificate only goes where you meant | It goes to **every host the program may reach** — any server that asks for a client cert gets your workload identity | Bounded by `require net`, so with a narrow `net` scope it's already contained. With a broad one, scope it: `mtls_identity(c, k, {"hosts": ["*.mesh.internal"]})` |
| The server can require client certificates (`client_ca`) | Not yet — only the **client** side ships | Terminating mTLS on the serve side needs a new `serve` clause (parser work); use a reverse proxy in front meanwhile |

## Agentic apps — `select`, `proc_*`, `bus_*` (engine v0.6.7+)

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `proc_spawn` works without a `require` | `Capability not granted: exec("cmd")` — same gate as `run`, never auto-granted | `require exec("cargo")` (scope = the command as written) |
| A `proc_spawn` child outlives the request / program | It is killed when its interpreter ends (TERM, KILL after 2 s) | For work that must survive, use `cron_after` or an agent |
| `proc_send` returns immediately | It is a blocking pipe write — a child that never reads stdin blocks you | Send what it reads; `proc_close_stdin` for EOF |
| `proc_recv` gives me a prompt without a newline | `line_mode` delivers per line; a partial line arrives at exit/EOF | `{"line_mode": false}` for raw chunks (bytes) |
| The child skips its `y/N` question, hangs, or says "not a terminal" (`ssh`, `sudo`, `npm`, `inquirer` menus, `vim`, an agentic CLI) | Pipes are not a tty; the program decided before you could answer | `proc_spawn(cmd, args, {"pty": true})` (v0.6.8+); try `--yes` / `CI=1` first |
| Under `pty: true` my `proc_send("y\n")` is ignored | A tty wants keystrokes: Enter is `\r`; the prompt text also arrives with ANSI noise | `proc_send(h, "y\r")`; read with `strip_ansi(...)`; Ctrl-C = `bytes([3])`, Ctrl-D = `bytes([4])` |
| `proc_close_stdin` errors on a pty / stderr events never come | A pty has one stream and no separate stdin | Send the EOF key; stderr arrives as `stdout` |
| `proc_resize` errors | Only a pty has a size | Spawn with `pty: true` (`cols`/`rows` there too) |
| `bus_publish("agent.*", x)` broadcasts | Error: a published topic is literal — globs are for `bus_subscribe` | Publish `"agent.done"`; subscribe to `"agent.*"` |
| `bus_publish(topic, my_task)` | Error: tasks/secrets don't cross the bus (data only) | Publish text/number/bool/list/map/bytes |
| A slow subscriber stalls the publisher | Default `on_full` is `drop_oldest` (bounded queue); the publisher never blocks | Read faster / raise `max_queue`; `"error"` if losing events must be loud |
| The bus reaches another process / node | In-process only | Same API on Redis is the roadmap; today one process |
| `select([])` waits | Returns `nothing` at once (nothing to wait for) | Check you passed live handles |
| `ws_select` rejects a process handle | It accepts any handle now (with its historical `conn` tag) | `select` is the same wait with `source`/`handle` tags |
| `agent_stop(id)` returns `false` | The agent was already `done`/`error`/`stopped` (or the id is wrong — ids come from `agents()`) | Use the `id` (`Name_0`), not the declared name |

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
| `apply(list, fn)` errors ("apply takes fn first") | Both orders work now: the intentional family (`apply`/`where`/`transform`/`reduce`/`sort_by`/`group_by`/`find_first`/`every`/`some`/`count_where`/`zip_with`) accepts `(fn, list, …)` AND `(list, fn, …)` | Either reads fine; the canonical documented idiom stays `apply(fn, list)`. Two tasks or two lists where one-and-one is expected → explicit error (never guessed) |
| `user of request.role` gets the user's role | It parses as `user of (request.role)` → `Map has no key 'role'` (the error now carries this hint) | Bind first: `let u be user of request`, then `u.role` |
| `f(1)` to `task f(a, b)` errors (missing arg) | `b` becomes `nothing` (permissive arity) | Give `b` a default: `task f(a, b = 0)`; or pass it. |
| `f(x = 1)` and `f(x == 1)` are the same | `=` is a **named arg**; `==` is an equality expression passed positionally | Use `=` for named args/defaults, `==` for comparison |
| `test "..."` blocks run under `synsema run` | They're **skipped** by `run`; only `synsema test` runs them | Run `synsema test file.syn`. See [testing.md](testing.md). |
| `assert_error(() => give 5)` passes | A `give` is not an error → it **fails** | `assert_error` passes only if the function raises a runtime error |
| `try/recover` lets the error bubble up | `recover` **swallows** it — the task/agent ends normally (DONE) | To re-propagate, call `raise(err)` inside `recover` (agent ends ERROR). `fail()` is HTTP-only, not for this. |
| `signal "x:" + text(id)` must be a literal | The channel name is an **expression** — dynamic names work | Use `signal`/`wait_for` with a computed name for per-job channels (see agents.md) |
| A route's `wait_for` hangs the request 30s when no signal comes | That's the **default** timeout | Set it: `wait_for "x" timeout 2 as r` (seconds, 0–3600). Bounds the wait so requests don't pile up. |

## Data & charts (CSV / stats / chart_svg — see [dataviz.md](dataviz.md))

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `csv_parse` converts `"42"` to a number | Everything stays **text** by default (lossless: `"00123"` is preserved) | Pass `{"numbers": true}` to convert numeric-looking fields |
| A 9th series/pie-slice picks a 9th color | **Error** — colors are never cycled (colorblind-safety: the fixed order is the mechanism) | Group the tail into an "Other" bucket, or pass your own `{"colors": [...]}` |
| `{"x": "mes"}` works with a map or number list | Error: `x`/`y` only apply to a **list of maps** (rows) | Other shapes carry their own x (labels/index/pairs) — drop the opts |
| A NaN/infinite value plots as a gap | **Error** (a silent gap or a broken SVG would lie to the reader) | Filter first with `where(...)` + `is_finite(...)` |
| `histogram` counts every value with explicit edges | Values **outside the edges are discarded** (NumPy semantics) | Widen the edges, or use integer `bins` (auto range [min, max]) |
| `chart(...)` returns SVG text | It returns a **content node** (negotiated HTML/MD/JSON) | For raw SVG text use `chart_svg(...)`; `chart()` lives inside `content(page([...]))` |
| A `"stacked_bar"` kind exists | No — stacking is an **opt**: `"bar"`/`"area"` + `{"stack": true}` | Stacked area with mixed signs at one x errors (ambiguous) → use stacked bar |
| Waterfall takes running totals | It takes **deltas**; the running total is computed for you | The MD/JSON outputs include both `delta` and `running` |
| `{"center": n}` works with the default heatmap scale | Error — `center` requires explicit `{"scale": "diverging"}` | `"auto"` already centers on 0 when values cross it; `center` is for other pivots |
| `{"bins": 4.0}` (float) works like `4` | Error — bins must be an **integer** or an ascending **edge list** | Mirrors `histogram()`; convert first with `round(x)`/`floor(x)` (there is no `int()`) |
| Boxplot draws a group of 1 value | Error — **≥2 values per group** (a 1-point box is garbage) | Aggregate differently or drop the group |
| `svg_to_png` renders animations / scripts | The PNG is the **static** state (resvg ignores scripts/SMIL) | By design — nothing in an SVG ever executes |
| A `<image href="http://...">` loads in the PNG | Never fetched — **no network, no disk** from a pure builtin | Embed the image as a `data:` URL if you need it rasterized |
| Any font in the SVG renders as requested | One embedded sans (DejaVu); unknown families fall back to it; missing glyphs (full CJK, color emoji) → tofu | Deterministic by design; custom/system fonts may come later |
| Huge `width`/`scale` just works | Above ~16.7M output pixels → error naming `max_pixels` | Deliberate anti-DoS ceiling; raise it explicitly: `{"max_pixels": n}` |

## Blockchain (sign/verify — see stdlib.md § Blockchain)

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| `keccak256` == SHA3-256 | Different padding: `keccak256("")` = `c5d24601…`, SHA3-256 = `a7ffc6f8…` | Ethereum uses PRE-NIST Keccak; `keccak256` gives you the Ethereum one |
| Pre-hash the message before `ed25519_sign` | Wrong signature (double hash) | ed25519 signs the **raw message** (RFC 8032); only secp256k1 takes a 32-byte digest |
| Pass the key as a hex string | Error — the key must be a `secret` | `require secret("K")` + `secret("K")`, or `as_secret(hex, "K")`; text secret = hex, bytes secret = raw |
| Signing works like hashing (pure) | Deny-by-default: needs `require sign("KEY_NAME")` + writes an audit entry; denied inside `sandbox` | Signing moves value — scope it to the key secret's name |
| Paste `slice(sig, 0, 32)` as r into the tx list | ~1 in 128 txs invalid (r/s must be RLP **integers**, minimal) | `bytes_to_int(slice(sig, 0, 32))`; `int_to_bytes(n, 32)` restores fixed width |
| `rlp_decode` accepts anything `rlp_encode`-shaped | Non-canonical encodings **error** (like Ethereum's decoders) | Two different byte strings never decode to the same structure silently |
| `ed25519_verify` accepts any RFC 8032 signature | **Strict**: small-order keys/points rejected (what Solana/Algorand reject) | A lenient verifier would accept forgeries the chain refuses |
| Sign inside a `cron` job with a top-level secret | The secret crosses **redacted** (safe but unusable) | Resolve the key INSIDE the task body: `let k be secret("HOT_KEY")` |
| `abi_encode("transfer(address to, uint256 amount)", …)` | Error — the ABI signature is **canonical** | No spaces, no parameter names: `"transfer(address,uint256)"` (the error shows the canonical form; `uint`→`uint256` normalizes) |
| Pass a token amount as a float (`1e24`) | Error — uint256 needs **exact integers** | Write the integer literal (`1000000000000000000000000` promotes to big int exactly); floats lose precision on money |
| `algorand_tx_encode` keeps `amt: 0` / empty `note` | Zero/empty/false fields are **OMITTED** (canonical msgpack, keys sorted) | That's what the network requires — emitting them changes the TXID or gets the tx rejected |
| Solana keeps accounts in the order you list them | Reordered by runtime rules (payer first; writable signers → ro signers → writable non-signers → ro non-signers; buckets sorted by pubkey bytes) | Matches the official SDK byte-for-byte; instruction indices point at the reordered table |
| Sign a v0 Solana message without its 0x80 prefix | Invalid signature on-chain — the signature **covers the version prefix** | `solana_message({..., "version": 0})` already includes the prefix; sign its output as-is |
| Pass `lookup_tables` to `solana_message` | Clear error: "not supported yet" | v0 without tables works today; PDAs/SPL now ship (`solana_pda`/`spl_ata`/`spl_transfer_checked_data`) |
| A deeply nested type / typed-data / txn / derivation path is fine | Nesting over **64 levels** (or a path over 256 chars / 32 segments) errors, atrapable | A DoS guard (like RLP's) — no real payload/path is that deep; hostile input can't crash the process |
| Derive Solana with a normal BIP-32 path | Wrong key — Solana uses **SLIP-0010**: `hd_derive(seed, "m/44'/501'/0'/0'", "ed25519")` (hardened-only; a non-hardened index errors) | ETH is the default `"secp256k1"`; ed25519 has no non-hardened derivation |
| Load an Algorand wallet phrase with `mnemonic_to_seed` | Algorand's 25-word phrase is **NOT BIP-39** — use `algorand_mnemonic`/`algorand_mnemonic_to_key` | Different checksum (sha512_256 over the key) and 11-bit packing; the 12/24-word BIP-39 path is for ETH/Solana |
| `mnemonic_generate`/`hd_derive`/`keystore_import` return usable bytes | They return a `secret` — `text()`/`json_encode` show `secret(NAME)`/`[redacted]` | Use it directly with `hd_derive`/`eth_address`/`secp256k1_sign`; back a phrase up on purpose with `reveal()` (gated + audited) |
| `reveal("W")` reveals the seed derived from a `"W"` mnemonic | Derived secrets carry a **derived name**: `mnemonic_to_seed` → `W.seed`, `algorand_mnemonic` → `W.mnemonic`, `hd_derive` → `W/path` | Grant with the prefix `reveal("W*")` (or the exact derived name); the `wallet`/`sign` scope of a derived key follows the same derived name |
| Custody works with `require sign` (or ambient) | Creating custody needs its OWN capability: `require wallet` (deny-by-default, audited in `wallet.log`, denied in `sandbox`) | `wallet` creates keys, `sign` moves value — an agent can derive addresses without spending |
| A wrong keystore passphrase returns garbage / partial key | Clear "wrong passphrase" error, **no material** — the MAC is checked before decrypting | Same for a bad mnemonic checksum: the error never echoes the phrase |
| A keystore with huge scrypt `n` grinds the CPU | Rejected fast ("out of the accepted range") before any KDF work | Anti-DoS cap on n·r and pbkdf2 c; Geth defaults (n=262144) pass |
| `ws_recv` blocks until a message arrives | Returns **`nothing`** after the timeout (default 30s) — never blocks forever | `let m be ws_recv(conn, 5)`; ping/pong handled transparently; a huge frame errors (16 MiB default cap), never buffers unbounded |
| `ws_connect` needs a new capability | It reuses **`net(host)`** (same scope as `http_*`); denied in `sandbox`; `wss://` validates the cert (every reconnect too) | No new door — WebSocket is transport, gated exactly like HTTP |
| Loop `ws_recv` over N connections to watch many feeds | O(N) busy-poll — use **`ws_select(conns, timeout)`** (readiness-driven, CPU ~0 idle, scales to thousands) | One call watches all; it returns `conn` (WHICH fired) and `name` if `conns` is a name→handle map |
| `ws_select` tells you a message arrived but not from where | It returns `{conn, type, data, name?}` — `conn` is the handle that fired | For a name→handle map you also get `name`; a dropped feed comes back `{type: "close", conn}` so you know which to resubscribe |
| Reconnection happens automatically | **Opt-in only:** `ws_connect(url, nothing, {"reconnect": {...}})`. Without it a drop is a `close`/error (batch-13 behavior) | Nothing silent — you asked for it. `on_reconnect` (a task) runs after reconnect to resubscribe; every attempt re-checks `net(host)` |
| Keepalive runs in the background | The engine is sync — keepalive/reconnect only tick **inside** `ws_select`/`ws_recv`/`ws_status` | Run your event loop (`while` + `ws_select`); a lone `ws_send` with no later recv won't advance timers |
| A slow consumer + fast feed grows memory unbounded | Inbound queue bounded in **messages AND bytes** (`max_queue` 1024 / `max_queue_bytes` 64 MiB) + **TCP backpressure**: at either cap it stops reading the socket, the peer throttles (no loss, no OOM) | `on_full`: `"block"` (default, backpressure), `"drop_oldest"`, or `"error"` (drains what's queued, then a catchable error — never a silent drop). A flooding server can't OOM you, even with big frames |
| A handle from one `parallel_map` worker works in another | Handles do **not** cross workers (CSP isolation) — each worker owns its own WS registry | The fan-out pattern is `parallel_map(watch_feed, urls)`: N workers × 1 connection each; never pass a handle between them |
| A half-open socket (peer vanished silently) stays "open" | With `keepalive` it's detected within `timeout` (auto-ping, no pong → dead) → reconnect or `close` | `{"keepalive": {"interval": 20, "timeout": 10}}`; `ws_status`/`ws_stats` report the truth |
| Opening connections in a loop is fine | A soft per-interpreter cap (`SYNSEMA_WS_MAX_CONNS`, default 4096) errors clearly when exceeded | Anti-footgun: a runaway loop can't open 100k sockets; close handles you're done with |
| The RPC read-side (`eth_*`/`solana_*`/`algorand_*` net calls) needs a new capability | Same **`net(host)`** as `http_*`; broadcasting is `net`-gated too (the signature already happened; `sign` stays the only value door) | A monitor agent with `net` reads everything and spends nothing |
| `tx_eip1559` fills sensible gas/fee defaults | **No silent defaults** — a missing `max_fee`/`gas`/`value` errors naming the reader helper (`eth_fee_history`/`eth_estimate_gas`) | Anti blind-signing extended to fees; the result map echoes every number for a `confirm` before signing |
| Reassemble the signed tx by hand (`bytes([2]) + rlp_encode(...)`) | Still works, but `tx_eip1559_raw(tx, sig)` does v/r/s (y-parity, minimal ints) for you | Pass the 65-byte sig from `secp256k1_sign` as-is — 27/28 v values are rejected with a clear error |
| A weird RPC response gets patched up | **Strict decode**: non-canonical hex-quantity (`0x01`), wrong shape, mismatched id, >16 MiB body → catchable error | A node is untrusted input (G23) — bad data never silently becomes a number |
| `eth_wait_receipt` ≠ success; `receipt` ≠ profit | It confirms **inclusion**: check `receipt["status"]` (0 = reverted) and Solana `status["err"]` | A tx can land AND fail; the waiters return the data, you check it |
| `eth_wait_receipt`/`solana_confirm`/`algorand_wait` hang until confirmed | Bounded polls: **`nothing`** at the timeout (default 60s), like `ws_recv` | An unconfirmed tx never hangs the agent; `algorand_wait` errors on a pool rejection (definitive) |
| Algorand's suggested `fee` is the flat fee | It's **per byte** (often 0); the flat minimum is `min_fee` (1000 µAlgo) | `algorand_params` returns BOTH so neither mistake compiles into a rejected/overpaid tx |
| `spl_balance` on a missing token account returns 0 | Catchable **error** (the ATA doesn't exist) | A wrong owner/mint would silently read 0 forever; on success the map includes the derived `ata` so you can verify it |
| A network blip (5xx / dropped connection) mid-wait kills the waiter | After a first successful poll, **transient** failures retry until the deadline (one stderr notice, no agent action needed) | Deadline mid-failure → the ERROR surfaces (not `nothing`) — "unconfirmed" ≠ "node stopped answering"; a wrong URL still fails fast on the FIRST poll |
| An L2 (Base/Arbitrum/Optimism) needs its own builtins | Same EVM wire — `eth_*`/`tx_eip1559` work as-is; read the chain id with `eth_chain_id(url)`, never hardcode | OP-stack: `eth_estimate_gas` is L2-execution only; the L1 data fee lands in the receipt (`l1Fee`, exact int) — total = gasUsed×effectiveGasPrice + l1Fee. Arbitrum folds it into gasUsed |
| `btc_tx` puts the fee wherever there's leftover | The fee is IMPLICIT (inputs − outputs); `btc_tx` requires it **declared** and checks `sum(inputs) == sum(outputs) + fee` (G28) | If it doesn't balance, the error names the exact sat diff ("did you forget the change output?") — forgetting change donates it to miners |
| The builder computes the change output | **No** — change is one more EXPLICIT output to your own address; coin selection is yours (out of scope) | Add `{"address": my_addr, "amount": total_in - sent - fee}`; a float amount errors (everything is exact SATS, 1 BTC = 100_000_000) |
| Sign the Bitcoin transaction once | Sign **once per input** — `btc_tx` returns `digests` (one each, right sighash: BIP-143 P2WPKH / BIP-341 P2TR); pass one sig per input to `btc_tx_raw`, same order | Only SIGHASH_ALL/DEFAULT; NONE/SINGLE/ANYONECANPAY error (out of scope) |
| A taproot address is my public key | It's the **TWEAKED** key (BIP-341 key-path); `btc_address(k, "p2tr")` / `schnorr_sign(digest, k, "taproot")` tweak internally | You never tweak by hand — the classic bug. `schnorr_sign` uses the SAME `sign` gate (no new capability) |
| bech32 works for every segwit address | BIP-350: v0 (P2WPKH/P2WSH) = **bech32**, v1 (taproot) = **bech32m**; the wrong variant is REJECTED | Lax decode = burned funds. A cross-network address in a tx errors naming both networks |
| Read the txid straight off the raw bytes | `btc_txid` is dSHA256 **without witness**, **byte-reversed** (the explorer/RPC form) | Avoids the classic "my txid is backwards"; `btc_send` re-checks the node's txid against the bytes |
| `btc_tx_raw` trusts the signatures I pass | It VERIFIES each signature against the UTXO's key **before assembling** — a wrong-key sig errors, nothing broadcast | The P2WPKH witness is DER+SIGHASH_ALL (low-s enforced) — you never touch DER |
| A tiny output (100 sats) is fine | Below the dust limit (546 P2PKH / 294 P2WPKH / 330 P2TR) → error naming the limit (it wouldn't relay) | `fee > sum(outputs)` also errors unless `"allow_absurd_fee": true` (explicit opt-in) |
| Export a WIF back out of a secret | `wif_import` exists (gated by `wallet`); the reverse export does NOT — no builtin returns a key | The deliberate backup is `reveal()` of the mnemonic; HD for BTC: `hd_derive(seed, "m/84'/0'/0'/0/0")` (BIP-84) / `"m/86'/0'/0'/0/0"` (BIP-86) |
| PSBT needs a signing capability | `psbt_encode`/`psbt_decode`/`psbt_finalize` are PURE — the cold-custody flow (agent prepares, human signs on a hardware wallet, agent finalizes+sends) needs no `sign` | The key never exists on the agent's machine; `psbt_decode` audits amounts/fee before you broadcast someone else's PSBT |

## Behavioral surprises

| What you expect | What actually happens | Why / workaround |
|---|---|---|
| String on multiple lines | `Unterminated string` error | Use `\n` or concatenate: `"line1\n" + "line2"` |
| `remember("preferencia", ...)` works | Error: invalid category | Categories are English: `preference`, `rule`, `learning`, `decision`, `context` |
| `intent: "..."` restricts what the program can do | No — the intent is descriptive only | Security is enforced by capabilities (`require`), in any language. The intent text never blocks. |
| `wait_for` wakes all waiters on one `signal` | Only ONE waiter gets it | Signals are a queue (consumed on read). For fan-out, emit N signals or use blackboard. |
| `wait_for` hangs forever on dead agent | Returns `nothing` quickly | The runtime detects this and returns — but ONLY when agents WERE spawned and all of them died. |
| `wait_for "x"` returns instantly when no agent was ever spawned | It blocks until the `timeout` (default 30s) | The fast return is for "all spawned agents died", not "zero agents". With no producer ever spawned, the runtime can't know none is coming → it waits. **Always pass a bounded `timeout`** when an emitter might be absent: `wait_for "x" timeout 2 as r`. |
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
| `… not permitted: declared but above the host ceiling (--sandbox/--cap-set)` | The `require` IS there; the HOST's ceiling (`--sandbox`, `--cap-set`, the embedder's `ceiling`) does not lend it | Nothing to change in the program — do NOT add the `require` again (loop). The host widens the ceiling or the call stays denied. Same text for `net`/`db`/`file`… via `Capability not granted: … — declared but above the host ceiling` |
| Comparing a secret with `==` in a loop over guesses | Fine — `==` on a secret is constant-time | For HMAC/signature checks use `verify_hmac` (also constant-time) |
| Expecting `env("X")` to return `nothing` when unset | It raises a clear error (fail-loud) | Pass a default: `env("X", "devvalue")`, or set it in `.env`/the environment |
| Putting a secret in a query param or JSON body | Redacted (fail-closed) → the upstream gets `secret(NAME)` | Send credentials via a header: `{"Authorization": bearer(secret("KEY"))}` |

## WebAssembly (wasip1 CLI + `@synsema/wasm` embed) — see [deploy.md](deploy.md) § WebAssembly

- **`.env` is NOT read by the embeddable artifact** (`synsema-wasm-web`): there is no
  filesystem or process. Pass `env: {KEY: "..."}` in `run`/`handle` opts; `secret("KEY")`
  resolves from there. (The wasip1 CLI DOES read `.env` through `wasmtime --dir .`.)
- **An async host hook with the sync API fails, by design**: `syn.run(src, {host: {http: async …}})`
  makes the call fail with `the host \`http\` hook returned a Promise — use runAsync/handleAsync`
  (the program sees it in `r["error"]`; a `kv` write is dropped with that warning in `log`). Async
  hooks (browser `fetch`, IndexedDB, LLM SDKs) need `runAsync`/`handleAsync` (Worker +
  `Atomics.wait`); in browsers that needs cross-origin isolation (COOP `same-origin` + COEP
  `require-corp`) — without it, use sync hooks.
- **`require` still rules**: the host lending `http`/`kv`/`llm` grants nothing — without
  `require net("host")`/`require memory("x")`/`require llm` the builtin fails with `Capability not
  granted` BEFORE the host is called; and the embedder's `ceiling` denies above what the host lends.
- **Handler mode is the native serve, not a lighter one**: `require serve(port)` is mandatory
  (`serve on 8080 is not permitted: missing capability serve(8080)`), and each request runs on a
  snapshot of the globals — a `set` on a global in a route does NOT persist; use `state_*`
  (durable through the host `kv`). `stream`/`proxy to` answer 501; `static`/rate limits are the
  platform's job.
- **Not in either artifact** (names exist, errors say why): `ws_*`, `mtls_identity`, `db_open`/`sql`/
  `mongo_*`/`redis_*`, `cron_*`, real threads (`spawn`/`parallel_map` run in-process). In wasip1
  without a host, `fetch` with `require net` fails `this host provides no http transport`.
- **A trap discards the instance** (a panic in wasm aborts): the JS glue recreates it on the next
  call; program errors never trap — they come back in `errors[]`.

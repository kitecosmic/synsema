# Synsema HTTP Server — `serve`

A native HTTP server with **zero dependencies**. Define routes in Synsema and the
runtime enforces a consistent response contract, pagination, auth and input
validation for you. The production build serves over Rust (`std::net` + tokio/
hyper/rustls); the Python reference uses `http.server` and stays byte-identical
for HTTP/1.1.

> Start a server with **`synsema serve program.syn`**, not `synsema run`. `run`
> executes a program once and a `serve on` block errors with *"serve is only
> available through the Synsema engine runtime"*. `serve` wires up that runtime
> (HTTP, crons, agents) and keeps the process alive.

## Capability

Serving on a port requires the `serve` capability, scoped to that exact port:

```
require serve(8080)
```

Without it, `serve on 8080` fails with a clear error:
`serve on 8080 is not permitted: missing capability serve(8080). Add `require serve(8080)``.
The scope is the port — `require serve(8080)` does **not** allow `serve on 9090`.

### Choosing a port

- **Public HTTPS → `443`** (with `tls auto`). This is the standard HTTPS port; clients
  reach `https://your-domain` with no `:port` suffix.
- **Public HTTP → `80`** — used only to serve the ACME challenge and **301-redirect to
  HTTPS**. Don't serve real traffic in clear text on `:80`.
- On Linux, ports **< 1024** (80/443) need privileges: run via a service manager, or grant
  the binary `setcap 'cap_net_bind_service=+ep'`.
- **Do not expose a public server on a common dev port** (`8080`, `3000`, `5000`, `8000`).
  Scanners sweep those first. They're fine for local/dev; for anything internet-facing use
  `443`. If you genuinely need a non-standard port (an internal service behind a firewall),
  it works — just open that exact port in the firewall and `require serve(<that port>)`;
  clients must include `:port` in the URL.

## Basic shape

```
require serve(8080)

serve on 8080
    auth with check_token            -- optional
    route "GET /products"
        give all_products()
    route "POST /products" requires auth
        expect body {name: text, price: number}
        let b be json of request
        give created(b)
```

- `serve on PORT` opens a server block. It starts a background, threaded server
  and returns immediately. The CLI keeps the process alive while servers run.
- `route "METHOD /path"` defines a handler. The body is ordinary Synsema.
- Named path params use `:name` → `route "GET /products/:id"`.
- A trailing **catch-all** `*name` captures the rest of the path (variable depth)
  → `route "GET /files/*path"` matches `/files/a/b/c` with `params.path == "a/b/c"`.
  It must be the last segment and needs at least one segment to capture.

### Route precedence (by specificity, not order)

When several routes could match the same path, the **most specific** wins —
regardless of declaration order, so a `:param` or catch-all can never accidentally
swallow a more specific route:

```
exact segment  >  :param  >  *catchall
```

`route "GET /files/special"` beats `route "GET /files/:id"` beats
`route "GET /files/*path"` for `/files/special`, even if the catch-all is declared
first.

### Soft keywords

`serve`, `on`, `route`, `auth`, `requires`, `expect`, `max_body`, `max_streams`,
`stream`, `send`, `rate_limit`, `per`, `static`, `from`, `cors`, `describe` and
`private` are **soft keywords**: they are special *only* at the start of their
construction (`serve on N`, `route "..."`, `requires auth`, `expect body {...}`,
`max_body "10mb"`, `max_streams N`, a `stream` block, `send` inside one,
`rate_limit N per window`, `static "./dir"`, `static "/p" from "./dir"`,
`cors "*"`, a `describe` block, `private`). Everywhere else they are ordinary
names — `let route be "/x"`, `let static be 1`, `let private be 1` and
`task auth(x)` are valid. The parser decides with fixed lookahead, never heuristics.

## The request

Inside a handler you have:

```
request          -- map with .method .path .body .json .headers .user .body_file
json of request  -- parsed JSON body (a map), or nothing
body of request  -- raw body text (in-memory bodies; "" when spilled to disk)
headers of request
user of request  -- set after auth (see below)
ip of request    -- the client's real peer IP (used for rate limiting)
body_file of request  -- temp file path when a large body spilled to disk, else nothing
read_body()      -- read the full body text (from memory or the temp file)
query            -- query string as a map: /x?page=2 → query.page == "2"
params           -- path params as a map: /products/:id → params.id
```

All `query` and `params` values are text. Use `read_body()` to get the whole
body regardless of where it lives (memory or disk) — see "Request body limits".

## Response contract (enforced by the runtime, on the BODY you `give`)

| You `give`            | Response body                                                        |
|-----------------------|----------------------------------------------------------------------|
| a **map**             | the object as-is                                                     |
| a **list**            | `{"items": [...], "count": <page>, "total": <real>, "cursor": <next or null>}` |
| a **scalar** (text/number/bool) | the value as JSON, as-is                                    |
| nothing / no `give`   | `null`                                                              |

Helpers set the HTTP status:

```
ok(x)             -- 200, body shaped per the table above
created(x)        -- 201
not_found(text)   -- 404 → {"error": text, "status": 404}
not_found(map)    -- 404 → the map as-is (custom 404 body)
fail(code, msg)   -- {"error": msg, "status": code}
fail(msg)         -- {"error": msg, "status": 400}
fail(code)        -- {"error": "error", "status": code}
```

Errors never crash the server:

```
expect failure         → 400  {"error": "...", "status": 400, "field": "..."}
malformed JSON body    → 400  {"error": "malformed JSON body", "status": 400}
uncaught error / 1/0   → 500  {"error": "...", "status": 500}
unauthorized           → 401
method not allowed     → 405  (with an `Allow` header listing valid methods)
unknown route          → 404
body larger than 1 MB  → 413  {"error": "payload too large", "status": 413}
```

`OPTIONS` returns `204` with an `Allow` header; `HEAD` behaves like `GET` with no
body. A malformed body is only an error when `Content-Type` says JSON; otherwise
`json of request` is `nothing` and `body of request` keeps the raw text.

### Error responses (dev vs `--secure`)

An uncaught error in a handler becomes a `500`. Its full detail is **always
logged** to the server console (observability). What the **client** sees depends
on the mode:

- **Dev (default):** the body includes the detail —
  `{"error": "<type>: <message>", "status": 500}` — so a human or agent can
  self-correct. (`expect`/`400` and other client errors always keep their detail.)
- **Production (`--secure`):** the body is generic —
  `{"error": "internal server error", "status": 500}` — no internals leak.

This applies to **all** uncaught 500s, not just templates.

## Serving web pages (HTML, static files, CORS)

`serve` is not only a JSON API — it can serve a real web app: HTML responses,
static assets (CSS/JS/images), and the CORS headers a browser needs.

### HTML and other content-types — `html()`, `respond()`

`give <value>` always produces JSON (`give "<h1>Hi</h1>"` returns the JSON string
`"<h1>Hi</h1>"`, **not** a page). To return non-JSON, use these helpers:

```
route "GET /"
    give html("<h1>Hello</h1>")           -- 200, text/html; charset=utf-8, raw body

route "GET /report.csv"
    give respond("a,b,c\n1,2,3", "text/csv")   -- any content-type

route "GET /legacy"
    give respond("<x/>", "application/xml", 404)   -- content-type + status

route "GET /old-path"
    give redirect("https://example.com/new-path")   -- 301 + Location, no body
```

- `html(content)` → status `200`, `Content-Type: text/html; charset=utf-8`, body
  written **verbatim** (no `json.dumps`, no quotes).
- `respond(content, content_type, status?)` → arbitrary content-type, optional
  status (default `200`).
- `redirect(url, status?)` → a `3xx` response with a `Location: <url>` header and no
  body. Default status `301` (permanent); pass `302` for a temporary redirect. The URL
  is rejected (500) if it contains CR/LF — this prevents header injection. Use it for
  canonical redirects (see `www → apex` under TLS below) or moved resources.
- `give <map>` / `give <list>` are unchanged — still JSON. For text plain use
  `respond(x, "text/plain")` (the `text(...)` builtin is value conversion, not a
  response helper).

### Static files — `static "./dir"` (and mounts)

Declare a directory and any GET/HEAD that doesn't match a declared route is served
from it. You can mount several dirs, each at its own URL prefix:

```
serve on 8090
    static "./public"                 -- root mount: "/" → ./public/index.html
    static "/assets" from "./assets"  -- mount ./assets under the "/assets" prefix
    route "POST /api/signup"          -- declared routes ALWAYS win over static
        ...
```

- A `GET`/`HEAD` with no matching route falls through to the static handler:
  the file is served with a content-type from its extension (`.html`, `.css`,
  `.js`, `.png`, `.svg`, `.json`, … — these common web types are **pinned** so the
  result doesn't depend on the host's mime registry); a missing file → `404` JSON.
- **Directory index.** `/` serves `index.html`; a subfolder serves its
  `index.html` too — `/docs/` (and `/docs`) → `<dir>/docs/index.html`.
- **Multiple mounts.** `static "./dir"` mounts at the root; `static "/p" from
  "./dir"` mounts under `/p`. Longer prefixes are matched first, so `/assets/...`
  is served from the `/assets` mount before the root mount is tried. Declaring two
  mounts at the **same** prefix is an **error** (no silent shadowing).
- **Declared routes always win.** If a path is declared (for any method) it is
  never shadowed by a file — a different method on it gets `405`, not a file.
- **Only `GET`/`HEAD`.** A `POST` to a static path is not served (→ `404`/`405`).
- **The declaration is the permission.** `static "./public"` grants reading from
  that directory; you do **not** also need a `file()` capability for it. Relative
  paths are resolved against the program's working directory.
- **Path traversal is blocked, per mount.** `../`, encoded `..%2f`, absolute paths
  and symlinks escaping the directory are rejected — the resolved real path must
  stay inside that mount's root.

> **Same-origin tip:** if the landing page is served by `static` from the same
> server as the API, the browser's `fetch` is **same-origin** and needs no CORS.

### CORS — `cors "*"` / `cors "https://app.com"`

For APIs called from a browser on a **different** origin, declare CORS:

```
serve on 8090
    cors "*"                     -- or cors "https://app.example.com"
    route "GET /api/data"
        give [...]
```

- With `cors` declared, every response carries `Access-Control-Allow-Origin:
  <origin>`. A preflight `OPTIONS` additionally returns
  `Access-Control-Allow-Methods` (the path's methods),
  `Access-Control-Allow-Headers: Content-Type, Authorization` and
  `Access-Control-Max-Age`.
- Without `cors`, no CORS headers are sent (unchanged behavior).
- **Credentials caveat:** the CORS spec forbids `*` for requests with
  credentials (`Authorization`/cookies). If you send credentials cross-origin, set
  a **specific** origin (`cors "https://app.example.com"`), not `*`.

## Web for agents — SSR, negotiation & discoverability

Two ways to render server-side, for two jobs:

- **`render("page.html", data)`** — templates, for **design pages** (landing,
  marketing) where you control the exact HTML.
- **`content(tree)`** — a semantic tree, for **content** humans *and* agents
  consume (blog/docs), negotiated to HTML / Markdown / JSON.

### Templates — `render()` (pixel-control SSR)

`render("page.html", data)` returns a `text/html` response from a template file.
The data map's keys become variables inside the template:

```
route "GET /"
    give render("home.html", {"title": "Welcome", "items": ["a", "b"], "featured": true})
```

```html
<!-- home.html — { ... } holes are Synsema expressions, AUTO-ESCAPED -->
<h1>{ title }</h1>
<ul>{ each item in items }<li>{ item }</li>{ end }</ul>
{ when featured }<aside>★</aside>{ otherwise }<aside>—</aside>{ end }
{ raw trusted_html }              <!-- raw opts out of escaping -->
```

- **A hole `{ x }` shows the value of `x`.** `x` can be a **data field** (any
  name — even a reserved word like `type`, `show`, `state`) or an **expression**
  like `{ format_time(created) }` or `{ a + b }`. A single bare name is looked up
  directly in the data, so simple field names always work; if the field isn't in
  the data you get a clear `field 'x' is not in the template data` error.
- **Auto-escape (XSS-safe by default):** every `{ expr }` value is HTML-escaped
  (`<script>` → `&lt;script&gt;`) — you never have to remember. `{ raw expr }`
  opts out for trusted HTML.
- **Flow control reuses Synsema:** `{ each VAR in EXPR }…{ end }` and
  `{ when EXPR }…{ otherwise }…{ end }` — the same `each`/`when` you already know,
  not a new dialect.
- **Paths are cwd-relative** and may not escape the working directory (traversal
  blocked).
- **Errors are caught early.** A template referenced as `render("literal.html")`
  is validated **at startup** (file exists + parses), so a typo/missing file
  fails when the program runs — not on the first request. A runtime error (e.g. a
  missing field) is a `500`: in dev the detail (with `file:line`) is returned so
  you or an agent can fix it; with `--secure` the body is generic and the detail
  only goes to the server log (see "Error responses" below).
- **`{`/`}` are delimiters.** Keep CSS/JS (which use braces) in external files
  served via `static`; for a literal brace use a string hole like `{ "{" }`.

### Semantic content — `content()` (negotiated)

For content that **both humans and agents** consume (blog posts, docs, a KB), you
describe the content **once** as a tree of semantic nodes and `give content(tree)`.
The runtime then negotiates the representation per request — HTML for browsers,
Markdown for agents, JSON for tools — from the **same route**.

```
task post_view(p)
    give page(
        [
            heading(1, title of p),
            prose("Published " + format_time(created of p)),
            prose(body of p),
            link("Back", "/blog")
        ],
        {"title": title of p, "description": excerpt of p}   -- <head> + SEO
    )

route "GET /blog/:slug"
    give content(post_view(load_post(params.slug)))          -- opt-in: negotiated
```

### Vocabulary (content nodes)

| Builtin | Renders to |
|---|---|
| `page(nodes, meta?)` | the document; `meta` (a map) feeds `<title>`/`<meta>` + JSON-LD |
| `heading(level, text)` | `<h1>`–`<h6>` / `#` |
| `prose(text)` | `<p>` / paragraph |
| `list(items)` / `ordered_list(items)` | `<ul>`/`<ol>` / `- ` / `1. ` |
| `link(text, href)` | `<a>` / `[text](href)` |
| `image(src, alt)` | `<img>` / `![alt](src)` |
| `section(nodes)` | `<section>` / grouped blocks |
| `code(text, lang?)` | `<pre><code>` / fenced ```` ``` ```` |
| `raw(html)` | the HTML **verbatim** (escape hatch) |

- **Opt-in:** only `give content(tree)` is negotiated. A route that gives
  `html()`/`respond()` stays HTML, a `{map}`/`list` stays JSON — no magic.
- **Auto-escape (XSS-safe by default):** all text in the HTML rendering is escaped
  (`<script>` → `&lt;script&gt;`), including the JSON-LD. Use `raw(html)` to opt
  out for trusted HTML. You never have to remember to escape.
- **SEO automatic:** `page` metadata (`title`, `description`) becomes `<title>`,
  `<meta name="description">` and a JSON-LD `WebPage` block.
- A content node used **without** `content()` (e.g. `give heading(...)`) degrades
  to its JSON form.

### Content negotiation (`Accept` + suffix)

The same `content()` route serves three formats. Two triggers, no `?query`:

```
GET /blog/hola                              # browser → HTML (default)
GET /blog/hola   Accept: text/markdown      # agent   → Markdown
GET /blog/hola.md                           # explicit → Markdown
GET /blog/hola.json                         # explicit → JSON (the node tree)
```

- **Default is HTML** — including `Accept: */*` or no/unclear `Accept`.
  `Accept: text/markdown` → Markdown; `Accept: application/json` → JSON.
- **Suffix** `.md`/`.json`/`.html` is an explicit selector. It is stripped before
  matching, so it works with `:param` routes (`/blog/hola.json` → slug `hola`).
- **No conflict with static files / literal routes.** A real file (`data.json`) or
  a route authored literally (`route "GET /report.json"`) is served **as-is** and
  wins over negotiation — the suffix only re-interprets a path a `:param` captured.
  A `*catch-all` keeps the dotted value too (it's not negotiated).
- Negotiation applies **only** to `content()` values; everything else is unchanged.

### Discoverability — `/llms.txt`, `/robots.txt`, `describe`, `private`

Every server is **discoverable by agents from day 1, zero config**:

- **`/llms.txt`** (the "robots.txt of the agent era") is auto-generated from the
  program `intent:`, the route table (method + path), and the `describe` block.
- **`/robots.txt`** is auto-served (allows crawlers and points them at the site).

Enrich or opt out with two clauses on the serve block:

```
serve on 8080
    describe                       -- enriches /llms.txt (optional)
        about: "Blog and waitlist for Synsema"
        api: ["GET /blog/:slug — an article", "POST /api/signup — join"]
    -- private                     -- opt-out: internal server, publish nothing
    route "GET /blog/:slug"
        give content(post_view(load_post(params.slug)))
```

- **`describe`** (soft keyword): `about:` becomes the `/llms.txt` title and
  `api:` a curated endpoint list. The `intent:` becomes the summary.
- **`private`** (soft keyword): disables `/llms.txt` (returns `404`) and makes
  `/robots.txt` `Disallow: /` — for internal servers/dashboards, so they don't
  leak their shape (secure by default).
- A declared route or a static file at `/llms.txt` or `/robots.txt` **overrides**
  the auto-generated one.
- Combined with the `content()` page metadata → JSON-LD, this closes the SEO +
  agent-discovery loop.

## Pagination

Collections are **never** returned unbounded.

- Default `limit` is 100 (max 1000).
- `?limit=N` sets the page size.
- `?cursor=N` (or `?offset=N`) sets where the page starts.
- `total` is always the real total; `cursor` is the next offset, or `null` on the last page.

```
GET /products?limit=2          → {"items":[...2...], "count":2, "total":57, "cursor":2}
GET /products?limit=2&cursor=2 → {"items":[...2...], "count":2, "total":57, "cursor":4}
```

**Rule:** with `give <list>`, the handler must return the **whole** collection —
the runtime is the sole owner of `LIMIT`/`OFFSET`/`total`. Never put `LIMIT` in
your own query when you `give <list>`, or `total` would be wrong. Note that
`give <list>` also loads the full collection into memory.

### `paged()` — for large tables (SQL pushdown, exact total)

For big result sets, `give paged("SELECT ...", [params])` fetches **only the
requested page** (the runtime appends `LIMIT`/`OFFSET`) and computes `total` with
a `COUNT(*)`, so nothing is fully materialized:

```
route "GET /products"
    give paged("SELECT id, name, price FROM products ORDER BY id")
```

- Same envelope and `?limit`/`?cursor` semantics as `give <list>`, but `total` is
  exact and only one page is read from the DB.
- Always pass values as `params` (parameterized) — never string-concatenate.
- Do **not** add your own `LIMIT`/`;` to the query.
- Outside a route handler, `paged()` degrades to the full result set.

## Streaming responses (SSE)

A route can emit many messages over time on one connection — LLM tokens, a data
feed, MCP events — using **Server-Sent Events**. Open a `stream` block and emit
with `send`:

```
serve on 8080
    max_streams 200                  -- optional; default 100

    route "GET /events"
        stream
            each tick in range(10)
                send {"count": tick}         -- → data: {"count":0}\n\n

    route "GET /llm"
        stream
            let answer be generate "reply" given prompt
            each token in answer
                send token as "token"        -- → event: token\n data: "..."\n\n
```

- `send <value>` emits `data: <json(value)>` (the value as-is — no pagination
  envelope; that is only for `give`). `send <value> as "name"` adds `event: name`.
- The stream ends when the `stream` block ends; the server then closes the
  connection. **`stream` and `give` are mutually exclusive** in a route: a route
  with a `stream` block responds in SSE mode, otherwise it follows the `give`
  contract.
- Response headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`,
  `X-Accel-Buffering: no` (disables proxy buffering), and no `Content-Length`.
  Each event is **flushed immediately**, so clients receive messages as they are
  produced.
- **Client disconnect:** if the client goes away mid-stream, the next `send`
  unwinds the handler cleanly (the `each`/loop stops), frees the thread, and
  never crashes the server.
- **Errors mid-stream:** the status was already sent, so the runtime emits a
  final `event: error` event and closes — never a crash.
- **Isolation:** each stream runs in its own interpreter/scope, like any request.
- **Concurrency cap:** in the current one-thread-per-connection model each open
  stream holds a thread, so `max_streams N` (default 100) bounds concurrent
  streams. Over the cap a new stream gets `503 {"error":"too many concurrent
  streams","status":503}` with a `Retry-After` header.
- **Pacing / heartbeat:** `sleep(seconds)` (requires `require time`) paces a
  stream; send a periodic event to keep proxies from timing out.

`stream`, `send` and `max_streams` are soft keywords — only special in this
construction; `let send be 1` is still valid.

## Rate limiting

Protect against brute-force, scraping and spam. Declare a limit on the serve
block (default for all routes) and/or override it per route:

```
serve on 8080
    rate_limit 100 per minute        -- default for every route, per client IP
    auth with check_token

    route "POST /login"
        rate_limit 5 per minute      -- stricter override
        ...

    route "GET /public"              -- inherits the 100/min default
        ...

    route "GET /webhook"
        rate_limit none              -- disable the inherited default
        ...
```

- `rate_limit <N> per <window>` — window is `second`, `minute` or `hour`.
- **Opt-in:** with no `rate_limit` there is no limit. `rate_limit none` (or
  `unlimited`) disables an inherited default on one route.
- **Algorithm:** token bucket — up to `N` per window sustained, with bursts up
  to `N`. Tokens refill continuously.
- **Keyed by the real peer IP.** `X-Forwarded-For` is **not** trusted (a client
  could forge it to evade the limit or flood the table). Per-user keying and
  trusted-proxy `X-Forwarded-For` are future work.
- **Order:** the limit is checked after route matching but **before** auth and
  the handler — so it also throttles the auth task (e.g. 5 login attempts/min
  even with invalid tokens).
- **Over the limit → 429** `{"error":"rate limit exceeded","status":429}` with a
  `Retry-After` header; responses also carry `RateLimit-Limit`,
  `RateLimit-Remaining` and `RateLimit-Reset`. The handler does not run.
- **Memory:** routes sharing the default share one bucket per IP; an overridden
  route gets its own. Stale buckets are purged automatically, so a flood of
  unique IPs can't grow the table without bound.
- The client IP is also available to handlers as `ip of request`.

`rate_limit` and `per` are soft keywords — `let per be 1` is still valid.

## Auth (incoming)

```
serve on 8080
    auth with check_token
    route "GET /me" requires auth
        give {"name": name of (user of request)}
```

For a route marked `requires auth`, the runtime:
1. extracts the bearer token from `Authorization: Bearer <token>`,
2. calls the `auth with` task with that token,
3. if it returns `nothing` → responds **401**,
4. otherwise the returned value is placed in `request.user`.

```
task check_token(token)
    when token == "secret"
        give {"name": "alice"}
    give nothing
```

A route that uses `requires auth` must have an `auth with <task>` on the `serve`
block — otherwise it's a parse error (`synsema check` catches it).

## Input validation

```
route "POST /users"
    expect body {name: text, age: number}
    ...
```

`expect body {field: type, ...}` validates the request's JSON body. A missing
field or a type mismatch → **400** with the offending `field` named. Types:
`text`, `number`, `bool`, `list`, `map`.

For finer checks than a type (email, phone, slug…), use `matches(value, pattern)`
— it is a **full match** (the whole value must match), so an unanchored pattern is
already safe for validation; no `^...$` needed:

```
route "POST /signup"
    expect body {email: text}
    let email be email of (json of request)
    when not matches(email, "[^@ ]+@[^@ ]+\.[^@ ]+")
        give fail(422, "that doesn't look like an email")
    ...
```

(For "does the pattern appear somewhere" use `find_all`/`capture` — see builtins.md.)

## Request body limits

The request body is bounded so a single oversized request can't exhaust memory.

```
serve on 8080
    max_body "10mb"        -- optional; default 1mb
    route "POST /upload"
        give {"bytes": length(read_body())}
```

- **Default:** 1 MB when `max_body` is not declared.
- **`max_body`** accepts a size string — `"512kb"`, `"10mb"`, `"1gb"`
  (case-insensitive, 1024-based) — or a raw byte count, or `"unlimited"` /
  `"none"` to disable the cap (only for trusted, internal use). The `"10mb"`
  form is recommended for readability.
- **Real bytes are counted**, never the declared `Content-Length`, so a lying
  length or a `Transfer-Encoding: chunked` body cannot evade the limit.
- **Over the limit → 413** `{"error":"payload too large","status":413}` and the
  connection is closed cleanly (`Connection: close`) — it never leaves an unread
  body to corrupt the next request on a keep-alive connection.
- **Memory vs disk:** small bodies stay in memory (`body of request`,
  `json of request`). Bodies larger than ~1 MB stream to a temp file;
  `body_file of request` is its path and `read_body()` reads it. The temp file
  is removed when the request finishes (even if the handler errors).
- **Chunked** request bodies (no `Content-Length`) are supported and counted.

This is why raising the limit is safe: the cap is on the in-memory buffer, not
on what can be served — large uploads stream to disk rather than being buffered.

## Isolation

Every request runs in its own isolated interpreter and scope (its own variables,
logs and trace) — just like a spawned agent. There is **no shared mutable state**
between requests except the blackboard (`share`/`observe`) and the database
(`sql`/`sql_exec`). Always use parameterized `sql(..., [params])` — never string
concatenation — so path/query/body values can't inject SQL.

## Full example

```
require serve(8080)
require db("./store.db")

db_open("./store.db")
sql_exec("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price NUMBER)")

task check_token(token)
    when token == "admin-key"
        give {"role": "admin"}
    give nothing

serve on 8080
    auth with check_token

    route "GET /products"
        give sql("SELECT id, name, price FROM products")

    route "GET /products/:id"
        let rows be sql("SELECT id, name, price FROM products WHERE id = ?", [params.id])
        when length(rows) == 0
            give not_found("product not found")
        give rows[0]

    route "POST /products" requires auth
        expect body {name: text, price: number}
        let b be json of request
        sql_exec("INSERT INTO products (name, price) VALUES (?, ?)", [name of b, price of b])
        give created({"created": true})
```

Run it:

```bash
synsema serve store.syn    # serves and stays alive while the server runs; Ctrl+C to stop
```

---

## Production web stack (Rust implementation)

The Rust server (tokio/hyper/rustls) adds, natively, what you'd normally put Caddy/nginx
in front for. These are Rust-only; the Python reference omits them. HTTP/1.1 responses
stay byte-identical to the Python oracle — TLS/vhost/proxy/HTTP-2 are additive.

### TLS / HTTPS

```
require serve(443)
serve on 443
    domain "example.com"
    tls cert "./cert.pem" key "./key.pem"   -- manual cert
    redirect https                           -- also listen on :80 and 301 → https
    route "GET /" ...
```

- `tls cert <expr> key <expr>` — manual certificate.
- `tls auto "email"` — **automatic HTTPS** via ACME (Let's Encrypt): issues the cert,
  serves the HTTP-01 challenge on :80, stores it in `~/.synsema/certs/`, and a
  background thread renews it (< 30 days). `domain` is **required** with `tls auto`.
- `domain` accepts **one domain or a list** — pass a list for a single **SAN certificate**
  covering several names (e.g. apex + `www`):

  ```
  serve on 443
      tls auto "admin@example.com"
      domain ["example.com", "www.example.com"]   -- one SAN cert for both
      route "GET /" ...
  ```

  Every name in the list must resolve (DNS A/AAAA) to this server and be reachable on
  `:80`, or the whole order fails. The cert is stored under the first (primary) domain.
- TLS 1.2+ enforced, **HSTS** automatic, **SNI** (per-host cert with vhosts).
- **HTTP/2** is negotiated automatically via ALPN over TLS; HTTP/1.1 is kept.

**`redirect https` and `www`:**
- With **`tls auto`**, the `:80` listener already serves the ACME challenge **and**
  301-redirects everything else to HTTPS — so `redirect https` is implicit; adding it is a
  silent no-op. `redirect https` only does work alongside a **manual** `tls cert`.
- The `:80 → :443` redirect **preserves the `Host`** — there is no automatic
  `www.example.com → example.com` canonicalization. To make `www` work over HTTPS, include
  it in the `domain` list (above) so it gets a valid cert. To *canonicalize* `www` to the
  apex, give `www` its own **vhost** (`host "www.example.com"`) whose only route redirects —
  do **not** add a catch-all route on the default host, because declared routes win over
  `static` mounts and a `GET /*path` would shadow all your assets:

  ```
  serve on 443
      tls auto "admin@example.com"
      domain ["example.com", "www.example.com"]
      host "www.example.com"
          route "GET /"
              give redirect("https://example.com/")
          route "GET /*path"
              give redirect("https://example.com/" + params.path)
      -- default host (apex) = your real site; statics keep working
      static "/assets" from "./static"
      route "GET /" ...
  ```

  Note: the catch-all `*path` **does not match the bare root `/`** (it needs at least one
  segment to capture), so the `www` vhost needs an explicit `route "GET /"` or
  `https://www.example.com/` — the most common case — would 404.

  vhost selection is by the request's `Host` (or, over HTTP/2, the `:authority` pseudo-
  header — both handled). If you need the host inside a handler, read it from
  `host of (headers of request)` (header keys are lower-case; there is no `host of request`
  shortcut).

### Virtual hosts (multi-domain)

```
serve on 443
    host "api.example.com"
        auth with check_token
        route "GET /users" ...
    host "app.example.com"
        static "./app"
    host "*.tenant.example.com"           -- wildcard subdomains
        route "GET /" ...
    route "GET /"                          -- default host (no Host match)
        give {"host": "default"}
```

Dispatched by the `Host` header: exact → wildcard → default. Each host has its own
routes/static/auth/cert, fully isolated (a route in one host 404s in another).

### Reverse proxy

```
route "GET /api/*path"
    proxy to "http://127.0.0.1:9000"      -- forwards the request to the upstream
```

The target is the base; the incoming path is appended (like nginx `proxy_pass`). Needs a
`require net "<host>"` capability for the upstream. Forwards status + content-type + body.

### Production static files

The `static` mounts get production behavior automatically:
- **ETag** + `304 Not Modified` on `If-None-Match`.
- **Range** / `206 Partial Content` (+ `416` on invalid range) for media.
- **gzip** when the client sends `Accept-Encoding: gzip` (compressible types).

---

## Template composition (layouts, includes)

`render()` templates compose, so you don't duplicate the page chrome (head, nav, footer):

- **`{ include "partials/nav.html" }`** — inline another template at this point. It renders
  with the current data (and any surrounding `each` loop variables). Use for reusable
  components: nav, footer, cards.
- **`{ layout "layouts/base.html" }`** — declared at the top of a page. The page's output is
  rendered, then injected into the layout where the layout has **`{ slot }`**. Layouts can
  themselves declare a layout (nested). The slot content is inserted raw (already rendered).

A base layout:
```html
<!DOCTYPE html><html><head><title>{ title }</title>
<link rel="stylesheet" href="/assets/style.css"></head>
<body>
  { include "partials/nav.html" }
  { slot }
  { include "partials/footer.html" }
</body></html>
```
A page that uses it:
```html
{ layout "layouts/base.html" }
<main class="wrap"><h1>{ title }</h1> ... </main>
```

Recommended project structure: `layouts/`, `partials/`, `pages/`, `static/` (CSS/JS),
`content/` (markdown/content sources). Paths are cwd-relative and traversal-safe.

**content() and CSS:** a `content()` page's HTML is wrapped in `<main class="prose">` and
can declare a stylesheet via page meta (`{"stylesheet": "/assets/style.css"}`) — head-only,
so the Markdown/JSON representations for agents stay clean.

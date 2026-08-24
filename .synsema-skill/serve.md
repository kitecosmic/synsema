# Synsema HTTP Server — `serve`

A native HTTP server with **zero dependencies**. Define routes in Synsema and the
runtime enforces a consistent response contract, pagination, auth and input
validation for you. It runs on an async Rust stack (`tokio`/`hyper`/`rustls`) as a
single static binary.

> Start a server with **`synsema serve program.syn`**, not `synsema run`. `run`
> executes a program once and a `serve on` block errors with *"serve is only
> available through the Synsema engine runtime"*. `serve` wires up that runtime
> (HTTP, crons, agents) and keeps the process alive.

> **This file is long (~1100 lines) — jump to the `## ` section you need instead of reading it all:**
> Capability · Basic shape · Mounted routes (`mount`) · The request (incl. `form of request`) ·
> Shared mutable state (`state_*`) · Response contract · Custom error pages (`errors with`) ·
> Serving web pages (HTML, static files with cache/fallback, CORS) ·
> Web for agents (SSR, negotiation & discoverability) ·
> Pagination · Streaming responses (SSE) · Rate limiting · Auth (incoming) · Agent identity ·
> Input validation · Request body limits · Isolation · Full example ·
> Production web stack (TLS / auto-HTTPS / vhosts / reverse proxy / HTTP-2) · Template composition

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

`serve`, `on`, `route`, `auth`, `errors`, `requires`, `expect`, `max_body`,
`max_streams`, `stream`, `send`, `rate_limit`, `per`, `static`, `from`, `cache`,
`fallback`, `cors`, `describe`, `private`, `mount` and `at` are **soft keywords**:
they are special *only* at the start of their construction (`serve on N`,
`route "..."`, `requires auth`, `errors with <task>`, `expect body {...}`,
`max_body "10mb"`, `max_streams N`, a `stream` block, `send` inside one,
`rate_limit N per window`, `static "./dir" [cache "1h"] [fallback "index.html"]`,
`cors "*"`, a `describe` block, `private`, `mount <expr> [at "/p"]`). Everywhere
else they are ordinary names — `let route be "/x"`, `let static be 1`,
`let cache be 1` and `task auth(x)` are valid. The parser decides with fixed
lookahead, never heuristics.

### Mounted routes — `mount` (routes that live in a module)

A module can export a **routes group** and the serve block mounts it — the way to
split a big serve into files:

```
-- shop.syn (module)
task fmt(n)                       -- PRIVATE helper: mounted bodies can call it
    give "$" + text(n)
export routes tienda
    route "GET /shop"
        give html("<h1>" + fmt(99) + "</h1>")
    route "POST /shop/buy"
        expect body {item: text}
        ...

-- app.syn
use "./shop.syn" as shop
serve on 8080
    mount shop.tienda              -- routes join the table as declared
    mount shop.tienda at "/v2"     -- same group under a prefix
```

- Mounted route bodies are ordinary route bodies: `request`/`query`/`params`,
  `expect`, `give`, helpers of the module (exported or private) by simple name.
- The group's shape is validated when the serve is built (fail-fast), including
  "`requires auth` needs an `auth with` on the serve block". `render("literal.html")`
  calls inside mounted bodies are startup-validated too, like any route.
- Prefix rules: `at "/p"` must start with `/`; `route "GET /"` mounted at `/p`
  answers at `/p`. Precedence/specificity work as for any route.
- v1 limits (clear errors): no `stream` routes in a group, no per-route
  `rate_limit` inside a group (the serve default applies), `mount` at serve level
  only (not inside `host` blocks).

## The request

Inside a handler you have:

```
request          -- map with .method .path .body .json .form .headers .cookies .user .body_file
json of request  -- parsed JSON body (a map), or nothing
form of request  -- parsed FORM body (a map; see below) — classic <form> posts
body of request  -- raw body text (in-memory bodies; "" when spilled to disk)
headers of request
cookies of request -- incoming cookies as a map (RFC 6265, undecoded; no header → empty map)
user of request  -- set after auth (see below)
ip of request    -- the client's real peer IP (used for rate limiting)
body_file of request  -- temp file path when a large body spilled to disk, else nothing
read_body()      -- read the full body TEXT (lossy for non-UTF-8)
read_body_bytes() -- read the full body as `bytes` (byte-exact, for binary uploads)
query            -- query string as a map: /x?page=2 → query.page == "2"
params           -- path params as a map: /products/:id → params.id
```

All `query` and `params` values are text. Use `read_body()` to get the whole
body regardless of where it lives (memory or disk) — see "Request body limits".

### `form of request` — classic HTML forms (no fetch/JSON needed)

Parsed from the body according to `Content-Type`; no form body → **empty map**
(always navigable, like `cookies`):

- `application/x-www-form-urlencoded` (a plain `<form method="post">`) →
  `{field: text}`, percent-decoded, `+` → space, last value wins.
- `multipart/form-data` (`<form enctype="multipart/form-data">`) → text fields as
  text; **file uploads** as `{filename, content_type, data}` where `data` is the
  exact `bytes`. Large bodies spilled to disk are read from the temp file.

```
route "POST /signup"
    let f be form of request
    when not contains(keys(f), "email")
        give fail(422, "missing email")
    give {"ok": true, "email": f.email}

route "POST /upload"
    let file be archivo of (form of request)
    write_file_bytes("uploads/" + (filename of file), data of file)   -- require file(...)
    give created({"bytes": length(data of file)})
```

⚠️ A missing map key errors (`Map has no key 'email'`) — check membership with
`contains(keys(f), "campo")` before accessing optional fields.

## Shared mutable state across requests (`state_*`)

⚠️ A `set globalVar to ...` inside a route handler does NOT persist to the next request —
each request runs on a per-request snapshot of the globals (this keeps requests isolated and
fast). For state shared **across requests/handlers**, use the `state_*` builtins (an in-memory
store with the life of the server):
```
route "POST /visit"
    state_incr("visits")            -- shared counter across all requests
    give "ok"
route "GET /count"
    give state_get("visits", 0)     -- default 0 if unset
```
- `state_set(key, value)` / `state_get(key, default?)` / `state_incr(key, delta?)` / `state_delete(key)` / `state_all()` → a map snapshot of every key (`{"a": 1, "hits": 2}`).
- In-memory (gone on restart). For durable state use SQL ([stdlib.md](stdlib.md)) or the agent
  memory (`remember`/`recall`) **and progress** (`create_progress`/`resume_point`/…) — **both persist
  across serve requests** (shared store), so a plan created in one request advances in the next.
  They require the program to declare its memory: `require memory("<name>")` at the top-level of the
  serve file (without it the whole family fails with `Capability not granted: memory` and no file is
  created). State lives in `<program-dir>/.synsema/state/<name>.db` ([memory.md](memory.md)). LLM ops
  (`reason`/`decide`/`generate`/`llm_step`) also work under serve with the `.env` provider — a modular
  orchestrator with memory, plans and an LLM runs directly from `serve`.

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

### Custom error pages — `errors with <task>`

By default runtime errors are JSON. For a real website, declare an errors task on
the serve block — it shapes the BODY of `401` / `404` / `405` / `500`:

```
task error_page(status, message, request)
    when status == 401
        give redirect("/login")                 -- a redirect's 3xx IS honored
    let accept be accept of (headers of request)
    when accept == nothing
        set accept to ""
    when contains(accept, "text/html")
        give render("pages/error.html", {"status": status, "message": message})
    give nothing                                -- nothing → default JSON (agents keep JSON)

serve on 8080
    errors with error_page
    ...
```

- The task takes exactly **3 parameters** `(status, message, request)` — arity is
  validated when the serve is built.
- **The error status is preserved** — a 404 page is served WITH status 404 (no
  soft-404s). The single exception: returning `redirect(...)` keeps its 3xx +
  `Location` (the "401 → login" pattern).
- Return `html(...)`, `render(...)`, a map, or `content(...)` (negotiated by
  `Accept` — the same error page serves HTML to browsers and Markdown to agents).
  `with_header`/`set_cookie` wrappers work.
- `nothing` → the default JSON body. If the errors task itself errors, the default
  JSON responds and the failure is logged — a bug here can never take down the
  error path.
- On a 500 under `--secure`, the task receives the already-redacted message
  ("internal server error") so a custom page can't re-leak internals; the full
  detail still goes to the server log.
- The 405's `Allow` header and the 429/`expect`-400 bodies are untouched (429 and
  validation 400s stay JSON by design).

### Request logging (the terminal is quiet by default)

`serve` does **not** write an access log — add a `log` in your handlers to see requests live:
`log "GET " + (path of request)` shows as `[serve] [LOG] GET /…` in the server terminal. Both
`log` and `print` reach it with a `[serve]` prefix. See [observability.md](observability.md#logging-under-serve-and-where-it-shows-up).

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
- `binary(bytes, content_type?, status?)` → a **binary** response (default
  `application/octet-stream`, `200`); the body is written byte-exact, not compressed. Also
  `give bytes(...)` directly → an octet-stream. Use for images/files/downloads. See
  [builtins.md](builtins.md) (bytes).
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
    static "/assets" from "./assets" cache "1h"          -- + Cache-Control policy
    static "/app" from "./dist" fallback "index.html"    -- + SPA history-fallback
    route "POST /api/signup"          -- declared routes ALWAYS win over static
        ...
```

- **`cache "<spec>"`** (optional, per mount) → a `Cache-Control` header on the
  mount's responses (200/206/304): `"immutable"` (→ `public, max-age=31536000,
  immutable`, for fingerprinted assets), `"no-store"`, raw seconds, or `<N>s/m/h/d`
  (`"30s"`, `"5m"`, `"1h"`, `"7d"`). An invalid spec fails at startup, never on a
  request. Without `cache`, no Cache-Control is sent (ETag/304 still apply).
- **`fallback "<file>"`** (optional, per mount) → when a path misses inside the
  mount, that file is served with **200** (nginx `try_files` semantics) — the SPA
  history-fallback. The file must exist at startup (fail-fast).

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
- **Flow control reuses Synsema:** `{ each VAR in EXPR }…{ end }` (with an optional
  `{ otherwise }` empty-list branch, and `enumerate(xs)` for indexes) and
  `{ when EXPR }…{ otherwise when EXPR2 }…{ otherwise }…{ end }` — the same
  `each`/`when` chaining you already know, not a new dialect. `each` over a
  non-list is a hard error (a map suggests `keys(m)`).
- **Paths are cwd-relative** and may not escape the working directory (traversal
  blocked).
- **Errors are caught early.** A template referenced as `render("literal.html")`
  is validated **at startup** (file exists + parses), so a typo/missing file
  fails when the program runs — not on the first request. A runtime error (e.g. a
  missing field) is a `500`: in dev the detail (with `file:line`) is returned so
  you or an agent can fix it; with `--secure` the body is generic and the detail
  only goes to the server log (see "Error responses" below).
- **`{`/`}` are delimiters — inline CSS/JS goes in a `{ raw }`…`{ end }` verbatim
  block** (everything inside is emitted literally, braces included). For a single
  literal brace use `{ "{" }`. External files via `static` remain the best home
  for big stylesheets/scripts. Holes themselves nest braces, so map literals in a
  hole (`{ include "c.html" with {"k": v} }`) are fine.
- **Template comments:** `{ -- anything }` emits nothing.
- **Data into inline `<script>`:** `{ raw json_for_script(x) }` — never
  `json_encode` there (a value containing `</script>` would break out of the tag;
  `json_for_script` escapes `<`/`>`/`&` as `\u00XX`).

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
- **Isolation:** each stream runs in an isolated scope, like any request — nothing
  it defines leaks into other requests or streams.
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

### Cookie sessions — the auth task can take `(token, request)`

Declare the auth task with **2 parameters** and it also receives the full request
map (same shape the route handlers see, `user` still nothing) — that unlocks
cookie sessions, since `request.cookies` is available before the route runs. A
1-parameter task behaves exactly as before (bearer only). Any other arity is an
error when the serve is built.

```
task check_session(token, request)
    let sid be request.cookies.sid
    when sid == nothing
        give nothing                    -- nothing → 401, same contract
    give redis_get(db, "sess:" + sid)   -- the value lands in request.user
```

### Response headers & cookies — `with_header`, `set_cookie`, `clear_cookie`

Any value a handler can `give` can be wrapped with extra response headers.
Repeated `with_header`/`set_cookie` calls accumulate (order preserved; repeated
names emit separate lines — that's what multiple `Set-Cookie` needs).

```
give with_header(respond("hi", "text/plain"), "X-Request-Id", rid)
give with_header(ok(data), "Cache-Control", "no-store")
give set_cookie(redirect("/panel"), "sid", session_id, {"max_age": 86400})
give clear_cookie(redirect("/"), "sid")          -- Max-Age=0 + epoch Expires
let sid be request.cookies.sid                    -- incoming cookies (map, never nothing)
```

- `set_cookie(resp, name, value, opts?)` defaults are the safe ones: `Path=/;
  Secure; HttpOnly; SameSite=Lax`. Opts: `max_age` (seconds), `path`, `domain`,
  `secure`, `http_only` (bools), `same_site` (`"Strict"|"Lax"|"None"` — `None`
  requires `secure: true`, the browser rejects it otherwise).
- `clear_cookie(resp, name, opts?)` — `path`/`domain` must match the ones used
  at set time or the browser won't delete it.
- Everything **fails hard** (same doctrine as `redirect()`): CR/LF or control
  chars in a value, invalid RFC 6265 cookie chars (the error suggests
  `decode(bytes(v), "base64url")`), and framing/hop-by-hop headers
  (`Content-Length`, `Transfer-Encoding`, `Connection`, … and `Content-Type` —
  set that with `respond(body, ct)`).
- Streaming (SSE) routes do not accept `with_header` yet — clear error, the
  response head is already on the wire.
- CSRF for cookie-based POSTs is userland: issue `token()` per session, embed it
  in the form, compare with `constant_time_eq` in the handler.

Full login flow (password → session cookie → protected route → logout): hash at
signup with `password_hash`, verify at login with `password_verify`, create
`sid = token()` (declare `require random` — same gate as `random()`), store the
session (redis/sql/state_set), respond with `set_cookie(...)`; the 2-param auth
task above resolves it on every request.

## Agent identity — serving agents, not just browsers

A human logs in with a password and carries a cookie. An **agent** carries a
capability token or signs each request, and the runtime meters it **per identity**
rather than per IP. Both kinds of subject go through the same `auth with` task —
it just returns a different shape, and the userland branches on it.

### The auth task returns the subject

```
task authenticate(token, request)
    -- agent: a capability token (id, caps, caveats) — see builtins.md
    let agent be captoken_verify(token, secret("ROOT_KEY"), {"aud": "orders-api"})
    when agent != nothing
        give agent
    -- human: a session cookie
    let sid be request.cookies.sid
    when sid != nothing
        give redis_get(db, "sess:" + sid)
    give nothing
```

The runtime reads the **identity** from whatever the task returned, using the shape
the verifiers already produce — no adapter needed:

| Returned value | Identity used |
|---|---|
| map with `id` | `captoken_verify` |
| map with `sub` | `jwt_verify` / `oidc_verify` |
| map with `keyid` | `http_signature_verify` |
| text | the text itself |
| anything else | no identity (quotas fall back to the IP shield) |

### What the runtime enforces per identity

- **Rate limit.** A route's `rate_limit` is applied **twice**: once per client IP
  before auth (that shield is what stops an anonymous flood from burning a worker
  on every auth attempt) and once per identity after it. The effective budget is
  the stricter of the two, and agents behind the same NAT stop stealing each
  other's quota. An attenuated token keeps its root's `id` on purpose: delegating
  must not multiply the delegator's budget.
- **Spend.** `spend(...)` inside a handler is booked to that identity, the audit
  line carries `identity="…"`, and a **captoken's `spend` caveat becomes a real
  ceiling** — the orchestrator delegates `{"spend": {"ETH": 0.01}}` and the server
  refuses the spend that would cross it, before the payment call happens. Read
  back with `spend_total(unit, identity)`. Three ceilings can apply at once and the
  strictest wins: per unit (`SYNSEMA_SPEND_CEILING`), per identity
  (`SYNSEMA_SPEND_CEILING_PER_IDENTITY="agent-1=EUR:50"`) and the delegated one.
  The **unit is free text** — fiat, crypto, commodities, credits: the ledger
  privileges no currency and keeps up to 28 decimal places.

### Signed requests as auth

For machine-to-machine, the request itself is signed and the auth task verifies it
— a stolen token is useless without the key (the 2-parameter form gives you the
whole request, which is what verification needs):

```
task verify_agent(token, request)
    let key be secret("AGENT_PUBKEY")
    let v be http_signature_verify(
        {"method": request.method, "url": base + request.path,
         "headers": request.headers, "body": request.body},
        key, {"alg": "ed25519"})
    when v == nothing
        give nothing
    give {"keyid": v.keyid, "kind": "agent"}      -- keyid becomes the identity
```

`v.nonce` (when the client sent one) is what you check against a replay store for
mutating routes — the builtin hands it to you; keeping it is userland.

### Discovery — `/.well-known/synsema-auth`

A serve that has auth wired publishes, in JSON, which mechanisms it understands
(bearer/captoken/JWT, cookie, RFC 9421 signatures with the covered components and
algorithms) and which endpoints are protected. It's the machine-readable companion
to `/llms.txt`: an agent that never read your docs can still figure out how to
authenticate. `private` hides it, exactly like `/llms.txt`.

### Enrolment and revocation (userland patterns)

- **Enrolling an agent:** it presents its ed25519 public key; a human approves via
  the approvals queue (`approve`); you store the key. From then on everything it
  does is signed and audited under that identity. De-registering = deleting the key.
- **Revoking a token:** captokens are attenuated offline, so there is no central
  check — keep TTLs short and pass a denylist of ids to `captoken_verify`
  (`{"revoked": [...]}`), typically read from redis.

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

## Production web stack

The server (async `tokio`/`hyper`/`rustls`) adds, natively, what you'd normally put Caddy/nginx
in front for: TLS, auto-HTTPS (ACME), virtual hosts, reverse proxy, HTTP/2.

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

### Deployment flags (CLI overrides)

The `serve` block stays declarative — there is **no `when`/conditional TLS**. Deployment
config is injected at launch with CLI flags so the **same `.syn` is dev-clean in the repo**
and prod-ready via flags (systemd/Docker). The flags **override the `serve` block**:

```bash
synsema serve <file>
    [--watch]                       # dev loop: restart on any .syn change (templates/static already hot-reload)
    [--port N]                      # overrides `serve on N` AND grants serve(N)
    [--domain d1[,d2,...]]          # overrides the file's `domain`
    [--tls-auto <email> | --tls-cert <p> --tls-key <p>]
    [--bind <addr>]                 # default 0.0.0.0
```

**Precedence: CLI flag > file clause > default.**

| Knob | Default | File clause | CLI flag (wins) |
|---|---|---|---|
| port | — | `serve on N` | `--port N` (also grants `serve(N)`) |
| TLS on/off | off (plain HTTP) | `tls auto` / `tls cert` | `--tls-auto <email>` / `--tls-cert …` |
| domains | — | `domain …` | `--domain d1,d2` |
| bind addr | `0.0.0.0` | — | `--bind <addr>` |

- **The presence of `--tls-auto` is the dev↔prod toggle**: without it (and without `tls` in
  the file) you get plain HTTP for local dev; with it you get ACME HTTPS in prod — same file.
- Fail-loud: `--tls-auto` with no domain (flag or file) → error; `--tls-auto` + `--tls-cert`
  → error; invalid port → error.
- The flags configure one deployment: with **multiple `serve` blocks** they are rejected
  with a clear error.

See [deploy.md](deploy.md) for the canonical dev-clean `.syn` + prod systemd unit.

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
`require net "<host>"` capability for the upstream. Forwards status + content-type + body
**and the upstream's end-to-end response headers** (`Location`, `Set-Cookie`, `Cache-Control`,
`ETag`, …), so redirects, cookies and caching work through it; hop-by-hop headers
(`Connection`, `Transfer-Encoding`, …) are dropped, and invalid upstream headers are skipped
(never panic the request).

**Proxying a whole site?** `route "GET /*path"` does **not** match the root `/` (the wildcard
needs ≥1 segment) — declare `route "GET /"` as well, and one route per method you forward
(GET, POST, …). Full multi-site edge recipe in [deploy.md](deploy.md) ("Multiple sites on one host").

### Production static files

The `static` mounts get production behavior automatically:
- **ETag** + `304 Not Modified` on `If-None-Match`.
- **Range** / `206 Partial Content` (+ `416` on invalid range) for media.
- **gzip** when the client sends `Accept-Encoding: gzip` (compressible types).
- **`Cache-Control`** via the mount's `cache "<spec>"` clause (see the static section).

**Dynamic responses gzip too**: `render()`/`html()`/`content()`/JSON bodies ≥ 1 KB
of a compressible type are gzip-compressed automatically when the client accepts it
(`Vary: Accept-Encoding` included; SSE, 204/206/304 and already-encoded bodies are
skipped).

---

## Template composition (layouts, named slots, includes with props)

`render()` templates compose, so you don't duplicate the page chrome (head, nav, footer):

- **`{ include "partials/nav.html" }`** — inline another template at this point. It renders
  with the current data (and any surrounding `each` loop variables).
- **`{ include "partials/card.html" with {"title": t} }`** — a component with **props**:
  the partial sees ONLY the props map (plus tasks/globals) — fully isolated.
- **`{ layout "layouts/base.html" }`** — declared at the top of a page. The page's output is
  rendered, then injected into the layout where the layout has **`{ slot }`**. Layouts can
  themselves declare a layout (nested). The slot content is inserted raw (already rendered).
- **Named slots:** the layout declares `{ slot "head_extra" }`; the page provides
  `{ fill "head_extra" }…{ end }` at its top level. Unfilled named slots render empty
  (optional extension points); a `fill` without a `layout` is an error.

A base layout:
```html
<!DOCTYPE html><html><head><title>{ title }</title>
<link rel="stylesheet" href="/assets/style.css">
{ slot "head_extra" }</head>
<body>
  { include "partials/nav.html" }
  { slot }
  { include "partials/footer.html" }
</body></html>
```
A page that uses it:
```html
{ layout "layouts/base.html" }
{ fill "head_extra" }<style>{ raw } .wrap { max-width: 60rem; } { end }</style>{ end }
<main class="wrap"><h1>{ title }</h1> ... </main>
```

Recommended project structure: `layouts/`, `partials/`, `pages/`, `static/` (CSS/JS),
`content/` (markdown/content sources). Paths are cwd-relative and traversal-safe —
**including `include`/`layout` paths inside templates** (they resolve against the
working directory, not against the including template).

**content() and CSS:** a `content()` page's HTML is wrapped in `<main class="prose">` and
can declare a stylesheet via page meta (`{"stylesheet": "/assets/style.css"}`) — head-only,
so the Markdown/JSON representations for agents stay clean.

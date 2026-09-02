# Frontend with Synsema

Synsema serves HTML from the server (SSR). There is **no imposed framework or CSS** —
you have full control. Two complementary paths:

- **`render()` templates** — full freedom: any HTML, your own CSS/JS, composed with
  layouts, named slots and partials-with-props. This is where creative, custom frontends live.
- **`content()` pages** — a structured format that auto-negotiates: the same URL returns
  HTML to humans and Markdown/JSON to agents. Use for docs/blog/anything agents should read.

Pick `render()` when you want design control; `content()` when you want agent-readable content.

## render() — free-form pages

`render("page.html", data)` returns an HTML response. The template is HTML with `{ ... }`
holes. You write the markup; nothing is added or imposed.

```
serve on 8080
    static "/assets" from "./static"          -- your CSS, JS, images, fonts
    route "GET /"
        give render("pages/home.html", {"title": "My App"})
```

### Holes — the full vocabulary

- `{ name }` / `{ expr }` — interpolate a value (HTML-escaped). Expressions can call
  builtins **and your own tasks** (`{ fmt_price(total) }`) — under `serve`, only tasks
  defined **before** the `serve` block (the per-request snapshot is taken there).
- `{ raw expr }` — opt out of escaping for trusted HTML.
- **`{ raw }` … `{ end }` — VERBATIM block**: everything inside is emitted literally,
  braces included. This is how you write **inline CSS/JS** in a template:
  ```html
  <style>{ raw }
    .card { border-radius: 12px; transition: transform .2s ease; }
    .card:hover { transform: translateY(-4px); }
  { end }</style>
  ```
  (Without it, CSS/JS braces are parsed as holes and error — the error message points here.)
- `{ each item in items } … { end }` — loop. Add an **empty branch** with
  `{ otherwise }`: `{ each p in products } … { otherwise } <p>No products.</p> { end }`.
  Need an index? `{ each e in enumerate(items) }{ e.index }: { e.item }{ end }`.
  `each` over a non-list is a **hard error** (a map suggests `keys(m)`), same as the language.
- `{ when cond } … { otherwise when cond2 } … { otherwise } … { end }` — conditionals,
  chained exactly like the language's `when`/`otherwise when`.
- `{ include "partials/card.html" }` — inline a partial with the **current** scope
  (data + loop variables).
- `{ include "partials/card.html" with {"title": t, "price": p} }` — a **component with
  props**: the partial sees ONLY the props map (plus tasks/globals), fully isolated.
  Holes nest braces, so map literals inside holes are fine.
- `{ layout "layouts/base.html" }` + `{ slot }` — page-into-layout composition (below).
- `{ slot "name" }` in a layout + `{ fill "name" } … { end }` in the page — **named
  slots** (per-page `<head>` extras, sidebars). A `fill` must be at the top level of the
  page and requires a `layout`; a named slot with no fill renders empty (optional
  extension point).
- `{ -- anything }` — template comment, emits nothing.
- `{ "{" }` — a literal brace outside a raw block.

### Auto-escape and passing data to client JS

Every `{ expr }` is HTML-escaped by default (XSS-safe). For **embedding data into an
inline `<script>`**, never use `json_encode` (a value containing `</script>` would break
out of the tag) — use **`json_for_script()`**, which escapes `<`, `>`, `&` as `\u00XX`:

```html
<script>
window.__DATA__ = { raw json_for_script(products) };
{ raw }
document.querySelectorAll(".card").forEach((c, i) => { c.style.transitionDelay = `${i * 40}ms`; });
{ end }
</script>
```

Alternative (no inline script at all): `<div id="boot" data-json="{ json_encode(data) }">`
+ `JSON.parse(document.getElementById("boot").dataset.json)` in a static `.js` — the
hole's auto-escape makes the attribute safe.

### Composition: layouts + named slots + partials

```html
<!-- layouts/base.html -->
<!DOCTYPE html><html><head><title>{ title }</title>
<link rel="stylesheet" href="/assets/app.css">
{ slot "head_extra" }</head>
<body>
  { include "partials/nav.html" }
  { slot }
  { include "partials/footer.html" }
</body></html>
```
```html
<!-- pages/home.html -->
{ layout "layouts/base.html" }
{ fill "head_extra" }<style>{ raw } .hero { padding: 4rem 2rem; } { end }</style>{ end }
<main class="hero"><h1>{ title }</h1>
  { each e in enumerate(cards) }
  { include "partials/card.html" with {"n": e.index + 1, "card": e.item} }
  { otherwise }<p>Nothing here yet.</p>{ end }
</main>
```

- Layouts can nest (a layout may declare its own `{ layout }`).
- **`include`/`layout` paths resolve against the working directory** (where you run
  `synsema serve`), NOT against the including template — `{ include "partials/nav.html" }`
  works the same from `pages/home.html` and from `layouts/base.html`.

### Suggested project structure (a convention, not a requirement)

```
app.syn          serve block: mounts, static, error pages
shop.syn         a module with `export routes` (see below)
layouts/     base.html, ...        (page shells with { slot } / { slot "name" })
partials/    nav.html, card.html   (reusable components; card takes props via `with`)
pages/       home.html, ...        (page templates, use a layout + { fill })
static/      app.css, app.js, img/ (served via `static`, with ETag/Range/gzip + cache policy)
```

### Splitting routes into modules — `export routes` + `mount`

A big site doesn't have to be one big serve block. A module can export a routes group
and the app mounts it (bodies can call the module's PRIVATE helpers):

```
-- shop.syn
export routes tienda
    route "GET /shop"
        give render("pages/shop.html", {"items": catalogo()})

-- app.syn
use "./shop.syn" as shop
serve on 8080
    mount shop.tienda              -- or: mount shop.tienda at "/store"
```

See [modules.md](modules.md) and [serve.md](serve.md) for the rules.

### The dev loop

- **Templates and static files hot-reload per request** — edit `pages/home.html` or
  `static/app.css`, refresh the browser, done. No restart.
- Changes to the `.syn` need a restart → run **`synsema serve app.syn --watch`**: it
  restarts the server automatically when any `.syn` under the program's directory changes.
- **`render("literal.html")` templates are validated at startup** (file exists + parses,
  recursively through literal `include`/`layout`) — a typo fails before the first request.
  `synsema check app.syn` validates them too, plus all `use` imports.
- **Capability (v0.6.14+):** a top-level `render(path)` reading a template from **disk** needs
  `require file.read("<path>")` (or `require file("templates/*")` for a tree) — one line covers a
  directory. Nested `{ include }`/`{ layout }` don't need their own (static, confined to the working
  dir), and a template **baked into a `synsema build` binary** needs no capability (it's the program).

## Installable on phones and desktop — PWA (engine v0.6.15+)

The same server-rendered site **installs** as an app (home-screen icon, full screen, offline shell,
push notifications) with three web files — `manifest.webmanifest`, `sw.js`, the `<head>` lines —
and nothing native. `synsema init --pwa` scaffolds all of it (page, service worker, icons
generated from an SVG, the API in `api.syn` — an `export routes` group with the push routes,
mounted by `app.syn` (v0.6.19+) — a one-off `push_keys.syn`; add `--desktop` for the desktop
entry `desk.syn`, see deploy.md § Desktop app); `.webmanifest` is served
with its pinned content-type. Android/desktop Chromium install from a button; iOS via *Share →
Add to Home Screen* (push only once installed; needs a trusted HTTPS cert). Full walkthrough
and the "add it to an existing app" steps: [serve.md](serve.md) § Installable app (PWA); the
push builtins (`push_send`, `push_vapid_keys`): [builtins.md](builtins.md) § Web Push.

## Forms, error pages, static policy (see [serve.md](serve.md))

- Classic `<form method="post">` → **`form of request`** (urlencoded and multipart,
  file uploads included) — no fetch/JSON needed.
- **`errors with <task>`** on the serve block → your own 401/404/405/500 pages
  (HTML for browsers, JSON stays for agents; 401 can `redirect("/login")`).
- **`static ... cache "1h"`** (Cache-Control per mount, `"immutable"` for fingerprinted
  assets) and **`static ... fallback "index.html"`** (SPA history-fallback).
- Dynamic responses (render/html/content/JSON) are **gzip-compressed** automatically.

## content() — agent-negotiable pages

`content(page([...nodes...], meta))` builds a semantic tree rendered as **HTML for humans
and Markdown/JSON for agents** from one source (the format is chosen by the `Accept` header
or a `.md` / `.json` URL suffix). Nodes: `heading`, `prose`, `list`, `ordered_list`,
`link`, `image`, `code`, `section`, `raw`.

The HTML representation is wrapped in `<main class="...">` (default `prose`). Control it via
the page `meta` — none of it leaks into the Markdown/JSON:

- `"stylesheet"`: a CSS URL → `<link>` in `<head>`.
- `"class"`: the container class (default `"prose"`; set your own).
- `"header"` / `"footer"`: raw HTML wrapped around the content (e.g. your site nav/footer —
  reuse the same partials via `body of render("partials/nav.html", {})`).
- `"title"` / `"description"`: `<title>`, meta description, and JSON-LD.

```
route "GET /docs/:slug"
    give content(page([heading(1, "Title"), prose("...")], {
        "title": "Title", "stylesheet": "/assets/app.css"
    }))
```

## Performance

SSR rendering is in-memory string work — fast (the Rust runtime serves in the Go/Node
tier). Parsed templates are **cached** (invalidated by file mtime/size, so hot-reload
still works) — an `include` inside a loop parses once, not per iteration. Static assets
ship with ETag/304, Range, gzip, and your `cache` policy; dynamic HTML/JSON gzips too.

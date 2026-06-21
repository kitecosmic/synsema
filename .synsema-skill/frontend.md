# Frontend with Synsema

Synsema serves HTML from the server (SSR). There is **no imposed framework or CSS** —
you have full control. Two complementary paths:

- **`render()` templates** — full freedom: any HTML, your own CSS/JS, composed with
  layouts and partials. This is where creative, custom frontends live.
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

Holes:
- `{ name }` — interpolate a value (HTML-escaped). `{ raw html }` to opt out of escaping.
- `{ each item in items } ... { end }` — loop. `{ when cond } ... { otherwise } ... { end }` — conditional.
- `{ "{" }` — emit a literal brace (put CSS/JS, which use braces, in external static files).

### Composition: layouts + partials (no duplicated chrome)

- **`{ include "partials/nav.html" }`** — inline a reusable component (nav, footer, card).
  It renders with the current data and any surrounding loop variables.
- **`{ layout "layouts/base.html" }`** at the top of a page — the page renders, then is
  injected into the layout at **`{ slot }`**. Layouts can nest. The slot is inserted raw.

```html
<!-- layouts/base.html -->
<!DOCTYPE html><html><head><title>{ title }</title>
<link rel="stylesheet" href="/assets/app.css"></head>
<body>
  { include "partials/nav.html" }
  { slot }
  { include "partials/footer.html" }
</body></html>
```
```html
<!-- pages/home.html -->
{ layout "layouts/base.html" }
<main class="hero"><h1>{ title }</h1> ... </main>
```

### Suggested project structure (a convention, not a requirement)

```
layouts/     base.html, ...        (page shells with { slot })
partials/    nav.html, footer.html (reusable components)
pages/       home.html, ...        (page templates, use a layout)
static/      app.css, app.js, img/ (served via `static`, with ETag/Range/gzip)
```

### Client-side interactivity

Serve your own JavaScript from `static/` and reference it in your templates. Synsema
doesn't restrict the client: vanilla JS, a bundle, htmx, a framework — your call.

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

SSR template rendering is in-memory string work — fast (the Rust runtime serves in the
Go/Node tier). Render shared partials once at startup (`let nav be body of render(...)`)
instead of per request. Static assets ship with ETag/304, Range, and gzip.

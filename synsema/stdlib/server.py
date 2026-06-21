"""
Synsema Native HTTP Server — zero dependencies, on top of http.server.

This implements the `serve on PORT` language construct. It is intentionally
small: the language semantics (capability check, per-request isolation,
auth, validation) live in the engine and interpreter. This module is the
HTTP plumbing plus the *response contract* enforced on every handler.

Response contract (enforced here, on the BODY a handler `give`s):
    give <list>  → {"items": [...], "count": <page>, "total": <real>, "cursor": <next|null>}
    give <map>   → the object as-is
    helpers:
        ok(x)            → 200, body shaped as above
        created(x)       → 201
        not_found(x)     → 404 {"error": x, "status": 404}
        fail(code, msg)  → {"error": msg, "status": code}

Pagination is always applied to collections: a default limit (100) and a
cursor/offset are honoured, and `total` is always present. A collection is
never returned unbounded.

Auth, validation and uncaught errors never crash the server — they become
401 / 400 / 500 JSON responses.
"""

import json
import os
import tempfile
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

from ..core.types import (
    SynValue, BuiltinTask, SynTask,
    SynText, SynNumber, SynBool, SynList, SynMap, SynNothing,
    syn_number, syn_text, syn_bool, syn_nothing, syn_list, syn_map,
)
from ..core.interpreter import ExpectViolation, GiveSignal
from ..capabilities.model import CapabilityViolation


DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
# Default cap on the request body buffered in memory. NOT a hard ceiling on
# what can be served: `max_body` in a serve block overrides it, and larger
# bodies spill to disk (see _RequestHandler). The cap protects memory.
MAX_BODY = 1_048_576  # 1 MB
# Above this many bytes a body is streamed to a temp file instead of memory.
MEM_SPILL = 1_048_576  # 1 MB
# Default cap on concurrent SSE streams (each holds a thread in this model).
DEFAULT_MAX_STREAMS = 100

# Content-types pinned for static serving so the result never depends on the
# host's mimetypes registry (e.g. Windows maps .js → text/plain). stdlib only.
_WEB_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".txt": "text/plain; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
    ".wasm": "application/wasm",
    ".pdf": "application/pdf",
}


class ClientGone(BaseException):
    """
    Raised inside an SSE handler when writing to a disconnected client fails.

    Inherits BaseException so it unwinds the handler cleanly without being
    swallowed by user-level `try/recover` (which catches Exception).
    """


def parse_body_size(value: Any) -> Optional[int]:
    """
    Resolve a max-body setting to a byte count, or None for unlimited.

    Accepts a number (raw bytes) or a string with an optional unit:
    "512kb", "10mb", "1gb" (case-insensitive, 1024-based), or
    "unlimited"/"none" to disable the cap.
    """
    if value is None:
        return MAX_BODY
    if isinstance(value, bool):
        return MAX_BODY
    if isinstance(value, (int, float)):
        n = int(value)
        return n if n > 0 else None
    s = str(value).strip().lower()
    if s in ("unlimited", "none", "off", "0"):
        return None
    import re
    m = re.match(r"^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$", s)
    if not m:
        return MAX_BODY
    units = {None: 1, "b": 1, "kb": 1024, "mb": 1024 ** 2, "gb": 1024 ** 3}
    return int(float(m.group(1)) * units[m.group(2)])

# Metadata flag marking a value produced by ok()/created()/not_found()/fail().
_ENVELOPE = "__serve_envelope__"

# Metadata flag marking a value produced by paged() (lazy SQL pagination).
_PAGED = "__serve_paged__"

# Metadata flag marking a value produced by html()/respond(): a raw body that
# bypasses the JSON contract and is written verbatim with a declared content-type.
_RAW = "__serve_raw__"

# Metadata flag marking a value produced by content(): a semantic content tree
# that is negotiated (HTML / Markdown / JSON) per the request (see Module B2).
_CONTENT = "__serve_content__"

# Metadata flag marking a single content node (heading/prose/list/...).
_NODE = "__content_node__"

# Format suffixes that select a representation of a content() value.
_FORMAT_SUFFIXES = (("md", "md"), ("json", "json"), ("html", "html"))


@dataclass
class RawResponse:
    """
    A response body written verbatim — no JSON encoding, an explicit
    Content-Type. Produced by html()/respond() and by static file serving.

    `body` is bytes (served as-is) or str (encoded UTF-8). `content_type` is the
    full header value (e.g. "text/html; charset=utf-8").
    """
    body: Any            # str or bytes
    content_type: str
    status: int = 200


# =========================================================
# SynValue ↔ JSON
# =========================================================

def python_to_syn(value: Any) -> SynValue:
    """Convert a JSON-decoded Python value into a SynValue (recursive)."""
    if value is None:
        return syn_nothing()
    if isinstance(value, bool):
        return syn_bool(value)
    if isinstance(value, (int, float)):
        return syn_number(value)
    if isinstance(value, str):
        return syn_text(value)
    if isinstance(value, list):
        return syn_list([python_to_syn(item) for item in value])
    if isinstance(value, dict):
        return syn_map({str(k): python_to_syn(v) for k, v in value.items()})
    return syn_text(str(value))


def syn_to_json(value: Optional[SynValue]) -> Any:
    """Convert a SynValue into a JSON-serializable Python value."""
    if value is None:
        return None
    # A paged() marker outside the response contract degrades gracefully:
    # materialize the full result (no LIMIT) as a plain list.
    if isinstance(value, SynValue) and value.metadata.get(_PAGED):
        rows, _total = value.raw["fetch"](None, 0)
        return [syn_to_json(r) for r in rows]
    # content()/node values degrade to their structured JSON tree anywhere they
    # are serialized as JSON (e.g. `give heading(...)` without content()).
    if isinstance(value, SynValue) and value.metadata.get(_CONTENT):
        return _node_to_json(value.raw)
    if isinstance(value, SynValue) and value.metadata.get(_NODE):
        return _node_to_json(value)
    t = value.type
    if isinstance(t, SynNothing):
        return None
    if isinstance(t, SynBool):
        return bool(value.raw)
    if isinstance(t, SynNumber):
        return value.raw  # int or float, JSON-safe as-is
    if isinstance(t, SynText):
        return value.raw
    if isinstance(t, SynList):
        return [syn_to_json(item) for item in value.raw]
    if isinstance(t, SynMap):
        return {str(k): syn_to_json(v) for k, v in value.raw.items()}
    return str(value)


# =========================================================
# Response contract
# =========================================================

def _page_window(query: Dict[str, str]) -> Tuple[int, int]:
    """Resolve (limit, offset) from the query string with sane defaults."""
    try:
        limit = int(query.get("limit", DEFAULT_LIMIT))
    except (TypeError, ValueError):
        limit = DEFAULT_LIMIT
    if limit <= 0:
        limit = DEFAULT_LIMIT
    if limit > MAX_LIMIT:
        limit = MAX_LIMIT

    raw_cursor = query.get("cursor", query.get("offset", "0"))
    try:
        offset = int(raw_cursor)
    except (TypeError, ValueError):
        offset = 0
    if offset < 0:
        offset = 0
    return limit, offset


def _envelope_from_page(items_json: list, count: int, total: int,
                        limit: int, offset: int) -> Dict[str, Any]:
    next_offset = offset + limit
    cursor = next_offset if next_offset < total else None
    return {"items": items_json, "count": count, "total": total, "cursor": cursor}


def _paginate(list_value: SynValue, query: Dict[str, str]) -> Dict[str, Any]:
    """Apply limit + cursor/offset to an in-memory collection."""
    items = list_value.raw
    total = len(items)
    limit, offset = _page_window(query)
    page = items[offset:offset + limit]
    return _envelope_from_page(
        [syn_to_json(item) for item in page], len(page), total, limit, offset,
    )


def _paginate_lazy(paged_value: SynValue, query: Dict[str, str]) -> Dict[str, Any]:
    """
    Paginate a paged() marker via SQL pushdown: only the page is fetched and
    `total` comes from a COUNT(*), so the collection is never fully materialized.
    """
    limit, offset = _page_window(query)
    rows, total = paged_value.raw["fetch"](limit, offset)
    return _envelope_from_page(
        [syn_to_json(r) for r in rows], len(rows), int(total), limit, offset,
    )


def _shape(value: Optional[SynValue], query: Dict[str, str]) -> Any:
    """Shape a handler's give-value into the JSON body per the contract."""
    if value is None:
        return None
    if isinstance(value, SynValue) and value.metadata.get(_PAGED):
        return _paginate_lazy(value, query)
    if isinstance(value.type, SynList):
        return _paginate(value, query)
    return syn_to_json(value)


def build_response(give_value: Optional[SynValue],
                   query: Dict[str, str]) -> Tuple[int, Any]:
    """
    Turn a handler's give-value into (http_status, body) per the contract.

    The body is JSON-shaped (a Python value) unless the handler gave an
    html()/respond() value, in which case it is a RawResponse written verbatim.
    Helper envelopes (ok/created/not_found/fail) carry an explicit status.
    """
    # Raw (html/respond) bypasses the JSON contract entirely.
    if isinstance(give_value, SynValue) and give_value.metadata.get(_RAW):
        r = give_value.raw
        status = int(r["status"].raw)
        body = r["body"].raw
        return status, RawResponse(body=body, content_type=str(r["content_type"].raw),
                                   status=status)
    status = 200
    value = give_value
    if isinstance(give_value, SynValue) and give_value.metadata.get(_ENVELOPE):
        status = int(give_value.raw["status"].raw)
        value = give_value.raw["value"]
    return status, _shape(value, query)


def _make_envelope(status: int, value: SynValue) -> SynValue:
    return SynValue(
        raw={"status": syn_number(status), "value": value},
        type=SynMap(),
        metadata={_ENVELOPE: True},
    )


def _raw_text(value: Optional[SynValue]) -> str:
    """Coerce a give-value to the raw text used as an html()/respond() body."""
    if value is None:
        return ""
    if isinstance(value.type, SynText):
        return value.raw
    return str(value)


def _make_raw(body: str, content_type: str, status: int) -> SynValue:
    return SynValue(
        raw={
            "body": syn_text(body),
            "content_type": syn_text(content_type),
            "status": syn_number(status),
        },
        type=SynMap(),
        metadata={_RAW: True},
    )


# =========================================================
# Semantic content tree (content() vocabulary) + renderers
# =========================================================

def _n_text(value: Optional[SynValue]) -> str:
    """Extract a plain string from a node-builder argument."""
    if value is None:
        return ""
    if isinstance(value.type, SynText):
        return value.raw
    return str(value)


def _n_nodes(value: Optional[SynValue]) -> list:
    """Extract a list of child SynValues from a node-builder argument."""
    if value is not None and isinstance(value.type, SynList):
        return list(value.raw)
    return []


def _n_meta(value: Optional[SynValue]) -> dict:
    """Extract a {str: str} metadata dict from a page() argument."""
    if value is None or not isinstance(value.type, SynMap):
        return {}
    out = {}
    for k, v in value.raw.items():
        out[str(k)] = v.raw if isinstance(getattr(v, "type", None), SynText) else str(v)
    return out


def _node(kind: str, **fields) -> SynValue:
    data = {"kind": kind}
    data.update(fields)
    return SynValue(raw=data, type=SynMap(), metadata={_NODE: True})


def _is_node(value: Any) -> bool:
    return isinstance(value, SynValue) and value.metadata.get(_NODE) is True


# -- JSON rendering (the tree as data) --

def _item_to_json(item: Any) -> Any:
    if _is_node(item):
        return _node_to_json(item)
    return syn_to_json(item) if isinstance(item, SynValue) else item


def _node_to_json(node: SynValue) -> Any:
    d = node.raw
    kind = d["kind"]
    if kind == "page":
        return {
            "type": "page",
            "meta": d.get("meta", {}),
            "nodes": [_node_to_json(n) for n in d.get("nodes", []) if _is_node(n)],
        }
    if kind in ("list", "ordered_list"):
        return {"type": kind, "items": [_item_to_json(i) for i in d.get("items", [])]}
    if kind == "section":
        return {"type": "section",
                "nodes": [_node_to_json(n) for n in d.get("nodes", []) if _is_node(n)]}
    out = {"type": kind}
    for key in ("level", "text", "href", "src", "alt", "lang", "html"):
        if key in d and d[key] is not None:
            out[key] = d[key]
    return out


# -- HTML rendering (semantic + <head> from metadata) --

def _esc(s: str) -> str:
    import html as _html
    return _html.escape(str(s), quote=True)


def _render_li(item: Any) -> str:
    if _is_node(item):
        return f"<li>{_render_node_html(item)}</li>"
    return f"<li>{_esc(item.raw if isinstance(item, SynValue) else item)}</li>"


def _render_node_html(node: SynValue) -> str:
    d = node.raw
    kind = d["kind"]
    if kind == "heading":
        lvl = min(6, max(1, int(d.get("level", 1))))
        return f"<h{lvl}>{_esc(d.get('text', ''))}</h{lvl}>\n"
    if kind == "prose":
        return f"<p>{_esc(d.get('text', ''))}</p>\n"
    if kind in ("list", "ordered_list"):
        tag = "ol" if kind == "ordered_list" else "ul"
        inner = "".join(_render_li(i) for i in d.get("items", []))
        return f"<{tag}>{inner}</{tag}>\n"
    if kind == "link":
        return f'<a href="{_esc(d.get("href", ""))}">{_esc(d.get("text", ""))}</a>\n'
    if kind == "image":
        return f'<img src="{_esc(d.get("src", ""))}" alt="{_esc(d.get("alt", ""))}">\n'
    if kind == "section":
        inner = "".join(_render_node_html(n) for n in d.get("nodes", []) if _is_node(n))
        return f"<section>\n{inner}</section>\n"
    if kind == "code":
        lang = d.get("lang")
        cls = f' class="language-{_esc(lang)}"' if lang else ""
        return f"<pre><code{cls}>{_esc(d.get('text', ''))}</code></pre>\n"
    if kind == "raw":
        return d.get("html", "")          # escape hatch: NOT escaped
    if kind == "page":
        return "".join(_render_node_html(n) for n in d.get("nodes", []) if _is_node(n))
    return ""


def _render_html(tree: SynValue) -> str:
    d = tree.raw
    meta = d.get("meta", {}) if d.get("kind") == "page" else {}
    title = meta.get("title")
    description = meta.get("description")
    # Optional stylesheet for the HTML representation only (head-only; the
    # Markdown/JSON representations of the same content() are unaffected).
    stylesheet = meta.get("stylesheet")
    head = ['<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">']
    if title:
        head.append(f"<title>{_esc(title)}</title>")
    if description:
        head.append(f'<meta name="description" content="{_esc(description)}">')
    if stylesheet:
        head.append(f'<link rel="stylesheet" href="{_esc(stylesheet)}">')
    # Structured data (JSON-LD) from the page metadata → SEO for crawlers/agents.
    if title or description:
        ld = {"@context": "https://schema.org", "@type": "WebPage"}
        if title:
            ld["name"] = title
        if description:
            ld["description"] = description
        # Escape <, >, & as \uXXXX so the JSON can't break out of the <script>
        # element (e.g. a </script> in the title) — valid JSON, XSS-safe.
        ld_json = (json.dumps(ld).replace("<", "\\u003c")
                   .replace(">", "\\u003e").replace("&", "\\u0026"))
        head.append('<script type="application/ld+json">' + ld_json + "</script>")
    # Optional site chrome (raw HTML) for the HTML representation only: a header
    # (nav) before the content and a footer after. Markdown/JSON stay clean. The
    # site passes the SAME nav/footer partials it uses elsewhere via `body of render(...)`.
    header = meta.get("header", "")
    footer = meta.get("footer", "")
    # The content container class is overridable (default "prose") so the page author —
    # not the language — controls styling. The Markdown/JSON representations ignore it.
    css_class = meta.get("class", "prose")
    if d.get("kind") == "page":
        body = "".join(_render_node_html(n) for n in d.get("nodes", []) if _is_node(n))
    else:
        body = _render_node_html(tree)
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        + "\n".join(head)
        + "\n</head>\n<body>\n"
        + header
        + f'<main class="{css_class}">\n'
        + body
        + "</main>\n"
        + footer
        + "</body>\n</html>\n"
    )


# -- Markdown rendering (for agents) --

def _md_inline(item: Any) -> str:
    if _is_node(item):
        return _render_node_md(item).strip()
    return str(item.raw if isinstance(item, SynValue) else item)


def _render_node_md(node: SynValue) -> str:
    d = node.raw
    kind = d["kind"]
    if kind == "heading":
        lvl = min(6, max(1, int(d.get("level", 1))))
        return "#" * lvl + " " + d.get("text", "")
    if kind == "prose":
        return d.get("text", "")
    if kind == "list":
        return "\n".join("- " + _md_inline(i) for i in d.get("items", []))
    if kind == "ordered_list":
        return "\n".join(f"{n}. " + _md_inline(i)
                         for n, i in enumerate(d.get("items", []), 1))
    if kind == "link":
        return f"[{d.get('text', '')}]({d.get('href', '')})"
    if kind == "image":
        return f"![{d.get('alt', '')}]({d.get('src', '')})"
    if kind == "section":
        return "\n\n".join(_render_node_md(n) for n in d.get("nodes", []) if _is_node(n))
    if kind == "code":
        lang = d.get("lang") or ""
        return f"```{lang}\n{d.get('text', '')}\n```"
    if kind == "raw":
        return d.get("html", "")          # raw HTML passes through Markdown
    if kind == "page":
        return "\n\n".join(_render_node_md(n) for n in d.get("nodes", []) if _is_node(n))
    return ""


def _render_markdown(tree: SynValue) -> str:
    d = tree.raw
    if d.get("kind") == "page":
        body = "\n\n".join(_render_node_md(n) for n in d.get("nodes", []) if _is_node(n))
    else:
        body = _render_node_md(tree)
    return body.rstrip() + "\n"


# -- Negotiation --

def negotiate_format(accept: str) -> str:
    """Map an Accept header to a content format. Default (incl. */*) is HTML."""
    a = (accept or "").lower()
    if "text/markdown" in a and "text/html" not in a:
        return "md"
    if "application/json" in a and "text/html" not in a:
        return "json"
    return "html"


def split_format_suffix(path: str) -> Tuple[str, Optional[str]]:
    """Strip a trailing .md/.json/.html, returning (logical_path, format|None)."""
    for ext, fmt in _FORMAT_SUFFIXES:
        dotted = "." + ext
        if path.endswith(dotted) and len(path) > len(dotted) and not path[:-len(dotted)].endswith("/"):
            return path[:-len(dotted)], fmt
    return path, None


def render_content(content_value: SynValue, fmt: str) -> RawResponse:
    """Render a content() value in the chosen format as a RawResponse."""
    tree = content_value.raw
    if fmt == "json":
        body = json.dumps(_node_to_json(tree))
        return RawResponse(body=body, content_type="application/json; charset=utf-8")
    if fmt == "md":
        return RawResponse(body=_render_markdown(tree),
                           content_type="text/markdown; charset=utf-8")
    return RawResponse(body=_render_html(tree),
                       content_type="text/html; charset=utf-8")


def register_serve_builtins(env):
    """Register the response helpers: ok, created, not_found, fail, html, respond."""

    def _ok(args: List[SynValue]) -> SynValue:
        value = args[0] if args else syn_nothing()
        return _make_envelope(200, value)

    def _created(args: List[SynValue]) -> SynValue:
        value = args[0] if args else syn_nothing()
        return _make_envelope(201, value)

    def _not_found(args: List[SynValue]) -> SynValue:
        value = args[0] if args else syn_text("not found")
        if not isinstance(value.type, SynMap):
            value = syn_map({
                "error": syn_text(str(value)),
                "status": syn_number(404),
            })
        return _make_envelope(404, value)

    def _fail(args: List[SynValue]) -> SynValue:
        """
        fail(code, msg) → {"error": msg, "status": code}
        fail(msg)       → {"error": msg, "status": 400}   (single text)
        fail(code)      → {"error": "error", "status": code}  (single number)
        Never silently drops the message.
        """
        code = 400
        msg = "error"
        if len(args) >= 2:
            first, second = args[0], args[1]
            if isinstance(first.type, SynNumber):
                code, msg = int(first.raw), str(second)
            else:
                # tolerate fail(msg, code) order too
                msg = str(first)
                if isinstance(second.type, SynNumber):
                    code = int(second.raw)
        elif len(args) == 1:
            only = args[0]
            if isinstance(only.type, SynNumber):
                code = int(only.raw)
            else:
                msg = str(only)
        body = syn_map({
            "error": syn_text(msg),
            "status": syn_number(code),
        })
        return _make_envelope(code, body)

    def _html(args: List[SynValue]) -> SynValue:
        """html(content) → 200, text/html; charset=utf-8, body written verbatim."""
        content = _raw_text(args[0]) if args else ""
        return _make_raw(content, "text/html; charset=utf-8", 200)

    def _respond(args: List[SynValue]) -> SynValue:
        """
        respond(content, content_type, status?) → body written verbatim with an
        arbitrary Content-Type. respond("a,b", "text/csv"), respond(x, "text/html", 404).
        """
        content = _raw_text(args[0]) if args else ""
        content_type = str(args[1].raw) if len(args) > 1 else "text/plain; charset=utf-8"
        status = 200
        if len(args) > 2 and isinstance(args[2].type, SynNumber):
            status = int(args[2].raw)
        return _make_raw(content, content_type, status)

    # -- Semantic content vocabulary (Module B1b) --

    def _page(args: List[SynValue]) -> SynValue:
        nodes = _n_nodes(args[0]) if args else []
        meta = _n_meta(args[1]) if len(args) > 1 else {}
        return _node("page", nodes=nodes, meta=meta)

    def _heading(args: List[SynValue]) -> SynValue:
        level = int(args[0].raw) if args and isinstance(args[0].type, SynNumber) else 1
        text = _n_text(args[1]) if len(args) > 1 else ""
        return _node("heading", level=level, text=text)

    def _prose(args: List[SynValue]) -> SynValue:
        return _node("prose", text=_n_text(args[0]) if args else "")

    def _list(args: List[SynValue]) -> SynValue:
        return _node("list", items=_n_nodes(args[0]) if args else [])

    def _ordered_list(args: List[SynValue]) -> SynValue:
        return _node("ordered_list", items=_n_nodes(args[0]) if args else [])

    def _link(args: List[SynValue]) -> SynValue:
        text = _n_text(args[0]) if args else ""
        href = _n_text(args[1]) if len(args) > 1 else ""
        return _node("link", text=text, href=href)

    def _image(args: List[SynValue]) -> SynValue:
        src = _n_text(args[0]) if args else ""
        alt = _n_text(args[1]) if len(args) > 1 else ""
        return _node("image", src=src, alt=alt)

    def _section(args: List[SynValue]) -> SynValue:
        return _node("section", nodes=_n_nodes(args[0]) if args else [])

    def _code(args: List[SynValue]) -> SynValue:
        text = _n_text(args[0]) if args else ""
        lang = _n_text(args[1]) if len(args) > 1 else None
        return _node("code", text=text, lang=lang)

    def _raw(args: List[SynValue]) -> SynValue:
        return _node("raw", html=_n_text(args[0]) if args else "")

    def _content(args: List[SynValue]) -> SynValue:
        tree = args[0] if args else _node("page", nodes=[], meta={})
        return SynValue(raw=tree, type=SynMap(), metadata={_CONTENT: True})

    builtins = {
        "ok": BuiltinTask("ok", _ok, 1),
        "created": BuiltinTask("created", _created, 1),
        "not_found": BuiltinTask("not_found", _not_found, 1),
        "fail": BuiltinTask("fail", _fail, -1),
        "html": BuiltinTask("html", _html, 1),
        "respond": BuiltinTask("respond", _respond, -1),
        # Content vocabulary + negotiable wrapper
        "page": BuiltinTask("page", _page, -1),
        "heading": BuiltinTask("heading", _heading, 2),
        "prose": BuiltinTask("prose", _prose, 1),
        "list": BuiltinTask("list", _list, 1),
        "ordered_list": BuiltinTask("ordered_list", _ordered_list, 1),
        "link": BuiltinTask("link", _link, 2),
        "image": BuiltinTask("image", _image, 2),
        "section": BuiltinTask("section", _section, 1),
        "code": BuiltinTask("code", _code, -1),
        "raw": BuiltinTask("raw", _raw, 1),
        "content": BuiltinTask("content", _content, 1),
    }
    for name, builtin in builtins.items():
        env.set(name, SynValue(raw=builtin, type=SynTask()))


# =========================================================
# Route table + runtime
# =========================================================

@dataclass
class RouteSpec:
    """A single resolved route. `handler` runs the body, `give`-value returned."""
    method: str
    path: str                       # pattern, e.g. /products/:id
    param_names: List[str] = field(default_factory=list)
    requires_auth: bool = False
    handler: Callable[[Dict[str, Any]], SynValue] = None
    streaming: bool = False
    # For streaming routes: stream_handler(ctx, emit) pushes SSE events.
    stream_handler: Callable[[Dict[str, Any], Callable], None] = None
    # Effective rate limit (capacity, window_seconds) or None for unlimited.
    rate_limit: Optional[Tuple[int, float]] = None
    rate_zone: Optional[str] = None     # bucket namespace (shared vs per-route)


class _QuietThreadingHTTPServer(ThreadingHTTPServer):
    """
    ThreadingHTTPServer that stays quiet about client disconnects.

    A client resetting the connection (RST / broken pipe) is routine — and with
    SSE it happens on every EventSource/`curl -N` that closes — so socketserver's
    default traceback is just noise that would bury real errors. We swallow only
    the connection-error family; genuine bugs still print.
    """

    def handle_error(self, request, client_address):
        import sys
        import traceback
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, BrokenPipeError,
                            ConnectionResetError, ConnectionAbortedError)):
            return
        traceback.print_exc()


class ServeRuntime:
    """
    Owns the HTTP server for one `serve on PORT` block.

    Route matching, auth, validation and the response contract are enforced
    here. The actual handler execution (per-request isolated interpreter) is
    supplied by the engine as the `handler` / `auth_handler` callables.
    """

    def __init__(self, port: int, routes: List[RouteSpec],
                 auth_handler: Optional[Callable[[str], Optional[SynValue]]] = None,
                 host: str = "0.0.0.0", max_body: Optional[int] = MAX_BODY,
                 max_streams: int = DEFAULT_MAX_STREAMS,
                 static_mounts: Optional[List[Tuple[str, str]]] = None,
                 cors_origin: Optional[str] = None,
                 intent: Optional[str] = None,
                 describe_about: Optional[str] = None,
                 describe_api: Optional[List[str]] = None,
                 private: bool = False,
                 secure: bool = False):
        self.port = int(port)
        self.host = host
        # In secure mode (production), uncaught 500s return a generic body so
        # internals don't leak; the full detail always goes to the server log.
        self.secure = bool(secure)
        # Routes are matched by specificity, NOT declaration order, so a
        # catch-all or :param can never swallow a more specific route. Sorting
        # once here means _match can just return the first matching route.
        self.routes = sorted(routes, key=lambda r: self._specificity(r.path))
        self.auth_handler = auth_handler
        self.max_body = max_body  # bytes, or None for unlimited
        self.max_streams = int(max_streams)
        # Static mounts — declared via `static "./dir"` (root) or
        # `static "/prefix" from "./dir"`. Each is (url_prefix, realpath_dir);
        # the declaration is the read permission (no file() capability). Longer
        # prefixes are tried first so a mounted dir wins over the root mount.
        mounts = [(self._norm_prefix(p), os.path.realpath(d))
                  for p, d in (static_mounts or [])]
        self.static_mounts = sorted(mounts, key=lambda m: len(m[0]), reverse=True)
        # CORS origin — declared via `cors "*"` / `cors "https://app.com"`.
        self.cors_origin = cors_origin
        # Agent discoverability (Module B3): /llms.txt + /robots.txt are served
        # by default; `describe` enriches /llms.txt and `private` disables it.
        self.intent = intent
        self.describe_about = describe_about
        self.describe_api = describe_api or []
        self.private = bool(private)
        self.httpd: Optional[ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self._stream_lock = threading.Lock()
        self._active_streams = 0
        self.rate_limiter = RateLimiter()

    # -- concurrent stream accounting --

    def try_acquire_stream(self) -> bool:
        with self._stream_lock:
            if self._active_streams >= self.max_streams:
                return False
            self._active_streams += 1
            return True

    def release_stream(self):
        with self._stream_lock:
            if self._active_streams > 0:
                self._active_streams -= 1

    # -- matching --

    @staticmethod
    def _specificity(pattern: str) -> List[int]:
        """
        Rank a pattern's segments for precedence: static(0) < :param(1) < *catchall(2).
        Sorting routes by this list ascending puts the most specific first, so a
        catch-all never wins over an exact or :param match for the same path.
        """
        ranks = []
        for seg in (s for s in pattern.split("/") if s != ""):
            if seg.startswith("*"):
                ranks.append(2)
            elif seg.startswith(":"):
                ranks.append(1)
            else:
                ranks.append(0)
        return ranks

    @staticmethod
    def _param_last_segment(pattern: str) -> bool:
        """True if the pattern's last segment is a :param (which could swallow a
        format suffix). A literal segment or a *catch-all keeps the dotted value."""
        segs = [s for s in pattern.split("/") if s != ""]
        return bool(segs) and segs[-1].startswith(":")

    @staticmethod
    def _path_match(pattern: str, path: str) -> Optional[Dict[str, str]]:
        """Return captured params if `path` matches `pattern`, else None.

        A `*name` segment is a catch-all: it must be last and captures the rest
        of the path (one or more segments) as `name`, joined by '/'.
        """
        actual = [s for s in path.split("/") if s != ""]
        segs = [s for s in pattern.split("/") if s != ""]
        params: Dict[str, str] = {}
        for i, pat_seg in enumerate(segs):
            if pat_seg.startswith("*"):
                # Catch-all: needs at least one remaining segment.
                rest = actual[i:]
                if not rest:
                    return None
                params[pat_seg[1:]] = "/".join(unquote(s) for s in rest)
                return params
            if i >= len(actual):
                return None
            act_seg = actual[i]
            if pat_seg.startswith(":"):
                params[pat_seg[1:]] = unquote(act_seg)
            elif pat_seg != act_seg:
                return None
        # No catch-all consumed the tail: lengths must match exactly.
        if len(actual) != len(segs):
            return None
        return params

    def _match(self, method: str, path: str) -> Tuple[Optional[RouteSpec], Dict[str, str]]:
        # self.routes is pre-sorted by specificity, so the first match wins.
        for route in self.routes:
            if route.method != method:
                continue
            params = self._path_match(route.path, path)
            if params is not None:
                return route, params
        return None, {}

    # -- static files --

    @staticmethod
    def _norm_prefix(prefix: Optional[str]) -> str:
        """Normalize a mount prefix to '/' or '/seg/.../' (always trailing-slashed)."""
        if not prefix or prefix == "/":
            return "/"
        p = "/" + prefix.strip("/")
        return p + "/"

    @staticmethod
    def _within(base: str, target: str) -> bool:
        return target == base or target.startswith(base + os.sep)

    @classmethod
    def _resolve_in(cls, base: str, rel: str) -> Optional[str]:
        """
        Resolve `rel` to a real file inside `base`, or None.

        Blocks path traversal: the resolved real path must stay within `base`
        (defeats `../`, absolute paths, and symlinks escaping the dir). An empty
        path or a directory resolves to its `index.html` when present.
        """
        rel = unquote(rel).lstrip("/")
        if rel == "":
            rel = "index.html"
        # An absolute path (or one os.path.join would treat as absolute) can't be
        # inside a relative request — reject outright before joining.
        if os.path.isabs(rel) or (len(rel) > 1 and rel[1] == ":"):
            return None
        target = os.path.realpath(os.path.join(base, rel))
        if not cls._within(base, target):
            return None
        if os.path.isdir(target):
            # Subfolder index: /docs/ → <base>/docs/index.html
            target = os.path.realpath(os.path.join(target, "index.html"))
            if not cls._within(base, target):
                return None
        if not os.path.isfile(target):
            return None
        return target

    @staticmethod
    def _static_content_type(path: str) -> str:
        # Pin the common web types so the result is predictable across hosts —
        # the OS mimetypes registry can map .js to text/plain (Windows), which
        # breaks JS modules in the browser. Fall back to mimetypes otherwise.
        ext = os.path.splitext(path)[1].lower()
        if ext in _WEB_CONTENT_TYPES:
            return _WEB_CONTENT_TYPES[ext]
        import mimetypes
        ctype, _enc = mimetypes.guess_type(path)
        if ctype is None:
            return "application/octet-stream"
        if ctype.startswith("text/") and "charset" not in ctype:
            return f"{ctype}; charset=utf-8"
        return ctype

    def serve_static(self, url_path: str) -> Optional[RawResponse]:
        """Return a RawResponse for a static file from a matching mount, or None.

        Mounts are tried longest-prefix-first; each enforces its own traversal
        protection against its own root.
        """
        for prefix, base in self.static_mounts:
            if prefix == "/":
                rel = url_path
            elif url_path == prefix.rstrip("/"):
                rel = ""                       # bare mount point → its index.html
            elif url_path.startswith(prefix):
                rel = url_path[len(prefix):]
            else:
                continue
            target = self._resolve_in(base, rel)
            if target is None:
                continue
            try:
                with open(target, "rb") as f:
                    data = f.read()
            except OSError:
                continue
            return RawResponse(body=data,
                               content_type=self._static_content_type(target),
                               status=200)
        return None

    # -- agent discoverability (/llms.txt, /robots.txt) --

    def _llms_txt(self) -> str:
        """
        Generate /llms.txt from the program intent, the describe block and the
        route table — the "robots.txt of the agent era". Markdown, per llmstxt.org.
        """
        title = self.describe_about or self.intent or "Synsema service"
        lines = [f"# {title}"]
        if self.intent and self.intent != title:
            lines += ["", f"> {self.intent}"]
        endpoints = sorted({(r.method, r.path) for r in self.routes},
                           key=lambda mp: (mp[1], mp[0]))
        if endpoints:
            lines += ["", "## Endpoints"]
            lines += [f"- {m} {p}" for m, p in endpoints]
        if self.describe_api:
            lines += ["", "## API"]
            lines += [f"- {item}" for item in self.describe_api]
        return "\n".join(lines) + "\n"

    def _robots_txt(self) -> str:
        # A private server tells crawlers to stay away; a public one allows them
        # and points at /llms.txt.
        if self.private:
            return "User-agent: *\nDisallow: /\n"
        return "User-agent: *\nAllow: /\n"

    def discovery_response(self, path: str) -> Optional[RawResponse]:
        """Serve the auto-generated /llms.txt or /robots.txt, or None."""
        if path == "/llms.txt" and not self.private:
            return RawResponse(body=self._llms_txt(),
                               content_type="text/plain; charset=utf-8")
        if path == "/robots.txt":
            return RawResponse(body=self._robots_txt(),
                               content_type="text/plain; charset=utf-8")
        return None

    def methods_for_path(self, path: str) -> List[str]:
        """Methods of all routes whose path pattern matches (for 405 / Allow / OPTIONS)."""
        methods = []
        for route in self.routes:
            if self._path_match(route.path, path) is not None:
                if route.method not in methods:
                    methods.append(route.method)
        return sorted(methods)

    @staticmethod
    def _bearer_token(headers: Dict[str, str]) -> str:
        auth = ""
        for k, v in headers.items():
            if k.lower() == "authorization":
                auth = v
                break
        if not auth:
            return ""
        parts = auth.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        return auth.strip()

    # -- dispatch --

    @staticmethod
    def _content_type(headers: Dict[str, str]) -> str:
        for k, v in headers.items():
            if k.lower() == "content-type":
                return v.lower()
        return ""

    def dispatch(self, method: str, path: str, query: Dict[str, str],
                 headers: Dict[str, str], body_str: Optional[str],
                 body_file: Optional[str] = None, client_ip: str = ""
                 ) -> Tuple[int, Any, Dict[str, str], Optional[Tuple]]:
        """Return (status, json_body, extra_headers, stream).

        `stream` is None for a normal one-shot response; for an SSE route that
        is ready to stream it is (route, ctx) and a stream slot has been
        acquired (the caller must call release_stream when done).

        body_str is the in-memory body text (or None when the body was spilled
        to disk, in which case body_file is the temp path).
        """
        # Match the full path first (declared routes and literal paths win as-is:
        # `GET /data.json` and a real data.json file both beat negotiation).
        route, params = self._match(method, path)

        # Content negotiation by URL suffix (.md/.json/.html): only when a :param
        # swallowed the suffix (e.g. /blog/:slug matched /blog/hola.json) do we
        # re-interpret it as a format. A literal route or *catch-all keeps the
        # dotted value. A real static file at the exact path still wins.
        explicit_fmt = None
        logical_path, sfx = split_format_suffix(path)
        if sfx is not None and route is not None and self._param_last_segment(route.path):
            if method == "GET" and self.static_mounts:
                raw = self.serve_static(path)
                if raw is not None:
                    return raw.status, raw, {}, None
            lroute, lparams = self._match(method, logical_path)
            if lroute is not None:
                route, params, explicit_fmt = lroute, lparams, sfx

        if route is None:
            allowed = self.methods_for_path(path)
            if allowed:
                # The path exists, but not for this method → 405, advertise Allow.
                # Declared routes always win over static, so don't fall through.
                return (
                    405,
                    {"error": "method not allowed", "status": 405},
                    {"Allow": ", ".join(allowed)},
                    None,
                )
            # No declared route at all: a GET/HEAD may be served from a static
            # mount or by the auto discovery files. (HEAD reaches here as "GET".)
            if method == "GET":
                if self.static_mounts:
                    raw = self.serve_static(path)
                    if raw is not None:
                        return raw.status, raw, {}, None
                disc = self.discovery_response(path)
                if disc is not None:
                    return disc.status, disc, {}, None
            return 404, {"error": f"no route for {method} {path}", "status": 404}, {}, None

        # Rate limit AFTER matching the route, BEFORE auth/handler — so a
        # brute-force on an authenticated route (e.g. /login) is throttled even
        # with invalid credentials. Keyed by the real peer IP, never X-Forwarded-For.
        rate_headers: Dict[str, str] = {}
        if route.rate_limit is not None:
            capacity, window = route.rate_limit
            key = f"{route.rate_zone}|{client_ip}"
            ok, remaining, retry_after, reset = self.rate_limiter.check(key, capacity, window)
            rate_headers = {
                "RateLimit-Limit": str(capacity),
                "RateLimit-Remaining": str(remaining),
                "RateLimit-Reset": str(int(reset) + 1),
            }
            if not ok:
                retry = str(int(retry_after) + 1)
                headers_429 = dict(rate_headers)
                headers_429["Retry-After"] = retry
                headers_429["RateLimit-Remaining"] = "0"
                return 429, {"error": "rate limit exceeded", "status": 429}, headers_429, None

        json_obj = None
        if body_str:
            ctype = self._content_type(headers)
            try:
                json_obj = json.loads(body_str)
            except (ValueError, TypeError):
                # Only an error if the client claimed JSON; otherwise keep the
                # raw body available and json = nothing.
                if "json" in ctype:
                    return 400, {"error": "malformed JSON body", "status": 400}, {}, None
                json_obj = None

        ctx: Dict[str, Any] = {
            "method": method,
            "path": path,
            "query": query,
            "params": params,
            "headers": headers,
            "body": body_str or "",
            "body_file": body_file,
            "json": json_obj,
            "client_ip": client_ip,
            "user": None,
        }

        if route.requires_auth:
            token = self._bearer_token(headers)
            user = self.auth_handler(token) if self.auth_handler else None
            if user is None or isinstance(getattr(user, "type", None), SynNothing):
                return 401, {"error": "unauthorized", "status": 401}, rate_headers, None
            ctx["user"] = user

        # SSE routes: acquire a stream slot and hand off to the streaming path.
        if route.streaming:
            if not self.try_acquire_stream():
                return (
                    503,
                    {"error": "too many concurrent streams", "status": 503},
                    {"Retry-After": "5"},
                    None,
                )
            return 200, None, {}, (route, ctx)

        try:
            give_value = route.handler(ctx)
        except ExpectViolation as e:
            return 400, {"error": str(e), "status": 400, "field": e.field}, rate_headers, None
        except GiveSignal as g:  # defensive: a give that escaped the handler
            give_value = g.value
        except CapabilityViolation as e:
            return 500, self.server_error(e), rate_headers, None
        except Exception as e:  # never crash the server
            return 500, self.server_error(e), rate_headers, None

        # A content() value is negotiated: explicit suffix wins, else the Accept
        # header (default HTML). Anything else follows the normal JSON contract.
        if isinstance(give_value, SynValue) and give_value.metadata.get(_CONTENT):
            fmt = explicit_fmt or negotiate_format(self._accept_header(headers))
            raw = render_content(give_value, fmt)
            return raw.status, raw, rate_headers, None

        status, body = build_response(give_value, query)
        return status, body, rate_headers, None

    @staticmethod
    def _accept_header(headers: Dict[str, str]) -> str:
        for k, v in headers.items():
            if k.lower() == "accept":
                return v
        return ""

    def server_error(self, exc: BaseException) -> Dict[str, Any]:
        """
        Body for an uncaught 500. The full detail is ALWAYS logged to the server
        console (observability). In secure mode the client gets a generic body
        (no info leak); in dev the detail is returned so a human or agent can
        self-correct.
        """
        import sys
        detail = f"{type(exc).__name__}: {exc}"
        sys.stderr.write(f"[serve:{self.port}] 500 {detail}\n")
        sys.stderr.flush()
        if self.secure:
            return {"error": "internal server error", "status": 500}
        return {"error": detail, "status": 500}

    # -- lifecycle --

    def start(self, background: bool = True):
        self.httpd = _QuietThreadingHTTPServer((self.host, self.port), _RequestHandler)
        self.httpd.runtime = self  # type: ignore[attr-defined]
        if background:
            self.thread = threading.Thread(
                target=self.httpd.serve_forever, name=f"serve:{self.port}", daemon=True,
            )
            self.thread.start()
        else:
            self.httpd.serve_forever()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None


class RateLimiter:
    """
    Token-bucket rate limiter, keyed by a caller-supplied string (zone|ip).

    Each key has a bucket of `capacity` tokens that refills at capacity/window
    tokens per second (pro-rated by elapsed time). A request consumes one token;
    if none are available it is rejected. This allows bursts up to `capacity`
    and a sustained rate of `capacity` per `window`.

    Stale buckets (unseen for > 2× their window) are purged lazily so a flood of
    unique keys can't grow the table without bound.
    """

    def __init__(self, cleanup_interval: float = 30.0):
        self._lock = threading.Lock()
        self._buckets: Dict[str, Tuple[float, float, float]] = {}  # key → (tokens, last, window)
        self._cleanup_interval = cleanup_interval
        self._last_cleanup = 0.0

    def check(self, key: str, capacity: int, window_seconds: float):
        """Return (allowed, remaining, retry_after, reset_seconds)."""
        import time as _time
        now = _time.monotonic()
        rate = capacity / window_seconds
        with self._lock:
            self._maybe_cleanup(now)
            tokens, last, _w = self._buckets.get(key, (float(capacity), now, window_seconds))
            tokens = min(float(capacity), tokens + (now - last) * rate)
            if tokens >= 1.0:
                tokens -= 1.0
                allowed = True
                retry_after = 0.0
            else:
                allowed = False
                retry_after = (1.0 - tokens) / rate
            self._buckets[key] = (tokens, now, window_seconds)
            remaining = int(tokens)
            reset = (capacity - tokens) / rate  # seconds until the bucket is full
            return allowed, remaining, retry_after, reset

    def _maybe_cleanup(self, now: float):
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        self._purge_locked(now)

    def _purge_locked(self, now: float):
        stale = [k for k, (t, last, w) in self._buckets.items() if now - last > 2 * w]
        for k in stale:
            del self._buckets[k]

    def purge(self):
        """Force a cleanup pass now (used by tests / maintenance)."""
        import time as _time
        with self._lock:
            self._purge_locked(_time.monotonic())

    def size(self) -> int:
        with self._lock:
            return len(self._buckets)


def _safe_unlink(path: Optional[str]):
    if path and os.path.exists(path):
        try:
            os.unlink(path)
        except OSError:
            pass


class _RequestHandler(BaseHTTPRequestHandler):
    """Adapts http.server requests onto ServeRuntime.dispatch."""

    protocol_version = "HTTP/1.1"

    def _write(self, status: int, body_obj: Any,
               extra_headers: Dict[str, str] = None, write_body: bool = True):
        # A RawResponse (html/respond/static) is written verbatim; anything else
        # follows the JSON contract.
        if isinstance(body_obj, RawResponse):
            body = body_obj.body
            payload = body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8")
            content_type = body_obj.content_type
        else:
            payload = json.dumps(body_obj).encode("utf-8")
            content_type = "application/json"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self._send_cors_headers()
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if write_body:
            self.wfile.write(payload)

    def _send_cors_headers(self):
        """Emit Access-Control-Allow-Origin when the serve block declared cors."""
        runtime = getattr(self.server, "runtime", None)
        origin = getattr(runtime, "cors_origin", None) if runtime else None
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)

    # -- body reading (counts real bytes, supports chunked, spills to disk) --

    def _iter_body(self):
        """Yield raw body byte-chunks, decoding Transfer-Encoding: chunked."""
        te = (self.headers.get("Transfer-Encoding", "") or "").lower()
        if "chunked" in te:
            while True:
                size_line = self.rfile.readline(65537).strip()
                if b";" in size_line:  # drop chunk extensions
                    size_line = size_line.split(b";", 1)[0].strip()
                if size_line == b"":
                    continue
                try:
                    chunk_size = int(size_line, 16)
                except ValueError:
                    break
                if chunk_size == 0:
                    self.rfile.readline()  # trailing CRLF after the last chunk
                    break
                yield self.rfile.read(chunk_size)
                self.rfile.readline()  # CRLF after each chunk
        else:
            remaining = int(self.headers.get("Content-Length", 0) or 0)
            while remaining > 0:
                block = self.rfile.read(min(65536, remaining))
                if not block:
                    break
                remaining -= len(block)
                yield block

    def _read_body(self, max_body: Optional[int]):
        """
        Read the request body, counting real bytes (never trusting
        Content-Length). Returns one of:
            ("mem", bytes)        small body kept in memory
            ("file", path)        large body spilled to a temp file
            ("too_large", None)   exceeded max_body — caller closes connection
        """
        spill_at = MEM_SPILL if max_body is None else min(max_body, MEM_SPILL)
        total = 0
        buf = bytearray()
        tmp = None
        tmp_path = None
        try:
            for chunk in self._iter_body():
                if not chunk:
                    continue
                total += len(chunk)
                if max_body is not None and total > max_body:
                    if tmp is not None:
                        tmp.close()
                        _safe_unlink(tmp_path)
                    return ("too_large", None)
                if tmp is None:
                    buf.extend(chunk)
                    if len(buf) > spill_at:
                        fd, tmp_path = tempfile.mkstemp(prefix="syn_body_")
                        tmp = os.fdopen(fd, "wb")
                        tmp.write(buf)
                        buf = bytearray()
                else:
                    tmp.write(chunk)
        except Exception:
            if tmp is not None:
                tmp.close()
                _safe_unlink(tmp_path)
            raise
        if tmp is not None:
            tmp.close()
            return ("file", tmp_path)
        return ("mem", bytes(buf))

    def _dispatch(self, method: str, write_body: bool = True):
        runtime: ServeRuntime = self.server.runtime  # type: ignore[attr-defined]
        body_file = None
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            query = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
            headers = {k: v for k, v in self.headers.items()}

            kind, payload = self._read_body(runtime.max_body)
            if kind == "too_large":
                # Don't leave an unread body on a live keep-alive connection:
                # respond and close (Go's MaxBytesReader pattern).
                self.close_connection = True
                self._write(
                    413, {"error": "payload too large", "status": 413},
                    write_body=write_body,
                )
                return
            if kind == "file":
                body_str = None
                body_file = payload
            else:
                body_str = payload.decode("utf-8", errors="replace") if payload else ""

            client_ip = self.client_address[0] if self.client_address else ""
            status, body_obj, extra, stream = runtime.dispatch(
                method, path, query, headers, body_str, body_file, client_ip,
            )
        except Exception as e:  # plumbing failure → 500, still no crash
            status, body_obj, extra, stream = 500, runtime.server_error(e), {}, None
        finally:
            if body_file:
                _safe_unlink(body_file)

        if stream is not None:
            route, ctx = stream
            self._stream_response(runtime, route, ctx, write_body)
            return

        self._write(status, body_obj, extra, write_body=write_body)

    def _stream_response(self, runtime: "ServeRuntime", route, ctx, write_body: bool):
        """Run an SSE route: send event-stream headers, then push events."""
        self.close_connection = True  # MVP: one stream per connection, then close
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")  # disable proxy buffering
            self.send_header("Connection", "close")
            self._send_cors_headers()
            self.end_headers()

            if not write_body:
                return  # HEAD probe: headers only

            def emit(value, event_name=None):
                payload = ""
                if event_name:
                    payload += f"event: {event_name}\n"
                payload += "data: " + json.dumps(syn_to_json(value)) + "\n\n"
                try:
                    self.wfile.write(payload.encode("utf-8"))
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionError, OSError):
                    raise ClientGone()

            try:
                route.stream_handler(ctx, emit)
            except ClientGone:
                pass  # client disconnected — unwind quietly
            except Exception as e:
                # Headers already sent; can't change status. Best-effort error event.
                try:
                    err = "event: error\ndata: " + json.dumps(
                        {"error": f"{type(e).__name__}: {e}"}
                    ) + "\n\n"
                    self.wfile.write(err.encode("utf-8"))
                    self.wfile.flush()
                except Exception:
                    pass
        finally:
            runtime.release_stream()

    def _handle(self):
        self._dispatch(self.command)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle

    def do_HEAD(self):
        # Same status + headers as GET, but no body.
        self._dispatch("GET", write_body=False)

    def do_OPTIONS(self):
        runtime: ServeRuntime = self.server.runtime  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        allowed = runtime.methods_for_path(parsed.path)
        if not allowed:
            self._write(404, {"error": f"no route for {parsed.path}", "status": 404})
            return
        allow = ", ".join(sorted(set(allowed + ["OPTIONS", "HEAD"])))
        self.send_response(204)
        self.send_header("Allow", allow)
        self.send_header("Content-Length", "0")
        # CORS preflight: advertise the methods/headers a browser may use.
        if getattr(runtime, "cors_origin", None):
            self.send_header("Access-Control-Allow-Origin", runtime.cors_origin)
            self.send_header("Access-Control-Allow-Methods", allow)
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def log_message(self, *args):  # keep the server quiet
        pass

"""
Syntecnia Native HTTP Server — zero dependencies, on top of http.server.

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
MAX_BODY = 1_048_576  # 1 MB — reject larger request bodies with 413

# Metadata flag marking a value produced by ok()/created()/not_found()/fail().
_ENVELOPE = "__serve_envelope__"

# Metadata flag marking a value produced by paged() (lazy SQL pagination).
_PAGED = "__serve_paged__"


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
    Turn a handler's give-value into (http_status, json_body) per the contract.
    Helper envelopes (ok/created/not_found/fail) carry an explicit status.
    """
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


def register_serve_builtins(env):
    """Register the response helpers: ok, created, not_found, fail."""

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

    builtins = {
        "ok": BuiltinTask("ok", _ok, 1),
        "created": BuiltinTask("created", _created, 1),
        "not_found": BuiltinTask("not_found", _not_found, 1),
        "fail": BuiltinTask("fail", _fail, -1),
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


class ServeRuntime:
    """
    Owns the HTTP server for one `serve on PORT` block.

    Route matching, auth, validation and the response contract are enforced
    here. The actual handler execution (per-request isolated interpreter) is
    supplied by the engine as the `handler` / `auth_handler` callables.
    """

    def __init__(self, port: int, routes: List[RouteSpec],
                 auth_handler: Optional[Callable[[str], Optional[SynValue]]] = None,
                 host: str = "0.0.0.0"):
        self.port = int(port)
        self.host = host
        self.routes = routes
        self.auth_handler = auth_handler
        self.httpd: Optional[ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    # -- matching --

    @staticmethod
    def _path_match(pattern: str, path: str) -> Optional[Dict[str, str]]:
        """Return captured params if `path` matches `pattern`, else None."""
        actual = [s for s in path.split("/") if s != ""]
        segs = [s for s in pattern.split("/") if s != ""]
        if len(segs) != len(actual):
            return None
        params: Dict[str, str] = {}
        for pat_seg, act_seg in zip(segs, actual):
            if pat_seg.startswith(":"):
                params[pat_seg[1:]] = unquote(act_seg)
            elif pat_seg != act_seg:
                return None
        return params

    def _match(self, method: str, path: str) -> Tuple[Optional[RouteSpec], Dict[str, str]]:
        for route in self.routes:
            if route.method != method:
                continue
            params = self._path_match(route.path, path)
            if params is not None:
                return route, params
        return None, {}

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
                 headers: Dict[str, str], body_str: str) -> Tuple[int, Any, Dict[str, str]]:
        """Return (status, json_body, extra_headers)."""
        route, params = self._match(method, path)
        if route is None:
            allowed = self.methods_for_path(path)
            if allowed:
                # The path exists, but not for this method → 405, advertise Allow.
                return (
                    405,
                    {"error": "method not allowed", "status": 405},
                    {"Allow": ", ".join(allowed)},
                )
            return 404, {"error": f"no route for {method} {path}", "status": 404}, {}

        json_obj = None
        if body_str:
            ctype = self._content_type(headers)
            try:
                json_obj = json.loads(body_str)
            except (ValueError, TypeError):
                # Only an error if the client claimed JSON; otherwise keep the
                # raw body available and json = nothing.
                if "json" in ctype:
                    return 400, {"error": "malformed JSON body", "status": 400}, {}
                json_obj = None

        ctx: Dict[str, Any] = {
            "method": method,
            "path": path,
            "query": query,
            "params": params,
            "headers": headers,
            "body": body_str,
            "json": json_obj,
            "user": None,
        }

        if route.requires_auth:
            token = self._bearer_token(headers)
            user = self.auth_handler(token) if self.auth_handler else None
            if user is None or isinstance(getattr(user, "type", None), SynNothing):
                return 401, {"error": "unauthorized", "status": 401}, {}
            ctx["user"] = user

        try:
            give_value = route.handler(ctx)
        except ExpectViolation as e:
            return 400, {"error": str(e), "status": 400, "field": e.field}, {}
        except GiveSignal as g:  # defensive: a give that escaped the handler
            give_value = g.value
        except CapabilityViolation as e:
            return 500, {"error": str(e), "status": 500}, {}
        except Exception as e:  # never crash the server
            return 500, {"error": f"{type(e).__name__}: {e}", "status": 500}, {}

        status, body = build_response(give_value, query)
        return status, body, {}

    # -- lifecycle --

    def start(self, background: bool = True):
        self.httpd = ThreadingHTTPServer((self.host, self.port), _RequestHandler)
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


class _RequestHandler(BaseHTTPRequestHandler):
    """Adapts http.server requests onto ServeRuntime.dispatch."""

    protocol_version = "HTTP/1.1"

    def _write(self, status: int, body_obj: Any,
               extra_headers: Dict[str, str] = None, write_body: bool = True):
        payload = json.dumps(body_obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if write_body:
            self.wfile.write(payload)

    def _dispatch(self, method: str, write_body: bool = True):
        runtime: ServeRuntime = self.server.runtime  # type: ignore[attr-defined]
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            query = {k: v[-1] for k, v in parse_qs(parsed.query).items()}

            length = int(self.headers.get("Content-Length", 0) or 0)
            if length > MAX_BODY:
                # Reject oversized payloads without reading the body.
                self._write(
                    413, {"error": "payload too large", "status": 413},
                    write_body=write_body,
                )
                return
            body = self.rfile.read(min(length, MAX_BODY)).decode("utf-8") if length else ""
            headers = {k: v for k, v in self.headers.items()}
            status, body_obj, extra = runtime.dispatch(method, path, query, headers, body)
        except Exception as e:  # plumbing failure → 500, still no crash
            status, body_obj, extra = 500, {"error": f"{type(e).__name__}: {e}", "status": 500}, {}

        self._write(status, body_obj, extra, write_body=write_body)

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
        self.end_headers()

    def log_message(self, *args):  # keep the server quiet
        pass

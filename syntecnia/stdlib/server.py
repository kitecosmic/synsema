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

# Metadata flag marking a value produced by ok()/created()/not_found()/fail().
_ENVELOPE = "__serve_envelope__"


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

def _paginate(list_value: SynValue, query: Dict[str, str]) -> Dict[str, Any]:
    """Apply limit + cursor/offset to a collection and build the page envelope."""
    items = list_value.raw
    total = len(items)

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

    page = items[offset:offset + limit]
    next_offset = offset + limit
    cursor = next_offset if next_offset < total else None

    return {
        "items": [syn_to_json(item) for item in page],
        "count": len(page),
        "total": total,
        "cursor": cursor,
    }


def _shape(value: Optional[SynValue], query: Dict[str, str]) -> Any:
    """Shape a handler's give-value into the JSON body per the contract."""
    if value is None:
        return None
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
        code = int(args[0].raw) if args and isinstance(args[0].type, SynNumber) else 400
        msg = str(args[1]) if len(args) > 1 else "error"
        body = syn_map({
            "error": syn_text(msg),
            "status": syn_number(code),
        })
        return _make_envelope(code, body)

    builtins = {
        "ok": BuiltinTask("ok", _ok, 1),
        "created": BuiltinTask("created", _created, 1),
        "not_found": BuiltinTask("not_found", _not_found, 1),
        "fail": BuiltinTask("fail", _fail, 2),
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

    def _match(self, method: str, path: str) -> Tuple[Optional[RouteSpec], Dict[str, str]]:
        actual = [s for s in path.split("/") if s != ""]
        for route in self.routes:
            if route.method != method:
                continue
            pattern = [s for s in route.path.split("/") if s != ""]
            if len(pattern) != len(actual):
                continue
            params: Dict[str, str] = {}
            matched = True
            for pat_seg, act_seg in zip(pattern, actual):
                if pat_seg.startswith(":"):
                    params[pat_seg[1:]] = unquote(act_seg)
                elif pat_seg != act_seg:
                    matched = False
                    break
            if matched:
                return route, params
        return None, {}

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

    def dispatch(self, method: str, path: str, query: Dict[str, str],
                 headers: Dict[str, str], body_str: str) -> Tuple[int, Any]:
        route, params = self._match(method, path)
        if route is None:
            return 404, {"error": f"no route for {method} {path}", "status": 404}

        json_obj = None
        if body_str:
            try:
                json_obj = json.loads(body_str)
            except (ValueError, TypeError):
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
                return 401, {"error": "unauthorized", "status": 401}
            ctx["user"] = user

        try:
            give_value = route.handler(ctx)
        except ExpectViolation as e:
            return 400, {"error": str(e), "status": 400, "field": e.field}
        except GiveSignal as g:  # defensive: a give that escaped the handler
            give_value = g.value
        except CapabilityViolation as e:
            return 500, {"error": str(e), "status": 500}
        except Exception as e:  # never crash the server
            return 500, {"error": f"{type(e).__name__}: {e}", "status": 500}

        return build_response(give_value, query)

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

    def _handle(self):
        runtime: ServeRuntime = self.server.runtime  # type: ignore[attr-defined]
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            query = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8") if length else ""
            headers = {k: v for k, v in self.headers.items()}
            status, body_obj = runtime.dispatch(self.command, path, query, headers, body)
        except Exception as e:  # plumbing failure → 500, still no crash
            status, body_obj = 500, {"error": f"{type(e).__name__}: {e}", "status": 500}

        payload = json.dumps(body_obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle

    def log_message(self, *args):  # keep the server quiet
        pass

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
    streaming: bool = False
    # For streaming routes: stream_handler(ctx, emit) pushes SSE events.
    stream_handler: Callable[[Dict[str, Any], Callable], None] = None


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
                 max_streams: int = DEFAULT_MAX_STREAMS):
        self.port = int(port)
        self.host = host
        self.routes = routes
        self.auth_handler = auth_handler
        self.max_body = max_body  # bytes, or None for unlimited
        self.max_streams = int(max_streams)
        self.httpd: Optional[ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self._stream_lock = threading.Lock()
        self._active_streams = 0

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
                 headers: Dict[str, str], body_str: Optional[str],
                 body_file: Optional[str] = None
                 ) -> Tuple[int, Any, Dict[str, str], Optional[Tuple]]:
        """Return (status, json_body, extra_headers, stream).

        `stream` is None for a normal one-shot response; for an SSE route that
        is ready to stream it is (route, ctx) and a stream slot has been
        acquired (the caller must call release_stream when done).

        body_str is the in-memory body text (or None when the body was spilled
        to disk, in which case body_file is the temp path).
        """
        route, params = self._match(method, path)
        if route is None:
            allowed = self.methods_for_path(path)
            if allowed:
                # The path exists, but not for this method → 405, advertise Allow.
                return (
                    405,
                    {"error": "method not allowed", "status": 405},
                    {"Allow": ", ".join(allowed)},
                    None,
                )
            return 404, {"error": f"no route for {method} {path}", "status": 404}, {}, None

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
            "user": None,
        }

        if route.requires_auth:
            token = self._bearer_token(headers)
            user = self.auth_handler(token) if self.auth_handler else None
            if user is None or isinstance(getattr(user, "type", None), SynNothing):
                return 401, {"error": "unauthorized", "status": 401}, {}, None
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
            return 400, {"error": str(e), "status": 400, "field": e.field}, {}, None
        except GiveSignal as g:  # defensive: a give that escaped the handler
            give_value = g.value
        except CapabilityViolation as e:
            return 500, {"error": str(e), "status": 500}, {}, None
        except Exception as e:  # never crash the server
            return 500, {"error": f"{type(e).__name__}: {e}", "status": 500}, {}, None

        status, body = build_response(give_value, query)
        return status, body, {}, None

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
        payload = json.dumps(body_obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        if self.close_connection:
            self.send_header("Connection", "close")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if write_body:
            self.wfile.write(payload)

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

            status, body_obj, extra, stream = runtime.dispatch(
                method, path, query, headers, body_str, body_file,
            )
        except Exception as e:  # plumbing failure → 500, still no crash
            status, body_obj, extra, stream = 500, {"error": f"{type(e).__name__}: {e}", "status": 500}, {}, None
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
        self.end_headers()

    def log_message(self, *args):  # keep the server quiet
        pass

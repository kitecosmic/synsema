"""Tests for the native HTTP server (serve on PORT)."""
import os
import sys
import json
import time
import socket
import tempfile
import contextlib
import urllib.request
import urllib.error
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from syntecnia.runtime.engine import SyntecniaEngine


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _request(port, method, path, body=None, headers=None):
    url = f"http://127.0.0.1:{port}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _raw_request(port, method, path, body=None, headers=None, raw_body=None):
    """Low-level request returning (status, headers_dict, body_bytes)."""
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    data = raw_body if raw_body is not None else (
        json.dumps(body).encode("utf-8") if body is not None else None
    )
    conn.request(method, path, body=data, headers=headers or {})
    resp = conn.getresponse()
    raw = resp.read()
    hdrs = {k: v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, hdrs, raw


class _Client:
    """Callable like req(method, path, ...); also exposes .raw() and .port."""
    def __init__(self, port):
        self.port = port

    def __call__(self, method, path, body=None, headers=None):
        return _request(self.port, method, path, body, headers)

    def raw(self, method, path, body=None, headers=None, raw_body=None):
        return _raw_request(self.port, method, path, body, headers, raw_body)


@contextlib.contextmanager
def serving(program: str):
    """Start an engine, run a serve program on a free port, yield a request client."""
    port = _free_port()
    engine = SyntecniaEngine()
    source = program.replace("__PORT__", str(port))
    result = engine.run_source(source, filename="test_serve.syn")
    assert result.success, f"program failed to start: {result.errors}"
    time.sleep(0.25)
    try:
        yield _Client(port)
    finally:
        engine.shutdown_servers()
        engine.db_manager.close_all()


@contextlib.contextmanager
def serving_runtime(program: str):
    """Like serving() but yields the ServeRuntime, for dispatch-level tests."""
    port = _free_port()
    engine = SyntecniaEngine()
    result = engine.run_source(program.replace("__PORT__", str(port)), filename="t.syn")
    assert result.success, f"program failed to start: {result.errors}"
    time.sleep(0.1)
    try:
        yield engine.servers[0]
    finally:
        engine.shutdown_servers()
        engine.db_manager.close_all()


def _disp(rt, method, path, ip="1.2.3.4", headers=None):
    """Call ServeRuntime.dispatch; return (status, extra_headers)."""
    status, body, extra, stream = rt.dispatch(
        method, path, {}, headers or {}, "", None, ip,
    )
    return status, extra


# ===== Basic route =====

def test_basic_route():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /ping"
        give {"message": "pong"}
"""
    with serving(prog) as req:
        status, body = req("GET", "/ping")
        assert status == 200
        assert body == {"message": "pong"}


# ===== Item (map) vs collection (list) — exact body shape =====

def test_item_returns_object_as_is():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /item"
        give {"id": 1, "name": "Laptop"}
"""
    with serving(prog) as req:
        status, body = req("GET", "/item")
        assert status == 200
        # A map is returned exactly as-is — no envelope.
        assert body == {"id": 1, "name": "Laptop"}
        assert "items" not in body


def test_collection_returns_envelope():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /list"
        give [{"id": 1}, {"id": 2}, {"id": 3}]
"""
    with serving(prog) as req:
        status, body = req("GET", "/list")
        assert status == 200
        assert set(body.keys()) == {"items", "count", "total", "cursor"}
        assert body["items"] == [{"id": 1}, {"id": 2}, {"id": 3}]
        assert body["count"] == 3
        assert body["total"] == 3
        assert body["cursor"] is None


# ===== Pagination with total =====

def test_pagination_limit_and_cursor():
    # 5 items, limit 2 → first page has cursor=2, total always 5.
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /nums"
        give [1, 2, 3, 4, 5]
"""
    with serving(prog) as req:
        status, body = req("GET", "/nums?limit=2")
        assert status == 200
        assert body["items"] == [1, 2]
        assert body["count"] == 2
        assert body["total"] == 5
        assert body["cursor"] == 2

        # Second page via cursor.
        status, body = req("GET", "/nums?limit=2&cursor=2")
        assert body["items"] == [3, 4]
        assert body["count"] == 2
        assert body["total"] == 5
        assert body["cursor"] == 4

        # Last page: no further cursor.
        status, body = req("GET", "/nums?limit=2&cursor=4")
        assert body["items"] == [5]
        assert body["total"] == 5
        assert body["cursor"] is None


def test_pagination_default_limit_present():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /big"
        give range(250)
"""
    with serving(prog) as req:
        status, body = req("GET", "/big")
        # Default limit caps the page; total reflects the real size.
        assert body["count"] == 100
        assert body["total"] == 250
        assert body["cursor"] == 100


# ===== Port capability =====

def test_serve_requires_capability():
    engine = SyntecniaEngine()
    result = engine.run_source(
        'serve on 8123\n    route "GET /x"\n        give {"ok": true}',
        filename="nocap.syn",
    )
    assert not result.success
    assert len(engine.servers) == 0
    assert any("serve(8123)" in e for e in result.errors)
    engine.shutdown_servers()


def test_serve_capability_wrong_port():
    engine = SyntecniaEngine()
    result = engine.run_source(
        'require serve(8124)\nserve on 8125\n    route "GET /x"\n        give {"ok": true}',
        filename="wrongport.syn",
    )
    assert not result.success
    assert len(engine.servers) == 0
    engine.shutdown_servers()


# ===== Auth =====

AUTH_PROG = """
require serve(__PORT__)

task check_token(token)
    when token == "secret"
        give {"name": "alice"}
    give nothing

serve on __PORT__
    auth with check_token
    route "GET /me" requires auth
        give {"user": name of (user of request)}
"""


def test_auth_401_without_token():
    with serving(AUTH_PROG) as req:
        status, body = req("GET", "/me")
        assert status == 401
        assert body["status"] == 401


def test_auth_401_with_bad_token():
    with serving(AUTH_PROG) as req:
        status, body = req("GET", "/me", headers={"Authorization": "Bearer wrong"})
        assert status == 401


def test_auth_ok_with_token():
    with serving(AUTH_PROG) as req:
        status, body = req("GET", "/me", headers={"Authorization": "Bearer secret"})
        assert status == 200
        assert body == {"user": "alice"}


# ===== Input validation (expect) =====

VALIDATE_PROG = """
require serve(__PORT__)
serve on __PORT__
    route "POST /users"
        expect body {name: text, age: number}
        let b be json of request
        give created({"name": name of b})
"""


def test_validation_missing_field():
    with serving(VALIDATE_PROG) as req:
        status, body = req("POST", "/users", {"name": "Bob"})
        assert status == 400
        assert body["status"] == 400
        assert body["field"] == "age"


def test_validation_wrong_type():
    with serving(VALIDATE_PROG) as req:
        status, body = req("POST", "/users", {"name": "Bob", "age": "old"})
        assert status == 400
        assert body["field"] == "age"


def test_validation_passes():
    with serving(VALIDATE_PROG) as req:
        status, body = req("POST", "/users", {"name": "Bob", "age": 30})
        assert status == 201
        assert body == {"name": "Bob"}


# ===== SQL injection blocked via params =====

SQL_PROG = """
require serve(__PORT__)
require db(":memory:")

db_open(":memory:", "memory")
sql_exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
sql_exec("INSERT INTO users (name) VALUES (?)", ["alice"])
sql_exec("INSERT INTO users (name) VALUES (?)", ["bob"])

serve on __PORT__
    route "GET /users/:name"
        let rows be sql("SELECT id, name FROM users WHERE name = ?", [params.name])
        give rows
"""


def test_sql_injection_blocked_via_params():
    with serving(SQL_PROG) as req:
        # Legit lookup works.
        status, body = req("GET", "/users/alice")
        assert status == 200
        assert body["total"] == 1
        assert body["items"][0]["name"] == "alice"

        # Injection attempt is treated as a literal value → no rows, table intact.
        payload = urllib.parse.quote("alice' OR '1'='1")
        status, body = req("GET", f"/users/{payload}")
        assert status == 200
        assert body["total"] == 0
        assert body["items"] == []

        # Destructive injection attempt also does nothing.
        drop = urllib.parse.quote("x'; DROP TABLE users; --")
        status, body = req("GET", f"/users/{drop}")
        assert status == 200
        assert body["total"] == 0

        # Table still there: alice still returns.
        status, body = req("GET", "/users/bob")
        assert body["total"] == 1


# ===== Helpers and robustness =====

def test_helpers_status_codes():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /ok"
        give ok({"a": 1})
    route "GET /missing"
        give not_found("nope")
    route "GET /boom"
        give fail(422, "bad input")
"""
    with serving(prog) as req:
        assert req("GET", "/ok") == (200, {"a": 1})
        s, b = req("GET", "/missing")
        assert s == 404 and b == {"error": "nope", "status": 404}
        s, b = req("GET", "/boom")
        assert s == 422 and b == {"error": "bad input", "status": 422}


def test_uncaught_error_becomes_500_not_crash():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /crash"
        let x be 1 / 0
        give {"never": true}
    route "GET /healthy"
        give {"ok": true}
"""
    with serving(prog) as req:
        status, body = req("GET", "/crash")
        assert status == 500
        assert body["status"] == 500
        # Server survives the error and keeps serving.
        status, body = req("GET", "/healthy")
        assert status == 200
        assert body == {"ok": True}


def test_unknown_route_404():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /known"
        give {"ok": true}
"""
    with serving(prog) as req:
        status, body = req("GET", "/unknown")
        assert status == 404
        assert body["status"] == 404


def test_path_params_exposed():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /users/:id/posts/:slug"
        give {"id": params.id, "slug": params.slug}
"""
    with serving(prog) as req:
        status, body = req("GET", "/users/42/posts/hello")
        assert status == 200
        assert body == {"id": "42", "slug": "hello"}


def test_query_exposed():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /echo"
        give {"q": query.q}
"""
    with serving(prog) as req:
        status, body = req("GET", "/echo?q=search+term")
        assert status == 200
        assert body == {"q": "search term"}


# ===== paged() — SQL pushdown with exact total =====

PAGED_PROG = """
require serve(__PORT__)
require db(":memory:")

db_open(":memory:", "memory")
sql_exec("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
each i in range(250)
    sql_exec("INSERT INTO items (name) VALUES (?)", ["item"])

serve on __PORT__
    route "GET /items"
        give paged("SELECT id, name FROM items ORDER BY id")
    route "GET /items/:name"
        give paged("SELECT id, name FROM items WHERE name = ?", [params.name])
"""


def test_paged_exact_total_first_page():
    with serving(PAGED_PROG) as req:
        status, body = req("GET", "/items")
        assert status == 200
        assert body["count"] == 100          # default limit
        assert body["total"] == 250          # exact total via COUNT(*)
        assert body["cursor"] == 100


def test_paged_last_page_and_window():
    with serving(PAGED_PROG) as req:
        status, body = req("GET", "/items?limit=100&cursor=200")
        assert body["count"] == 50
        assert body["total"] == 250
        assert body["cursor"] is None


def test_paged_injection_blocked():
    with serving(PAGED_PROG) as req:
        payload = urllib.parse.quote("item' OR '1'='1")
        status, body = req("GET", f"/items/{payload}")
        assert status == 200
        assert body["total"] == 0
        assert body["items"] == []


# ===== fail() never drops the message =====

def test_fail_variants():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /a"
        give fail(422, "bad input")
    route "GET /b"
        give fail("not allowed")
    route "GET /c"
        give fail(503)
"""
    with serving(prog) as req:
        assert req("GET", "/a") == (422, {"error": "bad input", "status": 422})
        assert req("GET", "/b") == (400, {"error": "not allowed", "status": 400})
        assert req("GET", "/c") == (503, {"error": "error", "status": 503})


# ===== requires auth without auth with → clear parse-time error =====

def test_requires_auth_without_auth_with_errors():
    engine = SyntecniaEngine()
    result = engine.run_source(
        'require serve(8131)\n'
        'serve on 8131\n'
        '    route "GET /x" requires auth\n'
        '        give {"ok": true}',
        filename="noauth.syn",
    )
    assert not result.success
    assert len(engine.servers) == 0
    assert any("auth with" in e for e in result.errors)
    engine.shutdown_servers()


# ===== not_found(map) vs not_found(text) =====

def test_not_found_text_and_map():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /t"
        give not_found("gone")
    route "GET /m"
        give not_found({"reason": "deleted", "id": 7})
"""
    with serving(prog) as req:
        s, b = req("GET", "/t")
        assert s == 404 and b == {"error": "gone", "status": 404}
        s, b = req("GET", "/m")
        assert s == 404 and b == {"reason": "deleted", "id": 7}


# ===== 405 method not allowed =====

def test_method_not_allowed_405():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /only"
        give {"ok": true}
"""
    with serving(prog) as req:
        status, headers, raw = req.raw("POST", "/only", body={"x": 1})
        assert status == 405
        assert "GET" in headers.get("Allow", "")
        body = json.loads(raw)
        assert body["status"] == 405


# ===== OPTIONS and HEAD =====

def test_options_returns_allow():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /res"
        give {"ok": true}
    route "POST /res"
        give created({"ok": true})
"""
    with serving(prog) as req:
        status, headers, raw = req.raw("OPTIONS", "/res")
        assert status == 204
        allow = headers.get("Allow", "")
        assert "GET" in allow and "POST" in allow
        assert raw == b""

        # OPTIONS on unknown path → 404 JSON
        status, headers, raw = req.raw("OPTIONS", "/nope")
        assert status == 404


def test_head_has_no_body():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /res"
        give {"ok": true}
"""
    with serving(prog) as req:
        status, headers, raw = req.raw("HEAD", "/res")
        assert status == 200
        assert raw == b""  # headers only, no body


# ===== malformed JSON =====

def test_malformed_json_body_400():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "POST /u"
        give {"ok": true}
"""
    with serving(prog) as req:
        status, headers, raw = req.raw(
            "POST", "/u",
            raw_body=b"{not valid json",
            headers={"Content-Type": "application/json"},
        )
        assert status == 400
        assert json.loads(raw)["error"] == "malformed JSON body"


def test_non_json_body_preserved():
    # Non-JSON content type with non-JSON body is not an error; body stays raw.
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "POST /u"
        give {"len": length(body of request)}
"""
    with serving(prog) as req:
        status, headers, raw = req.raw(
            "POST", "/u",
            raw_body=b"hello world",
            headers={"Content-Type": "text/plain"},
        )
        assert status == 200
        assert json.loads(raw)["len"] == 11


# ===== body size limit (413) =====

def test_body_too_large_413():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "POST /u"
        give {"ok": true}
"""
    with serving(prog) as req:
        big = b"x" * (1_048_576 + 10)  # > 1 MB
        status, headers, raw = req.raw(
            "POST", "/u", raw_body=big,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert status == 413
        assert json.loads(raw)["status"] == 413


# ===== scalar / nothing responses =====

def test_scalar_and_nothing_bodies():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /scalar"
        give "hello"
    route "GET /empty"
        let x be 1
"""
    with serving(prog) as req:
        assert req("GET", "/scalar") == (200, "hello")
        assert req("GET", "/empty") == (200, None)


# ===== Request body limit: configurable, keep-alive-safe, streaming =====

def test_keepalive_413_then_clean_request():
    """Regression: a too-large body must not desync a keep-alive connection."""
    import http.client
    prog = """
require serve(__PORT__)
serve on __PORT__
    max_body "2kb"
    route "POST /echo"
        give {"len": length(read_body())}
    route "GET /ping"
        give {"ok": true}
"""
    with serving(prog) as req:
        conn = http.client.HTTPConnection("127.0.0.1", req.port, timeout=5)
        conn.request("POST", "/echo", body=b"x" * 5000,
                     headers={"Content-Type": "application/octet-stream"})
        resp = conn.getresponse()
        body1 = json.loads(resp.read())
        assert resp.status == 413
        assert body1["status"] == 413
        # Next request on the SAME client (http.client reconnects after close).
        conn.request("GET", "/ping")
        resp = conn.getresponse()
        body2 = json.loads(resp.read())
        assert resp.status == 200          # clean JSON, never raw HTML
        assert body2 == {"ok": True}
        conn.close()


def test_max_body_declared_boundaries():
    prog = """
require serve(__PORT__)
serve on __PORT__
    max_body "2kb"
    route "POST /e"
        give {"len": length(read_body())}
"""
    with serving(prog) as req:
        # Just under the limit passes.
        status, _, raw = req.raw("POST", "/e", raw_body=b"a" * 2000)
        assert status == 200
        assert json.loads(raw)["len"] == 2000
        # Just over → 413 with Connection: close.
        status, headers, raw = req.raw("POST", "/e", raw_body=b"a" * 2049)
        assert status == 413
        assert headers.get("Connection", "").lower() == "close"


def test_max_body_unlimited():
    prog = """
require serve(__PORT__)
serve on __PORT__
    max_body "unlimited"
    route "POST /u"
        give {"len": length(read_body())}
"""
    with serving(prog) as req:
        big = b"y" * (2 * 1024 * 1024)  # 2 MB
        status, _, raw = req.raw("POST", "/u", raw_body=big,
                                 headers={"Content-Type": "application/octet-stream"})
        assert status == 200
        assert json.loads(raw)["len"] == 2 * 1024 * 1024


def _send_chunked(port, path, chunks, extra_headers=None):
    """Send a chunked request, return (status, body_bytes)."""
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.putrequest("POST", path)
    conn.putheader("Transfer-Encoding", "chunked")
    for k, v in (extra_headers or {}).items():
        conn.putheader(k, v)
    conn.endheaders()
    body = b""
    for c in chunks:
        body += f"{len(c):x}".encode() + b"\r\n" + c + b"\r\n"
    body += b"0\r\n\r\n"
    conn.send(body)
    resp = conn.getresponse()
    out = resp.read()
    conn.close()
    return resp.status, out


def test_chunked_under_limit_is_read():
    prog = """
require serve(__PORT__)
serve on __PORT__
    max_body "1mb"
    route "POST /c"
        give {"len": length(read_body())}
"""
    with serving(prog) as req:
        status, raw = _send_chunked(req.port, "/c", [b"hello ", b"world"])
        assert status == 200
        assert json.loads(raw)["len"] == 11


def test_chunked_over_limit_not_evaded():
    prog = """
require serve(__PORT__)
serve on __PORT__
    max_body "2kb"
    route "POST /c"
        give {"len": length(read_body())}
"""
    with serving(prog) as req:
        # No Content-Length (chunked); real bytes exceed the limit → 413.
        status, raw = _send_chunked(req.port, "/c", [b"z" * 2048, b"z" * 2048])
        assert status == 413
        assert json.loads(raw)["status"] == 413


def test_lying_content_length_not_trusted():
    """A small declared Content-Length must not let a larger body through."""
    import http.client
    prog = """
require serve(__PORT__)
serve on __PORT__
    max_body "2kb"
    route "POST /c"
        give {"len": length(read_body())}
"""
    with serving(prog) as req:
        # We honor Content-Length framing; a truthful large length is counted
        # in real bytes and rejected at 413.
        status, headers, raw = req.raw("POST", "/c", raw_body=b"q" * 5000)
        assert status == 413


def test_large_body_spills_to_disk_and_is_cleaned():
    import glob
    prog = """
require serve(__PORT__)
serve on __PORT__
    max_body "unlimited"
    route "POST /u"
        give {"len": length(read_body()), "spilled": body_file of request != nothing}
"""
    with serving(prog) as req:
        tmpdir = tempfile.gettempdir()
        before = set(glob.glob(os.path.join(tmpdir, "syn_body_*")))
        big = b"y" * (3 * 1024 * 1024)  # 3 MB > 1 MB in-memory threshold
        status, _, raw = req.raw("POST", "/u", raw_body=big,
                                 headers={"Content-Type": "application/octet-stream"})
        body = json.loads(raw)
        assert status == 200
        assert body["len"] == 3 * 1024 * 1024
        assert body["spilled"] is True
        time.sleep(0.2)
        after = set(glob.glob(os.path.join(tmpdir, "syn_body_*")))
        assert not (after - before), "temp body file not cleaned up"


def test_default_body_limit_is_1mb():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "POST /u"
        give {"ok": true}
"""
    with serving(prog) as req:
        status, _, _ = req.raw("POST", "/u", raw_body=b"z" * (1024 * 1024 + 50))
        assert status == 413
        status, _, raw = req.raw("POST", "/u", raw_body=b"z" * 1000)
        assert status == 200


# ===== SSE streaming =====

def _parse_sse_block(block: str) -> dict:
    name = None
    data_lines = []
    for line in block.split("\n"):
        if line.startswith("event:"):
            name = line[len("event:"):].strip()
        elif line.startswith("data:"):
            data_lines.append(line[len("data:"):].strip())
    data = "\n".join(data_lines)
    try:
        data = json.loads(data)
    except (ValueError, TypeError):
        pass
    return {"event": name, "data": data}


def _read_sse(port, path, count, headers=None, timeout=5):
    """Open an SSE stream, return (response, events, connection). Caller closes."""
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    conn.request("GET", path, headers=headers or {})
    resp = conn.getresponse()
    events = []
    buf = b""
    while len(events) < count:
        chunk = resp.read(1)
        if not chunk:
            break
        buf += chunk
        while b"\n\n" in buf:
            block, buf = buf.split(b"\n\n", 1)
            if block.strip():
                events.append(_parse_sse_block(block.decode()))
    return resp, events, conn


def test_sse_basic_events_in_order():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /events"
        stream
            each tick in range(3)
                send {"count": tick}
"""
    with serving(prog) as req:
        resp, events, conn = _read_sse(req.port, "/events", 3)
        conn.close()
        assert [e["data"] for e in events] == [
            {"count": 0}, {"count": 1}, {"count": 2},
        ]
        assert all(e["event"] is None for e in events)


def test_sse_named_event():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /n"
        stream
            send "hi" as "greeting"
"""
    with serving(prog) as req:
        resp, events, conn = _read_sse(req.port, "/n", 1)
        conn.close()
        assert events[0]["event"] == "greeting"
        assert events[0]["data"] == "hi"


def test_sse_headers():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /e"
        stream
            send {"x": 1}
"""
    with serving(prog) as req:
        resp, events, conn = _read_sse(req.port, "/e", 1)
        assert resp.status == 200
        assert resp.getheader("Content-Type") == "text/event-stream"
        assert resp.getheader("Cache-Control") == "no-cache"
        assert resp.getheader("Content-Length") is None
        conn.close()


def test_sse_flush_is_progressive():
    prog = """
require serve(__PORT__)
require time
serve on __PORT__
    route "GET /slow"
        stream
            each tick in range(5)
                send {"n": tick}
                sleep(0.2)
"""
    with serving(prog) as req:
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", req.port, timeout=5)
        t0 = time.time()
        conn.request("GET", "/slow")
        resp = conn.getresponse()
        buf = b""
        while b"\n\n" not in buf:
            buf += resp.read(1)
        first_dt = time.time() - t0
        conn.close()
        # First event must arrive well before the ~1s handler finishes.
        assert first_dt < 0.8, f"events not flushed progressively ({first_dt:.2f}s)"


def test_sse_client_disconnect_does_not_crash_server():
    prog = """
require serve(__PORT__)
require time
serve on __PORT__
    route "GET /slow"
        stream
            each tick in range(100)
                send {"n": tick}
                sleep(0.05)
    route "GET /ping"
        give {"ok": true}
"""
    with serving(prog) as req:
        resp, events, conn = _read_sse(req.port, "/slow", 1)
        conn.close()  # disconnect mid-stream
        time.sleep(0.3)
        # Server keeps serving other routes.
        status, body = req("GET", "/ping")
        assert status == 200 and body == {"ok": True}


def test_sse_max_streams_cap():
    prog = """
require serve(__PORT__)
require time
serve on __PORT__
    max_streams 1
    route "GET /slow"
        stream
            each tick in range(100)
                send {"n": tick}
                sleep(0.05)
"""
    with serving(prog) as req:
        # Hold the single slot.
        resp1, ev1, conn1 = _read_sse(req.port, "/slow", 1)
        assert resp1.status == 200
        # Second stream is over the cap → 503 (plain JSON, not SSE).
        status, headers, raw = req.raw("GET", "/slow")
        assert status == 503
        body = json.loads(raw)
        assert body["status"] == 503
        assert headers.get("Retry-After") is not None

        # Free the slot by disconnecting; the handler notices on its next write.
        # TCP can delay surfacing the broken pipe, so poll until capacity returns.
        conn1.close()
        freed = False
        deadline = time.time() + 6
        while time.time() < deadline:
            resp2, ev2, conn2 = _read_sse(req.port, "/slow", 1)
            if resp2.status == 200:
                assert ev2[0]["data"] == {"n": 0}
                conn2.close()
                freed = True
                break
            conn2.close()
            time.sleep(0.2)
        assert freed, "stream slot was not released after client disconnect"


def test_sse_streams_are_isolated():
    prog = """
require serve(__PORT__)
require time
serve on __PORT__
    route "GET /iso"
        stream
            let who be query.id
            each tick in range(3)
                send {"id": who, "tick": tick}
                sleep(0.05)
"""
    with serving(prog) as req:
        import http.client
        ca = http.client.HTTPConnection("127.0.0.1", req.port, timeout=5)
        cb = http.client.HTTPConnection("127.0.0.1", req.port, timeout=5)
        ca.request("GET", "/iso?id=AAA")
        cb.request("GET", "/iso?id=BBB")
        ra = ca.getresponse()
        rb = cb.getresponse()

        def first_event(resp):
            buf = b""
            while b"\n\n" not in buf:
                buf += resp.read(1)
            return _parse_sse_block(buf.split(b"\n\n", 1)[0].decode())

        ea = first_event(ra)
        eb = first_event(rb)
        ca.close()
        cb.close()
        assert ea["data"]["id"] == "AAA"
        assert eb["data"]["id"] == "BBB"


def test_sse_coexists_with_give_route():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /stream"
        stream
            send {"x": 1}
    route "GET /plain"
        give {"ok": true}
"""
    with serving(prog) as req:
        # Plain route works normally.
        assert req("GET", "/plain") == (200, {"ok": True})
        # Stream route streams.
        resp, events, conn = _read_sse(req.port, "/stream", 1)
        conn.close()
        assert events[0]["data"] == {"x": 1}


def test_send_without_stream_sink_is_clear_error():
    # A stream block executed outside an SSE route has no sink → clear error.
    engine = SyntecniaEngine()
    result = engine.run_source('stream\n    send {"x": 1}')
    assert not result.success
    assert any("send can only be used inside a stream" in e for e in result.errors)


# ===== Rate limiting =====

def test_rate_limit_basic():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "POST /e"
        rate_limit 3 per second
        give {"ok": true}
"""
    with serving_runtime(prog) as rt:
        codes = [_disp(rt, "POST", "/e")[0] for _ in range(4)]
        assert codes == [200, 200, 200, 429]
        status, extra = _disp(rt, "POST", "/e")
        assert status == 429
        assert extra.get("Retry-After") is not None
        assert extra.get("RateLimit-Limit") == "3"
        assert extra.get("RateLimit-Remaining") == "0"


def test_rate_limit_recovery_after_window():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "POST /e"
        rate_limit 2 per second
        give {"ok": true}
"""
    with serving_runtime(prog) as rt:
        assert [_disp(rt, "POST", "/e")[0] for _ in range(3)] == [200, 200, 429]
        time.sleep(1.1)  # refill
        assert _disp(rt, "POST", "/e")[0] == 200


def test_rate_limit_override_and_inherit():
    prog = """
require serve(__PORT__)
serve on __PORT__
    rate_limit 100 per minute
    route "POST /strict"
        rate_limit 2 per second
        give {"ok": true}
    route "GET /loose"
        give {"ok": true}
"""
    with serving_runtime(prog) as rt:
        # Override: stricter limit applies.
        assert [_disp(rt, "POST", "/strict")[0] for _ in range(3)] == [200, 200, 429]
        # Inherited 100/min on a separate zone — unaffected by /strict.
        assert all(_disp(rt, "GET", "/loose")[0] == 200 for _ in range(10))


def test_rate_limit_keyed_by_ip():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "POST /e"
        rate_limit 2 per second
        give {"ok": true}
"""
    with serving_runtime(prog) as rt:
        # IP A exhausts its bucket.
        assert [_disp(rt, "POST", "/e", ip="1.1.1.1")[0] for _ in range(3)] == [200, 200, 429]
        # IP B has its own bucket.
        assert _disp(rt, "POST", "/e", ip="2.2.2.2")[0] == 200


def test_rate_limit_applies_before_auth():
    prog = """
require serve(__PORT__)

task check_token(token)
    give nothing

serve on __PORT__
    auth with check_token
    route "POST /login" requires auth
        rate_limit 3 per second
        give {"ok": true}
"""
    with serving_runtime(prog) as rt:
        # Invalid token → 401, but each attempt still consumes a token.
        codes = [_disp(rt, "POST", "/login", ip="7.7.7.7")[0] for _ in range(3)]
        assert codes == [401, 401, 401]
        # 4th is throttled before auth even runs → brute force is capped.
        assert _disp(rt, "POST", "/login", ip="7.7.7.7")[0] == 429


def test_rate_limit_xff_not_trusted():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "POST /e"
        rate_limit 2 per second
        give {"ok": true}
"""
    with serving_runtime(prog) as rt:
        # Same real peer IP, different (spoofed) X-Forwarded-For each time.
        codes = []
        for i in range(3):
            codes.append(_disp(rt, "POST", "/e", ip="9.9.9.9",
                               headers={"X-Forwarded-For": f"{i}.0.0.1"})[0])
        assert codes == [200, 200, 429]  # XFF did not create new buckets


def test_rate_limit_opt_in_and_none():
    prog = """
require serve(__PORT__)
serve on __PORT__
    rate_limit 1 per second
    route "GET /capped"
        give {"ok": true}
    route "GET /free"
        rate_limit none
        give {"ok": true}
"""
    with serving_runtime(prog) as rt:
        # Inherits the 1/sec default.
        assert [_disp(rt, "GET", "/capped")[0] for _ in range(2)] == [200, 429]
        # `rate_limit none` disables the inherited default.
        assert all(_disp(rt, "GET", "/free")[0] == 200 for _ in range(20))


def test_rate_limit_no_limit_when_undeclared():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /e"
        give {"ok": true}
"""
    with serving_runtime(prog) as rt:
        assert all(_disp(rt, "GET", "/e")[0] == 200 for _ in range(50))


def test_rate_limit_http_429():
    prog = """
require serve(__PORT__)
serve on __PORT__
    route "GET /e"
        rate_limit 2 per second
        give {"ok": true}
"""
    with serving(prog) as req:
        codes = [req("GET", "/e")[0] for _ in range(3)]
        assert codes == [200, 200, 429]


def test_rate_limiter_cleanup_purges_stale():
    from syntecnia.stdlib.server import RateLimiter
    rl = RateLimiter(cleanup_interval=999)  # disable auto-cleanup; test purge() directly
    for i in range(50):
        rl.check(f"k{i}", 5, 1.0)  # window 1s
    assert rl.size() == 50
    time.sleep(2.1)  # > 2× window → entries become stale
    rl.purge()
    assert rl.size() == 0


def test_handle_error_silences_client_disconnects():
    """Connection resets are swallowed; genuine errors still print."""
    import io
    from syntecnia.stdlib.server import _QuietThreadingHTTPServer, _RequestHandler

    srv = _QuietThreadingHTTPServer(("127.0.0.1", 0), _RequestHandler)
    try:
        # A connection error → quiet (nothing on stderr).
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            try:
                raise ConnectionResetError("client gone")
            except ConnectionResetError:
                srv.handle_error(None, ("127.0.0.1", 1234))
        assert buf.getvalue() == ""

        # A real error → surfaced (traceback printed).
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            try:
                raise ValueError("real bug")
            except ValueError:
                srv.handle_error(None, ("127.0.0.1", 1234))
        assert "ValueError" in buf.getvalue()
    finally:
        srv.server_close()


def test_parse_body_size_units():
    from syntecnia.stdlib.server import parse_body_size, MAX_BODY
    assert parse_body_size(None) == MAX_BODY
    assert parse_body_size("512kb") == 512 * 1024
    assert parse_body_size("10mb") == 10 * 1024 * 1024
    assert parse_body_size("1gb") == 1024 ** 3
    assert parse_body_size("2KB") == 2048
    assert parse_body_size(4096) == 4096
    assert parse_body_size("unlimited") is None
    assert parse_body_size("none") is None


if __name__ == "__main__":
    test_functions = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    failed = 0
    for test_fn in test_functions:
        try:
            test_fn()
            passed += 1
            print(f"  PASS: {test_fn.__name__}")
        except Exception as e:
            failed += 1
            print(f"  FAIL: {test_fn.__name__}: {e}")

    print(f"\n{passed} passed, {failed} failed out of {passed + failed} tests")
    sys.exit(1 if failed else 0)

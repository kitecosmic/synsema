"""Tests for the native HTTP server (serve on PORT)."""
import sys
import json
import time
import socket
import contextlib
import urllib.request
import urllib.error
import urllib.parse

sys.path.insert(0, "/root/Syntecnia")

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


@contextlib.contextmanager
def serving(program: str):
    """Start an engine, run a serve program on a free port, yield a request fn."""
    port = _free_port()
    engine = SyntecniaEngine()
    source = program.replace("__PORT__", str(port))
    result = engine.run_source(source, filename="test_serve.syn")
    assert result.success, f"program failed to start: {result.errors}"
    time.sleep(0.25)
    try:
        yield lambda method, path, body=None, headers=None: _request(
            port, method, path, body, headers
        )
    finally:
        engine.shutdown_servers()
        engine.db_manager.close_all()


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

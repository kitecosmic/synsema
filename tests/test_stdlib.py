"""Tests for Syntecnia stdlib: HTTP, Database, Cron."""
import sys
import time
import os
sys.path.insert(0, "/root/Syntecnia")

from syntecnia.runtime.engine import SyntecniaEngine
from syntecnia.stdlib.http import http_request
from syntecnia.stdlib.database import DatabaseManager
from syntecnia.stdlib.cron import CronScheduler


# ===== HTTP (unit tests on the raw function) =====

def test_http_request_invalid_url():
    result = http_request("GET", "http://this-does-not-exist-12345.invalid")
    assert result["ok"] is False
    assert result["status"] == 0
    assert "error" in result


def test_http_builtins_in_engine():
    """http_get/http_post are available as builtins."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
let response be http_get("http://localhost:99999")
print(text(ok of response))
print(text(status of response))
""")
    assert result.success
    assert result.output[0] == "false"  # can't connect


def test_http_full_syntax():
    """The http() builtin accepts method, url, headers, query, body."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
let r be http("GET", "http://localhost:99999", {"Accept": "application/json"}, {"page": "1"})
print(text(ok of r))
""")
    assert result.success


# ===== Database =====

def test_db_manager_basic():
    db = DatabaseManager()
    db.open(":memory:", "memory")
    db.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    db.execute("INSERT INTO items (name, price) VALUES (?, ?)", ["Laptop", 999.99])
    db.execute("INSERT INTO items (name, price) VALUES (?, ?)", ["Mouse", 29.99])
    rows = db.query("SELECT * FROM items ORDER BY price")
    assert len(rows) == 2
    assert rows[0]["name"] == "Mouse"
    assert rows[1]["price"] == 999.99
    db.close()


def test_db_tables():
    db = DatabaseManager()
    db.open(":memory:", "memory")
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    db.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, total REAL)")
    tables = db.tables()
    assert "users" in tables
    assert "orders" in tables
    db.close()


def test_db_batch():
    db = DatabaseManager()
    db.open(":memory:", "memory")
    db.execute("CREATE TABLE nums (val INTEGER)")
    db.execute_many("INSERT INTO nums VALUES (?)", [[1], [2], [3], [4], [5]])
    rows = db.query("SELECT * FROM nums")
    assert len(rows) == 5
    db.close()


def test_db_builtins_in_engine():
    """SQL builtins work from Syntecnia code."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
db_open(":memory:", "memory")
sql_exec("CREATE TABLE products (name TEXT, price REAL)")
sql_exec("INSERT INTO products VALUES (?, ?)", ["Laptop", 999])
sql_exec("INSERT INTO products VALUES (?, ?)", ["Mouse", 29])
let products be sql("SELECT * FROM products ORDER BY price")
each p in products
    print(name of p + ": $" + text(price of p))
let tables be sql_tables()
print("Tables: " + text(length(tables)))
db_close()
""")
    assert result.success, f"Errors: {result.errors}"
    assert "Mouse" in result.output[0] and "29" in result.output[0]
    assert "Laptop" in result.output[1] and "999" in result.output[1]
    assert result.output[2] == "Tables: 1"


def test_db_file_persistence():
    """Database persists to file."""
    db_path = "/tmp/syntecnia_test.db"
    try:
        engine = SyntecniaEngine()
        result = engine.run_source(f"""
db_open("{db_path}")
sql_exec("CREATE TABLE IF NOT EXISTS test (val TEXT)")
sql_exec("INSERT INTO test VALUES (?)", ["hello"])
db_close()
""")
        assert result.success

        # Read back in new engine
        engine2 = SyntecniaEngine()
        result2 = engine2.run_source(f"""
db_open("{db_path}")
let rows be sql("SELECT * FROM test")
print(text(length(rows)))
db_close()
""")
        assert result2.success
        assert result2.output == ["1"]
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_db_parameterized_query():
    """Parameters prevent SQL injection."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
db_open(":memory:", "memory")
sql_exec("CREATE TABLE users (name TEXT)")
sql_exec("INSERT INTO users VALUES (?)", ["Alice"])
sql_exec("INSERT INTO users VALUES (?)", ["Bob"])
let name be "Alice"
let found be sql("SELECT * FROM users WHERE name = ?", [name])
print(text(length(found)))
db_close()
""")
    assert result.success
    assert result.output == ["1"]


# ===== Cron =====

def test_cron_scheduler_basic():
    scheduler = CronScheduler()
    counter = [0]
    def increment():
        counter[0] += 1

    scheduler.every(0.1, "counter", increment)
    time.sleep(0.35)
    scheduler.cancel("counter")
    assert counter[0] >= 2  # should have run 2-3 times


def test_cron_after():
    scheduler = CronScheduler()
    result = [None]
    def set_result():
        result[0] = "done"

    scheduler.after(0.1, "delayed", set_result)
    time.sleep(0.3)
    assert result[0] == "done"
    # Should not repeat
    result[0] = None
    time.sleep(0.2)
    assert result[0] is None


def test_cron_cancel():
    scheduler = CronScheduler()
    counter = [0]
    scheduler.every(0.1, "test", lambda: counter.__setitem__(0, counter[0] + 1))
    time.sleep(0.15)
    scheduler.cancel("test")
    count_at_cancel = counter[0]
    time.sleep(0.3)
    assert counter[0] == count_at_cancel  # stopped incrementing


def test_cron_list():
    scheduler = CronScheduler()
    scheduler.every(60, "job1", lambda: None)
    scheduler.every(120, "job2", lambda: None)
    jobs = scheduler.list_jobs()
    assert len(jobs) == 2
    names = [j["name"] for j in jobs]
    assert "job1" in names
    assert "job2" in names
    scheduler.cancel_all()


def test_cron_builtins_in_engine():
    """Cron builtins work from Syntecnia code."""
    engine = SyntecniaEngine()
    result = engine.run_source("""
task ticker()
    log "tick"

cron_every(60, ticker)
let jobs be cron_list()
print(text(length(jobs)))
print(cron_status())
cron_cancel("ticker")
""")
    assert result.success, f"Errors: {result.errors}"
    assert result.output[0] == "1"
    assert "ticker" in result.output[1]
    engine.cron_scheduler.cancel_all()


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

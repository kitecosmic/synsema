"""
Syntecnia Native Database — Zero-dependency SQL.

Uses sqlite3 (Python stdlib). The pattern is extensible to other DBs.

    require db("./store.db")

    let products be sql("SELECT * FROM products WHERE price > ?", [100])
    -- returns list of maps: [{"id": 1, "name": "Laptop", "price": 1299}, ...]

    sql_exec("INSERT INTO orders (product, quantity) VALUES (?, ?)", ["Laptop", 1])
    -- returns {"rows_affected": 1, "last_id": 42}

    sql_exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")

Connection management:
    db_open("./store.db")           -- open/create database
    db_open("./store.db", "readonly")  -- read-only mode
    db_close()                      -- close connection

    -- Or automatic: first sql() call auto-opens if db was required
"""

import sqlite3
from typing import Dict, List, Optional, Any


class DatabaseManager:
    """
    Manages SQLite connections for Syntecnia programs.
    Thread-safe per connection. Each agent should get its own manager.
    """

    def __init__(self):
        self.connections: Dict[str, sqlite3.Connection] = {}
        self.default_db: Optional[str] = None

    def open(self, path: str, mode: str = "readwrite") -> str:
        """Open a database connection. Returns the path as identifier."""
        if path in self.connections:
            return path

        if mode == "readonly":
            uri = f"file:{path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
        elif mode == "memory":
            conn = sqlite3.connect(":memory:")
            path = ":memory:"
        else:
            conn = sqlite3.connect(path)

        conn.row_factory = sqlite3.Row
        self.connections[path] = conn
        if self.default_db is None:
            self.default_db = path
        return path

    def close(self, path: str = None):
        """Close a database connection."""
        target = path or self.default_db
        if target and target in self.connections:
            self.connections[target].close()
            del self.connections[target]
            if self.default_db == target:
                self.default_db = next(iter(self.connections), None)

    def close_all(self):
        for path in list(self.connections.keys()):
            self.close(path)

    def _get_conn(self, path: str = None) -> sqlite3.Connection:
        target = path or self.default_db
        if not target or target not in self.connections:
            raise RuntimeError(
                "No database connection. Use db_open(\"path.db\") first."
            )
        return self.connections[target]

    def query(self, sql: str, params: list = None,
              db: str = None) -> List[Dict[str, Any]]:
        """Execute a SELECT query, return list of row dicts."""
        conn = self._get_conn(db)
        cursor = conn.execute(sql, params or [])
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        rows = []
        for row in cursor.fetchall():
            rows.append({col: row[i] for i, col in enumerate(columns)})
        return rows

    def execute(self, sql: str, params: list = None,
                db: str = None) -> Dict[str, Any]:
        """Execute an INSERT/UPDATE/DELETE/CREATE, return result info."""
        conn = self._get_conn(db)
        cursor = conn.execute(sql, params or [])
        conn.commit()
        return {
            "rows_affected": cursor.rowcount,
            "last_id": cursor.lastrowid,
        }

    def execute_many(self, sql: str, params_list: List[list],
                     db: str = None) -> Dict[str, Any]:
        """Execute a statement with multiple parameter sets (batch)."""
        conn = self._get_conn(db)
        cursor = conn.executemany(sql, params_list)
        conn.commit()
        return {
            "rows_affected": cursor.rowcount,
        }

    def tables(self, db: str = None) -> List[str]:
        """List all tables in the database."""
        rows = self.query(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
            db=db,
        )
        return [r["name"] for r in rows]


def register_database_builtins(env, db_manager: DatabaseManager):
    """Register database builtins in a Syntecnia environment."""
    from ..core.types import (
        SynValue, BuiltinTask, SynTask,
        syn_number, syn_text, syn_bool, syn_nothing, syn_list, syn_map,
        SynMap, SynText, SynList, SynNumber,
    )

    def _python_to_syn(val) -> SynValue:
        if val is None:
            return syn_nothing()
        if isinstance(val, bool):
            return syn_bool(val)
        if isinstance(val, (int, float)):
            return syn_number(val)
        if isinstance(val, str):
            return syn_text(val)
        if isinstance(val, bytes):
            return syn_text(val.decode("utf-8", errors="replace"))
        return syn_text(str(val))

    def _syn_to_python(val: SynValue):
        if isinstance(val.type, SynNumber):
            return val.raw
        return str(val) if str(val) != "nothing" else None

    def _db_open(args):
        """db_open(path, mode?)"""
        path = str(args[0].raw)
        mode = str(args[1].raw) if len(args) > 1 else "readwrite"
        db_manager.open(path, mode)
        return syn_bool(True)

    def _db_close(args):
        """db_close(path?)"""
        path = str(args[0].raw) if args else None
        db_manager.close(path)
        return syn_bool(True)

    def _sql(args):
        """sql(query, params?) → list of row maps"""
        query = str(args[0].raw)
        params = []
        if len(args) > 1 and isinstance(args[1].type, SynList):
            params = [_syn_to_python(p) for p in args[1].raw]

        rows = db_manager.query(query, params)
        result = []
        for row in rows:
            row_map = {k: _python_to_syn(v) for k, v in row.items()}
            result.append(syn_map(row_map))
        return syn_list(result)

    def _sql_exec(args):
        """sql_exec(statement, params?) → {rows_affected, last_id}"""
        statement = str(args[0].raw)
        params = []
        if len(args) > 1 and isinstance(args[1].type, SynList):
            params = [_syn_to_python(p) for p in args[1].raw]

        result = db_manager.execute(statement, params)
        return syn_map({
            "rows_affected": syn_number(result["rows_affected"]),
            "last_id": syn_number(result["last_id"] or 0),
        })

    def _sql_tables(args):
        """sql_tables() → list of table names"""
        tables = db_manager.tables()
        return syn_list([syn_text(t) for t in tables])

    def _sql_batch(args):
        """sql_batch(statement, params_list) → {rows_affected}"""
        statement = str(args[0].raw)
        params_list = []
        if len(args) > 1 and isinstance(args[1].type, SynList):
            for params_syn in args[1].raw:
                if isinstance(params_syn.type, SynList):
                    params_list.append([_syn_to_python(p) for p in params_syn.raw])

        result = db_manager.execute_many(statement, params_list)
        return syn_map({"rows_affected": syn_number(result["rows_affected"])})

    builtins = {
        "db_open": BuiltinTask("db_open", _db_open),
        "db_close": BuiltinTask("db_close", _db_close),
        "sql": BuiltinTask("sql", _sql),
        "sql_exec": BuiltinTask("sql_exec", _sql_exec),
        "sql_tables": BuiltinTask("sql_tables", _sql_tables, 0),
        "sql_batch": BuiltinTask("sql_batch", _sql_batch, 2),
    }
    for name, builtin in builtins.items():
        env.set(name, SynValue(raw=builtin, type=SynTask()))

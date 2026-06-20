//! SQL nativo (SQLite). Port de `syntecnia/stdlib/database.py`.
//!
//! `DatabaseManager` mantiene conexiones por path (con un `default_db`). Usa
//! `rusqlite` con SQLite estático (`bundled`). En autocommit (como el commit por
//! sentencia del oráculo). `query` devuelve filas como mapas columna→valor.
//!
//! Capa 6: acceso single-thread (un run por hilo). El acceso compartido desde los
//! hilos de `serve` (capa 8) requerirá Mutex; se aborda entonces.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use indexmap::IndexMap;
use rusqlite::types::Value;
use rusqlite::{params_from_iter, Connection, OpenFlags};

use syntecnia_core::interpreter::{Control, Interpreter, RuntimeError};
use syntecnia_core::number::Number;
use syntecnia_core::types::{
    syn_bool, syn_float, syn_int, syn_list, syn_map, syn_text, ServerValue, SynValue,
};

/// Handle al `DatabaseManager` abstrayendo el modo de acceso: `Rc<RefCell>` para
/// runs single-thread (conform), `Arc<Mutex>` para `serve` (db compartida entre
/// los hilos de conexión). Los builtins se registran genéricos sobre esto.
pub trait DbHandle: Clone + 'static {
    fn read<R>(&self, f: impl FnOnce(&DatabaseManager) -> R) -> R;
    fn write<R>(&self, f: impl FnOnce(&mut DatabaseManager) -> R) -> R;
}

impl DbHandle for Rc<RefCell<DatabaseManager>> {
    fn read<R>(&self, f: impl FnOnce(&DatabaseManager) -> R) -> R {
        f(&self.borrow())
    }
    fn write<R>(&self, f: impl FnOnce(&mut DatabaseManager) -> R) -> R {
        f(&mut self.borrow_mut())
    }
}

impl DbHandle for Arc<Mutex<DatabaseManager>> {
    fn read<R>(&self, f: impl FnOnce(&DatabaseManager) -> R) -> R {
        f(&self.lock().unwrap())
    }
    fn write<R>(&self, f: impl FnOnce(&mut DatabaseManager) -> R) -> R {
        f(&mut self.lock().unwrap())
    }
}

fn value_i64(v: &Value) -> i64 {
    match v {
        Value::Integer(i) => *i,
        Value::Real(f) => *f as i64,
        Value::Text(s) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

/// Una fila: columnas (en orden) → valor nativo SQLite.
pub type Row = IndexMap<String, Value>;

pub struct DatabaseManager {
    connections: IndexMap<String, Connection>,
    default_db: Option<String>,
}

impl Default for DatabaseManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DatabaseManager {
    pub fn new() -> Self {
        Self {
            connections: IndexMap::new(),
            default_db: None,
        }
    }

    /// Abre una conexión. Devuelve el path usado como identificador.
    pub fn open(&mut self, path: &str, mode: &str) -> Result<String, String> {
        let key = if mode == "memory" { ":memory:".to_string() } else { path.to_string() };
        if self.connections.contains_key(&key) {
            return Ok(key);
        }
        let conn = match mode {
            "readonly" => Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY),
            "memory" => Connection::open_in_memory(),
            _ => Connection::open(path),
        }
        .map_err(|e| e.to_string())?;
        self.connections.insert(key.clone(), conn);
        if self.default_db.is_none() {
            self.default_db = Some(key.clone());
        }
        Ok(key)
    }

    /// Cierra una conexión (o la default).
    pub fn close(&mut self, path: Option<&str>) {
        let target = path
            .map(|s| s.to_string())
            .or_else(|| self.default_db.clone());
        if let Some(t) = target {
            if self.connections.shift_remove(&t).is_some() && self.default_db.as_deref() == Some(&t) {
                self.default_db = self.connections.keys().next().cloned();
            }
        }
    }

    pub fn close_all(&mut self) {
        self.connections.clear();
        self.default_db = None;
    }

    fn conn(&self, db: Option<&str>) -> Result<&Connection, String> {
        let target = db.map(|s| s.to_string()).or_else(|| self.default_db.clone());
        target
            .and_then(|t| self.connections.get(&t))
            .ok_or_else(|| "No database connection. Use db_open(\"path.db\") first.".to_string())
    }

    /// Ejecuta un SELECT, devuelve filas como mapas columna→valor.
    pub fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>, String> {
        let conn = self.conn(None)?;
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let mut rows = stmt
            .query(params_from_iter(params.iter()))
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let mut m = IndexMap::new();
            for (i, col) in cols.iter().enumerate() {
                let v: Value = row.get(i).map_err(|e| e.to_string())?;
                m.insert(col.clone(), v);
            }
            out.push(m);
        }
        Ok(out)
    }

    /// Ejecuta INSERT/UPDATE/DELETE/CREATE. Devuelve (rows_affected, last_id).
    pub fn execute(&self, sql: &str, params: &[Value]) -> Result<(i64, i64), String> {
        let conn = self.conn(None)?;
        let affected = conn
            .execute(sql, params_from_iter(params.iter()))
            .map_err(|e| e.to_string())?;
        Ok((affected as i64, conn.last_insert_rowid()))
    }

    /// Ejecuta una sentencia con múltiples sets de parámetros (batch).
    pub fn execute_many(&self, sql: &str, params_list: &[Vec<Value>]) -> Result<i64, String> {
        let conn = self.conn(None)?;
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let mut total: i64 = 0;
        for params in params_list {
            total += stmt
                .execute(params_from_iter(params.iter()))
                .map_err(|e| e.to_string())? as i64;
        }
        Ok(total)
    }

    pub fn tables(&self) -> Result<Vec<String>, String> {
        let rows = self.query(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
            &[],
        )?;
        Ok(rows
            .iter()
            .filter_map(|r| match r.get("name") {
                Some(Value::Text(s)) => Some(s.clone()),
                _ => None,
            })
            .collect())
    }
}

// -- Conversión SynValue <-> SQLite Value --

fn value_to_syn(v: &Value) -> SynValue {
    match v {
        Value::Null => SynValue::Nothing,
        Value::Integer(i) => syn_int(*i),
        Value::Real(f) => syn_float(*f),
        Value::Text(s) => syn_text(s.as_str()),
        Value::Blob(b) => syn_text(String::from_utf8_lossy(b).into_owned()),
    }
}

/// `_syn_to_python` del oráculo: number→valor; nothing→NULL; resto→str(val).
fn syn_to_value(v: &SynValue) -> Value {
    match v {
        SynValue::Number(Number::Int(i)) => Value::Integer(*i),
        SynValue::Number(Number::Float(f)) => Value::Real(*f),
        SynValue::Number(Number::Big(b)) => match b.to_string().parse::<i64>() {
            Ok(i) => Value::Integer(i),
            Err(_) => Value::Text(b.to_string()),
        },
        SynValue::Nothing => Value::Null,
        // Bool/Text/List/Map → str(val) (Display de SynValue).
        other => Value::Text(other.to_string()),
    }
}

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg.into()))
}

fn raw_str(v: &SynValue) -> String {
    match v {
        SynValue::Text(s) => s.to_string(),
        SynValue::Number(n) => n.to_string(),
        SynValue::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        SynValue::Nothing => "None".to_string(),
        other => other.to_string(),
    }
}

/// Params de un 2º arg lista → Vec<Value>.
fn params_arg(v: Option<&SynValue>) -> Vec<Value> {
    match v {
        Some(SynValue::List(l)) => l.borrow().iter().map(syn_to_value).collect(),
        _ => Vec::new(),
    }
}

fn row_to_syn(row: &Row) -> SynValue {
    let mut m = IndexMap::new();
    for (k, v) in row {
        m.insert(k.clone(), value_to_syn(v));
    }
    syn_map(m)
}

/// Registra los builtins de base de datos sobre un `DbHandle` (compartido).
pub fn register_database_builtins<H: DbHandle>(interp: &Interpreter, db: H) {
    // db_open(path, mode?)
    {
        let db = db.clone();
        interp.register_builtin(
            "db_open",
            -1,
            Rc::new(move |_i, args, _loc| {
                let path = raw_str(args.first().ok_or_else(|| err("missing argument"))?);
                let mode = args.get(1).map(raw_str).unwrap_or_else(|| "readwrite".to_string());
                db.write(|m| m.open(&path, &mode)).map_err(err)?;
                Ok(syn_bool(true))
            }),
        );
    }

    // db_close(path?)
    {
        let db = db.clone();
        interp.register_builtin(
            "db_close",
            -1,
            Rc::new(move |_i, args, _loc| {
                let path = args.first().map(raw_str);
                db.write(|m| m.close(path.as_deref()));
                Ok(syn_bool(true))
            }),
        );
    }

    // sql(query, params?) → lista de mapas-fila
    {
        let db = db.clone();
        interp.register_builtin(
            "sql",
            -1,
            Rc::new(move |_i, args, _loc| {
                let query = raw_str(args.first().ok_or_else(|| err("missing argument"))?);
                let params = params_arg(args.get(1));
                let rows = db.read(|m| m.query(&query, &params)).map_err(err)?;
                Ok(syn_list(rows.iter().map(row_to_syn).collect()))
            }),
        );
    }

    // sql_exec(statement, params?) → {rows_affected, last_id}
    {
        let db = db.clone();
        interp.register_builtin(
            "sql_exec",
            -1,
            Rc::new(move |_i, args, _loc| {
                let stmt = raw_str(args.first().ok_or_else(|| err("missing argument"))?);
                let params = params_arg(args.get(1));
                let (affected, last_id) = db.read(|m| m.execute(&stmt, &params)).map_err(err)?;
                let mut m = IndexMap::new();
                m.insert("rows_affected".to_string(), syn_int(affected));
                m.insert("last_id".to_string(), syn_int(last_id));
                Ok(syn_map(m))
            }),
        );
    }

    // sql_tables() → lista de nombres
    {
        let db = db.clone();
        interp.register_builtin(
            "sql_tables",
            0,
            Rc::new(move |_i, _args, _loc| {
                let tables = db.read(|m| m.tables()).map_err(err)?;
                Ok(syn_list(tables.iter().map(|t| syn_text(t.as_str())).collect()))
            }),
        );
    }

    // sql_batch(statement, params_list) → {rows_affected}
    {
        let db = db.clone();
        interp.register_builtin(
            "sql_batch",
            2,
            Rc::new(move |_i, args, _loc| {
                let stmt = raw_str(args.first().ok_or_else(|| err("missing argument"))?);
                let params_list: Vec<Vec<Value>> = match args.get(1) {
                    Some(SynValue::List(l)) => l
                        .borrow()
                        .iter()
                        .map(|p| params_arg(Some(p)))
                        .collect(),
                    _ => Vec::new(),
                };
                let affected = db.read(|m| m.execute_many(&stmt, &params_list)).map_err(err)?;
                let mut m = IndexMap::new();
                m.insert("rows_affected".to_string(), syn_int(affected));
                Ok(syn_map(m))
            }),
        );
    }

    // paged(query, params?) → marcador de paginación lazy para `serve` (_PAGED).
    {
        let db = db.clone();
        interp.register_builtin(
            "paged",
            -1,
            Rc::new(move |_i, args, _loc| {
                let query = raw_str(args.first().ok_or_else(|| err("missing argument"))?);
                let params = params_arg(args.get(1));
                let dbf = db.clone();
                let fetch = move |limit: Option<i64>, offset: i64| -> Result<(Vec<SynValue>, i64), String> {
                    dbf.read(|m| match limit {
                        // limit None → materialización completa (sin contexto de serve).
                        None => {
                            let rows = m.query(&query, &params)?;
                            let n = rows.len() as i64;
                            Ok((rows.iter().map(row_to_syn).collect(), n))
                        }
                        Some(lim) => {
                            let count_sql =
                                format!("SELECT COUNT(*) AS _c FROM ({}) AS _sub", query);
                            let count_rows = m.query(&count_sql, &params)?;
                            let total = count_rows
                                .first()
                                .and_then(|r| r.values().next())
                                .map(value_i64)
                                .unwrap_or(0);
                            let page_sql = format!("{} LIMIT ? OFFSET ?", query);
                            let mut p = params.clone();
                            p.push(Value::Integer(lim));
                            p.push(Value::Integer(offset));
                            let rows = m.query(&page_sql, &p)?;
                            Ok((rows.iter().map(row_to_syn).collect(), total))
                        }
                    })
                };
                Ok(SynValue::Server(Rc::new(ServerValue::Paged(Rc::new(fetch)))))
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(row: &Row, key: &str) -> Value {
        row.get(key).cloned().unwrap()
    }

    #[test]
    fn db_manager_basic() {
        let mut db = DatabaseManager::new();
        db.open(":memory:", "memory").unwrap();
        db.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, price REAL)", &[])
            .unwrap();
        db.execute(
            "INSERT INTO items (name, price) VALUES (?, ?)",
            &[Value::Text("Laptop".into()), Value::Real(999.99)],
        )
        .unwrap();
        db.execute(
            "INSERT INTO items (name, price) VALUES (?, ?)",
            &[Value::Text("Mouse".into()), Value::Real(29.99)],
        )
        .unwrap();
        let rows = db.query("SELECT * FROM items ORDER BY price", &[]).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(cell(&rows[0], "name"), Value::Text("Mouse".into()));
        assert_eq!(cell(&rows[1], "price"), Value::Real(999.99));
        db.close(None);
    }

    #[test]
    fn db_tables() {
        let mut db = DatabaseManager::new();
        db.open(":memory:", "memory").unwrap();
        db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)", &[]).unwrap();
        db.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, total REAL)", &[]).unwrap();
        let tables = db.tables().unwrap();
        assert!(tables.contains(&"users".to_string()));
        assert!(tables.contains(&"orders".to_string()));
        db.close(None);
    }

    #[test]
    fn db_batch() {
        let mut db = DatabaseManager::new();
        db.open(":memory:", "memory").unwrap();
        db.execute("CREATE TABLE nums (val INTEGER)", &[]).unwrap();
        db.execute_many(
            "INSERT INTO nums VALUES (?)",
            &[
                vec![Value::Integer(1)],
                vec![Value::Integer(2)],
                vec![Value::Integer(3)],
                vec![Value::Integer(4)],
                vec![Value::Integer(5)],
            ],
        )
        .unwrap();
        let rows = db.query("SELECT * FROM nums", &[]).unwrap();
        assert_eq!(rows.len(), 5);
        db.close(None);
    }
}

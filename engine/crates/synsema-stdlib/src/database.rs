//! SQL nativo bajo una API universal (`db_open`/`sql`/`sql_exec`/…).
//!
//! `DatabaseManager` mantiene conexiones por key (con un `default_db`), cada una de un
//! `Backend`:
//!   - **SQLite** (`rusqlite`, estático `bundled`) — `db_open("./x.db")` / `:memory:`.
//!   - **Postgres** (M1; driver sync `postgres` = tokio-postgres con runtime interno, TLS
//!     rustls) — `db_open("postgres://user:pw@host/db")`. Placeholders `?` (se reescriben
//!     a `$n`). pgvector se usa en la query (`<->`/`<=>`), server-side.
//!   - **MySQL** (M2; driver sync puro-Rust `mysql`, TLS rustls opt-in) —
//!     `db_open("mysql://user:pw@host:3306/db")`. Placeholders `?` **nativos** (NO se
//!     reescriben). `last_insert_id()` real → el `last_id` de `sql_exec` funciona. BLOB vs
//!     TEXT se distinguen por el charset binario de la columna (MF-010, round-trip de bytes).
//!   - **MongoDB** (M3; primer backend NO-SQL; driver `mongodb` con su feature `sync`, TLS
//!     rustls) — `db_open("mongodb://user:pw@host:27017/db")`. NO usa `sql`/`sql_exec` (da
//!     error claro); tiene API propia `mongo_*` (find/insert/update/…) con documentos/filtros
//!     como **maps de Synsema ↔ BSON**. El `_id` (ObjectId) ↔ text hex.
//!   - **Redis** (M4; 3er paradigma: ni SQL ni documentos → **clave-valor + estructuras + TTL**;
//!     driver `redis` SÍNCRONO nativo, TLS rustls ring) — `db_open("redis://host:6379[/N]")`. NO
//!     usa `sql`/`sql_exec` NI `mongo_*` (error simétrico); tiene API propia `redis_*`
//!     (get/set/del/incr/hashes/listas/sets/TTL + **lock distribuido** `redis_lock`/`redis_unlock`).
//!     Los valores son byte-strings: `text` si es UTF-8, si no `bytes`; los enteros → `number`.
//!     Los estructurados van vía `json_encode`/`json_decode` (sin auto-JSON mágico).
//!
//! Gateado por la capability `db(scope)` (deny-by-default): SQLite scope = ruta, Postgres/
//! MySQL/Mongo scope = `canon_url` (scheme://host/db, sin credenciales). Acceso serializado (un
//! op por vez: `Rc<RefCell>` en run, `Arc<Mutex>` en serve) → una conexión por `db_open`.

use std::cell::RefCell;
use std::error::Error as StdError;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use std::str::FromStr;

use bytes::BytesMut;
use indexmap::IndexMap;
use mongodb::bson::spec::BinarySubtype;
use mongodb::bson::{oid::ObjectId, Binary, Bson, Decimal128, Document};
use mysql::consts::ColumnType;
use mysql::prelude::Queryable;
use postgres::types::{to_sql_checked, Format, FromSql, IsNull, ToSql, Type};
use postgres::{Client, NoTls};
use rusqlite::types::Value;
use rusqlite::{params_from_iter, Connection, OpenFlags};
use tokio_postgres_rustls::MakeRustlsConnect;

use synsema_capabilities::model::{canon_url, Capability, CapabilitySet, CapabilityType};
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::Number;
use synsema_core::types::{
    syn_bool, syn_bytes, syn_float, syn_int, syn_list, syn_map, syn_number, syn_text, ServerValue,
    SynValue,
};

use crate::server::{dumps, json_to_syn, syn_to_json};

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

/// Entero a partir de un `SynValue` (para extraer el COUNT de `paged`).
fn syn_to_i64(v: &SynValue) -> i64 {
    match v {
        SynValue::Number(n) => n.to_f64() as i64,
        SynValue::Text(s) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

/// Una fila: columnas (en orden) → `SynValue` ya mapeado (común a ambos backends).
pub type Row = IndexMap<String, SynValue>;

/// Motor concreto de una conexión.
enum Backend {
    Sqlite(Connection),
    Postgres(Client),
    Mysql(mysql::Conn),
    /// MongoDB (no-SQL). Ya scoped al db del connstring; la API propia es `mongo_*`.
    Mongo(mongodb::sync::Database),
    /// Redis (M4, KV/cache/estructuras). Conexión sync ya scoped al db-index del connstring;
    /// la API propia es `redis_*` (no SQL ni `mongo_*`).
    Redis(redis::Connection),
}

pub struct DatabaseManager {
    connections: IndexMap<String, Backend>,
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

    /// Abre una conexión. Rutea por scheme: `postgres://`/`postgresql://` → Postgres;
    /// `mysql://` → MySQL; `mongodb://`/`mongodb+srv://` → MongoDB; cualquier otra cosa →
    /// SQLite (camino actual, sin cambios). Devuelve la key usada como identificador
    /// (canon_url para los remotos; ruta/`:memory:` para SQLite).
    pub fn open(&mut self, target: &str, mode: &str) -> Result<String, String> {
        if is_mongo_url(target) {
            let key = canon_url(target);
            if self.connections.contains_key(&key) {
                return Ok(key);
            }
            let db = mongo_connect(target)?;
            self.connections.insert(key.clone(), Backend::Mongo(db));
            if self.default_db.is_none() {
                self.default_db = Some(key.clone());
            }
            Ok(key)
        } else if is_redis_url(target) {
            let key = canon_url(target);
            if self.connections.contains_key(&key) {
                return Ok(key);
            }
            let conn = redis_connect(target)?;
            self.connections.insert(key.clone(), Backend::Redis(conn));
            if self.default_db.is_none() {
                self.default_db = Some(key.clone());
            }
            Ok(key)
        } else if is_pg_url(target) {
            let key = canon_url(target);
            if self.connections.contains_key(&key) {
                return Ok(key);
            }
            let client = pg_connect(target)?;
            self.connections.insert(key.clone(), Backend::Postgres(client));
            if self.default_db.is_none() {
                self.default_db = Some(key.clone());
            }
            Ok(key)
        } else if is_mysql_url(target) {
            let key = canon_url(target);
            if self.connections.contains_key(&key) {
                return Ok(key);
            }
            let conn = mysql_connect(target)?;
            self.connections.insert(key.clone(), Backend::Mysql(conn));
            if self.default_db.is_none() {
                self.default_db = Some(key.clone());
            }
            Ok(key)
        } else {
            let key = if mode == "memory" { ":memory:".to_string() } else { target.to_string() };
            if self.connections.contains_key(&key) {
                return Ok(key);
            }
            let conn = match mode {
                "readonly" => Connection::open_with_flags(target, OpenFlags::SQLITE_OPEN_READ_ONLY),
                "memory" => Connection::open_in_memory(),
                _ => Connection::open(target),
            }
            .map_err(|e| e.to_string())?;
            self.connections.insert(key.clone(), Backend::Sqlite(conn));
            if self.default_db.is_none() {
                self.default_db = Some(key.clone());
            }
            Ok(key)
        }
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

    fn conn_mut(&mut self, db: Option<&str>) -> Result<&mut Backend, String> {
        let target = db.map(|s| s.to_string()).or_else(|| self.default_db.clone());
        target
            .and_then(move |t| self.connections.get_mut(&t))
            .ok_or_else(|| "No database connection. Use db_open(\"path.db\") first.".to_string())
    }

    /// Ejecuta un SELECT, devuelve filas como mapas columna→valor (ya en `SynValue`).
    pub fn query(&mut self, sql: &str, params: &[SynValue]) -> Result<Vec<Row>, String> {
        match self.conn_mut(None)? {
            Backend::Sqlite(c) => sqlite_query(c, sql, params),
            Backend::Postgres(c) => pg_query(c, sql, params),
            Backend::Mysql(c) => mysql_query(c, sql, params),
            Backend::Mongo(_) => Err(mongo_not_sql()),
            Backend::Redis(_) => Err(redis_not_sql()),
        }
    }

    /// Ejecuta INSERT/UPDATE/DELETE/CREATE. Devuelve (rows_affected, last_id).
    /// Postgres no tiene `last_insert_rowid` → `last_id = 0` (usar `INSERT … RETURNING id`).
    /// MySQL sí: `last_id = last_insert_id()` (a diferencia de PG).
    pub fn execute(&mut self, sql: &str, params: &[SynValue]) -> Result<(i64, i64), String> {
        match self.conn_mut(None)? {
            Backend::Sqlite(c) => {
                let pv: Vec<Value> = params.iter().map(syn_to_value).collect();
                let affected = c
                    .execute(sql, params_from_iter(pv.iter()))
                    .map_err(|e| e.to_string())?;
                Ok((affected as i64, c.last_insert_rowid()))
            }
            Backend::Postgres(c) => {
                let rewritten = rewrite_placeholders(sql);
                let pg: Vec<PgParam> = params.iter().map(syn_to_pg).collect();
                let refs: Vec<&(dyn ToSql + Sync)> = pg.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
                let n = c.execute(rewritten.as_str(), &refs).map_err(pg_err)?;
                Ok((n as i64, 0))
            }
            // `?` nativo (sin reescritura). `last_insert_id()` real (0 si no aplica).
            // Sin params → protocolo de TEXTO (`query_drop`): el de prepared statements
            // rechaza el control de transacciones y otros comandos (ERROR 1295: "not
            // supported in the prepared statement protocol"). Con params → prepared (binario)
            // para el bind. `execute` no lee valores tipados (solo counts) → el protocolo no
            // afecta el mapeo de tipos (a diferencia de `query`, que SIEMPRE va por binario).
            Backend::Mysql(c) => {
                if params.is_empty() {
                    c.query_drop(sql).map_err(mysql_err)?;
                } else {
                    c.exec_drop(sql, mysql_params(params)).map_err(mysql_err)?;
                }
                Ok((c.affected_rows() as i64, c.last_insert_id() as i64))
            }
            Backend::Mongo(_) => Err(mongo_not_sql()),
            Backend::Redis(_) => Err(redis_not_sql()),
        }
    }

    /// Ejecuta una sentencia con múltiples sets de parámetros (batch).
    pub fn execute_many(&mut self, sql: &str, params_list: &[Vec<SynValue>]) -> Result<i64, String> {
        match self.conn_mut(None)? {
            Backend::Sqlite(c) => {
                let mut stmt = c.prepare(sql).map_err(|e| e.to_string())?;
                let mut total: i64 = 0;
                for params in params_list {
                    let pv: Vec<Value> = params.iter().map(syn_to_value).collect();
                    total += stmt
                        .execute(params_from_iter(pv.iter()))
                        .map_err(|e| e.to_string())? as i64;
                }
                Ok(total)
            }
            Backend::Postgres(c) => {
                let rewritten = rewrite_placeholders(sql);
                let stmt = c.prepare(rewritten.as_str()).map_err(pg_err)?;
                let mut total: i64 = 0;
                for params in params_list {
                    let pg: Vec<PgParam> = params.iter().map(syn_to_pg).collect();
                    let refs: Vec<&(dyn ToSql + Sync)> =
                        pg.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
                    total += c.execute(&stmt, &refs).map_err(pg_err)? as i64;
                }
                Ok(total)
            }
            // Prepara una vez (`?` nativo) y reusa el statement por cada set de params.
            Backend::Mysql(c) => {
                let stmt = c.prep(sql).map_err(mysql_err)?;
                let mut total: i64 = 0;
                for params in params_list {
                    c.exec_drop(&stmt, mysql_params(params)).map_err(mysql_err)?;
                    total += c.affected_rows() as i64;
                }
                Ok(total)
            }
            Backend::Mongo(_) => Err(mongo_not_sql()),
            Backend::Redis(_) => Err(redis_not_sql()),
        }
    }

    /// Key de la conexión default (para el scope de la capability `db` en las ops de
    /// datos). `None` si no hay ninguna conexión abierta.
    pub fn default_path(&self) -> Option<String> {
        self.default_db.clone()
    }

    pub fn tables(&mut self) -> Result<Vec<String>, String> {
        let (sql, col) = match self.conn_mut(None)? {
            Backend::Sqlite(_) => (
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
                "name",
            ),
            Backend::Postgres(_) => (
                "SELECT tablename FROM pg_catalog.pg_tables \
                 WHERE schemaname NOT IN ('pg_catalog','information_schema') ORDER BY tablename",
                "tablename",
            ),
            // `SHOW TABLES` da una columna de nombre dinámico (`Tables_in_<db>`); se usa
            // information_schema con alias fijo `name` para leerla igual que los otros.
            Backend::Mysql(_) => (
                "SELECT table_name AS name FROM information_schema.tables \
                 WHERE table_schema = DATABASE() ORDER BY table_name",
                "name",
            ),
            // Mongo no es SQL: `sql_tables()` no aplica → `mongo_collections()`.
            Backend::Mongo(_) => return Err(mongo_not_sql()),
            // Redis no es SQL: `sql_tables()` no aplica → `redis_keys(pattern)`.
            Backend::Redis(_) => return Err(redis_not_sql()),
        };
        let rows = self.query(sql, &[])?;
        Ok(rows
            .iter()
            .filter_map(|r| match r.get(col) {
                Some(SynValue::Text(s)) => Some(s.to_string()),
                _ => None,
            })
            .collect())
    }

    /// Devuelve la `Collection<Document>` de la conexión Mongo default, o un error simétrico
    /// si la conexión default es SQL (sin sorpresas silenciosas).
    fn mongo_coll(&mut self, name: &str) -> Result<mongodb::sync::Collection<Document>, String> {
        match self.conn_mut(None)? {
            Backend::Mongo(db) => Ok(db.collection::<Document>(name)),
            Backend::Sqlite(_) | Backend::Postgres(_) | Backend::Mysql(_) => Err(mongo_wrong_backend()),
            Backend::Redis(_) => Err(redis_not_mongo()),
        }
    }

    // -- API Mongo (M3). Documentos/filtros = maps de Synsema ↔ BSON. --

    /// `mongo_find`: documentos que matchean `filter`, con `opts` (limit/skip/sort/fields).
    pub fn mongo_find(
        &mut self,
        coll: &str,
        filter: Document,
        opts: MongoFindOpts,
    ) -> Result<Vec<SynValue>, String> {
        let c = self.mongo_coll(coll)?;
        let mut action = c.find(filter);
        if let Some(l) = opts.limit {
            action = action.limit(l);
        }
        if let Some(s) = opts.skip {
            action = action.skip(s);
        }
        if let Some(sort) = opts.sort {
            action = action.sort(sort);
        }
        if let Some(proj) = opts.projection {
            action = action.projection(proj);
        }
        let cursor = action.run().map_err(mongo_err)?;
        let mut out = Vec::new();
        for doc in cursor {
            out.push(bson_to_syn(&Bson::Document(doc.map_err(mongo_err)?)));
        }
        Ok(out)
    }

    /// `mongo_find_one`: primer documento que matchea, o `nothing`.
    pub fn mongo_find_one(&mut self, coll: &str, filter: Document) -> Result<SynValue, String> {
        let c = self.mongo_coll(coll)?;
        match c.find_one(filter).run().map_err(mongo_err)? {
            Some(doc) => Ok(bson_to_syn(&Bson::Document(doc))),
            None => Ok(SynValue::Nothing),
        }
    }

    /// `mongo_insert`: inserta un documento, devuelve el `_id` (text hex si es ObjectId).
    pub fn mongo_insert(&mut self, coll: &str, doc: Document) -> Result<SynValue, String> {
        let c = self.mongo_coll(coll)?;
        let res = c.insert_one(doc).run().map_err(mongo_err)?;
        Ok(bson_to_syn(&res.inserted_id))
    }

    /// `mongo_insert_many`: inserta varios, devuelve la lista de `_id` en orden de inserción.
    pub fn mongo_insert_many(&mut self, coll: &str, docs: Vec<Document>) -> Result<Vec<SynValue>, String> {
        let n = docs.len();
        let c = self.mongo_coll(coll)?;
        let res = c.insert_many(docs).run().map_err(mongo_err)?;
        // `inserted_ids` es un map índice→id; se reordena 0..n.
        Ok((0..n)
            .map(|i| res.inserted_ids.get(&i).map(bson_to_syn).unwrap_or(SynValue::Nothing))
            .collect())
    }

    /// `mongo_update` (update_many): `update` debe traer operadores (`$set`/`$inc`/…).
    /// Devuelve `(matched, modified)`.
    pub fn mongo_update(&mut self, coll: &str, filter: Document, update: Document) -> Result<(i64, i64), String> {
        let c = self.mongo_coll(coll)?;
        let res = c.update_many(filter, update).run().map_err(mongo_err)?;
        Ok((res.matched_count as i64, res.modified_count as i64))
    }

    /// `mongo_delete` (delete_many): devuelve cuántos borró.
    pub fn mongo_delete(&mut self, coll: &str, filter: Document) -> Result<i64, String> {
        let c = self.mongo_coll(coll)?;
        let res = c.delete_many(filter).run().map_err(mongo_err)?;
        Ok(res.deleted_count as i64)
    }

    /// `mongo_count`: documentos que matchean `filter`.
    pub fn mongo_count(&mut self, coll: &str, filter: Document) -> Result<i64, String> {
        let c = self.mongo_coll(coll)?;
        Ok(c.count_documents(filter).run().map_err(mongo_err)? as i64)
    }

    /// `mongo_aggregate`: pipeline de agregación (lista de stages-documento) → lista de maps.
    pub fn mongo_aggregate(&mut self, coll: &str, pipeline: Vec<Document>) -> Result<Vec<SynValue>, String> {
        let c = self.mongo_coll(coll)?;
        let cursor = c.aggregate(pipeline).run().map_err(mongo_err)?;
        let mut out = Vec::new();
        for doc in cursor {
            out.push(bson_to_syn(&Bson::Document(doc.map_err(mongo_err)?)));
        }
        Ok(out)
    }

    /// `mongo_collections`: nombres de las colecciones del db.
    pub fn mongo_collections(&mut self) -> Result<Vec<String>, String> {
        match self.conn_mut(None)? {
            Backend::Mongo(db) => db.list_collection_names().run().map_err(mongo_err),
            Backend::Sqlite(_) | Backend::Postgres(_) | Backend::Mysql(_) => Err(mongo_wrong_backend()),
            Backend::Redis(_) => Err(redis_not_mongo()),
        }
    }

    // -- API Redis (M4). Acceso a la conexión sync + un runner genérico de comandos. --

    /// Devuelve la `redis::Connection` default, o un error simétrico si la conexión default es
    /// SQL/Mongo (sin sorpresas silenciosas, espeja `mongo_coll`).
    fn redis_conn(&mut self) -> Result<&mut redis::Connection, String> {
        match self.conn_mut(None)? {
            Backend::Redis(c) => Ok(c),
            Backend::Sqlite(_) | Backend::Postgres(_) | Backend::Mysql(_) => Err(redis_wrong_backend_sql()),
            Backend::Mongo(_) => Err(redis_wrong_backend_mongo()),
        }
    }

    /// Runner genérico de un comando Redis. `parts[0]` es el comando (p.ej. `b"SET"`) y el
    /// resto los argumentos, **cada uno como un único bulk-string binario-seguro** (redis-rs
    /// trata `&[u8]` como un solo argumento vía `write_args_from_slice`/`is_single_vec_arg`,
    /// NO uno por byte). La respuesta cruda (`redis::Value`) la mapea el llamador.
    pub fn redis_command(&mut self, parts: &[Vec<u8>]) -> Result<redis::Value, String> {
        let conn = self.redis_conn()?;
        let mut cmd = redis::Cmd::new();
        for p in parts {
            cmd.arg(p.as_slice());
        }
        cmd.query::<redis::Value>(conn).map_err(redis_err)
    }
}

// -- SQLite: ejecución + conversión SynValue <-> rusqlite Value --

fn sqlite_query(conn: &Connection, sql: &str, params: &[SynValue]) -> Result<Vec<Row>, String> {
    let pv: Vec<Value> = params.iter().map(syn_to_value).collect();
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let mut rows = stmt
        .query(params_from_iter(pv.iter()))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let mut m = IndexMap::new();
        for (i, col) in cols.iter().enumerate() {
            let v: Value = row.get(i).map_err(|e| e.to_string())?;
            m.insert(col.clone(), value_to_syn(&v));
        }
        out.push(m);
    }
    Ok(out)
}

fn value_to_syn(v: &Value) -> SynValue {
    match v {
        Value::Null => SynValue::Nothing,
        Value::Integer(i) => syn_int(*i),
        Value::Real(f) => syn_float(*f),
        Value::Text(s) => syn_text(s.as_str()),
        // BLOB → bytes byte-exacto (NO lossy): un blob no-UTF8 ya no se corrompe (MF-010).
        Value::Blob(b) => syn_bytes(b.clone()),
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
        // Secret (#8): se permite persistirlo — el plaintext se **revela en el borde
        // de la DB** (SQL parametrizado). No hay query-log que redactar (este crate no
        // loguea queries ni params); si se agregara uno en el futuro, DEBE redactar.
        SynValue::Secret(s) => Value::Text(s.expose().to_string()),
        // bytes → BLOB byte-exacto (round-trip con value_to_syn; MF-010).
        SynValue::Bytes(b) => Value::Blob(b[..].to_vec()),
        // Bool/Text/List/Map → str(val) (Display de SynValue).
        other => Value::Text(other.to_string()),
    }
}

// -- Postgres: conexión, rewriter, bind, lectura --

fn is_pg_url(target: &str) -> bool {
    target.starts_with("postgres://") || target.starts_with("postgresql://")
}

/// Mapea un error de Postgres a un mensaje útil: el `Display` de `postgres::Error` solo da
/// el *kind* ("db error", "error connecting to server"); el detalle SQL real (`ERROR: …`)
/// está en `as_db_error()`. Sin esto el debugging es a ciegas.
fn pg_err(e: postgres::Error) -> String {
    match e.as_db_error() {
        Some(db) => format!("db error: {}", db.message()),
        None => e.to_string(),
    }
}

/// Conecta a Postgres. `sslmode=disable` en el connstring → sin TLS; si no → rustls con
/// los root CAs del SO (mismo backend ring que el resto de stdlib). Aplica un
/// `connect_timeout` por defecto (10s) si el connstring no lo trae, para que apuntar a un
/// host caído falle rápido en vez de colgarse.
fn pg_connect(connstring: &str) -> Result<Client, String> {
    let mut config: postgres::Config = connstring.parse().map_err(pg_err)?;
    if config.get_connect_timeout().is_none() {
        config.connect_timeout(Duration::from_secs(10));
    }
    if connstring.contains("sslmode=disable") {
        config.connect(NoTls).map_err(pg_err)
    } else {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(c);
        }
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tls = MakeRustlsConnect::new(tls_config);
        config.connect(tls).map_err(pg_err)
    }
}

/// Reemplaza cada `?` por `$1`,`$2`,… EN ORDEN, ignorando los `?` dentro de literales de
/// string (`'...'`) o comillas dobles (`"..."`). PG usa `$n`; un `?` literal debe ir
/// entre comillas.
fn rewrite_placeholders(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 8);
    let mut n = 0;
    let (mut in_s, mut in_d) = (false, false);
    for c in sql.chars() {
        match c {
            '\'' if !in_d => {
                in_s = !in_s;
                out.push(c);
            }
            '"' if !in_s => {
                in_d = !in_d;
                out.push(c);
            }
            '?' if !in_s && !in_d => {
                n += 1;
                out.push('$');
                out.push_str(&n.to_string());
            }
            _ => out.push(c),
        }
    }
    out
}

/// Parámetro a bindear en Postgres. `ToSql` delega al tipo concreto; los enteros/floats
/// se adaptan al ancho de la columna (`ty`) para no mandar 8 bytes a un int4.
#[derive(Debug)]
enum PgParam {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
    Dec(rust_decimal::Decimal),
}

impl ToSql for PgParam {
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Box<dyn StdError + Sync + Send>> {
        match self {
            PgParam::Null => Ok(IsNull::Yes),
            PgParam::Bool(b) => b.to_sql(ty, out),
            PgParam::Int(i) => enc_int(*i, ty, out),
            PgParam::Float(f) => enc_float(*f, ty, out),
            // Texto CRUDO en formato TEXTO (ver encode_format): así el cast `?::vector` /
            // `?::numeric` / `?::jsonb` parsea la representación textual ("[0.9,0.1,0]",
            // "3.50", "{...}"). Mandarlo en binario haría que PG lea los bytes del texto
            // como el formato binario del tipo → basura.
            PgParam::Text(s) => {
                out.extend_from_slice(s.as_bytes());
                Ok(IsNull::No)
            }
            PgParam::Bytes(b) => b.to_sql(ty, out),
            PgParam::Dec(d) => enc_dec(*d, ty, out),
        }
    }
    /// `Text` se envía en formato TEXTO (para que el cast lo parsee); el resto en binario
    /// nativo (su binario coincide con su columna).
    fn encode_format(&self, _ty: &Type) -> Format {
        match self {
            PgParam::Text(_) => Format::Text,
            _ => Format::Binary,
        }
    }
    // Aceptamos cualquier tipo de columna: la validación real la hace el servidor (y el
    // cast explícito `?::vector`/etc. en la query). Evita rechazos por ancho de entero.
    fn accepts(_ty: &Type) -> bool {
        true
    }
    to_sql_checked!();
}

/// Resultado de codificar un parámetro a binario Postgres.
type PgEncode = Result<IsNull, Box<dyn StdError + Sync + Send>>;

/// El binario que escribimos DEBE coincidir con el tipo `ty` de la columna que infiere el
/// servidor: mandar el binario de un `f64` a una columna `numeric` (u 8 bytes de `i64` a un
/// `float8`) le da basura → errores como "invalid sign in external numeric value". Estos
/// helpers adaptan cada valor numérico al binario nativo de su columna destino.
fn enc_int(i: i64, ty: &Type, out: &mut BytesMut) -> PgEncode {
    if *ty == Type::INT2 {
        (i as i16).to_sql(ty, out)
    } else if *ty == Type::INT4 {
        (i as i32).to_sql(ty, out)
    } else if *ty == Type::FLOAT4 {
        (i as f32).to_sql(ty, out)
    } else if *ty == Type::FLOAT8 {
        (i as f64).to_sql(ty, out)
    } else if *ty == Type::NUMERIC {
        rust_decimal::Decimal::from(i).to_sql(ty, out)
    } else {
        i.to_sql(ty, out) // INT8 y default (cast explícito en la query)
    }
}

fn enc_float(f: f64, ty: &Type, out: &mut BytesMut) -> PgEncode {
    if *ty == Type::FLOAT4 {
        (f as f32).to_sql(ty, out)
    } else if *ty == Type::NUMERIC {
        match f64_to_decimal(f) {
            Some(d) => d.to_sql(ty, out),
            None => Err(format!("no se puede representar {f} como numeric").into()),
        }
    } else {
        f.to_sql(ty, out) // FLOAT8 y default
    }
}

fn enc_dec(d: rust_decimal::Decimal, ty: &Type, out: &mut BytesMut) -> PgEncode {
    use rust_decimal::prelude::ToPrimitive;
    if *ty == Type::FLOAT4 {
        (d.to_f64().unwrap_or(f64::NAN) as f32).to_sql(ty, out)
    } else if *ty == Type::FLOAT8 {
        d.to_f64().unwrap_or(f64::NAN).to_sql(ty, out)
    } else if *ty == Type::INT2 {
        (d.trunc().to_i64().unwrap_or(0) as i16).to_sql(ty, out)
    } else if *ty == Type::INT4 {
        (d.trunc().to_i64().unwrap_or(0) as i32).to_sql(ty, out)
    } else if *ty == Type::INT8 {
        d.trunc().to_i64().unwrap_or(0).to_sql(ty, out)
    } else {
        d.to_sql(ty, out) // NUMERIC y default
    }
}

/// `f64` → `Decimal` fiel al valor: la repr más corta que round-trippea (p.ej. `9.99` →
/// `"9.99"`) preserva el literal; si imprime en notación científica (magnitudes extremas,
/// no parseables por `from_str_exact`), cae a `from_f64`.
fn f64_to_decimal(f: f64) -> Option<rust_decimal::Decimal> {
    use rust_decimal::prelude::FromPrimitive;
    rust_decimal::Decimal::from_str_exact(&f.to_string())
        .ok()
        .or_else(|| rust_decimal::Decimal::from_f64(f))
}

fn syn_to_pg(v: &SynValue) -> PgParam {
    match v {
        SynValue::Nothing => PgParam::Null,
        SynValue::Bool(b) => PgParam::Bool(*b),
        SynValue::Number(Number::Int(i)) => PgParam::Int(*i),
        SynValue::Number(Number::Float(f)) => PgParam::Float(*f),
        // Decimal/Big → Decimal exacto si entra; si no, texto (PG castea).
        SynValue::Number(n) => match n.to_decimal() {
            Some(d) => PgParam::Dec(d),
            None => PgParam::Text(n.to_string()),
        },
        SynValue::Bytes(b) => PgParam::Bytes(b[..].to_vec()),
        SynValue::Secret(s) => PgParam::Text(s.expose().to_string()),
        SynValue::Text(s) => PgParam::Text(s.to_string()),
        // list/array (p.ej. un embedding) → texto pgvector "[a,b,c]"; en la query: `?::vector`.
        SynValue::List(l) => PgParam::Text(list_to_vector_text(&l.borrow())),
        SynValue::Array(a) => PgParam::Text(array_to_vector_text(a)),
        other => PgParam::Text(other.to_string()),
    }
}

/// `[a,b,c]` a partir de una lista de números (formato de entrada de pgvector).
fn list_to_vector_text(items: &[SynValue]) -> String {
    let parts: Vec<String> = items
        .iter()
        .map(|v| match v {
            SynValue::Number(n) => n.to_string(),
            other => other.to_string(),
        })
        .collect();
    format!("[{}]", parts.join(","))
}

fn array_to_vector_text(a: &ndarray::ArrayD<f64>) -> String {
    let parts: Vec<String> = a.iter().map(|f| f.to_string()).collect();
    format!("[{}]", parts.join(","))
}

/// pgvector: `vector` no tiene OID fijo (lo asigna la extensión) → se matchea por NOMBRE.
/// Formato binario: `u16 dim`, `u16 flags` (sin uso), luego `dim` × `f32` big-endian.
struct PgVector(Vec<f32>);

impl<'a> FromSql<'a> for PgVector {
    fn from_sql(_ty: &Type, raw: &'a [u8]) -> Result<PgVector, Box<dyn StdError + Sync + Send>> {
        if raw.len() < 4 {
            return Err("pgvector: buffer demasiado corto".into());
        }
        let dim = u16::from_be_bytes([raw[0], raw[1]]) as usize;
        let mut v = Vec::with_capacity(dim);
        let mut off = 4;
        for _ in 0..dim {
            if off + 4 > raw.len() {
                return Err("pgvector: buffer truncado".into());
            }
            v.push(f32::from_be_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]));
            off += 4;
        }
        Ok(PgVector(v))
    }
    fn accepts(ty: &Type) -> bool {
        ty.name() == "vector"
    }
}

fn pg_query(client: &mut Client, sql: &str, params: &[SynValue]) -> Result<Vec<Row>, String> {
    let rewritten = rewrite_placeholders(sql);
    let pg: Vec<PgParam> = params.iter().map(syn_to_pg).collect();
    let refs: Vec<&(dyn ToSql + Sync)> = pg.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
    let rows = client
        .query(rewritten.as_str(), &refs)
        .map_err(pg_err)?;
    Ok(rows.iter().map(pg_row_to_syn).collect())
}

fn pg_row_to_syn(row: &postgres::Row) -> Row {
    let mut m = IndexMap::new();
    for (i, col) in row.columns().iter().enumerate() {
        m.insert(col.name().to_string(), pg_cell_to_syn(row, i, col.type_()));
    }
    m
}

/// Lee `Option<T>`: NULL o tipo no convertible → `None`.
fn cell_opt<'a, T: FromSql<'a>>(row: &'a postgres::Row, i: usize) -> Option<T> {
    match row.try_get::<usize, Option<T>>(i) {
        Ok(opt) => opt,
        Err(_) => None,
    }
}

fn pg_cell_to_syn(row: &postgres::Row, i: usize, ty: &Type) -> SynValue {
    let nothing = SynValue::Nothing;
    if *ty == Type::BOOL {
        return cell_opt::<bool>(row, i).map(syn_bool).unwrap_or(nothing);
    }
    if *ty == Type::INT2 {
        return cell_opt::<i16>(row, i).map(|v| syn_int(v as i64)).unwrap_or(nothing);
    }
    if *ty == Type::INT4 {
        return cell_opt::<i32>(row, i).map(|v| syn_int(v as i64)).unwrap_or(nothing);
    }
    if *ty == Type::INT8 {
        return cell_opt::<i64>(row, i).map(syn_int).unwrap_or(nothing);
    }
    if *ty == Type::FLOAT4 {
        return cell_opt::<f32>(row, i).map(|v| syn_float(v as f64)).unwrap_or(nothing);
    }
    if *ty == Type::FLOAT8 {
        return cell_opt::<f64>(row, i).map(syn_float).unwrap_or(nothing);
    }
    if *ty == Type::NUMERIC {
        return cell_opt::<rust_decimal::Decimal>(row, i)
            .map(|d| syn_number(Number::Decimal(d)))
            .unwrap_or(nothing);
    }
    if *ty == Type::TEXT || *ty == Type::VARCHAR || *ty == Type::BPCHAR || *ty == Type::NAME {
        return cell_opt::<String>(row, i).map(syn_text).unwrap_or(nothing);
    }
    if *ty == Type::BYTEA {
        return cell_opt::<Vec<u8>>(row, i).map(syn_bytes).unwrap_or(nothing);
    }
    if *ty == Type::JSON || *ty == Type::JSONB {
        return cell_opt::<serde_json::Value>(row, i)
            .map(|v| json_to_syn(&v))
            .unwrap_or(nothing);
    }
    if *ty == Type::UUID {
        return cell_opt::<uuid::Uuid>(row, i)
            .map(|u| syn_text(u.to_string()))
            .unwrap_or(nothing);
    }
    if *ty == Type::TIMESTAMP {
        return cell_opt::<chrono::NaiveDateTime>(row, i)
            .map(|t| syn_text(t.to_string()))
            .unwrap_or(nothing);
    }
    if *ty == Type::TIMESTAMPTZ {
        return cell_opt::<chrono::DateTime<chrono::Utc>>(row, i)
            .map(|t| syn_text(t.to_rfc3339()))
            .unwrap_or(nothing);
    }
    if *ty == Type::DATE {
        return cell_opt::<chrono::NaiveDate>(row, i)
            .map(|t| syn_text(t.to_string()))
            .unwrap_or(nothing);
    }
    if *ty == Type::TIME {
        return cell_opt::<chrono::NaiveTime>(row, i)
            .map(|t| syn_text(t.to_string()))
            .unwrap_or(nothing);
    }
    // Arrays comunes → list.
    if *ty == Type::TEXT_ARRAY {
        return cell_opt::<Vec<String>>(row, i)
            .map(|v| syn_list(v.into_iter().map(syn_text).collect()))
            .unwrap_or(nothing);
    }
    if *ty == Type::INT4_ARRAY {
        return cell_opt::<Vec<i32>>(row, i)
            .map(|v| syn_list(v.into_iter().map(|x| syn_int(x as i64)).collect()))
            .unwrap_or(nothing);
    }
    if *ty == Type::INT8_ARRAY {
        return cell_opt::<Vec<i64>>(row, i)
            .map(|v| syn_list(v.into_iter().map(syn_int).collect()))
            .unwrap_or(nothing);
    }
    if *ty == Type::FLOAT8_ARRAY {
        return cell_opt::<Vec<f64>>(row, i)
            .map(|v| syn_list(v.into_iter().map(syn_float).collect()))
            .unwrap_or(nothing);
    }
    if *ty == Type::FLOAT4_ARRAY {
        return cell_opt::<Vec<f32>>(row, i)
            .map(|v| syn_list(v.into_iter().map(|x| syn_float(x as f64)).collect()))
            .unwrap_or(nothing);
    }
    if *ty == Type::BOOL_ARRAY {
        return cell_opt::<Vec<bool>>(row, i)
            .map(|v| syn_list(v.into_iter().map(syn_bool).collect()))
            .unwrap_or(nothing);
    }
    // pgvector (OID dinámico) → list de floats (índice ANN corre server-side).
    if ty.name() == "vector" {
        return cell_opt::<PgVector>(row, i)
            .map(|pv| syn_list(pv.0.into_iter().map(|f| syn_float(f as f64)).collect()))
            .unwrap_or(nothing);
    }
    // Fallback: intentar texto; si no se puede → nothing (sin corromper).
    cell_opt::<String>(row, i).map(syn_text).unwrap_or(nothing)
}

// -- MySQL: conexión, TLS opt-in, bind, lectura (M2) --

fn is_mysql_url(target: &str) -> bool {
    target.starts_with("mysql://")
}

/// Mapea un error del crate `mysql` a un mensaje útil. Su `Display` ya incluye el detalle
/// del server para `MySqlError` (código + SQLSTATE + mensaje), así que `to_string()` es
/// informativo (lección M1 #2: no devolver algo opaco). Wrapper nombrado para documentarlo.
fn mysql_err(e: mysql::Error) -> String {
    e.to_string()
}

/// TLS es **opt-in** en MySQL (el contenedor dev es plaintext) y el parser de URL del crate
/// `mysql` RECHAZA claves de query desconocidas (`UnknownParameter`) → no se puede pedir TLS
/// con `?ssl-mode=…` directo. Por eso interceptamos NOSOTROS el hint, lo quitamos del url y
/// devolvemos `(url_limpio, wants_tls)`. Hints: `ssl-mode`/`sslmode` ≠ `DISABLED` → on;
/// `ssl`/`require_ssl` ∈ {true,1,required,yes} → on. Ausente/`DISABLED` → plaintext.
fn split_tls_hint(url: &str) -> (String, bool) {
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, q),
        None => return (url.to_string(), false),
    };
    let mut wants_tls = false;
    let mut kept: Vec<&str> = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k.to_ascii_lowercase().as_str() {
            "ssl-mode" | "sslmode" => {
                let m = v.to_ascii_uppercase();
                wants_tls = !(m.is_empty() || m == "DISABLED" || m == "DISABLE");
            }
            "ssl" | "require_ssl" => {
                wants_tls = matches!(
                    v.to_ascii_lowercase().as_str(),
                    "true" | "1" | "required" | "yes"
                );
            }
            _ => kept.push(pair),
        }
    }
    let cleaned = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{}?{}", base, kept.join("&"))
    };
    (cleaned, wants_tls)
}

/// Conecta a MySQL. Aplica `connect_timeout` por defecto (10s) desde el día 1 (lección M1
/// #1: un `db_open` a un host caído NO debe colgarse). TLS opt-in (rustls, backend ring vía
/// webpki-roots): si el url lo pide, verifica el cert del server contra los root CAs
/// embebidos. El contenedor dev es plaintext → por defecto sin SSL.
fn mysql_connect(url: &str) -> Result<mysql::Conn, String> {
    let (clean_url, wants_tls) = split_tls_hint(url);
    let opts = mysql::Opts::from_url(&clean_url).map_err(|e| e.to_string())?;
    let mut builder = mysql::OptsBuilder::from_opts(opts)
        .tcp_connect_timeout(Some(Duration::from_secs(10)));
    if wants_tls {
        builder = builder.ssl_opts(Some(mysql::SslOpts::default()));
    }
    mysql::Conn::new(builder).map_err(mysql_err)
}

/// Params posicionales (`?` nativo). Vacío → `Params::Empty` (evita el chequeo de aridad
/// del driver cuando la query no tiene placeholders).
fn mysql_params(params: &[SynValue]) -> mysql::Params {
    if params.is_empty() {
        mysql::Params::Empty
    } else {
        mysql::Params::Positional(params.iter().map(syn_to_mysql).collect())
    }
}

/// `SynValue` → `mysql::Value` (bind). MySQL no tiene bool real → TINYINT (Int 0/1).
/// decimal/big → texto (el server castea a DECIMAL/NUMERIC exacto). bytes → bytes crudos
/// (BLOB/BINARY, round-trip MF-010). El secret se revela en el borde de la DB (SQL
/// parametrizado), igual que en SQLite/PG.
fn syn_to_mysql(v: &SynValue) -> mysql::Value {
    use mysql::Value as MyV;
    match v {
        SynValue::Nothing => MyV::NULL,
        SynValue::Bool(b) => MyV::Int(if *b { 1 } else { 0 }),
        SynValue::Number(Number::Int(i)) => MyV::Int(*i),
        SynValue::Number(Number::Float(f)) => MyV::Double(*f),
        SynValue::Number(n) => MyV::Bytes(n.to_string().into_bytes()),
        SynValue::Bytes(b) => MyV::Bytes(b[..].to_vec()),
        SynValue::Text(s) => MyV::Bytes(s.as_bytes().to_vec()),
        SynValue::Secret(s) => MyV::Bytes(s.expose().to_string().into_bytes()),
        other => MyV::Bytes(other.to_string().into_bytes()),
    }
}

fn mysql_query(conn: &mut mysql::Conn, sql: &str, params: &[SynValue]) -> Result<Vec<Row>, String> {
    let mut result = conn.exec_iter(sql, mysql_params(params)).map_err(mysql_err)?;
    let mut out = Vec::new();
    while let Some(row_res) = result.next() {
        let row = row_res.map_err(mysql_err)?;
        let cols = row.columns(); // Arc<[Column]> (mismo orden que los valores)
        let values = row.unwrap(); // Vec<Value>, consume la fila
        let mut m = IndexMap::new();
        for (i, val) in values.into_iter().enumerate() {
            let col = &cols[i];
            m.insert(col.name_str().to_string(), mysql_cell_to_syn(val, col));
        }
        out.push(m);
    }
    Ok(out)
}

/// True si la columna lleva datos binarios reales (BLOB/BINARY/VARBINARY) → la pseudo-
/// collation `binary`, cuyo id de charset es **63**. MySQL usa el MISMO `column_type` para
/// TEXT y BLOB; este es el discriminador para mandar binario→`bytes` y texto→`text`
/// (round-trip MF-010).
///
/// OJO (lección de la verificación viva): NO usar `ColumnFlags::BINARY_FLAG`. Ese flag marca
/// *collation binaria* (`_bin`), no *datos binarios*: una columna TEXT con collation
/// `utf8mb3_bin`/`utf8mb4_bin` (p.ej. `information_schema.tables.TABLE_NAME`) trae el flag
/// pero sigue siendo texto. El único indicador fiable de BLOB/BINARY es el charset id 63.
fn col_is_binary(col: &mysql::Column) -> bool {
    col.character_set() == 63
}

/// `Vec<u8>` válido utf8 → `text`; si no → `bytes` (no corrompe; sin utf8-lossy).
fn text_or_bytes(b: Vec<u8>) -> SynValue {
    match String::from_utf8(b) {
        Ok(s) => syn_text(s),
        Err(e) => syn_bytes(e.into_bytes()),
    }
}

/// Lee una celda MySQL → `SynValue` mirando el `Value` y el tipo/charset de la columna
/// (§5.2 del spec). Enteros/floats/fechas vienen tipados; DECIMAL/JSON/TEXT/BLOB vienen como
/// `Bytes` y se interpretan por `column_type` (+ flag binario para BLOB vs TEXT).
fn mysql_cell_to_syn(v: mysql::Value, col: &mysql::Column) -> SynValue {
    match v {
        mysql::Value::NULL => SynValue::Nothing,
        mysql::Value::Int(i) => syn_int(i),
        // BIGINT UNSIGNED puede pasarse de i64 → se preserva exacto como entero (Int/Big),
        // no como decimal (mantiene `type_of` entero).
        mysql::Value::UInt(u) => {
            if u <= i64::MAX as u64 {
                syn_int(u as i64)
            } else {
                syn_number(Number::parse_int_literal(&u.to_string()))
            }
        }
        mysql::Value::Float(f) => syn_float(f as f64),
        mysql::Value::Double(f) => syn_float(f),
        // DATE → fecha sola; DATETIME/TIMESTAMP → fecha y hora (ISO). Texto (como PG).
        mysql::Value::Date(y, mo, d, h, mi, s, us) => {
            let txt = if col.column_type() == ColumnType::MYSQL_TYPE_DATE {
                format!("{:04}-{:02}-{:02}", y, mo, d)
            } else if us > 0 {
                format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}", y, mo, d, h, mi, s, us)
            } else {
                format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, mo, d, h, mi, s)
            };
            syn_text(txt)
        }
        // TIME admite > 24h (días) y signo (intervalos). Texto `[-]HH:MM:SS[.ffffff]`.
        mysql::Value::Time(neg, days, h, mi, s, us) => {
            let total_h = days * 24 + h as u32;
            let sign = if neg { "-" } else { "" };
            let txt = if us > 0 {
                format!("{}{:02}:{:02}:{:02}.{:06}", sign, total_h, mi, s, us)
            } else {
                format!("{}{:02}:{:02}:{:02}", sign, total_h, mi, s)
            };
            syn_text(txt)
        }
        mysql::Value::Bytes(b) => {
            let nothing = SynValue::Nothing;
            match col.column_type() {
                // DECIMAL/NUMERIC: texto "9.99" → Decimal exacto (DE-009/21: type_of "decimal").
                ColumnType::MYSQL_TYPE_DECIMAL | ColumnType::MYSQL_TYPE_NEWDECIMAL => {
                    let s = String::from_utf8_lossy(&b);
                    match rust_decimal::Decimal::from_str_exact(s.trim()) {
                        Ok(d) => syn_number(Number::Decimal(d)),
                        Err(_) => syn_text(s.into_owned()),
                    }
                }
                // JSON → map/list (parsear con serde_json; reusa json_to_syn de M1).
                ColumnType::MYSQL_TYPE_JSON => serde_json::from_slice::<serde_json::Value>(&b)
                    .map(|j| json_to_syn(&j))
                    .unwrap_or(nothing),
                // VARCHAR/CHAR/TEXT/BLOB/ENUM/SET comparten column_type: el charset binario
                // (63) decide bytes (BLOB/BINARY) vs text (TEXT/VARCHAR/ENUM).
                ColumnType::MYSQL_TYPE_VARCHAR
                | ColumnType::MYSQL_TYPE_VAR_STRING
                | ColumnType::MYSQL_TYPE_STRING
                | ColumnType::MYSQL_TYPE_BLOB
                | ColumnType::MYSQL_TYPE_TINY_BLOB
                | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
                | ColumnType::MYSQL_TYPE_LONG_BLOB
                | ColumnType::MYSQL_TYPE_ENUM
                | ColumnType::MYSQL_TYPE_SET => {
                    if col_is_binary(col) {
                        syn_bytes(b)
                    } else {
                        text_or_bytes(b)
                    }
                }
                // Otros (BIT, GEOMETRY, fecha-como-texto…): binario→bytes, texto→utf8.
                _ => {
                    if col_is_binary(col) {
                        syn_bytes(b)
                    } else {
                        text_or_bytes(b)
                    }
                }
            }
        }
    }
}

// -- MongoDB: conexión, errores, conversión SynValue <-> BSON (M3) --

fn is_mongo_url(target: &str) -> bool {
    target.starts_with("mongodb://") || target.starts_with("mongodb+srv://")
}

/// Mapea un error del crate `mongodb` a un mensaje útil (su `Display` ya trae detalle del
/// server/driver; lección M1 #2: no devolver algo opaco). Wrapper nombrado para documentarlo.
fn mongo_err(e: mongodb::error::Error) -> String {
    e.to_string()
}

/// Error simétrico cuando se usan los builtins SQL (`sql`/`sql_exec`/`sql_tables`/…) sobre una
/// conexión MongoDB.
fn mongo_not_sql() -> String {
    "this is a MongoDB connection — use the mongo_* builtins (mongo_find/mongo_insert/…), not sql()/sql_exec()"
        .to_string()
}

/// Error simétrico cuando se usan los builtins `mongo_*` sobre una conexión SQL.
fn mongo_wrong_backend() -> String {
    "this is a SQL connection — use sql()/sql_exec(), not the mongo_* builtins".to_string()
}

/// Conecta a MongoDB y devuelve el `Database` ya scoped al db del connstring. Timeouts por
/// defecto (10s) de conexión Y de selección de servidor — sólo si el connstring no los trae
/// (respeta `?serverSelectionTimeoutMS=…`/`?connectTimeoutMS=…`). Lección M1: no colgarse con
/// un host caído; en Mongo el cuelgue clásico es el *server selection*, no el TCP connect.
///
/// El driver conecta **lazy** (`with_options` no toca la red) → hacemos un `ping` eager para
/// VALIDAR conectividad/auth en `db_open` (igual que PG/MySQL conectan en su `db_open`); así un
/// host caído o credenciales malas fallan acá, no recién en el primer `mongo_*`.
/// TLS lo controla el connstring (`?tls=true`); rustls (backend ring). El dev es plaintext.
fn mongo_connect(url: &str) -> Result<mongodb::sync::Database, String> {
    let mut opts = mongodb::options::ClientOptions::parse(url).run().map_err(mongo_err)?;
    if opts.connect_timeout.is_none() {
        opts.connect_timeout = Some(Duration::from_secs(10));
    }
    if opts.server_selection_timeout.is_none() {
        opts.server_selection_timeout = Some(Duration::from_secs(10));
    }
    let db_name = opts
        .default_database
        .clone()
        .ok_or_else(|| "mongodb url must include a database (mongodb://host/DBNAME)".to_string())?;
    let client = mongodb::sync::Client::with_options(opts).map_err(mongo_err)?;
    let db = client.database(&db_name);
    db.run_command(mongodb::bson::doc! { "ping": 1 })
        .run()
        .map_err(mongo_err)?;
    Ok(db)
}

/// Opciones de `mongo_find` (mapeadas desde un map `{limit, skip, sort, fields}`).
#[derive(Default)]
pub struct MongoFindOpts {
    pub limit: Option<i64>,
    pub skip: Option<u64>,
    pub sort: Option<Document>,
    pub projection: Option<Document>,
}

/// `SynValue` → BSON (recursivo). Int32 si entra, si no Int64; decimal/big → Decimal128 (texto
/// si no parsea); bytes → Binary (subtype Generic); list/map recursivos. El secret se revela
/// en el borde de la DB (igual que SQL). Para la clave `_id` ver `syn_map_to_doc`/`coerce_id`.
fn syn_to_bson(v: &SynValue) -> Bson {
    match v {
        SynValue::Nothing => Bson::Null,
        SynValue::Bool(b) => Bson::Boolean(*b),
        SynValue::Number(Number::Int(i)) => {
            if *i >= i32::MIN as i64 && *i <= i32::MAX as i64 {
                Bson::Int32(*i as i32)
            } else {
                Bson::Int64(*i)
            }
        }
        SynValue::Number(Number::Float(f)) => Bson::Double(*f),
        SynValue::Number(n) => match Decimal128::from_str(&n.to_string()) {
            Ok(d) => Bson::Decimal128(d),
            Err(_) => Bson::String(n.to_string()),
        },
        SynValue::Text(s) => Bson::String(s.to_string()),
        SynValue::Secret(s) => Bson::String(s.expose().to_string()),
        SynValue::Bytes(b) => Bson::Binary(Binary {
            subtype: BinarySubtype::Generic,
            bytes: b[..].to_vec(),
        }),
        SynValue::List(l) => Bson::Array(l.borrow().iter().map(syn_to_bson).collect()),
        SynValue::Map(m) => Bson::Document(syn_map_to_doc(&m.borrow())),
        other => Bson::String(other.to_string()),
    }
}

/// Map de Synsema → BSON `Document`. Para la clave `_id` aplica `coerce_id` (string hex-24 →
/// ObjectId) así `mongo_find("c", {"_id": id_text})` matchea el documento real.
fn syn_map_to_doc(m: &IndexMap<String, SynValue>) -> Document {
    let mut doc = Document::new();
    for (k, v) in m {
        let bson = if k == "_id" { coerce_id(v) } else { syn_to_bson(v) };
        doc.insert(k.clone(), bson);
    }
    doc
}

/// Convierte el valor de un filtro sobre `_id` a BSON, ascendiendo un string hex-24 a
/// ObjectId. Recurre en listas (`{"$in": [hex, …]}`) y operadores (`{"$gt": hex}`) para que
/// los hex anidados bajo `_id` también se conviertan. Un string que NO es un ObjectId válido
/// queda como String (ambigüedad rara, aceptada por el spec).
fn coerce_id(v: &SynValue) -> Bson {
    match v {
        SynValue::Text(s) => match ObjectId::parse_str(s.as_ref()) {
            Ok(oid) => Bson::ObjectId(oid),
            Err(_) => Bson::String(s.to_string()),
        },
        SynValue::List(l) => Bson::Array(l.borrow().iter().map(coerce_id).collect()),
        SynValue::Map(m) => {
            let mut doc = Document::new();
            for (k, val) in m.borrow().iter() {
                doc.insert(k.clone(), coerce_id(val));
            }
            Bson::Document(doc)
        }
        other => syn_to_bson(other),
    }
}

/// BSON → `SynValue` (recursivo). ObjectId → text hex (24); Decimal128 → decimal (texto si no
/// parsea); Binary → bytes; DateTime → ISO-8601; tipos raros (Regex/Symbol/…) → texto.
fn bson_to_syn(b: &Bson) -> SynValue {
    match b {
        Bson::Null | Bson::Undefined => SynValue::Nothing,
        Bson::Boolean(x) => syn_bool(*x),
        Bson::Int32(i) => syn_int(*i as i64),
        Bson::Int64(i) => syn_int(*i),
        Bson::Double(f) => syn_float(*f),
        Bson::Decimal128(d) => match rust_decimal::Decimal::from_str_exact(&d.to_string()) {
            Ok(dec) => syn_number(Number::Decimal(dec)),
            Err(_) => syn_text(d.to_string()),
        },
        Bson::String(s) => syn_text(s.as_str()),
        Bson::Binary(bin) => syn_bytes(bin.bytes.clone()),
        Bson::Array(a) => syn_list(a.iter().map(bson_to_syn).collect()),
        Bson::Document(d) => {
            let mut m = IndexMap::new();
            for (k, v) in d.iter() {
                m.insert(k.clone(), bson_to_syn(v));
            }
            syn_map(m)
        }
        Bson::ObjectId(oid) => syn_text(oid.to_hex()),
        Bson::DateTime(dt) => syn_text(dt.try_to_rfc3339_string().unwrap_or_else(|_| format!("{:?}", dt))),
        // Tipos BSON sin equivalente directo (Timestamp/Regex/Symbol/JS/MinKey/MaxKey/…) → texto.
        other => syn_text(format!("{:?}", other)),
    }
}

// -- Redis: conexión, errores, conversión SynValue <-> redis::Value (M4) --

fn is_redis_url(target: &str) -> bool {
    target.starts_with("redis://") || target.starts_with("rediss://")
}

/// Mapea un error del crate `redis` a un mensaje útil (su `Display` ya trae el detalle: kind +
/// el detalle del server; lección M1 #2: no devolver algo opaco). Wrapper nombrado para documentarlo.
fn redis_err(e: redis::RedisError) -> String {
    e.to_string()
}

/// Error simétrico cuando se usan los builtins SQL (`sql`/`sql_exec`/`sql_tables`/…) sobre una
/// conexión Redis.
fn redis_not_sql() -> String {
    "this is a Redis connection — use the redis_* builtins (redis_get/redis_set/redis_lock/…), not sql()/sql_exec()"
        .to_string()
}

/// Error simétrico cuando se usan los builtins `mongo_*` sobre una conexión Redis.
fn redis_not_mongo() -> String {
    "this is a Redis connection — use the redis_* builtins (redis_get/redis_set/redis_lock/…), not the mongo_* builtins"
        .to_string()
}

/// Error simétrico cuando se usan los builtins `redis_*` sobre una conexión SQL.
fn redis_wrong_backend_sql() -> String {
    "this is a SQL connection — use sql()/sql_exec(), not the redis_* builtins".to_string()
}

/// Error simétrico cuando se usan los builtins `redis_*` sobre una conexión MongoDB.
fn redis_wrong_backend_mongo() -> String {
    "this is a MongoDB connection — use the mongo_* builtins (mongo_find/…), not the redis_* builtins"
        .to_string()
}

/// Conecta a Redis (sync). `connect-timeout` explícito (lección M1 #1: no colgarse con un host
/// caído) + read/write timeouts (no colgar una op contra un peer mudo). Validación **eager** con
/// `PING` (igual que el ping de Mongo / el connect de PG/MySQL): auth/redis-down fallan ACÁ, no en
/// la 1ª op. El db-index (`redis://host:6379/2` → SELECT 2) lo maneja el crate al abrir; sin `/N`
/// = db 0. TLS: `rediss://…` activa rustls (provider ring por unificación de features). El dev es
/// `redis://` plaintext.
fn redis_connect(url: &str) -> Result<redis::Connection, String> {
    let client = redis::Client::open(url).map_err(redis_err)?;
    let mut conn = client
        .get_connection_with_timeout(Duration::from_secs(10))
        .map_err(redis_err)?;
    let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = conn.set_write_timeout(Some(Duration::from_secs(10)));
    redis::cmd("PING").query::<String>(&mut conn).map_err(redis_err)?;
    Ok(conn)
}

/// `SynValue` → argumento Redis (bytes que se mandan). Redis es *byte-string*: mapeo **explícito**,
/// binario-seguro, sin auto-JSON mágico (§5.1 del spec). text → bytes UTF-8; bytes → crudos;
/// number → su repr decimal (así `INCR` lo entiende); secret → se **revela** en el borde de la DB
/// (como SQL/Mongo). Bool/Map/List/Nothing (y el resto) → **error claro** orientando a `json_encode`.
fn syn_to_redis_arg(v: &SynValue) -> Result<Vec<u8>, String> {
    match v {
        SynValue::Text(s) => Ok(s.as_bytes().to_vec()),
        SynValue::Bytes(b) => Ok(b[..].to_vec()),
        SynValue::Number(n) => Ok(n.to_string().into_bytes()),
        SynValue::Secret(s) => Ok(s.expose().to_string().into_bytes()),
        other => Err(format!(
            "redis values must be text, bytes or number (got {}); use json_encode(...) for structured data",
            other.type_name()
        )),
    }
}

/// Reply Redis (`redis::Value`) → `SynValue` (recursivo, §5.2). `Nil` → `nothing` (clave/campo
/// ausente, pop vacío); `Int` → number; `BulkString` UTF-8 → `text`, si no `bytes` (heurística
/// binario-segura, como BLOB/TEXT en MySQL); `SimpleString`/`Okay` → text; `Array`/`Set` → `list`;
/// `Map` (RESP3) → `map`; tipos raros (Double/Boolean/BigNumber/Verbatim/Push/…) → el más cercano.
fn redis_value_to_syn(v: &redis::Value) -> SynValue {
    use redis::Value as RV;
    match v {
        RV::Nil => SynValue::Nothing,
        RV::Int(i) => syn_int(*i),
        RV::BulkString(bytes) => text_or_bytes(bytes.clone()),
        RV::SimpleString(s) => syn_text(s.as_str()),
        RV::Okay => syn_text("OK"),
        RV::Array(items) | RV::Set(items) => syn_list(items.iter().map(redis_value_to_syn).collect()),
        RV::Map(pairs) => {
            let mut m = IndexMap::new();
            for (k, val) in pairs {
                m.insert(redis_key_string(k), redis_value_to_syn(val));
            }
            syn_map(m)
        }
        RV::Double(f) => syn_float(*f),
        RV::Boolean(b) => syn_bool(*b),
        RV::BigNumber(n) => syn_number(Number::parse_int_literal(&n.to_string())),
        RV::VerbatimString { text, .. } => syn_text(text.as_str()),
        // Attribute/Push/ServerError y cualquier variante futura: best-effort a texto.
        other => syn_text(format!("{:?}", other)),
    }
}

/// Clave de un `Map`/par Redis → `String` (para mapear hashes). Las claves de hash son siempre
/// texto; un bulk no-UTF8 (raro) cae a lossy (sólo para la clave, no para el valor).
fn redis_key_string(v: &redis::Value) -> String {
    match v {
        redis::Value::BulkString(b) => String::from_utf8_lossy(b).into_owned(),
        redis::Value::SimpleString(s) => s.clone(),
        redis::Value::Int(i) => i.to_string(),
        other => format!("{:?}", other),
    }
}

/// Reply de `HGETALL` → `IndexMap` (field→valor). En RESP3 viene como `Map`; en RESP2 (default)
/// como `Array` plano de pares → se agrupa de a dos. Clave ausente → array vacío → map vacío.
fn redis_value_to_map(v: redis::Value) -> IndexMap<String, SynValue> {
    use redis::Value as RV;
    let mut m = IndexMap::new();
    match v {
        RV::Map(pairs) => {
            for (k, val) in pairs {
                m.insert(redis_key_string(&k), redis_value_to_syn(&val));
            }
        }
        RV::Array(items) | RV::Set(items) => {
            let mut it = items.into_iter();
            while let (Some(k), Some(val)) = (it.next(), it.next()) {
                m.insert(redis_key_string(&k), redis_value_to_syn(&val));
            }
        }
        _ => {}
    }
    m
}

/// Shaper directo: `redis::Value` → `SynValue` (la mayoría de los builtins).
fn redis_shape_value(v: redis::Value) -> SynValue {
    redis_value_to_syn(&v)
}

/// Shaper a bool (EXPIRE/PERSIST/SISMEMBER/EVAL del unlock): Redis responde `Int` 0/1.
fn redis_shape_bool(v: redis::Value) -> SynValue {
    match v {
        redis::Value::Int(i) => syn_bool(i != 0),
        redis::Value::Boolean(b) => syn_bool(b),
        redis::Value::Nil => syn_bool(false),
        _ => syn_bool(true),
    }
}

/// Token único por adquisición del lock distribuido (`redis_lock`): 16 bytes aleatorios → hex
/// (32 chars). Reusa el `rand` que el engine YA usa (random()/random_int()); no introduce un
/// crate nuevo. No es para cripto, sólo para que el token sea irrepetible/no-adivinable entre
/// agentes (el chequeo de propiedad del unlock es atómico vía Lua).
fn redis_gen_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    let mut s = String::with_capacity(32);
    for b in buf {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// -- Builtins --

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

/// Params de un 2º arg lista → Vec<SynValue> (cada backend los convierte a lo suyo).
fn params_arg(v: Option<&SynValue>) -> Vec<SynValue> {
    match v {
        Some(SynValue::List(l)) => l.borrow().iter().cloned().collect(),
        _ => Vec::new(),
    }
}

/// Scope canónico de `db` para un `db_open(target, mode)` (matchea la key que guarda
/// `open()` y la que devuelve `default_path()`): PG/MySQL/Mongo → canon_url; SQLite →
/// ruta/`:memory:`.
fn db_scope_for(target: &str, mode: &str) -> String {
    if is_pg_url(target) || is_mysql_url(target) || is_mongo_url(target) || is_redis_url(target) {
        canon_url(target)
    } else if mode == "memory" {
        ":memory:".to_string()
    } else {
        target.to_string()
    }
}

/// Chequea la capability `db(scope)`; convierte la violación en `Control::Error` SIN
/// ubicación (como secure.rs). `covers()` canoniza el scope, así que pasar el crudo.
fn require_db(caps: &Rc<RefCell<CapabilitySet>>, scope: &str, source: &str) -> Result<(), Control> {
    caps.borrow_mut()
        .require(&Capability::new(CapabilityType::Db, Some(scope.to_string())), source)
        .map_err(|v| Control::Error(RuntimeError::new(v.message)))
}

// -- Helpers de args para los builtins `mongo_*` (map de Synsema ↔ BSON Document) --

/// Arg de filtro opcional (map) → BSON `Document`. None / no-map → Document vacío (match all).
fn filter_arg(v: Option<&SynValue>) -> Document {
    match v {
        Some(SynValue::Map(m)) => syn_map_to_doc(&m.borrow()),
        _ => Document::new(),
    }
}

/// Arg map REQUERIDO (doc de insert / update) → `Document`; error claro si no es map.
fn required_doc_arg(v: Option<&SynValue>, ctx: &str) -> Result<Document, Control> {
    match v {
        Some(SynValue::Map(m)) => Ok(syn_map_to_doc(&m.borrow())),
        Some(other) => Err(err(format!("{}: expected a map, got {}", ctx, other.type_name()))),
        None => Err(err(format!("{}: missing the document argument", ctx))),
    }
}

/// Lista de maps → `Vec<Document>` (insert_many / pipeline de aggregate); error si algún
/// elemento no es map.
fn docs_list_arg(v: Option<&SynValue>, ctx: &str) -> Result<Vec<Document>, Control> {
    match v {
        Some(SynValue::List(l)) => {
            let mut out = Vec::new();
            for item in l.borrow().iter() {
                match item {
                    SynValue::Map(m) => out.push(syn_map_to_doc(&m.borrow())),
                    other => {
                        return Err(err(format!(
                            "{}: each element must be a map, got {}",
                            ctx,
                            other.type_name()
                        )))
                    }
                }
            }
            Ok(out)
        }
        _ => Err(err(format!("{}: expected a list of maps", ctx))),
    }
}

/// Opts de `mongo_find` desde un map `{limit, skip, sort, fields}` (claves desconocidas se
/// ignoran). `skip` negativo se descarta.
fn parse_find_opts(v: Option<&SynValue>) -> MongoFindOpts {
    let mut o = MongoFindOpts::default();
    if let Some(SynValue::Map(m)) = v {
        let m = m.borrow();
        if let Some(SynValue::Number(n)) = m.get("limit") {
            o.limit = Some(n.to_f64() as i64);
        }
        if let Some(SynValue::Number(n)) = m.get("skip") {
            let s = n.to_f64() as i64;
            if s >= 0 {
                o.skip = Some(s as u64);
            }
        }
        if let Some(SynValue::Map(s)) = m.get("sort") {
            o.sort = Some(syn_map_to_doc(&s.borrow()));
        }
        if let Some(SynValue::Map(f)) = m.get("fields") {
            o.projection = Some(syn_map_to_doc(&f.borrow()));
        }
    }
    o
}

/// Registra un builtin `redis_*` "directo": todos los args de Synsema se convierten a argumentos
/// Redis (vía `syn_to_redis_arg`), se antepone(n) el/los token(s) de comando (`tokens`), se corre
/// el comando contra la conexión default (gateado por `db`), y la respuesta se moldea con `shape`.
/// `min_args`/`max_args` validan la aridad (Synsema no la enforce: `param_count` es informativo).
#[allow(clippy::too_many_arguments)]
fn register_redis_simple<H: DbHandle>(
    interp: &Interpreter,
    db: &H,
    caps: &Rc<RefCell<CapabilitySet>>,
    name: &'static str,
    tokens: &'static [&'static str],
    param_count: i32,
    min_args: usize,
    max_args: Option<usize>,
    shape: fn(redis::Value) -> SynValue,
) {
    let db = db.clone();
    let caps = caps.clone();
    interp.register_builtin(
        name,
        param_count,
        Rc::new(move |_i, args, _loc| {
            if args.len() < min_args || max_args.is_some_and(|mx| args.len() > mx) {
                return Err(err(format!("{}: wrong number of arguments", name)));
            }
            let mut parts: Vec<Vec<u8>> = tokens.iter().map(|t| t.as_bytes().to_vec()).collect();
            for a in args.iter() {
                parts.push(syn_to_redis_arg(a).map_err(err)?);
            }
            if let Some(p) = db.read(|m| m.default_path()) {
                require_db(&caps, &p, name)?;
            }
            let v = db.write(|m| m.redis_command(&parts)).map_err(err)?;
            Ok(shape(v))
        }),
    );
}

/// Registra los builtins de base de datos sobre un `DbHandle` (compartido). Gateados por
/// la capability `db` (deny-by-default): `db_open` chequea el scope de la base que abre;
/// las ops de datos (sql/sql_exec/…) chequean el scope de la conexión default que usan.
/// `db_close` queda sin gatear (cerrar es benigno).
pub fn register_database_builtins<H: DbHandle>(
    interp: &Interpreter,
    db: H,
    caps: Rc<RefCell<CapabilitySet>>,
) {
    // db_open(target, mode?)
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "db_open",
            -1,
            Rc::new(move |_i, args, _loc| {
                let target = raw_str(args.first().ok_or_else(|| err("missing argument"))?);
                let mode = args.get(1).map(raw_str).unwrap_or_else(|| "readwrite".to_string());
                require_db(&caps, &db_scope_for(&target, &mode), "db_open()")?;
                db.write(|m| m.open(&target, &mode)).map_err(err)?;
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

    // json_encode(value) → text: serializa CUALQUIER valor a un string JSON. Compañero de la
    // API de DB para datos estructurados (p.ej. redis_set(k, json_encode({...}))), pero es un
    // builtin general (transform puro, SIN capability — como text/bytes/decode). Mismo mapeo que
    // los bodies de serve: secrets → "[redacted]" (seguro), bytes → base64, decimal exacto.
    interp.register_builtin(
        "json_encode",
        1,
        Rc::new(|_i, args, _loc| {
            let v = args.first().ok_or_else(|| err("json_encode: missing argument"))?;
            Ok(syn_text(dumps(&syn_to_json(v))))
        }),
    );

    // json_decode(text) → value: parsea un string JSON a un valor de Synsema (map/list/number/
    // text/bool/nothing). Error claro si el JSON es inválido. Sin capability.
    interp.register_builtin(
        "json_decode",
        1,
        Rc::new(|_i, args, _loc| {
            let s = raw_str(args.first().ok_or_else(|| err("json_decode: missing argument"))?);
            let j: serde_json::Value = serde_json::from_str(&s)
                .map_err(|e| err(format!("json_decode: invalid JSON: {}", e)))?;
            Ok(json_to_syn(&j))
        }),
    );

    // sql(query, params?) → lista de mapas-fila
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "sql",
            -1,
            Rc::new(move |_i, args, _loc| {
                let query = raw_str(args.first().ok_or_else(|| err("missing argument"))?);
                let params = params_arg(args.get(1));
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "sql()")?;
                }
                let rows = db.write(|m| m.query(&query, &params)).map_err(err)?;
                Ok(syn_list(rows.into_iter().map(syn_map).collect()))
            }),
        );
    }

    // sql_exec(statement, params?) → {rows_affected, last_id}
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "sql_exec",
            -1,
            Rc::new(move |_i, args, _loc| {
                let stmt = raw_str(args.first().ok_or_else(|| err("missing argument"))?);
                let params = params_arg(args.get(1));
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "sql_exec()")?;
                }
                let (affected, last_id) = db.write(|m| m.execute(&stmt, &params)).map_err(err)?;
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
        let caps = caps.clone();
        interp.register_builtin(
            "sql_tables",
            0,
            Rc::new(move |_i, _args, _loc| {
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "sql_tables()")?;
                }
                let tables = db.write(|m| m.tables()).map_err(err)?;
                Ok(syn_list(tables.iter().map(|t| syn_text(t.as_str())).collect()))
            }),
        );
    }

    // sql_batch(statement, params_list) → {rows_affected}
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "sql_batch",
            2,
            Rc::new(move |_i, args, _loc| {
                let stmt = raw_str(args.first().ok_or_else(|| err("missing argument"))?);
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "sql_batch()")?;
                }
                let params_list: Vec<Vec<SynValue>> = match args.get(1) {
                    Some(SynValue::List(l)) => {
                        l.borrow().iter().map(|p| params_arg(Some(p))).collect()
                    }
                    _ => Vec::new(),
                };
                let affected = db.write(|m| m.execute_many(&stmt, &params_list)).map_err(err)?;
                let mut m = IndexMap::new();
                m.insert("rows_affected".to_string(), syn_int(affected));
                Ok(syn_map(m))
            }),
        );
    }

    // paged(query, params?) → marcador de paginación lazy para `serve` (_PAGED).
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "paged",
            -1,
            Rc::new(move |_i, args, _loc| {
                let query = raw_str(args.first().ok_or_else(|| err("missing argument"))?);
                let params = params_arg(args.get(1));
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "paged()")?;
                }
                let dbf = db.clone();
                let fetch = move |limit: Option<i64>, offset: i64| -> Result<(Vec<SynValue>, i64), String> {
                    dbf.write(|m| match limit {
                        // limit None → materialización completa (sin contexto de serve).
                        None => {
                            let rows = m.query(&query, &params)?;
                            let n = rows.len() as i64;
                            Ok((rows.into_iter().map(syn_map).collect(), n))
                        }
                        Some(lim) => {
                            let count_sql =
                                format!("SELECT COUNT(*) AS _c FROM ({}) AS _sub", query);
                            let count_rows = m.query(&count_sql, &params)?;
                            let total = count_rows
                                .first()
                                .and_then(|r| r.values().next())
                                .map(syn_to_i64)
                                .unwrap_or(0);
                            let page_sql = format!("{} LIMIT ? OFFSET ?", query);
                            let mut p = params.clone();
                            p.push(syn_int(lim));
                            p.push(syn_int(offset));
                            let rows = m.query(&page_sql, &p)?;
                            Ok((rows.into_iter().map(syn_map).collect(), total))
                        }
                    })
                };
                Ok(SynValue::Server(Rc::new(ServerValue::Paged(Rc::new(fetch)))))
            }),
        );
    }

    // -- MongoDB (M3): API propia `mongo_*` (no-SQL). Gateadas por `db` como los SQL. --

    // mongo_find(coll, filter?, opts?) → lista de documentos (maps)
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "mongo_find",
            -1,
            Rc::new(move |_i, args, _loc| {
                let coll = raw_str(args.first().ok_or_else(|| err("mongo_find: missing collection"))?);
                let filter = filter_arg(args.get(1));
                let opts = parse_find_opts(args.get(2));
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "mongo_find()")?;
                }
                let docs = db.write(|m| m.mongo_find(&coll, filter, opts)).map_err(err)?;
                Ok(syn_list(docs))
            }),
        );
    }

    // mongo_find_one(coll, filter?) → documento (map) o nothing
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "mongo_find_one",
            -1,
            Rc::new(move |_i, args, _loc| {
                let coll = raw_str(args.first().ok_or_else(|| err("mongo_find_one: missing collection"))?);
                let filter = filter_arg(args.get(1));
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "mongo_find_one()")?;
                }
                db.write(|m| m.mongo_find_one(&coll, filter)).map_err(err)
            }),
        );
    }

    // mongo_insert(coll, doc) → _id insertado (text hex si es ObjectId)
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "mongo_insert",
            2,
            Rc::new(move |_i, args, _loc| {
                let coll = raw_str(args.first().ok_or_else(|| err("mongo_insert: missing collection"))?);
                let doc = required_doc_arg(args.get(1), "mongo_insert")?;
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "mongo_insert()")?;
                }
                db.write(|m| m.mongo_insert(&coll, doc)).map_err(err)
            }),
        );
    }

    // mongo_insert_many(coll, docs_list) → lista de _id (en orden)
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "mongo_insert_many",
            2,
            Rc::new(move |_i, args, _loc| {
                let coll = raw_str(args.first().ok_or_else(|| err("mongo_insert_many: missing collection"))?);
                let docs = docs_list_arg(args.get(1), "mongo_insert_many")?;
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "mongo_insert_many()")?;
                }
                let ids = db.write(|m| m.mongo_insert_many(&coll, docs)).map_err(err)?;
                Ok(syn_list(ids))
            }),
        );
    }

    // mongo_update(coll, filter, update) → {matched, modified}. `update` con operadores ($set/…).
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "mongo_update",
            3,
            Rc::new(move |_i, args, _loc| {
                let coll = raw_str(args.first().ok_or_else(|| err("mongo_update: missing collection"))?);
                let filter = filter_arg(args.get(1));
                let update = required_doc_arg(args.get(2), "mongo_update")?;
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "mongo_update()")?;
                }
                let (matched, modified) =
                    db.write(|m| m.mongo_update(&coll, filter, update)).map_err(err)?;
                let mut map = IndexMap::new();
                map.insert("matched".to_string(), syn_int(matched));
                map.insert("modified".to_string(), syn_int(modified));
                Ok(syn_map(map))
            }),
        );
    }

    // mongo_delete(coll, filter) → {deleted}
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "mongo_delete",
            2,
            Rc::new(move |_i, args, _loc| {
                let coll = raw_str(args.first().ok_or_else(|| err("mongo_delete: missing collection"))?);
                let filter = filter_arg(args.get(1));
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "mongo_delete()")?;
                }
                let deleted = db.write(|m| m.mongo_delete(&coll, filter)).map_err(err)?;
                let mut map = IndexMap::new();
                map.insert("deleted".to_string(), syn_int(deleted));
                Ok(syn_map(map))
            }),
        );
    }

    // mongo_count(coll, filter?) → number
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "mongo_count",
            -1,
            Rc::new(move |_i, args, _loc| {
                let coll = raw_str(args.first().ok_or_else(|| err("mongo_count: missing collection"))?);
                let filter = filter_arg(args.get(1));
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "mongo_count()")?;
                }
                let n = db.write(|m| m.mongo_count(&coll, filter)).map_err(err)?;
                Ok(syn_int(n))
            }),
        );
    }

    // mongo_aggregate(coll, pipeline_list) → lista de documentos (maps)
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "mongo_aggregate",
            2,
            Rc::new(move |_i, args, _loc| {
                let coll = raw_str(args.first().ok_or_else(|| err("mongo_aggregate: missing collection"))?);
                let pipeline = docs_list_arg(args.get(1), "mongo_aggregate")?;
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "mongo_aggregate()")?;
                }
                let docs = db.write(|m| m.mongo_aggregate(&coll, pipeline)).map_err(err)?;
                Ok(syn_list(docs))
            }),
        );
    }

    // mongo_collections() → lista de nombres de colecciones
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "mongo_collections",
            0,
            Rc::new(move |_i, _args, _loc| {
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "mongo_collections()")?;
                }
                let names = db.write(|m| m.mongo_collections()).map_err(err)?;
                Ok(syn_list(names.iter().map(|n| syn_text(n.as_str())).collect()))
            }),
        );
    }

    // -- Redis (M4): API propia `redis_*` (KV/cache/estructuras + lock). Gateadas por `db`. --
    //
    // Tres familias de DB: SQL (SQLite/PG/MySQL: sql/sql_exec) vs documentos (Mongo: mongo_*)
    // vs **KV/estructuras (Redis: redis_*)**. Los valores son `text`/`bytes`/`number`
    // (binario-seguros); los estructurados van por `json_encode`/`json_decode`.

    // KV + cache (los "directos": cada arg → arg Redis; respuesta moldeada por el shaper).
    register_redis_simple(interp, &db, &caps, "redis_get", &["GET"], 1, 1, Some(1), redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_del", &["DEL"], -1, 1, None, redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_exists", &["EXISTS"], -1, 1, None, redis_shape_value);
    // `KEYS` es O(N) (escanea TODO el keyspace): para prod preferir un patrón acotado; un
    // `redis_scan` no-bloqueante puede venir en un follow-up.
    register_redis_simple(interp, &db, &caps, "redis_keys", &["KEYS"], 1, 1, Some(1), redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_type", &["TYPE"], 1, 1, Some(1), redis_shape_value);

    // Contadores atómicos.
    register_redis_simple(interp, &db, &caps, "redis_incr", &["INCR"], 1, 1, Some(1), redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_decr", &["DECR"], 1, 1, Some(1), redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_incrby", &["INCRBY"], 2, 2, Some(2), redis_shape_value);

    // TTL.
    register_redis_simple(interp, &db, &caps, "redis_expire", &["EXPIRE"], 2, 2, Some(2), redis_shape_bool);
    register_redis_simple(interp, &db, &caps, "redis_ttl", &["TTL"], 1, 1, Some(1), redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_persist", &["PERSIST"], 1, 1, Some(1), redis_shape_bool);

    // Hashes.
    register_redis_simple(interp, &db, &caps, "redis_hget", &["HGET"], 2, 2, Some(2), redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_hdel", &["HDEL"], -1, 2, None, redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_hincrby", &["HINCRBY"], 3, 3, Some(3), redis_shape_value);

    // Listas (colas/pilas).
    register_redis_simple(interp, &db, &caps, "redis_lpush", &["LPUSH"], -1, 2, None, redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_rpush", &["RPUSH"], -1, 2, None, redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_lpop", &["LPOP"], 1, 1, Some(1), redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_rpop", &["RPOP"], 1, 1, Some(1), redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_lrange", &["LRANGE"], 3, 3, Some(3), redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_llen", &["LLEN"], 1, 1, Some(1), redis_shape_value);

    // Sets.
    register_redis_simple(interp, &db, &caps, "redis_sadd", &["SADD"], -1, 2, None, redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_srem", &["SREM"], -1, 2, None, redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_smembers", &["SMEMBERS"], 1, 1, Some(1), redis_shape_value);
    register_redis_simple(interp, &db, &caps, "redis_sismember", &["SISMEMBER"], 2, 2, Some(2), redis_shape_bool);

    // redis_set(key, val, ttl_secs?) → nothing (ok). Con ttl: `SET key val EX ttl`.
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "redis_set",
            -1,
            Rc::new(move |_i, args, _loc| {
                let key = syn_to_redis_arg(args.first().ok_or_else(|| err("redis_set: missing key"))?).map_err(err)?;
                let val = syn_to_redis_arg(args.get(1).ok_or_else(|| err("redis_set: missing value"))?).map_err(err)?;
                let mut parts = vec![b"SET".to_vec(), key, val];
                match args.get(2) {
                    None | Some(SynValue::Nothing) => {}
                    Some(SynValue::Number(n)) => {
                        parts.push(b"EX".to_vec());
                        parts.push(n.to_i64_trunc().unwrap_or(0).to_string().into_bytes());
                    }
                    Some(other) => {
                        return Err(err(format!(
                            "redis_set: ttl_secs must be a number, got {}",
                            other.type_name()
                        )))
                    }
                }
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "redis_set")?;
                }
                db.write(|m| m.redis_command(&parts)).map_err(err)?;
                Ok(SynValue::Nothing)
            }),
        );
    }

    // redis_mget(keys_list) → list (cada uno text/bytes/nothing). El arg es UNA lista de claves.
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "redis_mget",
            1,
            Rc::new(move |_i, args, _loc| {
                let items: Vec<SynValue> = match args.first() {
                    Some(SynValue::List(l)) => l.borrow().iter().cloned().collect(),
                    _ => return Err(err("redis_mget: expected a list of keys")),
                };
                if items.is_empty() {
                    return Ok(syn_list(vec![]));
                }
                let mut parts = vec![b"MGET".to_vec()];
                for k in &items {
                    parts.push(syn_to_redis_arg(k).map_err(err)?);
                }
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "redis_mget")?;
                }
                let v = db.write(|m| m.redis_command(&parts)).map_err(err)?;
                Ok(redis_value_to_syn(&v))
            }),
        );
    }

    // redis_mset(map) → nothing (ok). El arg es UN map clave→valor.
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "redis_mset",
            1,
            Rc::new(move |_i, args, _loc| {
                let map_ref = match args.first() {
                    Some(SynValue::Map(m)) => m,
                    _ => return Err(err("redis_mset: expected a map of key→value")),
                };
                let mut parts = vec![b"MSET".to_vec()];
                for (k, val) in map_ref.borrow().iter() {
                    parts.push(k.as_bytes().to_vec());
                    parts.push(syn_to_redis_arg(val).map_err(err)?);
                }
                if parts.len() == 1 {
                    return Ok(SynValue::Nothing); // map vacío: nada que setear
                }
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "redis_mset")?;
                }
                db.write(|m| m.redis_command(&parts)).map_err(err)?;
                Ok(SynValue::Nothing)
            }),
        );
    }

    // redis_hset(key, map) → number (campos nuevos). El 2º arg es UN map field→valor.
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "redis_hset",
            2,
            Rc::new(move |_i, args, _loc| {
                let key = syn_to_redis_arg(args.first().ok_or_else(|| err("redis_hset: missing key"))?).map_err(err)?;
                let map_ref = match args.get(1) {
                    Some(SynValue::Map(m)) => m,
                    _ => return Err(err("redis_hset: expected a map of field→value")),
                };
                let mut parts = vec![b"HSET".to_vec(), key];
                for (f, val) in map_ref.borrow().iter() {
                    parts.push(f.as_bytes().to_vec());
                    parts.push(syn_to_redis_arg(val).map_err(err)?);
                }
                if parts.len() == 2 {
                    return Err(err("redis_hset: the map has no fields"));
                }
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "redis_hset")?;
                }
                let v = db.write(|m| m.redis_command(&parts)).map_err(err)?;
                Ok(redis_value_to_syn(&v))
            }),
        );
    }

    // redis_hgetall(key) → map (field→valor). Siempre devuelve map (agrupa el array RESP2).
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "redis_hgetall",
            1,
            Rc::new(move |_i, args, _loc| {
                let key = syn_to_redis_arg(args.first().ok_or_else(|| err("redis_hgetall: missing key"))?).map_err(err)?;
                let parts = vec![b"HGETALL".to_vec(), key];
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "redis_hgetall")?;
                }
                let v = db.write(|m| m.redis_command(&parts)).map_err(err)?;
                Ok(syn_map(redis_value_to_map(v)))
            }),
        );
    }

    // redis_lock(key, ttl_ms?) → text (token) o nothing si está tomado. `SET key <token> NX PX ttl`
    // (default 30000 ms). El token es único por adquisición (16 bytes aleatorios → hex).
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "redis_lock",
            -1,
            Rc::new(move |_i, args, _loc| {
                let key = syn_to_redis_arg(args.first().ok_or_else(|| err("redis_lock: missing key"))?).map_err(err)?;
                let ttl_ms: i64 = match args.get(1) {
                    None | Some(SynValue::Nothing) => 30000,
                    Some(SynValue::Number(n)) => n.to_i64_trunc().unwrap_or(30000),
                    Some(other) => {
                        return Err(err(format!(
                            "redis_lock: ttl_ms must be a number, got {}",
                            other.type_name()
                        )))
                    }
                };
                if ttl_ms <= 0 {
                    return Err(err("redis_lock: ttl_ms must be positive"));
                }
                let token = redis_gen_token();
                let parts = vec![
                    b"SET".to_vec(),
                    key,
                    token.clone().into_bytes(),
                    b"NX".to_vec(),
                    b"PX".to_vec(),
                    ttl_ms.to_string().into_bytes(),
                ];
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "redis_lock")?;
                }
                let v = db.write(|m| m.redis_command(&parts)).map_err(err)?;
                match v {
                    // NX falló (la clave ya existe) → no adquirimos el lock.
                    redis::Value::Nil => Ok(SynValue::Nothing),
                    // OK → es nuestro: devolvemos el token para el unlock token-checked.
                    _ => Ok(syn_text(token)),
                }
            }),
        );
    }

    // redis_unlock(key, token) → bool. Libera SOLO si el token coincide (Lua atómico): evita
    // liberar el lock de otro agente (p.ej. si el nuestro ya expiró por TTL y lo tomó otro).
    {
        let db = db.clone();
        let caps = caps.clone();
        interp.register_builtin(
            "redis_unlock",
            2,
            Rc::new(move |_i, args, _loc| {
                let key = syn_to_redis_arg(args.first().ok_or_else(|| err("redis_unlock: missing key"))?).map_err(err)?;
                let token = syn_to_redis_arg(args.get(1).ok_or_else(|| err("redis_unlock: missing token"))?).map_err(err)?;
                const LUA: &str =
                    "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";
                let parts = vec![
                    b"EVAL".to_vec(),
                    LUA.as_bytes().to_vec(),
                    b"1".to_vec(),
                    key,
                    token,
                ];
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "redis_unlock")?;
                }
                let v = db.write(|m| m.redis_command(&parts)).map_err(err)?;
                Ok(redis_shape_bool(v))
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(row: &Row, key: &str) -> SynValue {
        row.get(key).cloned().unwrap()
    }

    #[test]
    fn db_manager_basic() {
        let mut db = DatabaseManager::new();
        db.open(":memory:", "memory").unwrap();
        db.execute(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, price REAL)",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO items (name, price) VALUES (?, ?)",
            &[syn_text("Laptop"), syn_float(999.99)],
        )
        .unwrap();
        db.execute(
            "INSERT INTO items (name, price) VALUES (?, ?)",
            &[syn_text("Mouse"), syn_float(29.99)],
        )
        .unwrap();
        let rows = db.query("SELECT * FROM items ORDER BY price", &[]).unwrap();
        assert_eq!(rows.len(), 2);
        match cell(&rows[0], "name") {
            SynValue::Text(s) => assert_eq!(&*s, "Mouse"),
            o => panic!("esperaba text, got {:?}", o),
        }
        match cell(&rows[1], "price") {
            SynValue::Number(n) => assert_eq!(n.to_f64(), 999.99),
            o => panic!("esperaba number, got {:?}", o),
        }
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
                vec![syn_int(1)],
                vec![syn_int(2)],
                vec![syn_int(3)],
                vec![syn_int(4)],
                vec![syn_int(5)],
            ],
        )
        .unwrap();
        let rows = db.query("SELECT * FROM nums", &[]).unwrap();
        assert_eq!(rows.len(), 5);
        db.close(None);
    }

    #[test]
    fn blob_bytes_value_roundtrip() {
        // MF-010: bytes ↔ BLOB byte-exacto en ambas direcciones (incl. no-UTF8).
        let raw = vec![255u8, 254, 0, 72, 73];
        assert_eq!(syn_to_value(&syn_bytes(raw.clone())), Value::Blob(raw.clone()));
        match value_to_syn(&Value::Blob(raw.clone())) {
            SynValue::Bytes(b) => assert_eq!(&b[..], &raw[..]),
            other => panic!("esperaba bytes, got {:?}", other),
        }
    }

    #[test]
    fn rewrite_placeholders_basic_and_literals() {
        assert_eq!(rewrite_placeholders("a=? AND b=?"), "a=$1 AND b=$2");
        // `?` dentro de un literal NO se toca.
        assert_eq!(rewrite_placeholders("x='lit?' AND y=?"), "x='lit?' AND y=$1");
        assert_eq!(rewrite_placeholders("no placeholders"), "no placeholders");
        // pgvector: el cast queda intacto; el `?` se numera.
        assert_eq!(
            rewrite_placeholders("ORDER BY emb <-> ?::vector LIMIT ?"),
            "ORDER BY emb <-> $1::vector LIMIT $2"
        );
    }

    #[test]
    fn list_to_vector_text_formats_embedding() {
        let v = vec![syn_float(0.85), syn_float(0.15), syn_int(1)];
        assert_eq!(list_to_vector_text(&v), "[0.85,0.15,1]");
    }

    #[test]
    fn pgvector_from_sql_parses_binary() {
        // dim=3, flags=0, luego 3 f32 big-endian (1.0, 2.0, 3.0).
        let mut raw = vec![0u8, 3, 0, 0];
        for f in [1.0f32, 2.0, 3.0] {
            raw.extend_from_slice(&f.to_be_bytes());
        }
        let pv = PgVector::from_sql(&Type::FLOAT4, &raw).unwrap();
        assert_eq!(pv.0, vec![1.0f32, 2.0, 3.0]);
    }

    // -- MySQL (M2): mapeo de tipos sin servidor (Column sintética) --

    fn mycol(ct: ColumnType) -> mysql::Column {
        mysql::Column::new(ct)
    }

    #[test]
    fn syn_to_mysql_bind_mapping() {
        use mysql::Value as MyV;
        assert_eq!(syn_to_mysql(&SynValue::Nothing), MyV::NULL);
        // MySQL no tiene bool real → TINYINT 0/1.
        assert_eq!(syn_to_mysql(&syn_bool(true)), MyV::Int(1));
        assert_eq!(syn_to_mysql(&syn_bool(false)), MyV::Int(0));
        assert_eq!(syn_to_mysql(&syn_int(42)), MyV::Int(42));
        assert_eq!(syn_to_mysql(&syn_float(3.5)), MyV::Double(3.5));
        // decimal → texto exacto (el server castea a DECIMAL/NUMERIC).
        let d = rust_decimal::Decimal::from_str_exact("9.99").unwrap();
        assert_eq!(
            syn_to_mysql(&syn_number(Number::Decimal(d))),
            MyV::Bytes(b"9.99".to_vec())
        );
        // bytes crudos (no-UTF8) byte-exacto (MF-010).
        let raw = vec![255u8, 0, 72, 73];
        assert_eq!(syn_to_mysql(&syn_bytes(raw.clone())), MyV::Bytes(raw));
        assert_eq!(syn_to_mysql(&syn_text("hola")), MyV::Bytes(b"hola".to_vec()));
    }

    #[test]
    fn mysql_read_int_float_null() {
        match mysql_cell_to_syn(mysql::Value::Int(42), &mycol(ColumnType::MYSQL_TYPE_LONGLONG)) {
            SynValue::Number(Number::Int(42)) => {}
            o => panic!("esperaba int 42, got {:?}", o),
        }
        match mysql_cell_to_syn(mysql::Value::Double(3.5), &mycol(ColumnType::MYSQL_TYPE_DOUBLE)) {
            SynValue::Number(n) => assert_eq!(n.to_f64(), 3.5),
            o => panic!("esperaba float, got {:?}", o),
        }
        assert!(matches!(
            mysql_cell_to_syn(mysql::Value::NULL, &mycol(ColumnType::MYSQL_TYPE_NULL)),
            SynValue::Nothing
        ));
    }

    #[test]
    fn mysql_read_uint_big_preserves_integer() {
        // BIGINT UNSIGNED > i64::MAX → entero exacto (Big), NO decimal (type_of entero).
        let big = u64::MAX;
        match mysql_cell_to_syn(mysql::Value::UInt(big), &mycol(ColumnType::MYSQL_TYPE_LONGLONG)) {
            SynValue::Number(n) => {
                assert!(n.is_integer());
                assert_eq!(n.to_string(), big.to_string());
            }
            o => panic!("esperaba entero, got {:?}", o),
        }
    }

    #[test]
    fn mysql_read_decimal_text_to_decimal() {
        // NEWDECIMAL llega como Bytes-texto "9.99" → Decimal exacto (DE-021: type_of "decimal").
        match mysql_cell_to_syn(
            mysql::Value::Bytes(b"9.99".to_vec()),
            &mycol(ColumnType::MYSQL_TYPE_NEWDECIMAL),
        ) {
            SynValue::Number(n) => {
                assert!(n.is_decimal());
                assert_eq!(n.to_string(), "9.99");
            }
            o => panic!("esperaba decimal, got {:?}", o),
        }
    }

    #[test]
    fn mysql_read_blob_vs_text_by_charset() {
        // BLOB/BINARY (charset binary 63) → bytes crudos, aun no-UTF8 (round-trip MF-010).
        let raw = vec![0xFFu8, 0x00, 0x48];
        let blob = mysql::Column::new(ColumnType::MYSQL_TYPE_BLOB).with_character_set(63);
        match mysql_cell_to_syn(mysql::Value::Bytes(raw.clone()), &blob) {
            SynValue::Bytes(b) => assert_eq!(&b[..], &raw[..]),
            o => panic!("esperaba bytes, got {:?}", o),
        }
        // TEXT (mismo column_type BLOB pero charset no-binario) → text.
        let text = mysql::Column::new(ColumnType::MYSQL_TYPE_BLOB).with_character_set(33);
        match mysql_cell_to_syn(mysql::Value::Bytes(b"hola".to_vec()), &text) {
            SynValue::Text(s) => assert_eq!(&*s, "hola"),
            o => panic!("esperaba text, got {:?}", o),
        }
        // REGRESIÓN (verificación viva): una columna TEXT con collation `_bin` (p.ej.
        // utf8mb3_bin = charset id 83, como `information_schema.tables.TABLE_NAME`) trae el
        // flag BINARY pero NO es binaria → debe leerse como text, no bytes.
        let utf8_bin = mysql::Column::new(ColumnType::MYSQL_TYPE_VAR_STRING)
            .with_character_set(83)
            .with_flags(mysql::consts::ColumnFlags::BINARY_FLAG);
        match mysql_cell_to_syn(mysql::Value::Bytes(b"syn_table".to_vec()), &utf8_bin) {
            SynValue::Text(s) => assert_eq!(&*s, "syn_table"),
            o => panic!("esperaba text (utf8_bin no es binario), got {:?}", o),
        }
    }

    #[test]
    fn mysql_read_json_to_map() {
        match mysql_cell_to_syn(
            mysql::Value::Bytes(br#"{"k":1}"#.to_vec()),
            &mycol(ColumnType::MYSQL_TYPE_JSON),
        ) {
            SynValue::Map(m) => assert_eq!(m.borrow().len(), 1),
            o => panic!("esperaba map, got {:?}", o),
        }
    }

    #[test]
    fn mysql_read_datetime_and_date_iso() {
        match mysql_cell_to_syn(
            mysql::Value::Date(2024, 1, 15, 9, 30, 0, 0),
            &mycol(ColumnType::MYSQL_TYPE_DATETIME),
        ) {
            SynValue::Text(s) => assert_eq!(&*s, "2024-01-15 09:30:00"),
            o => panic!("esperaba text, got {:?}", o),
        }
        match mysql_cell_to_syn(
            mysql::Value::Date(2024, 1, 15, 0, 0, 0, 0),
            &mycol(ColumnType::MYSQL_TYPE_DATE),
        ) {
            SynValue::Text(s) => assert_eq!(&*s, "2024-01-15"),
            o => panic!("esperaba text, got {:?}", o),
        }
    }

    #[test]
    fn text_or_bytes_strict_utf8() {
        match text_or_bytes(b"hola".to_vec()) {
            SynValue::Text(s) => assert_eq!(&*s, "hola"),
            o => panic!("esperaba text, got {:?}", o),
        }
        // utf8 inválido → bytes (no corrompe con lossy).
        match text_or_bytes(vec![255, 254, 0]) {
            SynValue::Bytes(b) => assert_eq!(&b[..], &[255, 254, 0]),
            o => panic!("esperaba bytes, got {:?}", o),
        }
    }

    #[test]
    fn split_tls_hint_opt_in_and_cleaning() {
        // Sin query → sin TLS, url intacto.
        assert_eq!(
            split_tls_hint("mysql://u:p@h:3306/db"),
            ("mysql://u:p@h:3306/db".to_string(), false)
        );
        // ssl-mode=REQUIRED → TLS on, param consumido (el driver lo rechazaría).
        assert_eq!(
            split_tls_hint("mysql://h/db?ssl-mode=REQUIRED"),
            ("mysql://h/db".to_string(), true)
        );
        // ssl-mode=DISABLED → TLS off.
        assert_eq!(
            split_tls_hint("mysql://h/db?ssl-mode=DISABLED"),
            ("mysql://h/db".to_string(), false)
        );
        // require_ssl=true mezclado con un param que el driver SÍ entiende → se preserva ese.
        assert_eq!(
            split_tls_hint("mysql://h/db?require_ssl=true&prefer_socket=false"),
            ("mysql://h/db?prefer_socket=false".to_string(), true)
        );
    }

    // -- MongoDB (M3): conversión SynValue ↔ BSON + _id, sin servidor --

    fn imap(pairs: Vec<(&str, SynValue)>) -> IndexMap<String, SynValue> {
        let mut m = IndexMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        m
    }

    const OID_HEX: &str = "507f1f77bcf86cd799439011";

    #[test]
    fn syn_to_bson_primitives() {
        assert!(matches!(syn_to_bson(&SynValue::Nothing), Bson::Null));
        assert!(matches!(syn_to_bson(&syn_bool(true)), Bson::Boolean(true)));
        // Int32 si entra; si no, Int64.
        assert!(matches!(syn_to_bson(&syn_int(42)), Bson::Int32(42)));
        assert!(matches!(syn_to_bson(&syn_int(5_000_000_000)), Bson::Int64(5_000_000_000)));
        assert!(matches!(syn_to_bson(&syn_float(3.5)), Bson::Double(_)));
        assert!(matches!(syn_to_bson(&syn_text("hi")), Bson::String(_)));
        // decimal → Decimal128 (texto exacto).
        let d = rust_decimal::Decimal::from_str_exact("9.99").unwrap();
        match syn_to_bson(&syn_number(Number::Decimal(d))) {
            Bson::Decimal128(dec) => assert_eq!(dec.to_string(), "9.99"),
            o => panic!("esperaba Decimal128, got {:?}", o),
        }
        // bytes → Binary (subtype Generic), byte-exacto.
        let raw = vec![0xFFu8, 0x00, 0x48];
        match syn_to_bson(&syn_bytes(raw.clone())) {
            Bson::Binary(b) => {
                assert_eq!(b.subtype, BinarySubtype::Generic);
                assert_eq!(b.bytes, raw);
            }
            o => panic!("esperaba Binary, got {:?}", o),
        }
    }

    #[test]
    fn bson_to_syn_primitives() {
        assert!(matches!(bson_to_syn(&Bson::Null), SynValue::Nothing));
        assert!(matches!(bson_to_syn(&Bson::Undefined), SynValue::Nothing));
        assert!(matches!(bson_to_syn(&Bson::Int32(7)), SynValue::Number(Number::Int(7))));
        assert!(matches!(bson_to_syn(&Bson::Int64(7)), SynValue::Number(Number::Int(7))));
        // ObjectId → text hex (24).
        let oid = ObjectId::parse_str(OID_HEX).unwrap();
        match bson_to_syn(&Bson::ObjectId(oid)) {
            SynValue::Text(s) => assert_eq!(&*s, OID_HEX),
            o => panic!("esperaba text hex, got {:?}", o),
        }
        // Decimal128 → decimal.
        let dec = Decimal128::from_str("9.99").unwrap();
        match bson_to_syn(&Bson::Decimal128(dec)) {
            SynValue::Number(n) => {
                assert!(n.is_decimal());
                assert_eq!(n.to_string(), "9.99");
            }
            o => panic!("esperaba decimal, got {:?}", o),
        }
        // Binary → bytes (byte-exacto, incl. no-UTF8).
        let raw = vec![0xFFu8, 0x00, 0x48];
        match bson_to_syn(&Bson::Binary(Binary { subtype: BinarySubtype::Generic, bytes: raw.clone() })) {
            SynValue::Bytes(b) => assert_eq!(&b[..], &raw[..]),
            o => panic!("esperaba bytes, got {:?}", o),
        }
    }

    #[test]
    fn bson_roundtrip_nested() {
        // map anidado con list, bytes, decimal, NULL → BSON → SynValue conserva estructura.
        let original = syn_map(imap(vec![
            ("name", syn_text("Ana")),
            ("age", syn_int(30)),
            ("tags", syn_list(vec![syn_text("a"), syn_text("b")])),
            ("meta", syn_map(imap(vec![("active", syn_bool(true)), ("note", SynValue::Nothing)]))),
            ("blob", syn_bytes(vec![1u8, 2, 255])),
        ]));
        let back = bson_to_syn(&syn_to_bson(&original));
        match back {
            SynValue::Map(m) => {
                let m = m.borrow();
                assert!(matches!(m.get("name"), Some(SynValue::Text(s)) if &**s == "Ana"));
                assert!(matches!(m.get("age"), Some(SynValue::Number(Number::Int(30)))));
                match m.get("tags") {
                    Some(SynValue::List(l)) => assert_eq!(l.borrow().len(), 2),
                    o => panic!("esperaba list, got {:?}", o),
                }
                match m.get("meta") {
                    Some(SynValue::Map(mm)) => {
                        assert!(matches!(mm.borrow().get("active"), Some(SynValue::Bool(true))));
                        assert!(matches!(mm.borrow().get("note"), Some(SynValue::Nothing)));
                    }
                    o => panic!("esperaba map anidado, got {:?}", o),
                }
                match m.get("blob") {
                    Some(SynValue::Bytes(b)) => assert_eq!(&b[..], &[1u8, 2, 255]),
                    o => panic!("esperaba bytes, got {:?}", o),
                }
            }
            o => panic!("esperaba map, got {:?}", o),
        }
    }

    #[test]
    fn coerce_id_hex_to_objectid() {
        // Bajo `_id`, un string hex-24 asciende a ObjectId; otra clave lo deja como String.
        let doc = syn_map_to_doc(&imap(vec![
            ("_id", syn_text(OID_HEX)),
            ("ref", syn_text(OID_HEX)),
            ("name", syn_text("Ana")),
        ]));
        match doc.get("_id") {
            Some(Bson::ObjectId(oid)) => assert_eq!(oid.to_hex(), OID_HEX),
            o => panic!("esperaba ObjectId en _id, got {:?}", o),
        }
        assert!(matches!(doc.get("ref"), Some(Bson::String(s)) if s == OID_HEX));
        // Un string que NO es un ObjectId válido bajo _id queda como String.
        let doc2 = syn_map_to_doc(&imap(vec![("_id", syn_text("not-an-oid"))]));
        assert!(matches!(doc2.get("_id"), Some(Bson::String(_))));
    }

    #[test]
    fn coerce_id_inside_in_operator() {
        // `{"_id": {"$in": ["hex1", "hex2"]}}` → cada hex anidado se vuelve ObjectId.
        let filter = syn_map_to_doc(&imap(vec![(
            "_id",
            syn_map(imap(vec![("$in", syn_list(vec![syn_text(OID_HEX), syn_text(OID_HEX)]))])),
        )]));
        match filter.get("_id") {
            Some(Bson::Document(inner)) => match inner.get("$in") {
                Some(Bson::Array(arr)) => {
                    assert_eq!(arr.len(), 2);
                    assert!(matches!(arr[0], Bson::ObjectId(_)));
                    assert!(matches!(arr[1], Bson::ObjectId(_)));
                }
                o => panic!("esperaba array en $in, got {:?}", o),
            },
            o => panic!("esperaba document en _id, got {:?}", o),
        }
    }

    // -- Redis (M4): mapeo de valores + scope, sin servidor --

    #[test]
    fn syn_to_redis_arg_mapping() {
        // text/bytes/number (incl. decimal) → bytes que se mandan.
        assert_eq!(syn_to_redis_arg(&syn_text("hola")).unwrap(), b"hola".to_vec());
        let raw = vec![0xFFu8, 0x00, 0x48];
        assert_eq!(syn_to_redis_arg(&syn_bytes(raw.clone())).unwrap(), raw);
        assert_eq!(syn_to_redis_arg(&syn_int(42)).unwrap(), b"42".to_vec());
        let d = rust_decimal::Decimal::from_str_exact("9.99").unwrap();
        assert_eq!(syn_to_redis_arg(&syn_number(Number::Decimal(d))).unwrap(), b"9.99".to_vec());
        // bool/map/list/nothing → error claro (orienta a json_encode).
        assert!(syn_to_redis_arg(&syn_bool(true)).is_err());
        assert!(syn_to_redis_arg(&SynValue::Nothing).is_err());
        assert!(syn_to_redis_arg(&syn_list(vec![syn_int(1)])).is_err());
        assert!(syn_to_redis_arg(&syn_map(imap(vec![("a", syn_int(1))]))).is_err());
        let e = syn_to_redis_arg(&syn_bool(true)).unwrap_err();
        assert!(e.contains("json_encode"), "el error debe orientar a json_encode: {}", e);
    }

    #[test]
    fn redis_value_to_syn_mapping() {
        use redis::Value as RV;
        assert!(matches!(redis_value_to_syn(&RV::Nil), SynValue::Nothing));
        assert!(matches!(redis_value_to_syn(&RV::Int(7)), SynValue::Number(Number::Int(7))));
        // BulkString UTF-8 → text.
        match redis_value_to_syn(&RV::BulkString(b"hola".to_vec())) {
            SynValue::Text(s) => assert_eq!(&*s, "hola"),
            o => panic!("esperaba text, got {:?}", o),
        }
        // BulkString no-UTF8 → bytes byte-exacto (heurística binario-segura).
        let raw = vec![0xFFu8, 0x00, 0x48];
        match redis_value_to_syn(&RV::BulkString(raw.clone())) {
            SynValue::Bytes(b) => assert_eq!(&b[..], &raw[..]),
            o => panic!("esperaba bytes, got {:?}", o),
        }
        // SimpleString / Okay → text.
        match redis_value_to_syn(&RV::SimpleString("string".to_string())) {
            SynValue::Text(s) => assert_eq!(&*s, "string"),
            o => panic!("esperaba text, got {:?}", o),
        }
        match redis_value_to_syn(&RV::Okay) {
            SynValue::Text(s) => assert_eq!(&*s, "OK"),
            o => panic!("esperaba text OK, got {:?}", o),
        }
        // Array → list (recursivo).
        match redis_value_to_syn(&RV::Array(vec![RV::Int(1), RV::BulkString(b"x".to_vec())])) {
            SynValue::List(l) => assert_eq!(l.borrow().len(), 2),
            o => panic!("esperaba list, got {:?}", o),
        }
        // Map (RESP3) → map (recursivo).
        match redis_value_to_syn(&RV::Map(vec![(
            RV::BulkString(b"f".to_vec()),
            RV::BulkString(b"v".to_vec()),
        )])) {
            SynValue::Map(m) => {
                assert!(matches!(m.borrow().get("f"), Some(SynValue::Text(s)) if &**s == "v"));
            }
            o => panic!("esperaba map, got {:?}", o),
        }
    }

    #[test]
    fn redis_value_to_map_resp2_and_resp3() {
        use redis::Value as RV;
        // RESP2 (default): array plano de pares → map (se agrupa de a dos).
        let flat = RV::Array(vec![
            RV::BulkString(b"a".to_vec()),
            RV::BulkString(b"1".to_vec()),
            RV::BulkString(b"b".to_vec()),
            RV::BulkString(b"2".to_vec()),
        ]);
        let m = redis_value_to_map(flat);
        assert_eq!(m.len(), 2);
        assert!(matches!(m.get("a"), Some(SynValue::Text(s)) if &**s == "1"));
        assert!(matches!(m.get("b"), Some(SynValue::Text(s)) if &**s == "2"));
        // RESP3: Map directo.
        let m3 = redis_value_to_map(RV::Map(vec![(RV::BulkString(b"k".to_vec()), RV::Int(9))]));
        assert!(matches!(m3.get("k"), Some(SynValue::Number(Number::Int(9)))));
        // clave ausente → array vacío → map vacío.
        assert!(redis_value_to_map(RV::Array(vec![])).is_empty());
    }

    #[test]
    fn redis_shape_bool_mapping() {
        assert!(matches!(redis_shape_bool(redis::Value::Int(1)), SynValue::Bool(true)));
        assert!(matches!(redis_shape_bool(redis::Value::Int(0)), SynValue::Bool(false)));
        assert!(matches!(redis_shape_bool(redis::Value::Nil), SynValue::Bool(false)));
    }

    #[test]
    fn is_redis_url_detects() {
        assert!(is_redis_url("redis://localhost:6379"));
        assert!(is_redis_url("rediss://h/0"));
        assert!(!is_redis_url("postgres://h/db"));
        assert!(!is_redis_url("mongodb://h/db"));
        assert!(!is_redis_url("./store.db"));
    }

    #[test]
    fn canon_url_redis_scope() {
        // credenciales/puerto fuera; db-index preservado.
        assert_eq!(canon_url("redis://u:p@Host:6379/2"), "redis://host/2");
        // gotcha del db-index: sin /N el scope NO trae db; /0 sí → son scopes distintos.
        assert_eq!(canon_url("redis://localhost:6379"), "redis://localhost");
        assert_eq!(canon_url("redis://localhost:6379/0"), "redis://localhost/0");
    }

    #[test]
    fn redis_gen_token_is_unique_hex() {
        let a = redis_gen_token();
        let b = redis_gen_token();
        assert_eq!(a.len(), 32, "16 bytes → 32 chars hex");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "cada adquisición debe dar un token distinto");
    }
}

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

use synsema_core::synlist::{list_values};
use synsema_core::types::{Key, MapObj, SynMap};
use std::cell::RefCell;
use std::error::Error as StdError;
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

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

use crate::json::json_to_syn;

/// Handle al `DatabaseManager` abstrayendo el modo de acceso: `Rc<RefCell>` para
/// runs single-thread (conform), `Arc<Mutex>` para `serve` (db compartida entre
/// los hilos de conexión). Los builtins se registran genéricos sobre esto.
pub trait DbHandle: Clone + 'static {
    fn read<R>(&self, f: impl FnOnce(&DatabaseManager) -> R) -> R;
    fn write<R>(&self, f: impl FnOnce(&mut DatabaseManager) -> R) -> R;
    /// v0.6.59 — como `write`, para quien va a usar la conexión default y NO está en la transacción
    /// que la tiene (`sql_transaction`): si está prestada, espera a que vuelva, hasta `TX_WAIT`.
    fn write_unlent<R>(&self, f: impl FnOnce(&mut DatabaseManager) -> R) -> Result<R, String>;
}

impl DbHandle for Rc<RefCell<DatabaseManager>> {
    fn read<R>(&self, f: impl FnOnce(&DatabaseManager) -> R) -> R {
        f(&self.borrow())
    }
    fn write<R>(&self, f: impl FnOnce(&mut DatabaseManager) -> R) -> R {
        f(&mut self.borrow_mut())
    }
    fn write_unlent<R>(&self, f: impl FnOnce(&mut DatabaseManager) -> R) -> Result<R, String> {
        // Un solo intérprete usa este gestor, y sus `sql*` van por la transacción mientras hay una:
        // acá no hay a quién esperar.
        let mut m = self.borrow_mut();
        if m.lent.is_some() {
            return Err(lent_busy(false));
        }
        Ok(f(&mut m))
    }
}

impl DbHandle for Arc<Mutex<DatabaseManager>> {
    fn read<R>(&self, f: impl FnOnce(&DatabaseManager) -> R) -> R {
        f(&lock_shared_db(self))
    }
    fn write<R>(&self, f: impl FnOnce(&mut DatabaseManager) -> R) -> R {
        f(&mut lock_shared_db(self))
    }
    fn write_unlent<R>(&self, f: impl FnOnce(&mut DatabaseManager) -> R) -> Result<R, String> {
        let mut m = lock_shared_db(self);
        if m.lent.is_some() {
            // Esperar a otra task es una espera: el hilo suelta su permiso de CPU.
            let _w = synsema_core::waiting::waiting();
            let returned = m.returned.clone();
            let deadline = Instant::now() + TX_WAIT;
            while m.lent.is_some() {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(lent_busy(true));
                }
                m = returned.wait_timeout(m, left).unwrap().0;
            }
        }
        Ok(f(&mut m))
    }
}

/// v0.6.59 — cuánto espera un `sql*` a que termine la transacción de otra task. Es la espera que
/// `rusqlite` le pone a SQLite entre procesos (`busy_timeout`, 5 s). Sin tope, una transacción que
/// espera a otra task (un agente) que espera la conexión no terminaría nunca.
const TX_WAIT: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 5 });

#[cold]
#[inline(never)]
fn lent_busy(waited: bool) -> String {
    let how = if waited {
        format!("has been inside another task's transaction (sql_transaction) for more than {} s", TX_WAIT.as_secs())
    } else {
        "is inside a transaction (sql_transaction)".to_string()
    };
    format!(
        "the database {}: a transaction holds the connection until its task ends, so keep slow calls (sleep, http, an LLM) out of it, and do not wait inside it for another task that uses this database",
        how
    )
}

/// v0.6.42 (auditoría ronda 2) — el lock de la base compartida de `serve`. Si está tomado (otro
/// hilo tiene la conexión mientras espera a la red), esperarlo es una espera: el hilo suelta su
/// permiso de CPU. Si no, los hilos en fila por la conexión retenían los permisos y una ruta que
/// ni toca la base esperaba detrás del N+1 de las demás. Libre, no cuesta nada.
fn lock_shared_db(m: &Mutex<DatabaseManager>) -> std::sync::MutexGuard<'_, DatabaseManager> {
    match m.try_lock() {
        Ok(g) => g,
        Err(std::sync::TryLockError::WouldBlock) => {
            let _w = synsema_core::waiting::waiting();
            m.lock().unwrap()
        }
        Err(std::sync::TryLockError::Poisoned(_)) => m.lock().unwrap(),
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
pub type Row = SynMap;

/// Motor concreto de una conexión.
enum Backend {
    Sqlite(Connection),
    Postgres(Client),
    Mysql(MysqlConn),
    /// MongoDB (no-SQL). Ya scoped al db del connstring; la API propia es `mongo_*`.
    Mongo(mongodb::sync::Database),
    /// Redis (M4, KV/cache/estructuras). Conexión sync ya scoped al db-index del connstring;
    /// la API propia es `redis_*` (no SQL ni `mongo_*`).
    Redis(redis::Connection),
}

/// Una conexión MySQL, y lo que el servidor informa de ella en sus respuestas (el seguimiento de
/// estado de sesión, que se pide en `mysql_connect`): el estado de la transacción y `autocommit`.
/// El servidor los manda cuando cambian, así que se anotan después de CADA statement
/// (`observe`): lo anotado es siempre lo último que dijo.
struct MysqlConn {
    conn: mysql::Conn,
    /// `false`: el servidor (o un proxy en el medio) no lo informa, el programa cambió una de
    /// las variables del seguimiento (`Backend::mysql_after_unread_set`), o llegó algo que no se
    /// entiende. Entonces el estado se pregunta (`Backend::mysql_left_by_call`) y los dos
    /// campos de abajo no valen.
    tracked: bool,
    /// El estado de la transacción (`mysql_tx_left`).
    tx_state: String,
    /// `autocommit` está en 1.
    autocommit: bool,
}

impl MysqlConn {
    /// Anota lo que informó la última respuesta. Un ERR no informa nada: lo que cambió durante
    /// un statement que falla llega con el OK siguiente.
    fn observe(&mut self) {
        if !self.tracked {
            return;
        }
        match mysql_tracked(&self.conn) {
            Ok((state, autocommit)) => {
                if let Some(state) = state {
                    self.tx_state = state;
                }
                if let Some(autocommit) = autocommit {
                    self.autocommit = autocommit;
                }
            }
            Err(_) => self.tracked = false,
        }
    }

    /// Un statement por el protocolo de texto, sin leer sus filas (`mysql_finish`).
    fn text(&mut self, sql: &str) -> Result<(), mysql::Error> {
        let r = self.conn.query_iter(sql).and_then(|mut result| mysql_finish(&mut result));
        self.observe();
        r
    }

    /// Un statement por el protocolo preparado, sin leer sus filas (`mysql_finish`).
    fn prepared<S: mysql::prelude::AsStatement>(&mut self, stmt: S, params: mysql::Params) -> Result<(), mysql::Error> {
        let r = self.conn.exec_iter(stmt, params).and_then(|mut result| mysql_finish(&mut result));
        self.observe();
        r
    }
}

impl std::ops::Deref for MysqlConn {
    type Target = mysql::Conn;
    fn deref(&self) -> &mysql::Conn {
        &self.conn
    }
}

impl std::ops::DerefMut for MysqlConn {
    fn deref_mut(&mut self) -> &mut mysql::Conn {
        &mut self.conn
    }
}

pub struct DatabaseManager {
    connections: IndexMap<String, Backend>,
    default_db: Option<String>,
    /// v0.6.59 — la conexión default mientras la tiene una transacción (`sql_transaction`): no está
    /// en `connections`, sino en el intérprete que la abrió.
    lent: Option<Lent>,
    /// Avisa a los que esperan en `write_unlent` cuando la transacción devuelve la conexión.
    returned: Arc<Condvar>,
}

/// Lo que el gestor recuerda de la conexión prestada a una transacción.
struct Lent {
    key: String,
    /// Su lugar en `connections`, para devolverla ahí (el orden decide la default al cerrar otra).
    index: usize,
    dialect: SqlDialect,
    /// `db_close` de esta base mientras estaba prestada: al volver se cierra.
    close_on_return: bool,
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
            lent: None,
            returned: Arc::new(Condvar::new()),
        }
    }

    /// `db_open` de una base ya abierta: está en `connections` o la tiene una transacción. En el
    /// segundo caso deshace un `db_close` que llegó durante la transacción (si no, la base se
    /// cerraba al terminar aunque lo último que pidió el programa fue abrirla) y, si no quedó
    /// ninguna default (`close_all`), vuelve a serlo.
    fn already_open(&mut self, key: &str) -> bool {
        if self.connections.contains_key(key) {
            return true;
        }
        let Some(l) = self.lent.as_mut().filter(|l| l.key == key) else { return false };
        l.close_on_return = false;
        if self.default_db.is_none() {
            self.default_db = Some(key.to_string());
        }
        true
    }

    /// v0.6.59 — saca la conexión default para una transacción. Sólo una a la vez: el que llama
    /// pasó por `write_unlent`.
    fn lend(&mut self) -> Result<Backend, String> {
        if self.lent.is_some() {
            return Err(lent_busy(false));
        }
        let no_connection = || "No database connection. Use db_open(\"path.db\") first.".to_string();
        let key = self.default_db.clone().ok_or_else(no_connection)?;
        let dialect = match self.connections.get(&key).ok_or_else(no_connection)? {
            Backend::Mongo(_) => return Err(mongo_not_sql()),
            Backend::Redis(_) => return Err(redis_not_sql()),
            b => b.dialect().ok_or_else(no_connection)?,
        };
        let (index, key, backend) = self.connections.shift_remove_full(&key).ok_or_else(no_connection)?;
        self.lent = Some(Lent { key, index, dialect, close_on_return: false });
        Ok(backend)
    }

    /// v0.6.59 — la transacción terminó. `None`: la conexión no quedó limpia y se cerró; la base
    /// sigue siendo la default, sin conexión, y el próximo `sql*` pide `db_open` (no se pasa en
    /// silencio a otra base).
    fn give_back(&mut self, backend: Option<Backend>) {
        if let Some(l) = self.lent.take() {
            match backend {
                Some(b) if !l.close_on_return => {
                    let at = l.index.min(self.connections.len());
                    self.connections.shift_insert(at, l.key, b);
                }
                Some(_) => {
                    // Un `db_close` que llegó durante la transacción: como `close`.
                    if self.default_db.as_deref() == Some(l.key.as_str()) {
                        self.default_db = self.connections.keys().next().cloned();
                    }
                }
                None => {}
            }
        }
        self.returned.notify_all();
    }

    /// Abre una conexión. Rutea por scheme: `postgres://`/`postgresql://` → Postgres;
    /// `mysql://` → MySQL; `mongodb://`/`mongodb+srv://` → MongoDB; cualquier otra cosa →
    /// SQLite (camino actual, sin cambios). Devuelve la key usada como identificador
    /// (canon_url para los remotos; ruta/`:memory:` para SQLite).
    pub fn open(&mut self, target: &str, mode: &str) -> Result<String, String> {
        // Ronda 4 (revisión, B6): la URL de un servidor llega al driver con el esquema en minúscula y
        // sin espacios adelante — lo mismo que ve el gate (`is_db_url`/`canon_url`); si no,
        // `"POSTGRES://…"` pasaba el gate como URL y el driver lo leía como `clave=valor`.
        let normalized = normalize_db_url(target);
        let target = normalized.as_str();
        if is_mongo_url(target) {
            let key = canon_url(target);
            if self.already_open(&key) {
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
            if self.already_open(&key) {
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
            if self.already_open(&key) {
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
            if self.already_open(&key) {
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
            if self.already_open(&key) {
                return Ok(key);
            }
            // v0.6.45 — se abre la ruta NORMALIZADA, la misma que chequeó `require db(...)` (antes se
            // abría la cruda y en Unix `link/..` llevaba a otro lado).
            let path = synsema_core::capscope::normalize_path(target);
            // Ronda 2 (A4) y ronda 3 (A1, A2): una URI `file:` de SQLite (`file:%2Fetc%2Fx.db`) o una
            // ruta con `://` nombran otro lugar que el que ve el scope. Se mira la ruta que SE ABRE
            // (`./file:…` y `x/../file:…` normalizan a `file:…`), y además una ruta relativa se abre
            // como `./<ruta>`: SQLite sólo toma como URI lo que empieza literalmente con `file:`.
            if path.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("file:")) || path.contains("://") {
                return Err(format!(
                    "db_open: {:?} is not a database path (a `file:` URI or a `://` URL that is not a known server); open the database by its path, e.g. db_open(\"./data/app.db\")",
                    target
                ));
            }
            let rooted = path.starts_with('/') || matches!(path.as_bytes(), [c, b':', ..] if c.is_ascii_alphabetic());
            let path = if rooted || path == ":memory:" { path } else { format!("./{}", path) };
            let mut conn = match mode {
                "readonly" => Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY),
                "memory" => Connection::open_in_memory(),
                _ => Connection::open(&path),
            }
            .map_err(sqlite_err)?;
            // Ronda 3 (B3): modo defensivo — sin `writable_schema`, `journal_mode=OFF` ni escrituras
            // a mano en el esquema o en las tablas internas de FTS5, que con un esquema armado le
            // hacían llegar texto no UTF-8 al authorizer. El esquema NO se marca como no confiable
            // (ronda 4, M1): eso rompía `MATCH`/`bm25()`/`snippet()` dentro de vistas y triggers de
            // una base existente, y no protege nada acá (Synsema no registra funciones SQL propias
            // ni habilita `load_extension`).
            conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
                .map_err(sqlite_err)?;
            // v0.6.45 — `ATTACH DATABASE '<ruta>'` y `VACUUM INTO '<ruta>'` (que por dentro hace un
            // ATTACH) abrían o creaban cualquier archivo sin pasar por `require db(...)`; con una
            // inyección SQL, la ruta la elegía un atacante. Se rechaza el ATTACH a un archivo; el de
            // una base temporal (`''`, lo que usa un VACUUM normal) o `:memory:` sigue. Otra base se
            // abre con `db_open`, que pasa por el gate.
            // Ronda 2 (A3): con el nombre como EXPRESIÓN (`ATTACH ? AS x`, `ATTACH 'a'||'.db'`),
            // SQLite le pasa NULL al authorizer y rusqlite lo da como `Unknown { SQLITE_ATTACH }`:
            // también se rechaza. Y los pragmas que cambian, para todo el proceso, dónde caen las
            // rutas relativas y los temporales de SQLite (B5).
            conn.authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| {
                use rusqlite::hooks::{AuthAction, Authorization};
                match ctx.action {
                    AuthAction::Attach { filename } if filename.is_empty() || filename == ":memory:" => Authorization::Allow,
                    AuthAction::Attach { .. } => Authorization::Deny,
                    AuthAction::Unknown { code, .. } if code == rusqlite::ffi::SQLITE_ATTACH => Authorization::Deny,
                    AuthAction::Pragma { pragma_name, .. }
                        if pragma_name.eq_ignore_ascii_case("data_store_directory")
                            || pragma_name.eq_ignore_ascii_case("temp_store_directory") =>
                    {
                        Authorization::Deny
                    }
                    _ => Authorization::Allow,
                }
            }))
            // rusqlite 0.41: instalarlo puede fallar; sin él no hay cierre de ATTACH, así que no se abre.
            .map_err(sqlite_err)?;
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
            // v0.6.59: la tiene una transacción; se cierra cuando termina.
            if let Some(l) = self.lent.as_mut().filter(|l| l.key == t) {
                l.close_on_return = true;
                return;
            }
            if self.connections.shift_remove(&t).is_some() && self.default_db.as_deref() == Some(&t) {
                self.default_db = self.connections.keys().next().cloned();
            }
        }
    }

    pub fn close_all(&mut self) {
        self.connections.clear();
        self.default_db = None;
        if let Some(l) = self.lent.as_mut() {
            l.close_on_return = true;
        }
    }

    fn conn_mut(&mut self, db: Option<&str>) -> Result<&mut Backend, String> {
        let target = db.map(|s| s.to_string()).or_else(|| self.default_db.clone());
        if let (Some(t), Some(l)) = (&target, &self.lent) {
            if *t == l.key {
                return Err(lent_busy(false));
            }
        }
        target
            .and_then(move |t| self.connections.get_mut(&t))
            .ok_or_else(|| "No database connection. Use db_open(\"path.db\") first.".to_string())
    }

    /// Corre `f` sobre la conexión default, fuera de una transacción. Si el statement la dejó en
    /// un estado del que el motor no la pudo sacar (`SqlConn::broken`), se cierra: la base sigue
    /// siendo la default, sin conexión, y el próximo `sql*` pide `db_open` (como en `give_back`).
    fn with_default<R>(&mut self, f: impl FnOnce(&mut SqlConn<'_>) -> Result<R, String>) -> Result<R, String> {
        let mut conn = SqlConn { backend: self.conn_mut(None)?, failed: None, called: None, broken: false };
        let r = f(&mut conn);
        if conn.broken {
            if let Some(key) = self.default_db.clone() {
                self.connections.shift_remove(&key);
            }
        }
        r
    }

    /// Ejecuta un SELECT, devuelve filas como mapas columna→valor (ya en `SynValue`).
    pub fn query(&mut self, sql: &str, params: &[SynValue]) -> Result<Vec<Row>, String> {
        self.with_default(|c| c.query(sql, params))
    }

    /// Ejecuta INSERT/UPDATE/DELETE/CREATE. Devuelve (rows_affected, last_id).
    /// Postgres no tiene `last_insert_rowid` → `last_id = 0` (usar `INSERT … RETURNING id`).
    /// MySQL sí: `last_id = last_insert_id()` (a diferencia de PG).
    pub fn execute(&mut self, sql: &str, params: &[SynValue]) -> Result<(i64, i64), String> {
        self.with_default(|c| c.execute(sql, params))
    }

    /// Ejecuta una sentencia con múltiples sets de parámetros (batch).
    pub fn execute_many(&mut self, sql: &str, params_list: &[Vec<SynValue>]) -> Result<i64, String> {
        self.with_default(|c| c.execute_many(sql, params_list))
    }

    /// El dialecto SQL de la conexión default (`None` sin conexión o si no es SQL).
    fn default_dialect(&self) -> Option<SqlDialect> {
        let key = self.default_db.as_ref()?;
        if let Some(l) = self.lent.as_ref().filter(|l| l.key == *key) {
            return Some(l.dialect);
        }
        self.connections.get(key)?.dialect()
    }

    /// Key de la conexión default (para el scope de la capability `db` en las ops de
    /// datos). `None` si no hay ninguna conexión abierta.
    pub fn default_path(&self) -> Option<String> {
        self.default_db.clone()
    }

    pub fn tables(&mut self) -> Result<Vec<String>, String> {
        self.with_default(|c| c.tables())
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
        // v0.6.42 — bajo `serve`, el hilo que espera la base suelta su permiso de ejecución.
        let _w = synsema_core::waiting::waiting();
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
        // v0.6.42 — bajo `serve`, el hilo que espera la base suelta su permiso de ejecución.
        let _w = synsema_core::waiting::waiting();
        let c = self.mongo_coll(coll)?;
        match c.find_one(filter).run().map_err(mongo_err)? {
            Some(doc) => Ok(bson_to_syn(&Bson::Document(doc))),
            None => Ok(SynValue::Nothing),
        }
    }

    /// `mongo_insert`: inserta un documento, devuelve el `_id` (text hex si es ObjectId).
    pub fn mongo_insert(&mut self, coll: &str, doc: Document) -> Result<SynValue, String> {
        // v0.6.42 — bajo `serve`, el hilo que espera la base suelta su permiso de ejecución.
        let _w = synsema_core::waiting::waiting();
        let c = self.mongo_coll(coll)?;
        let res = c.insert_one(doc).run().map_err(mongo_err)?;
        Ok(bson_to_syn(&res.inserted_id))
    }

    /// `mongo_insert_many`: inserta varios, devuelve la lista de `_id` en orden de inserción.
    pub fn mongo_insert_many(&mut self, coll: &str, docs: Vec<Document>) -> Result<Vec<SynValue>, String> {
        // v0.6.42 — bajo `serve`, el hilo que espera la base suelta su permiso de ejecución.
        let _w = synsema_core::waiting::waiting();
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
        // v0.6.42 — bajo `serve`, el hilo que espera la base suelta su permiso de ejecución.
        let _w = synsema_core::waiting::waiting();
        let c = self.mongo_coll(coll)?;
        let res = c.update_many(filter, update).run().map_err(mongo_err)?;
        Ok((res.matched_count as i64, res.modified_count as i64))
    }

    /// `mongo_delete` (delete_many): devuelve cuántos borró.
    pub fn mongo_delete(&mut self, coll: &str, filter: Document) -> Result<i64, String> {
        // v0.6.42 — bajo `serve`, el hilo que espera la base suelta su permiso de ejecución.
        let _w = synsema_core::waiting::waiting();
        let c = self.mongo_coll(coll)?;
        let res = c.delete_many(filter).run().map_err(mongo_err)?;
        Ok(res.deleted_count as i64)
    }

    /// `mongo_count`: documentos que matchean `filter`.
    pub fn mongo_count(&mut self, coll: &str, filter: Document) -> Result<i64, String> {
        // v0.6.42 — bajo `serve`, el hilo que espera la base suelta su permiso de ejecución.
        let _w = synsema_core::waiting::waiting();
        let c = self.mongo_coll(coll)?;
        Ok(c.count_documents(filter).run().map_err(mongo_err)? as i64)
    }

    /// `mongo_aggregate`: pipeline de agregación (lista de stages-documento) → lista de maps.
    pub fn mongo_aggregate(&mut self, coll: &str, pipeline: Vec<Document>) -> Result<Vec<SynValue>, String> {
        // v0.6.42 — bajo `serve`, el hilo que espera la base suelta su permiso de ejecución.
        let _w = synsema_core::waiting::waiting();
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
        // v0.6.42 — bajo `serve`, el hilo que espera la base suelta su permiso de ejecución.
        let _w = synsema_core::waiting::waiting();
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
        // v0.6.42 — bajo `serve`, el hilo que espera la base suelta su permiso de ejecución.
        let _w = synsema_core::waiting::waiting();
        let conn = self.redis_conn()?;
        let mut cmd = redis::Cmd::new();
        for p in parts {
            cmd.arg(p.as_slice());
        }
        cmd.query::<redis::Value>(conn).map_err(redis_err)
    }
}

// -- Las operaciones SQL de una conexión (v0.6.59: las usan el gestor y una transacción) --

impl Backend {
    /// El dialecto SQL (`None` si no es SQL).
    fn dialect(&self) -> Option<SqlDialect> {
        match self {
            Backend::Sqlite(_) => Some(SqlDialect::Sqlite),
            Backend::Postgres(_) => Some(SqlDialect::Postgres),
            Backend::Mysql(_) => Some(SqlDialect::Mysql),
            Backend::Mongo(_) | Backend::Redis(_) => None,
        }
    }

    fn query(&mut self, sql: &str, params: &[SynValue]) -> Result<Vec<Row>, String> {
        reject_sealed_all(params, "sql")?;
        match self {
            Backend::Sqlite(c) => sqlite_query(c, sql, params),
            Backend::Postgres(c) => pg_query(c, sql, params),
            Backend::Mysql(c) => mysql_query(c, sql, params),
            Backend::Mongo(_) => Err(mongo_not_sql()),
            Backend::Redis(_) => Err(redis_not_sql()),
        }
    }

    fn execute(&mut self, sql: &str, params: &[SynValue]) -> Result<(i64, i64), String> {
        reject_sealed_all(params, "sql")?;
        match self {
            Backend::Sqlite(c) => {
                let pv: Vec<Value> = params.iter().map(syn_to_value).collect();
                let affected = c
                    .execute(sql, params_from_iter(pv.iter()))
                    .map_err(sqlite_err)?;
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
            // Con params, por el protocolo preparado (binario); sin params, `mysql_execute_one`
            // elige: el de texto sólo para lo que es un statement solo. `execute` no lee valores
            // tipados (sólo counts) → el protocolo no afecta el mapeo de tipos.
            Backend::Mysql(c) => {
                if params.is_empty() {
                    mysql_execute_one(c, sql)?;
                } else {
                    c.prepared(sql, mysql_params(params)).map_err(mysql_err)?;
                }
                Ok((c.affected_rows() as i64, c.last_insert_id() as i64))
            }
            Backend::Mongo(_) => Err(mongo_not_sql()),
            Backend::Redis(_) => Err(redis_not_sql()),
        }
    }

    fn execute_many(&mut self, sql: &str, params_list: &[Vec<SynValue>]) -> Result<i64, String> {
        params_list.iter().try_for_each(|p| reject_sealed_all(p, "sql"))?;
        match self {
            Backend::Sqlite(c) => {
                let mut stmt = c.prepare(sql).map_err(sqlite_err)?;
                let mut total: i64 = 0;
                for params in params_list {
                    let pv: Vec<Value> = params.iter().map(syn_to_value).collect();
                    total += stmt
                        .execute(params_from_iter(pv.iter()))
                        .map_err(sqlite_err)? as i64;
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
                    c.prepared(&stmt, mysql_params(params)).map_err(mysql_err)?;
                    total += c.affected_rows() as i64;
                }
                Ok(total)
            }
            Backend::Mongo(_) => Err(mongo_not_sql()),
            Backend::Redis(_) => Err(redis_not_sql()),
        }
    }

    /// La consulta que lista las tablas y la columna que trae el nombre.
    fn tables_query(&self) -> Result<(&'static str, &'static str), String> {
        Ok(match self {
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
        })
    }

    /// Un statement de control que arma el motor (`COMMIT`, `SAVEPOINT …`): sin parámetros y sin
    /// pasar por `guard`. Postgres y MySQL, por el protocolo de texto (el de statements preparados
    /// de MySQL rechaza el control de transacciones, ERROR 1295).
    fn control(&mut self, sql: &str) -> Result<(), String> {
        match self {
            Backend::Sqlite(c) => c.execute_batch(sql).map_err(sqlite_err),
            Backend::Postgres(c) => c.batch_execute(sql).map_err(pg_err),
            Backend::Mysql(c) => c.text(sql).map_err(mysql_err),
            Backend::Mongo(_) => Err(mongo_not_sql()),
            Backend::Redis(_) => Err(redis_not_sql()),
        }
    }

    /// Abre una transacción. SQLite con `BEGIN IMMEDIATE`: el conflicto con otro proceso aparece
    /// acá, con la espera de `busy_timeout`, y no en el primer `INSERT`, donde SQLite ya no puede
    /// reintentar. Una base abierta de sólo lectura también lo acepta (medido, en modo DELETE y WAL).
    fn begin(&mut self) -> Result<(), String> {
        let sql = match self {
            Backend::Sqlite(_) => "BEGIN IMMEDIATE",
            Backend::Mysql(_) => "START TRANSACTION",
            _ => "BEGIN",
        };
        self.control(sql)
    }

    /// `COMMIT`. En MySQL, con `AND NO CHAIN NO RELEASE`: la variable de sesión `completion_type`
    /// hace que un `COMMIT` a secas abra otra transacción (`CHAIN`) o corte la conexión
    /// (`RELEASE`); dicho así, no depende de ella (medido en 8.0.46).
    fn commit(&mut self) -> Result<(), String> {
        let sql = match self {
            Backend::Mysql(_) => "COMMIT AND NO CHAIN NO RELEASE",
            _ => "COMMIT",
        };
        self.control(sql)
    }

    /// `ROLLBACK`. `true` si la conexión quedó fuera de una transacción. SQLite lo dice
    /// (`is_autocommit`): un error grave ya la deshizo, y entonces el `ROLLBACK` falla sin que
    /// haya nada abierto. En Postgres y MySQL, un `ROLLBACK` que falla es una conexión de la que
    /// no se sabe nada.
    fn rollback(&mut self) -> bool {
        let sql = match self {
            Backend::Mysql(_) => "ROLLBACK AND NO CHAIN NO RELEASE",
            _ => "ROLLBACK",
        };
        let r = self.control(sql);
        match self {
            Backend::Sqlite(c) => c.is_autocommit(),
            _ => r.is_ok(),
        }
    }

    /// Un statement que dejó una transacción abierta fuera de `sql_transaction`. La deshace.
    /// `Stray::left`: `Ok(true)` si había una; `Err` si no se pudo mirar (y entonces se deshace
    /// igual, por las dudas). (`guard` rechaza el control a mano por su primera palabra; esto mira el estado
    /// real de la conexión.)
    /// - SQLite lo dice (`is_autocommit`), después de cada statement.
    /// - MySQL, después de un statement `opaque` (un `CALL`; `ok`: si corrió sin error):
    ///   `mysql_left_by_call`. Deja `autocommit` en 1, que es como lo necesita el motor, y sin
    ///   decir nada: el programa no lo puede cambiar (`tx_guard`), así que sólo lo apaga un
    ///   procedimiento. Va después del `ROLLBACK`: con una transacción en curso,
    ///   `SET autocommit = 1` la confirma. Por eso mismo, una transacción en la que no hay nada
    ///   que deshacer (`TxLeft::NothingToUndo`) no lleva `ROLLBACK`: la cierra ese `SET`, y no es
    ///   un error.
    ///
    /// `Stray::clean`: la conexión quedó fuera de una transacción. Si el `ROLLBACK` falla no lo
    /// está (medido en 8.0.46: un procedimiento que deja una transacción XA activa; el `ROLLBACK`
    /// da ERROR 1399 y la conexión sigue adentro), y entonces no se puede seguir usando: lo que
    /// se escribiera después quedaría en esa transacción, que nadie confirma.
    ///
    /// MySQL, después de un statement que NO es un `CALL`: `mysql_left_by_statement`. `read` es lo
    /// que leyó `mysql_after_unread_set` (`Some(true)` si no hizo falta leer).
    fn close_stray_transaction(&mut self, opaque: bool, ok: bool, read: Option<bool>) -> Stray {
        match self {
            Backend::Sqlite(c) if !c.is_autocommit() => {
                let _ = c.execute_batch("ROLLBACK");
                Stray { left: Ok(true), autocommit_off: false, clean: c.is_autocommit() }
            }
            Backend::Mysql(_) => {
                let left = if opaque { self.mysql_left_by_call(ok) } else { Ok(self.mysql_left_by_statement(ok, read)) };
                // Sin saber qué quedó, se limpia como si hubiera quedado todo.
                let (tx, autocommit_off) = *left.as_ref().unwrap_or(&(TxLeft::Open, true));
                let clean = tx != TxLeft::Open || self.rollback();
                // `read` en `None`: no se pudo leer cómo quedó `autocommit`; se repone por las dudas.
                if clean && (autocommit_off || read.is_none()) {
                    self.restore_autocommit();
                }
                Stray { left: left.map(|(tx, _)| tx == TxLeft::Open), autocommit_off, clean }
            }
            _ => Stray { left: Ok(false), autocommit_off: false, clean: true },
        }
    }

    /// MySQL, después de un statement de afuera que no es un `CALL`: qué transacción dejó, y si
    /// dejó `autocommit` apagado (`mysql_statement_left`). Con seguimiento lo dijo el servidor en
    /// la respuesta, sin otra ida y vuelta: es la red de fondo de `tx_guard`, que lee el texto.
    fn mysql_left_by_statement(&self, ok: bool, read: Option<bool>) -> (TxLeft, bool) {
        let Backend::Mysql(c) = self else { return (TxLeft::None, false) };
        mysql_statement_left(c.tracked.then_some((c.tx_state.as_str(), c.autocommit)), ok, read)
    }

    /// MySQL: lo que el servidor informó hasta acá (el estado de la transacción y `autocommit`).
    /// `None` sin seguimiento.
    fn mysql_tracked_state(&self) -> Option<(String, bool)> {
        match self {
            Backend::Mysql(c) if c.tracked => Some((c.tx_state.clone(), c.autocommit)),
            _ => None,
        }
    }

    /// MySQL, adentro de `sql_transaction`: ¿la transacción que había antes del statement
    /// (`before`, de `mysql_tracked_state`) ya no es la misma? (`mysql_tx_ended`)
    fn mysql_tx_ended_since(&self, before: &str) -> bool {
        match self {
            Backend::Mysql(c) if c.tracked => mysql_tx_ended(before, &c.tx_state),
            _ => false,
        }
    }

    /// MySQL, después de un `CALL` de afuera: qué transacción dejó el procedimiento, y si hay que
    /// reponer `autocommit`.
    ///
    /// **Con seguimiento** (`MysqlConn::tracked`) ya lo dijo el servidor, en la respuesta del
    /// propio `CALL` y sin otra ida y vuelta (`MysqlConn::observe`). Un `CALL` que falla termina
    /// en un ERR, que no informa nada: lo que dejó llega con el OK siguiente, y para eso va un
    /// `DO 0` (medido en 8.0.46). `ok` es de fiar porque la respuesta se lee hasta el final
    /// (`mysql_finish`).
    ///
    /// **Sin seguimiento**, se pregunta: fijar el nivel de aislamiento de la PRÓXIMA transacción
    /// (el `SET` sin `SESSION` ni `GLOBAL`) da ERROR 1568 si hay una en curso, y pasa con
    /// `autocommit = 0` si no quedó nada pendiente. Dos límites, que el seguimiento no tiene: no
    /// distingue una lectura de una escritura pendiente, y pisa el nivel «de la próxima
    /// transacción» que el programa haya fijado. `autocommit` se repone siempre: no se sabe.
    fn mysql_left_by_call(&mut self, ok: bool) -> Result<(TxLeft, bool), String> {
        let Backend::Mysql(c) = self else { return Ok((TxLeft::None, false)) };
        if c.tracked && !ok {
            c.text("DO 0").map_err(mysql_err)?;
        }
        // (El `DO 0` pudo traer algo que no se entiende: entonces también se pregunta.)
        if c.tracked {
            return Ok((mysql_tx_left(&c.tx_state, c.autocommit), !c.autocommit));
        }
        match c.query_drop(MYSQL_IN_TRANSACTION_PROBE) {
            Ok(()) => Ok((TxLeft::None, true)),
            Err(mysql::Error::MySqlError(e)) if e.code == MYSQL_TX_IN_PROGRESS => Ok((TxLeft::Open, true)),
            Err(e) => Err(mysql_err(e)),
        }
    }

    /// MySQL: ¿este statement es un `SET` que el motor no sabe leer como lo lee el servidor
    /// (`mysql_unread_set`)? Después de uno así se mira lo que dejó (`mysql_after_unread_set`).
    fn unread_set(&self, sql: &str) -> bool {
        matches!(self, Backend::Mysql(_)) && mysql_unread_set(sql)
    }

    /// MySQL: lo que el motor sabe de `autocommit` sin preguntar. `None` sin seguimiento.
    fn mysql_autocommit(&self) -> Option<bool> {
        match self {
            Backend::Mysql(c) if c.tracked => Some(c.autocommit),
            _ => None,
        }
    }

    /// MySQL, después de un `SET` del programa que el motor no sabe leer: le pregunta al servidor
    /// cómo quedaron las variables que son del motor. No se fía del texto: el servidor reconoce
    /// el nombre de una variable escrito de formas que el motor no (medido en 8.0.46:
    /// `SET autocommít = 0` apaga `autocommit`), así que mira el resultado.
    /// - `Some(true)`: `autocommit` está en 1; `Some(false)`: quedó apagado; `None`: no se pudo
    ///   leer.
    /// - Si el seguimiento de sesión ya no está como lo pidió `mysql_connect` (o no se pudo
    ///   leer), la conexión queda sin seguimiento: desde ahí se pregunta
    ///   (`mysql_left_by_call`).
    fn mysql_after_unread_set(&mut self) -> Option<bool> {
        let Backend::Mysql(c) = self else { return Some(true) };
        // Sin seguimiento no se nombran sus variables: un servidor que no lo da puede no tenerlas.
        let sql = if c.tracked { MYSQL_READ_BACK } else { "SELECT @@session.autocommit, 1, 1" };
        let row: Result<Option<mysql::Row>, mysql::Error> = c.conn.query_first(sql);
        c.observe();
        let int = |row: &mysql::Row, i: usize| row.get_opt::<Option<i64>, usize>(i).and_then(Result::ok).flatten();
        let read = row.ok().flatten().and_then(|row| Some((int(&row, 0)?, int(&row, 1), int(&row, 2))));
        let Some((autocommit, state, variables)) = read else {
            c.tracked = false;
            return None;
        };
        if state != Some(1) || variables != Some(1) {
            c.tracked = false;
        }
        c.autocommit = autocommit != 0;
        Some(autocommit != 0)
    }

    /// MySQL, después de un `CALL` (afuera de una transacción, o al cerrar una en la que corrió
    /// uno): el procedimiento pudo dejar `autocommit = 0` sin que se note (no confirma nada), y
    /// entonces lo que se escriba después quedaría en una transacción que nadie confirma. Va
    /// después del `COMMIT`/`ROLLBACK`: con una transacción abierta, `SET autocommit = 1` la
    /// confirmaría.
    fn restore_autocommit(&mut self) {
        if let Backend::Mysql(_) = self {
            let _ = self.control("SET autocommit = 1");
        }
    }

    /// v0.6.59 — lo que un statement del programa no hace: manejar la transacción a mano. Mira las
    /// primeras palabras de código; `in_tx`: dentro de `sql_transaction`.
    fn guard(&self, sql: &str, in_tx: bool) -> Result<(), String> {
        let Some(d) = self.dialect() else { return Ok(()) };
        tx_guard(sql, d, in_tx)
    }

    /// Un statement que corre código que el motor no ve: en MySQL, un `CALL` (el cuerpo de un
    /// procedimiento puede abrir, confirmar o deshacer una transacción). En Postgres el servidor
    /// rechaza eso adentro de una transacción y no deja nada abierto afuera (medido en 16.15); en
    /// SQLite no hay procedimientos.
    fn opaque(&self, sql: &str) -> bool {
        matches!(self, Backend::Mysql(_)) && mysql_opaque(sql)
    }
}

/// MySQL: `CALL …` (también dentro de un comentario ejecutable: `MysqlHead`).
fn mysql_opaque(sql: &str) -> bool {
    mysql_head(sql).first_is(&["CALL"])
}

/// MySQL: cómo empieza un statement, leído de las dos maneras en que puede leerlo el servidor.
///
/// MySQL EJECUTA lo que va dentro de `/*! … */`. Con una versión (`/*!80000 … */`) lo ejecuta
/// sólo un servidor de esa versión o posterior, y `/*M! … */` sólo MariaDB: el motor no sabe si
/// el servidor al que le habla lo va a correr. Medido en 8.0.46: `/*!99999 SELECT */ COMMIT` es
/// un `COMMIT` para el servidor; leído con el comentario como código empieza con `SELECT`.
struct MysqlHead {
    /// Las dos primeras palabras con TODOS los comentarios ejecutables leídos como código.
    all: [String; 2],
    /// Las dos primeras palabras que el servidor lee seguro: con los comentarios ejecutables sin
    /// versión como código y los demás como comentarios.
    sure: [String; 2],
    /// Antes de `sure[i]` hay un comentario que sólo algunos servidores ejecutan: esa palabra
    /// puede no ser la que ocupa ese lugar.
    gap: [bool; 2],
}

impl MysqlHead {
    /// ¿La primera palabra es una de éstas, en alguna de las dos lecturas?
    fn first_is(&self, words: &[&str]) -> bool {
        words.contains(&self.all[0].as_str()) || words.contains(&self.sure[0].as_str())
    }
}

fn mysql_head(sql: &str) -> MysqlHead {
    let pair = |mut words: Vec<String>| {
        words.resize(2, String::new());
        let second = words.pop().unwrap_or_default();
        [words.pop().unwrap_or_default(), second]
    };
    if !sql.contains("/*") {
        let words = pair(leading_words(sql, SqlDialect::Mysql, 2));
        return MysqlHead { all: words.clone(), sure: words, gap: [false; 2] };
    }
    let all = pair(leading_words(&mysql_unwrap_executable_comments(sql, true), SqlDialect::Mysql, 2));
    let mut gap = [false; 2];
    let sure = pair(leading_words_marked(&mysql_unwrap_executable_comments(sql, false), SqlDialect::Mysql, 2, &mut gap));
    MysqlHead { all, sure, gap }
}

/// MySQL: ¿el texto tiene esta palabra, en ASCII y sin mirar mayúsculas? No lee SQL: también
/// cuenta adentro de un literal, de unas comillas o de un comentario. Leer dónde termina un
/// literal depende del `sql_mode` del servidor (`NO_BACKSLASH_ESCAPES`, `ANSI_QUOTES`), y el
/// servidor acepta el nombre de una variable entre comillas invertidas (medido en 8.0.46:
/// ``SET `autocommit` = 0``). De más, nunca de menos.
fn mysql_text_has(sql: &str, name: &str) -> bool {
    let name = name.as_bytes();
    sql.as_bytes().windows(name.len()).any(|w| w.eq_ignore_ascii_case(name))
}

/// MySQL: un `SET` del programa del que el motor no puede decir, por el texto, que no toca las
/// variables que son suyas (`autocommit` y las del seguimiento de sesión):
/// - tiene un carácter que no es ASCII: el servidor busca el nombre de una variable con la
///   comparación de su juego de caracteres, que iguala letras con tilde y otras a su letra base
///   (medido en 8.0.46: `autocommít`, `sessión_track_…`, `ſession_track_…`);
/// - o nombra `session_track`.
///
/// Un `SET` en ASCII que nombra `autocommit` no llega acá: lo rechaza `tx_guard`. Sólo un `SET`
/// cambia una variable de la sesión desde el programa (lo demás es el cuerpo de un procedimiento
/// o de una función, que el motor no ve).
fn mysql_unread_set(sql: &str) -> bool {
    mysql_head(sql).first_is(&["SET"]) && (!sql.is_ascii() || mysql_text_has(sql, "session_track"))
}

/// El chequeo de `Backend::guard`, sobre el texto y el dialecto.
fn tx_guard(sql: &str, d: SqlDialect, in_tx: bool) -> Result<(), String> {
    let by_hand = |first: &str, second: &str| {
        matches!(first, "BEGIN" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "RELEASE" | "END" | "ABORT")
            || (matches!(first, "START" | "PREPARE") && second == "TRANSACTION")
    };
    if d != SqlDialect::Mysql {
        let words = leading_words(sql, d, 2);
        let first = words.first().map(String::as_str).unwrap_or("");
        let second = words.get(1).map(String::as_str).unwrap_or("");
        return if by_hand(first, second) { Err(TX_BY_HAND.to_string()) } else { Ok(()) };
    }
    // MySQL: el statement se lee de las dos maneras en que lo puede leer el servidor
    // (`MysqlHead`), y vale la peor.
    let head = mysql_head(sql);
    let (first, second) = (head.sure[0].as_str(), head.sure[1].as_str());
    if by_hand(first, second)
        || by_hand(&head.all[0], &head.all[1])
        // La segunda palabra no se sabe.
        || (head.gap[1] && matches!(first, "START" | "PREPARE"))
        || head.first_is(&["XA"])
        // `autocommit` en cualquier parte del texto de un `SET` (`mysql_text_has`).
        || (head.first_is(&["SET"]) && mysql_text_has(sql, "autocommit"))
    {
        return Err(TX_BY_HAND.to_string());
    }
    // `PREPARE s FROM '…'` y `EXECUTE s` corren un statement que está en un texto (medido:
    // `PREPARE s FROM 'COMMIT'` + `EXECUTE s` confirma, y con `SET autocommit = 0` deja la
    // conexión compartida en una transacción). (`PREPARE TRANSACTION` ya salió arriba.)
    if head.first_is(&["PREPARE", "EXECUTE"]) {
        return Err(MYSQL_SQL_PREPARE.to_string());
    }
    // Lo que queda no es control de transacciones en ninguna de las dos lecturas, pero si la
    // primera palabra depende de la versión del servidor, el motor no sabe qué statement es: no
    // sabría si es un `CALL`, ni si confirma la transacción abierta.
    if head.gap[0] {
        return Err(MYSQL_COMMENT_FIRST.to_string());
    }
    // `CREATE`, `DROP`, `SET` y `LOAD` confirman o no según la segunda palabra: si no se sabe cuál
    // es, cuenta como que sí.
    if in_tx && head.gap[1] && matches!(first, "CREATE" | "DROP" | "SET" | "LOAD") {
        return Err(format!(
            "sql_transaction: in MySQL this {} statement may commit the open transaction: the comment after {} is one that only some servers run (/*!80000 … */ with a version, or /*M! … */), so the engine cannot tell which statement it is — run it outside sql_transaction, or write it without that comment",
            first, first
        ));
    }
    if in_tx && mysql_implicit_commit(first, second) {
        let what = if matches!(first, "SET" | "LOAD") { format!("{} {}", first, second) } else { first.to_string() };
        return Err(format!(
            "sql_transaction: in MySQL a {} statement commits the open transaction (MySQL has no transactional DDL), so the transaction could not roll it back — run it outside sql_transaction",
            what
        ));
    }
    Ok(())
}

/// El control de transacciones escrito a mano (`tx_guard`).
const TX_BY_HAND: &str = "BEGIN, COMMIT, ROLLBACK and SAVEPOINT are not run by hand (since v0.6.59): a hand-made transaction on a shared connection wraps the writes of other tasks. Put the statements in a task and run sql_transaction(task) — it commits when the task returns and rolls back if it fails; inside one, another sql_transaction(task) is a savepoint";

/// MySQL: `PREPARE` y `EXECUTE` de SQL (`tx_guard`).
const MYSQL_SQL_PREPARE: &str = "MySQL PREPARE and EXECUTE are not run from here (since v0.6.59): the statement they run is a text the engine does not see, and it could commit or roll back by hand. Pass the statement itself, with ? and a list of values — sql(\"SELECT … WHERE id = ?\", [id]) — the engine prepares it";

/// MySQL: un comentario que sólo algunos servidores ejecutan, antes de la primera palabra del
/// statement (`tx_guard`).
const MYSQL_COMMENT_FIRST: &str = "a MySQL comment that only some servers run — /*!80000 … */ with a version, or /*M! … */ — before the first word of a statement is not run from here (since v0.6.59): whether the server runs what is inside depends on its version, so the engine cannot tell which statement this is. Write the statement itself, without that comment";

/// MySQL: un statement que no es un `CALL` apagó `autocommit` (`SqlConn::run`). Sigue
/// `TX_BY_HAND`.
const TURNED_AUTOCOMMIT_OFF: &str = "this statement turned autocommit off on the connection, and the engine turns it back on (inside sql_transaction, when the transaction closes).";

/// MySQL: un statement que no es un `CALL` terminó la transacción de `sql_transaction`
/// (`SqlConn::run`, `mysql_tx_ended`).
const TX_ENDED_BY_STATEMENT: &str = "sql_transaction: this statement ended the transaction — the server reports that it was committed or rolled back — so what the transaction wrote before it can no longer be rolled back or committed as one. A statement inside sql_transaction must not manage transactions";

/// MySQL: un `CALL` cerró la transacción de `sql_transaction` (`SqlConn::run`).
const TX_ENDED_BY_CALL: &str = "sql_transaction: this CALL ended the transaction — the procedure ran COMMIT, ROLLBACK or a statement that commits (START TRANSACTION and DDL do), or the server rolled it back — so what the transaction wrote before the CALL can no longer be rolled back or committed as one. A procedure called inside sql_transaction must not manage transactions";

/// MySQL: un `CALL` dejó una transacción en curso fuera de `sql_transaction` (`SqlConn::run`).
/// Lo que el procedimiento ya había confirmado no se deshace, y el mensaje lo dice: quien
/// reintenta sin saberlo escribe dos veces.
const CALL_LEFT_OPEN: &str = "this CALL left a transaction open on the connection, and it was rolled back: what the procedure had not committed is undone; what it had already committed stays, and so does a write to a table without transactions (MyISAM). On a shared connection an open transaction would wrap the writes of other tasks. A procedure that opens a transaction closes it before it returns; one that leaves the commit to its caller is called inside sql_transaction(task)";

/// Lo que quedó abierto no se pudo deshacer, y la conexión se cerró (`SqlConn::run`). En MySQL,
/// un procedimiento que deja una transacción XA activa: `ROLLBACK` no la termina. Va después de
/// «this CALL» o «this statement».
const LEFT_OPEN_STUCK: &str = "left a transaction open on the connection and it could not be rolled back (in MySQL, a procedure that leaves an XA transaction active or idle: ROLLBACK does not end one), so the connection was closed — open it again with db_open. A statement run on it afterwards would have stayed inside that transaction, uncommitted. The server ends the transaction when the connection closes; what the procedure had already committed stays";

/// MySQL: no se pudo mirar el estado de la conexión después de un `CALL` (`SqlConn::run`).
const CALL_UNCHECKED: &str = "the connection could not be checked after this CALL, so it was rolled back to leave no transaction open (what the procedure had already committed stays). The check failed with";

/// MySQL: la sonda de `Backend::mysql_left_by_call`, para una conexión sin seguimiento.
const MYSQL_IN_TRANSACTION_PROBE: &str = "SET @@transaction_isolation = @@SESSION.transaction_isolation";
/// `ER_CANT_CHANGE_TX_CHARACTERISTICS`: «Transaction characteristics can't be changed while a
/// transaction is in progress».
const MYSQL_TX_IN_PROGRESS: u16 = 1568;

/// MySQL: cómo quedaron las variables del motor (`Backend::mysql_after_unread_set`): `autocommit`,
/// y si el seguimiento de sesión sigue como lo pidió `MYSQL_TRACK_SESSION` (la comparación la
/// hace el servidor, sin mirar mayúsculas; medido en 8.0.46). Una lista que además sigue otras
/// variables no es la del motor: de más, nunca de menos.
const MYSQL_READ_BACK: &str = "SELECT @@session.autocommit, @@session.session_track_transaction_info = 'STATE', @@session.session_track_system_variables = 'autocommit'";

/// MySQL, al conectar (`mysql_connect`): que el servidor informe en cada respuesta el estado de
/// la transacción y los cambios de `autocommit`. La tercera asignación es el testigo: si la
/// respuesta de este mismo `SET` trae `autocommit`, el seguimiento llega hasta acá (medido en
/// 8.0.46: sin la capacidad `CLIENT_SESSION_TRACK` negociada no trae nada). Y deja `autocommit`
/// en 1, que es como lo necesita el motor.
const MYSQL_TRACK_SESSION: &str =
    "SET SESSION session_track_transaction_info = 'STATE', session_track_system_variables = 'autocommit', autocommit = 1";

/// Lo que un `CALL` de afuera dejó en la conexión (`Backend::mysql_left_by_call`).
/// Lo que hizo `Backend::close_stray_transaction`.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Stray {
    /// `Ok(true)`: había una transacción abierta; `Err`: no se pudo mirar.
    left: Result<bool, String>,
    /// MySQL: `autocommit` quedó apagado (y ya se repuso). Después de un `CALL` no es un error:
    /// es el patrón de siempre de un procedimiento.
    autocommit_off: bool,
    /// La conexión quedó fuera de una transacción.
    clean: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TxLeft {
    /// Ninguna transacción.
    None,
    /// Una transacción que no abrió un `START TRANSACTION` y en la que no hay una escritura que
    /// deshacer: la que deja una lectura con `autocommit = 0` (el patrón de siempre,
    /// `SET autocommit = 0; START TRANSACTION; …; COMMIT`, seguido de un `SELECT`). Cerrarla no
    /// pierde nada, así que no es un error; la cierra reponer `autocommit`.
    NothingToUndo,
    /// Una transacción con algo pendiente, o abierta con `START TRANSACTION`.
    Open,
}

/// MySQL: el estado de la transacción que informa el servidor (`session_track_transaction_info =
/// 'STATE'`), ocho caracteres: `T` explícita o `I` implícita; `r`/`R` leyó una tabla sin o con
/// transacciones; `w`/`W` escribió en una; `s`/`S`; `L`. Un `_` donde no. Medido en 8.0.46: un
/// `DELETE` que no borra nada y un `SELECT … FOR UPDATE` sin filas también marcan `W`.
///
/// Lo que no se reconoce cuenta como una transacción abierta: de más, nunca de menos. Una
/// implícita sólo existe con `autocommit` apagado, así que con `autocommit` en 1 tampoco se
/// reconoce.
///
/// La última marca, `L`, dice que hay tablas bloqueadas con `LOCK TABLES`: no es una transacción
/// (medido: `_______L` hasta el `UNLOCK TABLES`, y un `CALL` en el medio daba el error de una
/// transacción abierta).
fn mysql_tx_left(state: &str, autocommit: bool) -> TxLeft {
    let b = state.as_bytes();
    let no_tx = |b: &[u8]| !b.is_empty() && b.iter().all(|&c| c == b'_');
    if no_tx(b) || (b.len() == 8 && b[7] == b'L' && no_tx(&b[..7])) {
        TxLeft::None
    } else if b.first() == Some(&b'I') && !b.contains(&b'W') && !autocommit {
        TxLeft::NothingToUndo
    } else {
        TxLeft::Open
    }
}

/// MySQL: lo que dejó un statement de afuera que no es un `CALL` (`Backend::mysql_left_by_statement`).
/// `tracked`: el estado y `autocommit` que informó el servidor, si hay seguimiento; `ok`: el
/// statement corrió sin error; `read`: lo que leyó `mysql_after_unread_set`.
///
/// Afuera de una transacción y con `autocommit` en 1, ningún statement deja un estado que empiece
/// con `T` o con `I` (medido en 8.0.46: `INSERT`, `SELECT … FOR UPDATE`, DDL, `LOCK TABLES`,
/// `HANDLER`, `GET_LOCK`, `SET`): si lo hay, el statement abrió una transacción a mano, se
/// escriba como se escriba. Sólo se miran esas dos letras: un estado que no se reconoce no es
/// motivo para deshacer nada después de un statement común.
///
/// Un statement que falla no abre una transacción ni apaga `autocommit`, y un ERR no informa
/// nada: ahí no se mira. Sin seguimiento sólo se sabe lo que se leyó.
fn mysql_statement_left(tracked: Option<(&str, bool)>, ok: bool, read: Option<bool>) -> (TxLeft, bool) {
    match tracked {
        Some((state, autocommit)) if ok => {
            let in_tx = matches!(state.as_bytes().first(), Some(b'T' | b'I'));
            (if in_tx { mysql_tx_left(state, autocommit) } else { TxLeft::None }, !autocommit)
        }
        _ => (TxLeft::None, read == Some(false)),
    }
}

/// MySQL, adentro de `sql_transaction`: ¿un statement terminó la transacción? `before` y `after`
/// son el estado que informó el servidor antes y después de él. La transacción del motor empieza
/// con `T`, y las marcas de lectura y escritura (las cuatro que siguen) sólo se suman mientras
/// dura: no las saca un `ROLLBACK TO SAVEPOINT` (medido en 8.0.46). Así que terminó si ya no
/// empieza con `T` (`COMMIT`, `ROLLBACK`, un statement que confirma) o si perdió una marca (un
/// `COMMIT AND CHAIN`, o un `START TRANSACTION`, que confirman y abren otra: `T___W___` pasa a
/// `T_______`).
///
/// Si `before` no empieza con `T` no se sabía que hubiera una transacción: no se mira.
fn mysql_tx_ended(before: &str, after: &str) -> bool {
    let (b, a) = (before.as_bytes(), after.as_bytes());
    b.first() == Some(&b'T') && (a.first() != Some(&b'T') || (1..=4).any(|i| b.get(i).is_some_and(|&mark| mark != b'_') && a.get(i) != b.get(i)))
}

/// MySQL: lo que informó el servidor en su última respuesta: el estado de la transacción, si
/// cambió, y `autocommit`, si lo asignaron (`true`: quedó en 1).
fn mysql_tracked(c: &mysql::Conn) -> Result<(Option<String>, Option<bool>), String> {
    use mysql::session_state_change::SessionStateChange;
    let mut state = None;
    let mut autocommit = None;
    for info in c.session_state_changes().map_err(|e| e.to_string())? {
        match info.decode().map_err(|e| e.to_string())? {
            SessionStateChange::TransactionState(s) => state = Some(s.as_str().into_owned()),
            SessionStateChange::SystemVariables(vars) => {
                for v in vars {
                    if v.name_str().eq_ignore_ascii_case("autocommit") {
                        autocommit = Some(v.value_str().eq_ignore_ascii_case("ON"));
                    }
                }
            }
            _ => {}
        }
    }
    Ok((state, autocommit))
}

/// MySQL: los statements que confirman la transacción abierta («Statements That Cause an Implicit
/// Commit» del manual), por su primera palabra. Medidos uno por uno contra MySQL 8.0.46
/// (2026-11-10). `CREATE`, `DROP`, `SET` y `LOAD` dependen de la segunda palabra:
/// `mysql_implicit_commit`.
/// - No están `UNLOCK` (sólo confirma con tablas bloqueadas por `LOCK TABLES`, que adentro de una
///   transacción se rechaza, y el `START TRANSACTION` del motor suelta las de antes) ni `PURGE`
///   (medido: no confirma).
/// - `RESET` se rechaza entero, aunque `RESET PERSIST` no confirma: de más, nunca de menos.
const MYSQL_IMPLICIT_COMMIT: &[&str] = &[
    "ALTER", "RENAME", "TRUNCATE", "GRANT", "REVOKE", "LOCK", "INSTALL", "UNINSTALL", "ANALYZE", "CACHE", "CHECK",
    "FLUSH", "OPTIMIZE", "REPAIR", "RESET", "START", "STOP", "CHANGE", "IMPORT", "CLONE",
];

/// MySQL: ¿este statement confirma la transacción abierta?
/// - `CREATE`/`DROP TEMPORARY TABLE` no (los demás `CREATE` y `DROP`, sí);
/// - `SET PASSWORD` y `SET DEFAULT ROLE` sí (tocan las tablas de `mysql`); el resto de `SET`, no;
/// - `LOAD INDEX INTO CACHE` sí; `LOAD DATA`, no;
/// - `START` llega acá sin `TRANSACTION` (`START REPLICA`): también confirma.
fn mysql_implicit_commit(first: &str, second: &str) -> bool {
    match first {
        "CREATE" | "DROP" => second != "TEMPORARY",
        "SET" => matches!(second, "PASSWORD" | "DEFAULT"),
        "LOAD" => second == "INDEX",
        _ => MYSQL_IMPLICIT_COMMIT.contains(&first),
    }
}

/// `sql_transaction` con algo que no es una task.
const TX_USAGE: &str = "sql_transaction expects a task with no parameters: sql_transaction(() => …) or sql_transaction(my_task) — it commits when the task returns and rolls back if it fails";

/// Un statement ya falló dentro de la transacción.
#[cold]
#[inline(never)]
fn tx_failed(first: &str) -> String {
    format!(
        "sql_transaction: a statement failed inside this transaction, so it rolls back (to survive a statement that may fail, run it in its own sql_transaction(task) and catch the error outside it) — the first error was: {}",
        first
    )
}

/// El blanco de SQL: Postgres cuenta el tabulador vertical; el resto, los de siempre.
fn is_sql_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// Las primeras `n` palabras de código de un statement, en mayúsculas. Salta el blanco, `;`, `(`
/// y los comentarios (`-- …`, `/* … */`, y `# …` en MySQL), y se corta en lo que no es una palabra.
/// Un comentario termina en el primer `*/` (en Postgres se anidan): así se ve más código que el
/// motor, nunca menos.
fn leading_words(sql: &str, dialect: SqlDialect, n: usize) -> Vec<String> {
    leading_words_marked(sql, dialect, n, &mut [])
}

/// `leading_words`, y en `gap[k]` si antes de la palabra `k` (o del final, si no la hay) se saltó
/// un comentario ejecutable de MySQL (`/*!…` o `/*M!…`).
fn leading_words_marked(sql: &str, dialect: SqlDialect, n: usize, gap: &mut [bool]) -> Vec<String> {
    let b = sql.as_bytes();
    let mut i = 0;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        loop {
            match b.get(i) {
                Some(&c) if is_sql_space(c) || c == b';' || c == b'(' => i += 1,
                Some(b'-') if b.get(i + 1) == Some(&b'-') => {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                }
                Some(b'#') if dialect == SqlDialect::Mysql => {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                }
                // MySQL: el cierre de un comentario ejecutable ya abierto
                // (`mysql_unwrap_executable_comments` borra la apertura): lo que sigue es código
                // del mismo statement (medido en 8.0.46: `/*! START */ TRANSACTION` abre una
                // transacción).
                Some(b'*') if dialect == SqlDialect::Mysql && b.get(i + 1) == Some(&b'/') => i += 2,
                Some(b'/') if b.get(i + 1) == Some(&b'*') => {
                    if mysql_executable_comment(&b[i..]).is_some() {
                        if let Some(g) = gap.get_mut(out.len()) {
                            *g = true;
                        }
                    }
                    i += 2;
                    while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                        i += 1;
                    }
                    i = (i + 2).min(b.len());
                }
                _ => break,
            }
        }
        let start = i;
        while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
            i += 1;
        }
        if i == start {
            break;
        }
        out.push(sql[start..i].to_ascii_uppercase());
    }
    out
}

/// MySQL: si `b` empieza con la apertura de un comentario ejecutable, su largo y si lo ejecuta
/// cualquier servidor (`true`: `/*!` a secas; `false`: `/*!` seguido de un dígito, que es una
/// versión, o `/*M!`, que es de MariaDB).
fn mysql_executable_comment(b: &[u8]) -> Option<(usize, bool)> {
    match b {
        [b'/', b'*', b'!', rest @ ..] => Some((3, !rest.first().is_some_and(u8::is_ascii_digit))),
        [b'/', b'*', b'M', b'!', ..] => Some((4, false)),
        _ => None,
    }
}

/// MySQL y MariaDB ejecutan lo que va dentro de `/*! … */`, `/*!50000 … */` y `/*M! … */`: se
/// borra la apertura (queda el contenido como código; el `*/` suelto lo salta `leading_words`). Con
/// `all` en `false` sólo se abren los que ejecuta cualquier servidor
/// (`mysql_executable_comment`); los demás quedan como comentarios.
fn mysql_unwrap_executable_comments(sql: &str, all: bool) -> String {
    let b = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    let mut from = 0;
    while i + 2 < b.len() {
        match mysql_executable_comment(&b[i..]) {
            Some((len, always)) if all || always => {
                out.push_str(&sql[from..i]);
                out.push(' ');
                i += len;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                from = i;
            }
            _ => i += 1,
        }
    }
    out.push_str(&sql[from..]);
    out
}

/// Una conexión SQL en uso: la default del gestor, o la de una transacción (`failed` anota ahí el
/// primer statement que falla).
struct SqlConn<'a> {
    backend: &'a mut Backend,
    failed: Option<&'a mut Option<String>>,
    /// De la transacción: corrió un statement opaco (`Backend::opaque`), o uno que dejó
    /// `autocommit` apagado: al cerrarla se repone.
    called: Option<&'a mut bool>,
    /// Fuera de una transacción: lo que dejó abierto un statement no se pudo deshacer. El que
    /// armó esta conexión la cierra (`DatabaseManager::with_default`).
    broken: bool,
}

impl SqlConn<'_> {
    fn run<R>(&mut self, sql: &str, f: impl FnOnce(&mut Backend) -> Result<R, String>) -> Result<R, String> {
        // Regla 2 del diseño: después de un statement que falló, la transacción sólo puede
        // deshacerse (Postgres ya la tiene abortada; en SQLite y MySQL se hace lo mismo).
        if let Some(slot) = &self.failed {
            if let Some(first) = &**slot {
                return Err(tx_failed(first));
            }
        }
        self.backend.guard(sql, self.failed.is_some())?;
        let opaque = self.backend.opaque(sql);
        let unread_set = self.backend.unread_set(sql);
        let Some(slot) = self.failed.as_mut() else {
            // Fuera de una transacción: nada queda abierto en la conexión compartida.
            let r = f(self.backend);
            let read = if unread_set { self.backend.mysql_after_unread_set() } else { Some(true) };
            let stray = self.backend.close_stray_transaction(opaque, r.is_ok(), read);
            if !stray.clean {
                self.broken = true;
                let what = if opaque { "this CALL" } else { "this statement" };
                return Err(match r {
                    Ok(_) => format!("{} {}", what, LEFT_OPEN_STUCK),
                    Err(e) => format!("{} — and {} {}", e, what, LEFT_OPEN_STUCK),
                });
            }
            return match stray.left {
                // Afuera `autocommit` está en 1 (lo deja el motor al conectar y después de cada
                // `CALL`): si quedó apagado, fue este statement.
                Ok(false) if stray.autocommit_off && !opaque && r.is_ok() => Err(format!("{} {}", TURNED_AUTOCOMMIT_OFF, TX_BY_HAND)),
                Ok(false) => r,
                // El statement ya falló: sale su error (lo que dejó abierto ya se deshizo).
                _ if r.is_err() => r,
                Ok(true) if opaque => Err(CALL_LEFT_OPEN.to_string()),
                Ok(true) => Err(format!("this statement left a transaction open on the connection, and it was rolled back. {}", TX_BY_HAND)),
                Err(e) => Err(format!("{}: {}", CALL_UNCHECKED, e)),
            };
        };
        if !opaque {
            // Adentro, `autocommit` puede estar apagado desde antes (un `CALL` anterior): sólo se
            // le carga a este statement si se sabe que estaba en 1. Reponerlo acá confirmaría la
            // transacción: se repone al cerrarla (`called`).
            let already_called = self.called.as_ref().is_some_and(|c| **c);
            let before = self.backend.mysql_tracked_state();
            let was_on = before.as_ref().map_or(!already_called, |(_, autocommit)| *autocommit);
            let r = f(self.backend);
            let autocommit = if unread_set { self.backend.mysql_after_unread_set() } else { self.backend.mysql_autocommit().or(Some(true)) };
            if autocommit != Some(true) {
                if let Some(c) = self.called.as_mut() {
                    **c = true;
                }
            }
            // La red de fondo de `tx_guard`: lo que informó el servidor (`mysql_tx_ended`).
            let ended = r.is_ok() && before.is_some_and(|(state, _)| self.backend.mysql_tx_ended_since(&state));
            let r = match r {
                Ok(_) if ended => Err(TX_ENDED_BY_STATEMENT.to_string()),
                Ok(_) if autocommit == Some(false) && was_on => Err(format!("{} {}", TURNED_AUTOCOMMIT_OFF, TX_BY_HAND)),
                r => r,
            };
            if let Err(e) = &r {
                **slot = Some(e.clone());
            }
            return r;
        }
        // Adentro de una transacción, un statement opaco (MySQL, `CALL`) va entre un savepoint y su
        // `RELEASE`: un savepoint muere con su transacción, así que si ya no está, el procedimiento
        // la cerró (aunque después haya abierto otra). Medido en 8.0.46.
        if let Some(c) = self.called.as_mut() {
            **c = true;
        }
        if let Err(e) = self.backend.control("SAVEPOINT synsema_call") {
            **slot = Some(e.clone());
            return Err(e);
        }
        let r = f(self.backend);
        let ended = self.backend.control("RELEASE SAVEPOINT synsema_call").is_err();
        match r {
            Ok(_) if ended => {
                **slot = Some(TX_ENDED_BY_CALL.to_string());
                Err(TX_ENDED_BY_CALL.to_string())
            }
            Ok(v) => Ok(v),
            Err(e) => {
                let e = if ended { format!("{} — and {}", e, TX_ENDED_BY_CALL) } else { e };
                **slot = Some(e.clone());
                Err(e)
            }
        }
    }

    fn query(&mut self, sql: &str, params: &[SynValue]) -> Result<Vec<Row>, String> {
        self.run(sql, |b| b.query(sql, params))
    }

    fn execute(&mut self, sql: &str, params: &[SynValue]) -> Result<(i64, i64), String> {
        self.run(sql, |b| b.execute(sql, params))
    }

    fn execute_many(&mut self, sql: &str, params_list: &[Vec<SynValue>]) -> Result<i64, String> {
        self.run(sql, |b| b.execute_many(sql, params_list))
    }

    fn tables(&mut self) -> Result<Vec<String>, String> {
        let (sql, col) = self.backend.tables_query()?;
        let rows = self.query(sql, &[])?;
        Ok(rows
            .iter()
            .filter_map(|r| match r.get(col) {
                Some(SynValue::Text(s)) => Some(s.to_string()),
                _ => None,
            })
            .collect())
    }
}

// -- La transacción de un intérprete (`sql_transaction`) --

/// La transacción abierta de un intérprete: tiene la conexión mientras corre su task.
struct Tx {
    backend: Backend,
    /// 1: la transacción; de 2 en adelante, savepoints.
    depth: usize,
    /// El primer statement que falló en el nivel abierto.
    failed: Option<String>,
    /// Corrió un statement opaco (MySQL, `CALL`): al cerrar se repone `autocommit`.
    called: bool,
}

/// Una por registro de builtins: un intérprete, y en `serve` un worker.
type TxCell = Rc<RefCell<Option<Tx>>>;

fn savepoint(level: usize) -> String {
    format!("synsema_tx_{}", level)
}

/// Corre `f` sobre la conexión SQL de este intérprete: la de su transacción si tiene una; si no,
/// la default del gestor, esperando si la tiene la transacción de otra task.
fn with_sql<H: DbHandle, R>(db: &H, tx: &TxCell, f: impl FnOnce(&mut SqlConn<'_>) -> Result<R, String>) -> Result<R, String> {
    if let Some(t) = tx.borrow_mut().as_mut() {
        return f(&mut SqlConn { backend: &mut t.backend, failed: Some(&mut t.failed), called: Some(&mut t.called), broken: false });
    }
    db.write_unlent(|m| m.with_default(f))?
}

/// Un nivel abierto por `sql_transaction`. Se cierra con `finish`; si se suelta sin eso (un pánico
/// que desenrolla), deshace el nivel y devuelve la conexión.
struct TxScope<H: DbHandle> {
    db: H,
    tx: TxCell,
    level: usize,
    done: bool,
}

impl<H: DbHandle> TxScope<H> {
    /// `BEGIN` (saca la conexión del gestor) o, dentro de una transacción, un savepoint.
    fn open(db: &H, tx: &TxCell) -> Result<Self, String> {
        let mut cell = tx.borrow_mut();
        let level = match cell.as_mut() {
            Some(t) => {
                if let Some(first) = &t.failed {
                    return Err(tx_failed(first));
                }
                let level = t.depth + 1;
                if let Err(e) = t.backend.control(&format!("SAVEPOINT {}", savepoint(level))) {
                    t.failed = Some(e.clone());
                    return Err(e);
                }
                t.depth = level;
                level
            }
            None => {
                let mut backend = db.write_unlent(|m| m.lend())??;
                if let Err(e) = backend.begin() {
                    let clean = backend.rollback();
                    db.write(|m| m.give_back(clean.then_some(backend)));
                    return Err(e);
                }
                *cell = Some(Tx { backend, depth: 1, failed: None, called: false });
                1
            }
        };
        Ok(TxScope { db: db.clone(), tx: tx.clone(), level, done: false })
    }

    /// La task terminó con `r`: confirma si devolvió y ningún statement falló; si no, deshace. El
    /// error de la task sale tal cual.
    fn finish<T, E>(mut self, r: Result<T, E>, err: impl FnOnce(String) -> E) -> Result<T, E> {
        self.done = true;
        let closed = self.end(r.is_ok());
        match (r, closed) {
            (Ok(v), Ok(())) => Ok(v),
            (Ok(_), Err(e)) => Err(err(e)),
            (Err(e), _) => Err(e),
        }
    }

    /// Cierra el nivel. `Err`: no quedó confirmado aunque la task haya devuelto.
    fn end(&mut self, returned: bool) -> Result<(), String> {
        let Ok(mut cell) = self.tx.try_borrow_mut() else { return Ok(()) };
        if self.level > 1 {
            let Some(t) = cell.as_mut() else { return Ok(()) };
            let failed = t.failed.take();
            t.depth = self.level - 1;
            let name = savepoint(self.level);
            if returned && failed.is_none() {
                let released = t.backend.control(&format!("RELEASE SAVEPOINT {}", name));
                if let Err(e) = &released {
                    t.failed = Some(e.clone());
                }
                return released;
            }
            // `ROLLBACK TO` deja el savepoint puesto: se suelta después. Si no se puede deshacer
            // (MySQL, tras un deadlock, ya no tiene el savepoint), la de afuera tampoco confirma.
            let mut undone = t.backend.control(&format!("ROLLBACK TO SAVEPOINT {}", name));
            if undone.is_ok() {
                undone = t.backend.control(&format!("RELEASE SAVEPOINT {}", name));
            }
            if let Err(e) = &undone {
                // La de afuera cita el error que empezó todo (el deadlock), no el del savepoint.
                t.failed = Some(failed.clone().unwrap_or_else(|| e.clone()));
            }
            return match failed {
                Some(first) => Err(tx_failed(&first)),
                None => undone,
            };
        }
        let Some(t) = cell.take() else { return Ok(()) };
        drop(cell);
        let Tx { mut backend, failed, called, .. } = t;
        let (closed, clean) = if returned && failed.is_none() {
            match backend.commit() {
                Ok(()) => (Ok(()), true),
                Err(e) => {
                    let clean = backend.rollback();
                    (Err(format!("sql_transaction: COMMIT failed, nothing was committed: {}", e)), clean)
                }
            }
        } else {
            let clean = backend.rollback();
            (failed.map_or(Ok(()), |first| Err(tx_failed(&first))), clean)
        };
        if clean && called {
            backend.restore_autocommit();
        }
        self.db.write(|m| m.give_back(clean.then_some(backend)));
        if clean {
            closed
        } else {
            // Caso 16 del diseño: no se devuelve una conexión con una transacción abierta.
            closed.and(Err("sql_transaction: the transaction could not be rolled back, so the connection was closed — open it again with db_open".to_string()))
        }
    }
}

impl<H: DbHandle> Drop for TxScope<H> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.end(false);
        }
    }
}

/// HB4 (v0.6.44): ningún secret SELLADO entra a un parámetro de DB. Las conversiones de abajo no
/// pueden fallar y mandan los bytes de un secret de bytes tal cual; un sellado tiene que cortarse
/// ANTES, con un error que lo diga (antes viajaba la cadena `secret(NAME)` como si fuera el valor).
/// Recorre listas y mapas (un documento de Mongo, un vector).
fn reject_sealed(v: &SynValue, who: &str) -> Result<(), String> {
    match v {
        SynValue::Secret(s) => s.expose_bytes_checked(who).map(|_| ()),
        // v0.6.55: una máscara no es un vector de números (pgvector, columnas): que lo diga.
        SynValue::Array(a) if a.dtype() == "bool" => Err(format!(
            "{}: a mask (bool array) is not a vector — m * 1.0 gives 0/1 floats",
            who
        )),
        SynValue::List(l) => list_values(l).iter().try_for_each(|x| reject_sealed(x, who)),
        SynValue::Map(m) => m.borrow().iter().try_for_each(|(_, x)| reject_sealed(x, who)),
        _ => Ok(()),
    }
}

fn reject_sealed_all(params: &[SynValue], who: &str) -> Result<(), String> {
    params.iter().try_for_each(|p| reject_sealed(p, who))
}

// -- SQLite: ejecución + conversión SynValue <-> rusqlite Value --

/// v0.6.46: un error de SQLite como texto. El authorizer de `db_open` rechaza el `ATTACH` a un
/// archivo (y `VACUUM INTO`, que lo usa) y dos pragmas; SQLite sólo dice `not authorized`, así que se
/// agrega el porqué y qué hacer.
#[cold]
#[inline(never)]
fn sqlite_err(e: rusqlite::Error) -> String {
    if e.sqlite_error_code() == Some(rusqlite::ErrorCode::AuthorizationForStatementDenied) {
        return format!(
            "{}: Synsema refuses ATTACH of a file (VACUUM INTO uses it) and the pragmas data_store_directory and temp_store_directory, so a query cannot open a database the program did not declare; open the other database with db_open(<path>), which needs require db(<path>)",
            e
        );
    }
    // M-r8-1 (v0.6.58): `rusqlite` 0.41 rechaza una cola con otra sentencia. Antes (0.30) corría la
    // primera y descartaba el resto sin avisar; el error ahora dice qué hacer.
    if matches!(e, rusqlite::Error::MultipleStatement) {
        // Ronda 9: sin «after the first ';'» (un ';' dentro de un texto señalaba el equivocado) ni
        // «inside a transaction» (en `serve` las rutas comparten la conexión: un BEGIN de una ruta
        // envuelve las escrituras de las otras, M-r9-1).
        return "one SQL statement per call: this call has more than one (sql, sql_exec and sql_batch run one; before v0.6.58 the rest was dropped without a word); run each statement with its own call".to_string();
    }
    e.to_string()
}

fn sqlite_query(conn: &Connection, sql: &str, params: &[SynValue]) -> Result<Vec<Row>, String> {
    let pv: Vec<Value> = params.iter().map(syn_to_value).collect();
    let mut stmt = conn.prepare(sql).map_err(sqlite_err)?;
    // Las columnas como claves una vez por consulta: cada fila suma una referencia (F4.4).
    let cols: Vec<Key> = stmt.column_names().map(Key::from).collect();
    let mut rows = stmt
        .query(params_from_iter(pv.iter()))
        .map_err(sqlite_err)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().map_err(sqlite_err)? {
        let mut m = SynMap::with_capacity(cols.len());
        for (i, col) in cols.iter().enumerate() {
            let v: Value = row.get(i).map_err(sqlite_err)?;
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
        // HB4: un secret de bytes va como BLOB (antes: `from_utf8_lossy`, otros bytes). Sólo si NO
        // está sellado: la conversión es segura por sí misma, sin depender de que cada entrada
        // haya llamado a `reject_sealed` (auditoría v0.6.44, A1). Un sellado cae al brazo de
        // abajo: `expose()` da el marcador `secret(NAME)`, nunca el material.
        SynValue::Secret(s) if s.is_bytes() && !s.is_sealed() => Value::Blob(s.expose_bytes().to_vec()),
        SynValue::Secret(s) => Value::Text(s.expose().to_string()),
        // bytes → BLOB byte-exacto (round-trip con value_to_syn; MF-010).
        SynValue::Bytes(b) => Value::Blob(b[..].to_vec()),
        // Bool/Text/List/Map → str(val) (Display de SynValue).
        other => Value::Text(other.to_string()),
    }
}

// -- Postgres: conexión, rewriter, bind, lectura --

fn is_pg_url(target: &str) -> bool {
    scheme_is(target, &["postgres://", "postgresql://"])
}

/// Una URL de servidor con el esquema en minúscula y sin espacios adelante; cualquier otra cosa (una
/// ruta de SQLite), tal cual.
fn normalize_db_url(target: &str) -> String {
    if !synsema_core::capscope::is_db_url(target) {
        return target.to_string();
    }
    let t = target.trim_start();
    match t.split_once("://") {
        Some((scheme, rest)) => format!("{}://{}", scheme.to_ascii_lowercase(), rest),
        None => t.to_string(),
    }
}

/// Ronda 4 (N2): el esquema de una URL de base, con el MISMO criterio que el gate
/// (`capscope::is_db_url`: sin distinguir mayúsculas ni espacios al principio). Si no, el gate decía
/// URL y `open` decía SQLite.
fn scheme_is(target: &str, schemes: &[&str]) -> bool {
    let l = target.trim_start().to_ascii_lowercase();
    schemes.iter().any(|s| l.starts_with(s))
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
    // v0.6.42 — bajo `serve`, el hilo que espera la red suelta su permiso de ejecución.
    let _w = synsema_core::waiting::waiting();
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
        SynValue::Secret(s) if s.is_bytes() && !s.is_sealed() => PgParam::Bytes(s.expose_bytes().to_vec()),
        SynValue::Secret(s) => PgParam::Text(s.expose().to_string()),
        SynValue::Text(s) => PgParam::Text(s.to_string()),
        // list/array (p.ej. un embedding) → texto pgvector "[a,b,c]"; en la query: `?::vector`.
        SynValue::List(l) => PgParam::Text(list_to_vector_text(&l.borrow().to_vec())),
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

fn array_to_vector_text(a: &synsema_core::types::NdArray) -> String {
    // v0.6.56: un `f32` va con su decimal más corto (pgvector guarda `float4`).
    let parts: Vec<String> = match a {
        synsema_core::types::NdArray::F32(x) => x.iter().map(|f| f.to_string()).collect(),
        _ => a.numbers_f64().iter().map(|f| f.to_string()).collect(),
    };
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
    // v0.6.42 — bajo `serve`, el hilo que espera la red suelta su permiso de ejecución.
    let _w = synsema_core::waiting::waiting();
    let rewritten = rewrite_placeholders(sql);
    let pg: Vec<PgParam> = params.iter().map(syn_to_pg).collect();
    let refs: Vec<&(dyn ToSql + Sync)> = pg.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
    let rows = client
        .query(rewritten.as_str(), &refs)
        .map_err(pg_err)?;
    // Todas las filas de una consulta tienen las mismas columnas: claves una vez (F4.4).
    let keys: Vec<Key> = match rows.first() {
        Some(r) => r.columns().iter().map(|c| Key::from(c.name())).collect(),
        None => Vec::new(),
    };
    Ok(rows.iter().map(|r| pg_row_to_syn(r, &keys)).collect())
}

fn pg_row_to_syn(row: &postgres::Row, keys: &[Key]) -> Row {
    let mut m = SynMap::with_capacity(keys.len());
    for ((i, col), k) in row.columns().iter().enumerate().zip(keys) {
        m.insert(k.clone(), pg_cell_to_syn(row, i, col.type_()));
    }
    m
}

/// Lee `Option<T>`: NULL o tipo no convertible → `None`.
/// Un `numeric` de Postgres en su formato binario (sin tope de dígitos): ndigits, weight,
/// sign, dscale y los dígitos en base 10000. NaN/±Infinity → float.
struct PgNumeric(SynValue);

impl<'a> FromSql<'a> for PgNumeric {
    fn from_sql(_ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn StdError + Sync + Send>> {
        let rd = |i: usize| -> Result<u16, Box<dyn StdError + Sync + Send>> {
            raw.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]])).ok_or_else(|| "numeric: short buffer".into())
        };
        let ndigits = rd(0)? as usize;
        let weight = rd(2)? as i16 as i64;
        let sign = rd(4)?;
        let dscale = rd(6)? as u32;
        match sign {
            0xC000 => return Ok(PgNumeric(syn_float(f64::NAN))),
            0xD000 => return Ok(PgNumeric(syn_float(f64::INFINITY))),
            0xF000 => return Ok(PgNumeric(syn_float(f64::NEG_INFINITY))),
            _ => {}
        }
        let mut d = num_bigint::BigInt::from(0);
        for k in 0..ndigits {
            d = d * 10000u32 + rd(8 + 2 * k)?;
        }
        // valor = d · 10000^(weight − ndigits + 1); con escala dscale: m = valor · 10^dscale.
        let exp10 = 4 * (weight - ndigits as i64 + 1) + dscale as i64;
        let m = if exp10 >= 0 { d * synsema_core::number::pow10_big(exp10 as u32) } else { d / synsema_core::number::pow10_big((-exp10) as u32) };
        let m = if sign == 0x4000 { -m } else { m };
        Ok(PgNumeric(syn_number(Number::decimal_from_parts(m, dscale))))
    }
    fn accepts(ty: &Type) -> bool {
        *ty == Type::NUMERIC
    }
}

fn cell_opt<'a, T: FromSql<'a>>(row: &'a postgres::Row, i: usize) -> Option<T> {
    row.try_get::<usize, Option<T>>(i).unwrap_or_default()
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
        // Cualquier precisión (numeric sin tope): el decimal exacto, grande si hace falta.
        return cell_opt::<PgNumeric>(row, i).map(|n| n.0).unwrap_or(nothing);
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
    scheme_is(target, &["mysql://"])
}

/// Mapea un error del crate `mysql` a un mensaje útil. Su `Display` ya incluye el detalle
/// del server para `MySqlError` (código + SQLSTATE + mensaje), así que `to_string()` es
/// informativo (lección M1 #2: no devolver algo opaco). Wrapper nombrado para documentarlo.
fn mysql_err(e: mysql::Error) -> String {
    e.to_string()
}

/// MySQL, un `sql_exec` sin valores: **un statement por llamada**, como en SQLite y Postgres.
///
/// El driver negocia `CLIENT_MULTI_STATEMENTS` y no deja apagarlo: por el protocolo de texto el
/// servidor corre todos los statements que haya en el texto (medido en v0.6.59: `INSERT …; COMMIT`
/// confirmaba a mano, sin pasar por `tx_guard`, que mira las primeras palabras). El protocolo
/// preparado acepta uno solo: a un texto con un segundo statement le contesta ERROR 1064 sin
/// correr nada.
///
/// El de texto queda para dos casos, los dos con UN statement:
/// - el texto no tiene un `;` (aparte del final): `mysql_single_statement`. Es el caso de casi
///   todos, y cuesta una ida y vuelta, como antes de v0.6.59; preparar un texto que la conexión
///   no tiene guardado cuesta dos (medido: 40 `INSERT` distintos tardaban el doble);
/// - el servidor ya leyó el texto entero y dice que no se prepara (ERROR 1295: el cuerpo de un
///   `CREATE PROCEDURE`, que lleva `;` adentro). Medido contra 8.0.46: con algo después del `;`
///   final, también esos dan 1064.
///
/// Ese segundo caso paga la preparación fallida cada vez: lo que no se prepara no queda guardado.
///
/// Los dos códigos se miran en la respuesta de PREPARAR, no en la de ejecutar: un procedimiento
/// puede dar el número que quiera (`SIGNAL … SET MYSQL_ERRNO = 1295`), y reintentar por texto un
/// `CALL` que ya corrió lo corre dos veces.
fn mysql_execute_one(c: &mut MysqlConn, sql: &str) -> Result<(), String> {
    if let Some(one) = mysql_single_statement(sql) {
        return c.text(one).map_err(mysql_err);
    }
    let stmt = match c.prep(sql) {
        Ok(stmt) => stmt,
        Err(mysql::Error::MySqlError(e)) if e.code == MYSQL_UNSUPPORTED_PS => return c.text(sql).map_err(mysql_err),
        Err(mysql::Error::MySqlError(e)) if e.code == MYSQL_PARSE_ERROR && sql.trim_end().trim_end_matches(';').contains(';') => {
            return Err(format!(
                "{} — if this call has more than one statement: one SQL statement per call (sql, sql_exec and sql_batch run one; before v0.6.59 a sql_exec without values ran them all in MySQL); run each statement with its own call",
                mysql::Error::MySqlError(e)
            ));
        }
        Err(e) => return Err(mysql_err(e)),
    };
    c.prepared(&stmt, mysql::Params::Empty).map_err(mysql_err)
}

/// MySQL: lee una respuesta hasta el final. Un `CALL` contesta con un resultado por cada `SELECT`
/// del procedimiento y uno más, vacío, cuando termina; si el procedimiento falla después de dar
/// un resultado, el error llega en el lugar del siguiente. Soltar la respuesta sin leerla (lo
/// que hacen `query_drop` y `exec_drop` del driver, y lo que hacía `sql` hasta v0.6.58 con lo que
/// sigue al primer resultado) descarta ese error, y el `CALL` pasaba por bueno (medido en 8.0.46).
/// Además, lo que quedó en la conexión viene en la última respuesta (`MysqlConn::observe`; medido
/// con dos resultados y un `INSERT` pendiente entre los dos).
fn mysql_finish<T: mysql::prelude::Protocol>(result: &mut mysql::QueryResult<'_, '_, '_, T>) -> Result<(), mysql::Error> {
    while let Some(set) = result.iter() {
        for row in set {
            row?;
        }
    }
    Ok(())
}

/// MySQL: el texto sin su `;` final, si no tiene ningún otro `;`. Los statements de un texto se
/// separan con `;` y con nada más, así que un texto sin ese byte es UN statement para el
/// servidor: no depende del `sql_mode` y no hay que leer literales ni comentarios como los lee
/// MySQL. Con un `;` adentro de un literal o de un comentario da `None`, y ahí decide el servidor
/// (`mysql_execute_one`).
fn mysql_single_statement(sql: &str) -> Option<&str> {
    let one = sql.trim_end();
    let one = one.strip_suffix(';').unwrap_or(one);
    (!one.contains(';')).then_some(one)
}

/// `ER_UNSUPPORTED_PS`: «This command is not supported in the prepared statement protocol yet».
const MYSQL_UNSUPPORTED_PS: u16 = 1295;
/// `ER_PARSE_ERROR`.
const MYSQL_PARSE_ERROR: u16 = 1064;

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
///
/// v0.6.59 — pide el seguimiento de estado de sesión (`MYSQL_TRACK_SESSION`). Un servidor o un
/// proxy que no lo da (no negocia la capacidad, o no conoce las variables) deja la conexión sin
/// seguimiento, y sirve igual. En los dos casos `autocommit` queda en 1.
fn mysql_connect(url: &str) -> Result<MysqlConn, String> {
    // v0.6.42 — bajo `serve`, el hilo que espera la red suelta su permiso de ejecución.
    let _w = synsema_core::waiting::waiting();
    let (clean_url, wants_tls) = split_tls_hint(url);
    let opts = mysql::Opts::from_url(&clean_url).map_err(|e| e.to_string())?;
    let mut builder = mysql::OptsBuilder::from_opts(opts)
        .tcp_connect_timeout(Some(Duration::from_secs(10)))
        .additional_capabilities(mysql::consts::CapabilityFlags::CLIENT_SESSION_TRACK);
    if wants_tls {
        builder = builder.ssl_opts(Some(mysql::SslOpts::default()));
    }
    let conn = mysql::Conn::new(builder).map_err(mysql_err)?;
    // `autocommit: false` hasta que el servidor diga otra cosa: ése es el testigo.
    let mut c = MysqlConn { conn, tracked: true, tx_state: "________".to_string(), autocommit: false };
    let asked = c.text(MYSQL_TRACK_SESSION).is_ok();
    c.tracked = asked && c.tracked && c.autocommit;
    if !asked {
        // Un `SET` que falla no asigna nada (medido en 8.0.46 con una variable que no existe):
        // `autocommit` va solo. Con `autocommit = 0` de fábrica en el servidor, lo que el
        // programa escribe fuera de una transacción no se confirmaría nunca, y desde v0.6.59 no
        // puede mandar `COMMIT` a mano.
        c.text("SET autocommit = 1").map_err(mysql_err)?;
    }
    Ok(c)
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
        SynValue::Secret(s) if !s.is_sealed() => MyV::Bytes(s.expose_bytes().to_vec()),
        SynValue::Secret(s) => MyV::Bytes(s.expose().into_owned().into_bytes()),
        other => MyV::Bytes(other.to_string().into_bytes()),
    }
}

fn mysql_query(c: &mut MysqlConn, sql: &str, params: &[SynValue]) -> Result<Vec<Row>, String> {
    let r = mysql_rows(&mut c.conn, sql, params);
    c.observe();
    r
}

fn mysql_rows(conn: &mut mysql::Conn, sql: &str, params: &[SynValue]) -> Result<Vec<Row>, String> {
    // v0.6.42 — bajo `serve`, el hilo que espera la red suelta su permiso de ejecución.
    let _w = synsema_core::waiting::waiting();
    let mut result = conn.exec_iter(sql, mysql_params(params)).map_err(mysql_err)?;
    let mut out = Vec::new();
    // Las columnas como claves una vez por consulta (F4.4); se rehacen si cambian.
    let mut keys: Vec<Key> = Vec::new();
    // Las filas del primer resultado (un `CALL` puede dar más: `mysql_finish`).
    if let Some(set) = result.iter() {
        for row_res in set {
            let row = row_res.map_err(mysql_err)?;
            let cols = row.columns(); // Arc<[Column]> (mismo orden que los valores)
            let values = row.unwrap(); // Vec<Value>, consume la fila
            if keys.len() != cols.len() || keys.iter().zip(cols.iter()).any(|(k, c)| k.as_str() != c.name_str()) {
                keys = cols.iter().map(|c| Key::from(c.name_str().as_ref())).collect();
            }
            let mut m = SynMap::with_capacity(cols.len());
            for (i, val) in values.into_iter().enumerate() {
                let col = &cols[i];
                m.insert(keys[i].clone(), mysql_cell_to_syn(val, col));
            }
            out.push(m);
        }
    }
    mysql_finish(&mut result).map_err(mysql_err)?;
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
                    match Number::parse_decimal(s.trim()) {
                        Some(d) => syn_number(d),
                        None => syn_text(s.into_owned()),
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
    scheme_is(target, &["mongodb://", "mongodb+srv://"])
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
    // v0.6.42 — bajo `serve`, el hilo que espera la red suelta su permiso de ejecución.
    let _w = synsema_core::waiting::waiting();
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
        SynValue::Secret(s) if s.is_bytes() && !s.is_sealed() => Bson::Binary(Binary { subtype: BinarySubtype::Generic, bytes: s.expose_bytes().to_vec() }),
        SynValue::Secret(s) => Bson::String(s.expose().to_string()),
        SynValue::Bytes(b) => Bson::Binary(Binary {
            subtype: BinarySubtype::Generic,
            bytes: b[..].to_vec(),
        }),
        SynValue::List(l) => Bson::Array(list_values(&l).iter().map(syn_to_bson).collect()),
        SynValue::Map(m) => Bson::Document(syn_map_to_doc(&m.borrow())),
        other => Bson::String(other.to_string()),
    }
}

/// Map de Synsema → BSON `Document`. Para la clave `_id` aplica `coerce_id` (string hex-24 →
/// ObjectId) así `mongo_find("c", {"_id": id_text})` matchea el documento real.
fn syn_map_to_doc(m: &MapObj) -> Document {
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
        SynValue::List(l) => Bson::Array(list_values(&l).iter().map(coerce_id).collect()),
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
        Bson::Decimal128(d) => match Number::parse_decimal(&d.to_string()) {
            Some(dec) => syn_number(dec),
            None => syn_text(d.to_string()),
        },
        Bson::String(s) => syn_text(s.as_str()),
        Bson::Binary(bin) => syn_bytes(bin.bytes.clone()),
        Bson::Array(a) => syn_list(a.iter().map(bson_to_syn).collect()),
        Bson::Document(d) => {
            let mut m = SynMap::new();
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
    scheme_is(target, &["redis://", "rediss://"])
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
    // v0.6.42 — bajo `serve`, el hilo que espera la base suelta su permiso de ejecución.
    let _w = synsema_core::waiting::waiting();
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
        // HB4: los bytes tal cual; un sellado es error (antes: la cadena `secret(NAME)`).
        SynValue::Secret(s) => Ok(s.expose_bytes_checked("redis")?.to_vec()),
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
            let mut m = SynMap::new();
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
fn redis_value_to_map(v: redis::Value) -> SynMap {
    use redis::Value as RV;
    let mut m = SynMap::new();
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
        Some(SynValue::List(l)) => list_values(&l).iter().cloned().collect(),
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
        .map_err(|v| Control::Error(v.into_error()))
}

// -- Helpers de args para los builtins `mongo_*` (map de Synsema ↔ BSON Document) --

/// Arg de filtro opcional (map) → BSON `Document`. None / no-map → Document vacío (match all).
fn filter_arg(v: Option<&SynValue>, ctx: &str) -> Result<Document, Control> {
    match v {
        Some(SynValue::Map(m)) => {
            reject_sealed(v.expect("Some"), ctx).map_err(err)?;
            Ok(syn_map_to_doc(&m.borrow()))
        }
        _ => Ok(Document::new()),
    }
}

/// Arg map REQUERIDO (doc de insert / update) → `Document`; error claro si no es map.
fn required_doc_arg(v: Option<&SynValue>, ctx: &str) -> Result<Document, Control> {
    match v {
        Some(SynValue::Map(m)) => {
            reject_sealed(v.expect("Some"), ctx).map_err(err)?;
            Ok(syn_map_to_doc(&m.borrow()))
        }
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
            for item in list_values(&l).iter() {
                match item {
                    SynValue::Map(m) => {
                        reject_sealed(item, ctx).map_err(err)?;
                        out.push(syn_map_to_doc(&m.borrow()))
                    }
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
    // v0.6.59 — la transacción abierta de ESTE intérprete (`sql_transaction`): mientras hay una, sus
    // `sql*` van por la conexión que ella tiene.
    let tx: TxCell = Rc::new(RefCell::new(None));

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
                // Ronda 2 (A4): la URI `file:` se rechaza ANTES del gate, con su propio mensaje (la
                // forma que se abre la vuelve a mirar `open`).
                let norm = synsema_core::capscope::normalize_path(&target);
                if (norm.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("file:")) || norm.contains("://"))
                    && !synsema_capabilities::model::is_db_url(&target)
                {
                    return Err(err(format!(
                        "db_open: {:?} is not a database path (a `file:` URI or a `://` URL that is not a known server); open the database by its path, e.g. db_open(\"./data/app.db\")",
                        target
                    )));
                }
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

    // json_encode/json_for_script/json_decode: MOVIDOS a json.rs (register_json_builtins)
    // — builtins generales puros (sin capability), existen también en el perfil wasm.

    // sql(query, params?) → lista de mapas-fila
    {
        let db = db.clone();
        let caps = caps.clone();
        let tx = tx.clone();
        interp.register_builtin(
            "sql",
            -1,
            Rc::new(move |_i, args, _loc| {
                let query = raw_str(args.first().ok_or_else(|| err("missing argument"))?);
                let params = params_arg(args.get(1));
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "sql()")?;
                }
                let rows = with_sql(&db, &tx, |c| c.query(&query, &params)).map_err(|e| sql_driver_error("sql", e))?;
                Ok(syn_list(rows.into_iter().map(syn_map).collect()))
            }),
        );
    }

    // sql_exec(statement, params?) → {rows_affected, last_id}
    {
        let db = db.clone();
        let caps = caps.clone();
        let tx = tx.clone();
        interp.register_builtin(
            "sql_exec",
            -1,
            Rc::new(move |_i, args, _loc| {
                let stmt = raw_str(args.first().ok_or_else(|| err("missing argument"))?);
                let params = params_arg(args.get(1));
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "sql_exec()")?;
                }
                // Con RETURNING el statement devuelve filas: el driver de SQLite lo EJECUTA y recién
                // después se queja. Ahí se rechaza antes, para que no quede escrito sin que el
                // programa lo sepa. Postgres y MySQL lo ejecutan bien y devuelven la cuenta.
                if db.read(|m| m.default_dialect()) == Some(SqlDialect::Sqlite)
                    && sql_code_words(&stmt, SqlDialect::Sqlite).any(|w| w.eq_ignore_ascii_case("RETURNING"))
                {
                    return Err(err("sql_exec: this statement returns rows (RETURNING) — run it with sql(statement, params) to get them (nothing was executed)"));
                }
                let (affected, last_id) = with_sql(&db, &tx, |c| c.execute(&stmt, &params)).map_err(|e| sql_driver_error("sql_exec", e))?;
                let mut m = SynMap::new();
                m.insert("rows_affected", syn_int(affected));
                m.insert("last_id", syn_int(last_id));
                Ok(syn_map(m))
            }),
        );
    }

    // sql_tables() → lista de nombres
    {
        let db = db.clone();
        let caps = caps.clone();
        let tx = tx.clone();
        interp.register_builtin(
            "sql_tables",
            0,
            Rc::new(move |_i, _args, _loc| {
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "sql_tables()")?;
                }
                let tables = with_sql(&db, &tx, |c| c.tables()).map_err(err)?;
                Ok(syn_list(tables.iter().map(|t| syn_text(t.as_str())).collect()))
            }),
        );
    }

    // sql_batch(statement, params_list) → {rows_affected}
    {
        let db = db.clone();
        let caps = caps.clone();
        let tx = tx.clone();
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
                        list_values(&l).iter().map(|p| params_arg(Some(p))).collect()
                    }
                    _ => Vec::new(),
                };
                // Como `sql_exec`: en SQLite un RETURNING escribe la fila y después falla, así que
                // se rechaza ANTES de ejecutar ninguna del batch.
                if db.read(|m| m.default_dialect()) == Some(SqlDialect::Sqlite)
                    && sql_code_words(&stmt, SqlDialect::Sqlite).any(|w| w.eq_ignore_ascii_case("RETURNING"))
                {
                    return Err(err("sql_batch: this statement returns rows (RETURNING) — run it with sql(statement, params) for each row to get them (nothing was executed)"));
                }
                let affected = with_sql(&db, &tx, |c| c.execute_many(&stmt, &params_list)).map_err(|e| sql_driver_error("sql_batch", e))?;
                let mut m = SynMap::new();
                m.insert("rows_affected", syn_int(affected));
                Ok(syn_map(m))
            }),
        );
    }

    // paged(query, params?) → marcador de paginación lazy para `serve` (_PAGED).
    {
        let db = db.clone();
        let caps = caps.clone();
        let tx = tx.clone();
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
                let txf = tx.clone();
                let fetch = move |limit: Option<i64>, offset: i64| -> Result<(Vec<SynValue>, i64), String> {
                    with_sql(&dbf, &txf, |m| match limit {
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
                Ok(SynValue::Server(synsema_core::types::Obj::new(ServerValue::Paged(Rc::new(fetch)))))
            }),
        );
    }

    // sql_transaction(task) → lo que devuelve la task (v0.6.59). La task corre con la conexión
    // default para ella sola: COMMIT si devuelve, ROLLBACK si sale de cualquier otra forma.
    // Adentro de otra, es un savepoint. Diseño: specs/v0.6.59-transacciones-diseno.md.
    {
        let db = db.clone();
        let caps = caps.clone();
        let tx = tx.clone();
        interp.register_builtin(
            "sql_transaction",
            1,
            Rc::new(move |i, args, loc| {
                let task = match args.first() {
                    Some(t @ (SynValue::Task(_) | SynValue::Builtin(_))) => t.clone(),
                    _ => return Err(err(TX_USAGE)),
                };
                // La task se llama sin argumentos, y una llamada interna no chequea la aridad: un
                // parámetro sin default quedaría en `nothing` y la transacción correría igual.
                if let SynValue::Task(t) = &task {
                    if let Some(p) = t.parameters.iter().find(|p| p.default.is_none()) {
                        let who = if t.name == "<lambda>" { "this lambda".to_string() } else { format!("task '{}'", t.name) };
                        return Err(err(format!(
                            "sql_transaction calls its task with no arguments, and {} needs '{}' — pass the values in a lambda: sql_transaction(() => my_task(a, b))",
                            who, p.name
                        )));
                    }
                }
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "sql_transaction()")?;
                }
                let scope = TxScope::open(&db, &tx).map_err(err)?;
                let r = i.call_callback(task, Vec::new(), loc);
                scope.finish(r, err)
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
                let filter = filter_arg(args.get(1), "mongo_find")?;
                // sort/fields también pasan por la conversión a BSON (auditoría v0.6.44, A1).
                if let Some(o) = args.get(2) {
                    reject_sealed(o, "mongo_find").map_err(err)?;
                }
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
                let filter = filter_arg(args.get(1), "mongo_find_one")?;
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
                let filter = filter_arg(args.get(1), "mongo_update")?;
                let update = required_doc_arg(args.get(2), "mongo_update")?;
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "mongo_update()")?;
                }
                let (matched, modified) =
                    db.write(|m| m.mongo_update(&coll, filter, update)).map_err(err)?;
                let mut map = SynMap::new();
                map.insert("matched", syn_int(matched));
                map.insert("modified", syn_int(modified));
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
                let filter = filter_arg(args.get(1), "mongo_delete")?;
                if let Some(p) = db.read(|m| m.default_path()) {
                    require_db(&caps, &p, "mongo_delete()")?;
                }
                let deleted = db.write(|m| m.mongo_delete(&coll, filter)).map_err(err)?;
                let mut map = SynMap::new();
                map.insert("deleted", syn_int(deleted));
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
                let filter = filter_arg(args.get(1), "mongo_count")?;
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
                    Some(SynValue::List(l)) => list_values(&l).iter().cloned().collect(),
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

    // ---- v0.6.59: transacciones (specs/v0.6.59-transacciones-diseno.md, la tabla de casos) ----

    fn tx_db() -> (Rc<RefCell<DatabaseManager>>, TxCell) {
        let mut m = DatabaseManager::new();
        m.open(":memory:", "memory").unwrap();
        m.execute("CREATE TABLE t (who TEXT)", &[]).unwrap();
        (Rc::new(RefCell::new(m)), Rc::new(RefCell::new(None)))
    }

    fn shared_db() -> Arc<Mutex<DatabaseManager>> {
        let mut m = DatabaseManager::new();
        m.open(":memory:", "memory").unwrap();
        m.execute("CREATE TABLE t (who TEXT)", &[]).unwrap();
        Arc::new(Mutex::new(m))
    }

    fn ins<H: DbHandle>(db: &H, tx: &TxCell, who: &str) -> Result<(), String> {
        with_sql(db, tx, |c| c.execute("INSERT INTO t VALUES (?)", &[syn_text(who)])).map(|_| ())
    }

    fn whos<H: DbHandle>(db: &H, tx: &TxCell) -> Vec<String> {
        with_sql(db, tx, |c| c.query("SELECT who FROM t ORDER BY rowid", &[]))
            .unwrap()
            .iter()
            .map(|r| r.get("who").map(|v| v.to_string()).unwrap_or_default())
            .collect()
    }

    fn tx_tmp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("synsema-v0659-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Mutación M17: todo builtin que registra este módulo existe en el perfil puro y en wasm como
    /// un stub que dice por qué no está (`pure::DB`). Sin este test, un builtin de base nuevo podía
    /// faltar ahí (y dar `Undefined variable` en vez del mensaje del perfil) sin que nada lo notara.
    #[test]
    fn v0659_every_database_builtin_is_a_stub_in_the_pure_profile() {
        fn builtins(interp: &Interpreter) -> std::collections::BTreeSet<String> {
            let env = interp.global_env.borrow();
            env.bindings.iter().filter(|(_, v)| matches!(v, SynValue::Builtin(_))).map(|(k, _)| k.to_string()).collect()
        }
        let bare = builtins(&Interpreter::new());
        let interp = Interpreter::new();
        let caps = Rc::new(RefCell::new(CapabilitySet::new("test")));
        register_database_builtins(&interp, Rc::new(RefCell::new(DatabaseManager::new())), caps);
        let ours: Vec<String> = builtins(&interp).difference(&bare).cloned().collect();
        assert!(ours.len() > 20 && ours.iter().any(|n| n == "sql_transaction"), "{:?}", ours);
        let missing: Vec<&String> = ours.iter().filter(|n| !crate::pure::DB.contains(&n.as_str())).collect();
        assert!(missing.is_empty(), "builtins de base sin stub en `pure::DB`: {:?}", missing);
    }

    /// Casos 1 y 2: confirma si la task devuelve, deshace si da error, y la conexión vuelve al gestor.
    #[test]
    fn v0659_a_transaction_commits_on_return_and_rolls_back_on_error() {
        let (db, tx) = tx_db();
        let s = TxScope::open(&db, &tx).unwrap();
        assert!(db.borrow().lent.is_some(), "la transacción tiene la conexión");
        ins(&db, &tx, "a").unwrap();
        assert_eq!(s.finish(Ok::<i32, String>(7), |e| e), Ok(7));
        assert!(db.borrow().lent.is_none() && tx.borrow().is_none());
        assert_eq!(whos(&db, &tx), ["a"]);

        let s = TxScope::open(&db, &tx).unwrap();
        ins(&db, &tx, "b").unwrap();
        assert_eq!(s.finish(Err::<i32, String>("boom".into()), |e| e), Err("boom".to_string()));
        assert_eq!(whos(&db, &tx), ["a"], "lo de la task que falló no queda");
        assert!(db.borrow().lent.is_none() && tx.borrow().is_none());
    }

    /// Caso 4 (regla 2): un statement que falla hace fallar la transacción aunque la task lo atrape.
    #[test]
    fn v0659_a_failed_statement_fails_its_transaction() {
        let (db, tx) = tx_db();
        let s = TxScope::open(&db, &tx).unwrap();
        ins(&db, &tx, "a").unwrap();
        let first = with_sql(&db, &tx, |c| c.execute("INSERT INTO no_such_table VALUES (1)", &[])).unwrap_err();
        assert!(first.contains("no_such_table"), "{}", first);
        let next = ins(&db, &tx, "b").unwrap_err();
        assert!(
            next.starts_with("sql_transaction: a statement failed inside this transaction") && next.ends_with(&first),
            "{}",
            next
        );
        assert_eq!(s.finish(Ok::<(), String>(()), |e| e), Err(next));
        assert!(whos(&db, &tx).is_empty());
    }

    /// Casos 5, 6 y 7: adentro de otra es un savepoint.
    #[test]
    fn v0659_a_nested_transaction_is_a_savepoint() {
        let (db, tx) = tx_db();
        // 5: la de adentro falla y la de afuera sigue.
        let outer = TxScope::open(&db, &tx).unwrap();
        ins(&db, &tx, "a").unwrap();
        let inner = TxScope::open(&db, &tx).unwrap();
        ins(&db, &tx, "b").unwrap();
        assert_eq!(inner.finish(Err::<(), String>("x".into()), |e| e), Err("x".to_string()));
        assert_eq!(whos(&db, &tx), ["a"]);
        ins(&db, &tx, "c").unwrap();
        outer.finish(Ok::<(), String>(()), |e| e).unwrap();
        assert_eq!(whos(&db, &tx), ["a", "c"]);
        // 5, con un statement que falla adentro: la de adentro da el error y la de afuera queda sana.
        let outer = TxScope::open(&db, &tx).unwrap();
        let inner = TxScope::open(&db, &tx).unwrap();
        with_sql(&db, &tx, |c| c.execute("INSERT INTO no_such_table VALUES (1)", &[])).unwrap_err();
        let e = inner.finish(Ok::<(), String>(()), |e| e).unwrap_err();
        assert!(e.starts_with("sql_transaction: a statement failed inside this transaction"), "{}", e);
        ins(&db, &tx, "d").unwrap();
        outer.finish(Ok::<(), String>(()), |e| e).unwrap();
        assert_eq!(whos(&db, &tx), ["a", "c", "d"]);
        // 6 y 7: las dos devuelven y confirma la de afuera; si la de afuera falla, se deshace todo.
        let outer = TxScope::open(&db, &tx).unwrap();
        let inner = TxScope::open(&db, &tx).unwrap();
        ins(&db, &tx, "e").unwrap();
        inner.finish(Ok::<(), String>(()), |e| e).unwrap();
        assert_eq!(whos(&db, &tx), ["a", "c", "d", "e"]);
        outer.finish(Err::<(), String>("y".into()), |e| e).unwrap_err();
        assert_eq!(whos(&db, &tx), ["a", "c", "d"]);
        let outer = TxScope::open(&db, &tx).unwrap();
        let inner = TxScope::open(&db, &tx).unwrap();
        ins(&db, &tx, "f").unwrap();
        inner.finish(Ok::<(), String>(()), |e| e).unwrap();
        outer.finish(Ok::<(), String>(()), |e| e).unwrap();
        assert_eq!(whos(&db, &tx), ["a", "c", "d", "f"]);
    }

    /// Casos 8 y 9: el control de transacciones a mano se rechaza por las primeras palabras de código.
    #[test]
    fn v0659_hand_made_transaction_control_is_refused() {
        use SqlDialect::{Mysql, Postgres, Sqlite};
        let refused = |sql: &str, d: SqlDialect| assert_eq!(tx_guard(sql, d, false), Err(TX_BY_HAND.to_string()), "{:?} {:?}", sql, d);
        let allowed = |sql: &str, d: SqlDialect| assert_eq!(tx_guard(sql, d, false), Ok(()), "{:?} {:?}", sql, d);
        for d in [Sqlite, Postgres, Mysql] {
            for sql in [
                "BEGIN",
                "begin immediate",
                "  \n\tCommit",
                "ROLLBACK",
                "rollback to x",
                "SAVEPOINT a",
                "RELEASE a",
                "END",
                "ABORT",
                "START TRANSACTION",
                "start\n transaction read only",
                "PREPARE TRANSACTION 'x'",
                "-- nota\nBEGIN",
                "/* nota */ COMMIT",
                "/* a */ /* b */\n-- c\n ROLLBACK",
                ";BEGIN",
                "(BEGIN",
                "\u{b}BEGIN",
                "BEGIN;",
            ] {
                refused(sql, d);
            }
            for sql in [
                "SELECT 'BEGIN'",
                "INSERT INTO t VALUES ('COMMIT')",
                "SELECT 1 /* BEGIN */",
                "SELECT 1 -- COMMIT",
                "CREATE TRIGGER g AFTER INSERT ON t BEGIN SELECT 1; END",
                "UPDATE t SET who = 'x' WHERE who = 'ROLLBACK'",
                "START",
                "ENDING",
                "BEGINNING",
                "",
                "/* sólo un comentario",
            ] {
                allowed(sql, d);
            }
        }
        // MySQL: `XA`, `SET autocommit`, `# …` y los comentarios que MySQL EJECUTA.
        for sql in [
            "XA START 'a'",
            "SET autocommit = 0",
            "set session AUTOCOMMIT=0",
            "SET @@autocommit=0",
            "SET sql_mode='', autocommit=0",
            "# nota\nBEGIN",
            "/*! START TRANSACTION */",
            "/*!50000 BEGIN */",
            "/*M! COMMIT */",
            "/*! SET */ autocommit=0",
            "SET /*! autocommit=0 */",
            // Ronda 4, medido en 8.0.46: el servidor acepta el nombre entre comillas invertidas.
            // `autocommit` cuenta en cualquier parte del texto de un `SET`.
            "SET `autocommit` = 0",
            "SET @@`autocommit` = 0",
            "SET @@session.`AutoCommit` = 0",
            "SET @a = 1, `autocommit` = 0",
            "SET @x = 'autocommit'",
            // Ronda 4, medido en 8.0.46: un comentario con una versión que el servidor no
            // ejecuta. El statement se lee de las dos maneras y vale la peor.
            "/*!99999 SELECT */ COMMIT",
            "/*!999999 SELECT */ COMMIT",
            "/*!99999 SELECT 1 */ BEGIN",
            "/*M! SELECT */ ROLLBACK",
            "/*!99999 SELECT */ SET autocommit = 0",
            "/*!99999 SELECT */ XA START 'a'",
            "/*!99999 SELECT */ /*! COMMIT */",
            "/*!50000 XA */ START 'a'",
            // El cierre del comentario no corta el statement (medido en 8.0.46).
            "/*! START */ TRANSACTION",
            "/*!50000 START */ TRANSACTION",
            "/*! START */ /*! TRANSACTION */",
            "/*! PREPARE */ TRANSACTION 'x'",
            "START /*!99999 x */ TRANSACTION",
            "START /*!50000 TRANSACTION */",
            // La segunda palabra no se sabe: `START` cuenta como `START TRANSACTION`.
            "START /*!99999 TRANSACTION */ REPLICA",
            // (En 8.0 esto es `START TRANSACTION`, y no lo dice ninguna de las dos lecturas.)
            "START /*!99999 x */ /*!50000 TRANSACTION */",
            "PREPARE /*M! TRANSACTION */ s FROM 'x'",
        ] {
            refused(sql, Mysql);
        }
        for sql in [
            "SET sql_mode = ''",
            "SELECT 'SET autocommit=0'",
            "/*! SELECT 1 */",
            "SELECT 'EXECUTE s'",
            "DEALLOCATE PREPARE s",
            // `autocommit` sólo cuenta en un `SET`.
            "SELECT autocommit FROM settings",
            "INSERT INTO t VALUES ('autocommit')",
            // Un comentario ejecutable después de la primera palabra no cambia qué statement es.
            "SELECT /*!80000 SQL_NO_CACHE */ 1",
            "SELECT /*! STRAIGHT_JOIN */ a FROM t",
            "INSERT /*!50000 IGNORE */ INTO t VALUES (1)",
            "SELECT 1 /*!99999 x */",
            "SELECT 1 /*M! x */",
            "CREATE /*!50000 TEMPORARY */ TABLE x (a INT)",
            // Sin versión lo ejecuta cualquier servidor: es código, y la primera palabra se sabe.
            "/*! SELECT */ 1",
            "/*! INSERT */ /*!50000 IGNORE */ INTO t VALUES (1)",
        ] {
            allowed(sql, Mysql);
        }
        // Un comentario que sólo algunos servidores ejecutan, antes de la primera palabra: el
        // motor no sabe qué statement es (ni si es un `CALL`), y no lo corre. Adentro y afuera.
        for sql in [
            "/*!99999 SELECT */ CALL p()",
            "/*!80000 SELECT 1 */",
            "/*!40101 SET NAMES utf8 */",
            "/*M! SELECT 1 */",
            "/*M!100100 SELECT 1 */",
            "/*!99999 x */ /*!50000 y */ SELECT 1",
            "-- nota\n/*!50000 SELECT */ SELECT 1",
            "(/*!50000 SELECT */ SELECT 1)",
            "/*! /*!99999 SELECT */ DO 1 */",
            "/*!99999 x */",
        ] {
            for in_tx in [false, true] {
                assert_eq!(tx_guard(sql, Mysql, in_tx), Err(MYSQL_COMMENT_FIRST.to_string()), "{:?} {}", sql, in_tx);
            }
        }
        // En SQLite y Postgres `/*! … */` es un comentario como cualquier otro.
        for d in [Sqlite, Postgres] {
            refused("/*!99999 SELECT */ COMMIT", d);
            allowed("/*!99999 COMMIT */ SELECT 1", d);
            allowed("/*!80000 SELECT 1 */", d);
        }
        // En Postgres `SET autocommit` no abre nada: el servidor no tiene esa variable.
        allowed("SET autocommit = 0", Postgres);
        // MySQL: `PREPARE` y `EXECUTE` de SQL corren un statement que está en un texto (medido:
        // `PREPARE s FROM 'COMMIT'` + `EXECUTE s` confirma). Adentro y afuera de una transacción.
        for sql in [
            "PREPARE s FROM 'COMMIT'",
            "prepare s from @q",
            "EXECUTE s",
            "execute s using @a",
            "/*! EXECUTE */ s",
            "-- nota\nEXECUTE s",
        ] {
            for in_tx in [false, true] {
                assert_eq!(tx_guard(sql, Mysql, in_tx), Err(MYSQL_SQL_PREPARE.to_string()), "{:?} {}", sql, in_tx);
            }
        }
        // En Postgres `PREPARE` sólo admite SELECT/INSERT/UPDATE/DELETE/MERGE/VALUES (medido).
        allowed("PREPARE s AS SELECT 1", Postgres);
        allowed("EXECUTE s", Postgres);
        allowed("EXECUTE s", Sqlite);
    }

    /// MySQL: un `CALL` es el statement que el motor no ve por dentro; sólo ahí se mira el estado.
    #[test]
    fn v0659_mysql_call_is_the_opaque_statement() {
        for sql in [
            "CALL p()",
            "call p(1, 2)",
            "  \n\tCall p()",
            "/*! CALL */ p()",
            "-- nota\nCALL p()",
            "# nota\nCALL p()",
            "(CALL p())",
            // Ronda 4: en cualquiera de las dos lecturas (`tx_guard` rechaza las dos primeras).
            "/*!99999 SELECT */ CALL p()",
            "/*!50000 CALL */ p()",
            "CALL /*!99999 x */ p()",
        ] {
            assert!(mysql_opaque(sql), "{:?}", sql);
        }
        for sql in ["SELECT 'CALL p()'", "CALLER", "INSERT INTO t VALUES ('CALL')", "SELECT 1 /* CALL p() */", "", "DO 1"] {
            assert!(!mysql_opaque(sql), "{:?}", sql);
        }
        // SQLite no tiene procedimientos y Postgres rechaza el control adentro de uno: no se mira.
        let mut sqlite = Backend::Sqlite(Connection::open_in_memory().unwrap());
        assert!(!sqlite.opaque("CALL p()"));
        for ok in [true, false] {
            assert_eq!(
                sqlite.close_stray_transaction(true, ok, Some(true)),
                Stray { left: Ok(false), autocommit_off: false, clean: true },
                "sin transacción abierta no hay nada que deshacer"
            );
            assert_eq!(sqlite.mysql_left_by_call(ok), Ok((TxLeft::None, false)), "mirar lo que dejó un CALL es de MySQL");
        }
    }

    /// Ronda 3 (B-r3-1): el estado que informa MySQL después de un `CALL`, tal como se midió en
    /// 8.0.46. Es un error lo que el `ROLLBACK` deshace (una `W`) y lo que se abrió a propósito
    /// (una `T`); una lectura con `autocommit = 0` no: cerrarla no pierde nada.
    #[test]
    fn v0659_mysql_tracked_state_after_a_call() {
        for (state, left) in [
            ("________", TxLeft::None),
            // `SET autocommit = 0; START TRANSACTION; INSERT; COMMIT; SELECT`: el patrón de siempre.
            ("I_R___S_", TxLeft::NothingToUndo),
            // `SET autocommit = 0` y una escritura en una tabla sin transacciones (MyISAM).
            ("I__w____", TxLeft::NothingToUndo),
            ("I_______", TxLeft::NothingToUndo),
            // `SET autocommit = 0; INSERT` sin confirmar; un `DELETE` que no borra; `FOR UPDATE`.
            ("I___W___", TxLeft::Open),
            ("I___W_S_", TxLeft::Open),
            ("I_R_W_S_", TxLeft::Open),
            // `START TRANSACTION`, con lo que sea adentro (también nada).
            ("T_______", TxLeft::Open),
            ("T_R___S_", TxLeft::Open),
            ("T___W___", TxLeft::Open),
            ("T__w____", TxLeft::Open),
            // Ronda 4: tablas bloqueadas con `LOCK TABLES`, sin transacción.
            ("_______L", TxLeft::None),
            ("T______L", TxLeft::Open),
            ("I___W__L", TxLeft::Open),
            ("___w___L", TxLeft::Open),
            ("______L", TxLeft::Open),
            // Lo que no se reconoce cuenta como abierta.
            ("", TxLeft::Open),
            ("X_______", TxLeft::Open),
            ("_R______", TxLeft::Open),
            ("____W___", TxLeft::Open),
            ("i_______", TxLeft::Open),
        ] {
            assert_eq!(mysql_tx_left(state, false), left, "{:?}", state);
        }
        // Una implícita con `autocommit` en 1 no existe: tampoco se reconoce. Lo demás no cambia.
        for (state, left) in [
            ("________", TxLeft::None),
            ("I_R___S_", TxLeft::Open),
            ("I__w____", TxLeft::Open),
            ("I___W___", TxLeft::Open),
            ("T_______", TxLeft::Open),
            ("T___W___", TxLeft::Open),
        ] {
            assert_eq!(mysql_tx_left(state, true), left, "{:?} con autocommit en 1", state);
        }
    }

    /// Ronda 4: la red de fondo. Después de un statement que no es un `CALL`, lo que informó el
    /// servidor dice si abrió una transacción o apagó `autocommit`, lo haya escrito como lo haya
    /// escrito; y adentro de `sql_transaction`, si la terminó.
    #[test]
    fn v0659_mysql_what_the_server_reports_after_a_statement() {
        // Afuera, con seguimiento y un statement que corrió.
        for (state, autocommit, left) in [
            ("________", true, (TxLeft::None, false)),
            // `LOCK TABLES`: no es una transacción.
            ("_______L", true, (TxLeft::None, false)),
            // Un `START TRANSACTION` a mano.
            ("T_______", true, (TxLeft::Open, false)),
            ("T___W___", true, (TxLeft::Open, false)),
            // `autocommit` apagado a mano, sin nada después.
            ("________", false, (TxLeft::None, true)),
            ("I___W___", false, (TxLeft::Open, true)),
            ("I_R___S_", false, (TxLeft::NothingToUndo, true)),
            // Un estado que no se reconoce y no empieza con `T` ni con `I`: no se deshace nada.
            ("_R______", true, (TxLeft::None, false)),
            ("", true, (TxLeft::None, false)),
            ("X_______", true, (TxLeft::None, false)),
        ] {
            assert_eq!(mysql_statement_left(Some((state, autocommit)), true, Some(true)), left, "{:?} {}", state, autocommit);
        }
        // Un statement que falló: no se mira lo anotado (un ERR no informa nada).
        assert_eq!(mysql_statement_left(Some(("T___W___", false)), false, Some(true)), (TxLeft::None, false));
        // Sin seguimiento sólo se sabe lo que se leyó después de un `SET`.
        assert_eq!(mysql_statement_left(None, true, Some(true)), (TxLeft::None, false));
        assert_eq!(mysql_statement_left(None, true, Some(false)), (TxLeft::None, true));
        assert_eq!(mysql_statement_left(None, true, None), (TxLeft::None, false));
        assert_eq!(mysql_statement_left(None, false, Some(false)), (TxLeft::None, true));
        // Con seguimiento, lo leído ya está en lo anotado.
        assert_eq!(mysql_statement_left(Some(("________", false)), true, Some(false)), (TxLeft::None, true));

        // Adentro: la transacción sigue.
        for (before, after) in [
            ("T_______", "T_______"),
            ("T_______", "T___W___"),
            ("T_R___S_", "T_R_W_S_"),
            ("T_R_W_S_", "T_RwWsS_"),
            ("T___W___", "T___W___"),
            // Las marcas que no son de lectura ni de escritura no cuentan.
            ("T___W_S_", "T___W___"),
            ("T___W__L", "T___W___"),
            // No se sabía que hubiera una transacción: no se mira.
            ("________", "________"),
            ("________", "T_______"),
            ("I___W___", "________"),
            ("", "________"),
        ] {
            assert!(!mysql_tx_ended(before, after), "{:?} -> {:?}", before, after);
        }
        // Adentro: terminó.
        for (before, after) in [
            // `COMMIT`, `ROLLBACK`, un DDL.
            ("T_______", "________"),
            ("T___W___", "________"),
            // Con `autocommit` apagado, lo que sigue a un `COMMIT` es una implícita.
            ("T___W___", "I___W___"),
            // `COMMIT AND CHAIN`, `START TRANSACTION`: otra transacción, sin las marcas.
            ("T___W___", "T_______"),
            ("T_R_W_S_", "T___W___"),
            ("T_RwWsS_", "T_R_W_S_"),
            ("T_r_____", "T_______"),
            ("T___W___", ""),
            ("T___W___", "T"),
        ] {
            assert!(mysql_tx_ended(before, after), "{:?} -> {:?}", before, after);
        }
        // Sólo en una conexión MySQL con seguimiento.
        let sqlite = Backend::Sqlite(Connection::open_in_memory().unwrap());
        assert_eq!(sqlite.mysql_tracked_state(), None);
        assert!(!sqlite.mysql_tx_ended_since("T___W___"));
        assert_eq!(sqlite.mysql_left_by_statement(true, Some(false)), (TxLeft::None, false));
    }

    /// Ronda 4 (B-r4-2, N-r4-1): después de un `SET` del que el texto no alcanza para decir que
    /// no toca las variables del motor, se le pregunta al servidor cómo quedaron. Sólo un `SET`:
    /// una tabla que se llama `session_tracking` no cambia nada.
    #[test]
    fn v0659_mysql_a_set_the_engine_cannot_read() {
        for sql in [
            "SET SESSION session_track_transaction_info = 'OFF'",
            "set session_track_system_variables = ''",
            "SET @@SESSION.Session_Track_Schema = 0",
            "SET @@session.`session_track_gtids` = 'OFF'",
            "/*! SET session_track_state_change = 1 */",
            "/*!50000 SET */ session_track_schema = 0",
            "SET @n = (SELECT COUNT(*) FROM session_tracking)",
            // Medido en 8.0.46: el servidor iguala estas letras a su letra base.
            "SET autocomm\u{ed}t = 0",
            "SET AUTOCOMM\u{cd}T = 0",
            "SET SESSION sessi\u{f3}n_track_transaction_info = 'OFF'",
            "SET \u{17f}ession_track_system_variables = ''",
            "SET sess\u{131}on_track_transaction_info = 'OFF'",
            "SET SESS\u{130}ON_TRACK_TRANSACTION_INFO = 'OFF'",
            // Y lo que no toca nada, pero el texto no alcanza para saberlo.
            "SET @a\u{f1}o = 1",
            "SET @x = 'caf\u{e9}'",
        ] {
            assert!(mysql_unread_set(sql), "{:?}", sql);
        }
        for sql in [
            "SET SESSION sql_mode = ''",
            "SET @a = 1",
            "SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE",
            // B-r4-2: no es un `SET`.
            "INSERT INTO session_tracking VALUES (1)",
            "SELECT * FROM user_session_tracker",
            "SELECT 'session_track_transaction_info'",
            "CREATE TABLE session_tracks (a INT)",
            "INSERT INTO t VALUES ('a\u{f1}o')",
            "CALL track_session()",
            "UPDATE t SET a = 'caf\u{e9}'",
            "",
        ] {
            assert!(!mysql_unread_set(sql), "{:?}", sql);
        }
        assert!(mysql_text_has("SET `AutoCommit` = 0", "autocommit"));
        assert!(mysql_text_has("x session_TRACK y", "session_track"));
        assert!(!mysql_text_has("SET autocomm\u{ed}t = 0", "autocommit"), "con otra letra no es el mismo texto: eso lo ve la lectura");
        assert!(!mysql_text_has("auto commit", "autocommit") && !mysql_text_has("", "autocommit"));
        // Sólo cuenta en una conexión MySQL: en las demás no hay nada que leer.
        let mut sqlite = Backend::Sqlite(Connection::open_in_memory().unwrap());
        assert!(!sqlite.unread_set("SET session_track_transaction_info = 'OFF'"));
        assert_eq!(sqlite.mysql_autocommit(), None);
        assert_eq!(sqlite.mysql_after_unread_set(), Some(true));
    }

    /// Ronda 4: cómo empieza un statement de MySQL, en las dos lecturas (`MysqlHead`).
    #[test]
    fn v0659_mysql_head_reads_a_statement_both_ways() {
        let head = |sql: &str| {
            let h = mysql_head(sql);
            (h.all.join(" "), h.sure.join(" "), h.gap)
        };
        let s = |a: &str, b: &str, gap: [bool; 2]| (a.to_string(), b.to_string(), gap);
        assert_eq!(head("select a from t"), s("SELECT A", "SELECT A", [false, false]));
        assert_eq!(head("COMMIT"), s("COMMIT ", "COMMIT ", [false, false]));
        assert_eq!(head(""), s(" ", " ", [false, false]));
        // Un comentario común no es un hueco.
        assert_eq!(head("/* nota */ SELECT /* otra */ a"), s("SELECT A", "SELECT A", [false, false]));
        // Sin versión: código en las dos lecturas.
        assert_eq!(head("/*! SELECT */ a"), s("SELECT A", "SELECT A", [false, false]));
        // Con versión, o de MariaDB: código en una, comentario en la otra, y el hueco donde cae.
        assert_eq!(head("/*!99999 SELECT */ COMMIT"), s("SELECT COMMIT", "COMMIT ", [true, false]));
        assert_eq!(head("/*M! SELECT */ COMMIT"), s("SELECT COMMIT", "COMMIT ", [true, false]));
        // El cierre de un comentario abierto no corta la lectura.
        assert_eq!(head("/*! START */ TRANSACTION"), s("START TRANSACTION", "START TRANSACTION", [false, false]));
        assert_eq!(head("/*! INSERT */ /*!50000 IGNORE */ INTO t"), s("INSERT IGNORE", "INSERT INTO", [false, true]));
        assert_eq!(head("SELECT /*!80000 x */ a"), s("SELECT X", "SELECT A", [false, true]));
        assert_eq!(head("SELECT a /*!80000 x */"), s("SELECT A", "SELECT A", [false, false]));
        assert_eq!(head("/*!80000 x */"), s("X ", " ", [true, false]));
        assert_eq!(head("SELECT /*!80000 x */"), s("SELECT X", "SELECT ", [false, true]));
        // Uno con versión adentro de uno sin versión.
        assert_eq!(head("/*! /*!99999 SELECT */ DO 1 */").2, [true, false]);
        assert_eq!(mysql_executable_comment(b"/*! x"), Some((3, true)));
        assert_eq!(mysql_executable_comment(b"/*!5 x"), Some((3, false)));
        assert_eq!(mysql_executable_comment(b"/*M! x"), Some((4, false)));
        assert_eq!(mysql_executable_comment(b"/* ! x"), None);
        assert_eq!(mysql_executable_comment(b"/*"), None);
    }

    /// Ronda 4 (B-r4-1): una conexión de la que el motor no pudo sacar la transacción que quedó
    /// abierta se cierra. La base sigue siendo la default, sin conexión: no se pasa en silencio a
    /// otra, y `db_open` la vuelve a abrir.
    #[test]
    fn v0659_a_connection_that_could_not_be_cleaned_is_closed() {
        let mut db = DatabaseManager::new();
        let first = db.open(":memory:", "memory").unwrap();
        let dir = std::env::temp_dir().join(format!("synsema-v0659-broken-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let other = db.open(dir.join("other.db").to_str().unwrap(), "readwrite").unwrap();
        assert_eq!(db.default_path(), Some(first.clone()));
        // Lo normal: nada se cierra.
        db.with_default(|c| c.execute("CREATE TABLE t (a INT)", &[])).unwrap();
        assert_eq!(db.query("SELECT COUNT(*) AS c FROM t", &[]).unwrap().len(), 1);
        // La conexión quedó rota: sale el resultado del statement, y la conexión se cierra.
        let r = db.with_default(|c| {
            c.broken = true;
            Err::<(), String>("lo que diga el statement".to_string())
        });
        assert_eq!(r, Err("lo que diga el statement".to_string()));
        assert_eq!(db.query("SELECT 1", &[]).unwrap_err(), "No database connection. Use db_open(\"path.db\") first.");
        assert_eq!(db.default_path(), Some(first.clone()), "la default no pasa a la otra base");
        assert!(db.connections.contains_key(&other) && !db.connections.contains_key(&first));
        // `db_open` la vuelve a abrir, y sigue siendo la default.
        assert_eq!(db.open(":memory:", "memory").unwrap(), first);
        assert_eq!(db.default_path(), Some(first));
        assert_eq!(db.query("SELECT 1 AS a", &[]).unwrap().len(), 1);
        db.close_all();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ronda 2 (N-r2-1): el protocolo de texto de MySQL corre todos los statements de un texto,
    /// así que sólo lo recibe un texto sin `;` (aparte del final), que es uno solo. Lo demás lo
    /// decide el servidor al prepararlo.
    #[test]
    fn v0659_mysql_text_protocol_only_for_a_text_without_a_second_statement() {
        for (sql, one) in [
            ("INSERT INTO t VALUES (1)", "INSERT INTO t VALUES (1)"),
            ("INSERT INTO t VALUES (1);", "INSERT INTO t VALUES (1)"),
            ("INSERT INTO t VALUES (1) ;  \n\t", "INSERT INTO t VALUES (1) "),
            ("CREATE PROCEDURE p() SELECT 1;", "CREATE PROCEDURE p() SELECT 1"),
            ("SELECT 1 -- nota;", "SELECT 1 -- nota"),
            ("", ""),
            (";", ""),
        ] {
            assert_eq!(mysql_single_statement(sql), Some(one), "{:?}", sql);
        }
        for sql in [
            "INSERT INTO t VALUES (1); COMMIT",
            "INSERT INTO t VALUES (1);COMMIT;",
            "INSERT INTO t VALUES (1);;",
            "INSERT INTO t VALUES (1); -- nota",
            "INSERT INTO t VALUES (1) /*! ; COMMIT */",
            "INSERT INTO t VALUES (';')",
            "SELECT 1 /* a;b */",
            "CREATE PROCEDURE p() BEGIN SELECT 1; END",
            "; COMMIT",
        ] {
            assert_eq!(mysql_single_statement(sql), None, "{:?}", sql);
        }
    }

    /// Caso 17: en MySQL un DDL confirma la transacción abierta; adentro de una se rechaza antes.
    #[test]
    fn v0659_mysql_ddl_inside_a_transaction_is_refused() {
        for sql in [
            "CREATE TABLE x (a INT)",
            "alter table x add b int",
            "DROP TABLE x",
            "TRUNCATE x",
            "RENAME TABLE x TO y",
            "LOCK TABLES x WRITE",
            // Medidos contra MySQL 8.0.46: confirman, y no estaban en la lista de memoria.
            "SET PASSWORD = 'x'",
            "set password for 'u'@'h' = 'x'",
            "SET DEFAULT ROLE r TO 'u'@'h'",
            "LOAD INDEX INTO CACHE x",
            "START REPLICA",
            "IMPORT TABLE FROM 'x.sdi'",
            "CLONE LOCAL DATA DIRECTORY = '/x'",
            "CREATE INDEX i ON x (a)",
            "DROP TABLE IF EXISTS x",
            "GRANT SELECT ON x TO u",
            "ANALYZE TABLE x",
            "FLUSH TABLES",
            "STOP REPLICA",
        ] {
            let e = tx_guard(sql, SqlDialect::Mysql, true).unwrap_err();
            assert!(e.contains("commits the open transaction"), "{}: {}", sql, e);
            assert_eq!(tx_guard(sql, SqlDialect::Mysql, false), Ok(()), "fuera de una transacción: {}", sql);
            assert_eq!(tx_guard(sql, SqlDialect::Postgres, true), Ok(()), "Postgres tiene DDL transaccional: {}", sql);
            assert_eq!(tx_guard(sql, SqlDialect::Sqlite, true), Ok(()), "{}", sql);
        }
        // Medidos: no confirman.
        for sql in [
            "CREATE TEMPORARY TABLE x (a INT)",
            "DROP TEMPORARY TABLE x",
            "INSERT INTO x VALUES (1)",
            "SELECT 1",
            "SET @a = 1",
            "SET sql_mode = ''",
            "SET ROLE NONE",
            "SET default_storage_engine = InnoDB",
            "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED",
            "LOAD DATA INFILE '/x' INTO TABLE x",
            "PURGE BINARY LOGS BEFORE '2000-01-01'",
            "UNLOCK TABLES",
            "CALL p()",
            "DO 1",
        ] {
            assert_eq!(tx_guard(sql, SqlDialect::Mysql, true), Ok(()), "{}", sql);
        }
        // Ronda 4: con un comentario que sólo algunos servidores ejecutan después de la primera
        // palabra, la segunda no se sabe; en las cuatro que dependen de ella cuenta como que sí.
        for sql in [
            "CREATE /*!50000 TEMPORARY */ TABLE x (a INT)",
            "DROP /*!99999 x */ TEMPORARY TABLE x",
            "SET /*!99999 PASSWORD = 'x', */ @a = 1",
            "LOAD /*M! INDEX INTO CACHE x */ DATA INFILE '/x' INTO TABLE x",
        ] {
            let e = tx_guard(sql, SqlDialect::Mysql, true).unwrap_err();
            assert!(e.contains("may commit the open transaction"), "{}: {}", sql, e);
            assert_eq!(tx_guard(sql, SqlDialect::Mysql, false), Ok(()), "fuera de una transacción: {}", sql);
        }
        // En las demás la segunda palabra no decide nada.
        assert_eq!(tx_guard("SELECT /*!80000 SQL_NO_CACHE */ 1", SqlDialect::Mysql, true), Ok(()));
        assert_eq!(tx_guard("INSERT /*!50000 IGNORE */ INTO t VALUES (1)", SqlDialect::Mysql, true), Ok(()));
        assert!(tx_guard("ALTER /*!50000 ONLINE */ TABLE x ADD b INT", SqlDialect::Mysql, true).unwrap_err().contains("ALTER statement commits"));
        let e = tx_guard("/*! SET */ PASSWORD = 'x'", SqlDialect::Mysql, true).unwrap_err();
        assert!(e.starts_with("sql_transaction: in MySQL a SET PASSWORD statement commits"), "{}", e);
        assert_eq!(tx_guard("/*! CREATE */ TEMPORARY TABLE x (a INT)", SqlDialect::Mysql, true), Ok(()));
        // El mensaje nombra el statement: `SET` a secas no confirma.
        let e = tx_guard("SET PASSWORD = 'x'", SqlDialect::Mysql, true).unwrap_err();
        assert!(e.starts_with("sql_transaction: in MySQL a SET PASSWORD statement commits"), "{}", e);
        let e = tx_guard("DROP TABLE x", SqlDialect::Mysql, true).unwrap_err();
        assert!(e.starts_with("sql_transaction: in MySQL a DROP statement commits"), "{}", e);
    }

    /// Caso 8 en el gestor y adentro de una transacción, y caso 10: nada queda abierto en la
    /// conexión compartida.
    #[test]
    fn v0659_nothing_leaves_a_transaction_open_on_the_shared_connection() {
        let (db, tx) = tx_db();
        assert_eq!(db.borrow_mut().execute("BEGIN", &[]), Err(TX_BY_HAND.to_string()));
        assert_eq!(db.borrow_mut().query("SAVEPOINT a", &[]).unwrap_err(), TX_BY_HAND);
        assert_eq!(db.borrow_mut().execute_many("COMMIT", &[vec![]]).unwrap_err(), TX_BY_HAND);
        // Adentro de una transacción también, y sin hacerla fallar: no llegó a la base.
        let s = TxScope::open(&db, &tx).unwrap();
        assert_eq!(with_sql(&db, &tx, |c| c.execute("COMMIT", &[])).unwrap_err(), TX_BY_HAND);
        ins(&db, &tx, "a").unwrap();
        s.finish(Ok::<(), String>(()), |e| e).unwrap();
        assert_eq!(whos(&db, &tx), ["a"]);
        // Caso 10: una transacción abierta por otro camino se deshace y el statement da error.
        if let Backend::Sqlite(c) = db.borrow_mut().conn_mut(None).unwrap() {
            c.execute_batch("BEGIN").unwrap();
        }
        let e = ins(&db, &tx, "b").unwrap_err();
        assert!(e.starts_with("this statement left a transaction open"), "{}", e);
        assert_eq!(whos(&db, &tx), ["a"], "lo que quedó en esa transacción se deshizo");
        ins(&db, &tx, "c").unwrap();
        assert_eq!(whos(&db, &tx), ["a", "c"]);
    }

    /// Caso 14: un nivel que se suelta sin `finish` (un pánico que desenrolla) deshace y devuelve
    /// la conexión.
    #[test]
    fn v0659_a_dropped_transaction_rolls_back_and_returns_the_connection() {
        let (db, tx) = tx_db();
        {
            let _s = TxScope::open(&db, &tx).unwrap();
            ins(&db, &tx, "a").unwrap();
        }
        assert!(db.borrow().lent.is_none() && tx.borrow().is_none());
        assert!(whos(&db, &tx).is_empty());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _s = TxScope::open(&db, &tx).unwrap();
            ins(&db, &tx, "b").unwrap();
            panic!("adentro de la task");
        }));
        assert!(r.is_err());
        assert!(db.borrow().lent.is_none() && tx.borrow().is_none());
        assert!(whos(&db, &tx).is_empty());
    }

    /// Casos 21 y 22, y el gestor mientras presta la conexión.
    #[test]
    fn v0659_lending_keeps_the_manager_consistent() {
        // 21: sin conexión.
        let db = Rc::new(RefCell::new(DatabaseManager::new()));
        let tx: TxCell = Rc::new(RefCell::new(None));
        assert_eq!(TxScope::open(&db, &tx).err().unwrap(), "No database connection. Use db_open(\"path.db\") first.");
        // Mientras presta: la base sigue abierta y sigue siendo la default.
        let (db, tx) = tx_db();
        let s = TxScope::open(&db, &tx).unwrap();
        assert_eq!(db.borrow().default_path().as_deref(), Some(":memory:"));
        assert_eq!(db.borrow().default_dialect(), Some(SqlDialect::Sqlite));
        assert_eq!(db.borrow_mut().open(":memory:", "memory").unwrap(), ":memory:");
        assert!(db.borrow().connections.is_empty(), "no se abrió otra conexión a la misma base");
        let e = db.borrow_mut().query("SELECT 1", &[]).unwrap_err();
        assert!(e.contains("is inside a transaction (sql_transaction)"), "{}", e);
        // 22: `db_close` adentro: termina la transacción y después se cierra.
        ins(&db, &tx, "a").unwrap();
        db.borrow_mut().close(None);
        ins(&db, &tx, "b").unwrap();
        assert_eq!(whos(&db, &tx), ["a", "b"]);
        s.finish(Ok::<(), String>(()), |e| e).unwrap();
        assert!(db.borrow().connections.is_empty() && db.borrow().default_path().is_none());
        // `db_close` y después `db_open` de la misma base, adentro: lo último que pidió el programa
        // fue abrirla, y al terminar sigue abierta (auditoría, B-2: quedaba sin conexión).
        let (db, tx) = tx_db();
        let s = TxScope::open(&db, &tx).unwrap();
        ins(&db, &tx, "a").unwrap();
        db.borrow_mut().close(None);
        assert_eq!(db.borrow_mut().open(":memory:", "memory").unwrap(), ":memory:");
        s.finish(Ok::<(), String>(()), |e| e).unwrap();
        assert_eq!(db.borrow().default_path().as_deref(), Some(":memory:"));
        assert_eq!(whos(&db, &tx), ["a"]);
        // Lo mismo después de un `close_all`, que además deja al gestor sin default.
        let s = TxScope::open(&db, &tx).unwrap();
        db.borrow_mut().close_all();
        assert!(db.borrow().default_path().is_none());
        assert_eq!(db.borrow_mut().open(":memory:", "memory").unwrap(), ":memory:");
        ins(&db, &tx, "b").unwrap();
        s.finish(Ok::<(), String>(()), |e| e).unwrap();
        assert_eq!(db.borrow().default_path().as_deref(), Some(":memory:"));
        assert_eq!(whos(&db, &tx), ["a", "b"]);
    }

    /// La conexión vuelve a su lugar (el orden decide la default al cerrar otra); una que no quedó
    /// limpia no vuelve, y la default NO pasa en silencio a otra base (caso 16).
    #[test]
    fn v0659_the_lent_connection_returns_to_its_place() {
        let dir = tx_tmp_dir("order");
        let a = dir.join("a.db").to_string_lossy().replace('\\', "/");
        let b = dir.join("b.db").to_string_lossy().replace('\\', "/");
        let mut m = DatabaseManager::new();
        m.open(&a, "readwrite").unwrap();
        m.open(&b, "readwrite").unwrap();
        let conn = m.lend().unwrap();
        assert_eq!(m.connections.keys().collect::<Vec<_>>(), [&b]);
        m.give_back(Some(conn));
        assert_eq!(m.connections.keys().collect::<Vec<_>>(), [&a, &b]);
        assert_eq!(m.default_path().as_deref(), Some(a.as_str()));
        drop(m.lend().unwrap());
        m.give_back(None);
        assert_eq!(m.default_path().as_deref(), Some(a.as_str()));
        assert_eq!(m.query("SELECT 1", &[]).unwrap_err(), "No database connection. Use db_open(\"path.db\") first.");
        m.close_all();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Una base abierta de sólo lectura también corre una transacción (`BEGIN IMMEDIATE` no falla
    /// ahí, con el diario en modo DELETE ni en WAL).
    #[test]
    fn v0659_a_readonly_database_can_run_a_transaction() {
        let dir = tx_tmp_dir("readonly");
        for mode in ["DELETE", "WAL"] {
            let path = dir.join(format!("ro-{}.db", mode)).to_string_lossy().replace('\\', "/");
            {
                let mut m = DatabaseManager::new();
                m.open(&path, "readwrite").unwrap();
                m.query(&format!("PRAGMA journal_mode = {}", mode), &[]).unwrap();
                m.execute("CREATE TABLE t (who TEXT)", &[]).unwrap();
                m.execute("INSERT INTO t VALUES ('a')", &[]).unwrap();
            }
            let mut m = DatabaseManager::new();
            m.open(&path, "readonly").unwrap();
            let db = Rc::new(RefCell::new(m));
            let tx: TxCell = Rc::new(RefCell::new(None));
            let s = TxScope::open(&db, &tx).unwrap_or_else(|e| panic!("{}: {}", mode, e));
            assert_eq!(whos(&db, &tx), ["a"], "{}", mode);
            s.finish(Ok::<(), String>(()), |e| e).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Caso 11, el de la auditoría (M-r9-1): lo que otra task escribe mientras hay una transacción
    /// espera a que termine y NO entra en ella: sobrevive a su `ROLLBACK`. Y la otra task hace su
    /// propia transacción sin error.
    #[test]
    fn v0659_another_tasks_write_waits_and_survives_the_rollback() {
        let db = shared_db();
        let tx: TxCell = Rc::new(RefCell::new(None));
        let s = TxScope::open(&db, &tx).unwrap();
        ins(&db, &tx, "a").unwrap();
        let other = {
            let db = db.clone();
            std::thread::spawn(move || {
                let mine: TxCell = Rc::new(RefCell::new(None));
                let t0 = Instant::now();
                ins(&db, &mine, "b").unwrap();
                let waited = t0.elapsed();
                let s2 = TxScope::open(&db, &mine).unwrap();
                ins(&db, &mine, "b2").unwrap();
                s2.finish(Ok::<(), String>(()), |e| e).unwrap();
                waited
            })
        };
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(whos(&db, &tx), ["a"], "la otra task todavía espera");
        s.finish(Err::<(), String>("rollback".into()), |e| e).unwrap_err();
        let waited = other.join().unwrap();
        assert!(waited >= Duration::from_millis(100), "esperó a la transacción: {:?}", waited);
        assert_eq!(whos(&db, &tx), ["b", "b2"]);
    }

    /// Casos 12 y 13: pasada la espera, un error atrapable y no un cuelgue; la transacción sigue.
    #[test]
    fn v0659_waiting_for_a_transaction_has_a_limit() {
        let db = shared_db();
        let tx: TxCell = Rc::new(RefCell::new(None));
        let s = TxScope::open(&db, &tx).unwrap();
        let other = {
            let db = db.clone();
            std::thread::spawn(move || {
                let mine: TxCell = Rc::new(RefCell::new(None));
                let t0 = Instant::now();
                let write = ins(&db, &mine, "b");
                let open = TxScope::open(&db, &mine).err();
                (write, open, t0.elapsed())
            })
        };
        let (write, open, waited) = other.join().unwrap();
        let e = write.unwrap_err();
        assert!(e.contains("inside another task's transaction (sql_transaction)"), "{}", e);
        assert_eq!(open, Some(e));
        assert!(waited >= TX_WAIT * 2 - Duration::from_millis(50), "{:?}", waited);
        ins(&db, &tx, "a").unwrap();
        s.finish(Ok::<(), String>(()), |e| e).unwrap();
        assert_eq!(whos(&db, &tx), ["a"]);
    }

    /// v0.6.46 (backlog §10): el `ATTACH` a un archivo (y `VACUUM INTO`) que rechaza el authorizer
    /// salía como `not authorized`, sin decir por qué ni qué hacer.
    #[test]
    fn v0655_a_mask_is_not_a_db_parameter() {
        let mut m = DatabaseManager::new();
        m.open(":memory:", "memory").unwrap();
        let mask = synsema_core::types::syn_mask(ndarray::ArrayD::from_shape_vec(ndarray::IxDyn(&[4]), vec![false, true, false, true]).unwrap());
        for p in [mask.clone(), synsema_core::types::syn_list(vec![mask])] {
            let e = m.query("SELECT ?", &[p]).unwrap_err();
            assert_eq!(e, "sql: a mask (bool array) is not a vector — m * 1.0 gives 0/1 floats");
        }
    }

    #[test]
    fn a_refused_attach_says_why() {
        let mut m = DatabaseManager::new();
        m.open(":memory:", "memory").unwrap();
        for q in ["ATTACH DATABASE 'otra.db' AS o", "VACUUM INTO 'copia.db'"] {
            let e = m.execute(q, &[]).unwrap_err();
            assert!(e.contains("refuses ATTACH") && e.contains("db_open"), "{}: {}", q, e);
        }
        let e = m.execute("SELECT nada FROM ningun_lado", &[]).unwrap_err();
        assert!(!e.contains("db_open"), "otro error queda igual: {}", e);
    }

    /// M-r8-1 (v0.6.58): con `rusqlite` 0.41, otra sentencia después del primer `;` es un error que
    /// dice qué hacer (antes corría la primera y descartaba el resto). No corre ninguna; una cola
    /// con espacios, `;` o un comentario sigue andando.
    #[test]
    fn m_r8_1_more_than_one_statement_is_a_guided_error() {
        let mut m = DatabaseManager::new();
        m.open(":memory:", "memory").unwrap();
        let guided = |e: String| assert!(e.starts_with("one SQL statement per call") && e.contains("its own call"), "{}", e);
        guided(m.execute("CREATE TABLE u (x); CREATE TABLE v (y)", &[]).unwrap_err());
        guided(m.query("SELECT 1 AS one; SELECT 2 AS two", &[]).unwrap_err());
        guided(m.execute_many("CREATE TABLE w (x); SELECT 1", &[vec![]]).unwrap_err());
        assert!(m.query("SELECT name FROM sqlite_master", &[]).unwrap().is_empty(), "no corrió la primera");
        for q in ["SELECT 1 AS one; -- un comentario", "SELECT 1 AS one;   ", "SELECT 1 AS one;;"] {
            assert_eq!(m.query(q, &[]).unwrap().len(), 1, "{}", q);
        }
    }

    fn has_returning(sql: &str, d: SqlDialect) -> bool {
        sql_code_words(sql, d).any(|w| w.eq_ignore_ascii_case("RETURNING"))
    }

    /// `\'` escapa la comilla dentro de un literal en MySQL; en SQLite y Postgres `\` es literal.
    #[test]
    fn sql_code_words_by_dialect() {
        let my = r"INSERT INTO t VALUES ('it\'s', 'returning')";
        assert!(!has_returning(my, SqlDialect::Mysql));
        assert!(!has_returning(r#"INSERT INTO t VALUES ("a\"b returning")"#, SqlDialect::Mysql));
        assert!(!has_returning(r"INSERT INTO t VALUES ('a\') RETURNING id", SqlDialect::Mysql));
        assert!(has_returning(r"INSERT INTO t VALUES ('a\\') RETURNING id", SqlDialect::Mysql));
        // SQLite / Postgres: `'a\'` es un literal completo; lo que sigue es código.
        let lite = r"INSERT INTO t VALUES ('a\', 'returning')";
        assert!(!has_returning(lite, SqlDialect::Sqlite));
        assert!(has_returning(r"INSERT INTO t VALUES ('a\') RETURNING id", SqlDialect::Sqlite));
        assert!(has_returning(r"INSERT INTO t VALUES ('a\') RETURNING id", SqlDialect::Postgres));
        assert!(!has_returning("INSERT INTO t VALUES ('x''returning')", SqlDialect::Sqlite));
        assert!(!has_returning("INSERT INTO t VALUES ('x') -- returning", SqlDialect::Postgres));
    }

    fn cell(row: &Row, key: &str) -> SynValue {
        row.get(key).cloned().unwrap()
    }

    /// `numeric` de Postgres en binario, de cualquier precisión (rust_decimal cortaba en 28).
    #[test]
    fn pg_numeric_binary_any_precision() {
        let enc = |ndigits: u16, weight: i16, sign: u16, dscale: u16, digits: &[u16]| {
            let mut b = Vec::new();
            for x in [ndigits, weight as u16, sign, dscale] {
                b.extend_from_slice(&x.to_be_bytes());
            }
            for d in digits {
                b.extend_from_slice(&d.to_be_bytes());
            }
            b
        };
        let read = |b: &[u8]| PgNumeric::from_sql(&Type::NUMERIC, b).unwrap().0.to_string();
        // 12345.678: dígitos base 10000 [1, 2345, 6780], weight 1, dscale 3.
        assert_eq!(read(&enc(3, 1, 0, 3, &[1, 2345, 6780])), "12345.678");
        assert_eq!(read(&enc(3, 1, 0x4000, 3, &[1, 2345, 6780])), "-12345.678");
        // 10^32 + 0.5: más de 28 dígitos, exacto.
        assert_eq!(
            read(&enc(10, 8, 0, 1, &[1, 0, 0, 0, 0, 0, 0, 0, 0, 5000])),
            "100000000000000000000000000000000.5"
        );
        // 0.0001 y 0.00 (dscale 2, sin dígitos).
        assert_eq!(read(&enc(1, -1, 0, 4, &[1])), "0.0001");
        assert_eq!(read(&enc(0, 0, 0, 2, &[])), "0.00");
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

    /// HB4: un secret de bytes llega a la DB con SUS bytes (antes `from_utf8_lossy`); uno sellado es
    /// error en query/execute/execute_many, también anidado (antes viajaba `secret(NAME)`).
    #[test]
    fn secrets_as_db_params_keep_their_bytes_and_sealed_ones_are_refused() {
        let mut db = DatabaseManager::new();
        db.open(":memory:", "memory").unwrap();
        db.execute("CREATE TABLE k (v BLOB)", &[]).unwrap();
        let raw = vec![0xffu8, 0x00, 0xfe, 0x80];
        db.execute("INSERT INTO k VALUES (?)", &[synsema_core::types::syn_secret_bytes("K", raw.clone())]).unwrap();
        let rows = db.query("SELECT v FROM k", &[]).unwrap();
        assert!(matches!(rows[0].get("v"), Some(SynValue::Bytes(b)) if b.to_vec() == raw), "los bytes del secret, no U+FFFD");
        let sealed = || -> SynValue { SynValue::Secret(synsema_core::types::Obj::new(synsema_core::secret::SecretInner::new_bytes_sealed("attestation_key", vec![7u8; 32]))) };
        for e in [
            db.execute("INSERT INTO k VALUES (?)", &[sealed()]).unwrap_err(),
            db.query("SELECT * FROM k WHERE v = ?", &[sealed()]).unwrap_err(),
            db.execute_many("INSERT INTO k VALUES (?)", &[vec![syn_int(1)], vec![sealed()]]).unwrap_err(),
            db.query("SELECT ?", &[syn_list(vec![syn_int(1), sealed()])]).unwrap_err(),
        ] {
            assert!(e.contains("secret(attestation_key) is sealed"), "{}", e);
        }
        assert_eq!(db.query("SELECT COUNT(*) AS n FROM k", &[]).unwrap().len(), 1);
        assert!(syn_to_redis_arg(&sealed()).unwrap_err().contains("is sealed"));
        // A1: ninguna conversión entrega el material sellado, aunque falte un guardia en alguna
        // entrada (antes `expose()` cerraba todos los bordes; las conversiones nuevas tienen que
        // seguir haciéndolo por sí mismas).
        let key = [7u8; 32];
        assert!(!matches!(syn_to_value(&sealed()), Value::Blob(ref b) if b[..] == key[..]));
        assert!(!matches!(syn_to_pg(&sealed()), PgParam::Bytes(ref b) if b[..] == key[..]));
        assert_eq!(syn_to_mysql(&sealed()), mysql::Value::Bytes(b"secret(attestation_key)".to_vec()));
        assert!(matches!(syn_to_bson(&sealed()), Bson::String(ref t) if t == "secret(attestation_key)"));
        let opts = synsema_core::types::syn_map({
            let mut sort = SynMap::new();
            sort.insert("k", sealed());
            let mut m = SynMap::new();
            m.insert("sort", synsema_core::types::syn_map(sort));
            m
        });
        assert!(reject_sealed(&opts, "mongo_find").unwrap_err().contains("is sealed"), "sort/fields de mongo_find");
        assert_eq!(syn_to_redis_arg(&synsema_core::types::syn_secret_bytes("K", raw.clone())).unwrap(), raw);
        assert_eq!(syn_to_mysql(&synsema_core::types::syn_secret_bytes("K", raw.clone())), mysql::Value::Bytes(raw.clone()));
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

    fn imap(pairs: Vec<(&str, SynValue)>) -> SynMap {
        let mut m = SynMap::new();
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

/// Los textos del driver de SQLite que no dicen qué hacer en Synsema, reescritos: un statement
/// que devuelve filas en `sql_exec`/`sql_batch` ("Execute returned results - did you mean to call
/// query?") y la cuenta de parámetros ("Wrong number of parameters passed to query. Got 0,
/// needed 1"). El resto pasa igual.
fn sql_driver_error(who: &str, e: String) -> Control {
    if e.contains("returned results") {
        return err(format!(
            "{}: this statement returns rows (SELECT, or RETURNING) — run it with sql(statement, params) to get them",
            who
        ));
    }
    if let Some(rest) = e.strip_prefix("Wrong number of parameters passed to query. Got ") {
        if let Some((got, needed)) = rest.split_once(", needed ") {
            return err(format!(
                "{}: the statement has {} parameter(s) but {} value(s) were passed — pass one per `?` (or `:name`, `@name`, `$name`; in SQLite `$…` inside the SQL is a parameter too): sql(statement, [v1, …])",
                who,
                needed.trim(),
                got.trim()
            ));
        }
    }
    err(e)
}

/// Cómo lee un motor los literales de un statement: en MySQL `\` escapa dentro de `'…'` y `"…"`;
/// en SQLite y Postgres es un carácter más.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SqlDialect {
    Sqlite,
    Postgres,
    Mysql,
}

/// Las palabras de CÓDIGO de un statement SQL: sin el contenido de literales `'…'`, identificadores
/// entre comillas (`"…"`, `` `…` ``, `[…]`) ni comentarios (`-- …`, `/* … */`). `'returning'`
/// dentro de un texto no es la cláusula RETURNING.
fn sql_code_words(sql: &str, dialect: SqlDialect) -> impl Iterator<Item = String> {
    let c: Vec<char> = sql.chars().collect();
    let mut code = String::with_capacity(sql.len());
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            q @ ('\'' | '"' | '`') => {
                // Hasta la comilla que cierra; la comilla doblada (`''`) es una comilla adentro,
                // y en MySQL también la escapada (`\'`).
                i += 1;
                while i < c.len() {
                    if dialect == SqlDialect::Mysql && q != '`' && c[i] == '\\' {
                        i += 2;
                        continue;
                    }
                    if c[i] == q {
                        if c.get(i + 1) == Some(&q) {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                i += 1;
                code.push(' ');
            }
            '[' => {
                while i < c.len() && c[i] != ']' {
                    i += 1;
                }
                i += 1;
                code.push(' ');
            }
            '-' if c.get(i + 1) == Some(&'-') => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
                code.push(' ');
            }
            '/' if c.get(i + 1) == Some(&'*') => {
                i += 2;
                while i < c.len() && !(c[i] == '*' && c.get(i + 1) == Some(&'/')) {
                    i += 1;
                }
                i += 2;
                code.push(' ');
            }
            // `$tag$ … $tag$` de Postgres (dollar quoting).
            '$' => {
                let mut j = i + 1;
                while j < c.len() && (c[j].is_ascii_alphanumeric() || c[j] == '_') {
                    j += 1;
                }
                if c.get(j) == Some(&'$') && !(j > i + 1 && c[i + 1].is_ascii_digit()) {
                    let tag: String = c[i..=j].iter().collect();
                    let rest: String = c[j + 1..].iter().collect();
                    match rest.find(&tag) {
                        Some(k) => i = j + 1 + rest[..k].chars().count() + tag.chars().count(),
                        None => i = c.len(),
                    }
                    code.push(' ');
                } else {
                    code.push('$');
                    i += 1;
                }
            }
            ch => {
                code.push(ch);
                i += 1;
            }
        }
    }
    code.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|w| !w.is_empty())
        .map(|w| w.to_string())
        .collect::<Vec<_>>()
        .into_iter()
}

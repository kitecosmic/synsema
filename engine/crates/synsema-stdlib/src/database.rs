//! SQL nativo bajo una API universal (`db_open`/`sql`/`sql_exec`/…).
//!
//! `DatabaseManager` mantiene conexiones por key (con un `default_db`), cada una de un
//! `Backend`:
//!   - **SQLite** (`rusqlite`, estático `bundled`) — `db_open("./x.db")` / `:memory:`.
//!   - **Postgres** (M1; driver sync `postgres` = tokio-postgres con runtime interno, TLS
//!     rustls) — `db_open("postgres://user:pw@host/db")`. Placeholders `?` (se reescriben
//!     a `$n`). pgvector se usa en la query (`<->`/`<=>`), server-side.
//!
//! Gateado por la capability `db(scope)` (deny-by-default): SQLite scope = ruta, Postgres
//! scope = `canon_url` (scheme://host/db, sin credenciales). Acceso serializado (un op por
//! vez: `Rc<RefCell>` en run, `Arc<Mutex>` en serve) → una conexión por `db_open`.

use std::cell::RefCell;
use std::error::Error as StdError;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use indexmap::IndexMap;
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

use crate::server::json_to_syn;

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
    /// cualquier otra cosa → SQLite (camino actual, sin cambios). Devuelve la key usada
    /// como identificador (canon_url para PG; ruta/`:memory:` para SQLite).
    pub fn open(&mut self, target: &str, mode: &str) -> Result<String, String> {
        if is_pg_url(target) {
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
        }
    }

    /// Ejecuta INSERT/UPDATE/DELETE/CREATE. Devuelve (rows_affected, last_id).
    /// Postgres no tiene `last_insert_rowid` → `last_id = 0` (usar `INSERT … RETURNING id`).
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
/// `open()` y la que devuelve `default_path()`): PG → canon_url; SQLite → ruta/`:memory:`.
fn db_scope_for(target: &str, mode: &str) -> String {
    if is_pg_url(target) {
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
}

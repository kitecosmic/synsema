//! Datos tabulares (v0.6.29, DATOS-3/6/14): una tabla es una LISTA DE MAPAS (la misma forma
//! que devuelven `sql()`, `csv_parse` y `json_decode`). Nada de índice ni `loc`: agrupar,
//! resumir, unir y pivotear devuelven listas de mapas, que van directo a `chart_svg`,
//! `csv_encode` o a la siguiente operación.
//!
//! Faltantes (DATOS-2/6): `nothing` es un dato FALTANTE y las agregaciones lo saltean (como
//! los null de polars/SQL); NaN es un resultado inválido y se PROPAGA.

use std::rc::Rc;

use indexmap::IndexMap;

use crate::interpreter::{BuiltinTask, Control, Interpreter, RuntimeError};
use crate::number::Number;
use crate::types::{syn_float, syn_int, syn_list, syn_map, syn_number, syn_text, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

fn rows_arg(v: &SynValue, who: &str) -> Result<Vec<SynValue>, Control> {
    match v {
        SynValue::List(l) => Ok(l.borrow().clone()),
        other => Err(err(format!("{}: expected a list of rows (maps), got {}", who, other.type_name()))),
    }
}

/// Una columna que no aparece en NINGUNA fila es un nombre mal escrito, no datos que faltan:
/// error con las columnas que sí hay (una columna presente en algunas filas y no en otras
/// es `nothing` donde falta).
pub(crate) fn check_column(rows: &[SynValue], col: &str, who: &str) -> Result<(), Control> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut seen: Vec<String> = Vec::new();
    for r in rows {
        if let SynValue::Map(m) = crate::labels::unwrap(r) {
            let m = m.borrow();
            if m.contains_key(col) {
                return Ok(());
            }
            for k in m.keys() {
                if seen.len() < 12 && !seen.contains(k) {
                    seen.push(k.clone());
                }
            }
        }
    }
    Err(err(format!(
        "{}: no row has a column {:?} (columns: {})",
        who,
        col,
        seen.iter().map(|c| format!("{:?}", c)).collect::<Vec<_>>().join(", ")
    )))
}

fn row_get(row: &SynValue, col: &str, who: &str) -> Result<SynValue, Control> {
    match row {
        SynValue::Map(m) => Ok(m.borrow().get(col).cloned().unwrap_or(SynValue::Nothing)),
        other => Err(err(format!("{}: every row must be a map, got {}", who, other.type_name()))),
    }
}

/// Cómo se calcula la clave de agrupación: una columna, varias, o una función.
pub enum KeySpec {
    Column(String),
    Columns(Vec<String>),
    Func(SynValue),
}

pub fn key_spec(v: &SynValue, who: &str) -> Result<KeySpec, Control> {
    match v {
        SynValue::Text(t) => Ok(KeySpec::Column(t.to_string())),
        SynValue::List(l) => {
            let mut cols = Vec::new();
            for c in l.borrow().iter() {
                match c {
                    SynValue::Text(t) => cols.push(t.to_string()),
                    other => return Err(err(format!("{}: column names must be text, got {}", who, other.type_name()))),
                }
            }
            if cols.is_empty() {
                return Err(err(format!("{}: pass at least one column", who)));
            }
            Ok(KeySpec::Columns(cols))
        }
        SynValue::Task(_) | SynValue::Builtin(_) => Ok(KeySpec::Func(v.clone())),
        other => Err(err(format!(
            "{}: the key must be a column name, a list of column names or a function, got {}",
            who,
            other.type_name()
        ))),
    }
}

pub fn key_of(interp: &mut Interpreter, spec: &KeySpec, row: &SynValue, who: &str) -> Result<SynValue, Control> {
    match spec {
        KeySpec::Column(c) => row_get(row, c, who),
        KeySpec::Columns(cs) => {
            let mut m = IndexMap::new();
            for c in cs {
                m.insert(c.clone(), row_get(row, c, who)?);
            }
            Ok(syn_map(m))
        }
        KeySpec::Func(f) => interp.call_task(f.clone(), vec![row.clone()]),
    }
}

/// Decimal y float no se comparan (`1.5d == 1.5` es error): una clave de agrupar, contar o
/// deduplicar que los mezcla separaría `1.5d` de `1.5` en silencio. El error sale sólo en una
/// comparación REAL: dos claves que, en la misma posición (la clave entera, un campo de un mapa o
/// un lugar de una lista), caen en el mismo grupo numérico — el mismo valor como float — y una es
/// decimal y la otra float. `unique(["a", 1.5, 1d])` no compara 1.5 con 1d; un NaN no cuenta.
#[derive(Default)]
pub(crate) struct NumMix {
    seen: std::collections::HashMap<String, (bool, bool)>,
}

impl NumMix {
    pub(crate) fn check(&mut self, v: &SynValue, who: &str) -> Result<(), Control> {
        if self.walk(v, String::new()) {
            return Err(err(format!("{}: {}", who, crate::number::MIX_DECIMAL_FLOAT)));
        }
        Ok(())
    }

    /// `true` si en alguna posición quedaron un decimal y un float.
    fn walk(&mut self, v: &SynValue, path: String) -> bool {
        let (dec, flt, x) = match crate::labels::unwrap(v) {
            SynValue::Number(n) if n.is_decimal() => (true, false, n.to_f64()),
            SynValue::Number(Number::Float(x)) if !x.is_nan() => (false, true, *x),
            SynValue::List(l) => {
                let items = l.borrow();
                return items.iter().enumerate().any(|(i, x)| self.walk(x, format!("{}[{}]", path, i)));
            }
            SynValue::Map(m) => {
                let m = m.borrow();
                return m.iter().any(|(k, x)| self.walk(x, format!("{}.{}:{}", path, k.len(), k)));
            }
            _ => return false,
        };
        // El grupo numérico: el valor como float (`-0.0` es `0.0`), en esta posición.
        let x = if x == 0.0 { 0.0 } else { x };
        let e = self.seen.entry(format!("{}#{:x}", path, x.to_bits())).or_default();
        e.0 |= dec;
        e.1 |= flt;
        e.0 && e.1
    }
}

/// ¿Comparar `a` con `b` junta un decimal con un float en la misma posición (el error de
/// `1d == 1.0`)? Recorre listas por índice y mapas por clave, como `==`. Un NaN no cuenta.
pub(crate) fn dec_float_clash(a: &SynValue, b: &SynValue) -> bool {
    let is_dec = |v: &SynValue| matches!(v, SynValue::Number(n) if n.is_decimal());
    let is_flt = |v: &SynValue| matches!(v, SynValue::Number(Number::Float(x)) if !x.is_nan());
    let (a, b) = (crate::labels::unwrap(a), crate::labels::unwrap(b));
    match (a, b) {
        (SynValue::List(x), SynValue::List(y)) => {
            let (x, y) = (x.borrow(), y.borrow());
            x.len() == y.len() && x.iter().zip(y.iter()).any(|(p, q)| dec_float_clash(p, q))
        }
        (SynValue::Map(x), SynValue::Map(y)) => {
            let (x, y) = (x.borrow(), y.borrow());
            x.len() == y.len() && x.iter().any(|(k, p)| y.get(k).is_some_and(|q| dec_float_clash(p, q)))
        }
        _ => (is_dec(a) && is_flt(b)) || (is_flt(a) && is_dec(b)),
    }
}

/// La igualdad del lenguaje (`==`, `in`, `match`, `contains`, `index_of`) en UNA pasada:
/// compara posición por posición (listas por índice, mapas por clave) y corta en la primera
/// diferencia, como `syn_equals`. `Err(())` sólo si una posición que de verdad se compara junta
/// un decimal con un float (`[1d] == [1.0]`); `["a", 1d] == ["b", 1.0]` es `false` (la posición
/// 0 ya decidió) y dos mapas con claves distintas son `false` sin mirar los valores.
pub(crate) fn strict_equals(a: &SynValue, b: &SynValue) -> Result<bool, ()> {
    // Un choque decimal/float queda PENDIENTE y se sigue buscando: si aparece una diferencia
    // real, es `false` (en cualquier orden de claves o de operandos: `A == B` y `B == A` dan lo
    // mismo); si no, el choque es el error.
    let mut clash = false;
    let eq = equals_walk(a, b, &mut clash);
    if !eq {
        Ok(false)
    } else if clash {
        Err(())
    } else {
        Ok(true)
    }
}

/// `false` en la primera diferencia real; una posición decimal/float cuenta como "igual por
/// ahora" y marca `clash`.
fn equals_walk(a: &SynValue, b: &SynValue, clash: &mut bool) -> bool {
    let (a, b) = (crate::labels::unwrap(a), crate::labels::unwrap(b));
    match (a, b) {
        (SynValue::List(x), SynValue::List(y)) => {
            let (x, y) = (x.borrow(), y.borrow());
            x.len() == y.len() && x.iter().zip(y.iter()).all(|(p, q)| equals_walk(p, q, clash))
        }
        (SynValue::Map(x), SynValue::Map(y)) => {
            let (x, y) = (x.borrow(), y.borrow());
            x.len() == y.len()
                && !x.keys().any(|k| !y.contains_key(k))
                && x.iter().all(|(k, p)| equals_walk(p, &y[k.as_str()], clash))
        }
        _ if dec_float_clash(a, b) => {
            *clash = true;
            true
        }
        _ => a.syn_equals(b),
    }
}

/// Agrupa en orden de PRIMERA aparición; la clave conserva valor y tipo y se compara con la
/// igualdad del lenguaje (`1 == 1.0`). → `[(clave, filas)]`.
pub fn groups(
    interp: &mut Interpreter,
    rows: &[SynValue],
    spec: &KeySpec,
    who: &str,
) -> Result<Vec<(SynValue, Vec<SynValue>)>, Control> {
    match spec {
        KeySpec::Column(c) => check_column(rows, c, who)?,
        KeySpec::Columns(cs) => {
            for c in cs {
                check_column(rows, c, who)?;
            }
        }
        KeySpec::Func(_) => {}
    }
    let mut out: Vec<(SynValue, Vec<SynValue>)> = Vec::new();
    // La clave canónica (`probe_key`) ya iguala exactamente lo que iguala `==` (y junta los
    // NaN en un grupo, como polars): un hash, sin comparar de a pares.
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut mix = NumMix::default();
    for row in rows {
        let k = key_of(interp, spec, row, who)?;
        mix.check(&k, who)?;
        let probe = probe_key(crate::labels::unwrap(&k));
        match index.get(&probe) {
            Some(&i) => out[i].1.push(row.clone()),
            None => {
                index.insert(probe, out.len());
                out.push((k, vec![row.clone()]));
            }
        }
    }
    Ok(out)
}

/// Forma de texto para el índice rápido de `groups`: números iguales (`1`, `1.0`, `1d`)
/// caen en el mismo balde; `syn_equals` decide igual.
pub(crate) fn probe_key(v: &SynValue) -> String {
    let mut out = String::new();
    canon_key(v, &mut out);
    out
}

/// La clave canónica de un valor para agrupar: dos valores que `==` iguala dan la misma
/// cadena. Tipada y autodelimitada (el texto va con su largo), así el texto `"1"` y el
/// número `1` no chocan; un mapa va con sus claves ordenadas (`==` no mira el orden); un
/// instante, en UTC (`==` compara el instante, no la zona); `true` es `1`, como en `==`.
fn canon_key(v: &SynValue, out: &mut String) {
    use std::fmt::Write;
    match crate::labels::unwrap(v) {
        SynValue::Nothing => out.push('z'),
        SynValue::Bool(b) => out.push_str(if *b { "n:1;" } else { "n:0;" }),
        SynValue::Number(n) => canon_number(n, out),
        SynValue::Complex(z) if z.im == 0.0 => canon_number(&Number::Float(z.re), out),
        SynValue::Complex(z) => {
            let _ = write!(out, "c:{};{};", crate::number::py_float_str(z.re), crate::number::py_float_str(z.im));
        }
        SynValue::Text(t) => {
            let _ = write!(out, "t{}:{}", t.len(), t);
        }
        SynValue::Bytes(b) => {
            let _ = write!(out, "y:{};", crate::bytesutil::hex_encode(b));
        }
        SynValue::List(l) => {
            out.push('[');
            for x in l.borrow().iter() {
                canon_key(x, out);
            }
            out.push(']');
        }
        SynValue::Map(m) => {
            let m = m.borrow();
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for k in keys {
                let _ = write!(out, "{}:{}", k.len(), k);
                canon_key(&m[k.as_str()], out);
            }
            out.push('}');
        }
        SynValue::Time(t) => match t.as_ref() {
            crate::temporal::Temporal::Date(d) => {
                let _ = write!(out, "D:{};", d);
            }
            crate::temporal::Temporal::DateTime(dt) => {
                let u = dt.with_timezone(&chrono::Utc);
                let _ = write!(out, "T:{}.{:09};", u.timestamp(), u.timestamp_subsec_nanos());
            }
            crate::temporal::Temporal::Duration(d) => {
                let _ = write!(out, "U:{:?};", d.num_nanoseconds().map(|n| n as i128).unwrap_or(d.num_seconds() as i128 * 1_000_000_000));
            }
        },
        // Un array: su forma y cada valor (el Display de uno grande se abrevia).
        SynValue::Array(a) => {
            let _ = write!(out, "A{:?}:", a.shape());
            for x in a.iter() {
                // -0.0 == 0.0 (como en `==`): una sola clave.
                let x = if *x == 0.0 { 0.0 } else { *x };
                let _ = write!(out, "{};", crate::number::py_float_str(x));
            }
        }
        // Un secret se compara por contenido (en `==`, en tiempo constante): acá va su hash,
        // nunca el texto.
        SynValue::Secret(sec) => {
            use sha2::Digest;
            let h = sha2::Sha256::digest(sec.expose_bytes());
            let _ = write!(out, "s:{};", crate::bytesutil::hex_encode(&h));
        }
        other => {
            let s = other.to_string();
            let _ = write!(out, "o{}:{}", s.len(), s);
        }
    }
}

/// Un número: todo valor entero (int, float o decimal) va como el entero exacto (`1`, `1.0`
/// y `1d` son una clave, como en `==`); un float con decimales, por su representación más
/// corta (única por f64); un decimal con decimales, normalizado (`1.50d` = `1.5d`). NaN es
/// una sola clave (un grupo para los NaN, como polars; `nothing` es otra).
fn canon_number(n: &Number, out: &mut String) {
    use std::fmt::Write;
    match n {
        Number::Float(x) if x.is_finite() && x.fract() == 0.0 => {
            let _ = write!(out, "n:{};", Number::integer_from_f64(*x));
        }
        Number::Float(x) => {
            let _ = write!(out, "f:{};", crate::number::py_float_str(*x));
        }
        Number::Decimal(_) | Number::BigDec(_) => match n.as_bigint() {
            Some(b) => {
                let _ = write!(out, "n:{};", b);
            }
            None => {
                // Normalizado (sin ceros a la derecha) sobre el valor exacto: `1.50d` = `1.5d`,
                // y un decimal grande igual a uno chico da la misma clave.
                let (mut m, mut s) = n.exact_ratio().unwrap();
                let ten = num_bigint::BigInt::from(10);
                while s > 0 && num_traits::Zero::is_zero(&(&m % &ten)) {
                    m /= &ten;
                    s -= 1;
                }
                let _ = write!(out, "d:{}e-{};", m, s);
            }
        },
        other => {
            let _ = write!(out, "n:{};", other);
        }
    }
}

/// `group_by(rows, key)` → `[{key, items}]` en orden de primera aparición.
pub fn group_by(interp: &mut Interpreter, args: &[SynValue]) -> Result<SynValue, Control> {
    let (rows, spec) = match (args.first(), args.get(1)) {
        // Orden histórico `group_by(fn, lista)` también (como sort_by).
        (Some(f @ (SynValue::Task(_) | SynValue::Builtin(_))), Some(l @ SynValue::List(_))) => {
            (rows_arg(l, "group_by")?, key_spec(f, "group_by")?)
        }
        (Some(l), Some(k)) => (rows_arg(l, "group_by")?, key_spec(k, "group_by")?),
        _ => return Err(err("group_by(items, key) takes the items and a key (column, columns or function)")),
    };
    let gs = groups(interp, &rows, &spec, "group_by")?;
    Ok(syn_list(
        gs.into_iter()
            .map(|(k, items)| {
                let mut m = IndexMap::new();
                m.insert("key".to_string(), k);
                m.insert("items".to_string(), syn_list(items));
                syn_map(m)
            })
            .collect(),
    ))
}

/// `summarize(rows, by, aggs)` → filas: las columnas de la clave + un valor por agregado.
/// `aggs` = mapa `nombre → función del grupo` (los `sum_of("col")`, `count()`, … de abajo o
/// cualquier `(group) => …`).
pub fn summarize(interp: &mut Interpreter, args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "summarize";
    let rows = rows_arg(args.first().ok_or_else(|| err("summarize(rows, by, aggs)"))?, W)?;
    let spec = key_spec(args.get(1).ok_or_else(|| err("summarize(rows, by, aggs): missing by"))?, W)?;
    let aggs = match args.get(2) {
        Some(SynValue::Map(m)) => m.borrow().clone(),
        Some(other) => return Err(err(format!("{}: aggs must be a map name → function, got {}", W, other.type_name()))),
        None => return Err(err("summarize(rows, by, aggs): missing aggs")),
    };
    check_agg_columns(&rows, aggs.values())?;
    let gs = groups(interp, &rows, &spec, W)?;
    in_table_op(|| summarize_groups(interp, &spec, &aggs, gs))
}

fn summarize_groups(
    interp: &mut Interpreter,
    spec: &KeySpec,
    aggs: &IndexMap<String, SynValue>,
    gs: Vec<(SynValue, Vec<SynValue>)>,
) -> Result<SynValue, Control> {
    const W: &str = "summarize";
    let mut out = Vec::with_capacity(gs.len());
    for (k, items) in gs {
        let mut row = IndexMap::new();
        match (spec, &k) {
            (KeySpec::Column(c), _) => {
                row.insert(c.clone(), k.clone());
            }
            (_, SynValue::Map(km)) => {
                for (kk, vv) in km.borrow().iter() {
                    row.insert(kk.clone(), vv.clone());
                }
            }
            _ => {
                row.insert("key".to_string(), k.clone());
            }
        }
        let group = syn_list(items);
        for (name, f) in aggs.iter() {
            if row.contains_key(name) {
                return Err(err(format!(
                    "{}: the aggregate {:?} has the name of a key column — it would overwrite the key; name it differently (e.g. {:?})",
                    W,
                    name,
                    format!("{}_agg", name)
                )));
            }
            let v = interp.call_task(f.clone(), vec![group.clone()])?;
            row.insert(name.clone(), v);
        }
        out.push(syn_map(row));
    }
    Ok(syn_list(out))
}

/// Números presentes de una columna del grupo: `nothing` se saltea; lo que no es número es
/// error (una columna de texto no se suma).
fn column_numbers(group: &SynValue, col: &str, who: &str) -> Result<Vec<Number>, Control> {
    let rows = rows_arg(group, who)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        match row_get(r, col, who)? {
            SynValue::Nothing => {}
            SynValue::Number(n) => out.push(n),
            other => {
                return Err(err(format!("{}: column {:?} has a {}, expected numbers", who, col, other.type_name())))
            }
        }
    }
    Ok(out)
}

fn has_nan(ns: &[Number]) -> bool {
    ns.iter().any(|n| matches!(n, Number::Float(x) if x.is_nan()))
}

thread_local! {
    /// La columna de cada agregado (`sum_of("v")` → "v"), por la identidad de su función: así
    /// `summarize`/`pivot` validan la columna contra la TABLA entera y no contra cada grupo (en
    /// una tabla con filas desparejas, un grupo puede no tener la columna sin que sea un error).
    static AGG_COLS: std::cell::RefCell<std::collections::HashMap<usize, (std::rc::Weak<BuiltinTask>, String, &'static str)>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
    /// > 0 mientras `summarize`/`pivot` llaman a los agregados (ya validaron las columnas).
    static IN_TABLE_OP: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Valida las columnas de los agregados de `aggs` contra la tabla completa.
fn check_agg_columns<'a>(rows: &[SynValue], aggs: impl Iterator<Item = &'a SynValue>) -> Result<(), Control> {
    for f in aggs {
        if let SynValue::Builtin(b) = f {
            let found = AGG_COLS.with(|m| {
                m.borrow().get(&(Rc::as_ptr(b) as usize)).and_then(|(w, col, kind)| {
                    w.upgrade().filter(|t| Rc::ptr_eq(t, b)).map(|_| (col.clone(), *kind))
                })
            });
            if let Some((col, kind)) = found {
                check_column(rows, &col, &format!("{}_of", kind))?;
            }
        }
    }
    Ok(())
}

/// Mientras vive, los agregados no re-validan columnas por grupo (la operación de tabla ya
/// las validó contra la tabla entera). Se suelta también si la operación falla.
struct TableOpGuard;

impl TableOpGuard {
    fn enter() -> TableOpGuard {
        IN_TABLE_OP.with(|c| c.set(c.get() + 1));
        TableOpGuard
    }
}

impl Drop for TableOpGuard {
    fn drop(&mut self) {
        IN_TABLE_OP.with(|c| c.set(c.get() - 1));
    }
}

/// Corre `f` con los agregados sin re-validar columnas por grupo.
fn in_table_op<T>(f: impl FnOnce() -> T) -> T {
    let _g = TableOpGuard::enter();
    f()
}

fn builtin_value(name: String, f: crate::interpreter::BuiltinFn) -> SynValue {
    SynValue::Builtin(Rc::new(BuiltinTask::new(name, 1, None, f)))
}

/// Constructores de agregados: `sum_of("monto")` devuelve la función `(group) => …`.
pub fn aggregator(kind: &'static str, args: &[SynValue]) -> Result<SynValue, Control> {
    let col = match (kind, args.first()) {
        ("count", _) => String::new(),
        (_, Some(SynValue::Text(t))) => t.to_string(),
        (_, other) => {
            return Err(err(format!(
                "{}_of(column): the column must be text, got {}",
                kind,
                other.map(|v| v.type_name()).unwrap_or("nothing")
            )))
        }
    };
    let q = if kind == "quantile" {
        match args.get(1) {
            Some(SynValue::Number(n)) if (0.0..=1.0).contains(&n.to_f64()) => n.to_f64(),
            _ => return Err(err("quantile_of(column, q): q must be a number in [0, 1]")),
        }
    } else {
        0.0
    };
    let label = if kind == "count" { "count()".to_string() } else { format!("{}_of({:?})", kind, col) };
    let col_for_registry = col.clone();
    let f: crate::interpreter::BuiltinFn = Rc::new(move |_i, a, _l| {
        let group = a.first().ok_or_else(|| err("an aggregate receives the group"))?;
        let who = if kind == "count" { "count" } else { kind };
        // Usado suelto sobre una lista de filas, la columna tiene que existir en ella; dentro de
        // `summarize`/`pivot` ya se validó contra la tabla entera.
        if kind != "count" && IN_TABLE_OP.with(|c| c.get()) == 0 {
            check_column(&rows_arg(group, who)?, &col, &format!("{}_of", kind))?;
        }
        match kind {
            "count" => Ok(syn_int(rows_arg(group, who)?.len() as i64)),
            "first" => Ok(rows_arg(group, who)?.first().map(|r| row_get(r, &col, who)).transpose()?.unwrap_or(SynValue::Nothing)),
            "n_unique" => {
                let rows = rows_arg(group, who)?;
                let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                let mut mix = NumMix::default();
                for r in &rows {
                    let v = row_get(r, &col, who)?;
                    if !matches!(v, SynValue::Nothing) {
                        mix.check(&v, "n_unique_of")?;
                        seen.insert(probe_key(&v));
                    }
                }
                Ok(syn_int(seen.len() as i64))
            }
            // min/max aceptan lo mismo que `min`/`max`: números, textos o fechas.
            "min" | "max" => {
                let rows = rows_arg(group, who)?;
                let vals: Vec<SynValue> = rows
                    .iter()
                    .map(|r| row_get(r, &col, who))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|v| !matches!(v, SynValue::Nothing))
                    .collect();
                if vals.is_empty() {
                    return Ok(SynValue::Nothing);
                }
                if kind == "min" {
                    crate::math::min(&[syn_list(vals)])
                } else {
                    crate::math::max(&[syn_list(vals)])
                }
            }
            _ => {
                let ns = column_numbers(group, &col, who)?;
                if has_nan(&ns) {
                    return Ok(syn_float(f64::NAN));
                }
                if ns.is_empty() {
                    return Ok(if kind == "sum" { syn_int(0) } else { SynValue::Nothing });
                }
                let list = syn_list(ns.into_iter().map(syn_number).collect());
                match kind {
                    "sum" => crate::stats::reduce_values(&list, crate::stats::Kind::Sum, 0.0),
                    "mean" => crate::stats::reduce_values(&list, crate::stats::Kind::Mean, 0.0),
                    "median" => crate::stats::reduce_values(&list, crate::stats::Kind::Median, 0.0),
                    "quantile" => crate::stats::reduce_values(&list, crate::stats::Kind::Quantile, q),
                    _ => unreachable!(),
                }
            }
        }
    });
    let v = builtin_value(label, f);
    if kind != "count" {
        if let SynValue::Builtin(b) = &v {
            AGG_COLS.with(|m| {
                let mut m = m.borrow_mut();
                if m.len() >= 1024 && m.len().is_power_of_two() {
                    m.retain(|_, (w, _, _)| w.strong_count() > 0);
                }
                m.insert(Rc::as_ptr(b) as usize, (Rc::downgrade(b), col_for_registry, kind));
            });
        }
    }
    Ok(v)
}

/// `count_by(rows, key)` → `[{key, count}]`, de más a menos frecuente (empates en orden de
/// primera aparición) — el `value_counts` de pandas.
pub fn count_by(interp: &mut Interpreter, args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "count_by";
    let rows = rows_arg(args.first().ok_or_else(|| err("count_by(items, key)"))?, W)?;
    let spec = match args.get(1) {
        Some(k) => key_spec(k, W)?,
        None => KeySpec::Func(SynValue::Nothing),
    };
    let gs = match spec {
        KeySpec::Func(SynValue::Nothing) => {
            // count_by(valores) sin clave: cuenta los valores mismos.
            let identity: crate::interpreter::BuiltinFn = Rc::new(|_i, a, _l| Ok(a[0].clone()));
            groups(interp, &rows, &KeySpec::Func(builtin_value("identity".into(), identity)), W)?
        }
        s => groups(interp, &rows, &s, W)?,
    };
    let mut counted: Vec<(SynValue, usize)> = gs.into_iter().map(|(k, v)| (k, v.len())).collect();
    counted.sort_by(|a, b| b.1.cmp(&a.1)); // estable: empates en orden de aparición
    Ok(syn_list(
        counted
            .into_iter()
            .map(|(k, n)| {
                let mut m = IndexMap::new();
                m.insert("key".to_string(), k);
                m.insert("count".to_string(), syn_int(n as i64));
                syn_map(m)
            })
            .collect(),
    ))
}

/// `join(left, right, on, how = "inner")` → filas. `on` = columna o lista de columnas
/// presentes en ambos lados. `how`: "inner", "left", "right", "outer", "semi" (las filas de
/// la izquierda que tienen pareja) o "anti" (las que no). Columnas repetidas que no son clave:
/// la de la derecha lleva el sufijo `_right` (como polars). Toda fila de salida tiene TODAS
/// las columnas (lo que no tiene pareja queda en `nothing`). Una clave `nothing` no empareja
/// con nada (como SQL). Orden: el de la izquierda y, en "right"/"outer", después las filas de
/// la derecha sin pareja. Por hash: lineal en el tamaño de las dos tablas.
pub fn join(args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "join";
    let left = rows_arg(args.first().ok_or_else(|| err("join(left, right, on, how?)"))?, W)?;
    let right = rows_arg(args.get(1).ok_or_else(|| err("join(left, right, on, how?): missing right"))?, W)?;
    let on: Vec<String> = match args.get(2) {
        Some(SynValue::Text(t)) => vec![t.to_string()],
        Some(SynValue::List(l)) => l
            .borrow()
            .iter()
            .map(|v| match v {
                SynValue::Text(t) => Ok(t.to_string()),
                other => Err(err(format!("{}: column names must be text, got {}", W, other.type_name()))),
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(err("join(left, right, on, how?): on must be a column name or a list of them")),
    };
    let how = match args.get(3) {
        None | Some(SynValue::Nothing) => "inner".to_string(),
        Some(SynValue::Text(t)) if matches!(t.as_ref(), "inner" | "left" | "right" | "outer" | "semi" | "anti") => {
            t.to_string()
        }
        Some(other) => {
            return Err(err(format!(
                "{}: how must be \"inner\", \"left\", \"right\", \"outer\", \"semi\" or \"anti\", got {}",
                W, other
            )))
        }
    };
    for c in &on {
        check_column(&left, c, "join (left)")?;
        check_column(&right, c, "join (right)")?;
        // Una clave decimal y otra float nunca serían iguales (`1.5d == 1.5` es error): un join
        // que las deja sin pareja en silencio. Error, como en `==` y en `group_by`.
        let mut mix = NumMix::default();
        let mut mixed = false;
        for r in left.iter().chain(right.iter()) {
            if mix.check(&row_get(r, c, W)?, W).is_err() {
                mixed = true;
                break;
            }
        }
        if mixed {
            return Err(err(format!(
                "{}: the key {:?} is decimal on one side and float on the other — they never match; convert one side first (decimal(x) or float(x))",
                W, c
            )));
        }
    }
    // Clave de emparejamiento; `None` si alguna parte es `nothing`.
    let key = |row: &SynValue| -> Result<Option<String>, Control> {
        let mut parts = Vec::with_capacity(on.len());
        for c in &on {
            let v = row_get(row, c, W)?;
            if matches!(v, SynValue::Nothing) {
                return Ok(None);
            }
            parts.push(v);
        }
        Ok(Some(probe_key(&syn_list(parts))))
    };
    let cols_of = |rows: &[SynValue]| -> Vec<String> {
        let mut cols: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for r in rows {
            if let SynValue::Map(m) = r {
                for k in m.borrow().keys() {
                    if seen.insert(k.clone()) {
                        cols.push(k.clone());
                    }
                }
            }
        }
        cols
    };
    // Las columnas de la clave van siempre (aunque la izquierda esté vacía, una fila sólo de la
    // derecha trae su clave).
    let mut left_cols = cols_of(&left);
    for c in on.iter().rev() {
        if !left_cols.contains(c) {
            left_cols.insert(0, c.clone());
        }
    }
    // Columnas de la derecha que no son clave, con su nombre de salida. Si `x_right` ya existe
    // en la izquierda, es error (como polars): renombrar en silencio o pisar pierde datos.
    // `semi` y `anti` no emiten columnas de la derecha: no hay nombres que choquen.
    let emits_right = !matches!(how.as_str(), "semi" | "anti");
    let mut right_out: Vec<(String, String)> = Vec::new();
    for c in cols_of(&right).into_iter().filter(|c| !on.contains(c)) {
        let name = if left_cols.contains(&c) { format!("{}_right", c) } else { c.clone() };
        if emits_right && name != c && left_cols.contains(&name) {
            return Err(err(format!(
                "{}: the right column {:?} would be named {:?}, which the left side already has — rename one of them first",
                W, c, name
            )));
        }
        right_out.push((c, name));
    }
    // Dos columnas de la derecha con el mismo nombre de salida (`x` → `x_right` y una
    // `x_right` propia) se pisarían: error.
    for (i, (c, name)) in right_out.iter().enumerate().filter(|_| emits_right) {
        if let Some((c2, _)) = right_out[..i].iter().find(|(_, n)| n == name) {
            return Err(err(format!(
                "{}: the right columns {:?} and {:?} would both be named {:?} — rename one of them first",
                W, c2, c, name
            )));
        }
    }
    let mut index: std::collections::HashMap<String, Vec<usize>> = std::collections::HashMap::new();
    for (j, r) in right.iter().enumerate() {
        if let Some(k) = key(r)? {
            index.entry(k).or_default().push(j);
        }
    }
    let row_of = |l: Option<&SynValue>, r: Option<&SynValue>| -> Result<SynValue, Control> {
        let mut out: IndexMap<String, SynValue> = IndexMap::new();
        for c in &left_cols {
            let v = match (l, r) {
                (Some(l), _) => row_get(l, c, W)?,
                // Fila sólo de la derecha: la clave viene de la derecha.
                (None, Some(r)) if on.contains(c) => row_get(r, c, W)?,
                _ => SynValue::Nothing,
            };
            out.insert(c.clone(), v);
        }
        for (c, name) in &right_out {
            let v = match r {
                Some(r) => row_get(r, c, W)?,
                None => SynValue::Nothing,
            };
            out.insert(name.clone(), v);
        }
        Ok(syn_map(out))
    };
    let mut out = Vec::new();
    let mut right_used = vec![false; right.len()];
    for l in &left {
        let matches: &[usize] = match key(l)? {
            Some(k) => index.get(&k).map(|v| v.as_slice()).unwrap_or(&[]),
            None => &[],
        };
        match how.as_str() {
            "semi" => {
                if !matches.is_empty() {
                    out.push(l.clone());
                }
            }
            "anti" => {
                if matches.is_empty() {
                    out.push(l.clone());
                }
            }
            _ => {
                for &j in matches {
                    right_used[j] = true;
                    out.push(row_of(Some(l), Some(&right[j]))?);
                }
                if matches.is_empty() && (how == "left" || how == "outer") {
                    out.push(row_of(Some(l), None)?);
                }
            }
        }
    }
    if how == "right" || how == "outer" {
        for (j, r) in right.iter().enumerate() {
            if !right_used[j] {
                out.push(row_of(None, Some(r))?);
            }
        }
    }
    Ok(syn_list(out))
}

/// `pivot(rows, index, columns, values, agg?)` → una fila por valor de `index`, una columna
/// por valor distinto de `columns`. Si una celda junta varias filas hace falta `agg` (una
/// función del grupo, p. ej. `sum_of("monto")`); sin `agg` eso es error, no un "first"
/// silencioso.
pub fn pivot(interp: &mut Interpreter, args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "pivot";
    let rows = rows_arg(args.first().ok_or_else(|| err("pivot(rows, index, columns, values, agg?)"))?, W)?;
    let text = |i: usize, what: &str| -> Result<String, Control> {
        match args.get(i) {
            Some(SynValue::Text(t)) => Ok(t.to_string()),
            _ => Err(err(format!("{}: {} must be a column name", W, what))),
        }
    };
    let index = text(1, "index")?;
    let columns = text(2, "columns")?;
    let values = text(3, "values")?;
    let agg = args.get(4).filter(|v| !matches!(v, SynValue::Nothing)).cloned();
    let by_index = groups(interp, &rows, &KeySpec::Column(index.clone()), W)?;
    for c in [&index, &columns, &values] {
        check_column(&rows, c, W)?;
    }
    check_agg_columns(&rows, agg.iter())?;
    let _table_op = TableOpGuard::enter();
    let mut col_order: Vec<SynValue> = Vec::new();
    let mut col_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut names: std::collections::HashMap<String, SynValue> = std::collections::HashMap::new();
    let mut mix = NumMix::default();
    for r in &rows {
        let c = row_get(r, &columns, W)?;
        mix.check(&c, W)?;
        if col_seen.insert(probe_key(&c)) {
            // Cada valor distinto es una columna; dos que se escriben igual (`1` y `"1"`) o
            // uno que se llama como el índice perderían datos en silencio.
            let name = match &c {
                SynValue::Text(t) => t.to_string(),
                other => other.to_string(),
            };
            if name == index {
                return Err(err(format!(
                    "{}: the value {} of {:?} would become a column named like the index {:?}",
                    W,
                    c.nested_repr(),
                    columns,
                    index
                )));
            }
            if let Some(prev) = names.insert(name.clone(), c.clone()) {
                return Err(err(format!(
                    "{}: the values {} and {} of {:?} would both become the column {:?} — convert the column first so they differ",
                    W,
                    prev.nested_repr(),
                    c.nested_repr(),
                    columns,
                    name
                )));
            }
            col_order.push(c);
        }
    }
    let mut out = Vec::with_capacity(by_index.len());
    for (k, items) in by_index {
        let mut row = IndexMap::new();
        row.insert(index.clone(), k);
        let cells = groups(interp, &items, &KeySpec::Column(columns.clone()), W)?;
        for c in &col_order {
            let name = match c {
                SynValue::Text(t) => t.to_string(),
                other => other.to_string(),
            };
            let cell = cells.iter().find(|(ck, _)| probe_key(ck) == probe_key(c));
            let v = match (cell, &agg) {
                (None, _) => SynValue::Nothing,
                (Some((_, g)), Some(f)) => interp.call_task(f.clone(), vec![syn_list(g.clone())])?,
                (Some((_, g)), None) if g.len() == 1 => row_get(&g[0], &values, W)?,
                (Some((_, g)), None) => {
                    return Err(err(format!(
                        "{}: {} rows fall in the same cell ({} = {}) — pass agg, e.g. sum_of({:?})",
                        W,
                        g.len(),
                        columns,
                        name,
                        values
                    )))
                }
            };
            row.insert(name, v);
        }
        out.push(syn_map(row));
    }
    Ok(syn_list(out))
}

/// `is_missing(x)` → `x == nothing`.
pub fn is_missing(args: &[SynValue]) -> Result<SynValue, Control> {
    Ok(crate::types::syn_bool(matches!(args.first(), Some(SynValue::Nothing))))
}

/// `fill_missing(xs, value)` (lista) / `fill_missing(rows, value | {col: value})` → copia con
/// cada `nothing` reemplazado.
pub fn fill_missing(args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "fill_missing";
    let items = rows_arg(args.first().ok_or_else(|| err("fill_missing(items, value)"))?, W)?;
    let fill = args.get(1).ok_or_else(|| err("fill_missing(items, value): missing the value"))?;
    let out = items
        .into_iter()
        .map(|it| match it {
            SynValue::Nothing => fill.clone(),
            SynValue::Map(m) => {
                let mut copy = m.borrow().clone();
                for (k, v) in copy.iter_mut() {
                    if matches!(v, SynValue::Nothing) {
                        match fill {
                            SynValue::Map(per_col) => {
                                if let Some(f) = per_col.borrow().get(k) {
                                    *v = f.clone();
                                }
                            }
                            other => *v = other.clone(),
                        }
                    }
                }
                syn_map(copy)
            }
            other => other,
        })
        .collect();
    Ok(syn_list(out))
}

/// `drop_missing(xs)` / `drop_missing(rows)` / `drop_missing(rows, [cols])` → sin los
/// `nothing` (en una tabla, sin las filas que tienen alguno en esas columnas — o en
/// cualquiera si no se dicen).
pub fn drop_missing(args: &[SynValue]) -> Result<SynValue, Control> {
    const W: &str = "drop_missing";
    let items = rows_arg(args.first().ok_or_else(|| err("drop_missing(items, columns?)"))?, W)?;
    let cols: Option<Vec<String>> = match args.get(1) {
        None | Some(SynValue::Nothing) => None,
        Some(SynValue::Text(t)) => Some(vec![t.to_string()]),
        Some(SynValue::List(l)) => Some(l.borrow().iter().map(|v| v.to_string()).collect()),
        Some(other) => return Err(err(format!("{}: columns must be a name or a list of names, got {}", W, other.type_name()))),
    };
    let keep = |it: &SynValue| -> bool {
        match it {
            SynValue::Nothing => false,
            SynValue::Map(m) => {
                let m = m.borrow();
                match &cols {
                    Some(cs) => cs.iter().all(|c| !matches!(m.get(c), None | Some(SynValue::Nothing))),
                    None => !m.values().any(|v| matches!(v, SynValue::Nothing)),
                }
            }
            _ => true,
        }
    };
    Ok(syn_list(items.into_iter().filter(|it| keep(it)).collect()))
}

/// `fill_nan(x, value)`: lista o array con cada NaN reemplazado.
pub fn fill_nan(args: &[SynValue]) -> Result<SynValue, Control> {
    let fill = match args.get(1) {
        Some(SynValue::Number(n)) => n.clone(),
        _ => return Err(err("fill_nan(values, number): the replacement must be a number")),
    };
    match args.first() {
        Some(SynValue::List(l)) => Ok(syn_list(
            l.borrow()
                .iter()
                .map(|v| match v {
                    SynValue::Number(Number::Float(x)) if x.is_nan() => syn_number(fill.clone()),
                    other => other.clone(),
                })
                .collect(),
        )),
        Some(SynValue::Array(a)) => {
            let f = fill.to_f64();
            Ok(SynValue::Array(Rc::new(a.mapv(|x| if x.is_nan() { f } else { x }))))
        }
        Some(other) => Err(err(format!("fill_nan: expected a list or an array, got {}", other.type_name()))),
        None => Err(err("fill_nan(values, number)")),
    }
}

#[allow(dead_code)]
fn _text(s: &str) -> SynValue {
    syn_text(s)
}

/// `mode(xs)` → el valor más frecuente (empate: el que apareció primero); `nothing` se
/// saltea.
pub fn mode(args: &[SynValue]) -> Result<SynValue, Control> {
    let items = rows_arg(args.first().ok_or_else(|| err("mode(values)"))?, "mode")?;
    let mut counts: Vec<(SynValue, usize)> = Vec::new();
    let mut at: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut mix = NumMix::default();
    for v in items {
        if matches!(v, SynValue::Nothing) {
            continue;
        }
        mix.check(&v, "mode")?;
        let k = probe_key(&v);
        match at.get(&k) {
            Some(&i) => counts[i].1 += 1,
            None => {
                at.insert(k, counts.len());
                counts.push((v, 1));
            }
        }
    }
    let best = counts.iter().map(|(_, c)| *c).max().ok_or_else(|| err("mode of an empty list"))?;
    Ok(counts.into_iter().find(|(_, c)| *c == best).map(|(k, _)| k).unwrap())
}

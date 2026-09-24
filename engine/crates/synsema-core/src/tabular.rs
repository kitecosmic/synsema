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

/// Agrupa en orden de PRIMERA aparición; la clave conserva valor y tipo y se compara con la
/// igualdad del lenguaje (`1 == 1.0`). → `[(clave, filas)]`.
pub fn groups(
    interp: &mut Interpreter,
    rows: &[SynValue],
    spec: &KeySpec,
    who: &str,
) -> Result<Vec<(SynValue, Vec<SynValue>)>, Control> {
    let mut out: Vec<(SynValue, Vec<SynValue>)> = Vec::new();
    // Índice rápido por la forma de texto + verificación con syn_equals (colisiones como
    // `1` vs `"1"` quedan en grupos distintos).
    let mut index: std::collections::HashMap<String, Vec<usize>> = std::collections::HashMap::new();
    for row in rows {
        let k = key_of(interp, spec, row, who)?;
        let probe = probe_key(crate::labels::unwrap(&k));
        let slot = index.entry(probe).or_default();
        match slot.iter().copied().find(|&i| out[i].0.syn_equals(&k)) {
            Some(i) => out[i].1.push(row.clone()),
            None => {
                slot.push(out.len());
                out.push((k, vec![row.clone()]));
            }
        }
    }
    Ok(out)
}

/// Forma de texto para el índice rápido de `groups`: números iguales (`1`, `1.0`, `1d`)
/// caen en el mismo balde; `syn_equals` decide igual.
fn probe_key(v: &SynValue) -> String {
    match v {
        SynValue::Number(n) => match n {
            Number::Float(x) if x.is_finite() && x.fract() == 0.0 => format!("n:{}", Number::integer_from_f64(*x)),
            Number::Decimal(_) => match n.as_bigint() {
                Some(b) => format!("n:{}", b),
                None => format!("n:{}", n.to_f64()),
            },
            Number::Float(x) => format!("n:{}", x),
            other => format!("n:{}", other),
        },
        other => format!("{}", other),
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
    let gs = groups(interp, &rows, &spec, W)?;
    let mut out = Vec::with_capacity(gs.len());
    for (k, items) in gs {
        let mut row = IndexMap::new();
        match (&spec, &k) {
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
        for (name, f) in &aggs {
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

fn builtin_value(name: String, f: crate::interpreter::BuiltinFn) -> SynValue {
    SynValue::Builtin(Rc::new(BuiltinTask { name, func: f, param_count: 1, param_names: None }))
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
    let f: crate::interpreter::BuiltinFn = Rc::new(move |_i, a, _l| {
        let group = a.first().ok_or_else(|| err("an aggregate receives the group"))?;
        let who = if kind == "count" { "count" } else { kind };
        match kind {
            "count" => Ok(syn_int(rows_arg(group, who)?.len() as i64)),
            "first" => Ok(rows_arg(group, who)?.first().map(|r| row_get(r, &col, who)).transpose()?.unwrap_or(SynValue::Nothing)),
            "n_unique" => {
                let rows = rows_arg(group, who)?;
                let mut seen: Vec<SynValue> = Vec::new();
                for r in &rows {
                    let v = row_get(r, &col, who)?;
                    if !matches!(v, SynValue::Nothing) && !seen.iter().any(|s| s.syn_equals(&v)) {
                        seen.push(v);
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
    Ok(builtin_value(label, f))
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
/// presentes en ambos lados. `how`: "inner", "left", "outer". Columnas repetidas que no son
/// clave: la de la derecha lleva el sufijo `_right` (como polars). Sin match → `nothing`.
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
        Some(SynValue::Text(t)) if matches!(t.as_ref(), "inner" | "left" | "outer") => t.to_string(),
        Some(other) => return Err(err(format!("{}: how must be \"inner\", \"left\" or \"outer\", got {}", W, other))),
    };
    let key = |row: &SynValue| -> Result<Vec<SynValue>, Control> { on.iter().map(|c| row_get(row, c, W)).collect() };
    let same = |a: &[SynValue], b: &[SynValue]| a.iter().zip(b).all(|(x, y)| x.syn_equals(y) && !matches!(x, SynValue::Nothing));
    let right_keys: Vec<Vec<SynValue>> = right.iter().map(key).collect::<Result<_, _>>()?;
    let right_cols: Vec<String> = {
        let mut cols: Vec<String> = Vec::new();
        for r in &right {
            if let SynValue::Map(m) = r {
                for k in m.borrow().keys() {
                    if !cols.contains(k) {
                        cols.push(k.clone());
                    }
                }
            }
        }
        cols
    };
    let merge_rows = |l: Option<&SynValue>, r: Option<&SynValue>| -> SynValue {
        let mut out: IndexMap<String, SynValue> = IndexMap::new();
        if let Some(SynValue::Map(m)) = l {
            for (k, v) in m.borrow().iter() {
                out.insert(k.clone(), v.clone());
            }
        }
        match r {
            Some(SynValue::Map(m)) => {
                for (k, v) in m.borrow().iter() {
                    if on.contains(k) {
                        out.entry(k.clone()).or_insert_with(|| v.clone());
                    } else if out.contains_key(k) {
                        out.insert(format!("{}_right", k), v.clone());
                    } else {
                        out.insert(k.clone(), v.clone());
                    }
                }
            }
            _ => {
                for k in &right_cols {
                    if on.contains(k) {
                        continue;
                    }
                    let name = if out.contains_key(k) { format!("{}_right", k) } else { k.clone() };
                    out.entry(name).or_insert(SynValue::Nothing);
                }
            }
        }
        syn_map(out)
    };
    let mut out = Vec::new();
    let mut right_used = vec![false; right.len()];
    for l in &left {
        let lk = key(l)?;
        let mut matched = false;
        for (j, rk) in right_keys.iter().enumerate() {
            if same(&lk, rk) {
                matched = true;
                right_used[j] = true;
                out.push(merge_rows(Some(l), Some(&right[j])));
            }
        }
        if !matched && (how == "left" || how == "outer") {
            out.push(merge_rows(Some(l), None));
        }
    }
    if how == "outer" {
        for (j, r) in right.iter().enumerate() {
            if !right_used[j] {
                out.push(merge_rows(None, Some(r)));
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
    let mut col_order: Vec<SynValue> = Vec::new();
    for r in &rows {
        let c = row_get(r, &columns, W)?;
        if !col_order.iter().any(|x| x.syn_equals(&c)) {
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
            let cell = cells.iter().find(|(ck, _)| ck.syn_equals(c));
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
    for v in items {
        if matches!(v, SynValue::Nothing) {
            continue;
        }
        match counts.iter_mut().find(|(k, _)| k.syn_equals(&v)) {
            Some(c) => c.1 += 1,
            None => counts.push((v, 1)),
        }
    }
    let best = counts.iter().map(|(_, c)| *c).max().ok_or_else(|| err("mode of an empty list"))?;
    Ok(counts.into_iter().find(|(_, c)| *c == best).map(|(k, _)| k).unwrap())
}

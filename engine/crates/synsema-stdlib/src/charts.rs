//! Charts nativos (Batch 8): `chart_svg(kind, data, opts?)` → texto SVG y el nodo
//! `chart(kind, data, opts?)` de `content()` (negociado: HTML = SVG inline, Markdown =
//! tabla de datos, JSON = series estructuradas).
//!
//! Doctrina (spec batch-8 §0/§2):
//! - **AGNÓSTICO de fuente (G2):** la entrada son VALORES del lenguaje (lista de mapas
//!   como las filas de `sql()`/`mongo_find`/`csv_parse`, mapa label→valor, lista de
//!   números, lista de pares, `array` 1D). Este módulo NO importa nada de `database.rs`
//!   ni conoce conexiones.
//! - **Componible, no caja negra (G3):** `chart_svg` devuelve TEXTO SVG plano que el
//!   usuario puede editar/incrustar/servir/guardar; todos los defaults (colores, tamaño,
//!   títulos) se sobreescriben por `opts`.
//! - **XSS-safe (G4):** todo texto proveniente de los datos se escapa en el SVG (y en
//!   la tabla Markdown del nodo). El único escape hatch sigue siendo `raw()`.
//! - **Determinista (G7):** sin random ni timestamps — mismo input → mismo SVG byte a
//!   byte (habilita golden tests y cacheo).
//! - **Errores claros y atrapables (G5/G10):** datos vacíos, kind desconocido, campo
//!   inexistente, y no numérico, >8 series sin `colors` → error de runtime normal en
//!   inglés (jamás un gráfico vacío silencioso, jamás panic sobre input del usuario).
//! - **Paleta CVD-safe con orden FIJO** — más de 8 series/slices es un error que sugiere
//!   agrupar en "Other" o pasar `colors` propios (jamás ciclar/inventar tonos: es el
//!   mecanismo de seguridad para daltonismo).
//!
//! PURO (G9): sin capability — funciona en run/test/conform/serve y DENTRO de `sandbox`.

use std::rc::Rc;

use indexmap::IndexMap;
use synsema_core::interpreter::{Control, RuntimeError};
use synsema_core::number::py_float_str;
use synsema_core::types::{
    syn_float, syn_int, syn_list, syn_map, syn_nothing, syn_text, SynValue,
};

use crate::server::esc;

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

// =========================================================
// Defaults de diseño (paleta validada CVD-safe, orden FIJO)
// =========================================================

const PALETTE: [&str; 8] = [
    "#2a78d6", "#008300", "#e87ba4", "#eda100", "#1baf7a", "#eb6834", "#4a3aa7", "#e34948",
];
const INK: &str = "#52514e"; // labels / ejes
const MUTED: &str = "#898781"; // ticks / texto recesivo
const GRID: &str = "#e1e0d9"; // grid hairline
const BASELINE: &str = "#c3c2b7"; // baseline / eje cero
const DEFAULT_WIDTH: f64 = 640.0;
const DEFAULT_HEIGHT: f64 = 360.0;

// =========================================================
// Modelo normalizado (compartido por chart_svg y chart())
// =========================================================

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bar,
    Line,
    Pie,
    Scatter,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Bar => "bar",
            Kind::Line => "line",
            Kind::Pie => "pie",
            Kind::Scatter => "scatter",
        }
    }
}

#[derive(Clone)]
enum XValue {
    Num(f64),
    Label(String),
}

struct Series {
    name: String,
    points: Vec<(XValue, f64)>,
}

struct ChartSpec {
    kind: Kind,
    title: Option<String>,
    x_label: Option<String>,
    y_label: Option<String>,
    /// Nombre del campo x cuando la data fue lista de mapas (cabecera de la tabla MD).
    x_name: Option<String>,
    series: Vec<Series>,
    width: f64,
    height: f64,
    colors: Vec<String>,
    legend: bool,
    background: Option<String>,
}

// =========================================================
// Lectura de opts
// =========================================================

const VALID_OPTS: [&str; 10] = [
    "title", "x", "y", "width", "height", "colors", "x_label", "y_label", "legend", "background",
];

fn opts_of(args: &[SynValue], name: &str) -> Result<IndexMap<String, SynValue>, Control> {
    match args.get(2) {
        None | Some(SynValue::Nothing) => Ok(IndexMap::new()),
        Some(SynValue::Map(m)) => {
            let m = m.borrow();
            for k in m.keys() {
                if !VALID_OPTS.contains(&k.as_str()) {
                    return Err(err(format!(
                        "{}: unknown option {:?}; valid options are: {}",
                        name,
                        k,
                        VALID_OPTS.join(", ")
                    )));
                }
            }
            Ok(m.clone())
        }
        Some(other) => Err(err(format!(
            "{}: options must be a map, got {}",
            name,
            other.type_name()
        ))),
    }
}

fn opt_text(
    opts: &IndexMap<String, SynValue>,
    key: &str,
    name: &str,
) -> Result<Option<String>, Control> {
    match opts.get(key) {
        None | Some(SynValue::Nothing) => Ok(None),
        Some(SynValue::Text(s)) => Ok(Some(s.to_string())),
        Some(other) => Err(err(format!(
            "{}: option {:?} must be text, got {}",
            name,
            key,
            other.type_name()
        ))),
    }
}

fn opt_dim(
    opts: &IndexMap<String, SynValue>,
    key: &str,
    default: f64,
    name: &str,
) -> Result<f64, Control> {
    match opts.get(key) {
        None => Ok(default),
        Some(SynValue::Number(n)) => {
            let v = n.to_f64();
            if !v.is_finite() || !(16.0..=8192.0).contains(&v) {
                return Err(err(format!(
                    "{}: option {:?} must be a number between 16 and 8192, got {}",
                    name,
                    key,
                    py_float_str(v)
                )));
            }
            Ok(v.round())
        }
        Some(other) => Err(err(format!(
            "{}: option {:?} must be a number, got {}",
            name,
            key,
            other.type_name()
        ))),
    }
}

fn is_hex_color(s: &str) -> bool {
    let Some(hex) = s.strip_prefix('#') else { return false };
    matches!(hex.len(), 3 | 4 | 6 | 8) && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `colors`: lista de hex que REEMPLAZA la paleta default (G3).
fn opt_colors(opts: &IndexMap<String, SynValue>, name: &str) -> Result<Vec<String>, Control> {
    match opts.get("colors") {
        None => Ok(PALETTE.iter().map(|c| c.to_string()).collect()),
        Some(SynValue::List(l)) => {
            let items = l.borrow();
            if items.is_empty() {
                return Err(err(format!("{}: option \"colors\" cannot be an empty list", name)));
            }
            let mut out = Vec::with_capacity(items.len());
            for it in items.iter() {
                match it {
                    SynValue::Text(s) if is_hex_color(s) => out.push(s.to_string()),
                    SynValue::Text(s) => {
                        return Err(err(format!(
                            "{}: option \"colors\" must contain hex colors like \"#2a78d6\", got {:?}",
                            name, s
                        )))
                    }
                    other => {
                        return Err(err(format!(
                            "{}: option \"colors\" must be a list of hex color texts, got a {} inside",
                            name,
                            other.type_name()
                        )))
                    }
                }
            }
            Ok(out)
        }
        Some(other) => Err(err(format!(
            "{}: option \"colors\" must be a list of hex colors, got {}",
            name,
            other.type_name()
        ))),
    }
}

// =========================================================
// Normalización de datos (las 5 formas — G2)
// =========================================================

/// Valor numérico de una serie, con contexto de fila/campo para el error (G5).
fn num_of(v: &SynValue, name: &str, what: &str) -> Result<f64, Control> {
    match v {
        SynValue::Number(n) => {
            let f = n.to_f64();
            if f.is_nan() {
                return Err(err(format!("{}: {} is NaN; filter or replace NaN values first", name, what)));
            }
            if f.is_infinite() {
                return Err(err(format!(
                    "{}: {} is infinite; filter or replace infinite values first",
                    name, what
                )));
            }
            Ok(f)
        }
        // G8: un secret jamás se plotea como número.
        SynValue::Secret(_) => Err(err(format!(
            "{}: {} is a secret; secrets are never plotted as values",
            name, what
        ))),
        other => Err(err(format!(
            "{}: {} must be a number, got {}",
            name,
            what,
            other.type_name()
        ))),
    }
}

/// Valor de eje x: número → posición; texto (u otro escalar) → label categórico.
/// Un `secret` como label → "[redacted]" (G8).
fn x_of(v: &SynValue) -> XValue {
    match v {
        SynValue::Number(n) => XValue::Num(n.to_f64()),
        SynValue::Text(s) => XValue::Label(s.to_string()),
        SynValue::Secret(_) => XValue::Label("[redacted]".to_string()),
        other => XValue::Label(other.to_string()),
    }
}

/// Campos `y` de opts: un texto o una lista de textos (multi-serie).
fn y_fields(opts: &IndexMap<String, SynValue>, name: &str) -> Result<Option<Vec<String>>, Control> {
    match opts.get("y") {
        None | Some(SynValue::Nothing) => Ok(None),
        Some(SynValue::Text(s)) => Ok(Some(vec![s.to_string()])),
        Some(SynValue::List(l)) => {
            let items = l.borrow();
            if items.is_empty() {
                return Err(err(format!("{}: option \"y\" cannot be an empty list", name)));
            }
            let mut out = Vec::with_capacity(items.len());
            for it in items.iter() {
                match it {
                    SynValue::Text(s) => out.push(s.to_string()),
                    other => {
                        return Err(err(format!(
                            "{}: option \"y\" must be a field name or a list of field names, got a {} inside",
                            name,
                            other.type_name()
                        )))
                    }
                }
            }
            Ok(Some(out))
        }
        Some(other) => Err(err(format!(
            "{}: option \"y\" must be a field name or a list of field names, got {}",
            name,
            other.type_name()
        ))),
    }
}

/// Forma 1: lista de mapas (filas de `sql()`/`mongo_find`/`csv_parse`/literal) + opts x/y.
fn from_rows(
    rows: &[SynValue],
    opts: &IndexMap<String, SynValue>,
    kind: Kind,
    name: &str,
) -> Result<Vec<Series>, Control> {
    let x_field = opt_text(opts, "x", name)?.ok_or_else(|| {
        err(format!(
            "{}: data is a list of maps (rows); pass {{\"x\": \"field\", \"y\": \"field\"}} to pick the columns",
            name
        ))
    })?;
    let ys = y_fields(opts, name)?.ok_or_else(|| {
        err(format!(
            "{}: data is a list of maps (rows); pass {{\"x\": \"field\", \"y\": \"field\"}} to pick the columns",
            name
        ))
    })?;
    let mut series: Vec<Series> =
        ys.iter().map(|f| Series { name: f.clone(), points: Vec::new() }).collect();
    for (i, row) in rows.iter().enumerate() {
        let m = match row {
            SynValue::Map(m) => m.borrow(),
            other => {
                return Err(err(format!(
                    "{}: row {} is a {}, but the first row is a map; all rows must have the same shape",
                    name,
                    i + 1,
                    other.type_name()
                )))
            }
        };
        let xv = m.get(&x_field).ok_or_else(|| {
            err(format!(
                "{}: the x field {:?} is missing in row {}",
                name,
                x_field,
                i + 1
            ))
        })?;
        let x = x_of(xv);
        if kind == Kind::Scatter {
            if let XValue::Label(l) = &x {
                return Err(err(format!(
                    "{}: scatter requires numeric x values, but the x field {:?} in row {} is {:?}",
                    name,
                    x_field,
                    i + 1,
                    l
                )));
            }
        }
        // En line/scatter la x numérica es POSICIÓN (escala numérica): NaN/inf darían
        // coordenadas "NaN" en el SVG — inválido y silencioso (G5). En bar/pie la x es
        // sólo identidad (label), así que no aplica.
        if matches!(kind, Kind::Line | Kind::Scatter) {
            if let XValue::Num(v) = &x {
                if !v.is_finite() {
                    return Err(err(format!(
                        "{}: the x field {:?} in row {} is {}; filter or replace non-finite values first",
                        name,
                        x_field,
                        i + 1,
                        if v.is_nan() { "NaN" } else { "infinite" }
                    )));
                }
            }
        }
        for (s, field) in series.iter_mut().zip(&ys) {
            let yv = m.get(field).ok_or_else(|| {
                err(format!(
                    "{}: the y field {:?} is missing in row {}",
                    name,
                    field,
                    i + 1
                ))
            })?;
            let y = num_of(yv, name, &format!("the y field {:?} in row {}", field, i + 1))?;
            s.points.push((x.clone(), y));
        }
    }
    Ok(series)
}

/// Forma 4: lista de pares `[[x, y], …]` (scatter/line).
fn from_pairs(rows: &[SynValue], kind: Kind, name: &str) -> Result<Vec<Series>, Control> {
    if !matches!(kind, Kind::Scatter | Kind::Line) {
        return Err(err(format!(
            "{}: a list of [x, y] pairs plots as \"scatter\" or \"line\", not {:?}; for \"bar\"/\"pie\" pass a map of label to value",
            name,
            kind.name()
        )));
    }
    let mut points = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        let pair = match row {
            SynValue::List(l) => l.borrow().clone(),
            other => {
                return Err(err(format!(
                    "{}: item {} is a {}, but the first item is a list; all items must be [x, y] pairs",
                    name,
                    i + 1,
                    other.type_name()
                )))
            }
        };
        if pair.len() != 2 {
            return Err(err(format!(
                "{}: item {} has {} element(s); every item must be an [x, y] pair",
                name,
                i + 1,
                pair.len()
            )));
        }
        let x = num_of(&pair[0], name, &format!("the x value of pair {}", i + 1))?;
        let y = num_of(&pair[1], name, &format!("the y value of pair {}", i + 1))?;
        points.push((XValue::Num(x), y));
    }
    Ok(vec![Series { name: "value".to_string(), points }])
}

/// Formas 3 y 5: lista de números / `array` 1D (x implícito = índice 0..n).
fn from_numbers(vals: Vec<f64>, kind: Kind, name: &str) -> Result<Vec<Series>, Control> {
    if !matches!(kind, Kind::Bar | Kind::Line) {
        return Err(err(format!(
            "{}: a plain list of numbers plots as \"bar\" or \"line\", not {:?}; \"pie\" needs labels (a map) and \"scatter\" needs [x, y] pairs",
            name,
            kind.name()
        )));
    }
    let points = vals
        .into_iter()
        .enumerate()
        .map(|(i, v)| (XValue::Num(i as f64), v))
        .collect();
    Ok(vec![Series { name: "value".to_string(), points }])
}

/// Punto de entrada compartido por `chart_svg` y `chart()` (spec §5.2): valida kind,
/// datos y opts, y devuelve el modelo normalizado.
fn normalize_series(args: &[SynValue], name: &str) -> Result<ChartSpec, Control> {
    if args.len() < 2 || args.len() > 3 {
        return Err(err(format!(
            "{} expects (kind, data, options?) — 2 or 3 argument(s), got {}",
            name,
            args.len()
        )));
    }
    let kind = match &args[0] {
        SynValue::Text(s) => match &**s {
            "bar" => Kind::Bar,
            "line" => Kind::Line,
            "pie" => Kind::Pie,
            "scatter" => Kind::Scatter,
            other => {
                return Err(err(format!(
                    "{}: unknown chart kind {:?}; valid kinds are: bar, line, pie, scatter",
                    name, other
                )))
            }
        },
        other => {
            return Err(err(format!(
                "{}: the chart kind must be text (\"bar\", \"line\", \"pie\" or \"scatter\"), got {}",
                name,
                other.type_name()
            )))
        }
    };
    let opts = opts_of(args, name)?;

    // x/y sólo aplican a la forma lista-de-mapas; en otra forma serían ignorados en
    // silencio (G5: nunca silencioso).
    let is_rows = matches!(&args[1], SynValue::List(l) if matches!(l.borrow().first(), Some(SynValue::Map(_))));
    if !is_rows && (opts.contains_key("x") || opts.contains_key("y")) {
        return Err(err(format!(
            "{}: options \"x\"/\"y\" only apply when data is a list of maps (rows)",
            name
        )));
    }

    let x_name = if is_rows { opt_text(&opts, "x", name)? } else { None };
    let series = match &args[1] {
        SynValue::List(l) => {
            let items = l.borrow().clone();
            if items.is_empty() {
                return Err(err(format!("{}: data is empty; nothing to plot", name)));
            }
            match &items[0] {
                SynValue::Map(_) => from_rows(&items, &opts, kind, name)?,
                SynValue::List(_) => from_pairs(&items, kind, name)?,
                SynValue::Number(_) => {
                    let mut vals = Vec::with_capacity(items.len());
                    for (i, it) in items.iter().enumerate() {
                        vals.push(num_of(it, name, &format!("item {}", i + 1))?);
                    }
                    from_numbers(vals, kind, name)?
                }
                other => {
                    return Err(err(format!(
                        "{}: data must be a list of maps (rows), a map of label to value, a list of numbers, a list of [x, y] pairs, or a 1-D array; got a list of {}",
                        name,
                        other.type_name()
                    )))
                }
            }
        }
        // Forma 2: mapa label→valor (natural para group_by + reduce).
        SynValue::Map(m) => {
            if kind == Kind::Scatter {
                return Err(err(format!(
                    "{}: a map of label to value plots as \"bar\", \"line\" or \"pie\"; \"scatter\" needs numeric [x, y] pairs",
                    name
                )));
            }
            let m = m.borrow();
            if m.is_empty() {
                return Err(err(format!("{}: data is empty; nothing to plot", name)));
            }
            let mut points = Vec::with_capacity(m.len());
            for (k, v) in m.iter() {
                let y = num_of(v, name, &format!("the value of {:?}", k))?;
                points.push((XValue::Label(k.clone()), y));
            }
            vec![Series { name: "value".to_string(), points }]
        }
        // Forma 5: array 1-D (2-D multi-serie = futuro).
        SynValue::Array(a) => {
            if a.ndim() != 1 {
                return Err(err(format!(
                    "{}: only 1-D arrays can be plotted directly (got a {}-D array); convert with to_list() or pass rows",
                    name,
                    a.ndim()
                )));
            }
            if a.is_empty() {
                return Err(err(format!("{}: data is empty; nothing to plot", name)));
            }
            let vals: Vec<f64> = a.iter().copied().collect();
            if vals.iter().any(|v| !v.is_finite()) {
                return Err(err(format!(
                    "{}: the data contains NaN or infinite values; filter or replace them first",
                    name
                )));
            }
            from_numbers(vals, kind, name)?
        }
        other => {
            return Err(err(format!(
                "{}: data must be a list of maps (rows), a map of label to value, a list of numbers, a list of [x, y] pairs, or a 1-D array; got {}",
                name,
                other.type_name()
            )))
        }
    };

    let colors = opt_colors(&opts, name)?;
    // Paleta de orden fijo: más series que colores es un error (jamás ciclar — G5 y
    // seguridad CVD). Pie: la misma regla sobre los slices.
    let needed = if kind == Kind::Pie { series[0].points.len() } else { series.len() };
    let what = if kind == Kind::Pie { "slices" } else { "series" };
    if needed > colors.len() {
        return Err(err(format!(
            "{}: {} {} but only {} colors are available; group the long tail into an \"Other\" bucket or pass a \"colors\" list with at least {} entries (colors are never cycled)",
            name,
            needed,
            what,
            colors.len(),
            needed
        )));
    }
    if kind == Kind::Pie && series.len() > 1 {
        return Err(err(format!(
            "{}: pie charts take a single series, got {}; plot one field or use \"bar\"",
            name,
            series.len()
        )));
    }

    let legend = match opts.get("legend") {
        None => kind == Kind::Pie || series.len() >= 2, // auto
        Some(SynValue::Bool(b)) => *b,
        Some(other) => {
            return Err(err(format!(
                "{}: option \"legend\" must be true or false, got {}",
                name,
                other.type_name()
            )))
        }
    };
    let background = match opt_text(&opts, "background", name)? {
        Some(b) if !is_hex_color(&b) => {
            return Err(err(format!(
                "{}: option \"background\" must be a hex color like \"#fcfcfb\", got {:?}",
                name, b
            )))
        }
        b => b,
    };

    Ok(ChartSpec {
        kind,
        title: opt_text(&opts, "title", name)?,
        x_label: opt_text(&opts, "x_label", name)?,
        y_label: opt_text(&opts, "y_label", name)?,
        x_name,
        series,
        width: opt_dim(&opts, "width", DEFAULT_WIDTH, name)?,
        height: opt_dim(&opts, "height", DEFAULT_HEIGHT, name)?,
        colors,
        legend,
        background,
    })
}

// =========================================================
// Formato numérico determinista
// =========================================================

/// Coordenada SVG: 2 decimales, sin ceros colgantes ("-0" → "0").
fn fx(v: f64) -> String {
    let s = format!("{:.2}", v);
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s == "-0" { "0".to_string() } else { s.to_string() }
}

/// Label corto de un valor de datos: enteros sin ".0"; el resto estilo Python.
fn fmt_x(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        py_float_str(v)
    }
}

/// Label de tick: legible también con números enormes/minúsculos (notación e).
fn fmt_tick(v: f64) -> String {
    if v == 0.0 {
        return "0".to_string();
    }
    let a = v.abs();
    if !(1e-4..1e7).contains(&a) {
        let exp = a.log10().floor() as i32;
        let mant = v / 10f64.powi(exp);
        let m = format!("{:.2}", mant);
        let m = m.trim_end_matches('0').trim_end_matches('.');
        format!("{}e{}", m, exp)
    } else {
        let s = format!("{:.6}", v);
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

// =========================================================
// Escalas (ticks "nice", deterministas)
// =========================================================

fn nice_step(range: f64, target: usize) -> f64 {
    let raw = range / target as f64;
    let mag = 10f64.powf(raw.log10().floor());
    let norm = raw / mag;
    let n = if norm <= 1.0 {
        1.0
    } else if norm <= 2.0 {
        2.0
    } else if norm <= 5.0 {
        5.0
    } else {
        10.0
    };
    n * mag
}

/// Ticks que CUBREN [min, max] (el rango del plot son los bordes de tick — ese es el
/// "margen" de line/scatter). min == max se expande antes de calcular.
fn ticks_covering(mut min: f64, mut max: f64) -> (Vec<f64>, f64, f64) {
    if min == max {
        let pad = if min == 0.0 { 0.5 } else { min.abs() * 0.1 };
        min -= pad;
        max += pad;
    }
    let step = nice_step(max - min, 5);
    let lo = (min / step).floor() * step;
    let hi = (max / step).ceil() * step;
    let n = ((hi - lo) / step).round() as i64;
    let ticks = (0..=n).map(|i| lo + step * i as f64).collect();
    (ticks, lo, hi)
}

// =========================================================
// Renderer SVG
// =========================================================

struct Layout {
    left: f64,
    top: f64,
    plot_w: f64,
    plot_h: f64,
}

fn layout(spec: &ChartSpec) -> Result<Layout, Control> {
    let left = 52.0 + if spec.y_label.is_some() { 18.0 } else { 0.0 };
    let top = 12.0 + if spec.title.is_some() { 26.0 } else { 0.0 };
    let right = 16.0 + if spec.legend { 132.0 } else { 0.0 };
    let bottom = 32.0 + if spec.x_label.is_some() { 18.0 } else { 0.0 };
    let (left, bottom) = if spec.kind == Kind::Pie { (16.0, 16.0) } else { (left, bottom) };
    let plot_w = spec.width - left - right;
    let plot_h = spec.height - top - bottom;
    if plot_w < 32.0 || plot_h < 32.0 {
        return Err(err(format!(
            "chart: the plot area is too small ({}x{}); increase \"width\"/\"height\"",
            fx(plot_w),
            fx(plot_h)
        )));
    }
    Ok(Layout { left, top, plot_w, plot_h })
}

fn svg_open(spec: &ChartSpec, out: &mut String) {
    out.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {w} {h}\" width=\"{w}\" height=\"{h}\" role=\"img\" font-family=\"system-ui, sans-serif\">\n",
        w = fx(spec.width),
        h = fx(spec.height)
    ));
    if let Some(t) = &spec.title {
        out.push_str(&format!("<title>{}</title>\n", esc(t)));
    }
    if let Some(bg) = &spec.background {
        out.push_str(&format!(
            "<rect x=\"0\" y=\"0\" width=\"{}\" height=\"{}\" fill=\"{}\"/>\n",
            fx(spec.width),
            fx(spec.height),
            esc(bg)
        ));
    }
    if let Some(t) = &spec.title {
        out.push_str(&format!(
            "<text x=\"{}\" y=\"22\" text-anchor=\"middle\" font-size=\"14\" font-weight=\"600\" fill=\"{}\">{}</text>\n",
            fx(spec.width / 2.0),
            INK,
            esc(t)
        ));
    }
}

/// Grid horizontal recesivo + labels de ticks del eje Y. Devuelve el mapeo y→px.
fn y_axis(
    ticks: &[f64],
    ylo: f64,
    yhi: f64,
    l: &Layout,
    out: &mut String,
) -> impl Fn(f64) -> f64 {
    let (top, plot_h, left, plot_w) = (l.top, l.plot_h, l.left, l.plot_w);
    let sy = move |v: f64| top + plot_h - (v - ylo) / (yhi - ylo) * plot_h;
    for t in ticks {
        let y = sy(*t);
        out.push_str(&format!(
            "<line x1=\"{}\" y1=\"{y}\" x2=\"{}\" y2=\"{y}\" stroke=\"{}\" stroke-width=\"1\"/>\n",
            fx(left),
            fx(left + plot_w),
            GRID,
            y = fx(y)
        ));
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"end\" font-size=\"11\" fill=\"{}\">{}</text>\n",
            fx(left - 8.0),
            fx(y + 3.5),
            MUTED,
            esc(&fmt_tick(*t))
        ));
    }
    sy
}

fn axis_labels(spec: &ChartSpec, l: &Layout, out: &mut String) {
    if let Some(xl) = &spec.x_label {
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" font-size=\"12\" fill=\"{}\">{}</text>\n",
            fx(l.left + l.plot_w / 2.0),
            fx(spec.height - 8.0),
            INK,
            esc(xl)
        ));
    }
    if let Some(yl) = &spec.y_label {
        let cy = l.top + l.plot_h / 2.0;
        out.push_str(&format!(
            "<text x=\"14\" y=\"{}\" text-anchor=\"middle\" font-size=\"12\" fill=\"{}\" transform=\"rotate(-90 14 {})\">{}</text>\n",
            fx(cy),
            INK,
            fx(cy),
            esc(yl)
        ));
    }
}

fn legend(items: &[(String, &str)], spec: &ChartSpec, l: &Layout, out: &mut String) {
    if !spec.legend {
        return;
    }
    let x = spec.width - 140.0;
    for (i, (label, color)) in items.iter().enumerate() {
        let y = l.top + 6.0 + 18.0 * i as f64;
        out.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"10\" height=\"10\" rx=\"2\" fill=\"{}\"/>\n",
            fx(x),
            fx(y),
            color
        ));
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"11\" fill=\"{}\">{}</text>\n",
            fx(x + 15.0),
            fx(y + 9.0),
            INK,
            esc(label)
        ));
    }
}

/// Labels de categoría bajo el eje X (como máximo ~12, salteando deterministamente).
fn category_labels(labels: &[String], centers: &[f64], l: &Layout, out: &mut String) {
    let step = labels.len().div_ceil(12).max(1);
    for (i, (label, cx)) in labels.iter().zip(centers).enumerate() {
        if i % step != 0 {
            continue;
        }
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" font-size=\"11\" fill=\"{}\">{}</text>\n",
            fx(*cx),
            fx(l.top + l.plot_h + 16.0),
            INK,
            esc(label)
        ));
    }
}

/// Label de un punto para el eje/tabla: texto tal cual, número compacto.
fn x_display(x: &XValue) -> String {
    match x {
        XValue::Label(s) => s.clone(),
        XValue::Num(v) => fmt_x(*v),
    }
}

/// ¿Eje x categórico? (algún label textual en la primera serie)
fn is_categorical(spec: &ChartSpec) -> bool {
    spec.series[0].points.iter().any(|(x, _)| matches!(x, XValue::Label(_)))
}

fn render_bar(spec: &ChartSpec, l: &Layout, out: &mut String) {
    let all: Vec<f64> = spec.series.iter().flat_map(|s| s.points.iter().map(|(_, y)| *y)).collect();
    let (mut lo, mut hi) = (0f64, 0f64);
    for v in &all {
        lo = lo.min(*v);
        hi = hi.max(*v);
    }
    if lo == 0.0 && hi == 0.0 {
        hi = 1.0;
    }
    // El eje Y de un bar SIEMPRE incluye el cero (nunca truncado).
    let (ticks, ylo, yhi) = ticks_covering(lo, hi);
    let sy = y_axis(&ticks, ylo, yhi, l, out);

    let n = spec.series[0].points.len();
    let m = spec.series.len();
    let band = l.plot_w / n as f64;
    let group_w = band * 0.72;
    let bar_w = group_w / m as f64;
    let y0 = sy(0.0);
    for (si, s) in spec.series.iter().enumerate() {
        let color = &spec.colors[si];
        for (i, (_, v)) in s.points.iter().enumerate() {
            let x = l.left + band * i as f64 + (band - group_w) / 2.0 + bar_w * si as f64
                + bar_w * 0.05;
            let y1 = sy(*v);
            // Negativos: barra bajo el eje (rect desde y0 hacia abajo).
            let (ry, rh) = if *v >= 0.0 { (y1, y0 - y1) } else { (y0, y1 - y0) };
            out.push_str(&format!(
                "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"/>\n",
                fx(x),
                fx(ry),
                fx(bar_w * 0.9),
                fx(rh),
                color
            ));
        }
    }
    // Baseline del cero por encima de las barras (visible con negativos).
    out.push_str(&format!(
        "<line x1=\"{}\" y1=\"{y}\" x2=\"{}\" y2=\"{y}\" stroke=\"{}\" stroke-width=\"1\"/>\n",
        fx(l.left),
        fx(l.left + l.plot_w),
        BASELINE,
        y = fx(y0)
    ));
    let labels: Vec<String> = spec.series[0].points.iter().map(|(x, _)| x_display(x)).collect();
    let centers: Vec<f64> = (0..n).map(|i| l.left + band * (i as f64 + 0.5)).collect();
    category_labels(&labels, &centers, l, out);
}

/// Mapeo x→px de line/scatter (banda categórica o escala numérica).
type XScale = Box<dyn Fn(&XValue, usize) -> f64>;

fn render_line_scatter(spec: &ChartSpec, l: &Layout, out: &mut String) {
    let all: Vec<f64> = spec.series.iter().flat_map(|s| s.points.iter().map(|(_, y)| *y)).collect();
    let (ymin, ymax) = all.iter().fold((f64::INFINITY, f64::NEG_INFINITY), |(a, b), v| {
        (a.min(*v), b.max(*v))
    });
    let (ticks, ylo, yhi) = ticks_covering(ymin, ymax);
    let sy = y_axis(&ticks, ylo, yhi, l, out);

    let categorical = is_categorical(spec);
    let sx: XScale = if categorical {
        let n = spec.series[0].points.len();
        let band = l.plot_w / n as f64;
        let left = l.left;
        Box::new(move |_x, i| left + band * (i as f64 + 0.5))
    } else {
        let xs: Vec<f64> = spec
            .series
            .iter()
            .flat_map(|s| s.points.iter())
            .map(|(x, _)| match x {
                XValue::Num(v) => *v,
                XValue::Label(_) => 0.0,
            })
            .collect();
        let (xmin, xmax) = xs.iter().fold((f64::INFINITY, f64::NEG_INFINITY), |(a, b), v| {
            (a.min(*v), b.max(*v))
        });
        let (xticks, xlo, xhi) = ticks_covering(xmin, xmax);
        // Ticks numéricos del eje X (sin grid vertical: el grid es sólo horizontal).
        for t in &xticks {
            let x = l.left + (t - xlo) / (xhi - xlo) * l.plot_w;
            out.push_str(&format!(
                "<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" font-size=\"11\" fill=\"{}\">{}</text>\n",
                fx(x),
                fx(l.top + l.plot_h + 16.0),
                MUTED,
                esc(&fmt_tick(*t))
            ));
        }
        let (left, plot_w) = (l.left, l.plot_w);
        Box::new(move |x, _i| match x {
            XValue::Num(v) => left + (v - xlo) / (xhi - xlo) * plot_w,
            XValue::Label(_) => left,
        })
    };

    // Baseline en el piso del plot.
    out.push_str(&format!(
        "<line x1=\"{}\" y1=\"{y}\" x2=\"{}\" y2=\"{y}\" stroke=\"{}\" stroke-width=\"1\"/>\n",
        fx(l.left),
        fx(l.left + l.plot_w),
        BASELINE,
        y = fx(l.top + l.plot_h)
    ));

    for (si, s) in spec.series.iter().enumerate() {
        let color = &spec.colors[si];
        if spec.kind == Kind::Line {
            let pts: Vec<String> = s
                .points
                .iter()
                .enumerate()
                .map(|(i, (x, y))| format!("{},{}", fx(sx(x, i)), fx(sy(*y))))
                .collect();
            out.push_str(&format!(
                "<polyline points=\"{}\" fill=\"none\" stroke=\"{}\" stroke-width=\"2\" stroke-linejoin=\"round\" stroke-linecap=\"round\"/>\n",
                pts.join(" "),
                color
            ));
        } else {
            // Markers de scatter ≥ 8 px de diámetro.
            for (i, (x, y)) in s.points.iter().enumerate() {
                out.push_str(&format!(
                    "<circle cx=\"{}\" cy=\"{}\" r=\"4\" fill=\"{}\"/>\n",
                    fx(sx(x, i)),
                    fx(sy(*y)),
                    color
                ));
            }
        }
    }
    if categorical {
        let labels: Vec<String> = spec.series[0].points.iter().map(|(x, _)| x_display(x)).collect();
        let n = labels.len();
        let band = l.plot_w / n as f64;
        let centers: Vec<f64> = (0..n).map(|i| l.left + band * (i as f64 + 0.5)).collect();
        category_labels(&labels, &centers, l, out);
    }
}

fn render_pie(spec: &ChartSpec, l: &Layout, out: &mut String, name: &str) -> Result<(), Control> {
    let points = &spec.series[0].points;
    let mut total = 0.0;
    for (x, v) in points {
        if *v < 0.0 {
            return Err(err(format!(
                "{}: pie values must be non-negative, got {} for {:?}",
                name,
                py_float_str(*v),
                x_display(x)
            )));
        }
        total += v;
    }
    if total <= 0.0 {
        return Err(err(format!("{}: pie values sum to 0; nothing to plot", name)));
    }
    let cx = l.left + l.plot_w / 2.0;
    let cy = l.top + l.plot_h / 2.0;
    let r = (l.plot_w.min(l.plot_h) / 2.0 - 4.0).max(8.0);
    let mut angle = -std::f64::consts::FRAC_PI_2; // arranca a las 12 en punto
    for (i, (_, v)) in points.iter().enumerate() {
        let frac = v / total;
        let color = &spec.colors[i];
        if frac >= 1.0 {
            out.push_str(&format!(
                "<circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"{}\"/>\n",
                fx(cx),
                fx(cy),
                fx(r),
                color
            ));
            break;
        }
        if frac == 0.0 {
            continue;
        }
        let a1 = angle + frac * std::f64::consts::TAU;
        let (x0, y0) = (cx + r * angle.cos(), cy + r * angle.sin());
        let (x1, y1) = (cx + r * a1.cos(), cy + r * a1.sin());
        let large = if (a1 - angle) > std::f64::consts::PI { 1 } else { 0 };
        out.push_str(&format!(
            "<path d=\"M {cx} {cy} L {x0} {y0} A {r} {r} 0 {large} 1 {x1} {y1} Z\" fill=\"{color}\"/>\n",
            cx = fx(cx),
            cy = fx(cy),
            x0 = fx(x0),
            y0 = fx(y0),
            r = fx(r),
            large = large,
            x1 = fx(x1),
            y1 = fx(y1),
            color = color
        ));
        angle = a1;
    }
    Ok(())
}

/// Renderer central: `ChartSpec` normalizado → SVG completo (determinista, G7).
fn render_svg(spec: &ChartSpec, name: &str) -> Result<String, Control> {
    let l = layout(spec)?;
    let mut out = String::with_capacity(2048);
    svg_open(spec, &mut out);
    match spec.kind {
        Kind::Bar => render_bar(spec, &l, &mut out),
        Kind::Line | Kind::Scatter => render_line_scatter(spec, &l, &mut out),
        Kind::Pie => render_pie(spec, &l, &mut out, name)?,
    }
    if spec.kind != Kind::Pie {
        axis_labels(spec, &l, &mut out);
    }
    let legend_items: Vec<(String, &str)> = if spec.kind == Kind::Pie {
        spec.series[0]
            .points
            .iter()
            .enumerate()
            .map(|(i, (x, _))| (x_display(x), spec.colors[i].as_str()))
            .collect()
    } else {
        spec.series
            .iter()
            .enumerate()
            .map(|(i, s)| (s.name.clone(), spec.colors[i].as_str()))
            .collect()
    };
    legend(&legend_items, spec, &l, &mut out);
    out.push_str("</svg>\n");
    Ok(out)
}

// =========================================================
// Builtins: chart_svg / chart (nodo de content())
// =========================================================

/// `chart_svg(kind, data, opts?)` → texto SVG plano (componible: replace_text /
/// `{ raw ... }` en render() / respond(svg, "image/svg+xml") / write_file).
pub fn chart_svg(args: &[SynValue]) -> Result<SynValue, Control> {
    let spec = normalize_series(args, "chart_svg")?;
    Ok(syn_text(render_svg(&spec, "chart_svg")?))
}

/// `chart(kind, data, opts?)` → nodo de `content()` (spec §5.2). Comparte TODA la
/// normalización y el renderer con `chart_svg`: el HTML del nodo son los MISMOS bytes.
pub fn chart_node(args: &[SynValue]) -> Result<SynValue, Control> {
    let spec = normalize_series(args, "chart")?;
    let svg = render_svg(&spec, "chart")?;
    // Series normalizadas como valores del lenguaje: alimentan la tabla Markdown y el
    // JSON estructurado ({"series": [{"name", "points": [[x, y], …]}, …]}).
    let series_val = syn_list(
        spec.series
            .iter()
            .map(|s| {
                let mut m = IndexMap::new();
                m.insert("name".to_string(), syn_text(s.name.as_str()));
                m.insert(
                    "points".to_string(),
                    syn_list(
                        s.points
                            .iter()
                            .map(|(x, y)| {
                                let xv = match x {
                                    XValue::Label(l) => syn_text(l.as_str()),
                                    XValue::Num(v) if v.fract() == 0.0 && v.abs() < 1e15 => {
                                        syn_int(*v as i64)
                                    }
                                    XValue::Num(v) => syn_float(*v),
                                };
                                syn_list(vec![xv, syn_float(*y)])
                            })
                            .collect(),
                    ),
                );
                syn_map(m)
            })
            .collect(),
    );
    let text_or_nothing = |o: &Option<String>| match o {
        Some(s) => syn_text(s.as_str()),
        None => syn_nothing(),
    };
    Ok(crate::server::make_node(
        "chart",
        vec![
            ("chart_kind", syn_text(spec.kind.name())),
            ("title", text_or_nothing(&spec.title)),
            ("x_label", text_or_nothing(&spec.x_label)),
            ("y_label", text_or_nothing(&spec.y_label)),
            ("x_name", text_or_nothing(&spec.x_name)),
            ("series", series_val),
            ("svg", syn_text(svg.as_str())),
        ],
    ))
}

// =========================================================
// Render Markdown del nodo (la salida para agentes: DATOS, no píxeles)
// =========================================================

/// Celda de la tabla Markdown: escapa `|` y HTML (G4 — muchos consumidores de MD
/// renderizan HTML embebido) y aplana saltos de línea.
fn md_cell(s: &str) -> String {
    esc(s).replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn field_str(node: &SynValue, key: &str) -> Option<String> {
    match node {
        SynValue::Server(s) => match s.get_field(key) {
            Some(SynValue::Text(t)) => Some(t.to_string()),
            _ => None,
        },
        _ => None,
    }
}

/// `chart()` en la representación Markdown: `**título**` + tabla de los datos
/// normalizados (columnas = x + una por serie). El agente obtiene los DATOS.
pub fn render_chart_md(node: &SynValue) -> String {
    let series = match node {
        SynValue::Server(s) => match s.get_field("series") {
            Some(SynValue::List(l)) => l.borrow().clone(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    // (nombre, puntos) de cada serie, leyendo los valores del nodo.
    let mut cols: Vec<(String, Vec<SynValue>)> = Vec::new();
    for s in &series {
        if let SynValue::Map(m) = s {
            let m = m.borrow();
            let name = m.get("name").map(|v| v.to_string()).unwrap_or_default();
            let points = match m.get("points") {
                Some(SynValue::List(l)) => l.borrow().clone(),
                _ => Vec::new(),
            };
            cols.push((name, points));
        }
    }
    if cols.is_empty() {
        return String::new();
    }
    let x_header = field_str(node, "x_label")
        .or_else(|| field_str(node, "x_name"))
        .unwrap_or_else(|| "x".to_string());
    let mut out = String::new();
    if let Some(t) = field_str(node, "title") {
        out.push_str(&format!("**{}**\n\n", md_cell(&t)));
    }
    out.push_str(&format!("| {} |", md_cell(&x_header)));
    for (name, _) in &cols {
        out.push_str(&format!(" {} |", md_cell(name)));
    }
    out.push_str("\n|");
    for _ in 0..=cols.len() {
        out.push_str(" --- |");
    }
    let rows = cols.iter().map(|(_, p)| p.len()).max().unwrap_or(0);
    for i in 0..rows {
        out.push_str("\n|");
        // La x de la fila sale de la primera serie que la tenga (todas comparten x).
        let x = cols.iter().find_map(|(_, p)| p.get(i)).and_then(|pt| match pt {
            SynValue::List(l) => l.borrow().first().map(|v| v.to_string()),
            _ => None,
        });
        out.push_str(&format!(" {} |", md_cell(&x.unwrap_or_default())));
        for (_, points) in &cols {
            let y = points.get(i).and_then(|pt| match pt {
                SynValue::List(l) => l.borrow().get(1).map(|v| v.to_string()),
                _ => None,
            });
            out.push_str(&format!(" {} |", md_cell(&y.unwrap_or_default())));
        }
    }
    out.push('\n');
    out
}

/// Registro de los builtins de charts. Se llama desde `register_serve_builtins`
/// (server.rs), que el runtime cablea en TODOS los modos (run/test/conform/serve — G9).
pub fn register_chart_builtins(interp: &synsema_core::interpreter::Interpreter) {
    interp.register_builtin("chart_svg", -1, Rc::new(|_i, a, _l| chart_svg(a)));
    interp.register_builtin("chart", -1, Rc::new(|_i, a, _l| chart_node(a)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map1(pairs: &[(&str, f64)]) -> SynValue {
        let mut m = IndexMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), syn_float(*v));
        }
        syn_map(m)
    }

    /// `Control` no implementa Debug: desarma el Result a mano.
    fn ok(r: Result<SynValue, Control>) -> SynValue {
        match r {
            Ok(v) => v,
            Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
            Err(_) => panic!("control inesperado"),
        }
    }

    fn svg_of(args: &[SynValue]) -> String {
        match ok(chart_svg(args)) {
            SynValue::Text(s) => s.to_string(),
            other => panic!("expected text, got {}", other.type_name()),
        }
    }

    fn err_of(args: &[SynValue]) -> String {
        match chart_svg(args) {
            Err(Control::Error(re)) => re.message,
            other => panic!("expected an error, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn bar_from_map_deterministic_and_structural() {
        let data = map1(&[("ene", 10.0), ("feb", 25.0), ("mar", 5.0)]);
        let args = vec![syn_text("bar"), data];
        let a = svg_of(&args);
        let b = svg_of(&args);
        assert_eq!(a, b, "mismo input debe dar el mismo SVG byte a byte (G7)");
        assert!(a.starts_with("<svg xmlns="), "{}", a);
        assert!(a.contains("viewBox=\"0 0 640 360\""), "{}", a);
        assert_eq!(a.matches("<rect").count(), 3, "una barra por categoría:\n{}", a);
        assert!(a.contains(PALETTE[0]), "primer color default en orden fijo");
        assert!(a.contains(">ene<") && a.contains(">feb<"), "labels de categoría:\n{}", a);
    }

    #[test]
    fn xss_labels_escaped_everywhere() {
        let data = map1(&[("<script>alert(1)</script>", 4.0), ("b", 2.0)]);
        let mut opts = IndexMap::new();
        opts.insert("title".to_string(), syn_text("<img onerror=x>"));
        let args = vec![syn_text("pie"), data, syn_map(opts)];
        let svg = svg_of(&args);
        assert!(!svg.contains("<script>"), "label sin escapar:\n{}", svg);
        assert!(!svg.contains("<img"), "título sin escapar:\n{}", svg);
        assert!(svg.contains("&lt;script&gt;"), "{}", svg);
        // Y en la tabla Markdown del nodo:
        let node = ok(chart_node(&args));
        let md = render_chart_md(&node);
        assert!(!md.contains("<script>"), "MD sin escapar:\n{}", md);
        assert!(md.contains("&lt;script&gt;"), "{}", md);
    }

    #[test]
    fn errors_are_clear() {
        assert!(err_of(&[syn_text("area"), map1(&[("a", 1.0)])])
            .contains("valid kinds are: bar, line, pie, scatter"));
        assert!(err_of(&[syn_text("bar"), syn_list(vec![])]).contains("data is empty"));
        let nine = map1(&[
            ("a", 1.0), ("b", 1.0), ("c", 1.0), ("d", 1.0), ("e", 1.0),
            ("f", 1.0), ("g", 1.0), ("h", 1.0), ("i", 1.0),
        ]);
        let e = err_of(&[syn_text("pie"), nine]);
        assert!(e.contains("Other") && e.contains("colors"), "{}", e);
        // campo inexistente en filas
        let mut row = IndexMap::new();
        row.insert("mes".to_string(), syn_text("ene"));
        row.insert("total".to_string(), syn_float(10.0));
        let rows = syn_list(vec![syn_map(row)]);
        let mut opts = IndexMap::new();
        opts.insert("x".to_string(), syn_text("mes"));
        opts.insert("y".to_string(), syn_text("venta"));
        let e = err_of(&[syn_text("bar"), rows, syn_map(opts)]);
        assert!(e.contains("\"venta\"") && e.contains("row 1"), "{}", e);
    }

    #[test]
    fn single_point_and_flat_series_render() {
        // 1 solo punto y todos los y iguales (rango 0) no dividen por cero.
        let svg = svg_of(&[syn_text("line"), syn_list(vec![syn_float(5.0)])]);
        assert!(svg.contains("<polyline"), "{}", svg);
        let flat = syn_list(vec![syn_float(3.0), syn_float(3.0), syn_float(3.0)]);
        let svg = svg_of(&[syn_text("bar"), flat]);
        assert_eq!(svg.matches("<rect").count(), 3, "{}", svg);
    }

    #[test]
    fn negative_bars_below_baseline() {
        let svg = svg_of(&[
            syn_text("bar"),
            syn_list(vec![syn_float(5.0), syn_float(-3.0)]),
        ]);
        assert_eq!(svg.matches("<rect").count(), 2, "{}", svg);
        assert!(svg.contains(BASELINE), "baseline del cero visible:\n{}", svg);
    }

    #[test]
    fn custom_colors_replace_palette() {
        let mut opts = IndexMap::new();
        opts.insert(
            "colors".to_string(),
            syn_list(vec![syn_text("#111111"), syn_text("#222222")]),
        );
        let svg = svg_of(&[
            syn_text("bar"),
            map1(&[("a", 1.0), ("b", 2.0)]),
            syn_map(opts),
        ]);
        assert!(svg.contains("#111111"), "{}", svg);
        assert!(!svg.contains(PALETTE[0]), "la paleta default fue reemplazada:\n{}", svg);
    }

    #[test]
    fn scatter_pairs_and_markers() {
        let pairs = syn_list(vec![
            syn_list(vec![syn_float(1.0), syn_float(2.0)]),
            syn_list(vec![syn_float(3.0), syn_float(4.0)]),
        ]);
        let svg = svg_of(&[syn_text("scatter"), pairs]);
        assert_eq!(svg.matches("<circle").count(), 2, "{}", svg);
        assert!(svg.contains("r=\"4\""), "markers ≥8px de diámetro:\n{}", svg);
    }

    #[test]
    fn non_finite_x_in_rows_is_an_error() {
        // Regresión: una x NaN en line/scatter producía coordenadas "NaN" en el SVG
        // (garbage silencioso, G5). Ahora es un error claro con fila y campo.
        let rows = syn_list(vec![
            {
                let mut m = IndexMap::new();
                m.insert("t".to_string(), syn_float(1.0));
                m.insert("v".to_string(), syn_float(2.0));
                syn_map(m)
            },
            {
                let mut m = IndexMap::new();
                m.insert("t".to_string(), syn_float(f64::NAN));
                m.insert("v".to_string(), syn_float(3.0));
                syn_map(m)
            },
        ]);
        let mut opts = IndexMap::new();
        opts.insert("x".to_string(), syn_text("t"));
        opts.insert("y".to_string(), syn_text("v"));
        let e = err_of(&[syn_text("line"), rows.clone(), syn_map(opts.clone())]);
        assert!(e.contains("NaN") && e.contains("row 2"), "{}", e);
        let e = err_of(&[syn_text("scatter"), rows, syn_map(opts)]);
        assert!(e.contains("NaN"), "{}", e);
        // En bar la x es identidad (label), no posición: NaN queda como label "nan".
        let mut m = IndexMap::new();
        m.insert("t".to_string(), syn_float(f64::NAN));
        m.insert("v".to_string(), syn_float(3.0));
        let mut opts = IndexMap::new();
        opts.insert("x".to_string(), syn_text("t"));
        opts.insert("y".to_string(), syn_text("v"));
        let svg = svg_of(&[syn_text("bar"), syn_list(vec![syn_map(m)]), syn_map(opts)]);
        assert!(!svg.contains("cx=\"NaN\""), "{}", svg);
    }

    #[test]
    fn secret_label_redacted() {
        let rows = syn_list(vec![{
            let mut m = IndexMap::new();
            m.insert("k".to_string(), synsema_core::types::syn_secret("API_KEY", "hunter2"));
            m.insert("v".to_string(), syn_float(1.0));
            syn_map(m)
        }]);
        let mut opts = IndexMap::new();
        opts.insert("x".to_string(), syn_text("k"));
        opts.insert("y".to_string(), syn_text("v"));
        let svg = svg_of(&[syn_text("bar"), rows, syn_map(opts)]);
        assert!(!svg.contains("hunter2"), "plaintext filtrado:\n{}", svg);
        // Y un secret como VALOR numérico → error (G8).
        let rows = syn_list(vec![{
            let mut m = IndexMap::new();
            m.insert("k".to_string(), syn_text("a"));
            m.insert("v".to_string(), synsema_core::types::syn_secret("API_KEY", "hunter2"));
            syn_map(m)
        }]);
        let mut opts = IndexMap::new();
        opts.insert("x".to_string(), syn_text("k"));
        opts.insert("y".to_string(), syn_text("v"));
        let e = err_of(&[syn_text("bar"), rows, syn_map(opts)]);
        assert!(e.contains("secret"), "{}", e);
    }
}

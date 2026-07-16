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
    syn_bool, syn_float, syn_int, syn_list, syn_map, syn_nothing, syn_text, SynValue,
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

/// Colores de un tema (Batch 10 §4). El tema `light` son EXACTAMENTE los defaults
/// del Batch 8 (G1: `{"theme": "light"}` y sin `theme` producen los mismos bytes).
/// Las escalas seq/div son los ÚNICOS caminos para valores continuos (G11); los
/// colores semánticos del waterfall son CVD-safe por decisión #6 (azul/naranja,
/// jamás verde/rojo).
struct ThemeColors {
    series: [&'static str; 8],
    ink: &'static str,
    muted: &'static str,
    grid: &'static str,
    baseline: &'static str,
    /// Stops de la escala secuencial del heatmap (claro → marca → oscuro).
    seq: [&'static str; 3],
    /// Stops de la escala divergente (naranja ↔ neutro ↔ azul), centrada.
    div: [&'static str; 3],
    wf_up: &'static str,
    wf_down: &'static str,
    wf_total: &'static str,
}

const LIGHT: ThemeColors = ThemeColors {
    series: PALETTE,
    ink: INK,
    muted: MUTED,
    grid: GRID,
    baseline: BASELINE,
    seq: ["#f1f6fd", "#2a78d6", "#123c6b"],
    div: ["#b34a12", "#fcfcfb", "#123c6b"],
    wf_up: "#2a78d6",
    wf_down: "#eb6834",
    wf_total: "#52514e",
};

/// Tema dark: mismas 8 series en el mismo orden fijo, aclaradas para fondo oscuro;
/// las escalas del heatmap invierten la dirección de luminosidad ("más" = más claro).
/// Contraste verificado por test con la fórmula WCAG (series ≥ 3:1, tinta ≥ 4.5:1
/// contra #1e1e1e).
const DARK: ThemeColors = ThemeColors {
    series: [
        "#5b9ce8", "#34a534", "#f09cbd", "#f5b62e", "#3fc795", "#f0854f", "#8577d6", "#ef6d6c",
    ],
    ink: "#c9c8c1",
    muted: "#8f8d86",
    grid: "#33322f",
    baseline: "#4a4944",
    seq: ["#1a2332", "#5b9ce8", "#d5e5f9"],
    div: ["#f0854f", "#24231f", "#5b9ce8"],
    wf_up: "#5b9ce8",
    wf_down: "#f0854f",
    wf_total: "#c9c8c1",
};

// =========================================================
// Modelo normalizado (compartido por chart_svg y chart())
// =========================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    Bar,
    Line,
    Pie,
    Scatter,
    Area,
    Heatmap,
    Histogram,
    Boxplot,
    Donut,
    Waterfall,
}

/// Lista canónica para mensajes de error (alfabética, autocontenida — G5).
const VALID_KINDS: &str =
    "area, bar, boxplot, donut, heatmap, histogram, line, pie, scatter, waterfall";

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Bar => "bar",
            Kind::Line => "line",
            Kind::Pie => "pie",
            Kind::Scatter => "scatter",
            Kind::Area => "area",
            Kind::Heatmap => "heatmap",
            Kind::Histogram => "histogram",
            Kind::Boxplot => "boxplot",
            Kind::Donut => "donut",
            Kind::Waterfall => "waterfall",
        }
    }

    /// Único punto de parseo kind-texto → enum. Los renderers de nodo (MD/JSON)
    /// vuelven a pasar por acá y hacen `match` EXHAUSTIVO sobre `Kind`: un kind
    /// nuevo sin brazo no compila (§7.5 — nada de `_` que tape casos).
    pub(crate) fn from_name(s: &str) -> Option<Kind> {
        Some(match s {
            "bar" => Kind::Bar,
            "line" => Kind::Line,
            "pie" => Kind::Pie,
            "scatter" => Kind::Scatter,
            "area" => Kind::Area,
            "heatmap" => Kind::Heatmap,
            "histogram" => Kind::Histogram,
            "boxplot" => Kind::Boxplot,
            "donut" => Kind::Donut,
            "waterfall" => Kind::Waterfall,
            _ => return None,
        })
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

/// Escala de color del heatmap, YA resuelta (auto → seq/div según los datos).
#[derive(Clone, Copy)]
enum HeatScale {
    Sequential,
    Diverging { center: f64 },
}

struct HeatmapData {
    x_labels: Vec<String>,
    y_labels: Vec<String>,
    /// Filas = y (fila 0 arriba), columnas = x. `None` = celda ausente (transparente).
    values: Vec<Vec<Option<f64>>>,
    scale: HeatScale,
    /// Stops RGB resueltos (tema o `colors` del usuario; siempre ≥ 2).
    stops: Vec<(f64, f64, f64)>,
}

/// Estadísticas Tukey de un grupo, calculadas UNA vez en la normalización: SVG,
/// tabla MD y JSON salen de estos mismos números (imposible que diverjan — §3.7).
struct BoxGroup {
    name: String,
    /// Extremos de los bigotes (último dato dentro de 1.5×IQR desde q1/q3).
    min: f64,
    q1: f64,
    median: f64,
    q3: f64,
    max: f64,
    outliers: Vec<f64>,
}

struct WfStep {
    label: String,
    delta: f64,
    /// Acumulado hasta este paso inclusive (misma fuente para SVG/MD/JSON).
    running: f64,
}

/// Datos normalizados por familia de chart (G2: valores del lenguaje, sin drivers).
enum ChartData {
    /// bar / line / pie / scatter / area / donut — las 5 formas del Batch 8.
    Series(Vec<Series>),
    Heatmap(HeatmapData),
    Histogram { counts: Vec<i64>, edges: Vec<f64> },
    Boxplot(Vec<BoxGroup>),
    Waterfall { steps: Vec<WfStep>, total_label: Option<String> },
}

struct ChartSpec {
    kind: Kind,
    title: Option<String>,
    x_label: Option<String>,
    y_label: Option<String>,
    /// Nombre del campo x cuando la data fue lista de mapas (cabecera de la tabla MD).
    x_name: Option<String>,
    data: ChartData,
    width: f64,
    height: f64,
    colors: Vec<String>,
    legend: bool,
    background: Option<String>,
    th: &'static ThemeColors,
    /// `{"stack": true}` — sólo bar/area; apila las series en el orden dado.
    stack: bool,
}

impl ChartSpec {
    /// Series de los kinds x/y (vacío para heatmap/histogram/boxplot/waterfall).
    fn series(&self) -> &[Series] {
        match &self.data {
            ChartData::Series(s) => s,
            _ => &[],
        }
    }
}

// =========================================================
// Lectura de opts
// =========================================================

const VALID_OPTS: [&str; 19] = [
    "title", "x", "y", "width", "height", "colors", "x_label", "y_label", "legend", "background",
    "theme", "stack", "value", "x_labels", "y_labels", "scale", "center", "bins", "total",
];

/// Opts comunes a TODOS los kinds.
const COMMON_OPTS: [&str; 9] =
    ["title", "width", "height", "colors", "x_label", "y_label", "legend", "background", "theme"];

/// Opts adicionales que aplican a cada kind. Una opt conocida pero fuera de su kind
/// es un error dirigido (G5: nunca ignorada en silencio) — p. ej. `stack: true` en
/// pie/scatter/heatmap/… falla listando los kinds que sí la soportan (§3.1).
fn kind_extra_opts(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Bar | Kind::Area => &["x", "y", "stack"],
        Kind::Line | Kind::Scatter | Kind::Pie | Kind::Donut | Kind::Boxplot => &["x", "y"],
        Kind::Heatmap => &["x", "y", "value", "x_labels", "y_labels", "scale", "center"],
        Kind::Histogram => &["bins"],
        Kind::Waterfall => &["x", "y", "total"],
    }
}

/// Kinds que aceptan una opt dada (para el mensaje de error dirigido).
fn kinds_supporting(opt: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for kind in [
        Kind::Bar,
        Kind::Line,
        Kind::Pie,
        Kind::Scatter,
        Kind::Area,
        Kind::Heatmap,
        Kind::Histogram,
        Kind::Boxplot,
        Kind::Donut,
        Kind::Waterfall,
    ] {
        if kind_extra_opts(kind).contains(&opt) {
            out.push(kind.name());
        }
    }
    out.join(", ")
}

fn opts_of(args: &[SynValue], kind: Kind, name: &str) -> Result<IndexMap<String, SynValue>, Control> {
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
                if !COMMON_OPTS.contains(&k.as_str())
                    && !kind_extra_opts(kind).contains(&k.as_str())
                {
                    return Err(err(format!(
                        "{}: option {:?} does not apply to {:?} charts; it only applies to: {}",
                        name,
                        k,
                        kind.name(),
                        kinds_supporting(k)
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

/// `theme`: `"light"` (default, exactamente los bytes del Batch 8) o `"dark"` (§4).
fn opt_theme(
    opts: &IndexMap<String, SynValue>,
    name: &str,
) -> Result<&'static ThemeColors, Control> {
    match opts.get("theme") {
        None | Some(SynValue::Nothing) => Ok(&LIGHT),
        Some(SynValue::Text(s)) => match &**s {
            "light" => Ok(&LIGHT),
            "dark" => Ok(&DARK),
            other => Err(err(format!(
                "{}: unknown theme {:?}; valid themes are: \"light\", \"dark\"",
                name, other
            ))),
        },
        Some(other) => Err(err(format!(
            "{}: option \"theme\" must be text (\"light\" or \"dark\"), got {}",
            name,
            other.type_name()
        ))),
    }
}

fn opt_bool(
    opts: &IndexMap<String, SynValue>,
    key: &str,
    name: &str,
) -> Result<bool, Control> {
    match opts.get(key) {
        None | Some(SynValue::Nothing) => Ok(false),
        Some(SynValue::Bool(b)) => Ok(*b),
        Some(other) => Err(err(format!(
            "{}: option {:?} must be true or false, got {}",
            name,
            key,
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

/// `colors`: lista de hex que REEMPLAZA los defaults (G3). `None` = usar los del
/// tema (la semántica exacta depende del kind: paleta de series, stops de escala,
/// o `[up, down, total]` del waterfall).
fn opt_colors(
    opts: &IndexMap<String, SynValue>,
    name: &str,
) -> Result<Option<Vec<String>>, Control> {
    match opts.get("colors") {
        None => Ok(None),
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
            Ok(Some(out))
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
        // En line/scatter/area la x numérica es POSICIÓN (escala numérica): NaN/inf
        // darían coordenadas "NaN" en el SVG — inválido y silencioso (G5). En bar/pie
        // la x es sólo identidad (label), así que no aplica.
        if matches!(kind, Kind::Line | Kind::Scatter | Kind::Area) {
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

/// Forma 4: lista de pares `[[x, y], …]` (scatter/line/area).
fn from_pairs(rows: &[SynValue], kind: Kind, name: &str) -> Result<Vec<Series>, Control> {
    if !matches!(kind, Kind::Scatter | Kind::Line | Kind::Area) {
        return Err(err(format!(
            "{}: a list of [x, y] pairs plots as \"scatter\", \"line\" or \"area\", not {:?}; for \"bar\"/\"pie\"/\"donut\" pass a map of label to value",
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
    if !matches!(kind, Kind::Bar | Kind::Line | Kind::Area) {
        return Err(err(format!(
            "{}: a plain list of numbers plots as \"bar\", \"line\" or \"area\", not {:?}; \"pie\"/\"donut\" need labels (a map) and \"scatter\" needs [x, y] pairs",
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
        SynValue::Text(s) => Kind::from_name(s).ok_or_else(|| {
            err(format!(
                "{}: unknown chart kind {:?}; valid kinds are: {}",
                name, s, VALID_KINDS
            ))
        })?,
        other => {
            return Err(err(format!(
                "{}: the chart kind must be text (one of: {}), got {}",
                name,
                VALID_KINDS,
                other.type_name()
            )))
        }
    };
    let opts = opts_of(args, kind, name)?;
    let th = opt_theme(&opts, name)?;
    let user_colors = opt_colors(&opts, name)?;
    let stack = opt_bool(&opts, "stack", name)?; // sólo llega en bar/area (opts_of)

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

    let data = match kind {
        Kind::Bar | Kind::Line | Kind::Pie | Kind::Scatter | Kind::Area | Kind::Donut => {
            ChartData::Series(normalize_xy(args, &opts, kind, name)?)
        }
        Kind::Heatmap => {
            ChartData::Heatmap(normalize_heatmap(args, &opts, &user_colors, th, name)?)
        }
        Kind::Histogram => {
            let (counts, edges) = normalize_histogram(args, &opts, name)?;
            ChartData::Histogram { counts, edges }
        }
        Kind::Boxplot => ChartData::Boxplot(normalize_boxplot(args, &opts, name)?),
        Kind::Waterfall => {
            let (steps, total_label) = normalize_waterfall(args, &opts, name)?;
            ChartData::Waterfall { steps, total_label }
        }
    };

    // Colores por kind (G3: el override del usuario REEMPLAZA; G11: jamás ciclar).
    let colors: Vec<String> = match &data {
        ChartData::Series(series) => {
            let palette: Vec<String> = match &user_colors {
                Some(c) => c.clone(),
                None => th.series.iter().map(|c| c.to_string()).collect(),
            };
            // Paleta de orden fijo: más series que colores es un error (jamás ciclar
            // — G5 y seguridad CVD). Pie/donut: la misma regla sobre los slices.
            let is_slices = matches!(kind, Kind::Pie | Kind::Donut);
            let needed = if is_slices { series[0].points.len() } else { series.len() };
            let what = if is_slices { "slices" } else { "series" };
            if needed > palette.len() {
                return Err(err(format!(
                    "{}: {} {} but only {} colors are available; group the long tail into an \"Other\" bucket or pass a \"colors\" list with at least {} entries (colors are never cycled)",
                    name,
                    needed,
                    what,
                    palette.len(),
                    needed
                )));
            }
            if is_slices && series.len() > 1 {
                return Err(err(format!(
                    "{}: {} charts take a single series, got {}; plot one field or use \"bar\"",
                    name,
                    kind.name(),
                    series.len()
                )));
            }
            palette
        }
        // Los stops del heatmap ya viven resueltos en HeatmapData.
        ChartData::Heatmap(_) => Vec::new(),
        ChartData::Histogram { .. } | ChartData::Boxplot(_) => match &user_colors {
            Some(c) => c.clone(),
            None => vec![th.series[0].to_string()],
        },
        ChartData::Waterfall { .. } => match &user_colors {
            Some(c) if c.len() == 3 => c.clone(),
            Some(c) => {
                return Err(err(format!(
                    "{}: waterfall \"colors\" must be [up, down, total] — exactly 3 colors, got {}",
                    name,
                    c.len()
                )))
            }
            None => {
                vec![th.wf_up.to_string(), th.wf_down.to_string(), th.wf_total.to_string()]
            }
        },
    };

    // Área apilada con signos mezclados en un mismo x: visualmente ambigua — error
    // que sugiere bar apilado (§3.1, G5: no dibujamos garbage).
    if stack && kind == Kind::Area {
        if let ChartData::Series(series) = &data {
            if series.len() > 1 {
                for i in 0..series[0].points.len() {
                    let mut pos = false;
                    let mut neg = false;
                    for s in series.iter() {
                        let v = s.points[i].1;
                        pos = pos || v > 0.0;
                        neg = neg || v < 0.0;
                    }
                    if pos && neg {
                        return Err(err(format!(
                            "{}: stacked area needs every series to share the same sign at each x, but x {:?} mixes positive and negative values; use {{\"stack\": true}} on a \"bar\" chart instead",
                            name,
                            x_display(&series[0].points[i].0)
                        )));
                    }
                }
            }
        }
    }

    let legend = match opts.get("legend") {
        None => match &data {
            ChartData::Series(series) => {
                matches!(kind, Kind::Pie | Kind::Donut) || series.len() >= 2
            }
            ChartData::Heatmap(_) => true, // leyenda = barra de gradiente (§3.2)
            // Los grupos/pasos se leen del eje x; la leyenda es opt-in.
            ChartData::Histogram { .. } | ChartData::Boxplot(_) | ChartData::Waterfall { .. } => {
                false
            }
        },
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
        data,
        width: opt_dim(&opts, "width", DEFAULT_WIDTH, name)?,
        height: opt_dim(&opts, "height", DEFAULT_HEIGHT, name)?,
        colors,
        legend,
        background,
        th,
        stack,
    })
}

/// Normalización de los kinds x/y (bar/line/pie/scatter/area/donut): las 5 formas
/// del Batch 8, sin cambios de semántica para los kinds existentes (G1).
fn normalize_xy(
    args: &[SynValue],
    opts: &IndexMap<String, SynValue>,
    kind: Kind,
    name: &str,
) -> Result<Vec<Series>, Control> {
    let series = match &args[1] {
        SynValue::List(l) => {
            let items = l.borrow().clone();
            if items.is_empty() {
                return Err(err(format!("{}: data is empty; nothing to plot", name)));
            }
            match &items[0] {
                SynValue::Map(_) => from_rows(&items, opts, kind, name)?,
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
                    "{}: a map of label to value plots as \"bar\", \"line\", \"area\", \"pie\" or \"donut\"; \"scatter\" needs numeric [x, y] pairs",
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
    Ok(series)
}

// =========================================================
// Interpolación de color (heatmap) — aritmética pura, sin deps (G6/G7)
// =========================================================

/// `#rgb`/`#rrggbb` → (r, g, b) en 0..255. Los stops de escala deben ser opacos
/// (un canal alfa haría ambigua la interpolación).
fn parse_stop(s: &str, name: &str) -> Result<(f64, f64, f64), Control> {
    let hex = s.strip_prefix('#').unwrap_or(s);
    let expand = |h: &str| -> Option<(u8, u8, u8)> {
        match h.len() {
            3 => {
                let d = |i: usize| u8::from_str_radix(&h[i..i + 1], 16).ok();
                Some((d(0)? * 17, d(1)? * 17, d(2)? * 17))
            }
            6 => {
                let d = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).ok();
                Some((d(0)?, d(2)?, d(4)?))
            }
            _ => None,
        }
    };
    match expand(hex) {
        Some((r, g, b)) => Ok((r as f64, g as f64, b as f64)),
        None => Err(err(format!(
            "{}: heatmap color stops must be opaque hex colors like \"#2a78d6\" (#rgb or #rrggbb), got {:?}",
            name, s
        ))),
    }
}

/// Interpolación lineal sobre N stops (t en [0, 1]) → `#rrggbb`. Determinista (G7):
/// stops fijos + aritmética pura + redondeo estable.
fn lerp_stops(stops: &[(f64, f64, f64)], t: f64) -> String {
    let t = t.clamp(0.0, 1.0);
    let seg = t * (stops.len() - 1) as f64;
    let i = (seg.floor() as usize).min(stops.len() - 2);
    let f = seg - i as f64;
    let (a, b) = (stops[i], stops[i + 1]);
    let ch = |x: f64, y: f64| (x + (y - x) * f).round() as u8;
    format!("#{:02x}{:02x}{:02x}", ch(a.0, b.0), ch(a.1, b.1), ch(a.2, b.2))
}

/// Posición t de un valor en la escala. Secuencial: min→0, max→1. Divergente:
/// centrada, con span simétrico (deltas de igual magnitud → igual intensidad).
/// Rango 0 → stop medio (t = 0.5), sin división por cero (§3.2).
fn heat_t(scale: HeatScale, mn: f64, mx: f64, v: f64) -> f64 {
    match scale {
        HeatScale::Sequential => {
            if mx > mn {
                (v - mn) / (mx - mn)
            } else {
                0.5
            }
        }
        HeatScale::Diverging { center } => {
            let span = (mn - center).abs().max((mx - center).abs());
            if span > 0.0 {
                0.5 + (v - center) / (2.0 * span)
            } else {
                0.5
            }
        }
    }
}

// =========================================================
// Normalización por kind nuevo (Batch 10)
// =========================================================

/// heatmap (§3.2): formato largo (rows + x/y/value) o matriz (lista de listas /
/// `array` 2D + x_labels/y_labels). Resuelve la escala (auto → seq/div según el
/// signo de los datos — regla documentada, no magia) y los stops UNA vez: SVG,
/// leyenda y salidas MD/JSON usan los mismos números.
fn normalize_heatmap(
    args: &[SynValue],
    opts: &IndexMap<String, SynValue>,
    user_colors: &Option<Vec<String>>,
    th: &'static ThemeColors,
    name: &str,
) -> Result<HeatmapData, Control> {
    let label_list = |key: &str| -> Result<Option<Vec<String>>, Control> {
        match opts.get(key) {
            None | Some(SynValue::Nothing) => Ok(None),
            Some(SynValue::List(l)) => {
                let items = l.borrow();
                let mut out = Vec::with_capacity(items.len());
                for it in items.iter() {
                    match it {
                        SynValue::Text(s) => out.push(s.to_string()),
                        SynValue::Number(n) => out.push(fmt_x(n.to_f64())),
                        SynValue::Secret(_) => out.push("[redacted]".to_string()),
                        other => {
                            return Err(err(format!(
                                "{}: option {:?} must be a list of label texts, got a {} inside",
                                name,
                                key,
                                other.type_name()
                            )))
                        }
                    }
                }
                Ok(Some(out))
            }
            Some(other) => Err(err(format!(
                "{}: option {:?} must be a list of label texts, got {}",
                name,
                key,
                other.type_name()
            ))),
        }
    };

    let is_rows = matches!(&args[1], SynValue::List(l) if matches!(l.borrow().first(), Some(SynValue::Map(_))));
    let (x_labels, y_labels, values) = if is_rows {
        // Formato largo/tidy (natural de sql() con GROUP BY).
        if opts.contains_key("x_labels") || opts.contains_key("y_labels") {
            return Err(err(format!(
                "{}: options \"x_labels\"/\"y_labels\" only apply to matrix data; rows take {{\"x\", \"y\", \"value\"}} field names",
                name
            )));
        }
        let need = |key: &str| -> Result<String, Control> {
            opt_text(opts, key, name)?.ok_or_else(|| {
                err(format!(
                    "{}: heatmap rows need {{\"x\": \"field\", \"y\": \"field\", \"value\": \"field\"}} to pick the columns",
                    name
                ))
            })
        };
        let (xf, yf, vf) = (need("x")?, need("y")?, need("value")?);
        let rows = match &args[1] {
            SynValue::List(l) => l.borrow().clone(),
            _ => Vec::new(),
        };
        let mut xs: Vec<String> = Vec::new();
        let mut ys: Vec<String> = Vec::new();
        let mut cells: Vec<Vec<Option<f64>>> = Vec::new();
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
            let get = |field: &str| -> Result<SynValue, Control> {
                m.get(field).cloned().ok_or_else(|| {
                    err(format!(
                        "{}: the field {:?} is missing in row {}",
                        name,
                        field,
                        i + 1
                    ))
                })
            };
            let xl = x_display(&x_of(&get(&xf)?));
            let yl = x_display(&x_of(&get(&yf)?));
            let v = num_of(
                &get(&vf)?,
                name,
                &format!("the value field {:?} in row {}", vf, i + 1),
            )?;
            let xi = match xs.iter().position(|s| *s == xl) {
                Some(p) => p,
                None => {
                    xs.push(xl.clone());
                    for r in cells.iter_mut() {
                        r.push(None);
                    }
                    xs.len() - 1
                }
            };
            let yi = match ys.iter().position(|s| *s == yl) {
                Some(p) => p,
                None => {
                    ys.push(yl.clone());
                    cells.push(vec![None; xs.len()]);
                    ys.len() - 1
                }
            };
            if cells[yi][xi].is_some() {
                return Err(err(format!(
                    "{}: duplicate heatmap cell (x {:?}, y {:?}) in row {}; aggregate the data first",
                    name,
                    xl,
                    yl,
                    i + 1
                )));
            }
            cells[yi][xi] = Some(v);
        }
        if cells.is_empty() {
            return Err(err(format!("{}: data is empty; nothing to plot", name)));
        }
        (xs, ys, cells)
    } else {
        // Matriz: lista de listas de números o `array` 2D (filas = y, columnas = x).
        // Cierra el pendiente "arrays 2D en charts" del Batch 8 §9 para este kind.
        if opts.contains_key("value") {
            return Err(err(format!(
                "{}: option \"value\" only applies when data is a list of maps (rows)",
                name
            )));
        }
        let cells: Vec<Vec<Option<f64>>> = match &args[1] {
            SynValue::List(l) => {
                let items = l.borrow().clone();
                if items.is_empty() {
                    return Err(err(format!("{}: data is empty; nothing to plot", name)));
                }
                let mut cells: Vec<Vec<Option<f64>>> = Vec::with_capacity(items.len());
                let mut width: Option<usize> = None;
                for (i, row) in items.iter().enumerate() {
                    let vals = match row {
                        SynValue::List(r) => r.borrow().clone(),
                        other => {
                            return Err(err(format!(
                                "{}: heatmap data must be rows with {{\"x\", \"y\", \"value\"}}, a matrix (list of number lists), or a 2-D array; got a list of {}",
                                name,
                                other.type_name()
                            )))
                        }
                    };
                    if vals.is_empty() {
                        return Err(err(format!(
                            "{}: matrix row {} is empty; nothing to plot",
                            name,
                            i + 1
                        )));
                    }
                    match width {
                        None => width = Some(vals.len()),
                        Some(w) if w != vals.len() => {
                            return Err(err(format!(
                                "{}: the matrix is ragged — row {} has {} value(s) but row 1 has {}; all rows must have the same length",
                                name,
                                i + 1,
                                vals.len(),
                                w
                            )))
                        }
                        Some(_) => {}
                    }
                    let mut out_row = Vec::with_capacity(vals.len());
                    for (j, v) in vals.iter().enumerate() {
                        out_row.push(Some(num_of(
                            v,
                            name,
                            &format!("the matrix value at row {}, column {}", i + 1, j + 1),
                        )?));
                    }
                    cells.push(out_row);
                }
                cells
            }
            SynValue::Array(a) => {
                if a.ndim() != 2 {
                    return Err(err(format!(
                        "{}: heatmap takes a 2-D array (rows × columns) or a list of rows, got a {}-D array",
                        name,
                        a.ndim()
                    )));
                }
                let (ny, nx) = (a.shape()[0], a.shape()[1]);
                if ny == 0 || nx == 0 {
                    return Err(err(format!("{}: data is empty; nothing to plot", name)));
                }
                let mut cells = Vec::with_capacity(ny);
                for i in 0..ny {
                    let mut row = Vec::with_capacity(nx);
                    for j in 0..nx {
                        let v = a[[i, j]];
                        if !v.is_finite() {
                            return Err(err(format!(
                                "{}: the data contains NaN or infinite values; filter or replace them first",
                                name
                            )));
                        }
                        row.push(Some(v));
                    }
                    cells.push(row);
                }
                cells
            }
            other => {
                return Err(err(format!(
                    "{}: heatmap data must be rows with {{\"x\", \"y\", \"value\"}}, a matrix (list of number lists), or a 2-D array; got {}",
                    name,
                    other.type_name()
                )))
            }
        };
        let (ny, nx) = (cells.len(), cells[0].len());
        let xs = match label_list("x_labels")? {
            Some(v) if v.len() != nx => {
                return Err(err(format!(
                    "{}: \"x_labels\" has {} label(s) but the matrix has {} column(s)",
                    name,
                    v.len(),
                    nx
                )))
            }
            Some(v) => v,
            None => (0..nx).map(|i| fmt_x(i as f64)).collect(),
        };
        let ys = match label_list("y_labels")? {
            Some(v) if v.len() != ny => {
                return Err(err(format!(
                    "{}: \"y_labels\" has {} label(s) but the matrix has {} row(s)",
                    name,
                    v.len(),
                    ny
                )))
            }
            Some(v) => v,
            None => (0..ny).map(|i| fmt_x(i as f64)).collect(),
        };
        (xs, ys, cells)
    };

    // Rango de la escala: sólo celdas presentes.
    let mut mn = f64::INFINITY;
    let mut mx = f64::NEG_INFINITY;
    for row in &values {
        for v in row.iter().flatten() {
            mn = mn.min(*v);
            mx = mx.max(*v);
        }
    }
    if !mn.is_finite() {
        return Err(err(format!("{}: data is empty; nothing to plot", name)));
    }

    let scale_txt = opt_text(opts, "scale", name)?.unwrap_or_else(|| "auto".to_string());
    // "center" pertenece al modo divergente EXPLÍCITO (con "auto" sería magia
    // silenciosa — G5).
    if opts.contains_key("center") && scale_txt != "diverging" {
        return Err(err(format!(
            "{}: option \"center\" requires {{\"scale\": \"diverging\"}} (got scale {:?})",
            name, scale_txt
        )));
    }
    let scale = match scale_txt.as_str() {
        // Regla escrita (§3.2): todos ≥ 0 o todos ≤ 0 → secuencial; cruzan el cero →
        // divergente centrada en 0.
        "auto" => {
            if mn >= 0.0 || mx <= 0.0 {
                HeatScale::Sequential
            } else {
                HeatScale::Diverging { center: 0.0 }
            }
        }
        "sequential" => HeatScale::Sequential,
        "diverging" => {
            let center = match opts.get("center") {
                None | Some(SynValue::Nothing) => 0.0,
                Some(SynValue::Number(n)) => {
                    let c = n.to_f64();
                    if !c.is_finite() {
                        return Err(err(format!(
                            "{}: option \"center\" must be a finite number",
                            name
                        )));
                    }
                    c
                }
                Some(other) => {
                    return Err(err(format!(
                        "{}: option \"center\" must be a number, got {}",
                        name,
                        other.type_name()
                    )))
                }
            };
            HeatScale::Diverging { center }
        }
        other => {
            return Err(err(format!(
                "{}: unknown scale {:?}; valid scales are: \"auto\", \"sequential\", \"diverging\"",
                name, other
            )))
        }
    };

    // Stops: `colors` del usuario (≥ 2, REEMPLAZA — G3/G11) o los del tema.
    let stops: Vec<(f64, f64, f64)> = match user_colors {
        Some(c) => {
            if c.len() < 2 {
                return Err(err(format!(
                    "{}: heatmap \"colors\" must be at least 2 gradient stops, got {}",
                    name,
                    c.len()
                )));
            }
            let mut out = Vec::with_capacity(c.len());
            for s in c {
                out.push(parse_stop(s, name)?);
            }
            out
        }
        None => {
            let defaults = match scale {
                HeatScale::Sequential => &th.seq,
                HeatScale::Diverging { .. } => &th.div,
            };
            defaults
                .iter()
                .map(|s| parse_stop(s, name))
                .collect::<Result<Vec<_>, _>>()?
        }
    };

    Ok(HeatmapData { x_labels, y_labels, values, scale, stops })
}

/// histogram (§3.3): números crudos + `bins` (REUTILIZA el binning del builtin
/// `histogram()` de synsema-core llamándolo — mismo código, jamás copiado) o el
/// mapa `{"counts", "edges"}` que ese builtin devuelve (composición directa:
/// `chart("histogram", histogram(datos, 20))`).
fn normalize_histogram(
    args: &[SynValue],
    opts: &IndexMap<String, SynValue>,
    name: &str,
) -> Result<(Vec<i64>, Vec<f64>), Control> {
    let raw = || -> Result<(Vec<i64>, Vec<f64>), Control> {
        let mut h_args = vec![args[1].clone()];
        if let Some(b) = opts.get("bins") {
            h_args.push(b.clone());
        }
        let result = synsema_core::math::histogram(&h_args)?;
        let m = match &result {
            SynValue::Map(m) => m.borrow().clone(),
            _ => {
                return Err(err(format!(
                    "{}: internal error — histogram() did not return a map",
                    name
                )))
            }
        };
        let counts = match m.get("counts") {
            Some(SynValue::List(l)) => l
                .borrow()
                .iter()
                .map(|v| match v {
                    SynValue::Number(n) => n.to_i64_trunc().unwrap_or(0),
                    _ => 0,
                })
                .collect(),
            _ => Vec::new(),
        };
        let edges = match m.get("edges") {
            Some(SynValue::List(l)) => l
                .borrow()
                .iter()
                .map(|v| match v {
                    SynValue::Number(n) => n.to_f64(),
                    _ => 0.0,
                })
                .collect(),
            _ => Vec::new(),
        };
        Ok((counts, edges))
    };
    match &args[1] {
        SynValue::List(l) => {
            let items = l.borrow();
            if items.is_empty() {
                return Err(err(format!("{}: data is empty; nothing to plot", name)));
            }
            if matches!(items.first(), Some(SynValue::Map(_))) {
                return Err(err(format!(
                    "{}: histogram plots raw numbers (a list or 1-D array) or the {{\"counts\", \"edges\"}} map from histogram(); got a list of maps",
                    name
                )));
            }
            drop(items);
            raw()
        }
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
            raw()
        }
        SynValue::Map(m) => {
            // El mapa {"counts", "edges"} de histogram() — se valida, no se re-binnea.
            if opts.contains_key("bins") {
                return Err(err(format!(
                    "{}: option \"bins\" only applies to raw numbers; this data already has counts and edges",
                    name
                )));
            }
            let m = m.borrow();
            for k in m.keys() {
                if k != "counts" && k != "edges" {
                    return Err(err(format!(
                        "{}: histogram map data takes exactly {{\"counts\", \"edges\"}} (the shape histogram() returns), got extra key {:?}",
                        name, k
                    )));
                }
            }
            let get_list = |key: &str| -> Result<Vec<SynValue>, Control> {
                match m.get(key) {
                    Some(SynValue::List(l)) => Ok(l.borrow().clone()),
                    Some(other) => Err(err(format!(
                        "{}: histogram {:?} must be a list of numbers, got {}",
                        name,
                        key,
                        other.type_name()
                    ))),
                    None => Err(err(format!(
                        "{}: histogram map data needs {:?} (the shape histogram() returns)",
                        name, key
                    ))),
                }
            };
            let counts_raw = get_list("counts")?;
            let edges_raw = get_list("edges")?;
            if edges_raw.len() != counts_raw.len() + 1 {
                return Err(err(format!(
                    "{}: length(edges) must be length(counts) + 1, got {} edge(s) for {} count(s)",
                    name,
                    edges_raw.len(),
                    counts_raw.len()
                )));
            }
            if counts_raw.is_empty() {
                return Err(err(format!("{}: data is empty; nothing to plot", name)));
            }
            let mut counts = Vec::with_capacity(counts_raw.len());
            for (i, c) in counts_raw.iter().enumerate() {
                match c {
                    SynValue::Number(n) if n.is_integer() => {
                        let v = n.to_i64_trunc().unwrap_or(-1);
                        if v < 0 {
                            return Err(err(format!(
                                "{}: histogram counts must be non-negative integers, got {} at index {}",
                                name,
                                py_float_str(n.to_f64()),
                                i
                            )));
                        }
                        counts.push(v);
                    }
                    SynValue::Number(n) => {
                        return Err(err(format!(
                            "{}: histogram counts must be integers, got {} at index {}",
                            name,
                            py_float_str(n.to_f64()),
                            i
                        )))
                    }
                    other => {
                        return Err(err(format!(
                            "{}: histogram counts must be integers, got {} at index {}",
                            name,
                            other.type_name(),
                            i
                        )))
                    }
                }
            }
            let mut edges = Vec::with_capacity(edges_raw.len());
            for (i, e) in edges_raw.iter().enumerate() {
                edges.push(num_of(e, name, &format!("histogram edge at index {}", i))?);
            }
            for w in edges.windows(2) {
                if w[0].partial_cmp(&w[1]) != Some(std::cmp::Ordering::Less) {
                    return Err(err(format!(
                        "{}: histogram edges must be strictly increasing, but {} is not greater than {}",
                        name,
                        py_float_str(w[1]),
                        py_float_str(w[0])
                    )));
                }
            }
            Ok((counts, edges))
        }
        other => Err(err(format!(
            "{}: histogram data must be a list of numbers, a 1-D array, or the {{\"counts\", \"edges\"}} map from histogram(); got {}",
            name,
            other.type_name()
        ))),
    }
}

/// Mediana/percentiles vía los builtins de synsema-core: MISMA interpolación lineal
/// que `median()`/`percentile()` (test de guardia §7.2 — reutilizada, jamás copiada).
fn core_percentile(vals: &[f64], p: f64, name: &str) -> Result<f64, Control> {
    let list = syn_list(vals.iter().map(|v| syn_float(*v)).collect());
    match synsema_core::math::percentile(&[list, syn_float(p)])? {
        SynValue::Number(n) => Ok(n.to_f64()),
        other => Err(err(format!(
            "{}: internal error — percentile() returned {}",
            name,
            other.type_name()
        ))),
    }
}

fn core_median(vals: &[f64], name: &str) -> Result<f64, Control> {
    let list = syn_list(vals.iter().map(|v| syn_float(*v)).collect());
    match synsema_core::math::median(&[list])? {
        SynValue::Number(n) => Ok(n.to_f64()),
        other => Err(err(format!(
            "{}: internal error — median() returned {}",
            name,
            other.type_name()
        ))),
    }
}

/// Estadísticas Tukey de UN grupo (§3.4): caja q1–q3, bigotes al último dato dentro
/// de 1.5×IQR, outliers individuales. Un grupo de 1 dato es garbage → error (G5).
fn box_group(label: &str, mut vals: Vec<f64>, name: &str) -> Result<BoxGroup, Control> {
    if vals.len() < 2 {
        return Err(err(format!(
            "{}: boxplot group {:?} has {} value(s); a boxplot needs at least 2 values per group",
            name,
            label,
            vals.len()
        )));
    }
    // num_of ya rechazó NaN/inf en todas las formas de entrada; el orden es total.
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let q1 = core_percentile(&vals, 25.0, name)?;
    let median = core_median(&vals, name)?;
    let q3 = core_percentile(&vals, 75.0, name)?;
    let iqr = q3 - q1;
    let (lo_fence, hi_fence) = (q1 - 1.5 * iqr, q3 + 1.5 * iqr);
    let mut outliers = Vec::new();
    let mut wmin = f64::INFINITY;
    let mut wmax = f64::NEG_INFINITY;
    for &v in &vals {
        if v < lo_fence || v > hi_fence {
            outliers.push(v);
        } else {
            wmin = wmin.min(v);
            wmax = wmax.max(v);
        }
    }
    // q1/q3 caen siempre dentro de las fences ⇒ hay al menos un dato adentro.
    Ok(BoxGroup { name: label.to_string(), min: wmin, q1, median, q3, max: wmax, outliers })
}

/// boxplot (§3.4): lista de números / `array` 1D (una caja), mapa label→lista
/// (caja por grupo, orden de inserción), o formato largo (rows + x/y).
fn normalize_boxplot(
    args: &[SynValue],
    opts: &IndexMap<String, SynValue>,
    name: &str,
) -> Result<Vec<BoxGroup>, Control> {
    match &args[1] {
        SynValue::List(l) => {
            let items = l.borrow().clone();
            if items.is_empty() {
                return Err(err(format!("{}: data is empty; nothing to plot", name)));
            }
            match &items[0] {
                SynValue::Map(_) => {
                    let field = |key: &str| -> Result<String, Control> {
                        opt_text(opts, key, name)?.ok_or_else(|| {
                            err(format!(
                                "{}: boxplot rows need {{\"x\": \"group field\", \"y\": \"value field\"}} to pick the columns",
                                name
                            ))
                        })
                    };
                    let (xf, yf) = (field("x")?, field("y")?);
                    let mut groups: IndexMap<String, Vec<f64>> = IndexMap::new();
                    for (i, row) in items.iter().enumerate() {
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
                        let g = m.get(&xf).map(|v| x_display(&x_of(v))).ok_or_else(|| {
                            err(format!(
                                "{}: the x field {:?} is missing in row {}",
                                name,
                                xf,
                                i + 1
                            ))
                        })?;
                        let yv = m.get(&yf).ok_or_else(|| {
                            err(format!(
                                "{}: the y field {:?} is missing in row {}",
                                name,
                                yf,
                                i + 1
                            ))
                        })?;
                        let v = num_of(
                            yv,
                            name,
                            &format!("the y field {:?} in row {}", yf, i + 1),
                        )?;
                        groups.entry(g).or_default().push(v);
                    }
                    groups
                        .into_iter()
                        .map(|(g, vals)| box_group(&g, vals, name))
                        .collect()
                }
                SynValue::Number(_) => {
                    let mut vals = Vec::with_capacity(items.len());
                    for (i, it) in items.iter().enumerate() {
                        vals.push(num_of(it, name, &format!("item {}", i + 1))?);
                    }
                    Ok(vec![box_group("value", vals, name)?])
                }
                other => Err(err(format!(
                    "{}: boxplot data must be a list of numbers, a map of group to value lists, rows with {{\"x\", \"y\"}}, or a 1-D array; got a list of {}",
                    name,
                    other.type_name()
                ))),
            }
        }
        SynValue::Map(m) => {
            let m = m.borrow();
            if m.is_empty() {
                return Err(err(format!("{}: data is empty; nothing to plot", name)));
            }
            let mut out = Vec::with_capacity(m.len());
            for (k, v) in m.iter() {
                let vals: Vec<f64> = match v {
                    SynValue::List(l) => {
                        let items = l.borrow();
                        let mut vals = Vec::with_capacity(items.len());
                        for (i, it) in items.iter().enumerate() {
                            vals.push(num_of(
                                it,
                                name,
                                &format!("value {} of group {:?}", i + 1, k),
                            )?);
                        }
                        vals
                    }
                    SynValue::Array(a) if a.ndim() == 1 => {
                        let vals: Vec<f64> = a.iter().copied().collect();
                        if vals.iter().any(|v| !v.is_finite()) {
                            return Err(err(format!(
                                "{}: group {:?} contains NaN or infinite values; filter or replace them first",
                                name, k
                            )));
                        }
                        vals
                    }
                    other => {
                        return Err(err(format!(
                            "{}: the value of boxplot group {:?} must be a list of numbers, got {}",
                            name,
                            k,
                            other.type_name()
                        )))
                    }
                };
                out.push(box_group(k, vals, name)?);
            }
            Ok(out)
        }
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
            Ok(vec![box_group("value", vals, name)?])
        }
        other => Err(err(format!(
            "{}: boxplot data must be a list of numbers, a map of group to value lists, rows with {{\"x\", \"y\"}}, or a 1-D array; got {}",
            name,
            other.type_name()
        ))),
    }
}

/// waterfall (§3.6): mapa label→delta (orden de inserción) o rows + x/y. Los
/// valores son DELTAS; el acumulado se calcula UNA vez acá (misma fuente para
/// SVG/MD/JSON). Delta 0 es dato real (barra plana), no error.
fn normalize_waterfall(
    args: &[SynValue],
    opts: &IndexMap<String, SynValue>,
    name: &str,
) -> Result<(Vec<WfStep>, Option<String>), Control> {
    let total_label = match opts.get("total") {
        None | Some(SynValue::Nothing) | Some(SynValue::Bool(false)) => None,
        Some(SynValue::Bool(true)) => Some("Total".to_string()),
        Some(SynValue::Text(s)) => Some(s.to_string()),
        Some(other) => {
            return Err(err(format!(
                "{}: option \"total\" must be true, false or a text label, got {}",
                name,
                other.type_name()
            )))
        }
    };
    let raw: Vec<(String, f64)> = match &args[1] {
        SynValue::Map(m) => {
            let m = m.borrow();
            if m.is_empty() {
                return Err(err(format!("{}: data is empty; nothing to plot", name)));
            }
            let mut out = Vec::with_capacity(m.len());
            for (k, v) in m.iter() {
                out.push((k.clone(), num_of(v, name, &format!("the delta of {:?}", k))?));
            }
            out
        }
        SynValue::List(l) => {
            let items = l.borrow().clone();
            if items.is_empty() {
                return Err(err(format!("{}: data is empty; nothing to plot", name)));
            }
            if !matches!(items[0], SynValue::Map(_)) {
                return Err(err(format!(
                    "{}: waterfall needs labeled deltas — a map of label to delta, or rows with {{\"x\": \"label field\", \"y\": \"delta field\"}}; got a list of {}",
                    name,
                    items[0].type_name()
                )));
            }
            let field = |key: &str| -> Result<String, Control> {
                opt_text(opts, key, name)?.ok_or_else(|| {
                    err(format!(
                        "{}: waterfall rows need {{\"x\": \"label field\", \"y\": \"delta field\"}} to pick the columns",
                        name
                    ))
                })
            };
            let (xf, yf) = (field("x")?, field("y")?);
            let mut out = Vec::with_capacity(items.len());
            for (i, row) in items.iter().enumerate() {
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
                let label = m.get(&xf).map(|v| x_display(&x_of(v))).ok_or_else(|| {
                    err(format!(
                        "{}: the x field {:?} is missing in row {}",
                        name,
                        xf,
                        i + 1
                    ))
                })?;
                let yv = m.get(&yf).ok_or_else(|| {
                    err(format!(
                        "{}: the y field {:?} is missing in row {}",
                        name,
                        yf,
                        i + 1
                    ))
                })?;
                let delta = num_of(
                    yv,
                    name,
                    &format!("the y field {:?} in row {}", yf, i + 1),
                )?;
                out.push((label, delta));
            }
            out
        }
        other => {
            return Err(err(format!(
                "{}: waterfall needs labeled deltas — a map of label to delta, or rows with {{\"x\": \"label field\", \"y\": \"delta field\"}}; got {}",
                name,
                other.type_name()
            )))
        }
    };
    let mut acc = 0.0;
    let steps = raw
        .into_iter()
        .map(|(label, delta)| {
            acc += delta;
            WfStep { label, delta, running: acc }
        })
        .collect();
    Ok((steps, total_label))
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
    let (left, bottom) = if matches!(spec.kind, Kind::Pie | Kind::Donut) {
        (16.0, 16.0)
    } else {
        (left, bottom)
    };
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
            spec.th.ink,
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
    th: &'static ThemeColors,
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
            th.grid,
            y = fx(y)
        ));
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"end\" font-size=\"11\" fill=\"{}\">{}</text>\n",
            fx(left - 8.0),
            fx(y + 3.5),
            th.muted,
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
            spec.th.ink,
            esc(xl)
        ));
    }
    if let Some(yl) = &spec.y_label {
        let cy = l.top + l.plot_h / 2.0;
        out.push_str(&format!(
            "<text x=\"14\" y=\"{}\" text-anchor=\"middle\" font-size=\"12\" fill=\"{}\" transform=\"rotate(-90 14 {})\">{}</text>\n",
            fx(cy),
            spec.th.ink,
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
            spec.th.ink,
            esc(label)
        ));
    }
}

/// Labels de categoría bajo el eje X (como máximo ~12, salteando deterministamente).
fn category_labels(
    labels: &[String],
    centers: &[f64],
    l: &Layout,
    th: &'static ThemeColors,
    out: &mut String,
) {
    let step = labels.len().div_ceil(12).max(1);
    for (i, (label, cx)) in labels.iter().zip(centers).enumerate() {
        if i % step != 0 {
            continue;
        }
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" font-size=\"11\" fill=\"{}\">{}</text>\n",
            fx(*cx),
            fx(l.top + l.plot_h + 16.0),
            th.ink,
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
fn is_categorical(series: &[Series]) -> bool {
    series[0].points.iter().any(|(x, _)| matches!(x, XValue::Label(_)))
}

fn render_bar(spec: &ChartSpec, l: &Layout, out: &mut String) {
    let series = spec.series();
    // Apilado (§3.1): una columna por x, tramos en el orden de las series. Con una
    // sola serie es un no-op inofensivo → mismo camino (y mismos bytes) que el bar
    // simple.
    if spec.stack && series.len() > 1 {
        render_bar_stacked(spec, series, l, out);
        return;
    }
    let all: Vec<f64> = series.iter().flat_map(|s| s.points.iter().map(|(_, y)| *y)).collect();
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
    let sy = y_axis(&ticks, ylo, yhi, l, spec.th, out);

    let n = series[0].points.len();
    let m = series.len();
    let band = l.plot_w / n as f64;
    let group_w = band * 0.72;
    let bar_w = group_w / m as f64;
    let y0 = sy(0.0);
    for (si, s) in series.iter().enumerate() {
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
        spec.th.baseline,
        y = fx(y0)
    ));
    let labels: Vec<String> = series[0].points.iter().map(|(x, _)| x_display(x)).collect();
    let centers: Vec<f64> = (0..n).map(|i| l.left + band * (i as f64 + 0.5)).collect();
    category_labels(&labels, &centers, l, spec.th, out);
}

/// Bar apilado: positivos hacia arriba, negativos hacia abajo del eje (estándar);
/// el eje Y incluye SIEMPRE el 0. La geometría de columna es la del bar simple con
/// una serie (mismos anchos) — sólo cambia el origen de cada tramo.
fn render_bar_stacked(spec: &ChartSpec, series: &[Series], l: &Layout, out: &mut String) {
    let n = series[0].points.len();
    let mut pos = vec![0f64; n];
    let mut neg = vec![0f64; n];
    let (mut lo, mut hi) = (0f64, 0f64);
    for s in series {
        for (i, (_, v)) in s.points.iter().enumerate() {
            if *v >= 0.0 {
                pos[i] += v;
                hi = hi.max(pos[i]);
            } else {
                neg[i] += v;
                lo = lo.min(neg[i]);
            }
        }
    }
    if lo == 0.0 && hi == 0.0 {
        hi = 1.0;
    }
    let (ticks, ylo, yhi) = ticks_covering(lo, hi);
    let sy = y_axis(&ticks, ylo, yhi, l, spec.th, out);

    let band = l.plot_w / n as f64;
    let group_w = band * 0.72;
    let y0 = sy(0.0);
    let mut pos_acc = vec![0f64; n];
    let mut neg_acc = vec![0f64; n];
    for (si, s) in series.iter().enumerate() {
        let color = &spec.colors[si];
        for (i, (_, v)) in s.points.iter().enumerate() {
            let x = l.left + band * i as f64 + (band - group_w) / 2.0 + group_w * 0.05;
            let (from, to) = if *v >= 0.0 {
                let from = pos_acc[i];
                pos_acc[i] += v;
                (from, pos_acc[i])
            } else {
                let from = neg_acc[i];
                neg_acc[i] += v;
                (from, neg_acc[i])
            };
            let (ry, rh) = if *v >= 0.0 {
                (sy(to), sy(from) - sy(to))
            } else {
                (sy(from), sy(to) - sy(from))
            };
            out.push_str(&format!(
                "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"/>\n",
                fx(x),
                fx(ry),
                fx(group_w * 0.9),
                fx(rh),
                color
            ));
        }
    }
    out.push_str(&format!(
        "<line x1=\"{}\" y1=\"{y}\" x2=\"{}\" y2=\"{y}\" stroke=\"{}\" stroke-width=\"1\"/>\n",
        fx(l.left),
        fx(l.left + l.plot_w),
        spec.th.baseline,
        y = fx(y0)
    ));
    let labels: Vec<String> = series[0].points.iter().map(|(x, _)| x_display(x)).collect();
    let centers: Vec<f64> = (0..n).map(|i| l.left + band * (i as f64 + 0.5)).collect();
    category_labels(&labels, &centers, l, spec.th, out);
}

/// Mapeo x→px de line/scatter/area (banda categórica o escala numérica).
type XScale = Box<dyn Fn(&XValue, usize) -> f64>;

/// Escala x compartida por line/scatter/area: banda categórica (centros) o escala
/// numérica "nice" — en cuyo caso dibuja acá los ticks del eje X (sin grid
/// vertical: el grid es sólo horizontal). Devuelve (categórica?, mapeo).
fn build_x_scale(
    series: &[Series],
    l: &Layout,
    th: &'static ThemeColors,
    out: &mut String,
) -> (bool, XScale) {
    let categorical = is_categorical(series);
    let sx: XScale = if categorical {
        let n = series[0].points.len();
        let band = l.plot_w / n as f64;
        let left = l.left;
        Box::new(move |_x, i| left + band * (i as f64 + 0.5))
    } else {
        let xs: Vec<f64> = series
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
        for t in &xticks {
            let x = l.left + (t - xlo) / (xhi - xlo) * l.plot_w;
            out.push_str(&format!(
                "<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" font-size=\"11\" fill=\"{}\">{}</text>\n",
                fx(x),
                fx(l.top + l.plot_h + 16.0),
                th.muted,
                esc(&fmt_tick(*t))
            ));
        }
        let (left, plot_w) = (l.left, l.plot_w);
        Box::new(move |x, _i| match x {
            XValue::Num(v) => left + (v - xlo) / (xhi - xlo) * plot_w,
            XValue::Label(_) => left,
        })
    };
    (categorical, sx)
}

fn render_line_scatter(spec: &ChartSpec, l: &Layout, out: &mut String) {
    let series = spec.series();
    let all: Vec<f64> = series.iter().flat_map(|s| s.points.iter().map(|(_, y)| *y)).collect();
    let (ymin, ymax) = all.iter().fold((f64::INFINITY, f64::NEG_INFINITY), |(a, b), v| {
        (a.min(*v), b.max(*v))
    });
    let (ticks, ylo, yhi) = ticks_covering(ymin, ymax);
    let sy = y_axis(&ticks, ylo, yhi, l, spec.th, out);

    let (categorical, sx) = build_x_scale(series, l, spec.th, out);

    // Baseline en el piso del plot.
    out.push_str(&format!(
        "<line x1=\"{}\" y1=\"{y}\" x2=\"{}\" y2=\"{y}\" stroke=\"{}\" stroke-width=\"1\"/>\n",
        fx(l.left),
        fx(l.left + l.plot_w),
        spec.th.baseline,
        y = fx(l.top + l.plot_h)
    ));

    for (si, s) in series.iter().enumerate() {
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
        let labels: Vec<String> = series[0].points.iter().map(|(x, _)| x_display(x)).collect();
        let n = labels.len();
        let band = l.plot_w / n as f64;
        let centers: Vec<f64> = (0..n).map(|i| l.left + band * (i as f64 + 0.5)).collect();
        category_labels(&labels, &centers, l, spec.th, out);
    }
}

/// area (§3.1): relleno al 25% de opacidad hasta el eje 0 + línea de 2px del color
/// de serie (el borde mantiene la identidad bajo CVD). El eje Y incluye SIEMPRE el
/// 0 (el relleno codifica magnitud desde cero). Con `stack: true`, cada banda va
/// del acumulado anterior al nuevo (signos mezclados por x ya rechazados en la
/// normalización).
fn render_area(spec: &ChartSpec, l: &Layout, out: &mut String) {
    let series = spec.series();
    let stacked = spec.stack && series.len() > 1;
    let n = series[0].points.len();

    let (mut lo, mut hi) = (0f64, 0f64);
    if stacked {
        let mut pos = vec![0f64; n];
        let mut neg = vec![0f64; n];
        for s in series {
            for (i, (_, v)) in s.points.iter().enumerate() {
                if *v >= 0.0 {
                    pos[i] += v;
                    hi = hi.max(pos[i]);
                } else {
                    neg[i] += v;
                    lo = lo.min(neg[i]);
                }
            }
        }
    } else {
        for s in series {
            for (_, v) in &s.points {
                lo = lo.min(*v);
                hi = hi.max(*v);
            }
        }
    }
    if lo == 0.0 && hi == 0.0 {
        hi = 1.0;
    }
    let (ticks, ylo, yhi) = ticks_covering(lo, hi);
    let sy = y_axis(&ticks, ylo, yhi, l, spec.th, out);

    let (categorical, sx) = build_x_scale(series, l, spec.th, out);

    // Acumulado por x del piso de cada banda (0 para todas si no hay stack).
    let mut base = vec![0f64; n];
    for (si, s) in series.iter().enumerate() {
        let color = &spec.colors[si];
        let mut tops: Vec<(f64, f64)> = Vec::with_capacity(n);
        let mut floors: Vec<(f64, f64)> = Vec::with_capacity(n);
        for (i, (x, v)) in s.points.iter().enumerate() {
            let x_px = sx(x, i);
            let floor = if stacked { base[i] } else { 0.0 };
            let top = floor + v;
            tops.push((x_px, sy(top)));
            floors.push((x_px, sy(floor)));
            if stacked {
                base[i] = top;
            }
        }
        // Polígono: borde superior de izquierda a derecha + piso de vuelta.
        let mut pts: Vec<String> =
            tops.iter().map(|(x, y)| format!("{},{}", fx(*x), fx(*y))).collect();
        pts.extend(floors.iter().rev().map(|(x, y)| format!("{},{}", fx(*x), fx(*y))));
        out.push_str(&format!(
            "<polygon points=\"{}\" fill=\"{}\" fill-opacity=\"0.25\"/>\n",
            pts.join(" "),
            color
        ));
        // El borde de 2px (misma pluma que line) mantiene la identidad de serie.
        let line_pts: Vec<String> =
            tops.iter().map(|(x, y)| format!("{},{}", fx(*x), fx(*y))).collect();
        out.push_str(&format!(
            "<polyline points=\"{}\" fill=\"none\" stroke=\"{}\" stroke-width=\"2\" stroke-linejoin=\"round\" stroke-linecap=\"round\"/>\n",
            line_pts.join(" "),
            color
        ));
    }

    // Baseline del cero por encima de los rellenos (visible con negativos).
    out.push_str(&format!(
        "<line x1=\"{}\" y1=\"{y}\" x2=\"{}\" y2=\"{y}\" stroke=\"{}\" stroke-width=\"1\"/>\n",
        fx(l.left),
        fx(l.left + l.plot_w),
        spec.th.baseline,
        y = fx(sy(0.0))
    ));
    if categorical {
        let labels: Vec<String> = series[0].points.iter().map(|(x, _)| x_display(x)).collect();
        let band = l.plot_w / n as f64;
        let centers: Vec<f64> = (0..n).map(|i| l.left + band * (i as f64 + 0.5)).collect();
        category_labels(&labels, &centers, l, spec.th, out);
    }
}

/// pie y donut comparten TODO salvo el path del slice (§3.5): `inner_frac` = 0
/// dibuja el pie del Batch 8 (mismos bytes — G1); 0.6 dibuja el anillo del donut.
fn render_pie(
    spec: &ChartSpec,
    l: &Layout,
    out: &mut String,
    name: &str,
    inner_frac: f64,
) -> Result<(), Control> {
    let points = &spec.series()[0].points;
    let mut total = 0.0;
    for (x, v) in points {
        if *v < 0.0 {
            return Err(err(format!(
                "{}: {} values must be non-negative, got {} for {:?}",
                name,
                spec.kind.name(),
                py_float_str(*v),
                x_display(x)
            )));
        }
        total += v;
    }
    if total <= 0.0 {
        return Err(err(format!(
            "{}: {} values sum to 0; nothing to plot",
            name,
            spec.kind.name()
        )));
    }
    let cx = l.left + l.plot_w / 2.0;
    let cy = l.top + l.plot_h / 2.0;
    let r = (l.plot_w.min(l.plot_h) / 2.0 - 4.0).max(8.0);
    let ri = r * inner_frac;
    let mut angle = -std::f64::consts::FRAC_PI_2; // arranca a las 12 en punto
    for (i, (_, v)) in points.iter().enumerate() {
        let frac = v / total;
        let color = &spec.colors[i];
        if frac >= 1.0 {
            if ri > 0.0 {
                // Anillo completo: círculo con stroke del grosor del anillo.
                out.push_str(&format!(
                    "<circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"none\" stroke=\"{}\" stroke-width=\"{}\"/>\n",
                    fx(cx),
                    fx(cy),
                    fx((r + ri) / 2.0),
                    color,
                    fx(r - ri)
                ));
            } else {
                out.push_str(&format!(
                    "<circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"{}\"/>\n",
                    fx(cx),
                    fx(cy),
                    fx(r),
                    color
                ));
            }
            break;
        }
        if frac == 0.0 {
            continue;
        }
        let a1 = angle + frac * std::f64::consts::TAU;
        let (x0, y0) = (cx + r * angle.cos(), cy + r * angle.sin());
        let (x1, y1) = (cx + r * a1.cos(), cy + r * a1.sin());
        let large = if (a1 - angle) > std::f64::consts::PI { 1 } else { 0 };
        if ri > 0.0 {
            // Sector anular: arco externo + arco interno de vuelta.
            let (xi0, yi0) = (cx + ri * angle.cos(), cy + ri * angle.sin());
            let (xi1, yi1) = (cx + ri * a1.cos(), cy + ri * a1.sin());
            out.push_str(&format!(
                "<path d=\"M {x0} {y0} A {r} {r} 0 {large} 1 {x1} {y1} L {xi1} {yi1} A {ri} {ri} 0 {large} 0 {xi0} {yi0} Z\" fill=\"{color}\"/>\n",
                x0 = fx(x0),
                y0 = fx(y0),
                r = fx(r),
                large = large,
                x1 = fx(x1),
                y1 = fx(y1),
                xi1 = fx(xi1),
                yi1 = fx(yi1),
                ri = fx(ri),
                xi0 = fx(xi0),
                yi0 = fx(yi0),
                color = color
            ));
        } else {
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
        }
        angle = a1;
    }
    Ok(())
}

/// heatmap (§3.2): grilla de celdas coloreadas por la escala resuelta; celda
/// ausente = transparente (sin rect). Sin texto en las celdas por default — los
/// valores viajan por MD/JSON. La leyenda es una barra de gradiente muestreada con
/// la MISMA función de color (sin `<linearGradient>` para evitar ids duplicados al
/// incrustar varios charts en una página).
fn render_heatmap(spec: &ChartSpec, hm: &HeatmapData, l: &Layout, out: &mut String) {
    let (nx, ny) = (hm.x_labels.len(), hm.y_labels.len());
    let mut mn = f64::INFINITY;
    let mut mx = f64::NEG_INFINITY;
    for row in &hm.values {
        for v in row.iter().flatten() {
            mn = mn.min(*v);
            mx = mx.max(*v);
        }
    }
    let cw = l.plot_w / nx as f64;
    let ch = l.plot_h / ny as f64;
    for (yi, row) in hm.values.iter().enumerate() {
        for (xi, v) in row.iter().enumerate() {
            if let Some(v) = v {
                let color = lerp_stops(&hm.stops, heat_t(hm.scale, mn, mx, *v));
                out.push_str(&format!(
                    "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"/>\n",
                    fx(l.left + cw * xi as f64),
                    fx(l.top + ch * yi as f64),
                    fx(cw),
                    fx(ch),
                    color
                ));
            }
        }
    }
    // Labels de fila (y) a la izquierda, con el mismo salteo determinista que las
    // categorías del eje x.
    let step = ny.div_ceil(12).max(1);
    for (yi, label) in hm.y_labels.iter().enumerate() {
        if yi % step != 0 {
            continue;
        }
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"end\" font-size=\"11\" fill=\"{}\">{}</text>\n",
            fx(l.left - 8.0),
            fx(l.top + ch * (yi as f64 + 0.5) + 3.5),
            spec.th.ink,
            esc(label)
        ));
    }
    let centers: Vec<f64> = (0..nx).map(|i| l.left + cw * (i as f64 + 0.5)).collect();
    category_labels(&hm.x_labels, &centers, l, spec.th, out);

    if spec.legend {
        // Barra de gradiente vertical: 24 segmentos muestreados de min (abajo) a
        // max (arriba); labels de extremos (y del centro si la escala es divergente).
        let lx = spec.width - 140.0;
        let lh = l.plot_h.min(120.0);
        let ly = l.top + 6.0;
        let segs = 24;
        for i in 0..segs {
            let t_val = if mx > mn {
                mn + (mx - mn) * (i as f64 + 0.5) / segs as f64
            } else {
                mn
            };
            let color = lerp_stops(&hm.stops, heat_t(hm.scale, mn, mx, t_val));
            let seg_h = lh / segs as f64;
            let y = ly + lh - seg_h * (i + 1) as f64;
            out.push_str(&format!(
                "<rect x=\"{}\" y=\"{}\" width=\"12\" height=\"{}\" fill=\"{}\"/>\n",
                fx(lx),
                fx(y),
                fx(seg_h),
                color
            ));
        }
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"10\" fill=\"{}\">{}</text>\n",
            fx(lx + 17.0),
            fx(ly + 8.0),
            spec.th.muted,
            esc(&fmt_tick(mx))
        ));
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"10\" fill=\"{}\">{}</text>\n",
            fx(lx + 17.0),
            fx(ly + lh),
            spec.th.muted,
            esc(&fmt_tick(mn))
        ));
        if let HeatScale::Diverging { center } = hm.scale {
            if mx > mn && center >= mn && center <= mx {
                let cy = ly + lh - lh * (center - mn) / (mx - mn);
                out.push_str(&format!(
                    "<text x=\"{}\" y=\"{}\" font-size=\"10\" fill=\"{}\">{}</text>\n",
                    fx(lx + 17.0),
                    fx(cy + 3.5),
                    spec.th.muted,
                    esc(&fmt_tick(center))
                ));
            }
        }
    }
}

/// histogram (§3.3): barras CONTIGUAS (es una distribución, no categorías), eje Y
/// desde 0, ticks del eje X en los bordes de bin (formato de ticks del Batch 8).
fn render_histogram(spec: &ChartSpec, counts: &[i64], edges: &[f64], l: &Layout, out: &mut String) {
    let mut hi = 0f64;
    for c in counts {
        hi = hi.max(*c as f64);
    }
    if hi == 0.0 {
        hi = 1.0;
    }
    let (ticks, ylo, yhi) = ticks_covering(0.0, hi);
    let sy = y_axis(&ticks, ylo, yhi, l, spec.th, out);

    let (e0, e1) = (edges[0], edges[edges.len() - 1]);
    let sx = |e: f64| l.left + (e - e0) / (e1 - e0) * l.plot_w;
    // Labels de borde de bin (mismo estilo/salteo que los ticks numéricos de line).
    let step = edges.len().div_ceil(12).max(1);
    for (i, e) in edges.iter().enumerate() {
        if i % step != 0 {
            continue;
        }
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" font-size=\"11\" fill=\"{}\">{}</text>\n",
            fx(sx(*e)),
            fx(l.top + l.plot_h + 16.0),
            spec.th.muted,
            esc(&fmt_tick(*e))
        ));
    }
    let y0 = sy(0.0);
    for (i, c) in counts.iter().enumerate() {
        let x0 = sx(edges[i]);
        let x1 = sx(edges[i + 1]);
        let y1 = sy(*c as f64);
        out.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"/>\n",
            fx(x0),
            fx(y1),
            fx(x1 - x0),
            fx(y0 - y1),
            spec.colors[0]
        ));
    }
    out.push_str(&format!(
        "<line x1=\"{}\" y1=\"{y}\" x2=\"{}\" y2=\"{y}\" stroke=\"{}\" stroke-width=\"1\"/>\n",
        fx(l.left),
        fx(l.left + l.plot_w),
        spec.th.baseline,
        y = fx(y0)
    ));
}

/// boxplot (§3.4): caja q1–q3, mediana de 2px, bigotes Tukey con tapas, outliers
/// como markers ≥ 6px. Todos los grupos en el color 1 (se distinguen por
/// posición+label, no por color — no consume las 8 series).
fn render_boxplot(spec: &ChartSpec, groups: &[BoxGroup], l: &Layout, out: &mut String) {
    let mut lo = f64::INFINITY;
    let mut hi = f64::NEG_INFINITY;
    for g in groups {
        lo = lo.min(g.min);
        hi = hi.max(g.max);
        for o in &g.outliers {
            lo = lo.min(*o);
            hi = hi.max(*o);
        }
    }
    let (ticks, ylo, yhi) = ticks_covering(lo, hi);
    let sy = y_axis(&ticks, ylo, yhi, l, spec.th, out);

    // Baseline en el piso del plot (mismo marco que line).
    out.push_str(&format!(
        "<line x1=\"{}\" y1=\"{y}\" x2=\"{}\" y2=\"{y}\" stroke=\"{}\" stroke-width=\"1\"/>\n",
        fx(l.left),
        fx(l.left + l.plot_w),
        spec.th.baseline,
        y = fx(l.top + l.plot_h)
    ));

    let n = groups.len();
    let band = l.plot_w / n as f64;
    let box_w = (band * 0.5).min(64.0);
    let color = &spec.colors[0];
    for (i, g) in groups.iter().enumerate() {
        let cx = l.left + band * (i as f64 + 0.5);
        // Bigotes (línea vertical) + tapas.
        out.push_str(&format!(
            "<line x1=\"{x}\" y1=\"{}\" x2=\"{x}\" y2=\"{}\" stroke=\"{}\" stroke-width=\"1\"/>\n",
            fx(sy(g.max)),
            fx(sy(g.q3)),
            color,
            x = fx(cx)
        ));
        out.push_str(&format!(
            "<line x1=\"{x}\" y1=\"{}\" x2=\"{x}\" y2=\"{}\" stroke=\"{}\" stroke-width=\"1\"/>\n",
            fx(sy(g.q1)),
            fx(sy(g.min)),
            color,
            x = fx(cx)
        ));
        for cap in [g.max, g.min] {
            out.push_str(&format!(
                "<line x1=\"{}\" y1=\"{y}\" x2=\"{}\" y2=\"{y}\" stroke=\"{}\" stroke-width=\"1\"/>\n",
                fx(cx - box_w / 4.0),
                fx(cx + box_w / 4.0),
                color,
                y = fx(sy(cap))
            ));
        }
        // Caja q1–q3 (IQR 0 → caja plana, sin división por cero).
        out.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\" fill-opacity=\"0.25\" stroke=\"{}\"/>\n",
            fx(cx - box_w / 2.0),
            fx(sy(g.q3)),
            fx(box_w),
            fx(sy(g.q1) - sy(g.q3)),
            color,
            color
        ));
        // Mediana (== median() del builtin — test de guardia).
        out.push_str(&format!(
            "<line x1=\"{}\" y1=\"{y}\" x2=\"{}\" y2=\"{y}\" stroke=\"{}\" stroke-width=\"2\"/>\n",
            fx(cx - box_w / 2.0),
            fx(cx + box_w / 2.0),
            color,
            y = fx(sy(g.median))
        ));
        for o in &g.outliers {
            out.push_str(&format!(
                "<circle cx=\"{}\" cy=\"{}\" r=\"3\" fill=\"{}\"/>\n",
                fx(cx),
                fx(sy(*o)),
                color
            ));
        }
    }
    let labels: Vec<String> = groups.iter().map(|g| g.name.clone()).collect();
    let centers: Vec<f64> = (0..n).map(|i| l.left + band * (i as f64 + 0.5)).collect();
    category_labels(&labels, &centers, l, spec.th, out);
}

/// waterfall (§3.6): barras flotantes (cada una arranca donde terminó la acumulada
/// anterior), conectores hairline, colores semánticos CVD-safe [up, down, total].
/// Delta 0 → rect de altura 0 con label visible (dato real, no error).
fn render_waterfall(
    spec: &ChartSpec,
    steps: &[WfStep],
    total_label: &Option<String>,
    l: &Layout,
    out: &mut String,
) {
    let total = steps.last().map(|s| s.running).unwrap_or(0.0);
    let (mut lo, mut hi) = (0f64, 0f64);
    let mut prev = 0.0;
    for s in steps {
        lo = lo.min(prev).min(s.running);
        hi = hi.max(prev).max(s.running);
        prev = s.running;
    }
    if lo == 0.0 && hi == 0.0 {
        hi = 1.0;
    }
    let (ticks, ylo, yhi) = ticks_covering(lo, hi);
    let sy = y_axis(&ticks, ylo, yhi, l, spec.th, out);

    let n = steps.len() + usize::from(total_label.is_some());
    let band = l.plot_w / n as f64;
    let group_w = band * 0.72;
    let bar_w = group_w * 0.9;
    let bar_x = |i: usize| l.left + band * i as f64 + (band - group_w) / 2.0 + group_w * 0.05;
    let (up, down, total_color) = (&spec.colors[0], &spec.colors[1], &spec.colors[2]);

    let mut prev = 0f64;
    for (i, s) in steps.iter().enumerate() {
        let (from, to) = (prev, s.running);
        let color = if s.delta >= 0.0 { up } else { down };
        out.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"/>\n",
            fx(bar_x(i)),
            fx(sy(from.max(to))),
            fx(bar_w),
            fx((sy(from) - sy(to)).abs()),
            color
        ));
        prev = to;
    }
    if total_label.is_some() {
        out.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"/>\n",
            fx(bar_x(steps.len())),
            fx(sy(total.max(0.0))),
            fx(bar_w),
            fx((sy(0.0) - sy(total)).abs()),
            total_color
        ));
    }
    // Conectores hairline entre barras consecutivas, al nivel del acumulado.
    for (i, s) in steps.iter().enumerate() {
        if i + 1 < n {
            let y = sy(s.running);
            out.push_str(&format!(
                "<line x1=\"{}\" y1=\"{y}\" x2=\"{}\" y2=\"{y}\" stroke=\"{}\" stroke-width=\"1\"/>\n",
                fx(bar_x(i) + bar_w),
                fx(bar_x(i + 1)),
                spec.th.baseline,
                y = fx(y)
            ));
        }
    }
    // Baseline del cero (el puente puede cruzarlo varias veces).
    out.push_str(&format!(
        "<line x1=\"{}\" y1=\"{y}\" x2=\"{}\" y2=\"{y}\" stroke=\"{}\" stroke-width=\"1\"/>\n",
        fx(l.left),
        fx(l.left + l.plot_w),
        spec.th.baseline,
        y = fx(sy(0.0))
    ));
    let mut labels: Vec<String> = steps.iter().map(|s| s.label.clone()).collect();
    if let Some(t) = total_label {
        labels.push(t.clone());
    }
    let centers: Vec<f64> = (0..n).map(|i| l.left + band * (i as f64 + 0.5)).collect();
    category_labels(&labels, &centers, l, spec.th, out);
}

/// Renderer central: `ChartSpec` normalizado → SVG completo (determinista, G7).
/// Los `match` sobre `Kind` son exhaustivos a propósito: un kind nuevo sin brazo
/// no compila (§7.5).
fn render_svg(spec: &ChartSpec, name: &str) -> Result<String, Control> {
    let l = layout(spec)?;
    let mut out = String::with_capacity(2048);
    svg_open(spec, &mut out);
    match (&spec.data, spec.kind) {
        (ChartData::Series(_), Kind::Bar) => render_bar(spec, &l, &mut out),
        (ChartData::Series(_), Kind::Line | Kind::Scatter) => {
            render_line_scatter(spec, &l, &mut out)
        }
        (ChartData::Series(_), Kind::Area) => render_area(spec, &l, &mut out),
        (ChartData::Series(_), Kind::Pie) => render_pie(spec, &l, &mut out, name, 0.0)?,
        // Radio interno fijo 0.6R (§3.5): azúcar visual honesto sobre el pie.
        (ChartData::Series(_), Kind::Donut) => render_pie(spec, &l, &mut out, name, 0.6)?,
        (ChartData::Heatmap(hm), _) => render_heatmap(spec, hm, &l, &mut out),
        (ChartData::Histogram { counts, edges }, _) => {
            render_histogram(spec, counts, edges, &l, &mut out)
        }
        (ChartData::Boxplot(groups), _) => render_boxplot(spec, groups, &l, &mut out),
        (ChartData::Waterfall { steps, total_label }, _) => {
            render_waterfall(spec, steps, total_label, &l, &mut out)
        }
        // normalize_series construye siempre la variante que corresponde al kind.
        (ChartData::Series(_), _) => {
            return Err(err(format!(
                "{}: internal error — normalized data does not match kind {:?}",
                name,
                spec.kind.name()
            )))
        }
    }
    if !matches!(spec.kind, Kind::Pie | Kind::Donut) {
        axis_labels(spec, &l, &mut out);
    }
    // Leyenda genérica de swatches. El heatmap dibuja su propia barra de gradiente
    // dentro del renderer; histogram/boxplot/waterfall la exponen opt-in.
    let legend_items: Vec<(String, &str)> = match &spec.data {
        ChartData::Series(series) => {
            if matches!(spec.kind, Kind::Pie | Kind::Donut) {
                series[0]
                    .points
                    .iter()
                    .enumerate()
                    .map(|(i, (x, _))| (x_display(x), spec.colors[i].as_str()))
                    .collect()
            } else {
                series
                    .iter()
                    .enumerate()
                    .map(|(i, s)| (s.name.clone(), spec.colors[i].as_str()))
                    .collect()
            }
        }
        ChartData::Heatmap(_) => Vec::new(),
        ChartData::Histogram { .. } => vec![("count".to_string(), spec.colors[0].as_str())],
        ChartData::Boxplot(groups) => {
            groups.iter().map(|g| (g.name.clone(), spec.colors[0].as_str())).collect()
        }
        ChartData::Waterfall { total_label, .. } => {
            let mut items = vec![
                ("increase".to_string(), spec.colors[0].as_str()),
                ("decrease".to_string(), spec.colors[1].as_str()),
            ];
            if let Some(t) = total_label {
                items.push((t.clone(), spec.colors[2].as_str()));
            }
            items
        }
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
/// normalización y el renderer con `chart_svg`: el HTML del nodo son los MISMOS
/// bytes. Los datos normalizados se guardan como valores del lenguaje POR KIND —
/// la tabla/matriz Markdown y el JSON estructurado (§3.7) salen de estos campos,
/// del mismo origen que el SVG (imposible que diverjan).
pub fn chart_node(args: &[SynValue]) -> Result<SynValue, Control> {
    let spec = normalize_series(args, "chart")?;
    let svg = render_svg(&spec, "chart")?;
    let text_or_nothing = |o: &Option<String>| match o {
        Some(s) => syn_text(s.as_str()),
        None => syn_nothing(),
    };
    let mut fields: Vec<(&str, SynValue)> = vec![
        ("chart_kind", syn_text(spec.kind.name())),
        ("title", text_or_nothing(&spec.title)),
        ("x_label", text_or_nothing(&spec.x_label)),
        ("y_label", text_or_nothing(&spec.y_label)),
        ("x_name", text_or_nothing(&spec.x_name)),
    ];
    match &spec.data {
        ChartData::Series(series) => {
            // {"series": [{"name", "points": [[x, y], …]}, …]} — como el Batch 8.
            let series_val = syn_list(
                series
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
                                            XValue::Num(v)
                                                if v.fract() == 0.0 && v.abs() < 1e15 =>
                                            {
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
            fields.push(("series", series_val));
            fields.push(("stack", syn_bool(spec.stack)));
        }
        ChartData::Heatmap(hm) => {
            fields.push((
                "x_labels",
                syn_list(hm.x_labels.iter().map(|s| syn_text(s.as_str())).collect()),
            ));
            fields.push((
                "y_labels",
                syn_list(hm.y_labels.iter().map(|s| syn_text(s.as_str())).collect()),
            ));
            fields.push((
                "values",
                syn_list(
                    hm.values
                        .iter()
                        .map(|row| {
                            syn_list(
                                row.iter()
                                    .map(|v| match v {
                                        Some(v) => syn_float(*v),
                                        None => syn_nothing(), // celda ausente → null
                                    })
                                    .collect(),
                            )
                        })
                        .collect(),
                ),
            ));
        }
        ChartData::Histogram { counts, edges } => {
            fields.push(("counts", syn_list(counts.iter().map(|c| syn_int(*c)).collect())));
            fields.push(("edges", syn_list(edges.iter().map(|e| syn_float(*e)).collect())));
        }
        ChartData::Boxplot(groups) => {
            fields.push((
                "groups",
                syn_list(
                    groups
                        .iter()
                        .map(|g| {
                            let mut m = IndexMap::new();
                            m.insert("name".to_string(), syn_text(g.name.as_str()));
                            m.insert("min".to_string(), syn_float(g.min));
                            m.insert("q1".to_string(), syn_float(g.q1));
                            m.insert("median".to_string(), syn_float(g.median));
                            m.insert("q3".to_string(), syn_float(g.q3));
                            m.insert("max".to_string(), syn_float(g.max));
                            m.insert(
                                "outliers".to_string(),
                                syn_list(g.outliers.iter().map(|o| syn_float(*o)).collect()),
                            );
                            syn_map(m)
                        })
                        .collect(),
                ),
            ));
        }
        ChartData::Waterfall { steps, total_label } => {
            fields.push((
                "steps",
                syn_list(
                    steps
                        .iter()
                        .map(|s| {
                            let mut m = IndexMap::new();
                            m.insert("label".to_string(), syn_text(s.label.as_str()));
                            m.insert("delta".to_string(), syn_float(s.delta));
                            m.insert("running".to_string(), syn_float(s.running));
                            syn_map(m)
                        })
                        .collect(),
                ),
            ));
            fields.push((
                "total",
                syn_float(steps.last().map(|s| s.running).unwrap_or(0.0)),
            ));
            fields.push((
                "total_label",
                match total_label {
                    Some(t) => syn_text(t.as_str()),
                    None => syn_nothing(),
                },
            ));
        }
    }
    fields.push(("svg", syn_text(svg.as_str())));
    Ok(crate::server::make_node("chart", fields))
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

fn field_val(node: &SynValue, key: &str) -> Option<SynValue> {
    match node {
        SynValue::Server(s) => s.get_field(key),
        _ => None,
    }
}

fn field_list(node: &SynValue, key: &str) -> Vec<SynValue> {
    match field_val(node, key) {
        Some(SynValue::List(l)) => l.borrow().clone(),
        _ => Vec::new(),
    }
}

/// Celda numérica de las tablas MD nuevas: el f64 guardado en el nodo, estilo
/// Python (mismo formato que el JSON — misma fuente, misma cara).
fn md_num(v: &SynValue) -> String {
    match v {
        SynValue::Number(n) => py_float_str(n.to_f64()),
        SynValue::Nothing => String::new(), // celda ausente del heatmap
        other => other.to_string(),
    }
}

/// `chart()` en la representación Markdown (§3.7): el agente obtiene los DATOS,
/// no píxeles. `match` EXHAUSTIVO sobre `Kind` — un kind nuevo sin brazo no compila.
pub fn render_chart_md(node: &SynValue) -> String {
    let kind = field_str(node, "chart_kind").and_then(|k| Kind::from_name(&k));
    let mut out = String::new();
    if let Some(t) = field_str(node, "title") {
        out.push_str(&format!("**{}**\n\n", md_cell(&t)));
    }
    match kind {
        Some(Kind::Bar | Kind::Line | Kind::Pie | Kind::Scatter | Kind::Area | Kind::Donut)
        | None => {
            // Tabla x + una columna por serie (Batch 8; None sólo si el nodo no es
            // un chart válido — devuelve tabla vacía, jamás panic).
            return md_series_table(node);
        }
        Some(Kind::Heatmap) => {
            // Matriz: filas = y_labels, columnas = x_labels, celdas = valores.
            let xs = field_list(node, "x_labels");
            let ys = field_list(node, "y_labels");
            let values = field_list(node, "values");
            out.push_str("| ");
            for x in &xs {
                out.push_str(&format!("| {} ", md_cell(&x.to_string())));
            }
            out.push_str("|\n|");
            for _ in 0..=xs.len() {
                out.push_str(" --- |");
            }
            for (yi, y) in ys.iter().enumerate() {
                out.push_str(&format!("\n| {} |", md_cell(&y.to_string())));
                let row = match values.get(yi) {
                    Some(SynValue::List(l)) => l.borrow().clone(),
                    _ => Vec::new(),
                };
                for xi in 0..xs.len() {
                    let cell = row.get(xi).map(md_num).unwrap_or_default();
                    out.push_str(&format!(" {} |", md_cell(&cell)));
                }
            }
            out.push('\n');
        }
        Some(Kind::Histogram) => {
            // Tabla rango | count (rangos semiabiertos, el último cerrado — la
            // semántica exacta de histogram()).
            let counts = field_list(node, "counts");
            let edges = field_list(node, "edges");
            out.push_str("| range | count |\n| --- | --- |");
            for (i, c) in counts.iter().enumerate() {
                let a = edges.get(i).map(md_num).unwrap_or_default();
                let b = edges.get(i + 1).map(md_num).unwrap_or_default();
                let close = if i + 1 == counts.len() { "]" } else { ")" };
                out.push_str(&format!(
                    "\n| [{}, {}{} | {} |",
                    md_cell(&a),
                    md_cell(&b),
                    close,
                    md_cell(&c.to_string())
                ));
            }
            out.push('\n');
        }
        Some(Kind::Boxplot) => {
            out.push_str(
                "| group | min | q1 | median | q3 | max | outliers |\n| --- | --- | --- | --- | --- | --- | --- |",
            );
            for g in field_list(node, "groups") {
                let m = match &g {
                    SynValue::Map(m) => m.borrow().clone(),
                    _ => continue,
                };
                let cell = |k: &str| m.get(k).map(md_num).unwrap_or_default();
                let name = m.get("name").map(|v| v.to_string()).unwrap_or_default();
                let outliers = match m.get("outliers") {
                    Some(SynValue::List(l)) => {
                        l.borrow().iter().map(md_num).collect::<Vec<_>>().join(", ")
                    }
                    _ => String::new(),
                };
                out.push_str(&format!(
                    "\n| {} | {} | {} | {} | {} | {} | {} |",
                    md_cell(&name),
                    md_cell(&cell("min")),
                    md_cell(&cell("q1")),
                    md_cell(&cell("median")),
                    md_cell(&cell("q3")),
                    md_cell(&cell("max")),
                    md_cell(&outliers)
                ));
            }
            out.push('\n');
        }
        Some(Kind::Waterfall) => {
            out.push_str("| label | delta | running |\n| --- | --- | --- |");
            for s in field_list(node, "steps") {
                let m = match &s {
                    SynValue::Map(m) => m.borrow().clone(),
                    _ => continue,
                };
                let label = m.get("label").map(|v| v.to_string()).unwrap_or_default();
                let delta = m.get("delta").map(md_num).unwrap_or_default();
                let running = m.get("running").map(md_num).unwrap_or_default();
                out.push_str(&format!(
                    "\n| {} | {} | {} |",
                    md_cell(&label),
                    md_cell(&delta),
                    md_cell(&running)
                ));
            }
            // Fila de total sólo si el chart la pidió ({"total": …} — opt-in).
            if let Some(t) = field_str(node, "total_label") {
                let total = field_val(node, "total").map(|v| md_num(&v)).unwrap_or_default();
                out.push_str(&format!("\n| {} |  | {} |", md_cell(&t), md_cell(&total)));
            }
            out.push('\n');
        }
    }
    out
}

/// Los campos de DATOS del nodo chart para el JSON negociado (§3.7), por kind.
/// El server los serializa tal cual (`syn_to_json`); acá vive el `match` exhaustivo
/// sobre `Kind` para que un kind nuevo sin salida JSON no compile.
pub(crate) fn chart_data_fields(node: &SynValue) -> Vec<(&'static str, SynValue)> {
    let empty = || syn_list(Vec::new());
    let get = |key: &str| field_val(node, key);
    let kind = field_str(node, "chart_kind").and_then(|k| Kind::from_name(&k));
    match kind {
        Some(Kind::Bar | Kind::Line | Kind::Pie | Kind::Scatter | Kind::Area | Kind::Donut)
        | None => {
            let mut fields = vec![("series", get("series").unwrap_or_else(empty))];
            // "stack": bool — sólo cuando está activo (el output default del Batch 8
            // no cambia — G1).
            if matches!(get("stack"), Some(SynValue::Bool(true))) {
                fields.push(("stack", syn_bool(true)));
            }
            fields
        }
        Some(Kind::Heatmap) => vec![
            ("x_labels", get("x_labels").unwrap_or_else(empty)),
            ("y_labels", get("y_labels").unwrap_or_else(empty)),
            ("values", get("values").unwrap_or_else(empty)),
        ],
        Some(Kind::Histogram) => vec![
            ("counts", get("counts").unwrap_or_else(empty)),
            ("edges", get("edges").unwrap_or_else(empty)),
        ],
        Some(Kind::Boxplot) => vec![("groups", get("groups").unwrap_or_else(empty))],
        Some(Kind::Waterfall) => vec![
            ("steps", get("steps").unwrap_or_else(empty)),
            ("total", get("total").unwrap_or_else(|| syn_float(0.0))),
        ],
    }
}

/// Tabla Markdown x + series (kinds del Batch 8 y area/donut).
fn md_series_table(node: &SynValue) -> String {
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
        assert!(err_of(&[syn_text("treemap"), map1(&[("a", 1.0)])])
            .contains("valid kinds are: area, bar, boxplot, donut, heatmap, histogram, line, pie, scatter, waterfall"));
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

    // =====================================================
    // Batch 10 — helpers de test
    // =====================================================

    fn opts_v(pairs: Vec<(&str, SynValue)>) -> SynValue {
        let mut m = IndexMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        syn_map(m)
    }

    fn rows_v(rows: Vec<Vec<(&str, SynValue)>>) -> SynValue {
        syn_list(
            rows.into_iter()
                .map(|r| {
                    let mut m = IndexMap::new();
                    for (k, v) in r {
                        m.insert(k.to_string(), v);
                    }
                    syn_map(m)
                })
                .collect(),
        )
    }

    fn nums(vals: &[f64]) -> SynValue {
        syn_list(vals.iter().map(|v| syn_float(*v)).collect())
    }

    fn node_field_of(node: &SynValue, key: &str) -> SynValue {
        match node {
            SynValue::Server(s) => s.get_field(key).unwrap_or_else(syn_nothing),
            other => panic!("no es un nodo: {}", other.type_name()),
        }
    }

    // =====================================================
    // Batch 10 — tema dark (§4)
    // =====================================================

    #[test]
    fn theme_light_is_the_default_bytes() {
        let data = map1(&[("a", 3.0), ("b", 7.0)]);
        let plain = svg_of(&[syn_text("bar"), data.clone()]);
        let light = svg_of(&[
            syn_text("bar"),
            data.clone(),
            opts_v(vec![("theme", syn_text("light"))]),
        ]);
        assert_eq!(plain, light, "theme light == default, byte a byte (G1)");
        let dark = svg_of(&[syn_text("bar"), data, opts_v(vec![("theme", syn_text("dark"))])]);
        assert_ne!(plain, dark);
        assert!(dark.contains("#5b9ce8"), "primera serie dark:\n{}", dark);
        assert!(dark.contains("#c9c8c1"), "tinta dark:\n{}", dark);
        assert!(!dark.contains(PALETTE[0]), "sin colores light en dark:\n{}", dark);
    }

    #[test]
    fn theme_errors_and_user_colors_precedence() {
        let data = map1(&[("a", 1.0)]);
        let e = err_of(&[syn_text("bar"), data.clone(), opts_v(vec![("theme", syn_text("sepia"))])]);
        assert!(e.contains("\"light\"") && e.contains("\"dark\""), "{}", e);
        // `colors` del usuario le gana al tema (G3).
        let svg = svg_of(&[
            syn_text("bar"),
            data,
            opts_v(vec![
                ("theme", syn_text("dark")),
                ("colors", syn_list(vec![syn_text("#123456")])),
            ]),
        ]);
        assert!(svg.contains("#123456"), "{}", svg);
        assert!(!svg.contains("#5b9ce8"), "la paleta dark fue reemplazada:\n{}", svg);
    }

    /// Luminancia relativa WCAG de un color hex (para asserts de contraste — §4:
    /// numéricos, no a ojo).
    fn wcag_luminance(hex: &str) -> f64 {
        let (r, g, b) = match parse_stop(hex, "test") {
            Ok(rgb) => rgb,
            Err(_) => panic!("hex inválido: {}", hex),
        };
        let lin = |c: f64| {
            let c = c / 255.0;
            if c <= 0.03928 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
    }

    fn wcag_contrast(a: &str, b: &str) -> f64 {
        let (la, lb) = (wcag_luminance(a), wcag_luminance(b));
        let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
        (hi + 0.05) / (lo + 0.05)
    }

    #[test]
    fn dark_theme_wcag_contrast() {
        for c in DARK.series {
            let ratio = wcag_contrast(c, "#1e1e1e");
            assert!(ratio >= 3.0, "serie dark {} contra #1e1e1e: {:.2} < 3.0", c, ratio);
        }
        let ink = wcag_contrast(DARK.ink, "#1e1e1e");
        assert!(ink >= 4.5, "tinta dark contra #1e1e1e: {:.2} < 4.5", ink);
    }

    // =====================================================
    // Batch 10 — area (± stack) y bar apilado (§3.1)
    // =====================================================

    fn rows_two_series() -> SynValue {
        rows_v(vec![
            vec![("mes", syn_text("ene")), ("a", syn_float(10.0)), ("b", syn_float(4.0))],
            vec![("mes", syn_text("feb")), ("a", syn_float(25.0)), ("b", syn_float(9.0))],
            vec![("mes", syn_text("mar")), ("a", syn_float(17.0)), ("b", syn_float(12.0))],
        ])
    }

    fn xy_ab() -> Vec<(&'static str, SynValue)> {
        vec![("x", syn_text("mes")), ("y", syn_list(vec![syn_text("a"), syn_text("b")]))]
    }

    #[test]
    fn area_renders_fill_plus_stroke() {
        let svg = svg_of(&[syn_text("area"), nums(&[1.0, 3.0, 2.0])]);
        assert_eq!(svg.matches("<polygon").count(), 1, "{}", svg);
        assert_eq!(svg.matches("<polyline").count(), 1, "{}", svg);
        assert!(svg.contains("fill-opacity=\"0.25\""), "{}", svg);
        assert!(svg.contains("stroke-width=\"2\""), "borde de identidad de serie:\n{}", svg);
    }

    #[test]
    fn stacked_area_tops_are_cumulative() {
        let mut o = xy_ab();
        o.push(("stack", syn_bool(true)));
        o.push(("legend", syn_bool(false)));
        let svg = svg_of(&[syn_text("area"), rows_two_series(), opts_v(o)]);
        assert_eq!(svg.matches("<polygon").count(), 2, "{}", svg);
        // La cima de la serie 2 en feb es 25 + 9 = 34: con el rango [0, 35] de
        // ticks_covering, y = top + plot_h * (1 - 34/35). Verificación numérica:
        // el polyline de la 2ª serie contiene la coordenada y de 34.
        // (En vez de recalcular el layout a mano, verificamos la propiedad clave:
        // ambas series comparten x, y la 2ª queda POR ENCIMA de la 1ª en cada x.)
        let poly_ys: Vec<f64> = svg
            .match_indices("<polyline")
            .map(|(i, _)| {
                let seg = &svg[i..svg[i..].find("/>").map(|e| i + e).unwrap_or(svg.len())];
                let pts = seg.split("points=\"").nth(1).unwrap().split('"').next().unwrap();
                pts.split(' ').next().unwrap().split(',').nth(1).unwrap().parse::<f64>().unwrap()
            })
            .collect();
        assert_eq!(poly_ys.len(), 2);
        assert!(
            poly_ys[1] < poly_ys[0],
            "la cima apilada de la serie 2 debe quedar por encima (y menor): {:?}",
            poly_ys
        );
    }

    #[test]
    fn stacked_area_mixed_signs_is_an_error() {
        let rows = rows_v(vec![
            vec![("x", syn_text("a")), ("p", syn_float(5.0)), ("q", syn_float(-2.0))],
        ]);
        let mut o = vec![("x", syn_text("x")), ("y", syn_list(vec![syn_text("p"), syn_text("q")]))];
        o.push(("stack", syn_bool(true)));
        let e = err_of(&[syn_text("area"), rows, opts_v(o)]);
        assert!(e.contains("stacked area") && e.contains("bar"), "{}", e);
    }

    #[test]
    fn stack_single_series_is_a_noop() {
        for kind in ["bar", "area"] {
            let plain = svg_of(&[syn_text(kind), nums(&[1.0, 2.0])]);
            let stacked = svg_of(&[
                syn_text(kind),
                nums(&[1.0, 2.0]),
                opts_v(vec![("stack", syn_bool(true))]),
            ]);
            assert_eq!(plain, stacked, "stack con 1 serie = no-op byte a byte ({})", kind);
        }
    }

    #[test]
    fn stack_on_unsupported_kind_is_an_error() {
        for kind in ["pie", "scatter", "heatmap", "boxplot", "waterfall", "histogram", "donut", "line"] {
            let e = err_of(&[
                syn_text(kind),
                map1(&[("a", 1.0)]),
                opts_v(vec![("stack", syn_bool(true))]),
            ]);
            assert!(
                e.contains("\"stack\"") && e.contains("bar, area"),
                "error dirigido para {}: {}",
                kind,
                e
            );
        }
    }

    #[test]
    fn stacked_bar_positive_up_negative_down() {
        let rows = rows_v(vec![
            vec![("x", syn_text("a")), ("p", syn_float(5.0)), ("q", syn_float(-3.0))],
            vec![("x", syn_text("b")), ("p", syn_float(2.0)), ("q", syn_float(4.0))],
        ]);
        let o = opts_v(vec![
            ("x", syn_text("x")),
            ("y", syn_list(vec![syn_text("p"), syn_text("q")])),
            ("stack", syn_bool(true)),
            ("legend", syn_bool(false)),
        ]);
        let svg = svg_of(&[syn_text("bar"), rows, o]);
        assert_eq!(svg.matches("<rect").count(), 4, "un tramo por serie por x:\n{}", svg);
        assert!(svg.contains(BASELINE), "baseline del cero visible:\n{}", svg);
        // Serie toda en 0 apilada: no divide por cero ni rompe.
        let rows0 = rows_v(vec![
            vec![("x", syn_text("a")), ("p", syn_float(0.0)), ("q", syn_float(0.0))],
        ]);
        let o0 = opts_v(vec![
            ("x", syn_text("x")),
            ("y", syn_list(vec![syn_text("p"), syn_text("q")])),
            ("stack", syn_bool(true)),
        ]);
        let svg0 = svg_of(&[syn_text("bar"), rows0, o0]);
        assert!(svg0.contains("<svg"), "{}", svg0);
    }

    // =====================================================
    // Batch 10 — heatmap (§3.2)
    // =====================================================

    fn heat_rows() -> SynValue {
        rows_v(vec![
            vec![("d", syn_text("lun")), ("h", syn_text("9")), ("v", syn_float(1.0))],
            vec![("d", syn_text("lun")), ("h", syn_text("10")), ("v", syn_float(5.0))],
            vec![("d", syn_text("mar")), ("h", syn_text("9")), ("v", syn_float(9.0))],
        ])
    }

    fn heat_opts() -> Vec<(&'static str, SynValue)> {
        vec![("x", syn_text("h")), ("y", syn_text("d")), ("value", syn_text("v"))]
    }

    #[test]
    fn heatmap_tidy_and_matrix_agree() {
        // Los mismos datos por las dos formas → mismo SVG (mismas labels).
        let mut o = heat_opts();
        o.push(("legend", syn_bool(false)));
        let tidy = svg_of(&[syn_text("heatmap"), heat_rows(), opts_v(o)]);
        // celda (mar, 10) ausente → 3 rects, no 4
        assert_eq!(tidy.matches("<rect").count(), 3, "celda ausente transparente:\n{}", tidy);
        assert!(tidy.contains("#f1f6fd"), "min = primer stop:\n{}", tidy);
        assert!(tidy.contains("#123c6b"), "max = último stop:\n{}", tidy);

        // Matriz completa equivalente no existe (falta una celda); usamos una 2x2
        // completa para comparar formas.
        let full_rows = rows_v(vec![
            vec![("d", syn_text("lun")), ("h", syn_text("9")), ("v", syn_float(1.0))],
            vec![("d", syn_text("lun")), ("h", syn_text("10")), ("v", syn_float(5.0))],
            vec![("d", syn_text("mar")), ("h", syn_text("9")), ("v", syn_float(9.0))],
            vec![("d", syn_text("mar")), ("h", syn_text("10")), ("v", syn_float(3.0))],
        ]);
        let mut o1 = heat_opts();
        o1.push(("legend", syn_bool(false)));
        let by_rows = svg_of(&[syn_text("heatmap"), full_rows, opts_v(o1)]);
        let matrix = syn_list(vec![nums(&[1.0, 5.0]), nums(&[9.0, 3.0])]);
        let by_matrix = svg_of(&[
            syn_text("heatmap"),
            matrix,
            opts_v(vec![
                ("x_labels", syn_list(vec![syn_text("9"), syn_text("10")])),
                ("y_labels", syn_list(vec![syn_text("lun"), syn_text("mar")])),
                ("legend", syn_bool(false)),
            ]),
        ]);
        assert_eq!(by_rows, by_matrix, "tidy y matriz con los mismos datos → mismo SVG");
    }

    #[test]
    fn heatmap_errors_are_clear() {
        // duplicada
        let dup = rows_v(vec![
            vec![("d", syn_text("lun")), ("h", syn_text("9")), ("v", syn_float(1.0))],
            vec![("d", syn_text("lun")), ("h", syn_text("9")), ("v", syn_float(2.0))],
        ]);
        let e = err_of(&[syn_text("heatmap"), dup, opts_v(heat_opts())]);
        assert!(e.contains("duplicate") && e.contains("row 2"), "{}", e);
        // matriz irregular
        let ragged = syn_list(vec![nums(&[1.0, 2.0]), nums(&[3.0])]);
        let e = err_of(&[syn_text("heatmap"), ragged]);
        assert!(e.contains("ragged") && e.contains("row 2"), "{}", e);
        // labels con largo equivocado
        let e = err_of(&[
            syn_text("heatmap"),
            syn_list(vec![nums(&[1.0, 2.0])]),
            opts_v(vec![("x_labels", syn_list(vec![syn_text("solo")]))]),
        ]);
        assert!(e.contains("x_labels") && e.contains("2 column(s)"), "{}", e);
        // center sin diverging explícito
        let e = err_of(&[
            syn_text("heatmap"),
            syn_list(vec![nums(&[1.0, 2.0])]),
            opts_v(vec![("center", syn_float(1.5))]),
        ]);
        assert!(e.contains("\"center\"") && e.contains("diverging"), "{}", e);
        // scale desconocida
        let e = err_of(&[
            syn_text("heatmap"),
            syn_list(vec![nums(&[1.0, 2.0])]),
            opts_v(vec![("scale", syn_text("rainbow"))]),
        ]);
        assert!(e.contains("auto") && e.contains("sequential") && e.contains("diverging"), "{}", e);
    }

    #[test]
    fn heatmap_scale_auto_rules() {
        // Todos positivos → secuencial (stops azules).
        let pos = svg_of(&[
            syn_text("heatmap"),
            syn_list(vec![nums(&[1.0, 9.0])]),
            opts_v(vec![("legend", syn_bool(false))]),
        ]);
        assert!(pos.contains("#f1f6fd") && pos.contains("#123c6b"), "{}", pos);
        // Cruzan el cero → divergente centrada en 0 (extremos naranja/azul).
        let div = svg_of(&[
            syn_text("heatmap"),
            syn_list(vec![nums(&[-4.0, 4.0])]),
            opts_v(vec![("legend", syn_bool(false))]),
        ]);
        assert!(div.contains("#b34a12") && div.contains("#123c6b"), "{}", div);
        // Rango 0 → stop medio, sin división por cero.
        let flat = svg_of(&[
            syn_text("heatmap"),
            syn_list(vec![nums(&[3.0, 3.0])]),
            opts_v(vec![("legend", syn_bool(false))]),
        ]);
        assert!(flat.contains("#2a78d6"), "stop medio secuencial:\n{}", flat);
        // Stops custom del usuario reemplazan (G3/G11).
        let custom = svg_of(&[
            syn_text("heatmap"),
            syn_list(vec![nums(&[1.0, 9.0])]),
            opts_v(vec![
                ("colors", syn_list(vec![syn_text("#000000"), syn_text("#ffffff")])),
                ("legend", syn_bool(false)),
            ]),
        ]);
        assert!(custom.contains("#000000") && custom.contains("#ffffff"), "{}", custom);
        assert!(!custom.contains("#f1f6fd"), "los stops default fueron reemplazados:\n{}", custom);
        // Un solo stop → error (una escala necesita 2).
        let e = err_of(&[
            syn_text("heatmap"),
            syn_list(vec![nums(&[1.0, 9.0])]),
            opts_v(vec![("colors", syn_list(vec![syn_text("#000000")]))]),
        ]);
        assert!(e.contains("2 gradient stops"), "{}", e);
    }

    #[test]
    fn heatmap_legend_gradient_toggles() {
        let with = svg_of(&[syn_text("heatmap"), syn_list(vec![nums(&[1.0, 9.0])])]);
        let without = svg_of(&[
            syn_text("heatmap"),
            syn_list(vec![nums(&[1.0, 9.0])]),
            opts_v(vec![("legend", syn_bool(false))]),
        ]);
        assert!(
            with.matches("<rect").count() > without.matches("<rect").count(),
            "la leyenda agrega la barra de gradiente:\ncon: {}\nsin: {}",
            with,
            without
        );
    }

    #[test]
    fn heatmap_100x100_and_extreme_values() {
        // 10k celdas: renderiza sin OOM y determinista.
        let matrix = syn_list(
            (0..100)
                .map(|i| nums(&(0..100).map(|j| ((i * j) % 97) as f64).collect::<Vec<_>>()))
                .collect(),
        );
        let args = vec![syn_text("heatmap"), matrix, opts_v(vec![("legend", syn_bool(false))])];
        let svg = svg_of(&args);
        assert_eq!(svg.matches("<rect").count(), 10_000, "una celda por valor");
        assert_eq!(svg, svg_of(&args), "determinista (G7)");
        // Números enormes/minúsculos en la escala: colores hex válidos, sin NaN.
        let extreme = svg_of(&[
            syn_text("heatmap"),
            syn_list(vec![nums(&[1e-18, 1e18])]),
            opts_v(vec![("legend", syn_bool(false))]),
        ]);
        assert!(!extreme.contains("NaN"), "{}", extreme);
        assert!(extreme.contains("#123c6b"), "max al último stop:\n{}", extreme);
    }

    // =====================================================
    // Batch 10 — histogram (§3.3)
    // =====================================================

    #[test]
    fn histogram_shares_binning_with_the_builtin() {
        let data = nums(&[1.0, 2.0, 2.0, 3.0, 3.0, 3.0, 9.0]);
        let with_bins = svg_of(&[
            syn_text("histogram"),
            data.clone(),
            opts_v(vec![("bins", syn_int(4))]),
        ]);
        // El mapa de histogram() directo → MISMO SVG (comparten binning — guardia).
        let map = ok(synsema_core::math::histogram(&[data, syn_int(4)]));
        let from_map = svg_of(&[syn_text("histogram"), map]);
        assert_eq!(with_bins, from_map);
        assert_eq!(with_bins.matches("<rect").count(), 4, "un rect por bin:\n{}", with_bins);
    }

    #[test]
    fn histogram_bars_are_contiguous() {
        let svg = svg_of(&[
            syn_text("histogram"),
            nums(&[0.0, 1.0, 2.0, 3.0]),
            opts_v(vec![("bins", syn_int(2))]),
        ]);
        // Dos rects: el fin del primero == el inicio del segundo (sin gap).
        let rects: Vec<(f64, f64)> = svg
            .match_indices("<rect")
            .map(|(i, _)| {
                let seg = &svg[i..];
                let attr = |k: &str| {
                    seg.split(&format!("{}=\"", k)).nth(1).unwrap().split('"').next().unwrap()
                        .parse::<f64>().unwrap()
                };
                (attr("x"), attr("width"))
            })
            .collect();
        assert_eq!(rects.len(), 2);
        assert!(
            (rects[0].0 + rects[0].1 - rects[1].0).abs() < 0.02,
            "barras contiguas: {:?}",
            rects
        );
    }

    #[test]
    fn histogram_map_form_validation() {
        let mk = |counts: Vec<SynValue>, edges: Vec<SynValue>| {
            let mut m = IndexMap::new();
            m.insert("counts".to_string(), syn_list(counts));
            m.insert("edges".to_string(), syn_list(edges));
            syn_map(m)
        };
        // length(edges) != length(counts) + 1 → error claro (§7.2).
        let bad = mk(vec![syn_int(1), syn_int(2)], vec![syn_float(0.0), syn_float(1.0)]);
        let e = err_of(&[syn_text("histogram"), bad]);
        assert!(e.contains("length(edges)") && e.contains("length(counts) + 1"), "{}", e);
        // edges no crecientes
        let bad = mk(vec![syn_int(1)], vec![syn_float(2.0), syn_float(1.0)]);
        let e = err_of(&[syn_text("histogram"), bad]);
        assert!(e.contains("strictly increasing"), "{}", e);
        // bins sobre el mapa → error
        let good = mk(vec![syn_int(1)], vec![syn_float(0.0), syn_float(1.0)]);
        let e = err_of(&[syn_text("histogram"), good, opts_v(vec![("bins", syn_int(3))])]);
        assert!(e.contains("\"bins\""), "{}", e);
    }

    // =====================================================
    // Batch 10 — boxplot (§3.4)
    // =====================================================

    #[test]
    fn boxplot_matches_the_stat_builtins() {
        // Caso calculado a mano: [1,2,3,4,5,100] con interpolación lineal →
        // q1 = 2.25, mediana = 3.5, q3 = 4.75; IQR = 2.5; fence sup = 8.5 →
        // bigote en 5, outlier 100.
        let args = vec![syn_text("boxplot"), nums(&[1.0, 2.0, 3.0, 4.0, 5.0, 100.0])];
        let node = ok(chart_node(&args));
        let groups = match node_field_of(&node, "groups") {
            SynValue::List(l) => l.borrow().clone(),
            other => panic!("groups no es lista: {}", other.type_name()),
        };
        let g = match &groups[0] {
            SynValue::Map(m) => m.borrow().clone(),
            _ => panic!("grupo no es mapa"),
        };
        let num = |k: &str| match g.get(k) {
            Some(SynValue::Number(n)) => n.to_f64(),
            _ => panic!("{} no es número", k),
        };
        // Los mismos números que devuelven los builtins (comparten código).
        let expect = |p: f64| match synsema_core::math::percentile(&[
            nums(&[1.0, 2.0, 3.0, 4.0, 5.0, 100.0]),
            syn_float(p),
        ]) {
            Ok(SynValue::Number(n)) => n.to_f64(),
            _ => panic!("percentile falló"),
        };
        assert_eq!(num("q1"), expect(25.0));
        assert_eq!(num("median"), expect(50.0));
        assert_eq!(num("q3"), expect(75.0));
        assert_eq!(num("q1"), 2.25);
        assert_eq!(num("median"), 3.5);
        assert_eq!(num("q3"), 4.75);
        assert_eq!(num("min"), 1.0);
        assert_eq!(num("max"), 5.0, "el bigote termina en el último dato ≤ fence");
        match g.get("outliers") {
            Some(SynValue::List(l)) => assert_eq!(l.borrow().len(), 1),
            _ => panic!("outliers no es lista"),
        }
        // Y el SVG dibuja el outlier como marker.
        let svg = svg_of(&args);
        assert_eq!(svg.matches("<circle").count(), 1, "{}", svg);
        assert_eq!(svg.matches("<rect").count(), 1, "una caja:\n{}", svg);
    }

    #[test]
    fn boxplot_errors_and_edge_cases() {
        // Grupo con 1 dato → error (G5).
        let mut m = IndexMap::new();
        m.insert("solo".to_string(), nums(&[7.0]));
        let e = err_of(&[syn_text("boxplot"), syn_map(m)]);
        assert!(e.contains("\"solo\"") && e.contains("at least 2"), "{}", e);
        // NaN → error (espeja los builtins).
        let e = err_of(&[syn_text("boxplot"), nums(&[1.0, f64::NAN])]);
        assert!(e.contains("NaN"), "{}", e);
        // Todos iguales: IQR 0 → caja plana, sin división por cero ni NaN.
        let svg = svg_of(&[syn_text("boxplot"), nums(&[4.0, 4.0, 4.0])]);
        assert!(!svg.contains("NaN"), "{}", svg);
        assert!(svg.contains("<rect"), "{}", svg);
        // Las 3 formas de data.
        let by_map = {
            let mut m = IndexMap::new();
            m.insert("web".to_string(), nums(&[1.0, 2.0, 3.0]));
            svg_of(&[syn_text("boxplot"), syn_map(m)])
        };
        let by_rows = svg_of(&[
            syn_text("boxplot"),
            rows_v(vec![
                vec![("g", syn_text("web")), ("v", syn_float(1.0))],
                vec![("g", syn_text("web")), ("v", syn_float(2.0))],
                vec![("g", syn_text("web")), ("v", syn_float(3.0))],
            ]),
            opts_v(vec![("x", syn_text("g")), ("y", syn_text("v"))]),
        ]);
        assert_eq!(by_map, by_rows, "mapa y rows con los mismos datos → mismo SVG");
    }

    // =====================================================
    // Batch 10 — donut (§3.5)
    // =====================================================

    #[test]
    fn donut_is_pie_with_a_hole() {
        let data = map1(&[("a", 4.0), ("b", 2.0), ("c", 1.0)]);
        let donut = svg_of(&[syn_text("donut"), data.clone()]);
        assert_eq!(donut.matches("<path").count(), 3, "un sector anular por slice:\n{}", donut);
        // Mismos ángulos que el pie: los puntos de arco EXTERNO del donut aparecen
        // también en el path del pie (mismo radio externo, mismos cortes).
        let pie = svg_of(&[syn_text("pie"), data]);
        for seg in donut.split("A ").skip(1).take(1) {
            let arc_start = seg.split(' ').take(2).collect::<Vec<_>>().join(" ");
            assert!(pie.contains(&arc_start), "radio externo compartido: {} en\n{}", arc_start, pie);
        }
        // Slice único (100%) → anillo (círculo con stroke).
        let single = svg_of(&[syn_text("donut"), map1(&[("todo", 5.0)])]);
        assert!(single.contains("fill=\"none\""), "anillo completo:\n{}", single);
        // Misma validación que pie: negativo → error, >8 slices → error.
        let e = err_of(&[syn_text("donut"), map1(&[("a", -1.0), ("b", 1.0)])]);
        assert!(e.contains("non-negative"), "{}", e);
    }

    // =====================================================
    // Batch 10 — waterfall (§3.6)
    // =====================================================

    fn wf_data() -> SynValue {
        map1(&[("ventas", 100.0), ("costos", -40.0), ("gastos", -25.0)])
    }

    #[test]
    fn waterfall_running_totals_and_colors() {
        let args = vec![
            syn_text("waterfall"),
            wf_data(),
            opts_v(vec![("total", syn_bool(true))]),
        ];
        let node = ok(chart_node(&args));
        let steps = match node_field_of(&node, "steps") {
            SynValue::List(l) => l.borrow().clone(),
            other => panic!("steps no es lista: {}", other.type_name()),
        };
        let running = |i: usize| match &steps[i] {
            SynValue::Map(m) => match m.borrow().get("running") {
                Some(SynValue::Number(n)) => n.to_f64(),
                _ => panic!("running no es número"),
            },
            _ => panic!("paso no es mapa"),
        };
        // running del paso N == suma de deltas 1..N (§7.2).
        assert_eq!(running(0), 100.0);
        assert_eq!(running(1), 60.0);
        assert_eq!(running(2), 35.0);
        match node_field_of(&node, "total") {
            SynValue::Number(n) => assert_eq!(n.to_f64(), 35.0),
            other => panic!("total no es número: {}", other.type_name()),
        }
        let svg = svg_of(&args);
        assert_eq!(svg.matches("<rect").count(), 4, "3 pasos + total:\n{}", svg);
        // Colores semánticos CVD-safe por default (decisión #6).
        assert!(svg.contains("#2a78d6") && svg.contains("#eb6834") && svg.contains("#52514e"));
        assert!(svg.contains(">Total<"), "label del total:\n{}", svg);
        // Sin total: 3 rects y sin label Total.
        let plain = svg_of(&[syn_text("waterfall"), wf_data()]);
        assert_eq!(plain.matches("<rect").count(), 3);
        assert!(!plain.contains(">Total<"));
    }

    #[test]
    fn waterfall_overrides_and_edge_cases() {
        // Override [up, down, total] (quien quiera verde/rojo, puede — G3).
        let svg = svg_of(&[
            syn_text("waterfall"),
            wf_data(),
            opts_v(vec![(
                "colors",
                syn_list(vec![syn_text("#00aa00"), syn_text("#aa0000"), syn_text("#333333")]),
            )]),
        ]);
        assert!(svg.contains("#00aa00") && svg.contains("#aa0000"), "{}", svg);
        assert!(!svg.contains("#2a78d6"), "{}", svg);
        // Cantidad equivocada de colores → error claro.
        let e = err_of(&[
            syn_text("waterfall"),
            wf_data(),
            opts_v(vec![("colors", syn_list(vec![syn_text("#00aa00")]))]),
        ]);
        assert!(e.contains("[up, down, total]") && e.contains("exactly 3"), "{}", e);
        // Delta 0 → barra de altura 0 con label visible (dato real, no error).
        let svg = svg_of(&[syn_text("waterfall"), map1(&[("sin cambio", 0.0)])]);
        assert!(svg.contains("height=\"0\""), "{}", svg);
        assert!(svg.contains(">sin cambio<"), "{}", svg);
        // El acumulado puede cruzar 0 varias veces (§7.5).
        let svg = svg_of(&[
            syn_text("waterfall"),
            map1(&[("a", 5.0), ("b", -8.0), ("c", 6.0), ("d", -9.0)]),
        ]);
        assert_eq!(svg.matches("<rect").count(), 4, "{}", svg);
        assert!(!svg.contains("NaN"), "{}", svg);
        // total con texto custom.
        let svg = svg_of(&[
            syn_text("waterfall"),
            wf_data(),
            opts_v(vec![("total", syn_text("Resultado"))]),
        ]);
        assert!(svg.contains(">Resultado<"), "{}", svg);
    }

    // =====================================================
    // Batch 10 — XSS / secret / unicode en kinds nuevos (G4/G8)
    // =====================================================

    #[test]
    fn xss_escaped_in_new_kinds() {
        let hostile = "<script>alert(1)</script>";
        // heatmap: celda con label hostil; boxplot: grupo hostil; waterfall: paso.
        let heat = rows_v(vec![
            vec![("x", syn_text(hostile)), ("y", syn_text("a")), ("v", syn_float(1.0))],
        ]);
        let svg = svg_of(&[syn_text("heatmap"), heat, opts_v(heat_opts_xyv())]);
        assert!(!svg.contains("<script>"), "{}", svg);
        assert!(svg.contains("&lt;script&gt;"), "{}", svg);
        let mut m = IndexMap::new();
        m.insert(hostile.to_string(), nums(&[1.0, 2.0]));
        let args = vec![syn_text("boxplot"), syn_map(m)];
        let svg = svg_of(&args);
        assert!(!svg.contains("<script>"), "{}", svg);
        // Y en el MD del nodo (la matriz/tabla también escapa — G4).
        let node = ok(chart_node(&args));
        let md = render_chart_md(&node);
        assert!(!md.contains("<script>"), "{}", md);
        assert!(md.contains("&lt;script&gt;"), "{}", md);
        let svg = svg_of(&[syn_text("waterfall"), map1(&[(hostile, 5.0)])]);
        assert!(!svg.contains("<script>"), "{}", svg);
    }

    fn heat_opts_xyv() -> Vec<(&'static str, SynValue)> {
        vec![("x", syn_text("x")), ("y", syn_text("y")), ("value", syn_text("v"))]
    }

    #[test]
    fn secret_redacted_in_new_kinds() {
        let s = || synsema_core::types::syn_secret("API_KEY", "hunter2");
        // Como label → [redacted]; como valor → error de tipo claro (G8).
        let rows = rows_v(vec![
            vec![("x", s()), ("y", syn_text("a")), ("v", syn_float(1.0))],
        ]);
        let svg = svg_of(&[syn_text("heatmap"), rows, opts_v(heat_opts_xyv())]);
        assert!(!svg.contains("hunter2"), "{}", svg);
        assert!(svg.contains("[redacted]"), "{}", svg);
        let rows = rows_v(vec![
            vec![("x", syn_text("a")), ("y", syn_text("b")), ("v", s())],
        ]);
        let e = err_of(&[syn_text("heatmap"), rows, opts_v(heat_opts_xyv())]);
        assert!(e.contains("secret") && !e.contains("hunter2"), "{}", e);
        let mut m = IndexMap::new();
        m.insert("g".to_string(), syn_list(vec![syn_float(1.0), s()]));
        let e = err_of(&[syn_text("boxplot"), syn_map(m)]);
        assert!(e.contains("secret") && !e.contains("hunter2"), "{}", e);
        let mut m = IndexMap::new();
        m.insert("delta".to_string(), s());
        let e = err_of(&[syn_text("waterfall"), syn_map(m)]);
        assert!(e.contains("secret") && !e.contains("hunter2"), "{}", e);
    }

    #[test]
    fn unicode_and_emoji_labels_render() {
        let svg = svg_of(&[syn_text("waterfall"), map1(&[("café ☕", 3.0), ("日本語", -1.0)])]);
        assert!(svg.contains("café ☕") && svg.contains("日本語"), "{}", svg);
        let mut m = IndexMap::new();
        m.insert("grupo 🚀".to_string(), nums(&[1.0, 2.0]));
        let svg = svg_of(&[syn_text("boxplot"), syn_map(m)]);
        assert!(svg.contains("grupo 🚀"), "{}", svg);
    }

    // =====================================================
    // Batch 10 — las 3 salidas comparten la fuente normalizada (§3.7)
    // =====================================================

    #[test]
    fn three_outputs_share_the_normalized_source() {
        let mk = |v: f64| {
            ok(chart_node(&[syn_text("waterfall"), map1(&[("a", 10.0), ("b", v)])]))
        };
        let (n1, n2) = (mk(-4.0), mk(-5.0));
        // Alterar un valor altera las TRES salidas (mismo origen).
        let svg = |n: &SynValue| match node_field_of(n, "svg") {
            SynValue::Text(t) => t.to_string(),
            _ => panic!("svg no es texto"),
        };
        assert_ne!(svg(&n1), svg(&n2));
        assert_ne!(render_chart_md(&n1), render_chart_md(&n2));
        let json_of = |n: &SynValue| format!("{:?}", chart_data_fields(n).iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Vec<_>>());
        assert_ne!(json_of(&n1), json_of(&n2));
        // Y el MD trae el acumulado correcto.
        let md = render_chart_md(&n1);
        assert!(md.contains("| label | delta | running |"), "{}", md);
        assert!(md.contains("| b | -4.0 | 6.0 |"), "{}", md);
    }

    #[test]
    fn kind_specific_opts_are_gated() {
        // Opt conocida pero de otro kind → error dirigido, jamás ignorada (G5).
        let e = err_of(&[syn_text("bar"), map1(&[("a", 1.0)]), opts_v(vec![("bins", syn_int(3))])]);
        assert!(e.contains("\"bins\"") && e.contains("histogram"), "{}", e);
        let e = err_of(&[syn_text("line"), nums(&[1.0]), opts_v(vec![("total", syn_bool(true))])]);
        assert!(e.contains("\"total\"") && e.contains("waterfall"), "{}", e);
        let e = err_of(&[
            syn_text("pie"),
            map1(&[("a", 1.0)]),
            opts_v(vec![("scale", syn_text("auto"))]),
        ]);
        assert!(e.contains("\"scale\"") && e.contains("heatmap"), "{}", e);
        // Opt desconocida → listado completo.
        let e = err_of(&[syn_text("bar"), map1(&[("a", 1.0)]), opts_v(vec![("zoom", syn_bool(true))])]);
        assert!(e.contains("unknown option") && e.contains("theme"), "{}", e);
    }
}

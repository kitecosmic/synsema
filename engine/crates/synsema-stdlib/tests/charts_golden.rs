//! Golden tests byte a byte de `chart_svg` (G1/G7).
//!
//! Cada caso renderiza un chart con datos fijos y compara el SVG completo contra
//! `tests/golden/<nombre>.svg`. Los goldens del Batch 8 (bar/line/pie/scatter) se
//! capturaron ANTES del Batch 10 y no se regeneran: si un cambio altera un byte del
//! output default de un kind existente, esto falla (G1 — cero regresión).
//!
//! Regenerar (sólo para kinds NUEVOS o cambios de spec aprobados):
//!   SYNSEMA_BLESS=1 cargo test -p synsema-stdlib --test charts_golden

use std::path::PathBuf;

use indexmap::IndexMap;
use synsema_core::types::{syn_bool, syn_float, syn_int, syn_list, syn_map, syn_text, SynValue};
use synsema_stdlib::charts::chart_svg;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("golden")
}

fn svg_of(args: &[SynValue]) -> String {
    match chart_svg(args) {
        Ok(SynValue::Text(s)) => s.to_string(),
        Ok(other) => panic!("chart_svg devolvió {}, no texto", other.type_name()),
        Err(_) => panic!("chart_svg falló"),
    }
}

fn check(name: &str, svg: &str) {
    let path = golden_dir().join(format!("{}.svg", name));
    if std::env::var("SYNSEMA_BLESS").is_ok() {
        std::fs::create_dir_all(golden_dir()).unwrap();
        std::fs::write(&path, svg).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("golden {:?} ilegible ({}); ¿falta bless?", path, e));
    assert_eq!(expected, svg, "el SVG de {:?} cambió respecto del golden (G1/G7)", name);
}

fn map_data(pairs: &[(&str, f64)]) -> SynValue {
    let mut m = IndexMap::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), syn_float(*v));
    }
    syn_map(m)
}

fn rows_mes_a_b() -> SynValue {
    let mk = |mes: &str, a: f64, b: f64| {
        let mut m = IndexMap::new();
        m.insert("mes".to_string(), syn_text(mes));
        m.insert("a".to_string(), syn_float(a));
        m.insert("b".to_string(), syn_float(b));
        syn_map(m)
    };
    syn_list(vec![mk("ene", 10.0, 4.0), mk("feb", 25.0, 9.0), mk("mar", 17.0, 12.0)])
}

fn opts(pairs: Vec<(&str, SynValue)>) -> SynValue {
    let mut m = IndexMap::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    syn_map(m)
}

fn xy_multi() -> SynValue {
    opts(vec![
        ("x", syn_text("mes")),
        ("y", syn_list(vec![syn_text("a"), syn_text("b")])),
    ])
}

// ===================== Batch 8 (capturados pre-Batch 10 — NO regenerar) =====================

#[test]
fn golden_bar_map_title() {
    let args = vec![
        syn_text("bar"),
        map_data(&[("ene", 10.0), ("feb", 25.0), ("mar", 5.0)]),
        opts(vec![("title", syn_text("Ventas"))]),
    ];
    check("bar_map_title", &svg_of(&args));
}

#[test]
fn golden_bar_rows_multi() {
    let args = vec![syn_text("bar"), rows_mes_a_b(), xy_multi()];
    check("bar_rows_multi", &svg_of(&args));
}

#[test]
fn golden_bar_negative() {
    let args = vec![syn_text("bar"), syn_list(vec![syn_float(5.0), syn_float(-3.0)])];
    check("bar_negative", &svg_of(&args));
}

#[test]
fn golden_line_numbers() {
    let args = vec![
        syn_text("line"),
        syn_list(vec![syn_float(1.0), syn_float(2.0), syn_float(3.0)]),
    ];
    check("line_numbers", &svg_of(&args));
}

#[test]
fn golden_line_rows_categorical_multi() {
    let args = vec![syn_text("line"), rows_mes_a_b(), xy_multi()];
    check("line_rows_categorical_multi", &svg_of(&args));
}

#[test]
fn golden_pie_map_title() {
    let args = vec![
        syn_text("pie"),
        map_data(&[("a", 4.0), ("b", 2.0), ("c", 1.0)]),
        opts(vec![("title", syn_text("Distribución"))]),
    ];
    check("pie_map_title", &svg_of(&args));
}

#[test]
fn golden_scatter_pairs() {
    let pairs = syn_list(vec![
        syn_list(vec![syn_float(1.0), syn_float(2.0)]),
        syn_list(vec![syn_float(3.0), syn_float(4.0)]),
        syn_list(vec![syn_float(5.0), syn_float(1.5)]),
    ]);
    check("scatter_pairs", &svg_of(&[syn_text("scatter"), pairs]));
}

// ===================== Batch 10 — kinds nuevos + tema dark =====================

#[test]
fn golden_area_stacked() {
    let args = vec![
        syn_text("area"),
        rows_mes_a_b(),
        opts(vec![
            ("x", syn_text("mes")),
            ("y", syn_list(vec![syn_text("a"), syn_text("b")])),
            ("stack", syn_bool(true)),
            ("title", syn_text("Acumulado")),
        ]),
    ];
    check("area_stacked", &svg_of(&args));
}

#[test]
fn golden_bar_stacked() {
    let args = vec![
        syn_text("bar"),
        rows_mes_a_b(),
        opts(vec![
            ("x", syn_text("mes")),
            ("y", syn_list(vec![syn_text("a"), syn_text("b")])),
            ("stack", syn_bool(true)),
        ]),
    ];
    check("bar_stacked", &svg_of(&args));
}

#[test]
fn golden_heatmap_tidy() {
    let mk = |d: &str, h: &str, v: f64| {
        let mut m = IndexMap::new();
        m.insert("d".to_string(), syn_text(d));
        m.insert("h".to_string(), syn_text(h));
        m.insert("v".to_string(), syn_float(v));
        syn_map(m)
    };
    let rows = syn_list(vec![
        mk("lun", "9", 1.0),
        mk("lun", "10", 5.0),
        mk("mar", "9", 9.0),
    ]);
    let args = vec![
        syn_text("heatmap"),
        rows,
        opts(vec![
            ("x", syn_text("h")),
            ("y", syn_text("d")),
            ("value", syn_text("v")),
            ("title", syn_text("Actividad")),
        ]),
    ];
    check("heatmap_tidy", &svg_of(&args));
}

#[test]
fn golden_heatmap_diverging_matrix() {
    let matrix = syn_list(vec![
        syn_list(vec![syn_float(-4.0), syn_float(2.0)]),
        syn_list(vec![syn_float(1.0), syn_float(4.0)]),
    ]);
    check("heatmap_diverging_matrix", &svg_of(&[syn_text("heatmap"), matrix]));
}

#[test]
fn golden_histogram_bins() {
    let data = syn_list(
        [1.0, 2.0, 2.0, 3.0, 3.0, 3.0, 9.0].iter().map(|v| syn_float(*v)).collect(),
    );
    let args = vec![syn_text("histogram"), data, opts(vec![("bins", syn_int(4))])];
    check("histogram_bins", &svg_of(&args));
}

#[test]
fn golden_boxplot_groups() {
    let mut m = IndexMap::new();
    m.insert(
        "web".to_string(),
        syn_list([1.0, 2.0, 3.0, 4.0, 5.0, 100.0].iter().map(|v| syn_float(*v)).collect()),
    );
    m.insert(
        "tel".to_string(),
        syn_list([2.0, 2.0, 3.0, 8.0, 9.0].iter().map(|v| syn_float(*v)).collect()),
    );
    check("boxplot_groups", &svg_of(&[syn_text("boxplot"), syn_map(m)]));
}

#[test]
fn golden_donut_map() {
    let args = vec![
        syn_text("donut"),
        map_data(&[("a", 4.0), ("b", 2.0), ("c", 1.0)]),
        opts(vec![("title", syn_text("Distribución"))]),
    ];
    check("donut_map", &svg_of(&args));
}

#[test]
fn golden_waterfall_total() {
    let args = vec![
        syn_text("waterfall"),
        map_data(&[("ventas", 100.0), ("costos", -40.0), ("gastos", -25.0)]),
        opts(vec![("total", syn_bool(true)), ("title", syn_text("Puente"))]),
    ];
    check("waterfall_total", &svg_of(&args));
}

#[test]
fn golden_bar_dark_theme() {
    let args = vec![
        syn_text("bar"),
        map_data(&[("ene", 10.0), ("feb", 25.0), ("mar", 5.0)]),
        opts(vec![("title", syn_text("Ventas")), ("theme", syn_text("dark"))]),
    ];
    check("bar_dark_theme", &svg_of(&args));
}

#[test]
fn golden_heatmap_dark_theme() {
    let matrix = syn_list(vec![
        syn_list(vec![syn_float(1.0), syn_float(5.0)]),
        syn_list(vec![syn_float(9.0), syn_float(3.0)]),
    ]);
    let args = vec![syn_text("heatmap"), matrix, opts(vec![("theme", syn_text("dark"))])];
    check("heatmap_dark_theme", &svg_of(&args));
}

#[test]
fn golden_bar_full_opts() {
    let args = vec![
        syn_text("bar"),
        map_data(&[("q1", 3.0), ("q2", 8.0)]),
        opts(vec![
            ("title", syn_text("Q")),
            ("width", syn_float(400.0)),
            ("height", syn_float(300.0)),
            ("x_label", syn_text("Trimestre")),
            ("y_label", syn_text("Total")),
            ("background", syn_text("#fcfcfb")),
            ("legend", syn_bool(false)),
        ]),
    ];
    check("bar_full_opts", &svg_of(&args));
}

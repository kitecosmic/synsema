//! Export PNG/PDF (Batch 9): `svg_to_png(svg, opts?)` → bytes y `svg_to_pdf(svg, opts?)`
//! → bytes. Conversores **GENERALES**: aceptan cualquier SVG como texto (el de
//! `chart_svg`, uno a mano, uno bajado por HTTP) — PROHIBIDO acoplarlos a los charts
//! (cero imports de `charts.rs`/`database.rs`, G2).
//!
//! Doctrina (spec batch-9 §0/§2):
//! - **PUROS (sin capability):** CPU sobre valores en memoria. No tocan red, disco ni
//!   reloj — el resolver de `<image href="...">` externo devuelve None a propósito
//!   (jamás filesystem/red desde un builtin puro; los data: URLs SVG sí resuelven).
//!   La salida sólo sale al mundo por builtins ya gateados (`write_file`, serve).
//! - **Determinismo (G5):** fuente sans EMBEBIDA (DejaVu Sans, licencia en NOTICE y en
//!   assets/DejaVuSans-LICENSE.txt) → el texto rasteriza IGUAL en Windows/Linux/macOS y
//!   en Docker `FROM scratch`. PNG sin chunks de tiempo; PDF sin CreationDate variable.
//!   Mismo SVG + mismas opts → mismos bytes (golden tests por hash).
//! - **Anti-DoS con aviso, no nerfeo (G6):** rasterizar es O(ancho×alto) → techo default
//!   de 16 Mpx **sobreescribible** vía `{"max_pixels": n}`; excederlo → error claro que
//!   menciona la opt. Nunca un límite silencioso ni inamovible.
//! - **Errores claros y atrapables (G4/G9):** SVG malformado → error con el detalle del
//!   parser; `secret` como svg → error de tipo (G7, nunca se rasteriza el plaintext);
//!   todo atrapable con `try`/`recover`; en serve un error → respuesta HTTP, no caída.
//!
//! Pitfalls honestos (van a docs): resvg IGNORA scripts/animaciones/algunos filtros (el
//! PNG es el estado estático); font-family desconocida cae a la embebida; glifos no
//! cubiertos (CJK completo, emoji color) → tofu. Fuentes del sistema/custom = futuro.

use std::rc::Rc;
use std::sync::{Arc, OnceLock};

use indexmap::IndexMap;
use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::py_float_str;
use synsema_core::types::{syn_bytes, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

/// Techo default anti-DoS: 16 Mpx (≈ 4096×4096). Sobreescribible vía `max_pixels` (G6).
const DEFAULT_MAX_PIXELS: u64 = 16_777_216;

// =========================================================
// Fuente embebida (una sola carga, compartida entre llamadas)
// =========================================================

/// DejaVu Sans embebida en el binario (~740 KB) — decisión #4 del spec: mismo
/// rasterizado en toda plataforma, binario autocontenido. Licencia: NOTICE.
static EMBEDDED_FONT: &[u8] = include_bytes!("../assets/DejaVuSans.ttf");

static FONTDB: OnceLock<Arc<fontdb::Database>> = OnceLock::new();

fn embedded_fontdb() -> Arc<fontdb::Database> {
    FONTDB
        .get_or_init(|| {
            let mut db = fontdb::Database::new();
            db.load_font_data(EMBEDDED_FONT.to_vec());
            // Toda familia genérica cae a la embebida: un SVG que pide "serif" o una
            // familia inexistente rasteriza igual en las tres plataformas (G5).
            db.set_sans_serif_family("DejaVu Sans");
            db.set_serif_family("DejaVu Sans");
            db.set_monospace_family("DejaVu Sans");
            db.set_cursive_family("DejaVu Sans");
            db.set_fantasy_family("DejaVu Sans");
            Arc::new(db)
        })
        .clone()
}

// =========================================================
// Parseo del SVG (compartido por PNG y PDF)
// =========================================================

/// El texto SVG del 1er argumento. `secret` → error específico (G7).
fn svg_arg<'a>(args: &'a [SynValue], name: &str) -> Result<&'a str, Control> {
    match args.first() {
        Some(SynValue::Text(s)) => Ok(s),
        Some(SynValue::Secret(_)) => Err(err(format!(
            "{} expects SVG text, got a secret (secrets are never rasterized)",
            name
        ))),
        Some(other) => Err(err(format!(
            "{} expects SVG text as the first argument, got {}",
            name,
            other.type_name()
        ))),
        None => Err(err(format!("{} expects SVG text as the first argument", name))),
    }
}

/// Texto SVG → árbol usvg con la fuente embebida y SIN I/O: el resolver de hrefs
/// externos (http://, rutas locales) devuelve None a propósito — un builtin puro no
/// sale a la red ni toca disco (G8); sólo los data: URLs embebidos resuelven.
fn parse_tree(svg: &str, name: &str) -> Result<usvg::Tree, Control> {
    let opt = usvg::Options {
        fontdb: embedded_fontdb(),
        font_family: "DejaVu Sans".to_string(),
        image_href_resolver: usvg::ImageHrefResolver {
            resolve_data: usvg::ImageHrefResolver::default_data_resolver(),
            resolve_string: Box::new(|_href, _opts| None),
        },
        ..Default::default()
    };
    usvg::Tree::from_str(svg, &opt)
        .map_err(|e| err(format!("{}: invalid SVG: {}", name, e)))
}

/// Rasteriza un SVG a un PNG de exactamente `w`×`h` píxeles (escala por eje: para
/// íconos se pasa cuadrado). Helper **Rust-side** para `synsema init --pwa` y
/// `synsema build --icon`: la misma fuente embebida y el mismo resolver sin I/O que
/// `svg_to_png`, sin pasar por `SynValue`. Puro: no toca red, disco ni reloj.
pub fn render_svg_png(svg: &str, w: u32, h: u32) -> Result<Vec<u8>, String> {
    if w == 0 || h == 0 {
        return Err("render_svg_png: width and height must be > 0".to_string());
    }
    let tree = parse_tree(svg, "render_svg_png").map_err(|c| match c {
        Control::Error(e) => e.to_string(),
        _ => "render_svg_png: invalid SVG".to_string(),
    })?;
    let (w0, h0) = (f64::from(tree.size().width()), f64::from(tree.size().height()));
    let mut pixmap = tiny_skia::Pixmap::new(w, h)
        .ok_or_else(|| format!("render_svg_png: cannot allocate a {}x{} pixmap", w, h))?;
    let transform =
        tiny_skia::Transform::from_scale((f64::from(w) / w0) as f32, (f64::from(h) / h0) as f32);
    resvg::render(&tree, transform, &mut pixmap.as_mut());
    pixmap.encode_png().map_err(|e| format!("render_svg_png: PNG encoding failed: {}", e))
}

/// Decodifica un PNG y lo re-escala a `side`×`side` (bicúbico, encajado sin deformar y
/// centrado sobre fondo transparente). Helper Rust-side para `synsema build --icon x.png`.
/// Un PNG que ya mide `side`×`side` vuelve tal cual (sin recodificar). Puro.
pub fn resize_png(png: &[u8], side: u32) -> Result<Vec<u8>, String> {
    if side == 0 {
        return Err("resize_png: side must be > 0".to_string());
    }
    let src = tiny_skia::Pixmap::decode_png(png).map_err(|e| format!("resize_png: invalid PNG: {}", e))?;
    if src.width() == side && src.height() == side {
        return Ok(png.to_vec());
    }
    let mut dst = tiny_skia::Pixmap::new(side, side)
        .ok_or_else(|| format!("resize_png: cannot allocate a {}x{} pixmap", side, side))?;
    let s = (side as f32 / src.width() as f32).min(side as f32 / src.height() as f32);
    let dx = (side as f32 - src.width() as f32 * s) / 2.0;
    let dy = (side as f32 - src.height() as f32 * s) / 2.0;
    let paint = tiny_skia::PixmapPaint { quality: tiny_skia::FilterQuality::Bicubic, ..Default::default() };
    dst.draw_pixmap(0, 0, src.as_ref(), &paint, tiny_skia::Transform::from_row(s, 0.0, 0.0, s, dx, dy), None);
    dst.encode_png().map_err(|e| format!("resize_png: PNG encoding failed: {}", e))
}

// =========================================================
// Lectura de opts
// =========================================================

fn opts_of(
    args: &[SynValue],
    name: &str,
    valid: &[&str],
) -> Result<IndexMap<String, SynValue>, Control> {
    match args.get(1) {
        None | Some(SynValue::Nothing) => Ok(IndexMap::new()),
        Some(SynValue::Map(m)) => {
            let m = m.borrow();
            for k in m.keys() {
                if !valid.contains(&k.as_str()) {
                    return Err(err(format!(
                        "{}: unknown option {:?}; valid options are: {}",
                        name,
                        k,
                        valid.join(", ")
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

/// Número positivo finito de una opt (dimensiones, scale, max_pixels).
fn opt_pos_number(
    opts: &IndexMap<String, SynValue>,
    key: &str,
    name: &str,
) -> Result<Option<f64>, Control> {
    match opts.get(key) {
        None => Ok(None),
        Some(SynValue::Number(n)) => {
            let v = n.to_f64();
            if !v.is_finite() || v <= 0.0 {
                return Err(err(format!(
                    "{}: option {:?} must be a positive number, got {}",
                    name,
                    key,
                    py_float_str(v)
                )));
            }
            Ok(Some(v))
        }
        Some(other) => Err(err(format!(
            "{}: option {:?} must be a number, got {}",
            name,
            key,
            other.type_name()
        ))),
    }
}

/// Color hex `#rgb` / `#rrggbb` / `#rrggbbaa` → RGBA. Estricto (G4).
fn parse_hex_color(s: &str, name: &str) -> Result<(u8, u8, u8, u8), Control> {
    let bad = || {
        err(format!(
            "{}: option \"background\" must be a hex color like \"#fcfcfb\", got {:?}",
            name, s
        ))
    };
    let hex = s.strip_prefix('#').ok_or_else(bad)?;
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    let h = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| bad());
    match hex.len() {
        3 => {
            let d = |i: usize| {
                u8::from_str_radix(&hex[i..i + 1], 16).map(|v| v * 17).map_err(|_| bad())
            };
            Ok((d(0)?, d(1)?, d(2)?, 255))
        }
        6 => Ok((h(0)?, h(2)?, h(4)?, 255)),
        8 => Ok((h(0)?, h(2)?, h(4)?, h(6)?)),
        _ => Err(bad()),
    }
}

// =========================================================
// svg_to_png(svg, opts?) → bytes
// =========================================================

pub fn svg_to_png(args: &[SynValue]) -> Result<SynValue, Control> {
    const NAME: &str = "svg_to_png";
    if args.is_empty() || args.len() > 2 {
        return Err(err(format!(
            "{} expects (svg, options?) — 1 or 2 argument(s), got {}",
            NAME,
            args.len()
        )));
    }
    let svg = svg_arg(args, NAME)?;
    let opts = opts_of(args, NAME, &["width", "height", "scale", "background", "max_pixels"])?;
    let want_w = opt_pos_number(&opts, "width", NAME)?;
    let want_h = opt_pos_number(&opts, "height", NAME)?;
    let scale = opt_pos_number(&opts, "scale", NAME)?;
    if scale.is_some() && (want_w.is_some() || want_h.is_some()) {
        // Conflicto explícito (spec §3.1): dos maneras de fijar el tamaño a la vez.
        return Err(err(format!(
            "{}: option \"scale\" conflicts with \"width\"/\"height\"; pass one or the other",
            NAME
        )));
    }
    let max_pixels = match opt_pos_number(&opts, "max_pixels", NAME)? {
        Some(v) => v as u64,
        None => DEFAULT_MAX_PIXELS,
    };
    let background = match opts.get("background") {
        None | Some(SynValue::Nothing) => None,
        Some(SynValue::Text(s)) => Some(parse_hex_color(s, NAME)?),
        Some(other) => {
            return Err(err(format!(
                "{}: option \"background\" must be text, got {}",
                NAME,
                other.type_name()
            )))
        }
    };

    let tree = parse_tree(svg, NAME)?;
    let (w0, h0) = (f64::from(tree.size().width()), f64::from(tree.size().height()));
    // usvg garantiza tamaño > 0 (un SVG sin dimensiones deducibles ya falló al parsear).
    let (out_w, out_h) = match (want_w, want_h, scale) {
        (Some(w), Some(h), _) => (w, h),
        (Some(w), None, _) => (w, w * h0 / w0), // una sola dimensión → mantiene aspecto
        (None, Some(h), _) => (h * w0 / h0, h),
        (None, None, Some(s)) => (w0 * s, h0 * s),
        (None, None, None) => (w0, h0),
    };
    let px_w = out_w.round().max(1.0) as u64;
    let px_h = out_h.round().max(1.0) as u64;
    if px_w.saturating_mul(px_h) > max_pixels {
        return Err(err(format!(
            "{}: the output would be {}x{} = {} pixels, above the {} pixel limit; render smaller or raise it with {{\"max_pixels\": n}}",
            NAME,
            px_w,
            px_h,
            px_w.saturating_mul(px_h),
            max_pixels
        )));
    }
    let mut pixmap = tiny_skia::Pixmap::new(px_w as u32, px_h as u32).ok_or_else(|| {
        err(format!("{}: cannot allocate a {}x{} pixmap", NAME, px_w, px_h))
    })?;
    if let Some((r, g, b, a)) = background {
        pixmap.fill(tiny_skia::Color::from_rgba8(r, g, b, a));
    }
    let transform =
        tiny_skia::Transform::from_scale((px_w as f64 / w0) as f32, (px_h as f64 / h0) as f32);
    resvg::render(&tree, transform, &mut pixmap.as_mut());
    let png = pixmap
        .encode_png()
        .map_err(|e| err(format!("{}: PNG encoding failed: {}", NAME, e)))?;
    Ok(syn_bytes(png))
}

// =========================================================
// svg_to_pdf(svg, opts?) → bytes
// =========================================================

pub fn svg_to_pdf(args: &[SynValue]) -> Result<SynValue, Control> {
    const NAME: &str = "svg_to_pdf";
    if args.is_empty() || args.len() > 2 {
        return Err(err(format!(
            "{} expects (svg, options?) — 1 or 2 argument(s), got {}",
            NAME,
            args.len()
        )));
    }
    let svg = svg_arg(args, NAME)?;
    let opts = opts_of(args, NAME, &["width", "height"])?;
    let want_w = opt_pos_number(&opts, "width", NAME)?;
    let want_h = opt_pos_number(&opts, "height", NAME)?;

    let tree = parse_tree(svg, NAME)?;
    let (w0, h0) = (f64::from(tree.size().width()), f64::from(tree.size().height()));

    // Override de tamaño de página (en puntos) vía dpi UNIFORME (la conversión es
    // vectorial: escalar no pierde nitidez). Escala no-uniforme no existe en el
    // conversor → si piden ambas dimensiones deben respetar el aspecto del SVG.
    let mut page = svg2pdf::PageOptions::default(); // dpi 72 → 1 px = 1 pt
    match (want_w, want_h) {
        (None, None) => {}
        (Some(w), None) => page.dpi = (72.0 * w0 / w) as f32,
        (None, Some(h)) => page.dpi = (72.0 * h0 / h) as f32,
        (Some(w), Some(h)) => {
            let ratio_svg = w0 / h0;
            let ratio_req = w / h;
            if (ratio_svg - ratio_req).abs() > 0.01 * ratio_svg {
                return Err(err(format!(
                    "{}: width/height {}x{} do not match the SVG aspect ratio ({}x{}); pass only one of them to scale proportionally",
                    NAME,
                    py_float_str(w),
                    py_float_str(h),
                    py_float_str(w0),
                    py_float_str(h0)
                )));
            }
            page.dpi = (72.0 * w0 / w) as f32;
        }
    }
    let conv = svg2pdf::ConversionOptions::default();
    let pdf = svg2pdf::to_pdf(&tree, conv, page)
        .map_err(|e| err(format!("{}: PDF conversion failed: {}", NAME, e)))?;
    Ok(syn_bytes(pdf))
}

/// Registro de los builtins de export. Se llama desde `register_serve_builtins`
/// (server.rs), que el runtime cablea en TODOS los modos (run/test/conform/serve) —
/// mismo patrón que charts. PUROS → funcionan también dentro de `sandbox` (G8).
pub fn register_raster_builtins(interp: &Interpreter) {
    interp.register_builtin("svg_to_png", -1, Rc::new(|_i, a, _l| svg_to_png(a)));
    interp.register_builtin("svg_to_pdf", -1, Rc::new(|_i, a, _l| svg_to_pdf(a)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use synsema_core::types::{syn_map, syn_secret, syn_text};

    /// `Control` no implementa Debug: desarma el Result a mano.
    fn ok(r: Result<SynValue, Control>) -> Vec<u8> {
        match r {
            Ok(SynValue::Bytes(b)) => b.to_vec(),
            Ok(other) => panic!("expected bytes, got {}", other.type_name()),
            Err(Control::Error(e)) => panic!("error inesperado: {}", e.message),
            Err(_) => panic!("control inesperado"),
        }
    }

    fn msg(r: Result<SynValue, Control>) -> String {
        match r {
            Err(Control::Error(e)) => e.message,
            Ok(v) => panic!("esperaba error, dio {}", v.type_name()),
            Err(_) => panic!("control inesperado"),
        }
    }

    const RED_RECT: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10" fill="#ff0000"/></svg>"##;

    /// Dimensiones del IHDR de un PNG (bytes 16..24, big-endian).
    fn png_dims(png: &[u8]) -> (u32, u32) {
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "magic PNG");
        let w = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
        let h = u32::from_be_bytes([png[20], png[21], png[22], png[23]]);
        (w, h)
    }

    #[test]
    fn png_magic_dims_and_pixel() {
        let png = ok(svg_to_png(&[syn_text(RED_RECT)]));
        assert_eq!(png_dims(&png), (10, 10));
        // Píxel muestreado rojo: decodifica con tiny-skia (RGBA premultiplicado).
        let pixmap = tiny_skia::Pixmap::decode_png(&png).expect("PNG válido");
        let px = pixmap.pixel(5, 5).unwrap();
        assert_eq!((px.red(), px.green(), px.blue(), px.alpha()), (255, 0, 0, 255));
    }

    #[test]
    fn png_deterministic_g5() {
        let a = ok(svg_to_png(&[syn_text(RED_RECT)]));
        let b = ok(svg_to_png(&[syn_text(RED_RECT)]));
        assert_eq!(a, b, "mismo SVG → mismos bytes (G5)");
    }

    #[test]
    fn png_scale_width_background() {
        let mut m = IndexMap::new();
        m.insert("scale".to_string(), synsema_core::types::syn_int(2));
        let png = ok(svg_to_png(&[syn_text(RED_RECT), syn_map(m)]));
        assert_eq!(png_dims(&png), (20, 20));

        // width solo → mantiene aspecto (SVG 10x10 → 40x40).
        let mut m = IndexMap::new();
        m.insert("width".to_string(), synsema_core::types::syn_int(40));
        let png = ok(svg_to_png(&[syn_text(RED_RECT), syn_map(m)]));
        assert_eq!(png_dims(&png), (40, 40));

        // Transparente por default fuera del dibujo; con background, esquina opaca.
        let tiny = r##"<svg xmlns="http://www.w3.org/2000/svg" width="4" height="4"><rect x="2" y="2" width="2" height="2" fill="#00ff00"/></svg>"##;
        let png = ok(svg_to_png(&[syn_text(tiny)]));
        let pm = tiny_skia::Pixmap::decode_png(&png).unwrap();
        assert_eq!(pm.pixel(0, 0).unwrap().alpha(), 0, "default transparente");
        let mut m = IndexMap::new();
        m.insert("background".to_string(), syn_text("#ffffff"));
        let png = ok(svg_to_png(&[syn_text(tiny), syn_map(m)]));
        let pm = tiny_skia::Pixmap::decode_png(&png).unwrap();
        let px = pm.pixel(0, 0).unwrap();
        assert_eq!((px.red(), px.green(), px.blue(), px.alpha()), (255, 255, 255, 255));
    }

    #[test]
    fn png_text_rasterizes_with_embedded_font() {
        let svg = r##"<svg xmlns="http://www.w3.org/2000/svg" width="120" height="40"><text x="8" y="28" font-size="20" fill="#000000">Hola 42</text></svg>"##;
        let png = ok(svg_to_png(&[syn_text(svg)]));
        let pm = tiny_skia::Pixmap::decode_png(&png).unwrap();
        // Glifos reales: algún píxel no-transparente en la zona del texto.
        let mut inked = 0;
        for y in 0..40 {
            for x in 0..120 {
                if pm.pixel(x, y).unwrap().alpha() > 0 {
                    inked += 1;
                }
            }
        }
        assert!(inked > 50, "el texto debería rasterizar glifos, inked={}", inked);
        // Determinista también con texto (la fuente es la embebida, no la del SO).
        assert_eq!(png, ok(svg_to_png(&[syn_text(svg)])));
    }

    #[test]
    fn png_errors_clear() {
        assert!(msg(svg_to_png(&[syn_text("<not-svg")])).contains("invalid SVG"));
        assert!(msg(svg_to_png(&[syn_secret("K", "x")])).contains("secret"));
        // scale + width = conflicto explícito.
        let mut m = IndexMap::new();
        m.insert("scale".to_string(), synsema_core::types::syn_int(2));
        m.insert("width".to_string(), synsema_core::types::syn_int(40));
        assert!(msg(svg_to_png(&[syn_text(RED_RECT), syn_map(m)])).contains("conflicts"));
        // Techo anti-DoS con aviso que menciona la opt (G6)…
        let mut m = IndexMap::new();
        m.insert("width".to_string(), synsema_core::types::syn_int(10_000_000));
        assert!(msg(svg_to_png(&[syn_text(RED_RECT), syn_map(m)])).contains("max_pixels"));
        // …y sobreescribible: el mismo tamaño pasa subiendo el techo (9 Mpx > default no,
        // acá usamos uno chico para no rasterizar de verdad 100 Mpx en el test).
        let mut m = IndexMap::new();
        m.insert("width".to_string(), synsema_core::types::syn_int(200));
        m.insert("max_pixels".to_string(), synsema_core::types::syn_int(100));
        assert!(msg(svg_to_png(&[syn_text(RED_RECT), syn_map(m)])).contains("max_pixels"));
        let mut m = IndexMap::new();
        m.insert("width".to_string(), synsema_core::types::syn_int(200));
        m.insert("max_pixels".to_string(), synsema_core::types::syn_int(100_000));
        ok(svg_to_png(&[syn_text(RED_RECT), syn_map(m)]));
    }

    #[test]
    fn hostile_svg_no_exec_no_io() {
        // <script> se ignora (resvg no ejecuta nada) y no rompe el render.
        let svg = r##"<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><script>alert(1)</script><rect width="8" height="8" fill="#0000ff"/></svg>"##;
        let png = ok(svg_to_png(&[syn_text(svg)]));
        assert_eq!(png_dims(&png), (8, 8));
        // href externo (red) y local (disco): el resolver devuelve None → no I/O, no error.
        let svg = r##"<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><image href="http://example.com/x.png" width="8" height="8"/><image href="C:/Windows/notepad.exe" width="8" height="8"/></svg>"##;
        let png = ok(svg_to_png(&[syn_text(svg)]));
        assert_eq!(png_dims(&png), (8, 8));
        // Entidades XML (billion laughs): usvg/roxmltree no expande → error limpio o
        // parseo sin expansión, jamás OOM. Cualquiera de los dos es aceptable; acá
        // basta con que NO reviente el proceso.
        let svg = r#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><svg xmlns="http://www.w3.org/2000/svg" width="4" height="4"><text>&lol2;</text></svg>"#;
        let _ = svg_to_png(&[syn_text(svg)]);
    }

    #[test]
    fn pdf_magic_page_and_deterministic() {
        let pdf = match svg_to_pdf(&[syn_text(RED_RECT)]) {
            Ok(SynValue::Bytes(b)) => b.to_vec(),
            Ok(other) => panic!("expected bytes, got {}", other.type_name()),
            Err(Control::Error(e)) => panic!("error: {}", e.message),
            Err(_) => panic!("control inesperado"),
        };
        assert_eq!(&pdf[..5], b"%PDF-", "magic PDF");
        let s = String::from_utf8_lossy(&pdf);
        assert!(s.contains("/Type /Page") || s.contains("/Type/Page"), "una página");
        assert!(!s.contains("/CreationDate"), "sin metadata variable (G5)");
        // Determinista byte a byte.
        let pdf2 = ok(svg_to_pdf(&[syn_text(RED_RECT)]));
        assert_eq!(pdf, pdf2);
    }

    #[test]
    fn pdf_size_override_and_aspect_guard() {
        // width solo → escala proporcional (vectorial, sin pérdida).
        let mut m = IndexMap::new();
        m.insert("width".to_string(), synsema_core::types::syn_int(100));
        ok(svg_to_pdf(&[syn_text(RED_RECT), syn_map(m)]));
        // width+height con aspecto distinto al del SVG → error claro.
        let mut m = IndexMap::new();
        m.insert("width".to_string(), synsema_core::types::syn_int(100));
        m.insert("height".to_string(), synsema_core::types::syn_int(300));
        assert!(msg(svg_to_pdf(&[syn_text(RED_RECT), syn_map(m)])).contains("aspect ratio"));
    }

    #[test]
    fn general_converter_handmade_svg_g2() {
        // SVG a mano con gradiente, path y transform — nada de charts (G2).
        let svg = r##"<svg xmlns="http://www.w3.org/2000/svg" width="30" height="30">
<defs><linearGradient id="g"><stop offset="0" stop-color="#ff0000"/><stop offset="1" stop-color="#0000ff"/></linearGradient></defs>
<path d="M 5 5 L 25 5 L 15 25 Z" fill="url(#g)" transform="rotate(15 15 15)"/>
</svg>"##;
        let png = ok(svg_to_png(&[syn_text(svg)]));
        assert_eq!(png_dims(&png), (30, 30));
        let pdf = ok(svg_to_pdf(&[syn_text(svg)]));
        assert_eq!(&pdf[..5], b"%PDF-");
    }
}

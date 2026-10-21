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

use synsema_core::types::{MapObj, SynMap};
use std::rc::Rc;
use std::sync::{Arc, OnceLock};

use synsema_core::interpreter::{Control, Interpreter, RuntimeError};
use synsema_core::number::py_float_str;
use synsema_core::types::{syn_bytes, SynValue};

fn err(msg: impl Into<String>) -> Control {
    Control::Error(RuntimeError::new(msg))
}

/// Techo default anti-DoS: 16 Mpx (≈ 4096×4096). Sobreescribible vía `max_pixels` (G6).
const DEFAULT_MAX_PIXELS: u64 = 16_777_216;

/// v0.6.45 — techo default de caracteres por `<text>`. usvg 0.45 (y su `main`) arma cada texto con un
/// costo que crece con el CUADRADO de su largo: por cada glifo vuelve a contar el texto desde el
/// principio (`code_point_at`). Medido en release: 16 k caracteres 0,3 s, 64 k 2,6 s, 128 k 10 s.
/// Sobreescribible vía `max_text_chars` (G6); el arreglo de fondo es un render propio (faltantes).
const DEFAULT_MAX_TEXT_CHARS: usize = 16_384;

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
    parse_tree_with(svg, name, embedded_fontdb(), false)
}

/// v0.6.20 — la fontdb embebida MÁS las fuentes propias del caller (`opts.fonts`): una base
/// nueva por llamada (clon de la embebida + cada archivo), así el determinismo se conserva
/// (mismo SVG + mismas opts + mismas fuentes → mismos bytes) y el caso sin `fonts` sigue
/// byte a byte igual (los goldens no cambian).
fn fontdb_with(fonts: &[Vec<u8>]) -> Arc<fontdb::Database> {
    if fonts.is_empty() {
        return embedded_fontdb();
    }
    let mut db: fontdb::Database = (*embedded_fontdb()).clone();
    for f in fonts {
        db.load_font_data(f.clone());
    }
    Arc::new(db)
}

/// v0.6.20 — `opts.fonts`: lista de rutas; el `loader` (el host con capabilities) exige
/// `file.read` por cada una y devuelve los bytes. Sin loader (perfil puro) la opción es un
/// error claro, no un silencio.
type FontLoader<'a> = &'a dyn Fn(&str) -> Result<Vec<u8>, Control>;

fn fonts_opt(
    opts: &MapObj,
    name: &str,
    loader: Option<FontLoader<'_>>,
) -> Result<Vec<Vec<u8>>, Control> {
    let list = match opts.get("fonts") {
        None | Some(SynValue::Nothing) => return Ok(Vec::new()),
        Some(SynValue::List(l)) => l.borrow().to_vec(),
        Some(other) => {
            return Err(err(format!(
                "{}: option \"fonts\" must be a list of font file paths, got {}",
                name,
                other.type_name()
            )))
        }
    };
    let Some(load) = loader else {
        return Err(err(format!(
            "{}: option \"fonts\" needs file access, which this profile does not have (the embedded font still works)",
            name
        )));
    };
    // Ronda 4 (revisión, M2): cada fuente suma caras que el render recorre por cada carácter que falta.
    const MAX_FONTS: usize = 16;
    if list.len() > MAX_FONTS {
        return Err(err(format!("{}: option \"fonts\" takes at most {} fonts, got {}", name, MAX_FONTS, list.len())));
    }
    let mut out = Vec::with_capacity(list.len());
    let mut faces = 0usize;
    for item in &list {
        let SynValue::Text(p) = item else {
            return Err(err(format!("{}: every entry of \"fonts\" must be a path (text), got {}", name, item.type_name())));
        };
        let data = load(p)?;
        // v0.6.45 (ronda 4, M4): usvg consulta el cmap de cada fuente por cada carácter (al elegir el
        // respaldo y al dar forma al texto); un cmap armado (miles de subtablas, un formato 13 de
        // millones de grupos) hacía cada consulta lineal y un render tardaba minutos. Se rechaza al
        // cargar, antes de que nadie la consulte.
        match crate::font_fallback::font_is_sane(&data) {
            Ok(n) => faces += n,
            Err(why) => return Err(err(format!("{}: font {:?} is not usable: {}", name, p, why))),
        }
        // Ronda 5 (M2): el tope es del TOTAL de caras (cada búsqueda de respaldo las recorre todas).
        if faces > crate::font_fallback::MAX_FACES {
            return Err(err(format!(
                "{}: option \"fonts\" adds up to more than {} faces (with {:?}); pass the single faces you use instead of whole collections",
                name,
                crate::font_fallback::MAX_FACES,
                p
            )));
        }
        out.push(data);
    }
    Ok(out)
}

/// `per_glyph`: con fuentes propias (`opts.fonts`), el respaldo es por glifo (`font_fallback`); sin
/// ellas, el de usvg tal cual (los goldens no cambian).
fn parse_tree_with(svg: &str, name: &str, fontdb: Arc<fontdb::Database>, per_glyph: bool) -> Result<usvg::Tree, Control> {
    parse_tree_limited(svg, name, fontdb, per_glyph, DEFAULT_MAX_TEXT_CHARS)
}

/// Lo mismo, con el techo de caracteres por `<text>` del caller (`max_text_chars`). El XML se lee
/// una sola vez: el conteo y usvg usan el mismo documento (con las entidades ya expandidas, así un
/// `<!ENTITY>` no esquiva el techo).
fn parse_tree_limited(
    svg: &str,
    name: &str,
    fontdb: Arc<fontdb::Database>,
    per_glyph: bool,
    max_text: usize,
) -> Result<usvg::Tree, Control> {
    let doc = parse_xml(svg).map_err(|e| err(format!("{}: invalid SVG: {}", name, e)))?;
    let longest = longest_text(&doc);
    if longest > max_text {
        return Err(err(format!(
            "{}: a <text> has {} characters, above the {} character limit (its layout time grows with the square of its length); split it into several <text> or raise it with {{\"max_text_chars\": n}}",
            name, longest, max_text
        )));
    }
    let parse = |per_glyph: bool, capped: bool, fontdb: Arc<fontdb::Database>| {
        parse_tree_once_with(svg, &doc, name, fontdb, per_glyph, capped, max_text)
    };
    if !per_glyph {
        return parse(false, false, fontdb);
    }
    // v0.6.45 (auditoría, B6): usvg copia glifo por glifo sólo si el respaldo da la MISMA cantidad de
    // glifos que la principal; con una ligadura (`fi`) o marcas combinantes en la principal, la copia
    // restringida da otra cantidad, usvg corta y el carácter que faltaba queda como tofu (antes, con
    // la fuente de respaldo entera, se veía). Si el armado por glifo deja glifos faltantes, se arma
    // también como siempre y gana el que deja menos: nunca peor que antes. La segunda pasada sólo
    // ocurre cuando quedó un faltante.
    let tree = parse(true, true, fontdb.clone())?;
    let missing = missing_glyphs(tree.root());
    if missing == 0 {
        return Ok(tree);
    }
    let plain = parse(false, true, fontdb)?;
    Ok(if missing_glyphs(plain.root()) < missing { plain } else { tree })
}

/// El XML como lo lee usvg (`Tree::from_str`: DTD permitido), con su mismo error.
fn parse_xml(svg: &str) -> Result<usvg::roxmltree::Document<'_>, usvg::Error> {
    let opt = usvg::roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() };
    usvg::roxmltree::Document::parse_with_options(svg, opt).map_err(usvg::Error::ParsingFailed)
}

/// Caracteres del `<text>` más largo: cada `<text>` suma el texto de todo lo que tiene adentro
/// (`tspan`, `textPath`). Un `<text>` dentro de otro ya se contó con el de afuera y se salta, así el
/// recorrido es lineal.
/// v0.6.45 (ronda 7): un `<tref>` arma el texto de OTRO elemento (usvg, `resolve_tref_text`), que
/// puede no estar en ningún `<text>`: cuenta como todo el texto del documento, lo máximo que puede
/// traer (contar de más está bien; resolver el `href` como usvg queda para el render propio).
fn longest_text(doc: &usvg::roxmltree::Document) -> usize {
    let mut total: Option<usize> = None;
    let mut total_text = || {
        *total.get_or_insert_with(|| {
            doc.descendants()
                .filter(|d| d.is_text())
                .map(|d| d.text().map_or(0, |t| t.chars().count()))
                .sum()
        })
    };
    let mut longest = 0;
    let mut nodes = doc.root().descendants();
    while let Some(n) = nodes.next() {
        if !(n.is_element() && n.tag_name().name() == "text") {
            continue;
        }
        let (mut len, mut last) = (0usize, n);
        for d in n.descendants() {
            if d.is_text() {
                len = len.saturating_add(d.text().map_or(0, |t| t.chars().count()));
            } else if d.is_element() && d.tag_name().name() == "tref" {
                len = len.saturating_add(total_text());
            }
            last = d;
        }
        longest = longest.max(len);
        if last != n {
            for d in nodes.by_ref() {
                if d == last {
                    break;
                }
            }
        }
    }
    longest
}

/// El `<text>` más largo de un SVG embebido en un `data:` (usvg lo arma aparte, con su propio
/// documento); 0 si no es un SVG.
fn longest_text_in_data(data: &[u8]) -> usize {
    let unzipped;
    let bytes = if data.starts_with(&[0x1f, 0x8b]) {
        match usvg::decompress_svgz(data) {
            Ok(d) => {
                unzipped = d;
                &unzipped[..]
            }
            Err(_) => return 0,
        }
    } else {
        data
    };
    match std::str::from_utf8(bytes).ok().and_then(|s| parse_xml(s).ok()) {
        Some(doc) => longest_text(&doc),
        None => 0,
    }
}

/// Cuántos glifos quedaron sin fuente (`.notdef`, el id 0) en el texto del árbol.
fn missing_glyphs(g: &usvg::Group) -> usize {
    g.children()
        .iter()
        .map(|n| match n {
            usvg::Node::Group(g) => missing_glyphs(g),
            usvg::Node::Text(t) => t.layouted().iter().flat_map(|s| s.positioned_glyphs.iter()).filter(|p| p.id.0 == 0).count(),
            _ => 0,
        })
        .sum()
}

/// `capped`: con `opts.fonts`, el respaldo de usvg con tope de rondas y memoria (ronda 5, M2); sin
/// fuentes propias, el de siempre (los goldens no cambian). `max_text` vale también para los SVG
/// embebidos en `data:`.
fn parse_tree_once_with(
    svg: &str,
    doc: &usvg::roxmltree::Document,
    name: &str,
    fontdb: Arc<fontdb::Database>,
    per_glyph: bool,
    capped: bool,
    max_text: usize,
) -> Result<usvg::Tree, Control> {
    let font_resolver = if per_glyph {
        // Los caracteres que puede pedir el texto: los del SVG (un superconjunto: también los del
        // marcado). Acotan el trabajo del respaldo por glifo (ronda 2, A7).
        let chars: std::collections::BTreeSet<char> = svg.chars().collect();
        usvg::FontResolver {
            select_font: usvg::FontResolver::default_font_selector(),
            select_fallback: crate::font_fallback::selector(std::sync::Arc::new(chars)),
        }
    } else if capped {
        usvg::FontResolver {
            select_font: usvg::FontResolver::default_font_selector(),
            select_fallback: crate::font_fallback::capped_default(),
        }
    } else {
        usvg::FontResolver::default()
    };
    // Un SVG en `data:` con un `<text>` sobre el techo no se arma: se anota y el render falla abajo
    // con el mismo error (el resolver no puede devolver un error).
    let nested = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let resolve_data = {
        let nested = nested.clone();
        let default = usvg::ImageHrefResolver::default_data_resolver();
        Box::new(move |mime: &str, data: Arc<Vec<u8>>, opts: &usvg::Options| {
            if matches!(mime, "image/svg+xml" | "text/plain") {
                let n = longest_text_in_data(&data);
                if n > max_text {
                    nested.fetch_max(n, std::sync::atomic::Ordering::Relaxed);
                    return None;
                }
            }
            default(mime, data, opts)
        })
    };
    let opt = usvg::Options {
        fontdb,
        font_resolver,
        font_family: "DejaVu Sans".to_string(),
        image_href_resolver: usvg::ImageHrefResolver {
            resolve_data,
            resolve_string: Box::new(|_href, _opts| None),
        },
        ..Default::default()
    };
    let tree = usvg::Tree::from_xmltree(doc, &opt)
        .map_err(|e| err(format!("{}: invalid SVG: {}", name, e)))?;
    let n = nested.load(std::sync::atomic::Ordering::Relaxed);
    if n > 0 {
        return Err(err(format!(
            "{}: an SVG embedded in a data: URL has a <text> of {} characters, above the {} character limit (its layout time grows with the square of its length); raise it with {{\"max_text_chars\": n}}",
            name, n, max_text
        )));
    }
    Ok(tree)
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
) -> Result<SynMap, Control> {
    match args.get(1) {
        None | Some(SynValue::Nothing) => Ok(SynMap::new()),
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
            Ok(m.to_map())
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
    opts: &MapObj,
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

/// `max_text_chars`: entero positivo (caracteres por `<text>`); sin la opción, el default.
fn max_text_opt(opts: &MapObj, name: &str) -> Result<usize, Control> {
    match opt_pos_number(opts, "max_text_chars", name)? {
        None => Ok(DEFAULT_MAX_TEXT_CHARS),
        Some(v) if v.fract() == 0.0 => Ok(v.min(usize::MAX as f64) as usize),
        Some(v) => Err(err(format!(
            "{}: option \"max_text_chars\" must be a whole number, got {}",
            name,
            py_float_str(v)
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
    svg_to_png_with(args, None)
}

/// v0.6.20 — `svg_to_png` con acceso a fuentes propias (`opts.fonts`) a través del loader
/// del host; `None` = perfil puro (la opción falla claro).
pub fn svg_to_png_with(args: &[SynValue], loader: Option<FontLoader<'_>>) -> Result<SynValue, Control> {
    const NAME: &str = "svg_to_png";
    if args.is_empty() || args.len() > 2 {
        return Err(err(format!(
            "{} expects (svg, options?) — 1 or 2 argument(s), got {}",
            NAME,
            args.len()
        )));
    }
    let svg = svg_arg(args, NAME)?;
    let opts = opts_of(args, NAME, &["width", "height", "scale", "background", "max_pixels", "max_text_chars", "fonts"])?;
    let max_text = max_text_opt(&opts, NAME)?;
    let fonts = fonts_opt(&opts, NAME, loader)?;
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

    let tree = parse_tree_limited(svg, NAME, fontdb_with(&fonts), !fonts.is_empty(), max_text)?;
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
    svg_to_pdf_with(args, None)
}

/// v0.6.20 — `svg_to_pdf` con fuentes propias (`opts.fonts`) a través del loader del host.
pub fn svg_to_pdf_with(args: &[SynValue], loader: Option<FontLoader<'_>>) -> Result<SynValue, Control> {
    const NAME: &str = "svg_to_pdf";
    if args.is_empty() || args.len() > 2 {
        return Err(err(format!(
            "{} expects (svg, options?) — 1 or 2 argument(s), got {}",
            NAME,
            args.len()
        )));
    }
    let svg = svg_arg(args, NAME)?;
    let opts = opts_of(args, NAME, &["width", "height", "max_text_chars", "fonts"])?;
    let want_w = opt_pos_number(&opts, "width", NAME)?;
    let want_h = opt_pos_number(&opts, "height", NAME)?;
    let max_text = max_text_opt(&opts, NAME)?;
    let fonts = fonts_opt(&opts, NAME, loader)?;

    let tree = parse_tree_limited(svg, NAME, fontdb_with(&fonts), !fonts.is_empty(), max_text)?;
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

/// v0.6.20 — el mismo registro, con fuentes propias: cada ruta de `opts.fonts` pasa por
/// `file.read` (disco; el bundle de `synsema build` como respaldo) — lo cablea el runtime
/// nativo DESPUÉS de `register_serve_builtins` (la última registración por nombre gana).
pub fn register_raster_builtins_with_caps(
    interp: &Interpreter,
    caps: std::rc::Rc<std::cell::RefCell<synsema_capabilities::model::CapabilitySet>>,
) {
    use synsema_capabilities::model::{normalize_path, Capability, CapabilityType};
    fn make_loader<'a>(
        caps: &'a std::rc::Rc<std::cell::RefCell<synsema_capabilities::model::CapabilitySet>>,
        source: &'static str,
    ) -> impl Fn(&str) -> Result<Vec<u8>, Control> + 'a {
        move |raw: &str| {
            let path = normalize_path(raw);
            // Assets del programa desde el bundle (sin file.read, con su línea de audit); lo
            // demás, del disco.
            if let Some(bytes) = synsema_core::bundle::get(&path) {
                synsema_capabilities::secure::bundled_audit(caps, CapabilityType::FileRead, &path, source);
                return Ok(bytes.to_vec());
            }
            caps.borrow_mut()
                .require(&Capability::new(CapabilityType::FileRead, Some(path.clone())), source)
                .map_err(|v| Control::Error(v.into_error()))?;
            // v0.6.46 (E8): sin ventana entre el chequeo y la apertura.
            let cannot = |e: std::io::Error| err(format!("{}: cannot read font {}: {}", source, path, e));
            let mut b = Vec::new();
            use std::io::Read;
            synsema_capabilities::secure::open_checked(
                caps,
                &path,
                synsema_capabilities::nofollow::OpenFor::READ,
                &[CapabilityType::FileRead],
                source,
            )
            .map_err(|r| match r {
                synsema_capabilities::nofollow::Refused::Denied(c) => c,
                synsema_capabilities::nofollow::Refused::Io(e) => cannot(e),
            })?
            .read_to_end(&mut b)
            .map_err(cannot)?;
            Ok(b)
        }
    }
    {
        let caps = caps.clone();
        interp.register_builtin(
            "svg_to_png",
            -1,
            Rc::new(move |_i, a, _l| {
                let loader = make_loader(&caps, "svg_to_png()");
                svg_to_png_with(a, Some(&loader))
            }),
        );
    }
    interp.register_builtin(
        "svg_to_pdf",
        -1,
        Rc::new(move |_i, a, _l| {
            let loader = make_loader(&caps, "svg_to_pdf()");
            svg_to_pdf_with(a, Some(&loader))
        }),
    );
}

#[cfg(test)]
mod tests {
    /// Un `name` mínimo (familia, estilo, nombre completo, PostScript) para la fuente de prueba.
    fn name_table(family: &str) -> Vec<u8> {
        let recs: Vec<(u16, Vec<u8>)> = [(1, family.to_string()), (2, "Book".to_string()), (4, family.to_string()), (6, family.replace(' ', ""))]
            .into_iter()
            .map(|(id, t)| (id, t.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()))
            .collect();
        let mut out = Vec::new();
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&(recs.len() as u16).to_be_bytes());
        out.extend_from_slice(&((6 + 12 * recs.len()) as u16).to_be_bytes());
        let mut strings = Vec::new();
        for (id, bytes) in &recs {
            for v in [3u16, 1, 0x409, *id, bytes.len() as u16, strings.len() as u16] {
                out.extend_from_slice(&v.to_be_bytes());
            }
            strings.extend_from_slice(bytes);
        }
        out.extend_from_slice(&strings);
        out
    }

    /// DejaVu con sólo ASCII y otra familia: una fuente "de marca" a la que le falta el `→`.
    fn ascii_font() -> Vec<u8> {
        let face = ttf_parser::Face::parse(EMBEDDED_FONT, 0).unwrap();
        let pairs: Vec<(u32, u16)> = (0x20u32..0x7f).filter_map(|cp| face.glyph_index(char::from_u32(cp).unwrap()).map(|g| (cp, g.0))).collect();
        crate::font_fallback::replace_tables(
            EMBEDDED_FONT,
            &[(*b"cmap", crate::font_fallback::cmap_format12(&pairs)), (*b"name", name_table("TestAscii"))],
        )
        .unwrap()
    }

    /// Una colección `.ttc` de `n` caras que comparten las tablas de `font` (como las CJK reales).
    fn collection(font: &[u8], n: usize) -> Vec<u8> {
        let num_tables = u16::from_be_bytes([font[4], font[5]]) as usize;
        let dir_len = 12 + 16 * num_tables;
        let header = 12 + 4 * n;
        let data_at = header + n * dir_len;
        let mut out = Vec::new();
        out.extend_from_slice(b"ttcf");
        out.extend_from_slice(&0x0001_0000u32.to_be_bytes());
        out.extend_from_slice(&(n as u32).to_be_bytes());
        for i in 0..n {
            out.extend_from_slice(&((header + i * dir_len) as u32).to_be_bytes());
        }
        for _ in 0..n {
            out.extend_from_slice(&font[..12]);
            for t in 0..num_tables {
                let r = &font[12 + 16 * t..28 + 16 * t];
                out.extend_from_slice(&r[..8]);
                let off = u32::from_be_bytes([r[8], r[9], r[10], r[11]]) as usize + data_at;
                out.extend_from_slice(&(off as u32).to_be_bytes());
                out.extend_from_slice(&r[12..16]);
            }
        }
        out.extend_from_slice(font);
        out
    }

    /// Ronda 5 (M2): el tope de caras es del TOTAL de `opts.fonts` (16 colecciones de 256 caras
    /// pasaban una por una y el render tardaba minutos).
    #[test]
    fn the_faces_of_all_fonts_are_capped_together() {
        use synsema_core::types::{syn_list, syn_text};
        let ttc = collection(EMBEDDED_FONT, 40);
        assert_eq!(crate::font_fallback::font_is_sane(&ttc), Ok(40));
        assert!(crate::font_fallback::font_is_sane(&collection(EMBEDDED_FONT, 65)).is_err());
        let opts_with = |n: usize| {
            let mut m = SynMap::new();
            m.insert("fonts", syn_list((0..n).map(|i| syn_text(format!("f{}.ttc", i))).collect()));
            m
        };
        let load = |_: &str| -> Result<Vec<u8>, Control> { Ok(ttc.clone()) };
        assert!(fonts_opt(&opts_with(1), "t", Some(&load)).is_ok());
        match fonts_opt(&opts_with(2), "t", Some(&load)) {
            Err(Control::Error(e)) => assert!(e.to_string().contains("faces"), "{}", e),
            _ => panic!("80 caras en total pasaron"),
        }
    }

    /// Ronda 5 (M2): para un mismo texto se prueban a lo sumo 16 fuentes de respaldo (usvg vuelve a
    /// dar forma al texto entero con cada una), en los dos selectores.
    #[test]
    fn the_fallback_tries_at_most_sixteen_fonts_per_text() {
        let mut db = fontdb::Database::new();
        for _ in 0..20 {
            db.load_font_data(EMBEDDED_FONT.to_vec());
        }
        let ids: Vec<fontdb::ID> = db.faces().map(|f| f.id).collect();
        let mut db = Arc::new(db);
        let n = crate::font_fallback::MAX_FALLBACK_ROUNDS;
        for sel in [
            crate::font_fallback::capped_default(),
            crate::font_fallback::selector(Arc::new(['A'].into_iter().collect())),
        ] {
            assert!(sel('A', &ids[..n], &mut db).is_some(), "quedan fuentes con la letra");
            assert!(sel('A', &ids[..=n], &mut db).is_none(), "pasado el tope, no se prueba otra");
        }
    }

    /// Ronda 5 (revisión): un render carga a lo sumo 16 copias restringidas (cada una pesa lo que su
    /// respaldo); pasado el tope, el respaldo se usa entero.
    #[test]
    fn a_render_loads_at_most_sixteen_restricted_copies() {
        let mut db = fontdb::Database::new();
        db.load_font_data(EMBEDDED_FONT.to_vec());
        for _ in 0..20 {
            db.load_font_data(ascii_font());
        }
        let original: Vec<fontdb::ID> = db.faces().map(|f| f.id).collect();
        let bases: Vec<fontdb::ID> = db.faces().filter(|f| f.families[0].0 == "TestAscii").map(|f| f.id).collect();
        assert_eq!(bases.len(), 20);
        let mut db = Arc::new(db);
        let sel = crate::font_fallback::selector(Arc::new("Hola → mundo".chars().collect()));
        let copies = bases
            .iter()
            .filter(|&&b| sel('→', &[b], &mut db).is_some_and(|id| !original.contains(&id)))
            .count();
        assert_eq!(copies, crate::font_fallback::MAX_COPIES_PER_RENDER);
    }

    /// Las familias que usó cada glifo del primer texto del SVG, en orden.
    fn glyph_families(svg: &str, per_glyph: bool) -> Vec<String> {
        let tree = parse_tree_with(svg, "test", fontdb_with(&[ascii_font()]), per_glyph).ok().unwrap();
        let db = tree.fontdb().clone();
        fn first_text(g: &usvg::Group) -> Option<usvg::Text> {
            for n in g.children() {
                match n {
                    usvg::Node::Text(t) => return Some((**t).clone()),
                    usvg::Node::Group(g) => {
                        if let Some(t) = first_text(g) {
                            return Some(t);
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        let text = first_text(tree.root()).expect("un texto");
        text.layouted()
            .iter()
            .flat_map(|sp| sp.positioned_glyphs.iter())
            .map(|g| db.face(g.font).map(|f| f.families[0].0.clone()).unwrap_or_default())
            .collect()
    }

    /// v0.6.45 (auditoría, B6): con una ligadura en la fuente principal (`ffi` de "Office"), la copia
    /// restringida da otra cantidad de glifos y usvg no copia nada: el `→` quedaba como tofu. Ahora
    /// gana el armado que deja menos glifos faltantes: ninguno.
    #[test]
    fn a_ligature_in_the_main_font_does_not_leave_tofu() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" width="300" height="40"><text x="4" y="28" font-family="TestAscii" font-size="20">Office → fine</text></svg>"#;
        let tree = parse_tree_with(svg, "test", fontdb_with(&[ascii_font()]), true).ok().unwrap();
        assert_eq!(super::missing_glyphs(tree.root()), 0);
    }

    /// v0.6.45 (auditoría, A6): un cmap formato 12 con un grupo `0x110000..=0xFFFFFFFF` (28 bytes)
    /// pedía ~4300 millones de inserciones al calcular la cobertura. Ahora la cobertura se consulta
    /// sobre el rango Unicode fijo y termina enseguida.
    /// v0.6.45 (auditoría, ronda 2, A7): `glyph_index` recorre todas las subtablas Unicode del cmap;
    /// una fuente con miles de registros multiplicaba el costo de cada consulta. Con más de 16 no se
    /// copia (se usa como respaldo de siempre).
    #[test]
    fn a_font_with_too_many_cmap_subtables_is_not_copied() {
        let n = 1000u16;
        let mut cmap = Vec::new();
        cmap.extend_from_slice(&0u16.to_be_bytes());
        cmap.extend_from_slice(&n.to_be_bytes());
        let sub_off = 4 + 8 * n as u32;
        for _ in 0..n {
            for v in [3u16, 10] {
                cmap.extend_from_slice(&v.to_be_bytes());
            }
            cmap.extend_from_slice(&sub_off.to_be_bytes());
        }
        for v in [12u16, 0] {
            cmap.extend_from_slice(&v.to_be_bytes());
        }
        cmap.extend_from_slice(&28u32.to_be_bytes());
        cmap.extend_from_slice(&0u32.to_be_bytes());
        cmap.extend_from_slice(&1u32.to_be_bytes());
        for v in [0x2192u32, 0x2192, 1] {
            cmap.extend_from_slice(&v.to_be_bytes());
        }
        let many = crate::font_fallback::replace_tables(EMBEDDED_FONT, &[(*b"cmap", cmap), (*b"name", name_table("Many"))]).unwrap();
        let mut db = fontdb::Database::new();
        db.load_font_data(ascii_font());
        db.load_font_data(many);
        let ids: Vec<fontdb::ID> = db.faces().map(|f| f.id).collect();
        let chars: std::collections::BTreeSet<char> = "Hola → mundo".chars().collect();
        assert!(crate::font_fallback::restrict(&db, ids[0], ids[1], &chars).is_none());
        // El control: la misma fuente con un cmap sano sí se copia.
        let mut db = fontdb::Database::new();
        db.load_font_data(ascii_font());
        db.load_font_data(EMBEDDED_FONT.to_vec());
        let ids: Vec<fontdb::ID> = db.faces().map(|f| f.id).collect();
        assert!(crate::font_fallback::restrict(&db, ids[0], ids[1], &chars).is_some());
    }

    /// Ronda 4 (M4): una fuente con un cmap armado se rechaza al CARGARLA (usvg la consultaría por
    /// cada carácter), con un error que lo dice; una fuente sana pasa.
    #[test]
    fn a_font_with_a_malformed_cmap_is_refused_at_load() {
        let mut cmap = Vec::new();
        cmap.extend_from_slice(&0u16.to_be_bytes());
        cmap.extend_from_slice(&40u16.to_be_bytes());
        let sub_off = 4 + 8 * 40u32;
        for _ in 0..40 {
            for v in [3u16, 10] {
                cmap.extend_from_slice(&v.to_be_bytes());
            }
            cmap.extend_from_slice(&sub_off.to_be_bytes());
        }
        for v in [12u16, 0] {
            cmap.extend_from_slice(&v.to_be_bytes());
        }
        cmap.extend_from_slice(&28u32.to_be_bytes());
        cmap.extend_from_slice(&0u32.to_be_bytes());
        cmap.extend_from_slice(&1u32.to_be_bytes());
        for v in [0x41u32, 0x41, 1] {
            cmap.extend_from_slice(&v.to_be_bytes());
        }
        let bad = crate::font_fallback::replace_tables(EMBEDDED_FONT, &[(*b"cmap", cmap)]).unwrap();
        assert!(crate::font_fallback::font_is_sane(&bad).is_err());
        assert!(crate::font_fallback::font_is_sane(EMBEDDED_FONT).is_ok());
        assert!(crate::font_fallback::font_is_sane(&ascii_font()).is_ok());
    }

    #[test]
    fn a_cmap_bomb_does_not_hang_the_fallback() {
        let mut cmap = Vec::new();
        for v in [0u16, 1, 3, 10] {
            cmap.extend_from_slice(&v.to_be_bytes());
        }
        cmap.extend_from_slice(&12u32.to_be_bytes());
        for v in [12u16, 0] {
            cmap.extend_from_slice(&v.to_be_bytes());
        }
        cmap.extend_from_slice(&28u32.to_be_bytes());
        cmap.extend_from_slice(&0u32.to_be_bytes());
        cmap.extend_from_slice(&1u32.to_be_bytes());
        for v in [0x2192u32, 0xFFFF_FFFF, 1] {
            cmap.extend_from_slice(&v.to_be_bytes());
        }
        let bomb = crate::font_fallback::replace_tables(EMBEDDED_FONT, &[(*b"cmap", cmap), (*b"name", name_table("Bomb"))]).unwrap();
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" width="300" height="40"><text x="4" y="28" font-family="TestAscii" font-size="20">Hola → mundo</text></svg>"#;
        let t = std::time::Instant::now();
        let tree = parse_tree_with(svg, "test", fontdb_with(&[ascii_font(), bomb]), true);
        assert!(tree.is_ok());
        assert!(t.elapsed() < std::time::Duration::from_secs(20), "tardó {:?}", t.elapsed());
    }

    /// v0.6.45 (B6): con una fuente propia a la que le falta un glifo, sólo ESE glifo cae a otra
    /// fuente (antes usvg pasaba el texto entero a DejaVu).
    #[test]
    fn a_missing_glyph_falls_back_alone() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" width="300" height="40"><text x="4" y="28" font-family="TestAscii" font-size="20">Hola → mundo</text></svg>"#;
        let fams = glyph_families(svg, true);
        assert_eq!(fams.len(), 12, "{:?}", fams);
        assert_eq!(fams.iter().filter(|f| f.as_str() == "TestAscii").count(), 11, "{:?}", fams);
        assert_eq!(fams[5], "DejaVu Sans", "la flecha viene del respaldo: {:?}", fams);
        // El selector de siempre (lo que hacía antes): todo el texto en DejaVu.
        let before = glyph_families(svg, false);
        assert!(before.iter().all(|f| f == "DejaVu Sans"), "{:?}", before);
    }

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
            Err(Control::Error(e)) => e.into_message(),
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
        let mut m = SynMap::new();
        m.insert("scale", synsema_core::types::syn_int(2));
        let png = ok(svg_to_png(&[syn_text(RED_RECT), syn_map(m)]));
        assert_eq!(png_dims(&png), (20, 20));

        // width solo → mantiene aspecto (SVG 10x10 → 40x40).
        let mut m = SynMap::new();
        m.insert("width", synsema_core::types::syn_int(40));
        let png = ok(svg_to_png(&[syn_text(RED_RECT), syn_map(m)]));
        assert_eq!(png_dims(&png), (40, 40));

        // Transparente por default fuera del dibujo; con background, esquina opaca.
        let tiny = r##"<svg xmlns="http://www.w3.org/2000/svg" width="4" height="4"><rect x="2" y="2" width="2" height="2" fill="#00ff00"/></svg>"##;
        let png = ok(svg_to_png(&[syn_text(tiny)]));
        let pm = tiny_skia::Pixmap::decode_png(&png).unwrap();
        assert_eq!(pm.pixel(0, 0).unwrap().alpha(), 0, "default transparente");
        let mut m = SynMap::new();
        m.insert("background", syn_text("#ffffff"));
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
        let mut m = SynMap::new();
        m.insert("scale", synsema_core::types::syn_int(2));
        m.insert("width", synsema_core::types::syn_int(40));
        assert!(msg(svg_to_png(&[syn_text(RED_RECT), syn_map(m)])).contains("conflicts"));
        // Techo anti-DoS con aviso que menciona la opt (G6)…
        let mut m = SynMap::new();
        m.insert("width", synsema_core::types::syn_int(10_000_000));
        assert!(msg(svg_to_png(&[syn_text(RED_RECT), syn_map(m)])).contains("max_pixels"));
        // …y sobreescribible: el mismo tamaño pasa subiendo el techo (9 Mpx > default no,
        // acá usamos uno chico para no rasterizar de verdad 100 Mpx en el test).
        let mut m = SynMap::new();
        m.insert("width", synsema_core::types::syn_int(200));
        m.insert("max_pixels", synsema_core::types::syn_int(100));
        assert!(msg(svg_to_png(&[syn_text(RED_RECT), syn_map(m)])).contains("max_pixels"));
        let mut m = SynMap::new();
        m.insert("width", synsema_core::types::syn_int(200));
        m.insert("max_pixels", synsema_core::types::syn_int(100_000));
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
        let mut m = SynMap::new();
        m.insert("width", synsema_core::types::syn_int(100));
        ok(svg_to_pdf(&[syn_text(RED_RECT), syn_map(m)]));
        // width+height con aspecto distinto al del SVG → error claro.
        let mut m = SynMap::new();
        m.insert("width", synsema_core::types::syn_int(100));
        m.insert("height", synsema_core::types::syn_int(300));
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

    fn one_text(body: &str) -> String {
        format!(r#"<svg xmlns="http://www.w3.org/2000/svg" width="40" height="20"><text x="0" y="15">{}</text></svg>"#, body)
    }

    fn max_text(n: i64) -> SynValue {
        let mut m = SynMap::new();
        m.insert("max_text_chars", synsema_core::types::syn_int(n));
        syn_map(m)
    }

    /// v0.6.45: un `<text>` sobre el techo (usvg lo arma con un costo que crece al cuadrado) es un
    /// error que dice cómo subirlo; con `max_text_chars` pasa. El techo es por `<text>`: el mismo
    /// largo repartido en dos pasa sin tocar nada. Cuentan los `tspan`.
    #[test]
    fn a_text_over_the_limit_is_refused_unless_raised() {
        let long = "a".repeat(DEFAULT_MAX_TEXT_CHARS + 1);
        for r in [svg_to_png(&[syn_text(one_text(&long))]), svg_to_pdf(&[syn_text(one_text(&long))])] {
            let m = msg(r);
            assert!(m.contains("16385 characters") && m.contains("max_text_chars"), "{}", m);
        }
        let n = DEFAULT_MAX_TEXT_CHARS as i64 + 1;
        ok(svg_to_png(&[syn_text(one_text(&long)), max_text(n)]));
        ok(svg_to_pdf(&[syn_text(one_text(&long)), max_text(n)]));
        let half = "a".repeat(DEFAULT_MAX_TEXT_CHARS / 2 + 1);
        let split = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="40" height="20"><text y="5">{h}</text><text y="15">{h}</text></svg>"#,
            h = half
        );
        ok(svg_to_png(&[syn_text(split)]));
        let spans = one_text(&format!("<tspan>{h}</tspan><tspan>{h}</tspan>", h = half));
        assert!(msg(svg_to_png(&[syn_text(spans)])).contains("max_text_chars"));
        assert!(msg(svg_to_png(&[syn_text(one_text("a")), max_text(0)])).contains("positive"));
    }

    /// v0.6.45: el conteo es sobre el texto con las entidades expandidas (una entidad de 1000 `a`
    /// usada 20 veces son 20 000 caracteres) y también vale para un SVG embebido en `data:`, que usvg
    /// arma aparte.
    #[test]
    fn the_text_limit_sees_entities_and_embedded_svgs() {
        let refs = "&a;".repeat(20);
        let svg = format!(
            r#"<!DOCTYPE svg [<!ENTITY a "{}">]><svg xmlns="http://www.w3.org/2000/svg" width="40" height="20"><text y="15">{}</text></svg>"#,
            "a".repeat(1000),
            refs
        );
        assert!(msg(svg_to_png(&[syn_text(svg)])).contains("20000 characters"));
        let inner = |n: usize| {
            format!(
                "%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10'%3E%3Ctext y='8'%3E{}%3C/text%3E%3C/svg%3E",
                "a".repeat(n)
            )
        };
        let outer = |n: usize| {
            format!(
                r#"<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"><image width="10" height="10" href="data:image/svg+xml,{}"/></svg>"#,
                inner(n)
            )
        };
        let m = msg(svg_to_png(&[syn_text(outer(DEFAULT_MAX_TEXT_CHARS + 1))]));
        assert!(m.contains("data: URL") && m.contains("max_text_chars"), "{}", m);
        ok(svg_to_png(&[syn_text(outer(10))]));
        // Ronda 7: un `<tref>` a un `<g>` (texto fuera de todo `<text>`) también, dentro de un `data:`.
        let tref = format!(
            "%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10'%3E%3Cdefs%3E%3Cg id='b'%3E{}%3C/g%3E%3C/defs%3E%3Ctext y='8'%3E%3Ctref href='%23b'/%3E%3C/text%3E%3C/svg%3E",
            "a".repeat(DEFAULT_MAX_TEXT_CHARS + 1)
        );
        let svg = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"><image width="10" height="10" href="data:image/svg+xml,{}"/></svg>"#,
            tref
        );
        let m = msg(svg_to_png(&[syn_text(svg)]));
        assert!(m.contains("data: URL") && m.contains("max_text_chars"), "{}", m);
    }

    /// v0.6.45 (ronda 7): `<tref>` arma el texto de otro elemento; el techo lo cuenta. Sin esto, un
    /// SVG de 16 KB con ocho `<tref>` armaba 128 000 caracteres (43 s).
    #[test]
    fn the_text_limit_counts_tref() {
        let over = DEFAULT_MAX_TEXT_CHARS + 1;
        // Un `<tref>` a un `<g>`: su texto no está en ningún `<text>` y no se dibuja.
        let g = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="40" height="20"><defs><g id="b">{}</g></defs><text y="15"><tref href="#b"/></text></svg>"##,
            "a".repeat(over)
        );
        assert!(msg(svg_to_png(&[syn_text(g)])).contains("max_text_chars"));
        // Dos `<tref>` a un `<text>` que por sí solo está bajo el techo.
        let half = DEFAULT_MAX_TEXT_CHARS / 2 + 1;
        let two = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="40" height="20"><defs><text id="b">{}</text></defs><text y="15"><tref xlink:href="#b"/><tref xlink:href="#b"/></text></svg>"##,
            "a".repeat(half)
        );
        assert!(msg(svg_to_png(&[syn_text(two)])).contains("max_text_chars"));
        // Un `<tref>` chico sigue pasando.
        let small = r##"<svg xmlns="http://www.w3.org/2000/svg" width="40" height="20"><defs><g id="b">hola</g></defs><text y="15"><tref href="#b"/></text></svg>"##;
        ok(svg_to_png(&[syn_text(small.to_string())]));
    }
}

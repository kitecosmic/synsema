//! v0.6.45 (B6): respaldo de fuente POR GLIFO en `svg_to_png`/`svg_to_pdf` con `opts.fonts`.
//!
//! El problema: usvg modela el texto entero de un chunk con cada fuente y, si la fuente de respaldo
//! cubre TODOS los caracteres del chunk, reemplaza todos los glifos (`shape_text` en
//! `usvg/src/text/layout.rs`). Con DejaVu de respaldo eso pasa casi siempre: un título en Unbounded
//! con un `→` salía entero en DejaVu, aunque el `→` estuviera en su propio `tspan`. Un selector de
//! respaldo propio no cambia ese atajo.
//!
//! La salida, sin tocar usvg: como respaldo se entrega una COPIA de la fuente elegida cuyo `cmap`
//! (la tabla carácter → glifo) sólo tiene los caracteres que a la fuente principal le faltan. Los
//! glifos y sus IDs son los mismos (no se toca `glyf`/`CFF`): sólo cambia qué caracteres dice tener.
//! Así el respaldo nunca cubre el texto entero, el atajo no dispara y usvg copia glifo por glifo —
//! lo que hacen un navegador y Cairo. La copia se arma una vez por par (principal, respaldo) y se
//! agrega a la base de fuentes de esa llamada. Determinista. Sólo se usa con `opts.fonts`: sin fuentes
//! propias el render es el de siempre (los goldens no cambian).

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use fontdb::{Database, ID};

/// El selector de respaldo para `usvg::FontResolver`.
pub fn selector() -> usvg::FallbackSelectionFn<'static> {
    let default = usvg::FontResolver::default_fallback_selector();
    // (principal, respaldo) → la copia restringida; y el conjunto de copias, que nunca son candidatas.
    let cache: Mutex<(HashMap<(ID, ID), ID>, Vec<ID>)> = Mutex::new((HashMap::new(), Vec::new()));
    Box::new(move |c, exclude, db| {
        let base = *exclude.first()?;
        let mut cache = cache.lock().ok()?;
        // Lo que eligió usvg (mismo estilo y familia que la principal), salteando nuestras copias.
        let mut excl: Vec<ID> = exclude.to_vec();
        excl.extend(cache.1.iter().copied());
        let found = default(c, &excl, db)?;
        if let Some(&r) = cache.0.get(&(base, found)) {
            return if exclude.contains(&r) { Some(found) } else { Some(r) };
        }
        let restricted = match restrict(db, base, found) {
            Some(b) => b,
            None => return Some(found), // una colección o un cmap que no se lee: lo de siempre
        };
        let db_mut = Arc::make_mut(db);
        let before: BTreeSet<ID> = db_mut.faces().map(|f| f.id).collect();
        db_mut.load_font_data(restricted);
        let rid = db_mut.faces().map(|f| f.id).find(|id| !before.contains(id))?;
        cache.0.insert((base, found), rid);
        cache.1.push(rid);
        Some(rid)
    })
}

/// Los caracteres (Unicode) que declara una fuente.
fn coverage(face: &ttf_parser::Face<'_>) -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    if let Some(cmap) = face.tables().cmap {
        for st in cmap.subtables {
            if st.is_unicode() {
                st.codepoints(|cp| {
                    set.insert(cp);
                });
            }
        }
    }
    set
}

/// La fuente `found` con un `cmap` de sólo lo que `base` no tiene.
fn restrict(db: &Database, base: ID, found: ID) -> Option<Vec<u8>> {
    let base_cov = db.with_face_data(base, |data, index| ttf_parser::Face::parse(data, index).ok().map(|f| coverage(&f)))??;
    db.with_face_data(found, |data, index| {
        if index != 0 {
            return None; // colección (.ttc): fuera de alcance, se usa la fuente tal cual
        }
        let face = ttf_parser::Face::parse(data, index).ok()?;
        let pairs: Vec<(u32, u16)> = coverage(&face)
            .into_iter()
            .filter(|cp| !base_cov.contains(cp))
            .filter_map(|cp| char::from_u32(cp).and_then(|ch| face.glyph_index(ch)).map(|g| (cp, g.0)))
            .collect();
        if pairs.is_empty() {
            return None;
        }
        replace_tables(data, &[(*b"cmap", cmap_format12(&pairs))])
    })?
}

/// Un `cmap` con una sola subtabla formato 12 (Unicode completo, plataforma 3 / codificación 10).
pub(crate) fn cmap_format12(pairs: &[(u32, u16)]) -> Vec<u8> {
    // Grupos de caracteres consecutivos con glifos consecutivos.
    let mut groups: Vec<(u32, u32, u32)> = Vec::new();
    for &(cp, g) in pairs {
        match groups.last_mut() {
            Some((start, end, gstart)) if cp == *end + 1 && g as u32 == *gstart + (cp - *start) => *end = cp,
            _ => groups.push((cp, cp, g as u32)),
        }
    }
    let mut sub = Vec::with_capacity(16 + 12 * groups.len());
    sub.extend_from_slice(&12u16.to_be_bytes());
    sub.extend_from_slice(&0u16.to_be_bytes());
    sub.extend_from_slice(&((16 + 12 * groups.len()) as u32).to_be_bytes());
    sub.extend_from_slice(&0u32.to_be_bytes()); // language
    sub.extend_from_slice(&(groups.len() as u32).to_be_bytes());
    for (s, e, g) in groups {
        sub.extend_from_slice(&s.to_be_bytes());
        sub.extend_from_slice(&e.to_be_bytes());
        sub.extend_from_slice(&g.to_be_bytes());
    }
    let mut out = Vec::with_capacity(12 + sub.len());
    out.extend_from_slice(&0u16.to_be_bytes()); // version
    out.extend_from_slice(&1u16.to_be_bytes()); // numTables
    out.extend_from_slice(&3u16.to_be_bytes()); // platform Windows
    out.extend_from_slice(&10u16.to_be_bytes()); // encoding UCS-4
    out.extend_from_slice(&12u32.to_be_bytes()); // offset
    out.extend_from_slice(&sub);
    out
}

fn be16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(d.get(at..at + 2)?.try_into().ok()?))
}
fn be32(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

/// Reescribe un sfnt (TrueType/OpenType de una sola fuente) con las tablas de `replace` en lugar de
/// las originales (o agregadas si no estaban). El directorio queda ordenado por tag, cada tabla
/// alineada a 4 bytes y con su checksum.
pub(crate) fn replace_tables(data: &[u8], replace: &[([u8; 4], Vec<u8>)]) -> Option<Vec<u8>> {
    if data.get(0..4)? == b"ttcf" {
        return None;
    }
    let num = be16(data, 4)? as usize;
    let mut tables: Vec<([u8; 4], Vec<u8>)> = Vec::with_capacity(num + replace.len());
    for i in 0..num {
        let rec = 12 + 16 * i;
        let tag: [u8; 4] = data.get(rec..rec + 4)?.try_into().ok()?;
        if replace.iter().any(|(t, _)| *t == tag) {
            continue;
        }
        let (off, len) = (be32(data, rec + 8)? as usize, be32(data, rec + 12)? as usize);
        tables.push((tag, data.get(off..off.checked_add(len)?)?.to_vec()));
    }
    tables.extend(replace.iter().cloned());
    tables.sort_by(|a, b| a.0.cmp(&b.0));
    let n = tables.len();
    let es = (usize::BITS - 1 - n.leading_zeros()) as u16;
    let search = (1u16 << es) * 16;
    let mut out = Vec::new();
    out.extend_from_slice(data.get(0..4)?); // sfntVersion
    out.extend_from_slice(&(n as u16).to_be_bytes());
    out.extend_from_slice(&search.to_be_bytes());
    out.extend_from_slice(&es.to_be_bytes());
    out.extend_from_slice(&((n as u16) * 16 - search).to_be_bytes());
    let mut offset = 12 + 16 * n;
    let mut body = Vec::new();
    for (tag, t) in &tables {
        let mut padded = t.clone();
        while padded.len() % 4 != 0 {
            padded.push(0);
        }
        let sum = padded.chunks(4).fold(0u32, |acc, w| acc.wrapping_add(u32::from_be_bytes(w.try_into().unwrap())));
        out.extend_from_slice(tag);
        out.extend_from_slice(&sum.to_be_bytes());
        out.extend_from_slice(&(offset as u32).to_be_bytes());
        out.extend_from_slice(&(t.len() as u32).to_be_bytes());
        offset += padded.len();
        body.extend_from_slice(&padded);
    }
    out.extend_from_slice(&body);
    Some(out)
}

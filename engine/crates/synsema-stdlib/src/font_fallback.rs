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
//! lo que hacen un navegador y Cairo. Determinista. Sólo se usa con `opts.fonts`: sin fuentes
//! propias el render es el de siempre (los goldens no cambian).
//!
//! Las fuentes las elige el programa (y pueden venir de un usuario), así que nada recorre lo que el
//! archivo declara sin tope (auditoría de v0.6.45, A6): la cobertura se consulta carácter por
//! carácter sobre el rango Unicode fijo, y la reescritura del sfnt tiene límites de tablas y de
//! tamaño. La copia se guarda por proceso con clave en el hash de los bytes de las dos fuentes: no
//! se rearma en cada render.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

use fontdb::{Database, ID};
use sha2::{Digest, Sha256};

/// Tope en BYTES de las copias restringidas que se guardan (una copia pesa lo que la fuente de
/// respaldo: 32 fuentes CJK eran ~1 GB retenido). Al pasarlo, la caché se vacía.
const CACHE_BYTES: usize = 128 << 20;
/// Una fuente con más tablas que esto no es una fuente que haya que reescribir (las reales tienen
/// ~10-40): se usa tal cual.
const MAX_TABLES: usize = 64;
/// Ronda 2 (A7): `glyph_index` de ttf-parser recorre TODAS las subtablas Unicode del cmap (un
/// archivo armado trae hasta 65 535 registros) y el formato 13 busca en forma lineal. Una fuente con
/// más subtablas que esto se usa tal cual, sin copia (las reales tienen 1-6).
const MAX_CMAP_SUBTABLES: usize = 16;
/// Ronda 3 (M5): por encima de esta cantidad de caracteres distintos en el SVG no se arma la copia
/// (cada uno es una consulta en las dos fuentes): se usa el respaldo de siempre.
const MAX_CHARS: usize = 4096;
/// Ronda 5 (M2): caras que se aceptan en `opts.fonts`, SUMADAS entre todos los archivos. usvg
/// recorre todas las caras de la base cada vez que busca un respaldo (y por cada una relee su
/// directorio de tablas): 16 colecciones de 256 caras hacían minutos de render. Una colección CJK
/// por peso (Noto Sans CJK, Source Han) trae 10 caras; la Super OTC de todos los pesos se parte.
pub const MAX_FACES: usize = 64;
/// Ronda 4 (revisión): grupos del formato 13 que se aceptan en `opts.fonts`.
const MAX_F13_GROUPS: usize = 4096;
/// Ronda 5 (M2): fuentes de respaldo que se prueban para un mismo texto. usvg vuelve a dar forma
/// al texto ENTERO con cada una: sin tope, el costo era (fuentes que aportan) × (largo del texto).
/// Un texto que mezcla más de 16 escrituras distintas deja el resto como tofu.
pub const MAX_FALLBACK_ROUNDS: usize = 16;
/// Ronda 5 (revisión): copias restringidas que un render carga en su base, en cantidad y en bytes
/// (cada par principal-respaldo es una copia del tamaño del respaldo: 48 principales por 13
/// respaldos de 10 MB eran ~6 GB). Pasado el tope, se usa el respaldo entero, como sin copia.
pub const MAX_COPIES_PER_RENDER: usize = 16;
const MAX_COPY_BYTES_PER_RENDER: usize = 64 << 20;

/// Ronda 5 (M2): el selector de usvg con el tope de rondas y con memoria POR RENDER (la misma
/// consulta — carácter y fuentes ya probadas — no vuelve a recorrer la base). Es el respaldo de
/// los renders con `opts.fonts` que no usan la copia restringida.
pub fn capped_default() -> usvg::FallbackSelectionFn<'static> {
    let default = memoized(usvg::FontResolver::default_fallback_selector());
    Box::new(move |c, exclude, db| {
        if exclude.len() > MAX_FALLBACK_ROUNDS {
            return None;
        }
        default(c, exclude, db)
    })
}

fn memoized(inner: usvg::FallbackSelectionFn<'static>) -> usvg::FallbackSelectionFn<'static> {
    let memo: Mutex<HashMap<(char, Vec<ID>), Option<ID>>> = Mutex::new(HashMap::new());
    Box::new(move |c, exclude, db| {
        let key = (c, exclude.to_vec());
        if let Some(hit) = memo.lock().ok().and_then(|m| m.get(&key).copied()) {
            return hit;
        }
        let r = inner(c, exclude, db);
        if let Ok(mut m) = memo.lock() {
            m.insert(key, r);
        }
        r
    })
}

/// La clave de una copia: SHA-256 de la principal, su índice, SHA-256 del respaldo y de los
/// caracteres consultados. Con un hash que resiste colisiones: en un `serve` con fuentes de
/// usuarios, una colisión hacía que el render de otro usara la copia de un atacante (ronda 2, B3).
type Key = ([u8; 32], u32, [u8; 32], [u8; 32]);

struct Copies {
    map: HashMap<Key, Arc<Vec<u8>>>,
    bytes: usize,
}

fn copies() -> &'static Mutex<Copies> {
    static C: OnceLock<Mutex<Copies>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(Copies { map: HashMap::new(), bytes: 0 }))
}

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// El selector de respaldo para `usvg::FontResolver`. `chars` son los caracteres del SVG que se va a
/// armar: la cobertura se consulta sólo para ésos (ronda 2, A7: el barrido de todo Unicode hacía
/// 1,1 M de consultas por par, y con una fuente armada cada consulta podía costar 65 535 lecturas).
pub fn selector(chars: Arc<BTreeSet<char>>) -> usvg::FallbackSelectionFn<'static> {
    let default = memoized(usvg::FontResolver::default_fallback_selector());
    let chars_sha = sha(chars.iter().collect::<String>().as_bytes());
    // (principal, respaldo) → la copia ya cargada en ESTA base; las copias, que nunca son
    // candidatas; y el SHA-256 de cada fuente (se calcula una vez por render).
    #[derive(Default)]
    struct Loaded {
        copies: HashMap<(ID, ID), ID>,
        ours: Vec<ID>,
        bytes: usize,
        shas: HashMap<ID, [u8; 32]>,
    }
    let loaded: Mutex<Loaded> = Mutex::new(Loaded::default());
    Box::new(move |c, exclude, db| {
        if exclude.len() > MAX_FALLBACK_ROUNDS {
            return None;
        }
        let base = *exclude.first()?;
        let mut excl: Vec<ID> = exclude.to_vec();
        if let Ok(l) = loaded.lock() {
            excl.extend(l.ours.iter().copied());
        }
        // Lo que eligió usvg (mismo estilo y familia que la principal), salteando nuestras copias.
        let found = default(c, &excl, db)?;
        // De acá en más, cualquier problema devuelve `found`: el respaldo de siempre, nunca nada.
        let Ok(mut l) = loaded.lock() else { return Some(found) };
        if let Some(&r) = l.copies.get(&(base, found)) {
            return if exclude.contains(&r) { Some(found) } else { Some(r) };
        }
        let mut sha_of = |id: ID| -> Option<[u8; 32]> {
            if let Some(h) = l.shas.get(&id) {
                return Some(*h);
            }
            let h = db.with_face_data(id, |d, _| sha(d))?;
            l.shas.insert(id, h);
            Some(h)
        };
        let (Some(hb), Some(hf)) = (sha_of(base), sha_of(found)) else { return Some(found) };
        let Some(bi) = db.face(base).map(|f| f.index) else { return Some(found) };
        let key: Key = (hb, bi, hf, chars_sha);
        let Some(restricted) = restricted_copy(db, base, found, key, &chars) else {
            // Ronda 4 (B3): el "no se copia" también se recuerda en este render (si no, cada consulta
            // volvía a parsear las dos fuentes).
            l.copies.insert((base, found), found);
            return Some(found);
        };
        if l.ours.len() >= MAX_COPIES_PER_RENDER || l.bytes + restricted.len() > MAX_COPY_BYTES_PER_RENDER {
            l.copies.insert((base, found), found);
            return Some(found);
        }
        l.bytes += restricted.len();
        let db_mut = Arc::make_mut(db);
        let before: BTreeSet<ID> = db_mut.faces().map(|f| f.id).collect();
        db_mut.load_font_data((*restricted).clone());
        let Some(rid) = db_mut.faces().map(|f| f.id).find(|id| !before.contains(id)) else { return Some(found) };
        l.copies.insert((base, found), rid);
        l.ours.push(rid);
        Some(rid)
    })
}

/// La copia restringida de `found` frente a `base`, de la caché del proceso o armada ahora.
fn restricted_copy(db: &Database, base: ID, found: ID, key: Key, chars: &BTreeSet<char>) -> Option<Arc<Vec<u8>>> {
    if let Some(hit) = copies().lock().ok()?.map.get(&key).cloned() {
        return Some(hit);
    }
    let bytes = Arc::new(restrict(db, base, found, chars)?);
    if bytes.len() > CACHE_BYTES {
        return Some(bytes); // ronda 3 (B5): una copia más grande que el tope no se guarda
    }
    if let Ok(mut c) = copies().lock() {
        if c.bytes + bytes.len() > CACHE_BYTES {
            c.map.clear();
            c.bytes = 0;
        }
        c.bytes += bytes.len();
        c.map.insert(key, bytes.clone());
    }
    Some(bytes)
}

/// v0.6.45 (ronda 4, M4) — ¿la fuente (o cada cara de una colección) se puede consultar sin un costo
/// que crezca con su archivo? La usan `svg_to_png`/`svg_to_pdf` al cargar `opts.fonts`. Devuelve
/// cuántas caras suma (las que se leen), para el tope del total.
pub fn font_is_sane(data: &[u8]) -> Result<usize, String> {
    // Ronda 4 (revisión, M2): usvg recorre las caras de la base y cada consulta vuelve a leer el
    // directorio de tablas de la cara: también se acotan las caras y las tablas.
    let faces = ttf_parser::fonts_in_collection(data).unwrap_or(1);
    if faces as usize > MAX_FACES {
        return Err(format!("a collection with {} faces (at most {})", faces, MAX_FACES));
    }
    let mut parsed = 0;
    for i in 0..faces {
        // Una cara que no se lee la saltea también la base de fuentes: no cuenta (ronda 4, B4).
        let Ok(face) = ttf_parser::Face::parse(data, i) else { continue };
        parsed += 1;
        if face.raw_face().table_records.len() as usize > MAX_TABLES {
            return Err(format!("a face has more than {} tables", MAX_TABLES));
        }
        if !cmap_is_sane(&face) {
            return Err(format!(
                "its character map has more than {} subtables or a format 13 subtable with more than {} groups",
                MAX_CMAP_SUBTABLES, MAX_F13_GROUPS
            ));
        }
    }
    if parsed == 0 {
        return Err("it does not parse as a font".to_string());
    }
    Ok(parsed)
}

/// ¿El cmap es razonable para consultar carácter por carácter? Ronda 3 (M5): `glyph_index` recorre
/// TODOS los registros (no sólo los Unicode: 65 535 registros no Unicode y uno Unicode pasaban el
/// tope), y el formato 13 busca en forma lineal: con alguno de los dos, no se copia.
fn cmap_is_sane(face: &ttf_parser::Face<'_>) -> bool {
    let Some(cmap) = face.tables().cmap else { return true };
    if cmap.subtables.into_iter().count() > MAX_CMAP_SUBTABLES {
        return false;
    }
    // Ronda 4 (B4): el formato 13 (búsqueda lineal) se acepta con pocos grupos — la LastResort de
    // Apple lo usa —; con miles, no. ttf-parser no expone los grupos: se leen del `cmap` crudo.
    let Some(raw) = face.raw_face().table(ttf_parser::Tag::from_bytes(b"cmap")) else { return true };
    let n = be16(raw, 2).unwrap_or(0) as usize;
    for i in 0..n.min(MAX_CMAP_SUBTABLES) {
        let Some(off) = be32(raw, 4 + 8 * i + 4) else { return false };
        let off = off as usize;
        if be16(raw, off) == Some(13) {
            match be32(raw, off + 12) {
                Some(groups) if groups as usize <= MAX_F13_GROUPS => {}
                _ => return false,
            }
        }
    }
    true
}

/// La fuente `found` con un `cmap` de sólo los caracteres de `chars` que `base` no tiene. Lo que el
/// archivo DECLARA no se enumera (un grupo armado del formato 12 pedía miles de millones de
/// vueltas), y una fuente con un cmap armado (demasiadas subtablas) no se copia.
pub(crate) fn restrict(db: &Database, base: ID, found: ID, chars: &BTreeSet<char>) -> Option<Vec<u8>> {
    db.with_face_data(base, |base_data, base_index| {
        let base_face = ttf_parser::Face::parse(base_data, base_index).ok()?;
        if chars.len() > MAX_CHARS || !cmap_is_sane(&base_face) {
            return None;
        }
        db.with_face_data(found, |data, index| {
            if index != 0 {
                return None; // colección (.ttc): fuera de alcance, se usa la fuente tal cual
            }
            let face = ttf_parser::Face::parse(data, index).ok()?;
            if !cmap_is_sane(&face) {
                return None;
            }
            let glyphs = face.number_of_glyphs();
            // Un glifo 0 (`.notdef`) no cubre nada, y un ID fuera de `numGlyphs` no existe.
            let covers = |f: &ttf_parser::Face<'_>, ch: char, n: u16| f.glyph_index(ch).is_some_and(|g| g.0 != 0 && g.0 < n);
            let base_glyphs = base_face.number_of_glyphs();
            let pairs: Vec<(u32, u16)> = chars
                .iter()
                .filter(|ch| !covers(&base_face, **ch, base_glyphs))
                .filter_map(|ch| face.glyph_index(*ch).filter(|g| g.0 != 0 && g.0 < glyphs).map(|g| (*ch as u32, g.0)))
                .collect();
            if pairs.is_empty() {
                return None;
            }
            replace_tables(data, &[(*b"cmap", cmap_format12(&pairs))])
        })?
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
/// alineada a 4 bytes y con su checksum. `None` (se usa la fuente tal cual) con más de `MAX_TABLES`
/// tablas, tags repetidos, o tablas que suman más que el archivo (un directorio armado con registros
/// superpuestos pedía copiar el archivo miles de veces).
pub(crate) fn replace_tables(data: &[u8], replace: &[([u8; 4], Vec<u8>)]) -> Option<Vec<u8>> {
    if data.get(0..4)? == b"ttcf" {
        return None;
    }
    let num = be16(data, 4)? as usize;
    if num + replace.len() > MAX_TABLES {
        return None;
    }
    let mut kept: Vec<([u8; 4], &[u8])> = Vec::with_capacity(num);
    let mut total = 0usize;
    for i in 0..num {
        let rec = 12 + 16 * i;
        let tag: [u8; 4] = data.get(rec..rec + 4)?.try_into().ok()?;
        if kept.iter().any(|(t, _)| *t == tag) {
            return None;
        }
        if replace.iter().any(|(t, _)| *t == tag) {
            continue;
        }
        let (off, len) = (be32(data, rec + 8)? as usize, be32(data, rec + 12)? as usize);
        total = total.checked_add(len)?;
        if total > data.len() {
            return None;
        }
        kept.push((tag, data.get(off..off.checked_add(len)?)?));
    }
    let mut tables: Vec<([u8; 4], &[u8])> = kept;
    tables.extend(replace.iter().map(|(t, b)| (*t, b.as_slice())));
    tables.sort_by(|a, b| a.0.cmp(&b.0));
    let n = tables.len();
    if n == 0 {
        return None;
    }
    let es = (usize::BITS - 1 - n.leading_zeros()) as u16;
    let search = (1u16 << es) * 16;
    let mut out = Vec::with_capacity(12 + 16 * n + total + replace.iter().map(|(_, b)| b.len() + 3).sum::<usize>());
    out.extend_from_slice(data.get(0..4)?); // sfntVersion
    out.extend_from_slice(&(n as u16).to_be_bytes());
    out.extend_from_slice(&search.to_be_bytes());
    out.extend_from_slice(&es.to_be_bytes());
    out.extend_from_slice(&((n as u16) * 16 - search).to_be_bytes());
    let dir_end = 12 + 16 * n;
    out.resize(dir_end, 0);
    for (i, (tag, t)) in tables.iter().enumerate() {
        let offset = out.len();
        out.extend_from_slice(t);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        let sum = out[offset..].chunks(4).fold(0u32, |acc, w| acc.wrapping_add(u32::from_be_bytes(w.try_into().unwrap())));
        let rec = 12 + 16 * i;
        out[rec..rec + 4].copy_from_slice(tag);
        out[rec + 4..rec + 8].copy_from_slice(&sum.to_be_bytes());
        out[rec + 8..rec + 12].copy_from_slice(&(offset as u32).to_be_bytes());
        out[rec + 12..rec + 16].copy_from_slice(&(t.len() as u32).to_be_bytes());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un directorio con miles de registros superpuestos (off = 0, len = todo el archivo) ya no pide
    /// copiar el archivo una vez por registro.
    #[test]
    fn overlapping_table_records_are_refused() {
        let n = 4000usize;
        let size = 12 + 16 * n;
        let mut d = vec![0u8; size];
        d[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        d[4..6].copy_from_slice(&(n as u16).to_be_bytes());
        for i in 0..n {
            let rec = 12 + 16 * i;
            d[rec..rec + 4].copy_from_slice(&(i as u32).to_be_bytes());
            d[rec + 12..rec + 16].copy_from_slice(&(size as u32).to_be_bytes());
        }
        assert!(replace_tables(&d, &[(*b"cmap", vec![0; 8])]).is_none());
        // Pocas tablas pero superpuestas: la suma de largos pasa el archivo.
        let n = 8usize;
        let size = 12 + 16 * n;
        let mut d = vec![0u8; size];
        d[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        d[4..6].copy_from_slice(&(n as u16).to_be_bytes());
        for i in 0..n {
            let rec = 12 + 16 * i;
            d[rec..rec + 4].copy_from_slice(&[b'a', b'a', b'a', b'a' + i as u8]);
            d[rec + 12..rec + 16].copy_from_slice(&(size as u32).to_be_bytes());
        }
        assert!(replace_tables(&d, &[(*b"cmap", vec![0; 8])]).is_none());
    }

    /// Una tabla reemplazada queda con su contenido, alineada y con checksum; las demás intactas.
    #[test]
    fn a_rewritten_font_keeps_its_other_tables() {
        let mut d = Vec::new();
        d.extend_from_slice(&0x0001_0000u32.to_be_bytes());
        d.extend_from_slice(&2u16.to_be_bytes());
        d.extend_from_slice(&[0u8; 6]);
        let body_a = b"AAAAAAAA";
        let body_c = b"CMAPOLD!";
        let dir = 12 + 32;
        for (i, (tag, body, off)) in [(*b"aaaa", &body_a[..], dir), (*b"cmap", &body_c[..], dir + 8)].iter().enumerate() {
            let _ = i;
            d.extend_from_slice(tag);
            d.extend_from_slice(&0u32.to_be_bytes());
            d.extend_from_slice(&(*off as u32).to_be_bytes());
            d.extend_from_slice(&(body.len() as u32).to_be_bytes());
        }
        d.extend_from_slice(body_a);
        d.extend_from_slice(body_c);
        let out = replace_tables(&d, &[(*b"cmap", b"NEW".to_vec())]).unwrap();
        assert_eq!(be16(&out, 4), Some(2));
        let find = |tag: &[u8; 4]| -> (usize, usize) {
            (0..2)
                .map(|i| 12 + 16 * i)
                .find(|r| &out[*r..*r + 4] == tag)
                .map(|r| (be32(&out, r + 8).unwrap() as usize, be32(&out, r + 12).unwrap() as usize))
                .unwrap()
        };
        let (oa, la) = find(b"aaaa");
        assert_eq!(&out[oa..oa + la], body_a);
        let (oc, lc) = find(b"cmap");
        assert_eq!(&out[oc..oc + lc], b"NEW");
        assert_eq!(oc % 4, 0);
    }
}

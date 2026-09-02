//! Cirugía mínima sobre un ejecutable PE (Windows) para `synsema build` (tanda escritorio):
//! `--no-console` (subsistema CONSOLE → GUI: dos bytes) e `--icon` (una sección `.rsrc`
//! nueva con `RT_ICON` + `RT_GROUP_ICON`). Sin dependencias: el formato es fijo y chico.
//!
//! Lo que se asume y se verifica (fail-loud): magic `MZ`, `PE\0\0`, optional header PE32 o
//! PE32+, subsistema 2 o 3. Para `--icon`, si el motor YA trae recursos (el release MSVC no
//! tiene ninguno; un motor compilado con la toolchain GNU trae un manifest `RT_MANIFEST`), el
//! árbol existente se LEE, se le reemplazan `RT_ICON`/`RT_GROUP_ICON` y se reescribe entero en
//! una sección nueva al final; la sección vieja queda como bytes muertos (el loader sólo sigue
//! `DataDirectory[2]`). Tiene que quedar lugar para un header de sección más.
//!
//! Referencia: PE/COFF spec (Microsoft), "Resource Directory", "Icon resources". El loader
//! busca por bisección: las entradas van nombres primero y luego ids ascendentes.

const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
const RT_ICON: u32 = 3;
const RT_GROUP_ICON: u32 = 14;
const LANG_EN_US: u32 = 0x0409;
/// IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
const RSRC_CHARACTERISTICS: u32 = 0x4000_0040;
/// Tope de entradas al leer un árbol (anti-corrupción: un PE roto no cuelga el build).
const MAX_RES_ENTRIES: usize = 8192;

/// Lo que hay que saber de un PE para tocarlo.
#[derive(Debug, Clone)]
pub struct PeInfo {
    pub pe_offset: usize,
    pub is_pe32_plus: bool,
    pub num_sections: usize,
    pub section_headers_offset: usize,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub subsystem: u16,
    /// (RVA, size) del directorio de recursos (entrada 2).
    pub resource_dir: (u32, u32),
    /// Nombres de las secciones (diagnóstico y tests).
    #[allow(dead_code)]
    pub section_names: Vec<String>,
}

pub fn is_pe(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or_else(|| "PE: truncated header".to_string())
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| "PE: truncated header".to_string())
}

fn opt_header_offset(pe: usize) -> usize {
    pe + 24
}

/// Offset (desde el inicio del optional header) del directorio de datos `index`.
fn data_dir_offset(is_plus: bool, index: usize) -> usize {
    (if is_plus { 112 } else { 96 }) + index * 8
}

pub fn parse(bytes: &[u8]) -> Result<PeInfo, String> {
    if !is_pe(bytes) {
        return Err("not a Windows executable (no MZ header)".to_string());
    }
    let pe_offset = u32_at(bytes, 0x3c)? as usize;
    if bytes.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
        return Err("not a PE image (PE signature missing)".to_string());
    }
    let num_sections = u16_at(bytes, pe_offset + 6)? as usize;
    let size_of_opt = u16_at(bytes, pe_offset + 20)? as usize;
    let opt = opt_header_offset(pe_offset);
    let magic = u16_at(bytes, opt)?;
    let is_pe32_plus = match magic {
        0x10b => false,
        0x20b => true,
        m => return Err(format!("PE: unknown optional header magic 0x{:x}", m)),
    };
    let section_alignment = u32_at(bytes, opt + 32)?;
    let file_alignment = u32_at(bytes, opt + 36)?;
    let size_of_headers = u32_at(bytes, opt + 60)?;
    let subsystem = u16_at(bytes, opt + 68)?;
    let num_dirs = u32_at(bytes, opt + if is_pe32_plus { 108 } else { 92 })? as usize;
    let resource_dir = if num_dirs > 2 {
        let d = opt + data_dir_offset(is_pe32_plus, 2);
        (u32_at(bytes, d)?, u32_at(bytes, d + 4)?)
    } else {
        (0, 0)
    };
    let section_headers_offset = opt + size_of_opt;
    let mut section_names = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let at = section_headers_offset + i * 40;
        let name = bytes.get(at..at + 8).ok_or("PE: truncated section table")?;
        let end = name.iter().position(|b| *b == 0).unwrap_or(8);
        section_names.push(String::from_utf8_lossy(&name[..end]).into_owned());
    }
    Ok(PeInfo {
        pe_offset,
        is_pe32_plus,
        num_sections,
        section_headers_offset,
        size_of_headers,
        section_alignment,
        file_alignment,
        subsystem,
        resource_dir,
        section_names,
    })
}

/// `--no-console`: subsistema CONSOLE (3) → GUI (2), dos bytes. Ya GUI → no-op.
pub fn set_subsystem_gui(bytes: &mut [u8]) -> Result<(), String> {
    let info = parse(bytes)?;
    let at = opt_header_offset(info.pe_offset) + 68;
    match info.subsystem {
        IMAGE_SUBSYSTEM_WINDOWS_GUI => Ok(()),
        IMAGE_SUBSYSTEM_WINDOWS_CUI => {
            bytes[at..at + 2].copy_from_slice(&IMAGE_SUBSYSTEM_WINDOWS_GUI.to_le_bytes());
            Ok(())
        }
        other => Err(format!("PE: unexpected subsystem {} (expected console=3 or gui=2)", other)),
    }
}

fn align_up(v: u32, a: u32) -> u32 {
    if a == 0 {
        v
    } else {
        v.div_ceil(a) * a
    }
}

/// RVA → offset en el archivo, exigiendo que `len` bytes estén dentro de los datos crudos de
/// su sección.
fn rva_to_offset(bytes: &[u8], info: &PeInfo, rva: u32, len: usize) -> Result<usize, String> {
    for i in 0..info.num_sections {
        let at = info.section_headers_offset + i * 40;
        let vsize = u32_at(bytes, at + 8)?;
        let va = u32_at(bytes, at + 12)?;
        let raw = u32_at(bytes, at + 16)?;
        let ptr = u32_at(bytes, at + 20)?;
        if rva >= va && rva < va.saturating_add(vsize.max(raw)) {
            let rel = (rva - va) as usize;
            let off = ptr as usize + rel;
            if rel + len > raw as usize || off + len > bytes.len() {
                return Err("PE: resource data outside its section".to_string());
            }
            return Ok(off);
        }
    }
    Err(format!("PE: RVA 0x{:x} is not inside any section", rva))
}

// =========================================================
// Árbol de recursos (genérico: se lee lo que haya y se reescribe entero)
// =========================================================

/// Clave de una entrada del directorio: id numérico o nombre (UTF-16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResKey {
    Id(u32),
    Name(Vec<u16>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResNode {
    Dir(ResDir),
    Data { bytes: Vec<u8>, codepage: u32 },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResDir {
    pub entries: Vec<(ResKey, ResNode)>,
}

fn parse_dir(bytes: &[u8], info: &PeInfo, base_off: usize, dir_off: u32, depth: usize, budget: &mut usize) -> Result<ResDir, String> {
    if depth > 3 {
        return Err("PE: resource tree deeper than 3 levels".to_string());
    }
    let at = base_off + dir_off as usize;
    let named = u16_at(bytes, at + 12)? as usize;
    let ids = u16_at(bytes, at + 14)? as usize;
    let mut entries = Vec::with_capacity(named + ids);
    for i in 0..named + ids {
        *budget = budget.checked_sub(1).ok_or_else(|| "PE: too many resource entries".to_string())?;
        let e = at + 16 + i * 8;
        let id = u32_at(bytes, e)?;
        let off = u32_at(bytes, e + 4)?;
        let key = if id & 0x8000_0000 != 0 {
            let so = base_off + (id & 0x7fff_ffff) as usize;
            let len = u16_at(bytes, so)? as usize;
            let mut name = Vec::with_capacity(len);
            for k in 0..len {
                name.push(u16_at(bytes, so + 2 + k * 2)?);
            }
            ResKey::Name(name)
        } else {
            ResKey::Id(id)
        };
        let node = if off & 0x8000_0000 != 0 {
            ResNode::Dir(parse_dir(bytes, info, base_off, off & 0x7fff_ffff, depth + 1, budget)?)
        } else {
            let d = base_off + off as usize;
            let rva = u32_at(bytes, d)?;
            let size = u32_at(bytes, d + 4)? as usize;
            let codepage = u32_at(bytes, d + 8)?;
            let o = rva_to_offset(bytes, info, rva, size)?;
            ResNode::Data { bytes: bytes[o..o + size].to_vec(), codepage }
        };
        entries.push((key, node));
    }
    Ok(ResDir { entries })
}

/// El árbol de recursos del PE (vacío si no tiene).
pub fn parse_tree(bytes: &[u8]) -> Result<ResDir, String> {
    let info = parse(bytes)?;
    let (rva, size) = info.resource_dir;
    if rva == 0 || size == 0 {
        return Ok(ResDir::default());
    }
    let base_off = rva_to_offset(bytes, &info, rva, 16)?;
    let mut budget = MAX_RES_ENTRIES;
    parse_dir(bytes, &info, base_off, 0, 0, &mut budget)
}

/// Copia ordenada como exige el loader: nombres primero (orden de código UTF-16), ids ascendentes.
fn sorted(d: &ResDir) -> ResDir {
    let mut names: Vec<(ResKey, ResNode)> = d.entries.iter().filter(|(k, _)| matches!(k, ResKey::Name(_))).cloned().collect();
    let mut ids: Vec<(ResKey, ResNode)> = d.entries.iter().filter(|(k, _)| matches!(k, ResKey::Id(_))).cloned().collect();
    names.sort_by(|a, b| match (&a.0, &b.0) {
        (ResKey::Name(x), ResKey::Name(y)) => x.cmp(y),
        _ => std::cmp::Ordering::Equal,
    });
    ids.sort_by_key(|(k, _)| match k {
        ResKey::Id(i) => *i,
        _ => 0,
    });
    let mut entries = names;
    entries.extend(ids);
    ResDir {
        entries: entries
            .into_iter()
            .map(|(k, n)| match n {
                ResNode::Dir(sub) => (k, ResNode::Dir(sorted(&sub))),
                other => (k, other),
            })
            .collect(),
    }
}

struct Layout {
    dir_size: u32,
    n_data: u32,
    str_size: u32,
    data_size: u32,
}

fn measure(d: &ResDir, l: &mut Layout) {
    l.dir_size += 16 + 8 * d.entries.len() as u32;
    for (k, n) in &d.entries {
        if let ResKey::Name(s) = k {
            l.str_size += 2 + 2 * s.len() as u32;
        }
        match n {
            ResNode::Dir(sub) => measure(sub, l),
            ResNode::Data { bytes, .. } => {
                l.n_data += 1;
                l.data_size += align_up(bytes.len() as u32, 8);
            }
        }
    }
}

struct Cursors {
    dir: u32,
    entry: u32,
    string: u32,
    data: u32,
}

fn write_dir(d: &ResDir, out: &mut [u8], cur: &mut Cursors, rva_base: u32) -> u32 {
    let at = cur.dir;
    cur.dir += 16 + 8 * d.entries.len() as u32;
    let named = d.entries.iter().filter(|(k, _)| matches!(k, ResKey::Name(_))).count() as u16;
    let ids = d.entries.len() as u16 - named;
    let a = at as usize;
    out[a + 12..a + 14].copy_from_slice(&named.to_le_bytes());
    out[a + 14..a + 16].copy_from_slice(&ids.to_le_bytes());
    for (i, (k, n)) in d.entries.iter().enumerate() {
        let e = a + 16 + i * 8;
        let id_field = match k {
            ResKey::Id(id) => *id,
            ResKey::Name(s) => {
                let so = cur.string as usize;
                out[so..so + 2].copy_from_slice(&(s.len() as u16).to_le_bytes());
                for (j, c) in s.iter().enumerate() {
                    out[so + 2 + j * 2..so + 4 + j * 2].copy_from_slice(&c.to_le_bytes());
                }
                cur.string += 2 + 2 * s.len() as u32;
                0x8000_0000 | so as u32
            }
        };
        let off_field = match n {
            ResNode::Dir(sub) => 0x8000_0000 | write_dir(sub, out, cur, rva_base),
            ResNode::Data { bytes, codepage } => {
                let de = cur.entry as usize;
                cur.entry += 16;
                let d0 = cur.data as usize;
                cur.data += align_up(bytes.len() as u32, 8);
                out[d0..d0 + bytes.len()].copy_from_slice(bytes);
                out[de..de + 4].copy_from_slice(&(rva_base + d0 as u32).to_le_bytes());
                out[de + 4..de + 8].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
                out[de + 8..de + 12].copy_from_slice(&codepage.to_le_bytes());
                de as u32
            }
        };
        out[e..e + 4].copy_from_slice(&id_field.to_le_bytes());
        out[e + 4..e + 8].copy_from_slice(&off_field.to_le_bytes());
    }
    at
}

/// Serializa el árbol como contenido de una sección `.rsrc` cuya VirtualAddress será
/// `rva_base` (los data entries llevan RVAs absolutos). Layout: directorios (DFS), data
/// entries, nombres, datos (alineados a 8).
pub fn serialize_tree(root: &ResDir, rva_base: u32) -> Vec<u8> {
    let root = sorted(root);
    let mut l = Layout { dir_size: 0, n_data: 0, str_size: 0, data_size: 0 };
    measure(&root, &mut l);
    let entries_start = l.dir_size;
    let strings_start = entries_start + l.n_data * 16;
    let data_start = align_up(strings_start + l.str_size, 8);
    let total = data_start + l.data_size;
    let mut out = vec![0u8; total as usize];
    let mut cur = Cursors { dir: 0, entry: entries_start, string: strings_start, data: data_start };
    write_dir(&root, &mut out, &mut cur, rva_base);
    debug_assert_eq!(cur.dir, entries_start);
    debug_assert_eq!(cur.entry, strings_start);
    debug_assert_eq!(cur.data, total);
    out
}

/// Agrega una sección `.rsrc` nueva al final del PE con el árbol dado y apunta el directorio
/// de recursos a ella. Falla (sin tocar nada) si no queda lugar para otro header de sección.
pub fn append_rsrc_section(bytes: &mut Vec<u8>, root: &ResDir) -> Result<(), String> {
    let info = parse(bytes)?;
    let new_hdr = info.section_headers_offset + info.num_sections * 40;
    if new_hdr + 40 > info.size_of_headers as usize {
        return Err("--icon: no room in the PE headers for another section".to_string());
    }
    // Fin virtual de la última sección → VA nueva.
    let mut last_va_end = 0u32;
    for i in 0..info.num_sections {
        let at = info.section_headers_offset + i * 40;
        let vsize = u32_at(bytes, at + 8)?;
        let va = u32_at(bytes, at + 12)?;
        let raw = u32_at(bytes, at + 16)?;
        last_va_end = last_va_end.max(va + vsize.max(raw));
    }
    let rva = align_up(last_va_end, info.section_alignment);
    let data = serialize_tree(root, rva);
    // Datos al final del archivo, alineados a FileAlignment.
    let raw_ptr = align_up(bytes.len() as u32, info.file_alignment);
    bytes.resize(raw_ptr as usize, 0);
    let raw_size = align_up(data.len() as u32, info.file_alignment);
    bytes.extend_from_slice(&data);
    bytes.resize((raw_ptr + raw_size) as usize, 0);
    // Header de la sección.
    let mut hdr = [0u8; 40];
    hdr[..5].copy_from_slice(b".rsrc");
    hdr[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
    hdr[12..16].copy_from_slice(&rva.to_le_bytes());
    hdr[16..20].copy_from_slice(&raw_size.to_le_bytes());
    hdr[20..24].copy_from_slice(&raw_ptr.to_le_bytes());
    hdr[36..40].copy_from_slice(&RSRC_CHARACTERISTICS.to_le_bytes());
    bytes[new_hdr..new_hdr + 40].copy_from_slice(&hdr);
    // NumberOfSections, SizeOfImage, DataDirectory[2].
    let ns = (info.num_sections + 1) as u16;
    bytes[info.pe_offset + 6..info.pe_offset + 8].copy_from_slice(&ns.to_le_bytes());
    let opt = opt_header_offset(info.pe_offset);
    let size_of_image = align_up(rva + data.len() as u32, info.section_alignment);
    bytes[opt + 56..opt + 60].copy_from_slice(&size_of_image.to_le_bytes());
    let d = opt + data_dir_offset(info.is_pe32_plus, 2);
    bytes[d..d + 4].copy_from_slice(&rva.to_le_bytes());
    bytes[d + 4..d + 8].copy_from_slice(&(data.len() as u32).to_le_bytes());
    Ok(())
}

// =========================================================
// Íconos
// =========================================================

/// Una imagen de ícono lista para el recurso: PNG (cualquier tamaño, Vista+) o el DIB de
/// un `.ico` clásico. `size` = lado en px (0 en el GRPICONDIR significa 256).
#[derive(Debug, Clone)]
pub struct IconImage {
    pub size: u32,
    pub bytes: Vec<u8>,
}

/// El `GRPICONDIR` (RT_GROUP_ICON) que apunta a los RT_ICON ids 1..=n.
fn group_icon_dir(images: &[IconImage]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + 14 * images.len());
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&1u16.to_le_bytes()); // type icon
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());
    for (i, im) in images.iter().enumerate() {
        let side = if im.size >= 256 { 0u8 } else { im.size as u8 };
        out.push(side); // bWidth
        out.push(side); // bHeight
        out.push(0); // bColorCount
        out.push(0); // bReserved
        out.extend_from_slice(&1u16.to_le_bytes()); // wPlanes
        out.extend_from_slice(&32u16.to_le_bytes()); // wBitCount
        out.extend_from_slice(&(im.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&((i + 1) as u16).to_le_bytes()); // nID
    }
    out
}

fn lang(node: ResNode) -> ResNode {
    ResNode::Dir(ResDir { entries: vec![(ResKey::Id(LANG_EN_US), node)] })
}

/// Pone los íconos de la app en el PE: se lee el árbol de recursos que haya (manifest, etc.),
/// se reemplazan `RT_ICON` (ids 1..=n) y `RT_GROUP_ICON` (id 1), idioma 0x0409, y se escribe
/// todo en una sección `.rsrc` nueva al final. Falla (sin tocar nada) si no hay lugar para otro
/// header de sección o si el árbol existente está corrupto.
pub fn add_icon(bytes: &mut Vec<u8>, images: &[IconImage]) -> Result<(), String> {
    if images.is_empty() {
        return Err("--icon: no icon images".to_string());
    }
    let mut root = parse_tree(bytes).map_err(|e| format!("--icon: cannot read the engine's resources ({}); build from another engine", e))?;
    root.entries.retain(|(k, _)| !matches!(k, ResKey::Id(RT_ICON) | ResKey::Id(RT_GROUP_ICON)));
    let icon_dir = ResDir {
        entries: images
            .iter()
            .enumerate()
            .map(|(i, im)| (ResKey::Id(i as u32 + 1), lang(ResNode::Data { bytes: im.bytes.clone(), codepage: 0 })))
            .collect(),
    };
    let group = ResDir { entries: vec![(ResKey::Id(1), lang(ResNode::Data { bytes: group_icon_dir(images), codepage: 0 }))] };
    root.entries.push((ResKey::Id(RT_ICON), ResNode::Dir(icon_dir)));
    root.entries.push((ResKey::Id(RT_GROUP_ICON), ResNode::Dir(group)));
    append_rsrc_section(bytes, &root)
}

/// Las imágenes de un `.ico`: cada entrada tal cual (PNG o DIB), con su lado.
pub fn ico_images(ico: &[u8]) -> Result<Vec<IconImage>, String> {
    if ico.len() < 6 || u16_at(ico, 0)? != 0 || u16_at(ico, 2)? != 1 {
        return Err("--icon: not an .ico file".to_string());
    }
    let count = u16_at(ico, 4)? as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let e = 6 + i * 16;
        let w = *ico.get(e).ok_or("--icon: truncated .ico")? as u32;
        let len = u32_at(ico, e + 8)? as usize;
        let off = u32_at(ico, e + 12)? as usize;
        let bytes = ico.get(off..off + len).ok_or("--icon: truncated .ico image")?.to_vec();
        out.push(IconImage { size: if w == 0 { 256 } else { w }, bytes });
    }
    if out.is_empty() {
        return Err("--icon: the .ico has no images".to_string());
    }
    Ok(out)
}

/// Un `.ico` mínimo (contenedor) a partir de imágenes PNG (para tests).
#[cfg(test)]
pub fn ico_from_images(images: &[IconImage]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut off = 6 + 16 * images.len() as u32;
    for im in images {
        let side = if im.size >= 256 { 0u8 } else { im.size as u8 };
        out.push(side);
        out.push(side);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(im.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
        off += im.bytes.len() as u32;
    }
    for im in images {
        out.extend_from_slice(&im.bytes);
    }
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Un PE sintético mínimo: DOS stub, PE, optional header (PE32+ o PE32), N secciones con
    /// datos de relleno; SizeOfHeaders = 0x400 (lugar para más headers).
    pub fn synthetic_pe(plus: bool, sections: usize, subsystem: u16) -> Vec<u8> {
        let file_align = 0x200u32;
        let sect_align = 0x1000u32;
        let mut b = vec![0u8; 0x400];
        b[0] = b'M';
        b[1] = b'Z';
        let pe = 0x80usize;
        b[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        b[pe..pe + 4].copy_from_slice(b"PE\0\0");
        b[pe + 6..pe + 8].copy_from_slice(&(sections as u16).to_le_bytes());
        let opt_size: u16 = if plus { 240 } else { 224 };
        b[pe + 20..pe + 22].copy_from_slice(&opt_size.to_le_bytes());
        let opt = pe + 24;
        b[opt..opt + 2].copy_from_slice(&(if plus { 0x20bu16 } else { 0x10bu16 }).to_le_bytes());
        b[opt + 32..opt + 36].copy_from_slice(&sect_align.to_le_bytes());
        b[opt + 36..opt + 40].copy_from_slice(&file_align.to_le_bytes());
        b[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        b[opt + 68..opt + 70].copy_from_slice(&subsystem.to_le_bytes());
        let nd = opt + if plus { 108 } else { 92 };
        b[nd..nd + 4].copy_from_slice(&16u32.to_le_bytes());
        let sh = opt + opt_size as usize;
        let mut raw_ptr = 0x400u32;
        let mut va = 0x1000u32;
        for i in 0..sections {
            let at = sh + i * 40;
            let name = format!(".s{}", i);
            b[at..at + name.len()].copy_from_slice(name.as_bytes());
            b[at + 8..at + 12].copy_from_slice(&0x100u32.to_le_bytes());
            b[at + 12..at + 16].copy_from_slice(&va.to_le_bytes());
            b[at + 16..at + 20].copy_from_slice(&0x200u32.to_le_bytes());
            b[at + 20..at + 24].copy_from_slice(&raw_ptr.to_le_bytes());
            raw_ptr += 0x200;
            va += sect_align;
        }
        b[opt + 56..opt + 60].copy_from_slice(&va.to_le_bytes());
        b.resize(raw_ptr as usize, 0xcc);
        b
    }

    fn data(node: &ResNode) -> &[u8] {
        match node {
            ResNode::Data { bytes, .. } => bytes,
            _ => panic!("no es un data entry"),
        }
    }

    fn dir(node: &ResNode) -> &ResDir {
        match node {
            ResNode::Dir(d) => d,
            _ => panic!("no es un directorio"),
        }
    }

    /// `root/<id>/<sub>/<lang 0x409>` → datos.
    fn leaf<'a>(root: &'a ResDir, id: u32, sub: u32) -> &'a [u8] {
        let (_, t) = root.entries.iter().find(|(k, _)| *k == ResKey::Id(id)).expect("tipo");
        let (_, s) = dir(t).entries.iter().find(|(k, _)| *k == ResKey::Id(sub)).expect("id");
        let (k, l) = &dir(s).entries[0];
        assert_eq!(*k, ResKey::Id(LANG_EN_US));
        data(l)
    }

    #[test]
    fn subsystem_flip_is_two_bytes_and_idempotent() {
        for plus in [false, true] {
            let mut b = synthetic_pe(plus, 3, 3);
            let before = b.clone();
            set_subsystem_gui(&mut b).unwrap();
            assert_eq!(parse(&b).unwrap().subsystem, 2);
            let diff: Vec<usize> = before.iter().zip(&b).enumerate().filter(|(_, (x, y))| x != y).map(|(i, _)| i).collect();
            assert_eq!(diff.len(), 1, "sólo cambia el byte bajo del subsistema: {:?}", diff);
            set_subsystem_gui(&mut b).unwrap(); // ya GUI: no-op
            assert_eq!(parse(&b).unwrap().subsystem, 2);
        }
        assert!(set_subsystem_gui(&mut b"not a pe".to_vec()).is_err());
    }

    #[test]
    fn add_icon_appends_a_resource_section_that_round_trips() {
        for plus in [false, true] {
            let mut b = synthetic_pe(plus, 5, 3);
            let png16 = b"\x89PNG\r\n\x1a\nfake16".to_vec();
            let png256 = b"\x89PNG\r\n\x1a\nfake256-larger-payload".to_vec();
            let images = vec![IconImage { size: 16, bytes: png16.clone() }, IconImage { size: 256, bytes: png256.clone() }];
            let old_len = b.len();
            add_icon(&mut b, &images).unwrap();
            let info = parse(&b).unwrap();
            assert_eq!(info.num_sections, 6);
            assert_eq!(info.section_names.last().map(String::as_str), Some(".rsrc"));
            assert_ne!(info.resource_dir, (0, 0));
            assert_eq!(b.len() % info.file_alignment as usize, 0);
            assert!(b.len() > old_len);
            // El header de la sección nueva apunta donde dice DataDirectory[2].
            let at = info.section_headers_offset + 5 * 40;
            assert_eq!(u32_at(&b, at + 12).unwrap(), info.resource_dir.0);
            // El árbol leído de vuelta: RT_ICON 1..=2 y RT_GROUP_ICON 1, ids ascendentes.
            let root = parse_tree(&b).unwrap();
            assert_eq!(root.entries.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(), vec![ResKey::Id(RT_ICON), ResKey::Id(RT_GROUP_ICON)]);
            assert_eq!(leaf(&root, RT_ICON, 1), &png16[..]);
            assert_eq!(leaf(&root, RT_ICON, 2), &png256[..]);
            let grp = leaf(&root, RT_GROUP_ICON, 1);
            assert_eq!(&grp[..6], &[0u8, 0, 1, 0, 2, 0]);
            let e = &grp[6..];
            assert_eq!(e[0], 16);
            assert_eq!(&e[12..14], &1u16.to_le_bytes());
            assert_eq!(e[14], 0, "256 se escribe como 0");
            assert_eq!(&e[26..28], &2u16.to_le_bytes());
            // Segunda vez: se reemplazan los íconos (no se duplican), sección nueva otra vez.
            let images2 = vec![IconImage { size: 32, bytes: b"\x89PNG\r\n\x1a\nv2".to_vec() }];
            add_icon(&mut b, &images2).unwrap();
            let info2 = parse(&b).unwrap();
            assert_eq!(info2.num_sections, 7);
            let root2 = parse_tree(&b).unwrap();
            assert_eq!(root2.entries.len(), 2);
            assert_eq!(dir(&root2.entries[0].1).entries.len(), 1, "sólo el ícono nuevo");
            assert_eq!(leaf(&root2, RT_ICON, 1), b"\x89PNG\r\n\x1a\nv2");
        }
    }

    #[test]
    fn merge_keeps_foreign_resources_and_sorts_for_the_loader() {
        let mut b = synthetic_pe(true, 4, 3);
        // Un motor con manifest (id 24) y un recurso con nombre, como los compilados con GNU.
        let manifest = b"<assembly/>".to_vec();
        let existing = ResDir {
            entries: vec![
                (ResKey::Id(24), ResNode::Dir(ResDir { entries: vec![(ResKey::Id(1), lang(ResNode::Data { bytes: manifest.clone(), codepage: 0 }))] })),
                (
                    ResKey::Name("ZETA".encode_utf16().collect()),
                    ResNode::Dir(ResDir { entries: vec![(ResKey::Id(7), lang(ResNode::Data { bytes: b"z".to_vec(), codepage: 1252 }))] }),
                ),
                (
                    ResKey::Name("ALFA".encode_utf16().collect()),
                    ResNode::Dir(ResDir { entries: vec![(ResKey::Id(1), lang(ResNode::Data { bytes: b"a".to_vec(), codepage: 0 }))] }),
                ),
            ],
        };
        append_rsrc_section(&mut b, &existing).unwrap();
        let back = parse_tree(&b).unwrap();
        assert_eq!(back.entries.len(), 3);
        assert!(matches!(&back.entries[0].0, ResKey::Name(n) if n == &"ALFA".encode_utf16().collect::<Vec<_>>()));
        assert!(matches!(&back.entries[1].0, ResKey::Name(n) if n == &"ZETA".encode_utf16().collect::<Vec<_>>()));
        assert_eq!(back.entries[2].0, ResKey::Id(24));
        assert_eq!(leaf(&back, 24, 1), &manifest[..]);
        let (_, z) = &back.entries[1];
        let (_, z7) = &dir(z).entries[0];
        assert!(matches!(&dir(z7).entries[0].1, ResNode::Data { bytes, codepage: 1252 } if bytes == b"z"));
        // --icon sobre ese motor: el manifest y los nombres sobreviven; ids ascendentes 3, 14, 24.
        let images = vec![IconImage { size: 48, bytes: b"\x89PNG\r\n\x1a\nicon".to_vec() }];
        add_icon(&mut b, &images).unwrap();
        let root = parse_tree(&b).unwrap();
        let keys: Vec<ResKey> = root.entries.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(keys[2..], [ResKey::Id(RT_ICON), ResKey::Id(RT_GROUP_ICON), ResKey::Id(24)]);
        assert!(matches!(&keys[0], ResKey::Name(_)) && matches!(&keys[1], ResKey::Name(_)));
        assert_eq!(leaf(&root, 24, 1), &manifest[..]);
        assert_eq!(leaf(&root, RT_ICON, 1), b"\x89PNG\r\n\x1a\nicon");
        assert_eq!(parse(&b).unwrap().num_sections, 6);
    }

    #[test]
    fn add_icon_refuses_when_headers_are_full() {
        let mut b = synthetic_pe(true, 3, 3);
        // SizeOfHeaders justo hasta el fin de la tabla de secciones: no hay lugar.
        let info = parse(&b).unwrap();
        let opt = opt_header_offset(info.pe_offset);
        let tight = (info.section_headers_offset + 3 * 40) as u32;
        b[opt + 60..opt + 64].copy_from_slice(&tight.to_le_bytes());
        let snapshot = b.clone();
        let e = add_icon(&mut b, &[IconImage { size: 16, bytes: vec![1, 2, 3] }]).unwrap_err();
        assert!(e.contains("no room"), "{}", e);
        assert_eq!(b, snapshot, "sin tocar");
    }

    #[test]
    fn corrupt_resource_tree_is_a_clear_error() {
        let mut b = synthetic_pe(true, 3, 3);
        // DataDirectory[2] apunta a la sección 2, cuyo contenido (0xcc…) es basura: el árbol
        // "tiene" 0xcccc entradas que se salen de la sección.
        let info = parse(&b).unwrap();
        let opt = opt_header_offset(info.pe_offset);
        let d = opt + data_dir_offset(true, 2);
        b[d..d + 4].copy_from_slice(&0x3000u32.to_le_bytes());
        b[d + 4..d + 8].copy_from_slice(&0x100u32.to_le_bytes());
        let e = add_icon(&mut b, &[IconImage { size: 16, bytes: vec![1, 2, 3] }]).unwrap_err();
        assert!(e.contains("cannot read the engine's resources"), "{}", e);
    }

    #[test]
    fn ico_container_round_trips() {
        let images = vec![IconImage { size: 32, bytes: b"png-a".to_vec() }, IconImage { size: 256, bytes: b"png-b-longer".to_vec() }];
        let ico = ico_from_images(&images);
        let back = ico_images(&ico).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].size, 32);
        assert_eq!(back[0].bytes, b"png-a");
        assert_eq!(back[1].size, 256);
        assert_eq!(back[1].bytes, b"png-b-longer");
        assert!(ico_images(b"nope").is_err());
    }
}

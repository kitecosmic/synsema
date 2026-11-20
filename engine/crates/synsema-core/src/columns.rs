//! v0.6.65: el storage físico de una tabla por columnas (`specs/v0.6.65-tablas-diseno.md` §3).
//!
//! Modelo Arrow simplificado (verificado contra
//! https://arrow.apache.org/docs/format/Columnar.html): columnas de un solo tipo con bitmap de
//! validez (bit en 1 = válido, bit en 0 = null), y una tabla que es una ventana
//! `(offset, n_rows)` sobre buffers compartidos. Inmutable: ninguna operación escribe; las
//! transformaciones (`slice`, `sort_by`, `where`) devuelven tablas nuevas que comparten los
//! buffers por referencia. El contrato de lenguaje («una tabla es una LISTA DE MAPAS» hasta
//! 0.6.64) vive en `tabular.rs`; los casos decididos están en el diseño §11.

use crate::synmap::{Key, SynMap};
use crate::types::{Obj, SendColumn, SynText, SynValue};

/// Bitmap de validez: bit en 1 = válido, bit en 0 = null (`nothing`), como el buffer de validez
/// de Arrow. Sólo existe si hay algún null (sin nulls es `None`, como Arrow omite el bitmap).
#[derive(Clone, Debug, PartialEq)]
pub struct Bitmap {
    words: Vec<u64>,
    len: usize,
    nulls: usize,
}

impl Bitmap {
    /// Todo válido. La última palabra queda enmascarada a los bits reales, para que el
    /// `PartialEq` derivado compare exactamente.
    pub fn all_valid(len: usize) -> Bitmap {
        let mut words = vec![u64::MAX; len.div_ceil(64)];
        if let Some(last) = words.last_mut() {
            let rem = len % 64;
            if rem != 0 {
                *last = u64::MAX >> (64 - rem);
            }
        }
        Bitmap { words, len, nulls: 0 }
    }
    /// Todo null (una columna sin ningún valor no nulo).
    pub fn all_null(len: usize) -> Bitmap {
        Bitmap { words: vec![0; len.div_ceil(64)], len, nulls: len }
    }
    /// Marca la fila `i` como null. Idempotente.
    pub fn set_null(&mut self, i: usize) {
        debug_assert!(i < self.len);
        let bit = 1u64 << (i % 64);
        if self.words[i / 64] & bit != 0 {
            self.words[i / 64] &= !bit;
            self.nulls += 1;
        }
    }
    #[inline]
    pub fn is_null(&self, i: usize) -> bool {
        self.words[i / 64] & (1u64 << (i % 64)) == 0
    }
    #[inline]
    pub fn null_count(&self) -> usize {
        self.nulls
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// El contenido físico de una columna: un bloque de un solo tipo, más su bitmap de validez.
/// `Value` es la válvula de escape (diseño §3): Decimal, Big, `Time`, `Bytes`, mezclas y
/// valores privados; nunca se degrada un valor a un bloque menos preciso.
#[derive(Clone, Debug)]
pub enum ColumnData {
    I64(Vec<i64>, Option<Bitmap>),
    F64(Vec<f64>, Option<Bitmap>),
    /// Sólo entra por Parquet `FLOAT` (diseño §4); se materializa como `Number::Float`
    /// ensanchado (exacto).
    F32(Vec<f32>, Option<Bitmap>),
    Bool(Vec<bool>, Option<Bitmap>),
    Text(Vec<SynText>, Option<Bitmap>),
    /// null = `SynValue::Nothing` (sin bitmap).
    Value(Vec<SynValue>),
}

impl Drop for ColumnData {
    fn drop(&mut self) {
        // Sólo `Value` contiene `SynValue`s (posibles listas/mapas anidados): soltarlos por el
        // mecanismo iterativo de v0.6.62, nunca con el drop glue por nivel. Los bloques
        // primitivos no tienen hijos.
        if let ColumnData::Value(cells) = self {
            crate::value_drop::map_slots(cells);
        }
    }
}

impl ColumnData {
    pub fn len(&self) -> usize {
        match self {
            ColumnData::I64(v, _) => v.len(),
            ColumnData::F64(v, _) => v.len(),
            ColumnData::F32(v, _) => v.len(),
            ColumnData::Bool(v, _) => v.len(),
            ColumnData::Text(v, _) => v.len(),
            ColumnData::Value(v) => v.len(),
        }
    }
    /// El nombre físico de la columna (para mensajes y el hash canónico).
    pub fn kind(&self) -> &'static str {
        match self {
            ColumnData::I64(..) => "i64",
            ColumnData::F64(..) => "f64",
            ColumnData::F32(..) => "f32",
            ColumnData::Bool(..) => "bool",
            ColumnData::Text(..) => "text",
            ColumnData::Value(_) => "value",
        }
    }
}

/// Una tabla: `n_rows` filas tomadas desde `offset` de cada buffer compartido. Una vista
/// (`slice`) comparte los `Obj<ColumnData>` y sólo cambia la ventana; como la tabla es
/// inmutable (diseño §6), la vista es siempre segura.
#[derive(Clone, Debug)]
pub struct ColumnTable {
    n_rows: usize,
    offset: usize,
    cols: Vec<(Key, Obj<ColumnData>)>,
}

impl ColumnTable {
    /// Construye desde buffers ya tipados (misma longitud para todas las columnas). Sin nulos
    /// conocidos todavía: quien construye pone los bitmaps en cada `ColumnData`.
    pub fn new(cols: Vec<(Key, Obj<ColumnData>)>) -> Result<ColumnTable, String> {
        let n_rows = cols.first().map_or(0, |(_, c)| c.len());
        for (k, c) in &cols {
            if c.len() != n_rows {
                return Err(format!(
                    "table: column {:?} has {} values but the table has {} rows",
                    k.as_str(),
                    c.len(),
                    n_rows
                ));
            }
        }
        Ok(ColumnTable { n_rows, offset: 0, cols })
    }

    #[inline]
    pub fn n_rows(&self) -> usize {
        self.n_rows
    }
    #[inline]
    pub fn n_cols(&self) -> usize {
        self.cols.len()
    }
    pub fn is_empty(&self) -> bool {
        self.n_rows == 0
    }
    /// El esquema (nombres en orden de primera aparición).
    pub fn schema(&self) -> Vec<Key> {
        self.cols.iter().map(|(k, _)| k.clone()).collect()
    }
    /// La posición de una columna por nombre.
    pub fn col_index(&self, name: &str) -> Option<usize> {
        self.cols.iter().position(|(k, _)| k.as_str() == name)
    }
    /// Bloque y ventana de una columna, para operaciones que no necesitan mapas de fila.
    pub fn column_window(&self, ci: usize) -> (&ColumnData, usize, usize) {
        (&self.cols[ci].1, self.offset, self.n_rows)
    }
    /// La ventana `[from, to)` como vista que comparte buffers (copia cero).
    pub fn slice(&self, from: usize, to: usize) -> Option<ColumnTable> {
        if from > to || to > self.n_rows {
            return None;
        }
        Some(ColumnTable {
            n_rows: to - from,
            offset: self.offset + from,
            cols: self.cols.clone(),
        })
    }

    /// Una sub-tabla con las filas `indices` (en ese orden), para los grupos de
    /// `summarize`/`group_by`/`count_by`. Reúne los bloques (una copia de los datos del
    /// grupo, sin materializar mapas por fila); los nulos siguen en su bitmap.
    pub fn gather(&self, indices: &[usize]) -> ColumnTable {
        let cols = self
            .cols
            .iter()
            .map(|(k, data)| {
                let gathered = match &**data {
                    ColumnData::I64(v, nulls) => {
                        ColumnData::I64(indices.iter().map(|&i| v[self.offset + i]).collect(), shift_nulls_gather(nulls, indices, |b, i| b.is_null(self.offset + i)))
                    }
                    ColumnData::F64(v, nulls) => {
                        ColumnData::F64(indices.iter().map(|&i| v[self.offset + i]).collect(), shift_nulls_gather(nulls, indices, |b, i| b.is_null(self.offset + i)))
                    }
                    ColumnData::F32(v, nulls) => {
                        ColumnData::F32(indices.iter().map(|&i| v[self.offset + i]).collect(), shift_nulls_gather(nulls, indices, |b, i| b.is_null(self.offset + i)))
                    }
                    ColumnData::Bool(v, nulls) => {
                        ColumnData::Bool(indices.iter().map(|&i| v[self.offset + i]).collect(), shift_nulls_gather(nulls, indices, |b, i| b.is_null(self.offset + i)))
                    }
                    ColumnData::Text(v, nulls) => {
                        ColumnData::Text(indices.iter().map(|&i| v[self.offset + i].clone()).collect(), shift_nulls_gather(nulls, indices, |b, i| b.is_null(self.offset + i)))
                    }
                    ColumnData::Value(cells) => {
                        ColumnData::Value(indices.iter().map(|&i| cells[self.offset + i].clone()).collect())
                    }
                };
                (k.clone(), Obj::new(gathered))
            })
            .collect();
        ColumnTable { n_rows: indices.len(), offset: 0, cols }
    }

    /// Selecciona posiciones sin desplegar filas. `gather` conserva el tipo físico y los
    /// bitmaps, incluso cuando no se selecciona ninguna fila.
    pub fn filter_mask(&self, mask: &[bool]) -> ColumnTable {
        debug_assert_eq!(mask.len(), self.n_rows);
        let indices: Vec<usize> = mask.iter().enumerate().filter_map(|(i, keep)| keep.then_some(i)).collect();
        self.gather(&indices)
    }

    /// La celda `(fila, columna)` materializada (null → `nothing`).
    pub fn cell(&self, row: usize, col: usize) -> SynValue {
        debug_assert!(row < self.n_rows && col < self.cols.len());
        let i = self.offset + row;
        let data = &self.cols[col].1;
        match &**data {
            ColumnData::I64(v, nulls) => match nulls.as_ref() {
                Some(b) if b.is_null(i) => SynValue::Nothing,
                _ => crate::types::syn_int(v[i]),
            },
            ColumnData::F64(v, nulls) => match nulls.as_ref() {
                Some(b) if b.is_null(i) => SynValue::Nothing,
                _ => crate::types::syn_number(crate::number::Number::Float(v[i])),
            },
            ColumnData::F32(v, nulls) => match nulls.as_ref() {
                Some(b) if b.is_null(i) => SynValue::Nothing,
                _ => crate::types::syn_number(crate::number::Number::Float(v[i] as f64)),
            },
            ColumnData::Bool(v, nulls) => match nulls.as_ref() {
                Some(b) if b.is_null(i) => SynValue::Nothing,
                _ => SynValue::Bool(v[i]),
            },
            ColumnData::Text(v, nulls) => match nulls.as_ref() {
                Some(b) if b.is_null(i) => SynValue::Nothing,
                _ => SynValue::Text(v[i].clone()),
            },
            ColumnData::Value(v) => v[i].clone(),
        }
    }

    /// La fila `i` materializada como un mapa con el esquema completo (diseño §3: las claves
    /// ausentes en el origen salen como `nothing`).
    pub fn row(&self, i: usize) -> SynMap {
        let mut m = SynMap::with_capacity(self.cols.len());
        for (ci, (k, _)) in self.cols.iter().enumerate() {
            m.insert(k.clone(), self.cell(i, ci));
        }
        m
    }

    /// Despliegue completo a lista de mapas (el camino de `to_rows`).
    pub fn to_rows(&self) -> Vec<SynValue> {
        (0..self.n_rows)
            .map(|i| crate::types::syn_map(self.row(i)))
            .collect()
    }

    /// El linaje de una tabla (v0.6.65): el sha256 de la receta **"table-v1"** — el CONTENIDO
    /// por columnas, sin armar filas: `b"table-v1\0"`, filas y columnas en LE, y por columna
    /// su nombre, su tipo físico (`columns.rs::kind`) y los valores de la ventana: primitivos
    /// en LE, texto con largo LE + utf-8, bool 0/1, `Value` celda por celda con su clave
    /// canónica de agrupar (`tabular::probe_key`; una celda nula o `nothing` es "z"), y los
    /// nulos de cada bloque como cantidad LE + índices LE. Igual que la receta "ndarray" de
    /// v0.6.56: el nombre cambia si la receta cambia (los recibos viejos quedan intactos) y
    /// un tercero puede recomputarla con la definición de arriba. Devuelve (hex, bytes).
    pub fn lineage_sha256(&self) -> (String, usize) {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        let mut total = 0usize;
        macro_rules! feed {
            ($b:expr) => {{
                let b: &[u8] = $b;
                h.update(b);
                total += b.len();
            }};
        }
        feed!(b"table-v1\0");
        feed!(&self.n_rows.to_le_bytes());
        feed!(&self.cols.len().to_le_bytes());
        for (k, col) in &self.cols {
            feed!(k.as_str().as_bytes());
            feed!(b"\0");
            feed!(col.kind().as_bytes());
            feed!(b"\0");
            let i0 = self.offset;
            let i1 = self.offset + self.n_rows;
            macro_rules! nulos {
                ($nulls:expr) => {{
                    let n = match $nulls {
                        Some(b) => b.null_count(),
                        None => 0,
                    };
                    feed!(&n.to_le_bytes());
                    if let Some(b) = $nulls {
                        for i in 0..self.n_rows {
                            if b.is_null(i0 + i) {
                                feed!(&i.to_le_bytes());
                            }
                        }
                    }
                }};
            }
            match &**col {
                ColumnData::I64(v, nulls) => {
                    nulos!(nulls);
                    for x in &v[i0..i1] {
                        feed!(&x.to_le_bytes());
                    }
                }
                ColumnData::F64(v, nulls) => {
                    nulos!(nulls);
                    for x in &v[i0..i1] {
                        feed!(&x.to_le_bytes());
                    }
                }
                ColumnData::F32(v, nulls) => {
                    nulos!(nulls);
                    for x in &v[i0..i1] {
                        feed!(&x.to_le_bytes());
                    }
                }
                ColumnData::Bool(v, nulls) => {
                    nulos!(nulls);
                    for x in &v[i0..i1] {
                        feed!(&[*x as u8]);
                    }
                }
                ColumnData::Text(v, nulls) => {
                    nulos!(nulls);
                    for x in &v[i0..i1] {
                        let b = x.as_str().as_bytes();
                        feed!(&b.len().to_le_bytes());
                        feed!(b);
                    }
                }
                ColumnData::Value(cells) => {
                    for cell in &cells[i0..i1] {
                        let key = crate::tabular::probe_key(cell);
                        feed!(key.as_bytes());
                    }
                }
            }
        }
        (crate::bytesutil::hex_encode(&h.finalize()), total)
    }

    // --- Recorrido de etiquetas (labels.rs): sólo las columnas `Value` pueden contener un
    // --- `Private`; los bloques primitivos no tienen dónde colgar una etiqueta.

    /// Los índices de las columnas `Value`.
    pub fn value_columns(&self) -> Vec<usize> {
        (0..self.cols.len())
            .filter(|&ci| matches!(&*self.cols[ci].1, ColumnData::Value(_)))
            .collect()
    }

    /// La celda cruda de una columna `Value` (referencia, sin materializar). `col_pos` es la
    /// posición DENTRO de `value_columns()`, no el índice del esquema.
    pub fn value_cell_ref(&self, row: usize, col_pos: usize) -> Option<&SynValue> {
        let cols = self.value_columns();
        let ci = *cols.get(col_pos)?;
        match &*self.cols[ci].1 {
            ColumnData::Value(cells) => cells.get(self.offset + row),
            _ => None,
        }
    }

    /// El nombre de esquema de la columna de posición `col_pos` entre las `Value`.
    pub fn value_col_name(&self, col_pos: usize) -> Option<&str> {
        let cols = self.value_columns();
        let ci = *cols.get(col_pos)?;
        Some(self.cols[ci].0.as_str())
    }

    /// Recorre las celdas de las columnas `Value`, fila por fila (el orden de
    /// `value_cell_ref`). El closure devuelve `false` para cortar.
    pub fn for_each_value_cell<F>(&self, mut f: F)
    where
        F: FnMut(usize, &str, &SynValue) -> bool,
    {
        let cols = self.value_columns();
        for &ci in cols.iter() {
            let name = self.cols[ci].0.as_str();
            let ColumnData::Value(cells) = &*self.cols[ci].1 else { continue };
            for row in 0..self.n_rows {
                let Some(cell) = cells.get(self.offset + row) else { continue };
                if !f(row, name, cell) {
                    return;
                }
            }
        }
    }

    /// Reconstruye la tabla con las celdas `Value` reemplazadas (el orden de
    /// `value_cell_ref`, fila por fila sobre las columnas `Value`). Las columnas primitivas
    /// se comparten (son inmutables); las `Value` salen en un `Obj` nuevo, conservando las
    /// celdas fuera de la ventana para que el `offset` de la vista siga cuadrando.
    pub fn rebuild_values(&self, values: Vec<SynValue>) -> ColumnTable {
        let vcols = self.value_columns();
        let nv = vcols.len().max(1);
        let cols = self
            .cols
            .iter()
            .enumerate()
            .map(|(ci, (k, data))| {
                match vcols.iter().position(|&v| v == ci) {
                    Some(pos) => {
                        let ColumnData::Value(orig) = &**data else {
                            unreachable!("posición de columna Value sobre otra cosa")
                        };
                        let mut cells: Vec<SynValue> = Vec::with_capacity(orig.len());
                        cells.extend(orig[..self.offset].iter().cloned());
                        for row in 0..self.n_rows {
                            cells.push(values[row * nv + pos].clone());
                        }
                        cells.extend(orig[self.offset + self.n_rows..].iter().cloned());
                        (k.clone(), Obj::new(ColumnData::Value(cells)))
                    }
                    None => (k.clone(), data.clone()),
                }
            })
            .collect();
        ColumnTable { n_rows: self.n_rows, offset: self.offset, cols }
    }

    /// Igualdad por valor (diseño §2): mismo esquema, misma cantidad de filas y celda a celda
    /// los mismos valores con los mismos nulos. Tipos físicos distintos (una columna `I64`
    /// frente a una `Value`) no son iguales, como los dtype de un array. Un `NaN` nunca es
    /// igual a otro (como `array_equal` de numpy, `types.rs:702`). `depth` se propaga a las
    /// celdas `Value` con el mismo mecanismo de las listas (`equals_next` → `value_eq::deep`).
    pub fn equals(&self, other: &ColumnTable, depth: usize) -> bool {
        if self.n_rows != other.n_rows || self.cols.len() != other.cols.len() {
            return false;
        }
        for ((ka, ca), (kb, cb)) in self.cols.iter().zip(other.cols.iter()) {
            if ka != kb {
                return false;
            }
            if !column_equals(ca, self.offset, cb, other.offset, self.n_rows, depth) {
                return false;
            }
        }
        true
    }
}

/// Igualdad de una columna en dos ventanas.
fn column_equals(
    a: &Obj<ColumnData>,
    a_off: usize,
    b: &Obj<ColumnData>,
    b_off: usize,
    len: usize,
    depth: usize,
) -> bool {
    macro_rules! block_eq {
        ($va:expr, $na:expr, $vb:expr, $nb:expr) => {{
            let nulls_eq = match ($na, $nb) {
                (None, None) => true,
                (Some(x), Some(y)) => (0..len).all(|i| {
                    let (ia, ib) = (a_off + i, b_off + i);
                    x.is_null(ia) == y.is_null(ib)
                }),
                _ => false,
            };
            nulls_eq
                && (0..len).all(|i| {
                    let (ia, ib) = (a_off + i, b_off + i);
                    match ($na, $nb) {
                        (Some(x), _) if x.is_null(ia) => true,
                        (_, Some(y)) if y.is_null(ib) => true,
                        _ => $va[ia] == $vb[ib],
                    }
                })
        }};
    }
    match (&**a, &**b) {
        (ColumnData::I64(va, na), ColumnData::I64(vb, nb)) => block_eq!(va, na, vb, nb),
        (ColumnData::F64(va, na), ColumnData::F64(vb, nb)) => block_eq!(va, na, vb, nb),
        (ColumnData::F32(va, na), ColumnData::F32(vb, nb)) => block_eq!(va, na, vb, nb),
        (ColumnData::Bool(va, na), ColumnData::Bool(vb, nb)) => block_eq!(va, na, vb, nb),
        (ColumnData::Text(va, na), ColumnData::Text(vb, nb)) => block_eq!(va, na, vb, nb),
        (ColumnData::Value(x), ColumnData::Value(y)) => {
            x.len() == y.len()
                && (0..len).all(|i| {
                    let (ia, ib) = (a_off + i, b_off + i);
                    x[ia].equals_next_depth(&y[ib], depth)
                })
        }
        _ => false,
    }
}

/// La familia de una celda para elegir el tipo físico de la columna (`table(rows)`, diseño
/// §4): todos los no nulos de una misma familia → bloque; cualquier otra cosa → `Value`.
#[derive(Clone, Copy, PartialEq)]
enum Family {
    AllNull,
    I64,
    F64,
    Bool,
    Text,
    Mixed,
}

fn family_of(v: &SynValue) -> Option<Family> {
    match v {
        SynValue::Nothing => None,
        SynValue::Bool(_) => Some(Family::Bool),
        SynValue::Number(crate::number::Number::Int(_)) => Some(Family::I64),
        SynValue::Number(crate::number::Number::Float(_)) => Some(Family::F64),
        SynValue::Text(_) => Some(Family::Text),
        _ => Some(Family::Mixed),
    }
}

fn degrade(f: Family, seen: Option<Family>) -> Family {
    match seen {
        // Sin valores todavía (o todo null): la primera familia gana.
        None | Some(Family::AllNull) => f,
        Some(s) if s == f => s,
        // Una vez mezclada, mezclada queda (la familia nueva NO resetea).
        _ => Family::Mixed,
    }
}

/// Construye una tabla desde una lista de mapas (el camino de `table(rows)`, diseño §4).
/// Dos pasadas sobre las filas (sin acumular celdas): la primera decide el esquema y el tipo
/// físico de cada columna; la segunda llena los bloques. Esquema = unión de claves en orden
/// de primera aparición; una columna toda nula queda `F64` nulo. La búsqueda de columna es
/// lineal sobre el esquema (los esquemas son angostos).
pub fn build_from_rows(rows: &[SynValue]) -> Result<ColumnTable, String> {
    // Esquema y familias en una pasada.
    let mut schema: Vec<Key> = Vec::new();
    let mut families: Vec<Family> = Vec::new();
    for row in rows {
        let SynValue::Map(m) = row else {
            return Err(format!(
                "table: expected a list of maps, got a list with a {}",
                row.type_name()
            ));
        };
        let m = m.borrow();
        for (k, v) in m.iter() {
            let ci = match schema.iter().position(|s| s == k) {
                Some(ci) => ci,
                None => {
                    schema.push(k.clone());
                    families.push(Family::AllNull);
                    schema.len() - 1
                }
            };
            if let Some(f) = family_of(v) {
                families[ci] = degrade(f, Some(families[ci]));
            }
        }
    }
    let n = rows.len();
    let mut cols: Vec<(Key, Obj<ColumnData>)> = Vec::with_capacity(schema.len());
    for (_ci, (k, fam)) in schema.iter().zip(families.iter()).enumerate() {
        let data = match fam {
            Family::AllNull => {
                // Una columna toda nula: F64 nulo (diseño §4). No puede pasar con el esquema
                // de primera aparición (una clave vista entró con algún valor), pero se
                // mantiene como seguro.
                ColumnData::F64(vec![0.0; n], Some(Bitmap::all_null(n)))
            }
            Family::I64 => {
                let mut vals = Vec::with_capacity(n);
                let mut nulls = None;
                for row in rows {
                    if let SynValue::Map(m) = row {
                        match m.borrow().get(k) {
                            Some(SynValue::Number(crate::number::Number::Int(x))) => vals.push(*x),
                            _ => {
                                nulls.get_or_insert_with(|| Bitmap::all_valid(n)).set_null(vals.len());
                                vals.push(0);
                            }
                        }
                    }
                }
                ColumnData::I64(vals, nulls)
            }
            Family::F64 => {
                let mut vals = Vec::with_capacity(n);
                let mut nulls = None;
                for row in rows {
                    if let SynValue::Map(m) = row {
                        match m.borrow().get(k) {
                            Some(SynValue::Number(crate::number::Number::Float(x))) => {
                                vals.push(*x)
                            }
                            _ => {
                                nulls.get_or_insert_with(|| Bitmap::all_valid(n)).set_null(vals.len());
                                vals.push(0.0);
                            }
                        }
                    }
                }
                ColumnData::F64(vals, nulls)
            }
            Family::Bool => {
                let mut vals = Vec::with_capacity(n);
                let mut nulls = None;
                for row in rows {
                    if let SynValue::Map(m) = row {
                        match m.borrow().get(k) {
                            Some(SynValue::Bool(x)) => vals.push(*x),
                            _ => {
                                nulls.get_or_insert_with(|| Bitmap::all_valid(n)).set_null(vals.len());
                                vals.push(false);
                            }
                        }
                    }
                }
                ColumnData::Bool(vals, nulls)
            }
            Family::Text => {
                let mut vals: Vec<SynText> = Vec::with_capacity(n);
                let mut nulls = None;
                for row in rows {
                    if let SynValue::Map(m) = row {
                        match m.borrow().get(k) {
                            Some(SynValue::Text(x)) => vals.push(x.clone()),
                            _ => {
                                nulls.get_or_insert_with(|| Bitmap::all_valid(n)).set_null(vals.len());
                                vals.push(SynText::from(""));
                            }
                        }
                    }
                }
                ColumnData::Text(vals, nulls)
            }
            Family::Mixed => {
                let mut vals = Vec::with_capacity(n);
                for row in rows {
                    if let SynValue::Map(m) = row {
                        vals.push(m.borrow().get(k).cloned().unwrap_or(SynValue::Nothing));
                    }
                }
                ColumnData::Value(vals)
            }
        };
        cols.push((k.clone(), Obj::new(data)));
    }
    ColumnTable::new(cols)
}

// --- Snapshots (`SendValue`): la copia cruza hilos como bloques owned (diseño §9) ---

impl ColumnTable {
    /// La ventana de la columna `ci` como snapshot copiado. El bitmap se reconstruye para la
    /// ventana (no comparte bits con el buffer entero).
    pub(crate) fn send_column(&self, ci: usize, depth: usize) -> SendColumn {
        let n = self.n_rows;
        let i0 = self.offset;
        match &*self.cols[ci].1 {
            ColumnData::I64(v, nulls) => {
                SendColumn::I64(v[i0..i0 + n].to_vec(), shift_nulls(nulls, i0, n))
            }
            ColumnData::F64(v, nulls) => {
                SendColumn::F64(v[i0..i0 + n].to_vec(), shift_nulls(nulls, i0, n))
            }
            ColumnData::F32(v, nulls) => {
                SendColumn::F32(v[i0..i0 + n].to_vec(), shift_nulls(nulls, i0, n))
            }
            ColumnData::Bool(v, nulls) => {
                SendColumn::Bool(v[i0..i0 + n].to_vec(), shift_nulls(nulls, i0, n))
            }
            ColumnData::Text(v, nulls) => SendColumn::Text(
                v[i0..i0 + n].iter().map(|t| t.as_str().to_string()).collect(),
                shift_nulls(nulls, i0, n),
            ),
            ColumnData::Value(cells) => SendColumn::Value(
                cells[i0..i0 + n]
                    .iter()
                    .map(|c| crate::types::to_send_at(c, depth + 1))
                    .collect(),
            ),
        }
    }

    /// Reconstruye una tabla desde su snapshot (el lado de `from_send`). El snapshot es
    /// rectangular por construcción (se copió de una tabla válida), así que no pasa por la
    /// validación de `new`.
    pub fn from_send(n_rows: usize, cols: Vec<(String, SendColumn)>, depth: usize) -> ColumnTable {
        let cols = cols
            .into_iter()
            .map(|(k, c)| {
                let data = match c {
                    SendColumn::I64(v, n) => ColumnData::I64(v, n),
                    SendColumn::F64(v, n) => ColumnData::F64(v, n),
                    SendColumn::F32(v, n) => ColumnData::F32(v, n),
                    SendColumn::Bool(v, n) => ColumnData::Bool(v, n),
                    SendColumn::Text(v, n) => {
                        ColumnData::Text(v.into_iter().map(SynText::from).collect(), n)
                    }
                    SendColumn::Value(cells) => ColumnData::Value(
                        cells
                            .into_iter()
                            .map(|c| crate::types::from_send_at(&c, depth + 1))
                            .collect(),
                    ),
                };
                (Key::from(k.as_str()), Obj::new(data))
            })
            .collect();
        ColumnTable { n_rows: n_rows, offset: 0, cols }
    }
}

/// El bitmap del snapshot: sólo los bits de la ventana; si no queda ningún null, `None`.
fn shift_nulls(nulls: &Option<Bitmap>, offset: usize, len: usize) -> Option<Bitmap> {
    let src = nulls.as_ref()?;
    let mut out = Bitmap::all_valid(len);
    for i in 0..len {
        if src.is_null(offset + i) {
            out.set_null(i);
        }
    }
    if out.null_count() == 0 { None } else { Some(out) }
}

/// El bitmap de un `gather`: los bits de las filas reunidas, en su orden.
fn shift_nulls_gather(
    nulls: &Option<Bitmap>,
    indices: &[usize],
    is_null: impl Fn(&Bitmap, usize) -> bool,
) -> Option<Bitmap> {
    let src = nulls.as_ref()?;
    let mut out = Bitmap::all_valid(indices.len());
    for (i, &row) in indices.iter().enumerate() {
        if is_null(src, row) {
            out.set_null(i);
        }
    }
    if out.null_count() == 0 { None } else { Some(out) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SynMap, SynValue};

    fn row(pairs: &[(&str, SynValue)]) -> SynValue {
        let mut m = SynMap::new();
        for (k, v) in pairs {
            m.insert(*k, v.clone());
        }
        crate::types::syn_map(m)
    }

    fn f(x: f64) -> SynValue {
        SynValue::Number(crate::number::Number::Float(x))
    }

    fn i(x: i64) -> SynValue {
        SynValue::Number(crate::number::Number::Int(x))
    }

    /// La receta "table-v1" del linaje ve los NULOS (un null no hashea como 0.0) y la
    /// VENTANA (una vista hashea sus filas, no el buffer entero).
    #[test]
    fn table_v1_lineage_sees_nulls_and_windows() {
        let a = build_from_rows(&[
            row(&[("k", i(1)), ("v", SynValue::Nothing)]),
            row(&[("k", i(2)), ("v", f(2.5))]),
        ])
        .expect("a");
        let b = build_from_rows(&[
            row(&[("k", i(1)), ("v", f(0.0))]),
            row(&[("k", i(2)), ("v", f(2.5))]),
        ])
        .expect("b");
        assert_ne!(a.lineage_sha256(), b.lineage_sha256(), "null ≠ 0.0");

        let full = build_from_rows(&[
            row(&[("k", i(1)), ("v", f(1.5))]),
            row(&[("k", i(2)), ("v", f(2.5))]),
            row(&[("k", i(3)), ("v", f(3.5))]),
        ])
        .expect("full");
        let view = full.slice(1, 3).expect("vista");
        let tail = build_from_rows(&[
            row(&[("k", i(2)), ("v", f(2.5))]),
            row(&[("k", i(3)), ("v", f(3.5))]),
        ])
        .expect("tail");
        assert_eq!(view.lineage_sha256(), tail.lineage_sha256(), "la ventana, no el buffer");
        assert_ne!(view.lineage_sha256(), full.lineage_sha256(), "1..3 ≠ tabla entera");
    }
}

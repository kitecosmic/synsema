//! Parser propio de GGUF, sin candle.
//!
//! GGUF es el formato de llama.cpp y el que publica todo el mundo: un header con metadata tipada,
//! una tabla de tensores y los datos, casi siempre cuantizados. Leerlo nosotros es lo que saca a
//! candle del camino de los LLM locales, que es **el 90% del uso**.
//!
//! ## El formato
//!
//! ```text
//! "GGUF" | version:u32 | tensor_count:u64 | kv_count:u64
//! kv_count × ( clave:string | tipo:u32 | valor )
//! tensor_count × ( nombre:string | n_dims:u32 | dims:u64… | tipo:u32 | offset:u64 )
//! padding hasta `general.alignment` (32 por defecto)
//! datos de los tensores, en los offsets declarados
//! ```
//!
//! Todo es little-endian. Los `offset` de los tensores son **relativos al inicio del bloque de
//! datos**, no al archivo: confundirlos es el error clásico y produce pesos que son ruido.
//!
//! ## Esto es dato ajeno
//!
//! Un `.gguf` se baja de internet. Cada largo y cada offset se valida contra el tamaño real antes
//! de indexar, y los enteros se leen con aritmética chequeada: un header manipulado tiene que dar
//! un error, nunca una lectura fuera de rango ni un `panic`.

use std::collections::HashMap;

/// Tipos de valor de la metadata, tal como los numera la especificación.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValueType {
    U8 = 0,
    I8 = 1,
    U16 = 2,
    I16 = 3,
    U32 = 4,
    I32 = 5,
    F32 = 6,
    Bool = 7,
    String = 8,
    Array = 9,
    U64 = 10,
    I64 = 11,
    F64 = 12,
}

impl ValueType {
    fn from_u32(v: u32) -> Result<Self, String> {
        Ok(match v {
            0 => ValueType::U8,
            1 => ValueType::I8,
            2 => ValueType::U16,
            3 => ValueType::I16,
            4 => ValueType::U32,
            5 => ValueType::I32,
            6 => ValueType::F32,
            7 => ValueType::Bool,
            8 => ValueType::String,
            9 => ValueType::Array,
            10 => ValueType::U64,
            11 => ValueType::I64,
            12 => ValueType::F64,
            other => return Err(format!("tipo de metadata desconocido: {}", other)),
        })
    }
}

/// Un valor de metadata, ya leído.
#[derive(Clone, Debug, PartialEq)]
pub enum MetaValue {
    U64(u64),
    I64(i64),
    F64(f64),
    Bool(bool),
    String(String),
    Array(Vec<MetaValue>),
}

impl MetaValue {
    /// Los enteros se guardan normalizados a `u64`/`i64`: un conversor tipa `uint32` donde otro
    /// tipa `int32`, y quien consulta no debería tener que saberlo.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            MetaValue::U64(v) => Some(*v),
            MetaValue::I64(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            MetaValue::I64(v) => Some(*v),
            MetaValue::U64(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    pub fn as_f32(&self) -> Option<f32> {
        match self {
            MetaValue::F64(v) => Some(*v as f32),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            MetaValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            MetaValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[MetaValue]> {
        match self {
            MetaValue::Array(v) => Some(v),
            _ => None,
        }
    }
}

/// Dónde están y de qué tipo son los datos de un tensor.
#[derive(Clone, Debug)]
pub struct TensorInfo {
    pub name: String,
    pub dims: Vec<usize>,
    /// El `ggml_type` crudo. Lo interpreta `quant`.
    pub kind: u32,
    /// Offset **relativo al bloque de datos**, no al archivo.
    pub offset: u64,
}

impl TensorInfo {
    pub fn element_count(&self) -> usize {
        self.dims.iter().product()
    }
}

/// Un GGUF ya parseado: metadata y tabla de tensores. Los datos quedan sin tocar.
///
/// Deriva `Debug` porque no contiene pesos: imprimirlo es ver el header, que es justo lo que uno
/// quiere cuando un modelo no carga.
#[derive(Debug)]
pub struct GgufHeader {
    pub version: u32,
    pub metadata: HashMap<String, MetaValue>,
    pub tensors: Vec<TensorInfo>,
    /// Dónde empieza el bloque de datos dentro del archivo.
    pub data_offset: usize,
    pub alignment: usize,
}

impl GgufHeader {
    pub fn arch(&self) -> Option<&str> {
        self.metadata.get("general.architecture").and_then(|v| v.as_str())
    }

    pub fn get(&self, key: &str) -> Option<&MetaValue> {
        self.metadata.get(key)
    }

    pub fn tensor(&self, name: &str) -> Option<&TensorInfo> {
        self.tensors.iter().find(|t| t.name == name)
    }
}

/// Un lector con posición, que **nunca lee fuera de rango**: cada avance se valida.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| "largo inverosímil en el header".to_string())?;
        if end > self.bytes.len() {
            return Err(format!(
                "el archivo termina antes de lo que declara (se pidieron {} bytes en {})",
                n, self.pos
            ));
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn string(&mut self) -> Result<String, String> {
        let len = self.u64()? as usize;
        // Un largo absurdo tiene que fallar acá, no al reservar memoria.
        if len > self.bytes.len() {
            return Err(format!("cadena de {} bytes en un archivo de {}", len, self.bytes.len()));
        }
        let raw = self.take(len)?;
        String::from_utf8(raw.to_vec()).map_err(|_| "cadena que no es UTF-8".to_string())
    }

    fn value(&mut self, ty: ValueType) -> Result<MetaValue, String> {
        Ok(match ty {
            ValueType::U8 => MetaValue::U64(self.take(1)?[0] as u64),
            ValueType::I8 => MetaValue::I64(self.take(1)?[0] as i8 as i64),
            ValueType::U16 => {
                MetaValue::U64(u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64)
            }
            ValueType::I16 => {
                MetaValue::I64(i16::from_le_bytes(self.take(2)?.try_into().unwrap()) as i64)
            }
            ValueType::U32 => MetaValue::U64(self.u32()? as u64),
            ValueType::I32 => {
                MetaValue::I64(i32::from_le_bytes(self.take(4)?.try_into().unwrap()) as i64)
            }
            ValueType::F32 => {
                MetaValue::F64(f32::from_le_bytes(self.take(4)?.try_into().unwrap()) as f64)
            }
            ValueType::Bool => MetaValue::Bool(self.take(1)?[0] != 0),
            ValueType::String => MetaValue::String(self.string()?),
            ValueType::U64 => MetaValue::U64(self.u64()?),
            ValueType::I64 => {
                MetaValue::I64(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
            }
            ValueType::F64 => {
                MetaValue::F64(f64::from_le_bytes(self.take(8)?.try_into().unwrap()))
            }
            ValueType::Array => {
                let inner = ValueType::from_u32(self.u32()?)?;
                if inner == ValueType::Array {
                    return Err("arrays anidados no están en el formato".to_string());
                }
                let n = self.u64()? as usize;
                // Cada elemento ocupa al menos un byte: si no entran en el archivo, el header miente.
                if n > self.bytes.len() {
                    return Err(format!("array de {} elementos en un archivo de {} bytes", n, self.bytes.len()));
                }
                let mut items = Vec::with_capacity(n.min(4096));
                for _ in 0..n {
                    items.push(self.value(inner)?);
                }
                MetaValue::Array(items)
            }
        })
    }
}

/// Parsea el header de un GGUF. No lee los datos de los tensores.
pub fn parse_header(bytes: &[u8]) -> Result<GgufHeader, String> {
    let mut c = Cursor::new(bytes);
    if c.take(4)? != b"GGUF" {
        return Err("no es un archivo GGUF (falta el magic)".to_string());
    }
    let version = c.u32()?;
    if !(1..=3).contains(&version) {
        return Err(format!("versión de GGUF no soportada: {}", version));
    }
    let tensor_count = c.u64()? as usize;
    let kv_count = c.u64()? as usize;
    // Cotas de cordura: un header real no declara millones de tensores.
    if tensor_count > 1_000_000 || kv_count > 1_000_000 {
        return Err("el header declara una cantidad inverosímil de entradas".to_string());
    }

    let mut metadata = HashMap::with_capacity(kv_count);
    for _ in 0..kv_count {
        let key = c.string()?;
        let ty = ValueType::from_u32(c.u32()?)?;
        metadata.insert(key, c.value(ty)?);
    }

    let mut tensors = Vec::with_capacity(tensor_count);
    for _ in 0..tensor_count {
        let name = c.string()?;
        let n_dims = c.u32()? as usize;
        if n_dims == 0 || n_dims > 4 {
            return Err(format!("'{}' declara {} dimensiones", name, n_dims));
        }
        let mut dims = Vec::with_capacity(n_dims);
        for _ in 0..n_dims {
            dims.push(c.u64()? as usize);
        }
        let kind = c.u32()?;
        let offset = c.u64()?;
        tensors.push(TensorInfo { name, dims, kind, offset });
    }

    let alignment = metadata
        .get("general.alignment")
        .and_then(|v| v.as_u64())
        .filter(|a| a.is_power_of_two() && *a <= 4096)
        .unwrap_or(32) as usize;
    // El bloque de datos arranca en el próximo múltiplo del alineamiento.
    let data_offset = c.pos.div_ceil(alignment) * alignment;
    if data_offset > bytes.len() {
        return Err("el bloque de datos empieza después del final del archivo".to_string());
    }

    Ok(GgufHeader { version, metadata, tensors, data_offset, alignment })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructor de GGUF mínimos, para testear sin bajar un modelo.
    struct Builder {
        kv: Vec<u8>,
        kv_count: u64,
        tensors: Vec<u8>,
        tensor_count: u64,
    }

    impl Builder {
        fn new() -> Self {
            Builder { kv: Vec::new(), kv_count: 0, tensors: Vec::new(), tensor_count: 0 }
        }

        fn str_bytes(s: &str) -> Vec<u8> {
            let mut o = (s.len() as u64).to_le_bytes().to_vec();
            o.extend_from_slice(s.as_bytes());
            o
        }

        fn kv_string(mut self, key: &str, value: &str) -> Self {
            self.kv.extend(Self::str_bytes(key));
            self.kv.extend(8u32.to_le_bytes()); // String
            self.kv.extend(Self::str_bytes(value));
            self.kv_count += 1;
            self
        }

        fn kv_u32(mut self, key: &str, value: u32) -> Self {
            self.kv.extend(Self::str_bytes(key));
            self.kv.extend(4u32.to_le_bytes()); // U32
            self.kv.extend(value.to_le_bytes());
            self.kv_count += 1;
            self
        }

        fn kv_array_u32(mut self, key: &str, values: &[u32]) -> Self {
            self.kv.extend(Self::str_bytes(key));
            self.kv.extend(9u32.to_le_bytes()); // Array
            self.kv.extend(4u32.to_le_bytes()); // de U32
            self.kv.extend((values.len() as u64).to_le_bytes());
            for v in values {
                self.kv.extend(v.to_le_bytes());
            }
            self.kv_count += 1;
            self
        }

        fn tensor(mut self, name: &str, dims: &[u64], kind: u32, offset: u64) -> Self {
            self.tensors.extend(Self::str_bytes(name));
            self.tensors.extend((dims.len() as u32).to_le_bytes());
            for d in dims {
                self.tensors.extend(d.to_le_bytes());
            }
            self.tensors.extend(kind.to_le_bytes());
            self.tensors.extend(offset.to_le_bytes());
            self.tensor_count += 1;
            self
        }

        fn build(self) -> Vec<u8> {
            let mut o = b"GGUF".to_vec();
            o.extend(3u32.to_le_bytes());
            o.extend(self.tensor_count.to_le_bytes());
            o.extend(self.kv_count.to_le_bytes());
            o.extend(self.kv);
            o.extend(self.tensors);
            // Relleno hasta el alineamiento y un poco de datos.
            while o.len() % 32 != 0 {
                o.push(0);
            }
            o.extend(vec![0u8; 256]);
            o
        }
    }

    #[test]
    fn reads_metadata_and_tensor_table() {
        let bytes = Builder::new()
            .kv_string("general.architecture", "qwen3")
            .kv_u32("qwen3.context_length", 40960)
            .tensor("token_embd.weight", &[4, 8], 0, 0)
            .build();
        let h = parse_header(&bytes).unwrap();
        assert_eq!(h.version, 3);
        assert_eq!(h.arch(), Some("qwen3"));
        assert_eq!(h.get("qwen3.context_length").unwrap().as_u64(), Some(40960));
        assert_eq!(h.tensors.len(), 1);
        let t = h.tensor("token_embd.weight").unwrap();
        assert_eq!(t.dims, vec![4, 8]);
        assert_eq!(t.element_count(), 32);
    }

    #[test]
    fn arrays_are_read_elementwise() {
        let bytes = Builder::new().kv_array_u32("tokenizer.ggml.token_type", &[1, 3, 4]).build();
        let h = parse_header(&bytes).unwrap();
        let arr = h.get("tokenizer.ggml.token_type").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[1].as_u64(), Some(3));
    }

    /// Un conversor tipa `int32` donde otro tipa `uint32`. Quien consulta no debería enterarse.
    #[test]
    fn integers_are_normalised_across_signedness() {
        let v = MetaValue::I64(7);
        assert_eq!(v.as_u64(), Some(7));
        assert_eq!(MetaValue::U64(7).as_i64(), Some(7));
        // Un negativo no se convierte a u64 en silencio.
        assert_eq!(MetaValue::I64(-1).as_u64(), None);
    }

    #[test]
    fn data_offset_is_aligned() {
        let bytes = Builder::new().kv_string("general.architecture", "llama").build();
        let h = parse_header(&bytes).unwrap();
        assert_eq!(h.alignment, 32);
        assert_eq!(h.data_offset % 32, 0, "el bloque de datos debe estar alineado");
    }

    // -- el archivo es ajeno --

    #[test]
    fn wrong_magic_is_rejected() {
        let err = parse_header(b"NOPE\0\0\0\0").unwrap_err();
        assert!(err.contains("magic"), "{}", err);
    }

    #[test]
    fn truncated_file_is_rejected_not_panicked() {
        let bytes = Builder::new().kv_string("general.architecture", "llama").build();
        for cut in [4, 8, 16, 24, 30] {
            assert!(parse_header(&bytes[..cut]).is_err(), "cortado en {} debía fallar", cut);
        }
    }

    #[test]
    fn absurd_counts_are_rejected() {
        let mut bytes = b"GGUF".to_vec();
        bytes.extend(3u32.to_le_bytes());
        bytes.extend(u64::MAX.to_le_bytes()); // tensor_count
        bytes.extend(0u64.to_le_bytes());
        assert!(parse_header(&bytes).is_err());
    }

    #[test]
    fn absurd_string_length_is_rejected() {
        let mut bytes = b"GGUF".to_vec();
        bytes.extend(3u32.to_le_bytes());
        bytes.extend(0u64.to_le_bytes());
        bytes.extend(1u64.to_le_bytes()); // un kv
        bytes.extend(u64::MAX.to_le_bytes()); // cuya clave mide u64::MAX
        assert!(parse_header(&bytes).is_err());
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut bytes = b"GGUF".to_vec();
        bytes.extend(99u32.to_le_bytes());
        bytes.extend(0u64.to_le_bytes());
        bytes.extend(0u64.to_le_bytes());
        let err = parse_header(&bytes).unwrap_err();
        assert!(err.contains("versión"), "{}", err);
    }

    #[test]
    fn too_many_dimensions_is_rejected() {
        let bytes = Builder::new().tensor("t", &[1, 1, 1, 1, 1], 0, 0).build();
        assert!(parse_header(&bytes).is_err());
    }
}

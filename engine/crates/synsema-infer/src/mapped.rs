//! Los bytes de un modelo, mapeados en vez de copiados.
//!
//! Antes de esto, cargar un GGUF costaba **dos veces** su tamaño: una por `fs::read` y otra por la
//! copia que se quedaba cada tensor. Un archivo de 7 GB pedía 14 GB de RAM, y eso ponía fuera de
//! alcance cualquier modelo mediano en una máquina normal.
//!
//! Con `mmap` el archivo no se lee: se **mapea**. El sistema operativo trae las páginas cuando se
//! tocan y las descarta cuando hace falta memoria, así que un modelo más grande que la RAM
//! **corre igual** — despacio, porque pagina, pero corre. Es lo que hacen llama.cpp y Ollama por
//! defecto, y la razón por la que un modelo de 7 GB anda en una máquina de 8.
//!
//! ## El riesgo del mapeo, dicho de frente
//!
//! `Mmap::map` es `unsafe` por un motivo real: si alguien **modifica o trunca el archivo** mientras
//! está mapeado, la memoria que ya entregamos cambia bajo los pies, y leerla puede violar el
//! contrato de Rust o matar el proceso con SIGBUS. No es teórico: pasa si el usuario reemplaza el
//! `.gguf` mientras el servidor corre.
//!
//! Lo asumimos porque la alternativa —copiar gigabytes— cuesta el doble de memoria y descarta los
//! modelos grandes, y porque el archivo es un checkpoint que el operador eligió, no una entrada de
//! red. Quien quiera la garantía fuerte tiene [`ModelBytes::read`], que copia.

use std::path::Path;
use std::sync::Arc;

/// Los bytes de un modelo: mapeados del disco o en memoria.
pub struct ModelBytes {
    inner: Source,
}

enum Source {
    /// Mapeado: no ocupa RAM hasta que se toca.
    Mapped(memmap2::Mmap),
    /// Copiado en memoria. Para tests y para archivos que no se pueden mapear.
    Owned(Vec<u8>),
}

impl ModelBytes {
    /// Mapea el archivo. **No lo lee**: las páginas llegan cuando se usan.
    ///
    /// Si el mapeo falla —hay sistemas de archivos que no lo permiten— cae a leer el archivo
    /// entero, que funciona igual aunque cueste memoria. Es mejor arrancar lento que no arrancar.
    pub fn map(path: &Path) -> Result<Self, String> {
        let file = std::fs::File::open(path)
            .map_err(|e| format!("no se pudo abrir '{}': {}", path.display(), e))?;
        // SAFETY: ver la nota del módulo. El archivo es un checkpoint elegido por el operador; si
        // lo reemplazan mientras corre, el mapeo deja de ser válido.
        match unsafe { memmap2::Mmap::map(&file) } {
            Ok(map) => Ok(ModelBytes { inner: Source::Mapped(map) }),
            Err(_) => Self::read(path),
        }
    }

    /// Lee el archivo entero a memoria. Cuesta su tamaño, y a cambio es inmune a que lo cambien.
    pub fn read(path: &Path) -> Result<Self, String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("no se pudo leer '{}': {}", path.display(), e))?;
        Ok(ModelBytes { inner: Source::Owned(data) })
    }

    /// Desde bytes ya en memoria. Para tests.
    pub fn from_vec(data: Vec<u8>) -> Self {
        ModelBytes { inner: Source::Owned(data) }
    }

    pub fn as_slice(&self) -> &[u8] {
        match &self.inner {
            Source::Mapped(m) => m,
            Source::Owned(v) => v,
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `true` si está mapeado. Va al diagnóstico: explica por qué la RAM reportada es menor que
    /// el modelo.
    pub fn is_mapped(&self) -> bool {
        matches!(self.inner, Source::Mapped(_))
    }
}

/// Una porción de los bytes de un modelo, que **no copia**.
///
/// Es lo que se queda cada tensor: un puntero al mapa compartido más su rango. Cien tensores de un
/// modelo de 7 GB siguen ocupando 7 GB de memoria virtual y nada de memoria propia.
#[derive(Clone)]
pub struct Slice {
    source: Arc<ModelBytes>,
    start: usize,
    len: usize,
}

impl Slice {
    /// Crea la porción validando el rango contra el tamaño real.
    pub fn new(source: Arc<ModelBytes>, start: usize, len: usize) -> Result<Self, String> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| "rango inverosímil sobre el modelo".to_string())?;
        if end > source.len() {
            return Err(format!(
                "rango [{}, {}) fuera de los {} bytes del modelo",
                start,
                end,
                source.len()
            ));
        }
        Ok(Slice { source, start, len })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.source.as_slice()[self.start..self.start + self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_bytes_round_trip() {
        let b = ModelBytes::from_vec(vec![1, 2, 3]);
        assert_eq!(b.as_slice(), &[1, 2, 3]);
        assert_eq!(b.len(), 3);
        assert!(!b.is_mapped());
    }

    #[test]
    fn slices_do_not_copy_and_validate_their_range() {
        let src = Arc::new(ModelBytes::from_vec(vec![10, 20, 30, 40]));
        let s = Slice::new(src.clone(), 1, 2).unwrap();
        assert_eq!(s.as_slice(), &[20, 30]);
        // Dos porciones comparten la misma fuente: no hay copia.
        let s2 = Slice::new(src.clone(), 0, 4).unwrap();
        assert_eq!(s2.len(), 4);
        assert_eq!(Arc::strong_count(&src), 3);
    }

    #[test]
    fn out_of_range_slices_are_rejected() {
        let src = Arc::new(ModelBytes::from_vec(vec![1, 2]));
        assert!(Slice::new(src.clone(), 0, 3).is_err());
        assert!(Slice::new(src.clone(), 2, 1).is_err());
        assert!(Slice::new(src, usize::MAX, 1).is_err());
    }

    #[test]
    fn mapping_a_real_file_works_and_reads_the_same() {
        let dir = std::env::temp_dir().join("synsema-infer-mmap-test");
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("bytes.bin");
        std::fs::write(&f, b"hola mundo").unwrap();

        let mapped = ModelBytes::map(&f).unwrap();
        assert_eq!(mapped.as_slice(), b"hola mundo");
        // Y leerlo da exactamente lo mismo, que es lo que permite elegir uno u otro.
        let read = ModelBytes::read(&f).unwrap();
        assert_eq!(mapped.as_slice(), read.as_slice());
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn missing_file_is_an_error_not_a_panic() {
        assert!(ModelBytes::map(Path::new("/no/existe/modelo.gguf")).is_err());
        assert!(ModelBytes::read(Path::new("/no/existe/modelo.gguf")).is_err());
    }
}

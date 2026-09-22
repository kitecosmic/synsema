//! Lectura de GGUF: apertura, metadata tipada y acceso a los pesos.
//!
//! Diseño:
//! - **Encapsula el parser.** Hoy el parseo lo hace candle (`gguf_file::Content`), pero eso no
//!   se ve desde afuera: el resto del crate pide `architecture()`, `context_length()`,
//!   `meta_u32(…)` y no sabe quién leyó los bytes. Cuando el parser sea nuestro, cambia este
//!   archivo y nada más.
//! - **Una sola lectura por carga.** El `Content` y el reader que se usan para la metadata son
//!   los mismos que después construyen los pesos (los offsets de tensores en `Content` son
//!   absolutos, así que el reader posicionado tras el header sirve tal cual). Es la propiedad
//!   F3-C del provider original y se conserva.
//! - **Los tipos declarados varían entre conversores** (i32 donde otro puso u32): los
//!   accesores toleran ambos en vez de fallar, porque un GGUF de la calle es dato ajeno.

use std::collections::HashMap;
use std::fs::File;

use candle_core::quantized::gguf_file;

/// Un GGUF abierto: metadata parseada y el reader listo para construir pesos.
pub struct GgufFile {
    pub(crate) content: gguf_file::Content,
    pub(crate) file: File,
    path: String,
}

impl GgufFile {
    /// Abre y parsea el header. No carga pesos: eso lo hace el registro de `arch.rs`.
    pub fn open(path: &str) -> Result<Self, String> {
        let mut file = File::open(path).map_err(|e| format!("no se pudo abrir el archivo: {}", e))?;
        let content = gguf_file::Content::read(&mut file)
            .map_err(|e| format!("no es un GGUF válido: {}", e))?;
        Ok(GgufFile { content, file, path: path.to_string() })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    fn md(&self) -> &HashMap<String, gguf_file::Value> {
        &self.content.metadata
    }

    /// `general.architecture`: la clave que elige la implementación. Sin ella no se sigue —
    /// adivinar la arquitectura daría basura silenciosa, que es justo lo que no queremos.
    pub fn architecture(&self) -> Result<String, String> {
        self.md()
            .get("general.architecture")
            .and_then(|v| v.to_string().ok())
            .cloned()
            .ok_or_else(|| "GGUF sin `general.architecture` en la metadata".to_string())
    }

    /// `{arch}.context_length`, con el default histórico del provider si el GGUF no lo declara.
    pub fn context_length(&self, arch: &str) -> usize {
        self.meta_u32(&format!("{}.context_length", arch)).map(|n| n as usize).unwrap_or(4096)
    }

    pub fn meta_u32(&self, key: &str) -> Option<u32> {
        self.md().get(key).and_then(|v| v.to_u32().ok())
    }

    pub fn meta_bool(&self, key: &str) -> Option<bool> {
        self.md().get(key).and_then(|v| v.to_bool().ok())
    }

    pub fn meta_string(&self, key: &str) -> Option<String> {
        self.md().get(key).and_then(|v| v.to_string().ok()).cloned()
    }

    pub fn meta_str_vec(&self, key: &str) -> Option<Vec<String>> {
        let vals = self.md().get(key)?.to_vec().ok()?;
        let mut out = Vec::with_capacity(vals.len());
        for v in vals {
            out.push(v.to_string().ok()?.clone());
        }
        Some(out)
    }

    /// Tolera i32 y u32: el tipo declarado varía entre conversores.
    pub fn meta_i64_vec(&self, key: &str) -> Option<Vec<i64>> {
        let vals = self.md().get(key)?.to_vec().ok()?;
        let mut out = Vec::with_capacity(vals.len());
        for v in vals {
            let n = v.to_i32().map(|n| n as i64).or_else(|_| v.to_u32().map(|n| n as i64)).ok()?;
            out.push(n);
        }
        Some(out)
    }

    pub fn meta_f32_vec(&self, key: &str) -> Option<Vec<f32>> {
        let vals = self.md().get(key)?.to_vec().ok()?;
        let mut out = Vec::with_capacity(vals.len());
        for v in vals {
            out.push(v.to_f32().ok()?);
        }
        Some(out)
    }

    /// Entrega el `Content` y el reader para construir los pesos. `pub(crate)`: sólo los
    /// adaptadores de backend lo usan, y consume el `GgufFile` porque `from_gguf` toma el
    /// `Content` por valor.
    pub(crate) fn into_parts(self) -> (gguf_file::Content, File) {
        (self.content, self.file)
    }
}

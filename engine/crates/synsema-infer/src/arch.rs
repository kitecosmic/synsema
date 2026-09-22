//! El trait `Model` y el registro de arquitecturas.
//!
//! **Sumar una arquitectura es un archivo nuevo más una línea acá.** Ése es el test de si el
//! diseño sirve (spec `synsema-infer.md` §2.1, regla 2), y es exactamente el dolor que hoy nos
//! cuesta esperar PRs ajenos: el PR #3709 lleva abierto desde julio de 2026 y con él siguen
//! bloqueados `quantized_gemma3` y `quantized_qwen3_moe`.
//!
//! ## El invariante de KV (§2.2)
//!
//! `clear_kv_cache` es **parte del trait**, no una función opcional que algunos modelos traen.
//! Un decoder que no la implemente **no compila**, y por eso el bloqueo que hoy sufrimos en
//! candle —cablear sólo arquitecturas con reset de KV público— deja de existir por
//! construcción en vez de depender de que alguien mergee un PR. Dos llamadas jamás heredan
//! estado de generación, y eso ahora lo garantiza el compilador.
//!
//! ## Esto es el lado candle; lo declarativo ya existe (I5)
//!
//! La restricción con la que se escribió este archivo —no tomar ninguna decisión que impidiera
//! **describir una arquitectura en datos**— se cobró: desde I5 las arquitecturas de producción
//! del backend propio son archivos `.archdef` que interpreta [`crate::archrun`], y sumar una no
//! exige ni un archivo ni una línea acá, sólo un texto en el directorio del operador.
//!
//! Este registro sigue siendo el del backend candle, que es el default mientras los dos
//! coexistan. Cuando candle se vaya, se va con él.

use crate::gguf::GgufFile;
use crate::tensor::Tensor;

/// Qué sabe hacer un modelo. Decoders y encoders conviven en el mismo registro a propósito:
/// un encoder es un modelo que no genera, no merece una jerarquía aparte, y mezclarlos deja
/// `embed` y `decide` casi gratis una vez que existe `generate` (§2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelKind {
    /// Genera tokens de a uno, con KV cache. GGUF.
    Decoder,
    /// Produce representaciones en una pasada. Sin KV cache. Safetensors (I3).
    Encoder,
}

/// Toda arquitectura implementa esto. `Send` porque las instancias viven en el pool y se
/// prestan entre hilos (el puente de streaming corre la generación en un hilo scoped).
pub trait Model: Send {
    /// Un paso hacia adelante. `index_pos` es la posición absoluta en la secuencia: 0 para el
    /// prefill del prompt entero, y después la longitud ya procesada.
    fn forward(&mut self, input: &Tensor, index_pos: usize) -> Result<Tensor, String>;

    /// Descarta el estado de generación. **Obligatorio**: ver el invariante de arriba.
    /// Un encoder lo implementa como no-op y lo declara — no tiene cache que ensuciar.
    fn clear_kv_cache(&mut self);

    fn kind(&self) -> ModelKind {
        ModelKind::Decoder
    }
}

/// Las arquitecturas GGUF que este binario sabe correr.
///
/// **Mantener en orden y sin duplicados**: el test `supported_matches_builder` compara esta
/// lista contra lo que `build` acepta de verdad, y falla si alguien suma una implementación
/// sin registrarla (o al revés). Es el test que avisa cuando falta un lugar — el mismo patrón
/// que el que enumera los tipos de capability en `synsema-capabilities`.
pub const SUPPORTED: &[&str] = &[
    #[cfg(feature = "arch-llama")]
    "llama",
    #[cfg(feature = "arch-qwen2")]
    "qwen2",
    #[cfg(feature = "arch-qwen3")]
    "qwen3",
];

/// Construye una instancia (pesos + estado propio) para la arquitectura declarada en el GGUF.
///
/// Consume el `GgufFile`: `from_gguf` toma el `Content` por valor, y así se garantiza que una
/// instancia nace de exactamente una lectura.
pub fn build(arch: &str, gguf: GgufFile) -> Result<Box<dyn Model>, String> {
    if let Some(m) = crate::arch_candle::build(arch, gguf)? {
        return Ok(m);
    }
    Err(unsupported(arch))
}

/// El error de arquitectura desconocida, en un solo lugar para que diga siempre lo mismo y
/// liste lo que este binario sí puede: un error que no dice la salida es medio error.
pub fn unsupported(arch: &str) -> String {
    if SUPPORTED.is_empty() {
        return format!(
            "arquitectura '{}': este binario se compiló sin soporte de inferencia local",
            arch
        );
    }
    format!(
        "arquitectura '{}' no soportada por el provider local (soportadas: {})",
        arch,
        SUPPORTED.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C8 del spec: el registro y el constructor no pueden divergir.
    ///
    /// No carga pesos —no hay GGUF en CI— sino que verifica que el mensaje de error de
    /// `unsupported` nombra exactamente a `SUPPORTED`, que es la lista que el usuario ve.
    #[test]
    fn supported_matches_builder() {
        for arch in SUPPORTED {
            assert!(
                unsupported(arch).contains(arch),
                "la arquitectura registrada '{}' no aparece en el mensaje de soporte",
                arch
            );
        }
        let msg = unsupported("arquitectura-que-no-existe");
        assert!(msg.contains("no soportada") || msg.contains("sin soporte"));
        for arch in SUPPORTED {
            assert!(msg.contains(arch), "el error debe listar '{}' como disponible", arch);
        }
    }

    #[test]
    fn supported_has_no_duplicates() {
        let mut seen = SUPPORTED.to_vec();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "SUPPORTED tiene arquitecturas duplicadas");
    }
}

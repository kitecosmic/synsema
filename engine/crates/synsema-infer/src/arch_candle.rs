//! Adaptadores sobre las arquitecturas cuantizadas de candle.
//!
//! **Este archivo es temporal por diseño y se borra entero en I4.** Está aparte de los
//! `arch_<familia>.rs` justo para eso: un archivo = "todo lo que todavía delega en candle",
//! y los nombres `arch_llama.rs`, `arch_qwen3.rs`, … quedan libres para las implementaciones
//! propias. Mientras exista, `git diff --stat` sobre él dice cuánto falta para la mudanza.
//!
//! Lo único que hace cada adaptador es envolver un `ModelWeights` de candle y cumplir el trait
//! `Model`. Fijate que el invariante de KV (§2.2) **ya se cumple solo**: estas tres
//! arquitecturas están acá y no otras porque son las que candle expone con `clear_kv_cache()`
//! público. Cuando la implementación sea nuestra, el trait deja de ser un filtro de lo que
//! candle nos concede y pasa a ser una condición que escribimos nosotros.

use crate::arch::{Model, ModelKind};
use crate::gguf::GgufFile;
use crate::tensor::Tensor;

use crate::backend_candle::device;

#[cfg(feature = "arch-llama")]
use candle_transformers::models::quantized_llama;
#[cfg(feature = "arch-qwen2")]
use candle_transformers::models::quantized_qwen2;
#[cfg(feature = "arch-qwen3")]
use candle_transformers::models::quantized_qwen3;

/// Genera el wrapper y su `impl Model` para un `ModelWeights` de candle. Los tres son idénticos
/// salvo el tipo, y escribirlos a mano sería invitar a que uno quede sin `clear_kv_cache`.
macro_rules! candle_decoder {
    ($name:ident, $weights:ty) => {
        struct $name($weights);

        impl Model for $name {
            fn forward(&mut self, input: &Tensor, index_pos: usize) -> Result<Tensor, String> {
                self.0
                    .forward(input.inner(), index_pos)
                    .map(Tensor::wrap)
                    .map_err(|e| format!("forward: {}", e))
            }

            fn clear_kv_cache(&mut self) {
                self.0.clear_kv_cache();
            }

            fn kind(&self) -> ModelKind {
                ModelKind::Decoder
            }
        }
    };
}

#[cfg(feature = "arch-llama")]
candle_decoder!(LlamaModel, quantized_llama::ModelWeights);
#[cfg(feature = "arch-qwen2")]
candle_decoder!(Qwen2Model, quantized_qwen2::ModelWeights);
#[cfg(feature = "arch-qwen3")]
candle_decoder!(Qwen3Model, quantized_qwen3::ModelWeights);

/// Construye la instancia si la arquitectura es una de las que candle nos da.
///
/// `Ok(None)` significa "no es mía", no "falló": `arch::build` decide entonces el error, que
/// vive en un solo lugar para que siempre liste las mismas arquitecturas disponibles.
pub(crate) fn build(arch: &str, gguf: GgufFile) -> Result<Option<Box<dyn Model>>, String> {
    // Chequear ANTES de consumir el GGUF: así una arquitectura desconocida no paga la lectura.
    if !matches!(arch, "llama" | "qwen2" | "qwen3") {
        return Ok(None);
    }
    let device = device();
    let (content, mut file) = gguf.into_parts();
    let model: Box<dyn Model> = match arch {
        #[cfg(feature = "arch-llama")]
        "llama" => Box::new(LlamaModel(
            quantized_llama::ModelWeights::from_gguf(content, &mut file, &device)
                .map_err(weights_error)?,
        )),
        #[cfg(feature = "arch-qwen2")]
        "qwen2" => Box::new(Qwen2Model(
            quantized_qwen2::ModelWeights::from_gguf(content, &mut file, &device)
                .map_err(weights_error)?,
        )),
        #[cfg(feature = "arch-qwen3")]
        "qwen3" => Box::new(Qwen3Model(
            quantized_qwen3::ModelWeights::from_gguf(content, &mut file, &device)
                .map_err(weights_error)?,
        )),
        // La arquitectura existe pero este binario se compiló sin su feature.
        _ => return Ok(None),
    };
    Ok(Some(model))
}

fn weights_error(e: candle_core::Error) -> String {
    format!("no se pudieron cargar los pesos: {}", e)
}

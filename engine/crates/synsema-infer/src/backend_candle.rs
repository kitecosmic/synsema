//! Backend candle: el inquilino de hoy.
//!
//! **Es temporal a propósito** (spec `synsema-infer.md` §0): candle es de Hugging Face, que
//! NVIDIA acordó comprar el 2026-09-02. El plan no es arrancarlo mañana —funciona y está
//! probado— sino que viva detrás de `backend.rs` para que la mudanza de I4 no toque nada más.
//!
//! **Dónde puede aparecer candle, y dónde no.** Los archivos que lo nombran son este, su par
//! `arch_candle.rs`, y tres puntos de contacto acotados: el alias `Inner` de `tensor.rs`, el
//! parser de `gguf.rs` y el `LogitsProcessor` de `sampling.rs`. Los tres están encapsulados
//! detrás de tipos propios, así que migrarlos es cambiar esos archivos y nada más. Lo que NO
//! puede pasar nunca es que aparezca en `lib.rs`: ahí se rompería la regla 3 y la mudanza de I4
//! dejaría de ser posible (criterio C2 del spec, que se verifica con un `grep`).

use candle_core::{Device, Tensor as CandleTensor};

use crate::tensor::Tensor;

pub(crate) const NAME: &str = "candle";

/// El dispositivo de cálculo. CPU y sólo CPU: la GPU está fuera del alcance a conciencia
/// (spec §8) — son años-persona y competir de frente con NVIDIA en su terreno.
pub(crate) fn device() -> Device {
    Device::Cpu
}

pub(crate) fn tensor_from_token_ids(ids: &[u32]) -> Result<Tensor, String> {
    CandleTensor::new(ids, &device())
        .and_then(|t| t.unsqueeze(0))
        .map(Tensor::wrap)
        .map_err(|e| format!("no se pudo armar el tensor de entrada: {}", e))
}

pub(crate) fn squeeze_batch(t: &Tensor) -> Result<Tensor, String> {
    t.inner()
        .squeeze(0)
        .map(Tensor::wrap)
        .map_err(|e| format!("no se pudo quitar la dimensión de batch: {}", e))
}

pub(crate) fn to_f32_vec(t: &Tensor) -> Result<Vec<f32>, String> {
    t.inner()
        .to_dtype(candle_core::DType::F32)
        .and_then(|t| t.flatten_all())
        .and_then(|t| t.to_vec1::<f32>())
        .map_err(|e| format!("no se pudieron leer los valores del tensor: {}", e))
}

pub(crate) fn shape_of(t: &Tensor) -> Vec<usize> {
    t.inner().dims().to_vec()
}

//! El backend de cálculo: quién hace las cuentas, y el punto único donde se elige.
//!
//! Diseño (spec `synsema-infer.md` §2.1 y §6):
//! - **Punto único de despacho.** Todo lo que toca al backend pasa por acá. `tensor.rs` llama
//!   a estas funciones; las arquitecturas llaman a `tensor.rs`. Nadie más.
//! - **Hoy hay un solo backend (candle) y el despacho es por `cfg`.** No hay un `trait Backend`
//!   con veinte operaciones porque sería adivinar: las operaciones de verdad (matmul, softmax,
//!   RoPE, RMSNorm, SwiGLU) recién aparecen en I4, cuando `backend_rust.rs` implemente
//!   arquitecturas propias. Un trait escrito antes de tener un segundo implementador se
//!   escribe mal, y el spec ya fija ese criterio para `archdef` (§2.4); vale igual acá.
//! - **I4 convierte esto en despacho de verdad**, y no sólo entre backends: el binario oficial
//!   hoy corre el camino escalar porque candle se compila sin AVX2 (`.synsema-skill/llm.md:205`).
//!   La detección de AVX2/AVX-512/NEON al arrancar vive en este archivo cuando llegue.
//!
//! Mientras tanto, la superficie es chica a propósito: las arquitecturas de I1 son adaptadores
//! sobre los modelos de candle (`arch_candle.rs`), que hacen su `forward` adentro. Lo único que
//! el crate necesita del backend es armar la entrada y desarmar los logits.

use crate::tensor::Tensor;

use crate::backend_candle as active;

/// Nombre del backend activo. Va al audit y a `llm status`: cuando en I4 coexistan dos,
/// esto es lo que dice cuál corrió.
pub fn name() -> &'static str {
    active::NAME
}

/// `[n]` → `[1, n]` en el dispositivo por defecto. Ver `Tensor::from_token_ids`.
pub(crate) fn tensor_from_token_ids(ids: &[u32]) -> Result<Tensor, String> {
    active::tensor_from_token_ids(ids)
}

/// `[1, n]` → `[n]`. Ver `Tensor::squeeze_batch`.
pub(crate) fn squeeze_batch(t: &Tensor) -> Result<Tensor, String> {
    active::squeeze_batch(t)
}

/// Los valores como `f32`. Ver `Tensor::to_f32_vec`.
pub(crate) fn to_f32_vec(t: &Tensor) -> Result<Vec<f32>, String> {
    active::to_f32_vec(t)
}

/// Forma del tensor, sólo para `Debug` y mensajes de error.
pub(crate) fn shape_of(t: &Tensor) -> Vec<usize> {
    active::shape_of(t)
}

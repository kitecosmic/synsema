//! El tipo `Tensor` de la casa: la frontera entre las arquitecturas y el backend.
//!
//! Diseño (spec `synsema-infer.md` §2.1, reglas 1 y 3):
//! - **Es opaco hacia afuera.** `lib.rs` lo reexporta, pero nadie fuera del crate puede
//!   sacarle el tensor del backend: el campo es `pub(crate)`. Ésa es la mitad de la regla
//!   de "cero candle en la API pública" que el compilador puede vigilar sola.
//! - **Un `arch_*.rs` habla con este módulo y con nada más.** Nunca con `backend_*`. Por eso
//!   las operaciones se piden acá y no al backend directamente.
//! - En I1 el backend es candle y `Inner` es su tensor. En I4 pasa a ser el nuestro **sin que
//!   ninguna arquitectura se entere**, que es el punto entero de este archivo.

use crate::backend;

/// El tensor del backend activo. Alias interno: cambiarlo es cambiar de backend.
pub(crate) type Inner = candle_core::Tensor;

/// Tensor de Synsema. Opaco: se construye y se opera sólo por los métodos de acá.
#[derive(Clone)]
pub struct Tensor(pub(crate) Inner);

impl Tensor {
    /// Envuelve un tensor del backend. `pub(crate)`: sólo los adaptadores del backend lo usan.
    pub(crate) fn wrap(inner: Inner) -> Self {
        Tensor(inner)
    }

    /// Presta el tensor del backend. `pub(crate)` por la misma razón que `wrap`.
    pub(crate) fn inner(&self) -> &Inner {
        &self.0
    }

    /// Crea un tensor 1-D de ids de token en el dispositivo por defecto (CPU) y le agrega
    /// la dimensión de batch: `[n]` → `[1, n]`. Es la única forma en que las arquitecturas
    /// arman su entrada, y por eso no necesitan conocer el dispositivo.
    pub fn from_token_ids(ids: &[u32]) -> Result<Self, String> {
        backend::tensor_from_token_ids(ids)
    }

    /// Saca la dimensión de batch: `[1, n]` → `[n]`. Se usa sobre los logits antes de samplear.
    pub fn squeeze_batch(&self) -> Result<Self, String> {
        backend::squeeze_batch(self)
    }

    /// Los valores como `f32`. Es la frontera por donde los dos backends se encuentran: el
    /// sampler trabaja sobre `&[f32]` y no sabe de tensores de nadie.
    pub fn to_f32_vec(&self) -> Result<Vec<f32>, String> {
        backend::to_f32_vec(self)
    }
}

impl std::fmt::Debug for Tensor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Sin volcar los datos: un tensor de logits tiene decenas de miles de floats.
        write!(f, "Tensor({:?})", backend::shape_of(self))
    }
}

//! El modelo de Laya: encoder ModernBERT más las cabezas de decisión.
//!
//! **Temporal como su hermano `arch_candle.rs`**: el encoder lo corre candle
//! (`candle_transformers::models::modernbert`) y las cabezas están escritas con `candle_nn`.
//! En I4, cuando exista `backend_rust`, este archivo se reescribe contra las ops propias y el
//! resto del crate no se entera.
//!
//! ## Qué corre, y qué no
//!
//! El checkpoint trae cuatro piezas: el encoder, una cabeza de decisión de dos capas, un
//! `scorer` que puntúa cada marcador, y un `act_head` que estima si conviene escalar. **Acá se
//! implementan las tres primeras.** El `act_head` queda fuera a conciencia: es una rama paralela
//! que no toca los logits —la respuesta es idéntica con o sin él— y el contrato de `judge` de
//! Synsema no expone una probabilidad de acción (`specs/system-one-judge.md` §4.2). Implementarlo
//! costaría `sort`, `stack` y las features de entropía para un número que nadie puede leer. Si
//! algún día el lenguaje lo expone, se agrega.
//!
//! ## Dos detalles del checkpoint que hay que respetar
//!
//! - **Los pesos se llaman `encoder.*` y candle busca `model.*`.** Se renombran al cargar; es la
//!   única traducción y vive en un solo lugar (`load`).
//! - **`self_attn.in_proj_weight` es un tensor fusionado** de query, key y value (`3·dims × dims`),
//!   como el `MultiheadAttention` de PyTorch. Se parte en tres al usarlo, no al cargarlo, para que
//!   los nombres del checkpoint no haya que tocarlos.

use std::collections::HashMap;

use candle_core::{DType, Device, IndexOp, Tensor, D};
use candle_nn::{ops::softmax_last_dim, Embedding, LayerNorm, Linear, Module, VarBuilder};
use candle_transformers::models::modernbert;

use crate::laya::AgentConfig;

/// Todo se corre en `f32` aunque el checkpoint sea `f16`: en CPU la media precisión se emula y
/// sale más lento, además de perder exactitud en la softmax de la calibración. El upstream
/// también ofrece `float32` para “closer agreement with upstream FP32 arithmetic”.
const RUN_DTYPE: DType = DType::F32;

/// Una capa de la cabeza de decisión: self-attention más MLP, ambas post-norm residuales.
struct HeadLayer {
    in_proj: Linear,
    out_proj: Linear,
    norm1: LayerNorm,
    norm2: LayerNorm,
    linear1: Linear,
    linear2: Linear,
    num_heads: usize,
    head_dim: usize,
}

impl HeadLayer {
    fn load(vb: &VarBuilder, prefix: &str, dims: usize) -> candle_core::Result<Self> {
        // Mismo criterio que el upstream: una cabeza cada 64 dimensiones, al menos una.
        let num_heads = std::cmp::max(1, dims / 64);
        let head_dim = dims / num_heads;
        let p = |name: &str| format!("{}.{}", prefix, name);

        // `in_proj_weight` / `in_proj_bias` van fusionados, sin el punto que usaría un submódulo.
        let in_w = vb.get((3 * dims, dims), &p("self_attn.in_proj_weight"))?;
        let in_b = vb.get(3 * dims, &p("self_attn.in_proj_bias"))?;
        let out_w = vb.get((dims, dims), &p("self_attn.out_proj.weight"))?;
        let out_b = vb.get(dims, &p("self_attn.out_proj.bias"))?;

        Ok(HeadLayer {
            in_proj: Linear::new(in_w, Some(in_b)),
            out_proj: Linear::new(out_w, Some(out_b)),
            norm1: layer_norm(vb, &p("norm1"), dims)?,
            norm2: layer_norm(vb, &p("norm2"), dims)?,
            linear1: linear(vb, &p("linear1"), 4 * dims, dims)?,
            linear2: linear(vb, &p("linear2"), dims, 4 * dims)?,
            num_heads,
            head_dim,
        })
    }

    /// `mask` viene como aditivo `[b, 1, 1, seq]` (0 donde se puede mirar, muy negativo donde no).
    fn forward(&self, xs: &Tensor, mask: &Tensor) -> candle_core::Result<Tensor> {
        let xs = (xs + self.attention(&self.norm1.forward(xs)?, mask)?)?;
        // El `TransformerEncoderLayer` de PyTorch usa ReLU por defecto, aunque el encoder y el
        // scorer usen GELU. No es un descuido del upstream: es el default que heredó el
        // entrenamiento, y cambiarlo acá rompería la paridad.
        let mlp = self.linear2.forward(&self.linear1.forward(&self.norm2.forward(&xs)?)?.relu()?)?;
        xs.add(&mlp)
    }

    fn attention(&self, xs: &Tensor, mask: &Tensor) -> candle_core::Result<Tensor> {
        let (b, len, dims) = xs.dims3()?;
        let qkv = self.in_proj.forward(xs)?.reshape((b, len, 3, self.num_heads, self.head_dim))?;
        // [b, len, 3, h, d] -> tres de [b, h, len, d]
        let split = |i: usize| -> candle_core::Result<Tensor> {
            qkv.i((.., .., i))?.transpose(1, 2)?.contiguous()
        };
        let (q, k, v) = (split(0)?, split(1)?, split(2)?);
        let scale = (self.head_dim as f64).powf(-0.5);
        let scores = (q.matmul(&k.transpose(D::Minus2, D::Minus1)?)? * scale)?;
        let scores = scores.broadcast_add(mask)?;
        let probs = softmax_last_dim(&scores)?;
        let out = probs.matmul(&v)?;
        let out = out.transpose(1, 2)?.reshape((b, len, dims))?;
        self.out_proj.forward(&out)
    }
}

/// El modelo completo, listo para puntuar marcadores.
pub struct LayaModel {
    encoder: modernbert::ModernBert,
    type_emb: Embedding,
    head: Vec<HeadLayer>,
    scorer_norm: LayerNorm,
    scorer_in: Linear,
    scorer_out: Linear,
    device: Device,
}

impl LayaModel {
    /// Carga el checkpoint. `weights` son los tensores tal como vienen del `.safetensors`, con sus
    /// nombres originales.
    pub fn load(
        weights: HashMap<String, Tensor>,
        encoder_config: &modernbert::Config,
        agent: &AgentConfig,
        device: &Device,
    ) -> candle_core::Result<Self> {
        let dims = encoder_config.hidden_size;

        // La única traducción de nombres: candle busca el encoder bajo `model.`, el checkpoint lo
        // guarda bajo `encoder.`. Todo lo demás conserva su nombre.
        let mut renamed: HashMap<String, Tensor> = HashMap::with_capacity(weights.len());
        for (name, tensor) in weights {
            let tensor = tensor.to_dtype(RUN_DTYPE)?.to_device(device)?;
            let key = match name.strip_prefix("encoder.") {
                Some(rest) => format!("model.{}", rest),
                None => name,
            };
            renamed.insert(key, tensor);
        }

        let vb = VarBuilder::from_tensors(renamed, RUN_DTYPE, device);
        let encoder = modernbert::ModernBert::load(vb.clone(), encoder_config)?;
        let type_emb = Embedding::new(vb.get((3, dims), "type_emb.weight")?, dims);

        let mut head = Vec::with_capacity(agent.head_layers);
        for i in 0..agent.head_layers {
            head.push(HeadLayer::load(&vb, &format!("head.layers.{}", i), dims)?);
        }

        // El `scorer` es un `nn.Sequential`: 0 LayerNorm, 1 Linear, 2 GELU (sin pesos), 3 Linear.
        // Por eso el salto del índice 2 al 3.
        Ok(LayaModel {
            encoder,
            type_emb,
            head,
            scorer_norm: layer_norm(&vb, "scorer.0", dims)?,
            scorer_in: linear(&vb, "scorer.1", dims, dims)?,
            scorer_out: linear(&vb, "scorer.3", 1, dims)?,
            device: device.clone(),
        })
    }

    /// Puntúa los marcadores de **una** secuencia y devuelve un logit por opción.
    ///
    /// Se corre de a una pregunta por vez: es lo que necesita `judge`, y evita el padding a la
    /// secuencia más larga del lote, que en CPU cuesta más de lo que ahorra.
    pub fn score_markers(
        &self,
        ids: &[u32],
        markers: &[usize],
        qtype: usize,
    ) -> candle_core::Result<Vec<f32>> {
        let len = ids.len();
        let input = Tensor::new(ids, &self.device)?.reshape((1, len))?;
        // Sin padding no hay nada que enmascarar: todos los tokens son válidos.
        let attention = Tensor::ones((1, len), RUN_DTYPE, &self.device)?;

        let hidden = self.encoder.forward(&input, &attention)?;

        // El tipo de pregunta entra como un sesgo constante sobre toda la secuencia.
        let qtype_id = Tensor::new(&[qtype as u32], &self.device)?;
        let type_vec = self.type_emb.forward(&qtype_id)?.unsqueeze(1)?;
        let mut hidden = hidden.broadcast_add(&type_vec)?;

        // Máscara aditiva para la cabeza: acá tampoco hay padding, así que es todo ceros.
        let mask = Tensor::zeros((1, 1, 1, len), RUN_DTYPE, &self.device)?;
        for layer in &self.head {
            hidden = layer.forward(&hidden, &mask)?;
        }

        // Un vector por marcador, y de ahí un escalar por opción.
        let idx: Vec<u32> = markers.iter().map(|&m| m as u32).collect();
        let picked = hidden.i(0)?.index_select(&Tensor::new(idx.as_slice(), &self.device)?, 0)?;
        let scored = self.scorer_out.forward(
            &self.scorer_in.forward(&self.scorer_norm.forward(&picked)?)?.gelu_erf()?,
        )?;
        scored.squeeze(D::Minus1)?.to_dtype(DType::F32)?.to_vec1::<f32>()
    }
}

fn linear(vb: &VarBuilder, prefix: &str, out: usize, inp: usize) -> candle_core::Result<Linear> {
    let w = vb.get((out, inp), &format!("{}.weight", prefix))?;
    let b = vb.get(out, &format!("{}.bias", prefix))?;
    Ok(Linear::new(w, Some(b)))
}

/// Las normas de las cabezas **sí** llevan bias, a diferencia de las del encoder
/// (`norm_bias: false` en su config). Cargar una por la otra no falla: da números mal.
fn layer_norm(vb: &VarBuilder, prefix: &str, dims: usize) -> candle_core::Result<LayerNorm> {
    let w = vb.get(dims, &format!("{}.weight", prefix))?;
    let b = vb.get(dims, &format!("{}.bias", prefix))?;
    Ok(LayerNorm::new(w, b, 1e-5))
}

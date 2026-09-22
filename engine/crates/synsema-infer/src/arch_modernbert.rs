//! ModernBERT y las cabezas de Laya, **escritos por nosotros**.
//!
//! Éste es el archivo que hace que I4 valga la pena: el mismo modelo que corre `arch_candle_laya.rs`,
//! sin candle. Cuando pase los goldens contra aquél, `arch_candle_laya.rs` y `arch_candle.rs` se
//! borran y la dependencia se va con ellos.
//!
//! ## La arquitectura, en una pasada
//!
//! ```text
//! ids → embedding → norm
//!     → 28 capas:  norm → atención (RoPE, global o local) → residual
//!                  norm → MLP (GELU con compuerta)        → residual
//!     → norm final
//!     → + sesgo del tipo de pregunta
//!     → 2 capas de decisión (atención + MLP con ReLU)
//!     → tomar las filas de los marcadores → scorer → un logit por opción
//! ```
//!
//! ## Los tres detalles donde un port se equivoca en silencio
//!
//! 1. **La capa 0 no tiene `attn_norm`.** En el checkpoint ese tensor directamente no está, porque
//!    upstream usa una identidad. Si uno "arregla" eso cargando otra norma, el modelo corre y
//!    responde mal.
//! 2. **RoPE tiene dos bases**: 160000 en las capas de atención global y 10000 en las locales. Es
//!    la clave del contexto largo de ModernBERT, y usar una sola base no falla: degrada.
//! 3. **Las normas del encoder NO llevan bias; las de las cabezas SÍ.** El checkpoint lo refleja
//!    (no hay `encoder.*.norm.bias` y sí hay `head.*.norm1.bias`), pero un cargador descuidado
//!    pondría ceros y nadie lo notaría hasta comparar números.

use std::collections::HashMap;

use crate::backend_rust as ops;
use crate::laya::AgentConfig;
use crate::tensor_rust::RTensor;

/// La configuración del encoder, leída de `encoder/config.json`.
#[derive(Clone, Debug)]
pub struct EncoderConfig {
    pub vocab_size: usize,
    pub hidden_size: usize,
    pub intermediate_size: usize,
    pub num_hidden_layers: usize,
    pub num_attention_heads: usize,
    pub norm_eps: f32,
    pub local_attention: usize,
    pub global_attn_every_n_layers: usize,
    pub global_rope_theta: f32,
    pub local_rope_theta: f32,
}

impl EncoderConfig {
    pub fn head_dim(&self) -> usize {
        self.hidden_size / self.num_attention_heads
    }

    /// Una capa es de atención **global** cuando su índice es múltiplo de
    /// `global_attn_every_n_layers`; el resto son locales. Es la regla del upstream y la misma que
    /// aplica candle.
    pub fn is_global(&self, layer: usize) -> bool {
        layer % self.global_attn_every_n_layers == 0
    }

    pub fn from_json(v: &serde_json::Value) -> Result<Self, String> {
        let model_type = v.get("model_type").and_then(|x| x.as_str()).unwrap_or("");
        if model_type != "modernbert" {
            return Err(format!(
                "encoder '{}' no soportado; Laya usa modernbert",
                if model_type.is_empty() { "(sin declarar)" } else { model_type }
            ));
        }
        let usize_of = |f: &str| -> Result<usize, String> {
            v.get(f)
                .and_then(|x| x.as_u64())
                .map(|n| n as usize)
                .ok_or_else(|| format!("el config del encoder no declara `{}`", f))
        };
        let rope = |kind: &str, fallback: f32| -> f32 {
            v.get("rope_parameters")
                .and_then(|r| r.get(kind))
                .and_then(|r| r.get("rope_theta"))
                .and_then(|x| x.as_f64())
                .map(|n| n as f32)
                .unwrap_or(fallback)
        };
        let cfg = EncoderConfig {
            vocab_size: usize_of("vocab_size")?,
            hidden_size: usize_of("hidden_size")?,
            intermediate_size: usize_of("intermediate_size")?,
            num_hidden_layers: usize_of("num_hidden_layers")?,
            num_attention_heads: usize_of("num_attention_heads")?,
            norm_eps: v
                .get("norm_eps")
                .or_else(|| v.get("layer_norm_eps"))
                .and_then(|x| x.as_f64())
                .unwrap_or(1e-5) as f32,
            local_attention: usize_of("local_attention")?,
            global_attn_every_n_layers: usize_of("global_attn_every_n_layers")?,
            global_rope_theta: rope("full_attention", 160_000.0),
            local_rope_theta: rope("sliding_attention", 10_000.0),
        };
        if cfg.hidden_size % cfg.num_attention_heads != 0 || cfg.head_dim() % 2 != 0 {
            return Err("ModernBERT necesita una dimensión de cabeza entera y par".to_string());
        }
        if v.get("hidden_activation").and_then(|x| x.as_str()).unwrap_or("gelu") != "gelu" {
            return Err("sólo se soporta la activación gelu del encoder".to_string());
        }
        Ok(cfg)
    }
}

/// Una capa del encoder. Sin bias en ningún lado: así viene ModernBERT.
struct EncoderLayer {
    /// `None` en la capa 0, donde upstream usa la identidad.
    attn_norm: Option<RTensor>,
    wqkv: RTensor,
    wo: RTensor,
    mlp_norm: RTensor,
    mlp_wi: RTensor,
    mlp_wo: RTensor,
    is_global: bool,
}

/// Una capa de decisión de Laya: atención más MLP, ambas con bias y normas con bias.
struct DecisionLayer {
    in_proj_w: RTensor,
    in_proj_b: RTensor,
    out_proj_w: RTensor,
    out_proj_b: RTensor,
    norm1_w: RTensor,
    norm1_b: RTensor,
    norm2_w: RTensor,
    norm2_b: RTensor,
    lin1_w: RTensor,
    lin1_b: RTensor,
    lin2_w: RTensor,
    lin2_b: RTensor,
    num_heads: usize,
    head_dim: usize,
}

/// El modelo completo, en Rust puro.
pub struct LayaRustModel {
    cfg: EncoderConfig,
    tok_embeddings: RTensor,
    emb_norm: RTensor,
    layers: Vec<EncoderLayer>,
    final_norm: RTensor,
    type_emb: RTensor,
    head: Vec<DecisionLayer>,
    scorer_norm_w: RTensor,
    scorer_norm_b: RTensor,
    scorer_in_w: RTensor,
    scorer_in_b: RTensor,
    scorer_out_w: RTensor,
    scorer_out_b: RTensor,
}

impl LayaRustModel {
    /// Arma el modelo desde los tensores del checkpoint, con sus nombres originales.
    pub fn load(
        mut w: HashMap<String, RTensor>,
        cfg: EncoderConfig,
        agent: &AgentConfig,
    ) -> Result<Self, String> {
        let take = |w: &mut HashMap<String, RTensor>, name: &str| -> Result<RTensor, String> {
            w.remove(name).ok_or_else(|| format!("falta el tensor '{}' en el checkpoint", name))
        };

        let mut layers = Vec::with_capacity(cfg.num_hidden_layers);
        for i in 0..cfg.num_hidden_layers {
            let p = format!("encoder.layers.{}", i);
            // La capa 0 no trae `attn_norm`: es la identidad, no un tensor que falte.
            let attn_norm = w.remove(&format!("{}.attn_norm.weight", p));
            if i > 0 && attn_norm.is_none() {
                return Err(format!("falta '{}.attn_norm.weight'", p));
            }
            layers.push(EncoderLayer {
                attn_norm,
                wqkv: take(&mut w, &format!("{}.attn.Wqkv.weight", p))?,
                wo: take(&mut w, &format!("{}.attn.Wo.weight", p))?,
                mlp_norm: take(&mut w, &format!("{}.mlp_norm.weight", p))?,
                mlp_wi: take(&mut w, &format!("{}.mlp.Wi.weight", p))?,
                mlp_wo: take(&mut w, &format!("{}.mlp.Wo.weight", p))?,
                is_global: cfg.is_global(i),
            });
        }

        let dims = cfg.hidden_size;
        let num_heads = std::cmp::max(1, dims / 64);
        let mut head = Vec::with_capacity(agent.head_layers);
        for i in 0..agent.head_layers {
            let p = format!("head.layers.{}", i);
            head.push(DecisionLayer {
                in_proj_w: take(&mut w, &format!("{}.self_attn.in_proj_weight", p))?,
                in_proj_b: take(&mut w, &format!("{}.self_attn.in_proj_bias", p))?,
                out_proj_w: take(&mut w, &format!("{}.self_attn.out_proj.weight", p))?,
                out_proj_b: take(&mut w, &format!("{}.self_attn.out_proj.bias", p))?,
                norm1_w: take(&mut w, &format!("{}.norm1.weight", p))?,
                norm1_b: take(&mut w, &format!("{}.norm1.bias", p))?,
                norm2_w: take(&mut w, &format!("{}.norm2.weight", p))?,
                norm2_b: take(&mut w, &format!("{}.norm2.bias", p))?,
                lin1_w: take(&mut w, &format!("{}.linear1.weight", p))?,
                lin1_b: take(&mut w, &format!("{}.linear1.bias", p))?,
                lin2_w: take(&mut w, &format!("{}.linear2.weight", p))?,
                lin2_b: take(&mut w, &format!("{}.linear2.bias", p))?,
                num_heads,
                head_dim: dims / num_heads,
            });
        }

        Ok(LayaRustModel {
            tok_embeddings: take(&mut w, "encoder.embeddings.tok_embeddings.weight")?,
            emb_norm: take(&mut w, "encoder.embeddings.norm.weight")?,
            final_norm: take(&mut w, "encoder.final_norm.weight")?,
            type_emb: take(&mut w, "type_emb.weight")?,
            // El scorer es un Sequential: 0 LayerNorm, 1 Linear, 2 GELU (sin pesos), 3 Linear.
            scorer_norm_w: take(&mut w, "scorer.0.weight")?,
            scorer_norm_b: take(&mut w, "scorer.0.bias")?,
            scorer_in_w: take(&mut w, "scorer.1.weight")?,
            scorer_in_b: take(&mut w, "scorer.1.bias")?,
            scorer_out_w: take(&mut w, "scorer.3.weight")?,
            scorer_out_b: take(&mut w, "scorer.3.bias")?,
            layers,
            head,
            cfg,
        })
    }

    /// Puntúa los marcadores de una secuencia: un logit por opción.
    pub fn score_markers(
        &self,
        ids: &[u32],
        markers: &[usize],
        qtype: usize,
    ) -> Result<Vec<f32>, String> {
        if ids.is_empty() {
            return Err("la secuencia está vacía".to_string());
        }
        let eps = self.cfg.norm_eps;

        // Embeddings y su norma.
        let mut x = ops::embedding(ids, &self.tok_embeddings)?;
        x = ops::layer_norm(&x, self.emb_norm.data(), None, eps)?;

        // El encoder.
        for layer in &self.layers {
            x = self.encoder_layer(layer, x, eps)?;
        }
        x = ops::layer_norm(&x, self.final_norm.data(), None, eps)?;

        // El sesgo del tipo de pregunta, constante sobre toda la secuencia.
        let type_row = self.type_emb.row(qtype)?.to_vec();
        ops::add_row_broadcast(&mut x, &type_row)?;

        // Las cabezas de decisión: acá no hay máscara, todos los tokens se ven.
        for layer in &self.head {
            x = self.decision_layer(layer, x)?;
        }

        // Sólo las filas de los marcadores llegan al scorer.
        let picked = ops::index_select(&x, markers)?;
        let mut h = ops::layer_norm(
            &picked,
            self.scorer_norm_w.data(),
            Some(self.scorer_norm_b.data()),
            1e-5,
        )?;
        h = ops::linear(&h, &self.scorer_in_w, Some(&self.scorer_in_b))?;
        ops::gelu(&mut h);
        let out = ops::linear(&h, &self.scorer_out_w, Some(&self.scorer_out_b))?;
        if !out.all_finite() {
            return Err("el modelo produjo valores no finitos".to_string());
        }
        // `[n_marcadores, 1]` → un logit por opción.
        Ok(out.data().to_vec())
    }

    fn encoder_layer(
        &self,
        layer: &EncoderLayer,
        x: RTensor,
        eps: f32,
    ) -> Result<RTensor, String> {
        let heads = self.cfg.num_attention_heads;
        let head_dim = self.cfg.head_dim();

        // Atención, con su norma previa (identidad en la capa 0).
        let normed = match &layer.attn_norm {
            Some(w) => ops::layer_norm(&x, w.data(), None, eps)?,
            None => x.clone(),
        };
        let qkv = ops::linear(&normed, &layer.wqkv, None)?;
        let parts = qkv.split_columns(3)?;
        let (mut q, mut k, v) = (parts[0].clone(), parts[1].clone(), parts[2].clone());

        let base =
            if layer.is_global { self.cfg.global_rope_theta } else { self.cfg.local_rope_theta };
        ops::rope_inplace(&mut q, heads, head_dim, base, 0)?;
        ops::rope_inplace(&mut k, heads, head_dim, base, 0)?;

        let attn = self.attention(&q, &k, &v, heads, head_dim, !layer.is_global)?;
        let projected = ops::linear(&attn, &layer.wo, None)?;
        let mut x = x;
        ops::add_inplace(&mut x, &projected)?;

        // MLP con compuerta: `Wi` produce el doble de ancho y se parte en valor y compuerta.
        let normed = ops::layer_norm(&x, layer.mlp_norm.data(), None, eps)?;
        let wi = ops::linear(&normed, &layer.mlp_wi, None)?;
        let halves = wi.split_columns(2)?;
        let mut value = halves[0].clone();
        ops::gelu(&mut value);
        ops::mul_inplace(&mut value, &halves[1])?;
        let mlp = ops::linear(&value, &layer.mlp_wo, None)?;
        ops::add_inplace(&mut x, &mlp)?;
        Ok(x)
    }

    fn decision_layer(&self, layer: &DecisionLayer, x: RTensor) -> Result<RTensor, String> {
        let normed =
            ops::layer_norm(&x, layer.norm1_w.data(), Some(layer.norm1_b.data()), 1e-5)?;
        let qkv = ops::linear(&normed, &layer.in_proj_w, Some(&layer.in_proj_b))?;
        let parts = qkv.split_columns(3)?;
        // Las cabezas de decisión NO usan RoPE ni máscara: ven toda la secuencia, sin posición.
        let attn = self.attention(
            &parts[0],
            &parts[1],
            &parts[2],
            layer.num_heads,
            layer.head_dim,
            false,
        )?;
        let projected = ops::linear(&attn, &layer.out_proj_w, Some(&layer.out_proj_b))?;
        let mut x = x;
        ops::add_inplace(&mut x, &projected)?;

        let normed =
            ops::layer_norm(&x, layer.norm2_w.data(), Some(layer.norm2_b.data()), 1e-5)?;
        let mut h = ops::linear(&normed, &layer.lin1_w, Some(&layer.lin1_b))?;
        // ReLU, no GELU: es el default del `TransformerEncoderLayer` de PyTorch, que es de donde
        // salieron estos pesos. Cambiarla acá rompería la paridad en silencio.
        ops::relu(&mut h);
        let out = ops::linear(&h, &layer.lin2_w, Some(&layer.lin2_b))?;
        ops::add_inplace(&mut x, &out)?;
        Ok(x)
    }

    /// Atención multi-cabeza sobre `[seq, heads*head_dim]`. `local` aplica la ventana deslizante.
    fn attention(
        &self,
        q: &RTensor,
        k: &RTensor,
        v: &RTensor,
        heads: usize,
        head_dim: usize,
        local: bool,
    ) -> Result<RTensor, String> {
        let (seq, width) = q.dims2()?;
        let mut out = RTensor::zeros(vec![seq, width]);
        let scale = (head_dim as f32).powf(-0.5);

        for h in 0..heads {
            let start = h * head_dim;
            let qh = q.columns(start, head_dim)?;
            let kh = k.columns(start, head_dim)?;
            let vh = v.columns(start, head_dim)?;

            let mut scores = ops::matmul(&qh, &kh.transpose()?)?;
            ops::scale_inplace(&mut scores, scale);
            if local {
                ops::mask_local_inplace(&mut scores, self.cfg.local_attention)?;
            }
            ops::softmax_rows(&mut scores)?;
            let head_out = ops::matmul(&scores, &vh)?;
            out.set_columns(start, &head_out)?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config_json() -> serde_json::Value {
        json!({
            "model_type": "modernbert",
            "vocab_size": 50368, "hidden_size": 1024, "num_hidden_layers": 28,
            "num_attention_heads": 16, "intermediate_size": 2624,
            "norm_eps": 1e-5, "local_attention": 128, "global_attn_every_n_layers": 3,
            "rope_parameters": {
                "full_attention": {"rope_theta": 160000.0},
                "sliding_attention": {"rope_theta": 10000.0}
            }
        })
    }

    #[test]
    fn config_reads_the_nested_rope_bases() {
        let cfg = EncoderConfig::from_json(&config_json()).unwrap();
        assert_eq!(cfg.global_rope_theta, 160_000.0);
        assert_eq!(cfg.local_rope_theta, 10_000.0);
        assert_eq!(cfg.head_dim(), 64);
    }

    /// El patrón de atención decide qué base de RoPE y qué máscara se usan: si se corre un índice,
    /// el modelo sigue funcionando y responde distinto.
    #[test]
    fn global_layers_are_every_third_starting_at_zero() {
        let cfg = EncoderConfig::from_json(&config_json()).unwrap();
        assert!(cfg.is_global(0));
        assert!(!cfg.is_global(1));
        assert!(!cfg.is_global(2));
        assert!(cfg.is_global(3));
        assert!(cfg.is_global(27), "la última capa de Laya es global");
        let globals = (0..28).filter(|&i| cfg.is_global(i)).count();
        assert_eq!(globals, 10, "28 capas con una global cada 3");
    }

    #[test]
    fn non_modernbert_is_rejected() {
        let mut c = config_json();
        c["model_type"] = json!("bert");
        assert!(EncoderConfig::from_json(&c).is_err());
    }

    #[test]
    fn odd_head_dimension_is_rejected() {
        let mut c = config_json();
        c["num_attention_heads"] = json!(3); // 1024/3 no es entero
        assert!(EncoderConfig::from_json(&c).is_err());
    }

    #[test]
    fn missing_tensor_says_which_one() {
        let cfg = EncoderConfig::from_json(&config_json()).unwrap();
        // `unwrap_err` pediría `Debug` en el modelo, que no tiene sentido derivar para un tipo
        // que contiene cientos de megabytes de pesos.
        let err = match LayaRustModel::load(HashMap::new(), cfg, &AgentConfig::default()) {
            Err(e) => e,
            Ok(_) => panic!("cargar sin tensores debía fallar"),
        };
        assert!(err.contains("falta el tensor") || err.contains("falta '"), "{}", err);
    }

    /// Un modelo de juguete —dos capas, dimensiones chicas— que ejercita el camino completo:
    /// embeddings, atención global y local, MLP con compuerta, cabezas y scorer.
    fn toy() -> (LayaRustModel, EncoderConfig) {
        let cfg = EncoderConfig {
            vocab_size: 10,
            hidden_size: 4,
            intermediate_size: 4,
            num_hidden_layers: 2,
            num_attention_heads: 2,
            norm_eps: 1e-5,
            local_attention: 2,
            global_attn_every_n_layers: 2,
            global_rope_theta: 160_000.0,
            local_rope_theta: 10_000.0,
        };
        let mut w: HashMap<String, RTensor> = HashMap::new();
        let ones = |r: usize, c: usize| RTensor::new(vec![0.1; r * c], vec![r, c]).unwrap();
        let vecn = |n: usize| RTensor::new(vec![1.0; n], vec![n]).unwrap();
        let zeros = |n: usize| RTensor::new(vec![0.0; n], vec![n]).unwrap();

        w.insert("encoder.embeddings.tok_embeddings.weight".into(), ones(10, 4));
        w.insert("encoder.embeddings.norm.weight".into(), vecn(4));
        w.insert("encoder.final_norm.weight".into(), vecn(4));
        for i in 0..2 {
            let p = format!("encoder.layers.{}", i);
            if i > 0 {
                w.insert(format!("{}.attn_norm.weight", p), vecn(4));
            }
            w.insert(format!("{}.attn.Wqkv.weight", p), ones(12, 4));
            w.insert(format!("{}.attn.Wo.weight", p), ones(4, 4));
            w.insert(format!("{}.mlp_norm.weight", p), vecn(4));
            w.insert(format!("{}.mlp.Wi.weight", p), ones(8, 4));
            w.insert(format!("{}.mlp.Wo.weight", p), ones(4, 4));
        }
        // Una fila DISTINTA por tipo: con las tres iguales, el test de que el tipo influye
        // no podría distinguir "no se aplica" de "se aplica y da lo mismo".
        w.insert(
            "type_emb.weight".into(),
            RTensor::new(
                vec![0.1, 0.1, 0.1, 0.1, 0.9, -0.4, 0.2, 0.7, -0.6, 0.3, -0.1, 0.5],
                vec![3, 4],
            )
            .unwrap(),
        );
        let p = "head.layers.0";
        w.insert(format!("{}.self_attn.in_proj_weight", p), ones(12, 4));
        w.insert(format!("{}.self_attn.in_proj_bias", p), zeros(12));
        w.insert(format!("{}.self_attn.out_proj.weight", p), ones(4, 4));
        w.insert(format!("{}.self_attn.out_proj.bias", p), zeros(4));
        w.insert(format!("{}.norm1.weight", p), vecn(4));
        w.insert(format!("{}.norm1.bias", p), zeros(4));
        w.insert(format!("{}.norm2.weight", p), vecn(4));
        w.insert(format!("{}.norm2.bias", p), zeros(4));
        w.insert(format!("{}.linear1.weight", p), ones(16, 4));
        w.insert(format!("{}.linear1.bias", p), zeros(16));
        w.insert(format!("{}.linear2.weight", p), ones(4, 16));
        w.insert(format!("{}.linear2.bias", p), zeros(4));
        w.insert("scorer.0.weight".into(), vecn(4));
        w.insert("scorer.0.bias".into(), zeros(4));
        w.insert("scorer.1.weight".into(), ones(4, 4));
        w.insert("scorer.1.bias".into(), zeros(4));
        w.insert("scorer.3.weight".into(), ones(1, 4));
        w.insert("scorer.3.bias".into(), zeros(1));

        let agent = AgentConfig { head_layers: 1, ..AgentConfig::default() };
        (LayaRustModel::load(w, cfg.clone(), &agent).unwrap(), cfg)
    }

    #[test]
    fn toy_model_runs_end_to_end_and_returns_one_logit_per_marker() {
        let (model, _) = toy();
        let ids = [1u32, 2, 3, 4, 5];
        let logits = model.score_markers(&ids, &[0, 2, 4], 0).unwrap();
        assert_eq!(logits.len(), 3, "un logit por marcador");
        assert!(logits.iter().all(|v| v.is_finite()), "logits: {:?}", logits);
    }

    #[test]
    fn toy_model_is_deterministic() {
        let (model, _) = toy();
        let ids = [1u32, 2, 3];
        let a = model.score_markers(&ids, &[0, 1], 0).unwrap();
        let b = model.score_markers(&ids, &[0, 1], 0).unwrap();
        assert_eq!(a, b, "dos corridas iguales deben dar lo mismo, bit a bit");
    }

    /// El tipo de pregunta entra al modelo: cambiarlo tiene que cambiar el resultado, porque si no
    /// el `type_emb` no se estaría aplicando.
    #[test]
    fn question_type_changes_the_result() {
        let (model, _) = toy();
        let ids = [1u32, 2, 3];
        let choice = model.score_markers(&ids, &[0, 1], 0).unwrap();
        let noul = model.score_markers(&ids, &[0, 1], 2).unwrap();
        assert_ne!(choice, noul, "el sesgo de tipo debe alterar los logits");
    }

    #[test]
    fn empty_sequence_is_an_error() {
        let (model, _) = toy();
        assert!(model.score_markers(&[], &[], 0).is_err());
    }

    #[test]
    fn marker_out_of_range_is_an_error_not_a_panic() {
        let (model, _) = toy();
        assert!(model.score_markers(&[1, 2], &[9], 0).is_err());
    }

    #[test]
    fn unknown_token_id_is_an_error() {
        let (model, _) = toy();
        assert!(model.score_markers(&[999], &[0], 0).is_err());
    }
}

/// El **oráculo de I4**: las dos implementaciones sobre los mismos pesos.
///
/// Mientras candle y el backend propio coexistan, ésta es la prueba que decide si el port es
/// correcto. No compara "parecido": compara logit a logit con una tolerancia declarada, sobre el
/// checkpoint real.
///
/// Se compila sólo cuando están las dos features, y se saltea sin `SYNSEMA_TEST_LAYA`.
#[cfg(all(test, feature = "arch-modernbert", feature = "rust-backend"))]
mod oracle {
    use super::*;
    use std::path::Path;

    /// Tolerancia por logit entre los dos backends.
    ///
    /// No es cero y no puede serlo: candle y nosotros sumamos en otro orden, y en `f32` el orden
    /// cambia los últimos dígitos. 28 capas amplifican eso. Lo que sí tiene que valer es que la
    /// diferencia sea **mucho menor que la separación entre opciones**, que es lo que decide la
    /// respuesta.
    const TOLERANCE: f32 = 5e-2;

    fn checkpoint() -> Option<std::path::PathBuf> {
        match std::env::var("SYNSEMA_TEST_LAYA") {
            Ok(d) if !d.trim().is_empty() => Some(std::path::PathBuf::from(d)),
            _ => {
                eprintln!("[skip] seteá SYNSEMA_TEST_LAYA=/ruta/al/checkpoint de Laya");
                None
            }
        }
    }

    fn read_json(p: &Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(p).expect("config legible"))
            .expect("config válido")
    }

    /// Una secuencia corta pero real: pasa por atención global y local, ambas ramas del encoder.
    const IDS: &[u32] = &[
        50281, 22122, 1953, 27, 6758, 7811, 943, 6016, 436, 2748, 32, 50282, 50284, 33484, 27,
        29838, 1271, 13, 10762, 13, 50284, 22174, 27, 19775, 13, 50282,
    ];
    const MARKERS: &[usize] = &[12, 20];

    #[test]
    fn rust_backend_matches_candle_on_the_real_checkpoint() {
        let Some(dir) = checkpoint() else { return };
        let agent = AgentConfig::from_json(&read_json(&dir.join("rl_agent_config.json"))).unwrap();
        let encoder_raw = read_json(&dir.join("encoder").join("config.json"));
        let weights_path = dir.join("model.safetensors");

        // Uno por vez: los dos modelos juntos en f32 son ~3,4 GB de RAM.
        let ours = {
            let w = crate::safetensors::load(&weights_path).expect("pesos legibles");
            let cfg = EncoderConfig::from_json(&encoder_raw).unwrap();
            let m = LayaRustModel::load(w, cfg, &agent).expect("modelo propio");
            m.score_markers(IDS, MARKERS, 0).expect("logits propios")
        };

        let theirs = {
            let w = candle_core::safetensors::load(&weights_path, &candle_core::Device::Cpu)
                .expect("pesos legibles por candle");
            let cfg = crate::decide::encoder_config_from_json(&encoder_raw).unwrap();
            let m = crate::arch_candle_laya::LayaModel::load(
                w,
                &cfg,
                &agent,
                &candle_core::Device::Cpu,
            )
            .expect("modelo candle");
            m.score_markers(IDS, MARKERS, 0).expect("logits candle")
        };

        assert_eq!(ours.len(), theirs.len(), "distinta cantidad de logits");
        let mut worst = 0f32;
        for (i, (a, b)) in ours.iter().zip(theirs.iter()).enumerate() {
            let d = (a - b).abs();
            if d > worst {
                worst = d;
            }
            assert!(
                d <= TOLERANCE,
                "logit {}: propio {} vs candle {} (dif {})",
                i,
                a,
                b,
                d
            );
        }
        eprintln!("[oráculo] diferencia máxima entre backends: {:.3e}", worst);

        // Y lo que de verdad decide la respuesta: el mismo ganador.
        let argmax = |v: &[f32]| {
            v.iter()
                .enumerate()
                .max_by(|x, y| x.1.partial_cmp(y.1).unwrap())
                .map(|(i, _)| i)
                .unwrap()
        };
        assert_eq!(argmax(&ours), argmax(&theirs), "los backends eligen opciones distintas");
    }
}

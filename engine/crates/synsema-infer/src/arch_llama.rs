//! Los decoders escritos a mano: **la implementación de referencia**.
//!
//! Desde I5 esto **no es el camino de producción**. Lo que corre un modelo es `archrun.rs`, que
//! ejecuta la definición declarativa de `defs/<arch>.archdef`. Este archivo se queda como el
//! oráculo contra el que se compara ese intérprete: el test `oracle` de `archrun.rs` corre las dos
//! sobre los mismos pesos y exige **el mismo bit**.
//!
//! Tener dos caminos donde uno verifica al otro no es lo mismo que tener dos que hay que mantener.
//! Éste sólo cambia si cambia la arquitectura de verdad, y si los dos cambian distinto, el test
//! lo grita antes de que salga un release.
//!
//! Las cuatro son la misma arquitectura con variaciones, así que viven en un archivo: separarlas
//! duplicaría el 90% del código y escondería en qué se diferencian, que es lo único interesante.
//! (En el formato declarativo esa comparación es literal: `diff defs/llama.archdef
//! defs/qwen3.archdef` son dos líneas.)
//!
//! | | llama | qwen2 | qwen3 | gemma3 |
//! |---|---|---|---|---|
//! | Sesgo en Q/K/V | no | **sí** | no | no |
//! | RMSNorm por cabeza en Q/K | no | no | **sí** | **sí** |
//! | Normas *después* de cada bloque | no | no | no | **sí** |
//! | Ventana deslizante alternada | no | no | no | **sí** (5 de cada 6 capas) |
//! | Embeddings escalados por √d | no | no | no | **sí** |
//! | Todo lo demás | RMSNorm, SwiGLU, GQA, RoPE | ídem | ídem | ídem |
//!
//! **gemma3 cierra el bloqueo que originó toda esta capa**: candle tiene `quantized_gemma3` pero
//! sin `clear_kv_cache`, así que el pool del motor no podía usarlo (PR #3709, abierto desde julio
//! de 2026). Acá el reset de KV es parte del tipo, no un favor de nadie.
//!
//! ## El KV cache y por qué es la parte con semántica
//!
//! Generar token a token sin cache obliga a recomputar toda la secuencia en cada paso. El cache
//! guarda las claves y valores ya calculados, y eso lo convierte en **estado mutable entre
//! llamadas**. De ahí sale el invariante que el motor ya tenía: dos llamadas jamás pueden heredar
//! estado de generación, así que `clear_kv_cache` no es una optimización sino una condición de
//! corrección, y por eso vive en el trait (`arch.rs` §2.2).
//!
//! ## Un detalle del formato que confunde
//!
//! GGUF guarda las dimensiones al revés que PyTorch: un `[2048, 1024]` en el header es una matriz
//! de `[out=1024, in=2048]`. Los **datos** están en el mismo orden, así que sólo hay que dar vuelta
//! las dimensiones al cargar — pero leerlas de frente produce matrices transpuestas que fallan por
//! forma en el mejor caso, y dan números mal en el peor.

use std::sync::Arc;

use crate::backend_rust as ops;
use crate::gguf_rust::GgufHeader;
use crate::mapped::{ModelBytes, Slice};
use crate::qmatmul::{QTensor, Weight};
use crate::quant::QuantType;
use crate::tensor_rust::RTensor;

/// La configuración de un decoder, leída de la metadata del GGUF.
#[derive(Clone, Debug)]
pub struct DecoderConfig {
    pub arch: String,
    pub block_count: usize,
    pub embedding_length: usize,
    pub feed_forward_length: usize,
    pub head_count: usize,
    pub head_count_kv: usize,
    pub head_dim: usize,
    pub rms_eps: f32,
    pub rope_base: f32,
    pub context_length: usize,
    /// qwen2 lleva sesgo en las proyecciones de atención; las otras no.
    pub qkv_bias: bool,
    /// qwen3 y gemma3 normalizan cada cabeza de Q y K antes de RoPE.
    pub qk_norm: bool,
    /// gemma3: ventana de atención local, y cada cuántas capas hay una global.
    pub sliding_window: Option<usize>,
    pub sliding_window_type: usize,
    /// gemma3 usa otra base de RoPE en las capas locales.
    pub rope_base_local: f32,
    /// gemma3 multiplica los embeddings por √(embedding_length). Sin eso, todo sale mal.
    pub scale_embeddings: bool,
    /// gemma3 aplica una norma más después de la atención y del MLP.
    pub post_norms: bool,
    /// La activación del MLP. **gemma3 NO usa SwiGLU con `silu`**: usa GELU con la aproximación
    /// tanh, igual que `gelu_pytorch_tanh` en HF y `ggml_gelu` en llama.cpp.
    pub ffn_activation: FfnAct,
}

/// La activación del MLP. Es una de las cosas que un GGUF **no** declara: llama.cpp la fija por
/// arquitectura, y nosotros también — sólo que en el camino declarativo es un paso que se lee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FfnAct {
    Silu,
    GeluTanh,
}

impl DecoderConfig {
    /// Las arquitecturas que este archivo sabe correr.
    pub const SUPPORTED: &'static [&'static str] = &["llama", "qwen2", "qwen3", "gemma3"];

    /// La config de las arquitecturas que **este archivo** sabe correr.
    ///
    /// El camino de produccion es el declarativo (`archrun.rs`), cuya lista de arquitecturas es la
    /// del registro de definiciones y no esta. Esta funcion queda para la implementacion de
    /// referencia, que por definicion solo cubre lo que tiene escrito a mano.
    pub fn from_header(h: &GgufHeader) -> Result<Self, String> {
        let cfg = Self::read_header(h)?;
        if !Self::SUPPORTED.contains(&cfg.arch.as_str()) {
            return Err(format!(
                "arquitectura '{}' no soportada por la implementacion de referencia (soportadas:                  {}); el camino declarativo puede tener una definicion",
                cfg.arch,
                Self::SUPPORTED.join(", ")
            ));
        }
        Ok(cfg)
    }

    /// Lee la metadata del GGUF **sin** juzgar si la arquitectura se puede correr.
    ///
    /// Quien decide eso es el que la va a correr: la implementacion de referencia mira su lista
    /// fija, y el interprete declarativo mira si hay definicion. Mezclar las dos cosas en una sola
    /// funcion fue un bug real: gemma3 se rechazaba por no estar en una lista que ya no mandaba.
    pub fn read_header(h: &GgufHeader) -> Result<Self, String> {
        let arch = h
            .arch()
            .ok_or_else(|| "el GGUF no declara `general.architecture`".to_string())?
            .to_string();
        let key = |k: &str| format!("{}.{}", arch, k);
        let usize_of = |k: &str| -> Result<usize, String> {
            h.get(&key(k))
                .and_then(|v| v.as_u64())
                .map(|n| n as usize)
                .ok_or_else(|| format!("el GGUF no declara `{}.{}`", arch, k))
        };
        let head_count = usize_of("attention.head_count")?;
        let embedding_length = usize_of("embedding_length")?;
        // `key_length` es explícito en qwen3; en el resto se deduce.
        let head_dim = h
            .get(&key("attention.key_length"))
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .unwrap_or_else(|| embedding_length / head_count.max(1));

        let cfg = DecoderConfig {
            block_count: usize_of("block_count")?,
            embedding_length,
            feed_forward_length: usize_of("feed_forward_length")?,
            head_count,
            // Sin GQA, tantas cabezas de clave como de consulta.
            head_count_kv: h
                .get(&key("attention.head_count_kv"))
                .and_then(|v| v.as_u64())
                .map(|n| n as usize)
                .unwrap_or(head_count),
            head_dim,
            rms_eps: h
                .get(&key("attention.layer_norm_rms_epsilon"))
                .and_then(|v| v.as_f32())
                .unwrap_or(1e-5),
            rope_base: h.get(&key("rope.freq_base")).and_then(|v| v.as_f32()).unwrap_or(10_000.0),
            context_length: h
                .get(&key("context_length"))
                .and_then(|v| v.as_u64())
                .map(|n| n as usize)
                .unwrap_or(4096),
            qkv_bias: arch == "qwen2",
            qk_norm: arch == "qwen3" || arch == "gemma3",
            sliding_window: h
                .get(&key("attention.sliding_window"))
                .and_then(|v| v.as_u64())
                .map(|n| n as usize),
            // El patrón no viene declarado: llama.cpp y candle lo fijan en 6.
            sliding_window_type: h
                .get(&key("attention.sliding_window_type"))
                .and_then(|v| v.as_u64())
                .map(|n| n as usize)
                .unwrap_or(6),
            rope_base_local: h
                .get(&key("rope.local_freq_base"))
                .and_then(|v| v.as_f32())
                .unwrap_or(10_000.0),
            scale_embeddings: arch == "gemma3",
            post_norms: arch == "gemma3",
            ffn_activation: if arch == "gemma3" { FfnAct::GeluTanh } else { FfnAct::Silu },
            arch,
        };
        if cfg.head_count == 0 || cfg.head_count_kv == 0 {
            return Err("el GGUF declara cero cabezas de atención".to_string());
        }
        if cfg.sliding_window_type == 0 {
            return Err("`sliding_window_type` no puede ser cero".to_string());
        }
        if cfg.head_count % cfg.head_count_kv != 0 {
            return Err(format!(
                "{} cabezas de consulta no se reparten entre {} de clave",
                cfg.head_count, cfg.head_count_kv
            ));
        }
        Ok(cfg)
    }

    /// La ventana de atención de una capa, si es local.
    ///
    /// gemma3 alterna: cinco capas locales y una global, con `(i+1) % 6 > 0` para las locales. Es
    /// el mismo criterio que usan llama.cpp y candle; correrlo una capa cambia el modelo.
    pub fn window_for(&self, layer: usize) -> Option<usize> {
        let w = self.sliding_window?;
        if (layer + 1) % self.sliding_window_type > 0 {
            Some(w)
        } else {
            None
        }
    }

    /// La base de RoPE de una capa: las locales usan la suya.
    pub fn rope_base_for(&self, layer: usize) -> f32 {
        if self.window_for(layer).is_some() {
            self.rope_base_local
        } else {
            self.rope_base
        }
    }

    /// Cuántas cabezas de consulta comparten cada cabeza de clave.
    pub fn group_size(&self) -> usize {
        self.head_count / self.head_count_kv
    }

    fn q_width(&self) -> usize {
        self.head_count * self.head_dim
    }

    fn kv_width(&self) -> usize {
        self.head_count_kv * self.head_dim
    }
}

struct Layer {
    attn_norm: RTensor,
    wq: Weight,
    wk: Weight,
    wv: Weight,
    wo: Weight,
    bq: Option<RTensor>,
    bk: Option<RTensor>,
    bv: Option<RTensor>,
    q_norm: Option<RTensor>,
    k_norm: Option<RTensor>,
    post_attn_norm: Option<RTensor>,
    post_ffn_norm: Option<RTensor>,
    ffn_norm: RTensor,
    ffn_gate: Weight,
    ffn_up: Weight,
    ffn_down: Weight,
}

/// Lo que se acumula por capa entre pasos de generación.
#[derive(Default)]
pub(crate) struct KvCache {
    /// `[tokens_vistos, kv_width]`
    pub(crate) keys: Option<RTensor>,
    pub(crate) values: Option<RTensor>,
}

/// Un decoder cargado, con su cache.
pub struct LlamaModel {
    cfg: DecoderConfig,
    token_embd: Weight,
    layers: Vec<Layer>,
    output_norm: RTensor,
    /// `None` cuando los embeddings están atados: la salida usa `token_embd`, que es lo que hace
    /// qwen3 (su GGUF directamente no trae `output.weight`).
    output: Option<Weight>,
    cache: Vec<KvCache>,
}

impl LlamaModel {
    /// Carga desde un GGUF ya parseado más sus bytes **mapeados**.
    ///
    /// Los pesos grandes no se copian: cada tensor se queda con una porción del mapa, así que el
    /// modelo ocupa lo que ocupa el archivo y no cuatro veces más.
    pub fn load(header: &GgufHeader, bytes: &Arc<ModelBytes>) -> Result<Self, String> {
        let cfg = DecoderConfig::from_header(header)?;
        let raw = bytes.as_slice();
        let get = |name: &str| -> Result<RTensor, String> { read_tensor(header, raw, name) };
        let maybe = |name: &str| -> Option<RTensor> { read_tensor(header, raw, name).ok() };
        // Los pesos grandes se quedan CUANTIZADOS: ahi esta el ahorro de I4-e.
        let big = |name: &str| -> Result<Weight, String> { read_weight(header, bytes, name) };
        let maybe_big = |name: &str| -> Option<Weight> { read_weight(header, bytes, name).ok() };

        let mut layers = Vec::with_capacity(cfg.block_count);
        for i in 0..cfg.block_count {
            let p = format!("blk.{}", i);
            layers.push(Layer {
                attn_norm: get(&format!("{}.attn_norm.weight", p))?,
                wq: big(&format!("{}.attn_q.weight", p))?,
                wk: big(&format!("{}.attn_k.weight", p))?,
                wv: big(&format!("{}.attn_v.weight", p))?,
                wo: big(&format!("{}.attn_output.weight", p))?,
                bq: maybe(&format!("{}.attn_q.bias", p)),
                bk: maybe(&format!("{}.attn_k.bias", p)),
                bv: maybe(&format!("{}.attn_v.bias", p)),
                q_norm: maybe(&format!("{}.attn_q_norm.weight", p)),
                k_norm: maybe(&format!("{}.attn_k_norm.weight", p)),
                post_attn_norm: maybe(&format!("{}.post_attention_norm.weight", p)),
                post_ffn_norm: maybe(&format!("{}.post_ffw_norm.weight", p)),
                ffn_norm: get(&format!("{}.ffn_norm.weight", p))?,
                ffn_gate: big(&format!("{}.ffn_gate.weight", p))?,
                ffn_up: big(&format!("{}.ffn_up.weight", p))?,
                ffn_down: big(&format!("{}.ffn_down.weight", p))?,
            });
        }

        let mut cache = Vec::with_capacity(cfg.block_count);
        cache.resize_with(cfg.block_count, KvCache::default);

        Ok(LlamaModel {
            token_embd: big("token_embd.weight")?,
            output_norm: get("output_norm.weight")?,
            output: maybe_big("output.weight"),
            layers,
            cache,
            cfg,
        })
    }

    pub fn config(&self) -> &DecoderConfig {
        &self.cfg
    }

    /// Cuántos tokens hay en el cache. Es la posición del próximo.
    pub fn cached_tokens(&self) -> usize {
        self.cache
            .first()
            .and_then(|c| c.keys.as_ref())
            .and_then(|k| k.dims2().ok())
            .map(|(n, _)| n)
            .unwrap_or(0)
    }

    /// Descarta el estado de generación. **No es una optimización**: sin esto, una llamada vería
    /// los tokens de la anterior.
    pub fn clear_kv_cache(&mut self) {
        for c in self.cache.iter_mut() {
            c.keys = None;
            c.values = None;
        }
    }

    /// Procesa `ids` y devuelve los logits del **último** token.
    ///
    /// La primera llamada de una generación pasa el prompt entero; las siguientes, un token por
    /// vez. La posición sale del cache, así que quien llama no tiene que llevarla.
    pub fn forward(&mut self, ids: &[u32]) -> Result<Vec<f32>, String> {
        if ids.is_empty() {
            return Err("no hay tokens que procesar".to_string());
        }
        let offset = self.cached_tokens();
        if offset + ids.len() > self.cfg.context_length {
            return Err(format!(
                "la secuencia ({} tokens) excede el contexto del modelo ({})",
                offset + ids.len(),
                self.cfg.context_length
            ));
        }

        let mut x = self.token_embd.embedding(ids)?;
        // gemma3 escala los embeddings por √d antes de la primera capa. Es chico de escribir y
        // enorme de olvidar: sin esto el modelo responde ruido.
        if self.cfg.scale_embeddings {
            ops::scale_inplace(&mut x, (self.cfg.embedding_length as f32).sqrt());
        }
        for i in 0..self.layers.len() {
            x = self.layer_forward(i, x, offset)?;
        }
        x = ops::rms_norm(&x, self.output_norm.data(), self.cfg.rms_eps)?;

        // Sólo el último token importa: los logits de los anteriores ya no se usan.
        let (n, _) = x.dims2()?;
        let last = ops::index_select(&x, &[n - 1])?;
        let head = self.output.as_ref().unwrap_or(&self.token_embd);
        let logits = head.matmul(&last)?;
        if !logits.all_finite() {
            return Err("el modelo produjo logits no finitos".to_string());
        }
        Ok(logits.data().to_vec())
    }

    fn layer_forward(
        &mut self,
        index: usize,
        x: RTensor,
        offset: usize,
    ) -> Result<RTensor, String> {
        let cfg = self.cfg.clone();
        let layer = &self.layers[index];

        let normed = ops::rms_norm(&x, layer.attn_norm.data(), cfg.rms_eps)?;
        // El sesgo va aparte: `Weight::matmul` no lo lleva, porque un peso cuantizado nunca trae
        // uno y mezclarlos escondería ese hecho.
        let mut q = layer.wq.matmul(&normed)?;
        let mut k = layer.wk.matmul(&normed)?;
        let mut v = layer.wv.matmul(&normed)?;
        if let Some(b) = &layer.bq {
            ops::add_row_broadcast(&mut q, b.data())?;
        }
        if let Some(b) = &layer.bk {
            ops::add_row_broadcast(&mut k, b.data())?;
        }
        if let Some(b) = &layer.bv {
            ops::add_row_broadcast(&mut v, b.data())?;
        }

        // qwen3: cada cabeza se normaliza ANTES de RoPE.
        if let Some(w) = &layer.q_norm {
            ops::rms_norm_per_head_inplace(
                &mut q,
                cfg.head_count,
                cfg.head_dim,
                w.data(),
                cfg.rms_eps,
            )?;
        }
        if let Some(w) = &layer.k_norm {
            ops::rms_norm_per_head_inplace(
                &mut k,
                cfg.head_count_kv,
                cfg.head_dim,
                w.data(),
                cfg.rms_eps,
            )?;
        }

        // La base de RoPE depende de si la capa es local o global (gemma3).
        let rope_base = cfg.rope_base_for(index);
        ops::rope_inplace(&mut q, cfg.head_count, cfg.head_dim, rope_base, offset)?;
        ops::rope_inplace(&mut k, cfg.head_count_kv, cfg.head_dim, rope_base, offset)?;

        // El cache: las claves y valores nuevos se pegan a los que ya había.
        let cache = &mut self.cache[index];
        let keys = append_rows(cache.keys.take(), k)?;
        let values = append_rows(cache.values.take(), v)?;
        cache.keys = Some(keys.clone());
        cache.values = Some(values.clone());

        let attn = attention_gqa(&cfg, &q, &keys, &values, offset, cfg.window_for(index))?;
        let mut projected = self.layers[index].wo.matmul(&attn)?;
        // gemma3: la norma va sobre la SALIDA del bloque, antes de sumar el residual.
        if let Some(w) = &self.layers[index].post_attn_norm {
            projected = ops::rms_norm(&projected, w.data(), cfg.rms_eps)?;
        }
        let mut x = x;
        ops::add_inplace(&mut x, &projected)?;

        // SwiGLU: `down( silu(gate(x)) * up(x) )`.
        let layer = &self.layers[index];
        let normed = ops::rms_norm(&x, layer.ffn_norm.data(), cfg.rms_eps)?;
        let mut gate = layer.ffn_gate.matmul(&normed)?;
        match cfg.ffn_activation {
            FfnAct::Silu => ops::silu(&mut gate),
            FfnAct::GeluTanh => ops::gelu_tanh(&mut gate),
        }
        let up = layer.ffn_up.matmul(&normed)?;
        ops::mul_inplace(&mut gate, &up)?;
        let mut down = layer.ffn_down.matmul(&gate)?;
        if let Some(w) = &layer.post_ffn_norm {
            down = ops::rms_norm(&down, w.data(), cfg.rms_eps)?;
        }
        ops::add_inplace(&mut x, &down)?;
        Ok(x)
    }
}

/// Atención con cabezas agrupadas: varias cabezas de consulta comparten una de clave/valor.
///
/// Es lo que hace que un modelo moderno tenga un cache mucho más chico. `group_size` cabezas de
/// consulta leen la misma cabeza de clave, así que el índice de la clave es `h / group_size`.
pub(crate) fn attention_gqa(
    cfg: &DecoderConfig,
    q: &RTensor,
    keys: &RTensor,
    values: &RTensor,
    offset: usize,
    window: Option<usize>,
) -> Result<RTensor, String> {
    let (q_len, q_width) = q.dims2()?;
    if q_width != cfg.q_width() {
        return Err(format!("consulta de ancho {} y no {}", q_width, cfg.q_width()));
    }
    // El cache tiene que traer tantas columnas como cabezas de clave: si un tensor se cargó
    // transpuesto, acá se nota con un error claro en vez de un resultado silenciosamente malo.
    let (k_len, k_width) = keys.dims2()?;
    let (v_len, v_width) = values.dims2()?;
    if k_width != cfg.kv_width() || v_width != cfg.kv_width() {
        return Err(format!(
            "el cache tiene claves de ancho {} y valores de {}, se esperaban {}",
            k_width,
            v_width,
            cfg.kv_width()
        ));
    }
    if k_len != v_len || k_len != offset + q_len {
        return Err(format!(
            "el cache tiene {} claves y {} valores para {} tokens ya vistos más {} nuevos",
            k_len, v_len, offset, q_len
        ));
    }
    let scale = (cfg.head_dim as f32).powf(-0.5);
    let group = cfg.group_size();
    let mut out = RTensor::zeros(vec![q_len, q_width]);

    for h in 0..cfg.head_count {
        let kv_head = h / group;
        let qh = q.columns(h * cfg.head_dim, cfg.head_dim)?;
        let kh = keys.columns(kv_head * cfg.head_dim, cfg.head_dim)?;
        let vh = values.columns(kv_head * cfg.head_dim, cfg.head_dim)?;

        let mut scores = ops::matmul(&qh, &kh.transpose()?)?;
        ops::scale_inplace(&mut scores, scale);
        // Causal, y con ventana si la capa es local (gemma3).
        match window {
            Some(w) => ops::mask_causal_window_inplace(&mut scores, offset, w)?,
            None => ops::mask_causal_inplace(&mut scores, offset)?,
        }
        ops::softmax_rows(&mut scores)?;
        let head_out = ops::matmul(&scores, &vh)?;
        out.set_columns(h * cfg.head_dim, &head_out)?;
    }
    Ok(out)
}

/// Pega filas nuevas debajo de las que ya había.
pub(crate) fn append_rows(existing: Option<RTensor>, new: RTensor) -> Result<RTensor, String> {
    match existing {
        None => Ok(new),
        Some(old) => {
            let (n_old, d_old) = old.dims2()?;
            let (n_new, d_new) = new.dims2()?;
            if d_old != d_new {
                return Err(format!("el cache tiene ancho {} y llegó {}", d_old, d_new));
            }
            let mut data = old.data().to_vec();
            data.extend_from_slice(new.data());
            RTensor::new(data, vec![n_old + n_new, d_old])
        }
    }
}

/// Lee un tensor del GGUF **sin dequantizarlo**, cuando su esquema lo permite.
///
/// Es la diferencia entre I4-c y I4-e: antes todo pasaba a `f32` al cargar y el modelo ocupaba
/// cuatro veces el archivo. `Weight::from_qtensor` decide por esquema y tamaño.
pub(crate) fn read_weight(
    header: &GgufHeader,
    bytes: &Arc<ModelBytes>,
    name: &str,
) -> Result<Weight, String> {
    let (kind, start, len, dims) = locate_tensor(header, bytes.as_slice(), name)?;
    // GGUF: [ne0, ne1] con ne0 contiguo -> para nosotros es [filas, columnas] = [ne1, ne0].
    let cols = dims[0];
    let rows = if dims.len() > 1 { dims[1] } else { 1 };
    let slice = Slice::new(bytes.clone(), start, len).map_err(|e| format!("'{}': {}", name, e))?;
    let q = QTensor::from_slice(kind, rows, cols, slice)
        .map_err(|e| format!("'{}': {}", name, e))?;
    Weight::from_qtensor(q).map_err(|e| format!("'{}': {}", name, e))
}

/// Ubica los bytes de un tensor y valida que entren en el archivo. Un `.gguf` es dato ajeno.
fn locate_tensor(
    header: &GgufHeader,
    bytes: &[u8],
    name: &str,
) -> Result<(QuantType, usize, usize, Vec<usize>), String> {
    let info = header.tensor(name).ok_or_else(|| format!("falta el tensor '{}' en el GGUF", name))?;
    let kind = QuantType::from_ggml(info.kind).map_err(|e| format!("'{}': {}", name, e))?;
    let n = info.element_count();
    let start = header
        .data_offset
        .checked_add(info.offset as usize)
        .ok_or_else(|| format!("'{}': offset inverosimil", name))?;
    let len = kind.bytes_for(n).map_err(|e| format!("'{}': {}", name, e))?;
    let end = start.checked_add(len).ok_or_else(|| format!("'{}': largo inverosimil", name))?;
    if end > bytes.len() {
        return Err(format!(
            "'{}': sus datos ([{}, {})) no entran en el archivo de {} bytes",
            name, start, end, bytes.len()
        ));
    }
    Ok((kind, start, end - start, info.dims.clone()))
}

/// Lee un tensor del GGUF y lo dequantiza. Para los chicos: normas y sesgos.
pub(crate) fn read_tensor(header: &GgufHeader, bytes: &[u8], name: &str) -> Result<RTensor, String> {
    let (kind, start, len, dims) = locate_tensor(header, bytes, name)?;
    let n: usize = dims.iter().product();
    let values = crate::quant::dequantize(kind, &bytes[start..start + len], n)?;
    let shape: Vec<usize> = dims.iter().rev().copied().collect();
    RTensor::new(values, shape)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_size_is_queries_per_key_head() {
        let cfg = DecoderConfig {
            arch: "qwen3".into(),
            block_count: 28,
            embedding_length: 2048,
            feed_forward_length: 6144,
            head_count: 16,
            head_count_kv: 8,
            head_dim: 128,
            rms_eps: 1e-6,
            rope_base: 1e6,
            context_length: 40960,
            qkv_bias: false,
            qk_norm: true,
            sliding_window: None,
            sliding_window_type: 6,
            rope_base_local: 10_000.0,
            scale_embeddings: false,
            post_norms: false,
            ffn_activation: FfnAct::Silu,
        };
        assert_eq!(cfg.group_size(), 2, "16 consultas sobre 8 claves");
        assert_eq!(cfg.q_width(), 2048);
        assert_eq!(cfg.kv_width(), 1024, "el cache de GQA es la mitad");
    }

    #[test]
    fn append_rows_stacks_and_checks_width() {
        let a = RTensor::new(vec![1., 2., 3., 4.], vec![2, 2]).unwrap();
        let b = RTensor::new(vec![5., 6.], vec![1, 2]).unwrap();
        let c = append_rows(Some(a), b).unwrap();
        assert_eq!(c.shape(), &[3, 2]);
        assert_eq!(c.data(), &[1., 2., 3., 4., 5., 6.]);

        let wrong = RTensor::new(vec![1., 2., 3.], vec![1, 3]).unwrap();
        assert!(append_rows(Some(c), wrong).is_err(), "ancho distinto debe fallar");
    }

    #[test]
    fn append_rows_from_empty_is_the_identity() {
        let a = RTensor::new(vec![1., 2.], vec![1, 2]).unwrap();
        let c = append_rows(None, a.clone()).unwrap();
        assert_eq!(c, a);
    }

    /// Los tres decoders declaran sus diferencias en la config, no en el código de cada uno.
    #[test]
    fn architecture_variants_are_declared_not_guessed() {
        assert!(DecoderConfig::SUPPORTED.contains(&"llama"));
        assert!(DecoderConfig::SUPPORTED.contains(&"qwen2"));
        assert!(DecoderConfig::SUPPORTED.contains(&"qwen3"));
        assert!(DecoderConfig::SUPPORTED.contains(&"gemma3"), "gemma3 llega en I4-d");
    }
}

/// **El oráculo del decoder.** Los mismos pesos, las dos implementaciones, los mismos logits.
///
/// Es la prueba que cierra I4-c: el encoder ya estaba verificado y la dequantización también, pero
/// un decoder tiene RoPE con posición, GQA y KV cache — tres cosas que pueden estar mal cada una
/// por su lado y producir texto que igual parece razonable.
///
/// Gateado por `SYNSEMA_TEST_GGUF`. Desde I4-e los pesos se quedan cuantizados y desde I4-d el
/// archivo se **mapea**, así que tener las dos implementaciones abiertas a la vez cuesta casi lo
/// que ocupa el `.gguf` — comparten el mismo mapa.
#[cfg(all(test, feature = "rust-backend", feature = "candle-backend"))]
mod oracle {
    use super::*;

    /// **Los dos caminos no son numéricamente equivalentes, y está bien.**
    ///
    /// candle corre el matmul *cuantizado* de ggml (`QMatMul::forward` despacha a
    /// `apply_op1_no_bwd`), que **cuantiza la activación a Q8_K** antes de multiplicar: es más
    /// rápido y usa menos memoria. Nosotros dequantizamos los pesos a `f32` y multiplicamos en
    /// `f32`, que es **más preciso** y más caro. Con 28 capas, esa diferencia de diseño se acumula
    /// hasta un ~6% del rango de los logits.
    ///
    /// Por eso el criterio de este oráculo **no es la distancia entre logits** —que compararía dos
    /// aproximaciones distintas del mismo número— sino lo único que cambia la salida: **qué token
    /// gana**, acá y a lo largo de una generación entera (ver `generated_tokens_match`).
    ///
    /// La dequantización sí se compara exacta, y da cero: ver el oráculo de `quant`.
    const REPORT_ONLY: f32 = f32::INFINITY;

    /// Un prompt corto de varios tokens: ejercita el prefill con máscara causal.
    const IDS: &[u32] = &[9707, 11, 1246, 525, 498, 30];

    #[test]
    fn rust_decoder_matches_candle_on_a_real_gguf() {
        let Ok(path) = std::env::var("SYNSEMA_TEST_GGUF") else {
            eprintln!("[skip] seteá SYNSEMA_TEST_GGUF=/ruta/a/modelo.gguf");
            return;
        };

        // Nuestro camino, completo: parser propio, dequantización propia, decoder propio.
        let ours = {
            let bytes = Arc::new(ModelBytes::map(std::path::Path::new(&path)).expect("GGUF mapeable"));
            let header = crate::gguf_rust::parse_header(bytes.as_slice()).expect("header propio");
            eprintln!(
                "[oráculo] arch {:?}, {} bloques",
                header.arch(),
                DecoderConfig::from_header(&header).map(|c| c.block_count).unwrap_or(0)
            );
            let mut model = LlamaModel::load(&header, &bytes).expect("modelo propio");
            model.forward(IDS).expect("logits propios")
        };

        // El de candle, sobre el mismo archivo.
        let theirs = {
            let mut file = std::fs::File::open(&path).unwrap();
            let content = candle_core::quantized::gguf_file::Content::read(&mut file)
                .expect("header de candle");
            let device = candle_core::Device::Cpu;
            let mut model =
                candle_transformers::models::quantized_qwen3::ModelWeights::from_gguf(
                    content, &mut file, &device,
                )
                .expect("modelo de candle");
            let input = candle_core::Tensor::new(IDS, &device)
                .unwrap()
                .reshape((1, IDS.len()))
                .unwrap();
            let logits = model.forward(&input, 0).expect("logits de candle");
            logits.squeeze(0).unwrap().to_dtype(candle_core::DType::F32).unwrap().to_vec1::<f32>().unwrap()
        };

        assert_eq!(ours.len(), theirs.len(), "distinta cantidad de logits");
        let range = theirs.iter().fold(0f32, |a, b| a.max(b.abs())).max(1e-6);
        let mut worst = 0f32;
        for (a, b) in ours.iter().zip(theirs.iter()) {
            worst = worst.max((a - b).abs());
        }
        eprintln!(
            "[oráculo] {} logits, peor diferencia {:.3e} sobre un rango de {:.2} ({:.2}%)              — esperado: los caminos difieren por diseño, ver la nota de REPORT_ONLY",
            ours.len(),
            worst,
            range,
            100.0 * worst / range
        );

        // Lo que decide el token: el argmax. Si coincide, el modelo dice lo mismo.
        let argmax = |v: &[f32]| {
            v.iter().enumerate().max_by(|x, y| x.1.partial_cmp(y.1).unwrap()).map(|(i, _)| i).unwrap()
        };
        assert_eq!(
            argmax(&ours),
            argmax(&theirs),
            "los backends eligen tokens distintos (propio {} vs candle {})",
            argmax(&ours),
            argmax(&theirs)
        );
        // No se afirma sobre la distancia: ver la nota de `REPORT_ONLY`. Se reporta para que una
        // regresión se note como un salto en el número, no como un test que pasa igual.
        assert!(worst <= REPORT_ONLY, "inalcanzable");
        assert!(worst.is_finite(), "los logits propios tienen que ser finitos");
    }

    /// El invariante que hace correcto al cache: limpiarlo tiene que devolver el modelo al estado
    /// inicial, no a "parecido".
    #[test]
    fn clearing_the_cache_restores_the_initial_state() {
        let Ok(path) = std::env::var("SYNSEMA_TEST_GGUF") else { return };
        let bytes = Arc::new(ModelBytes::map(std::path::Path::new(&path)).expect("GGUF mapeable"));
        let header = crate::gguf_rust::parse_header(bytes.as_slice()).expect("header");
        let mut model = LlamaModel::load(&header, &bytes).expect("modelo");

        let first = model.forward(IDS).expect("primera pasada");
        assert_eq!(model.cached_tokens(), IDS.len(), "el cache debe tener el prompt");

        // Continuar y limpiar: la próxima pasada tiene que dar EXACTAMENTE lo mismo que la primera.
        let _ = model.forward(&[IDS[0]]).expect("un token más");
        assert_eq!(model.cached_tokens(), IDS.len() + 1);
        model.clear_kv_cache();
        assert_eq!(model.cached_tokens(), 0, "limpiar deja el cache vacío");

        let again = model.forward(IDS).expect("segunda pasada");
        assert_eq!(first, again, "tras limpiar, la misma entrada da los mismos logits");
    }
    /// **La prueba que decide.** Genera greedy con los dos backends y compara los tokens.
    ///
    /// Si ocho pasos de generación eligen exactamente los mismos tokens, los modelos son
    /// equivalentes para lo único que hace un decoder: producir texto. Y ejercita el KV cache en
    /// serio, que el test de logits sueltos no hace.
    #[test]
    fn generated_tokens_match_between_backends() {
        let Ok(path) = std::env::var("SYNSEMA_TEST_GGUF") else {
            eprintln!("[skip] seteá SYNSEMA_TEST_GGUF=/ruta/a/modelo.gguf");
            return;
        };
        const STEPS: usize = 8;
        let argmax = |v: &[f32]| {
            v.iter().enumerate().max_by(|x, y| x.1.partial_cmp(y.1).unwrap()).map(|(i, _)| i as u32).unwrap()
        };

        let ours: Vec<u32> = {
            let bytes = Arc::new(ModelBytes::map(std::path::Path::new(&path)).expect("GGUF mapeable"));
            let header = crate::gguf_rust::parse_header(bytes.as_slice()).expect("header");
            let mut model = LlamaModel::load(&header, &bytes).expect("modelo propio");
            let mut out = Vec::with_capacity(STEPS);
            let mut next = argmax(&model.forward(IDS).expect("prefill"));
            for _ in 0..STEPS {
                out.push(next);
                next = argmax(&model.forward(&[next]).expect("decode"));
            }
            out
        };

        let theirs: Vec<u32> = {
            let mut file = std::fs::File::open(&path).unwrap();
            let content = candle_core::quantized::gguf_file::Content::read(&mut file).unwrap();
            let device = candle_core::Device::Cpu;
            let mut model = candle_transformers::models::quantized_qwen3::ModelWeights::from_gguf(
                content, &mut file, &device,
            )
            .expect("modelo de candle");
            let run = |m: &mut candle_transformers::models::quantized_qwen3::ModelWeights,
                       ids: &[u32],
                       pos: usize| {
                let t = candle_core::Tensor::new(ids, &device).unwrap().reshape((1, ids.len())).unwrap();
                m.forward(&t, pos)
                    .unwrap()
                    .squeeze(0)
                    .unwrap()
                    .to_dtype(candle_core::DType::F32)
                    .unwrap()
                    .to_vec1::<f32>()
                    .unwrap()
            };
            let mut out = Vec::with_capacity(STEPS);
            let mut next = argmax(&run(&mut model, IDS, 0));
            let mut pos = IDS.len();
            for _ in 0..STEPS {
                out.push(next);
                next = argmax(&run(&mut model, &[next], pos));
                pos += 1;
            }
            out
        };

        eprintln!("[oráculo] propio: {:?}", ours);
        eprintln!("[oráculo] candle: {:?}", theirs);
        assert_eq!(ours, theirs, "los backends generan secuencias distintas");
    }
    fn gemma3_cfg() -> DecoderConfig {
        DecoderConfig {
            arch: "gemma3".into(),
            block_count: 18,
            embedding_length: 640,
            feed_forward_length: 2048,
            head_count: 4,
            head_count_kv: 1,
            head_dim: 256,
            rms_eps: 1e-6,
            rope_base: 1e6,
            context_length: 32768,
            qkv_bias: false,
            qk_norm: true,
            sliding_window: Some(512),
            sliding_window_type: 6,
            rope_base_local: 10_000.0,
            scale_embeddings: true,
            post_norms: true,
            ffn_activation: FfnAct::GeluTanh,
        }
    }

    /// Cinco de cada seis capas son locales, y la sexta global. Correr el patron una capa cambia
    /// el modelo sin que nada falle.
    #[test]
    fn gemma3_alternates_five_local_layers_and_one_global() {
        let cfg = gemma3_cfg();
        for i in 0..5 {
            assert_eq!(cfg.window_for(i), Some(512), "la capa {} es local", i);
        }
        assert_eq!(cfg.window_for(5), None, "la sexta es global");
        assert_eq!(cfg.window_for(11), None);
        assert_eq!(cfg.window_for(6), Some(512));
        let globales = (0..18).filter(|&i| cfg.window_for(i).is_none()).count();
        assert_eq!(globales, 3, "18 capas, una global cada 6");
    }

    /// Las capas locales usan otra base de RoPE. Usar una sola no falla: degrada.
    #[test]
    fn gemma3_uses_a_different_rope_base_for_local_layers() {
        let cfg = gemma3_cfg();
        assert_eq!(cfg.rope_base_for(0), 10_000.0, "local");
        assert_eq!(cfg.rope_base_for(5), 1_000_000.0, "global");
    }

    #[test]
    fn non_gemma_has_no_window_and_one_rope_base() {
        let mut cfg = gemma3_cfg();
        cfg.sliding_window = None;
        assert_eq!(cfg.window_for(0), None);
        assert_eq!(cfg.rope_base_for(0), 1_000_000.0);
    }
}

/// **El oráculo de gemma3 (I4-d).** Nuestro decoder contra el de candle, sobre el modelo real.
///
/// Tiene un valor extra: `quantized_gemma3` de candle **no expone `clear_kv_cache`**, así que el
/// motor no puede usarlo en su pool (es el PR #3709, abierto desde julio de 2026). Acá sirve
/// igual como referencia de una corrida, y el nuestro sí cumple el invariante.
#[cfg(all(test, feature = "rust-backend", feature = "candle-backend"))]
mod oracle_gemma3 {
    use super::*;

    /// Un prompt de varios tokens: ejercita el prefill con ventana deslizante y máscara causal.
    const IDS: &[u32] = &[2, 8636, 235269, 1368, 708, 692, 235336];

    fn argmax(v: &[f32]) -> u32 {
        v.iter().enumerate().max_by(|x, y| x.1.partial_cmp(y.1).unwrap()).map(|(i, _)| i as u32).unwrap()
    }

    /// **Acá nos separamos de candle a propósito, y vale explicar por qué.**
    ///
    /// Hasta I5 este test exigía tokens IDÉNTICOS a los de candle, y pasaba. Daba confianza, y era
    /// confianza mal puesta: `quantized_gemma3.rs` de candle hardcodea `silu` en el MLP, mientras
    /// que su propio `gemma3.rs` (el no cuantizado) lee `hidden_activation` del config, que en
    /// Gemma 3 es `gelu_pytorch_tanh`. Los dos coincidíamos porque **habíamos copiado el mismo
    /// error**.
    ///
    /// Lo destapó la prueba en vivo: con `silu`, `gemma3:270m` responde `= 1/ 1/ 1/`; el mismo
    /// GGUF por Ollama —que es llama.cpp, y usa GELU— responde «The capital of France is Paris.».
    ///
    /// Es la lección que deja I4 entera: **un oráculo prueba que dos implementaciones coinciden,
    /// no que acierten.** Cuando la referencia es una sola, coincidir con ella es todo lo que se
    /// sabe. Por eso ahora este test afirma la DIFERENCIA: si algún día volviera a dar igual,
    /// significaría que alguien nos puso `silu` de vuelta.
    #[test]
    fn gemma3_deliberately_differs_from_candle_on_the_ffn_activation() {
        let Ok(path) = std::env::var("SYNSEMA_TEST_GEMMA3") else {
            eprintln!("[skip] seteá SYNSEMA_TEST_GEMMA3=/ruta/al/gguf de gemma3");
            return;
        };
        const STEPS: usize = 6;

        let ours: Vec<u32> = {
            let bytes = Arc::new(ModelBytes::map(std::path::Path::new(&path)).expect("GGUF mapeable"));
            let header = crate::gguf_rust::parse_header(bytes.as_slice()).expect("header propio");
            let cfg = DecoderConfig::from_header(&header).expect("config");
            eprintln!(
                "[oráculo gemma3] {} bloques, ventana {:?}, capas locales cada {}",
                cfg.block_count, cfg.sliding_window, cfg.sliding_window_type
            );
            let mut model = LlamaModel::load(&header, &bytes).expect("modelo propio");
            let mut out = Vec::with_capacity(STEPS);
            let mut next = argmax(&model.forward(IDS).expect("prefill"));
            for _ in 0..STEPS {
                out.push(next);
                next = argmax(&model.forward(&[next]).expect("decode"));
            }
            out
        };

        let theirs: Vec<u32> = {
            let mut file = std::fs::File::open(&path).unwrap();
            let content = candle_core::quantized::gguf_file::Content::read(&mut file).unwrap();
            let device = candle_core::Device::Cpu;
            let mut model = candle_transformers::models::quantized_gemma3::ModelWeights::from_gguf(
                content, &mut file, &device,
            )
            .expect("modelo de candle");
            let run = |m: &mut candle_transformers::models::quantized_gemma3::ModelWeights,
                       ids: &[u32],
                       pos: usize| {
                let t = candle_core::Tensor::new(ids, &device).unwrap().reshape((1, ids.len())).unwrap();
                m.forward(&t, pos)
                    .unwrap()
                    .flatten_all()
                    .unwrap()
                    .to_dtype(candle_core::DType::F32)
                    .unwrap()
                    .to_vec1::<f32>()
                    .unwrap()
            };
            let mut out = Vec::with_capacity(STEPS);
            let mut next = argmax(&run(&mut model, IDS, 0));
            let mut pos = IDS.len();
            for _ in 0..STEPS {
                out.push(next);
                next = argmax(&run(&mut model, &[next], pos));
                pos += 1;
            }
            out
        };

        eprintln!("[gemma3] propio (gelu_tanh): {:?}", ours);
        eprintln!("[gemma3] candle (silu):      {:?}", theirs);
        assert_ne!(
            ours, theirs,
            "gemma3 volvió a coincidir con candle, así que alguien puso `silu` de vuelta en el \
             MLP. Gemma usa `gelu_pytorch_tanh`; ver la nota de este test."
        );

        // Y que la diferencia sea EXACTAMENTE la activación: con `silu`, volvemos a coincidir.
        // Sin esto, el test sólo diría «somos distintos», que es lo que diría cualquier bug.
        let with_silu: Vec<u32> = {
            let bytes = Arc::new(ModelBytes::map(std::path::Path::new(&path)).expect("GGUF"));
            let header = crate::gguf_rust::parse_header(bytes.as_slice()).expect("header");
            let mut model = LlamaModel::load(&header, &bytes).expect("modelo");
            model.cfg.ffn_activation = FfnAct::Silu;
            let mut out = Vec::with_capacity(STEPS);
            let mut next = argmax(&model.forward(IDS).expect("prefill"));
            for _ in 0..STEPS {
                out.push(next);
                next = argmax(&model.forward(&[next]).expect("decode"));
            }
            out
        };
        assert_eq!(
            with_silu, theirs,
            "poniéndole `silu` al nuestro tiene que volver a dar lo mismo que candle: si no, la \
             diferencia no es sólo la activación y hay otra cosa mal"
        );
    }

    /// El invariante que candle no puede dar para esta arquitectura: limpiar el cache devuelve el
    /// modelo al estado inicial. Es, literalmente, lo que el PR #3709 pedía.
    #[test]
    fn gemma3_cache_can_be_cleared() {
        let Ok(path) = std::env::var("SYNSEMA_TEST_GEMMA3") else { return };
        let bytes = Arc::new(ModelBytes::map(std::path::Path::new(&path)).expect("GGUF mapeable"));
        let header = crate::gguf_rust::parse_header(bytes.as_slice()).expect("header");
        let mut model = LlamaModel::load(&header, &bytes).expect("modelo");

        let first = model.forward(IDS).expect("primera pasada");
        let _ = model.forward(&[first.len() as u32 % 100]).expect("un token más");
        model.clear_kv_cache();
        assert_eq!(model.cached_tokens(), 0);
        let again = model.forward(IDS).expect("segunda pasada");
        assert_eq!(first, again, "tras limpiar, la misma entrada da los mismos logits");
    }
}

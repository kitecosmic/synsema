//! Correr una arquitectura descrita en datos.
//!
//! [`archdef`](crate::archdef) define **qué** hace una arquitectura; esto la **hace**. Entre las dos
//! está la promesa de I5: el binario ya compilado corre un modelo cuya arquitectura no existía
//! cuando ese binario se compiló.
//!
//! ## Los pesos se atan una vez, no en cada token
//!
//! Cargar resuelve cada paso a sus tensores concretos —`blk.{i}.attn_q.weight` pasa a ser *el*
//! `Weight` de la capa 7— y arma una lista plana por capa. Generar un token recorre esa lista sin
//! volver a buscar nada por nombre. El costo de que la arquitectura sea un dato se paga al abrir el
//! modelo, una vez, y no por token.
//!
//! ## Por qué esto no es más lento que escribirlo en Rust
//!
//! Un paso es un `match` sobre una decena de variantes; el trabajo adentro del paso es un matmul de
//! millones de operaciones. La proporción es la misma que entre el `match` del intérprete de
//! Synsema y lo que hace una primitiva. Medir es lo que corresponde, y el test de paridad
//! (`archrun_matches_arch_llama`) mide además lo que importa más: que el resultado sea **idéntico
//! bit a bit** al de la implementación escrita a mano.
//!
//! ## `arch_llama.rs` sigue existiendo, y es a propósito
//!
//! Esa es la implementación de referencia. No corre en producción —este módulo sí—, pero es el
//! oráculo contra el que se compara el intérprete. Tener dos caminos donde uno verifica al otro es
//! distinto de tener dos caminos que hay que mantener: el de referencia sólo cambia cuando cambia
//! la definición de la arquitectura, y si cambian distinto, el test lo grita.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::arch_llama::{append_rows, attention_gqa, read_tensor, read_weight, DecoderConfig, KvCache};
use crate::archdef::{ActKind, ArchDef, ConfigKey, Expr, Op, Reg, Step, TensorRef};
use crate::backend_rust as ops;
use crate::gguf_rust::GgufHeader;
use crate::mapped::ModelBytes;
use crate::qmatmul::Weight;
use crate::tensor_rust::RTensor;

/// Un paso con sus tensores ya resueltos: lo que queda después de atar la definición a un modelo.
enum Bound {
    Embed { dst: usize, table: Weight },
    RmsNorm { dst: usize, src: usize, weight: RTensor },
    Matmul { dst: usize, src: usize, weight: Weight },
    AddBias { dst: usize, bias: RTensor },
    NormHeads { dst: usize, weight: RTensor, heads: usize },
    Rope { dst: usize, heads: usize },
    Attention { dst: usize, q: usize, k: usize, v: usize },
    Activation { dst: usize, kind: ActKind },
    Mul { dst: usize, src: usize },
    Add { dst: usize, src: usize },
    Scale { dst: usize, factor: f32 },
    Last { dst: usize, src: usize },
    Copy { dst: usize, src: usize },
}

impl Bound {
    /// El nombre de la operación, para los mensajes de error en tiempo de corrida.
    fn op_name(&self) -> &'static str {
        match self {
            Bound::Embed { .. } => "embed",
            Bound::RmsNorm { .. } => "rms_norm",
            Bound::Matmul { .. } => "matmul",
            Bound::AddBias { .. } => "add_bias",
            Bound::NormHeads { .. } => "norm_heads",
            Bound::Rope { .. } => "rope",
            Bound::Attention { .. } => "attention",
            Bound::Activation { .. } => "silu/gelu/gelu_tanh/relu",
            Bound::Mul { .. } => "mul",
            Bound::Add { .. } => "add",
            Bound::Scale { .. } => "scale",
            Bound::Last { .. } => "last",
            Bound::Copy { .. } => "copy",
        }
    }
}

/// Un paso atado más la línea de la que salió, para que un error en vivo señale el archivo.
struct BoundStep {
    bound: Bound,
    line: usize,
}

/// Un modelo corriendo una arquitectura declarativa.
pub struct ArchModel {
    def: ArchDef,
    cfg: DecoderConfig,
    prologue: Vec<BoundStep>,
    /// `[capa][paso]`. Los pesos de cada capa están resueltos desde la carga.
    block: Vec<Vec<BoundStep>>,
    epilogue: Vec<BoundStep>,
    /// Los registros que el prólogo deja vivos. El resto se limpia entre capas.
    persistent: BTreeSet<usize>,
    regs: Vec<Option<RTensor>>,
    cache: Vec<KvCache>,
    residual: usize,
    logits: usize,
}

impl ArchModel {
    /// Ata una definición a un GGUF concreto y deja el modelo listo para generar.
    ///
    /// Acá es donde una definición que no corresponde al archivo falla, y falla **entera**: si
    /// falta un tensor, se dice cuál, en qué línea de la definición y qué capa. El peor final
    /// posible es un error al abrir, nunca un modelo que arranca y responde ruido.
    pub fn load(
        def: ArchDef,
        header: &GgufHeader,
        bytes: &Arc<ModelBytes>,
    ) -> Result<Self, String> {
        let arch = header.arch().unwrap_or_default();
        if arch != def.name {
            return Err(format!(
                "la definición describe '{}' y el modelo dice ser '{}'",
                def.name, arch
            ));
        }
        let mut cfg = DecoderConfig::read_header(header)?;
        // El único parámetro que el GGUF no declara y la definición sí puede fijar.
        let swt = def.param("sliding_window_type", cfg.sliding_window_type as f64);
        if swt < 1.0 || swt.fract() != 0.0 {
            return Err(format!(
                "'{}': `param sliding_window_type {}` tiene que ser un entero de 1 para arriba",
                def.name, swt
            ));
        }
        cfg.sliding_window_type = swt as usize;

        let residual = def
            .residual()
            .ok_or_else(|| format!("'{}' no define el residual `x`", def.name))?
            .0;
        let logits = def
            .logits()
            .ok_or_else(|| format!("'{}' no produce `logits`", def.name))?
            .0;

        let prologue = bind_steps(&def.prologue, None, &cfg, header, bytes)?;
        let mut persistent = BTreeSet::new();
        for step in &def.prologue {
            persistent.insert(dst_of(&step.op));
        }

        let mut block = Vec::with_capacity(cfg.block_count);
        for layer in 0..cfg.block_count {
            block.push(bind_steps(&def.block, Some(layer), &cfg, header, bytes)?);
        }
        let epilogue = bind_steps(&def.epilogue, None, &cfg, header, bytes)?;

        let mut cache = Vec::with_capacity(cfg.block_count);
        cache.resize_with(cfg.block_count, KvCache::default);
        let regs = vec![None; def.reg_count()];

        Ok(ArchModel {
            def,
            cfg,
            prologue,
            block,
            epilogue,
            persistent,
            regs,
            cache,
            residual,
            logits,
        })
    }

    pub fn config(&self) -> &DecoderConfig {
        &self.cfg
    }

    pub fn definition(&self) -> &ArchDef {
        &self.def
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
    /// los tokens de la anterior. Es el invariante que candle no expone para `quantized_gemma3` y
    /// la razón por la que existe todo este crate.
    pub fn clear_kv_cache(&mut self) {
        for c in self.cache.iter_mut() {
            c.keys = None;
            c.values = None;
        }
        for r in self.regs.iter_mut() {
            *r = None;
        }
    }

    /// Procesa `ids` y devuelve los logits del **último** token.
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

        for r in self.regs.iter_mut() {
            *r = None;
        }
        run_section(&self.prologue, &mut self.regs, &self.cfg, &self.def, ids, None, offset, &mut self.cache)?;

        for layer in 0..self.block.len() {
            self.forget_temporaries();
            // El préstamo del bloque y el del cache no se pueden tomar a la vez sobre `self`, así
            // que el bloque sale de su lugar y vuelve. Es un `Vec` de punteros: no copia pesos.
            let steps = std::mem::take(&mut self.block[layer]);
            let r = run_section(
                &steps,
                &mut self.regs,
                &self.cfg,
                &self.def,
                ids,
                Some(layer),
                offset,
                &mut self.cache,
            );
            self.block[layer] = steps;
            r?;
        }

        self.forget_temporaries();
        run_section(&self.epilogue, &mut self.regs, &self.cfg, &self.def, ids, None, offset, &mut self.cache)?;

        let out = self.regs[self.logits]
            .as_ref()
            .ok_or_else(|| format!("'{}' terminó sin dejar `logits`", self.def.name))?;
        if !out.all_finite() {
            return Err("el modelo produjo logits no finitos".to_string());
        }
        Ok(out.data().to_vec())
    }

    /// Borra los registros que no dejó el prólogo.
    ///
    /// La validación ya garantiza que ninguna definición los lee de una capa a la otra; esto hace
    /// que además no pueda hacerlo. Es barato —poner unos punteros en `None`— y convierte una
    /// promesa del validador en una propiedad del intérprete.
    fn forget_temporaries(&mut self) {
        for (i, r) in self.regs.iter_mut().enumerate() {
            if !self.persistent.contains(&i) {
                *r = None;
            }
        }
    }

    /// El residual, para diagnóstico.
    pub fn residual_shape(&self) -> Option<(usize, usize)> {
        self.regs[self.residual].as_ref().and_then(|t| t.dims2().ok())
    }
}

fn dst_of(op: &Op) -> usize {
    match op {
        Op::Embed { dst, .. }
        | Op::RmsNorm { dst, .. }
        | Op::Matmul { dst, .. }
        | Op::AddBias { dst, .. }
        | Op::NormHeads { dst, .. }
        | Op::Rope { dst, .. }
        | Op::Attention { dst, .. }
        | Op::Activation { dst, .. }
        | Op::Mul { dst, .. }
        | Op::Add { dst, .. }
        | Op::Scale { dst, .. }
        | Op::Last { dst, .. }
        | Op::Copy { dst, .. } => dst.0,
    }
}

fn value_of(cfg: &DecoderConfig, key: ConfigKey) -> usize {
    match key {
        ConfigKey::HeadCount => cfg.head_count,
        ConfigKey::HeadCountKv => cfg.head_count_kv,
        ConfigKey::HeadDim => cfg.head_dim,
        ConfigKey::EmbeddingLength => cfg.embedding_length,
        ConfigKey::FeedForwardLength => cfg.feed_forward_length,
        ConfigKey::BlockCount => cfg.block_count,
        ConfigKey::ContextLength => cfg.context_length,
    }
}

fn eval(cfg: &DecoderConfig, e: Expr) -> f32 {
    match e {
        Expr::Literal(v) => v,
        Expr::Config(k) => value_of(cfg, k) as f32,
        Expr::Sqrt(k) => (value_of(cfg, k) as f32).sqrt(),
    }
}

/// Resuelve un tensor de peso denso (normas, sesgos), probando el alternativo si hace falta.
fn bind_dense(
    t: &TensorRef,
    layer: Option<usize>,
    header: &GgufHeader,
    bytes: &Arc<ModelBytes>,
    line: usize,
) -> Result<RTensor, String> {
    let (name, fallback) = t.resolve(layer.unwrap_or(0));
    match read_tensor(header, bytes.as_slice(), &name) {
        Ok(v) => Ok(v),
        Err(first) => match fallback {
            Some(f) => read_tensor(header, bytes.as_slice(), &f).map_err(|second| {
                format!("línea {}: ni '{}' ni '{}' ({}; {})", line, name, f, first, second)
            }),
            None => Err(format!("línea {}: {}", line, first)),
        },
    }
}

/// Resuelve un peso grande, que se queda cuantizado en memoria.
fn bind_weight(
    t: &TensorRef,
    layer: Option<usize>,
    header: &GgufHeader,
    bytes: &Arc<ModelBytes>,
    line: usize,
) -> Result<Weight, String> {
    let (name, fallback) = t.resolve(layer.unwrap_or(0));
    match read_weight(header, bytes, &name) {
        Ok(v) => Ok(v),
        Err(first) => match fallback {
            Some(f) => read_weight(header, bytes, &f).map_err(|second| {
                format!("línea {}: ni '{}' ni '{}' ({}; {})", line, name, f, first, second)
            }),
            None => Err(format!("línea {}: {}", line, first)),
        },
    }
}

fn bind_steps(
    steps: &[Step],
    layer: Option<usize>,
    cfg: &DecoderConfig,
    header: &GgufHeader,
    bytes: &Arc<ModelBytes>,
) -> Result<Vec<BoundStep>, String> {
    let mut out = Vec::with_capacity(steps.len());
    for s in steps {
        let line = s.line;
        let r = |g: Reg| g.0;
        let bound = match &s.op {
            Op::Embed { dst, table } => {
                Bound::Embed { dst: r(*dst), table: bind_weight(table, layer, header, bytes, line)? }
            }
            Op::RmsNorm { dst, src, weight } => Bound::RmsNorm {
                dst: r(*dst),
                src: r(*src),
                weight: bind_dense(weight, layer, header, bytes, line)?,
            },
            Op::Matmul { dst, src, weight } => Bound::Matmul {
                dst: r(*dst),
                src: r(*src),
                weight: bind_weight(weight, layer, header, bytes, line)?,
            },
            Op::AddBias { dst, bias } => Bound::AddBias {
                dst: r(*dst),
                bias: bind_dense(bias, layer, header, bytes, line)?,
            },
            Op::NormHeads { dst, weight, heads } => Bound::NormHeads {
                dst: r(*dst),
                weight: bind_dense(weight, layer, header, bytes, line)?,
                heads: value_of(cfg, *heads),
            },
            Op::Rope { dst, heads } => Bound::Rope { dst: r(*dst), heads: value_of(cfg, *heads) },
            Op::Attention { dst, q, k, v } => {
                Bound::Attention { dst: r(*dst), q: r(*q), k: r(*k), v: r(*v) }
            }
            Op::Activation { dst, kind } => Bound::Activation { dst: r(*dst), kind: *kind },
            Op::Mul { dst, src } => Bound::Mul { dst: r(*dst), src: r(*src) },
            Op::Add { dst, src } => Bound::Add { dst: r(*dst), src: r(*src) },
            Op::Scale { dst, factor } => {
                Bound::Scale { dst: r(*dst), factor: eval(cfg, *factor) }
            }
            Op::Last { dst, src } => Bound::Last { dst: r(*dst), src: r(*src) },
            Op::Copy { dst, src } => Bound::Copy { dst: r(*dst), src: r(*src) },
        };
        out.push(BoundStep { bound, line });
    }
    Ok(out)
}

/// Corre una lista de pasos sobre el archivo de registros.
#[allow(clippy::too_many_arguments)]
fn run_section(
    steps: &[BoundStep],
    regs: &mut [Option<RTensor>],
    cfg: &DecoderConfig,
    def: &ArchDef,
    ids: &[u32],
    layer: Option<usize>,
    offset: usize,
    cache: &mut [KvCache],
) -> Result<(), String> {
    for step in steps {
        run_step(step, regs, cfg, def, ids, layer, offset, cache).map_err(|e| {
            format!("'{}' línea {} (`{}`): {}", def.name, step.line, step.bound.op_name(), e)
        })?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_step(
    step: &BoundStep,
    regs: &mut [Option<RTensor>],
    cfg: &DecoderConfig,
    def: &ArchDef,
    ids: &[u32],
    layer: Option<usize>,
    offset: usize,
    cache: &mut [KvCache],
) -> Result<(), String> {
    // Leer un registro que la validación ya garantizó escrito. Si esto falla es un bug nuestro,
    // no de la definición, y el mensaje lo dice para no mandar a nadie a buscar donde no es.
    let read = |regs: &[Option<RTensor>], i: usize| -> Result<RTensor, String> {
        regs[i].clone().ok_or_else(|| {
            format!(
                "el registro `{}` está vacío, y la validación decía que no podía estarlo \
                 (esto es un bug del intérprete, no de la definición)",
                def.reg_name(Reg(i))
            )
        })
    };
    let take_mut = |regs: &mut [Option<RTensor>], i: usize| -> Result<RTensor, String> {
        regs[i].take().ok_or_else(|| {
            format!("el registro `{}` está vacío", def.reg_name(Reg(i)))
        })
    };

    match &step.bound {
        Bound::Embed { dst, table } => {
            regs[*dst] = Some(table.embedding(ids)?);
        }
        Bound::RmsNorm { dst, src, weight } => {
            let x = read(regs, *src)?;
            regs[*dst] = Some(ops::rms_norm(&x, weight.data(), cfg.rms_eps)?);
        }
        Bound::Matmul { dst, src, weight } => {
            let x = read(regs, *src)?;
            regs[*dst] = Some(weight.matmul(&x)?);
        }
        Bound::AddBias { dst, bias } => {
            let mut x = take_mut(regs, *dst)?;
            ops::add_row_broadcast(&mut x, bias.data())?;
            regs[*dst] = Some(x);
        }
        Bound::NormHeads { dst, weight, heads } => {
            let mut x = take_mut(regs, *dst)?;
            ops::rms_norm_per_head_inplace(&mut x, *heads, cfg.head_dim, weight.data(), cfg.rms_eps)?;
            regs[*dst] = Some(x);
        }
        Bound::Rope { dst, heads } => {
            let l = layer.ok_or("`rope` fuera de una capa")?;
            let mut x = take_mut(regs, *dst)?;
            // La base depende de si la capa es local o global: es lo que hace gemma3, y correrlo
            // una capa cambia el modelo entero.
            ops::rope_inplace(&mut x, *heads, cfg.head_dim, cfg.rope_base_for(l), offset)?;
            regs[*dst] = Some(x);
        }
        Bound::Attention { dst, q, k, v } => {
            let l = layer.ok_or("`attention` fuera de una capa")?;
            let qq = read(regs, *q)?;
            let kk = read(regs, *k)?;
            let vv = read(regs, *v)?;
            let c = &mut cache[l];
            // El cache crece con la secuencia, así que se guarda UNA vez y la atención lo lee
            // prestado. Copiarlo para guardarlo y quedarse con la copia —que es lo que hace la
            // implementación de referencia— duplica el tráfico de memoria en el paso más caliente,
            // y ese tráfico crece con el largo del contexto.
            c.keys = Some(append_rows(c.keys.take(), kk)?);
            c.values = Some(append_rows(c.values.take(), vv)?);
            let keys = c.keys.as_ref().expect("recién guardado");
            let values = c.values.as_ref().expect("recién guardado");
            regs[*dst] =
                Some(attention_gqa(cfg, &qq, keys, values, offset, cfg.window_for(l))?);
        }
        Bound::Activation { dst, kind } => {
            let mut x = take_mut(regs, *dst)?;
            match kind {
                ActKind::Silu => ops::silu(&mut x),
                ActKind::Gelu => ops::gelu(&mut x),
                ActKind::GeluTanh => ops::gelu_tanh(&mut x),
                ActKind::Relu => ops::relu(&mut x),
            }
            regs[*dst] = Some(x);
        }
        Bound::Mul { dst, src } => {
            let other = read(regs, *src)?;
            let mut x = take_mut(regs, *dst)?;
            ops::mul_inplace(&mut x, &other)?;
            regs[*dst] = Some(x);
        }
        Bound::Add { dst, src } => {
            let other = read(regs, *src)?;
            let mut x = take_mut(regs, *dst)?;
            ops::add_inplace(&mut x, &other)?;
            regs[*dst] = Some(x);
        }
        Bound::Scale { dst, factor } => {
            let mut x = take_mut(regs, *dst)?;
            ops::scale_inplace(&mut x, *factor);
            regs[*dst] = Some(x);
        }
        Bound::Last { dst, src } => {
            let x = read(regs, *src)?;
            let (n, _) = x.dims2()?;
            regs[*dst] = Some(ops::index_select(&x, &[n - 1])?);
        }
        Bound::Copy { dst, src } => {
            let x = read(regs, *src)?;
            regs[*dst] = Some(x);
        }
    }
    Ok(())
}

/// **El criterio I5-a, como test.** Las mismas cuatro arquitecturas, escritas dos veces —a mano en
/// `arch_llama.rs` y en datos en `defs/*.archdef`—, tienen que dar **el mismo bit**.
///
/// No «parecido», no «dentro de una tolerancia»: idéntico. Las dos ejecutan las mismas operaciones
/// en el mismo orden sobre los mismos pesos, así que cualquier diferencia es un error de
/// traducción, y una diferencia de un ULP en la capa 3 cambia el token 40 pasos después.
///
/// Si esto falla, el formato está mal y hay que rehacerlo **antes** de publicarlo. Es literalmente
/// la condición que el spec puso para dar I5 por buena.
#[cfg(all(test, feature = "rust-backend"))]
mod oracle {
    use super::*;
    use crate::arch_llama::LlamaModel;
    use crate::arch_registry::Registry;
    use crate::gguf_rust::parse_header;
    use std::path::Path;

    fn open(path: &str) -> (GgufHeader, Arc<ModelBytes>) {
        let bytes = Arc::new(ModelBytes::map(Path::new(path)).expect("mapear el gguf"));
        let header = parse_header(bytes.as_slice()).expect("parsear el gguf");
        (header, bytes)
    }

    /// Carga las dos implementaciones sobre **el mismo mapa** de bytes.
    ///
    /// Comparten el `Arc<ModelBytes>`, así que tener las dos en memoria cuesta casi lo mismo que
    /// tener una: los pesos son porciones del mismo archivo mapeado.
    fn both(path: &str) -> (LlamaModel, ArchModel) {
        let (header, bytes) = open(path);
        let arch = header.arch().expect("el gguf declara su arquitectura").to_string();
        let hand = LlamaModel::load(&header, &bytes).expect("implementación de referencia");
        let registry = Registry::load(None);
        let def = registry
            .find(&arch)
            .unwrap_or_else(|| panic!("no hay definición embebida para '{}'", arch))
            .clone();
        let decl = ArchModel::load(def, &header, &bytes).expect("intérprete declarativo");
        (hand, decl)
    }

    fn identical(a: &[f32], b: &[f32], what: &str) {
        assert_eq!(a.len(), b.len(), "{}: distinto tamaño de logits", what);
        if let Some(i) = a.iter().zip(b).position(|(x, y)| x.to_bits() != y.to_bits()) {
            panic!(
                "{}: el logit {} difiere — a mano {:e}, declarativo {:e}. \
                 La traducción del formato no es exacta y eso invalida I5-a.",
                what, i, a[i], b[i]
            );
        }
    }

    #[test]
    fn the_declarative_path_matches_the_handwritten_one_bit_for_bit() {
        let Ok(path) = std::env::var("SYNSEMA_TEST_GGUF") else {
            eprintln!("[skip] seteá SYNSEMA_TEST_GGUF=/ruta/a/modelo.gguf");
            return;
        };
        let (mut hand, mut decl) = both(&path);

        // 1) El prompt entero de una vez: cubre el camino con varias filas.
        let prompt: Vec<u32> = vec![1, 15, 264, 3928, 1938];
        identical(
            &hand.forward(&prompt).expect("a mano"),
            &decl.forward(&prompt).expect("declarativo"),
            "prompt",
        );

        // 2) Token a token: cubre el KV cache, el offset de RoPE y la máscara causal, que es donde
        //    una traducción mal hecha se nota recién en el segundo paso.
        for (step, id) in [42u32, 7, 1000].into_iter().enumerate() {
            identical(
                &hand.forward(&[id]).expect("a mano"),
                &decl.forward(&[id]).expect("declarativo"),
                &format!("token incremental {}", step + 1),
            );
        }

        // 3) Y después de limpiar, las dos vuelven al mismo punto de partida.
        hand.clear_kv_cache();
        decl.clear_kv_cache();
        identical(
            &hand.forward(&prompt).expect("a mano"),
            &decl.forward(&prompt).expect("declarativo"),
            "después de limpiar el cache",
        );
    }

    /// gemma3 es la que más piezas tiene —escala de embeddings, normas por cabeza, normas después
    /// del bloque, ventana alternada y dos bases de RoPE—, así que es la que de verdad prueba que
    /// el formato alcanza para describir una arquitectura completa.
    #[test]
    fn gemma3_also_matches_bit_for_bit() {
        let Ok(path) = std::env::var("SYNSEMA_TEST_GEMMA3") else {
            eprintln!("[skip] seteá SYNSEMA_TEST_GEMMA3=/ruta/al/gguf de gemma3");
            return;
        };
        let (mut hand, mut decl) = both(&path);
        let prompt: Vec<u32> = vec![2, 818, 3072, 529];
        identical(
            &hand.forward(&prompt).expect("a mano"),
            &decl.forward(&prompt).expect("declarativo"),
            "gemma3 prompt",
        );
        // La ventana deslizante alterna cada 6 capas: hay que pasar varios tokens para que las
        // capas locales y las globales vean cosas distintas.
        for id in [107u32, 108, 109, 110, 111, 112, 113] {
            identical(
                &hand.forward(&[id]).expect("a mano"),
                &decl.forward(&[id]).expect("declarativo"),
                "gemma3 incremental",
            );
        }
    }

    /// **El criterio I5-b, como test.** Una definición que viene **de un archivo** es la que de
    /// verdad corre el modelo.
    ///
    /// La primera mitad muestra que un archivo del disco produce el mismo resultado que la
    /// embebida. La segunda es la que cierra el argumento: si se le saca un paso al archivo, el
    /// resultado **cambia**. Sin eso, un test que sólo compara «igual a igual» no distingue entre
    /// «el archivo manda» y «el archivo se ignora y corre el camino compilado».
    #[test]
    fn a_definition_from_disk_is_what_actually_runs() {
        let Ok(path) = std::env::var("SYNSEMA_TEST_GGUF") else {
            eprintln!("[skip] seteá SYNSEMA_TEST_GGUF=/ruta/a/modelo.gguf");
            return;
        };
        let (header, bytes) = open(&path);
        let arch = header.arch().expect("arquitectura").to_string();
        let builtin = Registry::load(None);
        let embedded = builtin.find(&arch).expect("definición embebida").clone();

        // El texto de la embebida, escrito a un directorio como lo haría un tercero.
        let dir = std::env::temp_dir().join("synsema-archdef-disk-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("crear el directorio");
        let source = builtin_text(&arch).expect("el texto de la definición embebida");
        let file = dir.join(format!("{}.archdef", arch));
        std::fs::write(&file, source).expect("escribir la definición");

        let from_disk = Registry::load(Some(&dir));
        let disk_def = from_disk.find(&arch).expect("la del disco").clone();
        assert!(
            matches!(disk_def.origin, crate::archdef::DefOrigin::File(_)),
            "la del disco tiene que pisar a la embebida"
        );
        assert_eq!(disk_def.sha256, embedded.sha256, "es el mismo texto");

        let ids: Vec<u32> = vec![1, 15, 264, 3928, 1938];
        let mut a = ArchModel::load(embedded, &header, &bytes).expect("embebida");
        let mut b = ArchModel::load(disk_def, &header, &bytes).expect("del disco");
        identical(&a.forward(&ids).unwrap(), &b.forward(&ids).unwrap(), "disco vs embebida");

        // Ahora una definición del disco DISTINTA: sin el residual de la atención. Tiene que
        // cargar (es un programa válido) y dar otro resultado. Si diera el mismo, el archivo no
        // sería lo que manda.
        let mutilated = source.replacen("  add(x, o)", "  scale(o, 0.0)\n  add(x, o)", 1);
        assert_ne!(mutilated, source, "el fixture tiene que cambiar algo");
        std::fs::write(&file, &mutilated).expect("reescribir");
        let reloaded = Registry::load(Some(&dir));
        let changed = reloaded.find(&arch).expect("la modificada").clone();
        let mut c = ArchModel::load(changed, &header, &bytes).expect("la modificada carga");
        a.clear_kv_cache();
        let original = a.forward(&ids).unwrap();
        let altered = c.forward(&ids).unwrap();
        assert!(
            original.iter().zip(&altered).any(|(x, y)| x.to_bits() != y.to_bits()),
            "cambiar el archivo tiene que cambiar el resultado; si no, el archivo no es lo que corre"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **¿Cuánto cuesta que la arquitectura sea un dato?**
    ///
    /// La doc del módulo dice que casi nada, y eso hay que medirlo, no argumentarlo. El intérprete
    /// hace un `match` por paso; el paso hace un matmul de millones de operaciones. La proporción
    /// tendría que ser invisible.
    ///
    /// El guard es flojo a propósito —una máquina compartida hace ruido— y sólo agarra una
    /// regresión de las que importan: si el intérprete se vuelve el doble de lento, algo se rompió
    /// de verdad (una copia por paso, una búsqueda por nombre en el bucle).
    #[test]
    fn the_interpreter_costs_about_nothing() {
        let Ok(path) = std::env::var("SYNSEMA_TEST_GGUF") else {
            eprintln!("[skip] seteá SYNSEMA_TEST_GGUF=/ruta/a/modelo.gguf");
            return;
        };
        let (mut hand, mut decl) = both(&path);
        let prompt: Vec<u32> = vec![1, 15, 264, 3928, 1938];
        // Una pasada de calentamiento: la primera toca páginas del mapa que todavía no están.
        hand.forward(&prompt).unwrap();
        decl.forward(&prompt).unwrap();

        let tokens: Vec<u32> = (100..112).collect();
        let time = |f: &mut dyn FnMut(&[u32]) -> Result<Vec<f32>, String>| {
            let t0 = std::time::Instant::now();
            for id in &tokens {
                f(&[*id]).unwrap();
            }
            t0.elapsed().as_secs_f64()
        };
        let a = time(&mut |ids| hand.forward(ids));
        let b = time(&mut |ids| decl.forward(ids));

        let ratio = b / a;
        eprintln!(
            "[archrun] {} tokens — a mano {:.0} ms, declarativo {:.0} ms ({:+.1}%)",
            tokens.len(),
            a * 1000.0,
            b * 1000.0,
            (ratio - 1.0) * 100.0
        );
        assert!(
            ratio < 2.0,
            "el intérprete tardó {:.2}× lo que la implementación a mano; eso ya no es el costo \
             del `match`, es una copia o una búsqueda metida en el bucle",
            ratio
        );
    }

    /// El texto de una definición embebida, para el test de arriba.
    fn builtin_text(arch: &str) -> Option<&'static str> {
        match arch {
            "llama" => Some(include_str!("../defs/llama.archdef")),
            "qwen2" => Some(include_str!("../defs/qwen2.archdef")),
            "qwen3" => Some(include_str!("../defs/qwen3.archdef")),
            "gemma3" => Some(include_str!("../defs/gemma3.archdef")),
            _ => None,
        }
    }

    /// Una definición que no corresponde al modelo falla **al cargar**, con el tensor que falta.
    #[test]
    fn a_definition_that_does_not_match_the_model_fails_early() {
        let Ok(path) = std::env::var("SYNSEMA_TEST_GGUF") else { return };
        let (header, bytes) = open(&path);
        let arch = header.arch().unwrap().to_string();

        // Misma arquitectura declarada, pero pide un tensor que no existe.
        let text = builtin_text(&arch)
            .expect("una de las cuatro")
            .replacen("blk.{i}.attn_q.weight", "blk.{i}.no_existe.weight", 1);
        let def = crate::archdef::parse(&text, crate::archdef::DefOrigin::Embedded)
            .expect("el programa es válido: lo que falla es el modelo");
        let e = match ArchModel::load(def, &header, &bytes) {
            Ok(_) => panic!("cargó un modelo al que le falta un tensor"),
            Err(e) => e,
        };
        assert!(e.contains("no_existe"), "dice qué tensor falta: {}", e);

        // Y una definición de OTRA arquitectura se rechaza antes de mirar un solo tensor.
        let other = if arch == "llama" { "qwen2" } else { "llama" };
        let registry = Registry::load(None);
        let def = registry.find(other).unwrap().clone();
        let e = match ArchModel::load(def, &header, &bytes) {
            Ok(_) => panic!("cargó una definición de otra arquitectura"),
            Err(e) => e,
        };
        assert!(e.contains(other) && e.contains(&arch), "nombra las dos: {}", e);
    }
}
